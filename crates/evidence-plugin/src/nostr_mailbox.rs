//! The Nostr mailbox of this node (loop step 13, Ask across;
//! evidence-network/loop#442): the route `nostr_announce` advertises
//! (`ask.nostr {mailbox_key, relays}`) is read, and a request addressed to
//! it is answered. Everything about the events follows
//! `spec/bindings/nostr-mailbox-v0.md` of agent-action-capsule (cited here as
//! NMB); this module invents no format.
//!
//! **Responder** ([`round`], once every [`POLL`]): when
//! `advertise_evidence_requests` is on, each relay of the route is asked for
//! the kind [`REQUEST_KIND`] events addressed to the mailbox key (`#p`). An
//! event whose `id` or signature does not verify is never answered (NMB §4.1).
//! A request is answered once per event id, through the same in-process path
//! the mesh stream uses (`mesh_evidence_bridge::answer_in_process`), so the
//! disclosure gate, the in-flight pools and the "asked of you" log are the
//! mesh's. The signed envelope or refusal goes back as one kind
//! [`REPLY_KIND`] event signed by the mailbox key, naming the request event
//! (`e`) and its author (`p`), on the relay the request was read from
//! (NMB §4.2, §4.3). A request that yields nothing this node can sign gets
//! no reply, never an unsigned one (NMB §5.2); the asker records an absence.
//!
//! Answered ids are kept in [`ANSWERED_FILE`] so a restart does not answer a
//! request event again (NMB §6). Only requests newer than [`LOOKBACK`] are
//! read: the commitment promises an answer within a minute.
//!
//! Events are not encrypted (NMB §8): whoever reads the relay sees the request
//! and the answer. Use a relay that authenticates its readers.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::nostr_announce::{connect, lock, send_event, signed_event, Outcome, RELAY_TIMEOUT};

/// The request event kind (NMB §4, a placeholder).
pub const REQUEST_KIND: u64 = 4700;

/// The reply event kind (NMB §4, a placeholder).
pub const REPLY_KIND: u64 = 4701;

/// The only media type this node reads and answers: the JSON request and
/// reply of `evidence-interop/1` (NMB §4).
pub const MEDIA: &str = "application/json";

/// The mailbox is read this often.
pub const POLL: Duration = Duration::from_secs(5);

/// A request event older than this many seconds is not read: the
/// commitment's `answers_within` is a minute, and its asker's window has
/// closed.
pub const LOOKBACK: i64 = 300;

/// The most request events read from one relay in one round.
const LIMIT: usize = 64;

/// The most a request event's content may be (base64url text): a few KB is
/// a request, and the mesh path reads at most 1 MiB.
const MAX_CONTENT: usize = 1024 * 1024 * 4 / 3 + 4;

/// The request event ids this node has answered, one `<id> <created_at>` per
/// line, in the data directory.
pub const ANSWERED_FILE: &str = "nostr-mailbox.answered";

/// A signature-checked NIP-01 event (the fields the mailbox reads).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

/// `raw` as an event whose `id` is the NIP-01 hash of it and whose `sig`
/// verifies under its `pubkey` by BIP-340, or why not (NMB §4.1, §4.2 checks
/// 5 and 6).
pub fn verify_event(raw: &Value) -> Result<Event, String> {
    let text = |name: &str| {
        raw[name]
            .as_str()
            .map(str::to_string)
            .ok_or(format!("no {name}"))
    };
    let (id, pubkey, sig, content) = (text("id")?, text("pubkey")?, text("sig")?, text("content")?);
    let created_at = raw["created_at"].as_i64().ok_or("no created_at")?;
    let kind = raw["kind"].as_u64().ok_or("no kind")?;
    let mut tags = Vec::new();
    for tag in raw["tags"].as_array().ok_or("no tags")? {
        let parts = tag.as_array().ok_or("a tag is not an array")?;
        tags.push(
            parts
                .iter()
                .map(|p| {
                    p.as_str()
                        .map(str::to_string)
                        .ok_or("a tag part is not text")
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    let serial = serde_json::to_string(&json!([0, pubkey, created_at, kind, raw["tags"], content]))
        .map_err(|e| e.to_string())?;
    let hash = Sha256::digest(serial.as_bytes());
    if hex::encode(hash) != id {
        return Err("the id is not the hash of the event".into());
    }
    let key = hex::decode(&pubkey)
        .ok()
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or("the pubkey is not a BIP-340 key")?;
    let sig = hex::decode(&sig)
        .ok()
        .and_then(|b| Signature::try_from(b.as_slice()).ok())
        .ok_or("the signature is not a BIP-340 signature")?;
    key.verify_raw(&hash, &sig)
        .map_err(|_| "the signature does not verify".to_string())?;
    Ok(Event {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
    })
}

impl Event {
    /// The value of the one tag named `name`, or `None` when it is absent or
    /// repeated (NMB §4.1: "exactly one").
    pub fn one_tag(&self, name: &str) -> Option<&str> {
        let mut named = self
            .tags
            .iter()
            .filter(|t| t.first().map(String::as_str) == Some(name));
        let first = named.next()?;
        if named.next().is_some() {
            return None;
        }
        first.get(1).map(String::as_str)
    }
}

/// The request octets of `event` when it is a request to `mailbox_key` this
/// node reads: kind [`REQUEST_KIND`], exactly one `p` tag naming the mailbox
/// key, exactly one `m` tag naming [`MEDIA`], content base64url without
/// padding (NMB §4.1).
pub fn request_octets(event: &Event, mailbox_key: &str) -> Option<Vec<u8>> {
    if event.kind != REQUEST_KIND
        || event.one_tag("p") != Some(mailbox_key)
        || event.one_tag("m") != Some(MEDIA)
        || event.content.len() > MAX_CONTENT
    {
        return None;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&event.content)
        .ok()
}

/// The reply event to `request` (NMB §4.2), signed by the mailbox key.
pub fn reply_event(key: &SigningKey, request: &Event, octets: &[u8], at: i64) -> Value {
    signed_event(
        key,
        REPLY_KIND,
        json!([["e", request.id], ["p", request.pubkey], ["m", MEDIA]]),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(octets),
        at,
    )
}

/// The events `url` returns for one `REQ` of `filter`, up to its `EOSE`, at
/// most [`LIMIT`] of them, and in no more than [`RELAY_TIMEOUT`].
pub fn fetch(url: &str, filter: &Value) -> Result<Vec<Value>, String> {
    let started = Instant::now();
    let (mut socket, timer) = connect(url)?;
    let sub = "mailbox";
    socket
        .send(tungstenite::Message::text(
            json!(["REQ", sub, filter]).to_string(),
        ))
        .map_err(|e| format!("could not send: {e}"))?;
    let mut events = Vec::new();
    let outcome = loop {
        let left = RELAY_TIMEOUT.saturating_sub(started.elapsed());
        if left.is_zero() {
            break Err("no end of stored events in time".to_string());
        }
        timer
            .set_read_timeout(Some(left.max(Duration::from_millis(50))))
            .ok();
        let text = match socket.read() {
            Ok(tungstenite::Message::Text(text)) => text,
            Ok(tungstenite::Message::Close(_)) => {
                break Err("the relay closed the connection".into())
            }
            Ok(_) => continue,
            Err(e) => break Err(format!("closed before it answered: {e}")),
        };
        let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match parts.first().and_then(Value::as_str) {
            Some("EVENT") if parts.get(1).and_then(Value::as_str) == Some(sub) => {
                if let Some(event) = parts.get(2) {
                    events.push(event.clone());
                }
                if events.len() >= LIMIT {
                    break Ok(());
                }
            }
            Some("EOSE") if parts.get(1).and_then(Value::as_str) == Some(sub) => break Ok(()),
            Some("CLOSED") if parts.get(1).and_then(Value::as_str) == Some(sub) => {
                break Err(format!(
                    "the relay closed the subscription: {}",
                    parts.get(2).and_then(Value::as_str).unwrap_or_default()
                ))
            }
            _ => {}
        }
    };
    let _ = socket.send(tungstenite::Message::text(
        json!(["CLOSE", sub]).to_string(),
    ));
    let _ = socket.close(None);
    outcome.map(|()| events)
}

// ---------------------------------------------------------------------
// Which request events were answered
// ---------------------------------------------------------------------

/// The request event ids answered, read from [`ANSWERED_FILE`] in `dir`;
/// those older than twice [`LOOKBACK`] are dropped, since [`round`] no longer
/// reads them.
pub fn answered(dir: &Path, now: i64) -> BTreeMap<String, i64> {
    std::fs::read_to_string(dir.join(ANSWERED_FILE))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (id, at) = line.split_once(' ')?;
            Some((id.to_string(), at.parse::<i64>().ok()?))
        })
        .filter(|(_, at)| *at > now - 2 * LOOKBACK)
        .collect()
}

/// Write `ids` to [`ANSWERED_FILE`] in `dir`, whole and renamed into place.
fn keep(dir: &Path, ids: &BTreeMap<String, i64>) -> std::io::Result<()> {
    let tmp = dir.join(format!("{ANSWERED_FILE}.tmp"));
    let mut file = std::fs::File::create(&tmp)?;
    for (id, at) in ids {
        writeln!(file, "{id} {at}")?;
    }
    file.sync_all()?;
    std::fs::rename(tmp, dir.join(ANSWERED_FILE))
}

// ---------------------------------------------------------------------
// One round
// ---------------------------------------------------------------------

/// The last result per relay, for `doctor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayRead {
    /// `read` or `unreachable`.
    pub state: &'static str,
    pub detail: String,
    /// When, `YYYY-MM-DDTHH:MM:SSZ`.
    pub at: String,
    /// The requests answered since this node started.
    pub answered: usize,
}

static STATUS: Mutex<BTreeMap<String, RelayRead>> = Mutex::new(BTreeMap::new());

/// The last result per relay.
pub fn status() -> BTreeMap<String, RelayRead> {
    lock(&STATUS).clone()
}

/// One read of the mailbox on every relay of `relays`. `answer` turns request
/// octets into the signed reply octets, or `None` when there is nothing to
/// sign. Returns the request event ids answered.
pub async fn round<A, F>(
    dir: &Path,
    key: &SigningKey,
    relays: &[String],
    now: i64,
    answer: A,
) -> Vec<String>
where
    A: Fn(Vec<u8>) -> F,
    F: std::future::Future<Output = Option<Vec<u8>>>,
{
    let mailbox_key = hex::encode(key.verifying_key().to_bytes());
    let mut done = answered(dir, now);
    let mut answered_now = Vec::new();
    for url in relays {
        let filter = json!({
            "kinds": [REQUEST_KIND],
            "#p": [mailbox_key],
            "since": now - LOOKBACK,
            "limit": LIMIT,
        });
        let read = {
            let (url, filter) = (url.clone(), filter.clone());
            tokio::task::spawn_blocking(move || fetch(&url, &filter))
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
        };
        let events = match read {
            Ok(events) => events,
            Err(why) => {
                note(url, "unreachable", why, 0);
                continue;
            }
        };
        let mut count = 0;
        for raw in events {
            let Ok(request) = verify_event(&raw) else {
                continue;
            };
            // The relay is not trusted to filter by `since` or by `#p`.
            if done.contains_key(&request.id) || request.created_at < now - LOOKBACK {
                continue;
            }
            let Some(octets) = request_octets(&request, &mailbox_key) else {
                continue;
            };
            // Marked before the answer is built, so a crash between the
            // two never answers the request twice (NMB §6); the asker then
            // records an absence.
            done.insert(request.id.clone(), request.created_at);
            if let Err(e) = keep(dir, &done) {
                tracing::warn!(error = %e, "the answered request ids could not be kept");
            }
            let Some(reply) = answer(octets).await else {
                continue;
            };
            let event = reply_event(key, &request, &reply, now);
            let to = url.clone();
            let sent = tokio::task::spawn_blocking(move || send_event(&to, &event))
                .await
                .unwrap_or_else(|e| Outcome::Unreachable(e.to_string()));
            match sent {
                Outcome::Accepted => {
                    count += 1;
                    answered_now.push(request.id.clone());
                }
                Outcome::Rejected(why) | Outcome::Unreachable(why) => {
                    tracing::warn!(relay = %url, %why, "a mailbox reply was not accepted");
                }
            }
        }
        note(url, "read", String::new(), count);
    }
    answered_now
}

fn note(url: &str, state: &'static str, detail: String, answered: usize) {
    let mut held = lock(&STATUS);
    let before = held.get(url).map_or(0, |r| r.answered);
    held.insert(
        url.to_string(),
        RelayRead {
            state,
            detail,
            at: crate::evidence_answer::now_utc(),
            answered: before + answered,
        },
    );
}

/// A task in the plugin's runtime: every [`POLL`], read the mailbox while
/// `advertise_evidence_requests` is on.
pub fn spawn(
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    self_peer: crate::self_peer::SelfPeer,
) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(POLL);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            if !crate::commitment::Policy::current().advertise_evidence_requests {
                lock(&STATUS).clear();
                continue;
            }
            let Some(dir) = capsules.ledger_dir().parent().map(Path::to_path_buf) else {
                continue;
            };
            let Ok(Some(route)) = crate::nostr_announce::route(&dir, true) else {
                continue;
            };
            let Ok(key) = crate::nostr_announce::mailbox_key(&dir) else {
                continue;
            };
            let now = chrono::Utc::now().timestamp();
            let own = self_peer.learned();
            round(&dir, &key, &route.relays, now, |octets| {
                crate::mesh_evidence_bridge::answer_in_process(
                    capsules.clone(),
                    octets,
                    own.clone(),
                )
            })
            .await;
        }
    });
}

#[cfg(test)]
mod tests;
