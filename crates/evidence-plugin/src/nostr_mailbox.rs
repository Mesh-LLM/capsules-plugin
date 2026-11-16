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

/// The most request events read from one relay in one page.
const LIMIT: usize = 64;

/// The most pages (each older than the last) read from one relay in a round.
const PAGES: usize = 4;

/// The most bytes of events one page holds; a relay that sends more is cut off.
const PAGE_BYTES: usize = 8 * 1024 * 1024;

/// The most tags a request event may carry.
const MAX_TAGS: usize = 16;

/// A request event stamped more than this many seconds ahead of this node's
/// clock is not answered: its stamp would keep its id in [`ANSWERED_FILE`].
const SKEW: i64 = 60;

/// The most ids [`ANSWERED_FILE`] holds. Past it no new request is answered
/// until older ones expire (after twice [`LOOKBACK`]): an id dropped early
/// would be answered again when its event is delivered again.
const MAX_ANSWERED: usize = 2048;

/// A round stops starting new work after this long, so one slow relay cannot
/// hold the others past the commitment's `answers_within`.
const BUDGET: Duration = Duration::from_secs(40);

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
    // Before anything is copied or hashed.
    if raw["content"]
        .as_str()
        .is_some_and(|c| c.len() > MAX_CONTENT)
    {
        return Err("the content is too large".into());
    }
    let (id, pubkey, sig, content) = (text("id")?, text("pubkey")?, text("sig")?, text("content")?);
    let created_at = raw["created_at"].as_i64().ok_or("no created_at")?;
    let kind = raw["kind"].as_u64().ok_or("no kind")?;
    let mut tags = Vec::new();
    if raw["tags"].as_array().ok_or("no tags")?.len() > MAX_TAGS {
        return Err("too many tags".into());
    }
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
pub fn fetch(url: &str, filter: &Value) -> Result<(Vec<Value>, bool), String> {
    let started = Instant::now();
    let (mut socket, timer) = connect(url)?;
    let sub = "mailbox";
    socket
        .send(tungstenite::Message::text(
            json!(["REQ", sub, filter]).to_string(),
        ))
        .map_err(|e| format!("could not send: {e}"))?;
    let mut events = Vec::new();
    let mut bytes = 0;
    // Whether the page was cut short by its count or its bytes, so an older
    // page may hold more.
    let mut more = false;
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
                bytes += text.len();
                if let Some(event) = parts.get(2) {
                    events.push(event.clone());
                }
                if events.len() >= LIMIT || bytes >= PAGE_BYTES {
                    more = true;
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
    outcome.map(|()| (events, more))
}

// ---------------------------------------------------------------------
// Which request events were answered
// ---------------------------------------------------------------------

/// The request event ids answered, read from [`ANSWERED_FILE`] in `dir`;
/// those older than twice [`LOOKBACK`] are dropped, since [`round`] no longer
/// reads them.
/// A file that exists and cannot be read is an error, never an empty set: an
/// empty set would answer everything again.
pub fn answered(dir: &Path, now: i64) -> Result<BTreeMap<String, i64>, String> {
    let text = match std::fs::read_to_string(dir.join(ANSWERED_FILE)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("{ANSWERED_FILE} could not be read: {e}")),
    };
    Ok(text
        .lines()
        .filter_map(|line| {
            let (id, at) = line.split_once(' ')?;
            Some((id.to_string(), at.parse::<i64>().ok()?))
        })
        .filter(|(_, at)| *at > now - 2 * LOOKBACK)
        .collect())
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

/// Where the next round starts among the relays.
static START: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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

/// The request events `url` holds for `mailbox_key`, newest first, in pages
/// of [`LIMIT`] each older than the last, at most [`PAGES`] of them: a relay
/// that always returns the same newest page cannot hide an older request.
fn read_pages(
    url: &str,
    mailbox_key: &str,
    now: i64,
    keep_going: impl Fn() -> bool,
) -> Result<Vec<Value>, String> {
    let mut all: Vec<Value> = Vec::new();
    let mut until: Option<i64> = None;
    for _ in 0..PAGES {
        if !keep_going() {
            break;
        }
        let mut filter = json!({
            "kinds": [REQUEST_KIND],
            "#p": [mailbox_key],
            "since": now - LOOKBACK,
            "limit": LIMIT,
        });
        if let Some(until) = until {
            filter["until"] = json!(until);
        }
        let (page, full) = fetch(url, &filter)?;
        let oldest = page.iter().filter_map(|e| e["created_at"].as_i64()).min();
        all.extend(page);
        match (full, oldest) {
            // The next page starts at the oldest stamp seen (`until` is
            // inclusive, so events sharing it are read again and skipped by
            // id). A page that did not get older steps one second back: more
            // than a page of requests in one second are not all read.
            (true, Some(at)) => until = Some(if until == Some(at) { at - 1 } else { at }),
            _ => break,
        }
    }
    Ok(all)
}

/// One read of the mailbox on every relay of `relays`. `answer` turns request
/// octets into the signed reply octets, or `None` when there is nothing to
/// sign; `active` says whether the switch is still on, and is asked before
/// each relay and each answer. Returns the request event ids answered.
pub async fn round<A, F>(
    dir: &Path,
    key: &SigningKey,
    relays: &[String],
    now: i64,
    active: impl Fn() -> bool + Send + Sync + 'static,
    answer: A,
) -> Vec<String>
where
    A: Fn(Vec<u8>) -> F,
    F: std::future::Future<Output = Option<Vec<u8>>>,
{
    let began = Instant::now();
    let mailbox_key = hex::encode(key.verifying_key().to_bytes());
    let mut done = match answered(dir, now) {
        Ok(done) => done,
        Err(why) => {
            // Answering without the record of what was answered could answer
            // a request twice.
            tracing::warn!(%why, "the mailbox is not read");
            return Vec::new();
        }
    };
    let mut answered_now = Vec::new();
    // Each round starts one relay further on, so a relay that eats the budget
    // cannot keep the ones after it from ever being read.
    let first = START.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let active = std::sync::Arc::new(active);
    let within = || active() && began.elapsed() <= BUDGET;
    for i in 0..relays.len() {
        let url = &relays[(first + i) % relays.len()];
        if !within() {
            break;
        }
        let read = {
            let (url, mailbox_key) = (url.clone(), mailbox_key.clone());
            let active = active.clone();
            let ok = move || active() && began.elapsed() <= BUDGET;
            tokio::task::spawn_blocking(move || read_pages(&url, &mailbox_key, now, ok))
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
            if !within() {
                break;
            }
            let Ok(request) = verify_event(&raw) else {
                continue;
            };
            // The relay is not trusted to filter by `since` or by `#p`; a
            // stamp ahead of this clock is not kept in the answered set.
            if done.contains_key(&request.id)
                || request.created_at < now - LOOKBACK
                || request.created_at > now + SKEW
            {
                continue;
            }
            let Some(octets) = request_octets(&request, &mailbox_key) else {
                continue;
            };
            if done.len() >= MAX_ANSWERED {
                tracing::warn!(
                    "the mailbox answered {MAX_ANSWERED} requests lately: no more until older ones expire"
                );
                break;
            }
            // Kept before the answer is built, so a crash between the two
            // never answers the request twice (NMB §6; the asker then records
            // an absence). If it cannot be kept, the request is not answered.
            done.insert(request.id.clone(), request.created_at);
            if let Err(e) = keep(dir, &done) {
                tracing::warn!(error = %e, "the answered request ids could not be kept");
                done.remove(&request.id);
                break;
            }
            let Some(reply) = answer(octets).await else {
                continue;
            };
            // The switch may have been turned off while the answer was built.
            if !within() {
                break;
            }
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

fn on() -> bool {
    crate::commitment::Policy::current().advertise_evidence_requests
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
            if !on() {
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
            lock(&STATUS).retain(|url, _| route.relays.contains(url));
            let now = chrono::Utc::now().timestamp();
            let own = self_peer.learned();
            round(&dir, &key, &route.relays, now, on, |octets| {
                crate::mesh_evidence_bridge::answer_in_process(
                    capsules.clone(),
                    octets,
                    own.clone(),
                    true,
                )
            })
            .await;
        }
    });
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod tests_support;
