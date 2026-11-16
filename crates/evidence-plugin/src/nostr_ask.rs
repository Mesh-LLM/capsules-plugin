//! Ask a node over the Nostr mailbox its commitment advertises (loop step 13,
//! Ask across; evidence-network/loop#443), per `nostr-mailbox-v0` (NMB) of
//! agent-action-capsule: the asking half of what `nostr_mailbox` answers.
//!
//! The tool `nostr_evidence_request` takes the asked node's `ask.nostr` route
//! (`mailbox_key` and `relays`, read from a commitment the caller trusts, NMB
//! §3, §4.3) and the responder's evidence key (`key_id`, the key its answers
//! are signed under), and:
//!
//! 1. seals the request in this node's book of asks (`ask_book`) as it will
//!    be sent, before anything is sent, with a `deadline` (`answers_within`
//!    from now unless the caller set one) and a `nonce` (NMB §6);
//! 2. signs a kind 4700 event with a carriage key made for this request only
//!    (NMB §8) and publishes it to every relay listed; at least one must
//!    accept it;
//! 3. reads kind 4701 events naming the request event (`#e`), and takes the
//!    first reply (NMB §4.2): one the mailbox key signed, or, from another
//!    key, one whose content proves itself under the responder's key
//!    (an envelope or refusal that verifies for this very request), at most
//!    [`BY_CONTENT_LIMIT`] of the latter checked;
//! 4. records it as the response, verified under the responder key, or, when
//!    the window closes with no reply, as the absence (`mesh_evidence_bridge`
//!    `settle_ask`, the one path the mesh ask takes). A reply after the close
//!    is never read, as on the mesh path.
//!
//! The request is not signed as this node (`requester_auth`): the mailbox
//! carries no requester authentication and a responder answers every asker
//! over it as a stranger (`nostr_mailbox`).

use std::time::Duration;

use base64::Engine as _;
use k256::schnorr::SigningKey;
use mesh_llm_plugin::{PluginContext, PluginError, PluginResult};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::nostr_announce::{is_xonly_key, relay_error, send_event, signed_event, Outcome};
use crate::nostr_mailbox::{fetch, verify_event, Event, MEDIA, REPLY_KIND, REQUEST_KIND};

/// The tool name a local client calls
/// (`POST /api/plugins/capsules/tools/nostr_evidence_request`).
pub const OPERATION: &str = "nostr_evidence_request";

/// The most relays one ask names.
const MAX_RELAYS: usize = 8;

/// The most replies by content (NMB §4.2) checked for one request.
pub const BY_CONTENT_LIMIT: usize = 4;

/// How often the replies are read.
const POLL: Duration = Duration::from_millis(if cfg!(test) { 100 } else { 2000 });

/// The `answers_within` a request without a `deadline` gets, seconds.
const DEFAULT_WINDOW: i64 = 60;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NostrEvidenceRequestArgs {
    /// The asked node's mailbox key (`ask.nostr.mailbox_key` of its commitment):
    /// 64 lowercase hex, BIP-340.
    pub mailbox_key: String,
    /// Its relays (`ask.nostr.relays`): `wss://host[:port][/path]`.
    pub relays: Vec<String>,
    /// The key its answers are signed under (its commitment's `key_id`,
    /// Ed25519, 64 lowercase hex).
    pub responder_key: String,
    /// The request map (draft-mih-agent-evidence-request), sealed and sent as
    /// given plus a `deadline` and a `nonce` when it carries none.
    pub request: Value,
    /// Check the reply under `responder_key` and return the check beside it.
    /// On unless the caller turns it off.
    #[serde(default = "verify_by_default")]
    pub verify: bool,
    /// A request is published on the relay for everyone to read (NMB §8).
    /// Only `checkpoints` and `history_card/1`, which a stranger is answered,
    /// go without this; any other subject (an exchange, a record, a
    /// history) needs the caller to say, here, that it publishes it. A
    /// request that carries a requester's identity (`requester_auth`,
    /// `requester_id`) is never sent.
    #[serde(default)]
    pub publish_subject: bool,
}

fn verify_by_default() -> bool {
    true
}

/// What `args` must be before anything is sealed, or why not.
fn check(args: &NostrEvidenceRequestArgs) -> Result<ed25519_dalek::VerifyingKey, String> {
    if !is_xonly_key(&args.mailbox_key) {
        return Err("mailbox_key is not 64 lowercase hex of a BIP-340 key".into());
    }
    if args.relays.is_empty() || args.relays.len() > MAX_RELAYS {
        return Err(format!("name between 1 and {MAX_RELAYS} relays"));
    }
    for url in &args.relays {
        // A local relay of a test is not `wss://`.
        if cfg!(test) && url.starts_with("ws://127.0.0.1:") {
            continue;
        }
        if let Some(why) = relay_error(url) {
            return Err(format!("relay {url} {why}"));
        }
    }
    let key = crate::mesh_evidence_bridge::verifying_key(&args.responder_key)
        .ok_or("responder_key is not 64 lowercase hex of an Ed25519 key")?;
    let Some(map) = args.request.as_object() else {
        return Err("request is not a map".into());
    };
    if let Some(name) = ["requester_auth", "requester_id"]
        .into_iter()
        .find(|name| map.contains_key(*name))
    {
        return Err(format!(
            "request carries {name}: a mailbox request is public and asks as a stranger"
        ));
    }
    let bytes =
        evidence_request::jcs::to_string(&args.request).map_err(|e| format!("request: {e}"))?;
    let parsed = evidence_request::request::parse_json(bytes.as_bytes())
        .map_err(|e| format!("request: {e}"))?;
    // The subject of a stranger-safe derivation is checked too: `history_card/1`
    // is answered over `checkpoints` and `full_history` only, so a record or a
    // correlation asked under it is no stranger's ask.
    let names_only_the_log = matches!(
        parsed.subject,
        evidence_request::request::Subject::Checkpoints
            | evidence_request::request::Subject::FullHistory
    );
    if !args.publish_subject
        && !(crate::evidence_answer::stranger_safe(&parsed) && names_only_the_log)
    {
        return Err(
            "this request's subject would be published on the relay and a stranger is refused \
             it: only checkpoints and history_card/1 go without publish_subject: true"
                .into(),
        );
    }
    Ok(key)
}

/// `request` with a `deadline` `window` seconds from `now` and a fresh
/// `nonce`, each only when it carries none.
fn prepared(request: &Value, now: chrono::DateTime<chrono::Utc>, window: i64) -> Value {
    let mut request = request.clone();
    let map = request.as_object_mut().expect("checked to be a map");
    map.entry("deadline").or_insert_with(|| {
        json!((now + chrono::Duration::seconds(window))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string())
    });
    map.entry("nonce").or_insert_with(|| {
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw).expect("the OS random source is available");
        json!(hex::encode(raw))
    });
    request
}

/// A signing key made for one request: the carriage key (NMB §3, §8).
fn carriage_key() -> SigningKey {
    loop {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).expect("the OS random source is available");
        if let Ok(key) = SigningKey::from_bytes(&raw) {
            return key;
        }
    }
}

/// The request event (NMB §4.1) for `octets`, signed by `key`, expiring when the
/// waiting window closes (`deadline`, unix seconds).
pub fn request_event(
    key: &SigningKey,
    mailbox_key: &str,
    octets: &[u8],
    deadline: i64,
    at: i64,
) -> Value {
    signed_event(
        key,
        REQUEST_KIND,
        json!([
            ["p", mailbox_key],
            ["m", MEDIA],
            ["expiration", deadline.to_string()]
        ]),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(octets),
        at,
    )
}

/// Whether `event` is a reply to `request_id` as NMB §4.2 checks 1 to 4 say:
/// kind, exactly one `e` naming it, exactly one `m` equal to [`MEDIA`], and
/// content that decodes. Its octets when so.
pub fn reply_octets(event: &Event, request_id: &str) -> Option<Vec<u8>> {
    if event.kind != REPLY_KIND
        || event.one_tag("e") != Some(request_id)
        || event.one_tag("m") != Some(MEDIA)
    {
        return None;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&event.content)
        .ok()
}

/// Publish `event` to every relay (all at once), true when at least one
/// accepted it (NMB §4.3).
async fn publish(relays: &[String], event: &Value) -> bool {
    let sends: Vec<_> = relays
        .iter()
        .map(|url| {
            let (url, event) = (url.clone(), event.clone());
            tokio::task::spawn_blocking(move || send_event(&url, &event))
        })
        .collect();
    let mut accepted = false;
    for send in sends {
        match send.await {
            Ok(Outcome::Accepted) => accepted = true,
            Ok(Outcome::Rejected(why) | Outcome::Unreachable(why)) => {
                tracing::warn!(%why, "a mailbox request was not accepted by a relay");
            }
            Err(e) => tracing::warn!(error = %e, "a mailbox publish failed"),
        }
    }
    accepted
}

/// Read the replies to `request_id` on every relay until one is taken
/// (NMB §4.2): a reply the mailbox key signed is taken as it is; one from any
/// other key is taken only when `proves` accepts its octets, and at most
/// [`BY_CONTENT_LIMIT`] of those are tried. `proves` is told the request's
/// bytes' answer under the responder key.
async fn wait_for_reply(
    relays: Vec<String>,
    mailbox_key: String,
    request_id: String,
    proves: impl Fn(&[u8]) -> bool,
) -> std::io::Result<Vec<u8>> {
    let mut by_content = 0usize;
    let mut tried: std::collections::BTreeSet<String> = Default::default();
    loop {
        // Every relay at once, and the mailbox key's own replies apart from
        // the rest (`authors`), so a relay that is slow, or newer events of
        // other keys, cannot hide the reply that counts (NMB §4.2).
        let mut reads = tokio::task::JoinSet::new();
        for url in &relays {
            for authors in [true, false] {
                let mut filter = json!({"kinds": [REPLY_KIND], "#e": [request_id], "limit": 64});
                if authors {
                    filter["authors"] = json!([mailbox_key]);
                }
                let to = url.clone();
                reads.spawn_blocking(move || fetch(&to, &filter));
            }
        }
        while let Some(read) = reads.join_next().await {
            let Ok(Ok((events, _))) = read else { continue };
            for raw in events {
                let Ok(event) = verify_event(&raw) else {
                    continue;
                };
                let Some(octets) = reply_octets(&event, &request_id) else {
                    continue;
                };
                if event.pubkey == mailbox_key {
                    return Ok(octets);
                }
                // Counted by the hash, so a redelivered event is counted once.
                if by_content < BY_CONTENT_LIMIT && tried.insert(event.id.clone()) {
                    by_content += 1;
                    if proves(&octets) {
                        return Ok(octets);
                    }
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

/// How long the caller waits for the outcome before hearing "pending": the
/// ask settles in the background either way.
fn caller_wait() -> Duration {
    crate::mesh_evidence_bridge::env_millis("CAPSULES_NOSTR_ASK_WAIT_MS", 30_000)
}

/// The `nostr_evidence_request` tool. Returns `{answer, request_digest,
/// verification}` as `mesh_evidence_request` does (minus its `held`, which only the mesh path records), or an error; an ask the
/// reply to which has not come yet is recorded as pending until its window
/// closes and sealed as the response or the absence then.
pub async fn handle_nostr_evidence_request(
    args: NostrEvidenceRequestArgs,
    _context: &mut PluginContext<'_>,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
) -> PluginResult<Value> {
    ask(args, capsules).await
}

/// [`handle_nostr_evidence_request`], apart from the plugin context it does
/// not use.
pub(crate) async fn ask(
    args: NostrEvidenceRequestArgs,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
) -> PluginResult<Value> {
    let responder = check(&args).map_err(PluginError::invalid_params)?;
    let now = chrono::Utc::now();
    let request = prepared(&args.request, now, DEFAULT_WINDOW);
    let sent = evidence_request::jcs::to_string(&request)
        .map_err(|e| PluginError::invalid_params(e.to_string()))?
        .into_bytes();
    let asked = crate::ask_book::record_request(
        &capsules,
        &request,
        &args.responder_key,
        None,
        &crate::evidence_answer::now_utc(),
    )
    .map_err(|e| {
        PluginError::internal(format!(
            "could not record the request, so it was not sent: {e}"
        ))
    })?;
    let closes_at =
        tokio::time::Instant::now() + crate::mesh_evidence_bridge::until(&asked.window_closes);
    let deadline = chrono::DateTime::parse_from_rfc3339(&asked.window_closes)
        .map_or(now.timestamp() + DEFAULT_WINDOW, |t| t.timestamp());
    let carriage = carriage_key();
    let event = request_event(
        &carriage,
        &args.mailbox_key,
        &sent,
        deadline,
        now.timestamp(),
    );
    let request_id = event["id"].as_str().unwrap_or_default().to_string();

    let witness_keys = crate::checkpoint_cadence::active_witness_keys();
    let verify = {
        let key = responder;
        move |sent: &[u8], answer: &Value| {
            crate::evidence_answer::verify_response(sent, answer, &key, &witness_keys)
        }
    };
    let exchange = {
        let (relays, mailbox_key, sent) =
            (args.relays.clone(), args.mailbox_key.clone(), sent.clone());
        let proves = {
            let verify = verify.clone();
            move |octets: &[u8]| {
                serde_json::from_slice::<Value>(octets).is_ok_and(|answer| {
                    matches!(
                        verify(&sent, &answer)["state"].as_str(),
                        Some("artifact" | "refusal")
                    )
                })
            }
        };
        async move {
            if !publish(&relays, &event).await {
                // Nothing was sent, so none will come: the window runs out.
                std::future::pending::<()>().await;
            }
            wait_for_reply(relays, mailbox_key, request_id, proves).await
        }
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let pending = asked.record_id.clone();
    let closes = asked.window_closes.clone();
    tokio::spawn(crate::mesh_evidence_bridge::settle_ask(
        capsules,
        asked,
        verify,
        sent.clone(),
        exchange,
        closes_at,
        tx,
    ));
    match tokio::time::timeout(caller_wait(), rx).await {
        Ok(Ok(Ok((answer, verification)))) => Ok(if args.verify {
            json!({
                "answer": answer,
                "request_digest": evidence_request::digest::request_digest(&sent),
                "verification": verification,
            })
        } else {
            answer
        }),
        Ok(Ok(Err(error))) => Err(PluginError::internal(format!("no answer: {error:?}"))),
        _ => Err(PluginError::internal(format!(
            "no answer yet: the ask is recorded as {pending} and is pending until {closes}"
        ))),
    }
}

#[cfg(test)]
mod tests;
