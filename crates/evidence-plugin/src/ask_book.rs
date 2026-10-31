//! This node's book of asks (loop step 7, Ask): the record that it asked a
//! peer for evidence, sealed before the request is sent; the record of the
//! answer or refusal that came back; and the record that nothing did, once
//! the waiting window closed.
//!
//! **The rules are evidencebook's** (`evidencebook::ask`, the Go book's
//! `Request`, `RecordResponse` and `RecordAbsence`): the record kinds
//! (`evidence_request`, `evidence_response`, `recorded_absence`), their
//! statements, and [`evidencebook::ask::record_absence`] itself, which
//! refuses an absence while the request is pending and once any outcome is
//! recorded. This module is the [`Book`] the crate seals through: each
//! record is a local record of this node's ledger whose one block,
//! [`BLOCK`], holds the crate's entry and its commit time. The crate sees
//! the book as these records alone, in ledger order.
//!
//! **What the request record holds.** The request exactly as transmitted,
//! signed (`requester_auth`), so its JCS digest is the digest of the bytes
//! on the wire (`mesh_evidence_bridge::send_evidence_request` sends those
//! bytes). It names the peer asked (`audience`, `responder_ref`) in clear,
//! so none of these records ever leaves this node in an answer
//! (`evidence_log`'s `never_leaves`).
//!
//! **The window.** It closes at the later of the request's own `deadline`
//! and the crate's minimum
//! ([`evidencebook::ask::MINIMUM_ABSENCE_WINDOW_SECONDS`]) after the request
//! was recorded ([`window_closes`]), read from the record alone. Until then the request is pending and
//! nothing is recorded for it. A reply read inside the window is recorded
//! as a response; none by the close is recorded as an absence. The stream
//! is closed at the window's end, so a later reply is never read, and the
//! crate refuses a second outcome for a request: an absence is never
//! converted into an answer (ER "The Three-State Discipline").
//!
//! **A node that stopped inside a window** closes it when it starts again
//! ([`resume_asks`]): the request record is all it needs.
//!
//! **Where a reply is kept.** The reply's bytes, exactly as read, are kept
//! in [`REPLIES_DIR`] under the ledger directory, named by their SHA-256,
//! which the response record seals as `response_digest`; [`kept_reply`]
//! reads them back checked against it, for the owner's own composition.
//! They follow the ledger's lifecycle, and nothing serves them: like the
//! records of this book, they never leave this node in an answer.

use evidencebook::ask::{AskError, Book, Entry, SealError, Sealed};
use evidencebook::record::{record_types, EpistemicType, Link, LinkType};
use evidencebook::store::{Record, RecordSource};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::capsule_emit::CapsuleState;

/// The block of a local record that holds one entry of this book.
pub const BLOCK: &str = "evidence_book_entry";

/// The directory, under the ledger directory, that keeps each reply's bytes
/// as read, in a file named by their digest.
pub const REPLIES_DIR: &str = "ask-replies";

/// Whether a ledger record is one of this book's.
pub fn is_ask_record(record: &Value) -> bool {
    entry_block(record).is_some()
}

fn entry_block(record: &Value) -> Option<&Map<String, Value>> {
    record
        .pointer("/model_attestation/compute_attestation")?
        .get(BLOCK)?
        .as_object()
}

/// The book over this node's ledger, as the crate reads and seals it:
/// every record of this book, in ledger order, as `(record id, header)`.
struct AskBook<'a> {
    capsules: &'a CapsuleState,
    now: String,
    records: Vec<(String, Map<String, Value>)>,
}

impl<'a> AskBook<'a> {
    fn open(capsules: &'a CapsuleState, now: &str) -> Self {
        Self {
            capsules,
            now: now.to_string(),
            records: entries(capsules.ledger_dir()),
        }
    }

    fn record(&self, leaf_index: usize) -> Option<Record> {
        let (id, header) = self.records.get(leaf_index)?;
        Some(Record {
            leaf_index: leaf_index as u64,
            digest: id.clone(),
            body: serde_json::to_vec(header).ok()?,
        })
    }

    fn header(&self, record_id: &str) -> Option<&Map<String, Value>> {
        self.records
            .iter()
            .find(|(id, _)| id == record_id)
            .map(|(_, header)| header)
    }

    /// Whether a response or an absence citing `request_record_id` is
    /// recorded: the crate's own test, which [`record_response`] applies
    /// before it seals as the Go book's `RecordResponse` does.
    fn outcome_recorded(&self, request_record_id: &str) -> bool {
        self.records.iter().any(|(_, header)| {
            matches!(
                header.get("record_type").and_then(Value::as_str),
                Some(record_types::RESPONSE | record_types::RECORDED_ABSENCE)
            ) && cites(header, request_record_id)
        })
    }
}

/// Every record of this book on the ledger at `ledger_dir`, in ledger
/// order, as `(record id, header)`.
pub(crate) fn entries(ledger_dir: &std::path::Path) -> Vec<(String, Map<String, Value>)> {
    crate::evidence_panes::read_capsule_records(ledger_dir)
        .iter()
        .filter_map(|record| {
            let id = record.get("capsule_id")?.as_str()?.to_string();
            Some((id, entry_block(record)?.clone()))
        })
        .collect()
}

/// Whether the entry `header` cites `record_id`: how a response or an
/// absence names the request it is the outcome of.
pub(crate) fn cites(header: &Map<String, Value>, record_id: &str) -> bool {
    header
        .get("links")
        .and_then(Value::as_array)
        .is_some_and(|links| {
            links.iter().any(|l| {
                l.get("type").and_then(Value::as_str) == Some(LinkType::Cites.as_str())
                    && l.get("target").and_then(Value::as_str) == Some(record_id)
            })
        })
}

impl RecordSource for AskBook<'_> {
    fn record_by_digest(&self, digest: &str) -> Option<Record> {
        let leaf = self.records.iter().position(|(id, _)| id == digest)?;
        self.record(leaf)
    }
    fn record_at(&self, leaf_index: u64) -> Option<Record> {
        self.record(usize::try_from(leaf_index).ok()?)
    }
    fn correlation(&self, _id: &str) -> Vec<u64> {
        Vec::new()
    }
    fn citing(&self, _half_digest: &str) -> Vec<u64> {
        Vec::new()
    }
    fn header_of(&self, record: &Record) -> Option<Map<String, Value>> {
        serde_json::from_slice(&record.body).ok()
    }
}

impl Book for AskBook<'_> {
    fn len(&self) -> u64 {
        self.records.len() as u64
    }
    fn now(&self) -> String {
        self.now.clone()
    }
    fn seal(&mut self, entry: &Entry) -> Result<Sealed, SealError> {
        let header = header(entry, &self.now);
        let emitted = self
            .capsules
            .emit_ask_record(header.clone())
            .map_err(|e| SealError(e.to_string()))?;
        self.records.push((emitted.capsule_id.clone(), header));
        Ok(Sealed {
            record_id: emitted.capsule_id,
            committed_at: self.now.clone(),
        })
    }
    /// The checkpoint cadence cuts this ledger's checkpoints.
    fn checkpoint(&mut self) -> Result<(), SealError> {
        Ok(())
    }
}

/// The header members the crate reads back (`record_type`, `links`,
/// `statement`, `committed_at`), plus the entry's epistemic type.
fn header(entry: &Entry, committed_at: &str) -> Map<String, Value> {
    let links: Vec<Value> = entry
        .links
        .iter()
        .map(|l| json!({"type": l.link_type.as_str(), "target": l.target}))
        .collect();
    let mut header = Map::new();
    header.insert("record_type".into(), json!(entry.record_type));
    header.insert(
        "epistemic_type".into(),
        json!(entry.epistemic_type.as_str()),
    );
    header.insert("links".into(), Value::Array(links));
    header.insert("statement".into(), entry.statement.clone());
    header.insert("committed_at".into(), json!(committed_at));
    header
}

/// The record of having asked, and when its waiting window closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    pub record_id: String,
    /// RFC 3339 UTC.
    pub window_closes: String,
}

/// Seal `request`, exactly as it will be transmitted to `responder`, as an
/// `evidence_request` record (the statement `ask::request` seals:
/// `request` and `responder_ref`, plus the `commitment` held for the
/// responder, if any). `now` is whole-second RFC 3339 UTC.
///
/// Refused, with nothing sealed, as `ask::request` refuses: a request this
/// node would not read as well formed, or one reusing a nonce an earlier
/// request in this book carried (a response to that one could otherwise be
/// replayed onto it). A request the book could not later resolve is never
/// recorded, so every recorded request reaches an outcome.
pub fn record_request(
    capsules: &CapsuleState,
    request: &Value,
    responder: &str,
    commitment: Option<Value>,
    now: &str,
) -> Result<Asked, AskError> {
    let mut book = AskBook::open(capsules, now);
    check_request(&book, request)?;
    let window_closes = window_closes(request.get("deadline").and_then(Value::as_str), now)
        .ok_or_else(|| {
            AskError::Invalid("the request's deadline is not an RFC 3339 time".into())
        })?;
    let mut statement = Map::new();
    statement.insert("request".into(), request.clone());
    if !responder.is_empty() {
        statement.insert("responder_ref".into(), json!(responder));
    }
    // The commitment held for the responder (`crate::peer_commitments`),
    // which a refusal is later checked against.
    if let Some(commitment) = commitment {
        statement.insert("commitment".into(), commitment);
    }
    let sealed = book.seal(&Entry {
        record_type: record_types::REQUEST.into(),
        epistemic_type: EpistemicType::ObservedEvent,
        links: Vec::new(),
        statement: Value::Object(statement),
    })?;
    Ok(Asked {
        record_id: sealed.record_id,
        window_closes,
    })
}

/// The checks `evidencebook::ask::request` makes before it records a
/// request (its `parse_request` and nonce scan, which the crate keeps
/// private): the reader the responder uses, a derivation that is a token
/// `name/N` or a digest, and a nonce no earlier request here carried.
fn check_request(book: &AskBook<'_>, request: &Value) -> Result<(), AskError> {
    let bytes = evidence_request::jcs::to_string(request)
        .map_err(|e| AskError::Invalid(format!("request: {e}")))?;
    evidence_request::request::parse_json(bytes.as_bytes())
        .map_err(|e| AskError::Invalid(format!("request: {e}")))?;
    if let Some(derivation) = request.get("derivation").and_then(Value::as_str) {
        if !derivation_is_well_formed(derivation) {
            return Err(AskError::Invalid(format!(
                "request: derivation {derivation:?} is neither a token name/N nor a digest"
            )));
        }
    }
    let Some(nonce) = request.get("nonce").and_then(Value::as_str) else {
        return Ok(());
    };
    let reused = book.records.iter().any(|(_, h)| {
        h.get("record_type") == Some(&json!(record_types::REQUEST))
            && h.get("statement").and_then(|s| s.pointer("/request/nonce")) == Some(&json!(nonce))
    });
    if reused {
        return Err(AskError::Invalid(format!(
            "nonce {nonce:?} was already used by a request in this book"
        )));
    }
    Ok(())
}

/// Go's `ValidDerivation` (profile §5.2), as `evidencebook::ask` checks it.
fn derivation_is_well_formed(text: &str) -> bool {
    let digest = text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    digest
        || text.split_once('/').is_some_and(|(name, version)| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
                && !version.is_empty()
                && version.bytes().all(|b| b.is_ascii_digit())
        })
}

/// When the waiting window of a request recorded at `committed_at` closes:
/// the later of its `deadline` and the crate's minimum after `committed_at`,
/// in whole seconds, rounded up. It depends on the record alone, so a node
/// that restarts reads the same close. `None` when a time does not parse.
pub fn window_closes(deadline: Option<&str>, committed_at: &str) -> Option<String> {
    let parse = |t: &str| chrono::DateTime::parse_from_rfc3339(t).ok();
    let after = parse(committed_at)?.to_utc()
        + chrono::Duration::seconds(evidencebook::ask::MINIMUM_ABSENCE_WINDOW_SECONDS);
    let ceil = |t: chrono::DateTime<chrono::Utc>| {
        let whole = t.timestamp() + i64::from(t.timestamp_subsec_nanos() > 0);
        chrono::DateTime::from_timestamp(whole, 0)
    };
    let mut closes = ceil(after)?;
    if let Some(deadline) = deadline {
        closes = closes.max(ceil(parse(deadline)?.to_utc())?);
    }
    Some(closes.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// The outcome a reply is recorded as: the request draft's `artifact` and
/// `refusal` when it verified (or was not checked, which `verification`
/// says), and the received-and-failed sub-states the Go book names when it
/// failed. Never an absence.
fn outcome(answer: &Value, verification: &Value) -> &'static str {
    let refusal_shaped = answer.get("reason").is_some() && answer.get("artifact").is_none();
    match verification.get("state").and_then(Value::as_str) {
        Some("artifact") => "artifact",
        Some("refusal") => "refusal",
        Some("not_evidence") if refusal_shaped => "refusal_nonconformant",
        Some("not_evidence") => "artifact_verification_failed",
        _ if refusal_shaped => "refusal",
        _ => "artifact",
    }
}

/// Seal the reply that came back inside the window for the request
/// recorded as `request_record_id` as an `evidence_response` record citing
/// it: its outcome, the request's digest, the digest of the reply's bytes
/// (`response_digest`) and what checking it found, which for a signed
/// refusal includes its check against the commitment the request recorded
/// (`peer_commitments::policy_check`). The bytes are kept first
/// ([`REPLIES_DIR`]), so a sealed digest always has its bytes. Returns the
/// record and that verification. Refused once an outcome is recorded for
/// the request, so a reply never replaces an absence (or another reply).
pub fn record_response(
    capsules: &CapsuleState,
    request_record_id: &str,
    request_digest: &str,
    reply: &[u8],
    verification: &Value,
    now: &str,
) -> Result<(Sealed, Value), AskError> {
    let answer: Value = serde_json::from_slice(reply)
        .map_err(|e| AskError::Invalid(format!("the reply is not JSON: {e}")))?;
    let mut book = AskBook::open(capsules, now);
    let Some(statement) = book
        .header(request_record_id)
        .filter(|h| h.get("record_type") == Some(&json!(record_types::REQUEST)))
        .and_then(|h| h.get("statement"))
        .cloned()
    else {
        return Err(AskError::NotFound(format!(
            "{request_record_id} is not a request this book recorded"
        )));
    };
    if book.outcome_recorded(request_record_id) {
        return Err(AskError::Invalid(format!(
            "an outcome is already recorded for request {request_digest}"
        )));
    }
    let mut verification = verification.clone();
    if verification.get("state").and_then(Value::as_str) == Some("refusal") {
        let reason = verification["reason"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        verification["policy_check"] = crate::peer_commitments::policy_check(
            statement.get("commitment"),
            &statement["request"],
            &reason,
        );
    }
    let response_digest = hex::encode(Sha256::digest(reply));
    keep_reply(capsules.ledger_dir(), &response_digest, reply)
        .map_err(|e| SealError(format!("the reply's bytes could not be kept: {e}")))?;
    let sealed = book.seal(&Entry {
        record_type: record_types::RESPONSE.into(),
        epistemic_type: EpistemicType::ObservedEvent,
        links: vec![Link {
            link_type: LinkType::Cites,
            target: request_record_id.to_string(),
        }],
        statement: json!({
            "outcome": outcome(&answer, &verification),
            "request_digest": request_digest,
            "response_digest": response_digest,
            "verification": verification,
        }),
    })?;
    Ok((sealed, verification))
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Keep `reply` as `REPLIES_DIR/<digest>`, durably, before its digest is
/// sealed. Written to a temporary file of this call's own, then published
/// with a hard link, which never replaces a file already there, so replies
/// with identical bytes settled at once never expose a partial file (as
/// `agreement::Store::put`). The file is never removed: if the seal then
/// fails it is unreferenced, and another record may rely on the same bytes.
fn keep_reply(ledger_dir: &Path, digest: &str, reply: &[u8]) -> std::io::Result<()> {
    let dir = ledger_dir.join(REPLIES_DIR);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(digest);
    // Already kept (by another record, or a call still syncing): only the
    // directory sync below is left, so the link is durable either way.
    if !path.exists() {
        let tmp = dir.join(format!(
            ".{digest}.{}.{}.tmp",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let published = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            file.write_all(reply)?;
            file.sync_all()?;
            match std::fs::hard_link(&tmp, &path) {
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
                _ => Ok(()),
            }
        })();
        let _ = std::fs::remove_file(&tmp);
        published?;
    }
    // The link itself is durable before the record that relies on it.
    std::fs::File::open(&dir)?.sync_all()
}

/// The reply recorded by the `evidence_response` record
/// `response_record_id` of this node's ledger, as its exact bytes, checked
/// against the `response_digest` the record sealed: what the owner's own
/// composition carries. Refused, naming the record, when it is no response
/// record here (`NotFound`), when it was sealed before replies were kept
/// and so has no digest (`Invalid`), or when the kept bytes are missing or
/// are not the ones sealed (`Corrupt`). The payer's composition (#196)
/// is its first caller.
#[cfg_attr(not(test), allow(dead_code))]
pub fn kept_reply(ledger_dir: &Path, response_record_id: &str) -> Result<Vec<u8>, AskError> {
    let header = crate::evidence_panes::read_capsule_records(ledger_dir)
        .into_iter()
        .filter(|record| {
            record.get("capsule_id").and_then(Value::as_str) == Some(response_record_id)
        })
        .find_map(|record| entry_block(&record).cloned())
        .filter(|h| h.get("record_type") == Some(&json!(record_types::RESPONSE)))
        .ok_or_else(|| {
            AskError::NotFound(format!(
                "{response_record_id} is not a response this book recorded"
            ))
        })?;
    let Some(digest) = header
        .get("statement")
        .and_then(|s| s.get("response_digest"))
        .and_then(Value::as_str)
        .filter(|d| evidence_request::registry::is_digest(d))
    else {
        return Err(AskError::Invalid(format!(
            "response {response_record_id} was recorded before replies were kept: it seals no response_digest"
        )));
    };
    let bytes = std::fs::read(ledger_dir.join(REPLIES_DIR).join(digest)).map_err(|e| {
        AskError::Corrupt(format!(
            "the reply recorded by response {response_record_id} is not kept: {e}"
        ))
    })?;
    if hex::encode(Sha256::digest(&bytes)) != digest {
        return Err(AskError::Corrupt(format!(
            "the bytes kept for response {response_record_id} are not the reply it sealed"
        )));
    }
    Ok(bytes)
}

/// Seal `recorded_absence` for the request recorded as `request_record_id`,
/// its window having closed at `window_closes`: evidencebook's
/// `record_absence`, which refuses while the request is pending and once an
/// outcome is recorded.
pub fn record_absence(
    capsules: &CapsuleState,
    request_record_id: &str,
    window_closes: &str,
    now: &str,
) -> Result<Sealed, AskError> {
    let mut book = AskBook::open(capsules, now);
    evidencebook::ask::record_absence(&mut book, request_record_id, window_closes, "")
}

/// At start, for every recorded request with no outcome: seal its
/// `recorded_absence` when its window has closed by `now`, and return the
/// rest, whose window is still open, for the caller to close
/// (`mesh_evidence_bridge::absence_when_window_closes`). The stream each
/// was sent on ended with the process that sent it, so no reply can arrive
/// for any of them. Returns how many were sealed; one that cannot be is
/// logged and left pending.
pub fn resume_asks(capsules: &CapsuleState, now: &str) -> (usize, Vec<Asked>) {
    let mut book = AskBook::open(capsules, now);
    let Some(now_t) = chrono::DateTime::parse_from_rfc3339(now).ok() else {
        return (0, Vec::new());
    };
    let (overdue, open): (Vec<Asked>, Vec<Asked>) = book
        .records
        .iter()
        .filter(|(_, h)| h.get("record_type") == Some(&json!(record_types::REQUEST)))
        .filter(|(id, _)| !book.outcome_recorded(id))
        .filter_map(|(id, h)| {
            let committed_at = h.get("committed_at")?.as_str()?;
            let deadline = h
                .get("statement")
                .and_then(|s| s.pointer("/request/deadline"))
                .and_then(Value::as_str);
            Some(Asked {
                record_id: id.clone(),
                window_closes: window_closes(deadline, committed_at)?,
            })
        })
        .partition(|asked| {
            chrono::DateTime::parse_from_rfc3339(&asked.window_closes)
                .is_ok_and(|closes| closes <= now_t)
        });
    let mut sealed = 0;
    for asked in overdue {
        match evidencebook::ask::record_absence(
            &mut book,
            &asked.record_id,
            &asked.window_closes,
            "",
        ) {
            Ok(_) => sealed += 1,
            Err(error) => {
                tracing::warn!(%error, request_record = %asked.record_id, "an overdue absence could not be sealed");
            }
        }
    }
    (sealed, open)
}

#[cfg(test)]
mod tests;
