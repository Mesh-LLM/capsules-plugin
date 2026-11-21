//! The commitments this node holds for its peers (loop step 7, Ask,
//! acceptance item 4): the last one `mesh_commitment_fetch` fetched from
//! each peer that passed every check, so an ask can be judged against what
//! the peer advertised. A refusal carries no policy digest; what is checked
//! is the refusal against the policy the peer's commitment pins (Sherlock2,
//! Mesh-LLM/capsules-plugin#56).
//!
//! **Where.** `<data_dir>/`[`DIR`]`/<peer id>.json`, the frame as fetched
//! (`commitment::Signed::to_wire`). A later passing fetch replaces it. It is
//! never served.
//!
//! **What an ask records** ([`pinned`]): the digest of the held commitment
//! (SHA-256 of its JCS), the policy digest it pins and that policy's body,
//! in the `evidence_request` record (`crate::ask_book`), so a later fetch
//! never changes what the ask is judged against.
//!
//! **The check** ([`policy_check`]) on a signed refusal:
//! - `NOT_CHECKED` when no commitment was held at ask time;
//! - `MATCH` when the pinned policy allows the refusal: its reason blames
//!   the request, or the commitment does not answer the subject form;
//! - `MISMATCH` when the policy answers it to a stranger (`stranger_safe`)
//!   and the refusal withholds it (`derivation_unsupported`,
//!   `no_such_subject`);
//! - `MATCH` for a policy refusal under `evidence-interop/1` of record bodies
//!   the policy gives no one (`range` and `full_history`, or any record-body
//!   subject while `share_history_segments` is `off`);
//! - `NOT_CHECKED` otherwise: a `policy_declined` or `not_authorized`, which
//!   honest responders also send for load, size and signature limits, or an
//!   answer that depends on who asks, which the policy alone does not
//!   settle.

use std::path::{Path, PathBuf};

use evidence_request::registry::Reason;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::commitment::{self, Signed};

/// The directory under the data directory.
pub const DIR: &str = "peer-commitments";

/// The refusal reasons that can only mean the peer withheld what the policy
/// may promise: a derivation not offered, or a subject said not to exist.
/// `policy_declined` and `not_authorized` are not among them: an honest
/// responder also sends them for reasons no policy promises past. It sends
/// `policy_declined` for load and size limits (a full stranger pool, too
/// many checkpoints, an answer too large) and `not_authorized` when a
/// signed request fails a check (its audience before the responder knows
/// its own id, a deadline too far ahead, a full replay cache). So both read
/// `NOT_CHECKED`. The rest (`request_malformed`, `deadline_unmet`,
/// `coverage_unsatisfiable`, `retention_expired`) blame the request and
/// read `MATCH`.
///
/// That is the reading of a refusal to an `evidence-interop/0` request.
/// Under `evidence-interop/1` (IP v1 §6.3, ER -02) a responder declines for
/// its own load or limits with `capacity_exceeded` and refuses a requester
/// authentication that does not verify with `request_unauthenticated`, so
/// `policy_declined` and `not_authorized` are statements about policy and
/// are judged against the pinned policy like the reasons above.
/// `capacity_exceeded` reads `NOT_CHECKED` (no policy promises past a limit)
/// and `request_unauthenticated` blames the request.
const WITHHOLDING_REASONS: [Reason; 2] = [Reason::DerivationUnsupported, Reason::NoSuchSubject];

/// Refusal reasons the wire cannot tell apart from an honest limit under
/// `evidence-interop/0`; policy only under /1.
const AMBIGUOUS_REASONS: [Reason; 2] = [Reason::PolicyDeclined, Reason::NotAuthorized];

fn path(data_dir: &Path, peer_id: &str) -> Option<PathBuf> {
    // A mesh id is lowercase hex: nothing else names a file here.
    (!peer_id.is_empty()
        && peer_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    .then(|| data_dir.join(DIR).join(format!("{peer_id}.json")))
}

/// Hold `frame`, a commitment fetched from `peer_id` that passed every
/// check, in place of any held before.
pub fn hold(data_dir: &Path, peer_id: &str, frame: &Value) -> std::io::Result<()> {
    let path = path(data_dir, peer_id).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a mesh peer id")
    })?;
    std::fs::create_dir_all(path.parent().expect("under DIR"))?;
    // One temporary file per write, so two fetches of one peer at once
    // never write into each other's file; the rename publishes one whole.
    let tmp = path.with_extension(format!(
        "json.{}.tmp",
        crate::producer::capsule::fresh_store_nonce()
    ));
    std::fs::write(&tmp, serde_json::to_vec(frame)?)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// What an ask of `peer_id` records of the commitment held for it:
/// `{digest, policy_digest, policy, subjects}`. `None` when none is held, or
/// the held one no longer checks or names another node.
pub fn pinned(data_dir: &Path, peer_id: &str) -> Option<Value> {
    let bytes = std::fs::read(path(data_dir, peer_id)?).ok()?;
    let signed = Signed::from_wire(&serde_json::from_slice(&bytes).ok()?).ok()?;
    if !commitment::verify(&signed).is_empty() || signed.commitment["node_id"] != peer_id {
        return None;
    }
    let policy: Value = serde_json::from_slice(&signed.policy).ok()?;
    Some(json!({
        "digest": hex::encode(Sha256::digest(evidence_request::jcs::to_string(&signed.commitment).ok()?)),
        "policy_digest": signed.commitment.pointer("/lcap/policy_digest")?,
        "policy": policy.get("policy")?,
        "subjects": signed.commitment.pointer("/answers/subjects")?,
    }))
}

/// The check of a signed refusal of `request` for `reason` against the
/// commitment `pinned` at ask time (see the module doc).
pub fn policy_check(pinned: Option<&Value>, request: &Value, reason: &str) -> Value {
    let Some(pinned) = pinned else {
        return json!({"status": "NOT_CHECKED", "why": "no commitment held for the peer"});
    };
    let status = |status: &str, why: &str| json!({"status": status, "why": why, "policy_digest": pinned["policy_digest"]});
    let v1 = request.get("profile").and_then(Value::as_str)
        == Some(evidence_request::envelope::PROFILE_V1);
    // A request over the responder's size limit is refused before its
    // profile is read, so with /0's tokens (`evidence_answer`): its
    // `policy_declined` is that limit, not policy.
    let oversize = evidence_request::jcs::to_string(request).map_or(true, |text| {
        text.len() > crate::evidence_answer::MAX_REQUEST_BYTES
    });
    let v1 = v1 && !oversize;
    let ambiguous = AMBIGUOUS_REASONS.iter().any(|r| r.token() == reason);
    if reason == Reason::CapacityExceeded.token() {
        return status(
            "NOT_CHECKED",
            "the responder states a limit of its own, which no policy promises past",
        );
    }
    if ambiguous && !v1 {
        return status(
            "NOT_CHECKED",
            "an honest responder also sends this reason for limits no policy promises past",
        );
    }
    let withholds = ambiguous || WITHHOLDING_REASONS.iter().any(|r| r.token() == reason);
    if !withholds {
        return status("MATCH", "the refusal blames the request");
    }
    let Some(form) = subject_form(request) else {
        return status("NOT_CHECKED", "the request names no subject form");
    };
    let answered = pinned["subjects"]
        .as_array()
        .is_some_and(|s| s.iter().any(|f| f == form));
    if !answered {
        return status("MATCH", "the commitment does not answer this subject form");
    }
    let stranger_safe = pinned
        .pointer("/policy/stranger_safe")
        .and_then(Value::as_array)
        .is_some_and(|safe| {
            // `history_card/1` is answered over `full_history` or
            // `checkpoints` alike (`evidence_log`'s derivation forms).
            let asked = match request.get("derivation").and_then(Value::as_str) {
                Some(derivation) if matches!(form, "full_history" | "checkpoints") => derivation,
                None if matches!(form, "checkpoints" | "checkpoint_range") => form,
                _ => return false,
            };
            safe.iter().any(|s| s == asked)
        });
    if stranger_safe {
        return status(
            "MISMATCH",
            "the pinned policy answers this to any asker, and the refusal withholds it by policy",
        );
    }
    if ambiguous && answered_to_no_one(pinned, request, form) {
        return status(
            "MATCH",
            "the pinned policy answers record bodies of this subject to no one",
        );
    }
    status(
        "NOT_CHECKED",
        "whether this is answered depends on who asks",
    )
}

/// Whether the pinned policy gives `request`'s record bodies to no asker,
/// so a policy refusal of it is what the policy says for everyone (#172):
/// `range` and `full_history` with no derivation, under every setting (the
/// evidencebook#114 ruling, as `evidence_answer` applies it), and every
/// record-body subject while `share_history_segments` is `off`. A
/// derivation is answered by its own rules, so it is never one of these.
fn answered_to_no_one(pinned: &Value, request: &Value, form: &str) -> bool {
    if request.get("derivation").is_some() {
        return false;
    }
    let segments = pinned
        .pointer(&format!(
            "/policy/{}",
            crate::share_policy::HISTORY_SEGMENTS_KEY
        ))
        .and_then(Value::as_str);
    match form {
        "range" | "full_history" => true,
        "record" | "exchange" | "correlation" => segments == Some("off"),
        _ => false,
    }
}

/// The request's subject form token (`full_history`, `checkpoints`, ...).
fn subject_form(request: &Value) -> Option<&str> {
    let subject = request.get("subject")?.as_object()?;
    (subject.len() == 1)
        .then(|| subject.keys().next().map(String::as_str))
        .flatten()
}

#[cfg(test)]
mod tests;
