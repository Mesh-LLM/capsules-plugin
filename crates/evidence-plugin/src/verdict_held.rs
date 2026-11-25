//! `verdict_held/1`: whether this node holds a referee's verdict, asked by the
//! verdict's capsule id (Mesh-LLM/capsules-plugin#289; Steven u1598: the
//! verdicts held about a node are "checkable for omission by digest").
//!
//! A node's `service_history/2` counts the verdicts its own log holds. A node
//! that dropped a delivered verdict shows a smaller count, and nothing in the
//! count shows it. This derivation lets a referee, or any node that holds
//! the referee's signed delivery, ask: "do you hold verdict D?". Held: the
//! answer lists the record that holds it and its inclusion proof under the
//! anchor. Not held: the signed `no_such_subject` refusal, which the asker can
//! set beside the delivery it holds. It mirrors `exchange_corroboration/1`: the
//! subject is the existing `correlation` form (a 64-hex digest, here the
//! verdict's capsule id), the artifact carries ids, digests and a proof and
//! never a record body, the ruling, the referee or who asked, and it is the
//! same bytes for every requester at one anchor.
//!
//! What a refusal shows is the node's own signed statement. It is not proof
//! that the node never received the verdict: a delivery shows the verdict was
//! sent, not that it arrived (ISH §5.3), and what follows from a denial is
//! the asker's to judge.

use cll::checkpoint::{CheckpointRecord, DecodedCheckpointCose};
use cll::mmr::leaf_count;
use evidence_request::registry::is_digest;
use evidence_request::registry::{Reason, SubjectForm};
use evidence_request::request::{Derivation, Request, Subject};
use evidence_request::resolve::{self, Anchor};
use serde_json::{json, Map, Value};

use crate::evidence_log::LogView;

/// The definition document, as published beside this crate.
#[cfg(test)]
pub const DEFINITION_DOCUMENT: &str = include_str!("../../../derivations/verdict-held-1.json");

/// SHA-256 over the RFC 8785 bytes of the definition document: the
/// derivation's name on the wire. Pinned to the file by a test.
pub const DEFINITION_DIGEST: &str =
    "f457ecb2cd0089c83129365593d3d4f8cf1e52a99424d85d1041c042fc5e0418";

/// The members every entry carries, and nothing else.
const ENTRY_MEMBERS: [&str; 3] = ["inclusion", "record", "verdict"];

/// Whether `derivation` names this one.
pub fn is_derivation(derivation: Option<&Derivation>) -> bool {
    matches!(derivation, Some(Derivation::Digest(d)) if d == DEFINITION_DIGEST)
}

/// Resolution for this derivation: a correlation is held only when some
/// record of this node holds the verdict of that capsule id.
pub(crate) struct VerdictView<'a, 'b>(pub &'a LogView<'b>);

impl resolve::Responder for VerdictView<'_, '_> {
    fn holds_record(&self, digest: &str) -> bool {
        self.0.holds_record(digest)
    }
    fn holds_correlation(&self, id: &str) -> bool {
        self.0.index.leaves.iter().any(|l| holds(l, id))
    }
    fn cites_exchange(&self, half_digest: &str) -> bool {
        self.0.cites_exchange(half_digest)
    }
    fn positional_ordering(&self) -> bool {
        self.0.positional_ordering()
    }
    fn anchors(&self) -> Vec<Anchor> {
        self.0.anchors()
    }
    fn derivation_forms(&self, derivation: &Derivation) -> Option<Vec<SubjectForm>> {
        is_derivation(Some(derivation)).then(|| vec![SubjectForm::Correlation])
    }
}

/// Whether `leaf` is a record of this node holding the verdict `id`. A record
/// that never leaves this node is in no answer's matched set, so it holds
/// nothing for a requester (evidencebook#206 row 4).
pub(crate) fn holds(leaf: &crate::evidence_log::Leaf, id: &str) -> bool {
    !leaf.never_leaves
        && leaf
            .verdict
            .as_ref()
            .is_some_and(|v| v.verdict_capsule_id == id)
}

/// The leaf indices holding the verdict the subject names, committed under
/// `anchor`.
pub(crate) fn matching_records(
    req: &Request,
    anchor: &CheckpointRecord,
    view: &LogView<'_>,
) -> Vec<u64> {
    let Subject::Correlation(id) = &req.subject else {
        return Vec::new();
    };
    let covered = leaf_count(anchor.mmr_size).unwrap_or(0);
    view.index
        .leaves
        .iter()
        .enumerate()
        .filter(|(i, l)| (*i as u64) < covered && holds(l, id))
        .map(|(i, _)| i as u64)
        .collect()
}

/// The artifact's `entries`: for each record holding the verdict `id`, the
/// verdict's id, the record's digest and its inclusion proof at `anchor`, in
/// hex. `NoSuchSubject` when none is committed there.
pub(crate) fn entries(
    id: &str,
    anchor: &CheckpointRecord,
    records: &[u64],
    view: &LogView<'_>,
) -> Result<Value, Reason> {
    if records.is_empty() {
        return Err(Reason::NoSuchSubject);
    }
    let mut entries = Vec::with_capacity(records.len());
    for &i in records {
        let record = view.record_at(i).ok_or(Reason::CapacityExceeded)?;
        let proof = crate::evidence_artifact::inclusion(view, i, anchor.mmr_size)?;
        entries.push(json!({
            "verdict": id,
            "record": record.digest,
            "inclusion": hex::encode(proof),
        }));
    }
    Ok(Value::Array(entries))
}

/// The request that asks a node whether it holds the verdict `id`, pinned to
/// the anchor `pin` (what the docs show a requester sending through
/// `mesh_evidence_request`).
#[cfg(test)]
pub fn request_for(id: &str, pin: &str) -> Value {
    json!({
        "subject": {"correlation": id},
        "coverage": {"expected_pin": pin},
        "derivation": DEFINITION_DIGEST,
    })
}

/// The artifact's entries for the verdict `id`, under the anchor checkpoint
/// `cp`: each carries exactly the derivation's members, is for `id`, and its
/// record is proven under `cp`. Returns the records' digests and leaves.
pub(crate) fn check_entries(
    art: &Map<String, Value>,
    id: &str,
    cp: &DecodedCheckpointCose,
) -> Result<(Vec<String>, Vec<u64>), &'static str> {
    let covered = leaf_count(cp.mmr_size).map_err(|_| "the anchor checkpoint is malformed")?;
    let entries = art
        .get("entries")
        .and_then(Value::as_array)
        .filter(|e| !e.is_empty())
        .ok_or("the artifact carries no entries")?;
    let mut records = Vec::with_capacity(entries.len());
    let mut leaves = Vec::with_capacity(entries.len());
    for entry in entries {
        let map = entry.as_object().ok_or("an entry is malformed")?;
        let mut members: Vec<&str> = map.keys().map(String::as_str).collect();
        members.sort_unstable();
        if members != ENTRY_MEMBERS {
            return Err("an entry does not carry exactly the derivation's members");
        }
        let text = |k: &str| map.get(k).and_then(Value::as_str);
        if text("verdict") != Some(id) {
            return Err("an entry is for another verdict");
        }
        let record = text("record")
            .filter(|h| is_digest(h))
            .ok_or("an entry's record is malformed")?;
        let proof = text("inclusion")
            .and_then(|h| hex::decode(h).ok())
            .ok_or("an entry's inclusion proof is malformed")?;
        let leaf = crate::evidence_artifact::cll_proofs::inclusion_leaf(&proof)
            .ok_or("an entry's inclusion proof is malformed")?;
        if leaves.contains(&leaf) {
            return Err("an entry repeats a record already listed");
        }
        let record_bytes: [u8; 32] = hex::decode(record)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or("an entry's record is malformed")?;
        if leaf >= covered
            || !crate::evidence_artifact::cll_proofs::proves(
                &proof,
                leaf,
                &record_bytes,
                cp.mmr_size,
                &cp.new_peak_hashes,
            )
        {
            return Err("an entry's record is not included under the anchor");
        }
        records.push(record.to_string());
        leaves.push(leaf);
    }
    Ok((records, leaves))
}
