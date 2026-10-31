//! `evidence_bundle/1`: one of this node's exchange halves answered as an
//! Evidence Bundle (Mesh-LLM/capsules-plugin#197), the form a two-sided
//! receipt carries as the provider's `artifact` member
//! (action-state-group/evidencebook-deal#86 D4).
//!
//! **The request** names the half as a `record` subject (the payer asks for
//! the half it was pushed) with this derivation. Under an `expected_pin` the
//! answer is served under that checkpoint, which must cover the half; under
//! a `min_freshness`, under the earliest checkpoint that covers the half and
//! meets it, so the interval is as short as the request allows and the
//! artifact stays the same as the log grows (-00 §5).
//!
//! **The artifact** is the RFC 8785 form of an interval-complete
//! `evidence-bundle/v2` of this node's log, built by agent-action-capsule's
//! producer: rooted at the half, a range proof from the half to the
//! checkpoint's tip, and every record of that interval with its payload
//! withheld (no disclosures). The bundle carries no `countersignatures`, so
//! the envelope's `artifact_digest` is the bundle's `BundleDigest`, which is
//! what a `composed/v1` member binds its response to. The envelope carries
//! the anchor's `cll-checkpoint`, as for this node's other derivations.
//!
//! **Who gets it** is decided by the sharing policy before anything is built
//! (`evidence_answer`): the headers carried are records, so the answer is
//! gated as record bodies are, whole or refused, and every record of the
//! interval must be one the requester may have.

use agent_action_capsule::bundle::{
    build_evidence_bundle, bundle_digest, verify_bundle_strict, BuildOptions, Interval,
    StrictOptions,
};
use base64::Engine as _;
use cll::checkpoint::DecodedCheckpointCose;
use cll::mmr::leaf_count;
use evidence_request::cll_material::KIND_CHECKPOINT;
use evidence_request::envelope::{self, AnchorFreshness, Envelope};
use evidence_request::registry::{Reason, SubjectForm};
use evidence_request::request::{Coverage, Derivation, Freshness, Subject};
use evidence_request::resolve::{self, Anchor};
use evidence_request::time::parse_utc;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::deal_receipt::LogSource;
use crate::evidence_artifact::{profile_of, profile_time, Build};
use crate::evidence_log::{ChainCheckpoint, LedgerIndex, LogView};

/// The derivation token.
pub const TOKEN: &str = "evidence_bundle/1";

/// Whether `derivation` asks for this answer.
pub fn is_derivation(derivation: Option<&Derivation>) -> bool {
    matches!(derivation, Some(Derivation::Token(t)) if t == TOKEN)
}

/// The log as resolution sees it for this derivation: defined over a
/// `record` subject only.
pub(crate) struct BundleView<'a, 'b>(pub &'a LogView<'b>);

impl resolve::Responder for BundleView<'_, '_> {
    fn holds_record(&self, digest: &str) -> bool {
        self.0.holds_record(digest)
    }
    fn holds_correlation(&self, id: &str) -> bool {
        self.0.holds_correlation(id)
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
        is_derivation(Some(derivation)).then(|| vec![SubjectForm::Record])
    }
}

/// Whether leaf `leaf` is one of this node's exchange halves: a record with
/// an `x-mesh-poc-v1` block that may leave the node. A citing record, a deal
/// record or padding is not one.
pub(crate) fn is_exchange_half(view: &LogView<'_>, leaf: u64) -> bool {
    let Some(entry) = view.index.leaves.get(leaf as usize) else {
        return false;
    };
    if entry.padding || entry.never_leaves {
        return false;
    }
    view.record_at(leaf)
        .and_then(|record| serde_json::from_slice::<Value>(&record.body).ok())
        .is_some_and(|record| {
            record
                .pointer("/model_attestation/compute_attestation/x-mesh-poc-v1")
                .is_some_and(Value::is_object)
        })
}

/// The chain position of the checkpoint the answer for the half at `leaf` is
/// served under (see the module doc). `coverage_unsatisfiable` when no
/// checkpoint both covers the half and meets `coverage`.
pub(crate) fn serving_position(
    index: &LedgerIndex,
    coverage: &Coverage,
    leaf: u64,
) -> Result<usize, Reason> {
    let covers =
        |cp: &ChainCheckpoint| leaf_count(cp.record.mmr_size).is_ok_and(|covered| leaf < covered);
    let found = match coverage {
        Coverage::ExpectedPin(pin) => index
            .chain
            .iter()
            .position(|cp| cp.anchor_digest() == *pin)
            .filter(|&at| covers(&index.chain[at])),
        Coverage::MinFreshness(freshness) => index.chain.iter().position(|cp| {
            covers(cp)
                && match freshness {
                    Freshness::Size(n) => {
                        leaf_count(cp.record.mmr_size).is_ok_and(|covered| covered >= *n)
                    }
                    Freshness::Time(t) => {
                        parse_utc(&profile_time(&cp.record.timestamp)).is_some_and(|at| at >= *t)
                    }
                }
        }),
    };
    found.ok_or(Reason::CoverageUnsatisfiable)
}

/// The anchor `served` is, as resolution names one.
pub(crate) fn anchor_of(served: &ChainCheckpoint) -> Result<Anchor, Reason> {
    Ok(Anchor {
        digest: served.anchor_digest(),
        size: leaf_count(served.record.mmr_size).map_err(|_| Reason::CoverageUnsatisfiable)?,
        issued_at: served.record.timestamp.clone(),
    })
}

/// The signed envelope of the answer `b` asks for, under `served`.
pub(crate) fn envelope(
    b: &Build<'_>,
    view: &LogView<'_>,
    served: &ChainCheckpoint,
) -> Result<Envelope, Reason> {
    let Subject::Record(root) = &b.request.subject else {
        return Err(Reason::NoSuchSubject);
    };
    let first = *b.records.first().ok_or(Reason::NoSuchSubject)?;
    let declined = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(error = %e, "an evidence bundle answer could not be {what} -- declining");
        Reason::CapacityExceeded
    };
    let source = LogSource::at(view.index, served).map_err(|e| declined("read", &e))?;
    let mut options = BuildOptions::new(root.clone(), Interval::From(first + 1));
    // The interval is the whole selection: no citation is followed.
    options.closure_depth = 0;
    options.producer_key = Some(b.signing_key.verifying_key().to_bytes());
    let bundle = build_evidence_bundle(&source, &options).map_err(|e| declined("built", &e))?;
    let artifact =
        agent_action_capsule::canonical::jcs(&bundle).map_err(|e| declined("encoded", &e))?;
    let freshness = match &b.request.coverage {
        Coverage::MinFreshness(Freshness::Size(_)) => {
            Some(AnchorFreshness::Size(served.record.mmr_size))
        }
        Coverage::MinFreshness(Freshness::Time(_)) => Some(AnchorFreshness::Time(profile_time(
            &served.record.timestamp,
        ))),
        Coverage::ExpectedPin(_) => None,
    };
    envelope::sign_with_profile(
        &profile_of(b.request_bytes),
        b.request_bytes,
        envelope::EnvelopeParts {
            subject: b.request.subject.clone(),
            derivation: b.request.derivation.clone(),
            anchor: envelope::Anchor {
                digest: served.anchor_digest(),
                freshness,
            },
            artifact,
            verification: vec![(KIND_CHECKPOINT.to_string(), served.statement.clone())],
            issued_at: b.issued_at.to_string(),
        },
        b.signing_key,
    )
    .map_err(|e| declined("signed", &e))
}

/// Check the artifact of an answer for the half `root`, served under the
/// checkpoint `served` (the envelope's anchor, verified under the
/// responder's key, whose statement digests to `anchor`). Returns the leaf
/// indices the bundle carries: the half to the checkpoint's tip.
pub(crate) fn check_artifact(
    artifact: &[u8],
    root: &str,
    served: &DecodedCheckpointCose,
    anchor: &str,
) -> Result<Vec<u64>, String> {
    let bundle: Value =
        serde_json::from_slice(artifact).map_err(|_| "the artifact is not a bundle".to_string())?;
    // The octets are the bundle's own canonical form, so the response's
    // `artifact_digest` is its BundleDigest.
    let canonical = agent_action_capsule::canonical::jcs(&bundle)
        .map_err(|_| "the artifact is not a bundle".to_string())?;
    if canonical != artifact || bundle.get("countersignatures").is_some() {
        return Err("the artifact is not the bundle's canonical form".into());
    }
    let digest = bundle_digest(&bundle).map_err(|_| "the artifact is not a bundle".to_string())?;
    if digest != hex::encode(Sha256::digest(artifact)) {
        return Err("the artifact's digest is not its bundle digest".into());
    }
    if bundle.get("root").and_then(Value::as_str) != Some(root) {
        return Err("the bundle is not rooted at the requested half".into());
    }
    // Proven under the anchor itself, not another checkpoint of the log.
    let cose = bundle
        .pointer("/checkpoint/cose")
        .and_then(Value::as_str)
        .and_then(|b64| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b64)
                .ok()
        })
        .ok_or_else(|| "the bundle carries no checkpoint".to_string())?;
    if hex::encode(Sha256::digest(&cose)) != anchor {
        return Err("the bundle is proven under another checkpoint than the anchor".into());
    }
    let checked = verify_bundle_strict(
        &bundle,
        &StrictOptions {
            require_signature: false,
            witness_directory: None,
        },
    );
    let passed = |claim: &str| checked.claim(claim).is_some_and(|c| c.status == "pass");
    if !checked.ok()
        || ![
            "records",
            "checkpoint",
            "interval_coverage",
            "per_record_membership",
        ]
        .into_iter()
        .all(passed)
    {
        return Err(format!(
            "the bundle does not verify interval-complete ({})",
            checked.verdict()
        ));
    }
    // The interval starts at the half and ends at the anchor's tip.
    let certificate = bundle
        .get("completeness_certificate")
        .ok_or_else(|| "the bundle carries no completeness certificate".to_string())?;
    let seq = |member: &str| certificate.get(member).and_then(Value::as_u64);
    let root_seq = certificate
        .pointer(&format!("/memberships/{root}/log_coordinates/seq"))
        .and_then(Value::as_u64);
    let tip = leaf_count(served.mmr_size).map_err(|_| "the anchor's size is not an MMR size")?;
    match (seq("first_seq"), seq("last_seq"), root_seq) {
        (Some(first), Some(last), Some(at)) if first == at && first >= 1 && last == tip => {
            Ok((first - 1..last).collect())
        }
        _ => Err("the bundle's interval is not the half to the anchor's tip".into()),
    }
}

#[cfg(test)]
mod tests;
