//! The Service History (`service_history/1`, PRD-SERVICE-EVIDENCE §2, M2): a
//! Standard History under agent-action-capsule's inference-service history
//! profile (`spec/inference-service-history-profile-v0.md`, cited as ISH, at
//! f8c946ed): the `history_card/1` artifact embedded unchanged, and this
//! node's served exchanges counted per closed week.
//!
//! **The derivation.** Unregistered, and named on the wire by the digest of
//! its definition document (`derivations/service-history-1.json`,
//! [`DEFINITION_DIGEST`]), which carries ISH §4.1's frame: `profile`,
//! `level` `standard`, the Standard `coverage_declaration` and the
//! `period_policy` Steven ruled on 2026-10-22 (evidencebook#46): weeks from
//! Monday 2026-01-05 00:00 UTC, a floor of 5 per cell, complementary
//! suppression. The token `service_history/1` is the document's `name`,
//! never a request's `derivation`.
//!
//! **Never beside `standard_history/1`.** A node that serves this profile's
//! Standard Histories serves no `standard_history/1` card under its key
//! (ISH §6.1 item 8): two such cards at consecutive checkpoints could be
//! subtracted to isolate one exchange the periods protect. The responder
//! refuses [`STANDARD_HISTORY_TOKEN`] `derivation_unsupported`, and this
//! node's commitment does not list it.
//!
//! **Answered** only for `full_history` under an `expected_pin` naming an
//! anchor whose checkpoint time is a period boundary (ISH §6.1 items 2 and
//! 5, §8.4); anything else is `policy_declined`, the same for every
//! requester. The checkpoint cadence appends one padding record and cuts a
//! checkpoint at each boundary (`crate::checkpoint_cadence`). It is Standard History
//! (`share_standard_history`), and when either member cannot be built the
//! whole History is refused, never served with a member dropped.
//!
//! **The artifact** is ISH §8.2's object, as its RFC 8785 octets: `anchor`,
//! `coverage_declaration` (`interval` from the stream's start to the
//! anchor, and the anchor's `live_set`), `declared`, `derivation`,
//! `evidence_stream`, `history_card`, `history_card_digest`,
//! `period_counts` and `subject`. Both members are always declared, so the
//! bytes depend only on (subject, anchor, definition): the same for every
//! requester. The envelope carries no verification material (ISH §8.1); the
//! witness receipts of the card's checkpoints ride beside it in
//! `witness_receipts`, as for a direct card.
//!
//! - `history_card` is the `history_card/1` artifact this node serves for
//!   the same subject and anchor, as a JSON value. RFC 8785 is
//!   compositional, so its canonical octets are the direct artifact's
//!   octets, and `history_card_digest` is their SHA-256.
//! - `period_counts` is `{policy, periods}` in the form of ISH §9's vectors:
//!   `policy` the digest of the definition's `period_policy`, and one entry
//!   per closed period, with none left out, from the one that holds the
//!   stream's first record (none when no checkpoint commits one) to the one
//!   ending at the anchor, each `{from, to, cells}`. The cells
//!   count `exchanges_served`, one per model the provider states and one
//!   total (`dimension` null), all `self_reported`. A cell under the floor
//!   is published with no value and `suppressed: "below_floor"`, and
//!   where that leaves a published total beside exactly one suppressed
//!   model, the smallest other model is suppressed `complementary`
//!   (ISH §6.2). Latency is never counted (Steven, 2026-10-22).
//!
//! **Which period a record is in.** The one the first checkpoint covering it
//! commits into: the time this node's stream committed it (ISH §6.1), read
//! from the card itself. A checkpoint commits into the period holding its
//! time, except the first checkpoint at a boundary, which commits into the
//! period it ends: it closes that period, so it commits only records of the
//! periods before it (ISH §6.1 item 2). Checkpoint times are taken as never
//! going back (each is at least the one before it), so no checkpoint after
//! the one that closed a period adds to it, and a period's cells are the
//! same at every later anchor (ISH §6.1 item 4).
//!
//! **The derivation and the checks are the library's**
//! (`agent_action_capsule::inference_history`, evidencebook#322): this module
//! holds this node's definition document and what only a node does (the
//! request and anchor gates, the refusals as the responder sends them, and
//! the page's rendering).
//!
//! **Verified** by [`check_artifact`], from `evidence_artifact::check`, which
//! first checks the envelope and the embedded card as a direct
//! `history_card/1` answer's: every checkpoint signed by the responder, the
//! list starting at the stream's first checkpoint and ending at the anchor,
//! and each consistency proof; then the witness receipts. Shown by
//! [`render`] in ISH §8.5's order.

use evidence_request::registry::Reason;
use evidence_request::request::{Coverage, Derivation, Subject};
use serde_json::{Map, Value};

use agent_action_capsule::inference_history as ish;
#[cfg(test)]
pub use ish::Cell;
pub use ish::{Counts, Cut};

/// The definition document, as published beside this crate: the Standard
/// definition this node serves, and the one the digests below are of.
pub const DEFINITION_DOCUMENT: &str = include_str!("../../../derivations/service-history-1.json");

/// The token of the Standard History card this node never serves beside a
/// Service History (ISH §6.1 item 8): that card counts over a window ending
/// at any anchor, with no floor.
pub const STANDARD_HISTORY_TOKEN: &str = "standard_history/1";

/// SHA-256 over the RFC 8785 bytes of [`DEFINITION_DOCUMENT`]: the
/// derivation's name on the wire, and the artifact's `derivation`. Pinned
/// here for a test to hold [`Definition::active`] to.
#[cfg(test)]
pub const DEFINITION_DIGEST: &str =
    "cbc96d800ad206791db7e0793b80a2720c1908468ba99692b739aa8e74aab2d8";

/// SHA-256 over the RFC 8785 bytes of the definition's `period_policy`.
#[cfg(test)]
pub const POLICY_DIGEST: &str = "0d4b28af7ebfca01a49c1ad59e74b7d9bff0e6712dd3478b4ee35b8ff6af5150";

/// The refusal of the library's derivation, as the responder sends it.
fn reason(r: ish::Refusal) -> Reason {
    match r {
        ish::Refusal::PolicyDeclined => Reason::PolicyDeclined,
        ish::Refusal::CapacityExceeded => Reason::CapacityExceeded,
    }
}

/// A Standard definition: the library's derivation and checks run under it
/// (`agent_action_capsule::inference_history`). [`Definition::active`] is the
/// one this node serves.
#[derive(Debug)]
pub(crate) struct Definition(ish::Definition);

impl Definition {
    /// The definition at `document`, or the `definition_form` rule (ISH
    /// §8.3) it breaks.
    pub(crate) fn from_document(document: &Value) -> Result<Definition, String> {
        ish::Definition::from_document(document).map(Definition)
    }

    /// Whether a request for this definition is `policy_declined` before
    /// anything is resolved: a Service History is a run of whole closed
    /// periods at one pinned anchor, so any other subject or coverage is
    /// declined, the same for every requester (ISH §6.1 items 2 and 5).
    pub(crate) fn declines_request(&self, subject: &Subject, coverage: &Coverage) -> bool {
        !(matches!(subject, Subject::FullHistory) && matches!(coverage, Coverage::ExpectedPin(_)))
    }

    /// Whether an answer pinned to a checkpoint with time `timestamp` is
    /// `policy_declined`: only a period boundary is answered (ISH §6.1
    /// item 2).
    pub(crate) fn declines_anchor(&self, timestamp: &str) -> bool {
        self.0.declines_anchor(timestamp)
    }

    /// The digest that names the definition on the wire.
    pub(crate) fn digest(&self) -> &str {
        self.0.digest()
    }

    /// The definition this node serves: [`DEFINITION_DOCUMENT`], its
    /// digests and its policy. A build with the `test-period-policy` feature
    /// reads `CAPSULES_TEST_PERIOD_EPOCH` and `CAPSULES_TEST_PERIOD_LENGTH_S`
    /// from its environment and serves, and checks, a definition whose
    /// `period_policy` has them instead, so a test can reach a period
    /// boundary in minutes. That is another definition, so its digests are
    /// its own; without the feature, or with neither variable set, nothing
    /// differs.
    pub(crate) fn active() -> &'static Definition {
        static ACTIVE: std::sync::OnceLock<Definition> = std::sync::OnceLock::new();
        ACTIVE.get_or_init(|| {
            #[allow(unused_mut)]
            let mut document: Value =
                serde_json::from_str(DEFINITION_DOCUMENT).expect("the definition file is JSON");
            #[cfg(feature = "test-period-policy")]
            {
                let policy = &mut document["period_policy"];
                if let Ok(epoch) = std::env::var("CAPSULES_TEST_PERIOD_EPOCH") {
                    policy["epoch"] = serde_json::json!(epoch);
                }
                if let Ok(length) = std::env::var("CAPSULES_TEST_PERIOD_LENGTH_S") {
                    let length: u64 = length.parse().expect("a whole number of seconds");
                    policy["length_s"] = serde_json::json!(length);
                    policy["min_length_s"] = serde_json::json!(length);
                }
            }
            Definition::from_document(&document).expect("the definition file conforms")
        })
    }
}

/// The digest that names this node's Service History derivation.
pub fn definition_digest() -> &'static str {
    Definition::active().digest()
}

/// Whether `derivation` names this one.
pub fn is_derivation(derivation: Option<&Derivation>) -> bool {
    matches!(derivation, Some(Derivation::Digest(d)) if d == definition_digest())
}

#[cfg(test)]
/// Whether the checkpoint time `timestamp` is a boundary of this node's
/// periods.
fn is_boundary(timestamp: &str) -> bool {
    Definition::active().0.policy().is_boundary(timestamp)
}

/// The first period boundary of this node's periods strictly after the Unix
/// time `t`. A time no period reaches is a bug in the caller's clock, not a
/// boundary: it is the end of time.
pub fn next_boundary_after(t: i64) -> i64 {
    Definition::active()
        .0
        .next_boundary_after(t)
        .unwrap_or(i64::MAX)
}

/// The `period_counts` member at the anchor `chain.last()` under this node's
/// definition: see `agent_action_capsule::inference_history::period_counts`.
/// Under `evidence-interop/0` the responder sends `policy_declined` for a
/// `capacity_exceeded` too (`evidence_answer`).
pub(crate) fn period_counts(
    chain: &[Cut<'_>],
    model: &dyn Fn(u64) -> Option<String>,
) -> Result<Value, Reason> {
    ish::period_counts(&Definition::active().0, chain, model).map_err(reason)
}

/// The artifact's octets under this node's definition: `card` is the direct
/// `history_card/1` artifact's octets at `anchor`, `counts` the
/// `period_counts` member. `capacity_exceeded` when the card's octets are not
/// its own canonical form, so the embedded card could not be the direct one.
pub(crate) fn artifact(
    card: &[u8],
    counts: Value,
    anchor: &str,
    stream: &str,
    log_size: u64,
) -> Result<Vec<u8>, Reason> {
    artifact_for(Definition::active(), card, counts, anchor, stream, log_size)
}

/// [`artifact`] under `def`, which names the History's `derivation`; a test
/// builds the artifacts of other definitions, such as the vectors', with it.
pub(crate) fn artifact_for(
    def: &Definition,
    card: &[u8],
    counts: Value,
    anchor: &str,
    stream: &str,
    log_size: u64,
) -> Result<Vec<u8>, Reason> {
    // Deliberately broken in one CI build: the card is rebuilt from its
    // checkpoint list, without the consistency proofs.
    #[cfg(feature = "mutant-service-history-card-rebuilt")]
    let rebuilt = {
        let mut value: Value =
            serde_json::from_slice(card).map_err(|_| Reason::CapacityExceeded)?;
        if let Some(history) = value.get_mut("history").and_then(Value::as_array_mut) {
            for entry in history {
                entry["consistency_from_previous"] = Value::Null;
            }
        }
        evidence_request::jcs::to_string(&value)
            .map_err(|_| Reason::CapacityExceeded)?
            .into_bytes()
    };
    #[cfg(feature = "mutant-service-history-card-rebuilt")]
    let card = rebuilt.as_slice();
    ish::artifact(&def.0, card, counts, anchor, stream, log_size).map_err(reason)
}

/// Check a Service History artifact `art` (already checked to name this
/// subject and derivation) against its embedded card, already checked: its
/// checkpoints `chain`, the stream's first to the anchor, with the records
/// each covers; the anchor digest and stream. See
/// `agent_action_capsule::inference_history::check_artifact`.
pub(crate) fn check_artifact(
    def: &Definition,
    art: &Map<String, Value>,
    chain: &[Cut<'_>],
    anchor: &str,
    stream: &str,
) -> Result<Counts, String> {
    ish::check_artifact(&def.0, art, chain, anchor, stream)
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// The words a rendered History never uses: continuity, a signature or a
/// receipt is never execution, and nothing ranks a node (PRD T5, §4).
#[cfg(test)]
pub const DENY_LIST: [&str; 8] = [
    "model executed",
    "verified model",
    "ran on",
    "attested",
    "score",
    "rating",
    "rank",
    "reputation",
];

/// A checked History as lines of text, in ISH §8.5's order: what the counts
/// are, each count in its own row, the checkpoints and receipts, which
/// checks did not run, and the limits.
pub fn render(
    counts: &Counts,
    checkpoints: usize,
    receipts: &[crate::evidence_artifact::ReceiptStatus],
) -> Vec<String> {
    use crate::evidence_artifact::ReceiptStatus;
    let count = |status| receipts.iter().filter(|&&r| r == status).count();
    let (verified, no_key, stub) = (
        count(ReceiptStatus::Verified),
        count(ReceiptStatus::NoKey),
        count(ReceiptStatus::Stub),
    );
    let policy = *Definition::active().0.policy();
    let floor = policy.floor;
    let mut lines = vec![
        "Every count is this node's own statement (self_reported). Checkpoint continuity, \
         witness receipts and signatures never show what was computed."
            .to_string(),
        "Coverage: every record of this node's stream up to the anchor (stream_interval, \
         all_records); completeness is not established, since the counts were not checked \
         against records."
            .to_string(),
        format!(
            "Periods of {}; a count under {floor} is withheld.",
            if policy.length_s % 86_400 == 0 {
                format!("{} days", policy.length_s / 86_400)
            } else {
                format!("{} seconds", policy.length_s)
            }
        ),
    ];
    for period in &counts.periods {
        for cell in &period.cells {
            let what = match &cell.model {
                Some(m) => format!("exchanges served, model {m} (as the provider states it)"),
                None => "exchanges served, all models".to_string(),
            };
            let value = match &cell.value {
                Ok(n) => n.to_string(),
                Err(why) if why == "complementary" => {
                    "withheld (another withheld count could be derived from it)".to_string()
                }
                Err(_) => format!("withheld (under {floor})"),
            };
            lines.push(format!(
                "{} to {}: {what}: {value} (self_reported)",
                period.from, period.to
            ));
        }
    }
    lines.push(format!("{checkpoints} checkpoints of this node's own log"));
    if receipts.is_empty() {
        lines.push("witness receipts: no witness named".to_string());
    } else {
        lines.push(format!(
            "witness receipts counted: {verified} of {}",
            receipts.len()
        ));
        if verified > 0 {
            lines.push(
                "a counted receipt means a later rewrite of its checkpoint is detectable"
                    .to_string(),
            );
        }
        if no_key > 0 {
            lines.push(format!(
                "{no_key} not counted: no witness key is configured for its witness"
            ));
        }
        if stub > 0 {
            lines.push(format!(
                "{stub} not counted: a placeholder the witness never registered"
            ));
        }
    }
    lines.push(
        "Not checked: anchor_inclusion, coverage_declaration_population, \
         coverage_declaration_commitment, and period_fixed (one History held)."
            .to_string(),
    );
    lines.push(
        "Limits: the history card shows each checkpoint's exact log size, which the periods \
         do not cover."
            .to_string(),
    );
    lines
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod vector_tests;
