//! The Service History (`service_history/3`, PRD-SERVICE-EVIDENCE §2, M2): a
//! Standard History under agent-action-capsule's inference-service history
//! profile (`spec/inference-service-history-profile-v0.md`, cited as ISH, at
//! e1286e01), revision `inference-service-history/1`: the `history_card/1`
//! artifact embedded unchanged, and this node's served exchanges counted per
//! closed week.
//!
//! **The derivation.** Unregistered, and named on the wire by the digest of
//! its definition document (`derivations/service-history-3.json`,
//! [`DEFINITION_DIGEST`]), which carries ISH §4.1's frame: `profile`
//! `inference-service-history/1`, `level` `standard`, the Standard
//! `coverage_declaration` and the `period_policy` Steven ruled on 2026-10-22
//! (evidencebook#46): weeks from Monday 2026-01-05 00:00 UTC, a floor of 5
//! per cell, complementary suppression. The token `service_history/3` is the
//! document's `name`, never a request's `derivation`. `service_history/4`
//! ([`DEFINITION_DOCUMENT_VERDICTS`]) adds the verdict counts member.
//!
//! **Revision `/1` only, and only under a key minted for it** (ISH §6.1 item
//! 9; Steven's ruling on action-state-group/agent-action-capsule#616: "ship
//! as `inference-service-history/1` and freeze `/0`"). `/1` withholds a
//! total that pins two or more models withheld under the floor (ISH §6.2
//! item 5), which `/0` publishes, so no key serves both, and no key that
//! served `/0` serves `/1`. Every key an earlier release minted listed the
//! `/0` definitions (`service_history/1` and `/2`) in its commitment, so this
//! node serves a Service History only under a key whose revision record
//! (`keys/ish-revision`, [`record_minted_key`]) names that key and `/1`: written
//! once, when `CapsuleState::open` mints the key. Any other key serves none,
//! `/0` included: a key with no record (an earlier release's, or one whose
//! record was lost) or with another key's record refuses all four
//! definitions `derivation_unsupported` and lists none, so a lost or stale
//! record fails closed. A node gets a Service History again only under a new
//! key. `/1` is served under `evidence-interop/1` only (ISH, Interop profile
//! revision): an `evidence-interop/0` request for it is `policy_declined`.
//! As a requester this node still checks the `/0` definitions
//! ([`LEGACY_DOCUMENT_1`], [`LEGACY_DOCUMENT_2`]), which peers on earlier
//! releases serve.
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
/// definition this node serves (`service_history/3`), and the one the
/// digests below are of.
pub const DEFINITION_DOCUMENT: &str = include_str!("../../../derivations/service-history-3.json");

/// `service_history/4`: the same frame, periods and floor as `/3`, with the
/// verdict counts member (ISH §4.3, §5.3; Mesh-LLM/capsules-plugin#289).
pub const DEFINITION_DOCUMENT_VERDICTS: &str =
    include_str!("../../../derivations/service-history-4.json");

/// `service_history/1`, `inference-service-history/0`: frozen, served by
/// earlier releases, and only checked here.
pub const LEGACY_DOCUMENT_1: &str = include_str!("../../../derivations/service-history-1.json");

/// `service_history/2`, `/1` with verdict counts under
/// `inference-service-history/0`: frozen, and only checked here.
pub const LEGACY_DOCUMENT_2: &str = include_str!("../../../derivations/service-history-2.json");

/// SHA-256 over the RFC 8785 bytes of [`DEFINITION_DOCUMENT_VERDICTS`].
#[cfg(test)]
pub const DEFINITION_DIGEST_VERDICTS: &str =
    "33321827c0e8678cc16cd41f54e9e6bcb0f9d9dcd71e4d4019c39ecbdf6a3d3b";

/// SHA-256 over the RFC 8785 bytes of [`LEGACY_DOCUMENT_1`] and
/// [`LEGACY_DOCUMENT_2`]: what earlier releases served and listed.
#[cfg(test)]
pub const LEGACY_DIGEST_1: &str =
    "cbc96d800ad206791db7e0793b80a2720c1908468ba99692b739aa8e74aab2d8";
#[cfg(test)]
pub const LEGACY_DIGEST_2: &str =
    "0f6cee6c5c2f57e7682137e4b40a9dcfad0f8db5a69d5bebaf99995936ea96f2";

/// The token of the Standard History card this node never serves beside a
/// Service History (ISH §6.1 item 8): that card counts over a window ending
/// at any anchor, with no floor.
pub const STANDARD_HISTORY_TOKEN: &str = "standard_history/1";

/// SHA-256 over the RFC 8785 bytes of [`DEFINITION_DOCUMENT`]: the
/// derivation's name on the wire, and the artifact's `derivation`. Pinned
/// here for a test to hold [`Definition::active`] to.
#[cfg(test)]
pub const DEFINITION_DIGEST: &str =
    "1021d0c12dbea1c1ff288edc30d4f05197c64e7615796f41d17ade7467ea5780";

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
        ACTIVE.get_or_init(|| load(DEFINITION_DOCUMENT))
    }

    /// `service_history/4`, the definition that also carries verdict counts:
    /// [`DEFINITION_DOCUMENT_VERDICTS`] under the same test-only policy
    /// override as [`Definition::active`].
    pub(crate) fn active_verdicts() -> &'static Definition {
        static ACTIVE: std::sync::OnceLock<Definition> = std::sync::OnceLock::new();
        ACTIVE.get_or_init(|| load(DEFINITION_DOCUMENT_VERDICTS))
    }

    /// `service_history/1` ([`LEGACY_DOCUMENT_1`]), checked, never served.
    fn legacy_1() -> &'static Definition {
        static LEGACY: std::sync::OnceLock<Definition> = std::sync::OnceLock::new();
        LEGACY.get_or_init(|| load(LEGACY_DOCUMENT_1))
    }

    /// `service_history/2` ([`LEGACY_DOCUMENT_2`]), checked, never served.
    fn legacy_2() -> &'static Definition {
        static LEGACY: std::sync::OnceLock<Definition> = std::sync::OnceLock::new();
        LEGACY.get_or_init(|| load(LEGACY_DOCUMENT_2))
    }

    /// Whether this node serves this definition under a key whose revision
    /// record names `/1`: only an `inference-service-history/1` one (ISH
    /// §6.1 item 9).
    pub(crate) fn is_revision_1(&self) -> bool {
        self.0.profile() == ish::PROFILE_1
    }

    /// Whether this definition carries the verdict counts member.
    pub(crate) fn has_verdict_counts(&self) -> bool {
        self.0.has_verdict_counts()
    }
}

fn load(text: &str) -> Definition {
    #[allow(unused_mut)]
    let mut document: Value = serde_json::from_str(text).expect("the definition file is JSON");
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
}

/// The definition a derivation names, by the digest of its definition
/// document: `service_history/3` or `/4`, which this node serves, or `/1` or
/// `/2`, which it only checks. Whether a key serves it is
/// [`key_serves`].
pub(crate) fn definition_for(derivation: Option<&Derivation>) -> Option<&'static Definition> {
    let Some(Derivation::Digest(d)) = derivation else {
        return None;
    };
    [
        Definition::active(),
        Definition::active_verdicts(),
        Definition::legacy_1(),
        Definition::legacy_2(),
    ]
    .into_iter()
    .find(|def| def.digest() == d)
}

/// The digest that names this node's Service History derivation
/// (`service_history/3`).
pub fn definition_digest() -> &'static str {
    Definition::active().digest()
}

/// The digest that names `service_history/4`.
pub fn definition_digest_verdicts() -> &'static str {
    Definition::active_verdicts().digest()
}

/// Whether `derivation` names a Service History definition this node knows:
/// `/3` or `/4`, or the `/0` ones it checks.
pub fn is_derivation(derivation: Option<&Derivation>) -> bool {
    definition_for(derivation).is_some()
}

/// The file beside the node key that records the profile revision the key
/// serves Service History under (ISH §6.1 item 9).
pub const KEY_REVISION_FILE: &str = "ish-revision";

/// Record that the key `key`, just minted in `keys_dir`, serves `/1`: the
/// key's revision record, `{"key_id", "profile"}`, `key_id` the key's
/// [`crate::commitment::key_id`]. It is honoured only for that key, so a
/// record left beside another key serves nothing.
/// Written to a temporary file and renamed, so a reader never sees half
/// a record; a start that dies before the rename leaves the key with no
/// record, which serves no Service History.
pub(crate) fn record_minted_key(
    keys_dir: &std::path::Path,
    key: &ed25519_dalek::SigningKey,
) -> std::io::Result<()> {
    let record = serde_json::json!({
        "key_id": crate::commitment::key_id(key),
        "profile": ish::PROFILE_1,
    });
    let path = keys_dir.join(KEY_REVISION_FILE);
    let tmp = keys_dir.join(format!("{KEY_REVISION_FILE}.tmp"));
    std::fs::write(&tmp, format!("{record}\n"))?;
    std::fs::rename(&tmp, &path)
}

/// The node key under `keys_dir`, minted on first use: every place that
/// loads or mints it goes through here, so a key minted by this build
/// always gets its `/1` revision record ([`record_minted_key`]) and a key
/// already on disk never does (ISH §6.1 item 9).
pub(crate) fn load_or_create_key(
    keys_dir: &std::path::Path,
) -> anyhow::Result<crate::producer::keys::KeyPair> {
    let minting = !keys_dir.join("node-key.pem").exists();
    let keys = crate::producer::keys::load_or_create(keys_dir)?;
    if minting {
        record_minted_key(keys_dir, &keys.signing_key)?;
    }
    Ok(keys)
}

/// Whether the node whose ledger is `ledger_dir` serves Service History
/// under `key`: its record (`<data dir>/keys/ish-revision`, beside
/// `<data dir>/ledger`) names `key` and `/1`. A missing, unreadable or
/// malformed record, or one naming another key or revision, is `false`.
pub(crate) fn key_serves(ledger_dir: &std::path::Path, key: &ed25519_dalek::SigningKey) -> bool {
    let names_key = |path: std::path::PathBuf| {
        let Ok(text) = std::fs::read_to_string(path) else {
            return false;
        };
        let Ok(record) = serde_json::from_str::<Value>(&text) else {
            return false;
        };
        record.get("key_id").and_then(Value::as_str)
            == Some(crate::commitment::key_id(key).as_str())
            && record.get("profile").and_then(Value::as_str) == Some(ish::PROFILE_1)
    };
    // A test's ledger is a bare temporary directory with no data directory
    // around it, so a test node keeps its record in the ledger itself
    // ([`record_for_test`]).
    #[cfg(test)]
    if names_key(ledger_dir.join(KEY_REVISION_FILE)) {
        return true;
    }
    ledger_dir
        .parent()
        .is_some_and(|data_dir| names_key(data_dir.join("keys").join(KEY_REVISION_FILE)))
}

/// Give the test node whose ledger is `ledger_dir` the revision record of
/// `key`, as a key minted by this build has.
#[cfg(test)]
pub(crate) fn record_for_test(ledger_dir: &std::path::Path, key: &ed25519_dalek::SigningKey) {
    record_minted_key(ledger_dir, key).expect("the test ledger is writable");
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
#[cfg(test)]
pub(crate) fn period_counts(
    chain: &[Cut<'_>],
    model: &dyn Fn(u64) -> Option<String>,
) -> Result<Value, Reason> {
    period_counts_for(Definition::active(), chain, model)
}

/// [`period_counts`] under `def`.
pub(crate) fn period_counts_for(
    def: &Definition,
    chain: &[Cut<'_>],
    model: &dyn Fn(u64) -> Option<String>,
) -> Result<Value, Reason> {
    ish::period_counts(&def.0, chain, model).map_err(reason)
}

/// The `verdict_counts` member under `def`: `verdict(i)` is the `(model_hash,
/// result)` of the verdict the record at leaf `i` holds about this node. See
/// `agent_action_capsule::inference_history::verdict_counts`.
pub(crate) fn verdict_counts(
    def: &Definition,
    chain: &[Cut<'_>],
    verdict: &dyn Fn(u64) -> Option<(String, String)>,
) -> Result<Value, Reason> {
    ish::verdict_counts(&def.0, chain, verdict).map_err(reason)
}

/// [`artifact_for`] for a definition that carries `verdict_counts`.
pub(crate) fn artifact_with_verdicts(
    def: &Definition,
    card: &[u8],
    counts: Value,
    verdicts: Value,
    anchor: &str,
    stream: &str,
    log_size: u64,
) -> Result<Vec<u8>, Reason> {
    ish::artifact_with_verdicts(&def.0, card, counts, verdicts, anchor, stream, log_size)
        .map_err(reason)
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
    for period in counts.verdicts.iter().flatten() {
        for cell in &period.cells {
            let what = match &cell.model_hash {
                Some(m) => format!("referee verdicts {}, model {m}", cell.result),
                None => format!("referee verdicts {}, all models", cell.result),
            };
            let value = match &cell.value {
                Ok(n) => n.to_string(),
                Err(why) if why == "complementary" => {
                    "withheld (another withheld count could be derived from it)".to_string()
                }
                Err(_) => format!("withheld (under {floor})"),
            };
            lines.push(format!(
                "{} to {}: {what}: {value} (self_reported, held by this node, signed by the referee)",
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

#[cfg(test)]
mod vector_tests_v1;
