//! `GET deal-receipt-bundle`: the payer's receipt for one paid exchange, as
//! an Evidence Bundle that capsule-viewer renders (Mesh-LLM/capsules-plugin#96;
//! the plugin emits the bundle and draws nothing).
//!
//! The bundle carries this node's own `x-deal-v0` records for the exchange
//! (baseline, outcome, close, any later outcome and close after a close
//! `open`, and the in-log `deal_report` of each close), each proven in this
//! node's log by an inclusion proof against one signed checkpoint, with the
//! viewer's pointer `extensions["x-deal-v0"].sealed_report` naming the latest
//! report. Their payloads are disclosed, except an earlier report's, withheld
//! as PROFILE §1 has it for later bundles; nothing else of the ledger is
//! carried (not the exchange record, not any other record), and the baseline's
//! intent stays closed: the nonce that opens it is never in the bundle, so
//! the receipt shows the commitment, not the words (Sherlock2, #96 design
//! thread). The selection is the producer's, so the strict verifier reads the
//! bundle INCOMPLETE by design: the log is not shown whole.
//!
//! The route is the owner's own local API, like `history-page`; the share gate
//! does not apply. The owner may forward the file, but it carries the owner's
//! own report (audience `keep`), so it reads as the owner's copy, not the
//! counterparty's; a counterparty copy would come from a share path (#146).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use agent_action_capsule::bundle::{
    build_evidence_bundle, BuildError, BuildOptions, InclusionProof, Interval, ProofSource,
    RangeProof, StoredRecord,
};
use cll::mmr::leaf_count;
use evidencebook::deal;
use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::checkpoint_cadence::CheckpointHandle;
use crate::evidence_log::{self, LedgerIndex, LogView};

pub(crate) mod composition;

/// Why no bundle is given. Each is the node's own state, not an error.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No deal of this node is linked to the exchange (a free exchange, an
    /// unknown id, or a deal this node did not seal).
    NoDeal,
    /// The deal is sealed but its report is not yet.
    NotReported,
    /// A deal capsule's payload is not in the journal.
    PayloadMissing(String),
    /// No signed checkpoint covers the deal's records yet.
    NotCheckpointed,
}

impl Refusal {
    fn why(&self) -> String {
        match self {
            Refusal::NoDeal => "this node holds no deal for that exchange".into(),
            Refusal::NotReported => "the deal has no report yet".into(),
            Refusal::PayloadMissing(id) => format!("the payload of deal record {id} is not kept"),
            Refusal::NotCheckpointed => "no signed checkpoint covers the deal yet".into(),
        }
    }
}

/// What building the bundle ran into.
#[derive(Debug)]
pub enum Error {
    Refused(Refusal),
    Failed(String),
}

impl From<Refusal> for Error {
    fn from(r: Refusal) -> Self {
        Error::Refused(r)
    }
}

/// The deal capsules of `exchange_capsule_id`, in log order, with the payload
/// disclosed for each and the latest report's id.
struct Deal {
    ids: Vec<String>,
    payloads: BTreeMap<String, Value>,
    report: String,
}

/// The journal's payloads for `ids`, read after the index lock is released.
fn read_deal(ledger_dir: &Path, ids: Vec<String>) -> Result<Deal, Error> {
    // By bytes, like the deal flow reads it: a torn last line is skipped.
    let journal = match std::fs::read(ledger_dir.join(crate::deal_flow::PAYLOADS_FILE)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(Error::Failed(format!(
                "the deal journal is not readable: {e}"
            )))
        }
    };
    let mut payloads = BTreeMap::new();
    let mut reports = Vec::new();
    for line in journal.split(|b| *b == b'\n') {
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        let Some(id) = v.get("capsule_id").and_then(Value::as_str) else {
            continue;
        };
        if !ids.iter().any(|i| i == id) {
            continue;
        }
        if v.get("record_type").and_then(Value::as_str) == Some(deal::REPORT_TYPE) {
            reports.push(id.to_string());
        }
        if let Some(payload) = v.get("payload") {
            payloads
                .entry(id.to_string())
                .or_insert_with(|| payload.clone());
        }
    }
    // The latest in the log: the report of the latest close.
    let report = ids
        .iter()
        .rev()
        .find(|id| reports.contains(id))
        .cloned()
        .ok_or(Refusal::NotReported)?;
    if let Some(missing) = ids.iter().find(|id| !payloads.contains_key(*id)) {
        return Err(Refusal::PayloadMissing(missing.clone()).into());
    }
    // An earlier report is carried with its payload withheld: the bundle
    // discloses one copy's text, the latest.
    payloads.retain(|id, _| *id == report || !reports.contains(id));
    Ok(Deal {
        ids,
        payloads,
        report,
    })
}

/// The proofs and records of one consistent snapshot of this node's log, at
/// the checkpoint the bundle is proven against.
struct LogSource<'a> {
    index: &'a LedgerIndex,
    view: LogView<'a>,
    statement: Vec<u8>,
    size: u64,
}

fn failed(message: impl Into<String>) -> BuildError {
    BuildError::new(message)
}

impl ProofSource for LogSource<'_> {
    fn checkpoint(&self) -> Result<Vec<u8>, BuildError> {
        Ok(self.statement.clone())
    }

    fn leaves(&self) -> Result<Vec<[u8; 32]>, BuildError> {
        let covered = leaf_count(self.size).map_err(|e| failed(format!("checkpoint size: {e}")))?;
        self.index
            .leaves
            .iter()
            .take(covered as usize)
            .enumerate()
            .map(|(i, leaf)| {
                let bytes = hex::decode(&leaf.capsule_id)
                    .map_err(|_| failed(format!("leaf {} is not hex", i + 1)))?;
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| failed(format!("leaf {} is not 32 bytes", i + 1)))
            })
            .collect()
    }

    fn record(&self, capsule_id: &str) -> Result<Option<StoredRecord>, BuildError> {
        let Some(leaf_index) = self.index.leaf_index_of(capsule_id) else {
            return Ok(None);
        };
        let Some(record) = self.view.record_at(leaf_index) else {
            return Err(failed(format!("record {capsule_id} is not readable")));
        };
        let line: Value = serde_json::from_slice(&record.body)
            .map_err(|e| failed(format!("record {capsule_id}: {e}")))?;
        // The inline envelope is the producer signature (hex of the COSE
        // octets); the bundle producer takes it as the separate member.
        let producer_envelope = line
            .get("signature")
            .and_then(Value::as_str)
            .map(hex::decode)
            .transpose()
            .map_err(|_| failed(format!("record {capsule_id}: the signature is not hex")))?
            .unwrap_or_default();
        Ok(Some(StoredRecord {
            capsule: record.body,
            producer_envelope,
        }))
    }

    fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof, BuildError> {
        let leaf_index = seq
            .checked_sub(1)
            .ok_or_else(|| failed("seq 0 is not a leaf"))?;
        let proof = self
            .index
            .inclusion_proof(leaf_index, self.size)
            .map_err(|e| failed(format!("inclusion proof for seq {seq}: {e}")))?;
        Ok(InclusionProof {
            v: proof.v,
            kind: proof.kind,
            size: proof.size,
            leaf_index: proof.leaf_index,
            witness: proof.witness,
            peaks_left: proof.peaks_left,
            peaks_right: proof.peaks_right,
        })
    }

    fn range_proof(&self, first_seq: u64) -> Result<RangeProof, BuildError> {
        let tip = leaf_count(self.size).map_err(|e| failed(format!("checkpoint size: {e}")))?;
        if first_seq == 0 || first_seq > tip {
            return Err(failed(format!(
                "range proof from seq {first_seq}: outside 1..={tip}"
            )));
        }
        let proof = self
            .index
            .range_proof(first_seq - 1, tip - 1, self.size)
            .map_err(|e| failed(format!("range proof from seq {first_seq}: {e}")))?;
        Ok(RangeProof {
            from_seq: first_seq,
            to_seq: tip,
            size: proof.size,
            from_index: proof.from_index,
            to_index: proof.to_index,
            witness: proof.witness,
        })
    }
}

/// The records a receipt bundle carries, and what it adds.
pub(crate) struct Selection<'a> {
    /// The bundle's root: one of `ids`.
    pub root: &'a str,
    /// Every record carried; no citation is followed.
    pub ids: &'a [String],
    /// Members disclosed, by capsule id.
    pub disclosures: BTreeMap<String, Map<String, Value>>,
    pub extensions: Map<String, Value>,
}

/// The bundle of `selection` and nothing else of the log, proven against the
/// earliest checkpoint of this node's log that reaches every record: the
/// same bundle every time, and no count of what was sealed after.
pub(crate) fn selected_bundle(
    index: &LedgerIndex,
    node_key_id: &str,
    selection: Selection<'_>,
) -> Result<Value, Error> {
    built(index, node_key_id, selection, None)
}

/// The bundle of `selection` and every other record of the log from the
/// earliest of its records to the checkpoint, with a range proof
/// (interval-complete). Private: only [`composition`], the owner's own keep
/// file, shows the log whole. Every bundle that may go to a peer is
/// [`selected_bundle`]'s (Sherlock2, #199).
fn interval_bundle(
    index: &LedgerIndex,
    node_key_id: &str,
    selection: Selection<'_>,
) -> Result<Value, Error> {
    let first = selection
        .ids
        .iter()
        .filter_map(|id| index.leaf_index_of(id))
        .min()
        .ok_or(Refusal::NotCheckpointed)?;
    built(index, node_key_id, selection, Some(first + 1))
}

/// [`selected_bundle`], or with `interval_from` (a seq) the interval from
/// there to the checkpoint.
fn built(
    index: &LedgerIndex,
    node_key_id: &str,
    selection: Selection<'_>,
    interval_from: Option<u64>,
) -> Result<Value, Error> {
    let unreadable = |e: std::io::Error| Error::Failed(format!("the ledger is not readable: {e}"));
    let covering = index
        .chain
        .iter()
        .find(|c| {
            leaf_count(c.record.mmr_size).is_ok_and(|covered| {
                selection
                    .ids
                    .iter()
                    .all(|id| index.leaf_index_of(id).is_some_and(|i| i < covered))
            })
        })
        .ok_or(Refusal::NotCheckpointed)?;
    let source = LogSource {
        index,
        view: index.view().map_err(unreadable)?,
        statement: covering.statement.clone(),
        size: covering.record.mmr_size,
    };
    let interval = interval_from.map_or(Interval::ProducerSelected, Interval::From);
    let mut options = BuildOptions::new(selection.root.to_string(), interval);
    // The records named are the whole selection: no citation is followed.
    options.closure_depth = 0;
    options.include = selection.ids.to_vec();
    options.disclosures = selection.disclosures;
    options.extensions = selection.extensions;
    options.producer_key = hex::decode(node_key_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
    build_evidence_bundle(&source, &options)
        .map_err(|e| Error::Failed(format!("the bundle was not built: {e}")))
}

/// The receipt bundle for `exchange_capsule_id`, over the log at `ledger_dir`.
pub fn bundle(
    ledger_dir: &Path,
    node_key_id: &str,
    exchange_capsule_id: &str,
) -> Result<Value, Error> {
    let linked = |index: &LedgerIndex| -> Vec<String> {
        index
            .deal_capsules_of(exchange_capsule_id)
            .into_iter()
            .map(str::to_string)
            .collect()
    };
    let unreadable = |e: std::io::Error| Error::Failed(format!("the ledger is not readable: {e}"));
    let ids = evidence_log::with_index(ledger_dir, node_key_id, linked).map_err(unreadable)?;
    if ids.is_empty() {
        return Err(Refusal::NoDeal.into());
    }
    // The journal is read with the index lock released: it grows with every
    // deal capsule and other answers wait on that lock.
    let deal = read_deal(ledger_dir, ids)?;
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        if linked(index) != deal.ids {
            return Err(Error::Failed(
                "the deal changed while it was read; ask again".into(),
            ));
        }
        // The payloads are disclosed; nothing else (the intent's opening is
        // not in them, and its nonce is kept only in the node's journal).
        let disclosures = deal
            .payloads
            .iter()
            .map(|(id, payload)| {
                let mut members = Map::new();
                members.insert("agent_input".into(), payload.clone());
                (id.clone(), members)
            })
            .collect();
        let mut extensions = Map::new();
        extensions.insert(
            deal::PROFILE.into(),
            json!({ deal::REPORT_POINTER: deal.report }),
        );
        selected_bundle(
            index,
            node_key_id,
            Selection {
                root: &deal.report,
                ids: &deal.ids,
                disclosures,
                extensions,
            },
        )
    })
    .map_err(unreadable)?
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReceiptArgs {
    /// The exchange record's capsule id: 64 lowercase hex.
    pub capsule_id: Value,
}

/// The route's answer: `{"state": "bundle", "bundle": ...}`, or
/// `{"state": "refused", "why": ...}` for a node state that has no bundle.
pub fn answer(ledger_dir: &Path, node_key_id: &str, capsule_id: &Value) -> Result<Value, String> {
    let Some(id) = capsule_id.as_str().filter(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) else {
        return Err("capsule_id must be 64 lowercase hex".into());
    };
    match bundle(ledger_dir, node_key_id, id) {
        Ok(bundle) => Ok(json!({"state": "bundle", "bundle": bundle})),
        Err(Error::Refused(r)) => Ok(json!({"state": "refused", "why": r.why()})),
        Err(Error::Failed(why)) => Err(why),
    }
}

/// `builder` with the `deal-receipt-bundle` route declared. A deal whose
/// records no checkpoint covers yet gets one cut first, as a pushed half does.
pub fn with_route(
    builder: DeclarativePluginBuilder,
    capsules: Arc<crate::capsule_emit::CapsuleState>,
    checkpoints: Option<CheckpointHandle>,
) -> DeclarativePluginBuilder {
    builder.http_item(
        http::get("/deal-receipt-bundle")
            .binding_id("evidence_deal_receipt_bundle")
            .description(
                "The receipt bundle for the payer's deal of one paid exchange, for the \
                 viewer to render. Cuts a signed checkpoint when none covers the deal yet.",
            )
            .input::<ReceiptArgs>()
            .handle(move |args, _context| {
                let capsules = capsules.clone();
                let checkpoints = checkpoints.clone();
                Box::pin(async move {
                    let ledger_dir = capsules.ledger_dir().to_path_buf();
                    let node_key_id = crate::commitment::key_id(capsules.signing_key());
                    let exchange = args.capsule_id;
                    let last = {
                        let (dir, key, id) =
                            (ledger_dir.clone(), node_key_id.clone(), exchange.clone());
                        tokio::task::spawn_blocking(move || last_deal_capsule(&dir, &key, &id))
                            .await
                            .ok()
                            .flatten()
                    };
                    if let (Some(handle), Some(last)) = (checkpoints.as_ref(), last) {
                        // A cut that fails leaves the answer to say there is no
                        // covering checkpoint.
                        let _ = handle.coverage_for(&last).await;
                    }
                    tokio::task::spawn_blocking(move || {
                        answer(&ledger_dir, &node_key_id, &exchange)
                    })
                    .await
                    .map_err(|error| {
                        PluginError::internal(format!(
                            "deal receipt task did not complete: {error}"
                        ))
                    })?
                    .map_err(PluginError::internal)
                })
            }),
    )
}

/// The last deal capsule of the exchange, which a covering checkpoint must reach.
fn last_deal_capsule(ledger_dir: &Path, node_key_id: &str, exchange: &Value) -> Option<String> {
    let exchange = exchange.as_str()?;
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        index
            .deal_capsules_of(exchange)
            .last()
            .map(|id| id.to_string())
    })
    .ok()
    .flatten()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::capsule_emit::CapsuleState;
    use crate::deal_flow::SealedExchange;
    use crate::producer::checkpoint::{CheckpointCadenceConfig, CheckpointState};

    const EXCHANGE_ID: &str = "exchange-1";
    const PEER: &str = "peer-node-with-a-distinct-name";

    fn hex64(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn exchange_capsule() -> String {
        hex64('e')
    }

    /// Seal the payer's deal for `exchange`, delivered or not yet.
    pub(crate) fn seal_deal(state: &CapsuleState, exchange: &str, delivered: bool) {
        let request = hex64('d');
        let deals = state.deals();
        deals.on_invoice(state, EXCHANGE_ID, &hex64('a'), 1000, 1_790_000_000);
        deals.on_exchange(
            state,
            EXCHANGE_ID,
            &SealedExchange {
                capsule_id: exchange,
                peer: PEER,
                request_digest: &request,
                model: "model-x",
            },
            1_790_000_001,
        );
        if delivered {
            finish(state);
        }
    }

    fn finish(state: &CapsuleState) {
        let deals = state.deals();
        deals.on_paid(state, EXCHANGE_ID, &hex64('b'), 1000, 1_790_000_030);
        deals.on_delivered(state, EXCHANGE_ID, &hex64('c'), 1_790_000_040);
    }

    /// A node that has sealed a paid exchange's deal.
    fn node(delivered: bool) -> (tempfile::TempDir, CapsuleState) {
        let dir = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(dir.path(), "deal-receipt-test").unwrap();
        seal_deal(&state, &exchange_capsule(), delivered);
        (dir, state)
    }

    /// A checkpoint of the node's own key over everything sealed so far.
    pub(crate) fn cut(state: &CapsuleState) {
        let ledger = state.ledger_dir().to_path_buf();
        let (mut checkpoints, _) =
            CheckpointState::load(&ledger, "test-log", CheckpointCadenceConfig::default()).unwrap();
        let last = std::fs::read_to_string(ledger.join(evidence_log::CAPSULES_FILE))
            .unwrap()
            .lines()
            .last()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["capsule_id"].to_string())
            .unwrap();
        let last = last.trim_matches('"').to_string();
        checkpoints
            .checkpoint_covering(
                &last,
                state.signing_key(),
                &crate::checkpoint_cadence::anchor_for(),
            )
            .unwrap();
    }

    /// A bundle that may leave the owner's hands, or go to a peer, carries
    /// only its selection: no range proof (the log is not shown whole) and no
    /// composition. Only [`composition`] builds an interval-complete
    /// bundle (Sherlock2, #199).
    pub(crate) fn assert_selection_only(bundle: &Value) {
        assert_eq!(bundle["completeness"]["selection"], "producer-selected");
        assert!(bundle["completeness_certificate"]
            .get("range_proof")
            .is_none());
        assert!(bundle["completeness_certificate"]
            .get("first_seq")
            .is_none());
        assert!(bundle["extensions"]
            .get(composition::COMPOSED_KIND)
            .is_none());
    }

    fn built(state: &CapsuleState) -> Result<Value, Error> {
        bundle(
            state.ledger_dir(),
            &crate::commitment::key_id(state.signing_key()),
            &exchange_capsule(),
        )
    }

    #[test]
    fn a_paid_exchange_gives_a_bundle_of_exactly_its_four_deal_records() {
        let (_dir, state) = node(true);
        // Another record sealed after the deal: it must not be carried.
        state
            .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("node-a"))
            .unwrap();
        cut(&state);
        let bundle = built(&state).unwrap_or_else(|e| panic!("{e:?}"));
        assert_selection_only(&bundle);

        let deal_ids: Vec<String> = evidence_log::with_index(
            state.ledger_dir(),
            &crate::commitment::key_id(state.signing_key()),
            |index| {
                index
                    .deal_capsules_of(&exchange_capsule())
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            },
        )
        .unwrap();
        assert_eq!(deal_ids.len(), 4);
        let carried: Vec<&str> = bundle["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["capsule_id"].as_str().unwrap())
            .collect();
        let mut want: Vec<&str> = deal_ids.iter().map(String::as_str).collect();
        let mut got = carried.clone();
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want, "the deal's records and no others");

        let report = bundle["extensions"]["x-deal-v0"]["sealed_report"]
            .as_str()
            .unwrap();
        assert!(carried.contains(&report));
        let report_payload = &bundle["disclosures"][report]["agent_input"];
        assert_eq!(report_payload["type"], "deal_report");

        // Every claim passes but the interval: the bundle is producer-selected,
        // so what the log holds besides these records is not shown.
        let checked = agent_action_capsule::bundle::verify_bundle_strict(
            &bundle,
            &agent_action_capsule::bundle::StrictOptions {
                require_signature: true,
                witness_directory: None,
            },
        );
        let statuses: Vec<_> = checked
            .claims
            .iter()
            .map(|(name, c)| (*name, c.status.as_str()))
            .collect();
        assert_eq!(
            statuses,
            [
                ("records", "pass"),
                ("signatures", "pass"),
                ("graph_closure", "pass"),
                ("checkpoint", "pass"),
                ("interval_coverage", "withheld"),
                ("per_record_membership", "pass"),
                ("disclosures", "pass"),
            ]
        );
        // For capsulectl verify and the viewer by hand (see the PR).
        if let Some(out) = std::env::var_os("DEAL_RECEIPT_BUNDLE_OUT") {
            std::fs::write(out, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
        }
    }

    /// Sherlock2's acceptance add: the owner's file closes the intent. No
    /// nonce of the baseline's commitment, no opening, no raw peer id.
    #[test]
    fn the_bundle_carries_no_intent_opening_and_no_raw_peer() {
        let (_dir, state) = node(true);
        cut(&state);
        let bundle = built(&state).unwrap_or_else(|e| panic!("{e:?}"));
        let text = serde_json::to_string(&bundle).unwrap();
        let journal =
            std::fs::read_to_string(state.ledger_dir().join(crate::deal_flow::PAYLOADS_FILE))
                .unwrap();
        let nonce = journal
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find_map(|l| l.get("nonce").and_then(Value::as_str).map(str::to_string))
            .expect("the baseline's nonce is kept in the journal");
        assert!(!text.contains(&nonce), "the intent's nonce is not carried");
        assert!(!text.contains(PEER), "the raw peer id is not carried");
        // Decided, not accidental: the report says which model was asked
        // (Sherlock2, #145), so the owner's file names it.
        assert!(text.contains("model-x"), "the report names the model");
        assert!(
            !text.contains(&hex64('d')),
            "the request digest (the intent's text) is not carried"
        );
        // The report cites the exchange record by id (its `did` lines do);
        // the record itself is not carried.
        assert!(bundle["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["capsule_id"] != json!(exchange_capsule())));
    }

    #[test]
    fn a_deal_without_a_report_a_free_exchange_and_an_unknown_one_get_a_refusal() {
        let (_dir, state) = node(false);
        cut(&state);
        assert!(matches!(
            built(&state),
            Err(Error::Refused(Refusal::NotReported))
        ));
        let unknown = bundle(
            state.ledger_dir(),
            &crate::commitment::key_id(state.signing_key()),
            &hex64('9'),
        );
        assert!(matches!(unknown, Err(Error::Refused(Refusal::NoDeal))));
    }

    #[test]
    fn a_deal_no_checkpoint_covers_yet_gets_a_refusal() {
        let (_dir, state) = node(true);
        assert!(matches!(
            built(&state),
            Err(Error::Refused(Refusal::NotCheckpointed))
        ));
        cut(&state);
        assert!(built(&state).is_ok());
    }

    #[test]
    fn the_route_answer_names_a_refusal_and_rejects_a_malformed_id() {
        let (_dir, state) = node(true);
        let key = crate::commitment::key_id(state.signing_key());
        let answered = answer(state.ledger_dir(), &key, &json!(exchange_capsule())).unwrap();
        assert_eq!(answered["state"], "refused");
        assert!(answer(state.ledger_dir(), &key, &json!("NOT-HEX")).is_err());
        cut(&state);
        let answered = answer(state.ledger_dir(), &key, &json!(exchange_capsule())).unwrap();
        assert_eq!(answered["state"], "bundle");
    }

    /// The deal links to a real exchange record on the ledger, and the bundle
    /// carries that record neither as a record nor as a disclosure.
    #[test]
    fn a_real_exchange_record_is_not_carried() {
        let dir = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(dir.path(), "deal-receipt-test").unwrap();
        let exchange = state
            .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("node-a"))
            .unwrap()
            .capsule_id;
        seal_deal(&state, &exchange, true);
        cut(&state);
        let bundle = bundle(
            state.ledger_dir(),
            &crate::commitment::key_id(state.signing_key()),
            &exchange,
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(bundle["records"].as_array().unwrap().len(), 4);
        assert!(bundle["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["capsule_id"] != json!(exchange)));
        assert!(bundle["disclosures"].get(&exchange).is_none());
    }

    /// A deal closed `open` that settles later: the receipt names the latest
    /// report, discloses its text, and carries the earlier report withheld.
    #[test]
    fn a_late_settlement_gives_the_latest_report_and_withholds_the_earlier() {
        let (_dir, state) = node(false);
        state.deals().tick(&state, 1_790_000_000 + 15 * 60);
        let first = built_after_cut(&state);
        let first_report = first["extensions"]["x-deal-v0"]["sealed_report"].clone();

        let deals = state.deals();
        deals.on_paid(&state, EXCHANGE_ID, &hex64('b'), 1000, 1_790_001_000);
        deals.on_delivered(&state, EXCHANGE_ID, &hex64('c'), 1_790_001_010);
        let bundle = built_after_cut(&state);
        let report = bundle["extensions"]["x-deal-v0"]["sealed_report"]
            .as_str()
            .unwrap();
        assert_ne!(json!(report), first_report);
        let records = bundle["records"].as_array().unwrap();
        assert_eq!(records.len(), 10, "every deal record, both rounds");
        assert_eq!(
            records.last().unwrap()["capsule_id"],
            json!(report),
            "the latest report is the last record"
        );
        let text = &bundle["disclosures"][report]["agent_input"]["report"];
        assert_eq!(text["lifecycle"]["state"], "closed");
        // Earlier reports are carried, their text withheld.
        let first_report = first_report.as_str().unwrap();
        assert!(records.iter().any(|r| r["capsule_id"] == first_report));
        assert!(bundle["disclosures"].get(first_report).is_none());
        let reports = bundle["disclosures"]
            .as_object()
            .unwrap()
            .values()
            .filter(|d| d["agent_input"]["type"] == "deal_report")
            .count();
        assert_eq!(reports, 1);
        let checked = agent_action_capsule::bundle::verify_bundle_strict(
            &bundle,
            &agent_action_capsule::bundle::StrictOptions {
                require_signature: true,
                witness_directory: None,
            },
        );
        let failed: Vec<_> = checked
            .claims
            .iter()
            .filter(|(name, c)| *name != "interval_coverage" && c.status.as_str() != "pass")
            .map(|(name, c)| (*name, c.status.as_str()))
            .collect();
        assert!(failed.is_empty(), "{failed:?}");
    }

    fn built_after_cut(state: &CapsuleState) -> Value {
        cut(state);
        built(state).unwrap_or_else(|e| panic!("{e:?}"))
    }

    /// A checkpoint that stops short of the report does not cover the deal;
    /// once one does, a later checkpoint changes nothing in the bundle.
    #[test]
    fn the_earliest_covering_checkpoint_is_used() {
        let (_dir, state) = node(false);
        cut(&state);
        finish(&state);
        assert!(matches!(
            built(&state),
            Err(Error::Refused(Refusal::NotCheckpointed))
        ));
        cut(&state);
        let first = built(&state).unwrap_or_else(|e| panic!("{e:?}"));
        state
            .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("node-b"))
            .unwrap();
        cut(&state);
        assert_eq!(built(&state).unwrap_or_else(|e| panic!("{e:?}")), first);
    }
}
