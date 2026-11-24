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
    /// An interval-complete bundle would cross a padding record. A padding
    /// record is not a Capsule; agent-action-capsule 0.7 carries it only as a
    /// `non_record_leaves` entry (Bundle -02, #339), and that emission stays
    /// off (`carry_non_record_leaves`) until capsulectl, the hosted verify
    /// page and evidencebook check it (Steven's ruling u532, on the Q3
    /// rollout gate), so the producer refuses such an interval.
    PaddingInInterval,
}

impl Refusal {
    fn why(&self) -> String {
        match self {
            Refusal::NoDeal => "this node holds no deal for that exchange".into(),
            Refusal::NotReported => "the deal has no report yet".into(),
            Refusal::PayloadMissing(id) => format!("the payload of deal record {id} is not kept"),
            Refusal::NotCheckpointed => "no signed checkpoint covers the deal yet".into(),
            Refusal::PaddingInInterval => "the ledger holds a padding record in the interval; \
                this plugin does not yet put padding in an Evidence Bundle (non_record_leaves, \
                Bundle -02), so the receipt waits until the verifiers can check it"
                .into(),
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
pub(crate) struct LogSource<'a> {
    index: &'a LedgerIndex,
    view: LogView<'a>,
    statement: Vec<u8>,
    size: u64,
}

impl<'a> LogSource<'a> {
    /// The log as `checkpoint`, one of `index`'s, states it.
    pub(crate) fn at(
        index: &'a LedgerIndex,
        checkpoint: &evidence_log::ChainCheckpoint,
    ) -> std::io::Result<Self> {
        Ok(LogSource {
            index,
            view: index.view()?,
            statement: checkpoint.statement.clone(),
            size: checkpoint.record.mmr_size,
        })
    }
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
    let source = LogSource::at(index, covering).map_err(unreadable)?;
    if let Some(first) = interval_from {
        let covered = leaf_count(covering.record.mmr_size).map_or(0, |n| n as usize);
        let from = usize::try_from(first - 1).unwrap_or(usize::MAX);
        if index
            .leaves
            .iter()
            .take(covered)
            .skip(from)
            .any(|leaf| leaf.padding)
        {
            return Err(Refusal::PaddingInInterval.into());
        }
    }
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
            return Err(Error::Failed(DEAL_CHANGED.into()));
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

/// A receipt route's answer for a bundle: `bundle` is the bundle's JSON text,
/// the exact bytes the node serves, so a page that embeds it hands a verifier
/// those bytes unchanged (Mesh-LLM/capsules-plugin#96). Shared by the three
/// receipt routes.
pub(crate) fn bundle_answer(bundle: &Value) -> Value {
    json!({"state": "bundle", "bundle": bundle.to_string()})
}

/// The route's answer: `{"state": "bundle", "bundle": "<JSON text>"}`, or
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
        Ok(bundle) => Ok(bundle_answer(&bundle)),
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

/// What a bundle build says when the deal's records moved while it was read;
/// `receipt_lines` retries on exactly this.
const DEAL_CHANGED: &str = "the deal changed while it was read; ask again";

/// One line of `capsules deal-receipts`: a deal this node holds, either with
/// its receipt bundle (JSON text, as the route serves it) or held back by the
/// share policy. The shape the report builder reads (evidencebook#764):
/// `{"exchange_capsule_id", "receipt"}`, `{"exchange_capsule_id", "held": true}`
/// or, for a deal with no report (it had not closed), `{"exchange_capsule_id",
/// "not_closed": true}`, whatever `hold` says: nothing is read for it.
///
/// `exchanges` maps the exchange capsule ids on the page's chain to their
/// timestamps, so a receipt of a deal outside it is never built. With `hold`
/// set no payload is read and no bundle is built: every deal with a report is
/// `held`
/// (`hold` is why), and `diagnostics` says so. A deal whose payload the
/// journal lacks or that kept changing while it was read is left out and says
/// so on `diagnostics`.
///
/// A deal that has a report but no covering checkpoint *yet* and is on or
/// before `through` (a `YYYY-MM-DD`; none means every deal) fails the call and
/// is named: the next checkpoint clears it, and a page built without it would
/// read "Receipt not carried with this page", which capsule-viewer#351 locked
/// to mean the page was built wrong (Sherlock2, #337). A deal after `through`
/// is not on the report's page and is left out. A deal that has no report
/// (not closed: waiting for one could block every later report) is a
/// `not_closed` line. Any other refusal is left out and says why on
/// `diagnostics`. Any other failure to read the ledger or
/// build the bundle fails the call too, so a report is never sealed silently
/// missing a deal's receipt. A receipt is never built by cutting a
/// checkpoint: the route does that, this reads what exists.
pub(crate) fn receipt_lines(
    ledger_dir: &Path,
    node_key_id: &str,
    exchanges: &std::collections::HashMap<String, String>,
    through: Option<&str>,
    hold: Option<&str>,
    diagnostics: &mut dyn std::io::Write,
) -> std::io::Result<Vec<Value>> {
    let held: Vec<(String, bool)> = evidence_log::with_index(ledger_dir, node_key_id, |index| {
        index
            .deal_exchanges()
            .into_iter()
            .filter(|id| exchanges.contains_key(*id))
            .map(|id| (id.to_string(), index.deal_has_report(id)))
            .collect()
    })?;
    let mut lines = Vec::new();
    let mut not_ready = Vec::new();
    for (exchange, closed) in held {
        if !closed {
            // No report: the deal had not closed when this was read, so there
            // is no receipt to carry and none to hold back. The page says so
            // (capsule-viewer#358; evidencebook#786), not "held by policy". A
            // deal after `through` is not on the page: not asked about, so a
            // capsulectl without `not_closed` is never handed one for today's
            // still-open deals.
            let day = exchanges[&exchange].get(..10).unwrap_or("");
            if through.is_none_or(|through| day <= through) {
                lines.push(json!({"exchange_capsule_id": exchange, "not_closed": true}));
            }
            continue;
        }
        if let Some(why) = hold {
            // Said once per deal, so a held receipt is never taken for a
            // missing one.
            writeln!(
                diagnostics,
                "deal-receipts: exchange {exchange}: held: {why}"
            )?;
            lines.push(json!({"exchange_capsule_id": exchange, "held": true}));
            continue;
        }
        let mut built = bundle(ledger_dir, node_key_id, &exchange);
        if matches!(&built, Err(Error::Failed(why)) if why == DEAL_CHANGED) {
            built = bundle(ledger_dir, node_key_id, &exchange);
        }
        match built {
            Ok(bundle) => lines.push(json!({
                "exchange_capsule_id": exchange,
                "receipt": bundle.to_string(),
            })),
            Err(Error::Refused(Refusal::PayloadMissing(id))) => {
                writeln!(
                    diagnostics,
                    "deal-receipts: exchange {exchange}: the payload of deal record {id} is not kept; no receipt"
                )?;
            }
            Err(Error::Refused(Refusal::NotCheckpointed)) => {
                let day = exchanges[&exchange].get(..10).unwrap_or("");
                if through.is_none_or(|through| day <= through) {
                    not_ready.push(exchange);
                }
            }
            Err(Error::Refused(other)) => {
                writeln!(
                    diagnostics,
                    "deal-receipts: exchange {exchange}: {}; no receipt",
                    other.why()
                )?;
            }
            // The deal kept moving under a running node: left out, said so.
            Err(Error::Failed(why)) if why == DEAL_CHANGED => {
                writeln!(
                    diagnostics,
                    "deal-receipts: exchange {exchange}: {why}; no receipt"
                )?;
            }
            // The ledger could not be read or the bundle not built: never seal
            // a report that is silently missing this deal's receipt.
            Err(Error::Failed(why)) => {
                return Err(std::io::Error::other(format!("exchange {exchange}: {why}")));
            }
        }
    }
    if !not_ready.is_empty() {
        return Err(std::io::Error::other(format!(
            "the receipt of {} is not ready: no signed checkpoint covers the deal yet; run again after the next one",
            not_ready.join(", ")
        )));
    }
    Ok(lines)
}

/// The node's own key id, read from `<data_dir>/keys/node-key.pem` without
/// creating anything: a wrong `--data-dir` is an error, never a new key.
fn read_node_key_id(data_dir: &Path) -> Result<String, String> {
    let path = data_dir.join("keys").join("node-key.pem");
    let pem = std::fs::read_to_string(&path)
        .map_err(|e| format!("the node's key is not readable at {}: {e}", path.display()))?;
    let key = crate::producer::keys::load_signing_key_pem(&pem).map_err(|e| {
        format!(
            "the node's key at {} is not an Ed25519 PKCS#8 key: {e}",
            path.display()
        )
    })?;
    // The `key_id` form the ledger index and every checkpoint carry (the raw
    // public key in hex), not capsule-emit's short fingerprint.
    Ok(crate::commitment::key_id(&key))
}

/// What `capsules deal-receipts --help` says (Sherlock2's condition, ops
/// a2eadf09: the help names its job, and that the owner's own copy is not
/// gated). There is no flag that carries a receipt against the setting.
const HELP: &str = "Feeds the settlement report (scripts/settlement-report.sh --with-receipts): \
prints one JSON line per deal on the chain snapshot FILE, either its receipt \
bundle, {\"held\": true}, or {\"not_closed\": true} for a deal with no report \
yet (nothing to carry or hold back, whatever the setting). A receipt is carried only when this node's \
share_settlement_receipts setting is on (and share_record_at_completion is not \
off); otherwise every deal with a report is held and each says why on stderr. There is no \
flag to override that. A deal on or before --through (a day, YYYY-MM-DD) whose \
receipt is not ready yet (no signed checkpoint covers it) fails the command \
and is named; run again later. It reads without the node's lock.\n\n\
Your own copy of a receipt is not affected by the setting: the node's local \
deal-receipt-bundle route has no share gate.";

/// `capsules deal-receipts --chain FILE [--data-dir DIR]`: write one
/// [`receipt_lines`] line per deal whose exchange capsule is on the chain
/// snapshot `FILE` (the `capsules chain-lines` output the settlement report
/// reads), to stdout. Reads the ledger without the node's writer lock, so it
/// runs beside a running node. Whether receipts may be carried is this
/// process's own `share_settlement_receipts` (the node's console or
/// environment), the one resolver the node uses. Exit 0 on success, 2 for a
/// usage error, 1 when the ledger or key cannot be read.
pub fn cli(args: &[String]) -> i32 {
    const USAGE: &str =
        "usage: capsules deal-receipts --chain FILE [--data-dir DIR] [--through YYYY-MM-DD]";
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}\n\n{HELP}");
        return 0;
    }
    let (mut chain, mut data_dir, mut through) = (None, None, None::<String>);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match (arg.as_str(), rest.next()) {
            ("--chain", Some(v)) if !v.is_empty() => chain = Some(std::path::PathBuf::from(v)),
            ("--data-dir", Some(v)) if !v.is_empty() => {
                data_dir = Some(std::path::PathBuf::from(v))
            }
            ("--through", Some(v)) if v.len() == 10 => through = Some(v.clone()),
            _ => {
                eprintln!("deal-receipts: {USAGE}");
                return 2;
            }
        }
    }
    let Some(chain) = chain else {
        eprintln!("deal-receipts: {USAGE}");
        return 2;
    };
    let exchanges: std::collections::HashMap<String, String> = match std::fs::read_to_string(&chain)
    {
        Ok(text) => text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| {
                let id = v.get("capsule_id").and_then(Value::as_str)?;
                let at = v.get("timestamp").and_then(Value::as_str).unwrap_or("");
                Some((id.to_string(), at.to_string()))
            })
            .collect(),
        Err(e) => {
            eprintln!("deal-receipts: {}: {e}", chain.display());
            return 1;
        }
    };
    let data_dir = match data_dir.map_or_else(crate::data_dir::data_dir, Ok) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("deal-receipts: {e:#}");
            return 1;
        }
    };
    let key_id = match read_node_key_id(&data_dir) {
        Ok(id) => id,
        Err(why) => {
            eprintln!("deal-receipts: {why}");
            return 1;
        }
    };
    let hold = crate::share_policy::settlement_receipts_hold_reason();
    let lines = match receipt_lines(
        &data_dir.join("ledger"),
        &key_id,
        &exchanges,
        through.as_deref(),
        hold,
        &mut std::io::stderr(),
    ) {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("deal-receipts: {e}");
            return 1;
        }
    };
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    for line in lines {
        if writeln!(out, "{line}").is_err() {
            return 1;
        }
    }
    i32::from(out.flush().is_err())
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

    const EXCHANGE_ID: &str = "exchange-1";
    pub(crate) const PEER: &str = "peer-node-with-a-distinct-name";

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
        let (mut checkpoints, _) = crate::chain_store::test_load(&ledger, "test-log").unwrap();
        let last = crate::chain_store::read_chain_string(&ledger)
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

    const HELD: Option<&str> = Some("share_settlement_receipts is off");
    /// The exchange capsule's timestamp on the chain snapshot.
    const AT: &str = "2026-11-01T10:00:00Z";

    fn lines_for(
        state: &CapsuleState,
        on_chain: &[String],
        hold: Option<&str>,
    ) -> (Vec<Value>, String) {
        let exchanges = on_chain
            .iter()
            .map(|id| (id.clone(), AT.to_string()))
            .collect();
        let mut diagnostics = Vec::new();
        let lines = receipt_lines(
            state.ledger_dir(),
            &crate::commitment::key_id(state.signing_key()),
            &exchanges,
            None,
            hold,
            &mut diagnostics,
        )
        .unwrap();
        (lines, String::from_utf8(diagnostics).unwrap())
    }

    /// The command's own key read, not the tests' shortcut: the id it takes
    /// from `<data dir>/keys/node-key.pem` must be the one the ledger index and
    /// the checkpoints carry, or no deal ever has a covering checkpoint.
    #[test]
    fn the_key_read_from_the_data_dir_gives_a_receipt_on_a_real_node() {
        let (dir, state) = node(true);
        cut(&state);
        let key_id = read_node_key_id(dir.path()).unwrap();
        assert_eq!(key_id, crate::commitment::key_id(state.signing_key()));
        let exchanges = [(exchange_capsule(), AT.to_string())].into_iter().collect();
        let lines = receipt_lines(
            &dir.path().join("ledger"),
            &key_id,
            &exchanges,
            None,
            None,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].get("receipt").is_some(), "{lines:?}");
        // No key there: refused, and nothing is created.
        let empty = tempfile::tempdir().unwrap();
        assert!(read_node_key_id(empty.path()).is_err());
        assert!(!empty.path().join("keys").exists());
    }

    #[test]
    fn a_receipt_line_carries_the_bundle_the_route_serves() {
        let (_dir, state) = node(true);
        cut(&state);
        let (lines, diagnostics) = lines_for(&state, &[exchange_capsule()], None);
        assert_eq!(diagnostics, "");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["exchange_capsule_id"], json!(exchange_capsule()));
        assert!(lines[0].get("held").is_none());
        let key = crate::commitment::key_id(state.signing_key());
        let served = answer(state.ledger_dir(), &key, &json!(exchange_capsule())).unwrap();
        assert_eq!(lines[0]["receipt"], served["bundle"]);
    }

    /// Held by policy: no bundle is built, so none is read, and the line
    /// says only that the deal exists. No checkpoint covers the deal here,
    /// which would make a bundle refuse: held does not depend on it.
    #[test]
    fn a_policy_held_deal_is_a_held_line_and_no_bundle_is_built() {
        let (_dir, state) = node(true);
        let (lines, diagnostics) = lines_for(&state, &[exchange_capsule()], HELD);
        assert_eq!(
            diagnostics,
            format!(
                "deal-receipts: exchange {}: held: share_settlement_receipts is off\n",
                exchange_capsule()
            ),
            "a held deal says why"
        );
        assert_eq!(
            lines,
            vec![json!({"exchange_capsule_id": exchange_capsule(), "held": true})]
        );
        // The payload journal is not even needed.
        std::fs::remove_file(state.ledger_dir().join(crate::deal_flow::PAYLOADS_FILE)).ok();
        let (again, _) = lines_for(&state, &[exchange_capsule()], HELD);
        assert_eq!(again, lines);
    }

    /// The page must never read "Receipt not carried with this page" (locked in
    /// capsule-viewer#351 to mean "built wrong") for a deal that is only not
    /// checkpointed yet, so such a deal on the page fails the call and is named; a deal after the report's day, or off the chain, is not asked about.
    #[test]
    fn a_deal_on_the_page_with_no_receipt_yet_fails_the_call_and_is_named() {
        let key = |state: &CapsuleState| crate::commitment::key_id(state.signing_key());
        let ask = |state: &CapsuleState, id: &str, through: Option<&str>, hold| {
            let exchanges = [(id.to_string(), AT.to_string())].into_iter().collect();
            receipt_lines(
                state.ledger_dir(),
                &key(state),
                &exchanges,
                through,
                hold,
                &mut Vec::new(),
            )
        };
        // Sealed and delivered, but no checkpoint covers it yet.
        let (_dir, state) = node(true);
        for through in [None, Some("2026-11-01"), Some("2026-12-31")] {
            let why = ask(&state, &exchange_capsule(), through, None)
                .unwrap_err()
                .to_string();
            assert!(
                why.contains(&exchange_capsule()) && why.contains("not ready"),
                "{why}"
            );
        }
        // After the report's day, it is not on the page.
        assert!(ask(&state, &exchange_capsule(), Some("2026-10-31"), None)
            .unwrap()
            .is_empty());
        // A deal that has not closed has no report and may never get one, so it
        // must not block every later report: it is a `not_closed` entry (the
        // page says "No receipt: this deal had not closed", capsule-viewer#358),
        // never `held` (which says the owner chose to hold it back), whatever
        // the setting, and with nothing read.
        let (_dir2, open) = node(false);
        cut(&open);
        for hold in [None, HELD] {
            let (lines, said) = lines_for(&open, &[exchange_capsule()], hold);
            assert_eq!(
                lines,
                vec![json!({"exchange_capsule_id": exchange_capsule(), "not_closed": true})]
            );
            assert_eq!(said, "");
        }
        // The index's answer, pinned directly: a linked capsule that never
        // leaves the node is the report, and only the report is one.
        let key_id = key(&open);
        let closed = |state: &CapsuleState| {
            evidence_log::with_index(state.ledger_dir(), &key(state), |index| {
                index.deal_has_report(&exchange_capsule())
            })
            .unwrap()
        };
        assert!(!closed(&open));
        assert!(closed(&state), "{key_id}");
        // After the report's day an open deal is not on the page: no line.
        let exchanges = [(exchange_capsule(), AT.to_string())].into_iter().collect();
        let later = receipt_lines(
            open.ledger_dir(),
            &key(&open),
            &exchanges,
            Some("2026-10-31"),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(later.is_empty(), "{later:?}");
        // Off the chain snapshot: never read, held or not.
        cut(&state);
        assert!(ask(&state, &hex64('9'), None, None).unwrap().is_empty());
        assert!(ask(&state, &hex64('9'), None, HELD).unwrap().is_empty());
        // Once checkpointed, the receipt is carried.
        assert_eq!(
            ask(&state, &exchange_capsule(), None, None).unwrap().len(),
            1
        );
    }

    #[test]
    fn an_unreadable_ledger_fails_the_call_instead_of_leaving_the_deal_out() {
        let (_dir, state) = node(true);
        cut(&state);
        // A journal that cannot be read (a directory where the file is).
        let journal = state.ledger_dir().join(crate::deal_flow::PAYLOADS_FILE);
        std::fs::remove_file(&journal).unwrap();
        std::fs::create_dir(&journal).unwrap();
        let exchanges = [(exchange_capsule(), AT.to_string())].into_iter().collect();
        let result = receipt_lines(
            state.ledger_dir(),
            &crate::commitment::key_id(state.signing_key()),
            &exchanges,
            None,
            None,
            &mut Vec::new(),
        );
        let why = result.unwrap_err().to_string();
        assert!(why.contains("not readable"), "{why}");
    }

    #[test]
    fn a_missing_deal_payload_leaves_the_deal_out_and_says_so() {
        let (_dir, state) = node(true);
        cut(&state);
        // Drop one deal record that is not a report from the payload journal.
        let journal = state.ledger_dir().join(crate::deal_flow::PAYLOADS_FILE);
        let text = std::fs::read_to_string(&journal).unwrap();
        let first = text
            .lines()
            .position(|l| !l.contains(&format!("\"{}\"", deal::REPORT_TYPE)))
            .unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter_map(|(i, l)| (i != first).then_some(l))
            .collect();
        assert!(
            kept.len() < text.lines().count(),
            "a baseline line was dropped"
        );
        std::fs::write(&journal, kept.join("\n") + "\n").unwrap();
        let (lines, diagnostics) = lines_for(&state, &[exchange_capsule()], None);
        assert!(lines.is_empty());
        assert!(
            diagnostics.contains("not kept; no receipt"),
            "{diagnostics}"
        );
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
        // deal-view's opening-step rule for a keep report: `asked_step` names
        // a disclosed record whose block says `baseline`.
        let asked = report_payload["report"]["asked_step"].as_str().unwrap();
        assert!(carried.contains(&asked));
        assert_eq!(
            bundle["disclosures"][asked]["agent_input"]["x-deal-v0"]["record_type"],
            "baseline"
        );

        // Every claim passes but the interval: the bundle is producer-selected,
        // so what the log holds besides these records is not shown.
        let checked = agent_action_capsule::bundle::verify_bundle_strict(
            &bundle,
            &agent_action_capsule::bundle::StrictOptions {
                require_signature: true,
                witness_directory: None,
                ..Default::default()
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
        // The bundle is served as its JSON text, and that text is the bundle.
        let text = answered["bundle"].as_str().unwrap();
        let served: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            served,
            bundle(state.ledger_dir(), &key, &exchange_capsule()).unwrap()
        );
        assert_eq!(text, served.to_string());
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
                ..Default::default()
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
