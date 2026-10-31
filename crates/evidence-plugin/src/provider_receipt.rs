//! `GET provider-receipt-bundle`: the provider's own receipt for one paid
//! exchange it served, as an Evidence Bundle that capsule-viewer renders
//! (Mesh-LLM/capsules-plugin#134; Steven's ruling on #146: each side keeps its
//! half, and the counterparty's receipt is what its half says: the model and
//! what was paid, never the inference content).
//!
//! It is not a deal. The provider's half is the records it already seals: the
//! exchange record it served (`x-mesh-poc-v1`, role `served`: the model, the
//! digests) and its `payee_observed` settlement legs (what it received). The
//! typed seller deal the profile asks of a seller needs an offer, an
//! acceptance and an authority this node does not make, so none is sealed.
//!
//! Which legs belong to which exchange is the node's own note
//! ([`PROVIDER_LINKS_FILE`], the payment hash, written before the leg is
//! sealed): a leg names no exchange itself. The bundle is owner-only and producer-selected, like the
//! payer's ([`crate::deal_receipt`]); it carries those records and no
//! payload, so the digests stay and no inference content or payer identity
//! beyond what the records name is in it.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::checkpoint_cadence::CheckpointHandle;
use crate::deal_receipt::{selected_bundle, Error, Selection};
use crate::evidence_log::{self, LedgerIndex};

/// One `{"exchange_id", "payment_hash"}` line per payment this node received
/// and sealed a `payee_observed` leg for: the host's exchange id it was for.
pub const PROVIDER_LINKS_FILE: &str = "provider-links.jsonl";

/// Why no bundle is given.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No payment this node received is noted for that exchange.
    NoPayment,
    /// The exchange record this node served is not in its ledger (or not
    /// the only one).
    NoExchange,
    /// No signed checkpoint covers the records yet.
    NotCheckpointed,
}

impl Refusal {
    fn why(&self) -> &'static str {
        match self {
            Refusal::NoPayment => "this node noted no payment received for that exchange",
            Refusal::NoExchange => "this node holds no single served record for that exchange",
            Refusal::NotCheckpointed => "no signed checkpoint covers the records yet",
        }
    }
}

/// What building the bundle ran into.
#[derive(Debug)]
pub enum Failure {
    Refused(Refusal),
    Failed(String),
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        match e {
            // The shared builder refuses for one reason only: no checkpoint.
            Error::Refused(_) => Failure::Refused(Refusal::NotCheckpointed),
            Error::Failed(why) => Failure::Failed(why),
        }
    }
}

impl From<Refusal> for Failure {
    fn from(r: Refusal) -> Self {
        Failure::Refused(r)
    }
}

/// Note that the payment `payment_hash` was received for `exchange_id`. A
/// last line a crash cut short is ended first (the deal flow's append).
pub fn note_payment(
    ledger_dir: &Path,
    exchange_id: &str,
    payment_hash: &str,
) -> std::io::Result<()> {
    // One writer at a time: the append ends a torn last line first, which two
    // concurrent appends would mistake for each other's unfinished line.
    static WRITER: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    crate::deal_flow::append_line(
        &ledger_dir.join(PROVIDER_LINKS_FILE),
        &json!({"exchange_id": exchange_id, "payment_hash": payment_hash}),
    )
}

/// The legs for `exchange_id`: the `payee_observed` records whose payment
/// hash is one noted for it, in ledger order. Read from the capsules file
/// off the index lock, parsing only lines that name a noted hash.
fn legs_of(ledger_dir: &Path, exchange_id: &str) -> std::io::Result<Vec<String>> {
    let notes = match std::fs::read(ledger_dir.join(PROVIDER_LINKS_FILE)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut hashes: Vec<String> = Vec::new();
    for line in notes.split(|b| *b == b'\n') {
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if v.get("exchange_id").and_then(Value::as_str) != Some(exchange_id) {
            continue;
        }
        if let Some(hash) = v.get("payment_hash").and_then(Value::as_str) {
            if !hashes.iter().any(|h| h == hash) {
                hashes.push(hash.to_string());
            }
        }
    }
    if hashes.is_empty() {
        return Ok(Vec::new());
    }
    let ledger = match std::fs::File::open(ledger_dir.join(evidence_log::CAPSULES_FILE)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    // Streamed, a line at a time: the ledger grows without bound.
    let mut reader = std::io::BufReader::new(ledger);
    let mut legs = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if std::io::BufRead::read_until(&mut reader, b'\n', &mut line)? == 0 {
            break;
        }
        let text = String::from_utf8_lossy(&line);
        if !hashes.iter().any(|h| text.contains(h.as_str())) {
            continue;
        }
        let Ok(capsule) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let leg = capsule.get("settlement");
        let paid = leg
            .and_then(|l| l.pointer("/payment_ref/value"))
            .and_then(Value::as_str);
        if leg.and_then(|l| l.get("leg")).and_then(Value::as_str) == Some("payee_observed")
            && paid.is_some_and(|p| hashes.iter().any(|h| h == p))
        {
            if let Some(id) = capsule.get("capsule_id").and_then(Value::as_str) {
                legs.push(id.to_string());
            }
        }
    }
    Ok(legs)
}

/// The single exchange record this node served for the host's `exchange_id`:
/// a record with the mesh exchange block (`x-mesh-poc-v1`) that names that id
/// as its own and is not marked as the requester's side. The lifecycle and
/// settlement records the node seals for the same id are not it.
fn served_record(index: &LedgerIndex, exchange_id: &str) -> Option<String> {
    let view = index.view().ok()?;
    let mut served = index.correlated(exchange_id).iter().filter_map(|&i| {
        let record = view.record_at(i)?;
        let capsule: Value = serde_json::from_slice(&record.body).ok()?;
        let poc = capsule.pointer("/model_attestation/compute_attestation/x-mesh-poc-v1")?;
        let named = poc
            .pointer("/serving_provenance/exchange_id")
            .and_then(Value::as_str);
        (named == Some(exchange_id) && crate::evidence_panes::label_role(&capsule) == "served")
            .then_some(record.digest)
    });
    let first = served.next()?;
    served.next().is_none().then_some(first)
}

/// The provider's receipt bundle for the host's `exchange_id`.
pub fn bundle(ledger_dir: &Path, node_key_id: &str, exchange_id: &str) -> Result<Value, Failure> {
    let unreadable =
        |e: std::io::Error| Failure::Failed(format!("the ledger is not readable: {e}"));
    let noted = legs_of(ledger_dir, exchange_id).map_err(unreadable)?;
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        let legs: Vec<String> = noted
            .into_iter()
            .filter(|id| index.leaf_index_of(id).is_some())
            .collect();
        if legs.is_empty() {
            return Err(Refusal::NoPayment.into());
        }
        let exchange = served_record(index, exchange_id).ok_or(Refusal::NoExchange)?;
        let mut ids = vec![exchange.clone()];
        ids.extend(legs);
        Ok(selected_bundle(
            index,
            node_key_id,
            Selection {
                root: &exchange,
                ids: &ids,
                disclosures: BTreeMap::new(),
                extensions: Map::new(),
            },
        )?)
    })
    .map_err(unreadable)?
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProviderReceiptArgs {
    /// The host's exchange id (the Logs request's).
    pub exchange_id: Value,
}

/// `{"state": "bundle", "bundle": ...}`, or `{"state": "refused", "why": ...}`.
pub fn answer(ledger_dir: &Path, node_key_id: &str, exchange_id: &Value) -> Result<Value, String> {
    let Some(id) = exchange_id
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
    else {
        return Err("exchange_id must be a non-empty string".into());
    };
    match bundle(ledger_dir, node_key_id, id) {
        Ok(bundle) => Ok(json!({"state": "bundle", "bundle": bundle})),
        Err(Failure::Refused(r)) => Ok(json!({"state": "refused", "why": r.why()})),
        Err(Failure::Failed(why)) => Err(why),
    }
}

/// `builder` with the `provider-receipt-bundle` route declared. A checkpoint
/// is cut first when none covers the records yet (this may write to the log
/// and contact witnesses).
pub fn with_route(
    builder: DeclarativePluginBuilder,
    capsules: Arc<crate::capsule_emit::CapsuleState>,
    checkpoints: Option<CheckpointHandle>,
) -> DeclarativePluginBuilder {
    builder.http_item(
        http::get("/provider-receipt-bundle")
            .binding_id("evidence_provider_receipt_bundle")
            .description(
                "The provider's own receipt for one paid exchange it served: the model and what \
                 it received, for the viewer to render. Cuts a signed checkpoint when none \
                 covers the records yet.",
            )
            .input::<ProviderReceiptArgs>()
            .handle(move |args, _context| {
                let capsules = capsules.clone();
                let checkpoints = checkpoints.clone();
                Box::pin(async move {
                    let ledger_dir = capsules.ledger_dir().to_path_buf();
                    let node_key_id = crate::commitment::key_id(capsules.signing_key());
                    let exchange = args.exchange_id;
                    // The ledger is read off the async threads.
                    let last = {
                        let (dir, key, id) =
                            (ledger_dir.clone(), node_key_id.clone(), exchange.clone());
                        tokio::task::spawn_blocking(move || last_record(&dir, &key, &id))
                            .await
                            .ok()
                            .flatten()
                    };
                    if let (Some(handle), Some(last)) = (checkpoints.as_ref(), last) {
                        let _ = handle.coverage_for(&last).await;
                    }
                    tokio::task::spawn_blocking(move || {
                        answer(&ledger_dir, &node_key_id, &exchange)
                    })
                    .await
                    .map_err(|error| {
                        PluginError::internal(format!(
                            "provider receipt task did not complete: {error}"
                        ))
                    })?
                    .map_err(PluginError::internal)
                })
            }),
    )
}

/// The last-sealed of the records the bundle would carry, which a covering
/// checkpoint must reach.
fn last_record(ledger_dir: &Path, node_key_id: &str, exchange: &Value) -> Option<String> {
    let exchange_id = exchange.as_str()?;
    let noted = legs_of(ledger_dir, exchange_id).ok()?;
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        let mut ids = noted;
        ids.extend(served_record(index, exchange_id));
        ids.into_iter()
            .filter_map(|id| Some((index.leaf_index_of(&id)?, id)))
            .max()
            .map(|(_, id)| id)
    })
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule_emit::CapsuleState;
    use crate::deal_receipt::tests::cut;
    use crate::settlement_legs::tests::{dirs, two_nodes, WALLET};

    const HOST_EXCHANGE: &str = "p-ex";

    /// A provider that served an exchange for the host id `p-ex` and received
    /// its two payments (the legs `two_nodes` seals on node b).
    fn provider(dir: &Path) -> (CapsuleState, String) {
        let (a, _) = (tempfile::tempdir().unwrap(), ());
        two_nodes(a.path(), dir, WALLET);
        let state = CapsuleState::open(dir, "provider-node").unwrap();
        let mut served = crate::capsule_emit::tests::sample_exchange("payer-node");
        served.exchange_id = Some(HOST_EXCHANGE);
        let exchange = state.emit_for_exchange(&served).unwrap().capsule_id;
        (state, exchange)
    }

    fn key(state: &CapsuleState) -> String {
        crate::commitment::key_id(state.signing_key())
    }

    #[test]
    fn the_provider_gets_its_served_record_and_the_legs_it_noted_and_nothing_else() {
        let (_a, dir) = dirs();
        let (state, exchange) = provider(dir.path());
        // A later, unrelated record is not carried.
        state
            .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("someone-else"))
            .unwrap();
        cut(&state);
        let bundle = bundle(state.ledger_dir(), &key(&state), HOST_EXCHANGE)
            .unwrap_or_else(|e| panic!("{e:?}"));
        let records = bundle["records"].as_array().unwrap();
        assert_eq!(records.len(), 3, "the served record and two legs");
        assert_eq!(bundle["root"], json!(exchange));
        let legs: Vec<&Value> = records
            .iter()
            .filter(|r| r.get("settlement").is_some())
            .collect();
        assert_eq!(legs.len(), 2);
        // What the provider received is in the legs, with its unit.
        assert!(legs
            .iter()
            .any(|l| l["settlement"]["received"]["value"] == json!("995")));
        // 1 msat is 1e-11 BTC: the unit is in the amount (assetCode, assetScale).
        assert!(legs.iter().all(|l| {
            l["settlement"]["received"]["assetCode"] == json!("BTC")
                && l["settlement"]["received"]["assetScale"] == json!(11)
        }));
        // No payload is disclosed: the digests stay, no inference content.
        assert!(bundle["disclosures"]
            .as_object()
            .is_none_or(|d| d.is_empty()));
        crate::deal_receipt::tests::assert_selection_only(&bundle);
        let text = serde_json::to_string(&bundle).unwrap();
        assert!(!text.contains("hello"), "no response text");
        assert!(!text.contains("\"content\":\"hi\""), "no prompt text");
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
        assert!(statuses
            .iter()
            .all(|(n, s)| *s == "pass" || (*n == "interval_coverage" && *s == "withheld")));
        if let Some(out) = std::env::var_os("PROVIDER_RECEIPT_BUNDLE_OUT") {
            std::fs::write(out, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
        }
    }

    #[test]
    fn no_payment_no_served_record_and_no_checkpoint_are_refusals() {
        let (_a, dir) = dirs();
        let (state, _) = provider(dir.path());
        let ask = |id: &str| bundle(state.ledger_dir(), &key(&state), id);
        // Not yet checkpointed.
        assert!(matches!(
            ask(HOST_EXCHANGE),
            Err(Failure::Refused(Refusal::NotCheckpointed))
        ));
        cut(&state);
        assert!(ask(HOST_EXCHANGE).is_ok());
        assert!(matches!(
            ask("unknown"),
            Err(Failure::Refused(Refusal::NoPayment))
        ));
        // A payment noted for an exchange this node holds no served record for.
        note_payment(state.ledger_dir(), "orphan", &"a".repeat(64)).unwrap();
        assert!(matches!(
            ask("orphan"),
            Err(Failure::Refused(Refusal::NoPayment))
        ));
    }

    #[test]
    fn the_route_answer_names_a_refusal_and_rejects_an_empty_id() {
        let (_a, dir) = dirs();
        let (state, _) = provider(dir.path());
        let answered = answer(state.ledger_dir(), &key(&state), &json!("unknown")).unwrap();
        assert_eq!(answered["state"], "refused");
        assert!(answer(state.ledger_dir(), &key(&state), &json!("")).is_err());
        assert!(answer(state.ledger_dir(), &key(&state), &json!(7)).is_err());
    }

    /// A note cut short by a crash does not swallow the next one, and a
    /// payment noted twice (a replay) is one leg.
    #[test]
    fn a_torn_note_and_a_replayed_note_cost_no_leg() {
        let (_a, dir) = dirs();
        let (state, _) = provider(dir.path());
        cut(&state);
        let before = bundle(state.ledger_dir(), &key(&state), HOST_EXCHANGE).unwrap();
        let notes = state.ledger_dir().join(PROVIDER_LINKS_FILE);
        // The file as a crash left it: the last line cut short.
        let mut raw = std::fs::read(&notes).unwrap();
        raw.extend_from_slice(br#"{"exchange_id":"p-ex","payment_ha"#);
        std::fs::write(&notes, raw).unwrap();
        let hash = std::fs::read_to_string(&notes)
            .unwrap()
            .lines()
            .next()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["payment_hash"].clone())
            .unwrap();
        note_payment(state.ledger_dir(), HOST_EXCHANGE, hash.as_str().unwrap()).unwrap();
        note_payment(state.ledger_dir(), "later", &"b".repeat(64)).unwrap();
        let after = bundle(state.ledger_dir(), &key(&state), HOST_EXCHANGE).unwrap();
        assert_eq!(after["records"], before["records"], "still the same legs");
        assert_eq!(
            legs_of(state.ledger_dir(), "later").unwrap(),
            Vec::<String>::new()
        );
        let lines: Vec<_> = std::fs::read_to_string(&notes)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert!(
            lines.iter().any(|l| l.contains("\"later\"")),
            "the line after the torn one is whole"
        );
    }

    /// Two records served under one exchange id are not one exchange: no
    /// receipt picks between them.
    #[test]
    fn two_served_records_for_one_exchange_id_are_refused() {
        let (_a, dir) = dirs();
        let (state, _) = provider(dir.path());
        let mut again = crate::capsule_emit::tests::sample_exchange("payer-node");
        again.exchange_id = Some(HOST_EXCHANGE);
        state.emit_for_exchange(&again).unwrap();
        cut(&state);
        assert!(matches!(
            bundle(state.ledger_dir(), &key(&state), HOST_EXCHANGE),
            Err(Failure::Refused(Refusal::NoExchange))
        ));
    }

    /// Notes written from several threads at once are each whole lines.
    #[test]
    fn concurrent_notes_are_each_a_whole_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let workers: Vec<_> = (0..8)
            .map(|w| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        note_payment(&path, &format!("ex-{w}"), &format!("{w:02}{i:062}")).unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let lines = std::fs::read_to_string(path.join(PROVIDER_LINKS_FILE)).unwrap();
        assert_eq!(lines.lines().count(), 200);
        assert!(lines
            .lines()
            .all(|l| serde_json::from_str::<Value>(l).is_ok()));
    }
}
