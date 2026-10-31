//! A payer's catch-up of its earlier `mesh/settlement/terms` legs that went
//! to the provider uncovered (Mesh-LLM/capsules-plugin#187): each is pushed
//! again, once, as a bundle under a checkpoint covering it, so the provider
//! holds its checkpoint and inclusion proof (loop step 05
//! `pushed_under_checkpoint`). It moves no money and seals nothing on this
//! node: it only re-sends records already sealed.
//!
//! **Which legs.** The sender of a push seals nothing when it succeeds (the
//! citing records are the receiver's), so this node's ledger cannot tell a
//! covered push from a bare one. What tells is the receiver's reply: it names
//! the verified inclusion only for a bundle. The outcome of a push of a terms
//! leg is recorded in [`OUTCOMES_FILE`] ([`record`]): `covered`, here and when
//! a new leg is pushed; and, here only, `no_inclusion` (the receiver took the
//! leg but predates bundles, so it was sent bare). Only `covered` means
//! covered, but both are final: a leg with an outcome is never pushed again,
//! so an older receiver is not sent the bare leg on every start. A push the
//! receiver refused records nothing and is retried at the next start. Every own terms leg with none is due: one pushed bare
//! by a release before the fix, or one whose push failed and expired from the
//! in-memory retry queue ([`crate::settlement_legs`]).
//!
//! **Which peer.** A terms leg names no peer, so it is read from what this
//! node sealed: the leg's payment hash, the payer settlement record of that
//! invoice (its host exchange id), and this node's requested exchange record
//! for that id (the peer that served it). A leg for which that join does not
//! give exactly one peer is skipped and counted, never guessed.
//!
//! **Bounded.** One run per process, of at most [`MAX_PER_RUN`] push
//! attempts, oldest leg first. A peer a push did not reach is not tried again
//! in that run, so legs stuck on a peer that is gone never keep the run from
//! the others. A push that did not reach a receiver records nothing, and the
//! next run tries it again.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::producer::capsule::SETTLEMENT_BLOCK_POINTER;

/// One line per own terms leg whose push ended: `{capsule_id, outcome, peer,
/// at}`, `outcome` an [`Outcome`]'s wire value.
pub const OUTCOMES_FILE: &str = "covered-terms-legs.jsonl";

/// How many pushes one run attempts.
pub const MAX_PER_RUN: usize = 64;

/// How many of the legs left for want of a peer a plan names.
const UNKNOWN_PEER_NAMED: usize = 3;

/// A terms leg to push again to `peer`, under a checkpoint covering it.
#[derive(Debug, Clone, PartialEq)]
pub struct Due {
    pub peer: String,
    pub capsule: Value,
}

/// The legs due, oldest first, and the legs left for want of a peer: how
/// many, and the first few ids.
#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    pub due: Vec<Due>,
    pub unknown_peer: usize,
    pub unknown_peer_ids: Vec<String>,
}

/// How a push of a terms leg ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The receiver holds the leg and the inclusion it verified.
    Covered,
    /// The receiver took the leg with no inclusion: it predates bundles.
    NoInclusion,
}

impl Outcome {
    pub fn wire(self) -> &'static str {
        match self {
            Outcome::Covered => "covered",
            Outcome::NoInclusion => "no_inclusion",
        }
    }
}

/// One writer of [`OUTCOMES_FILE`] at a time: the catch-up and new pushes
/// both append.
static OUTCOMES_WRITER: Mutex<()> = Mutex::new(());

/// Whether this process's run has started.
static STARTED: AtomicBool = AtomicBool::new(false);

/// True exactly once per process: the caller then runs the catch-up.
pub fn claim_run() -> bool {
    !STARTED.swap(true, Ordering::SeqCst)
}

/// Every leg due in the ledger at `ledger_dir`, oldest first.
pub fn plan(ledger_dir: &Path) -> Plan {
    let records = crate::evidence_panes::read_capsule_records(ledger_dir);
    plan_from(&records, &ended(ledger_dir))
}

/// [`plan`] over `records` (this node's own, in ledger order) and the legs
/// whose push already ended.
pub fn plan_from(records: &[Value], ended: &HashSet<String>) -> Plan {
    // The payer's invoices: payment hash -> the host exchange ids its
    // settlement records name for it.
    let mut invoices: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    // This node's requested exchanges: host exchange id -> the serving peers.
    let mut served_by: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for record in records {
        if let Some(observed) = record.pointer(SETTLEMENT_BLOCK_POINTER) {
            let text = |key: &str| observed.get(key).and_then(Value::as_str);
            if let (Some("payer"), Some(phase), Some(hash), Some(exchange)) = (
                text("observed_by"),
                text("phase"),
                text("payment_hash"),
                text("exchange_id"),
            ) {
                if phase.ends_with("_invoice_issued") {
                    invoices.entry(hash).or_default().insert(exchange);
                }
            }
        }
        if crate::evidence_panes::label_role(record) == "requested" {
            let provenance = record
                .pointer("/model_attestation/compute_attestation/x-mesh-poc-v1/serving_provenance");
            let text = |key: &str| {
                provenance
                    .and_then(|p| p.get(key))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty() && *s != "unknown")
            };
            if let (Some(exchange), Some(peer)) = (text("exchange_id"), text("served_by_node_id")) {
                served_by.entry(exchange).or_default().insert(peer);
            }
        }
    }
    let only = |set: Option<&BTreeSet<&str>>| {
        set.filter(|s| s.len() == 1)
            .and_then(BTreeSet::first)
            .map(|one| one.to_string())
    };
    let mut plan = Plan::default();
    for record in records {
        let Some((capsule_id, hash)) = own_terms_leg(record) else {
            continue;
        };
        if ended.contains(capsule_id) {
            continue;
        }
        let peer =
            only(invoices.get(hash)).and_then(|exchange| only(served_by.get(exchange.as_str())));
        match peer {
            Some(peer) => plan.due.push(Due {
                peer,
                capsule: record.clone(),
            }),
            None => {
                plan.unknown_peer += 1;
                if plan.unknown_peer_ids.len() < UNKNOWN_PEER_NAMED {
                    plan.unknown_peer_ids.push(capsule_id.to_string());
                }
            }
        }
    }
    plan
}

/// One run over a plan's due legs: [`Run::next`] gives the next leg to push,
/// at most `limit` in all, past the legs of a peer named [`Run::unreached`].
pub struct Run {
    due: VecDeque<Due>,
    left: usize,
    unreached: HashSet<String>,
}

impl Run {
    pub fn new(due: Vec<Due>, limit: usize) -> Self {
        Self {
            due: due.into(),
            left: limit,
            unreached: HashSet::new(),
        }
    }

    pub fn next(&mut self) -> Option<Due> {
        if self.left == 0 {
            return None;
        }
        let leg = loop {
            let leg = self.due.pop_front()?;
            if !self.unreached.contains(&leg.peer) {
                break leg;
            }
        };
        self.left -= 1;
        Some(leg)
    }

    /// A push to `peer` did not reach it: its other legs wait for the next run.
    pub fn unreached(&mut self, peer: &str) {
        self.unreached.insert(peer.to_string());
    }
}

/// How a push of `capsule` ended; `None` when it did not end for good: the
/// push did not arrive, or the receiver refused it. A refusal is retried at
/// the next start like a push that did not arrive, since most clear on the
/// receiver's side (a key it has not polled yet after a restart,
/// `signature_unverified`; a newer checkpoint, `checkpoint_stale`; its
/// sharing turned back on); the per-peer skip in [`Run`] keeps that to one
/// push per peer per start.
pub fn outcome_of(capsule: &Value, pushed: &anyhow::Result<Value>) -> Option<Outcome> {
    match pushed {
        Ok(reply) if names_inclusion(capsule, reply) => Some(Outcome::Covered),
        Ok(_) => Some(Outcome::NoInclusion),
        Err(_) => None,
    }
}

/// Whether `reply` acknowledges a bundle of `capsule`: it names the
/// inclusion the receiver verified and holds for it.
pub fn names_inclusion(capsule: &Value, reply: &Value) -> bool {
    let id = capsule.get("capsule_id").and_then(Value::as_str);
    id.is_some()
        && reply
            .pointer("/inclusion/half_capsule_id")
            .and_then(Value::as_str)
            == id
}

/// A payer's terms leg: its capsule id and payment hash.
fn own_terms_leg(record: &Value) -> Option<(&str, &str)> {
    let member = record.get("settlement")?;
    let text = |pointer: &str| member.pointer(pointer).and_then(Value::as_str);
    if text("/leg") != Some("terms")
        || text("/sealer_role") != Some("payer")
        || text("/payment_ref/type") != Some("ln.payment_hash")
    {
        return None;
    }
    Some((
        record.get("capsule_id")?.as_str()?,
        text("/payment_ref/value")?,
    ))
}

/// The terms legs whose push ended. A torn line is skipped.
fn ended(ledger_dir: &Path) -> HashSet<String> {
    std::fs::read_to_string(ledger_dir.join(OUTCOMES_FILE))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|line| line.get("capsule_id")?.as_str().map(str::to_string))
        .collect()
}

/// Record `outcome` for `capsule`, an own terms leg pushed to `peer`. A leg
/// keeps its first outcome.
pub fn record(
    ledger_dir: &Path,
    capsule: &Value,
    peer: &str,
    outcome: Outcome,
) -> std::io::Result<()> {
    let Some((capsule_id, _)) = own_terms_leg(capsule) else {
        return Ok(());
    };
    let _one = OUTCOMES_WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if ended(ledger_dir).contains(capsule_id) {
        return Ok(());
    }
    let mut line = serde_json::to_vec(&json!({
        "capsule_id": capsule_id,
        "outcome": outcome.wire(),
        "peer": peer,
        "at": crate::producer::timestamp::utc_now_minute(),
    }))?;
    line.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_dir.join(OUTCOMES_FILE))?;
    file.write_all(&line)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule_emit::{CapsuleState, HostProvenance, ObservedHostExchange};
    use crate::lifecycle_channel::DispatchPath;
    use crate::settlement_channel::Phase;
    use crate::settlement_legs::tests::{event, PROVIDER_PEER};
    use std::sync::Arc;

    const HASH: &str = "8437d5a5e0c5aa3304c0e0d17288cd504593ca7e560e3691a30739f1725ee7c5";

    /// A payer that sealed what a live paid exchange seals before its terms
    /// leg is pushed: the invoice's settlement record, the terms leg, and
    /// (when `served_by` is given) its requested exchange record naming the
    /// serving peer.
    fn payer(dir: &Path, exchange_id: &str, served_by: Option<&str>) -> CapsuleState {
        let payer = CapsuleState::open(dir, "payer-node").unwrap();
        let invoice = event(
            "payer",
            exchange_id,
            Phase::InputInvoiceIssued,
            0,
            HASH,
            1000,
            &[],
        );
        payer
            .emit_settlement_record(&invoice.observation())
            .unwrap();
        assert!(payer
            .settlement_legs()
            .on_lifecycle(&payer, &invoice)
            .is_empty());
        if let Some(peer) = served_by {
            payer
                .emit_for_observed_host_exchange(&ObservedHostExchange {
                    model: "m",
                    exchange_id: Some(exchange_id),
                    request_digest: Some(&"c".repeat(64)),
                    response_digest: Some(&"d".repeat(64)),
                    tool_calls_digest: None,
                    reasoning_digest: None,
                    usage: None,
                    host_provenance: HostProvenance {
                        served_by_node_id: Some(peer.to_string()),
                        ..Default::default()
                    },
                    dispatch_path: DispatchPath::RemoteMesh,
                    nonce: Some("catch-up-nonce"),
                    peer_capsule_id: None,
                    peer_capsule_id_provenance: None,
                    twin_bracket_id: None,
                    response_text_digest: None,
                })
                .unwrap();
        }
        payer
    }

    fn lines(dir: &Path, name: &str) -> Vec<Value> {
        std::fs::read_to_string(dir.join(name))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The records of a payer whose terms leg `id` (invoice `hash`) is of
    /// exchange `exchange`, served by `peer`; with `peer` `None`, nothing names
    /// the server.
    fn sealed(id: &str, hash: &str, exchange: &str, peer: Option<&str>) -> Vec<Value> {
        let mut records = vec![json!({"model_attestation": {"compute_attestation": {
            "x-mesh-settlement-v1": {
                "observed_by": "payer", "phase": "input_invoice_issued",
                "payment_hash": hash, "exchange_id": exchange}}}})];
        if let Some(peer) = peer {
            records.push(requested(exchange, peer));
        }
        records.push(json!({"capsule_id": id, "settlement": {
            "leg": "terms", "sealer_role": "payer",
            "payment_ref": {"type": "ln.payment_hash", "value": hash}}}));
        records
    }

    fn requested(exchange: &str, peer: &str) -> Value {
        json!({"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {
            "role": "requested",
            "serving_provenance": {"exchange_id": exchange, "served_by_node_id": peer}}}}})
    }

    fn ids(due: &[Due]) -> Vec<&str> {
        due.iter()
            .map(|d| d.capsule["capsule_id"].as_str().unwrap())
            .collect()
    }

    /// A terms leg the provider holds from a bare push is pushed again under
    /// a checkpoint covering it: the provider then holds its inclusion and
    /// seals its `counterparty_inclusion` citing record, without holding or
    /// citing the half a second time. The payer records the leg covered, so a
    /// second run pushes nothing.
    #[tokio::test]
    async fn a_leg_pushed_bare_is_covered_once_by_the_catch_up() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let payer = payer(a.path(), "ex-bare", Some(PROVIDER_PEER));
        let provider = Arc::new(CapsuleState::open(b.path(), "provider-node").unwrap());
        let payer_peer = "payer-peer-catch-up";
        crate::peer_keys::announced::announce_for_test(
            payer_peer,
            &crate::commitment::key_id(payer.signing_key()),
        );
        let ledger = payer.ledger_dir().to_path_buf();
        let plan = plan(&ledger);
        assert_eq!(plan.unknown_peer, 0, "{plan:?}");
        let [due] = plan.due.as_slice() else {
            panic!("one leg due: {plan:?}");
        };
        assert_eq!(due.peer, PROVIDER_PEER);
        let leg_id = due.capsule["capsule_id"].as_str().unwrap().to_string();

        // What a release before the fix did: the bare leg, held.
        let bare = crate::record_push_bridge::tests::answer_push(
            &provider,
            payer_peer,
            &serde_json::to_vec(&due.capsule).unwrap(),
        )
        .await;
        assert_eq!(bare["status"], "received", "{bare}");
        assert!(!names_inclusion(&due.capsule, &bare), "{bare}");
        let held = provider.ledger_dir().to_path_buf();
        let inclusion = crate::record_push_receive::RECEIVED_INCLUSION_FILENAME;
        assert!(lines(&held, inclusion).is_empty());

        // The catch-up: the same leg, under a checkpoint of the payer's log.
        let (state, _) = crate::producer::checkpoint::CheckpointState::load(
            &ledger,
            "payer-log",
            crate::producer::checkpoint::CheckpointCadenceConfig::default(),
        )
        .unwrap();
        let handle =
            crate::checkpoint_cadence::CheckpointHandle::new(state, payer.signing_key().clone());
        let coverage = handle.coverage_for(&leg_id).await.unwrap();
        let body = crate::record_push_bridge::bundle_body(&due.capsule, &coverage);
        let reply = crate::record_push_bridge::tests::answer_push(
            &provider,
            payer_peer,
            &serde_json::to_vec(&body).unwrap(),
        )
        .await;
        assert_eq!(reply["inclusion"]["half_capsule_id"], leg_id, "{reply}");
        let outcome = outcome_of(&due.capsule, &Ok(reply)).unwrap();
        assert_eq!(outcome, Outcome::Covered);
        record(&ledger, &due.capsule, &due.peer, outcome).unwrap();

        let inclusions = lines(&held, inclusion);
        assert_eq!(inclusions.len(), 1, "{inclusions:?}");
        assert_eq!(inclusions[0]["half_capsule_id"], leg_id);
        for store in [
            crate::record_push_receive::RECEIVED_CAPSULES_FILENAME,
            crate::record_push_receive::RECEIVED_PROVENANCE_FILENAME,
        ] {
            assert_eq!(lines(&held, store).len(), 1, "held once: {store}");
        }
        let provider_chain = lines(&held, "capsules.jsonl");
        let cited = |block: &str| {
            provider_chain
                .iter()
                .filter(|r| {
                    r.pointer(&format!("/model_attestation/compute_attestation/{block}"))
                        .is_some()
                })
                .count()
        };
        assert_eq!(cited("received_half"), 1, "the half cited once");
        assert_eq!(cited("counterparty_inclusion"), 1, "its inclusion cited");

        // A second run: nothing due, nothing sent.
        assert_eq!(super::plan(&ledger), Plan::default());
        let outcomes = lines(&ledger, OUTCOMES_FILE);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0]["outcome"], "covered");
    }

    /// A leg whose serving peer this node never sealed (no requested record
    /// for its exchange) is skipped, never sent to a guessed peer.
    #[test]
    fn a_leg_whose_peer_is_unknown_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let payer = payer(dir.path(), "ex-unknown", None);
        let plan = plan(payer.ledger_dir());
        assert!(plan.due.is_empty(), "{plan:?}");
        assert_eq!(plan.unknown_peer, 1);
        assert_eq!(plan.unknown_peer_ids.len(), 1);
    }

    /// Two requested records naming different peers for one exchange leave
    /// the peer unknown. The plan counts every such leg and names only the
    /// first few.
    #[test]
    fn an_ambiguous_peer_is_skipped_and_counted() {
        let mut records = sealed("l0", "h0", "e0", Some("p1"));
        records.push(requested("e0", "p2"));
        for n in 1..10 {
            records.extend(sealed(&format!("l{n}"), &format!("h{n}"), "e", None));
        }
        let plan = plan_from(&records, &HashSet::new());
        assert!(plan.due.is_empty());
        assert_eq!(plan.unknown_peer, 10);
        assert_eq!(plan.unknown_peer_ids, ["l0", "l1", "l2"]);
    }

    /// More stuck legs than a run's bound, all to a peer that is gone, ahead
    /// of a live peer's: the run tries the dead peer once and still reaches
    /// every live leg, within the bound.
    #[test]
    fn legs_stuck_on_a_dead_peer_never_keep_a_run_from_the_others() {
        let mut records = Vec::new();
        for n in 0..MAX_PER_RUN + 1 {
            records.extend(sealed(
                &format!("dead-{n}"),
                &format!("hd{n}"),
                &format!("ed{n}"),
                Some("dead"),
            ));
        }
        for n in 0..2 {
            records.extend(sealed(
                &format!("live-{n}"),
                &format!("hl{n}"),
                &format!("el{n}"),
                Some("live"),
            ));
        }
        let plan = plan_from(&records, &HashSet::new());
        assert_eq!(plan.due.len(), MAX_PER_RUN + 3, "the plan is not capped");
        let mut run = Run::new(plan.due, MAX_PER_RUN);
        let mut pushed = Vec::new();
        while let Some(leg) = run.next() {
            if leg.peer == "dead" {
                run.unreached(&leg.peer);
            }
            pushed.push(leg.capsule["capsule_id"].as_str().unwrap().to_string());
        }
        assert_eq!(pushed, ["dead-0", "live-0", "live-1"]);

        let mut run = Run::new(plan_from(&records, &HashSet::new()).due, MAX_PER_RUN);
        let mut attempts = 0;
        while run.next().is_some() {
            attempts += 1;
        }
        assert_eq!(attempts, MAX_PER_RUN, "a run attempts at most its bound");
    }

    /// `no_inclusion` is final like `covered`: such a leg is not sent again.
    /// A push that never arrived, or one the receiver refused (whatever the
    /// reason, `signature_unverified` after its restart included), records
    /// nothing and stays due.
    #[test]
    fn a_leg_with_a_final_outcome_is_not_sent_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut records = Vec::new();
        for id in ["older", "refused", "unreached", "retry"] {
            records.extend(sealed(
                id,
                &format!("h-{id}"),
                &format!("e-{id}"),
                Some("p"),
            ));
        }
        let leg = |id: &str| {
            records
                .iter()
                .find(|r| r["capsule_id"] == id)
                .unwrap()
                .clone()
        };
        let refusal = |reason: &str| -> anyhow::Result<Value> {
            Err(anyhow::anyhow!("peer p refused record-push: {reason}"))
        };
        let pushes = [
            ("older", Ok(json!({"status": "received"}))),
            ("refused", refusal("checkpoint_stale")),
            ("unreached", Err(anyhow::anyhow!("could not reach peer p"))),
            ("retry", refusal("citing_record_seal_failed")),
        ];
        let mut ended = Vec::new();
        for (id, pushed) in &pushes {
            if let Some(outcome) = outcome_of(&leg(id), pushed) {
                record(dir.path(), &leg(id), "p", outcome).unwrap();
                ended.push((*id, outcome.wire()));
            }
        }
        assert_eq!(ended, [("older", "no_inclusion")]);
        let next = plan_from(&records, &super::ended(dir.path()));
        assert_eq!(ids(&next.due), ["refused", "unreached", "retry"]);
        assert_eq!(
            outcome_of(&leg("refused"), &refusal("signature_unverified")),
            None,
            "a key the receiver has not polled yet is retried"
        );
    }
}
