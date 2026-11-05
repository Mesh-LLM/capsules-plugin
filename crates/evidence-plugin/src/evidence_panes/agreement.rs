//! Service evidence agreement coverage on the Exchanges rows (design R7, R8,
//! R13).
//!
//! Each row whose own half this node sealed gets `agreement`, computed by
//! this node alone, for its side of the exchange (`side`: `requester` for a
//! requested half, `provider` for a served one). The other side keeps its own
//! figures on its own node; the two can differ (the requester counts its
//! requested halves, which can include exchanges the provider never served).
//!
//! `coverage` is one label, the first that applies in this order:
//!
//! - `set_up_after`: the half cites nothing and the first session with this
//!   counterparty started after it ("not covered: agreement set up after this
//!   exchange").
//! - `not_evaluated`: the half cites a session this node does not keep, so
//!   nothing is said about it here (never "no agreement").
//! - `outside_window`, `over_count`, `over_cap`: the half cites a session it
//!   is not covered by. Over cap is "not covered", never a failed exchange.
//! - `cap_not_evaluable`: a payment of this or an earlier exchange under the
//!   session has no observation held, so the known sum is only a lower bound
//!   and does not exceed the cap.
//! - `not_cited`: a session with this counterparty holds the half's time, but
//!   the half cites none ("agreement present; exchange does not cite it").
//! - `covered`.
//! - `no_agreement`: no session with this counterparty bears on the half. A
//!   half whose counterparty this node cannot name gets this too: no session
//!   is guessed for it.
//!
//! Count and cap run per session in this node's own log order. The count is
//! the half's position among this side's halves citing the session. The cap
//! sums, over every payment of every exchange citing the session, this
//! side's own observation: the payer's `payer_observed.amount` (routing fee
//! excluded) or the provider's `payee_observed.received`. An exchange's
//! payments are the invoices this node's own lifecycle records name under the
//! exchange's id, joined to a leg by `payment_ref`, so a leg that cites
//! nothing still counts (R12). The spend cap is the requester's own
//! assertion (`agent_origin_assertion`, §11.1.6).
//!
//! `finding` is the interop profile's §11.1.8 finding over the provider's
//! served half, read as the acceptor's execution record (R3), with the
//! session's proposal, accepted record and receipt. `requirements` maps it
//! and the served half to the contract's requirement results (R8). With no
//! served half held (a requester before the provider's half arrives) no
//! finding is stated: `finding` is null and `finding_not_evaluated` says
//! `served_half_not_held`; `evaluation_failed` means the evaluation erred.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use evidence_request::acceptance::{self, ExecutionRecord, Finding, Inputs, TrustPolicy};
use evidence_request::time::parse_rfc3339;
use serde_json::{json, Value};

use super::settlement::SettlementIndex;
use super::{label_role, poc_block, record_exchange_id};
use crate::agreement;
use crate::agreement_bridge::SessionView;

/// How the reader names the citation it reads from a half (R3).
const READER_METHOD: &str = "x-mesh-poc-v1/acceptance_digest";

/// What reading coverage needs beyond the rows and records.
pub(super) struct Context<'a> {
    /// The complete sessions this node keeps.
    pub sessions: &'a [SessionView],
    /// The peer key registry (`crate::peer_keys::registry`): node id to key.
    pub registry: Option<&'a str>,
    /// The settlement legs this node sealed, in log order.
    pub legs: &'a [Value],
    pub settlements: &'a SettlementIndex,
    /// When trust is decided (Unix seconds).
    pub now: i64,
}

/// A settlement leg: a record carrying the -00 `settlement` member.
pub(super) fn is_settlement_leg(record: &Value) -> bool {
    record.get("settlement").is_some_and(Value::is_object)
}

/// Whether `record` is a half citing a session.
pub(super) fn cites_a_session(record: &Value) -> bool {
    !is_settlement_leg(record) && cited(record).is_some()
}

/// Attach `agreement` to every row of `pane` whose own half is in `records`;
/// with no session kept, only to a half that cites one.
pub(super) fn attach_rows(pane: &mut Value, records: &[Value], ctx: &Context<'_>) {
    let Some(rows) = pane.get_mut("rows").and_then(Value::as_array_mut) else {
        return;
    };
    let by_id: HashMap<&str, &Value> = records
        .iter()
        .filter(|r| !is_settlement_leg(r))
        .filter_map(|r| Some((r.get("capsule_id")?.as_str()?, r)))
        .collect();
    let cell_id = |row: &Value, cell: &str| {
        row.get(cell)
            .and_then(|c| c.get("capsule_id"))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let own: BTreeSet<String> = rows.iter().filter_map(|row| cell_id(row, "mine")).collect();
    let tally = Tally::new(records, &own, ctx);
    for row in rows.iter_mut() {
        let Some(half) = cell_id(row, "mine").and_then(|id| by_id.get(id.as_str()).copied()) else {
            continue;
        };
        let theirs = cell_id(row, "theirs").and_then(|id| by_id.get(id.as_str()).copied());
        if let Some(value) = coverage(half, theirs, &tally, ctx) {
            row["agreement"] = value;
        }
    }
}

/// Which side of the exchange a half is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Requester,
    Provider,
}

impl Side {
    fn of(half: &Value) -> Option<Side> {
        match label_role(half) {
            "requested" => Some(Side::Requester),
            "served" => Some(Side::Provider),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Side::Requester => "requester",
            Side::Provider => "provider",
        }
    }

    /// The session's key for this side and for the counterparty.
    fn keys(self, s: &SessionView) -> (&str, &str) {
        match self {
            Side::Requester => (&s.proposer, &s.acceptor),
            Side::Provider => (&s.acceptor, &s.proposer),
        }
    }
}

/// The digest a half cites in its `acceptance` member, if any.
fn cited(half: &Value) -> Option<&str> {
    let link = poc_block(half)?.get("acceptance")?;
    (link.get("type").and_then(Value::as_str) == Some("cites"))
        .then(|| link.get("target").and_then(Value::as_str))
        .flatten()
}

fn half_time(half: &Value) -> Option<i64> {
    let t = half.get("timestamp")?.as_str()?;
    parse_rfc3339(t).map(|t| t.seconds)
}

fn provenance_text<'a>(half: &'a Value, key: &str) -> Option<&'a str> {
    poc_block(half)?
        .get("serving_provenance")?
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "unknown")
}

/// The counterparty's node id as the half names it: the provider a requested
/// half was served by, the requester a served half was asked by.
fn counterparty_node(half: &Value, side: Side) -> Option<&str> {
    match side {
        Side::Requester => provenance_text(half, "served_by_node_id"),
        Side::Provider => provenance_text(half, "requesting_party"),
    }
}

/// Per session, the running count and spend of this side's citing halves, in
/// this node's log order.
struct Tally {
    by_half: HashMap<String, Position>,
}

#[derive(Clone, Copy)]
struct Position {
    ordinal: u64,
    known_msat: u64,
    /// Some payment of this or an earlier exchange has no observation held.
    lower_bound: bool,
}

impl Tally {
    fn new(records: &[Value], own: &BTreeSet<String>, ctx: &Context<'_>) -> Tally {
        let observed = observations(ctx.legs);
        let mut running: HashMap<&str, Position> = HashMap::new();
        let mut by_half = HashMap::new();
        for half in records.iter().filter(|r| !is_settlement_leg(r)) {
            let Some(id) = half.get("capsule_id").and_then(Value::as_str) else {
                continue;
            };
            let (Some(side), Some(digest)) = (Side::of(half), cited(half)) else {
                continue;
            };
            if !own.contains(id) {
                continue;
            }
            let at = running.entry(digest).or_insert(Position {
                ordinal: 0,
                known_msat: 0,
                lower_bound: false,
            });
            at.ordinal += 1;
            let hashes = ctx
                .settlements
                .invoice_hashes(record_exchange_id(half), side == Side::Provider);
            for hash in hashes {
                match observed.get(&(side.leg(), hash)) {
                    Some(msat) => at.known_msat = at.known_msat.saturating_add(*msat),
                    None => at.lower_bound = true,
                }
            }
            by_half.insert(id.to_string(), *at);
        }
        Tally { by_half }
    }
}

impl Side {
    /// The leg holding this side's own observation of a payment.
    fn leg(self) -> &'static str {
        match self {
            Side::Requester => "payer_observed",
            Side::Provider => "payee_observed",
        }
    }
}

/// `(leg, payment hash)` to the observed amount: `amount` on a payer leg,
/// `received` on a payee leg. One per payment: a later leg for the same
/// payment replaces an earlier one.
fn observations(legs: &[Value]) -> HashMap<(&'static str, String), u64> {
    let mut out = HashMap::new();
    for leg in legs {
        let s = &leg["settlement"];
        let (kind, field) = match s.get("leg").and_then(Value::as_str) {
            Some("payer_observed") => ("payer_observed", "amount"),
            Some("payee_observed") => ("payee_observed", "received"),
            _ => continue,
        };
        let hash = s
            .pointer("/payment_ref/value")
            .and_then(Value::as_str)
            .filter(|_| {
                s.pointer("/payment_ref/type").and_then(Value::as_str) == Some("ln.payment_hash")
            });
        let msat = s.get(field).and_then(amount_msat);
        if let (Some(hash), Some(msat)) = (hash, msat) {
            out.insert((kind, hash.to_string()), msat);
        }
    }
    out
}

/// An -00 amount (`{value, assetCode, assetScale}`) in msat: BTC at scale 11
/// (1 BTC = 10^11 msat), as `settlement_legs` seals it. Any other asset or
/// scale is no observation, so the cap reads as a lower bound.
fn amount_msat(amount: &Value) -> Option<u64> {
    if amount.get("assetCode")?.as_str()? != "BTC" || amount.get("assetScale")?.as_u64()? != 11 {
        return None;
    }
    amount.get("value")?.as_str()?.parse().ok()
}

/// Why `finding` is null: the provider's served half is not held on this
/// node (the requester before it arrives), or the evaluation failed.
const SERVED_HALF_NOT_HELD: &str = "served_half_not_held";
const EVALUATION_FAILED: &str = "evaluation_failed";

fn coverage(
    half: &Value,
    theirs: Option<&Value>,
    tally: &Tally,
    ctx: &Context<'_>,
) -> Option<Value> {
    let side = Side::of(half)?;
    let id = half.get("capsule_id")?.as_str()?;
    let own_key = half
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let t = half_time(half);
    let peer_key = counterparty_node(half, side)
        .and_then(|node| crate::peer_keys::announced_key_in(ctx.registry, node));
    let with_peer: Vec<&SessionView> = ctx
        .sessions
        .iter()
        .filter(|s| {
            let (mine, theirs) = side.keys(s);
            mine == own_key && Some(theirs) == peer_key.as_deref()
        })
        .collect();
    let in_window = |s: &SessionView| t.is_some_and(|t| s.start <= t && t <= s.end);

    let mut out = json!({ "side": side.as_str() });
    let session = match cited(half) {
        Some(digest) => {
            out["acceptance_digest"] = json!(digest);
            // A half cites only a session its own side kept; one this node
            // does not keep is not evaluated here, and says so rather than
            // reading as "no agreement".
            let session = ctx
                .sessions
                .iter()
                .find(|s| s.acceptance_digest == digest && side.keys(s).0 == own_key);
            let (Some(session), Some(p)) = (session, tally.by_half.get(id).copied()) else {
                out["coverage"] = json!("not_evaluated");
                return Some(out);
            };
            out["coverage"] = json!(cited_label(session, in_window(session), p));
            out["count"] = json!({
                "position": p.ordinal,
                "max_exchanges": session.terms.max_exchanges,
            });
            out["spend"] = json!({
                "observed_msat": p.known_msat,
                "lower_bound": p.lower_bound,
                "spend_cap_msat": session.terms.spend_cap_msat,
                "basis": "agent_origin_assertion",
                "observed_by": side.leg(),
            });
            session
        }
        // A node that keeps no session says nothing about a half citing none.
        None if ctx.sessions.is_empty() => return None,
        None => {
            if let Some(s) = with_peer.iter().copied().find(|s| in_window(s)) {
                out["acceptance_digest"] = json!(s.acceptance_digest);
                out["coverage"] = json!("not_cited");
                s
            } else {
                let first = with_peer.iter().map(|s| s.start).min();
                let after = matches!((first, t), (Some(f), Some(t)) if f > t);
                out["coverage"] = json!(if after {
                    "set_up_after"
                } else {
                    "no_agreement"
                });
                return Some(out);
            }
        }
    };
    let served = match side {
        Side::Provider => Some(half),
        Side::Requester => theirs.filter(|h| Side::of(h) == Some(Side::Provider)),
    };
    // With no served half held, every finding the profile could reach reads
    // as the provider not citing the session; none is stated until it
    // arrives.
    let (finding, evidence) = match served {
        Some(h) => finding(session, h, ctx),
        None => (None, Vec::new()),
    };
    out["finding"] = json!(finding.map(Finding::as_str));
    if finding.is_none() {
        out["finding_not_evaluated"] = json!(if served.is_some() {
            EVALUATION_FAILED
        } else {
            SERVED_HALF_NOT_HELD
        });
    }
    out["requirements"] = requirements(session, served, finding, &evidence);
    Some(out)
}

/// The label for a half citing `session`, by the precedence in the module
/// doc.
fn cited_label(session: &SessionView, in_window: bool, p: Position) -> &'static str {
    if !in_window {
        "outside_window"
    } else if session
        .terms
        .max_exchanges
        .is_some_and(|max| p.ordinal > max)
    {
        "over_count"
    } else if p.known_msat > session.terms.spend_cap_msat {
        "over_cap"
    } else if p.lower_bound {
        "cap_not_evaluable"
    } else {
        "covered"
    }
}

/// The §11.1.8 finding for `session` over the served half, and the digests
/// each claim lists as evidence.
fn finding(
    session: &SessionView,
    served: &Value,
    ctx: &Context<'_>,
) -> (Option<Finding>, Vec<String>) {
    let Some(accepted) = acceptance::parse(&session.accepted) else {
        return (None, Vec::new());
    };
    let transaction = accepted.get("transaction").cloned().unwrap_or(Value::Null);
    let Ok(served_octets) = serde_json::to_vec(served) else {
        return (None, Vec::new());
    };
    let execution: Vec<&[u8]> = vec![&served_octets];
    let trust = TrustPolicy {
        parties: party_map(ctx.registry, &session.proposer, &session.acceptor),
        ..TrustPolicy::default()
    };
    let result = acceptance::evaluate(
        &Inputs {
            contract: &agreement::contract(),
            transaction: &transaction,
            proposer: &session.proposer,
            acceptor: &session.acceptor,
            records: &[&session.proposed, &session.accepted],
            execution_records: &execution,
            receipts: &[&session.receipt],
            trust: &trust,
            evaluation_time: &agreement::profile_time(ctx.now),
            session: true,
            form_ii_objects: 0,
            profiles_implemented: &[acceptance::PROFILE_ID],
        },
        read_served_half,
    );
    match result {
        Ok(r) => (Some(r.finding), r.evidence),
        Err(error) => {
            tracing::warn!(%error, "service evidence agreement not evaluated");
            (None, Vec::new())
        }
    }
}

/// The relying party's key-to-party map (R4): every key the peer key
/// registry announces, mapped to its node, so a node that announces another
/// key is still one party. A session party no announcement names (this
/// node's own key) is its own party.
fn party_map(registry: Option<&str>, proposer: &str, acceptor: &str) -> BTreeMap<String, String> {
    let mut parties: BTreeMap<String, String> = registry
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|v| v.as_object().cloned())
        .into_iter()
        .flatten()
        .filter_map(|(node, key)| Some((key.as_str()?.to_string(), node)))
        .filter(|(key, _)| !key.is_empty())
        .collect();
    for key in [proposer, acceptor] {
        parties
            .entry(key.to_string())
            .or_insert_with(|| format!("key:{key}"));
    }
    parties
}

/// The Mesh reader (R3): a half Capsule as an execution record. Its issuer is
/// the key its producer envelope verifies under, once its Class 1 checks
/// pass; its action time is its own `timestamp`; it cites what its
/// `acceptance` member cites. A session names no transaction per record.
fn read_served_half(octets: &[u8]) -> Option<ExecutionRecord> {
    let half: Value = serde_json::from_slice(octets).ok()?;
    let issuer = verified_issuer(&half);
    Some(ExecutionRecord {
        issuer,
        action_at: half
            .get("timestamp")
            .and_then(Value::as_str)
            .map(String::from),
        cites: cited(&half).map(String::from).into_iter().collect(),
        transaction: None,
        method: READER_METHOD.into(),
    })
}

/// The key `half` verifies under, when it passes its Class 1 checks and its
/// producer envelope verifies.
fn verified_issuer(half: &Value) -> Option<String> {
    if !agent_action_capsule::verify::verify(half, None).ok {
        return None;
    }
    capsule_emit_lib::cose::verify_producer_envelope(half).ok()
}

/// The contract's requirement results (R8). `R-prior` follows the finding;
/// `R-served` needs the served half held and verifying; `R-model-stated`
/// needs the model that half states to be one the session's policy names,
/// as stated, never verified: by its id, or with none, by the local GGUF its
/// weights digest names. Each result names what it relies on.
fn requirements(
    session: &SessionView,
    served: Option<&Value>,
    finding: Option<Finding>,
    evidence: &[String],
) -> Value {
    let prior = match finding {
        Some(Finding::AcceptedBeforeAction) => "met",
        Some(Finding::AcceptedAfterAction) => "not_met",
        _ => "not_evaluable",
    };
    let served_ok = served.map(|h| verified_issuer(h).is_some());
    let served_result = match served_ok {
        Some(true) => "met",
        Some(false) => "not_met",
        None => "not_evaluable",
    };
    let stated = served
        .filter(|_| served_ok == Some(true))
        .and_then(|h| poc_block(h)?.pointer("/serving_provenance/model"));
    let stated = |k: &str| stated.and_then(|m| m.get(k)?.as_str());
    let (model, digest) = (stated("canonical_ref"), stated("weights_digest"));
    // The half states its model by id, or, when a host names none (mesh-llm
    // 0.78), by the digest of the weights it served: a local GGUF's id is
    // that digest (`host_status::local_gguf_ref`). The id, when stated,
    // decides alone; the result says which form it rests on.
    let (named, stated_as) = match (model, digest) {
        (Some(m), _) => (Some(m.to_string()), Some("canonical_ref")),
        (None, Some(d)) => (
            crate::host_status::local_gguf_ref(d),
            Some("weights_digest"),
        ),
        (None, None) => (None, None),
    };
    let model_result = match (served_ok, &named) {
        (Some(true), Some(m)) if session.models.iter().any(|x| x == m) => "met",
        (Some(true), _) => "not_met",
        _ => "not_evaluable",
    };
    let served_id = served.and_then(|h| h.get("capsule_id")).cloned();
    json!([
        {
            "id": "R-prior",
            "result": prior,
            "contract_ref": agreement::CONTRACT_REF,
            "evidence": evidence,
        },
        {"id": "R-served", "result": served_result, "evidence": served_id},
        {
            "id": "R-model-stated",
            "result": model_result,
            "stated_model": model,
            "stated_weights_digest": if model.is_none() { digest } else { None },
            "stated_as": stated_as,
            "basis": "stated",
            "evidence": served_id,
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    mod exit_gate;
    mod t9;

    const ME: &str = "aa";
    const PEER_KEY: &str = "bb";
    const PEER_NODE: &str = "node-b";
    const T0: i64 = 1_793_000_000;

    fn session(digest: &str, start: i64, max: Option<u64>, cap: u64) -> SessionView {
        SessionView {
            acceptance_digest: digest.into(),
            proposer: PEER_KEY.into(),
            acceptor: ME.into(),
            start,
            end: start + 3_600,
            models: vec!["m".into()],
            terms: agreement::Terms {
                spend_cap_msat: cap,
                max_exchanges: max,
            },
            proposed: Vec::new(),
            accepted: Vec::new(),
            receipt: Vec::new(),
        }
    }

    /// A served half sealed by this node at `at`, for host exchange `ex`,
    /// citing `digest` when given.
    fn served(id: &str, at: i64, ex: &str, digest: Option<&str>) -> Value {
        let mut poc = json!({
            "role": "served",
            "serving_provenance": {"exchange_id": ex, "requesting_party": PEER_NODE},
        });
        if let Some(d) = digest {
            poc["acceptance"] = crate::producer::capsule::acceptance_link(d);
        }
        json!({
            "capsule_id": id,
            "key_id": ME,
            "timestamp": agreement::committed_time(at),
            "model_attestation": {"compute_attestation": {"x-mesh-poc-v1": poc}},
        })
    }

    /// A requested half sealed by this node at `at`, for its exchange `ex`,
    /// served by `PEER_NODE`, citing `digest` when given.
    fn requested(id: &str, at: i64, ex: &str, digest: Option<&str>) -> Value {
        let mut half = served(id, at, ex, digest);
        let poc = &mut half["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"];
        poc["role"] = json!("requested");
        poc["serving_provenance"] = json!({"exchange_id": ex, "served_by_node_id": PEER_NODE});
        half
    }

    /// The same session from the requester's side: this node proposed it.
    fn proposed_session(digest: &str, start: i64, max: Option<u64>, cap: u64) -> SessionView {
        let mut s = session(digest, start, max, cap);
        std::mem::swap(&mut s.proposer, &mut s.acceptor);
        s
    }

    fn invoice(ex: &str, hash: &str) -> Value {
        invoice_by("provider", ex, hash)
    }

    fn invoice_by(observed_by: &str, ex: &str, hash: &str) -> Value {
        json!({"model_attestation": {"compute_attestation": {"x-mesh-settlement-v1": {
            "observed_by": observed_by, "exchange_id": ex,
            "phase": "input_invoice_issued", "segment": 0, "payment_hash": hash,
        }}}})
    }

    /// An -00 amount in msat as `settlement_legs` seals it.
    fn msat(n: u64) -> Value {
        capsule_emit_lib::settlement::amount(n.into(), "BTC", 11)
    }

    fn payer_leg(hash: &str, amount: u64, fee: u64) -> Value {
        json!({"settlement": {
            "leg": "payer_observed",
            "amount": msat(amount),
            "routing_fee": msat(fee),
            "payment_ref": {"type": "ln.payment_hash", "value": hash},
        }})
    }

    fn payee_leg(hash: &str, received: u64, cites: Option<&str>) -> Value {
        let mut leg = json!({"settlement": {
            "leg": "payee_observed",
            "received": msat(received),
            "payment_ref": {"type": "ln.payment_hash", "value": hash},
        }});
        if let Some(d) = cites {
            leg["model_attestation"] = json!({"compute_attestation": {"x-mesh-poc-v1": {
                "acceptance": crate::producer::capsule::acceptance_link(d),
            }}});
        }
        leg
    }

    fn pane(halves: &[&Value]) -> Value {
        let rows: Vec<Value> = halves
            .iter()
            .map(|h| json!({"mine": {"capsule_id": h["capsule_id"]}}))
            .collect();
        json!({ "rows": rows })
    }

    /// `pane`'s rows with `theirs` naming the counterparty's half.
    fn with_theirs(mut pane: Value, theirs: &[Option<&Value>]) -> Value {
        for (row, t) in pane["rows"].as_array_mut().unwrap().iter_mut().zip(theirs) {
            if let Some(t) = t {
                row["theirs"] = json!({"capsule_id": t["capsule_id"]});
            }
        }
        pane
    }

    /// `agreement` on each row, after attaching with these inputs.
    fn attached(
        halves: &[Value],
        sessions: &[SessionView],
        invoices: &[Value],
        legs: &[Value],
    ) -> Vec<Value> {
        let registry = json!({ PEER_NODE: PEER_KEY }).to_string();
        attached_in(halves, sessions, invoices, legs, &registry, T0 + 7_200)
    }

    /// [`attached`] with this registry, evaluated at `now`.
    fn attached_in(
        halves: &[Value],
        sessions: &[SessionView],
        invoices: &[Value],
        legs: &[Value],
        registry: &str,
        now: i64,
    ) -> Vec<Value> {
        let mut index = SettlementIndex::default();
        for record in invoices {
            index.push(record.clone());
        }
        let ctx = Context {
            sessions,
            registry: Some(registry),
            legs,
            settlements: &index,
            now,
        };
        let mut p = pane(&halves.iter().collect::<Vec<_>>());
        attach_rows(&mut p, halves, &ctx);
        p["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["agreement"].clone())
            .collect()
    }

    fn coverage_of(rows: &[Value]) -> Vec<&str> {
        rows.iter()
            .map(|r| r["coverage"].as_str().unwrap())
            .collect()
    }

    /// Count and cap run in log order: the third citing exchange is over a
    /// count of two, and the one whose payment takes the sum past the cap is
    /// over cap; a window miss outranks both.
    #[test]
    fn count_cap_and_window_follow_log_order_and_precedence() {
        let s = session("d1", T0, Some(3), 1_500);
        let halves = [
            served("h1", T0 + 60, "e1", Some("d1")),
            served("h2", T0 + 120, "e2", Some("d1")),
            served("h3", T0 + 180, "e3", Some("d1")),
            served("h4", T0 + 240, "e4", Some("d1")),
            served("h5", T0 + 4_000, "e5", Some("d1")),
        ];
        let invoices: Vec<Value> = (1..=5)
            .map(|n| invoice(&format!("e{n}"), &format!("p{n}")))
            .collect();
        let legs: Vec<Value> = (1..=5)
            .map(|n| payee_leg(&format!("p{n}"), 500, None))
            .collect();
        let rows = attached(&halves, &[s], &invoices, &legs);
        assert_eq!(
            coverage_of(&rows),
            [
                "covered",
                "covered",
                "covered",
                "over_count",
                "outside_window"
            ]
        );
        assert_eq!(rows[2]["spend"]["observed_msat"], json!(1_500));
        assert_eq!(rows[2]["spend"]["basis"], json!("agent_origin_assertion"));
        assert_eq!(rows[3]["count"], json!({"position": 4, "max_exchanges": 3}));

        let tight = session("d1", T0, None, 900);
        let rows = attached(&halves[..3], &[tight], &invoices, &legs);
        assert_eq!(coverage_of(&rows), ["covered", "over_cap", "over_cap"]);
    }

    /// R12's condition: a payee leg that cites nothing (two sessions were
    /// open at once) still counts toward the cap through the exchange
    /// binding, so the sum is the same as with every leg cited.
    #[test]
    fn an_uncited_payee_leg_still_counts_toward_the_cap() {
        let sessions = [
            session("d1", T0, None, 10_000),
            session("d2", T0, None, 10_000),
        ];
        let halves = [
            served("h1", T0 + 60, "e1", Some("d1")),
            served("h2", T0 + 120, "e2", Some("d2")),
            served("h3", T0 + 180, "e3", Some("d1")),
        ];
        let invoices = [
            invoice("e1", "p1"),
            invoice("e2", "p2"),
            invoice("e3", "p3"),
        ];
        let sum =
            |legs: &[Value]| attached(&halves, &sessions, &invoices, legs)[2]["spend"].clone();
        let uncited = sum(&[
            payee_leg("p1", 700, None),
            payee_leg("p2", 50, None),
            payee_leg("p3", 300, None),
        ]);
        let cited = sum(&[
            payee_leg("p1", 700, Some("d1")),
            payee_leg("p2", 50, Some("d2")),
            payee_leg("p3", 300, Some("d1")),
        ]);
        assert_eq!(
            uncited["observed_msat"],
            json!(1_000),
            "d1's two payments only"
        );
        assert_eq!(uncited, cited);
    }

    /// A payment with no observation held makes this and every later
    /// exchange a lower bound: over cap only once the known sum exceeds it,
    /// otherwise no cap conclusion. When the observation arrives, the
    /// figures are recomputed.
    #[test]
    fn a_missing_observation_is_a_lower_bound_until_it_arrives() {
        let s = session("d1", T0, None, 1_000);
        let halves = [
            served("h1", T0 + 60, "e1", Some("d1")),
            served("h2", T0 + 120, "e2", Some("d1")),
            served("h3", T0 + 180, "e3", Some("d1")),
        ];
        let invoices = [
            invoice("e1", "p1"),
            invoice("e2", "p2"),
            invoice("e3", "p3"),
        ];
        let gap = [payee_leg("p2", 400, None), payee_leg("p3", 700, None)];
        let rows = attached(&halves, std::slice::from_ref(&s), &invoices, &gap);
        assert_eq!(
            coverage_of(&rows),
            ["cap_not_evaluable", "cap_not_evaluable", "over_cap"]
        );
        assert_eq!(rows[1]["spend"]["lower_bound"], json!(true));

        let filled = [payee_leg("p1", 100, None), gap[0].clone(), gap[1].clone()];
        let rows = attached(&halves, &[s], &invoices, &filled);
        assert_eq!(coverage_of(&rows), ["covered", "covered", "over_cap"]);
    }

    /// A half that cites nothing: "agreement present" when a session with
    /// its counterparty holds its time, "set up after" when the first such
    /// session started later, and "no agreement" when no session bears on
    /// it or its counterparty is not known. None of them reads as covered.
    #[test]
    fn an_uncited_half_is_labelled_by_the_sessions_around_it() {
        let s = session("d1", T0, None, 1_000);
        let mut unknown_peer = served("h4", T0 + 60, "e4", None);
        unknown_peer["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
            ["serving_provenance"]["requesting_party"] = json!("unknown");
        let halves = [
            served("h1", T0 - 600, "e1", None),
            served("h2", T0 + 60, "e2", None),
            served("h3", T0 + 7_200, "e3", None),
            unknown_peer,
        ];
        let rows = attached(&halves, &[s], &[], &[]);
        assert_eq!(
            coverage_of(&rows),
            ["set_up_after", "not_cited", "no_agreement", "no_agreement"]
        );
        assert_eq!(rows[1]["acceptance_digest"], json!("d1"));
        assert!(rows[0].get("finding").is_none());
    }

    /// An exchange's payments are every invoice its lifecycle records name
    /// (a deposit and a final invoice both count), and a payment observed
    /// twice counts once: a later leg for the same payment, such as one
    /// superseding an earlier observation, replaces it.
    #[test]
    fn every_invoice_of_an_exchange_counts_and_a_payment_counts_once() {
        let s = session("d1", T0, None, 10_000);
        let halves = [served("h1", T0 + 60, "e1", Some("d1"))];
        let invoices = [invoice("e1", "deposit"), invoice("e1", "final")];
        let spend = |legs: &[Value]| {
            attached(&halves, std::slice::from_ref(&s), &invoices, legs)[0]["spend"].clone()
        };
        let both = spend(&[
            payee_leg("deposit", 600, None),
            payee_leg("final", 400, None),
        ]);
        assert_eq!(both["observed_msat"], json!(1_000), "{both}");
        assert_eq!(both["lower_bound"], json!(false));
        let duplicate = spend(&[
            payee_leg("deposit", 600, None),
            payee_leg("deposit", 600, None),
            payee_leg("final", 400, None),
        ]);
        assert_eq!(
            duplicate["observed_msat"],
            json!(1_000),
            "a duplicate counts once"
        );
        let superseded = spend(&[
            payee_leg("deposit", 600, None),
            payee_leg("final", 400, None),
            payee_leg("deposit", 550, None),
        ]);
        assert_eq!(
            superseded["observed_msat"],
            json!(950),
            "the later observation stands"
        );
        let missing = spend(&[payee_leg("final", 400, None)]);
        assert_eq!(missing["observed_msat"], json!(400));
        assert_eq!(
            missing["lower_bound"],
            json!(true),
            "the deposit is not held"
        );
    }

    /// A side holding none of its own observations (the payer's legs are on
    /// the payer's node only) has only a lower bound, never "within cap",
    /// and the payee's legs held here are not read as the payer's.
    #[test]
    fn a_side_without_its_own_observations_cannot_evaluate_the_cap() {
        let s = proposed_session("d1", T0, None, 1_000);
        let halves = [requested("r1", T0 + 60, "e1", Some("d1"))];
        let invoices = [invoice_by("payer", "e1", "p1")];
        let rows = attached(&halves, &[s], &invoices, &[payee_leg("p1", 500, None)]);
        assert_eq!(
            rows[0]["coverage"],
            json!("cap_not_evaluable"),
            "{:#}",
            rows[0]
        );
        assert_eq!(rows[0]["spend"]["lower_bound"], json!(true));
    }

    /// The two sides count on their own records and can disagree: the
    /// requester counts an exchange the provider never served, so its third
    /// exchange is over a count of two while the provider's second is not.
    #[test]
    fn the_two_sides_count_their_own_exchanges_and_can_disagree() {
        let requester_side = proposed_session("d1", T0, Some(2), 10_000);
        let asked = [
            requested("r1", T0 + 60, "e1", Some("d1")),
            requested("r2", T0 + 120, "e2", Some("d1")),
            requested("r3", T0 + 180, "e3", Some("d1")),
        ];
        let rows = attached(&asked, &[requester_side], &[], &[]);
        assert_eq!(rows[2]["coverage"], json!("over_count"));
        assert_eq!(rows[2]["count"]["position"], json!(3));

        // The provider served the first and the third only.
        let provider_side = session("d1", T0, Some(2), 10_000);
        let served_halves = [
            served("h1", T0 + 60, "p1", Some("d1")),
            served("h3", T0 + 180, "p3", Some("d1")),
        ];
        let rows = attached(&served_halves, &[provider_side], &[], &[]);
        assert_eq!(rows[1]["count"]["position"], json!(2));
        assert_ne!(rows[1]["coverage"], json!("over_count"), "{:#}", rows[1]);
    }

    /// A settlement leg citing a session is never counted as an exchange.
    #[test]
    fn a_settlement_leg_is_never_a_citing_exchange() {
        let s = session("d1", T0, Some(1), 10_000);
        let mut leg = payee_leg("p0", 1, Some("d1"));
        leg["capsule_id"] = json!("leg");
        leg["key_id"] = json!(ME);
        let halves = [leg, served("h1", T0 + 60, "e1", Some("d1"))];
        let mut index = SettlementIndex::default();
        index.push(invoice("e1", "p1"));
        let ctx = Context {
            sessions: &[s],
            registry: None,
            legs: &[],
            settlements: &index,
            now: T0,
        };
        let mut p = pane(&[&halves[1]]);
        attach_rows(&mut p, &halves, &ctx);
        assert_eq!(p["rows"][0]["agreement"]["count"]["position"], json!(1));
    }

    /// An -00 amount is read as msat only as `settlement_legs` seals it: BTC
    /// at scale 11. Any other asset or scale is no observation.
    #[test]
    fn an_amount_is_msat_only_as_btc_at_scale_eleven() {
        assert_eq!(amount_msat(&msat(995)), Some(995));
        for other in [
            capsule_emit_lib::settlement::amount(995, "BTC", 8),
            capsule_emit_lib::settlement::amount(995, "USD", 11),
            json!({"value": "995", "unit": "msat"}),
        ] {
            assert_eq!(amount_msat(&other), None, "{other}");
        }
    }

    /// The requester's side: its own key is the proposer's, its counterparty
    /// the provider its half was served by, its spend the payer's
    /// `payer_observed.amount` (routing fee excluded) through its own
    /// invoices. With no served half held no finding is stated, never "not
    /// cited by the provider"; once the provider's half is held, the finding
    /// is evaluated over it.
    #[test]
    fn the_requester_side_counts_its_own_payments_and_waits_for_the_served_half() {
        let s = proposed_session("d1", T0, Some(2), 1_000);
        let halves = [
            requested("r1", T0 + 60, "e1", Some("d1")),
            requested("r2", T0 + 120, "e2", Some("d1")),
            requested("r3", T0 + 180, "e3", None),
        ];
        let invoices = [
            invoice_by("payer", "e1", "p1"),
            invoice_by("payer", "e2", "p2"),
        ];
        let legs = [payer_leg("p1", 400, 7), payer_leg("p2", 500, 9)];
        let rows = attached(&halves, std::slice::from_ref(&s), &invoices, &legs);
        assert_eq!(coverage_of(&rows), ["covered", "covered", "not_cited"]);
        assert_eq!(rows[0]["side"], json!("requester"));
        assert_eq!(
            rows[1]["spend"]["observed_msat"],
            json!(900),
            "fees excluded"
        );
        assert_eq!(rows[1]["spend"]["observed_by"], json!("payer_observed"));
        assert_eq!(rows[1]["spend"]["lower_bound"], json!(false));
        for row in &rows {
            assert_eq!(row["finding"], Value::Null, "{row:#}");
            assert_eq!(row["finding_not_evaluated"], json!(SERVED_HALF_NOT_HELD));
        }

        // The provider's served half arrives for the first exchange.
        let theirs = served("h1", T0 + 60, "e1-provider", Some("d1"));
        let mut records = halves.to_vec();
        records.push(theirs.clone());
        let mut index = SettlementIndex::default();
        for record in &invoices {
            index.push(record.clone());
        }
        let registry = json!({ PEER_NODE: PEER_KEY }).to_string();
        let ctx = Context {
            sessions: std::slice::from_ref(&s),
            registry: Some(&registry),
            legs: &legs,
            settlements: &index,
            now: T0 + 7_200,
        };
        let mut p = with_theirs(pane(&halves.iter().collect::<Vec<_>>()), &[Some(&theirs)]);
        attach_rows(&mut p, &records, &ctx);
        let first = &p["rows"][0]["agreement"];
        assert_eq!(
            first["requirements"][1]["evidence"],
            json!("h1"),
            "{first:#}"
        );
        assert_ne!(
            first["finding_not_evaluated"],
            json!(SERVED_HALF_NOT_HELD),
            "{first:#}"
        );
        assert_eq!(
            p["rows"][1]["agreement"]["finding_not_evaluated"],
            json!(SERVED_HALF_NOT_HELD)
        );
    }

    /// A half citing a session this node does not keep is not evaluated
    /// here: it says so, and never reads as "no agreement".
    #[test]
    fn a_cited_session_not_kept_here_is_not_evaluated() {
        let s = session("d1", T0, None, 1_000);
        let halves = [served("h1", T0 + 60, "e1", Some("elsewhere"))];
        let rows = attached(&halves, &[s], &[], &[]);
        assert_eq!(rows[0]["coverage"], json!("not_evaluated"));
        assert_eq!(rows[0]["acceptance_digest"], json!("elsewhere"));
        assert!(rows[0].get("count").is_none() && rows[0].get("finding").is_none());
    }

    /// A node keeping no session at all still says a half citing one is not
    /// evaluated here, read through the pane, and adds nothing to a half
    /// citing none.
    #[test]
    fn with_no_session_kept_a_cited_half_is_not_evaluated() {
        let (digest, agreement) = sealed_under_session_keeping(300, false);
        assert_eq!(
            agreement,
            json!({"side": "provider", "acceptance_digest": digest, "coverage": "not_evaluated"})
        );
        let halves = [served("h1", T0, "e1", None)];
        assert_eq!(attached(&halves, &[], &[], &[]), [Value::Null]);
    }

    /// The requirement results follow the finding and the served half: with
    /// no served half held, nothing is met or failed.
    #[test]
    fn requirements_without_a_served_half_are_not_evaluable() {
        let s = session("d1", T0, None, 1);
        let results = requirements(&s, None, Some(Finding::AcceptedExecutionCites), &[]);
        let all: Vec<&str> = results
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["result"].as_str().unwrap())
            .collect();
        assert_eq!(all, ["not_evaluable", "not_evaluable", "not_evaluable"]);
        let after = requirements(&s, None, Some(Finding::AcceptedAfterAction), &[]);
        assert_eq!(after[0]["result"], json!("not_met"));
    }

    /// The present Unix time, away from the end of its minute, so halves
    /// sealed next fall in the same minute.
    fn present_minute() -> i64 {
        let now = chrono::Utc::now().timestamp();
        if now % 60 < 50 {
            return now;
        }
        std::thread::sleep(std::time::Duration::from_secs((61 - now % 60) as u64));
        chrono::Utc::now().timestamp()
    }

    /// An exchange as the host reports it, for `model`.
    fn observed<'a>(
        model: &'a str,
        exchange_id: &'a str,
        request_digest: &'a str,
        dispatch_path: crate::lifecycle_channel::DispatchPath,
        host_provenance: crate::capsule_emit::HostProvenance,
    ) -> crate::capsule_emit::ObservedHostExchange<'a> {
        crate::capsule_emit::ObservedHostExchange {
            model,
            exchange_id: Some(exchange_id),
            request_digest: Some(request_digest),
            response_digest: None,
            tool_calls_digest: None,
            reasoning_digest: None,
            usage: None,
            host_provenance,
            dispatch_path,
            nonce: None,
            peer_capsule_id: None,
            peer_capsule_id_provenance: None,
            twin_bracket_id: None,
            response_text_digest: None,
            failure: None,
        }
    }

    /// A session agreed through the bridge at `at`, as both nodes keep it:
    /// proposed, accepted, and the requester's receipt delivered.
    fn agree(
        requester: &crate::capsule_emit::CapsuleState,
        provider: &crate::capsule_emit::CapsuleState,
        terms: &crate::agreement::SessionTerms,
        model: &str,
        at: i64,
    ) -> crate::agreement_bridge::Session {
        use crate::agreement::{Proposal, Store};
        use crate::agreement_bridge::{conclude, respond, Outcome};
        let (rstore, pstore) = (
            Store::open(requester.ledger_dir()),
            Store::open(provider.ledger_dir()),
        );
        let proposal = Proposal::new(
            requester.signing_key(),
            &hex::encode(provider.public_key()),
            &agreement::new_session_id(),
            terms,
            &[model.to_string()],
            at,
        );
        let reply = respond(provider, &pstore, &proposal.to_message(), &|_| true, at);
        let Outcome::Accepted { session, receipt } = conclude(
            requester,
            &rstore,
            &proposal,
            &serde_json::to_vec(&reply).unwrap(),
            at,
        ) else {
            panic!("accepted: {reply}")
        };
        let frame = serde_json::to_vec(&json!({ "receipt": receipt })).unwrap();
        assert_eq!(
            respond(provider, &pstore, &frame, &|_| true, at),
            json!({"ok": true})
        );
        session
    }

    /// One payment lifecycle event as `main.rs` handles it: the settlement
    /// record sealed, then the settlement legs told. The legs' pushes.
    fn lifecycle(
        node: &crate::capsule_emit::CapsuleState,
        role: &str,
        exchange_id: &str,
        phase: crate::settlement_channel::Phase,
        hash: &str,
        wallet: &[(&str, u64)],
    ) -> Vec<crate::settlement_legs::Push> {
        lifecycle_event(node, role, exchange_id, phase, Some(hash), 1_000, wallet)
    }

    /// [`lifecycle`] for any event: segment 0 when it names a payment.
    fn lifecycle_event(
        node: &crate::capsule_emit::CapsuleState,
        role: &str,
        exchange_id: &str,
        phase: crate::settlement_channel::Phase,
        hash: Option<&str>,
        amount_msat: u64,
        wallet: &[(&str, u64)],
    ) -> Vec<crate::settlement_legs::Push> {
        use crate::settlement_channel::{host_shaped_event, parse_and_check};
        let segment = hash.map(|_| 0);
        let mut body = host_shaped_event(exchange_id, phase, segment, hash, amount_msat);
        body["role"] = json!(role);
        if role == "provider" && phase == crate::settlement_channel::Phase::InputInvoiceIssued {
            body["source"] = json!("provider_asserted");
        }
        for (k, v) in wallet {
            body[*k] = json!(v);
        }
        body["event_ref"] = json!("");
        body["event_ref"] = json!(crate::producer::jcs::json_digest(&body).unwrap());
        let event = parse_and_check(&serde_json::to_vec(&body).unwrap()).unwrap();
        node.emit_settlement_record(&event.observation()).unwrap();
        node.settlement_legs().on_lifecycle(node, &event)
    }

    /// As the plugin seals them: a session agreed `before` seconds before
    /// this minute's start, a served half that cites it, one paid input
    /// segment of 1000 msat the provider's wallet credits as 995, and the
    /// provider's own Exchanges row for it. The session's digest and the
    /// row's `agreement`.
    fn sealed_under_session(before: i64) -> (String, Value) {
        sealed_under_session_keeping(before, true)
    }

    /// [`sealed_under_session`], with the provider's agreement store
    /// removed before the pane is read when `keep` is false.
    fn sealed_under_session_keeping(before: i64, keep: bool) -> (String, Value) {
        const MODEL: &str = "hf:example/agreement-pane@main";
        sealed_stating(before, keep, MODEL, Some(MODEL), None)
    }

    /// [`sealed_under_session_keeping`] for a session naming `model`, with
    /// the served half stating `stated_ref` and `stated_digest` as the
    /// host's model id and weights digest.
    fn sealed_stating(
        before: i64,
        keep: bool,
        model: &str,
        stated_ref: Option<&str>,
        stated_digest: Option<&str>,
    ) -> (String, Value) {
        use crate::agreement::SessionTerms;
        use crate::capsule_emit::{CapsuleState, HostProvenance};
        use crate::lifecycle_channel::DispatchPath;

        let model_name = stated_ref.unwrap_or(model);
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let requester = CapsuleState::open(a.path(), "requester").unwrap();
        let provider = CapsuleState::open(b.path(), "provider").unwrap();
        // One node id per call: tests share the announced key registry.
        let requester_node = format!("{:064x}", 0xa9e_e0a1_0000u64 + before as u64);
        crate::peer_keys::announced::announce_for_test(
            &requester_node,
            &hex::encode(requester.public_key()),
        );
        let now = present_minute();
        let terms = SessionTerms {
            spend_cap_msat: 3_000,
            max_exchanges: Some(5),
            window_seconds: 3_600,
        };
        let session = agree(
            &requester,
            &provider,
            &terms,
            model,
            now - now % 60 - before,
        );

        provider
            .settlement_legs()
            .decide_served_citation("p-ex", || {
                crate::agreement_bridge::served_citation(
                    &provider,
                    &requester_node,
                    &[model.into()],
                    now,
                )
            });
        let request = "a".repeat(64);
        provider
            .emit_for_observed_host_exchange(&observed(
                model_name,
                "p-ex",
                &request,
                DispatchPath::RawProxy,
                HostProvenance {
                    requested_by_node_id: Some(requester_node.clone()),
                    model_canonical_ref: stated_ref.map(String::from),
                    weights_digest: stated_digest.map(String::from),
                    ..HostProvenance::default()
                },
            ))
            .unwrap();

        // The payment, both nodes, in the order a live run sees it; the
        // payer's terms leg reaches the provider with the exchange event.
        use crate::settlement_channel::Phase;
        const HASH: &str = "8437d5a5e0c5aa3304c0e0d17288cd504593ca7e560e3691a30739f1725ee7c5";
        let wallet = [("credited_msat", 995), ("fee_msat", 5)];
        lifecycle(
            &provider,
            "provider",
            "p-ex",
            Phase::InputInvoiceIssued,
            HASH,
            &[],
        );
        lifecycle(
            &requester,
            "payer",
            "ex",
            Phase::InputInvoiceIssued,
            HASH,
            &[],
        );
        lifecycle(
            &provider,
            "provider",
            "p-ex",
            Phase::InputSettlementObserved,
            HASH,
            &wallet,
        );
        lifecycle(
            &requester,
            "payer",
            "ex",
            Phase::InputSettlementObserved,
            HASH,
            &[("fee_msat", 0)],
        );
        requester.settlement_legs().decide_citation("ex", || None);
        let provider_node = format!("{:064x}", 0xb0b_0000u64 + before as u64);
        let pushes =
            requester
                .settlement_legs()
                .on_exchange(&requester, "ex", Some(&provider_node), None);
        assert!(!pushes.is_empty(), "the payer's terms leg is pushed");
        for push in pushes {
            provider
                .settlement_legs()
                .on_received(&provider, &push.capsule);
        }

        if !keep {
            std::fs::remove_dir_all(provider.ledger_dir().join("agreements")).unwrap();
            let pane =
                super::super::build_pane_json("pane-c", provider.ledger_dir(), None).unwrap();
            return (
                session.acceptance_digest,
                pane["rows"][0]["agreement"].clone(),
            );
        }
        let pane = super::super::build_pane_json("pane-c", provider.ledger_dir(), None).unwrap();
        let rows = pane["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "{pane:#}");
        assert_eq!(
            rows[0]["agreement"]["spend"],
            json!({
                "observed_msat": 995,
                "lower_bound": false,
                "spend_cap_msat": 3_000,
                "basis": "agent_origin_assertion",
                "observed_by": "payee_observed",
            }),
            "the payee leg as sealed is read: {pane:#}"
        );
        (session.acceptance_digest, rows[0]["agreement"].clone())
    }

    fn results(agreement: &Value) -> Vec<&str> {
        agreement["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["result"].as_str().unwrap())
            .collect()
    }

    /// A half that states no model id but the digest of the weights it
    /// served (mesh-llm 0.78) states the local GGUF that digest names: met
    /// when the session names it, said to rest on the digest; not met when
    /// it names another. A stated id decides alone (evidencebook#48).
    #[test]
    fn a_half_stating_only_a_weights_digest_states_its_local_gguf() {
        let (d, other) = ("74a4da8c".repeat(8), "0b".repeat(32));
        let gguf = |d: &str| crate::host_status::local_gguf_ref(d).unwrap();
        let model_stated = |a: &Value| a["requirements"][2].clone();

        let (_, a) = sealed_stating(660, true, &gguf(&d), None, Some(&d));
        assert_eq!(results(&a), ["met", "met", "met"], "{a:#}");
        let r = model_stated(&a);
        assert_eq!(r["stated_as"], json!("weights_digest"), "{r:#}");
        assert_eq!(r["stated_weights_digest"], json!(d));
        assert_eq!(r["stated_model"], Value::Null);

        let (_, a) = sealed_stating(720, true, &gguf(&other), None, Some(&d));
        assert_eq!(model_stated(&a)["result"], json!("not_met"), "{a:#}");

        let (_, a) = sealed_stating(780, true, &gguf(&d), Some("hf:org/x@main"), Some(&d));
        let r = model_stated(&a);
        assert_eq!(r["result"], json!("not_met"), "the id decides: {r:#}");
        assert_eq!(r["stated_as"], json!("canonical_ref"));
        assert_eq!(r["stated_weights_digest"], Value::Null);
    }

    /// A session agreed ten minutes before a served half that cites it
    /// reads, on the provider's own row, as covered, accepted before the
    /// exchange, with every requirement met and the accepted record and the
    /// receipt as the evidence `R-prior` relies on.
    #[test]
    fn a_sealed_served_half_under_a_session_reads_accepted_before() {
        let (digest, agreement) = sealed_under_session(600);
        assert_eq!(agreement["side"], json!("provider"));
        assert_eq!(agreement["acceptance_digest"], json!(digest));
        assert_eq!(agreement["coverage"], json!("covered"), "{agreement:#}");
        assert_eq!(
            agreement["finding"],
            json!("accepted_before_action"),
            "{agreement:#}"
        );
        assert_eq!(results(&agreement), ["met", "met", "met"], "{agreement:#}");
        let evidence = agreement["requirements"][0]["evidence"].as_array().unwrap();
        assert!(evidence.contains(&json!(digest)), "{evidence:?}");
        assert_eq!(
            evidence.len(),
            2,
            "the accepted record and the receipt: {evidence:?}"
        );
    }

    /// Every committed time is to the minute, so a served half in the
    /// receipt's own minute cannot be ordered after it: the finding is
    /// "accepted, the execution cites it" and `R-prior` is not evaluable,
    /// never "accepted after" (interop profile §11.1.5 rule 2, AAC #461).
    #[test]
    fn a_served_half_in_the_receipts_minute_reads_ordering_not_established() {
        let (_, agreement) = sealed_under_session(0);
        assert_eq!(agreement["coverage"], json!("covered"), "{agreement:#}");
        assert_eq!(
            agreement["finding"],
            json!("accepted_execution_cites"),
            "{agreement:#}"
        );
        assert_eq!(
            results(&agreement),
            ["not_evaluable", "met", "met"],
            "{agreement:#}"
        );
    }
}
