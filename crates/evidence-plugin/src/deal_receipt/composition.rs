//! `POST deal-composition`: the payer's receipt with the other party's half,
//! as a `composed/v1` Evidence Bundle (Mesh-LLM/capsules-plugin#196; the
//! reader is deal-view's, action-state-group/evidencebook-deal#86 D4). The
//! plugin builds it so the disclosure check runs on the node, never in the
//! page (Sherlock2's C3).
//!
//! **The containing bundle** is this node's ledger under one signed
//! checkpoint, interval-complete: a range proof from the earliest record it
//! must carry to the checkpoint, and every record in that interval. Its root
//! is a composition record ([`ACTION_ID`], the payload deal-view's V0 reads:
//! `{type, profile, deal_id, composed_digest, request_records}`), sealed on
//! this ledger. Disclosed: that payload and the payer's `x-deal-v0` records
//! (audience `keep`), with `extensions["x-deal-v0"].sealed_report`. Carried
//! with its payload withheld: the exchange record the report's `did[].steps`
//! cite, whose client nonce is in its header (D4's V4). Every other record
//! of the interval is carried as its Capsule, payload withheld.
//!
//! **The members** come only from this node's book of asks
//! ([`crate::ask_book`]): one per request record the owner names, with the
//! outcome recorded for it. A half received by push has no request behind it
//! and is never a member. An absence's observer is this node, its only
//! observer. A refusal is the peer's signed refusal as it came back, read
//! from the kept reply (#198), observed by the peer's key; only one this
//! node verified under the key the peer announced is a member. So is an
//! `evidence_bundle/1` answer (#197): the provider's bundle, with the
//! envelope as received minus its artifact as the member's response.
//!
//! **The block** is set on the built bundle, as `capsulectl-deal deal
//! compose` sets it: agent-action-capsule's producer reserves `composed/v1`
//! and has no builder for it. No joins: the payer's half is not a member.
//!
//! The route is the owner's own local API, like `deal-receipt-bundle`. The
//! file is the owner's (audience `keep`), and the composition record never
//! leaves the node in an answer (`evidence_log::never_leaves`).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use agent_action_capsule::canonical::jcs;
use capsule_emit_lib::produce;
use evidencebook::deal;
use evidencebook::record::record_types;
use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{interval_bundle, read_deal, Error, Refusal, Selection};
use crate::checkpoint_cadence::CheckpointHandle;
use crate::evidence_log::{self, LedgerIndex};

/// The composition record's action id: the one deal-view's V0 requires,
/// as `capsulectl-deal` seals it.
pub const ACTION_ID: &str = "capsulectl-deal-composition";
/// The composition payload's `type`.
pub const COMPOSITION_TYPE: &str = "deal_composition";
/// The registered extension kind the block is carried under.
pub const COMPOSED_KIND: &str = "composed/v1";
/// Every observer's role: each is a party to the deal.
const OBSERVER_ROLE: &str = "party";

/// Whether a ledger record is a composition record.
pub fn is_composition(record: &Value) -> bool {
    record.get("action_id").and_then(Value::as_str) == Some(ACTION_ID)
}

/// Why a member cannot be composed: the owner's input or this node's state.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MemberRefusal {
    /// Not a request this node's book recorded.
    NotARequest(String),
    /// Recorded, with no outcome yet: a pending request is not a member.
    Pending(String),
    /// Answered with an artifact that is not an Evidence Bundle: only an
    /// `evidence_bundle/1` answer is a member.
    Answered(String),
    /// The bundle answer does not bind as D4 needs: its digest, or its
    /// checkpoint key, is not what the response signs.
    Unbound(String, String),
    /// Answered with a reply this node did not verify as the peer's refusal
    /// (nonconformant, or not checked under the peer's announced key).
    NotVerified(String, String),
    /// The reply recorded for the request is not kept intact (#198).
    ReplyNotKept(String, String),
    /// The refusal is signed under this node's own key.
    OwnKey(String),
    /// The outcome names another request than the one it cites.
    Inconsistent(String),
    /// The absence states no window.
    NoWindow(String),
    /// Named twice.
    Duplicate(String),
}

impl MemberRefusal {
    fn why(&self) -> String {
        match self {
            MemberRefusal::NotARequest(id) => {
                format!("{id} is not a request this node's book of asks recorded")
            }
            MemberRefusal::Pending(id) => {
                format!(
                    "request {id} has no recorded outcome yet: a pending request is not a member"
                )
            }
            MemberRefusal::Answered(id) => format!(
                "request {id} was answered with an artifact that is not an Evidence Bundle; ask \
                 for the half with the evidence_bundle/1 derivation"
            ),
            MemberRefusal::Unbound(id, why) => {
                format!("the bundle answering request {id} does not bind: {why}")
            }
            MemberRefusal::NotVerified(id, state) => format!(
                "the reply to request {id} was not verified as the peer's refusal ({state}), so \
                 it is not a member"
            ),
            MemberRefusal::ReplyNotKept(id, why) => {
                format!("the reply to request {id} cannot be read back: {why}")
            }
            MemberRefusal::OwnKey(id) => {
                format!("the refusal to request {id} is signed under this node's own key")
            }
            MemberRefusal::Inconsistent(id) => {
                format!("the outcome recorded for request {id} names another request digest")
            }
            MemberRefusal::NoWindow(id) => {
                format!("the absence recorded for request {id} states no window")
            }
            MemberRefusal::Duplicate(id) => format!("request {id} is named twice"),
        }
    }
}

/// What composing ran into.
#[derive(Debug)]
pub enum ComposeError {
    Receipt(Error),
    Member(MemberRefusal),
    /// The deal's report does not cite the exchange record in its `did` lines.
    NotCited,
    /// No member was named.
    NoMembers,
    /// The members' peers are more than the deal's one other party.
    TwoParties,
}

impl From<Error> for ComposeError {
    fn from(e: Error) -> Self {
        ComposeError::Receipt(e)
    }
}

impl From<Refusal> for ComposeError {
    fn from(r: Refusal) -> Self {
        ComposeError::Receipt(r.into())
    }
}

impl From<MemberRefusal> for ComposeError {
    fn from(r: MemberRefusal) -> Self {
        ComposeError::Member(r)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn jcs_digest(value: &Value) -> Result<String, Error> {
    jcs(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|e| Error::Failed(format!("no canonical form: {e}")))
}

/// The composed digest of a block (agent-disclosure-bundle-01, "The
/// composed/v1 Extension"; the core's `ComposedDigest`): SHA-256 of the JCS
/// of `{kind, members, observers, joins, not_requested}`, each reduced to
/// its declared fields and sorted. Member bodies, `missing` and
/// `composed_digest` are not in it. Only blocks this module builds are
/// given: no join and no `not_requested` entry.
pub(crate) fn composed_digest(members: &[Value], observers: &[Value]) -> Result<String, Error> {
    let pick = |v: &Value, names: &[&str]| -> Value {
        Value::Object(
            names
                .iter()
                .map(|n| ((*n).to_string(), v.get(*n).cloned().unwrap_or(Value::Null)))
                .collect(),
        )
    };
    let id = |v: &Value| v["id"].as_str().unwrap_or_default().to_string();
    let mut members: Vec<Value> = members
        .iter()
        .map(|m| {
            pick(
                m,
                &["id", "observer", "request_digest", "outcome", "digest"],
            )
        })
        .collect();
    members.sort_by_key(id);
    let mut observers: Vec<Value> = observers
        .iter()
        .map(|o| pick(o, &["id", "role", "custody_domain"]))
        .collect();
    observers.sort_by_key(id);
    jcs_digest(&json!({
        "kind": COMPOSED_KIND,
        "members": members,
        "observers": observers,
        "joins": [],
        "not_requested": [],
    }))
}

/// The member for the request recorded as `request_record`, from its
/// recorded outcome, with its observer: this node (`own`) for an absence,
/// only it observed; the refusing peer's key for a refusal (D4: a node's
/// checkpoint key is its signing key, so it is also the custody domain).
pub(crate) fn member(
    ledger_dir: &Path,
    entries: &[(String, Map<String, Value>)],
    own: &str,
    request_record: &str,
) -> Result<Value, ComposeError> {
    let record_type = |e: &Map<String, Value>| {
        e.get("record_type")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let request = entries
        .iter()
        .find(|(id, e)| {
            id == request_record && record_type(e).as_deref() == Some(record_types::REQUEST)
        })
        .and_then(|(_, e)| e.get("statement")?.get("request"))
        .ok_or_else(|| MemberRefusal::NotARequest(request_record.into()))?;
    // The digest of the bytes on the wire: the record holds the request as
    // transmitted, which went as its JCS bytes (`ask_book::check_request`).
    let request_digest = evidence_request::jcs::to_string(request)
        .map(|text| evidence_request::digest::request_digest(text.as_bytes()))
        .map_err(|e| Error::Failed(format!("request {request_record}: {e}")))?;
    let (outcome_id, outcome) = entries
        .iter()
        .find(|(_, e)| {
            matches!(
                record_type(e).as_deref(),
                Some(record_types::RESPONSE | record_types::RECORDED_ABSENCE)
            ) && crate::ask_book::cites(e, request_record)
        })
        .ok_or_else(|| MemberRefusal::Pending(request_record.into()))?;
    let statement = outcome.get("statement").cloned().unwrap_or(Value::Null);
    if statement.get("request_digest").and_then(Value::as_str) != Some(request_digest.as_str()) {
        return Err(MemberRefusal::Inconsistent(request_record.into()).into());
    }
    if record_type(outcome).as_deref() == Some(record_types::RESPONSE) {
        return answer_member(
            ledger_dir,
            own,
            request,
            request_record,
            &request_digest,
            outcome_id,
            &statement,
        );
    }
    let window = |name: &str| statement.pointer(&format!("/window/{name}")).cloned();
    let (Some(from), Some(to)) = (window("opened"), window("closed")) else {
        return Err(MemberRefusal::NoWindow(request_record.into()).into());
    };
    let mut absence = Map::new();
    absence.insert("request_digest".into(), json!(request_digest));
    absence.insert("window".into(), json!({"from": from, "to": to}));
    if let Some(route) = statement.get("route").filter(|r| r.is_string()) {
        absence.insert("route".into(), route.clone());
    }
    let absence = Value::Object(absence);
    Ok(json!({
        "id": request_record,
        "observer": own,
        "request_digest": request_digest,
        "outcome": "absence",
        "digest": jcs_digest(&absence)?,
        "absence": absence,
    }))
}

/// The member for an answered request, from the reply exactly as it came
/// back (the kept reply, #198). Only a reply this node verified under the
/// key the peer announced is a member, observed by that key: a refusal
/// (`verification.state` `refusal`), or an `evidence_bundle/1` answer
/// (`artifact`, #197). Anything else, such as a nonconformant refusal, an
/// unchecked reply or another artifact form, is refused by name rather
/// than carried as theirs, as `capsulectl-deal` refuses a copy it recorded
/// as failed.
fn answer_member(
    ledger_dir: &Path,
    own: &str,
    request: &Value,
    request_record: &str,
    request_digest: &str,
    response_record: &str,
    statement: &Value,
) -> Result<Value, ComposeError> {
    let outcome = statement.get("outcome").and_then(Value::as_str);
    let state = statement
        .pointer("/verification/state")
        .and_then(Value::as_str)
        .unwrap_or("not recorded");
    let refused = match outcome {
        Some("refusal") if state == "refusal" => true,
        Some("artifact") if state == "artifact" => false,
        _ => {
            let what = format!(
                "recorded {}, checked {state}",
                outcome.unwrap_or("no outcome")
            );
            return Err(MemberRefusal::NotVerified(request_record.into(), what).into());
        }
    };
    if !refused
        && request.get("derivation").and_then(Value::as_str) != Some(crate::bundle_answer::TOKEN)
    {
        return Err(MemberRefusal::Answered(request_record.into()).into());
    }
    let reply = crate::ask_book::kept_reply(ledger_dir, response_record)
        .map_err(|e| MemberRefusal::ReplyNotKept(request_record.into(), e.to_string()))?;
    let reply: Value = serde_json::from_slice(&reply).map_err(|e| {
        MemberRefusal::ReplyNotKept(request_record.into(), format!("not JSON: {e}"))
    })?;
    if refused {
        refusal_member(own, request_record, request_digest, reply)
    } else {
        artifact_member(own, request_record, request_digest, reply)
    }
}

/// The `artifact` member: the provider's bundle, from the answer's artifact
/// octets (its JCS, so its BundleDigest is the signed `artifact_digest`),
/// with the evidence-interop envelope as received minus its `artifact` as
/// the member's `response` (D4 as amended at evidencebook-deal c829087;
/// capsule-cli's `evidence-interop-envelope` response profile). The witness
/// receipts the reply carries beside the envelope are not part of it.
/// Observed by the envelope's `responder`, which must have signed the
/// bundle's checkpoint (D4: a node's checkpoint key is its signing key).
fn artifact_member(
    own: &str,
    request_record: &str,
    request_digest: &str,
    reply: Value,
) -> Result<Value, ComposeError> {
    use base64::Engine as _;
    let unbound = |why: &str| MemberRefusal::Unbound(request_record.into(), why.into());
    let Value::Object(mut response) = reply else {
        return Err(unbound("the reply is not an envelope").into());
    };
    let artifact = response
        .remove("artifact")
        .and_then(|a| a.as_str().map(str::to_string))
        .and_then(|a| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(a)
                .ok()
        })
        .ok_or_else(|| unbound("the envelope carries no artifact"))?;
    response.remove(crate::evidence_artifact::WITNESS_RECEIPTS);
    let bundle: Value =
        serde_json::from_slice(&artifact).map_err(|_| unbound("the artifact is not a bundle"))?;
    let digest = agent_action_capsule::bundle::bundle_digest(&bundle)
        .map_err(|_| unbound("the artifact is not a bundle"))?;
    if response.get("artifact_digest").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err(unbound("its digest is not the artifact_digest the response signs").into());
    }
    if response.get("request_digest").and_then(Value::as_str) != Some(request_digest) {
        return Err(MemberRefusal::Inconsistent(request_record.into()).into());
    }
    let key = response
        .get("responder")
        .and_then(Value::as_str)
        .filter(|k| evidence_request::registry::is_digest(k))
        .ok_or_else(|| unbound("the response names no responder"))?
        .to_string();
    if key == own {
        return Err(MemberRefusal::OwnKey(request_record.into()).into());
    }
    if bundle.pointer("/checkpoint/key_id").and_then(Value::as_str) != Some(key.as_str()) {
        return Err(unbound("its checkpoint is not signed by the responder").into());
    }
    Ok(json!({
        "id": request_record,
        "observer": key,
        "request_digest": request_digest,
        "outcome": "artifact",
        "digest": digest,
        "bundle": bundle,
        "response": Value::Object(response),
    }))
}

/// The `refusal` member: the signed refusal exactly as it came back,
/// observed by its key.
fn refusal_member(
    own: &str,
    request_record: &str,
    request_digest: &str,
    refusal: Value,
) -> Result<Value, ComposeError> {
    if refusal.get("request_digest").and_then(Value::as_str) != Some(request_digest) {
        return Err(MemberRefusal::Inconsistent(request_record.into()).into());
    }
    let key = refusal
        .get("key_id")
        .and_then(Value::as_str)
        .filter(|k| evidence_request::registry::is_digest(k))
        .ok_or_else(|| {
            MemberRefusal::NotVerified(request_record.into(), "the refusal names no key".into())
        })?;
    if key == own {
        return Err(MemberRefusal::OwnKey(request_record.into()).into());
    }
    Ok(json!({
        "id": request_record,
        "observer": key,
        "request_digest": request_digest,
        "outcome": "refusal",
        "digest": jcs_digest(&refusal)?,
        "refusal": refusal,
    }))
}

/// The `composed/v1` block over `request_records`: this node (`own`)
/// observes the absences, the peer its refusals and its bundle answers.
pub(crate) fn block(
    ledger_dir: &Path,
    own: &str,
    request_records: &[String],
) -> Result<Value, ComposeError> {
    if request_records.is_empty() {
        return Err(ComposeError::NoMembers);
    }
    let entries = crate::ask_book::entries(ledger_dir);
    let mut members = Vec::with_capacity(request_records.len());
    for (i, id) in request_records.iter().enumerate() {
        if request_records[..i].contains(id) {
            return Err(MemberRefusal::Duplicate(id.clone()).into());
        }
        members.push(member(ledger_dir, &entries, own, id)?);
    }
    members.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    // One observer per key, its custody domain the same key (D4). A deal has
    // one other party: a second peer key is refused.
    let mut keys: Vec<&str> = members
        .iter()
        .filter_map(|m| m["observer"].as_str())
        .collect();
    keys.sort_unstable();
    keys.dedup();
    if keys.iter().filter(|k| **k != own).count() > 1 {
        return Err(ComposeError::TwoParties);
    }
    let observers: Vec<Value> = keys
        .iter()
        .map(|k| json!({"id": k, "role": OBSERVER_ROLE, "custody_domain": k}))
        .collect();
    let digest = composed_digest(&members, &observers)?;
    Ok(json!({
        "members": members,
        "observers": observers,
        "joins": [],
        "composed_digest": digest,
    }))
}

/// The composition payload, as `capsulectl-deal` seals it, in JCS.
pub(crate) fn payload(
    deal_id: &str,
    composed_digest: &str,
    request_records: &[String],
) -> Result<Vec<u8>, Error> {
    jcs(&json!({
        "type": COMPOSITION_TYPE,
        "profile": deal::PROFILE,
        "deal_id": deal_id,
        "composed_digest": composed_digest,
        "request_records": request_records,
    }))
    .map_err(|e| Error::Failed(format!("the composition payload: {e}")))
}

/// Whether the report's `did` lines cite `exchange` as a step (each line's
/// `steps` are capsule ids, `deal_flow::report_body`).
fn report_cites(report: &Value, exchange: &str) -> bool {
    report
        .pointer("/report/did")
        .and_then(Value::as_array)
        .is_some_and(|did| {
            did.iter().any(|line| {
                line.get("steps")
                    .and_then(Value::as_array)
                    .is_some_and(|steps| steps.iter().any(|s| s.as_str() == Some(exchange)))
            })
        })
}

/// The composition record already sealed for `digest` (the payload's), so
/// composing the same members again seals nothing new.
fn sealed_composition(ledger_dir: &Path, digest: &str) -> Option<String> {
    crate::evidence_panes::read_capsule_records(ledger_dir)
        .iter()
        .filter(|r| is_composition(r))
        .find(|r| {
            r.pointer("/model_attestation/compute_attestation/agent_input_digest")
                .and_then(Value::as_str)
                == Some(digest)
        })
        .and_then(|r| r.get("capsule_id")?.as_str().map(str::to_string))
}

/// The Capsule a composition is sealed in: a local `fyi` record chained to
/// the ledger's head, committing the payload as its agent input.
fn composition_capsule(
    payload: &[u8],
    parent: Option<&str>,
    unix: i64,
) -> Result<produce::BuiltPayload, crate::deal_records::Error> {
    let timestamp = chrono::DateTime::from_timestamp(unix, 0)
        .ok_or_else(|| crate::deal_records::Error::Invalid("the clock is out of range".into()))?;
    Ok(produce::build(produce::Input {
        action_id: ACTION_ID.into(),
        action_type: deal::ACTION_TYPE_FYI.into(),
        operator: crate::producer::capsule::LOCAL_RECORD_OPERATOR.into(),
        developer: crate::producer::capsule::LOCAL_RECORD_DEVELOPER.into(),
        timestamp: Some(timestamp),
        chain: parent.map(|p| produce::Chain {
            parent_capsule_id: p.into(),
            relation: deal::RELATION_FOLLOWS.into(),
        }),
        compute: Some(produce::ComputeAttestation {
            agent_input_digest: sha256_hex(payload),
            ..Default::default()
        }),
        ..Default::default()
    })?)
}

/// The deal of `exchange`: its records and payloads, and its id. Refused
/// when the report does not cite the exchange record.
fn deal_of(
    ledger_dir: &Path,
    node_key_id: &str,
    exchange: &str,
) -> Result<(super::Deal, String), ComposeError> {
    let unreadable = |e: std::io::Error| Error::Failed(format!("the ledger is not readable: {e}"));
    let ids: Vec<String> = evidence_log::with_index(ledger_dir, node_key_id, |index| {
        index
            .deal_capsules_of(exchange)
            .into_iter()
            .map(str::to_string)
            .collect()
    })
    .map_err(unreadable)?;
    if ids.is_empty() {
        return Err(Refusal::NoDeal.into());
    }
    let deal = read_deal(ledger_dir, ids)?;
    let report = &deal.payloads[&deal.report];
    if !report_cites(report, exchange) {
        return Err(ComposeError::NotCited);
    }
    let deal_id = report
        .get("deal_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Failed("the deal report names no deal_id".into()))?
        .to_string();
    Ok((deal, deal_id))
}

/// A composition sealed on this ledger: its record, the block it names by
/// digest, and its payload.
#[derive(Debug)]
pub(crate) struct Composition {
    pub id: String,
    pub block: Value,
    pub payload: Value,
}

/// The `before` hook's refusal when the same composition was sealed while
/// this one waited for the ledger's writer lock.
const ALREADY_SEALED: &str = "the same composition was sealed meanwhile";

/// Seal (or find) the composition for `exchange` over `request_records`,
/// taken in id order: the same member set is one record, whatever order it
/// is named in.
pub(crate) fn seal(
    capsules: &crate::capsule_emit::CapsuleState,
    exchange: &str,
    request_records: &[String],
    unix: i64,
) -> Result<Composition, ComposeError> {
    use crate::deal_flow::Sealer as _;
    let ledger_dir = capsules.ledger_dir();
    let own = crate::commitment::key_id(capsules.signing_key());
    let (_, deal_id) = deal_of(ledger_dir, &own, exchange)?;
    let mut records = request_records.to_vec();
    records.sort_unstable();
    let block = block(ledger_dir, &own, &records)?;
    let digest = block["composed_digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let bytes = payload(&deal_id, &digest, &records)?;
    let payload: Value = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Failed(format!("the composition payload: {e}")))?;
    let committed = sha256_hex(&bytes);
    let found = |block: Value, payload: Value| {
        sealed_composition(ledger_dir, &committed).map(|id| Composition { id, block, payload })
    };
    if let Some(sealed) = found(block.clone(), payload.clone()) {
        return Ok(sealed);
    }
    // Checked again under the ledger's writer lock, so two asks at once
    // seal one record.
    let sealed =
        capsules.seal(
            &|head| composition_capsule(&bytes, head, unix),
            &|_| match sealed_composition(ledger_dir, &committed) {
                Some(_) => Err(std::io::Error::other(ALREADY_SEALED)),
                None => Ok(()),
            },
        );
    match sealed {
        Ok(id) => Ok(Composition { id, block, payload }),
        Err(e) => found(block, payload)
            .ok_or_else(|| Error::Failed(format!("the composition was not sealed: {e}")).into()),
    }
}

/// The composed bundle for `exchange` whose composition record [`seal`]
/// sealed.
pub(crate) fn bundle(
    ledger_dir: &Path,
    node_key_id: &str,
    exchange: &str,
    composition: &Composition,
) -> Result<Value, ComposeError> {
    let (deal, _) = deal_of(ledger_dir, node_key_id, exchange)?;
    let unreadable = |e: std::io::Error| Error::Failed(format!("the ledger is not readable: {e}"));
    let built = evidence_log::with_index(ledger_dir, node_key_id, |index: &LedgerIndex| {
        if index.deal_capsules_of(exchange)
            != deal.ids.iter().map(String::as_str).collect::<Vec<_>>()
        {
            return Err(Error::Failed(
                "the deal changed while it was read; ask again".into(),
            ));
        }
        if index.leaf_index_of(exchange).is_none() {
            return Err(Error::Failed(format!(
                "the exchange record {exchange} is not in this ledger"
            )));
        }
        let mut ids = deal.ids.clone();
        ids.push(exchange.to_string());
        ids.push(composition.id.clone());
        let mut disclosures: BTreeMap<String, Map<String, Value>> = deal
            .payloads
            .iter()
            .map(|(id, p)| {
                let mut members = Map::new();
                members.insert("agent_input".into(), p.clone());
                (id.clone(), members)
            })
            .collect();
        let mut members = Map::new();
        members.insert("agent_input".into(), composition.payload.clone());
        disclosures.insert(composition.id.clone(), members);
        let mut extensions = Map::new();
        extensions.insert(
            deal::PROFILE.into(),
            json!({ deal::REPORT_POINTER: deal.report }),
        );
        interval_bundle(
            index,
            node_key_id,
            Selection {
                root: &composition.id,
                ids: &ids,
                disclosures,
                extensions,
            },
        )
    })
    .map_err(unreadable)??;
    let mut built = built;
    built["extensions"][COMPOSED_KIND] = composition.block.clone();
    Ok(built)
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ComposeArgs {
    /// The exchange record's capsule id: 64 lowercase hex.
    pub capsule_id: Value,
    /// The request records (64 lowercase hex) of this node's asks whose
    /// recorded outcomes are the members.
    pub request_records: Vec<Value>,
}

fn hex64(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .map(str::to_string)
}

/// The route's input, checked: the exchange and the request records.
fn parse(args: &ComposeArgs) -> Result<(String, Vec<String>), String> {
    let exchange = hex64(&args.capsule_id).ok_or("capsule_id must be 64 lowercase hex")?;
    let records = args
        .request_records
        .iter()
        .map(hex64)
        .collect::<Option<Vec<_>>>()
        .ok_or("each request record must be 64 lowercase hex")?;
    Ok((exchange, records))
}

/// The route's answer once the composition is sealed (or refused) and a
/// checkpoint was cut over it: `{"state": "bundle", "bundle": ...}`, or
/// `{"state": "refused", "why": ...}` for the owner's input or this node's
/// state; an error for a failure the host reports.
pub(crate) fn answer(
    ledger_dir: &Path,
    node_key_id: &str,
    exchange: &str,
    sealed: Result<Composition, ComposeError>,
) -> Result<Value, String> {
    match sealed.and_then(|c| bundle(ledger_dir, node_key_id, exchange, &c)) {
        Ok(bundle) => Ok(json!({"state": "bundle", "bundle": bundle})),
        Err(error) => refused(error),
    }
}

/// A refusal's answer, or the error the host reports.
fn refused(error: ComposeError) -> Result<Value, String> {
    let why = match error {
        ComposeError::Receipt(Error::Failed(why)) => return Err(why),
        ComposeError::Receipt(Error::Refused(r)) => r.why(),
        ComposeError::Member(r) => r.why(),
        ComposeError::NotCited => "the deal's report does not cite that exchange record".into(),
        ComposeError::NoMembers => "name at least one request record".into(),
        ComposeError::TwoParties => {
            "the members were answered by more than one peer; a deal has one other party".into()
        }
    };
    Ok(json!({"state": "refused", "why": why}))
}

/// `builder` with the `deal-composition` route declared. It seals the
/// composition record (once per member set, in any order), cuts a
/// checkpoint covering it, and gives [`answer`].
pub fn with_route(
    builder: DeclarativePluginBuilder,
    capsules: Arc<crate::capsule_emit::CapsuleState>,
    checkpoints: Option<CheckpointHandle>,
) -> DeclarativePluginBuilder {
    builder.http_item(
        http::post("/deal-composition")
            .binding_id("evidence_deal_composition")
            .description(
                "The payer's receipt with the other party's half for one paid exchange: a \
                 composed/v1 bundle of this node's ledger whose members are the outcomes of \
                 this node's asks. Seals a composition record and cuts a checkpoint over it.",
            )
            .input::<ComposeArgs>()
            .handle(move |args, _context| {
                let capsules = capsules.clone();
                let checkpoints = checkpoints.clone();
                Box::pin(async move {
                    let (exchange, records) = parse(&args).map_err(PluginError::invalid_params)?;
                    let sealed = {
                        let (capsules, exchange) = (capsules.clone(), exchange.clone());
                        tokio::task::spawn_blocking(move || {
                            seal(
                                &capsules,
                                &exchange,
                                &records,
                                chrono::Utc::now().timestamp(),
                            )
                        })
                        .await
                        .map_err(|e| PluginError::internal(format!("composition task: {e}")))?
                    };
                    if let (Some(handle), Ok(sealed)) = (checkpoints.as_ref(), &sealed) {
                        // A cut that fails leaves the answer to say there is
                        // no covering checkpoint.
                        let _ = handle.coverage_for(&sealed.id).await;
                    }
                    tokio::task::spawn_blocking(move || {
                        let key = crate::commitment::key_id(capsules.signing_key());
                        answer(capsules.ledger_dir(), &key, &exchange, sealed)
                    })
                    .await
                    .map_err(|e| PluginError::internal(format!("composition task: {e}")))?
                    .map_err(PluginError::internal)
                })
            }),
    )
}

#[cfg(test)]
mod tests;
