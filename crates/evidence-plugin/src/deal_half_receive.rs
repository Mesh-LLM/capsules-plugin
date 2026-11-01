//! Receive a Goose node's deal half (`goose-deal-half/1`) that its operator
//! hands this node, and verify it under the keys the operator admitted
//! (action-state-group/evidencebook#291).
//!
//! **Why an operator tool.** A Goose node is not a mesh peer, so it cannot
//! use `record-push/1`. Goose moves a deal half as a file over whatever
//! channel the two parties use (evidencebook `python/examples/goose`), and
//! this tool is where such a file enters a Mesh node. The half's shape is
//! Goose's: `{"half": "goose-deal-half/1", "deal_id", "book_id", "steps":
//! [{"capsule", "payload"}...], "checkpoint": {"key_id", "statement"}}`.
//! Like record-push, this is plugin-internal behaviour, not a standardized
//! wire, and may change.
//!
//! **Which keys.** Never a key the half carries, and only keys the operator
//! admitted in `CAPSULES_PEER_KEYS`: a Goose node is never a mesh peer, so a
//! host announcement does not count. The steps' signing key must be one the
//! map gives a name ([`crate::peer_keys::accepted_via`] over the map alone),
//! and the half's checkpoint key must be the key it gives that name plus
//! [`CHECKPOINT_SUFFIX`]: the operator admits a Goose node with
//! `{"goose-seller": "<signing key>", "goose-seller/checkpoint": "<checkpoint
//! key>"}`, the two keys the node's `loop_join` prints.
//!
//! **The checks**, in order; the first that fails refuses the half and
//! nothing is stored or sealed:
//! 1. The text parses strictly and has exactly the members above, else
//!    `request_malformed`.
//! 2. The steps' key is accepted, else `signature_unverified`; the
//!    checkpoint's key is that peer's admitted checkpoint key, else
//!    `checkpoint_unverified`.
//! 3. Each step `n`: its Capsule carries neither member the record-push
//!    store reads as something other than a record (a bundle marker or a
//!    verdict delivery), else `record_unverified`; it passes the Class 1
//!    checks on its own bytes and its producer envelope verifies under the
//!    steps' key (`signature_unverified` otherwise); it is step `n` of the
//!    deal (its `action_id` and `deal_id`), carries its `deal_step` record
//!    header for the half's book, chains to the step before it, cites only
//!    its chain parent (the baseline may cite its admission, and a close step,
//!    in the new form, the counterparty's checkpoint: see
//!    [`OVERLAP_ACCEPTS_CURRENT_FORM`] for the two forms), commits its
//!    payload, and the payload passes x-deal-v0's record checks (evidencebook
//!    `deal::check`), else `record_unverified`.
//! 4. The checkpoint statement's signature verifies under its own key, and
//!    it commits exactly these steps (the MMR over their ids, in order), else
//!    `checkpoint_unverified`.
//! 5. No step makes a serving claim the record-push store refuses
//!    (`record_push_receive::claims_verdict`, judged against this node's own
//!    records), else `record_unverified`: checked before anything is stored,
//!    so a half that store would refuse part-way is refused whole.
//!
//! These are the checks the Goose node itself runs on a counterparty's half
//! (`verify_half`), except the profile's chain stage (x-deal-v0 §6), which
//! only the Python reference checker implements; the reply says so
//! (`"chain_stage": "not_checked"`).
//!
//! **What is kept.** Each step's Capsule is held exactly as the record-push
//! receiver holds a pushed half (`received-capsules.jsonl` with its
//! provenance, `via` [`VIA`]), the half's checkpoint and step ids go to
//! [`RECEIVED_DEAL_HALVES_FILENAME`], and this node seals the same
//! `counterparty_half` citing record for each step that it seals for a
//! pushed half. None of it enters this node's own chain except those citing
//! records. Handing the same half in again stores and seals nothing new.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use evidencebook::deal;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::record_push_receive as receive;

/// The MCP operation.
pub const RECEIVE_DEAL_HALF_OPERATION: &str = "receive_deal_half";

/// The one half format this tool reads.
pub const HALF_FORMAT: &str = "goose-deal-half/1";

/// What a peer's name is suffixed with in the key registry to name its
/// checkpoint key.
pub const CHECKPOINT_SUFFIX: &str = "/checkpoint";

/// The carrier written to each held step's provenance and citing record:
/// the operator handed the half in.
pub const VIA: &str = "operator";

/// The held store of received halves: one line per distinct checkpoint
/// received, with the deal, the keys, the steps' ids and the statement.
pub const RECEIVED_DEAL_HALVES_FILENAME: &str = "received-deal-halves.jsonl";

pub const REASON_REQUEST_MALFORMED: &str = "request_malformed";
pub const REASON_SIGNATURE_UNVERIFIED: &str = "signature_unverified";
pub const REASON_RECORD_UNVERIFIED: &str = "record_unverified";
pub const REASON_CHECKPOINT_UNVERIFIED: &str = "checkpoint_unverified";

/// The overlap window (D3, evidencebook#291): while this is true, a half in
/// the current form, whose close step cites only its chain parent, is
/// accepted beside the new form, whose close step also cites the
/// counterparty's checkpoint (Steven's ruling on evidencebook#303, option
/// (a)). The window closes with the first capsules-plugin release tagged at
/// least 30 days after the first evidencebook release whose Goose reference
/// sends halves in the new form. From that release on, a half in the current
/// form is refused `record_unverified`: the PR that closes it sets this to
/// false.
pub const OVERLAP_ACCEPTS_CURRENT_FORM: bool = true;

/// The two forms a half may take, as the reply and the held line name them.
pub const FORM_CURRENT: &str = "current";
pub const FORM_CITES_COUNTERPARTY_CHECKPOINT: &str = "cites_counterparty_checkpoint";

/// More steps than this in one half is refused before any is checked. A deal
/// is a handful of steps; this bounds the work one call can ask for.
pub const MAX_STEPS: usize = 256;

/// One receipt at a time: the held-store dedup reads and then appends.
static RECEIVING: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReceiveDealHalfArgs {
    /// The half's JSON text (`goose-deal-half/1`), exactly as the
    /// counterparty's file holds it.
    pub half: String,
}

/// Why a half was refused: one of the `REASON_*` codes, the 1-based step it
/// concerns when it concerns one, and what failed.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    pub reason: &'static str,
    pub step: Option<usize>,
    pub detail: String,
}

fn refused(reason: &'static str, step: Option<usize>, detail: impl Into<String>) -> Refused {
    Refused {
        reason,
        step,
        detail: detail.into(),
    }
}

/// A half that passed every check.
#[derive(Debug)]
pub struct Verified {
    pub deal_id: String,
    pub book_id: String,
    pub key_id: String,
    pub checkpoint_key_id: String,
    /// The peer name the keys were accepted under: the first, in the
    /// registry's order, whose checkpoint key matched.
    pub peer: String,
    pub accepted: crate::peer_keys::Accepted,
    /// Each step's Capsule, in order, as it arrived.
    pub capsules: Vec<Value>,
    pub statement_hex: String,
    /// [`FORM_CURRENT`] or [`FORM_CITES_COUNTERPARTY_CHECKPOINT`].
    pub form: &'static str,
    /// The counterparty checkpoints the close steps cite (the new form), in
    /// step order, each once. Cited, not verified: this node does not hold
    /// those checkpoints.
    pub counterparty_checkpoint_cites: Vec<String>,
}

/// The keys one call checks under.
pub struct Keys<'a> {
    /// The raw `CAPSULES_PEER_KEYS` value: the only keys a half is checked
    /// under.
    pub configured: Option<&'a str>,
    /// This node's own key, never accepted as a counterparty's.
    pub own_key: &'a str,
    /// Whether a half in the current form is still accepted: the tool passes
    /// [`OVERLAP_ACCEPTS_CURRENT_FORM`].
    pub accept_current_form: bool,
}

/// No host-announced keys: a Goose node's keys come from the operator.
static NO_ANNOUNCED: std::sync::LazyLock<BTreeMap<String, String>> =
    std::sync::LazyLock::new(BTreeMap::new);

fn exact_members(value: &Value, members: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|m| m.len() == members.len() && members.iter().all(|k| m.contains_key(*k)))
}

/// Where a step sits in the deal, which decides the links it may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StepRole {
    /// Step 1: no chain parent; it may cite the admission it rests on
    /// (evidencebook#307), which is no checkpoint.
    Baseline,
    /// A `close` step: its chain parent and, in the new form, the
    /// counterparty's checkpoint (evidencebook#303).
    Close,
    /// Any other step: its chain parent alone.
    Other,
}

/// A step header's links, by x-deal-v0's rule and its two exceptions:
/// exactly one `cites` link to the chain parent (none for the baseline);
/// beside it, at most one cite of the admission on the baseline, and cites of
/// the counterparty's checkpoint on a close step. Returns those checkpoint
/// cites, in order.
pub(crate) fn step_cites(
    header: &Value,
    parent: Option<&str>,
    role: StepRole,
) -> Result<Vec<String>, &'static str> {
    let links = header["links"]
        .as_array()
        .ok_or("the record header has no links")?;
    let mut parent_cited = false;
    let mut others = Vec::new();
    for link in links {
        let target = link["target"]
            .as_str()
            .filter(|_| exact_members(link, &["target", "type"]) && link["type"] == "cites")
            .filter(|t| receive::is_lower_hex(t, 64))
            .ok_or("a header link is not a cites link to a digest")?;
        if Some(target) == parent {
            if parent_cited {
                return Err("the record header cites its chain parent more than once");
            }
            parent_cited = true;
        } else {
            others.push(target.to_string());
        }
    }
    if parent.is_some() && !parent_cited {
        return Err("the record header does not cite the step's chain parent");
    }
    match role {
        StepRole::Baseline if others.len() <= 1 => Ok(Vec::new()),
        StepRole::Baseline => Err("the baseline cites more than its admission"),
        StepRole::Close => Ok(others),
        StepRole::Other if others.is_empty() => Ok(Vec::new()),
        StepRole::Other => Err("a step that is not a close cites more than its chain parent"),
    }
}

/// The first cite that names one of the half's own steps: never a
/// counterparty checkpoint.
pub(crate) fn own_step_cite<'a>(cites: &'a [String], capsules: &[Value]) -> Option<&'a str> {
    cites
        .iter()
        .find(|cite| capsules.iter().any(|c| c["capsule_id"] == cite.as_str()))
        .map(String::as_str)
}

/// Run every check over `text` at `now` (RFC 3339, for a carried
/// declaration's validity; a half carries none, so it only feeds
/// [`crate::peer_keys::accepted_via`]).
pub fn verify(text: &[u8], keys: &Keys<'_>, now: &str) -> Result<Verified, Refused> {
    let malformed = |detail: &str| refused(REASON_REQUEST_MALFORMED, None, detail);
    let half =
        crate::strict_json::parse(text).map_err(|_| malformed("the half is not strict JSON"))?;
    if !exact_members(
        &half,
        &["half", "deal_id", "book_id", "steps", "checkpoint"],
    ) {
        return Err(malformed(
            "a half has exactly the members half, deal_id, book_id, steps and checkpoint",
        ));
    }
    if half["half"] != HALF_FORMAT {
        return Err(malformed("not a goose-deal-half/1"));
    }
    let (Some(deal_id), Some(book_id)) = (half["deal_id"].as_str(), half["book_id"].as_str())
    else {
        return Err(malformed("deal_id and book_id are strings"));
    };
    let steps = match half["steps"].as_array() {
        Some(steps) if !steps.is_empty() && steps.len() <= MAX_STEPS => steps,
        _ => return Err(malformed("steps is a list of 1 to 256 steps")),
    };
    let checkpoint = &half["checkpoint"];
    if !exact_members(checkpoint, &["key_id", "statement"]) {
        return Err(malformed(
            "the checkpoint has exactly the members key_id and statement",
        ));
    }
    let (Some(checkpoint_key), Some(statement_hex)) = (
        checkpoint["key_id"].as_str(),
        checkpoint["statement"].as_str(),
    ) else {
        return Err(malformed(
            "the checkpoint's key_id and statement are strings",
        ));
    };
    let statement =
        hex::decode(statement_hex).map_err(|_| malformed("the checkpoint statement is not hex"))?;
    for (i, step) in steps.iter().enumerate() {
        if !exact_members(step, &["capsule", "payload"]) {
            return Err(refused(
                REASON_REQUEST_MALFORMED,
                Some(i + 1),
                "a step has exactly the members capsule and payload",
            ));
        }
    }

    // The cheap refusals first: keys this node accepts, before any work on
    // the records' bytes.
    let key_id = steps[0]["capsule"]["key_id"]
        .as_str()
        .filter(|k| receive::is_lower_hex(k, 64))
        .ok_or_else(|| refused(REASON_SIGNATURE_UNVERIFIED, Some(1), "step 1 names no key"))?;
    let accepted = crate::peer_keys::accepted_via(
        keys.configured,
        &NO_ANNOUNCED,
        key_id,
        keys.own_key,
        None,
        evidence_request::time::parse_utc(now),
    )
    .ok_or_else(|| {
        refused(
            REASON_SIGNATURE_UNVERIFIED,
            None,
            format!("this node accepts no peer with the key {key_id}"),
        )
    })?;
    let registry = crate::peer_keys::merged(keys.configured, &NO_ANNOUNCED);
    let peer = accepted
        .peers
        .iter()
        .find(|peer| {
            crate::peer_keys::announced_key_in(
                registry.as_deref(),
                &format!("{peer}{CHECKPOINT_SUFFIX}"),
            )
            .is_some_and(|admitted| !admitted.is_empty() && admitted == checkpoint_key)
        })
        .cloned()
        .ok_or_else(|| {
            refused(
                REASON_CHECKPOINT_UNVERIFIED,
                None,
                format!(
                    "the checkpoint key {checkpoint_key} is not admitted as <peer>{CHECKPOINT_SUFFIX} \
                     for a peer of the key {key_id}"
                ),
            )
        })?;

    let mut nodes = cll::mmr::MemoryNodeStore::new();
    let mut cites: Vec<String> = Vec::new();
    let mut parent: Option<String> = None;
    let mut capsules = Vec::with_capacity(steps.len());
    for (i, step) in steps.iter().enumerate() {
        let n = i + 1;
        let capsule = &step["capsule"];
        let unverified = |detail: String| refused(REASON_RECORD_UNVERIFIED, Some(n), detail);
        if capsule["key_id"] != key_id {
            return Err(refused(
                REASON_SIGNATURE_UNVERIFIED,
                Some(n),
                "the step is not under the half's one key",
            ));
        }
        // The record-push store takes a body with either member for a bundle
        // or a delivered verdict, not a record: refused here, before it
        // could refuse one step part-way through holding the half.
        if [
            receive::BUNDLE_MARKER,
            crate::referee::hold::DELIVERY_MARKER,
        ]
        .iter()
        .any(|member| capsule.get(*member).is_some())
        {
            return Err(unverified(
                "the Capsule carries a member the record-push store does not take as a record"
                    .into(),
            ));
        }
        let Some(capsule_id) = receive::record_id(capsule) else {
            return Err(refused(
                REASON_SIGNATURE_UNVERIFIED,
                Some(n),
                "the Capsule fails the Class 1 checks",
            ));
        };
        if !receive::signed_by(capsule, key_id) {
            return Err(refused(
                REASON_SIGNATURE_UNVERIFIED,
                Some(n),
                "the producer envelope does not verify under the half's key",
            ));
        }
        let subject = format!("{deal_id}/{n}");
        if capsule["action_id"] != subject.as_str() || capsule["deal_id"] != deal_id {
            return Err(unverified(format!("not step {n} of deal {deal_id}")));
        }
        let header = &capsule["evidence_record_header"];
        if header["record_type"] != deal::STEP_RECORD_TYPE
            || header["seq"] != n
            || header["subject_ref"] != subject.as_str()
            || header["book_id"] != book_id
        {
            return Err(unverified(
                "the step does not carry its deal step's record header".into(),
            ));
        }
        let chained = capsule
            .pointer("/chain/parent_capsule_id")
            .and_then(Value::as_str);
        if chained != parent.as_deref() {
            return Err(unverified(
                "the step does not chain to the step before it".into(),
            ));
        }
        let role = if n == 1 {
            StepRole::Baseline
        } else if step["payload"].pointer("/x-deal-v0/record_type")
            == Some(&json!(deal::TYPE_CLOSE))
        {
            StepRole::Close
        } else {
            StepRole::Other
        };
        for cite in step_cites(header, parent.as_deref(), role).map_err(|e| unverified(e.into()))? {
            if !cites.contains(&cite) {
                cites.push(cite);
            }
        }
        let payload =
            serde_json::to_vec(&step["payload"]).map_err(|e| unverified(e.to_string()))?;
        let digest = deal::digest(&payload).map_err(|e| unverified(format!("record: {e}")))?;
        let committed = capsule
            .pointer("/model_attestation/compute_attestation/agent_input_digest")
            .and_then(Value::as_str);
        if committed != Some(digest.as_str()) || header["payload_commitments"] != json!([digest]) {
            return Err(unverified("the Capsule does not commit its payload".into()));
        }
        deal::check(&payload, &[]).map_err(|e| unverified(format!("record: {e}")))?;
        let id: cll::mmr::Hash = hex::decode(capsule_id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| unverified("the capsule_id is not 32 bytes of hex".into()))?;
        cll::mmr::add_leaf(&mut nodes, cll::mmr::leaf_hash(&id))
            .map_err(|e| unverified(format!("the steps' MMR: {e}")))?;
        parent = Some(capsule_id.to_string());
        capsules.push(capsule.clone());
    }

    let cp_refused = |detail: String| refused(REASON_CHECKPOINT_UNVERIFIED, None, detail);
    let verified = cll::checkpoint::verify_checkpoint_cose_offline(&statement);
    let decoded = match verified.decoded {
        Some(decoded) if verified.ok => decoded,
        _ => {
            return Err(cp_refused(format!(
                "the statement: {}",
                verified.errors.join("; ")
            )))
        }
    };
    if decoded.key_id != checkpoint_key {
        return Err(cp_refused(
            "the statement is not signed by the half's checkpoint key".into(),
        ));
    }
    use cll::mmr::NodeReader;
    let size = nodes.size();
    if decoded.mmr_size != size {
        return Err(cp_refused(
            "the checkpoint does not cover exactly the half's steps".into(),
        ));
    }
    let peaks: Vec<cll::mmr::Hash> = cll::mmr::peaks(size)
        .map_err(|e| cp_refused(format!("the steps' MMR: {e}")))?
        .into_iter()
        .map(|pos| nodes.node(pos))
        .collect();
    if decoded.new_peak_hashes != peaks
        || decoded.root != hex::encode(cll::mmr::root_from_peaks(&peaks))
    {
        return Err(cp_refused(
            "the checkpoint does not commit these steps".into(),
        ));
    }

    // A cite of one of the half's own steps is not a counterparty
    // checkpoint.
    if let Some(own) = own_step_cite(&cites, &capsules) {
        return Err(refused(
            REASON_RECORD_UNVERIFIED,
            None,
            format!("a step cites {own}, one of the half's own steps, beside its chain parent"),
        ));
    }
    let form = if cites.is_empty() {
        if !keys.accept_current_form {
            return Err(refused(
                REASON_RECORD_UNVERIFIED,
                None,
                "the half cites no counterparty checkpoint, and the overlap window is closed",
            ));
        }
        FORM_CURRENT
    } else {
        FORM_CITES_COUNTERPARTY_CHECKPOINT
    };
    Ok(Verified {
        form,
        counterparty_checkpoint_cites: cites,
        deal_id: deal_id.to_string(),
        book_id: book_id.to_string(),
        key_id: key_id.to_string(),
        checkpoint_key_id: checkpoint_key.to_string(),
        peer,
        accepted,
        capsules,
        statement_hex: statement_hex.to_string(),
    })
}

/// Step 5: the first step whose serving claim the record-push store refuses
/// (`record_push_receive::claims_verdict`, against this node's own records).
fn refused_claim(ledger_dir: &Path, verified: &Verified) -> std::io::Result<Option<Refused>> {
    let servers: Vec<&str> = verified.accepted.peers.iter().map(String::as_str).collect();
    for (i, capsule) in verified.capsules.iter().enumerate() {
        if let Some(reason) = receive::claims_verdict(ledger_dir, capsule, &servers)? {
            return Ok(Some(refused(
                REASON_RECORD_UNVERIFIED,
                Some(i + 1),
                format!("the Capsule's serving claim is refused: {reason}"),
            )));
        }
    }
    Ok(None)
}

/// Hold a verified half: each step through the record-push receiver's store
/// (which re-runs its own checks and dedups), then the half's line in
/// [`RECEIVED_DEAL_HALVES_FILENAME`] unless that checkpoint is held already.
pub fn hold(node: &receive::Receiver<'_>, verified: &Verified, now: &str) -> std::io::Result<()> {
    let _one_at_a_time = RECEIVING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for capsule in &verified.capsules {
        let body = serde_json::to_vec(capsule)?;
        let (reply, _) = receive::receive_via(node, &body, Some(&verified.peer), now, VIA)?;
        if reply["status"] != "received" {
            // Steps 1 to 5 ran the store's checks under the same keys, so a
            // refusal here is this node's defect, not the half's.
            return Err(std::io::Error::other(format!(
                "the record-push store refused a verified step: {reply}"
            )));
        }
    }
    let held = receive::json_lines(node.ledger_dir, RECEIVED_DEAL_HALVES_FILENAME)?;
    if !held
        .iter()
        .any(|row| row["statement"] == verified.statement_hex.as_str())
    {
        let ids: Vec<&Value> = verified.capsules.iter().map(|c| &c["capsule_id"]).collect();
        receive::append(
            node.ledger_dir,
            RECEIVED_DEAL_HALVES_FILENAME,
            &json!({
                "half": HALF_FORMAT,
                "deal_id": verified.deal_id,
                "book_id": verified.book_id,
                "received_from": verified.peer,
                "via": VIA,
                "received_at": now,
                "key_id": verified.key_id,
                "checkpoint_key_id": verified.checkpoint_key_id,
                "step_capsule_ids": ids,
                "statement": verified.statement_hex,
                "form": verified.form,
                "counterparty_checkpoint_cites": verified.counterparty_checkpoint_cites,
            }),
        )?;
    }
    Ok(())
}

/// The tool's reply for a verified, held half.
fn received_reply(verified: &Verified) -> Value {
    json!({
        "ok": true,
        "status": "received",
        "deal_id": verified.deal_id,
        "book_id": verified.book_id,
        "received_from": verified.peer,
        "key_id": verified.key_id,
        "checkpoint_key_id": verified.checkpoint_key_id,
        "steps": verified.capsules.len(),
        "form": verified.form,
        "counterparty_checkpoint_cites": verified.counterparty_checkpoint_cites,
        "chain_stage": "not_checked",
    })
}

fn refused_reply(refusal: &Refused) -> Value {
    json!({
        "ok": false,
        "status": "refused",
        "reason": refusal.reason,
        "step": refusal.step,
        "detail": refusal.detail,
    })
}

/// Verify and hold in one blocking call, as the tool runs it. `configured`
/// is the raw `CAPSULES_PEER_KEYS` value.
pub fn receive_half(
    ledger_dir: &Path,
    signing_key: &ed25519_dalek::SigningKey,
    configured: Option<&str>,
    text: &[u8],
    now: &str,
) -> std::io::Result<Result<Verified, Refused>> {
    let own_key = hex::encode(signing_key.verifying_key().to_bytes());
    let keys = Keys {
        configured,
        own_key: &own_key,
        accept_current_form: OVERLAP_ACCEPTS_CURRENT_FORM,
    };
    let verified = match verify(text, &keys, now) {
        Ok(verified) => verified,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some(refusal) = refused_claim(ledger_dir, &verified)? {
        return Ok(Err(refusal));
    }
    let node = receive::Receiver {
        ledger_dir,
        signing_key,
        peer_keys: configured,
        announced: &NO_ANNOUNCED,
        // The operator handed this half in: like a record this node asked
        // for, it is held whatever the at-completion sharing setting says.
        record_at_completion_off: false,
        rejected_log_limit: receive::MAX_REJECTED_LOG_BYTES,
    };
    hold(&node, &verified, now)?;
    Ok(Ok(verified))
}

/// `receive_deal_half`: [`receive_and_cite`] under the operator's
/// `CAPSULES_PEER_KEYS`.
pub async fn handle(
    args: ReceiveDealHalfArgs,
    capsules: Arc<crate::capsule_emit::CapsuleState>,
) -> mesh_llm_plugin::PluginResult<Value> {
    let configured = crate::settings::var(crate::peer_keys::ENV_PEER_KEYS).ok();
    receive_and_cite(capsules, configured, args.half).await
}

/// Verify and hold `half`, then seal each step's citing record (each dedups,
/// so handing the half in again after a failed seal seals only what is
/// missing).
pub async fn receive_and_cite(
    capsules: Arc<crate::capsule_emit::CapsuleState>,
    configured: Option<String>,
    half: String,
) -> mesh_llm_plugin::PluginResult<Value> {
    let state = capsules.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        receive_half(
            state.ledger_dir(),
            state.signing_key(),
            configured.as_deref(),
            half.as_bytes(),
            &crate::producer::timestamp::utc_now_iso8601(),
        )
    })
    .await
    .map_err(|e| {
        mesh_llm_plugin::PluginError::internal(format!("receive_deal_half did not complete: {e}"))
    })?
    .map_err(|e| {
        mesh_llm_plugin::PluginError::internal(format!(
            "receive_deal_half could not store what it verified: {e}"
        ))
    })?;
    let verified = match outcome {
        Ok(verified) => verified,
        Err(refusal) => return Ok(refused_reply(&refusal)),
    };
    for capsule in &verified.capsules {
        let bytes = serde_json::to_vec(capsule)
            .map_err(|e| mesh_llm_plugin::PluginError::internal(e.to_string()))?;
        crate::record_push_bridge::seal_citing_record(
            &capsules,
            &verified.peer,
            &bytes,
            VIA,
            Some(&verified.accepted),
        )
        .await
        .map_err(|e| {
            mesh_llm_plugin::PluginError::internal(format!(
                "the half is held but a citing record did not seal (hand it in again to retry): {e}"
            ))
        })?;
    }
    Ok(received_reply(&verified))
}

#[cfg(test)]
mod tests;
