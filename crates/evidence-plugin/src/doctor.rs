//! `doctor` and `join`: loop step 12 (THE_LOOP.md, "Join") for a Mesh node.
//!
//! **`doctor`** inspects this node and talks to nobody. It returns a list of
//! findings and nothing else: no score, rank or grade is computed from it.
//! The check names and states are evidencebook's (`Book.Doctor`,
//! action-state-group/evidencebook#133), so loop step 12 reads one
//! `doctor.json` shape for a Mesh node and for a capsulectl book. It seals
//! nothing and never forces a checkpoint.
//!
//! **`probe`** asks this node's own responder `checkpoints`, then
//! `history_card/1`, as a stranger, in process: the same
//! [`evidence_answer::answer`] call the `evidence-request/1` channel makes
//! for a request that names no requester, with the daily reporter's request
//! bytes. It verifies each answer under the key the node's signed commitment
//! advertises and checks that the node answers under the policy that
//! commitment signs. A probe over the mesh needs a second node and stays the
//! reporter's.
//!
//! **`join`** checks that this node is ready to join, idempotently, and
//! writes nothing but a controller binding it is given (`controller_binding`
//! in its arguments), which it stores as this node's own only after
//! checking that it binds this node's key and applies
//! (`controller_binding::store_held`): the key and the book exist from the first start, and the
//! cadence cuts checkpoints over new activity. It reports what is in place
//! (the key, the book, the first checkpoint, the commitment that
//! `commitment/1` serves) and what is not, with `doctor`'s findings, probe
//! included. Listing the node is the evidence network's, by pull request to
//! its commitment list. It never seals a record to get a checkpoint: a
//! made-up record would be a false entry in the node's own history. A fresh
//! node's join names the checkpoint missing, and a re-run after its first
//! exchange completes it.
//!
//! The quickstart ([`quickstart`]) is printed from the same constants, and
//! INSTALL.md carries it between markers a test holds it to.

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::commitment::{self, Policy, Signed, STRANGER_SAFE};
use crate::evidence_answer::{self, Outcome, Responder, MAX_ANSWER_CHECKPOINTS};

/// `POST /api/plugins/<plugin_id>/tools/doctor`.
pub const DOCTOR_OPERATION: &str = "doctor";

/// `POST /api/plugins/<plugin_id>/tools/join`.
pub const JOIN_OPERATION: &str = "join";

/// The issue that owns a `history_card/1` refused past
/// [`MAX_ANSWER_CHECKPOINTS`]; a finding that meets it names it.
const LONG_LOG_ISSUE: &str = "Mesh-LLM/capsules-plugin#76";

// Check names, in the order doctor reports them (evidencebook `doctor.go`).
pub const SELF_ATTESTED: &str = "self_attested";
pub const CONTROLLER_BINDING: &str = "controller_binding";
pub const CHECKPOINT: &str = "checkpoint";
pub const WITNESS: &str = "witness";
pub const NOT_CHECKED: &str = "not_checked";
pub const UNSUPPORTED: &str = "unsupported";
pub const SHARING: &str = "sharing";
pub const POLICY_IN_COMMITMENT: &str = "policy_in_commitment";
pub const STRANGER_VIEW: &str = "stranger_view";
pub const IDENTIFIED_VIEW: &str = "identified_view";
pub const PROBE_CHECKPOINTS: &str = "probe_checkpoints";
pub const PROBE_HISTORY_CARD: &str = "probe_history_card";

// States. NOT_CHECKED means the check was not run, never that it passed.
pub const STATE_SELF_ATTESTED: &str = "self_attested";
pub const STATE_UNBOUND: &str = "unbound";
pub const STATE_BOUND: &str = "bound";
pub const STATE_PRESENT: &str = "present";
pub const STATE_MISSING: &str = "missing";
pub const STATE_WITNESSED: &str = "witnessed";
pub const STATE_UNWITNESSED: &str = "unwitnessed";
pub const STATE_NOT_CHECKED: &str = "NOT_CHECKED";
pub const STATE_UNSUPPORTED: &str = "unsupported";
pub const STATE_ON: &str = "on";
pub const STATE_OFF: &str = "off";
pub const STATE_ANSWERED: &str = "answered";
pub const STATE_MATCH: &str = "match";
pub const STATE_MISMATCH: &str = "mismatch";

/// One line of a doctor report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub check: &'static str,
    pub state: &'static str,
    pub detail: String,
    /// What shows the finding: an anchor, a policy digest or a binding digest.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<String>,
}

impl Finding {
    fn new(check: &'static str, state: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            state,
            detail: detail.into(),
            records: Vec::new(),
        }
    }

    fn with(mut self, record: impl Into<String>) -> Self {
        self.records.push(record.into());
        self
    }
}

/// The two stranger requests, with the members the daily reporter sends
/// (evidence-network/loop `scripts/daily_report.py`).
pub fn probe_requests() -> [(&'static str, Vec<u8>); 2] {
    let ask = |extra: Value| {
        let mut request = json!({
            "coverage": {"min_freshness": 1},
            "profile": evidence_request::envelope::PROFILE,
        });
        for (k, v) in extra.as_object().expect("an object") {
            request[k] = v.clone();
        }
        serde_json::to_vec(&request).expect("a JSON value serializes")
    };
    [
        (
            PROBE_CHECKPOINTS,
            ask(json!({"subject": {"checkpoints": null}})),
        ),
        (
            PROBE_HISTORY_CARD,
            ask(json!({"subject": {"full_history": null}, "derivation": "history_card/1"})),
        ),
    ]
}

/// What the ledger holds, read once.
struct Book {
    records: usize,
    leaves: usize,
    /// Every checkpoint's anchor digest, oldest first.
    anchors: Vec<String>,
    /// Leaves the latest checkpoint covers.
    covered: u64,
    /// The latest checkpoint's `mmr_size`, which names its line in
    /// `checkpoints.jsonl`.
    latest_size: Option<u64>,
}

fn read_book(responder: &Responder<'_>) -> Result<Book, String> {
    crate::evidence_log::with_index(
        responder.ledger_dir,
        &commitment::key_id(responder.signing_key),
        |index| Book {
            records: index.leaves.iter().filter(|l| !l.padding).count(),
            leaves: index.leaves.len(),
            anchors: index.chain.iter().map(|c| c.anchor_digest()).collect(),
            covered: index
                .chain
                .last()
                .and_then(|c| cll::mmr::leaf_count(c.record.mmr_size).ok())
                .unwrap_or(0),
            latest_size: index.chain.last().map(|c| c.record.mmr_size),
        },
    )
    .map_err(|e| format!("the ledger could not be read: {e}"))
}

/// The witness state of this node's checkpoints: the configured witness
/// URLs and, per checkpoint (by `mmr_size`), the witnesses whose receipt for
/// it checks (`witness_status`). Read apart from the book, so a checkpoint
/// cut in between is simply not in `held`.
#[derive(Clone, Debug, Default)]
pub struct Witnesses {
    pub configured: Vec<String>,
    pub held: BTreeMap<u64, Vec<String>>,
}

impl Witnesses {
    /// Read from `<ledger>/checkpoints.jsonl`, with the witnesses and keys
    /// the cadence took at start.
    pub fn read(ledger_dir: &std::path::Path) -> Self {
        let (configured, _) = crate::checkpoint_cadence::active_witness_urls();
        let keys = crate::checkpoint_cadence::active_witness_keys();
        Self::read_with(ledger_dir, configured, &keys)
    }

    fn read_with(
        ledger_dir: &std::path::Path,
        configured: Vec<String>,
        keys: &BTreeMap<String, String>,
    ) -> Self {
        let mut lines: Vec<Value> = crate::chain_store::checkpoints_string(ledger_dir)
            .lines()
            .filter_map(|l| serde_json::from_str(l.trim()).ok())
            .collect();
        crate::witness_status::annotate(&mut lines, &configured, keys, ledger_dir);
        let held = lines
            .iter()
            .filter_map(|cp| {
                let size = cp.get("mmr_size")?.as_u64()?;
                let urls: Vec<String> = cp
                    .get("witnesses")?
                    .as_array()?
                    .iter()
                    .filter(|r| r.get("checked") == Some(&json!(true)))
                    .filter_map(|r| r.get("ts_url").and_then(Value::as_str))
                    .map(crate::witness_status::display_url)
                    .collect();
                (!urls.is_empty()).then_some((size, urls))
            })
            .collect();
        Self { configured, held }
    }
}

/// The commitment this node serves on `commitment/1`, as that channel
/// serves it (`commitment_bridge::own`, built once per checkpoint and
/// policy), or why it serves none.
pub type Served = Result<Signed, String>;

/// Why a log past [`MAX_ANSWER_CHECKPOINTS`] refuses `history_card/1`, when
/// this book is one; empty otherwise.
fn long_log_note(book: &Book) -> String {
    if book.anchors.len() as u64 > MAX_ANSWER_CHECKPOINTS {
        format!(
            " (this book has {} checkpoints, past {MAX_ANSWER_CHECKPOINTS}: {LONG_LOG_ISSUE})",
            book.anchors.len()
        )
    } else {
        String::new()
    }
}

/// Whether this node's own binding (`controller_binding::read_held`) binds
/// `key_id` and applies now: `bound`, with the binding digest, or `unbound`
/// with the reason. It never names the other key: that is the operator's,
/// often a Nostr identity used elsewhere, and a finding may be shown to
/// anyone the operator shows `doctor` to (CB §9.3).
fn controller_binding(binding: Option<&Value>, key_id: &str, now: &str) -> Finding {
    let Some(record) = binding else {
        return Finding::new(
            CONTROLLER_BINDING,
            STATE_UNBOUND,
            format!(
                "no controller binding record names this node's key {key_id}: the node holds none"
            ),
        );
    };
    let checked = evidence_request::time::parse_utc(now)
        .ok_or_else(|| format!("the time {now} does not parse"))
        .and_then(|at| crate::controller_binding::binds_own(record, key_id, at));
    match checked {
        Ok(applied) => Finding::new(
            CONTROLLER_BINDING,
            STATE_BOUND,
            format!(
                "this node's key {key_id} is bound to its operator's key by the binding {}: both \
                 keys signed it, and it is inside its window",
                applied.digest
            ),
        )
        .with(applied.digest),
        Err(why) => Finding::new(
            CONTROLLER_BINDING,
            STATE_UNBOUND,
            format!("the controller binding this node holds does not count: {why}"),
        ),
    }
}

/// Every finding, the probe's included when `probe` is set. `responder` is
/// what this node answers with now, under `policy`; `served` is the
/// commitment it serves; `binding` is this node's own controller binding.
pub fn findings(
    responder: &Responder<'_>,
    policy: &Policy,
    served: &Served,
    witnesses: &Witnesses,
    binding: Option<&Value>,
    probe: bool,
) -> Result<Vec<Finding>, String> {
    let book = read_book(responder)?;
    let key_id = commitment::key_id(responder.signing_key);
    let latest = book.anchors.last();
    let mut out = vec![
        Finding::new(
            SELF_ATTESTED,
            STATE_SELF_ATTESTED,
            if book.records == 0 {
                "the book has no records yet".to_string()
            } else {
                format!(
                    "each of the {} records is sealed by this node's own key and by no other \
                     party; its content is this node's own statement of its half of an exchange",
                    book.records
                )
            },
        ),
        controller_binding(binding, &key_id, responder.now),
    ];
    out.push(match latest {
        None => Finding::new(
            CHECKPOINT,
            STATE_MISSING,
            "the book has no checkpoint, so a stranger's checkpoints and history_card/1 requests \
             are refused; the cadence cuts the first one after this node's first exchange",
        ),
        Some(anchor) if (book.covered as usize) < book.leaves => Finding::new(
            CHECKPOINT,
            STATE_PRESENT,
            format!(
                "the latest checkpoint covers {} of {} ledger entries; the rest are under no \
                 checkpoint yet",
                book.covered, book.leaves
            ),
        )
        .with(anchor),
        Some(anchor) => Finding::new(
            CHECKPOINT,
            STATE_PRESENT,
            format!(
                "the latest checkpoint covers all {} ledger entries",
                book.leaves
            ),
        )
        .with(anchor),
    });
    out.push(witness(book.latest_size, witnesses, book.anchors.len()));
    out.push(Finding::new(
        NOT_CHECKED,
        STATE_NOT_CHECKED,
        "answers this node received are kept apart from its book (the Evidence page lists them); \
         doctor does not inspect them",
    ));
    out.push(Finding::new(
        UNSUPPORTED,
        STATE_UNSUPPORTED,
        format!(
            "full_history record bodies are refused to everyone; full_history is answered only \
             through a derivation; every derivation other than {} is refused \
             derivation_unsupported",
            commitment::DERIVATIONS[1..].join(", ")
        ),
    ));
    let body = policy.body();
    let switches = [
        crate::share_policy::RECORD_AT_COMPLETION_KEY,
        crate::share_policy::HISTORY_SEGMENTS_KEY,
        crate::share_policy::ADJUDICATIONS_KEY,
        crate::share_policy::STANDARD_HISTORY_KEY,
        crate::share_policy::EXCHANGE_CORROBORATION_KEY,
    ]
    .iter()
    .map(|k| format!("{k}={}", body[*k].as_str().unwrap_or_default()))
    .collect::<Vec<_>>()
    .join(", ");
    let sharing_off = !policy.record_at_completion
        && policy.history_segments == "off"
        && !policy.adjudications_delivered
        && !policy.share_standard_history
        && !policy.share_exchange_corroboration;
    out.push(Finding::new(
        SHARING,
        if sharing_off { STATE_OFF } else { STATE_ON },
        switches,
    ));
    out.push(policy_in_commitment(responder, served, &book));
    out.push(Finding::new(
        STRANGER_VIEW,
        STATE_ANSWERED,
        if latest.is_none() {
            format!(
                "refusals only: {} are public, but there is no checkpoint to answer with",
                STRANGER_SAFE.join(" and ")
            )
        } else {
            format!(
                "{} to anyone (commitments only, no record); share_standard_history={} and \
                 share_exchange_corroboration={} say what else a requester that is not a \
                 counterparty receives",
                STRANGER_SAFE.join(" and "),
                body[crate::share_policy::STANDARD_HISTORY_KEY]
                    .as_str()
                    .unwrap_or_default(),
                body[crate::share_policy::EXCHANGE_CORROBORATION_KEY]
                    .as_str()
                    .unwrap_or_default(),
            )
        },
    ));
    out.push(Finding::new(
        IDENTIFIED_VIEW,
        STATE_ANSWERED,
        match policy.history_segments {
            "peers" => {
                "what a stranger receives, plus the records and exchanges it asks for by \
                        digest"
            }
            "counterparties" => {
                "what a stranger receives; record and exchange subjects are \
                                 refused until a record names it as counterparty, and then it \
                                 receives those records"
            }
            _ => {
                "what a stranger receives; record and exchange subjects are refused \
                  (history_segments=off)"
            }
        },
    ));
    if probe {
        let advertised = served.as_ref().ok();
        for (check, request) in probe_requests() {
            out.push(probe_one(check, &request, responder, &book, advertised));
        }
    }
    Ok(out)
}

fn witness(latest_size: Option<u64>, witnesses: &Witnesses, checkpoints: usize) -> Finding {
    let Some(size) = latest_size else {
        return Finding::new(
            WITNESS,
            STATE_UNWITNESSED,
            "there is no checkpoint to witness",
        );
    };
    if let Some(held) = witnesses.held.get(&size) {
        return Finding::new(
            WITNESS,
            STATE_WITNESSED,
            format!(
                "a receipt that checks is held for the latest checkpoint (checkpoint \
                 {checkpoints}) from {}",
                held.join(", ")
            ),
        );
    }
    if witnesses.configured.is_empty() {
        return Finding::new(
            WITNESS,
            STATE_UNWITNESSED,
            "no witness is configured: no checkpoint is delivered to one",
        );
    }
    Finding::new(
        WITNESS,
        STATE_UNWITNESSED,
        format!(
            "no witness receipt that checks is held for the latest checkpoint (checkpoint \
             {checkpoints})"
        ),
    )
}

/// One stranger request to this node's own responder, its answer verified
/// under the advertised key (this node's own when it serves no commitment)
/// and compared with what the advertised policy answers a stranger: an
/// artifact anchored at a checkpoint of this book. It records nothing.
fn probe_one(
    check: &'static str,
    request: &[u8],
    responder: &Responder<'_>,
    book: &Book,
    advertised: Option<&Signed>,
) -> Finding {
    let asked = if check == PROBE_CHECKPOINTS {
        "checkpoints"
    } else {
        "history_card/1"
    };
    let mismatch = |detail: String| Finding::new(check, STATE_MISMATCH, detail);
    if book.anchors.is_empty() {
        // With no checkpoint, a refusal is what the stranger view
        // predicts, and the probe would check nothing.
        return Finding::new(
            check,
            STATE_NOT_CHECKED,
            format!("there is no checkpoint, so a stranger asking {asked} is refused and nothing is checked"),
        );
    }
    let wire = match evidence_answer::answer(request, responder) {
        Outcome::Answered { wire, .. } | Outcome::Refused { wire, .. } => wire,
        Outcome::Unanswerable(why) => {
            return mismatch(format!("the responder did not answer {asked}: {why}"))
        }
    };
    let (key_id, under) = match advertised {
        Some(signed) => (
            signed.commitment["key_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            "the advertised key",
        ),
        None => (
            commitment::key_id(responder.signing_key),
            "this node's own key (it serves no commitment)",
        ),
    };
    let key = hex::decode(&key_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok());
    let Some(key) = key else {
        return mismatch("the commitment's key_id is not an Ed25519 key".into());
    };
    if let Some(signed) = advertised {
        let policy_digest = signed.commitment["lcap"]["policy_digest"].as_str();
        if responder.policy_digest != policy_digest {
            return mismatch(format!(
                "this node answers under policy {}, not the {} its commitment advertises",
                responder.policy_digest.unwrap_or("(none)"),
                policy_digest.unwrap_or("(none)")
            ));
        }
    }
    let verified = evidence_answer::verify_response(request, &wire, &key, &BTreeMap::new());
    match verified["state"].as_str() {
        Some("artifact") => {
            let anchor = verified["anchor"].as_str().unwrap_or_default();
            // The cadence may have cut a checkpoint since `book` was read,
            // and the answer may be anchored at it: read the chain again.
            let anchored = book.anchors.iter().any(|a| a == anchor)
                || read_book(responder).is_ok_and(|now| now.anchors.iter().any(|a| a == anchor));
            if anchored {
                Finding::new(
                    check,
                    STATE_MATCH,
                    format!(
                        "a stranger asking {asked} gets an artifact that verifies under {under} \
                         {key_id} and is anchored at a checkpoint of this book, as the \
                         advertised policy answers a stranger"
                    ),
                )
                .with(anchor)
            } else {
                mismatch(format!(
                    "the {asked} artifact verifies but is anchored at {anchor}, no checkpoint of \
                     this book"
                ))
            }
        }
        Some("refusal") => {
            let reason = verified["reason"].as_str().unwrap_or_default();
            mismatch(format!(
                "a stranger asking {asked} is refused {reason}, though the policy answers it to \
                 anyone{}",
                if reason == "policy_declined" {
                    long_log_note(book)
                } else {
                    String::new()
                }
            ))
        }
        _ => mismatch(format!(
            "the {asked} answer does not verify under {under}: {}",
            verified["why"].as_str().unwrap_or_default()
        )),
    }
}

/// Whether the commitment served carries the policy this node answers
/// under, and verifies.
fn policy_in_commitment(responder: &Responder<'_>, served: &Served, book: &Book) -> Finding {
    let missing = |detail: String| Finding::new(POLICY_IN_COMMITMENT, STATE_MISSING, detail);
    let signed = match served {
        Ok(signed) => signed,
        Err(why) => {
            return missing(format!(
                "no commitment is served: {why}{}",
                long_log_note(book)
            ))
        }
    };
    let problems = commitment::verify(signed);
    if !problems.is_empty() {
        return missing(format!(
            "the commitment served on commitment/1 does not verify: {}",
            problems.join("; ")
        ));
    }
    let digest = signed.commitment["lcap"]["policy_digest"].as_str();
    if digest != responder.policy_digest {
        return missing(format!(
            "the commitment served on commitment/1 advertises policy {}, but this node answers \
             under {}",
            digest.unwrap_or("(none)"),
            responder.policy_digest.unwrap_or("(none)")
        ));
    }
    Finding::new(
        POLICY_IN_COMMITMENT,
        STATE_PRESENT,
        "the commitment this node serves on commitment/1 verifies and its lcap.policy_digest is \
         the digest of the policy it answers under",
    )
    .with(digest.unwrap_or_default())
}

/// What `join` found: done (in place) and pending (not yet), each a line,
/// with doctor's findings and the commitment it serves.
pub fn join_report(
    responder: &Responder<'_>,
    policy: &Policy,
    served: &Served,
    witnesses: &Witnesses,
    binding: Option<&Value>,
) -> Result<Value, String> {
    let findings = findings(responder, policy, served, witnesses, binding, true)?;
    let state = |check: &str| {
        findings
            .iter()
            .find(|f| f.check == check)
            .map(|f| f.state)
            .unwrap_or_default()
    };
    let key_id = commitment::key_id(responder.signing_key);
    let mut done = vec![
        format!("the node key {key_id} exists"),
        format!("the book exists at {}", responder.ledger_dir.display()),
    ];
    let mut pending = Vec::new();
    if state(CHECKPOINT) == STATE_PRESENT {
        done.push("the book has a checkpoint".into());
    } else {
        pending.push(
            "the first checkpoint: the cadence cuts it after this node's first exchange; run \
             join again then"
                .into(),
        );
    }
    let commitment = findings
        .iter()
        .find(|f| f.check == POLICY_IN_COMMITMENT)
        .expect("findings always holds policy_in_commitment");
    if state(CONTROLLER_BINDING) == STATE_BOUND {
        done.push("the node key is bound to its operator's key".into());
    }
    if commitment.state == STATE_PRESENT {
        done.push("the commitment served on commitment/1 verifies".into());
    } else {
        pending.push(format!("the commitment: {}", commitment.detail));
    }
    for check in [PROBE_CHECKPOINTS, PROBE_HISTORY_CARD] {
        if state(check) != STATE_MATCH {
            pending.push(format!("{check}: {}", state(check)));
        }
    }
    let named = |check: &str, wanted: &[&str]| -> Vec<Value> {
        findings
            .iter()
            .filter(|f| f.check == check && wanted.contains(&f.state))
            .map(|f| json!({"check": f.check, "state": f.state, "detail": f.detail}))
            .collect()
    };
    Ok(json!({
        "joined": pending.is_empty(),
        "done": done,
        "pending": pending,
        "self_attested": named(SELF_ATTESTED, &[STATE_SELF_ATTESTED]),
        "unwitnessed": named(WITNESS, &[STATE_UNWITNESSED]),
        "unchecked": findings.iter().filter(|f| f.state == STATE_NOT_CHECKED)
            .map(|f| json!({"check": f.check, "detail": f.detail})).collect::<Vec<_>>(),
        "unbound": named(CONTROLLER_BINDING, &[STATE_UNBOUND]),
        "not_shared": named(SHARING, &[STATE_OFF]),
        "commitment": served.as_ref().ok().map(Signed::to_wire),
        "findings": findings,
    }))
}

// ---------------------------------------------------------------------
// The operations
// ---------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct DoctorArgs {
    /// Also ask this node's own responder checkpoints, then history_card/1,
    /// as a stranger, in process, and check both answers.
    #[serde(default)]
    pub probe: bool,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct JoinArgs {
    /// A controller binding record (controller-binding/0) that binds this
    /// node's key to its operator's, signed by both. Stored as this node's
    /// own binding when it binds this node's key and applies now; refused
    /// otherwise, and the binding already held is kept.
    #[serde(default)]
    pub controller_binding: Option<Value>,
    /// The operator's Nostr public key (BIP-340, 64 lowercase hex) to bind
    /// this node's key to. `join` signs the node's half and returns, under
    /// `controller_binding_ceremony.event`, the Nostr event the operator
    /// signs with their own signer and never publishes to a relay (CB §9.3);
    /// nothing is stored as bound until then.
    #[serde(default)]
    pub controller: Option<String>,
    /// That event, signed (NIP-01: `pubkey`, `created_at`, `kind`, `tags`,
    /// `content`, `sig`). Completes the pending binding and stores it, as
    /// `controller_binding` does.
    #[serde(default)]
    pub controller_event: Option<Value>,
}

impl JoinArgs {
    /// At most one of `controller_binding`, `controller` and
    /// `controller_event`, checked before anything is written: one call that
    /// stored one binding and then refused another would read as refused.
    fn one_binding_operation(&self) -> Result<(), String> {
        let given = usize::from(self.controller_binding.is_some())
            + usize::from(self.controller.is_some())
            + usize::from(self.controller_event.is_some());
        if given > 1 {
            return Err("give one of controller_binding, controller and controller_event".into());
        }
        Ok(())
    }
}

/// `doctor`: `{"findings": [...]}`.
pub async fn handle_doctor(
    args: DoctorArgs,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    node_id: Option<String>,
) -> mesh_llm_plugin::PluginResult<Value> {
    blocking(move || {
        let now = evidence_answer::now_utc();
        let witnesses = Witnesses::read(capsules.ledger_dir());
        let served = crate::commitment_bridge::own(&capsules, node_id.as_deref());
        let binding = held(&capsules);
        commitment::with_responder(&capsules, &now, node_id.as_deref(), |responder, policy| {
            findings(
                responder,
                policy,
                &served,
                &witnesses,
                binding.as_ref(),
                args.probe,
            )
            .map(|f| {
                json!({
                    "findings": f,
                    // Admission's price rule (#105): the pack, its digest,
                    // the operator's profile digest and values.
                    "admission_price": crate::admission::price::loaded_description(),
                })
            })
        })
    })
    .await
}

/// `join`: what is in place and what is not (see the module doc).
pub async fn handle_join(
    args: JoinArgs,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    node_id: Option<String>,
) -> mesh_llm_plugin::PluginResult<Value> {
    blocking(move || {
        args.one_binding_operation()?;
        let now = evidence_answer::now_utc();
        let data_dir = capsules
            .ledger_dir()
            .parent()
            .ok_or("the ledger has no data directory to keep a binding in")?;
        let at = evidence_request::time::parse_utc(&now)
            .ok_or_else(|| format!("the time {now} does not parse"))?;
        let own = commitment::key_id(capsules.signing_key());
        if let Some(record) = &args.controller_binding {
            crate::controller_binding::store_held(data_dir, record, &own, at)
                .map_err(|why| format!("the controller binding is refused: {why}"))?;
        }
        if let Some(event) = &args.controller_event {
            crate::controller_binding::finish(data_dir, event, &own, at)
                .map_err(|why| format!("the controller binding is refused: {why}"))?;
        }
        let ceremony = match &args.controller {
            Some(controller) => Some(
                crate::controller_binding::begin(
                    data_dir,
                    capsules.signing_key(),
                    controller,
                    &now,
                )
                .map_err(|why| format!("the controller binding is refused: {why}"))?,
            ),
            None => None,
        };
        let witnesses = Witnesses::read(capsules.ledger_dir());
        let served = crate::commitment_bridge::own(&capsules, node_id.as_deref());
        let binding = held(&capsules);
        let mut report = commitment::with_responder(
            &capsules,
            &now,
            node_id.as_deref(),
            |responder, policy| {
                join_report(responder, policy, &served, &witnesses, binding.as_ref())
            },
        )?;
        if let Some(event) = ceremony {
            report["controller_binding_ceremony"] = json!({
                "event": event,
                "next": "sign this Nostr event with the operator's own signer (for example a \
                         NIP-07 extension) and do not publish it to any relay, then run join with \
                         controller_event set to the signed event",
            });
        }
        // The ledger is `<data dir>/ledger`; the join switch keeps its state
        // in the data directory.
        report["network"] = crate::network_join::status(data_dir, &own, node_id.as_deref());
        Ok(report)
    })
    .await
}

/// This node's own controller binding, from the data directory the ledger
/// is in (`<data dir>/ledger`).
fn held(capsules: &crate::capsule_emit::CapsuleState) -> Option<Value> {
    crate::controller_binding::read_held(capsules.ledger_dir().parent()?)
}

async fn blocking(
    f: impl FnOnce() -> Result<Value, String> + Send + 'static,
) -> mesh_llm_plugin::PluginResult<Value> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| {
            mesh_llm_plugin::PluginError::internal(format!("doctor task did not complete: {e}"))
        })?
        .map_err(mesh_llm_plugin::PluginError::internal)
}

// ---------------------------------------------------------------------
// The quickstart
// ---------------------------------------------------------------------

/// The markers INSTALL.md carries the quickstart between.
#[cfg(test)]
pub const QUICKSTART_BEGIN: &str =
    "<!-- join-quickstart: generated by `capsules --print-join-quickstart`; do not edit -->";
#[cfg(test)]
pub const QUICKSTART_END: &str = "<!-- /join-quickstart -->";

/// The join quickstart, as Markdown: what `join` and `doctor` do and how to
/// run them, from the constants the tools use.
pub fn quickstart(plugin_id: &str) -> String {
    let tool = |op: &str| format!("$CONSOLE/api/plugins/{plugin_id}/tools/{op}");
    format!(
        "`CONSOLE` is your mesh-llm console, for example `http://127.0.0.1:3131`.\n\
         \n\
         1. **Get ready.** Nothing to set up by hand: the plugin creates its key and its book on\n\
         first start, and cuts its first checkpoint after the node's first exchange. `join`\n\
         checks all of it and lists what is in place and what is not:\n\
         \n\
         ```bash\n\
         curl -s -X POST -H 'content-type: application/json' -d '{{}}' {join}\n\
         ```\n\
         \n\
         `joined` is true once this node is ready to be listed: the book has a checkpoint, the\n\
         commitment it serves on `{channel}` verifies, and both stranger probes match. Before\n\
         the first exchange, `pending` names the missing checkpoint; run `join` again after it.\n\
         Running it again changes nothing.\n\
         \n\
         2. **Check.** `doctor` lists what is self-attested, unwitnessed, unchecked, unbound or\n\
         not shared, one finding per line, never a score. With `probe`, it also asks the\n\
         node's own responder `{cp}`, then `{hc}`, as a stranger, in process (no\n\
         network), and checks that each answer verifies under the key the commitment\n\
         advertises (the node's own key when it serves no commitment yet) and that the node\n\
         answers under the policy the commitment signs:\n\
         \n\
         ```bash\n\
         curl -s -X POST -H 'content-type: application/json' -d '{{\"probe\": true}}' {doctor}\n\
         ```\n\
         \n\
         3. **Bind the node to you (optional).** Give `join` your Nostr public key (64 hex,\n\
         the key behind your npub). It signs the node's half and returns, under\n\
         `controller_binding_ceremony.event`, a Nostr event for you to sign with your own\n\
         signer; the node never sees your secret key:\n\
         \n\
         ```bash\n\
         curl -s -X POST -H 'content-type: application/json' -d '{{\"controller\": \"<your key>\"}}' {join}\n\
         ```\n\
         \n\
         Sign it, do not publish it: never send this event to a relay, which would link your\n\
         key to the node. Then pass the signed event back:\n\
         \n\
         ```bash\n\
         curl -s -X POST -H 'content-type: application/json' -d '{{\"controller_event\": <signed event>}}' {join}\n\
         ```\n\
         \n\
         `doctor` then reports `controller_binding: bound`, and the commitment names the\n\
         binding by its digest alone, never your key. Show the binding record only to the\n\
         parties that need it. The binding holds for a year: the plugin does not yet send or\n\
         read revocations (Controller Binding §5), so it holds until its `not_after` or until\n\
         you run the ceremony again.\n\
         \n\
         4. **Publish the commitment.** This returns the signed commitment and its policy; then\n\
         add it to the commitment list by pull request:\n\
         https://github.com/evidence-network/loop/blob/main/nodes/README.md\n\
         \n\
         ```bash\n\
         curl -s -X POST -H 'content-type: application/json' -d '{{}}' {commitment}\n\
         ```\n\
         \n\
         5. **Join the list.** In the console (Configuration, Plugins, capsules), turn on\n\
         \"{switch}\". The statement under the switch is what you agree to. The node then\n\
         signs one join with its plugin key, with no handle and no operator name, and sends\n\
         it to the network's reporter node; `join` shows under `network` whether the reporter\n\
         has it. While no reporter is named yet (`network.reporter` is null), nothing is sent.\n\
         To leave, turn the switch off.\n\
         \n\
         `join` and `doctor` seal nothing and contact nobody; `join` writes only a binding or a pending one.\n",
        switch = crate::share_policy::JOIN_NETWORK_LABEL,
        join = tool(JOIN_OPERATION),
        doctor = tool(DOCTOR_OPERATION),
        commitment = tool(crate::commitment_bridge::OWN_COMMITMENT_OPERATION),
        channel = crate::commitment_bridge::COMMITMENT_CHANNEL,
        cp = STRANGER_SAFE[0],
        hc = STRANGER_SAFE[1],
    )
}

#[cfg(test)]
mod tests;
