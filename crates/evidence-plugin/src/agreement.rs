//! Service evidence agreements (PRD R-18 to R-21): one session-scoped
//! acceptance record of the interop profile (`evidence-interop/0` §11.1) per
//! bounded paid session with a provider.
//!
//! The requester proposes: a `proposed` record naming the session's Evidence
//! Contract, its model policy and its terms (spend cap, unit, payment
//! reference type, and optionally a count), each a JCS-digested document
//! carried beside the record. The provider checks the documents against
//! their digests and their shape, then answers with an `accepted` record.
//! The requester checks the answer and signs the §11.1.4 receipt; that
//! receipt is the session's ordering evidence (P-28). Every record, receipt
//! and document travels as JSON text and is kept byte-exact as received
//! ([`Store`]); digests are computed over the parsed value
//! ([`evidence_request::acceptance::record_digest`]), never over the octets.
//! Records and receipts are checked with the profile's own verifier
//! ([`evidence_request::acceptance::evaluate`]), so a record this plugin
//! signs, keeps or accepts is one every profile verifier reads the same way.
//!
//! Spend terms are an agent-origin assertion (§11.1.6): the payer's spend
//! control is local wallet configuration, not a signed authorization, so no
//! record carries `authority` and acceptance never authorizes spend.
//!
//! This module builds and checks the messages; carrying them is
//! [`agreement_bridge`](crate::agreement_bridge)'s job, and deciding when to
//! propose is the caller's (design rule R11).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use evidence_request::acceptance::{self, Inputs, TrustPolicy};
use evidence_request::status::Status;
use serde_json::{json, Map, Value};

/// The private mesh channel agreement messages travel on.
pub const CHANNEL: &str = "x-capsules-agreement/1";
/// The `transaction.scheme` of a session the requester names.
pub const TRANSACTION_SCHEME: &str = "x-capsules/session";
/// The payment reference type the terms name: the one the settlement legs
/// carry (`settlement_legs`, capsule-emit `PAYMENT_REF_TYPES`).
pub const PAYMENT_REF_TYPE: &str = "ln.payment_hash";
/// The spend unit the terms name.
pub const UNIT: &str = "msat";
/// The contract every session names, by reference.
pub const CONTRACT_REF: &str = "x-capsules/paid-session@1";

const PROFILE: &str = acceptance::PROFILE_ID;
const MAX_INTEGER: u64 = (1 << 53) - 1;

/// How far apart the two parties' clocks may be when the provider checks a
/// proposal's window.
pub const CLOCK_SKEW_SECONDS: i64 = 300;
/// The longest session window a provider accepts.
pub const MAX_WINDOW_SECONDS: u64 = 86_400;
/// The shortest session window a provider accepts.
pub const MIN_WINDOW_SECONDS: u64 = 60;
/// The most models a model policy may name, and the longest reference.
const MAX_POLICY_MODELS: usize = 16;
const MAX_MODEL_REF_LEN: usize = 512;

/// What the requester proposes for a session, from the operator's settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionTerms {
    /// The cumulative settled amount the session covers, in msat.
    pub spend_cap_msat: u64,
    /// How many exchanges the session covers; `None` for no count bound.
    pub max_exchanges: Option<u64>,
    /// How long the session lasts from its proposal, in seconds.
    pub window_seconds: u64,
}

/// The settings that set session terms.
pub const SPEND_CAP_SETTING: &str = "CAPSULES_AGREEMENT_SPEND_CAP_MSAT";
pub const MAX_EXCHANGES_SETTING: &str = "CAPSULES_AGREEMENT_MAX_EXCHANGES";
pub const WINDOW_SETTING: &str = "CAPSULES_AGREEMENT_WINDOW_SECONDS";
const DEFAULT_WINDOW_SECONDS: u64 = 3_600;

impl SessionTerms {
    /// The operator's session terms, or `None` when no spend cap is set:
    /// then no session is proposed and nothing changes (R11).
    pub fn from_settings() -> Option<SessionTerms> {
        Self::from_values(
            crate::settings::var(SPEND_CAP_SETTING).ok().as_deref(),
            crate::settings::var(MAX_EXCHANGES_SETTING).ok().as_deref(),
            crate::settings::var(WINDOW_SETTING).ok().as_deref(),
        )
    }

    fn from_values(
        cap: Option<&str>,
        count: Option<&str>,
        window: Option<&str>,
    ) -> Option<SessionTerms> {
        let uint = |s: &str| s.trim().parse::<u64>().ok().filter(|n| *n <= MAX_INTEGER);
        let spend_cap_msat = uint(cap?)?;
        let max_exchanges = match count {
            Some(c) if !c.trim().is_empty() => Some(uint(c).filter(|n| *n > 0)?),
            _ => None,
        };
        let window_seconds = match window {
            Some(w) if !w.trim().is_empty() => {
                uint(w).filter(|n| (MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(n))?
            }
            _ => DEFAULT_WINDOW_SECONDS,
        };
        Some(SessionTerms {
            spend_cap_msat,
            max_exchanges,
            window_seconds,
        })
    }

    /// The terms document (DESIGN §1): JCS-digested, named by `session.terms`.
    pub fn document(&self) -> Value {
        let mut doc = json!({
            "spend_cap": self.spend_cap_msat,
            "unit": UNIT,
            "payment_ref_type": PAYMENT_REF_TYPE,
        });
        if let Some(n) = self.max_exchanges {
            doc["max_exchanges"] = json!(n);
        }
        doc
    }
}

/// The terms a provider read from a proposal's terms document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    pub spend_cap_msat: u64,
    pub max_exchanges: Option<u64>,
}

/// Read a terms document by the shape R2 fixes, or `None`.
pub fn read_terms(doc: &Value) -> Option<Terms> {
    let doc = doc.as_object()?;
    if !doc.keys().all(|k| {
        matches!(
            k.as_str(),
            "spend_cap" | "unit" | "payment_ref_type" | "max_exchanges"
        )
    }) {
        return None;
    }
    let uint = |v: &Value| v.as_u64().filter(|n| *n <= MAX_INTEGER);
    if doc.get("unit")?.as_str()? != UNIT
        || doc.get("payment_ref_type")?.as_str()? != PAYMENT_REF_TYPE
    {
        return None;
    }
    Some(Terms {
        spend_cap_msat: uint(doc.get("spend_cap")?)?,
        max_exchanges: match doc.get("max_exchanges") {
            None => None,
            Some(v) => Some(uint(v).filter(|n| *n > 0)?),
        },
    })
}

/// The model canonical references a model policy names, read by the shape
/// DESIGN §1 fixes (`{"models": [{"model_canonical_ref", "weights_digest"?,
/// "quantization"?}, ...]}`, one to 16 entries), or `None`.
pub fn read_policy(doc: &Value) -> Option<Vec<String>> {
    let doc = doc.as_object()?;
    if doc.len() != 1 {
        return None;
    }
    let models = doc.get("models")?.as_array()?;
    if models.is_empty() || models.len() > MAX_POLICY_MODELS {
        return None;
    }
    models
        .iter()
        .map(|m| {
            let m = m.as_object()?;
            if !m.keys().all(|k| {
                matches!(
                    k.as_str(),
                    "model_canonical_ref" | "weights_digest" | "quantization"
                )
            }) || !m.values().all(Value::is_string)
            {
                return None;
            }
            let r = m.get("model_canonical_ref")?.as_str()?;
            (!r.is_empty() && r.len() <= MAX_MODEL_REF_LEN).then(|| r.to_string())
        })
        .collect()
}

/// The digest of [`contract`], published so a reader can check a record's
/// `contract_digest`. Changing the contract's content makes it `@2`; `@1`
/// never changes.
pub const CONTRACT_DIGEST: &str =
    "5f54aa7816d9ca9f469b8c4a8c79a0a67eadf475a0de4734368aa61f74efcc01";

/// The Evidence Contract every session names: what the provider undertakes
/// to produce evidence for. Payment is not a requirement: cap and count are
/// coverage labels, and over cap is "not covered", never a failure.
pub fn contract() -> Value {
    json!({
        "id": "x-capsules/paid-session",
        "version": "1",
        "requirements": [
            {"id": "R-prior", "statement": "the agreement was accepted before the exchange"},
            {"id": "R-served", "statement": "the provider's served half is present and verifies"},
            {"id": "R-model-stated", "statement": "the model the served half states is one the session's model policy names (stated, not verified)"},
        ],
    })
}

/// The model policy document (DESIGN §1): the models the requester expects
/// the provider to state it serves, by canonical reference. "States", never
/// "ran" (R-6).
pub fn model_policy(models: &[String]) -> Value {
    json!({"models": models.iter().map(|m| json!({"model_canonical_ref": m})).collect::<Vec<_>>()})
}

fn digest(v: &Value) -> String {
    acceptance::record_digest(v).expect("a parsed or built value is JCS-representable")
}

/// A time a record commits to, truncated to the minute, as every committed
/// time this plugin seals is (Evidence Layer -00 §12.1, "What a Checkpoint
/// Reveals"; capsule-emit's `utc_now_minute`): a disclosed agreement must not
/// reveal the node's activity pattern any finer than its other records do.
pub fn committed_time(unix_seconds: i64) -> String {
    profile_time(unix_seconds - unix_seconds.rem_euclid(60))
}

/// The profile's time form (§5.2), whole seconds, UTC.
pub fn profile_time(unix_seconds: i64) -> String {
    chrono::DateTime::from_timestamp(unix_seconds, 0)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// The profile's time form (§5.2): `YYYY-MM-DDTHH:MM:SSZ`, a real instant.
fn is_profile_time(s: &str) -> bool {
    s.len() == 20
        && s.ends_with('Z')
        && evidence_request::time::parse_rfc3339(s).is_some()
        && s.as_bytes()[10] == b'T'
}

fn hex_key(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// A proposal as sent: the signed `proposed` record and its three documents,
/// each as the JSON text that travels and is kept.
#[derive(Clone, Debug, PartialEq)]
pub struct Proposal {
    pub record: Value,
    pub record_text: String,
    /// The contract, model policy and terms, as text.
    pub documents: [String; 3],
}

impl Proposal {
    /// Build and sign a proposal from `requester` to `provider_key` for a new
    /// session `session_id` (≥128 random bits, text), starting `now`.
    pub fn new(
        requester: &SigningKey,
        provider_key: &str,
        session_id: &str,
        terms: &SessionTerms,
        models: &[String],
        now: i64,
    ) -> Proposal {
        let contract = contract();
        let policy = model_policy(models);
        let terms_doc = terms.document();
        let unsigned = json!({
            "profile": PROFILE,
            "state": "proposed",
            "contract_ref": CONTRACT_REF,
            "contract_digest": digest(&contract),
            "transaction": {"scheme": TRANSACTION_SCHEME, "id": session_id},
            "proposer": hex_key(requester),
            "acceptor": provider_key,
            "issued_at": committed_time(now),
            "session": {
                "not_before": committed_time(now),
                "not_after": committed_time(now + terms.window_seconds as i64),
                "policy": digest(&policy),
                "terms": digest(&terms_doc),
            },
        });
        let record = sign(unsigned, requester);
        Proposal {
            record_text: record.to_string(),
            record,
            documents: [
                contract.to_string(),
                policy.to_string(),
                terms_doc.to_string(),
            ],
        }
    }

    /// The message octets: `{"proposed": <text>, "documents": {"contract",
    /// "policy", "terms": <text>}}`.
    pub fn to_message(&self) -> Vec<u8> {
        let [contract, policy, terms] = &self.documents;
        serde_json::to_vec(&json!({
            "proposed": self.record_text,
            "documents": {"contract": contract, "policy": policy, "terms": terms},
        }))
        .expect("JSON values serialize")
    }

    /// The record digest of the `proposed` record.
    pub fn digest(&self) -> String {
        digest(&self.record)
    }
}

fn sign(unsigned: Value, key: &SigningKey) -> Value {
    let Value::Object(map) = unsigned else {
        unreachable!("records are objects")
    };
    Value::Object(acceptance::sign(map, key).expect("records built here are JCS-representable"))
}

/// Why a provider declines a proposal, or a requester refuses an answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the message is not JSON in the profile's data model")]
    Malformed,
    #[error("the record is not a valid {0} record")]
    Record(&'static str),
    #[error("the record's signature does not verify")]
    Signature,
    #[error("a document is missing or does not match its digest: {0}")]
    Document(&'static str),
    #[error("the terms document is not the shape this plugin reads")]
    Terms,
    #[error("the model policy is not the shape this plugin reads")]
    Policy,
    #[error("the record names another party")]
    Party,
    #[error("the session window does not hold the present time, or is too long")]
    Window,
    #[error("the answer does not answer this proposal")]
    NotThisProposal,
}

/// A proposal the provider checked.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedProposal {
    pub record: Map<String, Value>,
    pub record_text: String,
    pub digest: String,
    pub terms: Terms,
    pub models: Vec<String>,
    /// The contract, model policy and terms, as received.
    pub documents: [String; 3],
}

/// The provider's check of a proposal message: addressed to `own_key`,
/// carrying the three documents its digests name in the shapes this plugin
/// reads, this plugin's contract, and a window of at most a day that holds
/// `now` within the clock skew. The record's own form and signature are
/// checked with the answer ([`check_records`]).
pub fn check_proposal(message: &[u8], own_key: &str, now: i64) -> Result<CheckedProposal, Refusal> {
    let msg = acceptance::parse(message).ok_or(Refusal::Malformed)?;
    let text_at = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(String::from);
    let record_text = text_at(&msg, "proposed").ok_or(Refusal::Record("proposed"))?;
    let record = acceptance::parse(record_text.as_bytes()).ok_or(Refusal::Malformed)?;
    let Value::Object(r) = &record else {
        return Err(Refusal::Record("proposed"));
    };
    let text = |k: &str| r.get(k).and_then(Value::as_str);
    // The record's whole form (§11.1.2): the profile's verifier checks the
    // form of an answer, not of the proposal it answers.
    const MEMBERS: [&str; 10] = [
        "profile",
        "state",
        "contract_ref",
        "contract_digest",
        "transaction",
        "proposer",
        "acceptor",
        "issued_at",
        "session",
        "sig",
    ];
    if r.len() != MEMBERS.len()
        || !MEMBERS.iter().all(|k| r.contains_key(*k))
        || text("profile") != Some(PROFILE)
        || text("state") != Some("proposed")
        || !text("issued_at").is_some_and(is_profile_time)
        || !text("proposer").is_some_and(evidence_request::registry::is_digest)
        || !r
            .get("session")
            .and_then(Value::as_object)
            .is_some_and(|s| {
                s.len() == 4
                    && ["not_before", "not_after", "policy", "terms"]
                        .iter()
                        .all(|k| s.get(*k).is_some_and(Value::is_string))
                    && ["not_before", "not_after"]
                        .iter()
                        .all(|k| s[*k].as_str().is_some_and(is_profile_time))
            })
    {
        return Err(Refusal::Record("proposed"));
    }
    if text("acceptor") != Some(own_key) {
        return Err(Refusal::Party);
    }
    let docs = msg.get("documents").ok_or(Refusal::Document("documents"))?;
    let session = r.get("session").ok_or(Refusal::Record("proposed"))?;
    let named =
        |doc: &'static str, digest_at: Option<&Value>| -> Result<(String, Value), Refusal> {
            let text = text_at(docs, doc).ok_or(Refusal::Document(doc))?;
            let value = acceptance::parse(text.as_bytes()).ok_or(Refusal::Document(doc))?;
            (digest_at.and_then(Value::as_str) == Some(digest(&value).as_str()))
                .then_some((text, value))
                .ok_or(Refusal::Document(doc))
        };
    // The one contract this plugin undertakes, by its published digest.
    let (contract_text, _) = named("contract", r.get("contract_digest"))?;
    if text("contract_digest") != Some(CONTRACT_DIGEST)
        || text("contract_ref") != Some(CONTRACT_REF)
    {
        return Err(Refusal::Document("contract"));
    }
    let (policy_text, policy) = named("policy", session.get("policy"))?;
    let models = read_policy(&policy).ok_or(Refusal::Policy)?;
    let (terms_text, terms_doc) = named("terms", session.get("terms"))?;
    let terms = read_terms(&terms_doc).ok_or(Refusal::Terms)?;
    let window = |k: &str| {
        session
            .get(k)
            .and_then(Value::as_str)
            .and_then(evidence_request::time::parse_rfc3339)
            .map(|t| t.seconds)
    };
    // A window that starts now (within the clock skew), lasts a minute to a
    // day, and has not ended.
    match (window("not_before"), window("not_after")) {
        (Some(nb), Some(na))
            if (nb - now).abs() <= CLOCK_SKEW_SECONDS
                && now <= na
                && na >= nb
                && (MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(&((na - nb) as u64)) => {}
        _ => return Err(Refusal::Window),
    }
    match r.get("transaction") {
        Some(Value::Object(t))
            if t.get("scheme").and_then(Value::as_str) == Some(TRANSACTION_SCHEME)
                && t.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| (32..=128).contains(&id.len())) => {}
        _ => return Err(Refusal::Record("proposed")),
    }
    Ok(CheckedProposal {
        digest: digest(&record),
        record: r.clone(),
        record_text,
        terms,
        models,
        documents: [contract_text, policy_text, terms_text],
    })
}

/// The provider's answer to a checked proposal: `accepted` (or `declined`),
/// carrying the proposal's contract, transaction, parties and session, as
/// the §11.1.2 equality rule requires.
pub fn answer(checked: &CheckedProposal, provider: &SigningKey, accept: bool, now: i64) -> Value {
    let mut unsigned = Map::new();
    for k in [
        "profile",
        "contract_ref",
        "contract_digest",
        "transaction",
        "proposer",
        "acceptor",
        "session",
    ] {
        if let Some(v) = checked.record.get(k) {
            unsigned.insert(k.into(), v.clone());
        }
    }
    unsigned.insert(
        "state".into(),
        Value::from(if accept { "accepted" } else { "declined" }),
    );
    unsigned.insert(
        "proposal_digest".into(),
        Value::from(checked.digest.clone()),
    );
    unsigned.insert("issued_at".into(), Value::from(committed_time(now)));
    sign(Value::Object(unsigned), provider)
}

/// The proposal and an `accepted` answer, checked by the profile's verifier
/// as one candidate (§11.1.7): every deciding property `PASS`, and every
/// receipt given `PASS` too. `Err` names the first property that is not.
pub fn check_records(
    proposed: &[u8],
    accepted: &[u8],
    receipts: &[&[u8]],
    now: i64,
) -> Result<(), String> {
    let parsed = acceptance::parse(accepted).ok_or("the answer is not JSON")?;
    let field = |k: &str| {
        parsed
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let (proposer, acceptor) = (field("proposer"), field("acceptor"));
    let transaction = parsed.get("transaction").cloned().unwrap_or(Value::Null);
    let trust = TrustPolicy {
        parties: [
            (proposer.clone(), "requester".to_string()),
            (acceptor.clone(), "provider".to_string()),
        ]
        .into(),
        ..TrustPolicy::default()
    };
    let res = acceptance::evaluate(
        &Inputs {
            contract: &contract(),
            transaction: &transaction,
            proposer: &proposer,
            acceptor: &acceptor,
            records: &[proposed, accepted],
            execution_records: &[],
            receipts,
            trust: &trust,
            evaluation_time: &profile_time(now),
            session: true,
            form_ii_objects: 0,
            profiles_implemented: &[PROFILE],
        },
        acceptance::read_fixture_execution_record,
    )
    .map_err(|e| e.to_string())?;
    let candidate = res
        .candidates
        .first()
        .ok_or("the answer is not an accepted record for this proposal")?;
    for p in [
        "acceptance_form",
        "acceptance_signature",
        "acceptance_signer_trust",
        "acceptance_binding",
        "proposal_binding",
    ] {
        if candidate.status(p) != Some(Status::Pass) {
            return Err(format!("{p} is not PASS"));
        }
    }
    if res.receipts.len() != receipts.len() {
        return Err("a receipt is not for this acceptance".into());
    }
    // The verifier checks a receipt's members and signature, not the value
    // of its time: a receipt is the ordering point only when that is a time.
    for rc in receipts {
        let rc = acceptance::parse(rc).ok_or("a receipt is not JSON")?;
        if !rc
            .get("received_at")
            .and_then(Value::as_str)
            .is_some_and(is_profile_time)
            || rc.get("profile").and_then(Value::as_str) != Some(PROFILE)
        {
            return Err("a receipt's profile or received_at is not the profile's".into());
        }
    }
    for r in &res.receipts {
        for p in ["receipt_signature", "receipt_signer"] {
            if r.status(p) != Some(Status::Pass) {
                return Err(format!("{p} is not PASS"));
            }
        }
    }
    Ok(())
}

/// What a requester read from the provider's answer.
#[derive(Clone, Debug, PartialEq)]
pub enum Answer {
    /// The provider accepted: the record's text and digest.
    Accepted { text: String, digest: String },
    /// The provider declined, or countered (never auto-accepted, R9).
    NotAccepted,
}

/// The requester's check of an answer to `proposal`: an `accepted` record
/// the profile's verifier finds formed, signed by the provider the proposal
/// names and bound to the proposal.
pub fn check_answer(proposal: &Proposal, text: &str, now: i64) -> Result<Answer, Refusal> {
    let answer = acceptance::parse(text.as_bytes()).ok_or(Refusal::Malformed)?;
    if answer.get("proposal_digest").and_then(Value::as_str) != Some(proposal.digest().as_str()) {
        return Err(Refusal::NotThisProposal);
    }
    match answer.get("state").and_then(Value::as_str) {
        Some("accepted") => {}
        Some("declined" | "countered") => return Ok(Answer::NotAccepted),
        _ => return Err(Refusal::Record("answer")),
    }
    if answer.get("acceptor") != proposal.record.get("acceptor") {
        return Err(Refusal::Party);
    }
    check_records(proposal.record_text.as_bytes(), text.as_bytes(), &[], now).map_err(|why| {
        if why.starts_with("acceptance_signature") {
            Refusal::Signature
        } else {
            Refusal::Record("accepted")
        }
    })?;
    Ok(Answer::Accepted {
        digest: digest(&answer),
        text: text.to_string(),
    })
}

/// The requester's §11.1.4 receipt for an accepted record it holds,
/// received at `now`.
pub fn receipt(acceptance_digest: &str, requester: &SigningKey, now: i64) -> Value {
    sign(
        json!({
            "profile": PROFILE,
            "acceptance_digest": acceptance_digest,
            "received_at": committed_time(now),
            "receiver": hex_key(requester),
        }),
        requester,
    )
}

/// What kind of agreement object a stored file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Record,
    Receipt,
    Document,
}

impl Kind {
    fn dir(self) -> &'static str {
        match self {
            Kind::Record => "records",
            Kind::Receipt => "receipts",
            Kind::Document => "documents",
        }
    }
}

/// Agreement objects, kept byte-exact as sent or received, one file per
/// object named by its digest: `<ledger>/agreements/<kind>/<digest>.json`.
/// The first octets kept for a digest stay; a later copy of the same object
/// (whatever its spacing) is the same file.
pub struct Store {
    root: PathBuf,
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Counts the objects each [`Store`] root published in this process, so a
/// reader that keeps what it parsed (`agreement_bridge`'s session cache)
/// knows when to read again. Per root, so a write to one store never
/// invalidates another's cache.
static GENERATIONS: std::sync::Mutex<std::collections::BTreeMap<PathBuf, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn bump_generation(root: &Path) {
    *GENERATIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(root.to_path_buf())
        .or_insert(0) += 1;
}

/// Count a change made other than through [`Store::put`] (a test that
/// removes files).
#[cfg(test)]
pub fn bump_generation_for_tests(store: &Store) {
    bump_generation(&store.root);
}

/// The publication count of the store at `root` (see [`GENERATIONS`]).
pub fn generation(root: &Path) -> u64 {
    GENERATIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(root)
        .copied()
        .unwrap_or(0)
}

impl Store {
    /// Where this store keeps its objects.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn open(ledger_dir: &Path) -> Store {
        Store {
            root: ledger_dir.join("agreements"),
        }
    }

    /// Keep `octets` (which must parse in the profile's data model) and
    /// return their digest. Written to a temporary file of its own, then
    /// published with a hard link, which never replaces a file already
    /// there, so concurrent puts never expose a partial file.
    pub fn put(&self, kind: Kind, octets: &[u8]) -> std::io::Result<String> {
        let value = acceptance::parse(octets).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "not a profile JSON value")
        })?;
        let digest = digest(&value);
        let dir = self.root.join(kind.dir());
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{digest}.json"));
        if path.exists() {
            return Ok(digest);
        }
        let tmp = dir.join(format!(
            ".{digest}.{}.{}.tmp",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let written = (|| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(octets)?;
            f.sync_data()?;
            match std::fs::hard_link(&tmp, &path) {
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
                Err(_) => Ok(()),
                Ok(()) => {
                    bump_generation(&self.root);
                    Ok(())
                }
            }
        })();
        let _ = std::fs::remove_file(&tmp);
        written.map(|()| digest)
    }

    #[cfg(test)]
    pub fn root_for_tests(&self) -> &Path {
        &self.root
    }

    /// The octets kept under `digest`, as they were kept.
    pub fn get(&self, kind: Kind, digest: &str) -> Option<Vec<u8>> {
        if !evidence_request::registry::is_digest(digest) {
            return None;
        }
        std::fs::read(self.root.join(kind.dir()).join(format!("{digest}.json"))).ok()
    }

    /// Every object of `kind` kept, as octets, in digest order.
    pub fn all(&self, kind: Kind) -> Vec<Vec<u8>> {
        let Ok(entries) = std::fs::read_dir(self.root.join(kind.dir())) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|x| x == "json")
                    && !p
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            })
            .collect();
        paths.sort();
        paths
            .into_iter()
            .filter_map(|p| std::fs::read(p).ok())
            .collect()
    }
}

/// A fresh session id: 128 random bits, as 32 lowercase hex.
pub fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("the OS random source is available");
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_793_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn terms() -> SessionTerms {
        SessionTerms {
            spend_cap_msat: 3_000,
            max_exchanges: Some(2),
            window_seconds: 3_600,
        }
    }

    fn proposal(requester: &SigningKey, provider: &SigningKey, now: i64) -> Proposal {
        Proposal::new(
            requester,
            &hex_key(provider),
            &new_session_id(),
            &terms(),
            &["hf:example/model@main".to_string()],
            now,
        )
    }

    #[test]
    fn committed_times_are_to_the_minute() {
        let (p, q) = (key(1), key(2));
        let proposal = proposal(&p, &q, NOW);
        let r = &proposal.record;
        let start = profile_time(NOW - NOW.rem_euclid(60));
        assert_eq!(r["issued_at"], json!(start));
        assert_eq!(r["session"]["not_before"], json!(start));
        assert!(r["session"]["not_after"]
            .as_str()
            .unwrap()
            .ends_with(":00Z"));
        let checked = check_proposal(&proposal.to_message(), &hex_key(&q), NOW).unwrap();
        assert!(answer(&checked, &q, true, NOW + 7)["issued_at"]
            .as_str()
            .unwrap()
            .ends_with(":00Z"));
        assert!(receipt(&"ab".repeat(32), &p, NOW + 7)["received_at"]
            .as_str()
            .unwrap()
            .ends_with(":00Z"));
    }

    #[test]
    fn the_contract_is_the_published_one() {
        assert_eq!(digest(&contract()), CONTRACT_DIGEST);
    }

    #[test]
    fn terms_come_from_the_settings_or_not_at_all() {
        assert_eq!(SessionTerms::from_values(None, Some("2"), None), None);
        assert_eq!(
            SessionTerms::from_values(Some("3000"), None, None),
            Some(SessionTerms {
                spend_cap_msat: 3000,
                max_exchanges: None,
                window_seconds: DEFAULT_WINDOW_SECONDS
            })
        );
        assert_eq!(
            SessionTerms::from_values(Some("3000"), Some("2"), Some("60")),
            Some(SessionTerms {
                spend_cap_msat: 3000,
                max_exchanges: Some(2),
                window_seconds: 60
            })
        );
        for (cap, count, window) in [
            ("-1", "", ""),
            ("1.5", "", ""),
            ("9007199254740992", "", ""),
            ("3000", "0", ""),
            ("3000", "x", ""),
            ("3000", "", "0"),
            ("3000", "", "59"),
            ("3000", "", "86401"),
        ] {
            assert_eq!(
                SessionTerms::from_values(Some(cap), Some(count), Some(window)),
                None,
                "{cap} {count} {window}"
            );
        }
    }

    #[test]
    fn a_proposal_round_trips_into_an_accepted_record_and_a_receipt() {
        let (p, q) = (key(1), key(2));
        let proposal = proposal(&p, &q, NOW);
        let checked = check_proposal(&proposal.to_message(), &hex_key(&q), NOW + 5).unwrap();
        assert_eq!(checked.digest, proposal.digest());
        assert_eq!(checked.record_text, proposal.record_text);
        assert_eq!(checked.documents, proposal.documents, "documents as sent");
        assert_eq!(checked.models, vec!["hf:example/model@main".to_string()]);
        let accepted = answer(&checked, &q, true, NOW + 6).to_string();
        let Answer::Accepted { text, digest: d } =
            check_answer(&proposal, &accepted, NOW + 6).unwrap()
        else {
            panic!("accepted")
        };
        assert_eq!(text, accepted);
        let rc = receipt(&d, &p, NOW + 7).to_string();
        assert_eq!(
            check_records(
                proposal.record_text.as_bytes(),
                accepted.as_bytes(),
                &[rc.as_bytes()],
                NOW + 8,
            ),
            Ok(())
        );
        let mut no_time = receipt(&d, &p, NOW + 7);
        no_time["received_at"] = Value::Null;
        no_time.as_object_mut().unwrap().remove("sig");
        let no_time = sign(no_time, &p).to_string();
        assert!(
            check_records(
                proposal.record_text.as_bytes(),
                accepted.as_bytes(),
                &[no_time.as_bytes()],
                NOW + 8
            )
            .is_err(),
            "a receipt whose received_at is not a time"
        );
        let by_provider = receipt(&d, &q, NOW + 7).to_string();
        assert!(
            check_records(
                proposal.record_text.as_bytes(),
                accepted.as_bytes(),
                &[by_provider.as_bytes()],
                NOW + 8
            )
            .is_err(),
            "a receipt by the acceptor is not the proposer's"
        );
    }

    fn tampered(proposal: &Proposal, f: &dyn Fn(&mut Value)) -> Vec<u8> {
        let mut m: Value = serde_json::from_slice(&proposal.to_message()).unwrap();
        f(&mut m);
        serde_json::to_vec(&m).unwrap()
    }

    fn re_sign_record(m: &mut Value, key: &SigningKey, f: &dyn Fn(&mut Value)) {
        let mut r: Value = serde_json::from_str(m["proposed"].as_str().unwrap()).unwrap();
        f(&mut r);
        r.as_object_mut().unwrap().remove("sig");
        m["proposed"] = json!(sign(r, key).to_string());
    }

    fn re_document(m: &mut Value, key: &SigningKey, name: &str, doc: &Value) {
        let d = digest(doc);
        m["documents"][name] = json!(doc.to_string());
        re_sign_record(m, key, &|r| r["session"][name] = json!(d));
    }

    #[test]
    fn a_provider_refuses_a_proposal_it_cannot_check() {
        let (p, q) = (key(1), key(2));
        let proposal = proposal(&p, &q, NOW);
        let own = hex_key(&q);
        let refused = |msg: &[u8], now: i64| check_proposal(msg, &own, now).err();
        assert_eq!(refused(b"{\"a\":1,\"a\":1}", NOW), Some(Refusal::Malformed));
        assert_eq!(
            check_proposal(&proposal.to_message(), &hex_key(&key(3)), NOW).err(),
            Some(Refusal::Party),
            "addressed to another provider"
        );
        assert_eq!(
            refused(
                &tampered(&proposal, &|m| m["documents"]["terms"] = json!(
                    r#"{"spend_cap":9,"unit":"msat","payment_ref_type":"ln.payment_hash"}"#
                )),
                NOW
            ),
            Some(Refusal::Document("terms")),
            "a document that does not match its digest"
        );
        assert_eq!(
            refused(
                &tampered(&proposal, &|m| {
                    m["documents"].as_object_mut().unwrap().remove("policy");
                }),
                NOW
            ),
            Some(Refusal::Document("policy"))
        );
        for bad_policy in [
            json!(null),
            json!({}),
            json!({"models": []}),
            json!({"models": [{"model_canonical_ref": 7}]}),
            json!({"models": [{"model_canonical_ref": "m", "extra": "x"}]}),
            json!({"models": vec![json!({"model_canonical_ref": "m"}); 17]}),
        ] {
            assert_eq!(
                refused(
                    &tampered(&proposal, &|m| re_document(m, &p, "policy", &bad_policy)),
                    NOW
                ),
                Some(Refusal::Policy),
                "{bad_policy}"
            );
        }
        assert_eq!(
            refused(&proposal.to_message(), NOW + 3_601 + CLOCK_SKEW_SECONDS),
            Some(Refusal::Window)
        );
        assert_eq!(
            refused(
                &tampered(&proposal, &|m| re_sign_record(m, &p, &|r| r["session"]
                    ["not_after"] =
                    json!(profile_time(NOW + 86_401)))),
                NOW
            ),
            Some(Refusal::Window),
            "a window longer than a day"
        );
        for (label, nb, na) in [
            ("ended", NOW - 120, NOW - 1),
            ("shorter than a minute", NOW, NOW + 59),
            ("starting in the past", NOW - 3_000, NOW + 600),
        ] {
            assert_eq!(
                refused(
                    &tampered(&proposal, &|m| re_sign_record(m, &p, &|r| {
                        r["session"]["not_before"] = json!(profile_time(nb));
                        r["session"]["not_after"] = json!(profile_time(na));
                    })),
                    NOW
                ),
                Some(Refusal::Window),
                "{label}"
            );
        }
        // Signed by the proposer, but not a well-formed proposed record.
        for (label, change) in [
            (
                "no issued_at",
                &(|r: &mut Value| {
                    r.as_object_mut().unwrap().remove("issued_at");
                }) as &dyn Fn(&mut Value),
            ),
            ("a proposal_digest", &|r: &mut Value| {
                r["proposal_digest"] = json!("0".repeat(64))
            }),
            ("an unknown member", &|r: &mut Value| {
                r["extra"] = json!("x")
            }),
            ("issued_at not a profile time", &|r: &mut Value| {
                r["issued_at"] = json!("2026-10-12T00:00:00.5Z")
            }),
            ("a session member too many", &|r: &mut Value| {
                r["session"]["count"] = json!("2")
            }),
        ] {
            assert_eq!(
                refused(
                    &tampered(&proposal, &|m| re_sign_record(m, &p, change)),
                    NOW
                ),
                Some(Refusal::Record("proposed")),
                "{label}"
            );
        }
    }

    #[test]
    fn a_provider_whose_clock_lags_still_accepts() {
        let (p, q) = (key(1), key(2));
        let proposal = proposal(&p, &q, NOW);
        assert!(check_proposal(&proposal.to_message(), &hex_key(&q), NOW - 120).is_ok());
        // The window starts at the proposal's minute.
        let start = NOW - NOW.rem_euclid(60);
        assert_eq!(
            check_proposal(
                &proposal.to_message(),
                &hex_key(&q),
                start - CLOCK_SKEW_SECONDS - 1
            )
            .err(),
            Some(Refusal::Window)
        );
    }

    #[test]
    fn terms_of_another_shape_are_refused() {
        let ok = json!({"spend_cap": 1, "unit": "msat", "payment_ref_type": "ln.payment_hash"});
        assert!(read_terms(&ok).is_some());
        for bad in [
            json!({"spend_cap": 1, "unit": "sat", "payment_ref_type": "ln.payment_hash"}),
            json!({"spend_cap": 1, "unit": "msat", "payment_ref_type": "bolt11"}),
            json!({"spend_cap": 1, "unit": "msat", "payment_ref_type": "ln.payment_hash", "extra": 1}),
            json!({"spend_cap": 1, "unit": "msat", "payment_ref_type": "ln.payment_hash", "max_exchanges": 0}),
            json!({"unit": "msat", "payment_ref_type": "ln.payment_hash"}),
        ] {
            assert_eq!(read_terms(&bad), None, "{bad}");
        }
    }

    #[test]
    fn a_requester_refuses_a_malformed_or_foreign_answer_and_never_accepts_a_counter() {
        let (p, q) = (key(1), key(2));
        let proposal = proposal(&p, &q, NOW);
        let checked = check_proposal(&proposal.to_message(), &hex_key(&q), NOW).unwrap();
        let other = self::proposal(&p, &q, NOW);
        let accepted = answer(&checked, &q, true, NOW).to_string();
        assert_eq!(
            check_answer(&other, &accepted, NOW),
            Err(Refusal::NotThisProposal)
        );
        let by_other_key = answer(&checked, &key(3), true, NOW).to_string();
        assert_eq!(
            check_answer(&proposal, &by_other_key, NOW),
            Err(Refusal::Signature)
        );
        let resigned = |f: &dyn Fn(&mut Value)| {
            let mut v = answer(&checked, &q, true, NOW);
            f(&mut v);
            v.as_object_mut().unwrap().remove("sig");
            sign(v, &q).to_string()
        };
        // Signed by the provider, but not a well-formed accepted record.
        for bad in [
            resigned(&|v| {
                v.as_object_mut().unwrap().remove("issued_at");
            }),
            resigned(&|v| v["counter_contract_digest"] = json!("0".repeat(64))),
            resigned(&|v| v["session"]["not_after"] = json!("tomorrow")),
        ] {
            assert!(check_answer(&proposal, &bad, NOW).is_err(), "{bad}");
        }
        let declined = answer(&checked, &q, false, NOW).to_string();
        assert_eq!(
            check_answer(&proposal, &declined, NOW),
            Ok(Answer::NotAccepted)
        );
        let counter = resigned(&|v| {
            v["state"] = json!("countered");
            v["counter_contract_digest"] = json!("0".repeat(64));
        });
        assert_eq!(
            check_answer(&proposal, &counter, NOW),
            Ok(Answer::NotAccepted)
        );
    }

    #[test]
    fn the_store_keeps_the_first_octets_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path());
        // Member order and spacing as sent, not as re-serialized.
        let octets = br#"{ "b": "x", "a": 1 }"#;
        let d = store.put(Kind::Record, octets).unwrap();
        assert_eq!(d, digest(&json!({"a": 1, "b": "x"})));
        assert_eq!(store.get(Kind::Record, &d).as_deref(), Some(&octets[..]));
        assert_eq!(
            store.put(Kind::Record, br#"{"a":1,"b":"x"}"#).unwrap(),
            d,
            "the same object, spaced otherwise, is the same file"
        );
        assert_eq!(
            store.get(Kind::Record, &d).as_deref(),
            Some(&octets[..]),
            "the first stays"
        );
        assert_eq!(store.all(Kind::Record).len(), 1);
        assert!(store.put(Kind::Record, br#"{"a":1,"a":2}"#).is_err());
        assert_eq!(store.get(Kind::Record, "../x"), None);
    }

    #[test]
    fn concurrent_puts_of_one_object_publish_one_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(Store::open(dir.path()));
        let spacings: Vec<String> = (0..16)
            .map(|i| {
                format!(
                    "{{{}\"a\":1,\"b\":\"{}\"}}",
                    " ".repeat(i),
                    "x".repeat(4096)
                )
            })
            .collect();
        let handles: Vec<_> = spacings
            .iter()
            .cloned()
            .map(|text| {
                let store = store.clone();
                std::thread::spawn(move || store.put(Kind::Document, text.as_bytes()).unwrap())
            })
            .collect();
        let digests: std::collections::BTreeSet<String> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(digests.len(), 1);
        let kept = store.get(Kind::Document, digests.first().unwrap()).unwrap();
        assert!(
            spacings.iter().any(|s| s.as_bytes() == kept),
            "one of the copies, whole"
        );
        assert_eq!(
            std::fs::read_dir(dir.path().join("agreements/documents"))
                .unwrap()
                .count(),
            1,
            "no temporary file left"
        );
    }
}
