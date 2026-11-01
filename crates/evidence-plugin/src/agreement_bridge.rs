//! `x-capsules-agreement/1`: the private plugin mesh channel a requester
//! sets up a service evidence agreement with a provider over
//! ([`crate::agreement`]). Like `commitment/1`, it is declared in the
//! manifest and carried by mesh-llm's plugin mesh streams;
//! `OpenStreamRequest` names no channel, so the requester tags its open with
//! [`agreement::CHANNEL`] in `metadata_json` and `main.rs` dispatches on it.
//!
//! **The frames.** Each message is one stream: the requester writes its
//! frame and half-closes, the provider answers and closes. Records,
//! receipts and documents travel as JSON text, so each side keeps the octets
//! the other signed.
//!
//! - `{"proposed": "<record>", "documents": {...}}` → `{"answer": "<record>"}`,
//!   or `{"error": "<why>"}`. A proposal sent again gets the answer first
//!   given to it, so one proposal never has two answers (§11.1.1).
//! - `{"receipt": "<receipt>"}` → `{"ok": true}` or `{"error": "<why>"}`. The
//!   first receipt kept for an acceptance stays.
//!
//! A provider that predates agreements routes the tagged open to its
//! evidence responder, which answers at once with a frame of another shape:
//! the requester reads any reply without `answer` as "no agreement" and does
//! not wait (R9).
//!
//! **Bounds.** The provider answers only a proposer whose key a peer
//! announced (`peer_keys`), at most [`MAX_IN_FLIGHT`] frames at once, and
//! holds at most [`MAX_OPEN_SESSIONS_PER_REQUESTER`] unexpired sessions per
//! requester. Kept objects are never removed yet: retention is an open item
//! (`docs/AGREEMENTS.md`).
//!
//! **When.** The requester sets up a session on an exchange with a provider
//! once the operator set session terms
//! ([`agreement::SessionTerms::from_settings`]) and no unexpired session
//! with that provider names the exchange's model (R11). That exchange is
//! outside the agreement; later exchanges in the window cite it. The set-up
//! runs in its own task, off the host's ordered channel handling, under one
//! deadline; after a failure the requester waits [`RETRY_AFTER`] before it
//! proposes to that provider again.
//!
//! Where the operator granted the admission hook, the requester sets the
//! session up at `backend_selected` instead, before the request goes out,
//! holding it at most [`hook_wait`], which the operator sets below the
//! grant's `deadline_ms` ([`hold_for_session`]). A set-up that takes longer
//! finishes in the background and the request goes on; whether that
//! exchange then cites the session is decided at its terminal event, and
//! the provider cites only a session it held complete when it served.
//! A host that names no model there (or at the terminal event) is asked
//! for the provider's model through its status (`host_status`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{bind_side_stream, LocalListener, PluginContext, PluginError, PluginResult};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::agreement::{self, Answer, Kind, Proposal, SessionTerms, Store};
use crate::capsule_emit::CapsuleState;
use crate::mesh_evidence_bridge::{env_millis, next_stream_id, read_to_end_bounded};

/// The most agreement frames the provider works on at once.
pub const MAX_IN_FLIGHT: usize = 4;
/// The most unexpired sessions a provider holds with one requester.
pub const MAX_OPEN_SESSIONS_PER_REQUESTER: usize = 8;
/// The most sessions a provider accepts from one requester in a day, so
/// what it keeps grows by a bounded amount per requester.
pub const MAX_SESSIONS_PER_REQUESTER_PER_DAY: usize = 48;
/// How long a requester waits before proposing again to a provider after a
/// set-up that did not end in an agreement.
pub const RETRY_AFTER: Duration = Duration::from_secs(600);

/// True exactly when an inbound `OpenStreamRequest` is this module's.
pub fn is_agreement_request(request: &OpenStreamRequest) -> bool {
    request.metadata_json.as_deref() == Some(agreement::CHANNEL)
}

fn responder_timeout() -> Duration {
    env_millis("CAPSULES_AGREEMENT_RESPONDER_TIMEOUT_MS", 10_000)
}

/// Room the hold leaves under the declared deadline for the decision itself.
const HOLD_MARGIN_MS: u64 = 250;

/// How long after the admission hook is called a request may be held for
/// its session set-up. Off (0) unless the operator sets it, since the plugin
/// cannot see the grant's `deadline_ms`, which it must stay below; at most
/// [`HOLD_MARGIN_MS`] under [`crate::admission::HOOK_DEADLINE_MS`], what the
/// hook declares. Read once, at the first call (`main.rs` makes it at
/// start), so the hook never reads a setting while it holds a request.
pub fn hook_wait() -> Duration {
    static WAIT: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *WAIT.get_or_init(|| {
        env_millis("CAPSULES_AGREEMENT_HOOK_WAIT_MS", 0).min(Duration::from_millis(
            crate::admission::HOOK_DEADLINE_MS - HOLD_MARGIN_MS,
        ))
    })
}

/// The bounded wait for one frame's round trip, connect included (R9).
fn requester_timeout() -> Duration {
    env_millis("CAPSULES_AGREEMENT_TIMEOUT_MS", 8_000)
}

pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn own_key(capsules: &CapsuleState) -> String {
    hex::encode(capsules.public_key())
}

fn parse(octets: &[u8]) -> Option<Value> {
    evidence_request::acceptance::parse(octets)
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn window_start(record: &Value) -> Option<i64> {
    record
        .get("session")?
        .get("not_before")?
        .as_str()
        .and_then(evidence_request::time::parse_rfc3339)
        .map(|t| t.seconds)
}

fn window_end(record: &Value) -> Option<i64> {
    record
        .get("session")?
        .get("not_after")?
        .as_str()
        .and_then(evidence_request::time::parse_rfc3339)
        .map(|t| t.seconds)
}

// ---------------------------------------------------------------------
// Provider role
// ---------------------------------------------------------------------

/// Serializes the provider's proposal path, so a proposal sent twice at once
/// is answered once.
static PROPOSALS: Mutex<()> = Mutex::new(());

/// The provider's reply to one frame. `known_requester` says whether a peer
/// announced the proposer's key.
pub fn respond(
    capsules: &CapsuleState,
    store: &Store,
    frame: &[u8],
    known_requester: &dyn Fn(&str) -> bool,
    now: i64,
) -> Value {
    let error = |why: &str| json!({ "error": why });
    let Some(msg) = parse(frame) else {
        return error(&agreement::Refusal::Malformed.to_string());
    };
    if msg.get("proposed").is_some() {
        return match propose_answer(capsules, store, frame, known_requester, now) {
            Ok(answer_text) => json!({ "answer": answer_text }),
            Err(why) => error(&why),
        };
    }
    if let Some(receipt) = text(&msg, "receipt") {
        return match keep_receipt(store, receipt, &own_key(capsules), now) {
            Ok(()) => json!({ "ok": true }),
            Err(why) => error(&why),
        };
    }
    error("an agreement frame holds `proposed` or `receipt`")
}

fn propose_answer(
    capsules: &CapsuleState,
    store: &Store,
    frame: &[u8],
    known_requester: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<String, String> {
    // A proposal sent again gets its first answer back, whenever it comes:
    // the window rule below is for a new session, not for one answered.
    if let Some(answer) = first_answer(store, frame, &own_key(capsules)) {
        return Ok(answer);
    }
    let checked =
        agreement::check_proposal(frame, &own_key(capsules), now).map_err(|e| e.to_string())?;
    let proposer = checked
        .record
        .get("proposer")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !known_requester(&proposer) {
        return Err("no peer announced the proposer's key".into());
    }
    let _serial = PROPOSALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let records: Vec<(Vec<u8>, Value)> = store
        .all(Kind::Record)
        .into_iter()
        .filter_map(|o| parse(&o).map(|v| (o, v)))
        .collect();
    // A proposal sent again gets its first answer back.
    if let Some((octets, _)) = records
        .iter()
        .find(|(_, r)| text(r, "proposal_digest") == Some(checked.digest.as_str()))
    {
        return String::from_utf8(octets.clone()).map_err(|e| e.to_string());
    }
    let mine: Vec<&Value> = records
        .iter()
        .map(|(_, r)| r)
        .filter(|r| {
            text(r, "state") == Some("accepted") && text(r, "proposer") == Some(proposer.as_str())
        })
        .collect();
    let open = mine
        .iter()
        .filter(|r| window_end(r).is_some_and(|end| now <= end + agreement::CLOCK_SKEW_SECONDS))
        .count();
    if open >= MAX_OPEN_SESSIONS_PER_REQUESTER {
        return Err("the requester already holds the most open sessions".into());
    }
    let today = mine
        .iter()
        .filter(|r| window_start(r).is_some_and(|nb| now - nb < 86_400))
        .count();
    if today >= MAX_SESSIONS_PER_REQUESTER_PER_DAY {
        return Err("the requester has set up the most sessions for a day".into());
    }
    let answer_text = agreement::answer(&checked, capsules.signing_key(), true, now).to_string();
    // The profile's verifier checks the proposal's own form and signature
    // with the answer; nothing is kept or signed away unless it passes.
    agreement::check_records(
        checked.record_text.as_bytes(),
        answer_text.as_bytes(),
        &[],
        now,
    )?;
    // Documents and the proposal first, the answer last: an answer on disk
    // always has its proposal and documents beside it.
    for doc in &checked.documents {
        store
            .put(Kind::Document, doc.as_bytes())
            .map_err(keep_error)?;
    }
    store
        .put(Kind::Record, checked.record_text.as_bytes())
        .map_err(keep_error)?;
    store
        .put(Kind::Record, answer_text.as_bytes())
        .map_err(keep_error)?;
    Ok(answer_text)
}

/// The answer this provider kept for the proposal `frame` carries, when it
/// kept that proposal, byte for byte, and answered it.
fn first_answer(store: &Store, frame: &[u8], own_key: &str) -> Option<String> {
    let record_text = parse(frame).and_then(|m| text(&m, "proposed").map(String::from))?;
    let record = parse(record_text.as_bytes())?;
    let digest = evidence_request::acceptance::record_digest(&record).ok()?;
    if store.get(Kind::Record, &digest)? != record_text.as_bytes() {
        return None;
    }
    let _serial = PROPOSALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    store.all(Kind::Record).into_iter().find_map(|o| {
        let r = parse(&o)?;
        (text(&r, "proposal_digest") == Some(digest.as_str())
            && text(&r, "acceptor") == Some(own_key))
        .then(|| String::from_utf8(o).ok())
        .flatten()
    })
}

fn keep_error(e: std::io::Error) -> String {
    tracing::warn!(error = %e, "agreement object not kept");
    "the provider could not keep the agreement".into()
}

/// Keep a receipt for an accepted record this provider holds as acceptor,
/// once the profile's verifier finds it the proposer's (§11.1.4, §11.1.7).
fn keep_receipt(store: &Store, receipt: &str, own_key: &str, now: i64) -> Result<(), String> {
    let rc = parse(receipt.as_bytes()).ok_or("the receipt is not JSON")?;
    let digest = text(&rc, "acceptance_digest").ok_or("no acceptance_digest")?;
    let accepted = store
        .get(Kind::Record, digest)
        .ok_or("the provider holds no such accepted record")?;
    let record = parse(&accepted).ok_or("the provider holds no such accepted record")?;
    if text(&record, "state") != Some("accepted") || text(&record, "acceptor") != Some(own_key) {
        return Err("the provider holds no such accepted record".into());
    }
    let proposed = text(&record, "proposal_digest")
        .and_then(|d| store.get(Kind::Record, d))
        .ok_or("the provider holds no proposal for that acceptance")?;
    let _serial = PROPOSALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if receipt_for(store, digest).is_some() {
        return Ok(());
    }
    agreement::check_records(&proposed, &accepted, &[receipt.as_bytes()], now)?;
    store
        .put(Kind::Receipt, receipt.as_bytes())
        .map_err(keep_error)?;
    Ok(())
}

/// The receipt kept for the acceptance `digest`, if any.
fn receipt_for(store: &Store, digest: &str) -> Option<Vec<u8>> {
    store
        .all(Kind::Receipt)
        .into_iter()
        .find(|o| parse(o).is_some_and(|rc| text(&rc, "acceptance_digest") == Some(digest)))
}

fn in_flight() -> &'static tokio::sync::Semaphore {
    static SEMAPHORE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(MAX_IN_FLIGHT))
}

pub async fn handle_open_stream(
    request: OpenStreamRequest,
    capsules: Arc<CapsuleState>,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);
    tokio::spawn(async move {
        if let Err(error) = bridge_inbound(listener, capsules).await {
            tracing::warn!(%error, "agreement responder bridge failed");
        }
    });
    Ok(Some(response))
}

async fn bridge_inbound(
    listener: LocalListener,
    capsules: Arc<CapsuleState>,
) -> anyhow::Result<()> {
    let local = tokio::time::timeout(responder_timeout(), listener.accept()).await??;
    let (mut read_half, mut write_half) = local.into_split();
    let frame = tokio::time::timeout(
        responder_timeout(),
        read_to_end_bounded(&mut read_half, "inbound agreement frame"),
    )
    .await??;
    let reply = match in_flight().try_acquire() {
        Err(_) => json!({ "error": "the provider is busy; try again later" }),
        Ok(_permit) => {
            tokio::task::spawn_blocking(move || {
                let store = Store::open(capsules.ledger_dir());
                let registry = crate::peer_keys::registry();
                let known = |key: &str| {
                    crate::peer_keys::peer_id_for_key_in(registry.as_deref(), key).is_some()
                };
                respond(&capsules, &store, &frame, &known, now())
            })
            .await?
        }
    };
    let bytes = serde_json::to_vec(&reply)?;
    tokio::time::timeout(responder_timeout(), async {
        write_half.write_all(&bytes).await?;
        write_half.shutdown().await
    })
    .await??;
    Ok(())
}

// ---------------------------------------------------------------------
// Requester role
// ---------------------------------------------------------------------

/// An accepted session the requester holds with a provider.
#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    pub acceptance_digest: String,
    pub record: Value,
}

/// The unexpired session between `proposer` and `acceptor` that holds `now`,
/// names `model` in its model policy, and has its receipt and documents
/// kept; the latest-starting one if several do. A session whose set-up did
/// not finish (a receipt or document not kept) is never active.
pub fn active_session(
    store: &Store,
    proposer: &str,
    acceptor: &str,
    model: &str,
    now: i64,
) -> Option<Session> {
    sessions(store, proposer, acceptor, Some(model), now)
        .into_iter()
        .next()
}

/// Every unexpired session between `proposer` and `acceptor` that holds
/// `now`, has its receipt and documents kept and, with `model`, names it in
/// its policy; the latest-starting first.
fn sessions(
    store: &Store,
    proposer: &str,
    acceptor: &str,
    model: Option<&str>,
    now: i64,
) -> Vec<Session> {
    let mut found: Vec<&Complete> = Vec::new();
    let complete = complete_sessions(store);
    for c in complete.iter() {
        if text(&c.record, "proposer") == Some(proposer)
            && text(&c.record, "acceptor") == Some(acceptor)
            && c.start - agreement::CLOCK_SKEW_SECONDS <= now
            && now <= c.end
            && model.is_none_or(|m| c.models.iter().any(|x| x == m))
        {
            found.push(c);
        }
    }
    found.sort_by_key(|c| std::cmp::Reverse(c.start));
    found
        .into_iter()
        .map(|c| Session {
            acceptance_digest: c.digest.clone(),
            record: c.record.clone(),
        })
        .collect()
}

/// An accepted session whose set-up finished: its receipt, terms and model
/// policy are kept.
struct Complete {
    record: Value,
    digest: String,
    start: i64,
    end: i64,
    models: Vec<String>,
}

/// Every complete session `store` keeps, read from disk once per change: a
/// half or leg seal asks on every exchange, and the store only grows.
fn complete_sessions(store: &Store) -> Arc<Vec<Complete>> {
    type Cache = std::collections::HashMap<std::path::PathBuf, (u64, Arc<Vec<Complete>>)>;
    static CACHE: std::sync::OnceLock<Mutex<Cache>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Cache::new()));
    let generation = agreement::generation(store.root());
    if let Some((seen, sessions)) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(store.root())
    {
        if *seen == generation {
            return sessions.clone();
        }
    }
    let receipted: std::collections::BTreeSet<String> = store
        .all(Kind::Receipt)
        .into_iter()
        .filter_map(|o| parse(&o))
        .filter_map(|rc| text(&rc, "acceptance_digest").map(String::from))
        .collect();
    let document = |r: &Value, k: &str| {
        r.get("session")?
            .get(k)?
            .as_str()
            .and_then(|d| store.get(Kind::Document, d))
            .and_then(|o| parse(&o))
    };
    let sessions: Vec<Complete> = store
        .all(Kind::Record)
        .into_iter()
        .filter_map(|o| parse(&o))
        .filter(|r| text(r, "state") == Some("accepted"))
        .filter_map(|record| {
            let digest = evidence_request::acceptance::record_digest(&record).ok()?;
            if !receipted.contains(&digest) {
                return None;
            }
            document(&record, "terms")?;
            let models = agreement::read_policy(&document(&record, "policy")?)?;
            Some(Complete {
                start: window_start(&record)?,
                end: window_end(&record)?,
                digest,
                models,
                record,
            })
        })
        .collect();
    let sessions = Arc::new(sessions);
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(store.root().to_path_buf(), (generation, sessions.clone()));
    sessions
}

/// The acceptance the payer's `delivered` leg cites (R12): its session with
/// the provider at `peer`, for `model`, holding `now`.
pub fn delivered_citation(
    capsules: &CapsuleState,
    peer: &str,
    model: &str,
    now: i64,
) -> Option<String> {
    let registry = crate::peer_keys::registry();
    let provider = crate::peer_keys::announced_key_in(registry.as_deref(), peer)?;
    let store = Store::open(capsules.ledger_dir());
    active_session(&store, &own_key(capsules), &provider, model, now).map(|s| s.acceptance_digest)
}

/// The acceptance a provider's exchange cites (R5, R6, R12): its session
/// with the requester at `requester_peer` (the host's `requested_by_node_id`)
/// for the first of `models` it holds exactly one such session for, holding
/// `now`. `models` are the names the served exchange may be known by, in the
/// order they are tried (main.rs `served_models`). The provider decides this
/// once, at the exchange's terminal event; its served half and its payee leg
/// both use the decision, so a session that appears later never reaches them.
pub fn served_citation(
    capsules: &CapsuleState,
    requester_peer: &str,
    models: &[String],
    now: i64,
) -> Option<String> {
    let registry = crate::peer_keys::registry();
    served_citation_for_in(capsules, requester_peer, models, registry.as_deref(), now)
}

fn served_citation_for_in(
    capsules: &CapsuleState,
    requester_peer: &str,
    models: &[String],
    registry: Option<&str>,
    now: i64,
) -> Option<String> {
    models
        .iter()
        .find_map(|model| served_citation_in(capsules, requester_peer, model, registry, now))
}

fn served_citation_in(
    capsules: &CapsuleState,
    requester_peer: &str,
    model: &str,
    registry: Option<&str>,
    now: i64,
) -> Option<String> {
    let requester_peer = requester_peer.trim();
    if requester_peer.is_empty() || requester_peer == "unknown" {
        return None;
    }
    let requester = crate::peer_keys::announced_key_in(registry, requester_peer)?;
    let store = Store::open(capsules.ledger_dir());
    // One session for the model, or none cited: with several, the provider
    // does not guess which one the requester meant (R12).
    match sessions(&store, &requester, &own_key(capsules), Some(model), now).as_slice() {
        [only] => Some(only.acceptance_digest.clone()),
        _ => None,
    }
}

/// A complete session this node keeps, with what reading its coverage needs:
/// the parties, the window, the terms and models, and the octets of its
/// proposal, its accepted record and its receipt as kept.
pub(crate) struct SessionView {
    pub acceptance_digest: String,
    pub proposer: String,
    pub acceptor: String,
    pub start: i64,
    pub end: i64,
    pub models: Vec<String>,
    pub terms: agreement::Terms,
    pub proposed: Vec<u8>,
    pub accepted: Vec<u8>,
    pub receipt: Vec<u8>,
}

/// Every complete session kept under `ledger_dir`, the latest-starting first.
pub(crate) fn session_views(ledger_dir: &std::path::Path) -> Vec<SessionView> {
    let store = Store::open(ledger_dir);
    let mut views: Vec<SessionView> = complete_sessions(&store)
        .iter()
        .filter_map(|c| {
            let accepted = store.get(Kind::Record, &c.digest)?;
            let proposed =
                text(&c.record, "proposal_digest").and_then(|d| store.get(Kind::Record, d))?;
            let receipt = receipt_for(&store, &c.digest)?;
            let terms = c
                .record
                .get("session")
                .and_then(|s| s.get("terms"))
                .and_then(Value::as_str)
                .and_then(|d| store.get(Kind::Document, d))
                .and_then(|o| parse(&o))
                .and_then(|t| agreement::read_terms(&t))?;
            Some(SessionView {
                acceptance_digest: c.digest.clone(),
                proposer: text(&c.record, "proposer")?.to_string(),
                acceptor: text(&c.record, "acceptor")?.to_string(),
                start: c.start,
                end: c.end,
                models: c.models.clone(),
                terms,
                proposed,
                accepted,
                receipt,
            })
        })
        .collect();
    views.sort_by_key(|v| std::cmp::Reverse(v.start));
    views
}

/// The proposer of the complete session `acceptance_digest`, if this node
/// keeps it.
pub fn session_proposer(capsules: &CapsuleState, acceptance_digest: &str) -> Option<String> {
    let store = Store::open(capsules.ledger_dir());
    complete_sessions(&store)
        .iter()
        .find(|c| c.digest == acceptance_digest)
        .and_then(|c| text(&c.record, "proposer").map(String::from))
}

/// What the requester concluded from the provider's reply to a proposal.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Accepted: everything is kept and the receipt is to be sent.
    Accepted { session: Session, receipt: String },
    /// Declined, countered, refused, or a provider without the channel.
    NoAgreement(String),
}

/// The requester's step after the provider's reply: check the answer, sign
/// the receipt (§11.1.4), and keep the documents, the receipt, the proposal
/// and last the answer, so an answer on disk always has the rest beside it.
pub fn conclude(
    capsules: &CapsuleState,
    store: &Store,
    proposal: &Proposal,
    reply: &[u8],
    now: i64,
) -> Outcome {
    let Some(answer_text) = parse(reply).and_then(|r| text(&r, "answer").map(String::from)) else {
        return Outcome::NoAgreement("the provider gave no answer".into());
    };
    let (answer_text, digest) = match agreement::check_answer(proposal, &answer_text, now) {
        Ok(Answer::Accepted { text, digest }) => (text, digest),
        Ok(Answer::NotAccepted) => {
            return Outcome::NoAgreement("the provider did not accept".into())
        }
        Err(why) => return Outcome::NoAgreement(why.to_string()),
    };
    let receipt = agreement::receipt(&digest, capsules.signing_key(), now).to_string();
    let kept = (|| {
        for doc in &proposal.documents {
            store.put(Kind::Document, doc.as_bytes())?;
        }
        store.put(Kind::Receipt, receipt.as_bytes())?;
        store.put(Kind::Record, proposal.record_text.as_bytes())?;
        store.put(Kind::Record, answer_text.as_bytes())
    })();
    if let Err(e) = kept {
        return Outcome::NoAgreement(format!("the agreement could not be kept: {e}"));
    }
    Outcome::Accepted {
        session: Session {
            acceptance_digest: digest,
            record: parse(answer_text.as_bytes()).unwrap_or_default(),
        },
        receipt,
    }
}

/// Per provider: a set-up in flight (`None`), or when the last one that did
/// not end in an agreement finished.
static ATTEMPTS: Mutex<BTreeMap<String, Option<Instant>>> = Mutex::new(BTreeMap::new());

/// Whether a set-up with `peer_id` may start at `now`; if so, it is marked
/// in flight. A set-up in flight, or one that failed less than
/// [`RETRY_AFTER`] ago, holds the next back.
fn begin_attempt(
    attempts: &mut BTreeMap<String, Option<Instant>>,
    peer_id: &str,
    now: Instant,
) -> bool {
    match attempts.get(peer_id) {
        Some(None) => false,
        Some(Some(failed)) if now.duration_since(*failed) < RETRY_AFTER => false,
        _ => {
            attempts.insert(peer_id.to_string(), None);
            true
        }
    }
}

/// Ends the in-flight mark when the set-up ends, however it ends.
struct Attempt {
    peer_id: String,
    agreed: bool,
}

impl Drop for Attempt {
    fn drop(&mut self) {
        let mut attempts = ATTEMPTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.agreed {
            attempts.remove(&self.peer_id);
        } else {
            attempts.insert(self.peer_id.clone(), Some(Instant::now()));
        }
    }
}

/// Set up a session with the provider at `peer_id`, in its own task, if the
/// operator set session terms, a peer announced the provider's key, and no
/// unexpired session with it names `model`. Best effort: a failure is
/// logged, never raised; the exchange it was triggered by is unaffected.
pub fn ensure_session(
    context: PluginContext<'static>,
    capsules: Arc<CapsuleState>,
    peer_id: String,
    model: String,
) {
    if let Some(terms) = SessionTerms::from_settings() {
        spawn_set_up(context, capsules, peer_id, model, terms);
    }
}

/// [`ensure_session`] from the admission hook, at `backend_selected`, for
/// the model the host's status says `peer_id` serves. The set-up starts
/// before the request goes out; the request is held until it ends or
/// [`hook_wait`] has passed since `entered` (when the hook was called),
/// whichever is first. With no hold set, or a set-up still running when it
/// ends, the request goes on and the set-up finishes in the background.
pub async fn hold_for_session(
    context: PluginContext<'static>,
    capsules: Arc<CapsuleState>,
    peer_id: String,
    entered: Instant,
) {
    let set_up = tokio::spawn(async move {
        let terms = tokio::task::spawn_blocking(SessionTerms::from_settings).await;
        let Ok(Some(terms)) = terms else {
            return;
        };
        let Some(model) = crate::host_status::peer_model_now(&peer_id).await else {
            return;
        };
        if let Some(set_up) = spawn_set_up(context, capsules, peer_id, model, terms) {
            let _ = set_up.await;
        }
    });
    let budget = hook_wait().saturating_sub(entered.elapsed());
    if !budget.is_zero() && !wait_at_most(budget, set_up).await {
        tracing::info!("agreement set-up outlasted the admission hold; the request goes on");
    }
}

/// Whether `task` ended within `budget`. A task still running is left to
/// run.
async fn wait_at_most(budget: Duration, task: tokio::task::JoinHandle<()>) -> bool {
    tokio::time::timeout(budget, task).await.is_ok()
}

/// Whether this node keeps an unexpired complete session with the node
/// `peer_id`, in either role: what makes reading a model for its exchange
/// worth it.
pub fn holds_session_with(capsules: &CapsuleState, peer_id: &str) -> bool {
    let registry = crate::peer_keys::registry();
    let Some(key) = crate::peer_keys::announced_key_in(registry.as_deref(), peer_id) else {
        return false;
    };
    complete_sessions(&Store::open(capsules.ledger_dir()))
        .iter()
        .filter(|c| c.end >= now())
        .any(|c| {
            text(&c.record, "proposer") == Some(key.as_str())
                || text(&c.record, "acceptor") == Some(key.as_str())
        })
}

fn spawn_set_up(
    context: PluginContext<'static>,
    capsules: Arc<CapsuleState>,
    peer_id: String,
    model: String,
    terms: SessionTerms,
) -> Option<tokio::task::JoinHandle<()>> {
    Some(tokio::spawn(async move {
        let mut context = context;
        let peer = peer_id.clone();
        let result = set_up(&mut context, capsules, peer_id, model, terms).await;
        match result {
            Ok(Some(Outcome::Accepted { session, .. })) => {
                tracing::info!(peer_id = %peer, acceptance = %session.acceptance_digest, "service evidence agreement accepted")
            }
            Ok(Some(Outcome::NoAgreement(why))) => {
                tracing::info!(peer_id = %peer, %why, "no service evidence agreement")
            }
            Ok(None) => {}
            Err(error) => tracing::info!(peer_id = %peer, %error, "no service evidence agreement"),
        }
    }))
}

async fn set_up(
    context: &mut PluginContext<'static>,
    capsules: Arc<CapsuleState>,
    peer_id: String,
    model: String,
    terms: SessionTerms,
) -> anyhow::Result<Option<Outcome>> {
    let registry = crate::peer_keys::registry();
    let Some(provider_key) = crate::peer_keys::announced_key_in(registry.as_deref(), &peer_id)
    else {
        tracing::debug!(%peer_id, "no announced key for the provider; no agreement proposed");
        return Ok(None);
    };
    // The in-flight mark first, then the session check, so two exchange
    // events never both find no session and both propose; and the cheap
    // in-memory check before the scan of what is kept.
    let started = {
        let mut attempts = ATTEMPTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        begin_attempt(&mut attempts, &peer_id, Instant::now())
    };
    if !started {
        return Ok(None);
    }
    let mut attempt = Attempt {
        peer_id: peer_id.clone(),
        agreed: false,
    };
    let held = {
        let (capsules, provider_key, model) =
            (capsules.clone(), provider_key.clone(), model.clone());
        tokio::task::spawn_blocking(move || {
            let store = Store::open(capsules.ledger_dir());
            active_session(&store, &own_key(&capsules), &provider_key, &model, now()).is_some()
        })
        .await?
    };
    if held {
        // Not a failure: no cool-down.
        attempt.agreed = true;
        return Ok(None);
    }
    let proposal = Proposal::new(
        capsules.signing_key(),
        &provider_key,
        &agreement::new_session_id(),
        &terms,
        &[model],
        now(),
    );
    let reply = exchange_frame(context, &peer_id, &proposal.to_message()).await?;
    let outcome = {
        let capsules = capsules.clone();
        tokio::task::spawn_blocking(move || {
            let store = Store::open(capsules.ledger_dir());
            conclude(&capsules, &store, &proposal, &reply, now())
        })
        .await?
    };
    if let Outcome::Accepted { receipt, .. } = &outcome {
        attempt.agreed = true;
        // The provider keeps the receipt to serve with its History (R10). A
        // receipt it did not take is still the requester's ordering
        // evidence, kept above.
        let frame = serde_json::to_vec(&json!({ "receipt": receipt }))?;
        if let Err(error) = exchange_frame(context, &peer_id, &frame).await {
            tracing::info!(%peer_id, %error, "agreement receipt not delivered to the provider");
        }
    }
    Ok(Some(outcome))
}

async fn exchange_frame(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    frame: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let deadline = requester_timeout();
    let open = OpenMeshStreamRequest {
        stream_id: next_stream_id("agreement"),
        target_peer_id: peer_id.to_string(),
        plugin_id: String::new(), // the host fills this in.
        channel: agreement::CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some("application/json".to_string()),
        correlation_id: Some(next_stream_id("agreement-correlation")),
        metadata_json: Some(agreement::CHANNEL.to_string()),
        expected_bytes: None,
        idle_timeout_ms: Some(deadline.as_millis() as u64),
    };
    // One deadline covers the connect, the write and the reply.
    tokio::time::timeout(deadline, async {
        let stream = context
            .connect_mesh_stream(open)
            .await
            .map_err(|e| anyhow::anyhow!("could not reach the provider: {e}"))?;
        let (read_half, mut write_half) = stream.into_split();
        write_half.write_all(frame).await?;
        write_half.shutdown().await?;
        Ok::<_, anyhow::Error>(read_to_end_bounded(read_half, "agreement reply").await?)
    })
    .await
    .map_err(|_| anyhow::anyhow!("no reply within the bounded wait"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agreement::SessionTerms;

    const NOW: i64 = 1_793_000_000;
    const MODEL: &str = "hf:example/model@main";

    /// The admission hold ends at its budget and leaves the set-up running;
    /// a set-up that ends sooner ends the hold at once.
    #[tokio::test]
    async fn the_admission_hold_ends_at_its_budget_and_the_set_up_goes_on() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let slow = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = tx.send(());
        });
        let started = Instant::now();
        assert!(!wait_at_most(Duration::from_millis(50), slow).await);
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "the hold ended at its budget"
        );
        rx.await.expect("the set-up went on after the hold ended");
        let quick = tokio::spawn(async {});
        assert!(wait_at_most(Duration::from_secs(5), quick).await);
    }

    /// The hold is off unless the operator sets it.
    #[test]
    fn the_admission_hold_is_off_by_default() {
        assert_eq!(hook_wait(), Duration::ZERO);
    }

    /// A node keeps a session with a peer, in either role, only once one is
    /// complete, and only with that peer's announced key.
    #[test]
    fn a_session_is_held_with_a_peer_once_it_is_complete() {
        let p = pair();
        let (requester_node, provider_node) = ("7a".repeat(32), "7b".repeat(32));
        crate::peer_keys::announced::announce_for_test(&requester_node, &own_key(&p.requester));
        crate::peer_keys::announced::announce_for_test(&provider_node, &own_key(&p.provider));
        assert!(!holds_session_with(&p.requester, &provider_node));
        p.agree(now());
        assert!(holds_session_with(&p.requester, &provider_node));
        assert!(holds_session_with(&p.provider, &requester_node));
        assert!(
            !holds_session_with(&p.requester, &"7c".repeat(32)),
            "an unannounced peer"
        );

        // One that has expired is not held.
        let q = pair();
        crate::peer_keys::announced::announce_for_test(&"7d".repeat(32), &own_key(&q.provider));
        q.agree(now() - 2 * 3_600);
        assert!(!holds_session_with(&q.requester, &"7d".repeat(32)));
    }

    fn node(dir: &std::path::Path, name: &str) -> CapsuleState {
        CapsuleState::open(dir, name).unwrap()
    }

    fn terms() -> SessionTerms {
        SessionTerms {
            spend_cap_msat: 3_000,
            max_exchanges: Some(2),
            window_seconds: 3_600,
        }
    }

    struct Pair {
        _dirs: (tempfile::TempDir, tempfile::TempDir),
        requester: CapsuleState,
        provider: CapsuleState,
        rstore: Store,
        pstore: Store,
    }

    fn pair() -> Pair {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (requester, provider) = (node(a.path(), "requester"), node(b.path(), "provider"));
        let (rstore, pstore) = (
            Store::open(requester.ledger_dir()),
            Store::open(provider.ledger_dir()),
        );
        Pair {
            _dirs: (a, b),
            requester,
            provider,
            rstore,
            pstore,
        }
    }

    impl Pair {
        fn proposal(&self, now: i64) -> Proposal {
            self.proposal_for(MODEL, now)
        }
        fn proposal_for(&self, model: &str, now: i64) -> Proposal {
            Proposal::new(
                self.requester.signing_key(),
                &own_key(&self.provider),
                &agreement::new_session_id(),
                &terms(),
                &[model.into()],
                now,
            )
        }
        fn propose(&self, proposal: &Proposal, now: i64) -> Value {
            respond(
                &self.provider,
                &self.pstore,
                &proposal.to_message(),
                &|_| true,
                now,
            )
        }
        fn conclude(&self, proposal: &Proposal, reply: &Value, now: i64) -> Outcome {
            conclude(
                &self.requester,
                &self.rstore,
                proposal,
                &serde_json::to_vec(reply).unwrap(),
                now,
            )
        }
        fn send_receipt(&self, receipt: &str, now: i64) -> Value {
            respond(
                &self.provider,
                &self.pstore,
                &serde_json::to_vec(&json!({"receipt": receipt})).unwrap(),
                &|_| true,
                now,
            )
        }
        fn session(&self, store: &Store, model: &str, now: i64) -> Option<Session> {
            active_session(
                store,
                &own_key(&self.requester),
                &own_key(&self.provider),
                model,
                now,
            )
        }
        fn agree(&self, now: i64) -> (Proposal, Session, String) {
            self.agree_for(MODEL, now)
        }
        fn agree_for(&self, model: &str, now: i64) -> (Proposal, Session, String) {
            let proposal = self.proposal_for(model, now);
            let reply = self.propose(&proposal, now);
            let Outcome::Accepted { session, receipt } = self.conclude(&proposal, &reply, now)
            else {
                panic!("accepted: {reply}")
            };
            assert_eq!(self.send_receipt(&receipt, now), json!({"ok": true}));
            (proposal, session, receipt)
        }
    }

    /// Requester and provider in process: proposal, answer, receipt, and the
    /// session each side then holds, with the same octets on both sides.
    #[test]
    fn a_proposal_becomes_a_session_both_sides_hold() {
        let p = pair();
        let (proposal, session, _) = p.agree(NOW);
        for (store, label) in [(&p.rstore, "requester"), (&p.pstore, "provider")] {
            let held = p
                .session(store, MODEL, NOW + 10)
                .unwrap_or_else(|| panic!("{label} holds the session"));
            assert_eq!(held, session, "{label}");
            assert_eq!(
                store.all(Kind::Receipt).len(),
                1,
                "{label} keeps the receipt"
            );
            assert_eq!(
                store.all(Kind::Document).len(),
                3,
                "{label} keeps the documents"
            );
            let terms_doc = store
                .get(
                    Kind::Document,
                    held.record["session"]["terms"].as_str().unwrap(),
                )
                .unwrap();
            assert_eq!(
                agreement::read_terms(&serde_json::from_slice(&terms_doc).unwrap()),
                Some(agreement::Terms {
                    spend_cap_msat: 3_000,
                    max_exchanges: Some(2)
                }),
                "{label}"
            );
        }
        // The same octets on both sides: the proposal, the answer, the
        // receipt and every document.
        for kind in [Kind::Record, Kind::Receipt, Kind::Document] {
            assert_eq!(p.rstore.all(kind), p.pstore.all(kind), "{kind:?}");
        }
        assert_eq!(
            p.rstore.get(Kind::Record, &proposal.digest()).unwrap(),
            proposal.record_text.as_bytes()
        );
        // Not for another model, and not outside its window.
        assert_eq!(p.session(&p.rstore, "hf:other/model@main", NOW + 10), None);
        assert_eq!(p.session(&p.rstore, MODEL, NOW + 3_601), None);
    }

    #[test]
    fn a_proposal_sent_again_gets_its_first_answer() {
        let p = pair();
        let proposal = p.proposal(NOW);
        let first = p.propose(&proposal, NOW);
        let again = p.propose(&proposal, NOW + 5);
        assert_eq!(first, again, "one proposal, one answer (§11.1.1)");
        let much_later = p.propose(&proposal, NOW + agreement::CLOCK_SKEW_SECONDS + 1);
        assert_eq!(
            first, much_later,
            "even once a new window from it would be refused"
        );
        let answers = p
            .pstore
            .all(Kind::Record)
            .into_iter()
            .filter(|o| parse(o).is_some_and(|r| text(&r, "state") == Some("accepted")))
            .count();
        assert_eq!(answers, 1);
    }

    #[test]
    fn a_provider_answers_only_an_announced_requester() {
        let p = pair();
        let proposal = p.proposal(NOW);
        let reply = respond(
            &p.provider,
            &p.pstore,
            &proposal.to_message(),
            &|_| false,
            NOW,
        );
        assert!(reply.get("error").is_some(), "{reply}");
        assert!(p.pstore.all(Kind::Record).is_empty(), "nothing kept");
    }

    #[test]
    fn a_provider_holds_a_bounded_number_of_open_sessions_per_requester() {
        let p = pair();
        for i in 0..MAX_OPEN_SESSIONS_PER_REQUESTER {
            let reply = p.propose(&p.proposal(NOW + i as i64), NOW + i as i64);
            assert!(reply.get("answer").is_some(), "{reply}");
        }
        let reply = p.propose(&p.proposal(NOW + 20), NOW + 20);
        assert!(reply.get("error").is_some(), "{reply}");
        // Once the first sessions end, the requester may open more.
        let later = NOW + 3_600 + agreement::CLOCK_SKEW_SECONDS + 10;
        let reply = p.propose(&p.proposal(later), later);
        assert!(reply.get("answer").is_some(), "{reply}");
    }

    #[test]
    fn a_provider_accepts_a_bounded_number_of_sessions_per_requester_per_day() {
        let p = pair();
        let short = SessionTerms {
            window_seconds: 60,
            ..terms()
        };
        let propose_at = |t: i64| {
            let proposal = Proposal::new(
                p.requester.signing_key(),
                &own_key(&p.provider),
                &agreement::new_session_id(),
                &short,
                &[MODEL.into()],
                t,
            );
            p.propose(&proposal, t)
        };
        // One-minute sessions, one after another: never more than one open.
        let step = 60 + agreement::CLOCK_SKEW_SECONDS + 1;
        for i in 0..MAX_SESSIONS_PER_REQUESTER_PER_DAY as i64 {
            assert!(
                propose_at(NOW + i * step).get("answer").is_some(),
                "session {i}"
            );
        }
        let t = NOW + MAX_SESSIONS_PER_REQUESTER_PER_DAY as i64 * step;
        assert!(propose_at(t).get("error").is_some(), "the day's limit");
        assert!(
            propose_at(NOW + 86_400 + 10).get("answer").is_some(),
            "a day later"
        );
    }

    #[test]
    fn a_receipt_that_cannot_order_never_takes_the_first_place() {
        let p = pair();
        let proposal = p.proposal(NOW);
        let reply = p.propose(&proposal, NOW);
        let Outcome::Accepted { receipt, .. } = p.conclude(&proposal, &reply, NOW) else {
            panic!("accepted")
        };
        let mut no_time: Value = serde_json::from_str(&receipt).unwrap();
        no_time["received_at"] = Value::Null;
        no_time.as_object_mut().unwrap().remove("sig");
        let no_time = Value::Object(
            evidence_request::acceptance::sign(
                no_time.as_object().unwrap().clone(),
                p.requester.signing_key(),
            )
            .unwrap(),
        )
        .to_string();
        assert!(p.send_receipt(&no_time, NOW).get("error").is_some());
        assert_eq!(p.send_receipt(&receipt, NOW), json!({"ok": true}));
        assert!(p.session(&p.pstore, MODEL, NOW).is_some());
    }

    #[test]
    fn a_provider_keeps_one_receipt_and_only_the_proposers() {
        let p = pair();
        let proposal = p.proposal(NOW);
        let reply = p.propose(&proposal, NOW);
        let Outcome::Accepted { session, receipt } = p.conclude(&proposal, &reply, NOW) else {
            panic!("accepted")
        };
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let forged = agreement::receipt(&session.acceptance_digest, &stranger, NOW).to_string();
        assert!(p.send_receipt(&forged, NOW).get("error").is_some());
        let unknown =
            agreement::receipt(&"a".repeat(64), p.requester.signing_key(), NOW).to_string();
        assert!(p.send_receipt(&unknown, NOW).get("error").is_some());
        assert!(p.pstore.all(Kind::Receipt).is_empty());
        assert_eq!(p.send_receipt(&receipt, NOW), json!({"ok": true}));
        let later = agreement::receipt(
            &session.acceptance_digest,
            p.requester.signing_key(),
            NOW + 9,
        )
        .to_string();
        assert_eq!(p.send_receipt(&later, NOW + 9), json!({"ok": true}));
        assert_eq!(
            p.pstore.all(Kind::Receipt),
            vec![receipt.into_bytes()],
            "the first receipt stays"
        );
    }

    #[test]
    fn a_reply_without_an_answer_is_no_agreement_at_once() {
        let p = pair();
        let proposal = p.proposal(NOW);
        // What an evidence responder that predates agreements answers.
        for reply in [
            &br#"{"error":"malformed request"}"#[..],
            b"not json",
            br#"{"refusal":{}}"#,
        ] {
            assert!(
                matches!(
                    conclude(&p.requester, &p.rstore, &proposal, reply, NOW),
                    Outcome::NoAgreement(_)
                ),
                "{}",
                String::from_utf8_lossy(reply)
            );
        }
        assert!(
            p.rstore.all(Kind::Record).is_empty(),
            "nothing kept without an agreement"
        );
    }

    #[test]
    fn a_session_whose_set_up_did_not_finish_is_not_active() {
        let p = pair();
        let (_, session, _) = p.agree(NOW);
        // The requester lost its receipt: its session is not active, so it
        // proposes again rather than relying on a session it cannot order.
        let receipts = p.rstore.root_for_tests().join("receipts");
        std::fs::remove_dir_all(&receipts).unwrap();
        agreement::bump_generation_for_tests(&p.rstore);
        assert_eq!(p.session(&p.rstore, MODEL, NOW + 10), None);
        assert!(p.session(&p.pstore, MODEL, NOW + 10).is_some());
        let _ = session;
    }

    #[test]
    fn the_latest_starting_session_is_the_active_one() {
        let p = pair();
        let (_, _, _) = p.agree(NOW);
        let (_, second, _) = p.agree(NOW + 100);
        assert_eq!(p.session(&p.rstore, MODEL, NOW + 200), Some(second));
    }

    #[test]
    fn a_failed_set_up_holds_the_next_back_for_a_while() {
        let mut attempts = BTreeMap::new();
        let t0 = Instant::now();
        assert!(begin_attempt(&mut attempts, "peer", t0));
        assert!(!begin_attempt(&mut attempts, "peer", t0), "one in flight");
        assert!(begin_attempt(&mut attempts, "other", t0), "per peer");
        attempts.insert("peer".into(), Some(t0));
        assert!(!begin_attempt(
            &mut attempts,
            "peer",
            t0 + Duration::from_secs(1)
        ));
        assert!(begin_attempt(&mut attempts, "peer", t0 + RETRY_AFTER));
    }

    #[test]
    fn each_side_finds_the_session_its_counterparty_and_model_name() {
        let p = pair();
        let (_, session, _) = p.agree(NOW);
        let requester_peer = "aa".repeat(32);
        let registry = json!({ requester_peer.clone(): own_key(&p.requester) }).to_string();
        let served = |peer: &str, model: &str, now| {
            served_citation_in(&p.provider, peer, model, Some(&registry), now)
        };
        let want = Some(session.acceptance_digest.clone());
        assert_eq!(served(&requester_peer, MODEL, NOW + 10), want);
        // Another model, outside the window, an unknown or unannounced
        // requester: no citation.
        assert_eq!(
            served(&requester_peer, "hf:other/model@main", NOW + 10),
            None
        );
        assert_eq!(served(&requester_peer, MODEL, NOW + 3_601), None);
        assert_eq!(served("unknown", MODEL, NOW + 10), None);
        assert_eq!(served(&"cc".repeat(32), MODEL, NOW + 10), None);
        assert_eq!(
            session_proposer(&p.provider, &session.acceptance_digest),
            Some(own_key(&p.requester))
        );
        assert_eq!(session_proposer(&p.provider, &"0".repeat(64)), None);
    }

    /// A provider serving two local GGUFs, with a session for each, cites
    /// the one for the weights its served exchange states, though the event
    /// names no model and the status names no single one (evidencebook#48).
    /// The names are tried in order: the digest's first, then the status's
    /// when the digest's gives no session or several.
    #[test]
    fn a_provider_cites_by_the_weights_digest_then_by_the_status() {
        let p = pair();
        let model = |d: &str| crate::host_status::local_gguf_ref(&d.repeat(32)).unwrap();
        let (_, for_a, _) = p.agree_for(&model("aa"), NOW);
        let (_, for_b, _) = p.agree_for(&model("bb"), NOW);
        let (_, for_hf, _) = p.agree_for("hf:org/model@main", NOW);
        p.agree_for(&model("ee"), NOW);
        p.agree_for(&model("ee"), NOW);
        let requester_peer = "cc".repeat(32);
        let registry = json!({ requester_peer.clone(): own_key(&p.requester) }).to_string();
        let cites = |models: &[String]| {
            served_citation_for_in(
                &p.provider,
                &requester_peer,
                models,
                Some(&registry),
                NOW + 10,
            )
        };
        let status = "hf:org/model@main".to_string();
        assert_eq!(cites(&[model("bb")]), Some(for_b.acceptance_digest.clone()));
        assert_eq!(cites(&[model("aa")]), Some(for_a.acceptance_digest));
        assert_eq!(
            cites(&[model("bb"), status.clone()]),
            Some(for_b.acceptance_digest),
            "the digest's first"
        );
        assert_eq!(
            cites(&[model("dd"), status.clone()]),
            Some(for_hf.acceptance_digest.clone()),
            "no session for the digest: the status's"
        );
        assert_eq!(
            cites(&[model("ee"), status]),
            Some(for_hf.acceptance_digest),
            "two for the digest: the status's"
        );
        assert_eq!(cites(&[model("dd")]), None, "weights no session names");
        assert_eq!(cites(&[]), None);
    }

    #[test]
    fn complete_sessions_are_read_again_only_after_a_change() {
        let p = pair();
        let (_, first, _) = p.agree(NOW);
        let once = complete_sessions(&p.rstore);
        assert!(
            Arc::ptr_eq(&once, &complete_sessions(&p.rstore)),
            "unchanged: cached"
        );
        // Another store's change leaves this store's cache alone (#214: one
        // process-wide counter let parallel tests invalidate each other).
        agreement::bump_generation_for_tests(&p.pstore);
        assert!(
            Arc::ptr_eq(&once, &complete_sessions(&p.rstore)),
            "another store's change: cached"
        );
        let (_, second, _) = p.agree(NOW + 100);
        let again = complete_sessions(&p.rstore);
        assert!(!Arc::ptr_eq(&once, &again));
        let digests: Vec<&str> = again.iter().map(|c| c.digest.as_str()).collect();
        assert!(digests.contains(&first.acceptance_digest.as_str()));
        assert!(digests.contains(&second.acceptance_digest.as_str()));
    }

    #[test]
    fn only_a_tagged_open_is_an_agreement_frame() {
        let mut request = OpenStreamRequest::default();
        assert!(!is_agreement_request(&request));
        request.metadata_json = Some(crate::commitment_bridge::COMMITMENT_CHANNEL.into());
        assert!(!is_agreement_request(&request));
        request.metadata_json = Some(agreement::CHANNEL.into());
        assert!(is_agreement_request(&request));
        assert!(!crate::commitment_bridge::is_commitment_request(&request));
    }
}
