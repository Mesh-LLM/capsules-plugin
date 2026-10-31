//! Answering an evidence request in-process
//! (draft-mih-agent-evidence-request-00), for every subject. A referee's
//! `adjudicate` request is not a -00 subject and is refused, signed: this
//! node has no referee yet.
//!
//! The protocol is the `evidence-request` crate's: this module parses with
//! `request::parse_json`, resolves with `resolve::resolve` and signs
//! refusals with `refusal::sign`. The artifact answer is the interop
//! profile's signed envelope, built and checked in `evidence_artifact`. What
//! stays here is this node's own glue: the limits, the sharing-policy gate
//! and who asks.
//!
//! **Order, cheapest first.** Every step that can refuse runs before the
//! work after it, so a request is turned away before it costs anything. The
//! reasons below are those of an `evidence-interop/1` request; to a /0 one,
//! or before the profile is read, `capacity_exceeded` is sent as
//! `policy_declined` and `request_unauthenticated` as `not_authorized`
//! ([`under_profile`]), the tokens /0 used for the same causes:
//!
//! 1. the request's size ([`MAX_REQUEST_BYTES`]) → `capacity_exceeded`, before
//!    it is parsed (so `policy_declined`, as the profile is not read yet);
//! 2. parsing → `request_malformed` / `coverage_unsatisfiable`, and a
//!    malformed `requester_auth` (or a signed request with no `audience`)
//!    → `request_malformed`;
//! 3. a deadline already past → `deadline_unmet`;
//! 4. a request that carries record bodies, with the sharing policy
//!    switched `off` or over `range` or `full_history` →
//!    `not_authorized`, before anything is looked up;
//! 5. who asks (`requester_auth`), before the ledger is read: a signature
//!    that fails its window, its key, its `audience` (this node), its nonce
//!    or its stated id → `request_unauthenticated` (`capacity_exceeded` while
//!    this node does not know its own id); a valid signature under a key no host
//!    binds → read as unsigned where the answer needs no identity, refused
//!    otherwise; an unsigned request whose answer depends on who asks →
//!    refused (see below);
//! 6. an answer only a counterparty may have, to a node no record of this
//!    one names → refused, before the subject is looked up;
//! 7. resolution against the index → the crate's reason;
//! 8. the number of records (or checkpoints) the answer would carry, counted
//!    from the index without reading one → `capacity_exceeded` over
//!    [`MAX_ANSWER_RECORDS`] / [`MAX_ANSWER_CHECKPOINTS`];
//! 9. the sharing-policy gate on each of those records → `not_authorized`;
//! 10. building and signing; an answer larger than [`MAX_ANSWER_BYTES`] on
//!     the wire, or a fault building it → `capacity_exceeded`.
//!
//! `not_authorized` and `policy_declined` are then statements about policy
//! only (ER -02 §4.2, §11), which a requester may hold against the policy
//! this node's commitment pins (`peer_commitments::policy_check`).
//!
//! Every refusal is signed by this node's key and binds the digest of the
//! request bytes as received (`refusal::sign`). Nothing here unwraps or
//! panics on the request.
//!
//! **The sharing policy** (`share_policy::history_segments`) decides who gets
//! record bodies, by the same rule the plugin's `ledger-fetch/1` channel uses:
//! `off` serves none; a local block or an owner-maintenance record is never
//! served; under `peers` every other record goes to any node a signed
//! request proves; otherwise a record goes only to the node it names as the
//! other side of its exchange. A request with no proven node gets no record
//! under any setting. `range` and `full_history` reach records no one
//! requester is party to, and are refused `not_authorized` under every
//! setting, since only a derivation prepared for one recipient could grant
//! them and this node has none (the evidencebook#114 ruling, as the Go
//! responder applies it). An answer is served whole or refused whole (`not_authorized`): an
//! artifact is the same for every requester (§5), so it is never filtered
//! per asker. Checkpoints, the history card and the Service History carry no
//! record bodies and are not gated by it.
//!
//! **Who asks** is the node a signed request proved it came from: the
//! `requester_auth` signature verifies under a key a host announced for that
//! node, and the request names this node as its `audience`
//! (`requester_auth`). A request's `requester_id` is only the asker's word:
//! it picks among nodes that announced the same key, one that names any
//! other node is refused, and an unsigned request has no principal at all. So an answer that depends on who asks (record bodies
//! always, Standard History unless it is shared) is refused to an unsigned
//! request, before the ledger is read. With Standard History shared, an
//! unsigned request for it is answered as before.
//!
//! **Stranger-safe answers** (PRD R-8): `checkpoints` with no derivation and
//! `history_card/1` go to anyone who asks, whatever the settings: an
//! unsigned request, any node's, or one signed under a key no host binds. A
//! signature that fails is still refused. They carry this node's signed
//! checkpoints and their consistency proofs, the same artifact for every
//! requester, and no record. A community reporter and `doctor --probe` read
//! them as a stranger. Under `share_record_at_completion`, with the checkpoint
//! cadence on, each push cuts a checkpoint, so a checkpoint's time can be one
//! exchange's end time.
//!
//! **Standard History** is every other answer that carries no record bodies:
//! `service_history/1` and any other derivation but `exchange_corroboration/1`,
//! which has a setting of its own. It shows what this node serves, so with
//! `share_standard_history` off (the default) it goes only to a requester
//! that has proven it is a node some record of this one names as the other
//! side of an exchange. Every other requester (unsigned, a signature that
//! fails, or a proven node no record names) asking for Standard History gets
//! `policy_declined`, decided before the subject is resolved, so the refusal
//! is the same whether or not what was asked for exists. It is
//! `refusal::sign` of the request digest, the reason and `issued_at` alone:
//! no member names or depends on the asker, so two askers sending the same
//! bytes in the same second get the same bytes back. What differs between
//! two refusals is only what differs between the requests (their digest,
//! which covers every member each carries) and when they were answered
//! (`issued_at`), and the signature over those.
//!
//! **Record requests** (record bodies: `record`, `exchange`, `correlation`
//! with no derivation) get `not_authorized`, never `policy_declined`, when
//! the asker may not have them. Unless records go to any proven node
//! (`peers`), a proven node that no record names gets it before the subject
//! is resolved too, so a stranger cannot read this log's size or cadence
//! from which refusal it gets (it reads them from the checkpoint list). A
//! real counterparty asking for more than its own records still can. A
//! record that never leaves this node (`evidence_log::never_leaves`) is in
//! no `correlation`, `exchange` or `exchange_corroboration/1` answer's
//! matched set (`LedgerIndex::leaving`): the answer, or its refusal, is the
//! same whether or not one sits under the key (evidencebook#206 row 4). A
//! `record` request by such a record's exact digest is still refused
//! `not_authorized`: only an asker that already holds the digest can send
//! it.
//!
//! **The wire.** An artifact answer is the interop profile's flat reply
//! (agent-action-capsule `spec/interop-profile-v0.md` §6.2,
//! `evidence-interop/0`): the signed envelope with its artifact and
//! verification material beside it as unpadded base64url, plus this node's
//! witness receipts (`evidence_artifact::WITNESS_RECEIPTS`). A refusal is
//! the crate's refusal object. The `evidence-request/1` frames that carry
//! them are still JSON, pending the deterministic CBOR frames of the
//! draft's peer binding.

use cll::mmr::leaf_count;
use ed25519_dalek::SigningKey;
use evidence_request::digest::request_digest;
use evidence_request::refusal;
use evidence_request::registry::{Reason, DERIVATION_HISTORY_CARD};
use evidence_request::request::{self, Derivation, Request, Subject};
use evidence_request::resolve::{self, Resolution, ResolvedAnchor};
use evidence_request::time::parse_utc;
use evidencebook::received::{self, Appended, ReceivedLog, MAX_RECEIVED_LOG_BYTES};
use serde_json::{json, Map, Value};
use std::path::Path;

use crate::evidence_artifact::{self, Build, CheckError, ReceiptStatus};
use crate::evidence_log::{self, LedgerIndex, LogView};
use crate::requester_auth::{self, Form, Principal};

/// The largest request answered. A -00 request is a few hundred bytes; this
/// turns a large one away before it is parsed.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// The most records one answer carries. A larger subject is refused
/// `policy_declined`: ask for a range.
pub const MAX_ANSWER_RECORDS: u64 = 256;

/// The most checkpoints one answer carries (`checkpoints`, `history_card/1`).
pub const MAX_ANSWER_CHECKPOINTS: u64 = 1024;

/// The largest answer on the wire. The requester reads at most
/// `mesh_evidence_bridge::MAX_SIDE_STREAM_BYTES`, so a larger answer could
/// never arrive; it is refused here instead.
pub const MAX_ANSWER_BYTES: usize = crate::mesh_evidence_bridge::MAX_SIDE_STREAM_BYTES as usize;

/// What one request is answered against.
pub struct Responder<'a> {
    pub ledger_dir: &'a Path,
    pub signing_key: &'a SigningKey,
    /// Now, RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`): every `issued_at`.
    pub now: &'a str,
    /// `share_history_segments` (`commitment::Policy`).
    pub history_segments: &'a str,
    /// `share_standard_history` (`commitment::Policy`).
    pub share_standard_history: bool,
    /// `share_exchange_corroboration` (`commitment::Policy`).
    pub share_exchange_corroboration: bool,
    /// The keys a requester's signature is bound through
    /// (`requester_auth::bound_node`).
    pub keys: requester_auth::Keys<'a>,
    /// The (key_id, nonce) pairs already answered
    /// (`requester_auth::replay_cache()`).
    pub replay: &'a requester_auth::ReplayCache,
    /// This node's own mesh node id, which a signed request's `audience`
    /// must name. `None` until the host has reported it: then no signed
    /// request is addressed to this node.
    pub node_id: Option<&'a str>,
    /// The digest of the signed disclosure policy these switches are
    /// (`commitment::Policy::digest`), which every refusal names as its
    /// `policy_digest` member. `None` names none.
    pub policy_digest: Option<&'a str>,
}

/// The one outcome of a request.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// An artifact answer, on the wire.
    Answered {
        wire: Value,
        subject_kind: &'static str,
    },
    /// A signed refusal, on the wire.
    Refused {
        wire: Value,
        reason: Reason,
        subject_kind: Option<&'static str>,
    },
    /// No answer can be given (this node cannot sign one: its clock or its
    /// ledger could not be read). Nothing is sent; the requester records an
    /// absence, never a refusal this node did not sign.
    Unanswerable(String),
}

impl Outcome {
    /// The received-log status and reason.
    pub fn log_status(&self) -> (&'static str, Option<&'static str>) {
        match self {
            Outcome::Answered { .. } => ("answered", None),
            Outcome::Refused { reason, .. } => ("refused", Some(reason.token())),
            Outcome::Unanswerable(_) => ("unanswered", None),
        }
    }

    pub fn subject_kind(&self) -> Option<&'static str> {
        match self {
            Outcome::Answered { subject_kind, .. } => Some(subject_kind),
            Outcome::Refused { subject_kind, .. } => *subject_kind,
            Outcome::Unanswerable(_) => None,
        }
    }

    /// The bytes to send, if any.
    pub fn wire_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Outcome::Answered { wire, .. } | Outcome::Refused { wire, .. } => {
                serde_json::to_vec(wire).ok()
            }
            Outcome::Unanswerable(_) => None,
        }
    }
}

/// The requester's self-declared id: the request's optional top-level
/// `requester_id` text member. Read only from a request within
/// [`MAX_REQUEST_BYTES`].
pub fn requester_id(request_bytes: &[u8]) -> Option<String> {
    if request_bytes.len() > MAX_REQUEST_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(request_bytes).ok()?;
    value.get("requester_id")?.as_str().map(str::to_string)
}

/// Who a request proved it came from, as far as it got: the key its
/// signature verified under, and the node that key is bound to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Asker {
    pub key_id: Option<String>,
    pub node_id: Option<String>,
    /// `bound` when the key is bound to `node_id`; `unbound` when the
    /// signature verified under a key no host binds (never a principal).
    pub binding: Option<&'static str>,
    /// The `audience` a signed request named, as checked.
    pub audience: Option<String>,
    /// `checked` when the request's nonce went through the replay check;
    /// `unchecked` when it could not, because the unbound pool was full
    /// (ruling u290 §2).
    pub replay: Option<&'static str>,
}

/// Answer `request_bytes`, exactly as received, without logging it.
pub fn answer(request_bytes: &[u8], responder: &Responder<'_>) -> Outcome {
    answer_as(request_bytes, responder).0
}

/// [`answer`], with who asked.
fn answer_as(request_bytes: &[u8], responder: &Responder<'_>) -> (Outcome, Asker) {
    let mut asker = Asker::default();
    let outcome = answer_inner(request_bytes, responder, &mut asker);
    (outcome, asker)
}

/// The token a refusal for `reason` carries under the profile the request
/// asked for (IP v1 §6.3). The responder decides in `evidence-interop/1`'s
/// terms: `capacity_exceeded` for a limit or fault of its own,
/// `request_unauthenticated` for a requester authentication that does not
/// verify. `evidence-interop/0` pins ER -01, which registers neither, so a
/// /0 request (or one whose profile is not known yet) gets the token /0
/// used for the same cause: `policy_declined` and `not_authorized`.
fn under_profile(reason: Reason, v1: bool) -> Reason {
    match reason {
        Reason::CapacityExceeded if !v1 => Reason::PolicyDeclined,
        Reason::RequestUnauthenticated if !v1 => Reason::NotAuthorized,
        reason => reason,
    }
}

/// Whether the request octets ask for `evidence-interop/1`.
fn asks_v1(request_bytes: &[u8]) -> bool {
    evidence_artifact::profile_of(request_bytes) == evidence_request::envelope::PROFILE_V1
}

fn answer_inner(request_bytes: &[u8], responder: &Responder<'_>, asker: &mut Asker) -> Outcome {
    let digest = request_digest(request_bytes);
    // Set once the request's profile is read; until then a refusal carries
    // the tokens /0 registers, which /1 registers too.
    let v1 = std::cell::Cell::new(false);
    let refuse = |reason: Reason, subject_kind: Option<&'static str>| {
        let reason = under_profile(reason, v1.get());
        match refusal::sign(&digest, reason, responder.now, responder.signing_key) {
            Ok(r) => Outcome::Refused {
                wire: refusal_wire(&r, responder),
                reason,
                subject_kind,
            },
            Err(e) => Outcome::Unanswerable(format!("could not sign a {reason} refusal: {e}")),
        }
    };

    // 1. Size, before parsing.
    if request_bytes.len() > MAX_REQUEST_BYTES {
        return refuse(Reason::CapacityExceeded, None);
    }
    // 2. Parse.
    let req = match request::parse_json(request_bytes) {
        Ok(req) => req,
        Err(e) => return refuse(e.reason(), None),
    };
    let kind = Some(req.subject.form().token());
    let (map, form) = match serde_json::from_slice::<Value>(request_bytes) {
        Ok(Value::Object(map)) => {
            let form = requester_auth::form(&map);
            (map, form)
        }
        _ => return refuse(Reason::RequestMalformed, kind),
    };
    // A profile this node does not implement (profile §3.3 step 4).
    let Some(profile) = evidence_artifact::requested_profile(&map)
        .filter(|p| evidence_request::envelope::PROFILES.contains(p))
    else {
        return refuse(Reason::RequestMalformed, kind);
    };
    v1.set(profile == evidence_request::envelope::PROFILE_V1);
    if form == Form::Malformed {
        return refuse(Reason::RequestMalformed, kind);
    }
    // 3. Deadline.
    let Some(now) = parse_utc(responder.now) else {
        return Outcome::Unanswerable("this node's clock is not an RFC 3339 UTC time".into());
    };
    if req.deadline.is_some_and(|deadline| deadline < now) {
        return refuse(Reason::DeadlineUnmet, kind);
    }
    // 4. No record bodies to anyone: sharing switched off, or a subject
    // that spans parties.
    if carries_records(&req)
        && (responder.history_segments == "off" || spans_parties(&req))
        && policy_gate_applies()
    {
        return refuse(Reason::NotAuthorized, kind);
    }
    // 5. Who asks: the requester's signature, before anything is looked up.
    let principal = match requester(&map, form, &req, now, responder, asker, v1.get()) {
        Ok(principal) => principal,
        Err(reason) => return refuse(reason, kind),
    };
    let principal_nodes = principal.as_ref().map_or(&[][..], |p| &p.node_ids[..]);
    let principal_key = principal.as_ref().map(|p| p.key_id.as_str());

    let key_id = hex::encode(responder.signing_key.verifying_key().to_bytes());
    let built = evidence_log::with_index(responder.ledger_dir, &key_id, |index| {
        let view = index.view()?;
        Ok::<_, std::io::Error>(answer_from(
            &req,
            request_bytes,
            principal_nodes,
            principal_key,
            responder,
            &view,
        ))
    });
    match built {
        Ok(Ok(Ok(wire))) => match serde_json::to_vec(&wire) {
            Ok(bytes) if bytes.len() <= MAX_ANSWER_BYTES => Outcome::Answered {
                wire,
                subject_kind: req.subject.form().token(),
            },
            _ => refuse(Reason::CapacityExceeded, kind),
        },
        Ok(Ok(Err(reason))) => refuse(reason, kind),
        Ok(Err(e)) | Err(e) => Outcome::Unanswerable(format!("the ledger could not be read: {e}")),
    }
}

/// Whether the answer to `req` carries record bodies.
fn carries_records(req: &Request) -> bool {
    req.derivation.is_none() && !matches!(req.subject, Subject::Checkpoints)
}

/// Whether `req` asks for a stranger-safe answer (PRD R-8): `checkpoints`
/// with no derivation, or `history_card/1`, which is resolved only over
/// `full_history` and `checkpoints` (`evidence_log`). Neither carries a
/// record, so neither depends on who asks.
fn stranger_safe(req: &Request) -> bool {
    match &req.derivation {
        None => matches!(req.subject, Subject::Checkpoints),
        Some(Derivation::Token(t)) => t == DERIVATION_HISTORY_CARD,
        Some(Derivation::Digest(_)) => false,
    }
}

/// Whether `req` asks for record bodies over a subject no one requester is
/// party to (`range`, `full_history`): refused under every setting (see the
/// module doc).
fn spans_parties(req: &Request) -> bool {
    carries_records(req) && matches!(req.subject, Subject::Range(..) | Subject::FullHistory)
}

/// Whether the answer to `req` depends on who asks: record bodies, always;
/// Standard History, unless the operator shares it. A stranger-safe answer
/// never does.
fn needs_requester(req: &Request, responder: &Responder<'_>) -> bool {
    if stranger_safe(req) {
        return false;
    }
    // `exchange_corroboration/1` has a setting of its own: Standard History
    // being shared never releases it.
    if crate::exchange_corroboration::is_derivation(req.derivation.as_ref()) {
        if cfg!(feature = "mutant-corroboration-uses-standard-history-gate") {
            return !responder.share_standard_history;
        }
        return !responder.share_exchange_corroboration;
    }
    if carries_records(req) {
        policy_gate_applies()
    } else {
        !responder.share_standard_history
    }
}

/// Whether the answer to `req` goes only to a counterparty: one that depends
/// on who asks, except record bodies under `peers`, which go to any proven
/// node.
fn needs_counterparty(req: &Request, responder: &Responder<'_>) -> bool {
    needs_requester(req, responder)
        && !(carries_records(req) && responder.history_segments == "peers")
}

/// Step 5: the principal a signed request proves (`requester_auth::check`),
/// `None` for an unsigned one this answer does not need, or the refusal.
///
/// A malformed `requester_auth` is `request_malformed`. A signature that
/// fails any check is refused whatever was asked: under `evidence-interop/1`
/// (`v1`) `request_unauthenticated`, or `capacity_exceeded` for a request
/// this node cannot check because it does not know its own id yet; under
/// /0 as below. An unsigned request is
/// refused when the answer depends on who asks. The refusal for a record is
/// `not_authorized`; for Standard History it is `policy_declined`, the one
/// refusal every requester that is not a proven counterparty gets (R-8).
/// None of these reads the ledger, so each is the same whether or not what
/// was asked for exists.
fn requester(
    map: &Map<String, Value>,
    form: Form,
    req: &Request,
    now: evidence_request::time::UtcTime,
    responder: &Responder<'_>,
    asker: &mut Asker,
    v1: bool,
) -> Result<Option<Principal>, Reason> {
    let needed = needs_requester(req, responder);
    let refused = if carries_records(req) {
        Reason::NotAuthorized
    } else {
        Reason::PolicyDeclined
    };
    match form {
        Form::Malformed => Err(Reason::RequestMalformed),
        Form::Unsigned if needed => Err(refused),
        Form::Unsigned => Ok(None),
        Form::Signed { key_id, sig } => {
            let deadline = req.deadline.ok_or(Reason::RequestMalformed)?;
            let audience = map
                .get(requester_auth::AUDIENCE)
                .and_then(Value::as_str)
                .map(str::to_string);
            let checked = requester_auth::check(
                requester_auth::Channel::EvidenceRequest,
                map,
                &key_id,
                &sig,
                deadline,
                now,
                responder.keys,
                responder.replay,
                responder.node_id,
            );
            // The audience is recorded as checked: once the signature
            // verified.
            if checked
                .as_ref()
                .map_or_else(|f| f.verified_key().is_some(), |_| true)
            {
                asker.audience = audience;
            }
            match checked {
                Ok(principal) => {
                    asker.key_id = Some(principal.key_id.clone());
                    asker.node_id = Some(principal.node_id.clone());
                    asker.binding = Some("bound");
                    asker.replay = Some("checked");
                    Ok(Some(principal))
                }
                Err(failure) => {
                    asker.key_id = failure.verified_key().map(str::to_string);
                    asker.node_id = failure.verified_node().map(str::to_string);
                    match failure {
                        requester_auth::Failure::ClaimMismatch { .. } => {
                            asker.binding = Some("bound");
                            asker.replay = Some("checked");
                        }
                        requester_auth::Failure::Unbound { replay_checked, .. } => {
                            asker.binding = Some("unbound");
                            asker.replay = Some(if replay_checked {
                                "checked"
                            } else {
                                "unchecked"
                            });
                        }
                        _ => {}
                    }
                    // A valid signature under a key no host binds reads as
                    // an unsigned request where the answer needs no
                    // identity, and gets nothing more (ruling addendum §2),
                    // also when its nonce could not be held (u290 §2).
                    if failure.reads_as_unsigned() && !needed {
                        return Ok(None);
                    }
                    if v1 {
                        // A limit of this node's own, not the request's: the
                        // audience cannot be checked before this node knows
                        // its own id, or the key's nonces fill its replay
                        // cache.
                        let own_id_unknown = responder.node_id.is_none()
                            && matches!(failure, requester_auth::Failure::AudienceMismatch { .. });
                        let full =
                            matches!(failure, requester_auth::Failure::ReplayCacheFull { .. });
                        return Err(if own_id_unknown || full {
                            Reason::CapacityExceeded
                        } else {
                            Reason::RequestUnauthenticated
                        });
                    }
                    Err(if needed {
                        refused
                    } else {
                        Reason::NotAuthorized
                    })
                }
            }
        }
    }
}

/// The sharing-policy gate, except in the deliberately broken build CI uses
/// to show the parity run catches a responder that drops it, and inside
/// [`ungated`].
fn policy_gate_applies() -> bool {
    #[cfg(test)]
    if UNGATED.with(std::cell::Cell::get) {
        return false;
    }
    !cfg!(feature = "mutant-evidence-skips-policy-gate")
}

#[cfg(test)]
thread_local! {
    static UNGATED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `f`, with this thread's responder answering anyone every subject, as no
/// setting does. The artifact tests use it to have answers a requester must
/// still check (a `range` or `full_history` from a responder that grants
/// one) built by this node's responder.
#[cfg(test)]
pub(crate) fn ungated<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            UNGATED.with(|u| u.set(false));
        }
    }
    UNGATED.with(|u| u.set(true));
    let _reset = Reset;
    f()
}

/// Steps 6 to 10, over the index.
fn answer_from(
    req: &Request,
    request_bytes: &[u8],
    principal: &[String],
    principal_key: Option<&str>,
    responder: &Responder<'_>,
    view: &LogView<'_>,
) -> Result<Value, Reason> {
    let index = view.index;
    // 6. An answer only a counterparty may have, decided before the subject
    // is resolved: Standard History unless it is shared, and record bodies
    // unless they go to any peer. A node no record names learns nothing of
    // this log's size or cadence from which refusal it gets.
    // For record bodies, the holder of a key a cited half verified under is
    // a counterparty too (#172); Standard History keeps the id rule.
    if needs_counterparty(req, responder)
        && policy_gate_applies()
        && !is_counterparty(index, principal)
        && !(carries_records(req) && holds_a_cited_key(index, principal_key))
    {
        return Err(if carries_records(req) {
            Reason::NotAuthorized
        } else {
            Reason::PolicyDeclined
        });
    }
    // This node serves Service History, so it serves no `standard_history/1`
    // card under its key, whatever a later evidencebook registers (ISH §6.1
    // item 8).
    if matches!(&req.derivation,
        Some(Derivation::Token(t)) if t == crate::service_history::STANDARD_HISTORY_TOKEN)
    {
        return Err(Reason::DerivationUnsupported);
    }
    if crate::exchange_corroboration::is_derivation(req.derivation.as_ref()) {
        return corroboration_answer(req, request_bytes, principal, responder, view);
    }
    // A Service History is a run of whole closed periods at one pinned
    // anchor: any other subject or coverage is `policy_declined`, the same
    // for every requester, before anything is resolved (ISH §6.1 item 5).
    let service_history = crate::service_history::is_derivation(req.derivation.as_ref());
    let definition = crate::service_history::Definition::active();
    if service_history && definition.declines_request(&req.subject, &req.coverage) {
        return Err(Reason::PolicyDeclined);
    }
    // 7. Resolve.
    let anchor = match resolve::resolve(req, view) {
        Resolution::Artifact(anchor) => anchor,
        Resolution::Refuse(reason) => return Err(reason),
    };
    let at = serving_position(view, &anchor)?;
    // ... and only at an anchor on a period boundary (ISH §6.1 item 2).
    if service_history && definition.declines_anchor(&index.chain[at].record.timestamp) {
        return Err(Reason::PolicyDeclined);
    }

    // 8. Size, from the index.
    let covered =
        leaf_count(index.chain[at].record.mmr_size).map_err(|_| Reason::CoverageUnsatisfiable)?;
    let records: Vec<u64> = if carries_records(req) {
        // A keyed subject's matches, without the records that never leave.
        let keyed = match &req.subject {
            Subject::Correlation(id) => index.leaving(index.correlated(id)),
            Subject::Exchange(half) => index.leaving(index.citing(half)),
            _ => Vec::new(),
        };
        let count = match &req.subject {
            Subject::Range(a, b) => b.saturating_sub(*a).saturating_add(1),
            Subject::FullHistory => covered,
            Subject::Record(_) => 1,
            Subject::Correlation(_) | Subject::Exchange(_) => keyed.len() as u64,
            Subject::Checkpoints => 0,
        };
        if count > MAX_ANSWER_RECORDS {
            return Err(Reason::CapacityExceeded);
        }
        let records: Vec<u64> = match &req.subject {
            // The resolver refused a range reaching past the anchor.
            Subject::Range(a, b) => (*a..=*b).collect(),
            Subject::FullHistory => (0..covered).collect(),
            // Held, but after the anchor: not yet committed under it.
            Subject::Record(d) => match index.leaf_index_of(d) {
                Some(i) if i >= covered => return Err(Reason::CoverageUnsatisfiable),
                found => found.into_iter().collect(),
            },
            Subject::Correlation(_) | Subject::Exchange(_) => keyed,
            Subject::Checkpoints => Vec::new(),
        }
        .into_iter()
        .filter(|&i| i < covered)
        .collect();
        if records.is_empty() {
            return Err(Reason::NoSuchSubject);
        }
        records
    } else {
        if at as u64 + 1 > MAX_ANSWER_CHECKPOINTS {
            return Err(Reason::CapacityExceeded);
        }
        Vec::new()
    };

    // 9. Who may have these records.
    if policy_gate_applies()
        && !may_serve_all_to(
            index,
            &records,
            principal,
            principal_key,
            responder.history_segments,
        )
    {
        return Err(Reason::NotAuthorized);
    }

    // 10. Build and sign.
    evidence_artifact::build(
        &Build {
            request: req,
            request_bytes,
            resolved: &anchor,
            at,
            records: &records,
            signing_key: responder.signing_key,
            issued_at: responder.now,
        },
        view,
    )
}

/// Steps 7 to 10 for `exchange_corroboration/1`: resolved against the bound
/// client nonces only, answered whole or refused whole. Under the default
/// (the setting off), only to a node every matching half names as the other
/// side of its exchange; never a half that never leaves this node.
fn corroboration_answer(
    req: &Request,
    request_bytes: &[u8],
    principal: &[String],
    responder: &Responder<'_>,
    view: &LogView<'_>,
) -> Result<Value, Reason> {
    use crate::exchange_corroboration as corroboration;
    let index = view.index;
    let anchor = match resolve::resolve(req, &corroboration::NonceView(view)) {
        Resolution::Artifact(anchor @ ResolvedAnchor::Anchor(_)) => anchor,
        Resolution::Artifact(ResolvedAnchor::ExchangeHalf(_)) => return Err(Reason::NoSuchSubject),
        Resolution::Refuse(reason) => return Err(reason),
    };
    let at = serving_position(view, &anchor)?;
    #[allow(unused_mut)]
    let mut records = corroboration::matching_records(req, &index.chain[at].record, view);
    if records.len() as u64 > MAX_ANSWER_RECORDS {
        return Err(Reason::CapacityExceeded);
    }
    if needs_requester(req, responder) && policy_gate_applies() {
        if cfg!(feature = "mutant-corroboration-filters-per-asker") {
            records.retain(|&i| {
                index
                    .leaves
                    .get(i as usize)
                    .is_some_and(|l| names(principal, l.counterparty.as_deref()))
            });
        } else if !may_serve_all(index, &records, principal, "counterparties") {
            return Err(Reason::NotAuthorized);
        }
    }
    evidence_artifact::build(
        &Build {
            request: req,
            request_bytes,
            resolved: &anchor,
            at,
            records: &records,
            signing_key: responder.signing_key,
            issued_at: responder.now,
        },
        view,
    )
}

/// The chain position of the checkpoint an answer is served under. For an
/// anchor, the checkpoint it names. For an `exchange` subject pinned by the
/// requester's own half, the earliest checkpoint covering the last record
/// citing the half among those the latest one covers, so growth that adds
/// no citing record does not change the artifact (-00 §5), as the Go
/// responder chooses it. It is evidencebook's `answer::serving_checkpoint`
/// over this index (evidencebook#35); every failure, an anchor no
/// checkpoint states or a half no checkpoint covers yet, is
/// `coverage_unsatisfiable`.
fn serving_position(view: &LogView<'_>, anchor: &ResolvedAnchor) -> Result<usize, Reason> {
    use evidencebook::store::CheckpointedLog as _;
    let stated = view
        .stated_checkpoints()
        .map_err(|_| Reason::CoverageUnsatisfiable)?;
    evidencebook::answer::serving_checkpoint(view, &stated, anchor)
        .map_err(|_| Reason::CoverageUnsatisfiable)
}

/// Whether `counterparty` is one of `principal`, the nodes a signed
/// request's key is bound to (`requester_auth::Principal::node_ids`): the
/// key is the asker's identity, and each node it is bound to is the asker
/// (D-34).
fn names(principal: &[String], counterparty: Option<&str>) -> bool {
    counterparty.is_some_and(|named| {
        principal.iter().any(|node| {
            let node = node.trim();
            !node.is_empty() && node == named
        })
    })
}

/// Whether some record of this node names one of `principal`, the nodes a
/// signed request proved it came from, as the other side of its exchange
/// (a local block or an owner-maintenance record names no counterparty it
/// was exchanged with, and padding names none).
fn is_counterparty(index: &LedgerIndex, principal: &[String]) -> bool {
    index.leaves.iter().any(|leaf| {
        !leaf.padding && !leaf.never_leaves && names(principal, leaf.counterparty.as_deref())
    })
}

/// Whether `principal_key` is the key some cited half of this node verified
/// under (`Leaf::counterparty_key`): its holder is the other side of that
/// exchange.
fn holds_a_cited_key(index: &LedgerIndex, principal_key: Option<&str>) -> bool {
    principal_key.is_some_and(|key| {
        index.leaves.iter().any(|leaf| {
            !leaf.padding && !leaf.never_leaves && leaf.counterparty_key.as_deref() == Some(key)
        })
    })
}

/// Whether every record in `records` may go to `principal` under
/// `history_segments` (see the module doc).
pub(crate) fn may_serve_all(
    index: &LedgerIndex,
    records: &[u64],
    principal: &[String],
    history_segments: &str,
) -> bool {
    may_serve_all_to(index, records, principal, None, history_segments)
}

/// [`may_serve_all`], for a request signed under `principal_key`: under
/// `counterparties` a citing record also goes to the holder of the key its
/// cited half verified under (`Leaf::counterparty_key`), the other side of
/// that exchange, whatever id it asks under (#172).
fn may_serve_all_to(
    index: &LedgerIndex,
    records: &[u64],
    principal: &[String],
    principal_key: Option<&str>,
    history_segments: &str,
) -> bool {
    if records.is_empty() {
        return true;
    }
    if history_segments == "off" {
        return false;
    }
    let proven = principal.iter().any(|node| !node.trim().is_empty());
    records.iter().all(|&i| {
        let Some(leaf) = index.leaves.get(i as usize) else {
            return false;
        };
        !leaf.never_leaves
            && proven
            && (history_segments == "peers"
                || (!leaf.padding
                    && (names(principal, leaf.counterparty.as_deref())
                        || principal_key
                            .is_some_and(|key| leaf.counterparty_key.as_deref() == Some(key)))))
    })
}

/// Answer `request_bytes` (or, when `busy`, decline it unread), and log the
/// outcome to the "asked of you" log in `log_dir`. The one path the mesh
/// responder takes.
pub fn answer_and_log(
    request_bytes: &[u8],
    busy: bool,
    responder: &Responder<'_>,
    log_dir: Option<&Path>,
) -> Outcome {
    let requester_id = requester_id(request_bytes);
    let (outcome, asker) = if busy {
        (decline_busy(request_bytes, responder), Asker::default())
    } else {
        answer_as(request_bytes, responder)
    };
    let (status, reason) = outcome.log_status();
    let digest = request_digest(request_bytes);
    log_received(
        log_dir,
        &received::Entry {
            ts: responder.now,
            path: "evidence-request",
            requester_id: requester_id.as_deref(),
            subject_kind: outcome.subject_kind(),
            status,
            reason,
            request_digest: Some(&digest),
            principal_key_id: asker.key_id.as_deref(),
            principal_node_id: asker.node_id.as_deref(),
            principal_binding: asker.binding,
            audience: asker.audience.as_deref(),
            replay: asker.replay,
        },
    );
    outcome
}

/// A refusal on the wire: the crate's signed object, plus the digest of the
/// disclosure policy that applied as `policy_digest`. That member is NOT
/// signed: evidence-request 0.2.0 signs exactly `issued_at`, `reason` and
/// `request_digest` (`refusal::SIGNED_MEMBERS`), and its checks ignore any
/// other member. A requester checks it against the `lcap.policy_digest` of
/// this node's signed commitment (`crate::commitment`).
fn refusal_wire(refusal: &refusal::Refusal, responder: &Responder<'_>) -> Value {
    let mut wire = refusal.to_json();
    if let (Some(digest), Some(map)) = (responder.policy_digest, wire.as_object_mut()) {
        map.insert("policy_digest".into(), json!(digest));
    }
    wire
}

/// The "asked of you" log for this run (evidencebook's `received`), capped at
/// [`MAX_RECEIVED_LOG_BYTES`].
static RECEIVED_LOG: ReceivedLog = ReceivedLog::new(MAX_RECEIVED_LOG_BYTES);

/// Append `entry` to the "asked of you" log in `dir` when `dir` is the
/// directory locked for it at start (`data_dir::received_log_writable`).
/// Best-effort: an answer is decided before it is logged, so a failure is
/// reported in this node's own log and never changes it. A full log is
/// reported on its first drop, then every 1000th.
pub(crate) fn log_received(dir: Option<&Path>, entry: &received::Entry<'_>) {
    let dir = dir.filter(|d| crate::data_dir::received_log_writable(d));
    match RECEIVED_LOG.append(dir, entry) {
        Ok(Appended::Full { dropped }) if dropped == 1 || dropped.is_multiple_of(1000) => {
            tracing::warn!(
                dropped,
                max_bytes = MAX_RECEIVED_LOG_BYTES,
                "the received log is full; requests are no longer logged"
            );
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "could not append to the received log"),
    }
}

/// Now, as every `issued_at` is written.
pub fn now_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// `reason`, when the profile the request octets `sent` asked for registers
/// it (IP v1 §6.3): evidence-interop/0 the eight ER -01 tokens, /1 the ten of
/// ER -02. A refusal carries no profile, so its reason is read by its
/// request's.
pub(crate) fn registered_under_request(sent: &[u8], reason: Reason) -> Result<Reason, String> {
    let profile = evidence_artifact::profile_of(sent);
    if evidence_request::envelope::refusal_reasons(&profile).contains(&reason) {
        Ok(reason)
    } else {
        Err(format!("{reason} is not a refusal reason under {profile}"))
    }
}

/// A signed refusal of `request_bytes`, given without reading the ledger:
/// this node is already answering as many requests as it takes at once.
/// `capacity_exceeded` to an `evidence-interop/1` request, `policy_declined`
/// to a /0 one ([`under_profile`]).
pub fn decline_busy(request_bytes: &[u8], responder: &Responder<'_>) -> Outcome {
    let digest = request_digest(request_bytes);
    let reason = under_profile(Reason::CapacityExceeded, asks_v1(request_bytes));
    match refusal::sign(&digest, reason, responder.now, responder.signing_key) {
        Ok(r) => Outcome::Refused {
            wire: refusal_wire(&r, responder),
            reason,
            subject_kind: None,
        },
        Err(e) => Outcome::Unanswerable(format!("could not sign a {reason} refusal: {e}")),
    }
}

// ---------------------------------------------------------------------------
// The requester's side: is what came back evidence?
// ---------------------------------------------------------------------------

/// What a requester makes of a response to the request it sent (`sent`,
/// exactly the bytes written) from the responder whose key it expects:
///
/// - `{"state": "refusal", "reason"}`: a refusal that key signed, of this
///   request (`refusal::verify_for`);
/// - `{"state": "artifact", "anchor", "records", "checkpoints"}`: an answer
///   that verifies (`evidence_artifact::check`): `anchor` is the digest of
///   the checkpoint statement it is served under, `records` the leaf indices
///   it carries, `checkpoints` how many checkpoints it lists;
/// - `{"state": "not_evidence", "why"}`: anything else. It is not a refusal
///   and not an answer (§4.1).
///
/// `witness_keys` are the witness keys the operator configured, by witness
/// URL (`checkpoint_cadence::active_witness_keys`): configured keys only,
/// never a key this node pinned on first contact with a witness. Each
/// receipt the answer carries is checked under the key configured for ITS
/// witness's URL (URLs normalized, and duplicates resolved, as
/// `witness_status` does), never under another witness's key. A receipt
/// that fails only because of a configured key makes the answer not
/// evidence with `reason: "witness_receipt_unverified"`; one that fails with
/// no key at all fails as before. With keys configured, such an artifact also
/// reports `witnessed` (receipts verified) and each receipt's status. With
/// none, the result is exactly what it was before keys were passed.
pub fn verify_response(
    sent: &[u8],
    response: &Value,
    key: &ed25519_dalek::VerifyingKey,
    witness_keys: &std::collections::BTreeMap<String, String>,
) -> Value {
    let not_evidence = |why: String| json!({"state": "not_evidence", "why": why});
    let digest = request_digest(sent);
    if response.get("reason").is_some() {
        return match refusal::verify_for(response, key, &digest)
            .map_err(|e| e.to_string())
            .and_then(|reason| registered_under_request(sent, reason))
        {
            Ok(reason) => json!({"state": "refusal", "reason": reason.token()}),
            Err(why) => not_evidence(why),
        };
    }
    let Ok(req) = request::parse_json(sent) else {
        return not_evidence("the request sent is not a -00 request".into());
    };
    if crate::exchange_corroboration::is_derivation(req.derivation.as_ref()) {
        return match crate::exchange_corroboration::verify(sent, response, key, witness_keys) {
            crate::exchange_corroboration::Verified::Halves { anchor, halves } => {
                json!({"state": "artifact", "anchor": anchor, "halves": halves.len()})
            }
            crate::exchange_corroboration::Verified::Refusal(reason) => {
                json!({"state": "refusal", "reason": reason.token()})
            }
            crate::exchange_corroboration::Verified::Failed(why) => not_evidence(why),
        };
    }
    let witness_key = |ts_url: &str| {
        if cfg!(feature = "mutant-answer-ignores-witness-keys") {
            return None;
        }
        configured_witness_key(witness_keys, ts_url)
    };
    match evidence_artifact::check(sent, &req, response, key, &witness_key) {
        Ok(v) => {
            let mut out = json!({
                "state": "artifact",
                "anchor": v.anchor,
                "records": v.records,
                "checkpoints": v.checkpoints,
            });
            if let Some(history) = &v.history {
                let statuses: Vec<ReceiptStatus> = v.receipts.iter().map(|r| r.status).collect();
                out["lines"] = json!(crate::service_history::render(
                    history,
                    v.checkpoints,
                    &statuses
                ));
            }
            if !witness_keys.is_empty() {
                out["witnessed"] = json!(v
                    .receipts
                    .iter()
                    .filter(|r| r.status == ReceiptStatus::Verified)
                    .count());
                out["receipts"] = v
                    .receipts
                    .iter()
                    .map(|r| {
                        json!({
                            "checkpoint": r.checkpoint,
                            "ts_url": r.ts_url,
                            "status": match r.status {
                                ReceiptStatus::Verified => "verified",
                                ReceiptStatus::NoKey => "no_key",
                                ReceiptStatus::Stub => "stub",
                            },
                        })
                    })
                    .collect();
            }
            out
        }
        // A receipt failing under a configured key: the same answer passes
        // with no keys, so the key is what refused it.
        Err(e @ (CheckError::ReceiptBinding | CheckError::ReceiptMalformed))
            if !witness_keys.is_empty()
                && evidence_artifact::check(sent, &req, response, key, &|_| None).is_ok() =>
        {
            json!({"state": "not_evidence", "why": e.to_string(), "reason": "witness_receipt_unverified"})
        }
        Err(e) => not_evidence(e.to_string()),
    }
}

/// The key the operator configured for the witness at `ts_url`: the entry
/// whose URL is the same once normalized (`witness_status::normalize_url`).
/// A value that is not an Ed25519 key is no key.
pub(crate) fn configured_witness_key(
    witness_keys: &std::collections::BTreeMap<String, String>,
    ts_url: &str,
) -> Option<ed25519_dalek::VerifyingKey> {
    let normalized: std::collections::BTreeMap<String, &String> = witness_keys
        .iter()
        .map(|(url, key)| (crate::witness_status::normalize_url(url), key))
        .collect();
    let hex_key = normalized.get(&crate::witness_status::normalize_url(ts_url))?;
    let bytes: [u8; 32] = hex::decode(hex_key).ok()?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::evidence_request_parity::{
        announced_keys as announced, asker_key, corpus_checkpoints, corpus_ledger, sealed, served,
        write_jsonl, NODE_KEY_SEED,
    };

    use crate::requester_auth::{Keys, ReplayCache};
    use ed25519_dalek::Signer as _;
    use evidence_request::jcs;
    use sha2::{Digest, Sha256};

    const NOW: &str = "2026-09-29T00:00:00Z";

    /// This node's own mesh id, which a signed request's audience names.
    const RESPONDER: &str = crate::evidence_request_parity::RESPONDER_NODE;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&NODE_KEY_SEED)
    }

    fn key_id_of(key: &SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(NOW).unwrap().into()
    }

    /// `request` signed with `key` at [`NOW`] (`requester_auth::sign`).
    fn signed_with(key: &SigningKey, request: &Value) -> Vec<u8> {
        let mut request = request.clone();
        requester_auth::sign(
            requester_auth::Channel::EvidenceRequest,
            &mut request,
            key,
            now(),
            RESPONDER,
        );
        serde_json::to_vec(&request).unwrap()
    }

    /// `request` signed by the node `node`.
    fn signed_by(node: &str, request: &Value) -> Vec<u8> {
        signed_with(&asker_key(node), request)
    }

    /// Asked of a node with these settings and a fresh replay cache.
    fn ask_with(dir: &Path, bytes: &[u8], segments: &str, share_standard_history: bool) -> Outcome {
        ask_cached(
            dir,
            bytes,
            segments,
            share_standard_history,
            &ReplayCache::default(),
        )
    }

    fn ask_cached(
        dir: &Path,
        bytes: &[u8],
        segments: &str,
        share_standard_history: bool,
        replay: &ReplayCache,
    ) -> Outcome {
        let key = key();
        let announced = announced();
        answer(
            bytes,
            &Responder {
                ledger_dir: dir,
                signing_key: &key,
                now: NOW,
                history_segments: segments,
                share_standard_history,
                share_exchange_corroboration: false,
                keys: Keys {
                    announced: &announced,
                    configured: None,
                    own_key: None,
                },
                replay,
                node_id: Some(RESPONDER),
                policy_digest: None,
            },
        )
    }

    /// A ledger directory holding `ledger` and checkpoints cut at `cuts`
    /// (the corpus's own cutter, which cuts after 16 and 300 lines).
    fn node(ledger: &[Value]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_jsonl(&dir.path().join("capsules.jsonl"), ledger);
        let cps: Vec<Value> = corpus_checkpoints(ledger, &key())
            .iter()
            .map(|cp| cp.line())
            .collect();
        write_jsonl(&dir.path().join("checkpoints.jsonl"), &cps);
        dir
    }

    /// Asked with Standard History shared, as every node answered before it
    /// had the switch: these tests are about everything else.
    fn ask(dir: &Path, bytes: &[u8], segments: &str) -> Outcome {
        ask_with(dir, bytes, segments, true)
    }

    fn refused(outcome: &Outcome) -> Option<Reason> {
        match outcome {
            Outcome::Refused { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// No request, however formed, panics the responder or goes unanswered:
    /// each is a signed refusal bound to its own bytes.
    #[test]
    fn hostile_requests_are_signed_refusals_never_panics() {
        let dir = node(&corpus_ledger());
        let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
        let long_id = format!(
            r#"{{"subject":{{"correlation":"{}"}},"coverage":{{"min_freshness":1}}}}"#,
            "x".repeat(15_000)
        );
        let inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"null".to_vec(),
            b"[]".to_vec(),
            deep.into_bytes(),
            vec![0xff, 0xfe, 0x00],
            br#"{"subject":{"range":[0,18446744073709551615]},"coverage":{"min_freshness":1}}"#.to_vec(),
            br#"{"subject":{"range":[5,2]},"coverage":{"min_freshness":1}}"#.to_vec(),
            br#"{"subject":{"range":[-1,2]},"coverage":{"min_freshness":1}}"#.to_vec(),
            br#"{"subject":{"record":"a","range":[0,1]},"coverage":{"min_freshness":1}}"#.to_vec(),
            br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":18446744073709551615}}"#.to_vec(),
            br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":"not a time"}}"#.to_vec(),
            long_id.into_bytes(),
        ];
        for bytes in inputs {
            let outcome = ask(dir.path(), &bytes, "peers");
            let Outcome::Refused { wire, reason, .. } = &outcome else {
                panic!(
                    "{:?} was not refused: {outcome:?}",
                    String::from_utf8_lossy(&bytes)
                );
            };
            assert_eq!(
                refusal::verify_for(wire, &key().verifying_key(), &request_digest(&bytes)),
                Ok(*reason),
                "signed and bound to the request"
            );
        }
    }

    /// A `requester_id` that is not text is no identity at all: ignored, not
    /// a reason to refuse what needs none.
    #[test]
    fn a_requester_id_that_is_not_text_is_ignored() {
        let dir = node(&corpus_ledger());
        let bytes =
            br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":1},"requester_id":5}"#;
        assert_eq!(requester_id(bytes), None);
        assert!(matches!(
            ask(dir.path(), bytes, "peers"),
            Outcome::Answered { .. }
        ));
    }

    /// A refusal names the request it refuses: it does not verify as the
    /// answer to any other request.
    #[test]
    fn a_refusal_is_bound_to_its_request_digest() {
        let dir = node(&corpus_ledger());
        let bytes = br#"{"subject":{"record":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"coverage":{"min_freshness":1}}"#;
        let Outcome::Refused { wire, .. } = ask(dir.path(), bytes, "peers") else {
            panic!("refused");
        };
        let other = request_digest(b"another request");
        assert_eq!(
            refusal::verify_for(&wire, &key().verifying_key(), &other),
            Err(refusal::VerifyError::WrongRequest)
        );
    }

    /// Size and the `off` switch are decided before the ledger is read: with
    /// no ledger at all, the answer is still the policy refusal, not a
    /// failure to read one.
    #[test]
    fn cheap_refusals_come_before_the_ledger_is_read() {
        let missing = tempfile::tempdir().unwrap();
        let nowhere = missing.path().join("no-such-ledger");
        let big = vec![b' '; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            refused(&ask(&nowhere, &big, "peers")),
            Some(Reason::PolicyDeclined)
        );
        let record = format!(
            r#"{{"subject":{{"record":"{}"}},"coverage":{{"min_freshness":1}}}}"#,
            "a".repeat(64)
        );
        assert_eq!(
            refused(&ask(&nowhere, record.as_bytes(), "off")),
            Some(Reason::NotAuthorized)
        );
    }

    /// An answer that would not fit the stream the requester reads is
    /// declined, not sent to be cut off.
    #[test]
    fn an_answer_over_the_stream_cap_is_declined() {
        let mut ledger = vec![sealed(
            json!({"action_type": "fyi", "blob": "x".repeat(MAX_ANSWER_BYTES)}),
        )];
        let rest = corpus_ledger();
        ledger.extend(rest.into_iter().skip(1).take(15));
        let dir = node(&ledger);
        let record = format!(
            r#"{{"subject":{{"record":"{}"}},"coverage":{{"min_freshness":1}}}}"#,
            ledger[0]["capsule_id"].as_str().unwrap()
        );
        let record: Value = serde_json::from_str(&record).unwrap();
        assert_eq!(
            refused(&ask(dir.path(), &signed_by("node-y", &record), "peers")),
            Some(Reason::PolicyDeclined)
        );
    }

    /// The live paid run: the provider's served half carries the host's
    /// placeholder nonce, not the one the payer forwarded, so the payer's ask
    /// by its nonce is a signed "no such record". Asked by the exchange's two
    /// digests, the provider answers with that half, proven in its log; and
    /// nobody is answered by the placeholder.
    #[test]
    fn a_host_served_half_is_answered_by_its_digests_when_its_nonce_is_the_placeholder() {
        let (req, resp) = ("4b".repeat(32), "33".repeat(32));
        let mut ledger = corpus_ledger();
        ledger[3] = sealed(json!({
            "action_type": "fyi",
            "effect": {"status": "confirmed", "request_digest": req, "response_digest": resp},
            "model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {
                "role": "served",
                "client_nonce": crate::evidence_log::HOST_SERVED_NO_NONCE,
                "client_nonce_source": "host_served_observed",
            }}},
        }));
        let dir = node(&ledger);
        // Asked by a proven node: under `peers` any proven node may have it.
        let by = |id: &str| {
            signed_by(
                "node-y",
                &json!({"subject": {"correlation": id}, "coverage": {"min_freshness": 1}}),
            )
        };

        let by_nonce = by("payer-forwarded-nonce");
        assert_eq!(
            refused(&ask(dir.path(), &by_nonce, "peers")),
            Some(Reason::NoSuchSubject)
        );
        let by_placeholder = by(crate::evidence_log::HOST_SERVED_NO_NONCE);
        assert_eq!(
            refused(&ask(dir.path(), &by_placeholder, "peers")),
            Some(Reason::NoSuchSubject)
        );
        let by_one_wrong_digest = by(&crate::evidence_log::exchange_binding(&req, &req));
        assert_eq!(
            refused(&ask(dir.path(), &by_one_wrong_digest, "peers")),
            Some(Reason::NoSuchSubject)
        );

        let by_digests = by(&crate::evidence_log::exchange_binding(&req, &resp));
        let Outcome::Answered { wire, .. } = ask(dir.path(), &by_digests, "peers") else {
            panic!("answered");
        };
        let verification = verify_response(
            &by_digests,
            &wire,
            &key().verifying_key(),
            &Default::default(),
        );
        assert_eq!(verification["state"], json!("artifact"), "{verification}");
        assert_eq!(verification["records"], json!([3]));
    }

    /// A requester that is too busy gets a signed refusal, never a wait.
    #[test]
    fn a_busy_node_declines_with_a_signed_refusal() {
        let key = key();
        let (announced, replay) = (announced(), ReplayCache::default());
        let responder = Responder {
            ledger_dir: Path::new("/nonexistent"),
            signing_key: &key,
            now: NOW,
            history_segments: "peers",
            share_standard_history: true,
            share_exchange_corroboration: false,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &replay,
            node_id: Some(RESPONDER),
            policy_digest: None,
        };
        let bytes = br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":1}}"#;
        let Outcome::Refused { wire, reason, .. } = decline_busy(bytes, &responder) else {
            panic!("declined");
        };
        assert_eq!(reason, Reason::PolicyDeclined);
        assert!(refusal::verify_for(&wire, &key.verifying_key(), &request_digest(bytes)).is_ok());
    }

    /// The reasons ER -02 adds go only to an `evidence-interop/1` request
    /// (IP v1 §6.3); a /0 request gets the token /0 used for the same cause.
    #[test]
    fn under_profile_keeps_the_02_reasons_to_v1() {
        for (reason, v0) in [
            (Reason::CapacityExceeded, Reason::PolicyDeclined),
            (Reason::RequestUnauthenticated, Reason::NotAuthorized),
            (Reason::PolicyDeclined, Reason::PolicyDeclined),
            (Reason::NotAuthorized, Reason::NotAuthorized),
            (Reason::NoSuchSubject, Reason::NoSuchSubject),
        ] {
            assert_eq!(under_profile(reason, true), reason);
            assert_eq!(under_profile(reason, false), v0, "{reason}");
        }
    }

    /// A request whose signature fails is refused `request_unauthenticated`
    /// under evidence-interop/1, `not_authorized` under /0, before the ledger
    /// is read either way; a busy node declines a /1 request
    /// `capacity_exceeded` and a /0 one `policy_declined`.
    #[test]
    fn a_v1_request_is_refused_with_the_02_reasons() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let record = node_a_record(&ledger);
        for (profile, want) in [
            (Some("evidence-interop/1"), Reason::RequestUnauthenticated),
            (Some("evidence-interop/0"), Reason::NotAuthorized),
            (None, Reason::NotAuthorized),
        ] {
            let mut request = record.clone();
            if let Some(p) = profile {
                request["profile"] = json!(p);
            }
            requester_auth::sign(
                requester_auth::Channel::LedgerFetch,
                &mut request,
                &asker_key("node-a"),
                now(),
                RESPONDER,
            );
            let bytes = serde_json::to_vec(&request).unwrap();
            let reads = evidence_log::index_reads();
            let outcome = ask_with(dir.path(), &bytes, "peers", false);
            assert_eq!(evidence_log::index_reads(), reads, "the ledger was read");
            assert_eq!(
                outcome.wire_bytes(),
                Some(refusal_of(&bytes, want)),
                "{profile:?}"
            );
        }

        let key = key();
        let (announced, replay) = (announced(), ReplayCache::default());
        let responder = Responder {
            ledger_dir: Path::new("/nonexistent"),
            signing_key: &key,
            now: NOW,
            history_segments: "peers",
            share_standard_history: true,
            share_exchange_corroboration: false,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &replay,
            node_id: Some(RESPONDER),
            policy_digest: None,
        };
        for (bytes, want) in [
            (
                &br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":1},"profile":"evidence-interop/1"}"#[..],
                Reason::CapacityExceeded,
            ),
            (
                &br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":1}}"#[..],
                Reason::PolicyDeclined,
            ),
        ] {
            let Outcome::Refused { wire, reason, .. } = decline_busy(bytes, &responder) else {
                panic!("declined");
            };
            assert_eq!(reason, want);
            assert_eq!(
                refusal::verify_for(&wire, &key.verifying_key(), &request_digest(bytes)),
                Ok(want)
            );
        }
    }

    /// A refusal is read by its request's profile (IP v1 §6.3): an -02 reason
    /// answering a /0 or profile-less request is not a conforming refusal;
    /// answering a /1 request it is.
    #[test]
    fn the_requester_reads_a_refusal_by_its_requests_profile() {
        let key = key();
        let signed = |sent: &[u8], reason: Reason| -> Value {
            let r = refusal::sign(&request_digest(sent), reason, NOW, &key).unwrap();
            serde_json::to_value(r.to_json()).unwrap()
        };
        let v0 = br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":1}}"#;
        let v1 = br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":1},"profile":"evidence-interop/1"}"#;
        for reason in [Reason::CapacityExceeded, Reason::RequestUnauthenticated] {
            let got = verify_response(
                v0,
                &signed(v0, reason),
                &key.verifying_key(),
                &Default::default(),
            );
            assert_eq!(got["state"], json!("not_evidence"), "{reason}: {got}");
            let got = verify_response(
                v1,
                &signed(v1, reason),
                &key.verifying_key(),
                &Default::default(),
            );
            assert_eq!(got, json!({"state": "refusal", "reason": reason.token()}));
        }
        let got = verify_response(
            v0,
            &signed(v0, Reason::PolicyDeclined),
            &key.verifying_key(),
            &Default::default(),
        );
        assert_eq!(got["state"], json!("refusal"));
    }

    /// A bound key whose nonces fill its replay cache is refused before the
    /// ledger is read: `capacity_exceeded` under evidence-interop/1, a limit
    /// of this node's own; under /0 what it was before, `not_authorized`
    /// for a record.
    #[test]
    fn a_full_replay_cache_is_capacity_exceeded_under_v1() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let record = node_a_record(&ledger);
        let key_id = hex::encode(asker_key("node-a").verifying_key().to_bytes());
        for (profile, want) in [
            (Some("evidence-interop/1"), Reason::CapacityExceeded),
            (None, Reason::NotAuthorized),
        ] {
            let replay = ReplayCache::default();
            for i in 0..requester_auth::MAX_NONCES_PER_KEY {
                replay.first_use(&key_id, &format!("held-{i}"), i64::MAX / 2, 0, true);
            }
            let mut request = record.clone();
            if let Some(p) = profile {
                request["profile"] = json!(p);
            }
            let bytes = signed_by("node-a", &request);
            let reads = evidence_log::index_reads();
            let outcome = ask_cached(dir.path(), &bytes, "peers", false, &replay);
            assert_eq!(evidence_log::index_reads(), reads, "the ledger was read");
            assert_eq!(
                outcome.wire_bytes(),
                Some(refusal_of(&bytes, want)),
                "{profile:?}"
            );
        }
    }

    /// The corroboration path reads a refusal by its request's profile too.
    #[test]
    fn a_corroboration_refusal_is_read_by_its_requests_profile() {
        use crate::exchange_corroboration::{request_for, verify, Verified};
        let key = key();
        for (profile, conforms) in [(None, false), (Some("evidence-interop/1"), true)] {
            let mut request = request_for("deal-1");
            if let Some(p) = profile {
                request["profile"] = json!(p);
            }
            let sent = serde_json::to_vec(&request).unwrap();
            let r =
                refusal::sign(&request_digest(&sent), Reason::CapacityExceeded, NOW, &key).unwrap();
            let got = verify(
                &sent,
                &r.to_json(),
                &key.verifying_key(),
                &Default::default(),
            );
            match got {
                Verified::Refusal(reason) if conforms => {
                    assert_eq!(reason, Reason::CapacityExceeded)
                }
                Verified::Failed(_) if !conforms => {}
                other => panic!("{profile:?}: {other:?}"),
            }
        }
    }

    /// A node whose clock cannot be written as an `issued_at` signs nothing.
    #[test]
    fn a_bad_clock_answers_nothing() {
        let key = key();
        let (announced, replay) = (announced(), ReplayCache::default());
        let responder = Responder {
            ledger_dir: Path::new("/nonexistent"),
            signing_key: &key,
            now: "yesterday",
            history_segments: "peers",
            share_standard_history: true,
            share_exchange_corroboration: false,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &replay,
            node_id: Some(RESPONDER),
            policy_digest: None,
        };
        assert!(matches!(
            answer(b"{}", &responder),
            Outcome::Unanswerable(_)
        ));
        assert_eq!(answer(b"{}", &responder).wire_bytes(), None);
    }

    /// This node has no referee: a referee's `adjudicate` request is answered
    /// in-process with a signed refusal, never a verdict, never silence.
    #[test]
    fn an_adjudicate_request_is_refused_signed_never_a_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let request = json!({
            "v": 1,
            "subject": {"kind": "adjudicate", "halves": ["a".repeat(64), "b".repeat(64)]},
            "requester_id": "peer-x",
        })
        .to_string();
        let outcome = ask(dir.path(), request.as_bytes(), "peers");
        assert!(refused(&outcome).is_some(), "refused");
        let wire = outcome.wire_bytes().expect("something signed is sent");
        let reply: Value = serde_json::from_slice(&wire).unwrap();
        assert!(reply.get("adjudication_verdict").is_none());
        let key_id = hex::encode(key().verifying_key().to_bytes());
        assert_eq!(reply["key_id"], json!(key_id));
        let check = refusal::verify_for(
            &reply,
            &key().verifying_key(),
            &request_digest(request.as_bytes()),
        );
        assert!(
            check.is_ok(),
            "the refusal verifies under this node's key: {check:?}"
        );
    }

    pub(crate) const WITNESS: &str = "https://witness.example";

    /// A real witness receipt for `entry` under `key`: a COSE_Sign1 (EdDSA)
    /// over the root of a one-leaf RFC 9162 tree, with its inclusion proof.
    pub(crate) fn mint_receipt(entry: &[u8; 32], key: &SigningKey) -> String {
        use base64::Engine as _;
        use coset::cbor::Value as Cbor;
        use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
        let mut leaf = Sha256::new();
        leaf.update([0u8]);
        leaf.update(entry);
        let root = leaf.finalize();
        let mut proof = Vec::new();
        coset::cbor::ser::into_writer(
            &Cbor::Array(vec![1.into(), 0.into(), Cbor::Array(vec![])]),
            &mut proof,
        )
        .unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .value(395, 1.into())
            .build();
        let unprotected = HeaderBuilder::new()
            .value(
                396,
                Cbor::Map(vec![((-1).into(), Cbor::Array(vec![Cbor::Bytes(proof)]))]),
            )
            .build();
        let receipt = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .create_detached_signature(&root, &[], |tbs| key.sign(tbs).to_bytes().to_vec())
            .build();
        base64::engine::general_purpose::STANDARD.encode(receipt.to_tagged_vec().unwrap())
    }

    /// A node whose every checkpoint carries a receipt from [`WITNESS`],
    /// signed by `witness`, for that checkpoint's own entry.
    pub(crate) fn witnessed_node(witness: &SigningKey) -> tempfile::TempDir {
        node_with_witnesses(|entry| {
            json!([{
                "ts_url": WITNESS, "entry_hash": hex::encode(entry),
                "receipt_b64": mint_receipt(entry, witness),
                "leaf_index": 0, "tree_size": 1,
            }])
        })
    }

    /// A node whose every checkpoint carries `witnesses(its entry)`.
    pub(crate) fn node_with_witnesses(witnesses: impl Fn(&[u8; 32]) -> Value) -> tempfile::TempDir {
        let dir = node(&corpus_ledger());
        let path = dir.path().join("checkpoints.jsonl");
        let lines: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| {
                let mut cp: Value = serde_json::from_str(l).unwrap();
                let mut json_form = cp.clone();
                json_form.as_object_mut().unwrap().remove("checkpoint_cose");
                let record: cll::checkpoint::CheckpointRecord =
                    serde_json::from_value(json_form).unwrap();
                let entry: [u8; 32] = Sha256::digest(hex::decode(record.digest()).unwrap()).into();
                cp["witnesses"] = witnesses(&entry);
                cp
            })
            .collect();
        write_jsonl(&path, &lines);
        dir
    }

    const CHECKPOINTS: &[u8] =
        br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":1}}"#;

    fn verified_with(dir: &Path, keys: &[(&str, &SigningKey)]) -> Value {
        let Outcome::Answered { wire, .. } = ask(dir, CHECKPOINTS, "peers") else {
            panic!("answered");
        };
        let keys = keys
            .iter()
            .map(|(url, k)| (url.to_string(), hex::encode(k.verifying_key().to_bytes())))
            .collect();
        verify_response(CHECKPOINTS, &wire, &key().verifying_key(), &keys)
    }

    #[test]
    fn a_receipt_under_its_witnesss_configured_key_is_counted_witnessed() {
        let witness = SigningKey::from_bytes(&[21; 32]);
        let dir = witnessed_node(&witness);
        let v = verified_with(dir.path(), &[(WITNESS, &witness)]);
        assert_eq!(v["state"], json!("artifact"), "{v}");
        let receipts = v["receipts"].as_array().unwrap();
        assert!(!receipts.is_empty());
        assert!(receipts
            .iter()
            .all(|r| r["status"] == json!("verified") && r["ts_url"] == json!(WITNESS)));
        assert_eq!(v["witnessed"], json!(receipts.len()));
        // The configured URL is matched as the cadence matches it: normalized.
        let v = verified_with(dir.path(), &[("HTTPS://Witness.Example/", &witness)]);
        assert_eq!(v["witnessed"], json!(receipts.len()), "{v}");
    }

    #[test]
    fn a_receipt_that_does_not_verify_under_the_configured_key_is_refused_by_name() {
        let witness = SigningKey::from_bytes(&[21; 32]);
        let impostor = SigningKey::from_bytes(&[22; 32]);
        let dir = witnessed_node(&witness);
        let v = verified_with(dir.path(), &[(WITNESS, &impostor)]);
        assert_eq!(v["state"], json!("not_evidence"), "{v}");
        assert_eq!(v["reason"], json!("witness_receipt_unverified"));
        assert_eq!(
            v["why"],
            json!(crate::evidence_artifact::CheckError::ReceiptBinding.to_string())
        );
    }

    #[test]
    fn only_the_key_configured_for_that_witness_is_used() {
        let witness = SigningKey::from_bytes(&[21; 32]);
        let dir = witnessed_node(&witness);
        // The right key, configured for another witness: never tried on this one.
        let v = verified_with(dir.path(), &[("https://other.example", &witness)]);
        assert_eq!(v["state"], json!("artifact"), "{v}");
        assert_eq!(v["witnessed"], json!(0));
        assert!(v["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["status"] == json!("no_key")));
    }

    #[test]
    fn with_no_witness_keys_the_result_is_what_it_was_before() {
        let witness = SigningKey::from_bytes(&[21; 32]);
        let dir = witnessed_node(&witness);
        let v = verified_with(dir.path(), &[]);
        assert_eq!(v["state"], json!("artifact"), "{v}");
        let mut members: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        members.sort_unstable();
        assert_eq!(members, ["anchor", "checkpoints", "records", "state"]);
    }

    #[test]
    fn a_stub_receipt_is_listed_as_a_stub_and_not_counted() {
        let witness = SigningKey::from_bytes(&[21; 32]);
        let dir = node_with_witnesses(|entry| {
            json!([{"ts_url": WITNESS, "entry_hash": hex::encode(entry), "receipt_b64": "",
                    "leaf_index": 0, "tree_size": 1, "is_stub": true}])
        });
        let v = verified_with(dir.path(), &[(WITNESS, &witness)]);
        assert_eq!(v["state"], json!("artifact"), "{v}");
        assert_eq!(v["witnessed"], json!(0));
        assert!(v["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["status"] == json!("stub")));
    }

    #[test]
    fn a_bad_receipt_from_a_witness_with_no_key_fails_as_before_not_as_a_key_failure() {
        let witness = SigningKey::from_bytes(&[21; 32]);
        // A receipt from an unkeyed witness, carried on the wrong checkpoint.
        let dir = node_with_witnesses(|_| {
            json!([{"ts_url": "https://unkeyed.example", "entry_hash": "00".repeat(32),
                    "receipt_b64": mint_receipt(&[0; 32], &witness), "leaf_index": 0, "tree_size": 1}])
        });
        let v = verified_with(dir.path(), &[(WITNESS, &witness)]);
        assert_eq!(v["state"], json!("not_evidence"), "{v}");
        assert_eq!(v.get("reason"), None, "no configured key was involved: {v}");
        assert_eq!(
            verified_with(dir.path(), &[]),
            v,
            "the same answer as with no keys"
        );
    }

    #[test]
    fn two_entries_for_one_witness_resolve_as_the_witness_status_rows_do() {
        let witness = SigningKey::from_bytes(&[21; 32]);
        let impostor = SigningKey::from_bytes(&[22; 32]);
        let dir = witnessed_node(&witness);
        // Both normalize to WITNESS; as in `witness_status`, the entry that
        // comes last in the map's order wins ("https" sorts after "HTTPS").
        let v = verified_with(
            dir.path(),
            &[("HTTPS://Witness.Example", &impostor), (WITNESS, &witness)],
        );
        assert_eq!(v["state"], json!("artifact"), "{v}");
        assert!(v["witnessed"].as_u64().unwrap() > 0);
    }

    /// Asked of a node with the default settings: both switches unset,
    /// resolved by the plugin's own readers but not from this process's env
    /// or config file, so an operator's settings cannot change the result.
    /// Records to counterparties, Standard History not shared.
    fn ask_by_default(dir: &Path, bytes: &[u8]) -> Outcome {
        ask_with(
            dir,
            bytes,
            crate::share_policy::history_segments_for(None),
            crate::share_policy::shares_standard_history_for(None),
        )
    }

    /// The three requests that carry no record: the two stranger-safe ones,
    /// pinned to the corpus's newest checkpoint, then the Service History,
    /// pinned to its first, which is on a period boundary.
    fn standard_history_requests() -> Vec<Value> {
        let ledger = corpus_ledger();
        let cps = corpus_checkpoints(&ledger, &key());
        let coverage = json!({"expected_pin": cps[1].anchor()});
        vec![
            json!({"subject": {"checkpoints": null}, "coverage": coverage}),
            json!({"subject": {"full_history": null}, "coverage": coverage, "derivation": "history_card/1"}),
            json!({"subject": {"full_history": null}, "coverage": {"expected_pin": cps[0].anchor()},
                   "derivation": crate::service_history::definition_digest()}),
        ]
    }

    /// `served_summary/1`, pinned where it used to be answered: the
    /// corpus's newest checkpoint.
    fn served_summary_request() -> Value {
        let mut request = standard_history_requests()[1].clone();
        request["derivation"] = json!("served_summary/1");
        request
    }

    /// `checkpoints` and `history_card/1` (R-8).
    fn stranger_safe_requests() -> Vec<Value> {
        standard_history_requests()[..2].to_vec()
    }

    /// What a stranger is refused by default though it carries no record:
    /// the Service History, the retired served summary, and a derivation
    /// this node does not have.
    fn withheld_requests() -> Vec<Value> {
        let mut unknown = served_summary_request();
        unknown["derivation"] = json!("unregistered_fold/1");
        vec![
            standard_history_requests()[2].clone(),
            served_summary_request(),
            unknown,
        ]
    }

    /// The refusal of exactly these bytes, now: nothing else goes into it.
    fn refusal_of(bytes: &[u8], reason: Reason) -> Vec<u8> {
        let wire = refusal::sign(&request_digest(bytes), reason, NOW, &key())
            .unwrap()
            .to_json();
        serde_json::to_vec(&wire).unwrap()
    }

    /// PRD T7, the default half (R-8): `service_history/1` or any other
    /// derivation but `history_card/1`, asked by anyone who has not proven
    /// it is a counterparty, is refused `policy_declined`, signed, and the
    /// refusal is
    /// the refusal of the request's own bytes, now, and nothing else: an
    /// unsigned asker naming no id, one naming a counterparty's id, two
    /// signed strangers, a stranger signing while naming a counterparty, and
    /// the same bytes asked of a node that holds nothing at all. (Two askers
    /// never send the same signed bytes; unsigned bytes are the same
    /// whoever sends them, and get the same refusal.)
    #[test]
    fn standard_history_to_a_non_counterparty_is_the_refusal_of_its_own_bytes_whoever_asks() {
        let dir = node(&corpus_ledger());
        let empty = node(&[]);
        for request in withheld_requests() {
            let mut claims_a = request.clone();
            claims_a["requester_id"] = json!("node-a");
            let asks: Vec<Vec<u8>> = vec![
                serde_json::to_vec(&request).unwrap(),
                serde_json::to_vec(&claims_a).unwrap(),
                signed_by("node-y", &request),
                signed_by("node-z", &request),
                signed_by("node-y", &claims_a),
            ];
            for bytes in &asks {
                for ledger in [dir.path(), empty.path()] {
                    let outcome = ask_by_default(ledger, bytes);
                    assert_eq!(
                        outcome.wire_bytes(),
                        Some(refusal_of(bytes, Reason::PolicyDeclined)),
                        "{request}: {outcome:?}"
                    );
                }
            }
        }
    }

    /// A proven node that no record names gets one reason per kind of
    /// request, as the module doc says (#157): `policy_declined` for
    /// Standard History, `not_authorized` for record bodies, under the
    /// default settings.
    #[test]
    fn a_proven_node_no_record_names_gets_one_reason_per_kind_of_request() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let held = node_a_record(&ledger);
        for request in withheld_requests() {
            assert_eq!(
                refused(&ask_by_default(dir.path(), &signed_by("node-z", &request))),
                Some(Reason::PolicyDeclined),
                "{request}"
            );
        }
        let pin = held["coverage"].clone();
        for subject in [
            held["subject"].clone(),
            json!({"correlation": "n-1"}),
            json!({"exchange": "b".repeat(64)}),
        ] {
            let request = json!({"subject": subject, "coverage": pin});
            assert_eq!(
                refused(&ask_by_default(dir.path(), &signed_by("node-z", &request))),
                Some(Reason::NotAuthorized),
                "{subject}"
            );
        }
    }

    /// Two strangers asking the same thing get refusals that differ only
    /// where their requests do: the request digest, and the signature over
    /// it.
    #[test]
    fn two_askers_refusals_differ_only_by_their_own_request() {
        let dir = node(&corpus_ledger());
        for request in withheld_requests() {
            let refusal = |node: &str| match ask_by_default(dir.path(), &signed_by(node, &request))
            {
                Outcome::Refused { wire, .. } => wire,
                other => panic!("{other:?}"),
            };
            let (mut a, mut b) = (refusal("node-y"), refusal("node-z"));
            for wire in [&mut a, &mut b] {
                let members = wire.as_object_mut().unwrap();
                members.remove("request_digest").expect("binds its request");
                members.remove("sig").expect("signed");
            }
            assert_eq!(a, b, "{request}");
        }
    }

    /// The default half's other side: a node that proves it is one some
    /// record names as the other side of an exchange is answered all three.
    /// (Unknown derivations are refused it too, by `derivation_unsupported`.)
    #[test]
    fn a_counterparty_is_still_answered_standard_history() {
        let dir = node(&corpus_ledger());
        for request in standard_history_requests() {
            let bytes = signed_by("node-a", &request);
            let outcome = ask_by_default(dir.path(), &bytes);
            let Outcome::Answered { wire, .. } = &outcome else {
                panic!("{request}: {outcome:?}");
            };
            let verified =
                verify_response(&bytes, wire, &key().verifying_key(), &Default::default());
            assert_eq!(
                verified["state"],
                json!("artifact"),
                "{request}: {verified}"
            );
        }
    }

    /// A node that serves Service History serves no `standard_history/1`
    /// card under its key, to a counterparty or anyone, whatever the
    /// sharing setting (ISH §6.1 item 8), and does not list it.
    #[test]
    fn standard_history_1_is_never_served_beside_service_history() {
        assert!(!crate::commitment::DERIVATIONS.contains(&"standard_history/1"));
        let dir = node(&corpus_ledger());
        let pin = standard_history_requests()[0]["coverage"].clone();
        let request = json!({
            "subject": {"full_history": null},
            "coverage": pin,
            "derivation": crate::service_history::STANDARD_HISTORY_TOKEN,
        });
        for share in [true, false] {
            let bytes = signed_by("node-a", &request);
            let outcome = ask_with(
                dir.path(),
                &bytes,
                crate::share_policy::history_segments_for(None),
                share,
            );
            assert_eq!(
                outcome.wire_bytes(),
                Some(refusal_of(&bytes, Reason::DerivationUnsupported)),
                "share_standard_history={share}: {outcome:?}"
            );
        }
    }

    /// `served_summary/1` is retired (Mesh-LLM/capsules-plugin#106): beside
    /// the weekly Service History cells, the summary less those cells
    /// would give a suppressed week's count. Asked where it used to be
    /// answered, it is refused `derivation_unsupported`, as any derivation
    /// this node does not serve, to a counterparty and, with Standard
    /// History shared, to anyone. With it not shared, any other requester
    /// gets the gate's `policy_declined`, the one refusal a non-counterparty
    /// gets for every such derivation, so it learns nothing of which ones
    /// this node serves. It is not listed.
    #[test]
    fn served_summary_1_is_refused_to_every_requester() {
        assert!(!crate::commitment::DERIVATIONS.contains(&"served_summary/1"));
        let dir = node(&corpus_ledger());
        let request = served_summary_request();
        for share in [true, false] {
            for (asker, bytes) in [
                ("node-a", signed_by("node-a", &request)),
                ("node-z", signed_by("node-z", &request)),
                ("unsigned", serde_json::to_vec(&request).unwrap()),
            ] {
                let reason = if share || asker == "node-a" {
                    Reason::DerivationUnsupported
                } else {
                    Reason::PolicyDeclined
                };
                let outcome = ask_with(
                    dir.path(),
                    &bytes,
                    crate::share_policy::history_segments_for(None),
                    share,
                );
                assert_eq!(
                    outcome.wire_bytes(),
                    Some(refusal_of(&bytes, reason)),
                    "{asker}, share_standard_history={share}: {outcome:?}"
                );
            }
        }
    }

    /// R-8's stranger-safe half: `checkpoints` and `history_card/1` go to
    /// anyone under the default settings, and with record sharing off: an
    /// unsigned asker, one naming a counterparty's id, a proven node no
    /// record names, and a key no host binds. Each answer verifies, and
    /// its artifact is the one a counterparty gets.
    #[test]
    fn a_stranger_is_answered_checkpoints_and_the_history_card() {
        let dir = node(&corpus_ledger());
        let stranger = SigningKey::from_bytes(&[0x77; 32]);
        for request in stranger_safe_requests() {
            let mut claims_a = request.clone();
            claims_a["requester_id"] = json!("node-a");
            let artifact_of = |bytes: &[u8], outcome: Outcome| {
                let Outcome::Answered { wire, .. } = &outcome else {
                    panic!("{request}: {outcome:?}");
                };
                let verified =
                    verify_response(bytes, wire, &key().verifying_key(), &Default::default());
                assert_eq!(
                    verified["state"],
                    json!("artifact"),
                    "{request}: {verified}"
                );
                wire["artifact"].clone()
            };
            let counterparty = signed_by("node-a", &request);
            let expected = artifact_of(&counterparty, ask_by_default(dir.path(), &counterparty));
            for bytes in [
                serde_json::to_vec(&request).unwrap(),
                serde_json::to_vec(&claims_a).unwrap(),
                signed_by("node-z", &request),
                signed_with(&stranger, &request),
            ] {
                assert_eq!(
                    artifact_of(&bytes, ask_by_default(dir.path(), &bytes)),
                    expected,
                    "{request}"
                );
                assert_eq!(
                    artifact_of(&bytes, ask_with(dir.path(), &bytes, "off", false)),
                    expected,
                    "{request}, record sharing off"
                );
            }
        }
    }

    /// Answering a stranger writes nothing to the ledger: no record is
    /// sealed and no checkpoint cut, so asking never grows the log.
    #[test]
    fn answering_a_stranger_never_grows_the_ledger() {
        let dir = node(&corpus_ledger());
        let snapshot = || {
            let mut files: Vec<(std::ffi::OsString, Vec<u8>)> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (e.file_name(), std::fs::read(e.path()).unwrap())
                })
                .collect();
            files.sort();
            files
        };
        let before = snapshot();
        for request in stranger_safe_requests() {
            let outcome = ask_by_default(dir.path(), &signed_by("node-z", &request));
            assert!(matches!(outcome, Outcome::Answered { .. }), "{outcome:?}");
        }
        assert_eq!(snapshot(), before);
    }

    /// One limit for every caller: past the in-flight cap (one process-wide
    /// semaphore, `mesh_evidence_bridge::MAX_IN_FLIGHT_ANSWERS`), a
    /// stranger-safe request is declined alike whoever asks: unsigned, a key
    /// no host binds, a proven stranger or a counterparty. Each gets the
    /// refusal of its own bytes, before the ledger is read.
    #[test]
    fn past_the_in_flight_cap_every_asker_is_declined_alike() {
        let dir = node(&corpus_ledger());
        let key = key();
        let (announced, replay) = (announced(), ReplayCache::default());
        let responder = Responder {
            ledger_dir: dir.path(),
            signing_key: &key,
            now: NOW,
            history_segments: "counterparties",
            share_standard_history: false,
            share_exchange_corroboration: false,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &replay,
            node_id: Some(RESPONDER),
            policy_digest: None,
        };
        let stranger = SigningKey::from_bytes(&[0x77; 32]);
        for request in stranger_safe_requests() {
            for bytes in [
                serde_json::to_vec(&request).unwrap(),
                signed_with(&stranger, &request),
                signed_by("node-z", &request),
                signed_by("node-a", &request),
            ] {
                let reads = evidence_log::index_reads();
                assert_eq!(
                    answer_and_log(&bytes, true, &responder, None).wire_bytes(),
                    Some(refusal_of(&bytes, Reason::PolicyDeclined)),
                    "{request}"
                );
                assert_eq!(evidence_log::index_reads(), reads, "the ledger was read");
            }
        }
    }

    /// A counterparty is a node some record names as the other side, by
    /// its whole id; an empty or absent id is nobody's.
    #[test]
    fn a_counterparty_is_named_by_a_record() {
        let dir = node(&corpus_ledger());
        let key_id = hex::encode(key().verifying_key().to_bytes());
        evidence_log::with_index(dir.path(), &key_id, |index| {
            let one = |id: &str| vec![id.to_string()];
            assert!(is_counterparty(index, &one("node-a")));
            assert!(is_counterparty(index, &one(" node-b ")));
            assert!(!is_counterparty(index, &one("node")));
            assert!(!is_counterparty(index, &one("node-z")));
            assert!(!is_counterparty(index, &one(" ")));
            assert!(!is_counterparty(index, &[]));
            assert!(
                is_counterparty(index, &["node-z".into(), "node-a".into()]),
                "a key bound to several nodes is each of them"
            );
            Ok::<_, std::io::Error>(())
        })
        .unwrap()
        .unwrap();
    }

    /// A deal's steps name no counterparty themselves. The share gate takes
    /// it from the exchange record they are linked to (`deal-links.jsonl`),
    /// so under `counterparties` they go to that exchange's counterparty and
    /// to no one else, and a deal capsule with no link goes to nobody
    /// (Mesh-LLM/capsules-plugin#96). The report is the owner's own and
    /// never leaves, under any policy (#146).
    #[test]
    fn a_deal_capsule_goes_to_the_counterparty_of_the_exchange_it_is_of() {
        let hex = |c: char| c.to_string().repeat(64);
        let exchange = served(
            "node-a",
            "model-x",
            "confirmed",
            "10.000",
            json!({"nonce": "n-9"}),
        );
        let exchange_id = exchange["capsule_id"].as_str().unwrap().to_string();
        let ledger = vec![
            exchange,
            json!({"capsule_id": hex('1'), "deal_id": "deal-0123456789abcdef"}),
            json!({"capsule_id": hex('2'), "action_id": "capsulectl-deal-report"}),
            json!({"capsule_id": hex('3'), "deal_id": "deal-0123456789abcdef"}),
        ];
        let dir = node(&ledger);
        write_jsonl(
            &dir.path().join(evidence_log::DEAL_LINKS_FILE),
            &[
                json!({"capsule_id": hex('1'), "exchange_capsule_id": exchange_id}),
                json!({"capsule_id": hex('2'), "exchange_capsule_id": exchange_id}),
                json!({"capsule_id": "not a capsule id", "exchange_capsule_id": exchange_id}),
            ],
        );
        let key_id = hex::encode(key().verifying_key().to_bytes());
        evidence_log::with_index(dir.path(), &key_id, |index| {
            let who = |id: &str| vec![id.to_string()];
            let (step, report, unlinked) = ([1u64], [2u64], [3u64]);
            // The report is the owner's alone: no policy serves it.
            for policy in ["counterparties", "peers", "off"] {
                assert!(!may_serve_all(index, &report, &who("node-a"), policy));
                assert!(!may_serve_all(index, &[1, 2], &who("node-a"), policy));
            }
            {
                let records = &step[..];
                assert!(may_serve_all(
                    index,
                    records,
                    &who("node-a"),
                    "counterparties"
                ));
                assert!(!may_serve_all(
                    index,
                    records,
                    &who("node-b"),
                    "counterparties"
                ));
                assert!(may_serve_all(index, records, &who("node-b"), "peers"));
                assert!(!may_serve_all(index, records, &who("node-a"), "off"));
                assert!(!may_serve_all(index, records, &[], "peers"));
            }
            // No link: the capsule names nobody, so `counterparties` serves it to no one.
            assert!(!may_serve_all(
                index,
                &unlinked,
                &who("node-a"),
                "counterparties"
            ));
            assert!(!may_serve_all(
                index,
                &unlinked,
                &who("node-b"),
                "counterparties"
            ));
            Ok::<_, std::io::Error>(())
        })
        .unwrap()
        .unwrap();
    }

    fn append_jsonl(path: &Path, lines: &[Value]) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    }

    fn serves(dir: &Path, record: u64, node_id: &str) -> bool {
        let key_id = hex::encode(key().verifying_key().to_bytes());
        let who = vec![node_id.to_string()];
        evidence_log::with_index(dir, &key_id, |index| {
            may_serve_all(index, &[record], &who, "counterparties")
        })
        .unwrap()
    }

    /// The node writes a deal capsule's link, then the capsule. Both appearing
    /// after the node started, the next query names the capsule.
    #[test]
    fn a_deal_link_then_its_capsule_written_later_name_the_counterparty() {
        let hex = |c: char| c.to_string().repeat(64);
        let exchange = served(
            "node-a",
            "model-x",
            "confirmed",
            "10.000",
            json!({"nonce": "n-9"}),
        );
        let exchange_id = exchange["capsule_id"].as_str().unwrap().to_string();
        let dir = node(&[exchange]);
        assert!(serves(dir.path(), 0, "node-a"));
        append_jsonl(
            &dir.path().join(evidence_log::DEAL_LINKS_FILE),
            &[json!({"capsule_id": hex('1'), "exchange_capsule_id": exchange_id})],
        );
        append_jsonl(
            &dir.path().join(evidence_log::CAPSULES_FILE),
            &[json!({"capsule_id": hex('1'), "deal_id": "deal-0123456789abcdef"})],
        );
        assert!(serves(dir.path(), 1, "node-a"));
        assert!(!serves(dir.path(), 1, "node-b"));
    }

    /// A capsule indexed before its link stays unnamed (fail closed) until
    /// the links file is rewritten, which rebuilds the index.
    #[test]
    fn a_deal_capsule_indexed_before_its_link_is_named_after_a_rebuild() {
        let hex = |c: char| c.to_string().repeat(64);
        let exchange = served(
            "node-a",
            "model-x",
            "confirmed",
            "10.000",
            json!({"nonce": "n-9"}),
        );
        let exchange_id = exchange["capsule_id"].as_str().unwrap().to_string();
        let dir = node(&[
            exchange,
            json!({"capsule_id": hex('1'), "deal_id": "deal-0123456789abcdef"}),
        ]);
        let links = dir.path().join(evidence_log::DEAL_LINKS_FILE);
        write_jsonl(
            &links,
            &[json!({"capsule_id": hex('9'), "exchange_capsule_id": exchange_id.clone()})],
        );
        assert!(!serves(dir.path(), 1, "node-a"));
        append_jsonl(
            &links,
            &[json!({"capsule_id": hex('1'), "exchange_capsule_id": exchange_id.clone()})],
        );
        assert!(!serves(dir.path(), 1, "node-a"));
        write_jsonl(
            &links,
            &[json!({"capsule_id": hex('1'), "exchange_capsule_id": exchange_id})],
        );
        assert!(serves(dir.path(), 1, "node-a"));
        assert!(!serves(dir.path(), 1, "node-b"));
    }

    /// A link names a counterparty for a deal capsule only, never over what a
    /// record names itself, and the first link of a capsule stands.
    #[test]
    fn a_deal_link_is_for_deal_capsules_and_the_first_one_stands() {
        let hex = |c: char| c.to_string().repeat(64);
        let by_a = served(
            "node-a",
            "model-x",
            "confirmed",
            "10.000",
            json!({"nonce": "n-1"}),
        );
        let by_b = served(
            "node-b",
            "model-x",
            "confirmed",
            "11.000",
            json!({"nonce": "n-2"}),
        );
        let (id_a, id_b) = (
            by_a["capsule_id"].as_str().unwrap().to_string(),
            by_b["capsule_id"].as_str().unwrap().to_string(),
        );
        let mut deal_served_by_b = served(
            "node-b",
            "model-x",
            "confirmed",
            "12.000",
            json!({"nonce": "n-3"}),
        );
        deal_served_by_b["deal_id"] = json!("deal-0123456789abcdef");
        let deal_b_id = deal_served_by_b["capsule_id"].as_str().unwrap().to_string();
        let dir = node(&[
            by_a,
            by_b,
            json!({"capsule_id": hex('1'), "deal_id": "deal-0123456789abcdef"}),
            json!({"capsule_id": hex('2')}),
            deal_served_by_b,
        ]);
        write_jsonl(
            &dir.path().join(evidence_log::DEAL_LINKS_FILE),
            &[
                json!({"capsule_id": deal_b_id, "exchange_capsule_id": id_a}),
                json!({"capsule_id": hex('1'), "exchange_capsule_id": id_a}),
                json!({"capsule_id": hex('1'), "exchange_capsule_id": id_b}),
                json!({"capsule_id": hex('2'), "exchange_capsule_id": id_a}),
                json!({"capsule_id": id_b, "exchange_capsule_id": id_a}),
            ],
        );
        assert!(serves(dir.path(), 2, "node-a"));
        assert!(!serves(dir.path(), 2, "node-b"));
        // Not a deal capsule: the link names nobody. A record that names its
        // own counterparty keeps it.
        assert!(!serves(dir.path(), 3, "node-a"));
        assert!(serves(dir.path(), 1, "node-b"));
        assert!(!serves(dir.path(), 1, "node-a"));
        // A deal-marked record that names its own counterparty keeps it
        // against a link to another exchange.
        assert!(serves(dir.path(), 4, "node-b"));
        assert!(!serves(dir.path(), 4, "node-a"));
    }

    /// The writer appends a capsule's link and then the capsule between the
    /// refresh's read of the capsules and its read of the links. The capsule
    /// is not in this refresh, and the next one names it.
    #[test]
    fn a_deal_capsule_written_while_the_index_refreshes_is_named() {
        let hex = |c: char| c.to_string().repeat(64);
        let exchange = served(
            "node-a",
            "model-x",
            "confirmed",
            "10.000",
            json!({"nonce": "n-9"}),
        );
        let exchange_id = exchange["capsule_id"].as_str().unwrap().to_string();
        let dir = node(&[exchange]);
        let key_id = hex::encode(key().verifying_key().to_bytes());
        let (links, capsules) = (
            dir.path().join(evidence_log::DEAL_LINKS_FILE),
            dir.path().join(evidence_log::CAPSULES_FILE),
        );
        evidence_log::with_index(dir.path(), &key_id, |_| ()).unwrap();
        evidence_log::tests_between_reads::set(move || {
            append_jsonl(
                &links,
                &[json!({"capsule_id": hex('1'), "exchange_capsule_id": exchange_id})],
            );
            append_jsonl(
                &capsules,
                &[json!({"capsule_id": hex('1'), "deal_id": "deal-0123456789abcdef"})],
            );
        });
        evidence_log::with_index(dir.path(), &key_id, |_| ()).unwrap();
        assert!(serves(dir.path(), 1, "node-a"));
        assert!(!serves(dir.path(), 1, "node-b"));
    }

    /// `share_standard_history` on restores what every node did before:
    /// Standard History to anyone, signed or not, named or not.
    #[test]
    fn sharing_standard_history_answers_anyone_as_before() {
        let dir = node(&corpus_ledger());
        for request in standard_history_requests() {
            let mut names_z = request.clone();
            names_z["requester_id"] = json!("node-z");
            for bytes in [
                serde_json::to_vec(&request).unwrap(),
                serde_json::to_vec(&names_z).unwrap(),
                signed_by("node-z", &request),
            ] {
                let outcome = ask_with(dir.path(), &bytes, "counterparties", true);
                assert!(
                    matches!(outcome, Outcome::Answered { .. }),
                    "{request}: {outcome:?}"
                );
            }
        }
    }

    /// The switch governs Standard History only: record bodies stay under
    /// `share_history_segments`, whichever way it is set. node-b proves who
    /// it is and is some record's counterparty, just not this one's.
    #[test]
    fn sharing_standard_history_never_releases_a_record() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let record = record_request(&ledger, 0);
        let outcome = ask_with(
            dir.path(),
            &signed_by("node-b", &record),
            "counterparties",
            true,
        );
        assert_eq!(refused(&outcome), Some(Reason::NotAuthorized));
    }

    /// A request for record `i` of `ledger`, pinned to its newest checkpoint.
    fn record_request(ledger: &[Value], i: usize) -> Value {
        let pin = corpus_checkpoints(ledger, &key())[1].anchor();
        json!({
            "subject": {"record": ledger[i]["capsule_id"]},
            "coverage": {"expected_pin": pin},
        })
    }

    /// The corpus record node-a is the counterparty of, and a request for it.
    fn node_a_record(ledger: &[Value]) -> Value {
        let dir = node(ledger);
        let key_id = hex::encode(key().verifying_key().to_bytes());
        let i = evidence_log::with_index(dir.path(), &key_id, |index| {
            index
                .leaves
                .iter()
                .position(|leaf| leaf.counterparty.as_deref() == Some("node-a"))
        })
        .unwrap()
        .expect("the corpus names node-a");
        record_request(ledger, i)
    }

    // -----------------------------------------------------------------------
    // Who asks (requester_auth): the ruling's tests, T3 and D3.
    // -----------------------------------------------------------------------

    /// A valid signed request from the record's counterparty is answered,
    /// and the answer verifies.
    #[test]
    fn a_signed_request_from_the_counterparty_is_answered() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let bytes = signed_by("node-a", &node_a_record(&ledger));
        let Outcome::Answered { wire, .. } = ask_by_default(dir.path(), &bytes) else {
            panic!("answered");
        };
        let verified = verify_response(&bytes, &wire, &key().verifying_key(), &Default::default());
        assert_eq!(verified["state"], json!("artifact"), "{verified}");
    }

    /// `request` for node-a's record, asked of a node whose registry is
    /// `announced` and `configured`, under the default sharing settings.
    fn ask_keyed(
        dir: &Path,
        bytes: &[u8],
        announced: &std::collections::BTreeMap<String, String>,
        configured: Option<&str>,
    ) -> Outcome {
        let key = key();
        answer(
            bytes,
            &Responder {
                ledger_dir: dir,
                signing_key: &key,
                now: NOW,
                history_segments: crate::share_policy::history_segments_for(None),
                share_standard_history: crate::share_policy::shares_standard_history_for(None),
                share_exchange_corroboration: false,
                keys: Keys {
                    announced,
                    configured,
                    own_key: None,
                },
                replay: &ReplayCache::default(),
                node_id: Some(RESPONDER),
                policy_digest: None,
            },
        )
    }

    /// D-34: a request is accepted on the asker's evidence key, not on the
    /// peer id it asks under. node-a's key, announced again under a new id
    /// (its transport id rotated) and stating that id, is still the
    /// counterparty the record names.
    #[test]
    fn a_counterpartys_key_asking_under_a_new_transport_id_is_answered() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let ka = key_id_of(&asker_key("node-a"));
        let rotated = std::collections::BTreeMap::from([
            ("node-a".to_string(), ka.clone()),
            ("node-a-restarted".to_string(), ka),
        ]);
        let mut request = node_a_record(&ledger);
        request["requester_id"] = json!("node-a-restarted");
        let bytes = signed_by("node-a", &request);
        assert!(
            matches!(
                ask_keyed(dir.path(), &bytes, &rotated, None),
                Outcome::Answered { .. }
            ),
            "the key's every node is the asker"
        );
        let only_new = std::collections::BTreeMap::from([(
            "node-a-restarted".to_string(),
            key_id_of(&asker_key("node-a")),
        )]);
        assert_eq!(
            refused(&ask_keyed(dir.path(), &bytes, &only_new, None)),
            Some(Reason::NotAuthorized),
            "a key bound to no node a record names is no counterparty"
        );
    }

    /// The `CAPSULES_PEER_KEYS` stopgap: a key the operator lists, with no
    /// host announcing it, authenticates a request as the node its entry
    /// names (the Muse VM, which has no stable transport id).
    #[test]
    fn an_operator_listed_key_is_the_counterparty_its_entry_names() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let bytes = signed_by("node-a", &node_a_record(&ledger));
        let none = std::collections::BTreeMap::new();
        assert_eq!(
            refused(&ask_keyed(dir.path(), &bytes, &none, None)),
            Some(Reason::NotAuthorized),
            "no registry: no counterparty"
        );
        let configured = format!(r#"{{"node-a": "{}"}}"#, key_id_of(&asker_key("node-a")));
        assert!(matches!(
            ask_keyed(dir.path(), &bytes, &none, Some(&configured)),
            Outcome::Answered { .. }
        ));
    }

    /// A key no host announced and no operator listed is accepted when the
    /// request carries a controller declaration binding it to an accepted
    /// key: it asks as that key's nodes. A declaration anchored on this
    /// node's own key binds nothing (Sherlock2's door condition: a binding
    /// never makes a different counterparty).
    #[test]
    fn a_controller_declaration_carries_acceptance_to_the_key_it_binds() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let new_key = SigningKey::from_bytes(&[0x7c; 32]);
        let announced = announced();
        let declared = |anchor: &SigningKey, until: &str| {
            let mut request = node_a_record(&ledger);
            request[crate::controller_binding::MEMBER] = crate::controller_binding::bind_for_test(
                anchor,
                &new_key,
                "2026-01-01T00:00:00Z",
                until,
            );
            signed_with(&new_key, &request)
        };
        assert_eq!(
            refused(&ask_keyed(
                dir.path(),
                &signed_with(&new_key, &node_a_record(&ledger)),
                &announced,
                None
            )),
            Some(Reason::NotAuthorized),
            "no declaration: an unknown key"
        );
        let bound = declared(&asker_key("node-a"), "2030-01-01T00:00:00Z");
        assert!(matches!(
            ask_keyed(dir.path(), &bound, &announced, None),
            Outcome::Answered { .. }
        ));
        let expired = declared(&asker_key("node-a"), "2026-02-01T00:00:00Z");
        assert_eq!(
            refused(&ask_keyed(dir.path(), &expired, &announced, None)),
            Some(Reason::NotAuthorized),
            "a declaration out of its window is not used"
        );
        let mut with_self = announced.clone();
        with_self.insert(RESPONDER.to_string(), key_id_of(&key()));
        let on_own = declared(&key(), "2030-01-01T00:00:00Z");
        assert_eq!(
            refused(&ask_keyed(dir.path(), &on_own, &with_self, None)),
            Some(Reason::NotAuthorized),
            "a declaration anchored on this node's own key is not used"
        );
    }

    /// evidencebook#69 finding 1, end to end: this node seals a host-served
    /// exchange node-a asked for (the host names node-a as
    /// `requested_by_node_id`), and under the default settings node-a's
    /// signed request for that record is answered with it. node-b, signing
    /// for itself while stating node-a's `requester_id` (T3's spoof), is
    /// refused `not_authorized` before the ledger is read.
    #[test]
    fn a_host_served_record_goes_to_the_peer_that_asked_and_not_to_a_spoofer() {
        use crate::capsule_emit::{CapsuleState, HostProvenance, ObservedHostExchange};
        use crate::lifecycle_channel::DispatchPath;
        use crate::producer::anchor::AnchorClient;
        use crate::producer::checkpoint::{CheckpointCadenceConfig, CheckpointState};

        let data = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(data.path(), RESPONDER).unwrap();
        let emitted = state
            .emit_for_observed_host_exchange(&ObservedHostExchange {
                model: "m",
                exchange_id: Some("e-1"),
                request_digest: Some(&"4b".repeat(32)),
                response_digest: Some(&"33".repeat(32)),
                tool_calls_digest: None,
                reasoning_digest: None,
                usage: None,
                host_provenance: HostProvenance {
                    served_by_node_id: Some(RESPONDER.to_string()),
                    weights_digest: Some("ab".repeat(32)),
                    requested_by_node_id: Some("node-a".to_string()),
                    ..HostProvenance::default()
                },
                dispatch_path: DispatchPath::RawProxy,
                nonce: None,
                peer_capsule_id: None,
                peer_capsule_id_provenance: None,
                twin_bracket_id: None,
                response_text_digest: None,
            })
            .unwrap();
        let (mut checkpoints, _) = CheckpointState::load(
            state.ledger_dir(),
            RESPONDER,
            CheckpointCadenceConfig::default(),
        )
        .unwrap();
        let covering = checkpoints
            .checkpoint_covering(
                &emitted.capsule_id,
                state.signing_key(),
                &AnchorClient::new("http://127.0.0.1:1"),
            )
            .unwrap();
        // An anchor is pinned by the SHA-256 of its checkpoint's COSE
        // statement, as written beside the record in checkpoints.jsonl.
        let line: Value = std::fs::read_to_string(state.ledger_dir().join("checkpoints.jsonl"))
            .unwrap()
            .lines()
            .last()
            .map(|l| serde_json::from_str(l).unwrap())
            .unwrap();
        assert_eq!(line["mmr_size"], json!(covering.checkpoint.mmr_size));
        let statement = hex::decode(line["checkpoint_cose"].as_str().unwrap()).unwrap();
        let request = json!({
            "subject": {"record": emitted.capsule_id},
            "coverage": {"expected_pin": hex::encode(Sha256::digest(&statement))},
        });
        let announced = announced();
        let ask_node = |ledger_dir: &Path, bytes: &[u8]| {
            answer(
                bytes,
                &Responder {
                    ledger_dir,
                    signing_key: state.signing_key(),
                    now: NOW,
                    history_segments: crate::share_policy::history_segments_for(None),
                    share_standard_history: crate::share_policy::shares_standard_history_for(None),
                    share_exchange_corroboration: false,
                    keys: Keys {
                        announced: &announced,
                        configured: None,
                        own_key: None,
                    },
                    replay: &ReplayCache::default(),
                    node_id: Some(RESPONDER),
                    policy_digest: None,
                },
            )
        };

        let bytes = signed_by("node-a", &request);
        let outcome = ask_node(state.ledger_dir(), &bytes);
        let Outcome::Answered { wire, .. } = outcome else {
            panic!("node-a asked for the record of its own exchange: {outcome:?}");
        };
        let verified = verify_response(
            &bytes,
            &wire,
            &state.signing_key().verifying_key(),
            &Default::default(),
        );
        assert_eq!(verified["state"], json!("artifact"), "{verified}");

        let mut spoof = request.clone();
        spoof["requester_id"] = json!("node-a");
        let spoof = signed_by("node-b", &spoof);
        let reads = evidence_log::index_reads();
        assert_eq!(
            refused(&ask_node(state.ledger_dir(), &spoof)),
            Some(Reason::NotAuthorized)
        );
        assert_eq!(evidence_log::index_reads(), reads, "the ledger was read");
    }

    /// One member changed after signing, and the signature no longer covers
    /// the request: refused as an asker that proved nothing, `not_authorized`
    /// for a record and `policy_declined` once the change makes it Standard
    /// History. A signature that fails is refused even for a stranger-safe
    /// answer, which an unsigned request would get.
    #[test]
    fn a_member_changed_after_signing_is_refused() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut request = node_a_record(&ledger);
        request["nonce"] = json!("nonce-1");
        let signed: Value = serde_json::from_slice(&signed_by("node-a", &request)).unwrap();
        // Each change alone would still be answered to node-a (or refused for
        // another reason than who asks) if the signature were not checked.
        let changes: Vec<(&str, Value, Reason)> = vec![
            (
                "subject",
                json!({"correlation": "n-1"}),
                Reason::NotAuthorized,
            ),
            (
                "derivation",
                json!(crate::service_history::definition_digest()),
                Reason::PolicyDeclined,
            ),
            ("derivation", json!("history_card/1"), Reason::NotAuthorized),
            (
                "coverage",
                json!({"min_freshness": 1}),
                Reason::NotAuthorized,
            ),
            ("nonce", json!("nonce-2"), Reason::NotAuthorized),
            (
                "deadline",
                json!("2026-09-29T00:02:01Z"),
                Reason::NotAuthorized,
            ),
            ("route", json!("r"), Reason::NotAuthorized),
        ];
        for (member, value, reason) in changes {
            let mut changed = signed.clone();
            changed[member] = value;
            let bytes = serde_json::to_vec(&changed).unwrap();
            assert_eq!(
                refused(&ask_by_default(dir.path(), &bytes)),
                Some(reason),
                "{member}"
            );
        }
        let bytes = serde_json::to_vec(&signed).unwrap();
        assert!(matches!(
            ask_by_default(dir.path(), &bytes),
            Outcome::Answered { .. }
        ));
    }

    /// The same signed request twice within its deadline: the second is
    /// refused `not_authorized`.
    #[test]
    fn a_replayed_nonce_is_not_authorized() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let bytes = signed_by("node-a", &node_a_record(&ledger));
        let replay = ReplayCache::default();
        let segments = crate::share_policy::history_segments_for(None);
        assert!(matches!(
            ask_cached(dir.path(), &bytes, segments, false, &replay),
            Outcome::Answered { .. }
        ));
        assert_eq!(
            refused(&ask_cached(dir.path(), &bytes, segments, false, &replay)),
            Some(Reason::NotAuthorized)
        );
    }

    /// A signed request whose deadline has passed is `deadline_unmet`; one
    /// whose deadline is further ahead than the window is `not_authorized`.
    #[test]
    fn a_deadline_outside_the_window_is_refused() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut request = node_a_record(&ledger);
        request["deadline"] = json!("2026-09-28T23:59:59Z");
        assert_eq!(
            refused(&ask_by_default(dir.path(), &signed_by("node-a", &request))),
            Some(Reason::DeadlineUnmet)
        );
        request["deadline"] = json!("2026-09-29T00:05:01Z");
        assert_eq!(
            refused(&ask_by_default(dir.path(), &signed_by("node-a", &request))),
            Some(Reason::NotAuthorized)
        );
        request["deadline"] = json!("2026-09-29T00:05:00Z");
        assert!(matches!(
            ask_by_default(dir.path(), &signed_by("node-a", &request)),
            Outcome::Answered { .. }
        ));
    }

    /// A valid signature under a key no host announced (ruling addendum §2):
    /// where an unsigned request would be answered, it is answered exactly as
    /// one, the same artifact and nothing more, and the log says `unbound`
    /// with no node. Where the answer needs an identity (a record, under
    /// every setting) it is refused, before the ledger is read.
    #[test]
    fn an_unbound_key_reads_as_unsigned_only_where_no_identity_is_needed() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let stranger = SigningKey::from_bytes(&[0x77; 32]);
        let record = node_a_record(&ledger);
        let unsigned = serde_json::to_vec(&record).unwrap();
        let unbound = signed_with(&stranger, &record);
        let artifact = |outcome: Outcome| match outcome {
            Outcome::Answered { wire, .. } => wire["artifact"].clone(),
            other => panic!("{other:?}"),
        };
        // A record needs an identity under every setting, `peers` included.
        for bytes in [&unbound, &unsigned] {
            let reads = evidence_log::index_reads();
            assert_eq!(
                refused(&ask_with(dir.path(), bytes, "peers", false)),
                Some(Reason::NotAuthorized),
                "a record under peers"
            );
            assert_eq!(
                evidence_log::index_reads(),
                reads,
                "refused before the ledger is read"
            );
        }
        for request in standard_history_requests() {
            let unbound = signed_with(&stranger, &request);
            let unsigned = serde_json::to_vec(&request).unwrap();
            assert_eq!(
                artifact(ask_with(dir.path(), &unbound, "counterparties", true)),
                artifact(ask_with(dir.path(), &unsigned, "counterparties", true)),
                "Standard History shared: the unsigned answer, {request}"
            );
        }
        for request in withheld_requests() {
            let unbound = signed_with(&stranger, &request);
            let reads = evidence_log::index_reads();
            assert_eq!(
                refused(&ask_by_default(dir.path(), &unbound)),
                Some(Reason::PolicyDeclined),
                "Standard History not shared: {request}"
            );
            assert_eq!(
                evidence_log::index_reads(),
                reads,
                "refused before the ledger is read"
            );
        }
        let reads = evidence_log::index_reads();
        assert_eq!(
            refused(&ask_by_default(dir.path(), &unbound)),
            Some(Reason::NotAuthorized),
            "a record under counterparties"
        );
        assert_eq!(
            evidence_log::index_reads(),
            reads,
            "refused before the ledger is read"
        );

        let log = tempfile::tempdir().unwrap();
        let key = key();
        let (announced, replay) = (announced(), ReplayCache::default());
        let responder = Responder {
            ledger_dir: dir.path(),
            signing_key: &key,
            now: NOW,
            history_segments: "counterparties",
            share_standard_history: true,
            share_exchange_corroboration: false,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &replay,
            node_id: Some(RESPONDER),
            policy_digest: None,
        };
        let history = signed_with(&stranger, &standard_history_requests()[2]);
        let outcome = answer_and_log(&history, false, &responder, Some(log.path()));
        assert!(matches!(outcome, Outcome::Answered { .. }));
        let text = std::fs::read_to_string(log.path().join(received::RECEIVED_LOG_FILE)).unwrap();
        let line: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["principal_key_id"], json!(key_id_of(&stranger)));
        assert_eq!(line["principal_binding"], json!("unbound"));
        assert_eq!(line["principal_node_id"], Value::Null);
        assert_eq!(line["audience"], json!(RESPONDER));
        assert_eq!(line["replay"], json!("checked"));
    }

    /// The unbound pool full of live nonces (ruling u290 §2): a validly
    /// signed request under a key no host announced is answered as an
    /// unsigned one would be (here the Service History, shared), not refused, and logged `unbound` with
    /// `replay` `unchecked`. A replay the pool still holds is refused, and a
    /// bound key's replay is refused whatever that pool holds.
    #[test]
    fn a_full_unbound_pool_answers_as_unsigned_and_still_refuses_a_replay() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let stranger = SigningKey::from_bytes(&[0x77; 32]);
        let record = node_a_record(&ledger);
        // Where no identity is needed: the Service History, shared.
        let history = standard_history_requests()[2].clone();
        let unsigned = serde_json::to_vec(&history).unwrap();
        let held = signed_with(&stranger, &history);
        let bound = signed_by("node-a", &record);
        let (key, announced, replay) = (key(), announced(), ReplayCache::default());
        let ask = |bytes: &[u8], shared: bool, log: Option<&Path>| {
            let responder = Responder {
                ledger_dir: dir.path(),
                signing_key: &key,
                now: NOW,
                history_segments: "counterparties",
                share_standard_history: shared,
                share_exchange_corroboration: false,
                keys: Keys {
                    announced: &announced,
                    configured: None,
                    own_key: None,
                },
                replay: &replay,
                node_id: Some(RESPONDER),
                policy_digest: None,
            };
            answer_and_log(bytes, false, &responder, log)
        };
        let artifact = |outcome: Outcome| match outcome {
            Outcome::Answered { wire, .. } => wire["artifact"].clone(),
            other => panic!("{other:?}"),
        };
        let expected = artifact(ask(&unsigned, true, None));
        assert_eq!(artifact(ask(&held, true, None)), expected);
        assert!(matches!(ask(&bound, false, None), Outcome::Answered { .. }));
        let now = parse_utc(NOW).unwrap().seconds;
        for i in 1..requester_auth::MAX_UNBOUND_NONCES {
            assert_eq!(
                replay.first_use(&format!("filler-{i}"), "n", now + 60, now, false),
                requester_auth::Use::First
            );
        }

        let log = tempfile::tempdir().unwrap();
        let fresh = signed_with(&stranger, &history);
        assert_eq!(
            artifact(ask(&fresh, true, Some(log.path()))),
            expected,
            "answered as unsigned, not refused"
        );
        let text = std::fs::read_to_string(log.path().join(received::RECEIVED_LOG_FILE)).unwrap();
        let line: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["principal_key_id"], json!(key_id_of(&stranger)));
        assert_eq!(line["principal_binding"], json!("unbound"));
        assert_eq!(line["replay"], json!("unchecked"));
        assert_eq!(
            refused(&ask(&held, true, None)),
            Some(Reason::NotAuthorized),
            "a replay the pool holds"
        );
        assert_eq!(
            refused(&ask(&bound, false, None)),
            Some(Reason::NotAuthorized),
            "a bound key's replay"
        );
        assert_eq!(
            refused(&ask(&signed_with(&stranger, &record), false, None)),
            Some(Reason::NotAuthorized),
            "still nothing where the answer needs an identity"
        );
    }

    /// A signed request with no `audience` is `request_malformed`, before
    /// anything else, whatever the settings.
    #[test]
    fn a_signed_request_without_an_audience_is_malformed() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut signed: Value =
            serde_json::from_slice(&signed_by("node-a", &node_a_record(&ledger))).unwrap();
        signed.as_object_mut().unwrap().remove("audience");
        let bytes = serde_json::to_vec(&signed).unwrap();
        for segments in ["counterparties", "peers", "off"] {
            assert_eq!(
                refused(&ask_with(dir.path(), &bytes, segments, true)),
                Some(Reason::RequestMalformed),
                "{segments}"
            );
        }
    }

    /// A request naming a profile this node does not implement, or a
    /// `profile` that is not text, is refused `request_malformed` (profile
    /// §3.3 step 4), never answered as `evidence-interop/0`. One naming
    /// `evidence-interop/0`, or none, is answered under it.
    #[test]
    fn a_request_for_a_profile_not_implemented_is_malformed() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let with_profile = |profile: Value| {
            let mut req: Value = serde_json::from_slice(CHECKPOINTS).unwrap();
            req["profile"] = profile;
            serde_json::to_vec(&req).unwrap()
        };
        for profile in [json!("evidence-interop/2"), json!(""), json!(0)] {
            assert_eq!(
                refused(&ask(dir.path(), &with_profile(profile.clone()), "peers")),
                Some(Reason::RequestMalformed),
                "{profile}"
            );
        }
        // Each identifier this node implements is answered under itself
        // (IP §3.3); a request with none asks for evidence-interop/0.
        for (bytes, answered_under) in [
            (
                with_profile(json!("evidence-interop/0")),
                "evidence-interop/0",
            ),
            (CHECKPOINTS.to_vec(), "evidence-interop/0"),
            (
                with_profile(json!("evidence-interop/1")),
                "evidence-interop/1",
            ),
        ] {
            let Outcome::Answered { wire, .. } = ask(dir.path(), &bytes, "peers") else {
                panic!("answered");
            };
            assert_eq!(wire["profile"], json!(answered_under));
        }
    }

    /// node-a's request for its own record, addressed here but signed for
    /// another channel (a `ledger-fetch/1` fetch, a referee's `adjudicate`),
    /// is refused `not_authorized` before the ledger is read, even where an
    /// unsigned request would be answered: the signature fails on the
    /// Evidence Request's tag (ruling u338), and a failed signature is never
    /// read as unsigned. MUTANT: one tag shared by every channel and it is
    /// answered.
    #[test]
    fn a_request_signed_for_another_channel_is_refused_before_the_ledger_is_read() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let record = node_a_record(&ledger);
        for channel in [
            requester_auth::Channel::LedgerFetch,
            requester_auth::Channel::RefereeAdjudicate,
        ] {
            let mut request = record.clone();
            requester_auth::sign(
                channel,
                &mut request,
                &asker_key("node-a"),
                now(),
                RESPONDER,
            );
            let bytes = serde_json::to_vec(&request).unwrap();
            for segments in ["counterparties", "peers"] {
                let reads = evidence_log::index_reads();
                let outcome = ask_with(dir.path(), &bytes, segments, false);
                assert_eq!(evidence_log::index_reads(), reads, "the ledger was read");
                assert_eq!(
                    outcome.wire_bytes(),
                    Some(refusal_of(&bytes, Reason::NotAuthorized)),
                    "{channel:?} ({segments})"
                );
            }
        }
        assert!(matches!(
            ask_by_default(dir.path(), &signed_by("node-a", &record)),
            Outcome::Answered { .. }
        ));
    }

    /// The relay (ruling addendum §1): node-a's request to node-x, forwarded
    /// by node-x to this node, names node-x as its audience. It is refused
    /// `not_authorized` before the ledger is read, even where an unsigned
    /// request would be answered. Addressed to this node, it is answered.
    #[test]
    fn a_request_addressed_to_another_node_is_refused_before_the_ledger_is_read() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let record = node_a_record(&ledger);
        let mut to_x = record.clone();
        to_x["nonce"] = json!("relayed");
        requester_auth::sign(
            requester_auth::Channel::EvidenceRequest,
            &mut to_x,
            &asker_key("node-a"),
            now(),
            "node-x",
        );
        let to_x = serde_json::to_vec(&to_x).unwrap();
        for segments in ["counterparties", "peers"] {
            let reads = evidence_log::index_reads();
            let outcome = ask_with(dir.path(), &to_x, segments, false);
            assert_eq!(evidence_log::index_reads(), reads, "the ledger was read");
            assert_eq!(
                outcome.wire_bytes(),
                Some(refusal_of(&to_x, Reason::NotAuthorized)),
                "{segments}"
            );
        }
        assert!(matches!(
            ask_by_default(dir.path(), &signed_by("node-a", &record)),
            Outcome::Answered { .. }
        ));
        // A node that does not know its own id yet is no signed request's
        // audience.
        let key = key();
        let (announced, replay) = (announced(), ReplayCache::default());
        let responder = Responder {
            ledger_dir: dir.path(),
            signing_key: &key,
            now: NOW,
            history_segments: "peers",
            share_standard_history: true,
            share_exchange_corroboration: false,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &replay,
            node_id: None,
            policy_digest: None,
        };
        assert_eq!(
            refused(&answer(&signed_by("node-a", &record), &responder)),
            Some(Reason::NotAuthorized)
        );
    }

    /// What is never read as unsigned (ruling addendum §2): under `peers`,
    /// where an unsigned request is answered, each of these is still refused,
    /// signed by a bound key and by an unbound one alike. (A malformed
    /// `requester_auth`, a missing audience and a passed deadline are refused
    /// before the signature is looked at; the u289 hand mutants N1 and N2
    /// show those two rules bite.)
    #[test]
    fn a_failed_request_is_never_answered_as_unsigned() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        // Where an unsigned request is answered: the Service History, shared.
        let request = standard_history_requests()[2].clone();
        let stranger = SigningKey::from_bytes(&[0x77; 32]);
        for key in [asker_key("node-z"), stranger] {
            let signed: Value = serde_json::from_slice(&signed_with(&key, &request)).unwrap();
            let with = |member: &str, value: Value| {
                let mut r = signed.clone();
                r[member] = value;
                serde_json::to_vec(&r).unwrap()
            };
            let resign = |member: &str, value: Value| {
                let mut r = request.clone();
                r[member] = value;
                signed_with(&key, &r)
            };
            let mut no_audience = signed.clone();
            no_audience.as_object_mut().unwrap().remove("audience");
            let mut to_x = request.clone();
            requester_auth::sign(
                requester_auth::Channel::EvidenceRequest,
                &mut to_x,
                &key,
                now(),
                "node-x",
            );
            let cases: Vec<(&str, Vec<u8>, Reason)> = vec![
                (
                    "malformed requester_auth",
                    with("requester_auth", json!({"key_id": "ab"})),
                    Reason::RequestMalformed,
                ),
                (
                    "no audience",
                    serde_json::to_vec(&no_audience).unwrap(),
                    Reason::RequestMalformed,
                ),
                (
                    "deadline passed",
                    resign("deadline", json!("2026-09-28T23:59:59Z")),
                    Reason::DeadlineUnmet,
                ),
                (
                    "deadline outside the window",
                    resign("deadline", json!("2026-09-29T00:05:01Z")),
                    Reason::NotAuthorized,
                ),
                (
                    "bad signature",
                    with("nonce", json!("not-the-signed-one")),
                    Reason::NotAuthorized,
                ),
                (
                    "audience mismatch",
                    serde_json::to_vec(&to_x).unwrap(),
                    Reason::NotAuthorized,
                ),
            ];
            for (what, bytes, reason) in cases {
                assert_eq!(
                    refused(&ask_with(dir.path(), &bytes, "peers", true)),
                    Some(reason),
                    "{what}"
                );
            }
            // A replay: the first is answered, the second refused.
            let bytes = serde_json::to_vec(&signed).unwrap();
            let replay = ReplayCache::default();
            assert!(matches!(
                ask_cached(dir.path(), &bytes, "peers", true, &replay),
                Outcome::Answered { .. }
            ));
            assert_eq!(
                refused(&ask_cached(dir.path(), &bytes, "peers", true, &replay)),
                Some(Reason::NotAuthorized),
                "replay"
            );
        }
    }

    /// A node announcing node-a's public key as its own does not shut node-a
    /// out: node-a's request, signed and naming node-a, is still node-a's.
    /// The same signature naming no node is bound to neither, and naming a
    /// third node is a false claim, refused even under `peers`.
    #[test]
    fn a_node_announcing_another_nodes_key_does_not_unbind_it() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut announced = announced();
        announced.insert("node-m".into(), key_id_of(&asker_key("node-a")));
        let key = key();
        let ask = |bytes: &[u8], segments: &str| {
            let replay = ReplayCache::default();
            answer(
                bytes,
                &Responder {
                    ledger_dir: dir.path(),
                    signing_key: &key,
                    now: NOW,
                    history_segments: segments,
                    share_standard_history: false,
                    share_exchange_corroboration: false,
                    keys: Keys {
                        announced: &announced,
                        configured: None,
                        own_key: None,
                    },
                    replay: &replay,
                    node_id: Some(RESPONDER),
                    policy_digest: None,
                },
            )
        };
        let mut request = node_a_record(&ledger);
        assert_eq!(
            refused(&ask(&signed_by("node-a", &request), "counterparties")),
            Some(Reason::NotAuthorized),
            "naming no node: bound to neither"
        );
        request["requester_id"] = json!("node-a");
        assert!(matches!(
            ask(&signed_by("node-a", &request), "counterparties"),
            Outcome::Answered { .. }
        ));
        request["requester_id"] = json!("node-z");
        assert_eq!(
            refused(&ask(&signed_by("node-a", &request), "peers")),
            Some(Reason::NotAuthorized),
            "naming neither node: a false claim, never read as unsigned"
        );
    }

    /// A node stating another node's id under its own bound key is refused
    /// under `peers` too: a false claim is never read as unsigned.
    #[test]
    fn a_false_claim_is_refused_even_where_unsigned_is_answered() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut request = record_request(&ledger, 0);
        request["requester_id"] = json!("node-a");
        assert_eq!(
            refused(&ask_with(
                dir.path(),
                &signed_by("node-z", &request),
                "peers",
                true
            )),
            Some(Reason::NotAuthorized)
        );
    }

    /// An unsigned request may carry an `audience`; it is ignored there, as
    /// any member an unsigned request carries that no check reads.
    #[test]
    fn an_unsigned_request_naming_another_audience_is_answered_as_unsigned() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut request = stranger_safe_requests()[0].clone();
        request["audience"] = json!("node-x");
        assert!(matches!(
            ask_with(
                dir.path(),
                &serde_json::to_vec(&request).unwrap(),
                "counterparties",
                false
            ),
            Outcome::Answered { .. }
        ));
    }

    /// `requester_auth` with a 63-hex key is `request_malformed`, as is a
    /// signed request with no nonce.
    #[test]
    fn a_malformed_requester_auth_is_request_malformed() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut signed: Value =
            serde_json::from_slice(&signed_by("node-a", &node_a_record(&ledger))).unwrap();
        let mut short = signed.clone();
        let key_id = short["requester_auth"]["key_id"].as_str().unwrap()[1..].to_string();
        short["requester_auth"]["key_id"] = json!(key_id);
        assert_eq!(
            refused(&ask_by_default(
                dir.path(),
                &serde_json::to_vec(&short).unwrap()
            )),
            Some(Reason::RequestMalformed)
        );
        signed.as_object_mut().unwrap().remove("nonce");
        assert_eq!(
            refused(&ask_by_default(
                dir.path(),
                &serde_json::to_vec(&signed).unwrap()
            )),
            Some(Reason::RequestMalformed)
        );
    }

    /// A signature over the same map without the domain tag does not verify.
    #[test]
    fn a_signature_without_the_domain_tag_is_not_authorized() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut request = node_a_record(&ledger);
        request["nonce"] = json!("nonce-1");
        request["deadline"] = json!("2026-09-29T00:02:00Z");
        request["audience"] = json!(RESPONDER);
        let body = jcs::to_string(&request).unwrap();
        let a = asker_key("node-a");
        request["requester_auth"] = json!({
            "key_id": key_id_of(&a),
            "sig": hex::encode(a.sign(body.as_bytes()).to_bytes()),
        });
        let bytes = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            refused(&ask_by_default(dir.path(), &bytes)),
            Some(Reason::NotAuthorized)
        );
    }

    /// An unsigned request for a record is `not_authorized` before the ledger
    /// is read: the same bytes back for a record that exists and one that
    /// does not, and for a node with a ledger and one with none at all.
    #[test]
    fn an_unsigned_record_request_is_refused_alike_for_any_subject_before_the_ledger_is_read() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let missing = tempfile::tempdir().unwrap();
        let nowhere = missing.path().join("no-such-ledger");
        let held = node_a_record(&ledger);
        let mut absent = held.clone();
        absent["subject"] = json!({"record": "a".repeat(64)});
        for mut request in [held, absent] {
            request["requester_id"] = json!("node-a");
            let bytes = serde_json::to_vec(&request).unwrap();
            for ledger_dir in [dir.path(), nowhere.as_path()] {
                let reads = evidence_log::index_reads();
                let outcome = ask_by_default(ledger_dir, &bytes);
                assert_eq!(evidence_log::index_reads(), reads, "the ledger was read");
                assert_eq!(
                    outcome.wire_bytes(),
                    Some(refusal_of(&bytes, Reason::NotAuthorized)),
                    "{request}"
                );
            }
        }
    }

    /// PRD T3. Node y asks for node-a's record claiming to be node-a: with
    /// its own key and node-a's id, or with node-a's key id over its own
    /// signature. Each is a signed `not_authorized` bound to its request,
    /// given before the ledger is read. The same request from node-a,
    /// signed by node-a, is answered.
    #[test]
    fn a_node_claiming_to_be_another_is_refused_before_the_ledger_is_read() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let mut request = node_a_record(&ledger);
        request["requester_id"] = json!("node-a");

        let own_key_claims_a = signed_by("node-y", &request);
        let mut a_key_y_sig: Value = serde_json::from_slice(&own_key_claims_a).unwrap();
        a_key_y_sig["requester_auth"]["key_id"] = json!(key_id_of(&asker_key("node-a")));
        let a_key_y_sig = serde_json::to_vec(&a_key_y_sig).unwrap();

        for bytes in [&own_key_claims_a, &a_key_y_sig] {
            let reads = evidence_log::index_reads();
            let outcome = ask_by_default(dir.path(), bytes);
            assert_eq!(evidence_log::index_reads(), reads, "the ledger was read");
            let Outcome::Refused { wire, reason, .. } = &outcome else {
                panic!("{outcome:?}");
            };
            assert_eq!(*reason, Reason::NotAuthorized);
            assert_eq!(
                refusal::verify_for(wire, &key().verifying_key(), &request_digest(bytes)),
                Ok(Reason::NotAuthorized),
                "signed and bound to the request"
            );
        }
        assert!(matches!(
            ask_by_default(dir.path(), &signed_by("node-a", &request)),
            Outcome::Answered { .. }
        ));
    }

    /// D3: a proven node that no record of this one names gets the same
    /// `not_authorized` for any record subject, held or not, in range or
    /// past it, small or over the answer limit: the refusal tells it
    /// nothing about this log's size or cadence.
    #[test]
    fn a_stranger_learns_nothing_of_the_logs_size_from_a_record_refusal() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let held = node_a_record(&ledger);
        let pin = held["coverage"].clone();
        let subjects = [
            held["subject"].clone(),
            json!({"record": "a".repeat(64)}),
            json!({"range": [0, 3]}),
            json!({"range": [100_000, 100_001]}),
            json!({"range": [0, 100_000]}),
            json!({"full_history": null}),
            json!({"correlation": "no-such-nonce"}),
            json!({"exchange": "b".repeat(64)}),
        ];
        for subject in subjects {
            let request = json!({"subject": subject, "coverage": pin});
            let bytes = signed_by("node-z", &request);
            let outcome = ask_by_default(dir.path(), &bytes);
            assert_eq!(
                outcome.wire_bytes(),
                Some(refusal_of(&bytes, Reason::NotAuthorized)),
                "{subject}"
            );
        }
    }

    /// The artifact a subject is answered with is the same bytes for two
    /// different authorized requesters.
    #[test]
    fn two_authorized_requesters_get_the_same_artifact() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let artifact =
            |bytes: &[u8], segments: &str| match ask_with(dir.path(), bytes, segments, false) {
                Outcome::Answered { wire, .. } => wire["artifact"].clone(),
                other => panic!("{other:?}"),
            };
        let checkpoints = &standard_history_requests()[0];
        assert_eq!(
            artifact(&signed_by("node-a", checkpoints), "counterparties"),
            artifact(&signed_by("node-b", checkpoints), "counterparties")
        );
        let record = record_request(&ledger, 0);
        assert_eq!(
            artifact(&signed_by("node-y", &record), "peers"),
            artifact(&signed_by("node-z", &record), "peers")
        );
    }

    /// Under `peers` a record goes to any node a signed request proves, one
    /// no record names included, and to no stranger: an unsigned request, or
    /// one under a key no host binds, is refused before the ledger is read
    /// (the evidencebook#114 ruling, Q2). A signature that fails is refused.
    #[test]
    fn under_peers_a_record_goes_to_any_proven_node_and_never_to_a_stranger() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let record = record_request(&ledger, 0);
        assert!(matches!(
            ask_with(dir.path(), &signed_by("node-z", &record), "peers", false),
            Outcome::Answered { .. }
        ));
        let unsigned = serde_json::to_vec(&record).unwrap();
        let unbound = signed_with(&SigningKey::from_bytes(&[0x77; 32]), &record);
        for (what, bytes) in [("unsigned", &unsigned), ("unbound", &unbound)] {
            let reads = evidence_log::index_reads();
            assert_eq!(
                refused(&ask_with(dir.path(), bytes, "peers", true)),
                Some(Reason::NotAuthorized),
                "{what}"
            );
            assert_eq!(
                evidence_log::index_reads(),
                reads,
                "{what}: refused before the ledger is read"
            );
        }
        let mut tampered: Value = serde_json::from_slice(&signed_by("node-z", &record)).unwrap();
        tampered["nonce"] = json!("not-the-signed-one");
        assert_eq!(
            refused(&ask_with(
                dir.path(),
                &serde_json::to_vec(&tampered).unwrap(),
                "peers",
                false
            )),
            Some(Reason::NotAuthorized)
        );
    }

    /// `range` and `full_history` with no derivation are refused
    /// `not_authorized` under every setting, to every asker, their own
    /// counterparty included, and before the ledger is read, so the refusal
    /// is the same whether or not the subject exists (the evidencebook#114
    /// ruling, Q1: only a recipient-specific derivation grants them, and this
    /// node has none). The corpus's records 16 to 20 all name node-a.
    #[test]
    fn a_range_or_the_full_history_is_refused_to_everyone_under_every_setting() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let pin = corpus_checkpoints(&ledger, &key())[1].anchor();
        let coverage = json!({"expected_pin": pin});
        let subjects = [
            json!({"range": [16, 20]}),
            json!({"range": [0, 3]}),
            json!({"range": [100_000, 100_001]}),
            json!({"full_history": null}),
        ];
        for subject in subjects {
            let request = json!({"subject": subject, "coverage": coverage});
            let askers = [
                ("unsigned", serde_json::to_vec(&request).unwrap()),
                ("node-a", signed_by("node-a", &request)),
                ("node-z", signed_by("node-z", &request)),
            ];
            for segments in ["counterparties", "peers", "off"] {
                for (who, bytes) in &askers {
                    let reads = evidence_log::index_reads();
                    assert_eq!(
                        refused(&ask_with(dir.path(), bytes, segments, true)),
                        Some(Reason::NotAuthorized),
                        "{subject} {segments} {who}"
                    );
                    assert_eq!(
                        evidence_log::index_reads(),
                        reads,
                        "{subject} {segments} {who}: refused before the ledger is read"
                    );
                }
            }
        }
    }

    /// `correlation` is an exact-key lookup answered as `record` and
    /// `exchange` are (capsules#60, Sherlock2's condition for keeping it): a
    /// stranger gets nothing under any setting; under `counterparties` a node
    /// gets it only when every matching record names it; a key's prefix
    /// matches nothing. In the corpus, records 0 and 4 carry nonce `n-1` and
    /// name node-a.
    #[test]
    fn a_correlation_goes_by_exact_key_only_to_a_node_every_match_names() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let by =
            |key: &str| json!({"subject": {"correlation": key}, "coverage": {"min_freshness": 1}});
        let n1 = by("n-1");
        let stranger = SigningKey::from_bytes(&[0x77; 32]);
        for segments in ["counterparties", "peers", "off"] {
            for (who, bytes) in [
                ("unsigned", serde_json::to_vec(&n1).unwrap()),
                ("unbound", signed_with(&stranger, &n1)),
            ] {
                let reads = evidence_log::index_reads();
                assert_eq!(
                    refused(&ask_with(dir.path(), &bytes, segments, true)),
                    Some(Reason::NotAuthorized),
                    "{segments} {who}"
                );
                assert_eq!(
                    evidence_log::index_reads(),
                    reads,
                    "{segments} {who}: refused before the ledger is read"
                );
            }
        }
        assert!(matches!(
            ask_with(
                dir.path(),
                &signed_by("node-a", &n1),
                "counterparties",
                true
            ),
            Outcome::Answered { .. }
        ));
        assert_eq!(
            refused(&ask_with(
                dir.path(),
                &signed_by("node-b", &n1),
                "counterparties",
                true
            )),
            Some(Reason::NotAuthorized),
            "node-b is a counterparty, but not of these records"
        );
        assert_eq!(
            refused(&ask_with(
                dir.path(),
                &signed_by("node-a", &by("n-")),
                "counterparties",
                true
            )),
            Some(Reason::NoSuchSubject),
            "a prefix is not a key"
        );

        // Record 1, which names node-b, now carries n-1 too.
        let mut mixed = ledger.clone();
        mixed[1] = served(
            "node-b",
            "model-x",
            "confirmed",
            "20.000",
            json!({"nonce": "n-1"}),
        );
        let dir = node(&mixed);
        for asker in ["node-a", "node-b"] {
            assert_eq!(
                refused(&ask_with(
                    dir.path(),
                    &signed_by(asker, &n1),
                    "counterparties",
                    true
                )),
                Some(Reason::NotAuthorized),
                "{asker}: refused whole, never filtered"
            );
        }
        assert!(matches!(
            ask_with(dir.path(), &signed_by("node-z", &n1), "peers", true),
            Outcome::Answered { .. }
        ));
    }

    /// An `exchange` request about a half this node accepted on node-b's
    /// key, cited by the record `emit_citing_record` seals (no
    /// `x-mesh-poc-v1` block), is answered to node-b under `counterparties`,
    /// under either profile, and refused `not_authorized` to node-a, and to
    /// whoever the push named itself (Mesh-LLM/capsules-plugin#172, loop step
    /// 07). In the corpus that record cites `foreign_half()`, pushed under
    /// the id `node-pushed-under`.
    #[test]
    fn an_exchange_goes_to_the_node_that_sent_the_half_it_asks_about() {
        let half = crate::evidence_request_parity::foreign_half();
        let dir = node(&corpus_ledger());
        for profile in [None, Some("evidence-interop/0"), Some("evidence-interop/1")] {
            let mut request =
                json!({"subject": {"exchange": half}, "coverage": {"expected_pin": half}});
            if let Some(p) = profile {
                request["profile"] = json!(p);
            }
            let bytes = signed_by("node-b", &request);
            let Outcome::Answered { wire, .. } =
                ask_with(dir.path(), &bytes, "counterparties", false)
            else {
                panic!("{profile:?}: not answered to node-b");
            };
            let v = verify_response(&bytes, &wire, &key().verifying_key(), &Default::default());
            assert_eq!(v["state"], json!("artifact"), "{profile:?}: {v}");
            for other in ["node-a", "node-z"] {
                assert_eq!(
                    refused(&ask_with(
                        dir.path(),
                        &signed_by(other, &request),
                        "counterparties",
                        false
                    )),
                    Some(Reason::NotAuthorized),
                    "{profile:?}: {other} holds no key the half verified under"
                );
            }
            let pushed_under = ask_with(
                dir.path(),
                &signed_by("node-pushed-under", &request),
                "counterparties",
                false,
            );
            assert!(
                matches!(pushed_under, Outcome::Refused { .. }),
                "{profile:?}: the id a push names is no one's: {pushed_under:?}"
            );
        }
    }

    /// A record that never leaves this node is in no keyed answer's matched
    /// set (evidencebook#206 row 4, Mesh-LLM/capsules-plugin#161): asked by
    /// `correlation` or `exchange` over a key it sits under, the answer is the
    /// one a node without it gives, with the same records under the same
    /// checkpoint, or the same `no_such_subject` when it is the key's only
    /// match, never a refusal that says something is withheld there. In the
    /// corpus, records 0 and 4 carry nonce `n-1` and name node-a, and one
    /// record under checkpoint 0 cites the half; record 20, under checkpoint
    /// 1, becomes a deal report that carries both, plus a nonce and a half no
    /// other record has.
    #[test]
    fn a_record_that_never_leaves_changes_no_keyed_answer() {
        let half = hex::encode(Sha256::digest(b"the counterparty's own half"));
        let only_half = hex::encode(Sha256::digest(b"a half only the report cites"));
        let ledger = corpus_ledger();
        let mut with_report = ledger.clone();
        with_report[20] = sealed(json!({
            "action_id": "capsulectl-deal-report",
            "effect": {"status": "confirmed"},
            "nonce": "n-1",
            "client_nonce": "n-only",
            "references": [
                {"citation_purpose": "counterparty_half", "digest": half},
                {"citation_purpose": "counterparty_half", "digest": only_half},
            ],
        }));
        assert!(crate::evidence_log::never_leaves(&with_report[20]));
        let by = |subject: Value| match &subject["exchange"] {
            Value::String(h) => json!({"subject": subject, "coverage": {"expected_pin": h}}),
            _ => json!({"subject": subject, "coverage": {"min_freshness": 1}}),
        };
        let outcome = |ledger: &[Value], request: &Value, asker: &str, segments: &str| {
            let dir = node(ledger);
            let anchors: Vec<String> = corpus_checkpoints(ledger, &key())
                .iter()
                .map(|cp| cp.anchor())
                .collect();
            let bytes = signed_by(asker, request);
            match ask(dir.path(), &bytes, segments) {
                Outcome::Answered { wire, .. } => {
                    let v =
                        verify_response(&bytes, &wire, &key().verifying_key(), &Default::default());
                    assert_eq!(v["state"], json!("artifact"), "{v}");
                    let at = anchors.iter().position(|a| json!(a) == v["anchor"]);
                    Ok((at, v["records"].clone()))
                }
                other => Err(refused(&other)),
            }
        };
        let answered = [
            (by(json!({"correlation": "n-1"})), "node-y", "peers"),
            (by(json!({"exchange": half})), "node-y", "peers"),
            (
                by(json!({"correlation": "n-1"})),
                "node-a",
                "counterparties",
            ),
        ];
        for (request, asker, segments) in &answered {
            let without = outcome(&ledger, request, asker, segments);
            assert!(without.is_ok(), "{request} {segments}: {without:?}");
            assert_eq!(
                outcome(&with_report, request, asker, segments),
                without,
                "{request} {segments}"
            );
        }
        for request in [
            by(json!({"correlation": "n-only"})),
            by(json!({"exchange": only_half})),
        ] {
            for (asker, segments) in [("node-y", "peers"), ("node-a", "counterparties")] {
                for (what, ledger) in [("with", &with_report), ("without", &ledger)] {
                    assert_eq!(
                        outcome(ledger, &request, asker, segments),
                        Err(Some(Reason::NoSuchSubject)),
                        "{request} {segments} {what} the report"
                    );
                }
            }
        }
    }

    /// Step 6 admits the holder of a cited half's key to record bodies even
    /// when no record names it by id (#172): here the corpus's citing record
    /// is resealed as accepted on node-z's key, and node-z, a proven node no
    /// record names, is answered the exchange; node-b, named elsewhere but
    /// not the key the half verified under, is refused it. Standard History
    /// keeps the id rule.
    #[test]
    fn a_counterparty_known_only_by_the_key_its_half_verified_under_is_answered() {
        let half = crate::evidence_request_parity::foreign_half();
        let mut ledger = corpus_ledger();
        let at = ledger
            .iter()
            .position(|r| evidence_log::counterparty_half_citations(r).contains(&half))
            .unwrap();
        let mut citing = ledger[at].clone();
        citing["model_attestation"]["compute_attestation"]["received_half"]["sender_key_id"] =
            json!(hex::encode(asker_key("node-z").verifying_key().to_bytes()));
        citing.as_object_mut().unwrap().remove("capsule_id");
        ledger[at] = sealed(citing);
        let dir = node(&ledger);
        let request = json!({"subject": {"exchange": half}, "coverage": {"expected_pin": half},
                             "profile": "evidence-interop/1"});
        let bytes = signed_by("node-z", &request);
        let Outcome::Answered { wire, .. } = ask_with(dir.path(), &bytes, "counterparties", false)
        else {
            panic!("node-z holds the key the half verified under");
        };
        let v = verify_response(&bytes, &wire, &key().verifying_key(), &Default::default());
        assert_eq!(v["state"], json!("artifact"), "{v}");
        assert_eq!(
            refused(&ask_with(
                dir.path(),
                &signed_by("node-b", &request),
                "counterparties",
                false
            )),
            Some(Reason::NotAuthorized)
        );
        assert_eq!(
            refused(&ask_with(
                dir.path(),
                &signed_by("node-z", &withheld_requests()[0]),
                "counterparties",
                false
            )),
            Some(Reason::PolicyDeclined),
            "Standard History keeps the id rule"
        );
    }

    /// Who asked is recorded with the request's digest: the verified key and
    /// node when the signature and binding held, even when the request is
    /// refused for stating another node's id; nothing when it was unsigned.
    #[test]
    fn the_log_records_the_verified_principal_with_the_request_digest() {
        let ledger = corpus_ledger();
        let dir = node(&ledger);
        let log = tempfile::tempdir().unwrap();
        let key = key();
        let announced = announced();
        let replay = ReplayCache::default();
        let responder = Responder {
            ledger_dir: dir.path(),
            signing_key: &key,
            now: NOW,
            history_segments: "counterparties",
            share_standard_history: false,
            share_exchange_corroboration: false,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &replay,
            node_id: Some(RESPONDER),
            policy_digest: None,
        };
        let request = node_a_record(&ledger);
        let mut claims_a = request.clone();
        claims_a["requester_id"] = json!("node-a");
        let asks = [
            signed_by("node-a", &request),
            serde_json::to_vec(&claims_a).unwrap(),
            signed_by("node-y", &claims_a),
        ];
        for bytes in &asks {
            answer_and_log(bytes, false, &responder, Some(log.path()));
        }
        let lines: Vec<Value> =
            std::fs::read_to_string(log.path().join(received::RECEIVED_LOG_FILE))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
        let y = key_id_of(&asker_key("node-y"));
        let a = key_id_of(&asker_key("node-a"));
        let expected = [
            (Some(a.as_str()), Some("node-a"), None, "answered"),
            (None, None, Some("node-a"), "refused"),
            (Some(y.as_str()), Some("node-y"), Some("node-a"), "refused"),
        ];
        for ((line, bytes), (key_id, node_id, stated, status)) in
            lines.iter().zip(&asks).zip(expected)
        {
            assert_eq!(line["request_digest"], json!(request_digest(bytes)));
            assert_eq!(line["principal_key_id"], json!(key_id), "{line}");
            assert_eq!(line["principal_node_id"], json!(node_id), "{line}");
            assert_eq!(line["requester_id"], json!(stated), "{line}");
            assert_eq!(line["status"], json!(status), "{line}");
        }
        assert_eq!(lines.len(), 3);
    }

    fn received_entry() -> received::Entry<'static> {
        received::Entry {
            ts: "2026-09-29T00:00:00Z",
            path: "evidence-request",
            requester_id: Some("node-a"),
            subject_kind: Some("record"),
            status: "refused",
            reason: Some("no_such_subject"),
            request_digest: Some("ab"),
            principal_key_id: Some("cd"),
            principal_node_id: Some("node-a"),
            principal_binding: Some("bound"),
            audience: Some("node-r"),
            replay: Some("checked"),
        }
    }

    #[test]
    fn a_received_line_is_what_the_evidence_page_reads() {
        let dir = tempfile::tempdir().unwrap();
        log_received(Some(dir.path()), &received_entry());
        let read = crate::evidence_panes::read_received_log(dir.path());
        assert_eq!(read, vec![received_entry().to_json()]);
    }

    #[test]
    fn nothing_is_received_without_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("received-log");
        log_received(Some(&missing), &received_entry());
        log_received(None, &received_entry());
        assert!(!missing.exists());
    }
}
