//! The artifact response in the interop profile's form (`evidence-interop/0`,
//! agent-action-capsule `spec/interop-profile-v0.md` §6.2): this node builds
//! one from its ledger index ([`build`]) and checks one a peer sent
//! ([`check`]).
//!
//! The envelope is the `evidence-request` crate's (`envelope::sign`,
//! `envelope::parse_reply`, `Envelope::verify_for`), and so is the profile's
//! check of a record's Checkpointed Local Log material
//! (`cll_material::check_anchor_inclusion`). Building the artifact is the
//! responder's business, not that crate's: evidencebook's `answer::build`
//! builds it, over this node's read-only index (`evidence_log`, which is an
//! evidencebook store), so it never opens the durable node store this
//! plugin's checkpointer owns (evidencebook#35). This node's own
//! derivations' values (exchange corroboration's entries) are computed
//! here and carried through its `Derive`. The
//! artifact forms, evidencebook's (and the Go responder's):
//!
//! - `record`, no derivation: the record's line in the ledger, proven by the
//!   anchor's `cll-checkpoint`, its `cll-inclusion-proof` and, when the
//!   checkpoint extends another, its `cll-consistency-proof` (profile
//!   §6.2.1). The entry the proof covers is the record's `capsule_id`, which
//!   is not the SHA-256 of the line (that is the line without its
//!   `capsule_id` and producer envelope), so a profile verifier reports this
//!   check `NOT_CHECKED` (§6.2.1 step 5), never `FAIL`; this node's
//!   requester recomputes the `capsule_id` and checks the proof itself. The
//!   line is served whole so the requester keeps the producer's signature
//!   over it;
//! - `full_history`, `range`, `correlation`, `exchange`: RFC 8785 of
//!   `{anchor, evidence_stream, records, subject}`, each record
//!   `{body, digest, leaf_index}` with `body` in hex;
//! - `checkpoints`: RFC 8785 of `{anchor, checkpoints, evidence_stream,
//!   subject}`, each checkpoint its COSE statement in hex;
//! - `history_card/1`: RFC 8785 of `{anchor, derivation, evidence_stream,
//!   history, subject}`, each entry `{checkpoint, consistency_from_previous}`;
//! - `exchange_corroboration/1` (this node's own, named by its definition
//!   digest): RFC 8785 of `{anchor, derivation, entries, evidence_stream,
//!   subject}`, each entry the derivation's members with `inclusion` the
//!   half's `cll-inclusion-proof` at the anchor, in hex
//!   (`crate::exchange_corroboration`);
//! - `service_history/1` (this node's own, named by its definition digest):
//!   RFC 8785 of `{anchor, coverage_declaration, declared, derivation,
//!   evidence_stream, history_card, history_card_digest, period_counts,
//!   subject}`, the card the `history_card/1` artifact at the same anchor
//!   (`crate::service_history`). This node signs its envelope itself, with
//!   no material, as that profile asks.
//!
//! **Beyond the profile.** The profile defines no material for a record set,
//! the checkpoint list or a derivation (its P-13), and no carrier for a
//! witness's receipt. A requester here checks them all the same, so this
//! node sends, where a profile verifier reads nothing:
//!
//! - for a record set, the anchor's `cll-checkpoint` and one
//!   `cll-inclusion-proof` per record, in the artifact's order; for
//!   `exchange_corroboration/1`, the anchor's `cll-checkpoint`. A profile verifier reports `anchor_inclusion`
//!   `NOT_CHECKED` for these subjects before it reads any material
//!   (§6.2.1 step 1), so the extra items change nothing for it;
//! - the receipts its witnesses issued for the checkpoints the answer
//!   carries, as an unsigned top-level `witness_receipts` member of the
//!   reply, which a profile reader ignores. A receipt authenticates itself:
//!   it is bound to its checkpoint's digest and signed by its witness.
//!
//! The artifact is the same for every requester (-00 §5); the material and
//! the receipts may differ, as the profile allows.

use cll::checkpoint::{verify_checkpoint_cose_offline, DecodedCheckpointCose, WitnessRecord};
use cll::mmr::{leaf_count, Hash};
use ed25519_dalek::VerifyingKey;
use evidence_request::cll_material::{
    self, encode_inclusion_proof, KeyDecision, LogKeyPolicy, KIND_CHECKPOINT, KIND_CONSISTENCY,
    KIND_INCLUSION,
};
use evidence_request::envelope::{self, subject_value, AnchorFreshness, Binding, Envelope, Reply};
use evidence_request::registry::{Reason, DERIVATION_HISTORY_CARD};
use evidence_request::request::{Coverage, Derivation, Freshness, Request, Subject};
use evidence_request::resolve::ResolvedAnchor;
use evidence_request::time::parse_utc;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::evidence_log::{ChainCheckpoint, LogView};

pub(crate) mod cll_proofs;

use cll_proofs::{consistent, inclusion_leaf, proves};

/// The reply member that carries witness receipts beside the envelope.
pub const WITNESS_RECEIPTS: &str = "witness_receipts";

/// The most records, checkpoints or receipts a received answer may carry
/// before anything in it is checked (the responder's limits are lower).
const MAX_ITEMS: usize = 10_000;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// The responder's side.
// ---------------------------------------------------------------------------

/// What an answer is built from, once the request is resolved and the
/// sharing policy has passed it.
pub struct Build<'a> {
    pub request: &'a Request,
    /// The request's octets as received.
    pub request_bytes: &'a [u8],
    /// The anchor as `resolve::resolve` resolved it: what the envelope names.
    pub resolved: &'a ResolvedAnchor,
    /// The chain position of the checkpoint the answer is served under
    /// (a stated one).
    pub at: usize,
    /// The leaf indices of the records the answer carries, ascending, all
    /// under that checkpoint. Empty for a checkpoint list or a derivation.
    pub records: &'a [u64],
    pub signing_key: &'a ed25519_dalek::SigningKey,
    pub issued_at: &'a str,
}

/// Build and sign the answer: the profile's flat reply, carried in a JSON
/// frame, with this node's witness receipts beside the envelope. A reason when no answer can
/// be built.
pub fn build(b: &Build<'_>, view: &LogView<'_>) -> Result<Value, Reason> {
    let index = view.index;
    let served = index.chain.get(b.at).ok_or(Reason::CoverageUnsatisfiable)?;
    let service_history = crate::service_history::is_derivation(b.request.derivation.as_ref());
    let signed = if service_history {
        service_history_envelope(b, view, served)?
    } else {
        signed_envelope(b, view, served)?
    };
    let mut reply: Value = serde_json::from_slice(&signed.encode(Binding::Json))
        .map_err(|_| Reason::CapacityExceeded)?;
    // The checkpoints whose receipts go with the answer: every one listed
    // for a checkpoint list and a history card (embedded or not), else the
    // serving one.
    let lists_checkpoints = service_history
        || matches!(
            (&b.request.derivation, &b.request.subject),
            (Some(Derivation::Token(t)), _) if t == DERIVATION_HISTORY_CARD
        )
        || matches!(
            (&b.request.derivation, &b.request.subject),
            (None, Subject::Checkpoints)
        );
    let carried: &[ChainCheckpoint] = if lists_checkpoints {
        &index.chain[..=b.at]
    } else {
        std::slice::from_ref(served)
    };
    let receipts: Vec<Value> = carried
        .iter()
        .flat_map(|cp| {
            let digest = cp.anchor_digest();
            cp.record
                .witnesses
                .iter()
                .map(move |w| json!({"checkpoint": digest, "witness": w}))
        })
        .collect();
    if !receipts.is_empty() {
        reply[WITNESS_RECEIPTS] = Value::Array(receipts);
    }
    Ok(reply)
}

/// The envelope `answer::build` signs over this node's index, with
/// material beyond the profile (P-13) as this node has always sent it, this
/// node's own derivations carried through its `Derive`, and each crate
/// error the reason this node has always refused it with.
fn signed_envelope(
    b: &Build<'_>,
    view: &LogView<'_>,
    served: &ChainCheckpoint,
) -> Result<Envelope, Reason> {
    use evidencebook::answer::{self, AnswerError, Options, Selection};
    // This node's own derivations, computed before the crate builds the
    // answer so each can still refuse with its own reason.
    let corroboration = match (&b.request.derivation, &b.request.subject) {
        (Some(Derivation::Digest(d)), Subject::Correlation(id))
            if d == crate::exchange_corroboration::DEFINITION_DIGEST =>
        {
            Some(crate::exchange_corroboration::entries(
                id,
                &served.record,
                b.records,
                view,
            )?)
        }
        _ => None,
    };
    let derive = |name: &str, _: &Subject, _: &evidencebook::substrate::StatedCheckpoint| {
        if name == crate::exchange_corroboration::DEFINITION_DIGEST {
            corroboration.clone().map(|v| ("entries".to_string(), v))
        } else {
            None
        }
    };
    answer::build(
        view,
        view,
        b.request,
        b.request_bytes,
        b.resolved,
        &Selection {
            at: b.at,
            // A derivation of this node's own carries no records of the
            // crate's selection: the entries are its own.
            records: if corroboration.is_some() {
                Vec::new()
            } else {
                b.records.to_vec()
            },
        },
        Options {
            prove_beyond_profile: true,
            derive: Some(&derive),
            derivations: None,
            requester: None,
        },
        b.signing_key,
        b.issued_at,
    )
    .map_err(|e| match e {
        AnswerError::RecordNotFound | AnswerError::NoRecords | AnswerError::RecordDigest => {
            Reason::NoSuchSubject
        }
        AnswerError::AnchorNotFound | AnswerError::CitingNotAnchored => {
            Reason::CoverageUnsatisfiable
        }
        AnswerError::DerivationUnsupported => Reason::DerivationUnsupported,
        AnswerError::NotAuthorized => Reason::NotAuthorized,
        // A limit or a fault of this node's own: capacity_exceeded under
        // evidence-interop/1, policy_declined under /0 (`evidence_answer`).
        AnswerError::Sign(e) => {
            tracing::warn!(error = %e, "an evidence answer could not be signed -- declining");
            Reason::CapacityExceeded
        }
        _ => Reason::CapacityExceeded,
    })
}

/// The Service History's envelope (`crate::service_history`). Its artifact
/// has more members than a `Derive`d one, so this node signs it itself: the
/// card is the one `answer::build` serves a direct `history_card/1` request
/// at the same anchor, and, as the profile registers no material for a
/// derivation, the envelope carries none (ISH §8.1).
fn service_history_envelope(
    b: &Build<'_>,
    view: &LogView<'_>,
    served: &ChainCheckpoint,
) -> Result<Envelope, Reason> {
    use evidencebook::answer::{self, Options, Selection};
    let card_request = Request {
        subject: Subject::FullHistory,
        coverage: Coverage::ExpectedPin(served.anchor_digest()),
        derivation: Some(Derivation::Token(DERIVATION_HISTORY_CARD.to_string())),
        deadline: None,
        nonce: None,
        route: None,
    };
    let card = answer::build(
        view,
        view,
        &card_request,
        b.request_bytes,
        b.resolved,
        &Selection {
            at: b.at,
            records: Vec::new(),
        },
        Options::default(),
        b.signing_key,
        b.issued_at,
    )
    .map_err(|_| Reason::CapacityExceeded)?
    .artifact;
    let chain = &view.index.chain[..=b.at];
    let cuts: Vec<crate::service_history::Cut<'_>> = chain
        .iter()
        .map(|cp| {
            Ok(crate::service_history::Cut {
                timestamp: &cp.record.timestamp,
                leaves: leaf_count(cp.record.mmr_size).map_err(|_| Reason::CapacityExceeded)?,
            })
        })
        .collect::<Result<_, Reason>>()?;
    let leaves = &view.index.leaves;
    let counts = crate::service_history::period_counts(&cuts, &|i| {
        leaves
            .get(i as usize)
            .and_then(|l| l.facts.served.as_ref())
            .map(|s| s.group.clone())
    })?;
    let log_size = cuts.last().map_or(0, |c| c.leaves);
    let anchor = served.anchor_digest();
    let artifact =
        crate::service_history::artifact(&card, counts, &anchor, &served.record.log_id, log_size)?;
    envelope::sign_with_profile(
        &profile_of(b.request_bytes),
        b.request_bytes,
        envelope::EnvelopeParts {
            subject: b.request.subject.clone(),
            derivation: b.request.derivation.clone(),
            anchor: envelope::Anchor {
                digest: anchor,
                freshness: None,
            },
            artifact,
            verification: Vec::new(),
            issued_at: b.issued_at.to_string(),
        },
        b.signing_key,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "a Service History could not be signed -- declining");
        Reason::CapacityExceeded
    })
}

/// The profile identifier the request octets `sent` name ([`requested_profile`]),
/// `evidence-interop/0` when they are not a map or name none. The responder
/// checked it before building (`evidence_answer`), so it is one this node
/// implements, and the envelope is signed under it.
pub(crate) fn profile_of(sent: &[u8]) -> String {
    match serde_json::from_slice::<Value>(sent) {
        Ok(Value::Object(map)) => requested_profile(&map)
            .unwrap_or(envelope::PROFILE)
            .to_string(),
        _ => envelope::PROFILE.to_string(),
    }
}

/// A checkpoint time in the profile's form: UTC, any fraction dropped
/// (profile §5.2).
fn profile_time(timestamp: &str) -> String {
    match timestamp.split_once('.') {
        Some((seconds, _)) => format!("{seconds}Z"),
        None => timestamp.to_string(),
    }
}

pub(crate) fn inclusion(view: &LogView<'_>, leaf: u64, size: u64) -> Result<Vec<u8>, Reason> {
    view.index
        .inclusion_path(leaf, size)
        .and_then(|path| encode_inclusion_proof(leaf, &path))
        .ok_or(Reason::CapacityExceeded)
}

// ---------------------------------------------------------------------------
// The requester's side.
// ---------------------------------------------------------------------------

/// A received answer that checked out.
#[derive(Debug)]
pub struct Checked {
    /// The digest of the checkpoint the answer is served under.
    pub anchor: String,
    /// The leaf indices of the records it carries.
    pub records: Vec<u64>,
    /// The checkpoints it lists (`checkpoints`, `history_card/1`).
    pub checkpoints: usize,
    /// The time the first of them states, which starts the stream: a
    /// history card's key age. `None` when the answer lists none.
    pub first_checkpoint_at: Option<String>,
    /// The envelope's `artifact_digest`, checked against the artifact.
    pub artifact_digest: String,
    /// The halves an `exchange_corroboration/1` answer states, each proven
    /// under the anchor. Empty for any other answer.
    pub halves: Vec<crate::exchange_corroboration::Half>,
    /// The witness receipts it carries, each as checked.
    pub receipts: Vec<ReceiptCheck>,
    /// What a Service History counts. `None` for any other answer.
    pub history: Option<crate::service_history::Counts>,
}

/// What became of one witness receipt.
#[derive(Clone, Debug)]
pub struct ReceiptCheck {
    /// The digest of the checkpoint statement it is for.
    pub checkpoint: String,
    pub ts_url: String,
    pub status: ReceiptStatus,
}

/// A receipt's standing. Only `Verified` counts as witnessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// It proves its checkpoint under the key configured for its witness.
    Verified,
    /// Well formed and bound to its checkpoint, but no key is configured
    /// for its witness.
    NoKey,
    /// A placeholder that was never registered.
    Stub,
}

/// Why a received answer is not evidence.
#[derive(Debug, PartialEq, Eq)]
pub enum CheckError {
    /// The answer itself does not hold.
    Answer(String),
    /// A witness receipt is malformed, or not for the checkpoint it names.
    ReceiptMalformed,
    /// A witness receipt does not verify under the key configured for its
    /// witness, or is bound to another checkpoint.
    ReceiptBinding,
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::Answer(why) => f.write_str(why),
            CheckError::ReceiptMalformed => {
                f.write_str("a witness receipt on a checkpoint is malformed")
            }
            CheckError::ReceiptBinding => {
                f.write_str("a witness receipt does not cover the checkpoint it is carried on")
            }
        }
    }
}

fn fail<T>(why: impl Into<String>) -> Result<T, CheckError> {
    Err(CheckError::Answer(why.into()))
}

/// A checkpoint statement from the answer, verified under the responder's
/// key.
struct Stated {
    digest: String,
    cp: DecodedCheckpointCose,
}

/// The profile identifier a request names: its `profile` member, or
/// `evidence-interop/0` when it has none (profile §3.3 step 2). `None` when
/// the member is not text. This node answers and checks `evidence-interop/0`
/// and `evidence-interop/1` ([`envelope::PROFILES`]), each with its own
/// refusal reasons (IP v1 §6.3).
pub fn requested_profile(request: &Map<String, Value>) -> Option<&str> {
    match request.get("profile") {
        None => Some(envelope::PROFILE),
        Some(Value::String(profile)) => Some(profile),
        Some(_) => None,
    }
}

/// Check a reply `response` to the request whose octets as sent are `sent`
/// (parsed as `request`), from the responder whose key is `key`. Every check
/// the old pre-profile verifier made is made here: the envelope (the
/// responder, this request, its subject and derivation, the coverage asked
/// for), the artifact against the anchor checkpoint (signed by the same key),
/// every record against its digest and its inclusion proof, every
/// checkpoint list against its chain, and every witness receipt against its
/// checkpoint (under the key `witness_key` gives for its witness, if any).
pub fn check(
    sent: &[u8],
    request: &Request,
    response: &Value,
    key: &VerifyingKey,
    witness_key: &dyn Fn(&str) -> Option<VerifyingKey>,
) -> Result<Checked, CheckError> {
    let octets = serde_json::to_vec(response).map_err(|e| CheckError::Answer(e.to_string()))?;
    let env = match envelope::parse_reply(&octets, Binding::Json) {
        Ok(Reply::Envelope(env)) => env,
        Ok(Reply::Refusal(_)) => return fail("a refusal, not an answer"),
        Err(e) => return fail(e.to_string()),
    };
    // Profile §3.3 step 5: the envelope's profile is the one asked for.
    let asked = match serde_json::from_slice::<Value>(sent) {
        Ok(Value::Object(map)) => requested_profile(&map).map(str::to_string),
        _ => None,
    };
    let Some(asked) = asked.filter(|p| p == &env.profile) else {
        return fail("the answer is not under the profile the request named");
    };
    env.verify_for_profile(&asked, key, sent)
        .map_err(|e| CheckError::Answer(e.to_string()))?;
    if env.subject != request.subject || env.derivation != request.derivation {
        return fail("the answer is not for the requested subject or derivation");
    }
    if env.verification.len() > MAX_ITEMS + 2 {
        return fail("the answer carries too much material");
    }

    let derivation = match &env.derivation {
        None => None,
        Some(Derivation::Token(t)) if t == DERIVATION_HISTORY_CARD => Some(t.as_str()),
        Some(Derivation::Digest(d))
            if d == crate::exchange_corroboration::DEFINITION_DIGEST
                || d == crate::service_history::definition_digest() =>
        {
            Some(d.as_str())
        }
        Some(_) => return fail("the answer is for a derivation this node does not check"),
    };

    let mut halves = Vec::new();
    let mut history = None;
    let (served, records, listed) = match (derivation, &env.subject) {
        (None, Subject::Record(digest)) => {
            let report = cll_material::check_anchor_inclusion(&env, &ResponderLogKey(*key));
            let (served, leaf) = match report.status {
                // A record that is its own octets, as the profile proves one.
                cll_material::Status::Pass => {
                    // The check passed, so each kind is there exactly once.
                    let item = |kind: &str| {
                        env.verification
                            .iter()
                            .position(|v| v.kind == kind)
                            .map(|i| env.verification_content[i].as_slice())
                            .unwrap_or_default()
                    };
                    let proof = item(KIND_INCLUSION);
                    let leaf = inclusion_leaf(proof).ok_or_else(|| {
                        CheckError::Answer("the inclusion proof is malformed".into())
                    })?;
                    // The profile's check finds the path's root among the
                    // peaks; whether the leaf sits at its stated position
                    // under the anchor's size is checked here.
                    let served = stated(item(KIND_CHECKPOINT), key)?;
                    if !proves(
                        proof,
                        leaf,
                        &raw_digest(digest)?,
                        served.cp.mmr_size,
                        &served.cp.new_peak_hashes,
                    ) {
                        return fail("the record's inclusion proof does not hold");
                    }
                    (served, leaf)
                }
                // A record of this format, named by its `capsule_id`.
                cll_material::Status::NotChecked if env.artifact_digest != *digest => {
                    check_named_record(&env, digest, key)?
                }
                _ => return fail(format!("anchor_inclusion: {}", report.detail)),
            };
            (served, vec![leaf], Vec::new())
        }
        (Some(t), _) if t == DERIVATION_HISTORY_CARD => {
            let art = artifact_map(&env, Some(t))?;
            let (served, listed) = card_chain(&art, key)?;
            (served, Vec::new(), listed)
        }
        (Some(d), Subject::FullHistory) if d == crate::service_history::definition_digest() => {
            // A Standard History is answered only at a pinned anchor.
            if !matches!(request.coverage, Coverage::ExpectedPin(_)) {
                return fail("a Service History is answered only under an expected_pin");
            }
            if !env.verification.is_empty() {
                return fail("a Service History carries no verification material");
            }
            let art = artifact_map(&env, derivation)?;
            let card = art
                .get("history_card")
                .and_then(Value::as_object)
                .ok_or_else(|| CheckError::Answer("the artifact carries no history card".into()))?;
            let (served, listed) = card_chain(card, key)?;
            check_names(&art, &served)?;
            let times: Vec<&str> = listed.iter().map(|s| s.cp.timestamp.as_str()).collect();
            let log_size = leaf_count(served.cp.mmr_size)
                .map_err(|_| CheckError::Answer("the anchor's size is not an MMR size".into()))?;
            history = Some(
                crate::service_history::check_artifact(
                    crate::service_history::Definition::active(),
                    &art,
                    &times,
                    &served.digest,
                    &served.cp.log_id,
                    log_size,
                )
                .map_err(CheckError::Answer)?,
            );
            (served, Vec::new(), listed)
        }
        (Some(d), Subject::Correlation(id))
            if d == crate::exchange_corroboration::DEFINITION_DIGEST =>
        {
            let art = artifact_map(&env, derivation)?;
            let served = anchor_checkpoint_only(&env, key)?;
            check_names(&art, &served)?;
            let leaves;
            (halves, leaves) = crate::exchange_corroboration::check_entries(&art, id, &served.cp)
                .map_err(|why| CheckError::Answer(why.into()))?;
            (served, leaves, Vec::new())
        }
        (Some(_), _) => return fail("the answer is for a derivation of another subject"),
        (None, Subject::Checkpoints) => {
            let art = artifact_map(&env, None)?;
            let list = art
                .get("checkpoints")
                .and_then(Value::as_array)
                .filter(|l| !l.is_empty() && l.len() <= MAX_ITEMS)
                .ok_or_else(|| CheckError::Answer("the checkpoint list is malformed".into()))?;
            let mut listed = Vec::with_capacity(list.len());
            for item in list {
                let statement = item
                    .as_str()
                    .and_then(|h| hex::decode(h).ok())
                    .ok_or_else(|| CheckError::Answer("a listed checkpoint is malformed".into()))?;
                listed.push(stated(&statement, key)?);
            }
            let served = check_chain(listed, &art)?;
            (served.0, Vec::new(), served.1)
        }
        (None, subject) => {
            let art = artifact_map(&env, None)?;
            let (served, leaves) = check_record_set(&env, &art, subject, key)?;
            (served, leaves, Vec::new())
        }
    };

    check_coverage(&env, request, &served, &records)?;
    let carried: Vec<&Stated> = if listed.is_empty() {
        vec![&served]
    } else {
        listed.iter().collect()
    };
    let receipts = check_receipts(response.get(WITNESS_RECEIPTS), &carried, witness_key)?;
    Ok(Checked {
        anchor: served.digest,
        records,
        checkpoints: listed.len(),
        first_checkpoint_at: listed.first().map(|first| first.cp.timestamp.clone()),
        artifact_digest: env.artifact_digest.clone(),
        halves,
        receipts,
        history,
    })
}

/// A `history_card/1` artifact's checkpoint list: each checkpoint the
/// responder's, each consistency proof holding, the list starting the
/// stream and ending at the anchor `card` names. Returns the anchor and the
/// list.
fn card_chain(
    card: &Map<String, Value>,
    key: &VerifyingKey,
) -> Result<(Stated, Vec<Stated>), CheckError> {
    let history = card
        .get("history")
        .and_then(Value::as_array)
        .filter(|h| !h.is_empty() && h.len() <= MAX_ITEMS)
        .ok_or_else(|| CheckError::Answer("the history is malformed".into()))?;
    let mut listed: Vec<Stated> = Vec::with_capacity(history.len());
    for entry in history {
        let statement = hex_member(entry, "checkpoint")?;
        let cp = stated(&statement, key)?;
        match (listed.last(), entry.get("consistency_from_previous")) {
            (None, Some(Value::Null)) => {}
            (Some(prev), Some(Value::String(proof))) => {
                let proof = hex::decode(proof)
                    .map_err(|_| CheckError::Answer("a consistency proof is malformed".into()))?;
                if !consistent(
                    prev.cp.mmr_size,
                    &prev.cp.new_peak_hashes,
                    cp.cp.mmr_size,
                    &cp.cp.new_peak_hashes,
                    &proof,
                ) {
                    return fail("a consistency proof does not hold");
                }
            }
            _ => return fail("a history entry's consistency proof is missing or out of place"),
        }
        listed.push(cp);
    }
    check_chain(listed, card)
}

/// The material of an answer that carries only its anchor checkpoint (an
/// exchange corroboration), verified under `key`.
fn anchor_checkpoint_only(env: &Envelope, key: &VerifyingKey) -> Result<Stated, CheckError> {
    match (
        env.verification.as_slice(),
        env.verification_content.as_slice(),
    ) {
        ([item], [statement]) if item.kind == KIND_CHECKPOINT => stated(statement, key),
        _ => fail("the answer carries no anchor checkpoint"),
    }
}

/// The relying party's key policy for the anchor checkpoint: the
/// responder's own key, which signs this node's checkpoints.
struct ResponderLogKey(VerifyingKey);

impl LogKeyPolicy for ResponderLogKey {
    fn resolve(&self, _iss: &str, _sub: &str, kid: &[u8], _issued_at: &str) -> KeyDecision {
        if kid == self.0.as_bytes() {
            KeyDecision::Accept(self.0)
        } else {
            KeyDecision::Reject
        }
    }
}

/// A checkpoint statement that verifies under `key` (its `kid`), with its
/// own consistency claim checked (`verify_checkpoint_cose_offline`).
fn stated(statement: &[u8], key: &VerifyingKey) -> Result<Stated, CheckError> {
    let verified = verify_checkpoint_cose_offline(statement);
    match verified.decoded {
        Some(cp) if verified.ok && cp.key_id == hex::encode(key.as_bytes()) => Ok(Stated {
            digest: sha256_hex(statement),
            cp,
        }),
        _ => fail("a checkpoint is not the responder's, or does not verify"),
    }
}

/// The artifact as a JSON map, naming this subject and, exactly when one
/// was asked for, this derivation.
fn artifact_map(
    env: &Envelope,
    derivation: Option<&str>,
) -> Result<Map<String, Value>, CheckError> {
    let art: Value = serde_json::from_slice(&env.artifact)
        .map_err(|_| CheckError::Answer("the artifact is malformed".into()))?;
    let Value::Object(art) = art else {
        return fail("the artifact is malformed");
    };
    if art.get("subject") != Some(&subject_value(&env.subject))
        || art.get("derivation").and_then(Value::as_str) != derivation
        || (derivation.is_none() && art.contains_key("derivation"))
    {
        return fail("the artifact is not for the requested subject or derivation");
    }
    Ok(art)
}

/// The artifact names `served` as its anchor and its log as its stream.
fn check_names(art: &Map<String, Value>, served: &Stated) -> Result<(), CheckError> {
    if art.get("anchor").and_then(Value::as_str) != Some(served.digest.as_str()) {
        return fail("the artifact names another anchor than its checkpoint");
    }
    if art.get("evidence_stream").and_then(Value::as_str) != Some(served.cp.log_id.as_str()) {
        return fail("the artifact names another stream than its checkpoint's");
    }
    Ok(())
}

/// A listed chain (`checkpoints`, `history_card/1`) starts the stream, each
/// checkpoint extends the one before it, and the last is the anchor the
/// artifact names. Returns the anchor and the list.
fn check_chain(
    listed: Vec<Stated>,
    art: &Map<String, Value>,
) -> Result<(Stated, Vec<Stated>), CheckError> {
    let first = listed
        .first()
        .ok_or_else(|| CheckError::Answer("no checkpoints".into()))?;
    if first.cp.prev_size != 0 || !first.cp.prev_root.is_empty() {
        return fail("the checkpoint list does not start the stream");
    }
    for pair in listed.windows(2) {
        let (prev, next) = (&pair[0].cp, &pair[1].cp);
        if next.prev_size != prev.mmr_size
            || next.prev_root != prev.root
            || next.log_id != prev.log_id
            || next.mmr_size <= prev.mmr_size
        {
            return fail("a checkpoint does not extend the one listed before it");
        }
    }
    let last = listed.last().expect("not empty");
    check_names(art, last)?;
    let served = Stated {
        digest: last.digest.clone(),
        cp: last.cp.clone(),
    };
    Ok((served, listed))
}

/// A record of this format answering a `record` subject: the artifact is a
/// record whose recomputed `capsule_id` is the subject, and the material is
/// the anchor checkpoint, the record's inclusion proof and, when there is
/// one, the checkpoint's consistency proof, in that order. Returns the
/// anchor and the record's leaf.
fn check_named_record(
    env: &Envelope,
    digest: &str,
    key: &VerifyingKey,
) -> Result<(Stated, u64), CheckError> {
    if crate::evidence_log::record_digest(&env.artifact).as_deref() != Some(digest) {
        return fail("the artifact is not the record the subject names");
    }
    let kinds: Vec<&str> = env.verification.iter().map(|v| v.kind.as_str()).collect();
    if !matches!(
        kinds.as_slice(),
        [KIND_CHECKPOINT, KIND_INCLUSION] | [KIND_CHECKPOINT, KIND_INCLUSION, KIND_CONSISTENCY]
    ) {
        return fail("the material is not the anchor checkpoint and the record's proofs");
    }
    let served = stated(&env.verification_content[0], key)?;
    let leaf = inclusion_leaf(&env.verification_content[1])
        .ok_or_else(|| CheckError::Answer("the inclusion proof is malformed".into()))?;
    let covered = leaf_count(served.cp.mmr_size)
        .map_err(|_| CheckError::Answer("the anchor's size is not an MMR size".into()))?;
    let entry = raw_digest(digest)?;
    if leaf >= covered
        || !proves(
            &env.verification_content[1],
            leaf,
            &entry,
            served.cp.mmr_size,
            &served.cp.new_peak_hashes,
        )
    {
        return fail("the record's inclusion proof does not hold");
    }
    if let Some(proof) = env.verification_content.get(2) {
        if !consistent(
            served.cp.prev_size,
            &served.cp.prev_peak_hashes,
            served.cp.mmr_size,
            &served.cp.new_peak_hashes,
            proof,
        ) {
            return fail("the anchor's consistency proof does not hold");
        }
    }
    Ok((served, leaf))
}

fn raw_digest(digest: &str) -> Result<Hash, CheckError> {
    hex::decode(digest)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| CheckError::Answer("a record's digest is malformed".into()))
}

/// A record set: each record's body is the record its digest names, the
/// anchor checkpoint and one inclusion proof per record prove each under it,
/// and the records are the ones the subject names. A range or the full
/// history must be exactly those positions. A `correlation` or `exchange`
/// answer's records must each carry the identifier or cite the half, by the
/// rules the responder's index uses; that the set is complete is not
/// checkable here, and is what the requester's own half proves (-00 §6).
/// Returns the anchor and the leaves.
fn check_record_set(
    env: &Envelope,
    art: &Map<String, Value>,
    subject: &Subject,
    key: &VerifyingKey,
) -> Result<(Stated, Vec<u64>), CheckError> {
    let records = art
        .get("records")
        .and_then(Value::as_array)
        .filter(|r| !r.is_empty() && r.len() <= MAX_ITEMS)
        .ok_or_else(|| CheckError::Answer("the records are malformed".into()))?;
    let kinds: Vec<&str> = env.verification.iter().map(|v| v.kind.as_str()).collect();
    let expected =
        std::iter::once(KIND_CHECKPOINT).chain(std::iter::repeat_n(KIND_INCLUSION, records.len()));
    if !kinds.iter().copied().eq(expected) {
        return fail(
            "the material is not the anchor checkpoint and one inclusion proof per record",
        );
    }
    let served = stated(&env.verification_content[0], key)?;
    check_names(art, &served)?;
    let covered = leaf_count(served.cp.mmr_size)
        .map_err(|_| CheckError::Answer("the anchor's size is not an MMR size".into()))?;

    let mut leaves = Vec::with_capacity(records.len());
    let mut bodies = Vec::with_capacity(records.len());
    for (record, proof) in records.iter().zip(&env.verification_content[1..]) {
        let body = hex_member(record, "body")?;
        // A record of this format, or one that is its own octets.
        let digest = record
            .get("digest")
            .and_then(Value::as_str)
            .filter(|d| {
                *d == sha256_hex(&body)
                    || crate::evidence_log::record_digest(&body).as_deref() == Some(*d)
            })
            .ok_or_else(|| {
                CheckError::Answer("a record's body is not the record its digest names".into())
            })?;
        let leaf = record
            .get("leaf_index")
            .and_then(Value::as_u64)
            .filter(|&i| i < covered)
            .ok_or_else(|| CheckError::Answer("a record is not under the anchor".into()))?;
        if leaves.last().is_some_and(|&prev| prev >= leaf) {
            return fail("the records are not in log order");
        }
        let raw = raw_digest(digest)?;
        if !proves(
            proof,
            leaf,
            &raw,
            served.cp.mmr_size,
            &served.cp.new_peak_hashes,
        ) {
            return fail("a record's inclusion proof does not hold");
        }
        leaves.push(leaf);
        bodies.push(body);
    }
    let fits = match subject {
        Subject::Range(a, b) => leaves.iter().copied().eq(*a..=*b),
        Subject::FullHistory => leaves.iter().copied().eq(0..covered),
        Subject::Correlation(_) | Subject::Exchange(_) => {
            bodies.iter().all(|b| record_fits(subject, b))
        }
        // Answered before a record set is read.
        Subject::Record(_) | Subject::Checkpoints => false,
    };
    if !fits {
        return fail("the records are not the ones the subject names");
    }
    Ok((served, leaves))
}

/// Whether a record body is one the index files under a `correlation` or
/// `exchange` subject: a JSON object, not padding, that carries the
/// identifier or cites the half. It mirrors this plugin's own index, so it
/// holds only for answers from plugin peers (the one live caller is
/// `mesh_evidence_bridge`); -00 §3 does not yet define what "carries" means
/// for other responders.
fn record_fits(subject: &Subject, body: &[u8]) -> bool {
    let Some(record) = serde_json::from_slice::<Value>(body)
        .ok()
        .filter(|r| r.is_object() && !crate::producer::padding::is_padding(r))
    else {
        return false;
    };
    match subject {
        Subject::Correlation(id) => crate::evidence_log::record_correlation_ids(&record)
            .iter()
            .any(|c| c == id),
        Subject::Exchange(half) => crate::evidence_log::counterparty_half_citations(&record)
            .iter()
            .any(|h| h == half),
        _ => false,
    }
}

/// The coverage the request asked for: the pinned anchor, or one at least
/// as fresh as asked, which the envelope states as the anchor attains it.
fn check_coverage(
    env: &Envelope,
    request: &Request,
    served: &Stated,
    records: &[u64],
) -> Result<(), CheckError> {
    let half_pin = matches!((&request.subject, &request.coverage),
        (Subject::Exchange(half), Coverage::ExpectedPin(pin)) if half == pin);
    if !half_pin && env.anchor.digest != served.digest {
        return fail("the envelope names another anchor than the artifact's");
    }
    match &request.coverage {
        Coverage::ExpectedPin(pin) => {
            if env.anchor.digest != *pin || env.anchor.freshness.is_some() {
                return fail("the anchor is not the pinned one");
            }
        }
        Coverage::MinFreshness(Freshness::Size(n)) => {
            let covered = leaf_count(served.cp.mmr_size).unwrap_or(0);
            if env.anchor.freshness != Some(AnchorFreshness::Size(served.cp.mmr_size))
                || covered < *n
            {
                return fail("the anchor is not as fresh as asked");
            }
        }
        Coverage::MinFreshness(Freshness::Time(t)) => {
            let at = profile_time(&served.cp.timestamp);
            if env.anchor.freshness != Some(AnchorFreshness::Time(at.clone()))
                || parse_utc(&at).is_none_or(|at| at < *t)
            {
                return fail("the anchor is not as fresh as asked");
            }
        }
    }
    // A half pinned by itself is answered under the earliest checkpoint
    // covering the records served: the anchor's predecessor must not
    // already cover the last of them.
    if half_pin {
        let before = leaf_count(served.cp.prev_size)
            .map_err(|_| CheckError::Answer("the anchor's size is not an MMR size".into()))?;
        if records.iter().max().is_none_or(|&last| last < before) {
            return fail("the anchor is not the earliest covering the records");
        }
    }
    Ok(())
}

fn hex_member(value: &Value, member: &str) -> Result<Vec<u8>, CheckError> {
    value
        .get(member)
        .and_then(Value::as_str)
        .and_then(|h| hex::decode(h).ok())
        .ok_or_else(|| CheckError::Answer(format!("{member} is not hex")))
}

/// Check every receipt the reply carries. Each must name one of the
/// checkpoints the answer carries and be bound to it: its entry hash is
/// `SHA-256(checkpoint digest)`, the digest of the checkpoint's signed JSON
/// form, which its statement states. It must be a receipt this node reads.
/// When a key is configured for its witness, its proof and signature must
/// cover that entry under the key. Stubs were never registered and are
/// never verified.
fn check_receipts(
    carried: Option<&Value>,
    checkpoints: &[&Stated],
    witness_key: &dyn Fn(&str) -> Option<VerifyingKey>,
) -> Result<Vec<ReceiptCheck>, CheckError> {
    use base64::Engine as _;
    let Some(carried) = carried else {
        return Ok(Vec::new());
    };
    let list = carried
        .as_array()
        .filter(|l| l.len() <= MAX_ITEMS)
        .ok_or(CheckError::ReceiptMalformed)?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let checkpoint = item
            .get("checkpoint")
            .and_then(Value::as_str)
            .and_then(|d| checkpoints.iter().find(|cp| cp.digest == d))
            .ok_or(CheckError::ReceiptMalformed)?;
        let w: WitnessRecord = item
            .get("witness")
            .and_then(|w| serde_json::from_value(w.clone()).ok())
            .ok_or(CheckError::ReceiptMalformed)?;
        let check = |status| ReceiptCheck {
            checkpoint: checkpoint.digest.clone(),
            ts_url: w.ts_url.clone(),
            status,
        };
        if w.is_stub {
            out.push(check(ReceiptStatus::Stub));
            continue;
        }
        let digest = hex::decode(checkpoint.cp.to_checkpoint_record().digest())
            .map_err(|_| CheckError::ReceiptMalformed)?;
        let entry: [u8; 32] = Sha256::digest(&digest).into();
        if w.entry_hash != hex::encode(entry) {
            return Err(CheckError::ReceiptBinding);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&w.receipt_b64)
            .map_err(|_| CheckError::ReceiptMalformed)?;
        match witness_key(&w.ts_url) {
            Some(key) => match evidence_request::receipt::verify(&bytes, &entry, &key) {
                Ok(()) => out.push(check(ReceiptStatus::Verified)),
                Err(evidence_request::receipt::ReceiptError::Malformed(_)) => {
                    return Err(CheckError::ReceiptMalformed)
                }
                Err(evidence_request::receipt::ReceiptError::NotForThisLeaf) => {
                    return Err(CheckError::ReceiptBinding)
                }
            },
            None => {
                evidence_request::receipt::check_form(&bytes)
                    .map_err(|_| CheckError::ReceiptMalformed)?;
                out.push(check(ReceiptStatus::NoKey));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_answer::{self, Outcome, Responder};
    use crate::evidence_request_parity::{
        announced_keys, asker_key, corpus_ledger, corpus_ledger_dir, NODE_KEY_SEED, RESPONDER_NODE,
    };
    use ed25519_dalek::SigningKey;
    use evidence_request::envelope::EnvelopeParts;
    use evidence_request::request;

    const NOW: &str = "2026-09-29T00:00:00Z";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&NODE_KEY_SEED)
    }

    /// How [`Node::outcome`] sets the node up. The default answers anyone
    /// everything (`evidence_answer::ungated`), with exchange corroboration
    /// off and no commitment.
    #[derive(Clone, Copy, Default)]
    struct Setup {
        /// The sharing-policy gate applies.
        gated: bool,
        /// The node is busy and declines unread.
        busy: bool,
        /// `share_exchange_corroboration` is on.
        corroboration: bool,
        /// The digest of the policy the node's commitment signs.
        policy_digest: Option<&'static str>,
    }

    /// A node over the corpus, set up per request by [`Setup`].
    struct Node {
        _dir: tempfile::TempDir,
        ledger: std::path::PathBuf,
        anchors: Vec<String>,
    }

    fn node() -> Node {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger");
        let anchors = corpus_ledger_dir(&ledger, &key())
            .iter()
            .map(|c| c.anchor())
            .collect();
        Node {
            _dir: dir,
            ledger,
            anchors,
        }
    }

    impl Node {
        /// A node over `records` in place of the corpus, with the corpus's
        /// checkpoint positions.
        fn over(records: &[Value]) -> Node {
            use crate::evidence_request_parity::{corpus_checkpoints, write_jsonl};
            let dir = tempfile::tempdir().unwrap();
            let ledger = dir.path().join("ledger");
            let cps = corpus_checkpoints(records, &key());
            std::fs::create_dir_all(&ledger).unwrap();
            write_jsonl(&ledger.join(crate::evidence_log::CAPSULES_FILE), records);
            let lines: Vec<Value> = cps.iter().map(|c| c.line()).collect();
            write_jsonl(&ledger.join(crate::evidence_log::CHECKPOINTS_FILE), &lines);
            Node {
                _dir: dir,
                ledger,
                anchors: cps.iter().map(|c| c.anchor()).collect(),
            }
        }
    }

    impl Node {
        fn ask(&self, request: &Value) -> (Vec<u8>, Value) {
            let bytes = serde_json::to_vec(request).unwrap();
            let outcome = self.outcome(&bytes, Setup::default(), None);
            let Outcome::Answered { wire, .. } = outcome else {
                panic!("{request}: {outcome:?}");
            };
            (bytes, wire)
        }

        /// What the node set up as `setup` does with `bytes`, logging it to
        /// the received log in `log_dir` when one is given.
        fn outcome(
            &self,
            bytes: &[u8],
            setup: Setup,
            log_dir: Option<&std::path::Path>,
        ) -> Outcome {
            let announced = announced_keys();
            let replay = crate::requester_auth::ReplayCache::default();
            let key = key();
            let answer = || {
                evidence_answer::answer_and_log(
                    bytes,
                    setup.busy,
                    &Responder {
                        ledger_dir: &self.ledger,
                        signing_key: &key,
                        now: NOW,
                        history_segments: "peers",
                        share_standard_history: true,
                        share_exchange_corroboration: setup.corroboration,
                        keys: crate::requester_auth::Keys {
                            announced: &announced,
                            configured: None,
                            own_key: None,
                        },
                        replay: &replay,
                        node_id: Some(RESPONDER_NODE),
                        policy_digest: setup.policy_digest,
                    },
                    log_dir,
                )
            };
            if setup.gated {
                answer()
            } else {
                evidence_answer::ungated(answer)
            }
        }

        fn pin(&self, i: usize) -> Value {
            json!({"expected_pin": self.anchors[i]})
        }
    }

    fn check_reply(sent: &[u8], reply: &Value) -> Result<Checked, CheckError> {
        let req = request::parse_json(sent).unwrap();
        check(sent, &req, reply, &key().verifying_key(), &|_| None)
    }

    fn envelope_of(reply: &Value) -> Envelope {
        match envelope::parse_reply(&serde_json::to_vec(reply).unwrap(), Binding::Json) {
            Ok(Reply::Envelope(env)) => *env,
            other => panic!("{other:?}"),
        }
    }

    /// The same answer with `change` made to its parts, signed again by the
    /// responder: what a responder that lies, with its own key, can send.
    fn resigned(sent: &[u8], reply: &Value, change: impl FnOnce(&mut EnvelopeParts)) -> Value {
        resigned_by(&key(), sent, reply, change)
    }

    /// [`resigned`], by the responder whose key is `key`.
    fn resigned_by(
        key: &SigningKey,
        sent: &[u8],
        reply: &Value,
        change: impl FnOnce(&mut EnvelopeParts),
    ) -> Value {
        let env = envelope_of(reply);
        let mut parts = EnvelopeParts {
            subject: env.subject.clone(),
            derivation: env.derivation.clone(),
            anchor: env.anchor.clone(),
            artifact: env.artifact.clone(),
            verification: env
                .verification
                .iter()
                .zip(&env.verification_content)
                .map(|(v, o)| (v.kind.clone(), o.clone()))
                .collect(),
            issued_at: env.issued_at.clone(),
        };
        change(&mut parts);
        let signed = envelope::sign(sent, parts, key).unwrap();
        let mut out: Value = serde_json::from_slice(&signed.encode(Binding::Json)).unwrap();
        if let Some(r) = reply.get(WITNESS_RECEIPTS) {
            out[WITNESS_RECEIPTS] = r.clone();
        }
        out
    }

    fn artifact_json(parts: &EnvelopeParts) -> Value {
        serde_json::from_slice(&parts.artifact).unwrap()
    }

    fn jcs_bytes(v: &Value) -> Vec<u8> {
        evidence_request::jcs::to_string(v).unwrap().into_bytes()
    }

    /// A record answer carries the record's line and the profile's
    /// Checkpointed Local Log material for its `capsule_id`. A profile
    /// verifier cannot tie that name to the line and reports `NOT_CHECKED`,
    /// never `FAIL`; this node's requester checks it, for every record under
    /// either anchor.
    #[test]
    fn a_record_answer_is_checked_here_and_never_failed_by_the_profile() {
        let node = node();
        let ledger = corpus_ledger();
        for (i, record) in ledger.iter().enumerate().take(300) {
            if record.get("record_type") == Some(&json!("padding")) || i == 21 {
                continue;
            }
            let at = usize::from(i >= 16);
            let id = record["capsule_id"].as_str().unwrap();
            let (sent, reply) =
                node.ask(&json!({"subject": {"record": id}, "coverage": node.pin(at)}));
            let env = envelope_of(&reply);
            assert_eq!(
                env.artifact,
                record.to_string().into_bytes(),
                "the line, whole"
            );
            let report =
                cll_material::check_anchor_inclusion(&env, &ResponderLogKey(key().verifying_key()));
            assert_eq!(report.status, cll_material::Status::NotChecked, "{i}");
            assert_eq!(
                env.verification
                    .iter()
                    .map(|v| v.kind.as_str())
                    .collect::<Vec<_>>(),
                if at == 0 {
                    vec![KIND_CHECKPOINT, KIND_INCLUSION]
                } else {
                    vec![KIND_CHECKPOINT, KIND_INCLUSION, KIND_CONSISTENCY]
                }
            );
            let checked = check_reply(&sent, &reply).unwrap();
            assert_eq!(
                (checked.anchor.as_str(), checked.records.as_slice()),
                (node.anchors[at].as_str(), &[i as u64][..])
            );
        }
    }

    /// The same material proves the record's `capsule_id` preimage, a record
    /// that is its own octets: the profile's check passes on it, and this
    /// node's requester accepts it too, as it would from evidencebook.
    #[test]
    fn a_record_that_is_its_own_octets_passes_the_profile_and_is_accepted() {
        let node = node();
        let record = &corpus_ledger()[17];
        let id = record["capsule_id"].as_str().unwrap();
        let (sent, reply) = node.ask(&json!({"subject": {"record": id}, "coverage": node.pin(1)}));
        let mut preimage = record.clone();
        let members = preimage.as_object_mut().unwrap();
        for local in ["capsule_id", "signature", "key_id"] {
            members.remove(local);
        }
        let own = resigned(&sent, &reply, |p| p.artifact = jcs_bytes(&preimage));
        let report = cll_material::check_anchor_inclusion(
            &envelope_of(&own),
            &ResponderLogKey(key().verifying_key()),
        );
        assert_eq!(
            report.status,
            cll_material::Status::Pass,
            "{}",
            report.detail
        );
        assert_eq!(check_reply(&sent, &own).unwrap().records, [17]);
    }

    /// A record that is its own octets passes the profile's check whenever
    /// its path reaches some peak, so a leaf that is itself a peak, sent
    /// with an empty path, passes it at any position. This node's requester
    /// accepts it only at its own position under the anchor's size (review
    /// on Mesh-LLM/mesh-llm#2502: a real leaf 2 accepted as records `[0]`
    /// and `[100]`).
    #[test]
    fn a_record_that_is_its_own_octets_holds_only_at_its_own_position() {
        let (_dir, ledger, key, _) = producer_ledger(3, &[2]);
        let (stated_anchors, _) = anchors_of(&ledger, &key);
        let pin = json!({"expected_pin": stated_anchors[0]});
        let ask = |request: Value| {
            let (checked, wire) = ask_ledger(&ledger, &key, &request);
            checked.unwrap();
            (serde_json::to_vec(&request).unwrap(), wire)
        };
        let check_by = |sent: &[u8], reply: &Value| {
            let req = request::parse_json(sent).unwrap();
            check(sent, &req, reply, &key.verifying_key(), &|_| None)
        };
        // A leaf that is a peak on its own, and its digest.
        let (_, full) = ask(json!({"subject": {"full_history": null}, "coverage": pin}));
        let full = envelope_of(&full);
        let size = stated(&full.verification_content[0], &key.verifying_key())
            .unwrap()
            .cp
            .mmr_size;
        let peak = cll::mmr::peaks(size)
            .unwrap()
            .into_iter()
            .find(|&p| cll::mmr::height_at(p) == 0)
            .expect("the anchor has a one-leaf peak");
        let leaf = cll::mmr::pos_to_leaf_index(peak).unwrap();
        let records: Value = serde_json::from_slice(&full.artifact).unwrap();
        let digest = records["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["leaf_index"] == json!(leaf))
            .unwrap()["digest"]
            .clone();
        let (sent, reply) = ask(json!({"subject": {"record": digest}, "coverage": pin}));
        let mut preimage: Value = serde_json::from_slice(&envelope_of(&reply).artifact).unwrap();
        let members = preimage.as_object_mut().unwrap();
        for local in ["capsule_id", "signature", "key_id"] {
            members.remove(local);
        }
        assert_eq!(json!(sha256_hex(&jcs_bytes(&preimage))), digest);
        let own = resigned_by(&key, &sent, &reply, |p| p.artifact = jcs_bytes(&preimage));
        assert_eq!(check_by(&sent, &own).unwrap().records, [leaf]);
        for forged in [0, leaf - 1, 100, leaf_count(size).unwrap()] {
            let bad = resigned_by(&key, &sent, &reply, |p| {
                p.artifact = jcs_bytes(&preimage);
                p.verification[1].1 = encode_inclusion_proof(forged, &[]).unwrap();
            });
            let report = cll_material::check_anchor_inclusion(
                &envelope_of(&bad),
                &ResponderLogKey(key.verifying_key()),
            );
            assert_eq!(report.status, cll_material::Status::Pass, "{forged}");
            assert_eq!(
                check_by(&sent, &bad).unwrap_err(),
                CheckError::Answer("the record's inclusion proof does not hold".into()),
                "{forged}"
            );
        }
    }

    /// An answer is under the profile the request named. A responder that
    /// answers a request for another profile as `evidence-interop/0` is not
    /// believed, even signing over that request.
    #[test]
    fn an_answer_under_another_profile_than_asked_is_refused() {
        let node = node();
        let id = corpus_ledger()[17]["capsule_id"]
            .as_str()
            .unwrap()
            .to_string();
        let (sent, reply) = node.ask(&json!({"subject": {"record": id}, "coverage": node.pin(1)}));
        for profile in [
            json!("evidence-interop/0"),
            json!("evidence-interop/1"),
            json!(7),
        ] {
            let mut asked: Value = serde_json::from_slice(&sent).unwrap();
            asked["profile"] = profile.clone();
            let asked = serde_json::to_vec(&asked).unwrap();
            let answer = resigned(&asked, &reply, |_| {});
            let checked = check_reply(&asked, &answer);
            if profile == json!("evidence-interop/0") {
                assert!(checked.is_ok(), "{profile}");
            } else {
                assert_eq!(
                    checked.unwrap_err(),
                    CheckError::Answer(
                        "the answer is not under the profile the request named".into()
                    ),
                    "{profile}"
                );
            }
        }
    }

    /// A record answer whose line, proof or consistency proof is not the one
    /// it claims is not evidence, even signed by the responder.
    #[test]
    fn a_resigned_record_that_does_not_hold_is_refused() {
        let node = node();
        let ledger = corpus_ledger();
        let id = ledger[17]["capsule_id"].as_str().unwrap();
        let (sent, reply) = node.ask(&json!({"subject": {"record": id}, "coverage": node.pin(1)}));
        assert!(check_reply(&sent, &reply).is_ok());
        type Change = Box<dyn Fn(&mut EnvelopeParts)>;
        let other = ledger[18].to_string().into_bytes();
        let tampered: Vec<(&str, Change)> = vec![
            (
                "another record's line",
                Box::new(move |p| p.artifact = other.clone()),
            ),
            (
                "its own line, changed",
                Box::new(|p| {
                    let mut line: Value = serde_json::from_slice(&p.artifact).unwrap();
                    line["effect"]["status"] = json!("failed");
                    p.artifact = line.to_string().into_bytes();
                }),
            ),
            (
                "no inclusion proof",
                Box::new(|p| {
                    p.verification.truncate(1);
                }),
            ),
            (
                "a consistency proof that does not hold",
                Box::new(|p| {
                    let last = p.verification[2].1.len() - 1;
                    p.verification[2].1[last] ^= 1;
                }),
            ),
        ];
        for (what, change) in tampered {
            let bad = resigned(&sent, &reply, |p| change(p));
            assert!(
                matches!(check_reply(&sent, &bad), Err(CheckError::Answer(_))),
                "{what}"
            );
        }
    }

    /// The material a record set carries beyond the profile is read by no
    /// profile verifier: it reports `NOT_CHECKED` before it looks.
    #[test]
    fn a_record_sets_extra_material_is_not_checked_by_the_profile() {
        let node = node();
        let (sent, reply) =
            node.ask(&json!({"subject": {"range": [5, 12]}, "coverage": node.pin(0)}));
        let env = envelope_of(&reply);
        let report =
            cll_material::check_anchor_inclusion(&env, &ResponderLogKey(key().verifying_key()));
        assert_eq!(report.status, cll_material::Status::NotChecked);
        assert_eq!(
            check_reply(&sent, &reply).unwrap().records,
            (5..=12).collect::<Vec<_>>()
        );
    }

    /// The artifact is the same for every requester (-00 §5): an unsigned
    /// request and requests signed by two different nodes, differing too in
    /// their nonce and coverage form, get byte-identical artifacts.
    #[test]
    fn the_artifact_is_the_same_whoever_asks() {
        let node = node();
        let now = chrono::DateTime::parse_from_rfc3339(NOW).unwrap().into();
        let signed_by = |asker: &str, mut request: Value| {
            request["requester_id"] = json!(asker);
            crate::requester_auth::sign(
                crate::requester_auth::Channel::EvidenceRequest,
                &mut request,
                &crate::evidence_request_parity::asker_key(asker),
                now,
                RESPONDER_NODE,
            );
            request
        };
        for subject in [
            json!({"range": [16, 20]}),
            json!({"checkpoints": null}),
            json!({"correlation": "n-1"}),
        ] {
            let anonymous = node
                .ask(&json!({"subject": subject, "coverage": node.pin(1), "nonce": "a"}))
                .1;
            let by_a = node
                .ask(&signed_by(
                    "node-a",
                    json!({"subject": subject, "coverage": {"min_freshness": 300}, "nonce": "b"}),
                ))
                .1;
            let by_b = node
                .ask(&signed_by(
                    "node-b",
                    json!({"subject": subject, "coverage": node.pin(1), "nonce": "c"}),
                ))
                .1;
            for (who, other) in [("node-a", &by_a), ("node-b", &by_b)] {
                assert!(
                    other.get("artifact").is_some(),
                    "{subject}: {who} was answered"
                );
                assert_eq!(anonymous["artifact"], other["artifact"], "{subject}: {who}");
                assert_ne!(anonymous["request_digest"], other["request_digest"]);
            }
        }
    }

    /// What a responder signs with its own key is still checked against its
    /// log: a record set whose body, leaf, proof or anchor is not the one it
    /// claims is not evidence.
    #[test]
    fn a_resigned_record_set_that_does_not_hold_is_refused() {
        let node = node();
        let (sent, reply) =
            node.ask(&json!({"subject": {"range": [16, 20]}, "coverage": node.pin(1)}));
        assert!(check_reply(&sent, &reply).is_ok());
        type Change = Box<dyn Fn(&mut EnvelopeParts)>;
        let tampered: Vec<(&str, Change)> = vec![
            (
                "a changed body",
                Box::new(|p| {
                    let mut art = artifact_json(p);
                    art["records"][1]["body"] = json!(hex::encode(b"{}"));
                    p.artifact = jcs_bytes(&art);
                }),
            ),
            (
                "a body under another record's digest",
                Box::new(|p| {
                    let mut art = artifact_json(p);
                    art["records"][1]["body"] = art["records"][2]["body"].clone();
                    art["records"][1]["digest"] = art["records"][2]["digest"].clone();
                    p.artifact = jcs_bytes(&art);
                }),
            ),
            (
                "a record dropped from the range",
                Box::new(|p| {
                    let mut art = artifact_json(p);
                    art["records"].as_array_mut().unwrap().remove(2);
                    p.artifact = jcs_bytes(&art);
                    p.verification.remove(3);
                }),
            ),
            ("proofs swapped", Box::new(|p| p.verification.swap(1, 2))),
            (
                "a proof missing",
                Box::new(|p| {
                    p.verification.pop();
                }),
            ),
            (
                "another anchor named",
                Box::new(|p| {
                    let mut art = artifact_json(p);
                    art["anchor"] = json!("e".repeat(64));
                    p.artifact = jcs_bytes(&art);
                }),
            ),
            (
                "the anchor checkpoint signed by another key",
                Box::new(|p| {
                    let other = SigningKey::from_bytes(&[9; 32]);
                    let ledger = corpus_ledger();
                    let cps = crate::evidence_request_parity::corpus_checkpoints(&ledger, &other);
                    p.verification[0].1 = cps[1].statement.clone();
                }),
            ),
        ];
        for (what, change) in tampered {
            let bad = resigned(&sent, &reply, |p| change(p));
            assert!(
                matches!(check_reply(&sent, &bad), Err(CheckError::Answer(_))),
                "{what}"
            );
        }
    }

    /// A `correlation` or `exchange` answer may carry only records that
    /// carry the identifier or cite the half. A record that does not, slipped
    /// in with its own valid proof under the same anchor and signed by the
    /// responder, is refused; so is a padding record.
    #[test]
    fn a_record_set_with_a_record_the_subject_does_not_name_is_refused() {
        let node = node();
        let half = hex::encode(Sha256::digest(b"the counterparty's own half"));
        // The exchange is answered under the earliest checkpoint covering
        // the citing record, checkpoint 0; the others under checkpoint 1.
        for (subject, coverage, anchor, outsider) in [
            (json!({"correlation": "n-1"}), node.pin(1), 1, 1u64),
            (
                json!({"exchange": half}),
                json!({"expected_pin": half}),
                0,
                5u64,
            ),
            (json!({"correlation": "n-1"}), node.pin(1), 1, 8u64),
        ] {
            let (sent, reply) = node.ask(&json!({"subject": subject, "coverage": coverage}));
            let checked = check_reply(&sent, &reply).unwrap();
            assert!(!checked.records.contains(&outsider), "{subject}");
            // The outsider and its proof, from a range answer under the same anchor.
            let (_, other) = node.ask(&json!({
                "subject": {"range": [outsider, outsider]},
                "coverage": node.pin(anchor),
            }));
            let other = envelope_of(&other);
            let other_record =
                serde_json::from_slice::<Value>(&other.artifact).unwrap()["records"][0].clone();
            let other_proof = other.verification_content[1].clone();
            let bad = resigned(&sent, &reply, |p| {
                let mut art = artifact_json(p);
                let records = art["records"].as_array_mut().unwrap();
                let at = records
                    .iter()
                    .position(|r| r["leaf_index"].as_u64().unwrap() > outsider)
                    .unwrap_or(records.len());
                records.insert(at, other_record.clone());
                p.artifact = jcs_bytes(&art);
                p.verification
                    .insert(at + 1, (KIND_INCLUSION.to_string(), other_proof.clone()));
            });
            assert!(
                matches!(check_reply(&sent, &bad), Err(CheckError::Answer(_))),
                "{subject} with record {outsider}"
            );
        }
    }

    /// The index never files padding under a subject, so a padding record
    /// that carries the identifier or cites the half still does not fit.
    #[test]
    fn padding_never_fits_a_correlation_or_exchange() {
        let half = "c".repeat(64);
        let record = |record_type: &str| {
            serde_json::to_vec(&json!({
                "record_type": record_type,
                "nonce": "n-1",
                "references": [{
                    "type": "capsule", "digest_alg": "SHA-256", "digest": half,
                    "citation_purpose": "counterparty_half",
                }],
            }))
            .unwrap()
        };
        for subject in [
            Subject::Correlation("n-1".into()),
            Subject::Exchange(half.clone()),
        ] {
            assert!(record_fits(&subject, &record("served")), "{subject:?}");
            assert!(!record_fits(&subject, &record("padding")), "{subject:?}");
        }
        assert!(!record_fits(
            &Subject::Correlation("n-1".into()),
            b"not json"
        ));
    }

    /// A checkpoint list and a history card must start the stream and chain
    /// to the anchor, and a history card's consistency proofs must hold.
    #[test]
    fn a_resigned_checkpoint_list_or_history_that_does_not_chain_is_refused() {
        let node = node();
        let (sent, reply) =
            node.ask(&json!({"subject": {"checkpoints": null}, "coverage": node.pin(1)}));
        assert_eq!(check_reply(&sent, &reply).unwrap().checkpoints, 2);
        let bad = resigned(&sent, &reply, |p| {
            let mut art = artifact_json(p);
            art["checkpoints"].as_array_mut().unwrap().remove(0);
            p.artifact = jcs_bytes(&art);
        });
        assert!(
            check_reply(&sent, &bad).is_err(),
            "a list that does not start the stream"
        );

        let card = json!({"subject": {"full_history": null}, "coverage": node.pin(1), "derivation": "history_card/1"});
        let (sent, reply) = node.ask(&card);
        assert_eq!(check_reply(&sent, &reply).unwrap().checkpoints, 2);
        let bad = resigned(&sent, &reply, |p| {
            let mut art = artifact_json(p);
            let proof = art["history"][1]["consistency_from_previous"]
                .as_str()
                .unwrap()
                .to_string();
            let mut bytes = hex::decode(proof).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            art["history"][1]["consistency_from_previous"] = json!(hex::encode(bytes));
            p.artifact = jcs_bytes(&art);
        });
        assert!(
            check_reply(&sent, &bad).is_err(),
            "a consistency proof that does not hold"
        );
        let bad = resigned(&sent, &reply, |p| {
            let mut art = artifact_json(p);
            art["history"][1]["consistency_from_previous"] = Value::Null;
            p.artifact = jcs_bytes(&art);
        });
        assert!(
            check_reply(&sent, &bad).is_err(),
            "a missing consistency proof"
        );
    }

    /// The envelope must answer what was asked: the subject, the pin, and
    /// the freshness the anchor attains as the envelope states it.
    #[test]
    fn an_answer_to_another_question_is_refused() {
        let node = node();
        let ledger = corpus_ledger();
        let id = ledger[0]["capsule_id"].as_str().unwrap();
        let (sent, reply) =
            node.ask(&json!({"subject": {"record": id}, "coverage": {"min_freshness": 300}}));
        assert!(check_reply(&sent, &reply).is_ok());
        let bad = resigned(&sent, &reply, |p| {
            p.anchor.freshness = Some(AnchorFreshness::Size(1))
        });
        assert!(
            check_reply(&sent, &bad).is_err(),
            "a freshness the anchor does not attain"
        );
        // Asked under the other anchor: the same answer does not satisfy it.
        let other =
            serde_json::to_vec(&json!({"subject": {"record": id}, "coverage": node.pin(0)}))
                .unwrap();
        let req = request::parse_json(&other).unwrap();
        assert!(check(&other, &req, &reply, &key().verifying_key(), &|_| None).is_err());
        // Asked about another record, or another subject form: the answer
        // names a subject the request did not.
        let another = ledger[1]["capsule_id"].as_str().unwrap();
        for subject in [json!({"record": another}), json!({"range": [0, 0]})] {
            let asked = serde_json::to_vec(
                &json!({"subject": subject, "coverage": {"min_freshness": 300}}),
            )
            .unwrap();
            let req = request::parse_json(&asked).unwrap();
            // Signed for this request, so only the subject it names differs.
            let answer = resigned(&asked, &reply, |_| {});
            assert!(
                matches!(
                    check(&asked, &req, &answer, &key().verifying_key(), &|_| None),
                    Err(CheckError::Answer(_))
                ),
                "{subject}"
            );
        }
    }

    /// A `served_summary/1` answer, signed by the responder's own key, is
    /// not checked here: this node neither answers nor reads the served
    /// summary (Mesh-LLM/capsules-plugin#106), so an older peer's is refused
    /// like any derivation it does not check.
    #[test]
    fn a_served_summary_is_a_derivation_this_node_does_not_check() {
        let node = node();
        let (sent, reply) = node.ask(&json!({"subject": {"full_history": null}, "coverage": node.pin(1), "derivation": "history_card/1"}));
        let mut asked: Value = serde_json::from_slice(&sent).unwrap();
        asked["derivation"] = json!("served_summary/1");
        let sent = serde_json::to_vec(&asked).unwrap();
        let answer = resigned(&sent, &reply, |p| {
            p.derivation = Some(Derivation::Token("served_summary/1".into()));
        });
        assert_eq!(
            check_reply(&sent, &answer).unwrap_err(),
            CheckError::Answer("the answer is for a derivation this node does not check".into())
        );
    }

    /// A receipt is for one of the checkpoints the answer carries, by its
    /// statement's digest; naming any other is malformed.
    #[test]
    fn a_receipt_must_name_a_checkpoint_the_answer_carries() {
        let node = node();
        let (sent, mut reply) =
            node.ask(&json!({"subject": {"checkpoints": null}, "coverage": node.pin(1)}));
        let receipts = reply[WITNESS_RECEIPTS].as_array().unwrap().clone();
        assert_eq!(receipts.len(), 1, "the corpus's one stub witness");
        assert_eq!(receipts[0]["checkpoint"], json!(node.anchors[1]));
        let checked = check_reply(&sent, &reply).unwrap();
        assert_eq!(checked.receipts[0].status, ReceiptStatus::Stub);
        reply[WITNESS_RECEIPTS][0]["checkpoint"] = json!("e".repeat(64));
        assert_eq!(
            check_reply(&sent, &reply).unwrap_err(),
            CheckError::ReceiptMalformed
        );
    }

    /// A ledger the producer itself wrote: `records` sealed exchanges, with
    /// capsule-emit's own checkpointer cutting a checkpoint after each
    /// record listed in `cuts`. Returns the directory, the ledger and the
    /// node key.
    fn producer_ledger(
        records: usize,
        cuts: &[usize],
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        SigningKey,
        Vec<String>,
    ) {
        use crate::producer::anchor::AnchorClient;
        use crate::producer::checkpoint::{CheckpointCadenceConfig, CheckpointState};
        let dir = tempfile::tempdir().unwrap();
        let state = crate::capsule_emit::CapsuleState::open(dir.path(), "node-under-test").unwrap();
        let ledger = state.ledger_dir().to_path_buf();
        let (mut checkpoints, _) = CheckpointState::load(
            &ledger,
            "node-under-test",
            CheckpointCadenceConfig::default(),
        )
        .unwrap();
        let anchor = AnchorClient::new("http://127.0.0.1:1");
        let mut ids = Vec::new();
        for i in 0..records {
            let id = format!("e-{i}");
            let emitted = state
                .emit_for_exchange(&crate::capsule_emit::ExchangeRecord {
                    model: "m",
                    client_nonce: None,
                    request_bytes: b"{}",
                    response_bytes: b"{}",
                    latency_ms: 1.0,
                    exchange_id: Some(&id),
                    requesting_party: Some("party"),
                    host_provenance: None,
                })
                .unwrap();
            ids.push(emitted.capsule_id);
            if cuts.contains(&i) {
                checkpoints
                    .checkpoint_covering(&ids[i], state.signing_key(), &anchor)
                    .unwrap();
            }
        }
        let key = state.signing_key().clone();
        (dir, ledger, key, ids)
    }

    /// The anchors of `ledger` (stated checkpoints) and its chain length.
    fn anchors_of(ledger: &std::path::Path, key: &SigningKey) -> (Vec<String>, usize) {
        let key_id = hex::encode(key.verifying_key().to_bytes());
        crate::evidence_log::with_index(ledger, &key_id, |index| {
            let stated = index.chain.iter().map(|c| c.anchor_digest()).collect();
            (stated, index.chain.len())
        })
        .unwrap()
    }

    /// `request` answered from `ledger`, openly (`evidence_answer::ungated`),
    /// and checked as a requester checks it.
    fn ask_ledger(
        ledger: &std::path::Path,
        key: &SigningKey,
        request: &Value,
    ) -> (Result<Checked, CheckError>, Value) {
        let bytes = serde_json::to_vec(request).unwrap();
        let announced = announced_keys();
        let replay = crate::requester_auth::ReplayCache::default();
        let outcome = evidence_answer::ungated(|| {
            evidence_answer::answer_and_log(
                &bytes,
                false,
                &Responder {
                    ledger_dir: ledger,
                    signing_key: key,
                    now: NOW,
                    history_segments: "peers",
                    share_standard_history: true,
                    share_exchange_corroboration: false,
                    keys: crate::requester_auth::Keys {
                        announced: &announced,
                        configured: None,
                        own_key: None,
                    },
                    replay: &replay,
                    node_id: Some(RESPONDER_NODE),
                    policy_digest: None,
                },
                None,
            )
        });
        let Outcome::Answered { wire, .. } = outcome else {
            panic!("{request}: {outcome:?}");
        };
        let req = request::parse_json(&bytes).unwrap();
        (
            check(&bytes, &req, &wire, &key.verifying_key(), &|_| None),
            wire,
        )
    }

    /// A ledger the producer itself wrote, checkpointed by capsule-emit's
    /// own checkpointer: its checkpoints anchor answers, and a record, the
    /// full history and a history card served from it verify. A profile
    /// verifier reports the record `NOT_CHECKED`, never `FAIL`.
    #[test]
    fn a_ledger_the_producer_wrote_is_answered_and_verifies() {
        let (_dir, ledger, key, ids) = producer_ledger(5, &[2, 4]);
        let (stated, total) = anchors_of(&ledger, &key);
        assert_eq!(
            (stated.len(), total),
            (2, 2),
            "both checkpoints are stated anchors"
        );
        let (checked, wire) = ask_ledger(
            &ledger,
            &key,
            &json!({"subject": {"record": ids[3]}, "coverage": {"expected_pin": stated[1]}}),
        );
        assert_eq!(checked.unwrap().anchor, stated[1]);
        let report = cll_material::check_anchor_inclusion(
            &envelope_of(&wire),
            &ResponderLogKey(key.verifying_key()),
        );
        assert_eq!(
            report.status,
            cll_material::Status::NotChecked,
            "{}",
            report.detail
        );
        let full = json!({"subject": {"full_history": null}, "coverage": {"min_freshness": 1}});
        assert!(ask_ledger(&ledger, &key, &full).0.unwrap().records.len() >= 5);
        let card = json!({"subject": {"full_history": null}, "coverage": {"expected_pin": stated[1]}, "derivation": "history_card/1"});
        assert_eq!(ask_ledger(&ledger, &key, &card).0.unwrap().checkpoints, 2);
    }

    /// A checkpoint whose line lost its COSE statement ends the chain, as
    /// any checkpoint this index cannot take does: what came before it is
    /// still answered and verifies, and nothing after it is served, so every
    /// list an answer carries extends checkpoint by checkpoint.
    #[test]
    fn a_checkpoint_without_its_statement_ends_the_chain() {
        let (_dir, ledger, key, _) = producer_ledger(6, &[1, 3, 5]);
        let path = ledger.join(crate::evidence_log::CHECKPOINTS_FILE);
        let lines: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        let last = hex::encode(Sha256::digest(
            hex::decode(lines[2]["checkpoint_cose"].as_str().unwrap()).unwrap(),
        ));
        let mut stripped = lines.clone();
        stripped[1]
            .as_object_mut()
            .unwrap()
            .remove("checkpoint_cose");
        crate::evidence_request_parity::write_jsonl(&path, &stripped);
        let (anchors, total) = anchors_of(&ledger, &key);
        assert_eq!(total, 1, "the chain ends before the unstated checkpoint");

        let card = json!({"subject": {"full_history": null}, "coverage": {"expected_pin": anchors[0]}, "derivation": "history_card/1"});
        assert_eq!(ask_ledger(&ledger, &key, &card).0.unwrap().checkpoints, 1);
        let bytes = serde_json::to_vec(
            &json!({"subject": {"checkpoints": null}, "coverage": {"expected_pin": last}}),
        )
        .unwrap();
        let announced = announced_keys();
        let replay = crate::requester_auth::ReplayCache::default();
        let outcome = evidence_answer::answer_and_log(
            &bytes,
            false,
            &Responder {
                ledger_dir: &ledger,
                signing_key: &key,
                now: NOW,
                history_segments: "peers",
                share_standard_history: true,
                share_exchange_corroboration: false,
                keys: crate::requester_auth::Keys {
                    announced: &announced,
                    configured: None,
                    own_key: None,
                },
                replay: &replay,
                node_id: Some(RESPONDER_NODE),
                policy_digest: None,
            },
            None,
        );
        assert!(
            matches!(
                outcome,
                Outcome::Refused {
                    reason: Reason::CoverageUnsatisfiable,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }

    /// Every answer form this node gives, gated and ungated, refusals
    /// included, and the received-log line each one writes, byte for byte as Mesh-LLM/capsules-plugin 5d2d102 gave
    /// them: the baseline the move onto the evidencebook crate
    /// (evidencebook#35) is held to. Artifact octets, material kinds and
    /// order, witness receipts and signed refusals all sit in the wire.
    /// `CAPSULES_WRITE_ANSWER_FIXTURE=1` rewrites the fixture instead. Only a
    /// change that means to alter an answer rewrites it, says so, and updates
    /// the SHA-256 pinned below, so the rewrite shows in review; a move of
    /// code alone never does. `served_summary` and `served_summary_first`
    /// hold the `derivation_unsupported` refusals the retired served summary
    /// gets (Mesh-LLM/capsules-plugin#106).
    #[test]
    fn every_answer_form_is_byte_for_byte_the_baseline() {
        const FIXTURE: &str = "tests/fixtures/evidence_answers_5d2d102.json";
        const FIXTURE_SHA256: &str =
            "a3700f4095403d798151046b0acb78ee2b82d3e279d6332348eb6b5a5a51cbfc";
        let node = node();
        let last = node.anchors.len() - 1;
        let half = hex::encode(Sha256::digest(b"the counterparty's own half"));
        let leaves = leaf_count(node_size(&node, last)).unwrap();
        let plain = Setup::default();
        let gated = Setup {
            gated: true,
            ..plain
        };
        let unsigned = |request: Value| serde_json::to_vec(&request).unwrap();
        // Signed at `NOW` by `key` for this node, with a nonce fixed by the
        // case's name so the bytes are the same every run.
        let signed = |key: &SigningKey, name: &str, mut request: Value| {
            request["nonce"] = json!(hex::encode(Sha256::digest(name.as_bytes())));
            crate::requester_auth::sign(
                crate::requester_auth::Channel::EvidenceRequest,
                &mut request,
                key,
                chrono::DateTime::parse_from_rfc3339(NOW).unwrap().into(),
                RESPONDER_NODE,
            );
            serde_json::to_vec(&request).unwrap()
        };
        let ledger = corpus_ledger();
        let id = |i: usize| ledger[i]["capsule_id"].clone();
        let mut cases: Vec<(String, Vec<u8>, Setup)> = vec![
            (
                "range_last".into(),
                unsigned(
                    json!({"subject": {"range": [leaves.saturating_sub(10), leaves - 1]}, "coverage": node.pin(last)}),
                ),
                plain,
            ),
            (
                "range_first".into(),
                unsigned(json!({"subject": {"range": [0, 2]}, "coverage": node.pin(0)})),
                plain,
            ),
            (
                "range_fresh".into(),
                unsigned(json!({"subject": {"range": [1, 3]}, "coverage": {"min_freshness": 1}})),
                plain,
            ),
            (
                "full_history_first".into(),
                unsigned(json!({"subject": {"full_history": null}, "coverage": node.pin(0)})),
                plain,
            ),
            (
                "full_history_last".into(),
                unsigned(json!({"subject": {"full_history": null}, "coverage": node.pin(last)})),
                plain,
            ),
            (
                "correlation".into(),
                unsigned(json!({"subject": {"correlation": "n-1"}, "coverage": node.pin(last)})),
                plain,
            ),
            (
                "exchange".into(),
                unsigned(
                    json!({"subject": {"exchange": half}, "coverage": {"expected_pin": half}}),
                ),
                plain,
            ),
            (
                "checkpoints".into(),
                unsigned(json!({"subject": {"checkpoints": null}, "coverage": node.pin(last)})),
                plain,
            ),
            (
                "checkpoints_time".into(),
                unsigned(
                    json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": "2026-01-01T00:00:00Z"}}),
                ),
                plain,
            ),
            (
                "history_card_first".into(),
                unsigned(
                    json!({"subject": {"full_history": null}, "coverage": node.pin(0), "derivation": "history_card/1"}),
                ),
                plain,
            ),
            (
                "history_card".into(),
                unsigned(
                    json!({"subject": {"full_history": null}, "coverage": node.pin(last), "derivation": "history_card/1"}),
                ),
                plain,
            ),
            (
                "history_card_checkpoints".into(),
                unsigned(
                    json!({"subject": {"checkpoints": null}, "coverage": node.pin(last), "derivation": "history_card/1"}),
                ),
                plain,
            ),
            (
                "served_summary".into(),
                unsigned(
                    json!({"subject": {"full_history": null}, "coverage": node.pin(last), "derivation": "served_summary/1"}),
                ),
                plain,
            ),
            (
                "served_summary_first".into(),
                unsigned(
                    json!({"subject": {"full_history": null}, "coverage": node.pin(0), "derivation": "served_summary/1"}),
                ),
                plain,
            ),
            (
                "refused_unknown_pin".into(),
                unsigned(
                    json!({"subject": {"full_history": null}, "coverage": {"expected_pin": "00".repeat(32)}}),
                ),
                plain,
            ),
            (
                "refused_unknown_derivation".into(),
                unsigned(
                    json!({"subject": {"full_history": null}, "coverage": node.pin(last), "derivation": "no_such/1"}),
                ),
                plain,
            ),
            (
                "refused_range_past_the_log".into(),
                unsigned(
                    json!({"subject": {"range": [leaves, leaves + 2]}, "coverage": node.pin(last)}),
                ),
                plain,
            ),
            (
                "refused_unknown_record".into(),
                unsigned(
                    json!({"subject": {"record": "00".repeat(32)}, "coverage": node.pin(last)}),
                ),
                plain,
            ),
            (
                "refused_busy".into(),
                unsigned(json!({"subject": {"record": id(0)}, "coverage": node.pin(last)})),
                Setup {
                    busy: true,
                    ..plain
                },
            ),
            // A node with a commitment adds its policy digest to a refusal.
            (
                "refused_with_policy_digest".into(),
                unsigned(
                    json!({"subject": {"record": "00".repeat(32)}, "coverage": node.pin(last)}),
                ),
                Setup {
                    policy_digest: Some("ab"),
                    ..plain
                },
            ),
            // The received log's identity fields: a stated id past the cut,
            // a key the host binds, and a key nobody binds.
            (
                "requester_id_cut".into(),
                unsigned(
                    json!({"subject": {"record": id(0)}, "coverage": node.pin(last), "requester_id": "r".repeat(200)}),
                ),
                plain,
            ),
            (
                "signed_bound".into(),
                signed(
                    &asker_key("node-a"),
                    "signed_bound",
                    json!({"subject": {"record": id(0)}, "coverage": node.pin(last), "requester_id": "node-a"}),
                ),
                plain,
            ),
            (
                "signed_unbound".into(),
                signed(
                    &SigningKey::from_bytes(&[7; 32]),
                    "signed_unbound",
                    json!({"subject": {"record": id(0)}, "coverage": node.pin(last)}),
                ),
                plain,
            ),
        ];
        // Both sides of the first checkpoint and the record no checkpoint
        // covers, padding (8-15, 22-23) and the local block (21) included, as
        // the ungated node answers them; then the sharing-policy gate's
        // answers to a stranger and to node-a.
        for i in (0..24).chain([ledger.len() - 1]) {
            for anchor in [0, last] {
                cases.push((
                    format!("record_{i}_at_{anchor}"),
                    unsigned(json!({"subject": {"record": id(i)}, "coverage": node.pin(anchor)})),
                    plain,
                ));
            }
            let request = json!({"subject": {"record": id(i)}, "coverage": node.pin(last)});
            let name = format!("gated_record_{i}_by_node_a");
            cases.push((
                name.clone(),
                signed(&asker_key("node-a"), &name, request.clone()),
                gated,
            ));
            cases.push((
                format!("gated_record_{i}_unsigned"),
                unsigned(request),
                gated,
            ));
        }
        let log = tempfile::tempdir().unwrap();
        let mut got = serde_json::Map::new();
        for (name, bytes, setup) in &cases {
            let wire = match node.outcome(bytes, *setup, Some(log.path())) {
                Outcome::Answered { wire, .. } | Outcome::Refused { wire, .. } => wire,
                Outcome::Unanswerable(why) => panic!("{name}: {why}"),
            };
            got.insert(name.clone(), wire);
        }
        // No corpus record binds a client nonce, so exchange corroboration
        // is asked of a node whose leaf 3 is a served half that binds one.
        let mut bound = ledger.clone();
        bound[3] = crate::evidence_request_parity::sealed(json!({
            "action_type": "fyi",
            "effect": {
                "status": "confirmed",
                "request_digest": "309957a1892149c2ec8f2b55d3b742d19f821ab3d534ff8b486f70846a76397b",
                "response_digest": "6fd96e3c9fcc6c5ef8b787eb7603c742072030a98fec58c6b2ded29c738d3578",
            },
            "model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {
                "role": "served",
                "client_nonce_source": "client",
                "client_nonce": "c-1",
                "serving_provenance": {"requesting_party": "node-a", "served_by_node_id": RESPONDER_NODE},
            }}},
        }));
        let corroborating = Node::over(&bound);
        let request =
            crate::exchange_corroboration::request_for(&hex::encode(Sha256::digest(b"c-1")));
        let outcome = corroborating.outcome(
            &serde_json::to_vec(&request).unwrap(),
            Setup {
                corroboration: true,
                ..plain
            },
            Some(log.path()),
        );
        let Outcome::Answered { wire, .. } = outcome else {
            panic!("exchange corroboration: {outcome:?}");
        };
        got.insert("exchange_corroboration".into(), wire);
        let lines: Vec<Value> =
            std::fs::read_to_string(log.path().join(evidencebook::received::RECEIVED_LOG_FILE))
                .unwrap()
                .lines()
                .map(|line| Value::String(line.into()))
                .collect();
        assert_eq!(
            lines.len(),
            cases.len() + 1,
            "one received-log line per request"
        );
        got.insert("received_log".into(), Value::Array(lines));
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
        if std::env::var_os("CAPSULES_WRITE_ANSWER_FIXTURE").is_some() {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&Value::Object(got)).unwrap() + "\n",
            )
            .unwrap();
            return;
        }
        let text = std::fs::read(&path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&text)),
            FIXTURE_SHA256,
            "the fixture was rewritten"
        );
        let want: serde_json::Map<String, Value> = serde_json::from_slice(&text).unwrap();
        assert_eq!(
            got.keys().collect::<Vec<_>>(),
            want.keys().collect::<Vec<_>>()
        );
        for (name, wire) in &want {
            assert_eq!(
                serde_json::to_string(&got[name]).unwrap(),
                serde_json::to_string(wire).unwrap(),
                "{name}"
            );
        }
    }

    /// The MMR size of the node's checkpoint `i`, from its pinned answer.
    fn node_size(node: &Node, i: usize) -> u64 {
        let (_, reply) =
            node.ask(&json!({"subject": {"checkpoints": null}, "coverage": node.pin(i)}));
        let list = serde_json::from_slice::<Value>(&envelope_of(&reply).artifact).unwrap()
            ["checkpoints"]
            .as_array()
            .unwrap()
            .clone();
        let statement = hex::decode(list.last().unwrap().as_str().unwrap()).unwrap();
        verify_checkpoint_cose_offline(&statement)
            .decoded
            .unwrap()
            .mmr_size
    }

    /// A checkpoint line whose witness entry is not a receipt (no `ts_url`)
    /// does not read as a checkpoint, so nothing is served under it.
    #[test]
    fn a_malformed_witness_entry_is_not_read_as_a_checkpoint() {
        let dir =
            crate::evidence_answer::tests::node_with_witnesses(|_| json!([{"entry_hash": "ab"}]));
        let key_id = hex::encode(key().verifying_key().to_bytes());
        let chain = crate::evidence_log::with_index(dir.path(), &key_id, |index| index.chain.len());
        assert_eq!(chain.unwrap(), 0, "no checkpoint is read");
    }

    /// The serving checkpoint for an `exchange` subject is the earliest one
    /// covering the last record citing the half: a citing record committed
    /// again after the first checkpoint moves the answer under the second,
    /// and a citing record no checkpoint covers yet moves nothing.
    #[test]
    fn an_exchange_is_served_under_the_checkpoint_covering_its_last_citing_record() {
        let half = hex::encode(Sha256::digest(b"the counterparty's own half"));
        let ledger = corpus_ledger();
        let citing = ledger
            .iter()
            .position(|r| crate::evidence_log::counterparty_half_citations(r).contains(&half))
            .unwrap();
        assert!(citing < 16, "the corpus cites the half under checkpoint 0");
        let ask = |ledger: &[Value]| {
            let node = Node::over(ledger);
            let (sent, reply) = node
                .ask(&json!({"subject": {"exchange": half}, "coverage": {"expected_pin": half}}));
            let checked = check_reply(&sent, &reply).unwrap();
            (checked.anchor, node.anchors.clone(), checked.records)
        };
        let (anchor, anchors, records) = ask(&ledger);
        assert_eq!(anchor, anchors[0]);
        assert_eq!(records, vec![citing as u64]);

        let mut twice = ledger.clone();
        twice[20] = ledger[citing].clone();
        let (anchor, anchors, records) = ask(&twice);
        assert_eq!(anchor, anchors[1]);
        assert_eq!(records, vec![citing as u64, 20]);

        let mut uncovered = ledger.clone();
        let last = uncovered.len() - 1;
        uncovered[last] = ledger[citing].clone();
        let (anchor, anchors, _) = ask(&uncovered);
        assert_eq!(
            anchor, anchors[0],
            "a citing record past the latest checkpoint moves nothing"
        );
    }

    /// What `build` refuses with where only the builder can refuse: a line
    /// rewritten after it was indexed is `no_such_subject`, and a record
    /// the serving checkpoint cannot prove is `policy_declined`, as before
    /// the answers moved onto evidencebook.
    #[test]
    fn the_builders_own_refusals_keep_their_reasons() {
        use evidence_request::resolve::{self, Resolution};
        let node = node();
        let ledger = corpus_ledger();
        let key_id = hex::encode(key().verifying_key().to_bytes());
        let ask = |leaf: u64, at: usize, rewrite: bool| {
            let wire = json!({"subject": {"record": ledger[leaf as usize]["capsule_id"]},
                              "coverage": node.pin(at)});
            let bytes = serde_json::to_vec(&wire).unwrap();
            let req = request::parse_json(&bytes).unwrap();
            crate::evidence_log::with_index(&node.ledger, &key_id, |index| {
                if rewrite {
                    // Same length, another capsule_id: no longer the line indexed.
                    let path = node.ledger.join(crate::evidence_log::CAPSULES_FILE);
                    let text = std::fs::read_to_string(&path).unwrap();
                    let id = ledger[leaf as usize]["capsule_id"].as_str().unwrap();
                    let other: String = id.chars().rev().collect();
                    std::fs::write(&path, text.replacen(id, &other, 1)).unwrap();
                }
                let view = index.view().unwrap();
                let Resolution::Artifact(resolved) = resolve::resolve(&req, &view) else {
                    panic!("resolved");
                };
                build(
                    &Build {
                        request: &req,
                        request_bytes: &bytes,
                        resolved: &resolved,
                        at,
                        records: &[leaf],
                        signing_key: &key(),
                        issued_at: NOW,
                    },
                    &view,
                )
            })
            .unwrap()
        };
        assert!(ask(2, 0, false).is_ok());
        // Leaf 20 is under the last checkpoint only: no proof to it under
        // the first, a fault of this node's own (the responder keeps such a
        // record out before it builds). capacity_exceeded, which the
        // responder sends as policy_declined to an evidence-interop/0 request.
        assert_eq!(ask(20, 0, false).unwrap_err(), Reason::CapacityExceeded);
        assert_eq!(ask(2, 0, true).unwrap_err(), Reason::NoSuchSubject);
    }
}
