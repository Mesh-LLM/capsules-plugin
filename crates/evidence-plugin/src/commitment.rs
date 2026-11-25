//! This node's commitment (loop step 3, Advertise): one signed object that
//! says how the node can be asked for evidence and what it can answer, never
//! what it has done. It carries no counts.
//!
//! **Shapes.** The commitment is `evidence-commitment/1`, with the staple
//! filed as one `history_cards` entry that names its stream and the
//! checkpoint key, so a third party verifies the staple offline (a `/0`, with
//! a bare `history_card`, is still read from a peer). Its policy is
//! `disclosure-policy/0`, exactly as evidence-network/loop checks them
//! (`steps/03-advertise.md`, `scripts/check_commitment.py`): the members
//! below and no others, each signed with this node's key by Ed25519 over the
//! RFC 8785 (JCS) form of the object without `sig`, `sig.value` unpadded
//! base64url. `lcap.policy_digest` is the SHA-256 of the signed policy
//! file's bytes, which are that file's JCS form, so the same settings and key
//! always give the same digest.
//!
//! **The policy states what is enforced.** [`Policy`] is read from the same
//! setting readers the answer gate reads (`share_policy`), and the
//! responder's own switches come from it (`mesh_evidence_bridge`), so the
//! digest a commitment advertises and the digest a refusal names
//! (`evidence_answer::Responder::policy_digest`) are of one policy. The
//! default settings give exactly the pinned file
//! `policies/disclosure-default.json` ([`DEFAULT_POLICY`]); a test holds the
//! two together, so the file cannot drift from the code.
//!
//! **What it is built from.** `checkpoint` is this node's latest signed
//! checkpoint statement, whole. The staple is the `history_card/2` answer
//! this node gives any stranger at that checkpoint (`evidence-interop/0`,
//! presented by this node). A node with no checkpoint yet has no commitment.
//!
//! **The controller binding.** When this node holds a binding of its key to
//! its operator's that applies (`controller_binding::binds_own`), the
//! commitment names it in the optional `controller_binding` member by its
//! binding digest alone (CB §4, §9.3; loop's `steps/03-advertise.md`), never
//! the record, so the commitment never names the operator's key. Steven's
//! step 12 ruling (Mesh-LLM/capsules-plugin#54): the binding is optional.
//!
//! **Carriers.** The `commitment/1` mesh channel serves it to a peer
//! (`commitment_bridge`); the `commitment` operation hands it to the
//! operator, who publishes it to loop's `nodes/commitments/` by pull request.
//! A requester checks a fetched one with [`verify`].

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use evidence_request::registry::is_digest;
use evidence_request::registry::{SubjectForm, DERIVATION_HISTORY_CARD};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::evidence_answer::{self, Outcome, Responder};
use crate::share_policy;

pub const COMMITMENT_PROFILE: &str = "evidence-commitment/1";
/// The profile this plugin signed until `/1`; a peer's commitment of it is
/// still read, as one card (loop's `PROFILE_0`).
pub const LEGACY_COMMITMENT_PROFILE: &str = "evidence-commitment/0";
/// The community a mesh node's stapled card belongs to (loop's
/// `history_cards.DEFAULT_COMMUNITY`).
pub const COMMUNITY: &str = "mesh-llm";
/// The communities a peer's stapled card may name: a word-for-word copy of
/// loop's closed list (`scripts/history_cards.py` `COMMUNITIES`, evidence-network/loop).
/// A new community is added there first and here after it (Mesh-LLM/capsules-plugin#320).
/// Only [`COMMUNITY`] is written on this node's own card.
const KNOWN_COMMUNITIES: [&str; 3] = ["mesh-llm", "muse", "goose"];
pub const POLICY_PROFILE: &str = "disclosure-policy/0";
/// The stapled answer's format: the plugin's flat interop reply.
pub const STAPLE_PROFILE: &str = "evidence-interop/0";

/// The policy body the default settings give, as shipped.
#[cfg(test)]
pub const DEFAULT_POLICY: &str = include_str!("../../../policies/disclosure-default.json");

/// How an ask reaches this node: its own evidence-request channel over the
/// mesh, addressed by node id.
pub const ASK_BINDING: &str = "capsules-evidence-request/iroh";

/// The kind of claim this node's records answer: each is its own half of an
/// exchange it performed with a counterparty.
pub const PREDICATE_CLASSES: [&str; 1] = ["performed:counterparty_half"];

/// An automatic responder answers within the responder's own bounds (10 s
/// per step, plus the mesh stream's); a node silent for longer is absent.
pub const ANSWERS_WITHIN: &str = "PT1M";

/// The derivations this node answers, each as an ask names it:
/// `checkpoints` (the subject, which needs none), the registered tokens, and
/// `exchange_corroboration/1` and `service_history/1` by the digest of each
/// one's definition document, its name on the wire. Service History's is the
/// definition this node serves (`service_history::definition_digest`), so it
/// is read once at run time. A counterparty is answered each of them under
/// every setting; who else gets one is the policy's to say. `checkpoints`
/// and `checkpoint_range` are the subjects, named like the derivations; the
/// unranged `checkpoints` leaves the list once its full answer no longer fits
/// ([`Policy::checkpoints`]).
pub static DERIVATIONS: std::sync::LazyLock<[&str; 8]> = std::sync::LazyLock::new(|| {
    [
        "checkpoints",
        evidence_request::registry::DERIVATION_HISTORY_CARD,
        evidence_request::registry::DERIVATION_HISTORY_CARD_2,
        crate::exchange_corroboration::DEFINITION_DIGEST,
        crate::service_history::definition_digest(),
        crate::service_history::definition_digest_2(),
        crate::verdict_held::DEFINITION_DIGEST,
        CHECKPOINT_RANGE,
    ]
});

/// The subject form that asks for checkpoints at positions a through b (ER
/// -03 §3.1, §8.1.3): its own name, so it is answered whatever the size of
/// the whole list.
pub const CHECKPOINT_RANGE: &str = "checkpoint_range";

/// The subject that asks for every checkpoint, content-free as in -02.
pub const CHECKPOINTS: &str = "checkpoints";

/// The card this node staples in its commitment: the bounded `/2` (ER -03
/// §8.1.2), whose size grows with the log of the checkpoint count, so a
/// node past 350 checkpoints still fits `MAX_ANSWER_BYTES`. A commitment read
/// from a peer may staple either card ([`CARD_DERIVATIONS`]).
pub const STAPLED_DERIVATION: &str = "history_card/2";

/// The cards a `commitment/1` may staple.
const CARD_DERIVATIONS: [&str; 2] = ["history_card/1", "history_card/2"];

/// Answered to anyone, signed or not (PRD R-8).
pub const STRANGER_SAFE: [&str; 4] = [
    CHECKPOINTS,
    "history_card/1",
    "history_card/2",
    CHECKPOINT_RANGE,
];

/// DER SubjectPublicKeyInfo prefix of an Ed25519 key (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The disclosure switches, as the answer gate reads them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Whether this node still answers `history_card/1`: true until the full
    /// `/1` answer over its log would exceed `MAX_ANSWER_BYTES`
    /// ([`answers_fit`]). A log only grows, so it turns false once,
    /// and the policy digest moves once with it. Not a setting.
    pub history_card_1: bool,
    /// Whether this node still answers the unranged `checkpoints`: true until
    /// that answer over its log would exceed `MAX_ANSWER_BYTES` (or hold more
    /// than `MAX_ANSWER_CHECKPOINTS`), measured beside `/1` by [`answers_fit`].
    /// ER -03 §8.1.3: a responder whose full list outgrows an answer SHOULD
    /// NOT list `checkpoints`; `checkpoint_range` and the cards stay. Turns
    /// false once, like `history_card_1`, and moves the policy digest with
    /// it. Not a setting.
    pub checkpoints: bool,
    pub record_at_completion: bool,
    pub history_segments: &'static str,
    pub share_standard_history: bool,
    pub share_exchange_corroboration: bool,
    pub advertise_evidence_requests: bool,
    pub adjudications_delivered: bool,
}

impl Policy {
    /// This process's settings.
    pub fn current() -> Self {
        Self::from_settings(share_policy::var_or_unreadable)
    }

    /// The policy `var` gives, each switch read by its own reader.
    pub fn from_settings(var: impl Fn(&str) -> Option<String>) -> Self {
        let raw = |env: &str| var(env);
        Self {
            history_card_1: true,
            checkpoints: true,
            record_at_completion: !share_policy::record_at_completion_is_off_for(
                raw(share_policy::ENV_RECORD_AT_COMPLETION).as_deref(),
            ),
            history_segments: share_policy::history_segments_for(
                raw(share_policy::ENV_HISTORY_SEGMENTS).as_deref(),
            ),
            share_standard_history: share_policy::shares_standard_history_for(
                raw(share_policy::ENV_STANDARD_HISTORY).as_deref(),
            ),
            share_exchange_corroboration: share_policy::shares_exchange_corroboration_for(
                raw(share_policy::ENV_EXCHANGE_CORROBORATION).as_deref(),
            ),
            advertise_evidence_requests: share_policy::advertises_evidence_requests_for(
                raw(share_policy::ENV_ADVERTISE_EVIDENCE_REQUESTS).as_deref(),
            ),
            adjudications_delivered: share_policy::adjudications_delivered_for(
                raw(share_policy::ENV_ADJUDICATIONS).as_deref(),
            ),
        }
    }

    /// `record_at_completion` as the operator sets it.
    pub fn record_at_completion_value(&self) -> &'static str {
        if self.record_at_completion {
            "counterparty"
        } else {
            "off"
        }
    }

    /// `adjudications` as the operator sets it.
    pub fn adjudications_value(&self) -> &'static str {
        if self.adjudications_delivered {
            "deliver_to_subjects"
        } else {
            "off"
        }
    }

    /// The `policy` member: each switch under its setting name, with the
    /// value the operator would set for it.
    pub fn body(&self) -> Value {
        let on_off = |on: bool| if on { "on" } else { "off" };
        json!({
            share_policy::ADVERTISE_EVIDENCE_REQUESTS_KEY: on_off(self.advertise_evidence_requests),
            share_policy::ADJUDICATIONS_KEY: self.adjudications_value(),
            share_policy::EXCHANGE_CORROBORATION_KEY: on_off(self.share_exchange_corroboration),
            share_policy::HISTORY_SEGMENTS_KEY: self.history_segments,
            share_policy::RECORD_AT_COMPLETION_KEY: self.record_at_completion_value(),
            share_policy::STANDARD_HISTORY_KEY: on_off(self.share_standard_history),
            "stranger_safe": STRANGER_SAFE
                .iter()
                .filter(|d| self.names(d))
                .collect::<Vec<_>>(),
        })
    }

    /// Whether this policy names `derivation` (or subject, for the two
    /// names that are both): not `history_card/1` and not the unranged
    /// `checkpoints` once their full answers no longer fit.
    fn names(&self, derivation: &str) -> bool {
        match derivation {
            DERIVATION_HISTORY_CARD => self.history_card_1,
            CHECKPOINTS => self.checkpoints,
            _ => true,
        }
    }

    /// The derivations this node answers ([`DERIVATIONS`]), without
    /// `history_card/1` and `checkpoints` once their full answers no longer
    /// fit.
    pub fn derivations(&self) -> Vec<&'static str> {
        DERIVATIONS
            .iter()
            .copied()
            .filter(|d| self.names(d))
            .collect()
    }

    /// The subject forms this node answers (`Subject::form().token()`).
    /// `full_history` only through a derivation: its record bodies are
    /// refused under every setting.
    pub fn subjects(&self) -> Vec<&'static str> {
        let mut forms = vec![
            SubjectForm::Checkpoints,
            SubjectForm::CheckpointRange,
            SubjectForm::FullHistory,
        ];
        if !self.checkpoints {
            forms.remove(0);
        }
        if self.history_segments != "off" {
            forms.extend([
                SubjectForm::Record,
                SubjectForm::Exchange,
                SubjectForm::Correlation,
            ]);
        }
        forms.into_iter().map(SubjectForm::token).collect()
    }

    /// The signed policy file's bytes: its JCS form.
    pub fn signed_bytes(&self, key: &SigningKey) -> Vec<u8> {
        let doc = sign(
            json!({
                "profile": POLICY_PROFILE,
                "key_id": key_id(key),
                "policy": self.body(),
            }),
            key,
        );
        jcs(&doc).into_bytes()
    }

    /// `lcap.policy_digest`: the SHA-256 of [`Policy::signed_bytes`].
    pub fn digest(&self, key: &SigningKey) -> String {
        hex::encode(Sha256::digest(self.signed_bytes(key)))
    }
}

/// A commitment and the policy file it commits to.
#[derive(Clone, Debug, PartialEq)]
pub struct Signed {
    pub commitment: Value,
    pub policy: Vec<u8>,
}

impl Signed {
    /// The pair as the `commitment/1` channel and the `commitment` operation
    /// carry it: the policy bytes in standard base64, so they hash the same
    /// at the other end.
    pub fn to_wire(&self) -> Value {
        json!({
            "commitment": self.commitment,
            "policy": base64::engine::general_purpose::STANDARD.encode(&self.policy),
        })
    }

    pub fn from_wire(wire: &Value) -> Result<Self, String> {
        let commitment = wire
            .get("commitment")
            .filter(|c| c.is_object())
            .ok_or("no commitment object")?
            .clone();
        let policy = wire
            .get("policy")
            .and_then(Value::as_str)
            .ok_or("no policy")?;
        let policy = base64::engine::general_purpose::STANDARD
            .decode(policy)
            .map_err(|_| "policy is not base64")?;
        Ok(Self { commitment, policy })
    }
}

/// Run `f` with this node's responder as configured now, and the policy its
/// switches come from: an answer, a refusal and a commitment built in `f`
/// are all under that one policy.
pub fn with_responder<T>(
    capsules: &crate::capsule_emit::CapsuleState,
    now: &str,
    own_node: Option<&str>,
    f: impl FnOnce(&Responder<'_>, &Policy) -> T,
) -> T {
    with_responder_for(capsules, now, own_node, false, false, f)
}

/// [`with_responder`], with `busy` for a request that is declined unread
/// (no ledger read for the policy), and with `strangers_only` a responder that binds no
/// key to any node: a signed request then proves no principal and reads as an
/// unsigned one, answered only what a stranger gets. For a carrier that
/// publishes its answers to whoever reads them (nostr-mailbox-v0 §8).
pub fn with_responder_for<T>(
    capsules: &crate::capsule_emit::CapsuleState,
    now: &str,
    own_node: Option<&str>,
    strangers_only: bool,
    busy: bool,
    f: impl FnOnce(&Responder<'_>, &Policy) -> T,
) -> T {
    let mut policy = Policy::current();
    // A request declined for being busy is answered before the ledger is
    // read, so it takes the last measurement instead of making one.
    let fit = if busy {
        last_measured(capsules.ledger_dir())
    } else {
        answers_fit(capsules.ledger_dir(), capsules.signing_key(), now)
    };
    policy.history_card_1 = fit.history_card_1;
    policy.checkpoints = fit.checkpoints;
    let digest = policy.digest(capsules.signing_key());
    let announced = if strangers_only {
        Default::default()
    } else {
        crate::peer_keys::announced::snapshot()
    };
    let configured = if strangers_only {
        None
    } else {
        crate::settings::var(crate::peer_keys::ENV_PEER_KEYS).ok()
    };
    let own_key = hex::encode(capsules.public_key());
    let responder = Responder {
        ledger_dir: capsules.ledger_dir(),
        signing_key: capsules.signing_key(),
        now,
        history_segments: policy.history_segments,
        share_standard_history: policy.share_standard_history,
        share_exchange_corroboration: policy.share_exchange_corroboration,
        keys: crate::requester_auth::Keys {
            announced: &announced,
            configured: configured.as_deref(),
            own_key: Some(&own_key),
        },
        replay: crate::requester_auth::replay_cache(),
        node_id: own_node,
        policy_digest: Some(&digest),
    };
    f(&responder, &policy)
}

/// Which full answers over this node's log still fit `MAX_ANSWER_BYTES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit {
    /// A stranger's full `history_card/1`.
    pub history_card_1: bool,
    /// A stranger's unranged `checkpoints`.
    pub checkpoints: bool,
}

impl Fit {
    const ALL: Fit = Fit {
        history_card_1: true,
        checkpoints: true,
    };
}

/// What [`answers_fit`] last measured per ledger: the (checkpoints, witness
/// receipts) stamp it was measured at, and what fit.
type Measured = std::collections::HashMap<std::path::PathBuf, ((usize, usize), Fit)>;
static CACHE: std::sync::Mutex<Option<Measured>> = std::sync::Mutex::new(None);

/// The last measurement for `ledger_dir`, without reading the ledger: what a
/// request declined for being busy names in its refusal's policy digest. It
/// names everything until a measurement says otherwise.
fn last_measured(ledger_dir: &std::path::Path) -> Fit {
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|m| m.get(ledger_dir))
        .map_or(Fit::ALL, |(_, fit)| *fit)
}

/// Whether a stranger's full `history_card/1` and full `checkpoints` over
/// this node's log still fit `MAX_ANSWER_BYTES` (and the count caps): each
/// answer is built as the responder builds it and counts as not fitting only
/// when refused for size. The two are measured apart because the card adds to
/// the checkpoints, so each crosses at its own size. A log with no
/// checkpoint, or one the ledger could not read, keeps both named. Measured
/// again only when the chain or its witness receipts change, and a form that
/// does not fit is never measured again, since a log only grows.
pub fn answers_fit(ledger_dir: &std::path::Path, key: &SigningKey, now: &str) -> Fit {
    use crate::evidence_answer::Outcome;
    use evidence_request::registry::Reason;
    // (checkpoints, witness receipts) the answers were measured at. Receipts
    // ride in an answer, so one arriving for an existing checkpoint can push
    // it over without a new checkpoint. The lock is held while measuring, so
    // concurrent callers measure once.
    let key_id = key_id(key);
    let Ok(stamp) = crate::evidence_log::with_index(ledger_dir, &key_id, |i| {
        (
            i.chain.len(),
            i.chain
                .iter()
                .map(|c| c.record.witnesses.len())
                .sum::<usize>(),
        )
    }) else {
        return Fit::ALL;
    };
    let len = stamp.0;
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let before = cache
        .get_or_insert_with(Default::default)
        .get(ledger_dir)
        .copied();
    if let Some((cached, fit)) = before {
        // Once past the cap, always past it (the log only grows).
        if cached == stamp || (!fit.history_card_1 && !fit.checkpoints) {
            return fit;
        }
    }
    let known = before.map_or(Fit::ALL, |(_, fit)| fit);
    let announced = Default::default();
    let responder = Responder {
        ledger_dir,
        signing_key: key,
        now,
        history_segments: "off",
        share_standard_history: false,
        share_exchange_corroboration: false,
        keys: crate::requester_auth::Keys {
            announced: &announced,
            configured: None,
            own_key: None,
        },
        replay: crate::requester_auth::replay_cache(),
        node_id: None,
        policy_digest: None,
    };
    let fits = |known: bool, request: Value| {
        known
            && (len == 0
                || !matches!(
                    crate::evidence_answer::answer(
                        &serde_json::to_vec(&request).expect("a JSON value serializes"),
                        &responder,
                    ),
                    Outcome::Refused {
                        reason: Reason::CapacityExceeded | Reason::PolicyDeclined,
                        ..
                    }
                ))
    };
    let fit = Fit {
        history_card_1: fits(
            known.history_card_1,
            json!({
                "coverage": {"min_freshness": 1},
                "profile": evidence_request::envelope::PROFILE,
                "subject": {"full_history": null},
                "derivation": DERIVATION_HISTORY_CARD,
            }),
        ),
        checkpoints: fits(
            known.checkpoints,
            json!({
                "coverage": {"min_freshness": 1},
                "profile": evidence_request::envelope::PROFILE,
                "subject": {CHECKPOINTS: null},
            }),
        ),
    };
    cache
        .get_or_insert_with(Default::default)
        .insert(ledger_dir.to_path_buf(), (stamp, fit));
    fit
}

/// Why no commitment was built, and whether building it again from the same
/// node id, policy and checkpoint would fail the same way (`lasting`): a
/// refused staple or a frame too large would; a ledger that could not be
/// read might not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unbuilt {
    pub why: String,
    pub lasting: bool,
}

impl Unbuilt {
    fn lasting(why: String) -> Self {
        Self { why, lasting: true }
    }

    fn passing(why: String) -> Self {
        Self {
            why,
            lasting: false,
        }
    }
}

/// This node's latest checkpoint statement and its anchor digest.
fn latest_checkpoint(responder: &Responder<'_>) -> Result<(Vec<u8>, String), String> {
    crate::evidence_log::with_index(
        responder.ledger_dir,
        &key_id(responder.signing_key),
        |index| {
            index
                .chain
                .last()
                .map(|c| (c.statement.clone(), c.anchor_digest()))
        },
    )
    .map_err(|e| format!("the ledger could not be read: {e}"))?
    .ok_or_else(|| "this node has no checkpoint yet, so it has nothing to commit to".into())
}

/// The anchor digest of the checkpoint [`build`] would commit to now.
pub fn latest_anchor(responder: &Responder<'_>) -> Result<String, String> {
    latest_checkpoint(responder).map(|(_, anchor)| anchor)
}

/// Build and sign this node's commitment. `responder` is what this node
/// answers with: the staple is its answer to a stranger.
pub fn build(
    responder: &Responder<'_>,
    node_id: &str,
    policy: &Policy,
    binding: Option<&str>,
    route: Option<&crate::nostr_announce::Route>,
) -> Result<Signed, Unbuilt> {
    let key = responder.signing_key;
    let key_id = key_id(key);
    let (statement, anchor) = latest_checkpoint(responder).map_err(Unbuilt::passing)?;
    let staple_request = json!({
        "subject": {"full_history": null},
        "coverage": {"expected_pin": anchor},
        "derivation": STAPLED_DERIVATION,
    });
    let staple = match evidence_answer::answer(
        &serde_json::to_vec(&staple_request).expect("a JSON value serializes"),
        responder,
    ) {
        Outcome::Answered { wire, .. } => {
            serde_json::to_vec(&wire).expect("a JSON value serializes")
        }
        Outcome::Refused { reason, .. } => {
            return Err(Unbuilt::lasting(format!(
                "this node refused its own {STAPLED_DERIVATION}: {reason}"
            )))
        }
        Outcome::Unanswerable(why) => return Err(Unbuilt::passing(why)),
    };
    let stream = staple_stream(&staple).ok_or_else(|| {
        Unbuilt::lasting(format!(
            "this node's {STAPLED_DERIVATION} names no evidence_stream"
        ))
    })?;
    let policy_bytes = policy.signed_bytes(key);
    let b64 = |raw: &[u8]| base64::engine::general_purpose::STANDARD.encode(raw);
    let sha = |raw: &[u8]| hex::encode(Sha256::digest(raw));
    let mut doc = json!({
        "profile": COMMITMENT_PROFILE,
        "node_id": node_id,
        "key_id": key_id,
        "spki": b64(&spki(&key.verifying_key())),
        "issued_at": responder.now,
        "ask": {"endpoint": format!("mesh:{node_id}"), "bindings": [ASK_BINDING]},
        "answers": {"subjects": policy.subjects(), "derivations": policy.derivations()},
        "lcap": {
            "policy_digest": sha(&policy_bytes),
            "policy_uri": format!("policies/{node_id}.json"),
            "predicate_classes": PREDICATE_CLASSES,
        },
        "checkpoint": {"sha256": sha(&statement), "bytes": b64(&statement)},
        "human_gated": false,
        "answers_within": ANSWERS_WITHIN,
        "history_cards": [{
            "stream": stream,
            "community": COMMUNITY,
            "derivation": STAPLED_DERIVATION,
            "sha256": sha(&staple),
            "bytes": b64(&staple),
            "checkpoint_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(spki(&key.verifying_key())),
        }],
    });
    if let Some(digest) = binding {
        doc[CONTROLLER_BINDING] = json!({ "digest": digest });
    }
    if let Some(route) = route {
        doc["ask"]["nostr"] = route.to_json();
    }
    let signed = Signed {
        commitment: sign(doc, key),
        policy: policy_bytes,
    };
    fits(&signed).map_err(Unbuilt::lasting)?;
    Ok(signed)
}

/// A peer reads at most `MAX_COMMITMENT_BYTES` of a `commitment/1` reply.
/// The staple inside it is a whole answer (at most `MAX_ANSWER_BYTES`),
/// base64-encoded again, so the cap is above the answer's: a commitment whose
/// frame is larger could be built but never fetched, so it is not offered at
/// all.
pub(crate) fn fits(signed: &Signed) -> Result<(), String> {
    let size = serde_json::to_vec(&signed.to_wire()).map_or(usize::MAX, |b| b.len());
    let cap = crate::mesh_evidence_bridge::MAX_COMMITMENT_BYTES as usize;
    if size > cap {
        return Err(format!(
            "the commitment would be {size} bytes, larger than a peer reads ({cap})"
        ));
    }
    Ok(())
}

/// Every check loop's `check_commitment.py` makes on a commitment and its
/// policy, from the node that sent them: the members exactly, no count, the
/// signature under `spki` (which must be `key_id`), the policy's digest and
/// signature under the same key, and the checkpoint's and staple's bytes.
/// The staple's own signature and the checkpoint attestation are not
/// verified here, as loop does not.
pub fn verify(signed: &Signed) -> Vec<String> {
    let doc = &signed.commitment;
    let mut problems = shape_problems(doc);
    if !problems.is_empty() {
        return problems;
    }
    problems.extend(count_problems(doc, &mut Vec::new()));
    let key = match key_of(doc) {
        Ok(key) => Some(key),
        Err(e) => {
            problems.push(e);
            None
        }
    };
    if let Some(key) = &key {
        if !signature_verifies(doc, key) {
            problems.push("signature does not verify under spki".into());
        }
    }
    let digest_of = |name: &str, member: &Value| -> Result<Vec<u8>, String> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(member["bytes"].as_str().unwrap_or_default())
            .map_err(|_| format!("{name}.bytes is not base64"))?;
        if hex::encode(Sha256::digest(&raw)) != member["sha256"] {
            return Err(format!("{name}.bytes do not match {name}.sha256"));
        }
        Ok(raw)
    };
    if let Err(e) = digest_of("checkpoint", &doc["checkpoint"]) {
        problems.push(e);
    }
    if doc["profile"] == LEGACY_COMMITMENT_PROFILE {
        match digest_of("history_card", &doc["history_card"]) {
            Ok(raw) => problems.extend(staple_problems(
                "history_card",
                &raw,
                &doc["key_id"],
                &doc["history_card"]["derivation"],
            )),
            Err(e) => problems.push(e),
        }
    } else {
        for (i, card) in doc["history_cards"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let name = format!("history_cards[{i}]");
            match digest_of(&name, card) {
                Ok(raw) => {
                    problems.extend(staple_problems(
                        &name,
                        &raw,
                        &doc["key_id"],
                        &card["derivation"],
                    ));
                    if staple_stream(&raw).is_none()
                        || staple_stream(&raw).as_deref() != card["stream"].as_str()
                    {
                        problems.push(format!(
                            "{name}.stream is not the card's own evidence_stream"
                        ));
                    }
                }
                Err(e) => problems.push(e),
            }
        }
    }
    if hex::encode(Sha256::digest(&signed.policy)) != doc["lcap"]["policy_digest"] {
        problems.push("lcap.policy_digest is not the sha256 of the policy bytes".into());
    } else if let Some(key) = &key {
        let policy: Option<Value> = serde_json::from_slice(&signed.policy).ok();
        match policy {
            Some(p)
                if p["profile"] == POLICY_PROFILE
                    && p["key_id"] == doc["key_id"]
                    && p["policy"].is_object() =>
            {
                if !signature_verifies(&p, key) {
                    problems.push(
                        "the policy's signature does not verify under the commitment's key".into(),
                    );
                }
            }
            _ => problems.push(format!(
                "the policy is not a {POLICY_PROFILE} document for key_id"
            )),
        }
    }
    problems
}

/// `key_id` form of a key: the raw public key, lowercase hex.
pub fn key_id(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn spki(key: &VerifyingKey) -> Vec<u8> {
    [&ED25519_SPKI_PREFIX[..], &key.to_bytes()[..]].concat()
}

/// `spki` form of a key: its DER SubjectPublicKeyInfo, standard base64.
pub(crate) fn spki_b64(key: &VerifyingKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(spki(key))
}

fn jcs(value: &Value) -> String {
    evidence_request::jcs::to_string(value)
        .expect("strings, booleans and lists always canonicalize")
}

fn without_sig(doc: &Value) -> Value {
    let mut map = doc.as_object().cloned().unwrap_or_default();
    map.remove("sig");
    Value::Object(map)
}

/// `doc` with `sig`: Ed25519 by `key` over the JCS form of `doc` without `sig`.
pub(crate) fn sign(doc: Value, key: &SigningKey) -> Value {
    let sig = key.sign(jcs(&without_sig(&doc)).as_bytes());
    let mut map = doc.as_object().cloned().unwrap_or_default();
    map.insert(
        "sig".into(),
        json!({
            "alg": "Ed25519",
            "canon": "jcs",
            "value": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }),
    );
    Value::Object(map)
}

pub(crate) fn signature_verifies(doc: &Value, key: &VerifyingKey) -> bool {
    let sig = &doc["sig"];
    if sig["alg"] != "Ed25519" || sig["canon"] != "jcs" {
        return false;
    }
    let Some(raw) = sig["value"]
        .as_str()
        .and_then(|v| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(v)
                .ok()
        })
        .and_then(|raw| <[u8; 64]>::try_from(raw).ok())
    else {
        return false;
    };
    let Ok(body) = evidence_request::jcs::to_string(&without_sig(doc)) else {
        return false;
    };
    key.verify(body.as_bytes(), &Signature::from_bytes(&raw))
        .is_ok()
}

/// The checkpoint key a commitment states for its stapled cards
/// (`history_cards[].checkpoint_key`, evidence-commitment-carriers-v0 §3) when
/// `signed` verifies and is `responder_key`'s: `Ok(None)` when no card names
/// one (checkpoints are signed by the evidence key), an error when the
/// commitment does not verify, is another key's, or its cards disagree (they
/// name different checkpoint keys, or only some name one: one key is applied
/// to the whole answer, so a mixed set is ambiguous). Never read from anything that has not verified.
pub fn checkpoint_key_of(
    signed: &Signed,
    responder_key: &str,
) -> Result<Option<VerifyingKey>, String> {
    let problems = verify(signed);
    if !problems.is_empty() {
        return Err(format!(
            "the commitment does not verify: {}",
            problems.join("; ")
        ));
    }
    if signed.commitment["key_id"] != responder_key {
        return Err("the commitment is not the responder_key's".into());
    }
    let cards = signed.commitment["history_cards"]
        .as_array()
        .map_or(&[][..], |a| a.as_slice());
    checkpoint_key_of_cards(cards)
}

/// The one checkpoint key a set of cards names: none when no card names one,
/// an error when only some do or they name different keys.
fn checkpoint_key_of_cards(cards: &[Value]) -> Result<Option<VerifyingKey>, String> {
    let named = cards
        .iter()
        .filter(|card| card["checkpoint_key"].is_string())
        .count();
    if named != 0 && named != cards.len() {
        return Err("only some of the commitment's cards name a checkpoint key".into());
    }
    let mut keys = cards
        .iter()
        .filter_map(|card| card["checkpoint_key"].as_str())
        .map(|b64| {
            let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|_| "checkpoint_key is not base64url".to_string())?;
            let raw: [u8; 32] = der
                .strip_prefix(&ED25519_SPKI_PREFIX[..])
                .and_then(|k| k.try_into().ok())
                .ok_or("checkpoint_key is not an Ed25519 SubjectPublicKeyInfo")?;
            VerifyingKey::from_bytes(&raw)
                .map_err(|_| "checkpoint_key is not a valid key".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    keys.dedup_by_key(|k| k.to_bytes());
    match keys.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(*one)),
        _ => Err("the commitment's cards name different checkpoint keys".into()),
    }
}

/// The key `doc`'s `spki` carries, when it is the key `key_id` names.
pub(crate) fn key_of(doc: &Value) -> Result<VerifyingKey, String> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(doc["spki"].as_str().unwrap_or_default())
        .map_err(|_| "spki is not base64".to_string())?;
    let raw: [u8; 32] = der
        .strip_prefix(&ED25519_SPKI_PREFIX[..])
        .and_then(|k| k.try_into().ok())
        .ok_or("spki is not an Ed25519 SubjectPublicKeyInfo")?;
    if hex::encode(raw) != doc["key_id"] {
        return Err("key_id is not the key in spki".into());
    }
    VerifyingKey::from_bytes(&raw).map_err(|_| "spki is not a valid Ed25519 key".into())
}

/// The members, and each object member's members, exactly (loop's `SCHEMA`
/// for `/0`; `/1` swaps `history_card` for the list `history_cards`, see
/// [`schema`]).
const SCHEMA: [(&str, &[&str]); 13] = [
    ("profile", &[]),
    ("node_id", &[]),
    ("key_id", &[]),
    ("spki", &[]),
    ("issued_at", &[]),
    ("ask", &["endpoint", "bindings"]),
    ("answers", &["subjects", "derivations"]),
    (
        "lcap",
        &["policy_digest", "policy_uri", "predicate_classes"],
    ),
    ("checkpoint", &["sha256", "bytes"]),
    ("human_gated", &[]),
    ("answers_within", &[]),
    ("history_card", &["derivation", "sha256", "bytes"]),
    ("sig", &["alg", "canon", "value"]),
];

/// The members of one `history_cards` entry (loop's `CARD_MEMBERS` and
/// `CARD_OPTIONAL`).
const CARD_MEMBERS: [&str; 6] = [
    "stream",
    "community",
    "derivation",
    "sha256",
    "bytes",
    "checkpoint_key",
];

/// The schema of `profile`'s commitment: `/0` holds `history_card`, `/1`
/// holds the list `history_cards` in its place.
fn schema(profile: &Value) -> Vec<(&'static str, &'static [&'static str])> {
    let legacy = profile == LEGACY_COMMITMENT_PROFILE;
    SCHEMA
        .iter()
        .filter(|(n, _)| legacy || *n != "history_card")
        .copied()
        .chain((!legacy).then_some(("history_cards", &[][..])))
        .collect()
}

/// The member that names this node's controller binding by its digest.
pub const CONTROLLER_BINDING: &str = "controller_binding";

/// Optional members, checked when present (loop's `OPTIONAL`).
const OPTIONAL: [(&str, &[&str]); 1] = [(CONTROLLER_BINDING, &["digest"])];

fn shape_problems(doc: &Value) -> Vec<String> {
    let Some(map) = doc.as_object() else {
        return vec!["not a JSON object".into()];
    };
    let mut problems = Vec::new();
    let schema = schema(&doc["profile"]);
    let legacy = doc["profile"] == LEGACY_COMMITMENT_PROFILE;
    for (name, members) in schema.iter().chain(&OPTIONAL) {
        let (name, members) = (*name, *members);
        let Some(v) = map.get(name) else {
            if !OPTIONAL.iter().any(|(n, _)| *n == name) {
                problems.push(format!("missing {name}"));
            }
            continue;
        };
        let ok = match (name, members.is_empty()) {
            ("human_gated", _) => v.is_boolean(),
            ("history_cards", _) => v.is_array(),
            (_, true) => v.is_string(),
            (_, false) => match v.as_object() {
                Some(inner) => {
                    problems.extend(
                        members
                            .iter()
                            .filter(|m| !inner.contains_key(**m))
                            .map(|m| format!("missing {name}.{m}")),
                    );
                    problems.extend(
                        inner
                            .keys()
                            .filter(|k| !members.contains(&k.as_str()))
                            .filter(|k| !(name == "ask" && k.as_str() == "nostr" && !legacy))
                            .map(|k| format!("unknown field {name}.{k}")),
                    );
                    true
                }
                None => false,
            },
        };
        if !ok {
            problems.push(format!("{name} has the wrong type"));
        }
    }
    problems.extend(
        map.keys()
            .filter(|k| !schema.iter().chain(&OPTIONAL).any(|(n, _)| n == k))
            .map(|k| format!("unknown field {k}")),
    );
    if problems.is_empty() {
        if doc["profile"] != COMMITMENT_PROFILE && doc["profile"] != LEGACY_COMMITMENT_PROFILE {
            problems.push(format!(
                "profile must be {LEGACY_COMMITMENT_PROFILE} or {COMMITMENT_PROFILE}"
            ));
        }
        let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
        for name in ["node_id", "key_id"] {
            if !is_digest(&text(&doc[name])) {
                problems.push(format!("{name} is not 64 lowercase hex"));
            }
        }
        if let Some(route) = doc["ask"].get("nostr") {
            problems.extend(crate::nostr_announce::route_problems(route));
        }
        if doc.get(CONTROLLER_BINDING).is_some()
            && !is_digest(&text(&doc[CONTROLLER_BINDING]["digest"]))
        {
            problems.push("controller_binding.digest is not a sha256 (64 lowercase hex)".into());
        }
        if !is_digest(&text(&doc["lcap"]["policy_digest"])) {
            problems.push("lcap.policy_digest is not a sha256 (64 lowercase hex)".into());
        }
        let issued_at = text(&doc["issued_at"]);
        if issued_at.len() != 20
            || chrono::NaiveDateTime::parse_from_str(&issued_at, "%Y-%m-%dT%H:%M:%SZ").is_err()
        {
            problems.push("issued_at must be YYYY-MM-DDTHH:MM:SSZ".into());
        }
        if !is_duration(&text(&doc["answers_within"])) {
            problems
                .push("answers_within must be an ISO 8601 duration (PnD, PTnH, PTnM, PTnS)".into());
        }
        for name in [&doc["ask"]["endpoint"], &doc["lcap"]["policy_uri"]] {
            if text(name).trim().is_empty() {
                problems.push("ask.endpoint and lcap.policy_uri must be non-empty".into());
            }
        }
        if !doc["lcap"]["predicate_classes"]
            .as_array()
            .is_some_and(|a| a.iter().all(|c| is_predicate_class(&text(c))))
        {
            problems.push("lcap.predicate_classes must be a list of <kind>:<source>".into());
        }
        if doc["profile"] == LEGACY_COMMITMENT_PROFILE {
            if doc["history_card"]["derivation"] != "history_card/1" {
                problems.push("history_card.derivation must be history_card/1".into());
            }
        } else {
            problems.extend(card_problems(&doc["history_cards"]));
        }
        let lists = [
            &doc["ask"]["bindings"],
            &doc["answers"]["subjects"],
            &doc["answers"]["derivations"],
            &doc["lcap"]["predicate_classes"],
        ];
        if lists.iter().any(|l| {
            !l.as_array()
                .is_some_and(|a| !a.is_empty() && a.iter().all(Value::is_string))
        }) {
            problems.push("every list must be a non-empty list of names".into());
        }
        if !doc["answers"]["derivations"]
            .as_array()
            .is_some_and(|a| a.iter().any(|d| CARD_DERIVATIONS.iter().any(|c| d == c)))
        {
            problems.push(
                "answers.derivations must include a history card, the derivation stapled".into(),
            );
        }
    }
    problems
}

/// Loop's `card_field_errors`: a non-empty list of cards with exactly the
/// members, each stream a plain log id and no stream twice (case aside), the
/// community known, the checkpoint key an Ed25519 SPKI, sorted by stream.
fn card_problems(cards: &Value) -> Vec<String> {
    let cards = cards.as_array().map(Vec::as_slice).unwrap_or_default();
    if cards.is_empty() {
        return vec!["history_cards must hold at least one card".into()];
    }
    let mut problems = Vec::new();
    let mut streams: Vec<String> = Vec::new();
    for (i, card) in cards.iter().enumerate() {
        let name = format!("history_cards[{i}]");
        let Some(map) = card.as_object() else {
            problems.push(format!("{name} must be an object"));
            continue;
        };
        problems.extend(
            CARD_MEMBERS
                .iter()
                .filter(|m| **m != "checkpoint_key" && !map.contains_key(**m))
                .map(|m| format!("missing {name}.{m}")),
        );
        problems.extend(
            map.keys()
                .filter(|k| !CARD_MEMBERS.contains(&k.as_str()))
                .map(|k| format!("unknown field {name}.{k}")),
        );
        let text = |m: &str| map.get(m).and_then(Value::as_str);
        if map.contains_key("stream") && !text("stream").is_some_and(is_stream) {
            problems.push(format!("{name}.stream must be a plain log id"));
        }
        if let Some(stream) = text("stream") {
            if streams.iter().any(|s| s.eq_ignore_ascii_case(stream)) {
                problems.push(format!("{name} staples stream {stream} again"));
            }
            streams.push(stream.to_string());
        }
        if map.contains_key("community")
            && !text("community").is_some_and(|c| KNOWN_COMMUNITIES.contains(&c))
        {
            problems.push(format!("{name}.community is not a known community"));
        }
        if map.contains_key("derivation")
            && !text("derivation").is_some_and(|d| CARD_DERIVATIONS.contains(&d))
        {
            problems.push(format!(
                "{name}.derivation must be history_card/1 or history_card/2"
            ));
        }
        if map.contains_key("sha256") && !text("sha256").is_some_and(is_digest) {
            problems.push(format!("{name}.sha256 is not 64 lowercase hex"));
        }
        if let Some(key) = map.get("checkpoint_key") {
            if !key.as_str().is_some_and(is_ed25519_spki) {
                problems.push(format!(
                    "{name}.checkpoint_key is not an Ed25519 SubjectPublicKeyInfo"
                ));
            }
        }
    }
    if streams.windows(2).any(|w| w[0] > w[1]) {
        problems.push("history_cards must be sorted by stream".into());
    }
    problems
}

/// A book's log id as loop's `STREAM` takes it: plain names joined by `/`,
/// each of letters, digits, `.`, `_` and `-`, not starting with a symbol.
fn is_stream(s: &str) -> bool {
    !s.is_empty()
        && s.split('/').all(|seg| {
            seg.starts_with(|c: char| c.is_ascii_alphanumeric())
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

/// An Ed25519 SubjectPublicKeyInfo in base64url or base64, padded or not.
fn is_ed25519_spki(s: &str) -> bool {
    let url = s.replace('+', "-").replace('/', "_");
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(url.trim_end_matches('='))
        .is_ok_and(|der| der.len() == 44 && der.starts_with(&ED25519_SPKI_PREFIX))
}

/// `PnD`, `PTnH`, `PTnM`, `PTnS` and their ordered combinations, with at
/// least one part (loop's `DURATION`).
fn is_duration(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('P') else {
        return false;
    };
    let (date, time) = match rest.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };
    // Each part: digits then its unit, units in order, each at most once.
    fn parts(s: &str, units: &[char]) -> Option<usize> {
        let (mut n, mut next, mut digits) = (0, 0, 0);
        for c in s.chars() {
            if c.is_ascii_digit() {
                digits += 1;
                continue;
            }
            let at = units[next..].iter().position(|u| *u == c)? + next;
            if digits == 0 {
                return None;
            }
            (next, digits, n) = (at + 1, 0, n + 1);
        }
        (digits == 0).then_some(n)
    }
    match (
        parts(date, &['D']),
        time.map(|t| parts(t, &['H', 'M', 'S'])),
    ) {
        (Some(d), None) => d > 0,
        (Some(_), Some(Some(t))) => t > 0,
        _ => false,
    }
}

/// `<kind>:<source>`: a lowercase kind, then a source of lowercase letters,
/// digits and `_./-` (loop's `PREDICATE_CLASS`).
fn is_predicate_class(s: &str) -> bool {
    let Some((kind, source)) = s.split_once(':') else {
        return false;
    };
    kind.starts_with(|c: char| c.is_ascii_lowercase())
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && source.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && source
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_./-".contains(&b))
}

/// Loop's count rule: no member named as a count, no number, no string of
/// decimal digits. The `bytes` of the checkpoint and the staple are signed
/// artifacts carried whole, not members, and are not scanned.
fn count_problems(value: &Value, path: &mut Vec<String>) -> Vec<String> {
    const COUNT_WORDS: [&str; 11] = [
        "count", "counts", "total", "totals", "tally", "num", "number", "quantity", "size", "n",
        "nb",
    ];
    let here = |path: &[String]| path.join(".");
    match value {
        Value::Object(map) => {
            let mut problems = Vec::new();
            for (k, v) in map {
                path.push(k.clone());
                let opaque = path.len() == 2
                    && path[1] == "bytes"
                    && matches!(path[0].as_str(), "checkpoint" | "history_card")
                    || path.len() == 3 && path[0] == "history_cards" && path[2] == "bytes";
                if !opaque {
                    if tokens(k).iter().any(|t| COUNT_WORDS.contains(&t.as_str())) {
                        problems.push(format!("{}: a key named as a count", here(path)));
                    }
                    problems.extend(count_problems(v, path));
                }
                path.pop();
            }
            problems
        }
        Value::Array(items) => items
            .iter()
            .enumerate()
            .flat_map(|(i, v)| {
                path.push(i.to_string());
                let p = count_problems(v, path);
                path.pop();
                p
            })
            .collect(),
        Value::Number(_) => vec![format!("{}: a number", here(path))],
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            vec![format!("{}: a decimal number as a string", here(path))]
        }
        _ => Vec::new(),
    }
}

/// A key split as loop splits it: on `_`, `-`, `.` and camelCase.
fn tokens(name: &str) -> Vec<String> {
    let mut out = String::new();
    let mut prev: Option<char> = None;
    for c in name.chars() {
        if c.is_ascii_uppercase()
            && prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
        {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
        prev = Some(c);
    }
    out.split(['_', '-', '.'])
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// The log id the staple's history card result names (`evidence_stream`),
/// the stream its commitment entry is filed under.
fn staple_stream(raw: &[u8]) -> Option<String> {
    let card: Value = serde_json::from_slice(raw).ok()?;
    let artifact = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(card.get("artifact")?.as_str()?)
        .ok()?;
    let result: Value = serde_json::from_slice(&artifact).ok()?;
    result
        .get("evidence_stream")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The problems of one stapled card: its answer is this profile's, presented
/// by its subject, and names the derivation its carrier declares (`declared`).
fn staple_problems(name: &str, raw: &[u8], key_id: &Value, declared: &Value) -> Vec<String> {
    let Ok(card) = serde_json::from_slice::<Map<String, Value>>(raw) else {
        return vec![format!("{name}.bytes are not a JSON answer")];
    };
    if card.get("profile").and_then(Value::as_str) != Some(STAPLE_PROFILE) {
        return vec![format!("{name} is not an {STAPLE_PROFILE} answer")];
    }
    let mut problems = Vec::new();
    match card.get("derivation").and_then(Value::as_str) {
        Some(d) if CARD_DERIVATIONS.contains(&d) && declared.as_str() == Some(d) => {}
        Some(d) if CARD_DERIVATIONS.contains(&d) => problems.push(format!(
            "{name} declares {declared} but its answer's derivation is {d}"
        )),
        _ => problems.push(format!(
            "{name} answer's derivation is not history_card/1 or history_card/2"
        )),
    }
    if card.get("responder") != Some(key_id) {
        problems.push(format!(
            "{name} is not presented by its subject: its responder is not key_id"
        ));
    }
    // Both must be present: a staple with neither has no history in it.
    let artifact = card.get("artifact").and_then(Value::as_str).and_then(|a| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(a)
            .ok()
    });
    let stated = card.get("artifact_digest").and_then(Value::as_str);
    let matches = match (artifact, stated) {
        (Some(artifact), Some(stated)) => hex::encode(Sha256::digest(artifact)) == stated,
        _ => false,
    };
    if !matches {
        problems.push(format!(
            "{name} answer's artifact_digest is not the sha256 of its artifact"
        ));
    }
    problems
}

#[cfg(test)]
pub(crate) mod tests;
