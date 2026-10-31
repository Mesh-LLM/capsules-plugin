//! `evidence_bundle/1`, answered and checked against ledgers built
//! in-process.

use super::*;
use crate::capsule_emit::CapsuleState;
use crate::evidence_answer::{answer, Outcome, Responder};
use crate::evidence_request_parity::{announced_keys, asker_key, RESPONDER_NODE};
use crate::requester_auth::{Keys, ReplayCache};
use evidence_request::envelope::{Binding, EnvelopeParts, Reply};
use serde_json::json;

const NOW: &str = "2026-09-29T00:00:00Z";

/// What a node seals, in order.
enum Seal {
    /// An exchange half this node served for that node.
    Served(&'static str),
    Padding,
    /// A deal, whose report never leaves the node.
    Deal,
    /// A checkpoint over everything sealed so far.
    Cut,
}

/// A node that sealed its records with the real producer.
struct Node {
    _dir: tempfile::TempDir,
    state: CapsuleState,
    /// Every capsule id, in ledger order.
    ids: Vec<String>,
}

impl Node {
    fn new(seals: &[Seal]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(dir.path(), RESPONDER_NODE).unwrap();
        let mut node = Node {
            _dir: dir,
            state,
            ids: Vec::new(),
        };
        node.seal(seals);
        node
    }

    fn seal(&mut self, seals: &[Seal]) {
        let state = &self.state;
        for seal in seals {
            match seal {
                Seal::Served(party) => {
                    state
                        .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange(party))
                        .unwrap();
                }
                Seal::Padding => {
                    state.pad_one().unwrap();
                }
                Seal::Deal => crate::deal_receipt::tests::seal_deal(state, &"e".repeat(64), true),
                Seal::Cut => crate::deal_receipt::tests::cut(state),
            }
        }
        self.ids = std::fs::read_to_string(state.ledger_dir().join("capsules.jsonl"))
            .unwrap()
            .lines()
            .map(|l| {
                let line: Value = serde_json::from_str(l).unwrap();
                line["capsule_id"].as_str().unwrap().to_string()
            })
            .collect();
    }

    fn id(&self, i: usize) -> String {
        self.ids[i].clone()
    }

    /// The anchor digests of the node's checkpoints, in order.
    fn anchors(&self) -> Vec<String> {
        std::fs::read_to_string(self.state.ledger_dir().join("checkpoints.jsonl"))
            .unwrap()
            .lines()
            .map(|l| {
                let line: Value = serde_json::from_str(l).unwrap();
                let cose = hex::decode(line["checkpoint_cose"].as_str().unwrap()).unwrap();
                hex::encode(Sha256::digest(cose))
            })
            .collect()
    }

    fn key(&self) -> &ed25519_dalek::SigningKey {
        self.state.signing_key()
    }

    fn ask(&self, sent: &[u8], history_segments: &str) -> Outcome {
        let announced = announced_keys();
        answer(
            sent,
            &Responder {
                ledger_dir: self.state.ledger_dir(),
                signing_key: self.key(),
                now: NOW,
                history_segments,
                share_standard_history: true,
                share_exchange_corroboration: true,
                keys: Keys {
                    announced: &announced,
                    configured: None,
                    own_key: None,
                },
                replay: &ReplayCache::default(),
                node_id: Some(RESPONDER_NODE),
                policy_digest: None,
            },
        )
    }

    fn check(
        &self,
        sent: &[u8],
        wire: &Value,
    ) -> Result<crate::evidence_artifact::Checked, String> {
        let request = evidence_request::request::parse_json(sent).unwrap();
        crate::evidence_artifact::check(sent, &request, wire, &self.key().verifying_key(), &|_| {
            None
        })
        .map_err(|e| e.to_string())
    }
}

/// 0: node-b's; checkpoint 0; 1: node-a's, the half asked for; 2, 3:
/// node-a's; checkpoint 1; 4: node-b's; 5: node-a's; checkpoint 2.
fn node() -> Node {
    use Seal::*;
    Node::new(&[
        Served("node-b"),
        Cut,
        Served("node-a"),
        Served("node-a"),
        Served("node-a"),
        Cut,
        Served("node-b"),
        Served("node-a"),
        Cut,
    ])
}

fn request(subject: Value, coverage: Value) -> Value {
    json!({"subject": subject, "coverage": coverage, "derivation": TOKEN, "deadline": "2026-09-29T00:05:00Z"})
}

fn signed(node: &str, mut request: Value) -> Vec<u8> {
    let now = chrono::DateTime::parse_from_rfc3339(NOW).unwrap().into();
    request["nonce"] = json!(hex::encode(Sha256::digest(request.to_string().as_bytes())));
    crate::requester_auth::sign(
        crate::requester_auth::Channel::EvidenceRequest,
        &mut request,
        &asker_key(node),
        now,
        RESPONDER_NODE,
    );
    serde_json::to_vec(&request).unwrap()
}

fn for_record(node: &Node, i: usize, coverage: Value) -> Value {
    request(json!({"record": node.id(i)}), coverage)
}

fn refused(outcome: &Outcome) -> Option<Reason> {
    match outcome {
        Outcome::Refused { reason, .. } => Some(*reason),
        _ => None,
    }
}

fn wire_of(outcome: Outcome) -> Value {
    match outcome {
        Outcome::Answered { wire, .. } => wire,
        other => panic!("answered, not {other:?}"),
    }
}

fn envelope_of(wire: &Value) -> Envelope {
    match envelope::parse_reply(&serde_json::to_vec(wire).unwrap(), Binding::Json) {
        Ok(Reply::Envelope(env)) => *env,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_counterparty_gets_the_half_to_the_earliest_covering_checkpoint_as_a_bundle() {
    let node = node();
    let sent = signed("node-a", for_record(&node, 1, json!({"min_freshness": 1})));
    let wire = wire_of(node.ask(&sent, "counterparties"));
    let env = envelope_of(&wire);
    let bundle: Value = serde_json::from_slice(&env.artifact).unwrap();

    // The member binding: artifact_digest is the bundle's BundleDigest.
    assert_eq!(env.artifact_digest, bundle_digest(&bundle).unwrap());
    assert_eq!(
        env.artifact,
        agent_action_capsule::canonical::jcs(&bundle).unwrap()
    );
    assert_eq!(bundle["bundle_kind"], "evidence-bundle/v2");
    assert_eq!(bundle["root"], node.id(1));
    // Served under checkpoint 1, the earliest covering the half: leaves 1-3.
    assert_eq!(env.anchor.digest, node.anchors()[1]);
    let carried: Vec<&str> = bundle["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["capsule_id"].as_str().unwrap())
        .collect();
    assert_eq!(carried, [node.id(1), node.id(2), node.id(3)]);
    assert_eq!(bundle["completeness_certificate"]["first_seq"], 2);
    assert_eq!(bundle["completeness_certificate"]["last_seq"], 4);
    // Headers as sealed, nothing disclosed beyond them.
    assert!(bundle.get("disclosures").is_none());
    let strict = verify_bundle_strict(
        &bundle,
        &StrictOptions {
            require_signature: false,
            witness_directory: None,
        },
    );
    assert!(strict.ok(), "{:?}", strict.claims);
    assert_eq!(strict.claim("interval_coverage").unwrap().status, "pass");

    let checked = node
        .check(&sent, &wire)
        .expect("the requester's check holds");
    assert_eq!(checked.records, [1, 2, 3]);
    assert_eq!(checked.anchor, node.anchors()[1]);
    assert_eq!(checked.artifact_digest, env.artifact_digest);
}

#[test]
fn the_same_request_gets_the_same_artifact_as_the_log_grows() {
    let mut node = node();
    let sent = signed("node-a", for_record(&node, 1, json!({"min_freshness": 1})));
    let before = envelope_of(&wire_of(node.ask(&sent, "peers"))).artifact;
    node.seal(&[Seal::Served("node-a"), Seal::Cut]);
    let after = envelope_of(&wire_of(node.ask(&sent, "peers"))).artifact;
    assert_eq!(before, after);
}

#[test]
fn a_pinned_or_fresher_anchor_extends_the_interval_and_another_party_refuses_it() {
    let node = node();
    for coverage in [
        json!({"expected_pin": node.anchors()[2]}),
        json!({"min_freshness": 5}),
    ] {
        let sent = signed("node-a", for_record(&node, 1, coverage.clone()));
        // Leaf 4 is node-b's: never to node-a under the default policy.
        assert_eq!(
            refused(&node.ask(&sent, "counterparties")),
            Some(Reason::NotAuthorized),
            "{coverage}"
        );
        let wire = wire_of(node.ask(&sent, "peers"));
        let checked = node
            .check(&sent, &wire)
            .expect("the requester's check holds");
        assert_eq!(checked.records, [1, 2, 3, 4, 5], "{coverage}");
        assert_eq!(checked.anchor, node.anchors()[2]);
    }
}

#[test]
fn a_record_that_never_leaves_refuses_the_whole_answer_under_every_setting() {
    use Seal::*;
    let node = Node::new(&[
        Served("node-b"),
        Served("node-a"),
        Deal,
        Served("node-a"),
        Cut,
    ]);
    let sent = signed("node-a", for_record(&node, 1, json!({"min_freshness": 1})));
    for setting in ["counterparties", "peers"] {
        assert_eq!(
            refused(&node.ask(&sent, setting)),
            Some(Reason::NotAuthorized),
            "{setting}"
        );
    }
}

#[test]
fn an_unsigned_request_another_party_and_sharing_off_are_not_authorized() {
    let node = node();
    let request = for_record(&node, 1, json!({"min_freshness": 1}));
    let unsigned = serde_json::to_vec(&request).unwrap();
    assert_eq!(
        refused(&node.ask(&unsigned, "peers")),
        Some(Reason::NotAuthorized)
    );
    // node-b is a counterparty of this node, but not of this half.
    let by_b = signed("node-b", request.clone());
    assert_eq!(
        refused(&node.ask(&by_b, "counterparties")),
        Some(Reason::NotAuthorized)
    );
    // node-y is named by no record.
    let by_y = signed("node-y", request.clone());
    assert_eq!(
        refused(&node.ask(&by_y, "counterparties")),
        Some(Reason::NotAuthorized)
    );
    let by_a = signed("node-a", request);
    assert_eq!(
        refused(&node.ask(&by_a, "off")),
        Some(Reason::NotAuthorized)
    );
}

#[test]
fn only_an_exchange_half_under_a_covering_checkpoint_is_answered() {
    let node = node();
    let ask = |subject: Value, coverage: Value| {
        refused(&node.ask(&signed("node-a", request(subject, coverage)), "peers"))
    };
    let fresh = json!({"min_freshness": 1});
    // An unknown digest is not held.
    assert_eq!(
        ask(json!({"record": "ab".repeat(32)}), fresh.clone()),
        Some(Reason::NoSuchSubject)
    );
    // The derivation is defined over a record only.
    assert_eq!(
        ask(json!({"correlation": "n-1"}), fresh),
        Some(Reason::NoSuchSubject)
    );
    // Checkpoint 0 does not cover the half.
    assert_eq!(
        ask(
            json!({"record": node.id(1)}),
            json!({"expected_pin": node.anchors()[0]})
        ),
        Some(Reason::CoverageUnsatisfiable)
    );
}

#[test]
fn a_half_no_checkpoint_covers_yet_is_coverage_unsatisfiable() {
    use Seal::*;
    let node = Node::new(&[Served("node-b"), Cut, Served("node-a")]);
    let sent = signed("node-a", for_record(&node, 1, json!({"min_freshness": 1})));
    assert_eq!(
        refused(&node.ask(&sent, "peers")),
        Some(Reason::CoverageUnsatisfiable)
    );
}

/// `wire` with `artifact` in place of its own, signed again by the node.
fn resigned(node: &Node, sent: &[u8], wire: &Value, artifact: Vec<u8>) -> Value {
    let env = envelope_of(wire);
    let parts = EnvelopeParts {
        subject: env.subject.clone(),
        derivation: env.derivation.clone(),
        anchor: env.anchor.clone(),
        artifact,
        verification: env
            .verification
            .iter()
            .zip(&env.verification_content)
            .map(|(v, o)| (v.kind.clone(), o.clone()))
            .collect(),
        issued_at: env.issued_at.clone(),
    };
    let signed = envelope::sign(sent, parts, node.key()).unwrap();
    serde_json::from_slice(&signed.encode(Binding::Json)).unwrap()
}

#[test]
fn the_requester_refuses_a_bundle_that_is_not_the_canonical_interval_under_the_anchor() {
    let node = node();
    let sent = signed("node-a", for_record(&node, 1, json!({"min_freshness": 1})));
    let wire = wire_of(node.ask(&sent, "peers"));
    let bundle: Value = serde_json::from_slice(&envelope_of(&wire).artifact).unwrap();

    // Not its canonical form: the artifact digest is no BundleDigest.
    let pretty = serde_json::to_vec_pretty(&bundle).unwrap();
    assert!(node
        .check(&sent, &resigned(&node, &sent, &wire, pretty))
        .unwrap_err()
        .contains("canonical"));

    // A record dropped from the interval.
    let mut short = bundle.clone();
    short["records"].as_array_mut().unwrap().pop();
    let short = agent_action_capsule::canonical::jcs(&short).unwrap();
    assert!(node
        .check(&sent, &resigned(&node, &sent, &wire, short))
        .is_err());

    // The bundle of the later checkpoint, under the earlier anchor.
    let later = signed(
        "node-a",
        for_record(&node, 1, json!({"expected_pin": node.anchors()[2]})),
    );
    let later = envelope_of(&wire_of(node.ask(&later, "peers"))).artifact;
    assert!(node
        .check(&sent, &resigned(&node, &sent, &wire, later))
        .unwrap_err()
        .contains("another checkpoint"));

    // Rooted elsewhere: the half asked for is not the root.
    let other = signed("node-a", for_record(&node, 3, json!({"min_freshness": 1})));
    let other = envelope_of(&wire_of(node.ask(&other, "peers"))).artifact;
    assert!(node
        .check(&sent, &resigned(&node, &sent, &wire, other))
        .unwrap_err()
        .contains("rooted"));
}

/// A padding record is not a Capsule, so no Evidence Bundle carries a range
/// over one yet (action-state-group/agent-action-capsule#339), and the
/// checkpoint cadence pads before each checkpoint by default. Until AAC
/// carries non-record leaves, such an interval is declined as a limit of
/// this node's own (`capacity_exceeded`, `policy_declined` under /0), never
/// answered with a bundle that does not verify.
#[test]
fn an_interval_over_padding_is_declined_until_bundles_carry_it() {
    use Seal::*;
    let node = Node::new(&[Served("node-a"), Padding, Cut]);
    let sent = signed("node-a", for_record(&node, 0, json!({"min_freshness": 1})));
    assert_eq!(
        refused(&node.ask(&sent, "counterparties")),
        Some(Reason::PolicyDeclined)
    );
    // Padding is no half.
    let padding = signed("node-a", for_record(&node, 1, json!({"min_freshness": 1})));
    assert_eq!(
        refused(&node.ask(&padding, "peers")),
        Some(Reason::NoSuchSubject)
    );
}

#[test]
fn a_time_freshness_is_served_under_the_earliest_covering_checkpoint_it_allows() {
    let node = node();
    let since = signed(
        "node-a",
        for_record(&node, 1, json!({"min_freshness": "2020-01-01T00:00:00Z"})),
    );
    let wire = wire_of(node.ask(&since, "counterparties"));
    let checked = node
        .check(&since, &wire)
        .expect("the requester's check holds");
    assert_eq!(checked.anchor, node.anchors()[1]);
    assert_eq!(checked.records, [1, 2, 3]);
    // No checkpoint is that fresh.
    let future = signed(
        "node-a",
        for_record(&node, 1, json!({"min_freshness": "2099-01-01T00:00:00Z"})),
    );
    assert_eq!(
        refused(&node.ask(&future, "counterparties")),
        Some(Reason::CoverageUnsatisfiable)
    );
}

/// Over `MAX_ANSWER_RECORDS` records from the half to the tip: declined as
/// a limit of this node's own (`capacity_exceeded`, `policy_declined` under
/// /0) before any record is read.
#[test]
fn an_interval_over_the_record_limit_is_declined() {
    let limit = crate::evidence_answer::MAX_ANSWER_RECORDS as usize;
    let mut seals: Vec<Seal> = (0..=limit).map(|_| Seal::Served("node-a")).collect();
    seals.push(Seal::Cut);
    let node = Node::new(&seals);
    let first = signed("node-a", for_record(&node, 0, json!({"min_freshness": 1})));
    assert_eq!(
        refused(&node.ask(&first, "counterparties")),
        Some(Reason::PolicyDeclined)
    );
    // The last half alone is within every limit.
    let last = signed(
        "node-a",
        for_record(&node, limit, json!({"min_freshness": 1})),
    );
    let wire = wire_of(node.ask(&last, "counterparties"));
    assert_eq!(node.check(&last, &wire).unwrap().records, [limit as u64]);
}
