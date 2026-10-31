use super::*;
use crate::capsule_emit::CapsuleState;
use crate::deal_receipt::tests::{cut, seal_deal};
use std::path::Path;

const ASKED_AT: &str = "2026-10-29T12:00:00Z";
const CLOSES: &str = "2026-10-29T12:01:00Z";
const LATER: &str = "2026-10-29T12:02:00Z";
/// The node that served the exchange, as the deal recorded it.
const PEER: &str = crate::deal_receipt::tests::PEER;

/// The provider's half the payer asks for (test data: the fixture's exchange
/// record names none, so any record is the ask for it).
const THEIR_HALF: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

/// The payer's ask for the provider's half as an Evidence Bundle (#197).
fn request(nonce: &str) -> Value {
    json!({
        "subject": {"record": THEIR_HALF},
        "coverage": {"min_freshness": 1},
        "derivation": crate::bundle_answer::TOKEN,
        "audience": PEER,
        "nonce": nonce,
    })
}

fn request_digest(nonce: &str) -> String {
    evidence_request::digest::request_digest(
        evidence_request::jcs::to_string(&request(nonce))
            .unwrap()
            .as_bytes(),
    )
}

/// A refusal of the ask with `nonce`, in the evidence-request JSON binding.
fn refusal(nonce: &str, key: &str) -> Value {
    json!({
        "request_digest": request_digest(nonce),
        "reason": "not_authorized",
        "issued_at": LATER,
        "key_id": key,
        "sig": "5".repeat(128),
    })
}

/// The provider's signing key: its refusals are signed for real, so the
/// samples verify under `capsulectl verify`'s refusal profile too.
fn peer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[9; 32])
}

fn peer_key() -> String {
    hex::encode(peer().verifying_key().as_bytes())
}

/// The provider's refusal of the ask with `nonce`, signed.
fn signed_refusal(nonce: &str) -> Value {
    evidence_request::refusal::sign(
        &request_digest(nonce),
        evidence_request::registry::Reason::NotAuthorized,
        LATER,
        &peer(),
    )
    .unwrap()
    .to_json()
}

struct Node {
    _dir: tempfile::TempDir,
    state: CapsuleState,
    exchange: String,
}

impl Node {
    fn key(&self) -> String {
        crate::commitment::key_id(self.state.signing_key())
    }

    /// An ask of the provider recorded now, with no outcome.
    fn ask(&self, nonce: &str) -> String {
        self.ask_of(nonce, PEER)
    }

    /// An ask of `responder` recorded now, with no outcome.
    fn ask_of(&self, nonce: &str, responder: &str) -> String {
        crate::ask_book::record_request(&self.state, &request(nonce), responder, None, ASKED_AT)
            .unwrap()
            .record_id
    }

    /// An ask whose window closed with nothing back.
    fn absent(&self, nonce: &str) -> String {
        let id = self.ask(nonce);
        crate::ask_book::record_absence(&self.state, &id, CLOSES, LATER).unwrap();
        id
    }

    /// An ask answered with `reply` (bytes as read), checked as `verification`.
    fn answered(&self, nonce: &str, reply: &Value, verification: Value) -> String {
        let id = self.ask(nonce);
        crate::ask_book::record_response(
            &self.state,
            &id,
            &request_digest(nonce),
            &serde_json::to_vec(reply).unwrap(),
            &verification,
            LATER,
        )
        .unwrap();
        id
    }

    /// The ask `provider.asked(nonce)` sends, recorded with `wire` as its
    /// answer, verified.
    fn answered_with_request(&self, provider: &Provider, nonce: &str, wire: &Value) -> String {
        let (request, _) = provider.asked(nonce);
        let id = crate::ask_book::record_request(&self.state, &request, PEER, None, ASKED_AT)
            .unwrap()
            .record_id;
        let digest = evidence_request::digest::request_digest(
            evidence_request::jcs::to_string(&request)
                .unwrap()
                .as_bytes(),
        );
        crate::ask_book::record_response(
            &self.state,
            &id,
            &digest,
            &serde_json::to_vec(wire).unwrap(),
            &json!({"state": "artifact"}),
            LATER,
        )
        .unwrap();
        id
    }

    /// An ask the provider refused, as this node verified it.
    fn refused(&self, nonce: &str) -> (String, Value) {
        let refusal = signed_refusal(nonce);
        let id = self.answered(
            nonce,
            &refusal,
            json!({"state": "refusal", "reason": "not_authorized"}),
        );
        (id, refusal)
    }

    fn seal(&self, records: &[String]) -> Result<Composition, ComposeError> {
        seal(&self.state, &self.exchange, records, 1_790_000_100)
    }

    fn sealed(&self, records: &[String]) -> Composition {
        self.seal(records).unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn compose(&self, records: &[String]) -> Value {
        let composition = self.sealed(records);
        cut(&self.state);
        bundle(
            self.state.ledger_dir(),
            &self.key(),
            &self.exchange,
            &composition,
        )
        .unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn compositions(&self) -> usize {
        crate::evidence_panes::read_capsule_records(self.state.ledger_dir())
            .iter()
            .filter(|r| is_composition(r))
            .count()
    }
}

/// A payer that served a paid exchange and closed its deal, with another
/// record sealed between the exchange and the deal.
fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let state = CapsuleState::open(dir.path(), "deal-composition-test").unwrap();
    let exchange = state
        .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("node-a"))
        .unwrap()
        .capsule_id;
    state
        .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("node-b"))
        .unwrap();
    seal_deal(&state, &exchange, true);
    Node {
        _dir: dir,
        state,
        exchange,
    }
}

fn record_ids(bundle: &Value) -> Vec<String> {
    bundle["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["capsule_id"].as_str().unwrap().to_string())
        .collect()
}

fn root_record(bundle: &Value) -> &Value {
    let root = bundle["root"].as_str().unwrap();
    bundle["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["capsule_id"] == root)
        .unwrap()
}

#[test]
fn the_composition_is_an_interval_complete_bundle_rooted_at_its_record() {
    let node = node();
    let absent = node.absent("n-1");
    let bundle = node.compose(std::slice::from_ref(&absent));

    // The root is the composition record, in the shape deal-view's V0 reads.
    let root = root_record(&bundle);
    assert_eq!(root["action_id"], ACTION_ID);
    let disclosed = &bundle["disclosures"][bundle["root"].as_str().unwrap()]["agent_input"];
    assert_eq!(disclosed["type"], "deal_composition");
    assert_eq!(disclosed["profile"], "x-deal-v0");
    assert!(disclosed["deal_id"].as_str().unwrap().starts_with("deal-"));
    assert_eq!(disclosed["request_records"], json!([absent]));
    let block = &bundle["extensions"][COMPOSED_KIND];
    assert_eq!(disclosed["composed_digest"], block["composed_digest"]);
    assert_eq!(
        root["model_attestation"]["compute_attestation"]["agent_input_digest"],
        json!(sha256_hex(&jcs(disclosed).unwrap()))
    );

    // Interval-complete: every ledger record from the exchange to the
    // checkpoint, and the strict verifier's interval claim passes.
    let ledger: Vec<String> = crate::evidence_panes::read_capsule_records(node.state.ledger_dir())
        .iter()
        .map(|r| r["capsule_id"].as_str().unwrap().to_string())
        .collect();
    let from = ledger.iter().position(|id| *id == node.exchange).unwrap();
    assert_eq!(record_ids(&bundle), ledger[from..].to_vec());
    let checked = agent_action_capsule::bundle::verify_bundle_strict(
        &bundle,
        &agent_action_capsule::bundle::StrictOptions {
            require_signature: true,
            witness_directory: None,
        },
    );
    let statuses: Vec<_> = checked
        .claims
        .iter()
        .map(|(name, c)| (*name, c.status.as_str()))
        .collect();
    assert_eq!(
        statuses,
        [
            ("records", "pass"),
            ("signatures", "pass"),
            ("graph_closure", "pass"),
            ("checkpoint", "pass"),
            ("interval_coverage", "pass"),
            ("per_record_membership", "pass"),
            ("disclosures", "pass"),
        ]
    );

    // The payer's half: its deal records disclosed, the report named, the
    // cited exchange carried with no payload.
    let report = bundle["extensions"]["x-deal-v0"]["sealed_report"]
        .as_str()
        .unwrap();
    assert_eq!(
        bundle["disclosures"][report]["agent_input"]["type"],
        "deal_report"
    );
    assert!(record_ids(&bundle).contains(&node.exchange));
    assert!(bundle["disclosures"].get(&node.exchange).is_none());
    // Only the composition and the deal's four records are disclosed.
    assert_eq!(bundle["disclosures"].as_object().unwrap().len(), 5);

    if let Some(out) = std::env::var_os("DEAL_COMPOSITION_BUNDLE_OUT") {
        std::fs::write(out, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
    }
}

/// The deal flow's own order: the invoice comes before this node seals the
/// exchange record. No deal record precedes the exchange record, so the
/// interval starts at the cited exchange half, and it is complete.
#[test]
fn the_interval_starts_at_the_exchange_half_in_the_deal_flows_order() {
    let dir = tempfile::tempdir().unwrap();
    let state = CapsuleState::open(dir.path(), "deal-composition-test").unwrap();
    let deals = state.deals();
    let h = |c: char| c.to_string().repeat(64);
    deals.on_invoice(&state, "exchange-1", &h('a'), 1000, 1_790_000_000);
    let exchange = state
        .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("node-a"))
        .unwrap()
        .capsule_id;
    deals.on_exchange(
        &state,
        "exchange-1",
        &crate::deal_flow::SealedExchange {
            capsule_id: &exchange,
            peer: PEER,
            request_digest: &h('d'),
            model: "model-x",
        },
        1_790_000_001,
    );
    deals.on_paid(&state, "exchange-1", &h('b'), 1000, 1_790_000_030);
    deals.on_delivered(&state, "exchange-1", &h('c'), 1_790_000_040);
    let node = Node {
        _dir: dir,
        state,
        exchange,
    };
    let bundle = node.compose(&[node.absent("n-1")]);
    let ledger: Vec<String> = crate::evidence_panes::read_capsule_records(node.state.ledger_dir())
        .iter()
        .map(|r| r["capsule_id"].as_str().unwrap().to_string())
        .collect();
    let carried = record_ids(&bundle);
    let first = ledger.iter().position(|id| *id == carried[0]).unwrap();
    assert_eq!(
        carried,
        ledger[first..].to_vec(),
        "every record from the first carried one"
    );
    // The baseline waits for the exchange record (`deal_flow`: a deal's
    // first step is sealed once the exchange's record is), so the interval
    // starts at the cited exchange half.
    assert_eq!(carried[0], node.exchange);
    assert_eq!(
        bundle["completeness_certificate"]["first_seq"],
        json!(first as u64 + 1)
    );
    let checked = agent_action_capsule::bundle::verify_bundle_strict(
        &bundle,
        &agent_action_capsule::bundle::StrictOptions {
            require_signature: true,
            witness_directory: None,
        },
    );
    assert!(checked
        .claims
        .iter()
        .all(|(_, c)| c.status.as_str() == "pass"));
}

#[test]
fn an_absence_member_is_observed_by_the_payer_with_its_window() {
    let node = node();
    let absent = node.absent("n-1");
    let bundle = node.compose(std::slice::from_ref(&absent));
    let block = &bundle["extensions"][COMPOSED_KIND];
    let key = node.key();
    assert_eq!(
        block["observers"],
        json!([{"id": key, "role": "party", "custody_domain": key}])
    );
    assert_eq!(block["joins"], json!([]));
    let member = &block["members"][0];
    let request_digest = evidence_request::digest::request_digest(
        evidence_request::jcs::to_string(&request("n-1"))
            .unwrap()
            .as_bytes(),
    );
    assert_eq!(member["id"], json!(absent));
    assert_eq!(member["observer"], json!(key));
    assert_eq!(member["outcome"], "absence");
    assert_eq!(member["request_digest"], json!(request_digest));
    assert_eq!(member["absence"]["request_digest"], json!(request_digest));
    assert_eq!(
        member["absence"]["window"],
        json!({"from": ASKED_AT, "to": CLOSES})
    );
    assert_eq!(
        member["digest"],
        json!(jcs_digest(&member["absence"]).unwrap())
    );
}

/// The composed digest is the core's: these vectors are the Go
/// `bundle.ComposedDigest` of the same block (agent-action-capsule a8b6432).
#[test]
fn the_composed_digest_matches_the_core() {
    let members = [json!({
        "id": "b".repeat(64), "observer": "a".repeat(64), "request_digest": "c".repeat(64),
        "outcome": "absence", "digest": "d".repeat(64),
        "absence": {"request_digest": "c".repeat(64), "window": {"from": "x", "to": "y"}},
    })];
    let observers =
        [json!({"id": "a".repeat(64), "role": "party", "custody_domain": "a".repeat(64)})];
    assert_eq!(
        composed_digest(&members, &observers).unwrap(),
        GO_COMPOSED_DIGEST
    );
}

const GO_COMPOSED_DIGEST: &str = "8ae1e9223712405140650cf8ed87c4446fd56df0cfcd3e098e7c2e61a4503eae";

#[test]
fn composing_the_same_members_again_seals_nothing_new() {
    let node = node();
    let records = vec![node.absent("n-1"), node.absent("n-2")];
    let first = node.sealed(&records).id;
    let head = node.state.chain_head();
    assert_eq!(node.sealed(&records).id, first);
    // The same set in another order is the same composition.
    let reversed: Vec<String> = records.iter().rev().cloned().collect();
    let again = node.sealed(&reversed);
    assert_eq!(again.id, first);
    let mut sorted = records.clone();
    sorted.sort();
    assert_eq!(again.payload["request_records"], json!(sorted));
    assert_eq!(node.state.chain_head(), head);
    // Another member set is another composition.
    assert_ne!(node.sealed(&records[..1]).id, first);
    assert_eq!(node.compositions(), 2);
}

#[test]
fn asks_at_once_for_the_same_composition_seal_one_record() {
    let node = node();
    let records = vec![node.absent("n-1")];
    let ids: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| node.sealed(&records).id))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(ids.iter().all(|id| *id == ids[0]));
    assert_eq!(node.compositions(), 1);
}

#[test]
fn a_pending_unknown_or_repeated_request_is_not_a_member() {
    let node = node();
    let pending = node.ask("n-1");
    let absent = node.absent("n-2");
    let refusal = |records: &[String]| match node.seal(records) {
        Err(ComposeError::Member(r)) => r,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        refusal(std::slice::from_ref(&pending)),
        MemberRefusal::Pending(pending.clone())
    );
    assert_eq!(
        refusal(&["9".repeat(64)]),
        MemberRefusal::NotARequest("9".repeat(64))
    );
    // A record of the book that is not a request is not one either.
    let absence_record = crate::evidence_panes::read_capsule_records(node.state.ledger_dir())
        .last()
        .unwrap()["capsule_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        refusal(std::slice::from_ref(&absence_record)),
        MemberRefusal::NotARequest(absence_record.clone())
    );
    assert_eq!(
        refusal(&[absent.clone(), absent.clone()]),
        MemberRefusal::Duplicate(absent.clone())
    );
    assert!(matches!(node.seal(&[]), Err(ComposeError::NoMembers)));
}

/// The checkpoint cadence pads checkpoints by default. A padding record is
/// not a Capsule, so the interval cannot be carried until
/// agent-action-capsule#339 ships: the owner hears why, not a host error.
#[test]
fn an_interval_over_padding_is_refused_by_name() {
    let node = node();
    let records = vec![node.absent("n-1")];
    let composition = node.sealed(&records);
    node.state.pad_one().unwrap();
    cut(&node.state);
    let answer = answer(
        node.state.ledger_dir(),
        &node.key(),
        &node.exchange,
        Ok(composition),
    )
    .unwrap();
    assert_eq!(answer["state"], "refused");
    assert!(answer["why"]
        .as_str()
        .unwrap()
        .contains("agent-action-capsule#339"));
}

#[test]
fn a_verified_refusal_is_a_member_observed_by_the_peers_key() {
    let node = node();
    let absent = node.absent("n-1");
    let (refused, refusal) = node.refused("n-2");
    let bundle = node.compose(&[absent.clone(), refused.clone()]);
    let block = &bundle["extensions"][COMPOSED_KIND];
    let member = block["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == json!(refused))
        .unwrap();
    assert_eq!(member["outcome"], "refusal");
    assert_eq!(member["observer"], json!(peer_key()));
    assert_eq!(member["request_digest"], json!(request_digest("n-2")));
    // The refusal exactly as it came back, under its own digest.
    assert_eq!(member["refusal"], refusal);
    assert_eq!(member["digest"], json!(jcs_digest(&refusal).unwrap()));
    let mut want = vec![
        json!({"id": node.key(), "role": "party", "custody_domain": node.key()}),
        json!({"id": peer_key(), "role": "party", "custody_domain": peer_key()}),
    ];
    want.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    assert_eq!(block["observers"], json!(want));
    assert_eq!(
        block["composed_digest"],
        json!(composed_digest(
            block["members"].as_array().unwrap(),
            block["observers"].as_array().unwrap()
        )
        .unwrap())
    );
    if let Some(out) = std::env::var_os("DEAL_COMPOSITION_REFUSAL_OUT") {
        std::fs::write(out, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
    }
}

/// The provider: a node that served the payer an exchange half and cut a
/// checkpoint over it, answering as `evidence_answer` does.
struct Provider {
    _dir: tempfile::TempDir,
    state: CapsuleState,
    half: String,
}

impl Provider {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state =
            CapsuleState::open(dir.path(), crate::evidence_request_parity::RESPONDER_NODE).unwrap();
        let half = state
            .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("node-a"))
            .unwrap()
            .capsule_id;
        cut(&state);
        Provider {
            _dir: dir,
            state,
            half,
        }
    }

    fn key(&self) -> String {
        hex::encode(self.state.signing_key().verifying_key().as_bytes())
    }

    /// The payer's ask for the half as an Evidence Bundle, signed as node-a
    /// (the half's counterparty), and the provider's reply on the wire.
    fn asked(&self, nonce: &str) -> (Value, Value) {
        let mut request = json!({
            "subject": {"record": self.half},
            "coverage": {"min_freshness": 1},
            "derivation": crate::bundle_answer::TOKEN,
            "deadline": CLOSES,
            "nonce": nonce,
        });
        crate::requester_auth::sign(
            crate::requester_auth::Channel::EvidenceRequest,
            &mut request,
            &crate::evidence_request_parity::asker_key("node-a"),
            chrono::DateTime::parse_from_rfc3339(ASKED_AT)
                .unwrap()
                .into(),
            crate::evidence_request_parity::RESPONDER_NODE,
        );
        let sent = evidence_request::jcs::to_string(&request).unwrap();
        let announced = crate::evidence_request_parity::announced_keys();
        let outcome = crate::evidence_answer::answer(
            sent.as_bytes(),
            &crate::evidence_answer::Responder {
                ledger_dir: self.state.ledger_dir(),
                signing_key: self.state.signing_key(),
                now: ASKED_AT,
                history_segments: "counterparties",
                share_standard_history: true,
                share_exchange_corroboration: true,
                keys: crate::requester_auth::Keys {
                    announced: &announced,
                    configured: None,
                    own_key: None,
                },
                replay: &crate::requester_auth::ReplayCache::default(),
                node_id: Some(crate::evidence_request_parity::RESPONDER_NODE),
                policy_digest: None,
            },
        );
        match outcome {
            crate::evidence_answer::Outcome::Answered { wire, .. } => (request, wire),
            other => panic!("answered, not {other:?}"),
        }
    }
}

impl Node {
    /// The payer's ask of `provider`, recorded with the answer that came
    /// back, as this node verified it.
    fn asked_bundle(&self, provider: &Provider, nonce: &str) -> (String, Value) {
        let (_, wire) = provider.asked(nonce);
        (self.answered_with_request(provider, nonce, &wire), wire)
    }
}

#[test]
fn a_bundle_answer_is_an_artifact_member_with_its_envelope_as_the_response() {
    let node = node();
    let provider = Provider::new();
    let absent = node.absent("n-1");
    let (asked, wire) = node.asked_bundle(&provider, "n-2");
    let bundle = node.compose(&[absent, asked.clone()]);
    let block = &bundle["extensions"][COMPOSED_KIND];
    let member = block["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == json!(asked))
        .unwrap();
    assert_eq!(member["outcome"], "artifact");
    assert_eq!(member["observer"], json!(provider.key()));
    // Their bundle: rooted at their half, under their checkpoint.
    assert_eq!(member["bundle"]["root"], json!(provider.half));
    assert_eq!(
        member["bundle"]["checkpoint"]["key_id"],
        json!(provider.key())
    );
    assert_eq!(
        member["digest"],
        json!(agent_action_capsule::bundle::bundle_digest(&member["bundle"]).unwrap())
    );
    // The envelope as received, minus its artifact.
    let mut response = wire.as_object().unwrap().clone();
    response.remove("artifact");
    response.remove(crate::evidence_artifact::WITNESS_RECEIPTS);
    assert_eq!(member["response"], Value::Object(response));
    assert_eq!(member["response"]["artifact_digest"], member["digest"]);
    assert_eq!(
        member["response"]["request_digest"],
        member["request_digest"]
    );
    assert!(block["observers"].as_array().unwrap().contains(
        &json!({"id": provider.key(), "role": "party", "custody_domain": provider.key()})
    ));
    // The member's bundle verifies interval-complete on its own.
    let checked = agent_action_capsule::bundle::verify_bundle_strict(
        &member["bundle"],
        &agent_action_capsule::bundle::StrictOptions {
            require_signature: true,
            witness_directory: None,
        },
    );
    assert!(checked
        .claims
        .iter()
        .all(|(_, c)| c.status.as_str() == "pass" || c.status.as_str() == "withheld"));
    assert_eq!(checked.claim("interval_coverage").unwrap().status, "pass");
    if let Some(out) = std::env::var_os("DEAL_COMPOSITION_ARTIFACT_OUT") {
        std::fs::write(out, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
    }
}

#[test]
fn a_bundle_answer_that_does_not_bind_is_not_a_member() {
    let node = node();
    let provider = Provider::new();
    let (_, mut wire) = provider.asked("n-1");
    // Another artifact_digest than the bundle's: the response would not
    // bind it.
    wire["artifact_digest"] = json!("0".repeat(64));
    let id = node.answered_with_request(&provider, "n-1", &wire);
    let unbound = |id: String, why: &str| match node.seal(&[id]) {
        Err(ComposeError::Member(MemberRefusal::Unbound(_, got))) => {
            assert!(got.contains(why), "{got}")
        }
        other => panic!("{other:?}"),
    };
    unbound(id, "artifact_digest");

    // No responder to observe it.
    let (_, mut wire) = provider.asked("n-2");
    wire.as_object_mut().unwrap().remove("responder");
    unbound(
        node.answered_with_request(&provider, "n-2", &wire),
        "names no responder",
    );

    // A bundle whose checkpoint names another key than the responder, with
    // the artifact and its digest made consistent, so only that check fails.
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (_, mut wire) = provider.asked("n-3");
    let mut bundle: Value =
        serde_json::from_slice(&b64.decode(wire["artifact"].as_str().unwrap()).unwrap()).unwrap();
    bundle["checkpoint"]["key_id"] = json!("8".repeat(64));
    wire["artifact"] = json!(b64.encode(agent_action_capsule::canonical::jcs(&bundle).unwrap()));
    wire["artifact_digest"] = json!(agent_action_capsule::bundle::bundle_digest(&bundle).unwrap());
    unbound(
        node.answered_with_request(&provider, "n-3", &wire),
        "not signed by the responder",
    );
}

#[test]
fn an_answer_not_verified_as_their_refusal_is_not_a_member() {
    let node = node();
    let refusal_of = |records: &[String]| match node.seal(records) {
        Err(ComposeError::Member(r)) => r,
        other => panic!("{other:?}"),
    };
    // Not checked under an announced key.
    let unchecked = node.answered(
        "n-1",
        &signed_refusal("n-1"),
        json!({"state": "no_announced_key"}),
    );
    assert!(matches!(
        refusal_of(&[unchecked]),
        MemberRefusal::NotVerified(..)
    ));
    // A refusal that did not verify.
    let bad = node.answered(
        "n-2",
        &signed_refusal("n-2"),
        json!({"state": "not_evidence", "why": "bad signature"}),
    );
    assert!(matches!(refusal_of(&[bad]), MemberRefusal::NotVerified(..)));
    // An artifact that is no bundle.
    let artifact = node.answered(
        "n-3",
        &json!({"artifact": "00", "request_digest": request_digest("n-3")}),
        json!({"state": "artifact"}),
    );
    assert!(matches!(
        refusal_of(&[artifact]),
        MemberRefusal::Unbound(..)
    ));
    // An ask for something else than their half: their history.
    let mut history = request("n-7");
    history["subject"] = json!({"full_history": null});
    history["derivation"] = json!("history_card/1");
    let other = crate::ask_book::record_request(&node.state, &history, PEER, None, ASKED_AT)
        .unwrap()
        .record_id;
    crate::ask_book::record_absence(&node.state, &other, CLOSES, LATER).unwrap();
    assert!(matches!(refusal_of(&[other]), MemberRefusal::NotTheHalf(_)));
    // A refusal whose carried reason is not what was signed.
    let mut altered = signed_refusal("n-8");
    altered["reason"] = json!("policy_declined");
    let altered = node.answered(
        "n-8",
        &altered,
        json!({"state": "refusal", "reason": "not_authorized"}),
    );
    assert!(matches!(
        refusal_of(&[altered]),
        MemberRefusal::NotVerified(..)
    ));
    // Signed under this node's own key.
    let own = node.answered(
        "n-4",
        &refusal("n-4", &node.key()),
        json!({"state": "refusal", "reason": "not_authorized"}),
    );
    assert!(matches!(refusal_of(&[own]), MemberRefusal::OwnKey(_)));
    // A refusal of another request.
    let other = node.answered(
        "n-5",
        &signed_refusal("n-6"),
        json!({"state": "refusal", "reason": "not_authorized"}),
    );
    assert!(matches!(
        refusal_of(&[other]),
        MemberRefusal::Inconsistent(_)
    ));
}

#[test]
fn a_refusal_whose_kept_reply_was_altered_is_not_a_member() {
    let node = node();
    let (refused, refusal) = node.refused("n-1");
    let kept = node
        .state
        .ledger_dir()
        .join(crate::ask_book::REPLIES_DIR)
        .join(sha256_hex(&serde_json::to_vec(&refusal).unwrap()));
    std::fs::write(&kept, b"{}").unwrap();
    assert!(matches!(
        node.seal(&[refused]),
        Err(ComposeError::Member(MemberRefusal::ReplyNotKept(..)))
    ));
}

#[test]
fn an_ask_of_another_node_than_the_provider_is_not_a_member() {
    let node = node();
    // A verified refusal from a node this deal never dealt with.
    let id = node.ask_of("n-1", "some-other-node");
    crate::ask_book::record_response(
        &node.state,
        &id,
        &request_digest("n-1"),
        &serde_json::to_vec(&signed_refusal("n-1")).unwrap(),
        &json!({"state": "refusal", "reason": "not_authorized"}),
        LATER,
    )
    .unwrap();
    assert!(matches!(
        node.seal(&[id]),
        Err(ComposeError::Member(MemberRefusal::NotTheProvider(_)))
    ));
    // And no absence of theirs either.
    let other = node.ask_of("n-2", "some-other-node");
    crate::ask_book::record_absence(&node.state, &other, CLOSES, LATER).unwrap();
    assert!(matches!(
        node.seal(&[other]),
        Err(ComposeError::Member(MemberRefusal::NotTheProvider(_)))
    ));
}

/// The deal state keeps the latest deals only; one it dropped still has
/// its records, but no longer says who served the exchange.
#[test]
fn a_deal_that_no_longer_names_its_provider_composes_nothing() {
    let node = node();
    let absent = node.absent("n-1");
    let dir = node.state.ledger_dir().parent().unwrap().to_path_buf();
    std::fs::remove_file(node.state.ledger_dir().join("deals.json")).unwrap();
    let reopened = CapsuleState::open(&dir, "deal-composition-test").unwrap();
    assert!(matches!(
        seal(&reopened, &node.exchange, &[absent], 1_790_000_100),
        Err(ComposeError::NoProvider)
    ));
}

/// What a peer adds beside the signed members, signed by nothing, stays out
/// of the owner's file (Sherlock2, #207).
#[test]
fn unsigned_members_a_peer_adds_are_not_carried() {
    let node = node();
    let mut refusal = signed_refusal("n-1");
    refusal["detail"] = json!("anything the peer likes");
    refusal["policy_digest"] = json!("9".repeat(64));
    let refused = node.answered(
        "n-1",
        &refusal,
        json!({"state": "refusal", "reason": "not_authorized"}),
    );
    let provider = Provider::new();
    let (_, mut wire) = provider.asked("n-2");
    wire["note"] = json!("unsigned");
    wire[crate::evidence_artifact::WITNESS_RECEIPTS] = json!([{"checkpoint": "x", "witness": {}}]);
    let answered = node.answered_with_request(&provider, "n-2", &wire);
    // One peer per composition: the refusal's, then the provider's.
    let member_of = |id: &String| {
        let bundle = node.compose(std::slice::from_ref(id));
        bundle["extensions"][COMPOSED_KIND]["members"][0].clone()
    };
    assert_eq!(member_of(&refused)["refusal"], signed_refusal("n-1"));
    let answered = member_of(&answered);
    let response = answered["response"].as_object().unwrap();
    let mut keys: Vec<&str> = response.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut want: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|k| {
            ![
                "artifact",
                "note",
                crate::evidence_artifact::WITNESS_RECEIPTS,
            ]
            .contains(k)
        })
        .collect();
    want.sort_unstable();
    assert_eq!(keys, want);
}

#[test]
fn a_bundle_answer_from_this_node_or_of_another_request_is_not_a_member() {
    let node = node();
    let provider = Provider::new();
    let (_, mut wire) = provider.asked("n-1");
    wire["responder"] = json!(node.key());
    let own = node.answered_with_request(&provider, "n-1", &wire);
    assert!(matches!(
        node.seal(&[own]),
        Err(ComposeError::Member(MemberRefusal::OwnKey(_)))
    ));
    let (_, mut wire) = provider.asked("n-2");
    wire["request_digest"] = json!("7".repeat(64));
    let other = node.answered_with_request(&provider, "n-2", &wire);
    assert!(matches!(
        node.seal(&[other]),
        Err(ComposeError::Member(MemberRefusal::Inconsistent(_)))
    ));
}

#[test]
fn an_ask_for_another_record_than_the_half_the_exchange_names_is_not_a_member() {
    let digest = request_digest("n-1");
    let header = |v: Value| v.as_object().unwrap().clone();
    let entries = vec![(
        "a".repeat(64),
        header(
            json!({"record_type": "evidence_request", "statement": {"request": request("n-1"), "responder_ref": PEER}}),
        ),
    )];
    let _ = digest;
    assert!(matches!(
        member(
            Path::new("/nonexistent"),
            &entries,
            &"f".repeat(64),
            PEER,
            Some(&"d".repeat(64)),
            &"a".repeat(64)
        ),
        Err(ComposeError::Member(MemberRefusal::NotTheHalf(_)))
    ));
}

#[test]
fn refusals_from_two_peers_are_not_one_deal() {
    let node = node();
    let (a, _) = node.refused("n-1");
    let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let refusal = evidence_request::refusal::sign(
        &request_digest("n-2"),
        evidence_request::registry::Reason::NotAuthorized,
        LATER,
        &other,
    )
    .unwrap()
    .to_json();
    let b = node.answered(
        "n-2",
        &refusal,
        json!({"state": "refusal", "reason": "not_authorized"}),
    );
    assert!(matches!(node.seal(&[a, b]), Err(ComposeError::TwoParties)));
}

#[test]
fn an_exchange_with_no_deal_is_refused() {
    let node = node();
    let absent = node.absent("n-1");
    let none = seal(&node.state, &"9".repeat(64), &[absent], 1_790_000_100);
    assert!(matches!(
        none,
        Err(ComposeError::Receipt(Error::Refused(Refusal::NoDeal)))
    ));
}

#[test]
fn the_composition_record_never_leaves_the_node_by_any_answer_or_fetch() {
    let node = node();
    let id = node.sealed(&[node.absent("n-1")]).id;
    let record = node.state.lookup(&id).unwrap().unwrap().capsule;
    assert!(crate::evidence_log::never_leaves(&record));
    // Every serving path reads that predicate: the index's leaf flag (the
    // evidence answers and their sharing gate) and the ledger fetch. Not
    // even to a proven peer under `peers`.
    let peer = ["node-b".to_string()];
    let (flag, served) = evidence_log::with_index(node.state.ledger_dir(), &node.key(), |index| {
        let leaf = index.leaf_index_of(&id).unwrap();
        (
            index.leaves[leaf as usize].never_leaves,
            crate::evidence_answer::may_serve_all(index, &[leaf], &peer, "peers"),
        )
    })
    .unwrap();
    assert!(flag);
    assert!(!served);
    assert!(!crate::ledger_fetch_bridge::may_serve(
        &record, &peer, "peers"
    ));
    // It is not one of the deal's records: the receipt bundle is unchanged.
    let deal_ids = evidence_log::with_index(node.state.ledger_dir(), &node.key(), |index| {
        index.deal_capsules_of(&node.exchange).len()
    })
    .unwrap();
    assert_eq!(deal_ids, 4);
}

#[test]
fn a_composition_no_checkpoint_covers_is_refused() {
    let node = node();
    let composition = node.sealed(&[node.absent("n-1")]);
    assert!(matches!(
        bundle(
            node.state.ledger_dir(),
            &node.key(),
            &node.exchange,
            &composition
        ),
        Err(ComposeError::Receipt(Error::Refused(
            Refusal::NotCheckpointed
        )))
    ));
}

/// The handler's answer: a refusal of the owner's input or of this node's
/// state is an answer, not a host error; a sealed composition with no
/// checkpoint over it yet is refused; a covered one is the bundle.
#[test]
fn the_route_answers_a_bundle_or_names_the_refusal() {
    let node = node();
    let answer_of = |sealed| answer(node.state.ledger_dir(), &node.key(), &node.exchange, sealed);
    let pending = node.ask("n-1");
    let refused = answer_of(node.seal(std::slice::from_ref(&pending))).unwrap();
    assert_eq!(refused["state"], "refused");
    assert!(refused["why"]
        .as_str()
        .unwrap()
        .contains("no recorded outcome"));

    let absent = node.absent("n-2");
    let uncovered = answer_of(node.seal(std::slice::from_ref(&absent))).unwrap();
    assert_eq!(uncovered["state"], "refused");
    assert!(uncovered["why"].as_str().unwrap().contains("checkpoint"));

    cut(&node.state);
    let answered = answer_of(node.seal(std::slice::from_ref(&absent))).unwrap();
    assert_eq!(answered["state"], "bundle");
    assert_eq!(
        answered["bundle"]["extensions"][COMPOSED_KIND]["members"][0]["id"],
        json!(absent)
    );
    assert!(answer_of(Err(Error::Failed("disk".into()).into())).is_err());
}

#[test]
fn an_absence_with_no_window_is_named_as_such() {
    let digest = evidence_request::digest::request_digest(
        evidence_request::jcs::to_string(&request("n-1"))
            .unwrap()
            .as_bytes(),
    );
    let header = |v: Value| v.as_object().unwrap().clone();
    let entries = vec![
        (
            "a".repeat(64),
            header(
                json!({"record_type": "evidence_request", "statement": {"request": request("n-1"), "responder_ref": PEER}}),
            ),
        ),
        (
            "b".repeat(64),
            header(json!({
                "record_type": "recorded_absence",
                "links": [{"type": "cites", "target": "a".repeat(64)}],
                "statement": {"request_digest": digest},
            })),
        ),
    ];
    assert!(matches!(
        member(
            Path::new("/nonexistent"),
            &entries,
            &"f".repeat(64),
            PEER,
            None,
            &"a".repeat(64)
        ),
        Err(ComposeError::Member(MemberRefusal::NoWindow(_)))
    ));
}

#[test]
fn the_route_input_is_checked() {
    let ok = ComposeArgs {
        capsule_id: json!("a".repeat(64)),
        request_records: vec![json!("b".repeat(64))],
    };
    assert!(parse(&ok).is_ok());
    let bad = ComposeArgs {
        capsule_id: json!("A".repeat(64)),
        request_records: vec![],
    };
    assert!(parse(&bad).is_err());
    let bad = ComposeArgs {
        capsule_id: json!("a".repeat(64)),
        request_records: vec![json!(1)],
    };
    assert!(parse(&bad).is_err());
}
