use super::*;
use crate::capsule_emit::CapsuleState;
use crate::deal_receipt::tests::{cut, seal_deal};

const ASKED_AT: &str = "2026-10-29T12:00:00Z";
const CLOSES: &str = "2026-10-29T12:01:00Z";
const LATER: &str = "2026-10-29T12:02:00Z";
const PEER: &str = "9c1f0a2be45d7388a6b0c1d2e3f40516273849a5b6c7d8e9f00112233445566a";

fn request(nonce: &str) -> Value {
    json!({
        "subject": {"full_history": null},
        "coverage": {"min_freshness": 1},
        "derivation": "history_card/1",
        "audience": PEER,
        "nonce": nonce,
    })
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
        crate::ask_book::record_request(&self.state, &request(nonce), PEER, None, ASKED_AT)
            .unwrap()
            .record_id
    }

    /// An ask whose window closed with nothing back.
    fn absent(&self, nonce: &str) -> String {
        let id = self.ask(nonce);
        crate::ask_book::record_absence(&self.state, &id, CLOSES, LATER).unwrap();
        id
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

#[test]
fn an_answered_request_is_refused_until_its_reply_can_be_a_member() {
    let node = node();
    let id = node.ask("n-1");
    let digest = evidence_request::digest::request_digest(
        evidence_request::jcs::to_string(&request("n-1"))
            .unwrap()
            .as_bytes(),
    );
    crate::ask_book::record_response(
        &node.state,
        &id,
        &digest,
        br#"{"reason":"policy_denied"}"#,
        &json!({"state": "unchecked"}),
        LATER,
    )
    .unwrap();
    assert!(matches!(
        node.seal(std::slice::from_ref(&id)),
        Err(ComposeError::Member(MemberRefusal::Answered(_)))
    ));
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
                json!({"record_type": "evidence_request", "statement": {"request": request("n-1")}}),
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
        member(&entries, &"a".repeat(64)),
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
