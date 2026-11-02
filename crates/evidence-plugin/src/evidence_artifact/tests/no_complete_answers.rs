//! evidencebook#206 row 7 (Mesh-LLM/capsules-plugin#233): no answer this
//! node selects for a requester verifies as COMPLETE. One vector per answer
//! kind, `vectors/no-complete-answer/vectors.json`: the request, the node's
//! reply under fixed keys and time, and what a requester reads from it.
//!
//! The reading ([`reading`]) is the strictest a requester can take from an
//! answer on its own: a verified artifact is COMPLETE only when it shows
//! every record of the log up to its anchor. Otherwise it is INCOMPLETE, and
//! a signed refusal is REFUSED. The answers carry no interval claim to
//! check, so selection among records is never certified. A kind that read
//! COMPLETE would be a finding of its own. `full_history` is the control: it
//! does show every record, so it reads COMPLETE where the node serves it, and
//! the node serves it to no asker (`spans_parties`, refused `not_authorized`
//! under every sharing setting; ungated here only so the control can run).
//!
//! `CAPSULES_WRITE_NO_COMPLETE_VECTORS=1 cargo test -p evidence-plugin
//! the_vectors_are_the_nodes_answers` rewrites the file; then regenerate
//! `vectors/SHA256SUMS`.

use super::*;

const VECTORS: &str = "../../vectors/no-complete-answer/vectors.json";

/// Members an artifact would need to state an interval it covers.
const INTERVAL_MEMBERS: [&str; 5] = [
    "interval",
    "completeness",
    "coverage",
    "range",
    "certificate",
];

/// `COMPLETE`, `INCOMPLETE` or `REFUSED`, from the reply alone.
fn reading(node: &Node, sent: &[u8], reply: &Value) -> (&'static str, Value) {
    if reply.get("reason").is_some() {
        return ("REFUSED", json!({"reason": reply["reason"]}));
    }
    let checked = check_reply(sent, reply).expect("a node's own answer verifies");
    let at = node
        .anchors
        .iter()
        .position(|a| *a == checked.anchor)
        .unwrap();
    let leaves = leaf_count(node_size(node, at)).unwrap();
    let whole: Vec<u64> = (0..leaves).collect();
    let members: Vec<String> = match serde_json::from_slice::<Value>(&envelope_of(reply).artifact) {
        Ok(Value::Object(m)) if !checked.records.is_empty() || checked.checkpoints > 0 => {
            m.keys().cloned().collect()
        }
        _ => Vec::new(),
    };
    for member in &members {
        assert!(!INTERVAL_MEMBERS.contains(&member.as_str()), "{member}");
    }
    let verdict = if checked.records == whole {
        "COMPLETE"
    } else {
        "INCOMPLETE"
    };
    (
        verdict,
        json!({
            "anchor_leaves": leaves,
            "records": checked.records,
            "checkpoints": checked.checkpoints,
            "halves": checked.halves.len(),
        }),
    )
}

/// The nodes the cases are asked of: the corpus, and the corpus with a
/// served half that binds a client nonce (the corroboration case's).
fn nodes() -> (Node, Node) {
    let ledger = corpus_ledger();
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
    (node(), Node::over(&bound))
}

/// (kind, what, request, setup, asked of the corroborating node)
type Case = (&'static str, &'static str, Vec<u8>, Setup, bool);

fn cases(node: &Node) -> Vec<Case> {
    let last = node.anchors.len() - 1;
    let ledger = corpus_ledger();
    let half = hex::encode(Sha256::digest(b"the counterparty's own half"));
    let ask = |request: Value| serde_json::to_vec(&request).unwrap();
    let plain = Setup::default();
    let corroboration = ask(crate::exchange_corroboration::request_for(&hex::encode(
        Sha256::digest(b"c-1"),
    )));
    let pin = node.pin(last);
    let first = node.pin(0);
    vec![
        (
            "record",
            "a record of the second checkpoint",
            ask(json!({"subject": {"record": ledger[17]["capsule_id"]}, "coverage": pin})),
            plain,
            false,
        ),
        (
            "correlation",
            "the records under one correlation key",
            ask(json!({"subject": {"correlation": "n-1"}, "coverage": pin})),
            plain,
            false,
        ),
        (
            "exchange",
            "the records citing a counterparty's half",
            ask(json!({"subject": {"exchange": half}, "coverage": {"expected_pin": half}})),
            plain,
            false,
        ),
        (
            "checkpoints",
            "the checkpoint list",
            ask(json!({"subject": {"checkpoints": null}, "coverage": pin})),
            plain,
            false,
        ),
        (
            "history_card/1",
            "the history card",
            ask(
                json!({"subject": {"full_history": null}, "coverage": pin, "derivation": "history_card/1"}),
            ),
            plain,
            false,
        ),
        (
            "served_summary/1",
            "retired: refused to every asker (capsules-plugin#106)",
            ask(
                json!({"subject": {"full_history": null}, "coverage": pin, "derivation": "served_summary/1"}),
            ),
            plain,
            false,
        ),
        (
            "exchange_corroboration/1",
            "the halves of a served exchange",
            corroboration,
            Setup {
                corroboration: true,
                ..plain
            },
            true,
        ),
        (
            "control:full_history",
            "every record up to the first checkpoint; never served to an asker",
            ask(json!({"subject": {"full_history": null}, "coverage": first})),
            plain,
            false,
        ),
    ]
}

fn generate() -> Value {
    let (plain, corroborating) = nodes();
    let out: Vec<Value> = cases(&plain)
        .into_iter()
        .map(|(kind, what, request, setup, corroboration)| {
            let node = if corroboration {
                &corroborating
            } else {
                &plain
            };
            let reply = match node.outcome(&request, setup, None) {
                Outcome::Answered { wire, .. } | Outcome::Refused { wire, .. } => wire,
                Outcome::Unanswerable(why) => panic!("{kind}: {why}"),
            };
            let (verdict, shown) = reading(node, &request, &reply);
            json!({
                "kind": kind,
                "what": what,
                "request": serde_json::from_slice::<Value>(&request).unwrap(),
                "reply": reply,
                "reading": verdict,
                "shown": shown,
            })
        })
        .collect();
    json!({
        "about": "evidencebook#206 row 7: no producer-selected answer verifies as COMPLETE. See evidence_artifact/tests/no_complete_answers.rs for the reading.",
        "node_key_seed": hex::encode(NODE_KEY_SEED),
        "issued_at": NOW,
        "cases": out,
    })
}

/// Every kind but the control reads INCOMPLETE or REFUSED, never COMPLETE,
/// and the file is what the node answers today.
#[test]
fn the_vectors_are_the_nodes_answers() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    let got = generate();
    if std::env::var_os("CAPSULES_WRITE_NO_COMPLETE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
        return;
    }
    let want: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        got, want,
        "regenerate the vectors if the answer changed on purpose"
    );
}

/// The file's replies are verified afresh from the file alone, so a vector
/// cannot claim a reading its reply does not give.
#[test]
fn no_selected_answer_reads_complete() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    let file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let kinds: Vec<&str> = file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "record",
            "correlation",
            "exchange",
            "checkpoints",
            "history_card/1",
            "served_summary/1",
            "exchange_corroboration/1",
            "control:full_history",
        ]
    );
    for case in file["cases"].as_array().unwrap() {
        let kind = case["kind"].as_str().unwrap();
        let sent = serde_json::to_vec(&case["request"]).unwrap();
        let (plain, corroborating) = nodes();
        let node = if kind == "exchange_corroboration/1" {
            corroborating
        } else {
            plain
        };
        let (verdict, _) = reading(&node, &sent, &case["reply"]);
        assert_eq!(verdict, case["reading"], "{kind}");
        let want = if kind == "control:full_history" {
            "COMPLETE"
        } else if kind == "served_summary/1" {
            "REFUSED"
        } else {
            "INCOMPLETE"
        };
        assert_eq!(verdict, want, "{kind}");
    }
}
