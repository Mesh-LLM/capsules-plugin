//! evidencebook#206 row 7 (Mesh-LLM/capsules-plugin#233): no answer this
//! node selects for a requester verifies as COMPLETE. One vector per answer
//! kind, `vectors/no-complete-answer/vectors.json`: the request, the node's
//! reply under fixed keys and time, and what a requester reads from it.
//!
//! The reading ([`reading`]) is the strictest a requester can take from an
//! answer on its own: a verified artifact is COMPLETE only when it shows
//! every record of the log up to its anchor. Otherwise it is INCOMPLETE, and
//! a signed refusal is REFUSED. Every case is asked of the node ungated (the
//! sharing policy would only refuse more). An answer that carries no record
//! (`checkpoints`, `history_card/1`) reads INCOMPLETE because it shows none,
//! and the check that it states no interval is [`CLAIMS`] over every member
//! name of its artifact. The anchor's size comes from the node's own
//! checkpoint list, not from the file. The answers carry no interval claim to
//! check, so selection among records is never certified. A kind that read
//! COMPLETE would be a finding of its own. `full_history` is the control: it
//! does show every record, so it reads COMPLETE where the node serves it, and
//! the node serves it to no asker (`spans_parties`, refused `not_authorized`
//! under every sharing setting; ungated here so the control can run).
//!
//! `CAPSULES_WRITE_NO_COMPLETE_VECTORS=1 cargo test -p evidence-plugin
//! the_vectors_are_the_nodes_answers` rewrites the file; then regenerate
//! `vectors/SHA256SUMS`.

use super::*;

const VECTORS: &str = "../../vectors/no-complete-answer/vectors.json";

/// Fragments of a member name that would state a covered interval or a
/// completeness claim; no member name of an answer's artifact, at any depth,
/// may hold one. Any new member name is read here before it passes.
const CLAIMS: [&str; 8] = [
    "interval",
    "complete",
    "coverage",
    "range",
    "cover",
    "span",
    "certificate",
    "size",
];

/// Every member name in `v`, at any depth, sorted and unique.
fn member_names(v: &Value, out: &mut std::collections::BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                out.insert(k.clone());
                member_names(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| member_names(x, out)),
        _ => {}
    }
}

/// `COMPLETE`, `INCOMPLETE` or `REFUSED`, from the reply and the node's own
/// checkpoint list (for the anchor's size).
fn reading(node: &Node, sent: &[u8], reply: &Value) -> (&'static str, Value) {
    let state = evidence_answer::verify_response(
        sent,
        reply,
        &key().verifying_key(),
        &std::collections::BTreeMap::new(),
    );
    match state["state"].as_str() {
        Some("refusal") => return ("REFUSED", json!({"reason": state["reason"]})),
        Some("artifact") => {}
        _ => panic!("a node's own reply verifies: {state}"),
    }
    let checked = check_reply(sent, reply).expect("a node's own answer verifies");
    let at = node
        .anchors
        .iter()
        .position(|a| *a == checked.anchor)
        .unwrap();
    let leaves = leaf_count(node_size(node, at)).unwrap();
    let whole: Vec<u64> = (0..leaves).collect();
    // A single record's artifact is the record's own line, whose members are
    // the record's, not a statement about the answer.
    let single = request::parse_json(sent)
        .map(|r| r.derivation.is_none() && matches!(r.subject, Subject::Record(_)))
        .unwrap_or(false);
    let mut members = std::collections::BTreeSet::new();
    if !single {
        let artifact = serde_json::from_slice::<Value>(&envelope_of(reply).artifact).unwrap();
        member_names(&artifact, &mut members);
    }
    for member in &members {
        let lower = member.to_lowercase();
        assert!(!CLAIMS.iter().any(|c| lower.contains(c)), "{member}");
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
            "members": members,
        }),
    )
}

/// Whether a kind is asked of the corroborating node, and what it must read.
fn expectation(kind: &str) -> (bool, &'static str) {
    match kind {
        "exchange_corroboration/1" => (true, "INCOMPLETE"),
        "served_summary/1" => (false, "REFUSED"),
        "control:full_history" => (false, "COMPLETE"),
        _ => (false, "INCOMPLETE"),
    }
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

/// (kind, what, request, setup)
type Case = (&'static str, &'static str, Vec<u8>, Setup);

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
        ),
        (
            "correlation",
            "the records under one correlation key",
            ask(json!({"subject": {"correlation": "n-1"}, "coverage": pin})),
            plain,
        ),
        (
            "exchange",
            "the records citing a counterparty's half",
            ask(json!({"subject": {"exchange": half}, "coverage": {"expected_pin": half}})),
            plain,
        ),
        (
            "checkpoints",
            "the checkpoint list",
            ask(json!({"subject": {"checkpoints": null}, "coverage": pin})),
            plain,
        ),
        (
            "history_card/1",
            "the history card",
            ask(
                json!({"subject": {"full_history": null}, "coverage": pin, "derivation": "history_card/1"}),
            ),
            plain,
        ),
        (
            "served_summary/1",
            "retired: refused to every asker (capsules-plugin#106)",
            ask(
                json!({"subject": {"full_history": null}, "coverage": pin, "derivation": "served_summary/1"}),
            ),
            plain,
        ),
        (
            "exchange_corroboration/1",
            "the halves of a served exchange",
            corroboration,
            Setup {
                corroboration: true,
                ..plain
            },
        ),
        (
            "control:full_history",
            "every record up to the first checkpoint; never served to an asker",
            ask(json!({"subject": {"full_history": null}, "coverage": first})),
            plain,
        ),
    ]
}

fn generate() -> Value {
    let (plain, corroborating) = nodes();
    let out: Vec<Value> = cases(&plain)
        .into_iter()
        .map(|(kind, what, request, setup)| {
            let (corroboration, expect) = expectation(kind);
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
                "corroborating": corroboration,
                "expect": expect,
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

/// The file's replies are read afresh (signatures and refusals verified), so
/// a vector cannot claim a reading its reply does not give.
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
    let (plain, corroborating) = nodes();
    for case in file["cases"].as_array().unwrap() {
        let kind = case["kind"].as_str().unwrap();
        let sent = serde_json::to_vec(&case["request"]).unwrap();
        let node = if case["corroborating"] == json!(true) {
            &corroborating
        } else {
            &plain
        };
        let (verdict, _) = reading(node, &sent, &case["reply"]);
        assert_eq!(verdict, case["reading"], "{kind}");
        let (corroboration, expect) = expectation(kind);
        assert_eq!(case["corroborating"], json!(corroboration), "{kind}");
        assert_eq!(verdict, expect, "{kind}");
    }
}
