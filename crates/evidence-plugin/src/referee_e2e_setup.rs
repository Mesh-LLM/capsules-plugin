//! Setup for the referee step of the two-node run (`scripts/e2e-two-node.sh`),
//! run by the script while both nodes are up.
//!
//! A twin pair needs three serving machines: two twins and a referee that is
//! neither (`docs/TWIN-REFEREE-SELECTION.md`). The run has one, so the twins
//! are two test keys ([`TWINS`]) that both nodes' operators announce, and
//! their halves are made here from the provider's own served record of one
//! exchange. The requester holds them through its own receiver, as if the
//! twins had pushed them. Everything after that runs between the two nodes,
//! through the plugin's own tools: the requester puts the pair to the
//! provider (`mesh_evidence_request`), the provider signs the verdict and
//! seals `adjudication_issued`, then delivers the verdict to the requester
//! (`deliver_adjudication`), which seals `adjudication_received`.
//!
//! Not covered: the live trigger (`referee::live`), which assembles the pair
//! from real twin traffic and chooses the referee.
//!
//! These are not under `two_node_e2e::`, so the scenario checks, which run
//! after the nodes stop, never run them.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::record_push_receive::{receive, Receiver, MAX_REJECTED_LOG_BYTES};

/// The two twins' node ids.
pub(crate) const TWINS: [&str; 2] = ["e2e-twin-a", "e2e-twin-b"];
/// The pair's twin bracket id.
pub(crate) const TWIN_BRACKET_ID: &str = "e2e-referee-pair";
/// The exchange whose served record the twins' halves are made from, and
/// whose answer is the referee's (the script's first exchange).
const PROMPT: &str = "Reply with the number 1 and nothing else.";
const KEY_SEED_PREFIX: &str = "capsules-e2e-referee/v1/";

/// A twin's test key: the Ed25519 key whose seed is SHA-256 of
/// [`KEY_SEED_PREFIX`] followed by the twin's id. For this run only.
pub(crate) fn twin_key(twin: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(format!("{KEY_SEED_PREFIX}{twin}")).into();
    SigningKey::from_bytes(&seed)
}

/// The twins' announced keys, as an operator's key map.
pub(crate) fn twin_peer_keys() -> Map<String, Value> {
    TWINS
        .iter()
        .map(|twin| {
            let key = hex::encode(twin_key(twin).verifying_key().to_bytes());
            (twin.to_string(), json!(key))
        })
        .collect()
}

fn env_path(var: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| panic!("{var} must be set")))
}

fn read_json(path: &Path) -> Value {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Writes the twins' key map to `E2E_TWIN_KEYS`, for the script to give
/// both nodes before they start.
#[test]
#[ignore = "run by scripts/e2e-two-node.sh"]
fn write_twin_keys() {
    let path = env_path("E2E_TWIN_KEYS");
    std::fs::write(&path, Value::Object(twin_peer_keys()).to_string()).unwrap();
}

/// The provider's served record of the exchange it answered with `response`
/// (by the answer: the host rewrites a request before the provider seals it).
fn served_record_of(provider_ledger: &Path, response: &Value) -> Value {
    let digest = crate::capsule_emit::digest_json(response).unwrap();
    let text = crate::chain_store::read_chain_string(provider_ledger).unwrap();
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| {
            record
                .pointer("/model_attestation/compute_attestation/x-mesh-poc-v1/role")
                .and_then(Value::as_str)
                == Some("served")
        })
        .find(|record| {
            record
                .pointer("/effect/response_digest")
                .and_then(Value::as_str)
                == Some(&digest)
        })
        .unwrap_or_else(|| panic!("the provider has no served record of the answer {response}"))
}

/// One twin's half: the provider's served record, as `twin` would have
/// sealed it answering `response`, signed with the twin's key.
fn twin_half(template: &Value, twin: &str, request: &Value, response: &Value) -> Value {
    let key = twin_key(twin);
    let mut half = template.clone();
    let request_digest = crate::capsule_emit::digest_json(request).unwrap();
    let response_digest = crate::capsule_emit::digest_json(response).unwrap();
    half["effect"]["request_digest"] = json!(request_digest);
    half["effect"]["response_digest"] = json!(response_digest);
    let attestation = half
        .pointer_mut("/model_attestation/compute_attestation")
        .expect("a mesh half carries compute_attestation");
    attestation["agent_input_digest"] = json!(request_digest);
    attestation["agent_output_digest"] = json!(response_digest);
    let provenance = attestation
        .pointer_mut("/x-mesh-poc-v1/serving_provenance")
        .expect("a mesh half carries serving_provenance");
    provenance["served_by_node_id"] = json!(twin);
    provenance["exchange_id"] = json!(format!("{TWIN_BRACKET_ID}-{twin}"));
    half["key_id"] = json!(hex::encode(key.verifying_key().to_bytes()));
    let id = capsule_emit_lib::jcs::compute_capsule_id(&half).expect("recompute capsule_id");
    half["capsule_id"] = json!(id);
    capsule_emit_lib::capsule::attach_producer_envelope(&mut half, &key).expect("sign the half");
    half
}

/// Makes the twins' halves of the run's first exchange, has the running
/// requester hold them through its own receiver (each from its twin), and
/// writes the adjudicate request to `E2E_ADJUDICATE_REQUEST`.
///
/// The twins were asked the first exchange's request, at temperature 0.
/// Twin A answered what the provider did; twin B answered otherwise from
/// the first word, so the verdict contradicts twin B. The
/// referee answer is the provider's own answer to that exchange, which its
/// chain records. Reads `E2E_PROVIDER_DIR` and `E2E_REQUESTER_DIR` (the
/// running nodes' plugin data), and `E2E_FIRST_EXCHANGE` (the script's saved
/// request and response).
#[test]
#[ignore = "run by scripts/e2e-two-node.sh while both nodes are up"]
fn put_twin_halves_on_the_requester() {
    let provider_dir = env_path("E2E_PROVIDER_DIR");
    let requester_dir = env_path("E2E_REQUESTER_DIR");
    let exchange = read_json(&env_path("E2E_FIRST_EXCHANGE"));
    let (request, answer) = (&exchange["request_body"], &exchange["response_body"]);
    assert_eq!(request.pointer("/messages/0/content"), Some(&json!(PROMPT)));
    let template = served_record_of(&provider_dir.join("ledger"), answer);

    // Each twin's own answer: the same text as the provider's, or another,
    // under its own response id, so no twin's answer is the provider's body.
    let text = answer
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .expect("the provider answered with text");
    // Twin B differs at the first word, so the referee's answer, which is
    // twin A's, decides: the verdict contradicts twin B.
    let answers = [text.to_string(), format!("twin-b {text}")];
    let pem = std::fs::read_to_string(requester_dir.join("keys").join("node-key.pem")).unwrap();
    let requester_key = capsule_emit_lib::keys::load_signing_key_pem(&pem).unwrap();
    let peer_keys = Value::Object(twin_peer_keys()).to_string();
    let receiver = Receiver {
        ledger_dir: &requester_dir.join("ledger"),
        signing_key: &requester_key,
        peer_keys: Some(&peer_keys),
        record_at_completion_off: false,
        rejected_log_limit: MAX_REJECTED_LOG_BYTES,
        announced: crate::peer_keys::NONE_ANNOUNCED,
    };
    let now = crate::producer::timestamp::utc_now_iso8601();
    let mut halves = Vec::new();
    for (twin, content) in TWINS.iter().zip(answers) {
        let mut response = answer.clone();
        response["id"] = json!(format!("{TWIN_BRACKET_ID}-{twin}"));
        response["choices"][0]["message"]["content"] = json!(content);
        let half = twin_half(&template, twin, request, &response);
        let reply = receive(&receiver, half.to_string().as_bytes(), Some(twin), &now)
            .expect("the requester's own writes succeed");
        assert_eq!(reply["status"], json!("received"), "{twin}: {reply}");
        halves.push(json!({"capsule": half, "request_body": request, "response_body": response}));
    }
    let adjudicate = json!({
        "subject": {"kind": crate::referee::service::ADJUDICATE_SUBJECT_KIND},
        "selection_tier": 2,
        "twin_bracket_id": TWIN_BRACKET_ID,
        "halves": halves,
        "referee_answer": {"request_body": request, "response_body": answer},
    });
    std::fs::write(env_path("E2E_ADJUDICATE_REQUEST"), adjudicate.to_string()).unwrap();
}
