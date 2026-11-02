//! The #315 conformance vectors (`vectors/inference-service-history-v0`,
//! action-state-group/agent-action-capsule#315 at f8c946ed) against this
//! node's use of the library. The library runs every Standard case of the
//! vectors itself (`agent-action-capsule`, `tests/inference_history_vectors.rs`,
//! evidencebook#322); what stays here is that this copy is the source's
//! bytes, and that the artifact this node builds for the generator's
//! served-only History is the generator's artifact.

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;

const VECTORS: &str = include_str!("../../../../vectors/inference-service-history-v0/vectors.json");

fn cases() -> Vec<Value> {
    let corpus: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(corpus["count"], json!(27));
    corpus["cases"].as_array().unwrap().clone()
}

fn id(case: &Value) -> &str {
    case["id"].as_str().unwrap()
}

/// The JSON a case carries as octets.
fn octets(part: &Value) -> Value {
    serde_json::from_str(part["octets_text"].as_str().unwrap()).unwrap()
}

/// The artifact of a case's reply envelope.
fn artifact_of(reply: &Value) -> serde_json::Map<String, Value> {
    let envelope = octets(reply);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(envelope["artifact"].as_str().unwrap().trim_end_matches('='))
        .unwrap();
    serde_json::from_slice::<Value>(&bytes)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn the_vector_files_are_the_ones_pinned() {
    // The copy is byte-identical to the source's, which its own manifest and
    // SHA256SUMS pin.
    let digest = hex::encode(Sha256::digest(VECTORS.as_bytes()));
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../vectors/inference-service-history-v0/manifest.json"
    ))
    .unwrap();
    assert_eq!(manifest["files"][0]["sha256"], json!(digest));
    assert_eq!(manifest["files"][0]["count"], json!(27));
}

/// The two-node e2e script names its two-minute definition by the digest it
/// computes with `jq`; this build computes the same one.
#[test]
fn the_e2e_override_is_another_definition_with_its_own_digest() {
    let mut document: Value = serde_json::from_str(DEFINITION_DOCUMENT).unwrap();
    document["period_policy"]["length_s"] = json!(120);
    document["period_policy"]["min_length_s"] = json!(120);
    let def = Definition::from_document(&document).unwrap();
    assert_eq!(def.0.policy().length_s, 120);
    assert_eq!(
        def.digest(),
        "cf7f57f95044d0cb573320f6eaba74d4a85bc73136f23c8112ca9d41f5c11eeb"
    );
    assert_ne!(def.digest(), DEFINITION_DIGEST);
    assert_ne!(def.0.policy_digest(), POLICY_DIGEST);
}

/// The served exchanges per model that the generator's
/// `standard-served-only` case counts in its three closed days (its
/// `SERVED`); the requested ones are in no cell.
const SERVED_ONLY: [[(&str, u64); 2]; 3] = [
    [("model-a", 12), ("model-b", 7)],
    [("model-a", 9), ("model-b", 3)],
    [("model-a", 6), ("model-b", 5)],
];

/// The artifact this node builds for the generator's served-only History
/// is the generator's artifact, byte for byte: the same cells from the same
/// per-model counts, the same members, the same JCS octets. The embedded
/// card is the card's own canonical octets (the vectors' card is a
/// corpus-only shape, ISH §9, so the direct `history_card/1` of a real node
/// is not rebuilt here).
#[test]
fn the_served_only_artifact_is_the_generators_bytes() {
    let all = cases();
    let case = all
        .iter()
        .find(|c| id(c) == "standard-served-only")
        .unwrap();
    let def = Definition::from_document(&case["inputs"]["definition"]).unwrap();
    let want = artifact_of(&case["inputs"]["reply"]);
    let theirs = want["period_counts"]["periods"].as_array().unwrap();
    assert_eq!(theirs.len(), SERVED_ONLY.len());
    // One record per served exchange, in period order, with a checkpoint
    // inside each period and the anchor at the end of the last.
    let mut models: Vec<&str> = Vec::new();
    let mut times: Vec<(String, u64)> = Vec::new();
    for (period, served) in theirs.iter().zip(SERVED_ONLY) {
        for (model, n) in served {
            models.extend(std::iter::repeat_n(model, n as usize));
        }
        let from = period["from"].as_str().unwrap();
        let inside = format!("{}T12:00:00Z", &from[..10]);
        times.push((inside, models.len() as u64));
    }
    times.push((
        theirs.last().unwrap()["to"].as_str().unwrap().to_string(),
        models.len() as u64,
    ));
    let chain: Vec<Cut<'_>> = times
        .iter()
        .map(|(timestamp, leaves)| Cut {
            timestamp,
            leaves: *leaves,
        })
        .collect();
    let counts = agent_action_capsule::inference_history::period_counts(&def.0, &chain, &|i| {
        models.get(i as usize).map(|m| m.to_string())
    })
    .unwrap();
    assert_eq!(
        counts, want["period_counts"],
        "cells, floor and complementary rule"
    );
    let card = evidence_request::jcs::to_string(&want["history_card"]).unwrap();
    let got = artifact_for(
        &def,
        card.as_bytes(),
        counts,
        want["anchor"].as_str().unwrap(),
        want["evidence_stream"].as_str().unwrap(),
        want["coverage_declaration"]["live_set"][0]["count"]
            .as_u64()
            .unwrap(),
    )
    .unwrap();
    let generated = {
        let envelope = octets(&case["inputs"]["reply"]);
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(envelope["artifact"].as_str().unwrap().trim_end_matches('='))
            .unwrap()
    };
    assert_eq!(got, generated);
}

/// ISH §5.1: this plugin counts exchanges served and no other unit, so a
/// served count is never summed with a requested one, and no cell is a score.
/// Checked over the cells this node's own derivation produces.
#[test]
fn a_cell_counts_served_exchanges_and_nothing_else() {
    let models: Vec<&str> = std::iter::repeat_n("model-a", 6)
        .chain(std::iter::repeat_n("model-b", 3))
        .collect();
    let chain = [
        Cut {
            timestamp: "2026-01-07T12:00:00Z",
            leaves: 9,
        },
        Cut {
            timestamp: "2026-01-12T00:00:00Z",
            leaves: 9,
        },
    ];
    let counts = period_counts(&chain, &|i| models.get(i as usize).map(|m| m.to_string())).unwrap();
    let cells = counts["periods"][0]["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 3, "two models and the total");
    for cell in cells {
        assert_eq!(cell["unit"], json!("exchanges_served"));
        assert_eq!(cell["label"], json!("self_reported"));
        let published = cell.get("suppressed").is_none();
        assert_eq!(
            cell.as_object().unwrap().len(),
            if published { 4 } else { 5 },
            "no member beyond dimension, label, unit, value (and suppressed)"
        );
    }
}
