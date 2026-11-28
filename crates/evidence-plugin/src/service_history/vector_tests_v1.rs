//! The `inference-service-history/1` conformance vectors
//! (`vectors/inference-service-history-v1`, action-state-group/agent-action-capsule#671
//! at e1286e01, unchanged in the crate release 0.15.0 this plugin pins)
//! against this node's use of the library: the copy is the source's bytes,
//! every case checks as its `expected` block says through this node's
//! `check_artifact`, and the tables this node's derivation produces for the
//! generator's counts are the vectors' tables.
//!
//! The cases name example definitions (`service_history_example/1`) and a
//! corpus-only card (ISH §9), so they run through the definition-parameterized
//! [`check_artifact`] wrapper, as the `/0` set does in `vector_tests.rs`, not
//! through the envelope path, which knows only this node's own definitions;
//! the envelope path under `service_history/3` and `/4` is `tests.rs`'s.

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;

const VECTORS: &str = include_str!("../../../../vectors/inference-service-history-v1/vectors.json");

fn cases() -> Vec<Value> {
    let corpus: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(corpus["count"], json!(13));
    corpus["cases"].as_array().unwrap().clone()
}

fn id(case: &Value) -> &str {
    case["id"].as_str().unwrap()
}

fn case(want: &str) -> Value {
    cases().into_iter().find(|c| id(c) == want).unwrap()
}

/// The artifact of a case's reply envelope.
fn artifact_of(case: &Value) -> Map<String, Value> {
    let envelope: Value =
        serde_json::from_str(case["inputs"]["reply"]["octets_text"].as_str().unwrap()).unwrap();
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
    let digest = hex::encode(Sha256::digest(VECTORS.as_bytes()));
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../vectors/inference-service-history-v1/manifest.json"
    ))
    .unwrap();
    assert_eq!(manifest["files"][0]["sha256"], json!(digest));
    assert_eq!(manifest["files"][0]["count"], json!(13));
}

/// Every case, its verdict counts too where its definition carries them,
/// fails the one History property its `expected` block names, or none,
/// when this node checks it under the case's own `/1` definition.
#[test]
fn every_case_checks_as_the_vectors_expect() {
    let all = cases();
    for case in &all {
        let def = Definition::from_document(&case["inputs"]["definition"]).unwrap();
        assert!(def.is_revision_1(), "{}", id(case));
        let art = artifact_of(case);
        let chain: Vec<Cut<'_>> = art["history_card"]["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| Cut {
                timestamp: h["checkpoint"]["timestamp"].as_str().unwrap(),
                leaves: h["checkpoint"]["log_size"].as_u64().unwrap(),
            })
            .collect();
        let got = check_artifact(
            &def,
            &art,
            &chain,
            art["anchor"].as_str().unwrap(),
            art["evidence_stream"].as_str().unwrap(),
        );
        let fails = case["expected"]["fails"].as_array().unwrap();
        assert!(fails.len() <= 1, "{}", id(case));
        match (fails.first().and_then(Value::as_str), got) {
            (None, Ok(_)) => {}
            (Some(want), Err(why)) => {
                assert_eq!(why.split(':').next().unwrap(), want, "{}: {why}", id(case))
            }
            (want, got) => panic!("{}: expected {want:?}, got {got:?}", id(case)),
        }
    }
    assert_eq!(all.len(), 13);
}

/// 2 October's cells in `member` of a case's artifact.
fn october_2(case: &Value, member: &str) -> Value {
    artifact_of(case)[member]["periods"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["from"] == json!("2026-10-02T00:00:00Z"))
        .unwrap()["cells"]
        .clone()
}

/// A stream whose only records are on 2 October, committed by a checkpoint
/// inside that day and anchored at its end: the History holds that one
/// period.
fn october_2_chain(records: u64) -> [Cut<'static>; 2] {
    [
        Cut {
            timestamp: "2026-10-02T12:00:00Z",
            leaves: records,
        },
        Cut {
            timestamp: "2026-10-03T00:00:00Z",
            leaves: records,
        },
    ]
}

/// The served counts per model behind each positive case's 2 October table
/// (the generator's `period_counts(day2)`,
/// `python/scripts/generate_inference_service_history_v1_vectors.py`).
const SERVED: [(&str, &[(&str, u64)]); 4] = [
    (
        "v1-total-withheld-two-under-floor",
        &[("model-a", 4), ("model-b", 4)],
    ),
    (
        "v1-total-withheld-five-ones",
        &[
            ("model-a", 1),
            ("model-b", 1),
            ("model-c", 1),
            ("model-d", 1),
            ("model-e", 1),
        ],
    ),
    (
        "v1-total-under-floor-withheld-complementary",
        &[("model-a", 1), ("model-b", 1)],
    ),
    (
        "v1-total-pins-nothing-published",
        &[("model-a", 3), ("model-b", 4)],
    ),
];

/// This node's derivation, run on the generator's counts, produces each
/// positive case's 2 October table cell for cell: 4 and 4, and five of 1,
/// withhold their totals; 1 and 1 withholds its total of 2 `complementary`,
/// not `below_floor`, which no verifier could see (ISH §6.2 item 5, SH-14);
/// 3 and 4 publishes its total of 7.
#[test]
fn the_tables_this_node_produces_are_the_vectors_tables() {
    for (case_id, served) in SERVED {
        let case = case(case_id);
        let def = Definition::from_document(&case["inputs"]["definition"]).unwrap();
        let models: Vec<&str> = served
            .iter()
            .flat_map(|(m, n)| std::iter::repeat_n(*m, *n as usize))
            .collect();
        let chain = october_2_chain(models.len() as u64);
        let counts = period_counts_for(&def, &chain, &|i| {
            models.get(i as usize).map(|m| m.to_string())
        })
        .unwrap();
        let periods = counts["periods"].as_array().unwrap();
        assert_eq!(periods.len(), 1, "{case_id}");
        assert_eq!(
            periods[0]["cells"],
            october_2(&case, "period_counts"),
            "{case_id}"
        );
    }
    // The 1 and 1 total is withheld for the sum it would give away, not for
    // being under the floor.
    let tiny = october_2(
        &case("v1-total-under-floor-withheld-complementary"),
        "period_counts",
    );
    assert_eq!(
        tiny.as_array().unwrap().last().unwrap()["suppressed"],
        json!("complementary")
    );
}

/// The same rule in a verdict result's table: 4 contradicted about each of
/// two model hashes withholds the contradicted total, and this node's
/// derivation gives the vector's 2 October verdict cells for the verdicts it
/// holds that day.
#[test]
fn the_verdict_table_this_node_produces_is_the_vectors_table() {
    let case = case("v1-verdict-total-withheld");
    let def = Definition::from_document(&case["inputs"]["definition"]).unwrap();
    assert!(def.has_verdict_counts());
    let h1 = "19959928f6b42ab2e5e313c77ea4e67e13e9265aebf11fea9788e695a7a68155";
    let h2 = "3bb1c705103018aa08e500771ca00da6ef470150d703166d1c1edbdb9fad5a8d";
    let held: Vec<(&str, &str)> = [
        (h2, "corroborated", 5),
        (h1, "contradicted", 4),
        (h2, "contradicted", 4),
        (h1, "inconclusive", 11),
    ]
    .iter()
    .flat_map(|&(hash, result, n)| std::iter::repeat_n((hash, result), n))
    .collect();
    let chain = october_2_chain(held.len() as u64);
    let counts = verdict_counts(&def, &chain, &|i| {
        held.get(i as usize)
            .map(|(hash, result)| (hash.to_string(), result.to_string()))
    })
    .unwrap();
    let periods = counts["periods"].as_array().unwrap();
    assert_eq!(periods.len(), 1);
    let want = october_2(&case, "verdict_counts");
    assert_eq!(periods[0]["cells"], want);
    let total = want
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["dimension"] == json!({"result": "contradicted"}))
        .unwrap();
    assert_eq!(total["suppressed"], json!("complementary"));
}

/// This node's own definitions are the `/1` ones, and frame for frame the
/// `/0` ones they follow: only `profile` and `name` differ (ISH §4.1: a new
/// name and digest, never an in-place change).
#[test]
fn this_nodes_definitions_are_the_legacy_ones_under_revision_1() {
    for (served, legacy, name) in [
        (DEFINITION_DOCUMENT, LEGACY_DOCUMENT_1, "service_history/3"),
        (
            DEFINITION_DOCUMENT_VERDICTS,
            LEGACY_DOCUMENT_2,
            "service_history/4",
        ),
    ] {
        let mut served: Value = serde_json::from_str(served).unwrap();
        let legacy: Value = serde_json::from_str(legacy).unwrap();
        assert_eq!(served["profile"], json!("inference-service-history/1"));
        assert_eq!(legacy["profile"], json!("inference-service-history/0"));
        assert_eq!(served["name"], json!(name));
        served["profile"] = legacy["profile"].clone();
        served["name"] = legacy["name"].clone();
        assert_eq!(served, legacy);
    }
}
