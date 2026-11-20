//! capsule-engine's shared `asg/inference` conformance vectors (#263), the
//! ones the Python reference, the Go port and the Rust crate all pass, held
//! against the evaluator this plugin links: the price caps and the allow and
//! deny `counterparty_list` cases, clear and fingerprint kinds. The copies
//! are in `vectors/capsule-engine-guard-inference-v0/` (`vectors/SOURCES.md`).
//! This is the proof that the plugin evaluates the operator's
//! `policy-profile/v0` as the format's other implementations do.

use capsule_engine::guard::{record_for, Action, Engine, History, Profile};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/capsule-engine-guard-inference-v0")
}

/// One case decided as the vectors' runners decide an action-ledger case:
/// each step's record enters the history under the capsule id the reference
/// sealed for it. `Err` is a refusal, which agrees with an expected error.
/// A step's outcome and each constraint's id, result and evidence digest.
type Step = (String, Vec<(String, String, String)>);

fn decide(case: &Value, input: &Value) -> Result<Vec<Step>, String> {
    let mut engine = Engine::inference().map_err(|e| e.to_string())?;
    if let Some(profile) = input.get("profile") {
        let profile =
            Profile::decode(&serde_json::to_vec(profile).unwrap()).map_err(|e| e.to_string())?;
        engine = engine.with_profile(&profile).map_err(|e| e.to_string())?;
    }
    let expected = case["expected"]["steps"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut history = History::new();
    let mut out = Vec::new();
    for (i, step) in input["steps"].as_array().unwrap().iter().enumerate() {
        let action =
            Action::decode(&serde_json::to_vec(step).unwrap()).map_err(|e| e.to_string())?;
        let decision = engine
            .decide(&action, &history)
            .map_err(|e| e.to_string())?;
        let id = expected
            .get(i)
            .and_then(|s| s["capsule_id"].as_str())
            .unwrap_or("")
            .to_string();
        out.push((
            decision.outcome().as_str().to_string(),
            decision
                .constraints()
                .iter()
                .map(|c| {
                    (
                        c.id().to_string(),
                        c.result().as_str().to_string(),
                        c.evidence_digest().to_string(),
                    )
                })
                .collect(),
        ));
        history.append(record_for(&action, &decision, id));
    }
    Ok(out)
}

#[test]
fn the_shared_inference_vectors_hold_here() {
    let set: Value =
        serde_json::from_slice(&std::fs::read(dir().join("inference.json")).unwrap()).unwrap();
    let cases = set["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 25, "the shared set's cases");
    let mut failures = Vec::new();
    for case in cases {
        let name = case["case"].as_str().unwrap();
        let file = Path::new(case["input"].as_str().unwrap())
            .file_name()
            .unwrap()
            .to_owned();
        let raw = std::fs::read(dir().join("inputs").join(file)).unwrap();
        let sum = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&raw))
        };
        assert_eq!(
            sum,
            case["input_sha256"].as_str().unwrap(),
            "{name}: not the pinned input"
        );
        let input: Value = serde_json::from_slice(&raw).unwrap();
        let got = decide(case, &input);
        if case["expected"].get("error").is_some() {
            if got.is_ok() {
                failures.push(format!("{name}: expected a refusal"));
            }
            continue;
        }
        let steps = match got {
            Ok(steps) => steps,
            Err(e) => {
                failures.push(format!("{name}: refused: {e}"));
                continue;
            }
        };
        let want = case["expected"]["steps"].as_array().unwrap();
        if steps.len() != want.len() {
            failures.push(format!(
                "{name}: {} steps, expected {}",
                steps.len(),
                want.len()
            ));
            continue;
        }
        for (i, ((outcome, constraints), w)) in steps.iter().zip(want).enumerate() {
            if outcome != w["outcome"].as_str().unwrap() {
                failures.push(format!(
                    "{name} step {i}: outcome {outcome}, expected {}",
                    w["outcome"]
                ));
            }
            let wc = w["constraints"].as_array().unwrap();
            let same = constraints.len() == wc.len()
                && constraints.iter().zip(wc).all(|((id, result, digest), e)| {
                    e["id"] == *id && e["result"] == *result && e["evidence_digest"] == *digest
                });
            if !same {
                failures.push(format!(
                    "{name} step {i}: constraints {constraints:?} differ from {wc:?}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
