// SPDX-License-Identifier: BSD-3-Clause
//! Evidence Bundle -03 History members and the `same_key` join basis
//! (Mesh-LLM/capsules-plugin#331): the 30 cases of
//! `vectors/bundle/composed-history/` (pinned in `vectors/SOURCES.md`), run
//! through `agent-action-capsule`'s composed verifier, the one
//! `verify_bundle_strict` runs on a `composed/v1` block, and compared with
//! each case's whole `expect`. The reader is ported from the crate's own
//! `tests/bundle_composed_vectors.rs` (tag `crates/agent-action-capsule-v0.14.0`),
//! which reads the same vectors as the Python, Go and TypeScript tests do.

use agent_action_capsule::bundle::{
    composed_digest_preimage, verify_bundle_with_options, BundleOptions, ComposedOptions,
    ComposedResult, VerificationResult, COMPOSED_KIND,
};
use agent_action_capsule::verify::decode_capsule_json;
use serde_json::{json, Map, Value};

fn cases(directory: &str, count: usize) -> Vec<Value> {
    let path = format!(
        "{}/../../vectors/bundle/{directory}/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&path).expect("vectors.json");
    let vectors = decode_capsule_json(&data).expect("valid JSON");
    let cases = vectors["cases"].as_array().expect("cases").clone();
    assert_eq!(cases.len(), count, "{directory}");
    assert_eq!(vectors["count"], json!(count), "{directory}");
    cases
}

/// Compare through the canonical text so number spellings agree.
fn same(got: &Value, want: &Value) -> bool {
    let got: Value = serde_json::from_str(&got.to_string()).unwrap();
    let want: Value = serde_json::from_str(&want.to_string()).unwrap();
    got == want
}

fn block_of(container: &Value) -> &Value {
    &container["extensions"][COMPOSED_KIND]
}

fn composed_of(result: &VerificationResult) -> &ComposedResult {
    assert_eq!(result.extensions.len(), 1);
    let extension = &result.extensions[0];
    assert_eq!(extension.kind, COMPOSED_KIND);
    assert!(extension.integrity_covered);
    let composed = extension.composed.as_ref().expect("a composed result");
    assert_eq!(composed.status, extension.status);
    composed
}

/// A composed result in the vectors' `expect` vocabulary.
fn expect_shape(result: &ComposedResult) -> Value {
    let mut members = Map::new();
    for m in &result.members {
        let claims = m.bundle.as_ref().map(|b| {
            json!({
                "graph_closure": b.graph_closure.status,
                "interval_coverage": b.interval_coverage.status,
                "per_record_membership": b.per_record_membership.status,
            })
        });
        let mut member = json!({
            "outcome": m.outcome, "body": m.body, "digest": m.digest, "claims": claims,
        });
        if let Some(history) = m.bundle.as_ref().and_then(|b| b.history.as_ref()) {
            member["history"] = json!({"state": history.state, "since": history.since});
        }
        if let Some(signature) = &m.response_signature {
            let binding = |finding: &str| {
                if m.findings.iter().any(|f| f == finding) {
                    "mismatch"
                } else {
                    "matches"
                }
            };
            member["response"] = json!({
                "request_digest": binding("response_request_digest_mismatch"),
                "artifact_digest": binding("response_artifact_digest_mismatch"),
                "signature": signature,
            });
        }
        if let Some(h) = &m.history {
            member["history_member"] = json!({
                "derivation": h.derivation, "envelope_signature": h.envelope_signature,
                "artifact_digest": h.artifact_digest, "request_digest": h.request_digest,
                "artifact_anchor": h.artifact_anchor, "anchor_checkpoint": h.anchor_checkpoint,
                "key": h.key, "time": h.time,
            });
        }
        members.insert(m.id.clone(), member);
    }
    let closure = result.composition_closure.as_ref().unwrap();
    let mut closure_value = json!({"status": closure.status, "missing": closure.missing});
    if closure.status == "withheld" {
        closure_value["finding"] = json!(closure.findings[0]);
    }
    let joins: Vec<Value> = result
        .joins
        .iter()
        .map(|j| {
            let mut value = json!({
                "members": j.members, "declared": j.declared,
                "derived": j.derived, "result": j.result,
            });
            if !j.keys.is_empty() {
                value["keys"] = j
                    .keys
                    .iter()
                    .map(|k| json!({"member": k.member, "key": k.key}))
                    .collect();
            }
            if let Some(t) = &j.history_times {
                value["history_times"] = json!({
                    "history": t.history, "history_time": t.history_time, "record": t.record,
                    "record_time": t.record_time, "relation": t.relation,
                });
            }
            value
        })
        .collect();
    let corroboration: Vec<Value> = result
        .corroboration
        .iter()
        .map(|c| {
            let mut value = json!({"members": c.members, "result": c.result});
            for (key, field) in [
                ("reason", &c.reason),
                ("report", &c.report),
                ("qualifier", &c.qualifier),
            ] {
                if let Some(field) = field {
                    value[key] = json!(field);
                }
            }
            value
        })
        .collect();
    json!({
        "composed_digest": result.composed_digest.as_ref().unwrap().recomputed,
        "status": result.status,
        "members": members,
        "composition_closure": closure_value,
        "joins": joins,
        "corroboration": corroboration,
    })
}

fn expectation(expect: &Value, skip: &[&str]) -> Value {
    let mut want = expect.as_object().unwrap().clone();
    for key in skip {
        want.remove(*key);
    }
    Value::Object(want)
}

fn options_of<'a>(case: &'a Value) -> BundleOptions<'a> {
    let list = |name: &str| -> &'a [Value] {
        case.get(name)
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
    };
    BundleOptions {
        composed: ComposedOptions {
            controller_bindings: list("controller_bindings"),
            binding_revocations: list("binding_revocations"),
            ..ComposedOptions::default()
        },
        ..BundleOptions::default()
    }
}

/// -03 History members and the `same_key` basis: the whole `expect`, or, for
/// a malformed block, a failed check with no composition result.
#[test]
fn composed_history_vectors() {
    let cases = cases("composed-history", 30);
    let digest_of = |id: &str| {
        cases.iter().find(|c| c["id"] == json!(id)).unwrap()["expect"]["composed_digest"].clone()
    };
    assert_eq!(
        digest_of("history-member-missing"),
        digest_of("history-two-parties")
    );
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let container = &case["container"];
        let expect = &case["expect"];
        let result = verify_bundle_with_options(container, &options_of(case));
        let composed = composed_of(&result);
        if expect.get("malformed") == Some(&json!(true)) {
            assert_eq!(composed.status, "fail", "{id}");
            assert!(composed.malformed, "{id}: {:?}", composed.findings);
            assert!(composed.joins.is_empty(), "{id}");
            continue;
        }
        let preimage = composed_digest_preimage(block_of(container)).expect("preimage");
        assert_eq!(
            expect["canonical_preimage"].as_str().unwrap().as_bytes(),
            preimage.as_slice(),
            "{id}"
        );
        assert_eq!(
            expect["status"],
            json!(composed.status),
            "{id}: {:?}",
            composed.findings
        );
        let want = expectation(
            expect,
            &["canonical_preimage", "composed_digest_equals_case"],
        );
        assert!(
            same(&expect_shape(composed), &want),
            "{id}:\n got  {}\n want {}",
            expect_shape(composed),
            want
        );
    }
}
