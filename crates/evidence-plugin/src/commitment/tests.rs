use super::*;
use crate::evidence_request_parity::{corpus_ledger_dir, NODE_KEY_SEED};
use crate::requester_auth::{Keys, ReplayCache};
use std::collections::BTreeMap;

const NOW: &str = "2026-10-28T00:00:00Z";
pub(crate) const NODE: &str = "16a607c33006dd4243cb2347c4bdbaa5129a590b5257eea62ac5047abcf87864";

fn key() -> SigningKey {
    SigningKey::from_bytes(&NODE_KEY_SEED)
}

pub(crate) fn defaults() -> Policy {
    Policy::from_settings(|_| None)
}

/// A commitment over the parity corpus, signed by its node, under `policy`.
pub(crate) fn built(policy: &Policy) -> Signed {
    let dir = tempfile::tempdir().unwrap();
    let key = key();
    corpus_ledger_dir(dir.path(), &key);
    let digest = policy.digest(&key);
    let announced = BTreeMap::new();
    let replay = ReplayCache::default();
    let responder = Responder {
        ledger_dir: dir.path(),
        signing_key: &key,
        now: NOW,
        history_segments: policy.history_segments,
        share_standard_history: policy.share_standard_history,
        share_exchange_corroboration: policy.share_exchange_corroboration,
        keys: Keys {
            announced: &announced,
            configured: None,
            own_key: None,
        },
        replay: &replay,
        node_id: Some(NODE),
        policy_digest: Some(&digest),
    };
    build(&responder, NODE, policy, None).unwrap()
}

/// `signed` with `edit` applied to its commitment, signed again.
fn resigned(signed: &Signed, edit: impl FnOnce(&mut Value)) -> Signed {
    let mut doc = signed.commitment.clone();
    edit(&mut doc);
    Signed {
        commitment: sign(doc, &key()),
        policy: signed.policy.clone(),
    }
}

/// `signed` with `edit` applied to its stapled card, carried and signed
/// again: only the staple's own checks can refuse it.
fn restapled(signed: &Signed, edit: impl FnOnce(&mut Value)) -> Signed {
    resigned(signed, |d| {
        let mut card: Value = serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(d["history_card"]["bytes"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        edit(&mut card);
        let raw = serde_json::to_vec(&card).unwrap();
        d["history_card"]["bytes"] = json!(base64::engine::general_purpose::STANDARD.encode(&raw));
        d["history_card"]["sha256"] = json!(hex::encode(Sha256::digest(&raw)));
    })
}

#[test]
fn the_default_settings_give_exactly_the_pinned_policy_file() {
    let pinned: Value = serde_json::from_str(DEFAULT_POLICY).unwrap();
    assert_eq!(defaults().body(), pinned);
    // The file is the body as the plugin would print it, so it can be read
    // as the documentation of the default.
    assert_eq!(
        DEFAULT_POLICY,
        format!("{}\n", serde_json::to_string_pretty(&pinned).unwrap())
    );
}

#[test]
fn every_switch_changes_the_policy_and_its_digest() {
    let key = key();
    let default_digest = defaults().digest(&key);
    for (env, value) in [
        (share_policy::ENV_RECORD_AT_COMPLETION, "off"),
        (share_policy::ENV_HISTORY_SEGMENTS, "peers"),
        (share_policy::ENV_HISTORY_SEGMENTS, "off"),
        (share_policy::ENV_STANDARD_HISTORY, "on"),
        (share_policy::ENV_EXCHANGE_CORROBORATION, "on"),
        (share_policy::ENV_ADVERTISE_EVIDENCE_REQUESTS, "on"),
        (share_policy::ENV_ADJUDICATIONS, "deliver_to_subjects"),
    ] {
        let policy = Policy::from_settings(|e| (e == env).then(|| value.to_string()));
        assert_ne!(policy, defaults(), "{env}={value}");
        assert_ne!(policy.digest(&key), default_digest, "{env}={value}");
    }
}

#[test]
fn a_value_the_plugin_does_not_know_is_stated_as_it_is_read() {
    // An unknown `share_history_segments` is read as off, and the policy
    // says off, never the value the operator typed.
    let policy = Policy::from_settings(|e| {
        (e == share_policy::ENV_HISTORY_SEGMENTS).then(|| "everyone".to_string())
    });
    assert_eq!(policy.body()["share_history_segments"], "off");
}

#[test]
fn the_digest_is_of_the_signed_policy_file_and_does_not_change_between_signings() {
    let key = key();
    let policy = defaults();
    let bytes = policy.signed_bytes(&key);
    assert_eq!(bytes, policy.signed_bytes(&key));
    assert_eq!(policy.digest(&key), hex::encode(Sha256::digest(&bytes)));
    let doc: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["profile"], POLICY_PROFILE);
    assert_eq!(doc["key_id"], key_id(&key));
    assert_eq!(doc["policy"], policy.body());
    assert!(signature_verifies(&doc, &key.verifying_key()));
}

#[test]
fn the_answers_lists_are_pinned_and_follow_the_settings() {
    assert_eq!(
        *DERIVATIONS,
        [
            "checkpoints",
            "history_card/1",
            crate::exchange_corroboration::DEFINITION_DIGEST,
            crate::service_history::DEFINITION_DIGEST,
        ]
    );
    assert_eq!(
        defaults().subjects(),
        [
            "checkpoints",
            "full_history",
            "record",
            "exchange",
            "correlation"
        ]
    );
    let off = Policy::from_settings(|e| {
        (e == share_policy::ENV_HISTORY_SEGMENTS).then(|| "off".to_string())
    });
    assert_eq!(off.subjects(), ["checkpoints", "full_history"]);
    let signed = built(&off);
    assert_eq!(
        signed.commitment["answers"]["subjects"],
        json!(["checkpoints", "full_history"])
    );
    assert_eq!(
        signed.commitment["answers"]["derivations"],
        json!(*DERIVATIONS)
    );
}

#[test]
fn a_built_commitment_has_exactly_the_members_and_verifies() {
    let signed = built(&defaults());
    let doc = &signed.commitment;
    assert_eq!(verify(&signed), Vec::<String>::new());
    let mut members: Vec<&str> = doc
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    let mut schema: Vec<&str> = SCHEMA.iter().map(|(n, _)| *n).collect();
    schema.sort_unstable();
    assert_eq!(members, schema);
    assert_eq!(doc["node_id"], NODE);
    assert_eq!(doc["key_id"], key_id(&key()));
    assert_eq!(doc["issued_at"], NOW);
    assert_eq!(doc["ask"]["endpoint"], format!("mesh:{NODE}"));
    assert_eq!(doc["lcap"]["policy_uri"], format!("policies/{NODE}.json"));
    assert_eq!(doc["lcap"]["policy_digest"], defaults().digest(&key()));
    assert_eq!(doc["human_gated"], false);
    assert_eq!(doc["answers_within"], ANSWERS_WITHIN);
}

/// The controller binding is named by its digest alone, only when given,
/// and any other shape of the member is refused (loop's `OPTIONAL`).
#[test]
fn a_controller_binding_is_named_by_its_digest_alone() {
    let digest = "ab".repeat(32);
    let signed = resigned(&built(&defaults()), |d| {
        d[CONTROLLER_BINDING] = json!({ "digest": digest })
    });
    assert_eq!(verify(&signed), Vec::<String>::new());
    assert!(built(&defaults())
        .commitment
        .get(CONTROLLER_BINDING)
        .is_none());
    for (value, says) in [
        (
            json!({"digest": "AB".repeat(32)}),
            "controller_binding.digest is not a sha256",
        ),
        (json!({}), "missing controller_binding.digest"),
        (
            json!({"digest": digest, "keys": [digest]}),
            "unknown field controller_binding.keys",
        ),
        (json!(digest), "controller_binding has the wrong type"),
    ] {
        let bad = resigned(&built(&defaults()), |d| {
            d[CONTROLLER_BINDING] = value.clone()
        });
        let problems = verify(&bad);
        assert!(
            problems.iter().any(|p| p.contains(says)),
            "{says}: {problems:?}"
        );
    }
}

#[test]
fn the_checkpoint_is_the_latest_and_the_staple_is_what_a_stranger_gets() {
    let dir = tempfile::tempdir().unwrap();
    let cps = corpus_ledger_dir(dir.path(), &key());
    let signed = built(&defaults());
    let raw = |member: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(signed.commitment[member]["bytes"].as_str().unwrap())
            .unwrap()
    };
    // A checkpoint's anchor digest is the SHA-256 of its statement.
    let latest = cps.last().unwrap().anchor();
    assert_eq!(hex::encode(Sha256::digest(raw("checkpoint"))), latest);
    let staple: Value = serde_json::from_slice(&raw("history_card")).unwrap();
    assert_eq!(staple["profile"], STAPLE_PROFILE);
    assert_eq!(staple["derivation"], "history_card/1");
    assert_eq!(staple["responder"], key_id(&key()));
    assert_eq!(staple["anchor"]["digest"], latest);
}

#[test]
fn no_checkpoint_means_no_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let key = key();
    let announced = BTreeMap::new();
    let replay = ReplayCache::default();
    let policy = defaults();
    let responder = Responder {
        ledger_dir: dir.path(),
        signing_key: &key,
        now: NOW,
        history_segments: policy.history_segments,
        share_standard_history: false,
        share_exchange_corroboration: false,
        keys: Keys {
            announced: &announced,
            configured: None,
            own_key: None,
        },
        replay: &replay,
        node_id: Some(NODE),
        policy_digest: None,
    };
    let err = build(&responder, NODE, &policy, None).unwrap_err();
    assert!(err.why.contains("no checkpoint"), "{err:?}");
    assert!(!err.lasting);
}

#[test]
fn the_wire_form_round_trips_the_policy_bytes_exactly() {
    let signed = built(&defaults());
    assert_eq!(Signed::from_wire(&signed.to_wire()).unwrap(), signed);
}

#[test]
fn each_tampering_is_refused() {
    let signed = built(&defaults());
    let cases: Vec<(&str, Signed)> = vec![
        ("a member changed after signing", {
            let mut s = signed.clone();
            s.commitment["human_gated"] = json!(true);
            s
        }),
        (
            "an unknown member",
            resigned(&signed, |d| d["extra"] = json!("x")),
        ),
        (
            "a missing member",
            resigned(&signed, |d| {
                d.as_object_mut().unwrap().remove("answers_within");
            }),
        ),
        (
            "a count",
            resigned(&signed, |d| d["ask"]["bindings"] = json!(["12"])),
        ),
        (
            "a key named as a count",
            resigned(&signed, |d| {
                d["lcap"]["predicate_classes"] = json!({"answerCount": "x"})
            }),
        ),
        (
            "another node's policy",
            Signed {
                commitment: signed.commitment.clone(),
                policy: Policy::from_settings(|e| {
                    (e == share_policy::ENV_STANDARD_HISTORY).then(|| "on".to_string())
                })
                .signed_bytes(&key()),
            },
        ),
        ("a policy signed by another key", {
            let other = SigningKey::from_bytes(&[9; 32]);
            let mut doc: Value = serde_json::from_slice(&signed.policy).unwrap();
            doc = sign(doc, &other);
            let policy = jcs(&doc).into_bytes();
            resigned(
                &Signed {
                    commitment: signed.commitment.clone(),
                    policy: policy.clone(),
                },
                |d| d["lcap"]["policy_digest"] = json!(hex::encode(Sha256::digest(&policy))),
            )
        }),
        (
            "checkpoint bytes not their digest",
            resigned(&signed, |d| {
                d["checkpoint"]["sha256"] = json!("0".repeat(63) + "a")
            }),
        ),
        (
            "a staple presented by another",
            restapled(&signed, |card| card["responder"] = json!("ab".repeat(32))),
        ),
        (
            "a staple with no artifact and no artifact_digest",
            restapled(&signed, |card| {
                let card = card.as_object_mut().unwrap();
                card.remove("artifact");
                card.remove("artifact_digest");
            }),
        ),
        (
            "a staple whose artifact is not base64url",
            restapled(&signed, |card| card["artifact"] = json!("!!")),
        ),
        (
            "a staple whose artifact_digest is not a string",
            restapled(&signed, |card| card["artifact_digest"] = json!(null)),
        ),
        (
            "a key_id that is not spki",
            resigned(&signed, |d| d["key_id"] = json!("ab".repeat(32))),
        ),
        (
            "a duration that is not one",
            resigned(&signed, |d| d["answers_within"] = json!("PT")),
        ),
        (
            "a predicate class with no source",
            resigned(&signed, |d| {
                d["lcap"]["predicate_classes"] = json!(["performed"])
            }),
        ),
    ];
    for (name, case) in cases {
        assert!(!verify(&case).is_empty(), "{name} must be refused");
    }
}

#[test]
fn the_count_rule_splits_names_as_loop_does() {
    assert_eq!(tokens("answerCount"), ["answer", "count"]);
    assert_eq!(
        tokens("history_card.size-n"),
        ["history", "card", "size", "n"]
    );
    assert!(count_problems(&json!({"a": 3}), &mut Vec::new()).len() == 1);
    assert!(count_problems(&json!({"a": "3a"}), &mut Vec::new()).is_empty());
    // The opaque bytes are not scanned.
    assert!(count_problems(&json!({"checkpoint": {"bytes": "123"}}), &mut Vec::new()).is_empty());
}

#[test]
fn durations_and_classes_read_as_loop_reads_them() {
    for ok in ["PT1M", "P1D", "PT24H", "P1DT2H", "PT1H30M5S"] {
        assert!(is_duration(ok), "{ok}");
    }
    for bad in ["", "P", "PT", "P1DT", "1M", "PT1M1H", "PTM", "P1H"] {
        assert!(!is_duration(bad), "{bad}");
    }
    assert!(is_predicate_class("performed:counterparty_half"));
    assert!(is_predicate_class("recorded:self_attested"));
    assert!(!is_predicate_class("Performed:x"));
    assert!(!is_predicate_class("performed:"));
}

#[test]
fn a_refusal_names_the_digest_of_the_policy_it_was_refused_under() {
    let dir = tempfile::tempdir().unwrap();
    let key = key();
    corpus_ledger_dir(dir.path(), &key);
    let policy = defaults();
    let digest = policy.digest(&key);
    let announced = BTreeMap::new();
    let replay = ReplayCache::default();
    let responder = Responder {
        ledger_dir: dir.path(),
        signing_key: &key,
        now: NOW,
        history_segments: policy.history_segments,
        share_standard_history: policy.share_standard_history,
        share_exchange_corroboration: policy.share_exchange_corroboration,
        keys: Keys {
            announced: &announced,
            configured: None,
            own_key: None,
        },
        replay: &replay,
        node_id: Some(NODE),
        policy_digest: Some(&digest),
    };
    let service_history = json!({
        "subject": {"full_history": null},
        "coverage": {"min_freshness": 1},
        "derivation": crate::service_history::definition_digest(),
    });
    let bytes = serde_json::to_vec(&service_history).unwrap();
    for outcome in [
        evidence_answer::answer(&bytes, &responder),
        evidence_answer::decline_busy(&bytes, &responder),
    ] {
        let Outcome::Refused { wire, .. } = outcome else {
            panic!("a stranger is refused service_history/1 by default");
        };
        assert_eq!(wire["policy_digest"], digest);
        // The member is beside the signed ones: the refusal still checks.
        let check = evidence_request::refusal::check(&wire);
        assert!(check.conformant, "{wire}");
    }
    let signed = built(&policy);
    assert_eq!(signed.commitment["lcap"]["policy_digest"], digest);
}

#[test]
fn a_commitment_larger_than_a_peer_reads_is_not_offered() {
    let mut signed = built(&defaults());
    assert!(fits(&signed).is_ok());
    signed.policy = vec![b' '; crate::mesh_evidence_bridge::MAX_SIDE_STREAM_BYTES as usize];
    let err = fits(&signed).unwrap_err();
    assert!(err.contains("larger than a peer reads"), "{err}");
}
