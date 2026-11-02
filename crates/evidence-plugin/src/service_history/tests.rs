use std::path::Path;

use ed25519_dalek::SigningKey;
use evidence_request::jcs;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::*;
use crate::evidence_answer::{self, Outcome, Responder};
use crate::evidence_request_parity::{
    announced_keys, checkpoints_cut_at, served, write_jsonl, CorpusCheckpoint, NODE_KEY_SEED,
    RESPONDER_NODE,
};
use crate::requester_auth::{Keys, ReplayCache};

const NOW: &str = "2026-01-27T00:00:00Z";

/// Mondays, 00:00 UTC: the policy's boundaries.
const WEEK_1: &str = "2026-01-12T00:00:00Z";
const WEEK_2: &str = "2026-01-19T00:00:00Z";
const WEEK_3: &str = "2026-01-26T00:00:00Z";

fn key() -> SigningKey {
    SigningKey::from_bytes(&NODE_KEY_SEED)
}

fn digest_of_document(text: &str) -> String {
    let document: Value = serde_json::from_str(text).unwrap();
    hex::encode(Sha256::digest(
        jcs::to_string(&document).unwrap().as_bytes(),
    ))
}

fn definition() -> Value {
    serde_json::from_str(DEFINITION_DOCUMENT).unwrap()
}

#[test]
fn the_digests_are_those_of_the_definition_file() {
    assert_eq!(digest_of_document(DEFINITION_DOCUMENT), DEFINITION_DIGEST);
    let d = definition();
    assert_eq!(
        hex::encode(Sha256::digest(
            jcs::to_string(&d["period_policy"]).unwrap().as_bytes()
        )),
        POLICY_DIGEST
    );
}

/// ISH §4.1's frame for the Standard level, with the values Steven ruled
/// (evidencebook#46, 2026-10-22), and no other member.
#[test]
fn the_definition_carries_the_standard_frame_and_nothing_else() {
    let d = definition();
    let mut keys: Vec<&str> = d.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "coverage_declaration",
            "embeds",
            "excludes",
            "kind",
            "level",
            "members",
            "name",
            "period_policy",
            "profile",
            "reads",
            "spec",
            "subjects",
        ]
    );
    assert_eq!(d["profile"], json!("inference-service-history/0"));
    assert_eq!(d["name"], json!("service_history/1"));
    assert_eq!(d["kind"], json!("projection"));
    assert_eq!(d["level"], json!("standard"));
    assert_eq!(d["embeds"], json!(["history_card/1"]));
    assert_eq!(d["subjects"], json!(["full_history"]));
    assert_eq!(
        d["coverage_declaration"],
        json!({"kind": "stream_interval", "rule": "all_records"})
    );
    assert_eq!(
        d["period_policy"],
        json!({"epoch": "2026-01-05T00:00:00Z", "length_s": 604800, "min_length_s": 86400,
               "floor": 5, "suppression": "complementary"})
    );
    assert_eq!(
        d["spec"],
        json!("https://github.com/Mesh-LLM/capsules-plugin/blob/main/docs/SERVICE-HISTORY.md")
    );
    assert!(d["excludes"]
        .as_array()
        .unwrap()
        .contains(&json!("requester identity")));
    // The members, in order, each required, the counts in one unit.
    let members = d["members"].as_array().unwrap();
    let names: Vec<&str> = members
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["history_card", "period_counts"]);
    assert!(members.iter().all(|m| m["required"] == json!(true)));
    assert_eq!(members[0]["derivation"], json!("history_card/1"));
    assert_eq!(
        members[1]["units"],
        json!([{"where": "periods[].cells[]", "unit": "exchanges_served"}])
    );
    // `reads` is the ordered union of the members', and reads no latency
    // and no requester-identity field.
    let mut union: Vec<&Value> = Vec::new();
    for read in members.iter().flat_map(|m| m["reads"].as_array().unwrap()) {
        if !union.contains(&read) {
            union.push(read);
        }
    }
    assert_eq!(
        d["reads"].as_array().unwrap().iter().collect::<Vec<_>>(),
        union
    );
    let reads = d["reads"].to_string();
    for field in [
        "latency",
        "requesting_party",
        "counterparty_ref",
        "initiator_ref",
    ] {
        assert!(!reads.contains(field), "{field}");
    }
}

#[test]
fn boundaries_are_the_mondays_from_the_epoch() {
    assert!(is_boundary("2026-01-05T00:00:00Z"));
    assert!(is_boundary(WEEK_1));
    assert!(is_boundary("2025-12-29T00:00:00Z"));
    assert!(!is_boundary("2026-01-12T00:01:00Z"));
    assert!(!is_boundary("2026-01-13T00:00:00Z"));
    assert!(!is_boundary("2026-01-12T00:00:00.5Z"));
    assert!(!is_boundary("not a time"));
}

/// A model per leaf, from a list.
fn models<'a>(list: &'a [Option<&'a str>]) -> impl Fn(u64) -> Option<String> + 'a {
    move |i| list.get(i as usize).copied().flatten().map(str::to_string)
}

fn cuts<'a>(list: &[(&'a str, u64)]) -> Vec<Cut<'a>> {
    list.iter()
        .map(|&(timestamp, leaves)| Cut { timestamp, leaves })
        .collect()
}

fn cell(model: Option<&str>, value: Result<u64, &str>) -> Value {
    let mut c = json!({
        "dimension": model.map(|m| json!({"model": m})),
        "label": "self_reported",
        "unit": "exchanges_served",
        "value": value.ok(),
    });
    if let Err(why) = value {
        c["suppressed"] = json!(why);
    }
    c
}

/// ISH §9.1's day two, by the week: a's 9 and b's 3 under a total of 12.
#[test]
fn a_model_a_published_total_gives_away_is_withheld_with_it() {
    let mut list = vec![Some("a"); 9];
    list.extend([Some("b"); 3]);
    let counts = period_counts(
        &cuts(&[("2026-01-06T09:00:00Z", 12), (WEEK_1, 12)]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(
        counts["periods"][0]["cells"],
        json!([
            cell(Some("a"), Err("complementary")),
            cell(Some("b"), Err("below_floor")),
            cell(None, Ok(12)),
        ])
    );
}

#[test]
fn every_closed_period_is_counted_in_order_and_the_open_one_never() {
    // Week 0 (from the epoch): 6 a and 5 b. Week 1: 7 a, committed by the
    // checkpoint that closes it. Week 2: none.
    let mut list = vec![Some("a"); 6];
    list.extend([Some("b"); 5]);
    list.push(None); // not a served exchange
    list.extend([Some("a"); 7]);
    let counts = period_counts(
        &cuts(&[("2026-01-07T12:00:00Z", 12), (WEEK_2, 19), (WEEK_3, 19)]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(counts["policy"], json!(POLICY_DIGEST));
    assert_eq!(
        counts["periods"],
        json!([
            {"from": "2026-01-05T00:00:00Z", "to": WEEK_1, "cells": [
                cell(Some("a"), Ok(6)), cell(Some("b"), Ok(5)), cell(None, Ok(11))]},
            {"from": WEEK_1, "to": WEEK_2, "cells": [cell(Some("a"), Ok(7)), cell(None, Ok(7))]},
            {"from": WEEK_2, "to": WEEK_3, "cells": [cell(None, Err("below_floor"))]},
        ])
    );
    // At the week-2 anchor, week 2 is open and not listed.
    let earlier = period_counts(
        &cuts(&[("2026-01-07T12:00:00Z", 12), (WEEK_2, 19)]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(earlier["periods"].as_array().unwrap().len(), 2);
    // ... and the weeks both list are the same cells (ISH §6.1 item 4).
    assert_eq!(
        earlier["periods"].as_array().unwrap()[..],
        counts["periods"].as_array().unwrap()[..2]
    );
}

#[test]
fn a_checkpoint_time_that_goes_back_never_adds_to_a_closed_period() {
    let list = vec![Some("a"); 12];
    let at_week_1 = period_counts(
        &cuts(&[("2026-01-07T00:00:00Z", 6), (WEEK_1, 6)]),
        &models(&list),
    )
    .unwrap();
    let later = period_counts(
        &cuts(&[
            ("2026-01-07T00:00:00Z", 6),
            (WEEK_1, 6),
            ("2026-01-08T00:00:00Z", 12),
            (WEEK_2, 12),
        ]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(at_week_1["periods"][0], later["periods"][0]);
    assert_eq!(later["periods"][1]["cells"][1], cell(None, Ok(6)));
}

#[test]
fn an_anchor_off_a_boundary_is_declined() {
    for anchor in ["2026-01-12T00:01:00Z", "2026-01-13T00:00:00Z", "garbage"] {
        assert_eq!(
            period_counts(&cuts(&[(anchor, 1)]), &models(&[])),
            Err(Reason::PolicyDeclined),
            "{anchor}"
        );
    }
}

/// A stream whose first checkpoint is at a boundary: that checkpoint closes
/// the period before it, and its records are in it.
#[test]
fn a_first_checkpoint_at_a_boundary_closes_the_period_before_it() {
    let counts = period_counts(&cuts(&[(WEEK_1, 3)]), &models(&[Some("a"); 3])).unwrap();
    assert_eq!(
        counts["periods"],
        json!([{"from": "2026-01-05T00:00:00Z", "to": WEEK_1, "cells": [
            cell(Some("a"), Err("below_floor")), cell(None, Err("below_floor"))]}])
    );
}

/// A second checkpoint at the same boundary (a push cut in the same
/// minute) commits into the period that boundary opens, never the one the
/// first closed.
#[test]
fn a_second_checkpoint_at_a_boundary_never_reopens_the_period_closed() {
    let list = vec![Some("a"); 12];
    let first = period_counts(
        &cuts(&[("2026-01-07T00:00:00Z", 2), (WEEK_1, 6)]),
        &models(&list),
    )
    .unwrap();
    let both = period_counts(
        &cuts(&[("2026-01-07T00:00:00Z", 2), (WEEK_1, 6), (WEEK_1, 12)]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(first, both);
    assert_eq!(first["periods"][0]["cells"][1], cell(None, Ok(6)));
}

// ---------------------------------------------------------------------
// Through this node's answer and a requester's check
// ---------------------------------------------------------------------

/// 30 lines: 9 of model a and 3 of b in week 0, then 6 of a and 12 of b in
/// week 1; checkpoints inside week 0, at week 1's start, inside week 1, at
/// week 2's start and inside week 2.
fn ledger() -> Vec<Value> {
    let mut ledger = Vec::new();
    for (model, n) in [("a", 9), ("b", 3), ("a", 6), ("b", 12)] {
        for i in 0..n {
            ledger.push(served(
                "node-a",
                model,
                "confirmed",
                "10.000",
                json!({ "nonce": format!("{model}-{}-{i}", ledger.len()) }),
            ));
        }
    }
    ledger
}

fn checkpoints() -> Vec<CorpusCheckpoint> {
    checkpoints_cut_at(
        &ledger(),
        &key(),
        &[
            (6, "2026-01-07T10:00:00Z"),
            (12, WEEK_1),
            (20, "2026-01-14T08:00:00Z"),
            (30, WEEK_2),
        ],
    )
}

fn node() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write_jsonl(&dir.path().join("capsules.jsonl"), &ledger());
    let lines: Vec<Value> = checkpoints().iter().map(CorpusCheckpoint::line).collect();
    write_jsonl(&dir.path().join("checkpoints.jsonl"), &lines);
    dir
}

fn ask(dir: &Path, request: &Value) -> Outcome {
    let key = key();
    let announced = announced_keys();
    evidence_answer::answer(
        &serde_json::to_vec(request).unwrap(),
        &Responder {
            ledger_dir: dir,
            signing_key: &key,
            now: NOW,
            history_segments: "counterparties",
            share_standard_history: true,
            share_exchange_corroboration: false,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &ReplayCache::default(),
            node_id: Some(RESPONDER_NODE),
            policy_digest: None,
        },
    )
}

fn history_request(pin: &str) -> Value {
    json!({"subject": {"full_history": null}, "coverage": {"expected_pin": pin},
           "derivation": DEFINITION_DIGEST})
}

fn answered(outcome: Outcome) -> Value {
    match outcome {
        Outcome::Answered { wire, .. } => wire,
        other => panic!("not answered: {other:?}"),
    }
}

fn artifact_of(wire: &Value) -> Map<String, Value> {
    use evidence_request::envelope::{parse_reply, Binding, Reply};
    let Ok(Reply::Envelope(env)) = parse_reply(&serde_json::to_vec(wire).unwrap(), Binding::Json)
    else {
        panic!("not an envelope: {wire}");
    };
    serde_json::from_slice(&env.artifact).unwrap()
}

fn verified(request: &Value, wire: &Value) -> Value {
    evidence_answer::verify_response(
        &serde_json::to_vec(request).unwrap(),
        wire,
        &key().verifying_key(),
        &Default::default(),
    )
}

#[test]
fn a_history_at_a_boundary_is_answered_and_checks() {
    let dir = node();
    let anchor = checkpoints()[3].anchor();
    let request = history_request(&anchor);
    let wire = answered(ask(dir.path(), &request));
    let art = artifact_of(&wire);
    assert_eq!(art["anchor"], json!(anchor));
    assert_eq!(art["derivation"], json!(DEFINITION_DIGEST));
    assert_eq!(art["declared"], json!(["history_card", "period_counts"]));
    assert_eq!(
        art["coverage_declaration"]["live_set"],
        json!([{"checkpoint": anchor, "count": 30, "start": 0, "stream": "corpus-node-log"}])
    );
    // Week 0: 9 a and 3 b, the first two checkpoints. Week 1: 6 a and 12 b.
    assert_eq!(
        art["period_counts"]["periods"],
        json!([
            {"from": "2026-01-05T00:00:00Z", "to": WEEK_1, "cells": [
                cell(Some("a"), Err("complementary")),
                cell(Some("b"), Err("below_floor")),
                cell(None, Ok(12))]},
            {"from": WEEK_1, "to": WEEK_2, "cells": [
                cell(Some("a"), Ok(6)), cell(Some("b"), Ok(12)), cell(None, Ok(18))]},
        ])
    );
    // No verification material (ISH §8.1); the card's receipts ride beside.
    assert!(wire.get("verification").is_none() && wire.get("verification_content").is_none());
    assert_eq!(wire["witness_receipts"].as_array().unwrap().len(), 3);

    let v = verified(&request, &wire);
    assert_eq!(v["state"], json!("artifact"), "{v}");
    assert_eq!(v["checkpoints"], json!(4));
    let lines: Vec<&str> = v["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert!(lines.contains(
        &"2026-01-12T00:00:00Z to 2026-01-19T00:00:00Z: exchanges served, model b (as the provider states it): 12 (self_reported)"
    ));
    // The corpus's receipts are stubs: none counted, none read as a witness.
    assert!(lines.contains(&"witness receipts counted: 0 of 3"));
    assert!(lines.contains(&"3 not counted: a placeholder the witness never registered"));
    let text = lines.join("\n").to_lowercase();
    assert!(!text.contains("detectable"));
    for word in DENY_LIST {
        assert!(!text.contains(word), "{word}");
    }
}

/// A History asked under `evidence-interop/1` is answered under /1 (ISH
/// "Interop profile revision", IP §3.3): the same artifact, an envelope
/// naming /1, and a requester's check of it passes.
#[test]
fn a_history_asked_under_v1_is_answered_under_v1() {
    let dir = node();
    let anchor = checkpoints()[3].anchor();
    let v0 = answered(ask(dir.path(), &history_request(&anchor)));
    let mut request = history_request(&anchor);
    request["profile"] = json!("evidence-interop/1");
    let v1 = answered(ask(dir.path(), &request));
    assert_eq!(v1["profile"], json!("evidence-interop/1"));
    assert_eq!(v0["profile"], json!("evidence-interop/0"));
    assert_eq!(artifact_of(&v1), artifact_of(&v0));
    let v = verified(&request, &v1);
    assert_eq!(v["state"], json!("artifact"), "{v}");
    // An answer under the other identifier is not the answer asked for.
    assert_ne!(verified(&request, &v0)["state"], json!("artifact"));
}

/// The embedded card is byte for byte the direct `history_card/1` artifact
/// at the same anchor, and `history_card_digest` its SHA-256.
#[test]
fn the_embedded_card_is_the_direct_card() {
    let dir = node();
    let anchor = checkpoints()[3].anchor();
    let art = artifact_of(&answered(ask(dir.path(), &history_request(&anchor))));
    let card = artifact_of(&answered(ask(
        dir.path(),
        &json!({"subject": {"full_history": null}, "coverage": {"expected_pin": anchor},
                "derivation": "history_card/1"}),
    )));
    let direct = jcs::to_string(&Value::Object(card)).unwrap();
    assert_eq!(jcs::to_string(&art["history_card"]).unwrap(), direct);
    assert_eq!(
        art["history_card_digest"],
        json!(hex::encode(Sha256::digest(direct.as_bytes())))
    );
}

/// Every refusal ISH §8.4 gives a Standard History: the same token, signed,
/// for every requester.
#[test]
fn every_case_the_definition_refuses_is_policy_declined() {
    let dir = node();
    let cps = checkpoints();
    let mut range = history_request(&cps[3].anchor());
    range["subject"] = json!({"range": [0, 5]});
    let mut fresh = history_request(&cps[3].anchor());
    fresh["coverage"] = json!({"min_freshness": 1});
    for request in [
        history_request(&cps[2].anchor()), // inside week 1
        history_request(&cps[0].anchor()), // inside week 0
        range,
        fresh,
    ] {
        for asker in [None, Some("node-z")] {
            let mut request = request.clone();
            if let Some(asker) = asker {
                request["requester_id"] = json!(asker);
            }
            match ask(dir.path(), &request) {
                Outcome::Refused { reason, .. } => {
                    assert_eq!(reason, Reason::PolicyDeclined, "{request}")
                }
                other => panic!("{request}: {other:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------
// What a requester rejects, one rule at a time
// ---------------------------------------------------------------------

/// The answered artifact at week 2, and the card's checkpoint times.
fn checked_parts() -> (Map<String, Value>, Vec<(String, u64)>, String) {
    let dir = node();
    let anchor = checkpoints()[3].anchor();
    let art = artifact_of(&answered(ask(dir.path(), &history_request(&anchor))));
    let times = checkpoints()
        .iter()
        .map(|c| {
            (
                c.record.timestamp.clone(),
                cll::mmr::leaf_count(c.record.mmr_size).unwrap(),
            )
        })
        .collect();
    (art, times, anchor)
}

fn check(
    art: &Map<String, Value>,
    times: &[(String, u64)],
    anchor: &str,
) -> Result<Counts, String> {
    let chain: Vec<Cut<'_>> = times
        .iter()
        .map(|(timestamp, leaves)| Cut {
            timestamp,
            leaves: *leaves,
        })
        .collect();
    check_artifact(Definition::active(), art, &chain, anchor, "corpus-node-log")
}

#[test]
fn the_answered_artifact_checks() {
    let (art, times, anchor) = checked_parts();
    let counts = check(&art, &times, &anchor).unwrap();
    assert_eq!(counts.periods.len(), 2);
    assert_eq!(
        counts.periods[1].cells[1],
        Cell {
            model: Some("b".into()),
            value: Ok(12)
        }
    );
}

/// The periods of a History artifact.
fn periods(a: &mut Map<String, Value>) -> &mut Vec<Value> {
    a.get_mut("period_counts").unwrap()["periods"]
        .as_array_mut()
        .unwrap()
}

/// One change to a History artifact.
type Tamper = Box<dyn Fn(&mut Map<String, Value>)>;

#[test]
fn a_tampered_history_does_not_check() {
    let (art, times, anchor) = checked_parts();
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "a closed period dropped",
            Box::new(|a| {
                periods(a).remove(0);
            }),
        ),
        (
            "the last closed period dropped",
            Box::new(|a| {
                periods(a).pop();
            }),
        ),
        ("no period listed", Box::new(|a| periods(a).clear())),
        (
            "a period twice",
            Box::new(|a| {
                let p = periods(a)[1].clone();
                periods(a).push(p);
            }),
        ),
        (
            "the open period counted",
            Box::new(|a| {
                periods(a).push(json!({"from": WEEK_2, "to": WEEK_3, "cells": [cell(None, Err("below_floor"))]}));
            }),
        ),
        (
            "a start in another time form",
            Box::new(|a| {
                periods(a)[0]["from"] = json!("2026-01-05T00:00:00+00:00");
            }),
        ),
        (
            "a cell below the floor published",
            Box::new(|a| {
                periods(a)[0]["cells"][1] = cell(Some("b"), Ok(3));
            }),
        ),
        (
            "the complementary cell published",
            Box::new(|a| {
                periods(a)[0]["cells"][0] = cell(Some("a"), Ok(9));
            }),
        ),
        (
            "a cell twice",
            Box::new(|a| {
                let c = periods(a)[1]["cells"][0].clone();
                periods(a)[1]["cells"].as_array_mut().unwrap().insert(0, c);
            }),
        ),
        (
            "two totals",
            Box::new(|a| {
                periods(a)[1]["cells"]
                    .as_array_mut()
                    .unwrap()
                    .push(cell(None, Err("below_floor")));
            }),
        ),
        (
            "models that do not add up",
            Box::new(|a| {
                periods(a)[1]["cells"][2] = cell(None, Ok(19));
            }),
        ),
        (
            "a sum past u64",
            Box::new(|a| {
                periods(a)[1]["cells"][0] = cell(Some("a"), Ok(u64::MAX));
            }),
        ),
        (
            "a count labelled peer_confirmed",
            Box::new(|a| {
                periods(a)[1]["cells"][2]["label"] = json!("peer_confirmed");
            }),
        ),
        (
            "served and requested counted together",
            Box::new(|a| {
                periods(a)[1]["cells"][2]["unit"] = json!("exchanges");
            }),
        ),
        (
            "another policy",
            Box::new(|a| {
                a.get_mut("period_counts").unwrap()["policy"] = json!("00".repeat(32));
            }),
        ),
        (
            "a wrong live-set count",
            Box::new(|a| {
                a.get_mut("coverage_declaration").unwrap()["live_set"][0]["count"] = json!(29);
            }),
        ),
        (
            "an interval that starts later",
            Box::new(|a| {
                a.get_mut("coverage_declaration").unwrap()["interval"]["from"] =
                    json!("00".repeat(32));
            }),
        ),
        (
            "the card for another subject",
            Box::new(|a| {
                a.get_mut("history_card").unwrap()["subject"] = json!({"checkpoints": null});
            }),
        ),
        (
            "a member the definition does not list",
            Box::new(|a| {
                a.insert("served_summary".into(), json!({}));
            }),
        ),
        (
            "a member dropped",
            Box::new(|a| {
                a.remove("period_counts");
            }),
        ),
    ];
    for (name, change) in cases {
        let mut tampered = art.clone();
        change(&mut tampered);
        // Keep the card digest true to the card, so the change itself is
        // what fails.
        let card = jcs::to_string(&tampered["history_card"]).unwrap();
        tampered.insert(
            "history_card_digest".into(),
            json!(hex::encode(Sha256::digest(card.as_bytes()))),
        );
        assert!(check(&tampered, &times, &anchor).is_err(), "{name}");
    }
}

#[test]
fn an_anchor_off_a_boundary_does_not_check() {
    let (art, mut times, anchor) = checked_parts();
    times.last_mut().unwrap().0 = "2026-01-19T00:01:00Z".into();
    let why = check(&art, &times, &anchor).unwrap_err();
    assert!(why.starts_with("period_anchor"), "{why}");
}

#[test]
fn a_card_digest_that_is_not_the_card_does_not_check() {
    let (mut art, times, anchor) = checked_parts();
    art.insert("history_card_digest".into(), json!("00".repeat(32)));
    assert!(check(&art, &times, &anchor).is_err());
}

/// An answer re-signed by the node over `request`, with `artifact` and
/// `verification`, as a requester would receive it.
fn resigned(
    request: &Value,
    artifact: &Map<String, Value>,
    verification: Vec<(String, Vec<u8>)>,
) -> Value {
    use evidence_request::envelope::{self, Anchor, Binding, EnvelopeParts};
    let bytes = serde_json::to_vec(request).unwrap();
    let req = evidence_request::request::parse_json(&bytes).unwrap();
    let env = envelope::sign(
        &bytes,
        EnvelopeParts {
            subject: req.subject,
            derivation: req.derivation,
            anchor: Anchor {
                digest: artifact["anchor"].as_str().unwrap().to_string(),
                freshness: None,
            },
            artifact: jcs::to_string(&Value::Object(artifact.clone()))
                .unwrap()
                .into_bytes(),
            verification,
            issued_at: NOW.into(),
        },
        &key(),
    )
    .unwrap();
    serde_json::from_slice(&env.encode(Binding::Json)).unwrap()
}

#[test]
fn an_answer_with_material_or_without_a_pin_is_not_evidence() {
    let (art, _, anchor) = checked_parts();
    let request = history_request(&anchor);
    // The same artifact, re-signed with no change, checks.
    let same = verified(&request, &resigned(&request, &art, Vec::new()));
    assert_eq!(same["state"], json!("artifact"), "{same}");
    let material = vec![(
        "cll-checkpoint".to_string(),
        checkpoints()[3].statement.clone(),
    )];
    let v = verified(&request, &resigned(&request, &art, material));
    assert_eq!(v["state"], json!("not_evidence"), "{v}");
    let mut fresh = request.clone();
    fresh["coverage"] = json!({"min_freshness": 1});
    let v = verified(&fresh, &resigned(&fresh, &art, Vec::new()));
    assert_eq!(v["state"], json!("not_evidence"), "{v}");
}

/// Two models withheld and one published above the total: not the
/// complementary rule, the sum.
#[test]
fn a_published_model_above_the_total_does_not_check() {
    let (mut art, times, anchor) = checked_parts();
    periods(&mut art)[1]["cells"] = json!([
        cell(Some("a"), Err("below_floor")),
        cell(Some("b"), Err("below_floor")),
        cell(Some("c"), Ok(20)),
        cell(None, Ok(12)),
    ]);
    let why = check(&art, &times, &anchor).unwrap_err();
    assert!(why.contains("do not add up"), "{why}");
}

/// A node whose ledger has `extra` more lines than [`ledger`] and whose
/// checkpoints are cut at `cuts`.
fn node_cut(extra: usize, cuts: &[(usize, &str)]) -> tempfile::TempDir {
    let mut ledger = ledger();
    for i in 0..extra {
        ledger.push(served(
            "node-a",
            "a",
            "confirmed",
            "10.000",
            json!({ "nonce": format!("late-{i}") }),
        ));
    }
    let dir = tempfile::tempdir().unwrap();
    write_jsonl(&dir.path().join("capsules.jsonl"), &ledger);
    let lines: Vec<Value> = checkpoints_cut_at(&ledger, &key(), cuts)
        .iter()
        .map(CorpusCheckpoint::line)
        .collect();
    write_jsonl(&dir.path().join("checkpoints.jsonl"), &lines);
    dir
}

/// What the History page is given, for a node whose switch is `share`.
fn page_given(dir: &Path, share: bool) -> Value {
    let key = key();
    let announced = announced_keys();
    let replay = ReplayCache::default();
    crate::history_page::serve(&Responder {
        ledger_dir: dir,
        signing_key: &key,
        now: NOW,
        history_segments: "counterparties",
        share_standard_history: share,
        share_exchange_corroboration: false,
        keys: Keys {
            announced: &announced,
            configured: None,
            own_key: None,
        },
        replay: &replay,
        node_id: Some(RESPONDER_NODE),
        policy_digest: None,
    })
    .unwrap()
}

fn reply_of(page: &Value) -> Value {
    serde_json::from_str(page["reply"].as_str().unwrap()).unwrap()
}

/// The card by default, the Service History once `share_standard_history`
/// is on and a boundary checkpoint exists.
#[test]
fn the_history_page_is_given_the_form_the_policy_shares() {
    let dir = node();
    let off = page_given(dir.path(), false);
    assert_eq!(off["form"], "history_card/1");
    assert_eq!(off["outcome"], "answered");
    let on = page_given(dir.path(), true);
    assert_eq!(on["form"], "service_history/1");
    assert_eq!(on["outcome"], "answered");
    assert_eq!(reply_of(&on)["responder"], on["node_key_id"]);
}

/// The Service History is pinned to the latest boundary checkpoint, not to
/// the head: a node whose head is cut after the boundary still gives it.
#[test]
fn the_service_history_is_pinned_to_the_latest_boundary_not_the_head() {
    let cuts = [
        (6, "2026-01-07T10:00:00Z"),
        (12, WEEK_1),
        (20, "2026-01-14T08:00:00Z"),
        (30, WEEK_2),
        (34, "2026-01-20T08:00:00Z"),
    ];
    let dir = node_cut(4, &cuts);
    let boundary = checkpoints_cut_at(
        &{
            let mut l = ledger();
            for i in 0..4 {
                l.push(served(
                    "node-a",
                    "a",
                    "confirmed",
                    "10.000",
                    json!({ "nonce": format!("late-{i}") }),
                ));
            }
            l
        },
        &key(),
        &cuts,
    )[3]
    .anchor();
    let page = page_given(dir.path(), true);
    assert_eq!(page["form"], "service_history/1");
    assert_eq!(page["outcome"], "answered");
    assert_eq!(reply_of(&page)["anchor"]["digest"], boundary);
}

/// With the switch on but no checkpoint at a boundary, the page holds the
/// card, and says so.
#[test]
fn without_a_boundary_checkpoint_the_page_holds_the_card() {
    let dir = node_cut(
        0,
        &[(6, "2026-01-07T10:00:00Z"), (20, "2026-01-14T08:00:00Z")],
    );
    let page = page_given(dir.path(), true);
    assert_eq!(page["form"], "history_card/1");
    assert_eq!(page["outcome"], "answered");
}

/// The Service History reply the History page's tests open
/// (`tests/fixtures/service_history_reply.json`), regenerated here: the node
/// is deterministic (fixed key, ledger and clock), so a drift in the wire
/// shape fails this test. `UPDATE_FIXTURES=1 cargo test` rewrites it.
#[test]
fn the_service_history_reply_fixture_is_what_the_node_serves() {
    let dir = node();
    let key = key();
    let anchor = checkpoints().last().unwrap().anchor();
    let served = answered(ask(dir.path(), &history_request(&anchor)));
    let text = format!("{}\n", serde_json::to_string(&served).unwrap());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/service_history_reply.json");
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    assert_eq!(
        served["responder"],
        hex::encode(key.verifying_key().as_bytes())
    );
}
