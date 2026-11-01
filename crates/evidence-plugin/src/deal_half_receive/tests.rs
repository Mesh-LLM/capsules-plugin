use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use super::*;

/// Two final halves of one deal from the Goose loop reference's scripted run
/// (`vectors/SOURCES.md`).
const BUYER: &str = include_str!("../../../../vectors/goose-deal-half/buyer-final-half.json");
const SELLER: &str = include_str!("../../../../vectors/goose-deal-half/seller-final-half.json");
/// The buyer's first half: one step.
const BUYER_FIRST: &str = include_str!("../../../../vectors/goose-deal-half/buyer-half.json");
/// `BUYER_FIRST` re-sealed with a serving claim (`vectors/SOURCES.md`).
const SERVED_CLAIM: &str =
    include_str!("../../../../vectors/goose-deal-half/served-claim-half.json");

/// `SELLER` in the new form: its close step also cites the buyer's checkpoint
/// (`vectors/SOURCES.md`).
const NEW_FORM: &str =
    include_str!("../../../../vectors/goose-deal-half/counterparty-cite-half.json");

/// `SELLER` with its baseline also citing an admission record, as Goose
/// halves sealed after evidencebook#307 do (`vectors/SOURCES.md`).
const ADMISSION_CITE: &str =
    include_str!("../../../../vectors/goose-deal-half/admission-cite-half.json");

const NOW: &str = "2026-11-01T00:00:00Z";

fn half(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn signing_key_of(half: &Value) -> String {
    half["steps"][0]["capsule"]["key_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn checkpoint_key_of(half: &Value) -> String {
    half["checkpoint"]["key_id"].as_str().unwrap().to_string()
}

/// The operator's map admitting `half`'s node as `name`.
fn admitting(name: &str, half: &Value) -> String {
    json!({
        name: signing_key_of(half),
        format!("{name}/checkpoint"): checkpoint_key_of(half),
    })
    .to_string()
}

fn own() -> String {
    hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())
}

fn check(text: &[u8], configured: &str) -> Result<Verified, Refused> {
    let own = own();
    verify(
        text,
        &Keys {
            configured: Some(configured),
            own_key: &own,
            accept_current_form: true,
        },
        NOW,
    )
}

fn refusal(text: &[u8], configured: &str) -> Refused {
    check(text, configured).expect_err("refused")
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn both_halves_of_a_goose_deal_verify_under_the_admitted_keys() {
    for (name, text) in [("goose-buyer", BUYER), ("goose-seller", SELLER)] {
        let h = half(text);
        let verified = check(text.as_bytes(), &admitting(name, &h)).expect(name);
        assert_eq!(verified.deal_id, h["deal_id"]);
        assert_eq!(verified.book_id, h["book_id"]);
        assert_eq!(verified.peer, name);
        assert_eq!(verified.key_id, signing_key_of(&h));
        assert_eq!(verified.checkpoint_key_id, checkpoint_key_of(&h));
        assert_eq!(
            verified.capsules.len(),
            h["steps"].as_array().unwrap().len()
        );
        assert_eq!(
            verified.accepted.via,
            crate::peer_keys::AcceptedVia::OperatorStopgap
        );
    }
    // Both halves are of the same deal, under different keys.
    let (b, s) = (half(BUYER), half(SELLER));
    assert_eq!(b["deal_id"], s["deal_id"]);
    assert_ne!(signing_key_of(&b), signing_key_of(&s));
}

#[test]
fn a_key_this_node_does_not_accept_is_refused_before_any_record_is_read() {
    let s = half(SELLER);
    // The buyer's keys admitted, the seller's half handed in.
    let r = refusal(SELLER.as_bytes(), &admitting("goose-buyer", &half(BUYER)));
    assert_eq!((r.reason, r.step), (REASON_SIGNATURE_UNVERIFIED, None));
    assert!(r.detail.contains(&signing_key_of(&s)), "{}", r.detail);
    // No map at all.
    let own = own();
    let r = verify(
        SELLER.as_bytes(),
        &Keys {
            configured: None,
            own_key: &own,
            accept_current_form: true,
        },
        NOW,
    )
    .unwrap_err();
    assert_eq!(r.reason, REASON_SIGNATURE_UNVERIFIED);
}

#[test]
fn this_nodes_own_key_is_never_a_counterparty() {
    let s = half(SELLER);
    let r = verify(
        SELLER.as_bytes(),
        &Keys {
            configured: Some(&admitting("goose-seller", &s)),
            own_key: &signing_key_of(&s),
            accept_current_form: true,
        },
        NOW,
    )
    .unwrap_err();
    assert_eq!(r.reason, REASON_SIGNATURE_UNVERIFIED);
}

#[test]
fn the_checkpoint_key_must_be_admitted_for_the_same_peer() {
    let s = half(SELLER);
    // No checkpoint entry.
    let only_signing = json!({"goose-seller": signing_key_of(&s)}).to_string();
    let r = refusal(SELLER.as_bytes(), &only_signing);
    assert_eq!(r.reason, REASON_CHECKPOINT_UNVERIFIED);
    // The checkpoint key admitted under another peer's name.
    let elsewhere = json!({
        "goose-seller": signing_key_of(&s),
        "someone-else/checkpoint": checkpoint_key_of(&s),
    })
    .to_string();
    assert_eq!(
        refusal(SELLER.as_bytes(), &elsewhere).reason,
        REASON_CHECKPOINT_UNVERIFIED
    );
    // A different checkpoint key admitted for this peer.
    let other = json!({
        "goose-seller": signing_key_of(&s),
        "goose-seller/checkpoint": checkpoint_key_of(&half(BUYER)),
    })
    .to_string();
    assert_eq!(
        refusal(SELLER.as_bytes(), &other).reason,
        REASON_CHECKPOINT_UNVERIFIED
    );
    // The half naming a checkpoint key the operator admitted does not help
    // when the statement is signed by another key.
    let mut swapped = s.clone();
    swapped["checkpoint"]["statement"] = half(BUYER)["checkpoint"]["statement"].clone();
    let r = refusal(&bytes(&swapped), &admitting("goose-seller", &s));
    assert_eq!(r.reason, REASON_CHECKPOINT_UNVERIFIED);
    assert!(r.detail.contains("not signed by"), "{}", r.detail);
}

#[test]
fn a_changed_payload_is_refused_at_its_step() {
    let s = half(SELLER);
    let mut tampered = s.clone();
    let payload = &mut tampered["steps"][2]["payload"];
    let record = payload.as_object_mut().unwrap();
    let (key, _) = record
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
        .unwrap();
    record.insert(format!("{key}-x"), json!("added"));
    let r = refusal(&bytes(&tampered), &admitting("goose-seller", &s));
    assert_eq!((r.reason, r.step), (REASON_RECORD_UNVERIFIED, Some(3)));
}

#[test]
fn a_changed_capsule_fails_its_signature_or_class_1() {
    let s = half(SELLER);
    let mut tampered = s.clone();
    tampered["steps"][1]["capsule"]["timestamp"] = json!("2020-01-01T00:00:00Z");
    let r = refusal(&bytes(&tampered), &admitting("goose-seller", &s));
    assert_eq!((r.reason, r.step), (REASON_SIGNATURE_UNVERIFIED, Some(2)));
}

#[test]
fn a_dropped_last_step_is_not_what_the_checkpoint_commits() {
    let s = half(SELLER);
    let mut short = s.clone();
    short["steps"].as_array_mut().unwrap().pop();
    let r = refusal(&bytes(&short), &admitting("goose-seller", &s));
    assert_eq!(r.reason, REASON_CHECKPOINT_UNVERIFIED);
    assert!(r.detail.contains("exactly"), "{}", r.detail);
}

#[test]
fn a_dropped_or_reordered_middle_step_is_refused_where_the_deal_breaks() {
    let s = half(SELLER);
    let mut gap = s.clone();
    gap["steps"].as_array_mut().unwrap().remove(1);
    let r = refusal(&bytes(&gap), &admitting("goose-seller", &s));
    assert_eq!((r.reason, r.step), (REASON_RECORD_UNVERIFIED, Some(2)));

    let mut swapped = s.clone();
    swapped["steps"].as_array_mut().unwrap().swap(0, 1);
    let r = refusal(&bytes(&swapped), &admitting("goose-seller", &s));
    assert_eq!((r.reason, r.step), (REASON_RECORD_UNVERIFIED, Some(1)));
}

#[test]
fn a_half_of_another_deal_id_is_refused() {
    let s = half(SELLER);
    let mut other = s.clone();
    other["deal_id"] = json!("deal-0000000000000000");
    let r = refusal(&bytes(&other), &admitting("goose-seller", &s));
    assert_eq!((r.reason, r.step), (REASON_RECORD_UNVERIFIED, Some(1)));
}

#[test]
fn malformed_halves_are_refused_before_any_key_is_looked_up() {
    let s = half(SELLER);
    let keys = admitting("goose-seller", &s);
    let mut extra = s.clone();
    extra["note"] = json!("unsigned");
    let mut wrong_format = s.clone();
    wrong_format["half"] = json!("goose-deal-half/2");
    let mut no_steps = s.clone();
    no_steps["steps"] = json!([]);
    let mut step_extra = s.clone();
    step_extra["steps"][0]["more"] = json!(1);
    let mut checkpoint_extra = s.clone();
    checkpoint_extra["checkpoint"]["size"] = json!(1);
    let mut not_hex = s.clone();
    not_hex["checkpoint"]["statement"] = json!("zz");
    for (case, body) in [
        ("extra member", bytes(&extra)),
        ("format", bytes(&wrong_format)),
        ("no steps", bytes(&no_steps)),
        ("checkpoint member", bytes(&checkpoint_extra)),
        ("statement", bytes(&not_hex)),
        ("not json", b"{".to_vec()),
        (
            "duplicate member",
            br#"{"half":"goose-deal-half/1","half":"goose-deal-half/1"}"#.to_vec(),
        ),
    ] {
        assert_eq!(
            refusal(&body, &keys).reason,
            REASON_REQUEST_MALFORMED,
            "{case}"
        );
    }
    let r = refusal(&bytes(&step_extra), &keys);
    assert_eq!((r.reason, r.step), (REASON_REQUEST_MALFORMED, Some(1)));
}

#[test]
fn too_many_steps_are_refused_unread() {
    let s = half(SELLER);
    let mut many = s.clone();
    let step = s["steps"][0].clone();
    many["steps"] = Value::Array(vec![step; MAX_STEPS + 1]);
    assert_eq!(
        refusal(&bytes(&many), &admitting("goose-seller", &s)).reason,
        REASON_REQUEST_MALFORMED
    );
}

/// This node's own chain, oldest first (the shelf, `chain_store`).
fn chain(dir: &std::path::Path) -> Vec<Value> {
    crate::chain_store::chain_string(dir)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn lines(dir: &std::path::Path, name: &str) -> Vec<Value> {
    std::fs::read_to_string(dir.join(name))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn a_refused_half_keeps_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let s = half(SELLER);
    let mut short = s.clone();
    short["steps"].as_array_mut().unwrap().pop();
    let outcome = receive_half(
        dir.path(),
        &key,
        Some(&admitting("goose-seller", &s)),
        &bytes(&short),
        NOW,
    )
    .unwrap();
    assert!(outcome.is_err());
    assert!(
        std::fs::read_dir(dir.path()).unwrap().next().is_none(),
        "nothing written"
    );
}

#[tokio::test]
async fn a_verified_half_is_held_and_cited_once_however_often_it_is_handed_in() {
    let dir = tempfile::tempdir().unwrap();
    let capsules = Arc::new(
        crate::capsule_emit::CapsuleState::open(dir.path(), "node-under-test").expect("open"),
    );
    let s = half(SELLER);
    let ids: Vec<Value> = s["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step["capsule"]["capsule_id"].clone())
        .collect();
    let configured = Some(admitting("goose-seller", &s));

    let first = receive_and_cite(capsules.clone(), configured.clone(), SELLER.into())
        .await
        .unwrap();
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(first["steps"], ids.len());
    assert_eq!(first["received_from"], "goose-seller");
    assert_eq!(first["chain_stage"], "not_checked");

    let again = receive_and_cite(capsules.clone(), configured, SELLER.into())
        .await
        .unwrap();
    assert_eq!(again["ok"], true, "{again}");

    let ledger = capsules.ledger_dir();
    let held: Vec<Value> = lines(ledger, receive::RECEIVED_CAPSULES_FILENAME)
        .iter()
        .map(|c| c["capsule_id"].clone())
        .collect();
    assert_eq!(held, ids, "every step held once, in order");
    let provenance = lines(ledger, receive::RECEIVED_PROVENANCE_FILENAME);
    assert!(provenance
        .iter()
        .all(|p| p["via"] == VIA && p["received_from"] == "goose-seller"));
    let halves = lines(ledger, RECEIVED_DEAL_HALVES_FILENAME);
    assert_eq!(halves.len(), 1, "{halves:?}");
    assert_eq!(halves[0]["deal_id"], s["deal_id"]);
    assert_eq!(halves[0]["statement"], s["checkpoint"]["statement"]);
    assert_eq!(halves[0]["step_capsule_ids"], Value::Array(ids.clone()));
    assert_eq!(halves[0]["checkpoint_key_id"], checkpoint_key_of(&s));

    let cited: Vec<Value> = chain(ledger)
        .into_iter()
        .filter_map(|r| {
            r.pointer("/model_attestation/compute_attestation/received_half")
                .cloned()
        })
        .collect();
    assert_eq!(
        cited.len(),
        ids.len(),
        "one citing record per step: {cited:?}"
    );
    for (citing, id) in cited.iter().zip(&ids) {
        assert_eq!(&citing["cited_capsule_id"], id);
        assert_eq!(citing["via"], VIA);
    }
}

#[tokio::test]
async fn a_refusal_is_a_reply_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let capsules = Arc::new(
        crate::capsule_emit::CapsuleState::open(dir.path(), "node-under-test").expect("open"),
    );
    let reply = receive_and_cite(capsules, None, SELLER.into())
        .await
        .unwrap();
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["reason"], REASON_SIGNATURE_UNVERIFIED);
}

#[test]
fn a_one_step_half_verifies() {
    let h = half(BUYER_FIRST);
    assert_eq!(h["steps"].as_array().unwrap().len(), 1);
    let verified = check(BUYER_FIRST.as_bytes(), &admitting("goose-buyer", &h)).expect("one step");
    assert_eq!(verified.capsules.len(), 1);
}

#[test]
fn a_book_id_the_steps_do_not_sign_is_refused() {
    let s = half(SELLER);
    let mut other = s.clone();
    other["book_id"] = json!("deal/deal-0000000000000000");
    let r = refusal(&bytes(&other), &admitting("goose-seller", &s));
    assert_eq!((r.reason, r.step), (REASON_RECORD_UNVERIFIED, Some(1)));
}

#[test]
fn a_key_only_a_host_announced_is_not_a_goose_nodes_key() {
    // `verify` reads the operator's map alone: with the signing key known
    // only to the host registry, the half is refused. (`handle` passes the
    // map alone; the host snapshot never reaches this module.)
    let s = half(SELLER);
    crate::peer_keys::announced::announce_for_test("host-peer-goose", &signing_key_of(&s));
    let checkpoint_only = json!({"host-peer-goose/checkpoint": checkpoint_key_of(&s)}).to_string();
    let r = refusal(SELLER.as_bytes(), &checkpoint_only);
    assert_eq!(r.reason, REASON_SIGNATURE_UNVERIFIED);
}

#[test]
fn a_step_the_record_push_store_would_not_take_as_a_record_is_refused() {
    let s = half(SELLER);
    let keys = admitting("goose-seller", &s);
    for member in [
        receive::BUNDLE_MARKER,
        crate::referee::hold::DELIVERY_MARKER,
    ] {
        let mut marked = s.clone();
        marked["steps"][1]["capsule"][member] = json!(1);
        let r = refusal(&bytes(&marked), &keys);
        assert_eq!(
            (r.reason, r.step),
            (REASON_RECORD_UNVERIFIED, Some(2)),
            "{member}"
        );
    }
}

#[test]
fn a_serving_claim_the_store_refuses_is_refused_whole_before_anything_is_stored() {
    let h = half(SERVED_CLAIM);
    let keys = admitting("goose-buyer", &h);
    // Every deal check accepts it: the claim is the only problem.
    check(SERVED_CLAIM.as_bytes(), &keys).expect("the deal checks pass");
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let r = receive_half(dir.path(), &key, Some(&keys), SERVED_CLAIM.as_bytes(), NOW)
        .unwrap()
        .expect_err("refused");
    assert_eq!((r.reason, r.step), (REASON_RECORD_UNVERIFIED, Some(1)));
    assert!(
        r.detail.contains(receive::REASON_SERVED_BY_MISMATCH),
        "{}",
        r.detail
    );
    assert!(
        std::fs::read_dir(dir.path()).unwrap().next().is_none(),
        "nothing written"
    );
}

#[tokio::test]
async fn a_half_held_but_not_yet_cited_is_cited_when_handed_in_again() {
    let dir = tempfile::tempdir().unwrap();
    let capsules = Arc::new(
        crate::capsule_emit::CapsuleState::open(dir.path(), "node-under-test").expect("open"),
    );
    let s = half(SELLER);
    let keys = admitting("goose-seller", &s);
    // As if the citing seals failed after the steps were held.
    receive_half(
        capsules.ledger_dir(),
        capsules.signing_key(),
        Some(&keys),
        SELLER.as_bytes(),
        NOW,
    )
    .unwrap()
    .expect("held");
    let cited = |capsules: &crate::capsule_emit::CapsuleState| {
        chain(capsules.ledger_dir())
            .into_iter()
            .filter(|r| {
                r.pointer("/model_attestation/compute_attestation/received_half")
                    .is_some()
            })
            .count()
    };
    assert_eq!(cited(&capsules), 0);
    let reply = receive_and_cite(capsules.clone(), Some(keys), SELLER.into())
        .await
        .unwrap();
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(cited(&capsules), s["steps"].as_array().unwrap().len());
    assert_eq!(
        lines(capsules.ledger_dir(), RECEIVED_DEAL_HALVES_FILENAME).len(),
        1
    );
}

#[test]
fn during_the_overlap_window_both_forms_verify() {
    let current = half(SELLER);
    let verified =
        check(SELLER.as_bytes(), &admitting("goose-seller", &current)).expect("current form");
    assert_eq!(verified.form, FORM_CURRENT);
    assert!(verified.counterparty_checkpoint_cites.is_empty());

    let new = half(NEW_FORM);
    let verified = check(NEW_FORM.as_bytes(), &admitting("goose-seller", &new)).expect("new form");
    assert_eq!(verified.form, FORM_CITES_COUNTERPARTY_CHECKPOINT);
    let links = new["steps"].as_array().unwrap().last().unwrap()["capsule"]
        ["evidence_record_header"]["links"]
        .clone();
    assert_eq!(
        verified.counterparty_checkpoint_cites,
        vec![links[1]["target"].as_str().unwrap().to_string()]
    );
}

#[test]
fn once_the_window_closes_only_the_new_form_verifies() {
    let own = own();
    let closed = |text: &str| {
        let h = half(text);
        verify(
            text.as_bytes(),
            &Keys {
                configured: Some(&admitting("goose-seller", &h)),
                own_key: &own,
                accept_current_form: false,
            },
            NOW,
        )
    };
    let r = closed(SELLER).expect_err("current form refused");
    assert_eq!((r.reason, r.step), (REASON_RECORD_UNVERIFIED, None));
    assert_eq!(
        closed(NEW_FORM).expect("new form").form,
        FORM_CITES_COUNTERPARTY_CHECKPOINT
    );
}

#[tokio::test]
async fn the_form_is_held_and_replied() {
    let dir = tempfile::tempdir().unwrap();
    let capsules = Arc::new(
        crate::capsule_emit::CapsuleState::open(dir.path(), "node-under-test").expect("open"),
    );
    let new = half(NEW_FORM);
    let reply = receive_and_cite(
        capsules.clone(),
        Some(admitting("goose-seller", &new)),
        NEW_FORM.into(),
    )
    .await
    .unwrap();
    assert_eq!(reply["form"], FORM_CITES_COUNTERPARTY_CHECKPOINT, "{reply}");
    assert_eq!(
        reply["counterparty_checkpoint_cites"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let held = lines(capsules.ledger_dir(), RECEIVED_DEAL_HALVES_FILENAME);
    assert_eq!(held[0]["form"], FORM_CITES_COUNTERPARTY_CHECKPOINT);
    assert_eq!(
        held[0]["counterparty_checkpoint_cites"],
        reply["counterparty_checkpoint_cites"]
    );
}

#[test]
fn a_step_header_cites_by_its_place_in_the_deal() {
    let (parent, other, more) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
    let cites = |links: Value, role| step_cites(&json!({"links": links}), Some(&parent), role);
    let only_parent = json!([{"target": parent, "type": "cites"}]);
    let with_other =
        json!([{"target": parent, "type": "cites"}, {"target": other, "type": "cites"}]);
    for role in [StepRole::Other, StepRole::Close] {
        assert_eq!(cites(only_parent.clone(), role), Ok(vec![]), "{role:?}");
    }
    // A close step's extra cites are the counterparty's checkpoint.
    assert_eq!(
        cites(with_other.clone(), StepRole::Close),
        Ok(vec![other.clone()])
    );
    // Any other step cites its parent alone.
    assert!(cites(with_other, StepRole::Other).is_err());
    // The baseline has no parent; one more cite is its admission
    // (evidencebook#307), no checkpoint, and two are too many.
    let baseline = |links: Value| step_cites(&json!({"links": links}), None, StepRole::Baseline);
    assert_eq!(baseline(json!([])), Ok(vec![]));
    assert_eq!(
        baseline(json!([{"target": other, "type": "cites"}])),
        Ok(vec![])
    );
    assert!(baseline(
        json!([{"target": other, "type": "cites"}, {"target": more, "type": "cites"}])
    )
    .is_err());
    for bad in [
        json!([{"target": other, "type": "cites"}]),
        json!([]),
        json!([{"target": parent, "type": "follows"}]),
        json!([{"target": parent, "type": "cites", "note": 1}]),
        json!([{"target": "not-hex", "type": "cites"}]),
        json!([{"target": parent, "type": "cites"}, {"target": parent, "type": "cites"}]),
        json!("not a list"),
    ] {
        assert!(cites(bad.clone(), StepRole::Close).is_err(), "{bad}");
    }
}

#[test]
fn a_baseline_citing_its_admission_is_the_current_form() {
    let h = half(ADMISSION_CITE);
    let verified =
        check(ADMISSION_CITE.as_bytes(), &admitting("goose-seller", &h)).expect("verifies");
    assert_eq!(verified.form, FORM_CURRENT);
    assert!(verified.counterparty_checkpoint_cites.is_empty());
}

#[test]
fn a_cite_of_the_halfs_own_step_is_not_a_counterparty_checkpoint() {
    // `step_cites` cannot know the half's ids; `verify` checks the collected
    // cites against them with `own_step_cite`.
    let s = half(SELLER);
    let first = s["steps"][0]["capsule"].clone();
    let id = first["capsule_id"].as_str().unwrap().to_string();
    assert_eq!(
        own_step_cite(std::slice::from_ref(&id), std::slice::from_ref(&first)),
        Some(id.as_str())
    );
    assert_eq!(own_step_cite(&["c".repeat(64)], &[first]), None);
}
