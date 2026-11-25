use super::*;

use sha2::{Digest, Sha256};

const ASKED_AT: &str = "2026-10-29T12:00:00Z";
const PEER: &str = "peer-asked";

fn state() -> (CapsuleState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let capsules = CapsuleState::open(dir.path(), "node-under-test").expect("open state");
    (capsules, dir)
}

fn request(deadline: Option<&str>) -> Value {
    let mut request = json!({
        "subject": {"full_history": null},
        "coverage": {"min_freshness": 1},
        "derivation": "history_card/1",
        "audience": PEER,
        "nonce": "n-1",
    });
    if let Some(deadline) = deadline {
        request["deadline"] = json!(deadline);
    }
    request
}

fn digest_of(request: &Value) -> String {
    hex::encode(Sha256::digest(
        evidence_request::jcs::to_string(request).unwrap(),
    ))
}

/// `answer` as the bytes a peer sent.
fn reply(answer: &Value) -> Vec<u8> {
    serde_json::to_vec(answer).unwrap()
}

/// The book's records, as `(record id, header)`, in ledger order.
fn records(capsules: &CapsuleState) -> Vec<(String, Map<String, Value>)> {
    AskBook::open(capsules, ASKED_AT).records
}

fn header_of(capsules: &CapsuleState, id: &str) -> Map<String, Value> {
    records(capsules)
        .into_iter()
        .find(|(rid, _)| rid == id)
        .expect("recorded")
        .1
}

fn cites(header: &Map<String, Value>) -> Vec<String> {
    header["links"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["type"] == "cites")
        .map(|l| l["target"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn the_ask_is_sealed_as_an_evidence_request_holding_the_request_sent() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();

    let header = header_of(&capsules, &asked.record_id);
    assert_eq!(header["record_type"], "evidence_request");
    assert_eq!(header["epistemic_type"], "observed_event");
    assert_eq!(header["committed_at"], ASKED_AT);
    assert_eq!(header["statement"]["request"], sent);
    assert_eq!(header["statement"]["responder_ref"], PEER);
    assert_eq!(
        capsules.chain_head().as_deref(),
        Some(asked.record_id.as_str())
    );
    assert_eq!(asked.window_closes, "2026-10-29T12:01:00Z");
}

#[test]
fn an_ask_record_never_leaves_this_node() {
    let (capsules, _dir) = state();
    let asked = record_request(&capsules, &request(None), PEER, None, ASKED_AT).unwrap();
    let record = capsules.lookup(&asked.record_id).unwrap().unwrap().capsule;
    assert!(is_ask_record(&record));
    let index = crate::evidence_log::with_index(capsules.ledger_dir(), "k", |index| {
        index
            .leaves
            .iter()
            .map(|l| l.never_leaves)
            .collect::<Vec<_>>()
    })
    .unwrap();
    assert_eq!(index, [true], "the request record is holder-only");
}

#[test]
fn the_window_closes_at_the_later_of_the_deadline_and_the_minimum() {
    assert_eq!(
        window_closes(None, ASKED_AT).as_deref(),
        Some("2026-10-29T12:01:00Z"),
        "never before the crate's 60 s minimum"
    );
    assert_eq!(
        window_closes(Some("2026-10-29T12:02:00Z"), ASKED_AT).as_deref(),
        Some("2026-10-29T12:02:00Z"),
        "never before the request's own deadline"
    );
    assert_eq!(
        window_closes(Some("2026-10-29T12:00:30Z"), ASKED_AT).as_deref(),
        Some("2026-10-29T12:01:00Z")
    );
    assert_eq!(
        window_closes(None, "2026-10-29T12:00:00.250Z").as_deref(),
        Some("2026-10-29T12:01:01Z"),
        "rounded up to a whole second"
    );
    assert_eq!(window_closes(Some("tomorrow"), ASKED_AT), None);
}

#[test]
fn a_request_the_book_could_not_resolve_is_never_recorded() {
    let (capsules, _dir) = state();
    let refused = |request: Value| {
        let result = record_request(&capsules, &request, PEER, None, ASKED_AT);
        assert!(
            matches!(result, Err(AskError::Invalid(_))),
            "{request}: {result:?}"
        );
    };
    refused(request(Some("tomorrow")));
    refused(json!({"subject": {"kind": "record", "capsule_id": "aa"}}));
    let mut bad_derivation = request(None);
    bad_derivation["derivation"] = json!("Foo");
    refused(bad_derivation);
    assert!(records(&capsules).is_empty(), "nothing sealed");
    assert_eq!(capsules.chain_head(), None);
}

#[test]
fn a_nonce_is_never_used_twice() {
    let (capsules, _dir) = state();
    record_request(&capsules, &request(None), PEER, None, ASKED_AT).unwrap();
    let again = record_request(&capsules, &request(None), PEER, None, ASKED_AT);
    assert!(matches!(again, Err(AskError::Invalid(_))), "{again:?}");
    let mut fresh = request(None);
    fresh["nonce"] = json!("n-2");
    record_request(&capsules, &fresh, PEER, None, ASKED_AT).unwrap();
    assert_eq!(records(&capsules).len(), 2);

    // An empty nonce is refused every time, nothing sealed: the crate reads
    // it as none, so a second such ask could not be told apart.
    for _ in 0..2 {
        let empty = record_request(
            &capsules,
            &with_nonce(request(None), ""),
            PEER,
            None,
            ASKED_AT,
        );
        assert!(
            matches!(&empty, Err(AskError::Invalid(m)) if m.contains("nonce is empty")),
            "{empty:?}"
        );
    }
    assert_eq!(records(&capsules).len(), 2);
}

#[test]
fn no_answer_by_the_close_is_a_recorded_absence_citing_the_request() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();

    let absence = record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        "2026-10-29T12:01:01Z",
    )
    .unwrap();
    let header = header_of(&capsules, &absence.record_id);
    assert_eq!(header["record_type"], "recorded_absence");
    assert_eq!(cites(&header), std::slice::from_ref(&asked.record_id));
    let statement = &header["statement"];
    assert_eq!(statement["outcome"], "recorded_absence");
    assert_eq!(statement["request_digest"], digest_of(&sent));
    assert_eq!(
        statement["window"],
        json!({"opened": ASKED_AT, "closed": "2026-10-29T12:01:00Z"})
    );
    assert_eq!(statement["recorded_at"], "2026-10-29T12:01:01Z");
}

#[test]
fn a_pending_request_is_never_recorded_as_absent() {
    let (capsules, _dir) = state();
    let asked = record_request(&capsules, &request(None), PEER, None, ASKED_AT).unwrap();
    let early = record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        "2026-10-29T12:00:30Z",
    );
    assert!(matches!(early, Err(AskError::Invalid(_))), "{early:?}");
    let short = record_absence(
        &capsules,
        &asked.record_id,
        "2026-10-29T12:00:10Z",
        "2026-10-29T12:05:00Z",
    );
    assert!(matches!(short, Err(AskError::Invalid(_))), "{short:?}");
    assert_eq!(records(&capsules).len(), 1, "nothing but the request");
}

#[test]
fn a_reply_in_the_window_is_the_response_and_forecloses_an_absence() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();
    let answer = json!({"artifact": "AAAA", "derivation": "history_card/1"});
    let verification = json!({"state": "artifact", "anchor": "a", "records": [], "checkpoints": 1});

    let response = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        &reply(&answer),
        &verification,
        "2026-10-29T12:00:02Z",
    )
    .unwrap();
    let header = header_of(&capsules, &response.0.record_id);
    assert_eq!(header["record_type"], "evidence_response");
    assert_eq!(cites(&header), std::slice::from_ref(&asked.record_id));
    assert_eq!(
        header["statement"],
        json!({
            "outcome": "artifact",
            "request_digest": digest_of(&sent),
            "response_digest": hex::encode(Sha256::digest(reply(&answer))),
            "verification": verification,
        })
    );

    let absence = record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        "2026-10-29T12:01:01Z",
    );
    assert!(matches!(absence, Err(AskError::Invalid(_))), "{absence:?}");
}

#[test]
fn a_late_reply_never_replaces_the_absence() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();
    record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        "2026-10-29T12:01:01Z",
    )
    .unwrap();

    let late = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        &reply(&json!({"reason": "policy_declined"})),
        &json!({"state": "refusal", "reason": "policy_declined"}),
        "2026-10-29T12:01:05Z",
    );
    assert!(matches!(late, Err(AskError::Invalid(_))), "{late:?}");
    assert!(
        !capsules.ledger_dir().join(REPLIES_DIR).exists(),
        "a refused reply is not kept"
    );
    let kinds: Vec<_> = records(&capsules)
        .into_iter()
        .map(|(_, h)| h["record_type"].clone())
        .collect();
    assert_eq!(kinds, ["evidence_request", "recorded_absence"]);
}

#[test]
fn a_response_cites_only_a_recorded_request() {
    let (capsules, _dir) = state();
    let late = record_response(
        &capsules,
        &"0".repeat(64),
        "d",
        &reply(&json!({})),
        &json!({"state": "artifact"}),
        ASKED_AT,
    );
    assert!(matches!(late, Err(AskError::NotFound(_))), "{late:?}");
}

#[test]
fn each_reply_is_recorded_as_what_it_is_never_as_an_absence() {
    let refusal = json!({"reason": "not_authorized", "sig": "s"});
    let artifact = json!({"artifact": "AAAA"});
    let state = |s: &str| json!({"state": s});
    assert_eq!(outcome(&artifact, &state("artifact")), "artifact");
    assert_eq!(outcome(&refusal, &state("refusal")), "refusal");
    assert_eq!(
        outcome(&refusal, &state("not_evidence")),
        "refusal_nonconformant"
    );
    assert_eq!(
        outcome(&artifact, &state("not_evidence")),
        "artifact_verification_failed"
    );
    assert_eq!(outcome(&refusal, &state("no_announced_key")), "refusal");
    assert_eq!(outcome(&artifact, &state("no_announced_key")), "artifact");
}

fn with_nonce(mut request: Value, nonce: &str) -> Value {
    request["nonce"] = json!(nonce);
    request
}

#[test]
fn at_start_the_absences_owed_are_sealed_once_and_open_windows_returned() {
    let (capsules, _dir) = state();
    let overdue = record_request(&capsules, &request(None), PEER, None, ASKED_AT).unwrap();
    let answered = record_request(
        &capsules,
        &with_nonce(request(None), "n-2"),
        PEER,
        None,
        ASKED_AT,
    )
    .unwrap();
    record_response(
        &capsules,
        &answered.record_id,
        "d",
        &reply(&json!({"artifact": "AAAA"})),
        &json!({"state": "artifact"}),
        "2026-10-29T12:00:01Z",
    )
    .unwrap();
    let still_open = record_request(
        &capsules,
        &with_nonce(request(Some("2026-10-29T12:10:00Z")), "n-3"),
        PEER,
        None,
        ASKED_AT,
    )
    .unwrap();

    let now = "2026-10-29T12:05:00Z";
    let (sealed, open) = resume_asks(&capsules, now);
    assert_eq!(sealed, 1);
    assert_eq!(
        open,
        std::slice::from_ref(&still_open),
        "the open window is the caller's to close"
    );
    assert_eq!(still_open.window_closes, "2026-10-29T12:10:00Z");
    let absences: Vec<_> = records(&capsules)
        .into_iter()
        .filter(|(_, h)| h["record_type"] == "recorded_absence")
        .map(|(_, h)| (cites(&h), h["statement"]["window"]["closed"].clone()))
        .collect();
    assert_eq!(
        absences,
        [(vec![overdue.record_id], json!("2026-10-29T12:01:00Z"))]
    );
    assert_eq!(resume_asks(&capsules, now).0, 0, "once");

    let (sealed, open) = resume_asks(&capsules, "2026-10-29T12:10:00Z");
    assert_eq!(
        (sealed, open.len()),
        (1, 0),
        "the third, once its deadline passed"
    );
    let last = records(&capsules).pop().expect("a record").1;
    assert_eq!(last["record_type"], "recorded_absence");
    assert_eq!(cites(&last), [still_open.record_id]);
}

#[test]
fn a_signed_refusal_is_checked_against_the_commitment_the_ask_recorded() {
    let (capsules, _dir) = state();
    let commitment = json!({
        "digest": "c".repeat(64),
        "policy_digest": "p".repeat(64),
        "policy": {"stranger_safe": ["checkpoints", "history_card/1"]},
        "subjects": ["checkpoints", "full_history"],
    });
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, Some(commitment.clone()), ASKED_AT).unwrap();
    assert_eq!(
        header_of(&capsules, &asked.record_id)["statement"]["commitment"],
        commitment
    );

    let (response, verification) = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        &reply(&json!({"reason": "no_such_subject"})),
        &json!({"state": "refusal", "reason": "no_such_subject"}),
        "2026-10-29T12:00:02Z",
    )
    .unwrap();
    assert_eq!(verification["policy_check"]["status"], "MISMATCH");
    let header = header_of(&capsules, &response.record_id);
    assert_eq!(header["statement"]["outcome"], "refusal");
    assert_eq!(header["statement"]["verification"], verification);
}

#[test]
fn the_ask_record_takes_the_books_shape_with_the_commitment_held() {
    let (capsules, _dir) = state();
    let commitment = json!({"digest": "c".repeat(64), "policy": {"stranger_safe": []}});
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, Some(commitment.clone()), ASKED_AT).unwrap();
    let statement = &header_of(&capsules, &asked.record_id)["statement"];
    assert_eq!(statement["request"], sent);
    assert_eq!(statement["responder_ref"], PEER);
    assert_eq!(statement["composed_elsewhere"], true);
    assert_eq!(statement["commitment"], commitment);

    // A commitment that is not a JSON object is refused, and nothing sealed.
    let before = records(&capsules).len();
    let refused = record_request(
        &capsules,
        &with_nonce(request(None), "n-2"),
        PEER,
        Some(json!(["not", "an", "object"])),
        ASKED_AT,
    );
    assert!(matches!(refused, Err(AskError::Invalid(_))), "{refused:?}");
    assert_eq!(records(&capsules).len(), before);
}

/// Request records sealed by this plugin before it called evidencebook's
/// `request_sent_with_commitment` (Mesh-LLM/capsules-plugin main at
/// 21923241, throwaway keys): no `composed_elsewhere`, and one with the
/// `commitment` held beside the request. Frozen bytes, never rebuilt here.
const OLD_SHAPE: &str = include_str!("../../../../vectors/ask-book/old-shape-request.json");
const OLD_SHAPE_HELD: &str =
    include_str!("../../../../vectors/ask-book/old-shape-request-with-commitment.json");

/// `line`'s record as the ledger checks it on read (capsule-emit's
/// `to_record`): its id recomputes, and its producer envelope verifies over
/// that id under the `key_id` it names. Returns the record's id and entry.
fn verified_old_record(line: &str) -> (String, Map<String, Value>) {
    let mut record: Map<String, Value> = serde_json::from_str(line).unwrap();
    let signature = record.remove("signature").unwrap();
    let key_id = record.remove("key_id").unwrap();
    let id = record["capsule_id"].as_str().unwrap().to_string();
    assert_eq!(
        agent_action_capsule::canonical::compute_capsule_id(&record).unwrap(),
        id
    );
    let envelope = hex::decode(signature.as_str().unwrap()).unwrap();
    let verified = agent_action_capsule::envelope::verify(&id, &envelope);
    assert!(verified.ok, "{:?}", verified.findings);
    assert_eq!(key_id, hex::encode(&verified.public_key));
    let entry = entry_block(&Value::Object(record)).unwrap().clone();
    (id, entry)
}

#[test]
fn requests_sealed_in_the_old_shape_still_verify_and_read() {
    // Each frozen record verifies as a ledger line. Its book entry, byte for
    // byte as frozen, is then sealed through this node's own ledger at its
    // own commit time, so the reader and the functions below take it from
    // the ledger as they take any record this book holds.
    let (capsules, _dir) = state();
    let mut ids = Vec::new();
    for line in [OLD_SHAPE, OLD_SHAPE_HELD] {
        let (_, frozen) = verified_old_record(line);
        assert_eq!(frozen["record_type"], "evidence_request");
        assert!(frozen["statement"].get("composed_elsewhere").is_none());
        let committed_at = frozen["committed_at"].as_str().unwrap();
        let sealed = AskBook::open(&capsules, committed_at)
            .seal(&Entry {
                record_type: record_types::REQUEST.into(),
                epistemic_type: EpistemicType::ObservedEvent,
                links: Vec::new(),
                statement: frozen["statement"].clone(),
            })
            .unwrap();
        assert_eq!(header_of(&capsules, &sealed.record_id), frozen);
        ids.push(sealed.record_id);
    }
    assert!(header_of(&capsules, &ids[1])["statement"]["commitment"].is_object());

    // Their nonces stay used: a new ask with either is refused, nothing sealed.
    for nonce in ["n-1", "n-2"] {
        let again = record_request(
            &capsules,
            &with_nonce(request(None), nonce),
            PEER,
            None,
            ASKED_AT,
        );
        assert!(
            matches!(&again, Err(AskError::Invalid(m)) if m.contains("nonce already used")),
            "{nonce}: {again:?}"
        );
    }
    assert_eq!(records(&capsules).len(), 2);

    // A refusal is judged against the commitment the old record holds.
    let held = header_of(&capsules, &ids[1])["statement"].clone();
    let (_, verification) = record_response(
        &capsules,
        &ids[1],
        &digest_of(&held["request"]),
        &reply(&json!({"reason": "no_such_subject"})),
        &json!({"state": "refusal", "reason": "no_such_subject"}),
        "2026-10-29T12:00:02Z",
    )
    .unwrap();
    assert_eq!(verification["policy_check"]["status"], "MISMATCH");

    // And a window closes into an absence citing the old record.
    let absent = record_absence(
        &capsules,
        &ids[0],
        "2026-10-29T12:05:00Z",
        "2026-10-29T12:10:00Z",
    );
    assert!(absent.is_ok(), "{absent:?}");
    assert_eq!(
        cites(&header_of(&capsules, &absent.unwrap().record_id)),
        vec![ids[0].clone()]
    );
}

#[test]
fn an_artifact_carries_no_policy_check() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();
    let (_, verification) = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        &reply(&json!({"artifact": "AAAA"})),
        &json!({"state": "artifact"}),
        "2026-10-29T12:00:02Z",
    )
    .unwrap();
    assert_eq!(verification, json!({"state": "artifact"}));
}

/// The reply as a peer sent it: not canonical JSON, so keeping it "as read"
/// is visible.
const SENT_REPLY: &[u8] = b"{ \"reason\" : \"policy_declined\",\n  \"sig\": \"s\" }";

fn answered(capsules: &CapsuleState) -> String {
    let sent = request(None);
    let asked = record_request(capsules, &sent, PEER, None, ASKED_AT).unwrap();
    record_response(
        capsules,
        &asked.record_id,
        &digest_of(&sent),
        SENT_REPLY,
        &json!({"state": "refusal", "reason": "policy_declined"}),
        "2026-10-29T12:00:02Z",
    )
    .unwrap()
    .0
    .record_id
}

#[test]
fn the_reply_is_kept_as_read_under_the_digest_its_response_seals() {
    let (capsules, _dir) = state();
    let response = answered(&capsules);
    let digest = hex::encode(Sha256::digest(SENT_REPLY));
    assert_eq!(
        header_of(&capsules, &response)["statement"]["response_digest"],
        json!(digest)
    );
    assert_eq!(
        std::fs::read(capsules.ledger_dir().join(REPLIES_DIR).join(&digest)).unwrap(),
        SENT_REPLY
    );
    assert_eq!(
        kept_reply(capsules.ledger_dir(), &response).unwrap(),
        SENT_REPLY
    );
    // The record that seals the digest is one of this book's, which never
    // leaves this node in an answer.
    let record = crate::evidence_panes::read_capsule_records(capsules.ledger_dir())
        .into_iter()
        .find(|r| r["capsule_id"] == json!(response))
        .unwrap();
    assert!(crate::evidence_log::never_leaves(&record));
}

#[test]
fn a_kept_reply_is_read_only_for_a_response_with_its_bytes_intact() {
    let (capsules, _dir) = state();
    let response = answered(&capsules);
    let ledger = capsules.ledger_dir();
    let kept = ledger
        .join(REPLIES_DIR)
        .join(hex::encode(Sha256::digest(SENT_REPLY)));

    let request_record = records(&capsules)[0].0.clone();
    let not_a_response = kept_reply(ledger, &request_record);
    assert!(
        matches!(&not_a_response, Err(AskError::NotFound(m)) if m.contains(&request_record)),
        "{not_a_response:?}"
    );

    std::fs::write(&kept, b"{}").unwrap();
    let altered = kept_reply(ledger, &response);
    assert!(
        matches!(&altered, Err(AskError::Corrupt(m)) if m.contains(&response)),
        "{altered:?}"
    );

    std::fs::remove_file(&kept).unwrap();
    let missing = kept_reply(ledger, &response);
    assert!(
        matches!(&missing, Err(AskError::Corrupt(m)) if m.contains(&response)),
        "{missing:?}"
    );
}

#[test]
fn a_response_sealed_before_replies_were_kept_is_refused_by_name() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();
    // The statement `record_response` sealed before it kept replies.
    let old = AskBook::open(&capsules, "2026-10-29T12:00:02Z")
        .seal(&Entry {
            record_type: record_types::RESPONSE.into(),
            epistemic_type: EpistemicType::ObservedEvent,
            links: vec![Link {
                link_type: LinkType::Cites,
                target: asked.record_id,
            }],
            statement: json!({
                "outcome": "refusal",
                "request_digest": digest_of(&sent),
                "verification": {"state": "refusal"},
            }),
        })
        .unwrap();
    let refused = kept_reply(capsules.ledger_dir(), &old.record_id);
    assert!(
        matches!(&refused, Err(AskError::Invalid(m)) if m.contains(&old.record_id)),
        "{refused:?}"
    );
}

#[test]
fn identical_replies_kept_at_once_are_kept_whole_once() {
    let dir = tempfile::tempdir().unwrap();
    let digest = hex::encode(Sha256::digest(SENT_REPLY));
    std::thread::scope(|scope| {
        let keeps: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| keep_reply(dir.path(), &digest, SENT_REPLY)))
            .collect();
        for keep in keeps {
            keep.join().unwrap().unwrap();
        }
    });
    let replies = dir.path().join(REPLIES_DIR);
    assert_eq!(std::fs::read(replies.join(&digest)).unwrap(), SENT_REPLY);
    let names: Vec<_> = std::fs::read_dir(&replies)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        [std::ffi::OsString::from(&digest)],
        "no temporary file is left"
    );
}

#[test]
fn a_reply_that_is_not_json_is_neither_kept_nor_recorded() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();
    let refused = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        b"not json",
        &json!({"state": "not_evidence"}),
        "2026-10-29T12:00:02Z",
    );
    assert!(matches!(refused, Err(AskError::Invalid(_))), "{refused:?}");
    assert!(!capsules.ledger_dir().join(REPLIES_DIR).exists());
    assert_eq!(records(&capsules).len(), 1);
}
