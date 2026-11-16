use super::*;
use std::net::TcpListener;
use std::sync::Arc;

fn mailbox() -> SigningKey {
    SigningKey::from_bytes(&[9; 32]).unwrap()
}

fn asker() -> SigningKey {
    SigningKey::from_bytes(&[5; 32]).unwrap()
}

fn key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn b64(octets: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(octets)
}

/// A request event from the asker's carriage key to `to`.
fn request(to: &str, octets: &[u8], at: i64) -> Value {
    signed_event(
        &asker(),
        REQUEST_KIND,
        json!([["p", to], ["m", MEDIA]]),
        &b64(octets),
        at,
    )
}

/// A relay on 127.0.0.1 that holds `stored`, answers every `REQ` with them
/// and `EOSE`, and keeps every `EVENT` it is sent.
fn relay(stored: Vec<Value>) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let got = Arc::new(Mutex::new(Vec::new()));
    let seen = got.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (seen, stored) = (seen.clone(), stored.clone());
            std::thread::spawn(move || {
                let Ok(mut ws) = tungstenite::accept(stream) else {
                    return;
                };
                while let Ok(tungstenite::Message::Text(text)) = ws.read() {
                    let parts: Vec<Value> = serde_json::from_str(&text).unwrap();
                    match parts[0].as_str().unwrap() {
                        "REQ" => {
                            for event in &stored {
                                let frame = json!(["EVENT", parts[1], event]);
                                ws.send(tungstenite::Message::text(frame.to_string()))
                                    .unwrap();
                            }
                            let _ = ws.send(tungstenite::Message::text(
                                json!(["EOSE", parts[1]]).to_string(),
                            ));
                        }
                        "EVENT" => {
                            let id = parts[1]["id"].clone();
                            seen.lock().unwrap().push(parts[1].clone());
                            let _ = ws.send(tungstenite::Message::text(
                                json!(["OK", id, true, ""]).to_string(),
                            ));
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    (url, got)
}

fn dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "mailbox-{}-{}",
        std::process::id(),
        crate::producer::capsule::fresh_store_nonce()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

const NOW: i64 = 1_790_000_000;

#[test]
fn an_event_is_checked_by_its_id_and_its_signature() {
    let good = request(&key_hex(&mailbox()), b"{}", NOW);
    assert!(verify_event(&good).is_ok());
    let mut tampered = good.clone();
    tampered["content"] = json!(b64(b"{\"x\":1}"));
    assert!(verify_event(&tampered).unwrap_err().contains("id"));
    // the id recomputed over the changed content, the signature no longer fits
    let mut resigned = tampered.clone();
    let serial = serde_json::to_string(&json!([
        0,
        resigned["pubkey"],
        resigned["created_at"],
        resigned["kind"],
        resigned["tags"],
        resigned["content"]
    ]))
    .unwrap();
    resigned["id"] = json!(hex::encode(Sha256::digest(serial.as_bytes())));
    assert!(verify_event(&resigned).unwrap_err().contains("signature"));
}

#[test]
fn only_a_json_request_event_addressed_to_the_key_is_read() {
    let to = key_hex(&mailbox());
    let read = |raw: Value| request_octets(&verify_event(&raw).unwrap(), &to);
    assert_eq!(
        read(request(&to, b"{\"a\":1}", NOW)),
        Some(b"{\"a\":1}".to_vec())
    );
    assert_eq!(
        read(request(&key_hex(&asker()), b"{}", NOW)),
        None,
        "another mailbox"
    );
    let tag = |tags: Value, kind: u64| signed_event(&asker(), kind, tags, &b64(b"{}"), NOW);
    assert_eq!(
        read(tag(json!([["p", to], ["m", MEDIA]]), 1)),
        None,
        "another kind"
    );
    assert_eq!(
        read(tag(
            json!([["p", to], ["p", to], ["m", MEDIA]]),
            REQUEST_KIND
        )),
        None,
        "two p tags"
    );
    assert_eq!(
        read(tag(
            json!([["p", to], ["m", "application/cbor"]]),
            REQUEST_KIND
        )),
        None,
        "another media type"
    );
    assert_eq!(
        read(tag(json!([["p", to]]), REQUEST_KIND)),
        None,
        "no media type"
    );
    let bad = signed_event(
        &asker(),
        REQUEST_KIND,
        json!([["p", to], ["m", MEDIA]]),
        "***",
        NOW,
    );
    assert_eq!(read(bad), None, "content that is not base64url");
}

#[test]
fn a_request_is_answered_with_a_reply_event_the_asker_can_check() {
    let to = key_hex(&mailbox());
    let asked = request(&to, b"{\"ask\":1}", NOW - 3);
    let (url, got) = relay(vec![asked.clone()]);
    let d = dir();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let done = tokio::runtime::Runtime::new().unwrap().block_on(round(
        &d,
        &mailbox(),
        &[url],
        NOW,
        || true,
        move |octets| {
            log.lock().unwrap().push(octets);
            std::future::ready(Some(b"{\"signed\":\"answer\"}".to_vec()))
        },
    ));
    assert_eq!(done, vec![asked["id"].as_str().unwrap().to_string()]);
    assert_eq!(
        seen.lock().unwrap().clone(),
        vec![b"{\"ask\":1}".to_vec()],
        "the request octets, unchanged"
    );
    let sent = got.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let reply = verify_event(&sent[0]).unwrap();
    assert_eq!(reply.kind, REPLY_KIND);
    assert_eq!(reply.pubkey, to, "signed by the mailbox key");
    assert_eq!(reply.one_tag("e"), asked["id"].as_str());
    assert_eq!(reply.one_tag("p"), asked["pubkey"].as_str());
    assert_eq!(reply.one_tag("m"), Some(MEDIA));
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&reply.content)
            .unwrap(),
        b"{\"signed\":\"answer\"}"
    );
}

#[test]
fn a_request_event_is_answered_once_across_rounds_and_restarts() {
    let to = key_hex(&mailbox());
    let (url, got) = relay(vec![request(&to, b"{}", NOW - 3)]);
    let d = dir();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let again = |at: i64| {
        rt.block_on(round(
            &d,
            &mailbox(),
            std::slice::from_ref(&url),
            at,
            || true,
            |_| std::future::ready(Some(b"{}".to_vec())),
        ))
    };
    assert_eq!(again(NOW).len(), 1);
    assert_eq!(again(NOW + 5).len(), 0, "the same round again");
    // a restart reads the ids from the data directory
    assert_eq!(answered(&d, NOW + 10).unwrap().len(), 1);
    assert_eq!(again(NOW + 10).len(), 0, "after a restart");
    assert_eq!(got.lock().unwrap().len(), 1);
}

#[test]
fn what_is_not_a_verified_current_request_to_this_key_gets_no_reply() {
    let to = key_hex(&mailbox());
    let mut tampered = request(&to, b"{}", NOW - 3);
    tampered["content"] = json!(b64(b"{\"x\":1}"));
    let elsewhere = request(&key_hex(&asker()), b"{}", NOW - 3);
    let old = request(&to, b"{}", NOW - LOOKBACK - 10);
    // the relay is not trusted to filter: it hands over all three anyway
    let (url, got) = relay(vec![tampered, elsewhere, old]);
    let d = dir();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let done = rt.block_on(round(
        &d,
        &mailbox(),
        &[url],
        NOW,
        || true,
        |_| std::future::ready(Some(b"{}".to_vec())),
    ));
    assert!(done.is_empty());
    assert!(got.lock().unwrap().is_empty());
}

#[test]
fn a_request_this_node_cannot_sign_for_gets_no_reply_and_is_not_asked_again() {
    let to = key_hex(&mailbox());
    let (url, got) = relay(vec![request(&to, b"not json", NOW - 3)]);
    let d = dir();
    let rt = tokio::runtime::Runtime::new().unwrap();
    for at in [NOW, NOW + 5] {
        let done = rt.block_on(round(
            &d,
            &mailbox(),
            std::slice::from_ref(&url),
            at,
            || true,
            |_| std::future::ready(None),
        ));
        assert!(done.is_empty());
    }
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(answered(&d, NOW + 5).unwrap().len(), 1);
}

#[test]
fn a_relay_that_cannot_be_reached_is_reported_and_the_next_is_read() {
    let to = key_hex(&mailbox());
    let (url, got) = relay(vec![request(&to, b"{}", NOW - 3)]);
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("ws://{}", l.local_addr().unwrap())
    };
    let d = dir();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let done = rt.block_on(round(
        &d,
        &mailbox(),
        &[dead.clone(), url.clone()],
        NOW,
        || true,
        |_| std::future::ready(Some(b"{}".to_vec())),
    ));
    assert_eq!(done.len(), 1);
    assert_eq!(got.lock().unwrap().len(), 1);
    assert_eq!(status()[&dead].state, "unreachable");
    assert_eq!(status()[&url].state, "read");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_node_answers_a_mailbox_request_as_it_answers_a_mesh_stream() {
    let to = key_hex(&mailbox());
    let sent = br#"{"subject":{"checkpoints":null},"coverage":{"min_freshness":1},"requester_id":"node-a"}"#;
    let (url, got) = relay(vec![request(&to, sent, NOW - 3)]);
    let d = dir();
    let capsules =
        Arc::new(crate::capsule_emit::CapsuleState::open(&d, "node-under-test").unwrap());
    let done = round(
        &d,
        &mailbox(),
        &[url],
        NOW,
        || true,
        |octets| crate::mesh_evidence_bridge::answer_in_process(capsules.clone(), octets, None),
    )
    .await;
    assert_eq!(done.len(), 1);
    let reply = verify_event(&got.lock().unwrap()[0]).unwrap();
    let octets = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&reply.content)
        .unwrap();
    let answer: Value =
        serde_json::from_slice(&octets).expect("the reply octets are the node's JSON answer");
    // Whatever it is (an artifact, or a refusal of an unsigned stranger), the node signed it for this request.
    assert!(
        answer
            .to_string()
            .contains(&evidence_request::digest::request_digest(sent)),
        "{answer}"
    );
}

/// Sherlock2's acceptance condition for loop#442: nostr-mailbox-v0 has no
/// requester authentication (§4.1), so every mailbox asker is a stranger, and
/// a record or a full history is refused to one over the mailbox as over the
/// mesh.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_or_history_request_over_the_mailbox_is_refused() {
    let to = key_hex(&mailbox());
    let digest = "ab".repeat(32);
    let asked = [
        json!({"subject": {"record": digest}, "coverage": {"min_freshness": 1}}),
        json!({"subject": {"full_history": null}, "coverage": {"min_freshness": 1}}),
        json!({"subject": {"range": {"from": 0, "to": 1}}, "coverage": {"min_freshness": 1}}),
    ];
    for ask in asked {
        let sent = serde_json::to_vec(&ask).unwrap();
        let (url, got) = relay(vec![request(&to, &sent, NOW - 3)]);
        let d = dir();
        let capsules =
            Arc::new(crate::capsule_emit::CapsuleState::open(&d, "node-under-test").unwrap());
        let done = round(
            &d,
            &mailbox(),
            &[url],
            NOW,
            || true,
            |octets| crate::mesh_evidence_bridge::answer_in_process(capsules.clone(), octets, None),
        )
        .await;
        assert_eq!(done.len(), 1, "{ask}");
        let reply = verify_event(&got.lock().unwrap()[0]).unwrap();
        let octets = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&reply.content)
            .unwrap();
        let answer: Value = serde_json::from_slice(&octets).unwrap();
        assert!(
            answer.get("reason").is_some() && answer.get("artifact").is_none(),
            "a stranger over the mailbox gets a refusal of {ask}, got {answer}"
        );
    }
}

#[test]
fn a_request_stamped_in_the_future_is_not_answered_or_kept() {
    let to = key_hex(&mailbox());
    let (url, got) = relay(vec![request(&to, b"{}", NOW + 100_000)]);
    let d = dir();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let done = rt.block_on(round(
        &d,
        &mailbox(),
        &[url],
        NOW,
        || true,
        |_| std::future::ready(Some(b"{}".to_vec())),
    ));
    assert!(done.is_empty() && got.lock().unwrap().is_empty());
    assert!(answered(&d, NOW).unwrap().is_empty());
}

#[test]
fn a_request_is_not_answered_when_the_answered_ids_cannot_be_kept_or_read() {
    let to = key_hex(&mailbox());
    let (url, got) = relay(vec![request(&to, b"{}", NOW - 3)]);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let reply = |_: Vec<u8>| std::future::ready(Some(b"{}".to_vec()));
    // a directory that does not exist: the id cannot be kept
    let missing = dir().join("gone");
    let done = rt.block_on(round(
        &missing,
        &mailbox(),
        std::slice::from_ref(&url),
        NOW,
        || true,
        reply,
    ));
    assert!(done.is_empty());
    // a record that exists and cannot be read as text: the round does nothing
    let d = dir();
    std::fs::create_dir(d.join(ANSWERED_FILE)).unwrap();
    assert!(answered(&d, NOW).is_err());
    let done = rt.block_on(round(
        &d,
        &mailbox(),
        std::slice::from_ref(&url),
        NOW,
        || true,
        reply,
    ));
    assert!(done.is_empty());
    assert!(got.lock().unwrap().is_empty());
}

#[test]
fn an_older_request_behind_a_full_page_is_still_read() {
    let to = key_hex(&mailbox());
    // 64 newer requests fill the first page; the older one is on the next
    let mut stored: Vec<Value> = (0..LIMIT as i64)
        .map(|i| request(&to, format!("{{\"n\":{i}}}").as_bytes(), NOW - 1))
        .collect();
    stored.push(request(&to, b"{\"old\":1}", NOW - 100));
    let (url, got) = paged_relay(stored);
    let d = dir();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let done = rt.block_on(round(
        &d,
        &mailbox(),
        &[url],
        NOW,
        || true,
        |_| std::future::ready(Some(b"{}".to_vec())),
    ));
    assert_eq!(done.len(), LIMIT + 1);
    assert_eq!(got.lock().unwrap().len(), LIMIT + 1);
}

#[test]
fn a_switch_turned_off_mid_round_stops_the_answers() {
    let to = key_hex(&mailbox());
    let (url, got) = relay(vec![
        request(&to, b"{\"a\":1}", NOW - 3),
        request(&to, b"{\"a\":2}", NOW - 2),
    ]);
    let d = dir();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let asked = std::cell::Cell::new(0);
    let done = rt.block_on(round(
        &d,
        &mailbox(),
        &[url],
        NOW,
        || {
            asked.set(asked.get() + 1);
            asked.get() <= 2 // the relay, the first answer; then off
        },
        |_| std::future::ready(Some(b"{}".to_vec())),
    ));
    assert_eq!(done.len(), 1);
    assert_eq!(got.lock().unwrap().len(), 1);
}

/// A relay that honours `until` and `limit`, newest first, as NIP-01 says.
fn paged_relay(stored: Vec<Value>) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let got = Arc::new(Mutex::new(Vec::new()));
    let seen = got.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (seen, stored) = (seen.clone(), stored.clone());
            std::thread::spawn(move || {
                let Ok(mut ws) = tungstenite::accept(stream) else {
                    return;
                };
                while let Ok(tungstenite::Message::Text(text)) = ws.read() {
                    let parts: Vec<Value> = serde_json::from_str(&text).unwrap();
                    match parts[0].as_str().unwrap() {
                        "REQ" => {
                            let until = parts[2]["until"].as_i64().unwrap_or(i64::MAX);
                            let limit = parts[2]["limit"].as_u64().unwrap() as usize;
                            let mut page: Vec<&Value> = stored
                                .iter()
                                .filter(|e| e["created_at"].as_i64().unwrap() <= until)
                                .collect();
                            page.sort_by_key(|e| {
                                std::cmp::Reverse(e["created_at"].as_i64().unwrap())
                            });
                            for event in page.into_iter().take(limit) {
                                let frame = json!(["EVENT", parts[1], event]);
                                ws.send(tungstenite::Message::text(frame.to_string()))
                                    .unwrap();
                            }
                            let _ = ws.send(tungstenite::Message::text(
                                json!(["EOSE", parts[1]]).to_string(),
                            ));
                        }
                        "EVENT" => {
                            let id = parts[1]["id"].clone();
                            seen.lock().unwrap().push(parts[1].clone());
                            let _ = ws.send(tungstenite::Message::text(
                                json!(["OK", id, true, ""]).to_string(),
                            ));
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    (url, got)
}

#[test]
fn an_event_with_too_much_content_or_too_many_tags_is_not_read() {
    let to = key_hex(&mailbox());
    let big = signed_event(
        &asker(),
        REQUEST_KIND,
        json!([["p", to], ["m", MEDIA]]),
        &"A".repeat(MAX_CONTENT + 1),
        NOW,
    );
    assert!(verify_event(&big).unwrap_err().contains("too large"));
    let tags: Vec<Value> = (0..=MAX_TAGS)
        .map(|i| json!(["x", i.to_string()]))
        .collect();
    let many = signed_event(&asker(), REQUEST_KIND, json!(tags), "", NOW);
    assert!(verify_event(&many).unwrap_err().contains("too many tags"));
}
