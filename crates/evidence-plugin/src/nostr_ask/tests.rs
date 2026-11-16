use super::*;
use crate::nostr_mailbox::tests_support::{relay_store, Store};
use std::sync::Arc;

fn mailbox() -> SigningKey {
    SigningKey::from_bytes(&[9; 32]).unwrap()
}

fn mailbox_hex() -> String {
    hex::encode(mailbox().verifying_key().to_bytes())
}

fn dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nostr-ask-{}-{}",
        std::process::id(),
        crate::producer::capsule::fresh_store_nonce()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn node() -> (Arc<crate::capsule_emit::CapsuleState>, std::path::PathBuf) {
    let d = dir();
    (
        Arc::new(crate::capsule_emit::CapsuleState::open(&d, "node-under-test").unwrap()),
        d,
    )
}

fn args(relay: &str, responder_key: &str, request: Value) -> NostrEvidenceRequestArgs {
    NostrEvidenceRequestArgs {
        mailbox_key: mailbox_hex(),
        relays: vec![relay.to_string()],
        responder_key: responder_key.to_string(),
        request,
        verify: true,
    }
}

#[test]
fn the_route_and_the_responder_key_are_checked_before_anything_is_sealed() {
    let ok = args(
        "wss://relay.example",
        &"ab".repeat(32),
        json!({"subject": {"checkpoints": null}}),
    );
    // the all-"ab" key is not a valid Ed25519 point, so use a real one
    let real = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[3; 32])
            .verifying_key()
            .to_bytes(),
    );
    let good = NostrEvidenceRequestArgs {
        responder_key: real.clone(),
        ..ok
    };
    assert!(check(&good).is_ok());
    let bad = |f: &dyn Fn(&mut NostrEvidenceRequestArgs)| {
        let mut a = args(
            "wss://relay.example",
            &real,
            json!({"subject": {"checkpoints": null}}),
        );
        f(&mut a);
        check(&a).unwrap_err()
    };
    assert!(bad(&|a| a.mailbox_key = "00".repeat(32)).contains("mailbox_key"));
    assert!(bad(&|a| a.relays = vec![]).contains("relays"));
    assert!(bad(&|a| a.relays = vec!["http://x".into()]).contains("relay"));
    assert!(bad(&|a| a.responder_key = "zz".into()).contains("responder_key"));
    assert!(bad(&|a| a.request = json!([1])).contains("map"));
}

#[test]
fn a_request_gets_a_deadline_and_a_nonce_only_when_it_has_none() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-16T12:00:00Z")
        .unwrap()
        .to_utc();
    let bare = prepared(&json!({"subject": {"checkpoints": null}}), now, 60);
    assert_eq!(bare["deadline"], "2026-11-16T12:01:00Z");
    assert_eq!(bare["nonce"].as_str().unwrap().len(), 32);
    let set = prepared(
        &json!({"subject": {"checkpoints": null}, "deadline": "2027-01-01T00:00:00Z", "nonce": "n"}),
        now,
        60,
    );
    assert_eq!(
        (set["deadline"].as_str(), set["nonce"].as_str()),
        (Some("2027-01-01T00:00:00Z"), Some("n"))
    );
}

#[test]
fn the_request_event_is_addressed_signed_by_a_carriage_key_and_expires_at_the_deadline() {
    let carriage = carriage_key();
    let e = request_event(
        &carriage,
        &mailbox_hex(),
        b"{}",
        1_790_000_060,
        1_790_000_000,
    );
    let event = verify_event(&e).unwrap();
    assert_eq!(event.kind, REQUEST_KIND);
    assert_eq!(event.one_tag("p"), Some(mailbox_hex().as_str()));
    assert_eq!(event.one_tag("m"), Some(MEDIA));
    assert_eq!(event.one_tag("expiration"), Some("1790000060"));
    assert_ne!(
        event.pubkey,
        mailbox_hex(),
        "a fresh key, never the mailbox key"
    );
    assert_ne!(
        carriage_key().verifying_key().to_bytes(),
        carriage.verifying_key().to_bytes()
    );
}

/// A reply event for `request_id` from `key`, carrying `octets`.
fn reply(key: &SigningKey, request_id: &str, octets: &[u8], media: &str, kind: u64) -> Value {
    signed_event(
        key,
        kind,
        json!([["e", request_id], ["p", "00"], ["m", media]]),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(octets),
        1_790_000_000,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mailbox_keys_reply_is_taken_and_others_only_when_they_prove_themselves() {
    let rid = "ab".repeat(32);
    let stranger = SigningKey::from_bytes(&[5; 32]).unwrap();
    let wait = |events: Vec<Value>, proves: bool| {
        let rid = rid.clone();
        async move {
            let url = relay_store(Store::with(events));
            tokio::time::timeout(
                Duration::from_secs(2),
                wait_for_reply(vec![url], mailbox_hex(), rid, move |_| proves),
            )
            .await
        }
    };
    let rid2 = "ab".repeat(32);
    // not a reply: another kind, another request, another media type, bad content
    let noise = vec![
        reply(&mailbox(), &rid2, b"x", MEDIA, 4700),
        reply(&mailbox(), &"cd".repeat(32), b"x", MEDIA, REPLY_KIND),
        reply(&mailbox(), &rid2, b"x", "text/plain", REPLY_KIND),
    ];
    assert!(
        wait(noise.clone(), true).await.is_err(),
        "none of them is a reply"
    );
    // the mailbox key's own reply is taken as it is
    let mut with_own = noise.clone();
    with_own.push(reply(&mailbox(), &rid2, b"{\"mine\":1}", MEDIA, REPLY_KIND));
    assert_eq!(
        wait(with_own, false).await.unwrap().unwrap(),
        b"{\"mine\":1}"
    );
    // another key's reply counts only if its content proves itself
    let theirs = vec![reply(
        &stranger,
        &rid2,
        b"{\"theirs\":1}",
        MEDIA,
        REPLY_KIND,
    )];
    assert!(wait(theirs.clone(), false).await.is_err());
    assert_eq!(
        wait(theirs, true).await.unwrap().unwrap(),
        b"{\"theirs\":1}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_is_sealed_sent_answered_by_a_node_on_the_mailbox_and_recorded_as_the_response() {
    // The asked node: a real responder reading the same relay.
    let (asked_node, asked_dir) = node();
    let responder_key = hex::encode(asked_node.public_key());
    let store = Store::with(vec![]);
    let url = relay_store(store.clone());
    let serve = {
        let (url, asked_node, asked_dir) = (url.clone(), asked_node.clone(), asked_dir.clone());
        tokio::spawn(async move {
            for _ in 0..200 {
                let now = chrono::Utc::now().timestamp();
                crate::nostr_mailbox::round(
                    &asked_dir,
                    &mailbox(),
                    std::slice::from_ref(&url),
                    now,
                    || true,
                    |octets| {
                        crate::mesh_evidence_bridge::answer_in_process(
                            asked_node.clone(),
                            octets,
                            None,
                            true,
                        )
                    },
                )
                .await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    };
    // The asking node.
    let (me, me_dir) = node();
    let answered = ask(
        args(
            &url,
            &responder_key,
            json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 1}}),
        ),
        me.clone(),
    )
    .await
    .expect("an answer");
    serve.abort();
    let state = answered["verification"]["state"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        matches!(state.as_str(), "artifact" | "refusal"),
        "{answered}"
    );
    // The request was sealed before it was sent, and its reply is the recorded response.
    let records = crate::ask_book::entries(me.ledger_dir());
    let types: Vec<&str> = records
        .iter()
        .filter_map(|(_, h)| h["record_type"].as_str())
        .collect();
    assert!(
        types.contains(&"evidence_request") && types.contains(&"evidence_response"),
        "{types:?}"
    );
    assert!(!types.contains(&"recorded_absence"));
    // What went to the relay: a request event from a fresh key, naming the asked mailbox.
    let sent: Vec<Value> = store
        .all()
        .into_iter()
        .filter(|e| e["kind"] == REQUEST_KIND)
        .collect();
    assert_eq!(sent.len(), 1);
    assert_ne!(sent[0]["pubkey"], mailbox_hex());
    let _ = (me_dir, asked_dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mailbox_keys_reply_is_found_under_newer_events_of_other_keys() {
    let rid = "ab".repeat(32);
    let stranger = SigningKey::from_bytes(&[5; 32]).unwrap();
    let at = |key: &SigningKey, octets: &[u8], t: i64| {
        signed_event(
            key,
            REPLY_KIND,
            json!([["e", rid], ["p", "00"], ["m", MEDIA]]),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(octets),
            t,
        )
    };
    // the real reply is older than 64 events from another key
    let mut events = vec![at(&mailbox(), b"{\"mine\":1}", 1_790_000_000)];
    for i in 0..70 {
        events.push(at(
            &stranger,
            format!("{{\"n\":{i}}}").as_bytes(),
            1_790_000_100 + i,
        ));
    }
    let url = relay_store(Store::with(events));
    let got = tokio::time::timeout(
        Duration::from_secs(3),
        wait_for_reply(vec![url], mailbox_hex(), rid.clone(), |_| false),
    )
    .await
    .expect("found")
    .unwrap();
    assert_eq!(got, b"{\"mine\":1}");
}
