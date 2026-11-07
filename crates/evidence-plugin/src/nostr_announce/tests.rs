use super::*;
use std::net::TcpListener;

const NODE: &str = "ab00000000000000000000000000000000000000000000000000000000000001";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32]).unwrap()
}

/// What a mock relay does with the events it is sent.
#[derive(Clone, Copy)]
enum Relay {
    Accepts,
    Refuses,
    /// Refuses an event with content over this many bytes as too large.
    Caps(usize),
    /// Closes the connection at once.
    Hangs,
    /// Closes with a Size close frame on an event with content over this.
    ClosesOver(usize),
}

/// A relay on 127.0.0.1 that keeps every event it is sent; the URL it is at.
fn mock(behaviour: Relay) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let got = Arc::new(Mutex::new(Vec::new()));
    let seen = got.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                if matches!(behaviour, Relay::Hangs) {
                    return;
                }
                let Ok(mut ws) = tungstenite::accept(stream) else {
                    return;
                };
                while let Ok(tungstenite::Message::Text(text)) = ws.read() {
                    let parts: Vec<Value> = serde_json::from_str(&text).unwrap();
                    assert_eq!(parts[0], "EVENT");
                    let event = parts[1].clone();
                    let id = event["id"].clone();
                    let content = event["content"].as_str().unwrap_or_default().len();
                    if let Relay::ClosesOver(max) = behaviour {
                        if content > max {
                            let _ = ws.close(Some(tungstenite::protocol::CloseFrame {
                                code: tungstenite::protocol::frame::coding::CloseCode::Size,
                                reason: "message too big".into(),
                            }));
                            let _ = ws.flush();
                            return;
                        }
                    }
                    let reply = match behaviour {
                        Relay::Refuses => json!(["OK", id, false, "blocked: not for this relay"]),
                        Relay::Caps(max) if content > max => {
                            json!(["OK", id, false, "invalid: event too large"])
                        }
                        _ => {
                            seen.lock().unwrap().push(event);
                            json!(["OK", id, true, ""])
                        }
                    };
                    ws.send(tungstenite::Message::text(reply.to_string()))
                        .unwrap();
                }
            });
        }
    });
    (url, got)
}

fn commitment() -> Value {
    json!({"profile": "evidence-commitment/1", "node_id": NODE, "pad": "x".repeat(4000)})
}

fn verified(event: &Value) {
    use k256::schnorr::{Signature, VerifyingKey};
    let serial = serde_json::to_string(&json!([
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"]
    ]))
    .unwrap();
    let id = Sha256::digest(serial.as_bytes());
    assert_eq!(event["id"], hex::encode(id), "NIP-01 id");
    let pubkey =
        VerifyingKey::from_bytes(&hex::decode(event["pubkey"].as_str().unwrap()).unwrap()).unwrap();
    let sig = Signature::try_from(
        hex::decode(event["sig"].as_str().unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    pubkey
        .verify_raw(&id, &sig)
        .expect("BIP-340 signature over the id");
}

#[test]
fn the_event_is_the_addressable_announce_of_the_spec() {
    let octets = octets(&commitment());
    let e = event(&key(), NODE, &octets, true, 1_790_000_000);
    verified(&e);
    assert_eq!(e["kind"], 34700);
    assert_eq!(
        e["tags"],
        json!([
            ["d", NODE],
            ["t", "evidence-commitment"],
            ["x", hex::encode(Sha256::digest(&octets))]
        ])
    );
    let carried = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(e["content"].as_str().unwrap())
        .unwrap();
    assert_eq!(carried, octets, "the commitment bytes, whole");
}

#[test]
fn over_a_cap_the_event_carries_the_digest_and_no_commitment() {
    let octets = octets(&commitment());
    let e = event(&key(), NODE, &octets, false, 1_790_000_000);
    verified(&e);
    assert_eq!(e["content"], "");
    assert_eq!(
        e["tags"][2],
        json!(["x", hex::encode(Sha256::digest(&octets))])
    );
}

#[test]
fn a_relay_that_accepts_gets_the_whole_commitment() {
    let (url, got) = mock(Relay::Accepts);
    let octets = octets(&commitment());
    assert_eq!(
        publish_to(&url, &key(), NODE, &octets, 1),
        Outcome::Accepted
    );
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_ne!(got[0]["content"], "");
    verified(&got[0]);
}

#[test]
fn a_relay_that_says_too_large_gets_the_digest_alone() {
    let (url, got) = mock(Relay::Caps(100));
    let octets = octets(&commitment());
    assert_eq!(
        publish_to(&url, &key(), NODE, &octets, 1),
        Outcome::Accepted
    );
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1, "the refused full event was not kept");
    assert_eq!(got[0]["content"], "");
    assert_eq!(got[0]["tags"][2][1], hex::encode(Sha256::digest(&octets)));
    verified(&got[0]);
}

#[test]
fn a_refusal_and_a_dead_relay_are_told_apart() {
    let octets = octets(&commitment());
    let (refusing, _) = mock(Relay::Refuses);
    assert_eq!(
        publish_to(&refusing, &key(), NODE, &octets, 1),
        Outcome::Rejected("blocked: not for this relay".into())
    );
    let (hanging, _) = mock(Relay::Hangs);
    assert!(matches!(
        publish_to(&hanging, &key(), NODE, &octets, 1),
        Outcome::Unreachable(_)
    ));
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", closed.local_addr().unwrap());
    drop(closed);
    assert!(matches!(
        publish_to(&url, &key(), NODE, &octets, 1),
        Outcome::Unreachable(_)
    ));
}

fn book() -> Mutex<BTreeMap<String, RelayStatus>> {
    Mutex::new(BTreeMap::new())
}

fn route_to(relays: &[&str]) -> Route {
    Route {
        mailbox_key: hex::encode(key().verifying_key().to_bytes()),
        relays: relays.iter().map(|r| r.to_string()).collect(),
    }
}

#[test]
fn announce_publishes_to_each_relay_once_and_keeps_each_result() {
    let (a, got_a) = mock(Relay::Accepts);
    let (b, got_b) = mock(Relay::Refuses);
    let route = route_to(&[&a, &b]);
    let book = book();
    let c = commitment();
    assert_eq!(
        announce(
            &book,
            &key(),
            NODE,
            &c,
            &route,
            "2026-11-07T00:00:00Z",
            5,
            publish_to
        ),
        2
    );
    let held = book.lock().unwrap();
    assert_eq!(held[&a].state, "accepted");
    assert_eq!(held[&b].state, "rejected");
    assert_eq!(held[&b].detail, "blocked: not for this relay");
    drop(held);
    // The same commitment: the accepting relay is left alone, the refusing
    // one waits out its retry window.
    assert_eq!(
        announce(
            &book,
            &key(),
            NODE,
            &c,
            &route,
            "2026-11-07T00:01:00Z",
            6,
            publish_to
        ),
        0
    );
    assert_eq!(got_a.lock().unwrap().len(), 1);
    assert!(got_b.lock().unwrap().is_empty());
}

#[test]
fn a_changed_commitment_goes_to_every_relay_again() {
    let (a, got_a) = mock(Relay::Accepts);
    let route = route_to(&[&a]);
    let book = book();
    let first = commitment();
    announce(
        &book,
        &key(),
        NODE,
        &first,
        &route,
        "2026-11-07T00:00:00Z",
        5,
        publish_to,
    );
    let mut second = commitment();
    second["pad"] = "y".into();
    assert_eq!(
        announce(
            &book,
            &key(),
            NODE,
            &second,
            &route,
            "2026-11-07T00:02:00Z",
            7,
            publish_to
        ),
        1
    );
    let got = got_a.lock().unwrap();
    assert_eq!(got.len(), 2);
    assert_ne!(
        got[0]["tags"][2], got[1]["tags"][2],
        "the new digest replaces the old"
    );
    assert_eq!(
        book.lock().unwrap()[&a].digest,
        hex::encode(Sha256::digest(octets(&second)))
    );
}

#[test]
fn a_relay_dropped_from_the_route_leaves_the_status() {
    let (a, _) = mock(Relay::Accepts);
    let (b, _) = mock(Relay::Accepts);
    let book = book();
    let c = commitment();
    announce(
        &book,
        &key(),
        NODE,
        &c,
        &route_to(&[&a, &b]),
        "t",
        5,
        publish_to,
    );
    let mut c2 = commitment();
    c2["pad"] = "z".into();
    announce(
        &book,
        &key(),
        NODE,
        &c2,
        &route_to(&[&a]),
        "t",
        6,
        publish_to,
    );
    assert_eq!(book.lock().unwrap().keys().collect::<Vec<_>>(), vec![&a]);
}

#[test]
fn a_failed_relay_is_tried_again_after_the_wait() {
    let stale = RelayStatus {
        state: "unreachable",
        detail: String::new(),
        digest: "d".into(),
        at: String::new(),
        started: Instant::now() - RETRY_AFTER - Duration::from_secs(1),
    };
    assert!(due(Some(&stale), "d"));
    let fresh = RelayStatus {
        started: Instant::now(),
        ..stale.clone()
    };
    assert!(!due(Some(&fresh), "d"));
    assert!(due(Some(&fresh), "other"));
    assert!(due(None, "d"));
}

#[test]
fn relays_default_to_mesh_llms_and_an_override_is_checked() {
    assert_eq!(
        relays(None).unwrap(),
        DEFAULT_RELAYS.map(String::from).to_vec()
    );
    assert_eq!(relays(Some("  ")).unwrap().len(), 5);
    assert_eq!(
        relays(Some("wss://a.example, wss://b.example:8443/x")).unwrap(),
        vec!["wss://a.example", "wss://b.example:8443/x"]
    );
    for bad in [
        "ws://a.example",
        "wss://A.example",
        "wss://a.example:443",
        "wss://a.example/",
        "wss://user@a.example",
        "wss://a.example?x=1",
        "https://a.example",
        "wss://a.example:70000",
    ] {
        assert!(relays(Some(bad)).is_err(), "{bad} must be refused");
    }
    assert!(
        relays(Some("wss://a.example wss://a.example")).is_err(),
        "twice"
    );
    for default in DEFAULT_RELAYS {
        assert_eq!(relay_error(default), None, "{default}");
    }
}

#[test]
fn the_mailbox_key_is_made_once_kept_private_and_never_the_node_key() {
    let dir = tempfile::tempdir().unwrap();
    let first = mailbox_key(dir.path()).unwrap();
    let again = mailbox_key(dir.path()).unwrap();
    assert_eq!(first.to_bytes(), again.to_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
    assert_eq!(leftovers.len(), 1, "no staged copy is left behind");
    std::fs::write(dir.path().join(KEY_FILE), "not a key").unwrap();
    assert!(
        mailbox_key(dir.path()).is_err(),
        "a damaged key is not replaced"
    );
}

#[test]
fn off_makes_no_key_and_no_route() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(route(dir.path(), false).unwrap(), None);
    assert!(!dir.path().join(KEY_FILE).exists());
    let on = route(dir.path(), true).unwrap().unwrap();
    assert_eq!(on.relays.len(), 5);
    assert!(is_xonly_key(&on.mailbox_key));
    assert_eq!(route_problems(&on.to_json()), Vec::<String>::new());
}

#[test]
fn a_received_route_is_checked_as_loops_checker_does() {
    let good = route_to(&["wss://a.example"]).to_json();
    assert!(route_problems(&good).is_empty());
    let mut no_relays = good.clone();
    no_relays["relays"] = json!([]);
    assert!(route_problems(&no_relays)[0].contains("at least one"));
    let mut twice = good.clone();
    twice["relays"] = json!(["wss://a.example", "wss://a.example"]);
    assert!(route_problems(&twice)[0].contains("repeats"));
    let mut bad_key = good.clone();
    bad_key["mailbox_key"] = "AA".repeat(32).into();
    assert!(route_problems(&bad_key)[0].contains("x-only"));
    let mut extra = good.clone();
    extra["more"] = 1.into();
    assert!(route_problems(&extra)[0].contains("unknown field ask.nostr.more"));
    assert!(
        route_problems(&json!({"mailbox_key": good["mailbox_key"]}))[0]
            .contains("missing ask.nostr.relays")
    );
}

#[test]
fn a_lost_or_replaced_mailbox_key_is_noticed_and_cleared_by_a_publish() {
    let dir = tempfile::tempdir().unwrap();
    let first = hex::encode(mailbox_key(dir.path()).unwrap().verifying_key().to_bytes());
    assert_eq!(
        key_change(dir.path(), &first),
        None,
        "nothing published yet"
    );
    note_published(dir.path(), &first);
    assert_eq!(key_change(dir.path(), &first), None, "same key");
    std::fs::remove_file(dir.path().join(KEY_FILE)).unwrap();
    let second = hex::encode(mailbox_key(dir.path()).unwrap().verifying_key().to_bytes());
    assert_ne!(first, second, "a lost key file makes a new key");
    let note = key_change(dir.path(), &second).expect("the change is reported");
    assert!(note.contains(&first) && note.contains(&second));
    note_published(dir.path(), &second);
    assert_eq!(
        key_change(dir.path(), &second),
        None,
        "an accepted publish under the new key clears it"
    );
}

#[test]
fn a_relay_that_closes_on_a_long_message_gets_the_digest_alone() {
    let (url, got) = mock(Relay::ClosesOver(100));
    let octets = octets(&commitment());
    assert_eq!(
        publish_to(&url, &key(), NODE, &octets, 1),
        Outcome::Accepted
    );
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["content"], "");
}

#[test]
fn a_stalled_relay_does_not_hold_the_others_past_the_deadline() {
    let (fast, _) = mock(Relay::Accepts);
    let slow = "wss://slow.example".to_string();
    let route = route_to(&[&fast, &slow]);
    let book = book();
    let started = Instant::now();
    let tried = announce(
        &book,
        &key(),
        NODE,
        &commitment(),
        &route,
        "t",
        5,
        |url, key, node, octets, at| {
            if url.starts_with("wss://slow") {
                std::thread::sleep(Duration::from_secs(4));
                return Outcome::Accepted;
            }
            publish_to(url, key, node, octets, at)
        },
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "returned at the deadline"
    );
    assert_eq!(tried, 2);
    let held = book.lock().unwrap();
    assert_eq!(held[&fast].state, "accepted");
    assert_eq!(held[&slow].state, "unreachable");
}

#[test]
fn two_first_uses_at_once_end_with_one_key_and_no_staging_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let keys: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || mailbox_key(&path).unwrap().to_bytes())
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert!(keys.iter().all(|k| *k == keys[0]));
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
}

#[test]
fn a_relay_that_drips_its_handshake_loses_its_connection_and_its_thread() {
    // Accepts, then sends a byte every 100 ms and never completes a handshake.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                while stream.write_all(b"x").is_ok() {
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
        }
    });
    let started = Instant::now();
    let outcome = publish_to(&url, &key(), NODE, &octets(&commitment()), 1);
    assert!(matches!(outcome, Outcome::Unreachable(_)), "{outcome:?}");
    assert!(started.elapsed() < CONNECTION_LIFETIME * 2 + Duration::from_secs(2));
}

#[test]
fn a_relay_still_being_published_to_gets_no_second_thread() {
    let url = "wss://busy.example".to_string();
    let route = route_to(&[&url]);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let make = |calls: Arc<std::sync::atomic::AtomicUsize>| {
        move |_: &str, _: &SigningKey, _: &str, _: &[u8], _: i64| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(3));
            Outcome::Accepted
        }
    };
    // Two separate books so the second round is due again; the worker of the
    // first is still running when the second starts.
    announce(
        &book(),
        &key(),
        NODE,
        &commitment(),
        &route,
        "t",
        1,
        make(calls.clone()),
    );
    announce(
        &book(),
        &key(),
        NODE,
        &commitment(),
        &route,
        "t",
        2,
        make(calls.clone()),
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    std::thread::sleep(Duration::from_secs(3));
}
