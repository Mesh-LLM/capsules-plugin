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
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.path().join(KEY_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
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
