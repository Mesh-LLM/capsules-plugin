//! A relay that stores what it is sent, for tests of both halves.
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

/// The events a test relay holds.
#[derive(Clone, Default)]
pub struct Store(Arc<Mutex<Vec<Value>>>);

impl Store {
    pub fn with(events: Vec<Value>) -> Self {
        Self(Arc::new(Mutex::new(events)))
    }

    pub fn all(&self) -> Vec<Value> {
        self.0.lock().unwrap().clone()
    }
}

fn matches(filter: &Value, event: &Value) -> bool {
    let kind = filter["kinds"]
        .as_array()
        .is_none_or(|k| k.contains(&event["kind"]));
    let tag = |name: &str, letter: &str| {
        filter[name].as_array().is_none_or(|wanted| {
            event["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t[0] == letter && wanted.iter().any(|w| *w == t[1]))
        })
    };
    let at = event["created_at"].as_i64().unwrap();
    kind && tag("#p", "p")
        && tag("#e", "e")
        && filter["since"].as_i64().is_none_or(|s| at >= s)
        && filter["until"].as_i64().is_none_or(|u| at <= u)
}

/// A NIP-01 relay on 127.0.0.1 over `store`: `EVENT` stores, `REQ` returns
/// the newest matching events up to `limit` and `EOSE`. Its URL.
pub fn relay_store(store: Store) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let store = store.clone();
            std::thread::spawn(move || {
                let Ok(mut ws) = tungstenite::accept(stream) else {
                    return;
                };
                while let Ok(tungstenite::Message::Text(text)) = ws.read() {
                    let parts: Vec<Value> = serde_json::from_str(&text).unwrap();
                    match parts[0].as_str().unwrap() {
                        "REQ" => {
                            let limit = parts[2]["limit"].as_u64().unwrap_or(100) as usize;
                            let mut hits: Vec<Value> = store
                                .all()
                                .into_iter()
                                .filter(|e| matches(&parts[2], e))
                                .collect();
                            hits.sort_by_key(|e| {
                                std::cmp::Reverse(e["created_at"].as_i64().unwrap())
                            });
                            for event in hits.into_iter().take(limit) {
                                let _ = ws.send(tungstenite::Message::text(
                                    json!(["EVENT", parts[1], event]).to_string(),
                                ));
                            }
                            let _ = ws.send(tungstenite::Message::text(
                                json!(["EOSE", parts[1]]).to_string(),
                            ));
                        }
                        "EVENT" => {
                            let id = parts[1]["id"].clone();
                            store.0.lock().unwrap().push(parts[1].clone());
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
    url
}
