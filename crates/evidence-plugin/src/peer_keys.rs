//! The announced-key registry a pushed record's signature is checked against.
//!
//! A record's own `key_id` and `signature` prove that the holder of that key
//! signed that exact `capsule_id`. They do not prove who holds the key. This
//! registry is the other half: a map from a mesh peer id (its full endpoint
//! id) to the `key_id` that peer is known to sign with. The key is the
//! identity a node accepts, and the peer id a push or request arrives under
//! is a hint (D-34): [`accepted_via`] accepts a key any entry gives, or one a
//! carried controller declaration binds to such a key, and says which.
//!
//! It has two sources, merged by [`registry`]:
//!
//! - **The host's announced keys,** when the host lists the `plugin_keys.v1`
//!   capability: each peer's key for this plugin, bound to that peer by its
//!   own node key and checked by the host before it lists it at
//!   `GET /api/plugin-keys` ([`announced`]); a peer the host stops listing
//!   loses its key after [`announced::UNLISTED_TTL`]. Off a host without the
//!   capability, nothing is read.
//! - **The operator's map,** `CAPSULES_PEER_KEYS`: a JSON object mapping peer
//!   id to that peer's `key_id` (the raw Ed25519 public key, lowercase hex),
//!   e.g. `{"node-a": "3a1f…", "node-b": "9c02…"}`. It still works alone,
//!   and is the fallback for a peer whose host announces nothing. The name
//!   may be any label: the stopgap for a node with no stable peer id.
//!
//! A peer absent from both is unknown. A peer the two sources give different
//! keys is "cannot verify" until the operator removes the stale entry: never
//! a choice between them. Every way the operator's value can fail (empty,
//! not JSON, not an object, the entry not a non-empty string) means "cannot
//! verify", never a guessed or default key.

/// The environment variable the registry is read from.
pub const ENV_PEER_KEYS: &str = "CAPSULES_PEER_KEYS";

/// No announced keys: for a receiver whose registry is the operator's map
/// alone.
#[cfg(test)]
pub const NONE_ANNOUNCED: &std::collections::BTreeMap<String, String> =
    &std::collections::BTreeMap::new();

/// The registry every check reads: the operator's map ([`ENV_PEER_KEYS`])
/// merged with the keys the host announced ([`announced::snapshot`]), as the
/// raw JSON object [`announced_key_in`] and [`peer_id_for_key_in`] take.
/// `None` when neither has anything.
pub fn registry() -> Option<String> {
    let configured = crate::settings::var(ENV_PEER_KEYS).ok();
    merged(configured.as_deref(), &announced::snapshot())
}

/// [`registry`] from its two sources. An operator value that is set but
/// unusable stays unusable (`Some` of itself, so every lookup is "cannot
/// verify"); a peer the two give different keys gets an empty key, which no
/// lookup accepts.
pub fn merged(
    configured: Option<&str>,
    announced: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    let configured = configured.filter(|raw| !raw.is_empty());
    let mut map = match configured {
        None => serde_json::Map::new(),
        Some(raw) => match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => return Some(raw.to_string()),
        },
    };
    if configured.is_none() && announced.is_empty() {
        return None;
    }
    for (peer, key) in announced {
        let agreed = match map.get(peer) {
            None => key.clone(),
            Some(serde_json::Value::String(set)) if set == key => key.clone(),
            Some(_) => String::new(),
        };
        map.insert(peer.clone(), serde_json::Value::String(agreed));
    }
    Some(serde_json::Value::Object(map).to_string())
}

/// The keys the host announces for this plugin, read from the host's
/// `GET /api/plugin-keys` when it lists `plugin_keys.v1`.
pub mod announced {
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock, PoisonError};
    use std::time::{Duration, Instant};

    /// The host capability that says it announces plugin keys.
    pub const CAPABILITY: &str = "plugin_keys.v1";
    /// The host's console API, where it lists announced keys. Unset:
    /// [`DEFAULT_CONSOLE_URL`].
    pub const ENV_CONSOLE_URL: &str = "CAPSULES_HOST_CONSOLE_URL";
    pub const DEFAULT_CONSOLE_URL: &str = "http://127.0.0.1:3131";
    const ROUTE: &str = "/api/plugin-keys";
    const EVERY: Duration = Duration::from_secs(30);
    const TIMEOUT: Duration = Duration::from_secs(5);
    /// How long a peer the host no longer lists keeps the key it announced.
    /// A key is therefore honoured at most `EVERY + UNLISTED_TTL` after the
    /// host last listed it: a compromised owner that is offline cannot be
    /// withdrawn by the host any faster, so this bounds it. The residual is
    /// that a peer unlisted for longer is refused until it announces again.
    pub const UNLISTED_TTL: Duration = Duration::from_secs(600);

    /// What this node knows: each peer's key, and when the host last listed
    /// that peer with it.
    #[derive(Default)]
    struct Known {
        keys: BTreeMap<String, String>,
        listed_at: BTreeMap<String, Instant>,
    }

    fn known() -> &'static Mutex<Known> {
        static KNOWN: OnceLock<Mutex<Known>> = OnceLock::new();
        KNOWN.get_or_init(|| Mutex::new(Known::default()))
    }

    /// Peer id to this plugin's announced key, as last read. Empty off a
    /// host without the capability.
    pub fn snapshot() -> BTreeMap<String, String> {
        known()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .clone()
    }

    /// Record `key` as announced for `peer`, as a host answer would: for
    /// tests that need a peer whose key this node knows.
    #[cfg(test)]
    pub fn announce_for_test(peer: &str, key: &str) {
        let mut known = known().lock().unwrap_or_else(PoisonError::into_inner);
        known.keys.insert(peer.to_string(), key.to_string());
        known.listed_at.insert(peer.to_string(), Instant::now());
    }

    /// The host's console API base: [`ENV_CONSOLE_URL`], or
    /// [`DEFAULT_CONSOLE_URL`].
    pub fn console_url() -> String {
        crate::settings::var(ENV_CONSOLE_URL)
            .ok()
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| DEFAULT_CONSOLE_URL.to_string())
    }

    fn is_key(key: &str) -> bool {
        key.len() == 64 && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Fold one `GET /api/plugin-keys` answer into `known`: this node's own
    /// key and each listed peer's key for `plugin`. A peer the answer lists
    /// without a key for `plugin` withdrew it, and is forgotten. A peer it
    /// does not list (no longer connected) keeps the key it announced until
    /// [`UNLISTED_TTL`] after the host last listed it with that key, then is
    /// forgotten: its binding was checked when received, but the host can
    /// no longer vouch for it, and an offline owner cannot be withdrawn.
    pub fn fold(
        known: &mut BTreeMap<String, String>,
        listed_at: &mut BTreeMap<String, Instant>,
        answer: &serde_json::Value,
        plugin: &str,
        now: Instant,
    ) {
        let mut listed: Vec<(&str, Option<&str>)> = Vec::new();
        if let Some(own) = answer.get("node_id").and_then(|v| v.as_str()) {
            listed.push((
                own,
                answer
                    .pointer(&format!("/plugin_keys/{plugin}"))
                    .and_then(|v| v.as_str()),
            ));
        }
        if let Some(peers) = answer.get("peers").and_then(|v| v.as_object()) {
            for (peer, keys) in peers {
                listed.push((peer.as_str(), keys.get(plugin).and_then(|v| v.as_str())));
            }
        }
        for (peer, key) in listed {
            if peer.is_empty() {
                continue;
            }
            match key.filter(|key| is_key(key)) {
                Some(key) => {
                    known.insert(peer.to_string(), key.to_string());
                    listed_at.insert(peer.to_string(), now);
                }
                None => {
                    known.remove(peer);
                    listed_at.remove(peer);
                }
            }
        }
        // A key with no listing time (never listed by this host) counts as
        // expired too.
        known.retain(|peer, _| {
            listed_at
                .get(peer)
                .is_some_and(|at| now.saturating_duration_since(*at) < UNLISTED_TTL)
        });
        listed_at.retain(|peer, _| known.contains_key(peer));
    }

    /// Start reading the host's announced keys, when `host_supports` says it
    /// has them; otherwise do nothing, and the operator's map alone applies.
    pub fn start(host_supports: bool, plugin: &'static str) {
        static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        if !host_supports {
            tracing::info!("the host announces no plugin keys; CAPSULES_PEER_KEYS alone applies");
            return;
        }
        let url = format!("{}{ROUTE}", console_url().trim_end_matches('/'));
        tokio::spawn(async move {
            let client = match reqwest::Client::builder().timeout(TIMEOUT).build() {
                Ok(client) => client,
                Err(error) => {
                    tracing::warn!(%error, "announced plugin keys are not read");
                    return;
                }
            };
            loop {
                match client.get(&url).send().await {
                    Ok(response) if response.status().is_success() => {
                        match response.json::<serde_json::Value>().await {
                            Ok(answer) => {
                                let mut guard =
                                    known().lock().unwrap_or_else(PoisonError::into_inner);
                                let Known { keys, listed_at } = &mut *guard;
                                fold(keys, listed_at, &answer, plugin, Instant::now());
                            }
                            Err(error) => {
                                tracing::debug!(%error, "unreadable announced plugin keys")
                            }
                        }
                    }
                    Ok(response) => {
                        tracing::debug!(status = %response.status(), "announced plugin keys not listed")
                    }
                    Err(error) => tracing::debug!(%error, "announced plugin keys not reachable"),
                }
                tokio::time::sleep(EVERY).await;
            }
        });
    }
}

/// This node's own key, announced by the host on this plugin's behalf, so a
/// peer reads it at its own `GET /api/plugin-keys` ([`announced`]) and can
/// check what this node pushes without `CAPSULES_PEER_KEYS` naming it.
pub mod own {
    /// What became of the announce.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Announced {
        /// The host took the key and announces it.
        Sent,
        /// The host does not list `plugin_keys.v1`: nothing was sent.
        HostLacksCapability,
        /// The host refused the key, or did not answer.
        Refused(String),
    }

    /// Ask the host to announce `public_key`, the raw Ed25519 key every
    /// record this node seals is signed with (its `key_id`). Public bytes
    /// only. `send` is the host call (`PluginContext::announce_plugin_key`).
    /// Off a host without the capability nothing is sent, and the node runs
    /// as before: peers then need `CAPSULES_PEER_KEYS` to name it.
    pub async fn announce<F, Fut, R, E>(
        host_supports: bool,
        public_key: [u8; 32],
        send: F,
    ) -> Announced
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Result<R, E>>,
        E: std::fmt::Display,
    {
        let key_id = hex::encode(public_key);
        if !host_supports || cfg!(feature = "mutant-own-key-not-announced") {
            tracing::info!(
                %key_id,
                "the host announces no plugin keys; this node's key was not announced"
            );
            return Announced::HostLacksCapability;
        }
        match send(public_key.to_vec()).await {
            Ok(_) => {
                tracing::info!(%key_id, "this node's key is announced by the host");
                Announced::Sent
            }
            Err(error) => {
                tracing::warn!(%key_id, %error, "this node's key was not announced");
                Announced::Refused(error.to_string())
            }
        }
    }
}

/// The `key_id` configured for `peer_id` in `registry`, the raw value of
/// [`ENV_PEER_KEYS`] (`None` when it is unset). `None` whenever the answer is
/// not a non-empty string: see the module doc.
pub fn announced_key_in(registry: Option<&str>, peer_id: &str) -> Option<String> {
    if peer_id.is_empty() {
        return None;
    }
    let raw = registry.filter(|raw| !raw.is_empty())?;
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    match parsed.as_object()?.get(peer_id)? {
        serde_json::Value::String(key_id) if !key_id.is_empty() => Some(key_id.clone()),
        _ => None,
    }
}

/// Every peer `registry` gives exactly `key_id`, in the registry's order.
/// Empty for an empty key, an unusable registry, or a key no entry gives.
pub fn peers_for_key_in(registry: Option<&str>, key_id: &str) -> Vec<String> {
    if key_id.is_empty() {
        return Vec::new();
    }
    let parsed = registry
        .filter(|raw| !raw.is_empty())
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
    let Some(serde_json::Value::Object(map)) = parsed else {
        return Vec::new();
    };
    map.into_iter()
        .filter(|(_, key)| key.as_str() == Some(key_id))
        .map(|(peer, _)| peer)
        .collect()
}

/// How a sender's evidence key came to be accepted (D-34): the identity a
/// node accepts is the key, and the peer id it arrived under is a hint.
/// Recorded beside what was accepted as provenance (`accepted_via`); nothing
/// gates on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptedVia {
    /// A host announced the key for some peer (`plugin_keys.v1`), and the
    /// operator's map gives that peer no other key.
    HostAnnounced,
    /// Only the operator's [`ENV_PEER_KEYS`] lists it: the stopgap for a
    /// node with no stable peer id, never a binding.
    OperatorStopgap,
    /// A carried controller declaration (`controller_binding`) binds it to
    /// `anchor_key`, a key accepted one of the other two ways.
    ControllerDeclaration {
        binding_digest: String,
        anchor_key: String,
    },
}

impl AcceptedVia {
    /// The recorded token.
    pub fn token(&self) -> &'static str {
        match self {
            AcceptedVia::HostAnnounced => "host_announced",
            AcceptedVia::OperatorStopgap => "operator_stopgap",
            AcceptedVia::ControllerDeclaration { .. } => "controller_declaration",
        }
    }
}

/// A key this node accepts, how, and the peers it is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub via: AcceptedVia,
    /// The peers the key (or, for a declaration, its anchor key) is bound to
    /// in the registry: the host's peers when a host announced it, else the
    /// operator's names for it. Never empty.
    pub peers: Vec<String>,
    /// The carried declaration, when it applies and binds the key, however
    /// the key was accepted: a sender's operator binding (loop step 12)
    /// rides beside a key its host announced too
    /// (Mesh-LLM/capsules-plugin#113). Recorded, never gated on.
    pub binding: Option<crate::controller_binding::Applied>,
}

/// Whether this node accepts `key_id`, from the operator's map
/// (`configured`, raw) and the host's announced keys, or through
/// `declaration`, a carried `controller-binding/0` record that applies at
/// `now` (no time: no declaration is used) and binds `key_id` to a key
/// accepted those ways. `own_key` (this node's) is never accepted, nor used
/// as a declaration's anchor, and a key
/// a carried declaration binds to it is not accepted however else it is
/// known ([`binds_to_own`]): it is this node's side, never a counterparty.
pub fn accepted_via(
    configured: Option<&str>,
    announced: &std::collections::BTreeMap<String, String>,
    key_id: &str,
    own_key: &str,
    declaration: Option<&serde_json::Value>,
    now: Option<evidence_request::time::UtcTime>,
) -> Option<Accepted> {
    let registry = merged(configured, announced);
    let direct = |key: &str| -> Option<Accepted> {
        if key == own_key {
            return None;
        }
        let peers = peers_for_key_in(registry.as_deref(), key);
        if peers.is_empty() {
            return None;
        }
        // A key a host announced is bound to the host's peers only: an
        // operator label never adds a second name to it.
        let hosted: Vec<String> = peers
            .iter()
            .filter(|p| announced.get(*p).map(String::as_str) == Some(key))
            .cloned()
            .collect();
        Some(if hosted.is_empty() {
            Accepted {
                via: AcceptedVia::OperatorStopgap,
                peers,
                binding: None,
            }
        } else {
            Accepted {
                via: AcceptedVia::HostAnnounced,
                peers: hosted,
                binding: None,
            }
        })
    };
    if key_id == own_key || binds_to_own(declaration, key_id, own_key, now) {
        return None;
    }
    let binding = declaration
        .zip(now)
        .and_then(|(declaration, now)| crate::controller_binding::applies(declaration, now))
        .filter(|applied| applied.other(key_id).is_some());
    if let Some(accepted) = direct(key_id) {
        return Some(Accepted {
            binding,
            ..accepted
        });
    }
    let applied = binding?;
    let anchor = applied.other(key_id)?.to_string();
    let anchored = direct(&anchor)?;
    Some(Accepted {
        via: AcceptedVia::ControllerDeclaration {
            binding_digest: applied.digest.clone(),
            anchor_key: anchor,
        },
        peers: anchored.peers,
        binding: Some(applied),
    })
}

/// Whether `declaration` is a controller declaration that applies at `now`
/// and binds `key_id` to `own_key`, this node's own key. Its holders signed
/// that the two keys have one controller (CB v0 §6.2): a key so bound is
/// this node's side, so it is accepted from no one, however else it is
/// known.
pub fn binds_to_own(
    declaration: Option<&serde_json::Value>,
    key_id: &str,
    own_key: &str,
    now: Option<evidence_request::time::UtcTime>,
) -> bool {
    let (Some(declaration), Some(now)) = (declaration, now) else {
        return false;
    };
    !own_key.is_empty()
        && crate::controller_binding::applies(declaration, now)
            .is_some_and(|applied| applied.other(key_id) == Some(own_key))
}

/// The one announced peer whose key is `key_id` in `registry`: this node's
/// own id from its own key. `None` when no peer, or more than one, announces
/// it: never a guess.
pub fn peer_id_for_key_in(registry: Option<&str>, key_id: &str) -> Option<String> {
    if key_id.is_empty() {
        return None;
    }
    let raw = registry.filter(|raw| !raw.is_empty())?;
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    let mut named = parsed
        .as_object()?
        .iter()
        .filter(|(_, key)| key.as_str() == Some(key_id))
        .map(|(peer, _)| peer.clone());
    match (named.next(), named.next()) {
        (Some(peer), None) => Some(peer),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_configured_non_empty_string_is_an_announced_key() {
        let registry = r#"{"node-a": "ab", "node-b": "", "node-c": 7}"#;
        assert_eq!(
            announced_key_in(Some(registry), "node-a").as_deref(),
            Some("ab")
        );
        assert_eq!(
            announced_key_in(Some(registry), "node-b"),
            None,
            "empty key"
        );
        assert_eq!(
            announced_key_in(Some(registry), "node-c"),
            None,
            "not a string"
        );
        assert_eq!(announced_key_in(Some(registry), "m9"), None, "unknown peer");
        assert_eq!(announced_key_in(Some(registry), ""), None, "no peer id");
        assert_eq!(announced_key_in(None, "node-a"), None, "unset");
        assert_eq!(announced_key_in(Some(""), "node-a"), None, "empty");
        assert_eq!(
            announced_key_in(Some("{node-a:"), "node-a"),
            None,
            "not JSON"
        );
        assert_eq!(
            announced_key_in(Some(r#"["ab"]"#), "node-a"),
            None,
            "not an object"
        );
    }

    /// D-34: a key is accepted by what it is, under any peer id, and the
    /// way it was accepted is said. A disagreeing operator entry vetoes,
    /// and this node's own key is never a sender's.
    #[test]
    fn a_key_is_accepted_by_value_and_says_how() {
        let now = evidence_request::time::parse_utc("2026-10-28T00:00:00Z");
        let own = "ee".repeat(32);
        let accept = |configured: Option<&str>, announced: &[(&str, &str)], key: &str| {
            accepted_via(configured, &keys_of(announced), key, &own, None, now)
        };
        let host = accept(None, &[("node-a", KA)], KA).unwrap();
        assert_eq!(host.via, AcceptedVia::HostAnnounced);
        assert_eq!(host.peers, ["node-a"]);
        let stopgap = accept(Some(&format!(r#"{{"muse-vm": "{KA}"}}"#)), &[], KA).unwrap();
        assert_eq!(stopgap.via, AcceptedVia::OperatorStopgap);
        assert_eq!(stopgap.peers, ["muse-vm"]);
        let both = accept(
            Some(&format!(r#"{{"node-a": "{KA}"}}"#)),
            &[("node-a", KA), ("node-a-2", KA)],
            KA,
        )
        .unwrap();
        assert_eq!(
            both.via,
            AcceptedVia::HostAnnounced,
            "a host binding wins the label"
        );
        assert_eq!(both.peers, ["node-a", "node-a-2"]);
        let labelled = accept(
            Some(&format!(r#"{{"my-label": "{KA}"}}"#)),
            &[("node-a", KA)],
            KA,
        )
        .unwrap();
        assert_eq!(
            labelled.peers,
            ["node-a"],
            "a label adds no name to a hosted key"
        );
        assert_eq!(accept(None, &[("node-a", KA)], KB), None, "unknown key");
        assert_eq!(
            accept(
                Some(&format!(r#"{{"node-a": "{KB}"}}"#)),
                &[("node-a", KA)],
                KA
            ),
            None,
            "a disagreeing entry vetoes"
        );
        assert_eq!(
            accept(Some("{node-a:"), &[("node-a", KA)], KA),
            None,
            "unusable map"
        );
        assert_eq!(accept(None, &[("self", &own)], &own), None, "own key");
        assert_eq!(accept(None, &[("node-a", KA)], ""), None, "no key");
    }

    /// A declaration carries acceptance from an accepted key to the other
    /// key it binds, never from this node's own key, and only with a time.
    #[test]
    fn a_declaration_extends_acceptance_from_an_accepted_key_only() {
        use ed25519_dalek::SigningKey;
        let now = evidence_request::time::parse_utc("2026-10-28T00:00:00Z");
        let (anchor, member, own) = (
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
            SigningKey::from_bytes(&[3; 32]),
        );
        let hex_of = |k: &SigningKey| hex::encode(k.verifying_key().to_bytes());
        let (ka, km, ko) = (hex_of(&anchor), hex_of(&member), hex_of(&own));
        let binding = crate::controller_binding::bind_for_test(
            &anchor,
            &member,
            "2026-10-01T00:00:00Z",
            "2027-10-01T00:00:00Z",
        );
        let configured = format!(r#"{{"muse-controller": "{ka}"}}"#);
        let none = keys_of(&[]);
        let got = accepted_via(Some(&configured), &none, &km, &ko, Some(&binding), now).unwrap();
        assert_eq!(got.peers, ["muse-controller"]);
        let AcceptedVia::ControllerDeclaration {
            binding_digest,
            anchor_key,
        } = got.via
        else {
            panic!("a declaration");
        };
        assert_eq!(anchor_key, ka);
        assert_eq!(binding_digest.len(), 64);
        assert_eq!(
            accepted_via(Some(&configured), &none, &km, &ko, Some(&binding), None),
            None,
            "no time, no declaration"
        );
        assert_eq!(
            accepted_via(None, &none, &km, &ko, Some(&binding), now),
            None,
            "an anchor nobody accepts"
        );
        let on_own = crate::controller_binding::bind_for_test(
            &own,
            &member,
            "2026-10-01T00:00:00Z",
            "2027-10-01T00:00:00Z",
        );
        let with_self = keys_of(&[("self", ko.as_str())]);
        assert_eq!(
            accepted_via(None, &with_self, &km, &ko, Some(&on_own), now),
            None,
            "anchored on this node's own key"
        );
        let member_announced = keys_of(&[("self", ko.as_str()), ("node-m", km.as_str())]);
        assert!(accepted_via(None, &member_announced, &km, &ko, None, now).is_some());
        assert_eq!(
            accepted_via(None, &member_announced, &km, &ko, Some(&on_own), now),
            None,
            "a known key declared one controller with this node is refused"
        );
    }

    #[test]
    fn a_key_names_a_peer_only_when_exactly_one_announces_it() {
        let registry = r#"{"node-a": "ab", "node-b": "cd", "node-c": "cd"}"#;
        assert_eq!(
            peer_id_for_key_in(Some(registry), "ab").as_deref(),
            Some("node-a")
        );
        assert_eq!(
            peer_id_for_key_in(Some(registry), "cd"),
            None,
            "two peers announce it"
        );
        assert_eq!(
            peer_id_for_key_in(Some(registry), "ef"),
            None,
            "nobody announces it"
        );
        assert_eq!(peer_id_for_key_in(Some(registry), ""), None, "no key");
        assert_eq!(peer_id_for_key_in(None, "ab"), None, "unset");
    }

    fn keys_of(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(p, k)| (p.to_string(), k.to_string()))
            .collect()
    }

    const KA: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const KB: &str = "bb00000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn announced_keys_fill_in_beside_the_operator_map() {
        let registry = merged(
            Some(&format!(r#"{{"node-a": "{KA}"}}"#)),
            &keys_of(&[("node-b", KB)]),
        );
        assert_eq!(
            announced_key_in(registry.as_deref(), "node-a").as_deref(),
            Some(KA)
        );
        assert_eq!(
            announced_key_in(registry.as_deref(), "node-b").as_deref(),
            Some(KB)
        );
        let alone = merged(None, &keys_of(&[("node-b", KB)]));
        assert_eq!(
            announced_key_in(alone.as_deref(), "node-b").as_deref(),
            Some(KB),
            "no operator map"
        );
        assert_eq!(merged(None, &keys_of(&[])), None, "nothing from either");
    }

    #[test]
    fn two_sources_that_disagree_about_a_peer_verify_nothing_for_it() {
        let registry = merged(
            Some(&format!(r#"{{"node-a": "{KA}", "node-b": "{KB}"}}"#)),
            &keys_of(&[("node-a", KB), ("node-b", KB)]),
        );
        assert_eq!(
            announced_key_in(registry.as_deref(), "node-a"),
            None,
            "disagree"
        );
        assert_eq!(
            announced_key_in(registry.as_deref(), "node-b").as_deref(),
            Some(KB),
            "agree"
        );
        assert_eq!(
            peer_id_for_key_in(registry.as_deref(), KA),
            None,
            "the stale key names nobody"
        );
    }

    #[test]
    fn an_unusable_operator_map_stays_unusable_beside_announced_keys() {
        let registry = merged(Some("{node-a:"), &keys_of(&[("node-b", KB)]));
        assert_eq!(announced_key_in(registry.as_deref(), "node-b"), None);
    }

    #[test]
    fn the_hosts_answer_folds_in_own_and_peer_keys_for_this_plugin_only() {
        let mut known = keys_of(&[("gone", KA), ("withdrew", KA)]);
        let now = std::time::Instant::now();
        let mut listed_at: std::collections::BTreeMap<_, _> = ["gone", "withdrew"]
            .iter()
            .map(|peer| (peer.to_string(), now))
            .collect();
        let answer = serde_json::json!({
            "node_id": "self",
            "plugin_keys": {"capsules": KA, "other": KB},
            "peers": {
                "node-b": {"capsules": KB},
                "node-c": {"other": KB},
                "withdrew": {},
                "short": {"capsules": "ab"},
            }
        });
        announced::fold(&mut known, &mut listed_at, &answer, "capsules", now);
        assert_eq!(
            known,
            keys_of(&[("gone", KA), ("node-b", KB), ("self", KA)]),
            "own key in; a peer with another plugin's key only, a withdrawn key and a malformed key out; \
             a peer no longer listed keeps the key it announced within the TTL"
        );
    }

    #[test]
    fn an_unlisted_peers_key_expires_after_the_ttl_and_a_listed_one_does_not() {
        use std::time::Instant;
        let t0 = Instant::now();
        let mut known = std::collections::BTreeMap::new();
        let mut listed_at = std::collections::BTreeMap::new();
        let both = serde_json::json!({"node_id": "self", "peers": {
            "offline": {"capsules": KA}, "online": {"capsules": KB}}});
        announced::fold(&mut known, &mut listed_at, &both, "capsules", t0);
        assert_eq!(known.len(), 2);
        // The host keeps listing `online` and stops listing `offline`.
        let only_online = serde_json::json!({"node_id": "self", "peers": {
            "online": {"capsules": KB}}});
        let before = t0 + announced::UNLISTED_TTL - std::time::Duration::from_secs(1);
        announced::fold(&mut known, &mut listed_at, &only_online, "capsules", before);
        assert_eq!(
            known,
            keys_of(&[("offline", KA), ("online", KB)]),
            "within the TTL"
        );
        let after = t0 + announced::UNLISTED_TTL;
        announced::fold(&mut known, &mut listed_at, &only_online, "capsules", after);
        assert_eq!(
            known,
            keys_of(&[("online", KB)]),
            "the unlisted key expired"
        );
        // A returning peer is refused until the host lists it again.
        announced::fold(&mut known, &mut listed_at, &both, "capsules", after);
        assert_eq!(
            known,
            keys_of(&[("offline", KA), ("online", KB)]),
            "re-announced"
        );
    }

    /// What `own::announce` handed the host, if anything, and its outcome.
    async fn announce_capturing(
        host_supports: bool,
        public_key: [u8; 32],
        host_answer: Result<(), &str>,
    ) -> (own::Announced, Option<Vec<u8>>) {
        let mut sent = None;
        let announced = own::announce(host_supports, public_key, |bytes| {
            sent = Some(bytes);
            async move { host_answer }
        })
        .await;
        (announced, sent)
    }

    /// A node, as a peer's receiver sees it after one push: its own state
    /// (keys and all) in a scratch directory, and the corpus's verified
    /// bare half sealed again with that node's key, so the half is one this
    /// node signed.
    struct Sender {
        _dir: tempfile::TempDir,
        state: crate::capsule_emit::CapsuleState,
        peer_id: String,
        body: Vec<u8>,
    }

    fn sender() -> Sender {
        use crate::record_push_parity::{body_bytes, parity_dir, read_json};
        let corpus = read_json(&parity_dir().join("corpus/record_push.json"));
        let push = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "bare_valid")
            .expect("corpus case bare_valid")["pushes"][0]
            .clone();
        let dir = tempfile::tempdir().unwrap();
        let state = crate::capsule_emit::CapsuleState::open(dir.path(), "sender").unwrap();
        let body = sealed_by(&body_bytes(&push), state.signing_key());
        Sender {
            _dir: dir,
            state,
            peer_id: push["sender"].as_str().unwrap().to_string(),
            body,
        }
    }

    /// The half in `body`, sealed again with `key`: what that key's holder
    /// can push.
    fn sealed_by(body: &[u8], key: &ed25519_dalek::SigningKey) -> Vec<u8> {
        let mut half: serde_json::Value = serde_json::from_slice(body).unwrap();
        half["capsule_id"] =
            serde_json::json!(capsule_emit_lib::jcs::compute_capsule_id(&half).unwrap());
        capsule_emit_lib::capsule::attach_producer_envelope(&mut half, key).unwrap();
        half.to_string().into_bytes()
    }

    /// `sender`'s push, received by a node whose registry is `registry`:
    /// `Ok(())` when it is held, else the refusal reason.
    fn push(sender: &Sender, registry: Option<&str>) -> Result<(), String> {
        push_body(&sender.peer_id, &sender.body, registry)
    }

    /// `body`, pushed by `peer_id` to a node whose registry is `registry`.
    fn push_body(peer_id: &str, body: &[u8], registry: Option<&str>) -> Result<(), String> {
        use crate::record_push_receive::{receive, Receiver, MAX_REJECTED_LOG_BYTES};
        let dir = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let receiver = Receiver {
            ledger_dir: dir.path(),
            signing_key: &key,
            peer_keys: registry,
            record_at_completion_off: false,
            rejected_log_limit: MAX_REJECTED_LOG_BYTES,
            announced: crate::peer_keys::NONE_ANNOUNCED,
        };
        let reply = receive(&receiver, body, Some(peer_id), "2026-10-12T00:00:00Z").unwrap();
        match reply["reason"].as_str() {
            Some(reason) => Err(reason.to_string()),
            None => {
                assert_eq!(reply["status"], "received", "{reply}");
                Ok(())
            }
        }
    }

    /// The sender announces its key, its host lists it to the receiver's host
    /// as the sender's key for this plugin (`GET /api/plugin-keys`), and the
    /// receiver folds it in: its registry, with no `CAPSULES_PEER_KEYS`.
    async fn registry_after_announce(sender: &Sender) -> Option<String> {
        let (_, sent) = announce_capturing(true, sender.state.public_key(), Ok(())).await;
        let mut known = std::collections::BTreeMap::new();
        let mut listed_at = std::collections::BTreeMap::new();
        if let Some(bytes) = sent {
            let answer = serde_json::json!({
                "node_id": "receiver",
                "plugin_keys": {},
                "peers": {&sender.peer_id: {crate::PLUGIN_ID: hex::encode(bytes)}},
            });
            announced::fold(
                &mut known,
                &mut listed_at,
                &answer,
                crate::PLUGIN_ID,
                std::time::Instant::now(),
            );
        }
        merged(None, &known)
    }

    #[tokio::test]
    async fn the_announce_carries_the_key_this_nodes_records_verify_against() {
        let sender = sender();
        let (announced, sent) = announce_capturing(true, sender.state.public_key(), Ok(())).await;
        assert_eq!(announced, own::Announced::Sent);
        let sent = sent.expect("the key was handed to the host");
        let half: serde_json::Value = serde_json::from_slice(&sender.body).unwrap();
        assert_eq!(
            Some(hex::encode(&sent).as_str()),
            half["key_id"].as_str(),
            "the announced bytes are the key_id a sealed record carries"
        );
        assert_eq!(
            sent,
            sender.state.signing_key().verifying_key().to_bytes(),
            "public bytes only, never the private key"
        );
    }

    #[tokio::test]
    async fn a_peers_announced_key_verifies_its_pushed_half_with_no_configured_keys() {
        let sender = sender();
        assert_eq!(
            push(&sender, None),
            Err(crate::record_push_receive::REASON_SIGNATURE_UNVERIFIED.to_string()),
            "no registry at all: the push is unverified"
        );
        let registry = registry_after_announce(&sender).await;
        assert_eq!(push(&sender, registry.as_deref()), Ok(()));
    }

    #[tokio::test]
    async fn an_announced_key_that_disagrees_with_the_configured_one_verifies_nothing() {
        let sender = sender();
        let stale_key = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let stale_body = sealed_by(&sender.body, &stale_key);
        let configured = serde_json::json!({
            &sender.peer_id: hex::encode(stale_key.verifying_key().to_bytes()),
        })
        .to_string();
        assert_eq!(
            push_body(&sender.peer_id, &stale_body, Some(&configured)),
            Ok(()),
            "the configured key alone verifies the half its holder sealed"
        );
        let announced: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&registry_after_announce(&sender).await.expect("announced"))
                .unwrap();
        let registry = merged(Some(&configured), &announced);
        assert_eq!(
            push(&sender, registry.as_deref()),
            Err(crate::record_push_receive::REASON_SIGNATURE_UNVERIFIED.to_string()),
            "the announced key does not win"
        );
        assert_eq!(
            push_body(&sender.peer_id, &stale_body, registry.as_deref()),
            Err(crate::record_push_receive::REASON_SIGNATURE_UNVERIFIED.to_string()),
            "the configured key does not win"
        );
    }

    #[tokio::test]
    async fn a_host_without_the_capability_is_sent_nothing_and_a_refusal_is_returned() {
        let (announced, sent) = announce_capturing(false, [3; 32], Ok(())).await;
        assert_eq!(announced, own::Announced::HostLacksCapability);
        assert_eq!(sent, None, "nothing is sent to an older host");
        let (announced, sent) = announce_capturing(true, [3; 32], Err("not a key")).await;
        assert_eq!(announced, own::Announced::Refused("not a key".into()));
        assert!(sent.is_some());
    }
}
