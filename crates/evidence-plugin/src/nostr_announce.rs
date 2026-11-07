//! The Nostr carrier of this node's commitment (loop step 3, Advertise;
//! Mesh-LLM/capsules-plugin#212): when `advertise_evidence_requests` is on,
//! the signed `evidence-commitment/1` is published as one addressable event
//! to the relays the commitment itself lists. Everything about the event
//! follows `spec/bindings/evidence-commitment-carriers-v0.md` §3 and §5.3 of
//! agent-action-capsule (cited here as ECC); this module invents no format.
//!
//! **Off by default.** With the switch off nothing is published, no mailbox
//! key is made and the commitment has no `ask.nostr` member. Publishing is
//! the operator's opt-in disclosure (ECC §1): a stranger who finds the event
//! learns what the commitment says and nothing else.
//!
//! **The route.** The commitment's `ask.nostr` member is `{mailbox_key,
//! relays}` (ECC §3). The mailbox key is a secp256k1 BIP-340 key this plugin
//! makes on first use and keeps in [`KEY_FILE`] in the data directory, owner
//! readable only. It is not the node's Ed25519 key and not the operator's
//! Nostr key (the controller binding names that one): it signs the announce
//! event and nothing else. The relays are mesh-llm's own discovery relays
//! ([`DEFAULT_RELAYS`], the list in mesh-client's `network/nostr.rs`) unless
//! [`ENV_RELAYS`] names others.
//!
//! **The event** (ECC §5.3): kind [`KIND`] (a placeholder in NIP-01's
//! addressable range, so a relay keeps only the newest per mailbox key and
//! `d`), tags `d` = node id, `t` = `evidence-commitment`, `x` = SHA-256 of
//! the commitment octets, and the octets in base64url without padding as
//! content. A relay that caps events below that size gets the same event
//! with empty content and the `x` tag: never an edited commitment, whose
//! signature would fail. The plugin hosts no URI, so it adds no `r` tag.
//!
//! **Republishing.** [`tick`] runs once a minute. A relay that accepted this
//! commitment is left alone; a changed commitment goes to every relay again,
//! and a relay that did not accept is tried again after [`RETRY_AFTER`].
//! [`status`] is what `doctor` shows: the last result
//! per relay, `accepted`, `rejected` or `unreachable`.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use k256::schnorr::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The placeholder addressable kind of the announce event (ECC §5.3).
pub const KIND: u64 = 34700;

/// The `t` tag's value, and the filter a stranger subscribes with.
pub const TAG_T: &str = "evidence-commitment";

/// The relays mesh-llm's own `discover` uses (mesh-client
/// `network/nostr.rs`, `DEFAULT_RELAYS`), in its written form.
pub const DEFAULT_RELAYS: [&str; 5] = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
    "wss://nostr.land",
    "wss://nostr.wine",
];

/// A comma or space separated list of `wss://` relays that replaces
/// [`DEFAULT_RELAYS`].
pub const ENV_RELAYS: &str = "CAPSULES_NOSTR_RELAYS";

/// The mailbox key, 64 hex and a newline, in the data directory.
pub const KEY_FILE: &str = "nostr-mailbox.key";

/// The mailbox public key of the last accepted publish, kept so a lost or
/// replaced key file is noticed (`key_change`).
pub const LAST_FILE: &str = "nostr-mailbox.published";

/// What `doctor` says whenever the route is on: the route is announce-only.
pub const ANNOUNCE_ONLY: &str = "announce-only: this node publishes where to find it and does not \
    read the Nostr mailbox, so an ask sent there is not answered until loop#305 lands; do not send one";

/// A relay that did not accept is tried again after this long.
pub const RETRY_AFTER: Duration = Duration::from_secs(300);

/// How long [`announce`] waits for all relays together.
const ANNOUNCE_DEADLINE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 30 });

/// The most one connection lives, handshake included: at this point its
/// socket is shut down, so a relay that drips bytes cannot keep a thread.
const CONNECTION_LIFETIME: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 20 });

/// The relays a worker thread is still on, so a stalled relay never has two.
static IN_FLIGHT: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Removes its relay from [`IN_FLIGHT`] when the worker ends.
struct Flight(String);

impl Drop for Flight {
    fn drop(&mut self) {
        lock(&IN_FLIGHT).retain(|u| *u != self.0);
    }
}

/// How long one relay gets to connect, accept the event and answer.
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------
// The route: the mailbox key and the relays
// ---------------------------------------------------------------------

/// `ask.nostr` of the commitment (ECC §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The mailbox key, BIP-340 x-only, 64 lowercase hex.
    pub mailbox_key: String,
    pub relays: Vec<String>,
}

impl Route {
    pub fn to_json(&self) -> Value {
        json!({"mailbox_key": self.mailbox_key, "relays": self.relays})
    }
}

/// The route this node advertises, or `None` when `advertise` is off. Makes
/// the mailbox key the first time it is needed. An `Err` is a reason the
/// node cannot advertise (a relay list that is not valid, a key file that
/// cannot be read): the commitment is then served without a route and the
/// reason is shown by `doctor`.
pub fn route(data_dir: &Path, advertise: bool) -> Result<Option<Route>, String> {
    if !advertise {
        return Ok(None);
    }
    let relays = relays(crate::settings::var(ENV_RELAYS).ok().as_deref())?;
    let key = mailbox_key(data_dir)?;
    Ok(Some(Route {
        mailbox_key: hex::encode(key.verifying_key().to_bytes()),
        relays,
    }))
}

/// The relays `raw` names, or [`DEFAULT_RELAYS`] when it names none.
pub fn relays(raw: Option<&str>) -> Result<Vec<String>, String> {
    let named: Vec<&str> = raw
        .unwrap_or_default()
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();
    if named.is_empty() {
        return Ok(DEFAULT_RELAYS.map(String::from).to_vec());
    }
    let mut out: Vec<String> = Vec::new();
    for url in named {
        if let Some(why) = relay_error(url) {
            return Err(format!("{ENV_RELAYS}: {url} {why}"));
        }
        if out.iter().any(|seen| seen == url) {
            return Err(format!("{ENV_RELAYS}: {url} is listed twice"));
        }
        out.push(url.to_string());
    }
    Ok(out)
}

/// Why `url` is not a relay URL in the one written form loop's
/// `check_commitment.py` accepts: `wss://`, a lowercase DNS name or a
/// bracketed compressed IPv6 literal, an optional port that is not 443 and
/// an optional path that is not a bare `/`.
pub fn relay_error(url: &str) -> Option<&'static str> {
    const FORM: &str =
        "is not wss://host[:port][/path] with a lowercase host, and no credentials, query or fragment";
    let Some(rest) = url.strip_prefix("wss://") else {
        return Some(FORM);
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    let (host, port) = if let Some(end) = authority.find(']') {
        let (host, tail) = authority.split_at(end + 1);
        match tail {
            "" => (host, None),
            t if t.starts_with(':') => (host, Some(&t[1..])),
            _ => return Some(FORM),
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let host_ok = if let Some(literal) = host.strip_prefix('[') {
        let Some(literal) = literal.strip_suffix(']') else {
            return Some(FORM);
        };
        match literal.parse::<std::net::Ipv6Addr>() {
            Ok(addr) if addr.to_string() == literal => true,
            Ok(_) => return Some("writes its IPv6 literal other than in its compressed form"),
            Err(_) => return Some("has a host that is not an IPv6 literal"),
        }
    } else {
        !host.is_empty()
            && host.split('.').all(|label| {
                let b = label.as_bytes();
                !b.is_empty()
                    && b.iter()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                    && b[0] != b'-'
                    && b[b.len() - 1] != b'-'
            })
    };
    if !host_ok {
        return Some(FORM);
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) || port.starts_with('0') {
            return Some(FORM);
        }
        match port.parse::<u32>() {
            Ok(p) if p > 65535 => return Some("has a port above 65535"),
            Ok(443) => return Some("names the default port 443; leave it out"),
            Ok(_) => {}
            Err(_) => return Some(FORM),
        }
    }
    if let Some(path) = path {
        if path == "/" {
            return Some("ends in a bare /; leave it out");
        }
        let allowed = |c: u8| c.is_ascii_alphanumeric() || b"._~!$&'()*+,;=:@%/-".contains(&c);
        if !path.bytes().all(allowed) {
            return Some(FORM);
        }
    }
    None
}

/// What is wrong with a received `ask.nostr` member, as loop's checker words
/// it: exactly `{mailbox_key, relays}`, both required.
pub fn route_problems(route: &Value) -> Vec<String> {
    let Some(map) = route.as_object() else {
        return vec!["ask.nostr must be an object".into()];
    };
    let mut problems: Vec<String> = ["mailbox_key", "relays"]
        .iter()
        .filter(|m| !map.contains_key(**m))
        .map(|m| format!("missing ask.nostr.{m}"))
        .collect();
    problems.extend(
        map.keys()
            .filter(|k| !["mailbox_key", "relays"].contains(&k.as_str()))
            .map(|k| format!("unknown field ask.nostr.{k}")),
    );
    if !problems.is_empty() {
        return problems;
    }
    match route["mailbox_key"].as_str() {
        Some(key) if is_xonly_key(key) => {}
        _ => problems
            .push("ask.nostr.mailbox_key is not a secp256k1 x-only key (64 lowercase hex)".into()),
    }
    match route["relays"].as_array() {
        Some(list) if !list.is_empty() => {
            let mut seen: Vec<&str> = Vec::new();
            for (i, url) in list.iter().enumerate() {
                match url.as_str() {
                    None => problems.push(format!("ask.nostr.relays[{i}] is not a string")),
                    Some(url) => match relay_error(url) {
                        Some(why) => problems.push(format!("ask.nostr.relays[{i}] {why}")),
                        None if seen.contains(&url) => {
                            problems.push(format!("ask.nostr.relays[{i}] repeats an earlier relay"))
                        }
                        None => seen.push(url),
                    },
                }
            }
        }
        Some(_) => problems.push("ask.nostr.relays must list at least one relay".into()),
        None => problems.push("ask.nostr.relays must be a list".into()),
    }
    problems
}

fn is_xonly_key(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && hex::decode(text)
            .ok()
            .is_some_and(|raw| k256::schnorr::VerifyingKey::from_bytes(&raw).is_ok())
}

/// The mailbox key in `data_dir`, made and kept there on first use. Two
/// first uses at once end with one key: the file is linked into place, never
/// overwritten.
pub fn mailbox_key(data_dir: &Path) -> Result<SigningKey, String> {
    let path = data_dir.join(KEY_FILE);
    if let Some(key) = read_key(&path)? {
        return Ok(key);
    }
    let key = loop {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("no random source: {e}"))?;
        if let Ok(key) = SigningKey::from_bytes(&seed) {
            break key;
        }
    };
    // A staging file of its own per call, removed whether or not it was
    // written, so a failed write never blocks the next try and two first
    // uses at once do not meet in one file.
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix).map_err(|e| format!("no random source: {e}"))?;
    let staged = data_dir.join(format!("{KEY_FILE}.{}.tmp", hex::encode(suffix)));
    let written = write_private(&staged, &format!("{}\n", hex::encode(key.to_bytes())));
    let linked = written
        .map_err(|e| format!("could not write the mailbox key: {e}"))
        .map(|()| std::fs::hard_link(&staged, &path));
    let _ = std::fs::remove_file(&staged);
    let linked = linked?;
    match linked {
        Ok(()) => Ok(key),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            read_key(&path)?.ok_or_else(|| "the mailbox key file vanished".to_string())
        }
        Err(e) => Err(format!("could not keep the mailbox key: {e}")),
    }
}

fn read_key(path: &Path) -> Result<Option<SigningKey>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
    };
    let raw = hex::decode(text.trim()).map_err(|_| format!("{} is not hex", path.display()))?;
    SigningKey::from_bytes(&raw)
        .map(Some)
        .map_err(|_| format!("{} is not a secp256k1 key", path.display()))
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // Owner-only and never through a link on Unix; elsewhere the data
    // directory's own access rules apply, as for the node's other keys.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

/// The note `doctor` shows when the mailbox key is not the one the last
/// accepted publish used: a key file that was lost or replaced makes a new
/// key (`mailbox_key`), whose commitment goes to every relay again. The
/// events the old key signed stay on the relays; a verifier takes the newest
/// commitment per node (ECC V4), so they are stale, not wrong.
pub fn key_change(data_dir: &Path, current: &str) -> Option<String> {
    let old = std::fs::read_to_string(data_dir.join(LAST_FILE)).ok()?;
    let old = old.trim();
    (old != current).then(|| {
        format!(
            "the mailbox key changed from {old} to {current} (the key file was lost or replaced): \
             the commitment names the new key and is published again under it; events signed by \
             {old} stay on the relays until they expire and are older commitments"
        )
    })
}

fn note_published(data_dir: &Path, current: &str) {
    let _ = std::fs::write(data_dir.join(LAST_FILE), format!("{current}\n"));
}

// ---------------------------------------------------------------------
// The event
// ---------------------------------------------------------------------

/// The commitment octets as published: the commitment object's JSON, whole.
pub fn octets(commitment: &Value) -> Vec<u8> {
    serde_json::to_vec(commitment).expect("a JSON value serializes")
}

/// The announce event (ECC §5.3) for `octets`, signed by `key`. With
/// `inline` false the content is empty and only the `x` tag names the
/// commitment (ECC §5.3, Size).
pub fn event(key: &SigningKey, node_id: &str, octets: &[u8], inline: bool, at: i64) -> Value {
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let tags = json!([
        ["d", node_id],
        ["t", TAG_T],
        ["x", hex::encode(Sha256::digest(octets))],
    ]);
    let content = if inline {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(octets)
    } else {
        String::new()
    };
    // NIP-01: the id is the SHA-256 of this exact serialization.
    let serial = serde_json::to_string(&json!([0, pubkey, at, KIND, tags, content]))
        .expect("a JSON value serializes");
    let id = Sha256::digest(serial.as_bytes());
    let mut aux = [0u8; 32];
    getrandom::getrandom(&mut aux).expect("the OS random source is available");
    let sig = key.sign_raw(&id, &aux).expect("a 32 byte message signs");
    json!({
        "id": hex::encode(id),
        "pubkey": pubkey,
        "created_at": at,
        "kind": KIND,
        "tags": tags,
        "content": content,
        "sig": hex::encode(sig.to_bytes()),
    })
}

// ---------------------------------------------------------------------
// Publishing to one relay
// ---------------------------------------------------------------------

/// What one relay said to the event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    /// The relay answered and refused, with its words.
    Rejected(String),
    /// No answer: it could not be reached, or it closed or timed out.
    Unreachable(String),
}

/// Whether a refusal says the event was too large for the relay.
fn says_too_large(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    [
        "too large",
        "too big",
        "too long",
        "max_message",
        "max message",
        "size",
        "exceed",
    ]
    .iter()
    .any(|w| reason.contains(w))
}

/// Publish the commitment to `url`: the whole commitment first, and the
/// digest alone when the relay says that is too large (its NIP-11 limit, or
/// its refusal, or a connection it closes on the long message).
pub fn publish_to(url: &str, key: &SigningKey, node_id: &str, octets: &[u8], at: i64) -> Outcome {
    let full = event(key, node_id, octets, true, at);
    let size = serde_json::to_vec(&full).map_or(usize::MAX, |b| b.len());
    let capped = relay_limit(url).is_some_and(|max| size > max);
    if !capped {
        match send_event(url, &full) {
            Outcome::Rejected(why) if says_too_large(&why) => {}
            // A relay that closes or drops the connection on a message it
            // finds too long says little: try the digest alone once.
            Outcome::Unreachable(_) => {}
            other => return other,
        }
    }
    send_event(url, &event(key, node_id, octets, false, at))
}

/// The relay's `max_message_length` from its NIP-11 document, when it gives
/// one: a plain GET of the same host over https, with the NIP-11 `Accept`.
fn relay_limit(url: &str) -> Option<usize> {
    let http = url.replacen("wss://", "https://", 1);
    let doc: Value = ureq::get(&http)
        .set("Accept", "application/nostr+json")
        .timeout(Duration::from_secs(5))
        .call()
        .ok()?
        .into_json()
        .ok()?;
    doc["limitation"]["max_message_length"]
        .as_u64()
        .map(|n| n as usize)
}

/// One `["EVENT", event]` and the relay's `["OK", ...]` for it.
fn send_event(url: &str, event: &Value) -> Outcome {
    let started = Instant::now();
    let (mut socket, deadline) = match connect(url) {
        Ok(pair) => pair,
        Err(why) => return Outcome::Unreachable(why),
    };
    let wanted = event["id"].as_str().unwrap_or_default().to_string();
    let frame = json!(["EVENT", event]).to_string();
    if let Err(e) = socket.send(tungstenite::Message::text(frame)) {
        return Outcome::Unreachable(format!("could not send: {e}"));
    }
    let outcome = loop {
        if started.elapsed() > RELAY_TIMEOUT {
            break Outcome::Unreachable("no answer in time".into());
        }
        // The time left, on the socket, so a relay that sends slowly cannot
        // stretch one read past the deadline.
        let left = RELAY_TIMEOUT
            .saturating_sub(started.elapsed())
            .max(Duration::from_millis(50));
        deadline.set_read_timeout(Some(left)).ok();
        let message = match socket.read() {
            Ok(m) => m,
            Err(e) => break Outcome::Unreachable(format!("closed before it answered: {e}")),
        };
        let text = match message {
            tungstenite::Message::Text(text) => text,
            tungstenite::Message::Close(frame) => {
                let said = frame.map_or("no reason".to_string(), |f| {
                    format!("{:?}: {}", f.code, f.reason)
                });
                break Outcome::Unreachable(format!("the relay closed the connection: {said}"));
            }
            _ => continue,
        };
        let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if parts.first().and_then(Value::as_str) == Some("OK")
            && parts.get(1).and_then(Value::as_str) == Some(wanted.as_str())
        {
            let said = parts.get(3).and_then(Value::as_str).unwrap_or_default();
            break if parts.get(2) == Some(&Value::Bool(true)) {
                Outcome::Accepted
            } else {
                Outcome::Rejected(said.to_string())
            };
        }
    };
    let _ = socket.close(None);
    outcome
}

type Socket = tungstenite::WebSocket<Box<dyn Stream>>;

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// A WebSocket to `url` (`wss://`, or `ws://` for a local relay of a test),
/// every step bounded by [`RELAY_TIMEOUT`].
fn connect(url: &str) -> Result<(Socket, TcpStream), String> {
    let tls = url.starts_with("wss://");
    let rest = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .ok_or("not a ws:// or wss:// URL")?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .filter(|(_, p)| p.bytes().all(|c| c.is_ascii_digit()))
        .map_or(authority, |(h, _)| h)
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let address = if authority
        .rsplit_once(':')
        .is_some_and(|(_, p)| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
    {
        authority.to_string()
    } else {
        format!("{authority}:{}", if tls { 443 } else { 80 })
    };
    let target = address
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host} has no address"))?;
    let tcp = TcpStream::connect_timeout(&target, RELAY_TIMEOUT)
        .map_err(|e| format!("could not connect: {e}"))?;
    tcp.set_read_timeout(Some(RELAY_TIMEOUT)).ok();
    tcp.set_write_timeout(Some(RELAY_TIMEOUT)).ok();
    let timer = tcp
        .try_clone()
        .map_err(|e| format!("could not clone the socket: {e}"))?;
    let watchdog = tcp
        .try_clone()
        .map_err(|e| format!("could not clone the socket: {e}"))?;
    std::thread::spawn(move || {
        std::thread::sleep(CONNECTION_LIFETIME);
        let _ = watchdog.shutdown(std::net::Shutdown::Both);
    });
    let stream: Box<dyn Stream> = if tls {
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| format!("bad host name: {e}"))?;
        let connection = rustls::ClientConnection::new(tls_config(), name)
            .map_err(|e| format!("could not start TLS: {e}"))?;
        Box::new(rustls::StreamOwned::new(connection, tcp))
    } else {
        Box::new(tcp)
    };
    let (socket, _) = tungstenite::client(url, stream)
        .map_err(|e| format!("the WebSocket handshake failed: {e}"))?;
    Ok((socket, timer))
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

// ---------------------------------------------------------------------
// What was published, and when
// ---------------------------------------------------------------------

/// The last result for one relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayStatus {
    /// `accepted`, `rejected` or `unreachable`.
    pub state: &'static str,
    pub detail: String,
    /// The commitment digest (`x`) this result is for.
    pub digest: String,
    /// When it happened, `YYYY-MM-DDTHH:MM:SSZ`.
    pub at: String,
    started: Instant,
}

static STATUS: Mutex<BTreeMap<String, RelayStatus>> = Mutex::new(BTreeMap::new());

/// A pending [`key_change`] note, until a publish under the new key is accepted.
static KEY_NOTE: Mutex<Option<String>> = Mutex::new(None);

/// The mailbox key change `doctor` reports, if one is pending.
pub fn key_note() -> Option<String> {
    lock(&KEY_NOTE).clone()
}

/// Why the last [`tick`] published nothing, when it could not.
static BLOCKED: Mutex<Option<String>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The last result per relay.
pub fn status() -> BTreeMap<String, RelayStatus> {
    lock(&STATUS).clone()
}

/// Why this node is not publishing though the switch is on, if so.
pub fn blocked() -> Option<String> {
    lock(&BLOCKED).clone()
}

/// A relay is published to again when its last result is not for this
/// digest, or when it did not accept and [`RETRY_AFTER`] has passed.
fn due(last: Option<&RelayStatus>, digest: &str) -> bool {
    match last {
        None => true,
        Some(s) if s.digest != digest => true,
        Some(s) if s.state != "accepted" => s.started.elapsed() >= RETRY_AFTER,
        Some(_) => false,
    }
}

/// Publish `commitment` to each of `route.relays` that is due, through
/// `publish`, and keep each result. Returns how many relays were tried.
#[allow(clippy::too_many_arguments)]
pub fn announce(
    book: &Mutex<BTreeMap<String, RelayStatus>>,
    key: &SigningKey,
    node_id: &str,
    commitment: &Value,
    route: &Route,
    now: &str,
    at: i64,
    publish: impl Fn(&str, &SigningKey, &str, &[u8], i64) -> Outcome + Send + Sync + 'static,
) -> usize {
    let octets = octets(commitment);
    let digest = hex::encode(Sha256::digest(&octets));
    let todo: Vec<&String> = {
        let held = lock(book);
        route
            .relays
            .iter()
            .filter(|url| due(held.get(*url), &digest))
            .collect()
    };
    // Relays are slow and independent: one thread each, and none is waited
    // for past `ANNOUNCE_DEADLINE`, so one that stalls cannot hold the others'
    // results or the next tick.
    let (send, receive) = std::sync::mpsc::channel();
    let octets = Arc::new(octets);
    let publish = Arc::new(publish);
    let mut launched: Vec<&String> = Vec::new();
    for url in &todo {
        {
            let mut busy = lock(&IN_FLIGHT);
            if busy.contains(*url) {
                continue;
            }
            busy.push((*url).clone());
        }
        launched.push(url);
        let flight = Flight((*url).clone());
        let (send, url, key, node_id) = (
            send.clone(),
            (*url).clone(),
            key.clone(),
            node_id.to_string(),
        );
        let (octets, publish) = (octets.clone(), publish.clone());
        std::thread::spawn(move || {
            // The guard travels with the result and is released by whoever
            // takes it in (below), or here if nobody does or the worker
            // panics: there is no moment when the result is in and the relay
            // still reads as busy.
            let flight = flight;
            let outcome = publish(&url, &key, &node_id, &octets, at);
            let _ = send.send((url, outcome, flight));
        });
    }
    drop(send);
    let until = Instant::now() + ANNOUNCE_DEADLINE;
    let mut results: Vec<(String, Outcome)> = Vec::new();
    while results.len() < launched.len() {
        let left = until.saturating_duration_since(Instant::now());
        match receive.recv_timeout(left) {
            // Dropping the guard here frees the relay before this returns.
            Ok((url, outcome, flight)) => {
                drop(flight);
                results.push((url, outcome));
            }
            Err(_) => break,
        }
    }
    for url in &launched {
        if !results.iter().any(|(u, _)| u == *url) {
            results.push((
                (*url).clone(),
                Outcome::Unreachable("no answer in time".into()),
            ));
        }
    }
    let tried = results.len();
    let mut held = lock(book);
    held.retain(|url, _| route.relays.contains(url));
    for (url, outcome) in results {
        let (state, detail) = match outcome {
            Outcome::Accepted => ("accepted", String::new()),
            Outcome::Rejected(why) => ("rejected", why),
            Outcome::Unreachable(why) => ("unreachable", why),
        };
        held.insert(
            url,
            RelayStatus {
                state,
                detail,
                digest: digest.clone(),
                at: now.to_string(),
                started: Instant::now(),
            },
        );
    }
    tried
}

/// One minute's work: publish this node's commitment to the relays it lists
/// when the switch is on, and say why not when it cannot.
pub fn tick(capsules: &crate::capsule_emit::CapsuleState, node_id: Option<&str>) {
    let advertise = crate::commitment::Policy::current().advertise_evidence_requests;
    let result = (|| -> Result<Option<usize>, String> {
        if !advertise {
            lock(&STATUS).clear();
            return Ok(None);
        }
        let node_id = node_id.ok_or("this node's mesh id is not known yet")?;
        let data_dir = capsules
            .ledger_dir()
            .parent()
            .ok_or("the ledger has no data directory to keep the mailbox key in")?;
        let route = route(data_dir, true)?.ok_or("no route")?;
        let signed = crate::commitment_bridge::own(capsules, Some(node_id))?;
        let key = mailbox_key(data_dir)?;
        let now = crate::evidence_answer::now_utc();
        let at = chrono::Utc::now().timestamp();
        *lock(&KEY_NOTE) = key_change(data_dir, &route.mailbox_key);
        let tried = announce(
            &STATUS,
            &key,
            node_id,
            &signed.commitment,
            &route,
            &now,
            at,
            publish_to,
        );
        if lock(&STATUS).values().any(|r| r.state == "accepted") {
            note_published(data_dir, &route.mailbox_key);
            *lock(&KEY_NOTE) = None;
        }
        Ok(Some(tried))
    })();
    *lock(&BLOCKED) = match result {
        Ok(_) => None,
        Err(why) => {
            tracing::warn!(%why, "the commitment is not published");
            Some(why)
        }
    };
}

/// A minute-by-minute task in the plugin's runtime.
pub fn spawn(
    capsules: Arc<crate::capsule_emit::CapsuleState>,
    node_id: impl Fn() -> Option<String> + Send + 'static,
) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(60));
        loop {
            every.tick().await;
            let capsules = capsules.clone();
            let node = node_id();
            let _ = tokio::task::spawn_blocking(move || tick(&capsules, node.as_deref())).await;
        }
    });
}

#[cfg(test)]
mod tests;
