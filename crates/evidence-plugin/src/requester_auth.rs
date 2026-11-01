//! Who asked: the requester's signature on an evidence request, both sides.
//!
//! A request's `requester_id` is the asker's own word. A node that answers
//! some askers and not others (a record to the node it names, Standard
//! History to a counterparty) needs to know who asked, so the asker signs.
//!
//! **The signature** is a profile member of this deployment inside the
//! request map, never an Evidence Request field:
//!
//! ```text
//! requester_auth = {"key_id": <64 lowercase hex>, "sig": <128 lowercase hex>}
//! sig = Ed25519(UTF8("<channel>/requester-auth") || 0x00
//!               || UTF8(JCS(the request map without requester_auth)))
//! ```
//!
//! `key_id` is the key this node's records are signed with, the one it
//! announces through its host (`peer_keys::own`). The domain tag keeps a
//! request signature from ever verifying as a record or anything else that
//! key signs, and each [`Channel`] has its own, so a request signed for one
//! never verifies as a request on another. Every other member is covered. A signed request carries an
//! `audience`, the node it is addressed to, so a node it was sent to cannot
//! forward it to another; and a `nonce` and a `deadline`, so a responder
//! refuses it once that deadline has passed, and a second time before then
//! (the replay cache is in memory, and for a key no host binds it is
//! best-effort: [`MAX_UNBOUND_NONCES`]). A restart forgets the nonces, so the
//! cache keeps one number on disk, the latest deadline it may hold for a
//! bound key, and after a restart it holds no nonce whose deadline is at or
//! before it ([`ReplayCache::persisted`]). The spec ruling is
//! `svc-ev-m1-request-signing-ruling` with its u289 addendum, as amended by
//! em-spec u290 and u338 (one tag per channel).
//!
//! **The asker** ([`sign_outgoing`]) signs only once its host took its key
//! ([`AskerKey::set_announced`]): a key no host announced is bound to no
//! node. `ledger-fetch/1` and a referee's `adjudicate` requests are signed
//! and checked the same way ([`principal`]), each under its own tag.
//!
//! **The responder** ([`check`]) runs before anything is looked up: window,
//! signature, audience, replay, then the key's binding and the stated id
//! against it. It yields the verified principal, the key and every node it
//! is bound to ([`claimants`]: announced by a host, listed by the operator,
//! or reached through a carried controller declaration), or why there is
//! none. The key is the asker's identity, not the peer id it asks under
//! (D-34).
//! `evidence_answer` decides what that means for the subject asked: a valid
//! signature under a key no host binds ([`Failure::Unbound`]) reads as an
//! unsigned request where the answer needs no identity; every other failure
//! is refused.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use evidence_request::jcs;
use evidence_request::time::UtcTime;
use serde_json::{json, Map, Value};

/// The request member the signature travels in.
pub const MEMBER: &str = "requester_auth";

/// The request member naming the node a signed request is addressed to:
/// its mesh node id, as the asker addressed the stream. Required whenever
/// [`MEMBER`] is present.
pub const AUDIENCE: &str = "audience";

/// What a signed request asks for, which picks its domain tag: the
/// carrier's own identifier, then `/requester-auth` (ruling u338). A
/// responder takes it from the door the request came in at, never from a
/// member of the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// An Evidence Request (`mesh_evidence_bridge::EVIDENCE_REQUEST_CHANNEL`).
    /// Its tag is the one M1 signed under.
    EvidenceRequest,
    /// A record fetch by id (`ledger_fetch_bridge::LEDGER_FETCH_CHANNEL`).
    LedgerFetch,
    /// A referee's `adjudicate` request. It travels on the evidence stream
    /// and has no channel identifier of its own, so its tag names one:
    /// `referee-adjudicate/1`. Both ends tell it by its `subject.kind`
    /// (`referee::service::is_adjudicate_request`), which the signature
    /// covers.
    RefereeAdjudicate,
}

impl Channel {
    /// Every channel, for the tests that sign for one and verify as another.
    #[cfg(test)]
    pub const ALL: [Channel; 3] = [
        Channel::EvidenceRequest,
        Channel::LedgerFetch,
        Channel::RefereeAdjudicate,
    ];

    /// This channel's domain tag, except in the deliberately broken build
    /// CI uses to show the tests catch one tag shared by every channel.
    pub fn tag(self) -> &'static str {
        if cfg!(feature = "mutant-requester-auth-shared-tag") {
            return "evidence-request/1/requester-auth";
        }
        match self {
            Channel::EvidenceRequest => "evidence-request/1/requester-auth",
            Channel::LedgerFetch => "ledger-fetch/1/requester-auth",
            Channel::RefereeAdjudicate => "referee-adjudicate/1/requester-auth",
        }
    }
}

/// How far ahead a signed request's deadline may be, in seconds. A later
/// deadline is refused: the replay cache holds each nonce until its deadline.
pub const MAX_WINDOW_SECS: i64 = 300;

/// How far ahead this node sets the deadline of a request it signs, in
/// seconds: inside [`MAX_WINDOW_SECS`], with room for the two clocks to
/// disagree.
pub const ASKER_DEADLINE_SECS: i64 = 120;

/// The longest nonce a signed request may carry, in bytes.
pub const MAX_NONCE_BYTES: usize = 256;

/// The most nonces held for one bound key at once. Each is held at most
/// [`MAX_WINDOW_SECS`]; past it, that key's next request is refused rather
/// than a nonce forgotten, and one key filling its share refuses no other.
pub const MAX_NONCES_PER_KEY: usize = 4096;

/// The most nonces held, all together, for keys no host binds. Anyone can
/// make such a key, so they share one pool, and no bound key is affected.
/// Replay checking there is best-effort: each nonce is held until its
/// deadline, and while the pool is full of live nonces a new one is not
/// held, so its request is answered as unsigned, labelled replay-unchecked
/// (ruling u290 §2). Refusing it instead would let anyone flood the pool to
/// deny every upgraded asker, and an unsigned request gets the same answer.
pub const MAX_UNBOUND_NONCES: usize = 16_384;

/// The file in the data directory holding the latest deadline the replay
/// cache may hold, as Unix seconds in decimal ([`ReplayCache::persisted`]).
pub const HORIZON_FILE: &str = "replay-horizon";

/// How far past a new nonce's deadline the cache moves the horizon it keeps
/// on disk, in seconds, so it writes the file at most about once per this
/// many seconds of deadlines, not once per request.
pub const HORIZON_STEP_SECS: i64 = 30;

/// The signing input for `map` on `channel`: its domain tag, a zero byte,
/// and the map without [`MEMBER`] in the protocol crate's canonical JSON
/// (RFC 8785 for strings, maps and integers; it encodes no non-integer
/// number). `None` when the map has none.
pub fn signing_input(channel: Channel, map: &Map<String, Value>) -> Option<Vec<u8>> {
    let mut covered = map.clone();
    covered.remove(MEMBER);
    let body = jcs::to_string(&Value::Object(covered)).ok()?;
    let tag = channel.tag().as_bytes();
    let mut input = Vec::with_capacity(tag.len() + 1 + body.len());
    input.extend_from_slice(tag);
    input.push(0);
    input.extend_from_slice(body.as_bytes());
    Some(input)
}

/// Sign `request` for `channel` as `key`, addressed to the node `audience`:
/// set [`AUDIENCE`], add a fresh `nonce` and a `deadline` [`ASKER_DEADLINE_SECS`]
/// after `now` unless it carries them, then [`MEMBER`] over the rest. A
/// request that already carries [`MEMBER`], is not a map, or has no JSON
/// form to sign is left exactly as it is.
pub fn sign(
    channel: Channel,
    request: &mut Value,
    key: &SigningKey,
    now: chrono::DateTime<chrono::Utc>,
    audience: &str,
) {
    let Some(given) = request.as_object() else {
        return;
    };
    if given.contains_key(MEMBER) {
        return;
    }
    let mut map = given.clone();
    map.insert(AUDIENCE.into(), json!(audience));
    map.entry("nonce")
        .or_insert_with(|| json!(crate::producer::capsule::fresh_store_nonce()));
    map.entry("deadline").or_insert_with(|| {
        let deadline = now + chrono::Duration::seconds(ASKER_DEADLINE_SECS);
        json!(deadline.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    });
    let Some(input) = signing_input(channel, &map) else {
        return;
    };
    let sig = key.sign(&input);
    map.insert(
        MEMBER.into(),
        json!({
            "key_id": hex::encode(key.verifying_key().to_bytes()),
            "sig": hex::encode(sig.to_bytes()),
        }),
    );
    *request = Value::Object(map);
}

/// The key this node signs its requests with, once its host took it.
#[derive(Default)]
pub struct AskerKey(OnceLock<SigningKey>);

impl AskerKey {
    /// This node's host took its key (`peer_keys::own::Announced::Sent`):
    /// from now on, every request it sends is signed with `key`.
    pub fn set_announced(&self, key: SigningKey) {
        let _ = self.0.set(key);
    }

    /// Sign an outgoing request on `channel` to the node `audience`
    /// ([`sign`]) when this node's key is announced; otherwise leave it
    /// unsigned, as before.
    pub fn sign_outgoing(&self, channel: Channel, request: &mut Value, audience: &str) {
        if let Some(key) = self.0.get() {
            sign(channel, request, key, chrono::Utc::now(), audience);
        }
    }

    /// Whether requests this node sends are signed.
    pub fn is_announced(&self) -> bool {
        self.0.get().is_some()
    }
}

/// The one [`AskerKey`] this node's requests are signed with.
pub fn asker_key() -> &'static AskerKey {
    static SIGNER: AskerKey = AskerKey(OnceLock::new());
    &SIGNER
}

/// [`AskerKey::sign_outgoing`] on [`asker_key`].
pub fn sign_outgoing(channel: Channel, request: &mut Value, audience: &str) {
    asker_key().sign_outgoing(channel, request, audience);
}

/// What a request's [`MEMBER`] says, by form alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Form {
    /// No [`MEMBER`].
    Unsigned,
    /// A well-formed [`MEMBER`], with the [`AUDIENCE`], `nonce` and
    /// `deadline` a signed request carries.
    Signed { key_id: String, sig: String },
    /// [`MEMBER`] is there but is not `{key_id, sig}` in lowercase hex of the
    /// right lengths, or the request lacks a text [`AUDIENCE`], a `nonce` of
    /// 1 to [`MAX_NONCE_BYTES`] bytes or a `deadline`: `request_malformed`.
    Malformed,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The [`Form`] of the parsed request map `map`.
pub fn form(map: &Map<String, Value>) -> Form {
    let Some(auth) = map.get(MEMBER) else {
        return Form::Unsigned;
    };
    let Some(auth) = auth.as_object() else {
        return Form::Malformed;
    };
    let text = |k: &str| auth.get(k).and_then(Value::as_str);
    let (Some(key_id), Some(sig)) = (text("key_id"), text("sig")) else {
        return Form::Malformed;
    };
    if auth.len() != 2 || !is_lower_hex(key_id, 64) || !is_lower_hex(sig, 128) {
        return Form::Malformed;
    }
    let nonce_ok = map
        .get("nonce")
        .and_then(Value::as_str)
        .is_some_and(|n| (1..=MAX_NONCE_BYTES).contains(&n.len()));
    if !nonce_ok
        || !map.get("deadline").is_some_and(Value::is_string)
        || !map.get(AUDIENCE).is_some_and(Value::is_string)
    {
        return Form::Malformed;
    }
    Form::Signed {
        key_id: key_id.to_string(),
        sig: sig.to_string(),
    }
}

/// The nodes `key_id` is bound to: each peer whose key for this plugin the
/// host announced as `key_id`, after checking that peer's binding against
/// its node key (`peer_keys::announced`); or, when no host announced it,
/// each entry of the operator's map (`CAPSULES_PEER_KEYS`) that gives
/// `key_id`: the stopgap for a node with no stable peer id (D-34), which
/// never adds a second name to a key a host binds. An operator entry that
/// gives an announced peer another key vetoes it, as for pushed records
/// (`peer_keys::merged`).
///
/// A host binds a key to a node by the node's signature alone, without
/// proof that the node holds the key, so a node can announce another's
/// public key. A request's own signature is that proof, so more than one
/// node here does not make the key unusable: the request's stated id picks
/// among them ([`bound_node`]).
pub fn claimants(
    announced: &BTreeMap<String, String>,
    configured: Option<&str>,
    key_id: &str,
) -> Vec<String> {
    let merged = crate::peer_keys::merged(configured, announced);
    let peers = crate::peer_keys::peers_for_key_in(merged.as_deref(), key_id);
    let hosted: Vec<String> = peers
        .iter()
        .filter(|peer| announced.get(*peer).map(String::as_str) == Some(key_id))
        .cloned()
        .collect();
    if hosted.is_empty() {
        peers
    } else {
        hosted
    }
}

/// Who a request's key is, for [`check`]: the nodes it is bound to, and the
/// key whose replay budget its nonces draw on.
struct Claimed {
    nodes: Vec<String>,
    /// The request's own key, or, for a key a declaration binds, the
    /// declaration's anchor: an anchor's holder can bind any number of new
    /// keys, and they share its [`MAX_NONCES_PER_KEY`].
    replay_key: String,
}

/// [`claimants`] of `key_id`, or, when it has none, the claimants of the key
/// a controller declaration carried in the request (`controller_binding`,
/// covered by its signature) binds it to, when that binding applies at
/// `now` (`peer_keys::accepted_via`). A declaration that binds `key_id` to
/// this node's own key ([`Keys::own_key`], else the key the registry gives
/// `own_node`) makes it bound to no node, even one a host announced: it is
/// this node's side, never another node asking.
fn request_claimants(
    keys: Keys<'_>,
    map: &Map<String, Value>,
    key_id: &str,
    now: UtcTime,
    own_node: Option<&str>,
) -> Claimed {
    let own = |nodes: Vec<String>| Claimed {
        nodes,
        replay_key: key_id.to_string(),
    };
    let declaration = map.get(crate::controller_binding::MEMBER);
    let merged = crate::peer_keys::merged(keys.configured, keys.announced);
    let own_key = keys
        .own_key
        .map(str::to_string)
        .or_else(|| {
            own_node.and_then(|node| crate::peer_keys::announced_key_in(merged.as_deref(), node))
        })
        .unwrap_or_default();
    if crate::peer_keys::binds_to_own(declaration, key_id, &own_key, Some(now)) {
        return own(Vec::new());
    }
    let direct = claimants(keys.announced, keys.configured, key_id);
    if !direct.is_empty() || declaration.is_none() {
        return own(direct);
    }
    match crate::peer_keys::accepted_via(
        keys.configured,
        keys.announced,
        key_id,
        &own_key,
        declaration,
        Some(now),
    ) {
        Some(crate::peer_keys::Accepted {
            via: crate::peer_keys::AcceptedVia::ControllerDeclaration { anchor_key, .. },
            peers,
            ..
        }) => Claimed {
            nodes: peers,
            replay_key: anchor_key,
        },
        _ => own(Vec::new()),
    }
}

/// What a key's [`claimants`] and a request's stated id make of who asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binding {
    /// The node the request comes from: the stated id when it is one of the
    /// claimants (the signature proves the asker holds the key, and that
    /// node announced it), or the key's one claimant when none is stated.
    Node(String),
    /// The key is bound, but the stated id is none of its nodes: a false
    /// claim. Carries the key's node when it has exactly one.
    Mismatch(Option<String>),
    /// No host binds the key, or several nodes announced it and the request
    /// states no id to pick between them.
    Unbound,
}

/// The [`Binding`] of a request signed under a key with these
/// `claimants`, stating `stated`.
pub fn bound_node(claimants: &[String], stated: Option<&str>) -> Binding {
    match (claimants, stated) {
        ([], _) => Binding::Unbound,
        (_, Some(id)) if claimants.iter().any(|node| node == id) => Binding::Node(id.to_string()),
        ([one], Some(_)) => Binding::Mismatch(Some(one.clone())),
        (_, Some(_)) => Binding::Mismatch(None),
        ([one], None) => Binding::Node(one.clone()),
        (_, None) => Binding::Unbound,
    }
}

/// What [`ReplayCache::first_use`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    /// Not seen before, and now held until its deadline.
    First,
    /// Already held within its deadline.
    Replayed,
    /// A bound key's nonce this cache cannot hold or cannot vouch for: the
    /// key already holds [`MAX_NONCES_PER_KEY`] live nonces, its deadline is
    /// at or before the horizon of the run before a restart (it may have
    /// been held then), or the new horizon could not be written. Refused
    /// like a replay, since an unheld nonce could be replayed later; a limit
    /// of this node's own.
    Full,
    /// An unbound key's nonce, not seen, but not held either: the unbound
    /// pool is full of live nonces, or its deadline is at or before the
    /// horizon of the run before a restart. An unbound key never moves the
    /// horizon: its request reads as unsigned and gets what any asker gets,
    /// so its replay check stays in memory, and a key anyone can make cannot
    /// lengthen what a restart refuses bound keys.
    Unchecked,
}

/// The nonces seen, each held until its deadline: per key for bound keys,
/// and in one shared pool for keys no host binds.
#[derive(Default)]
pub struct ReplayCache {
    bound: Mutex<HashMap<String, HashMap<String, i64>>>,
    unbound: Mutex<HashMap<(String, String), i64>>,
    horizon: Mutex<Horizon>,
}

/// What a [`ReplayCache`] keeps across a restart. Unset (the default) for a
/// cache that keeps nothing: every deadline is after `floor`, and nothing
/// is written.
#[derive(Default)]
struct Horizon {
    /// Where `kept` is written ([`HORIZON_FILE`]).
    file: Option<PathBuf>,
    /// The last write failed: logged once, until one succeeds.
    failing: bool,
    /// The horizon the run before this one left: a nonce whose deadline is
    /// at or before it may have been held then, and is not held now.
    floor: Option<i64>,
    /// No nonce held has a later deadline; the file holds it.
    kept: Option<i64>,
}

impl Horizon {
    /// Whether `deadline` may belong to a nonce held before this run.
    fn before_restart(&self, deadline: i64) -> bool {
        self.floor.is_some_and(|floor| deadline <= floor)
    }

    /// Make room to hold a nonce until `deadline`: write a later horizon
    /// first when the kept one is earlier. False when that write failed, so
    /// the nonce must not be held: after a restart it would be forgotten.
    fn cover(&mut self, deadline: i64) -> bool {
        let Some(file) = &self.file else {
            return true;
        };
        if self.kept.is_some_and(|kept| deadline <= kept) {
            return true;
        }
        let next = deadline.saturating_add(HORIZON_STEP_SECS);
        // Durable before the nonce is held: the file, then its directory
        // entry, so a power loss cannot roll the rename back.
        let written = crate::owner_maintenance::write_atomically(file, next.to_string().as_bytes())
            .and_then(|()| match file.parent() {
                Some(dir) => crate::ask_book::sync_dir(dir),
                None => Ok(()),
            });
        match written {
            Ok(()) => {
                self.kept = Some(next);
                self.failing = false;
                true
            }
            Err(error) => {
                if !self.failing {
                    tracing::error!(%error, file = %file.display(), "the replay horizon cannot be written; signed requests from bound keys are refused capacity_exceeded until it can");
                }
                self.failing = true;
                false
            }
        }
    }
}

impl ReplayCache {
    /// A cache that survives a restart: it keeps the latest deadline it may
    /// hold for a bound key in `data_dir`'s [`HORIZON_FILE`], written before
    /// any bound key's nonce with a later deadline is held, and holds no
    /// nonce whose deadline is at or before the one the last run left, since
    /// that run may have held it and this one has forgotten it. If the
    /// horizon cannot be written, a bound key's nonce is not held, so its
    /// request is refused (fail closed); the first failure is logged as an
    /// error. `now` is Unix seconds.
    ///
    /// A missing file is a first run, so nothing is refused (a node upgraded
    /// from a version that wrote none is unprotected for that one restart).
    /// A file that cannot be read or parsed counts as a horizon
    /// [`MAX_WINDOW_SECS`] and [`HORIZON_STEP_SECS`] from `now`, the latest
    /// any held nonce could have; so does a horizon later than that, which
    /// only a clock that moved back leaves.
    pub fn persisted(data_dir: &Path, now: i64) -> ReplayCache {
        let file = data_dir.join(HORIZON_FILE);
        let latest = now
            .saturating_add(MAX_WINDOW_SECS)
            .saturating_add(HORIZON_STEP_SECS);
        let floor = match std::fs::read_to_string(&file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Ok(text) => Some(
                text.trim()
                    .parse::<i64>()
                    .map_or(latest, |kept| kept.min(latest)),
            ),
            Err(_) => Some(latest),
        };
        ReplayCache {
            horizon: Mutex::new(Horizon {
                file: Some(file),
                failing: false,
                floor,
                kept: floor,
            }),
            ..ReplayCache::default()
        }
    }

    /// Record `nonce` for `key_id` until `deadline` (Unix seconds).
    /// [`Use::Replayed`] when it is already held; [`Use::Full`] when a bound
    /// key already holds [`MAX_NONCES_PER_KEY`] live nonces, its deadline is
    /// at or before the last run's horizon, or the horizon cannot be written;
    /// [`Use::Unchecked`] when unbound keys together hold
    /// [`MAX_UNBOUND_NONCES`] live nonces or an unbound key's deadline is at
    /// or before the last run's horizon.
    pub fn first_use(
        &self,
        key_id: &str,
        nonce: &str,
        deadline: i64,
        now: i64,
        bound: bool,
    ) -> Use {
        if !bound {
            let mut seen = self.unbound.lock().unwrap_or_else(PoisonError::into_inner);
            let pair = (key_id.to_string(), nonce.to_string());
            if seen.get(&pair).is_some_and(|&until| until >= now) {
                return Use::Replayed;
            }
            if seen.len() >= MAX_UNBOUND_NONCES {
                seen.retain(|_, &mut until| until >= now);
            }
            if seen.len() >= MAX_UNBOUND_NONCES {
                return Use::Unchecked;
            }
            let horizon = self.horizon.lock().unwrap_or_else(PoisonError::into_inner);
            if horizon.before_restart(deadline) {
                return Use::Unchecked;
            }
            seen.insert(pair, deadline);
            return Use::First;
        }
        let mut seen = self.bound.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, nonces| {
            nonces.retain(|_, &mut until| until >= now);
            !nonces.is_empty()
        });
        let nonces = seen.entry(key_id.to_string()).or_default();
        if nonces.contains_key(nonce) {
            return Use::Replayed;
        }
        if nonces.len() >= MAX_NONCES_PER_KEY {
            return Use::Full;
        }
        let mut horizon = self.horizon.lock().unwrap_or_else(PoisonError::into_inner);
        if horizon.before_restart(deadline) || !horizon.cover(deadline) {
            return Use::Full;
        }
        nonces.insert(nonce.to_string(), deadline);
        Use::First
    }
}

static CACHE: OnceLock<ReplayCache> = OnceLock::new();

/// The one cache the mesh responder uses: the one [`keep_replay_horizon`]
/// set, else (in tests) one that keeps nothing across a restart.
pub fn replay_cache() -> &'static ReplayCache {
    CACHE.get_or_init(ReplayCache::default)
}

/// Make [`replay_cache`] the one that survives a restart, kept in
/// `data_dir` ([`ReplayCache::persisted`]). Called once at startup, before
/// any request is answered; false when the cache was already in use.
pub fn keep_replay_horizon(data_dir: &Path) -> bool {
    CACHE
        .set(ReplayCache::persisted(
            data_dir,
            chrono::Utc::now().timestamp(),
        ))
        .is_ok()
}

/// The keys a responder checks a signature's binding against.
#[derive(Clone, Copy)]
pub struct Keys<'a> {
    /// `peer_keys::announced::snapshot()`.
    pub announced: &'a BTreeMap<String, String>,
    /// `CAPSULES_PEER_KEYS`, raw.
    pub configured: Option<&'a str>,
    /// This node's own key (`key_id`), never a declaration's anchor. `None`:
    /// the key the registry gives this node's id.
    pub own_key: Option<&'a str>,
}

/// The requester a signed request proved to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// The key the signature verified under.
    pub key_id: String,
    /// The node that key is bound to ([`bound_node`]).
    pub node_id: String,
    /// Every node that key is bound to ([`claimants`]): the asker is each of
    /// them, since the key, not the peer id it asks under, is its identity
    /// (D-34). Holds `node_id`.
    pub node_ids: Vec<String>,
}

/// Why a signed request names no principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The deadline is more than [`MAX_WINDOW_SECS`] ahead.
    OutsideWindow,
    /// The signature does not verify over the signing input.
    BadSignature,
    /// The request is addressed to another node than this one (or this node
    /// does not know its own id yet).
    AudienceMismatch { key_id: String },
    /// This (key_id, nonce) was already seen within its deadline.
    Replayed { key_id: String },
    /// A bound key's nonce cannot be held or vouched for ([`Use::Full`]):
    /// no room, a deadline at or before the last run's horizon, or a horizon
    /// that cannot be written. A limit of this node's own, refused as a
    /// replay would be.
    ReplayCacheFull { key_id: String },
    /// The key is bound to no node, or to several and the request states
    /// no id. The only failure that may read as unsigned
    /// ([`Failure::reads_as_unsigned`]). `replay_checked` is false when the
    /// nonce was not held ([`Use::Unchecked`]): the unbound pool was full, or
    /// its deadline was at or before the last run's horizon.
    Unbound {
        key_id: String,
        replay_checked: bool,
    },
    /// The key is bound, and the request states a `requester_id` that is
    /// none of its nodes (`node_id`: its node, when it has one).
    ClaimMismatch {
        key_id: String,
        node_id: Option<String>,
    },
}

impl Failure {
    /// The key the signature verified under, if it did.
    pub fn verified_key(&self) -> Option<&str> {
        match self {
            Failure::OutsideWindow | Failure::BadSignature => None,
            Failure::AudienceMismatch { key_id }
            | Failure::Replayed { key_id }
            | Failure::ReplayCacheFull { key_id }
            | Failure::Unbound { key_id, .. }
            | Failure::ClaimMismatch { key_id, .. } => Some(key_id),
        }
    }

    /// The node that key is bound to, if the binding verified.
    pub fn verified_node(&self) -> Option<&str> {
        match self {
            Failure::ClaimMismatch { node_id, .. } => node_id.as_deref(),
            _ => None,
        }
    }

    /// Whether a request that failed this way is answered as an unsigned
    /// one would be, where the answer needs no identity: only a valid
    /// signature under a key the host cannot bind (ruling addendum §2).
    /// Every other failure is refused.
    pub fn reads_as_unsigned(&self) -> bool {
        matches!(self, Failure::Unbound { .. })
            || cfg!(feature = "mutant-requester-auth-downgrades-all")
    }
}

/// Check a [`Form::Signed`] request received on `channel`, before anything
/// else is read: its window, its signature under that channel's tag, its [`AUDIENCE`] against `own_node` (this node's
/// id), its nonce, then its key's binding and its stated id against the
/// bound one. `deadline` is the parsed request's.
#[allow(clippy::too_many_arguments)]
pub fn check(
    channel: Channel,
    map: &Map<String, Value>,
    key_id: &str,
    sig: &str,
    deadline: UtcTime,
    now: UtcTime,
    keys: Keys<'_>,
    replay: &ReplayCache,
    own_node: Option<&str>,
) -> Result<Principal, Failure> {
    if deadline.seconds > now.seconds.saturating_add(MAX_WINDOW_SECS) {
        return Err(Failure::OutsideWindow);
    }
    if !verifies(channel, map, key_id, sig) {
        return Err(Failure::BadSignature);
    }
    let audience = map.get(AUDIENCE).and_then(Value::as_str);
    if !audience_matches(audience, own_node) {
        return Err(Failure::AudienceMismatch {
            key_id: key_id.to_string(),
        });
    }
    let stated = map
        .get("requester_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let Claimed {
        nodes: claimants,
        replay_key,
    } = request_claimants(keys, map, key_id, now, own_node);
    let nonce = map.get("nonce").and_then(Value::as_str).unwrap_or_default();
    // A key a declaration binds draws on its anchor's budget, its nonces
    // kept apart from the anchor's own and from other bound keys'.
    let nonce = if replay_key == key_id {
        nonce.to_string()
    } else {
        format!("{key_id}/{nonce}")
    };
    let bound = !claimants.is_empty();
    let replay_checked =
        match replay.first_use(&replay_key, &nonce, deadline.seconds, now.seconds, bound) {
            Use::First => true,
            Use::Unchecked => false,
            Use::Replayed => {
                return Err(Failure::Replayed {
                    key_id: key_id.to_string(),
                })
            }
            Use::Full => {
                return Err(Failure::ReplayCacheFull {
                    key_id: key_id.to_string(),
                })
            }
        };
    let node_id = match bound_node(&claimants, stated) {
        Binding::Node(node_id) => node_id,
        Binding::Mismatch(node_id) => {
            return Err(Failure::ClaimMismatch {
                key_id: key_id.to_string(),
                node_id,
            })
        }
        Binding::Unbound => {
            return Err(Failure::Unbound {
                key_id: key_id.to_string(),
                replay_checked,
            })
        }
    };
    Ok(Principal {
        key_id: key_id.to_string(),
        node_id,
        node_ids: claimants,
    })
}

/// Why a request on another of this plugin's channels (`ledger-fetch/1`, a
/// referee's `adjudicate`) is refused by who asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A malformed [`MEMBER`], a signed request with no text [`AUDIENCE`],
    /// nonce or deadline, or a deadline that is not an RFC 3339 UTC time.
    Malformed,
    /// Its deadline has passed, a check in [`check`] failed, or it is
    /// unsigned where the answer needs an identity.
    NotAuthorized,
}

/// Who asks, for a request received on `channel`, another of this plugin's
/// channels, by the rules `evidence_answer` applies to an evidence request, before anything
/// is looked up: a signed request past its deadline or failing [`check`] is
/// refused; a valid signature under a key no host binds reads as unsigned
/// where the answer needs no identity (`needed` false); an unsigned request
/// is refused where it does. `Ok(None)` is an asker that proved nothing.
pub fn principal(
    channel: Channel,
    map: &Map<String, Value>,
    now: UtcTime,
    keys: Keys<'_>,
    replay: &ReplayCache,
    own_node: Option<&str>,
    needed: bool,
) -> Result<Option<Principal>, Refused> {
    let (key_id, sig) = match form(map) {
        Form::Malformed => return Err(Refused::Malformed),
        Form::Unsigned if needed => return Err(Refused::NotAuthorized),
        Form::Unsigned => return Ok(None),
        Form::Signed { key_id, sig } => (key_id, sig),
    };
    let deadline = map
        .get("deadline")
        .and_then(Value::as_str)
        .and_then(evidence_request::time::parse_utc)
        .ok_or(Refused::Malformed)?;
    if deadline < now {
        return Err(Refused::NotAuthorized);
    }
    match check(
        channel, map, &key_id, &sig, deadline, now, keys, replay, own_node,
    ) {
        Ok(principal) => Ok(Some(principal)),
        Err(failure) if failure.reads_as_unsigned() && !needed => Ok(None),
        Err(_) => Err(Refused::NotAuthorized),
    }
}

/// The key whose share a request draws on, when `map`, received on
/// `channel`, proves a principal now: [`check`] without its replay step and
/// without recording anything, and with a deadline not already past (that
/// is refused before [`check`] runs). The key is the one its nonces draw on
/// too: the request's own, or a declaration's anchor, whose holder can bind
/// any number of new keys. The mesh responder uses it to pick which
/// in-flight pool, and which key's share of it, a request draws from before
/// it spends a permit, so a request that yields `None` is a stranger's. A
/// replayed request passes and is refused later by [`check`], before any
/// ledger read.
pub fn proves_principal(
    channel: Channel,
    map: &Map<String, Value>,
    now: UtcTime,
    keys: Keys<'_>,
    own_node: Option<&str>,
) -> Option<String> {
    let Form::Signed { key_id, sig } = form(map) else {
        return None;
    };
    let deadline = map
        .get("deadline")
        .and_then(Value::as_str)
        .and_then(evidence_request::time::parse_utc)?;
    let stated = map
        .get("requester_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty());
    if deadline < now
        || deadline.seconds > now.seconds.saturating_add(MAX_WINDOW_SECS)
        || !verifies(channel, map, &key_id, &sig)
        || !audience_matches(map.get(AUDIENCE).and_then(Value::as_str), own_node)
    {
        return None;
    }
    let Claimed { nodes, replay_key } = request_claimants(keys, map, &key_id, now, own_node);
    matches!(bound_node(&nodes, stated), Binding::Node(_)).then_some(replay_key)
}

/// Whether a signed request's [`AUDIENCE`] is this node, compared as exact
/// strings. A node that does not know its own id yet matches nothing.
fn audience_matches(audience: Option<&str>, own_node: Option<&str>) -> bool {
    if cfg!(feature = "mutant-requester-auth-skips-audience") {
        return true;
    }
    matches!((audience, own_node), (Some(a), Some(own)) if a == own)
}

/// Whether `sig` verifies over [`signing_input`] of `map` on `channel` under
/// `key_id`,
/// except in the deliberately broken build CI uses to show the tests catch
/// a responder that skips it.
fn verifies(channel: Channel, map: &Map<String, Value>, key_id: &str, sig: &str) -> bool {
    if cfg!(feature = "mutant-requester-auth-skips-verify") {
        return true;
    }
    let key = hex::decode(key_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok());
    let sig = hex::decode(sig)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b));
    match (key, sig, signing_input(channel, map)) {
        (Some(key), Some(sig), Some(input)) => key.verify_strict(&input, &sig).is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().into()
    }

    fn signed(seed: u8) -> Map<String, Value> {
        let mut request = json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 60}, "nonce": "n-1"});
        sign(
            Channel::EvidenceRequest,
            &mut request,
            &key(seed),
            at("2026-10-13T00:00:00Z"),
            "node-r",
        );
        request.as_object().unwrap().clone()
    }

    #[test]
    fn a_signed_request_carries_the_member_a_nonce_and_a_deadline_inside_the_window() {
        let map = signed(1);
        let Form::Signed { key_id, .. } = form(&map) else {
            panic!("not signed: {map:?}");
        };
        assert_eq!(key_id, hex::encode(key(1).verifying_key().to_bytes()));
        assert_eq!(map["nonce"], json!("n-1"), "a caller's nonce is kept");
        assert_eq!(map["deadline"], json!("2026-10-13T00:02:00Z"));
        assert_eq!(map[AUDIENCE], json!("node-r"));
        let mut fresh = json!({"subject": {"checkpoints": null}});
        sign(
            Channel::EvidenceRequest,
            &mut fresh,
            &key(1),
            at("2026-10-13T00:00:00Z"),
            "node-r",
        );
        assert!(is_lower_hex(fresh["nonce"].as_str().unwrap(), 64));
    }

    #[test]
    fn the_signature_covers_the_domain_tag() {
        let map = signed(1);
        let Form::Signed { key_id, sig } = form(&map) else {
            panic!()
        };
        assert!(verifies(Channel::EvidenceRequest, &map, &key_id, &sig));
        // The same map signed without the tag does not verify.
        let mut covered = map.clone();
        covered.remove(MEMBER);
        let body = jcs::to_string(&Value::Object(covered)).unwrap();
        let untagged = hex::encode(key(1).sign(body.as_bytes()).to_bytes());
        assert!(!verifies(
            Channel::EvidenceRequest,
            &map,
            &key_id,
            &untagged
        ));
    }

    /// Each channel's tag is its carrier's identifier, then the profile
    /// member (ruling u338). The Evidence Request's is the one M1 signed
    /// under, so those signatures still verify.
    #[test]
    fn each_channel_signs_under_its_own_identifier() {
        let tags = Channel::ALL.map(Channel::tag);
        assert_eq!(
            tags,
            [
                format!(
                    "{}/requester-auth",
                    crate::mesh_evidence_bridge::EVIDENCE_REQUEST_CHANNEL
                ),
                format!(
                    "{}/requester-auth",
                    crate::ledger_fetch_bridge::LEDGER_FETCH_CHANNEL
                ),
                "referee-adjudicate/1/requester-auth".to_string(),
            ]
        );
        assert_eq!(tags[0], "evidence-request/1/requester-auth");
    }

    /// A request signed for one channel never verifies as a request on
    /// another, even when its body would be read there: for every pair, the
    /// signature fails on the tag, and a valid signature on the wrong
    /// channel is refused, never read as unsigned.
    #[test]
    fn a_request_signed_for_one_channel_fails_on_every_other() {
        let now = evidence_request::time::parse_utc("2026-10-13T00:00:00Z").unwrap();
        let node = "node-a";
        let announced = BTreeMap::from([(
            node.to_string(),
            hex::encode(key(4).verifying_key().to_bytes()),
        )]);
        let keys = Keys {
            announced: &announced,
            configured: None,
            own_key: None,
        };
        for signed_for in Channel::ALL {
            // One body every channel reads: a fetch's capsule_id, an
            // adjudicate subject, the asker's stated id.
            let mut request = json!({
                "capsule_id": "cap-1",
                "subject": {"kind": "adjudicate"},
                "requester_id": node,
            });
            sign(
                signed_for,
                &mut request,
                &key(4),
                at("2026-10-13T00:00:00Z"),
                "node-r",
            );
            let map = request.as_object().unwrap();
            let Form::Signed { key_id, sig } = form(map) else {
                panic!("not signed: {request}");
            };
            let deadline =
                evidence_request::time::parse_utc(map["deadline"].as_str().unwrap()).unwrap();
            for received_on in Channel::ALL {
                let replay = ReplayCache::default();
                let checked = check(
                    received_on,
                    map,
                    &key_id,
                    &sig,
                    deadline,
                    now,
                    keys,
                    &replay,
                    Some("node-r"),
                );
                let asked = principal(
                    received_on,
                    map,
                    now,
                    keys,
                    &ReplayCache::default(),
                    Some("node-r"),
                    false,
                );
                if received_on == signed_for {
                    assert_eq!(
                        checked.map(|p| p.node_id),
                        Ok(node.to_string()),
                        "{signed_for:?} as itself"
                    );
                    assert!(matches!(asked, Ok(Some(_))), "{signed_for:?} as itself");
                } else {
                    assert_eq!(
                        checked,
                        Err(Failure::BadSignature),
                        "signed for {signed_for:?}, received on {received_on:?}"
                    );
                    assert_eq!(
                        asked,
                        Err(Refused::NotAuthorized),
                        "signed for {signed_for:?}, received on {received_on:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_member_that_is_not_two_lowercase_hex_strings_is_malformed() {
        let base = signed(1);
        let with = |auth: Value| {
            let mut m = base.clone();
            m.insert(MEMBER.into(), auth);
            form(&m)
        };
        let key_id = base[MEMBER]["key_id"].as_str().unwrap();
        let sig = base[MEMBER]["sig"].as_str().unwrap();
        assert_eq!(
            with(json!({"key_id": &key_id[1..], "sig": sig})),
            Form::Malformed
        );
        assert_eq!(
            with(json!({"key_id": key_id.to_uppercase(), "sig": sig})),
            Form::Malformed
        );
        assert_eq!(
            with(json!({"key_id": key_id, "sig": &sig[2..]})),
            Form::Malformed
        );
        assert_eq!(
            with(json!({"key_id": key_id, "sig": sig, "x": 1})),
            Form::Malformed
        );
        assert_eq!(with(json!("signed")), Form::Malformed);
        let mut no_nonce = base.clone();
        no_nonce.remove("nonce");
        assert_eq!(form(&no_nonce), Form::Malformed);
        let mut long_nonce = base.clone();
        long_nonce.insert("nonce".into(), json!("n".repeat(MAX_NONCE_BYTES + 1)));
        assert_eq!(form(&long_nonce), Form::Malformed);
        let mut no_deadline = base.clone();
        no_deadline.remove("deadline");
        assert_eq!(form(&no_deadline), Form::Malformed);
        let mut no_audience = base.clone();
        no_audience.remove(AUDIENCE);
        assert_eq!(form(&no_audience), Form::Malformed);
        let mut audience_not_text = base.clone();
        audience_not_text.insert(AUDIENCE.into(), json!(["node-r"]));
        assert_eq!(form(&audience_not_text), Form::Malformed);
    }

    /// A key a declaration binds asks as its anchor's nodes and draws on its
    /// anchor's nonce budget. A declaration binding a key to this node's own
    /// key, however this node's key is listed, leaves it bound to no node.
    /// Keys a controller declaration binds draw on their anchor's share of
    /// the in-flight pool, so an anchor's holder cannot widen it by binding
    /// new keys (evidencebook#206 row 3).
    #[test]
    fn declared_keys_prove_the_anchor_as_their_share() {
        let now = evidence_request::time::parse_utc("2026-10-28T00:00:00Z").unwrap();
        let anchor = key(1);
        let ka = hex::encode(anchor.verifying_key().to_bytes());
        let announced = BTreeMap::from([("node-a".to_string(), ka.clone())]);
        let keys = Keys {
            announced: &announced,
            configured: None,
            own_key: Some(&hex::encode(key(3).verifying_key().to_bytes())),
        };
        for member in [key(2), key(4)] {
            let mut request = json!({
                "subject": {"checkpoints": null},
                "coverage": {"min_freshness": 60},
                "nonce": "n-1",
                crate::controller_binding::MEMBER: crate::controller_binding::bind_for_test(
                    &anchor,
                    &member,
                    "2026-10-01T00:00:00Z",
                    "2027-10-01T00:00:00Z",
                ),
            });
            sign(
                Channel::EvidenceRequest,
                &mut request,
                &member,
                at("2026-10-28T00:00:00Z"),
                "node-r",
            );
            assert_eq!(
                proves_principal(
                    Channel::EvidenceRequest,
                    request.as_object().unwrap(),
                    now,
                    keys,
                    Some("node-r"),
                ),
                Some(ka.clone()),
                "the anchor's share, not the member's own"
            );
        }
    }

    #[test]
    fn a_declared_key_shares_its_anchors_budget_and_never_anchors_on_this_node() {
        let now = evidence_request::time::parse_utc("2026-10-28T00:00:00Z").unwrap();
        let (anchor, member, own) = (key(1), key(2), key(3));
        let hex_of = |k: &SigningKey| hex::encode(k.verifying_key().to_bytes());
        let (ka, km, ko) = (hex_of(&anchor), hex_of(&member), hex_of(&own));
        let declared = |a: &SigningKey| {
            let mut map = Map::new();
            map.insert(
                crate::controller_binding::MEMBER.into(),
                crate::controller_binding::bind_for_test(
                    a,
                    &member,
                    "2026-10-01T00:00:00Z",
                    "2027-10-01T00:00:00Z",
                ),
            );
            map
        };
        let announced = BTreeMap::from([("node-a".to_string(), ka.clone())]);
        let keys = Keys {
            announced: &announced,
            configured: None,
            own_key: Some(&ko),
        };
        let claimed = request_claimants(keys, &declared(&anchor), &km, now, Some("self"));
        assert_eq!(claimed.nodes, ["node-a"]);
        assert_eq!(claimed.replay_key, ka, "the anchor's budget");
        // An operator label on the hosted anchor adds no name to the key it
        // binds either.
        let label_too = format!(r#"{{"my-label": "{ka}"}}"#);
        let labelled_keys = Keys {
            configured: Some(&label_too),
            ..keys
        };
        let claimed = request_claimants(labelled_keys, &declared(&anchor), &km, now, Some("self"));
        assert_eq!(claimed.nodes, ["node-a"]);
        assert_eq!(
            bound_node(&claimed.nodes, None),
            Binding::Node("node-a".into())
        );
        assert_eq!(
            bound_node(&claimed.nodes, Some("my-label")),
            Binding::Mismatch(Some("node-a".into()))
        );
        let plain = request_claimants(keys, &Map::new(), &ka, now, Some("self"));
        assert_eq!(plain.replay_key, ka);

        // This node's key listed under a label that is not its id.
        let labelled = format!(r#"{{"my-label": "{ko}"}}"#);
        let keys = Keys {
            announced: &BTreeMap::new(),
            configured: Some(&labelled),
            own_key: Some(&ko),
        };
        assert!(
            request_claimants(keys, &declared(&own), &km, now, Some("self"))
                .nodes
                .is_empty()
        );
        // A key a host announced, declared one controller with this node.
        let both = BTreeMap::from([("node-m".to_string(), km.clone())]);
        let keys = Keys {
            announced: &both,
            configured: None,
            own_key: Some(&ko),
        };
        assert_eq!(
            request_claimants(keys, &Map::new(), &km, now, None).nodes,
            ["node-m"]
        );
        assert!(request_claimants(keys, &declared(&own), &km, now, None)
            .nodes
            .is_empty());
    }

    /// Fresh keys an anchor's holder binds cannot widen its nonce budget.
    #[test]
    fn declared_keys_cannot_widen_the_anchors_nonce_budget() {
        let cache = ReplayCache::default();
        let anchor = "aa".repeat(32);
        for i in 0..MAX_NONCES_PER_KEY {
            let nonce = format!("k{i}/n");
            assert_eq!(
                cache.first_use(&anchor, &nonce, 2_000, 1_000, true),
                Use::First
            );
        }
        assert_eq!(
            cache.first_use(&anchor, "fresh-key/n", 2_000, 1_000, true),
            Use::Full,
            "the anchor's budget is spent, whichever key asks"
        );
    }

    #[test]
    fn a_key_binds_through_the_host_or_the_operators_stopgap_and_a_disagreeing_entry_vetoes() {
        let k = "ab".repeat(32);
        let announced = BTreeMap::from([("node-a".to_string(), k.clone())]);
        assert_eq!(claimants(&announced, None, &k), ["node-a"]);
        let configured_only = format!(r#"{{"muse-vm": "{k}"}}"#);
        assert_eq!(
            claimants(&BTreeMap::new(), Some(&configured_only), &k),
            ["muse-vm"],
            "the stopgap names a node with no stable peer id"
        );
        let both = format!(r#"{{"muse-vm": "{k}", "node-a": "{k}"}}"#);
        assert_eq!(
            claimants(&announced, Some(&both), &k),
            ["node-a"],
            "a label never adds a second name to a key a host binds"
        );
        let disagrees = format!(r#"{{"node-a": "{}"}}"#, "cd".repeat(32));
        assert!(claimants(&announced, Some(&disagrees), &k).is_empty());
        assert!(claimants(&announced, Some("not json"), &k).is_empty());
    }

    /// A node announcing another's public key does not unbind it: the
    /// request's signature proves who holds the key, and its stated id picks
    /// among the nodes that announced it. Naming none of them is unbound;
    /// naming another node than a key's one claimant is a false claim.
    #[test]
    fn the_stated_id_picks_among_the_nodes_that_announced_the_key() {
        let node = |id: &str| Binding::Node(id.to_string());
        let both = ["node-a".to_string(), "node-m".to_string()];
        assert_eq!(bound_node(&both, Some("node-a")), node("node-a"));
        assert_eq!(bound_node(&both, None), Binding::Unbound);
        assert_eq!(bound_node(&both, Some("node-z")), Binding::Mismatch(None));
        let one = ["node-a".to_string()];
        assert_eq!(bound_node(&one, None), node("node-a"));
        assert_eq!(bound_node(&one, Some("node-a")), node("node-a"));
        assert_eq!(
            bound_node(&one, Some("node-z")),
            Binding::Mismatch(Some("node-a".into()))
        );
        assert_eq!(bound_node(&[], Some("node-a")), Binding::Unbound);
    }

    #[test]
    fn a_nonce_is_used_once_until_its_deadline() {
        let cache = ReplayCache::default();
        assert_eq!(cache.first_use("k", "n", 100, 0, true), Use::First);
        assert_eq!(cache.first_use("k", "n", 100, 50, true), Use::Replayed);
        assert_eq!(
            cache.first_use("k2", "n", 100, 50, true),
            Use::First,
            "per key"
        );
        assert_eq!(
            cache.first_use("k", "n", 300, 101, true),
            Use::First,
            "after its deadline"
        );
        assert_eq!(cache.first_use("u", "n", 100, 0, false), Use::First);
        assert_eq!(
            cache.first_use("u", "n", 100, 50, false),
            Use::Replayed,
            "an unbound key's nonce too"
        );
    }

    #[test]
    fn a_key_that_fills_its_share_refuses_only_itself_until_its_nonces_expire() {
        let cache = ReplayCache::default();
        for i in 0..MAX_NONCES_PER_KEY {
            assert_eq!(
                cache.first_use("noisy", &i.to_string(), 100, 0, true),
                Use::First
            );
        }
        assert_eq!(
            cache.first_use("noisy", "one-more", 100, 1, true),
            Use::Full,
            "a bound key with no room is refused, never unchecked"
        );
        assert_eq!(
            cache.first_use("quiet", "n", 100, 1, true),
            Use::First,
            "another key is unaffected"
        );
        assert_eq!(
            cache.first_use("noisy", "one-more", 200, 101, true),
            Use::First,
            "after they expire"
        );
    }

    /// Keys no host binds share one pool. While it is full of live nonces a
    /// new one is unchecked, not refused; one it holds is still a replay;
    /// and no bound key is affected (ruling u290 §2).
    #[test]
    fn a_full_unbound_pool_leaves_new_nonces_unchecked_and_bound_keys_alone() {
        let cache = ReplayCache::default();
        for i in 0..MAX_UNBOUND_NONCES {
            assert_eq!(
                cache.first_use(&format!("k{i}"), "n", 100, 0, false),
                Use::First
            );
        }
        assert_eq!(cache.first_use("fresh", "n", 100, 1, false), Use::Unchecked);
        assert_eq!(
            cache.first_use("fresh", "n", 100, 2, false),
            Use::Unchecked,
            "an unchecked nonce is not held"
        );
        assert_eq!(cache.first_use("k0", "n", 100, 1, false), Use::Replayed);
        assert_eq!(cache.first_use("bound", "n", 100, 1, true), Use::First);
        assert_eq!(cache.first_use("bound", "n", 100, 1, true), Use::Replayed);
    }

    /// Nonces past their deadline are pruned from a full unbound pool, so
    /// the room they held is checked again; live ones stay held.
    #[test]
    fn a_full_unbound_pool_prunes_nonces_past_their_deadline() {
        let cache = ReplayCache::default();
        let half = MAX_UNBOUND_NONCES / 2;
        for i in 0..MAX_UNBOUND_NONCES {
            let deadline = if i < half { 100 } else { 300 };
            assert_eq!(
                cache.first_use(&format!("k{i}"), "n", deadline, 0, false),
                Use::First
            );
        }
        assert_eq!(
            cache.first_use("fresh", "n", 400, 100, false),
            Use::Unchecked,
            "at its deadline a nonce is live"
        );
        assert_eq!(
            cache.first_use("fresh", "n", 400, 101, false),
            Use::First,
            "past it, pruned"
        );
        assert_eq!(
            cache.first_use("fresh", "n", 400, 102, false),
            Use::Replayed,
            "and the new one is held"
        );
        assert_eq!(
            cache.first_use(&format!("k{half}"), "n", 300, 102, false),
            Use::Replayed,
            "a live nonce survives the prune"
        );
    }

    /// A signed request captured before a restart is refused after it while
    /// its deadline lasts: the horizon on disk outlives the nonces in memory
    /// (evidencebook#206 row 1). A request signed after the restart, with a
    /// deadline past the horizon, is held as usual.
    #[test]
    fn a_nonce_held_before_a_restart_is_refused_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let before = ReplayCache::persisted(dir.path(), 0);
        assert_eq!(before.first_use("k", "n", 120, 0, true), Use::First);
        assert_eq!(before.first_use("u", "n", 120, 0, false), Use::First);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(HORIZON_FILE)).unwrap(),
            (120 + HORIZON_STEP_SECS).to_string(),
            "written before the nonce is held, one step ahead"
        );
        assert_eq!(
            before.first_use("k", "m", 120 + HORIZON_STEP_SECS, 1, true),
            Use::First
        );
        drop(before);

        let after = ReplayCache::persisted(dir.path(), 10);
        assert_eq!(
            after.first_use("k", "n", 120, 10, true),
            Use::Full,
            "a bound key's replay is refused"
        );
        assert_eq!(
            after.first_use("u", "n", 120, 10, false),
            Use::Unchecked,
            "an unbound key's reads as unsigned"
        );
        assert_eq!(
            after.first_use("k", "fresh", 120 + HORIZON_STEP_SECS, 10, true),
            Use::Full,
            "at the horizon a deadline may still be one held before"
        );
        let past = 121 + HORIZON_STEP_SECS;
        assert_eq!(after.first_use("k", "fresh", past, 10, true), Use::First);
        assert_eq!(after.first_use("k", "fresh", past, 11, true), Use::Replayed);
    }

    /// No file: a first run refuses nothing. An unreadable horizon, or one
    /// past the latest a held nonce could have, counts as that latest one.
    #[test]
    fn the_horizon_is_bounded_when_missing_unreadable_or_too_late() {
        let latest = 1000 + MAX_WINDOW_SECS + HORIZON_STEP_SECS;
        let dir = tempfile::tempdir().unwrap();
        let first_run = ReplayCache::persisted(dir.path(), 1000);
        assert_eq!(first_run.first_use("k", "n", 1001, 1000, true), Use::First);

        for text in ["not a number", "999999999"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(HORIZON_FILE), text).unwrap();
            let cache = ReplayCache::persisted(dir.path(), 1000);
            assert_eq!(
                cache.first_use("k", "a", latest, 1000, true),
                Use::Full,
                "{text}"
            );
            assert_eq!(
                cache.first_use("k", "b", latest + 1, 1000, true),
                Use::First,
                "{text}"
            );
        }
    }

    /// A bound key's nonce is not held when the horizon cannot be written
    /// first, since a restart would forget it; an unbound key's never needs
    /// the horizon written.
    #[test]
    fn a_nonce_is_not_held_when_its_horizon_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ReplayCache::persisted(&dir.path().join("missing"), 0);
        assert_eq!(cache.first_use("k", "n", 120, 0, true), Use::Full);
        assert_eq!(
            cache.first_use("k", "n", 120, 1, true),
            Use::Full,
            "and still not held"
        );
        assert_eq!(cache.first_use("u", "n", 120, 0, false), Use::First);
    }

    /// A key anyone can make cannot lengthen what a restart refuses: an
    /// unbound key's longest deadline before the restart leaves the horizon
    /// alone, so a bound key's ordinary request after it is held.
    #[test]
    fn an_unbound_key_never_moves_the_horizon() {
        let dir = tempfile::tempdir().unwrap();
        let before = ReplayCache::persisted(dir.path(), 0);
        assert_eq!(
            before.first_use("u", "n", MAX_WINDOW_SECS, 0, false),
            Use::First
        );
        assert!(!dir.path().join(HORIZON_FILE).exists());
        assert_eq!(before.first_use("k", "n", 20, 0, true), Use::First);
        drop(before);

        let after = ReplayCache::persisted(dir.path(), 10);
        assert_eq!(
            after.first_use("k", "fresh", 10 + ASKER_DEADLINE_SECS, 10, true),
            Use::First,
            "the horizon is the bound key's 20 + {HORIZON_STEP_SECS}, not the unbound 300"
        );
    }

    /// The horizon file is written once per step of deadlines, not per
    /// request.
    #[test]
    fn the_horizon_is_written_once_per_step() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(HORIZON_FILE);
        let cache = ReplayCache::persisted(dir.path(), 0);
        assert_eq!(cache.first_use("k", "0", 100, 0, true), Use::First);
        std::fs::remove_file(&file).unwrap();
        for i in 1..=HORIZON_STEP_SECS {
            assert_eq!(
                cache.first_use("k", &i.to_string(), 100 + i, 0, true),
                Use::First
            );
        }
        assert!(
            !file.exists(),
            "inside the kept horizon, nothing is written"
        );
        assert_eq!(
            cache.first_use("k", "next", 101 + HORIZON_STEP_SECS, 0, true),
            Use::First
        );
        assert!(file.exists());
    }

    /// The audience is this node's id, exactly; a node that does not know
    /// its id matches nothing.
    #[test]
    fn the_audience_must_be_exactly_this_node() {
        assert!(audience_matches(Some("node-r"), Some("node-r")));
        assert!(!audience_matches(Some("node-x"), Some("node-r")));
        assert!(!audience_matches(Some("node-r "), Some("node-r")));
        assert!(!audience_matches(Some("node-r"), None));
        assert!(!audience_matches(None, Some("node-r")));
    }

    #[test]
    fn a_request_that_cannot_be_signed_is_sent_as_given() {
        let mut request =
            json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 1.5}});
        let given = request.clone();
        sign(
            Channel::EvidenceRequest,
            &mut request,
            &key(1),
            at("2026-10-13T00:00:00Z"),
            "node-r",
        );
        assert_eq!(
            request, given,
            "no nonce or deadline added to an unsigned request"
        );
    }

    /// Only a request that would be checked to a principal counts as one: a
    /// bad signature, another audience or channel, a deadline past or too far
    /// ahead, an unbound key and a false claim are all strangers.
    #[test]
    fn only_a_request_that_checks_to_a_principal_proves_one() {
        let now = evidence_request::time::parse_utc("2026-10-13T00:00:00Z").unwrap();
        let k = hex::encode(key(1).verifying_key().to_bytes());
        let announced = BTreeMap::from([("node-a".to_string(), k)]);
        let keys = Keys {
            announced: &announced,
            configured: None,
            own_key: None,
        };
        let proves = |map: &Map<String, Value>, own: Option<&str>| {
            proves_principal(Channel::EvidenceRequest, map, now, keys, own).is_some()
        };
        let good = signed(1);
        assert_eq!(
            proves_principal(Channel::EvidenceRequest, &good, now, keys, Some("node-r")),
            Some(announced["node-a"].clone()),
            "the key whose share it draws on"
        );
        assert!(
            proves_principal(Channel::RefereeAdjudicate, &good, now, keys, Some("node-r"))
                .is_none(),
            "another channel's tag"
        );
        assert!(!proves(&good, Some("node-x")), "another audience");
        assert!(!proves(&good, None), "a node that does not know its id");
        assert!(!proves(&signed(2), Some("node-r")), "a key no host binds");
        let mut unsigned = good.clone();
        unsigned.remove(MEMBER);
        assert!(!proves(&unsigned, Some("node-r")));
        let mut tampered = good.clone();
        tampered.insert("nonce".into(), json!("n-2"));
        assert!(!proves(&tampered, Some("node-r")), "a bad signature");
        let with_deadline = |deadline: &str| {
            let mut m = good.clone();
            m.remove(MEMBER);
            m.insert("deadline".into(), json!(deadline));
            let mut v = Value::Object(m);
            sign(
                Channel::EvidenceRequest,
                &mut v,
                &key(1),
                at("2026-10-13T00:00:00Z"),
                "node-r",
            );
            v.as_object().unwrap().clone()
        };
        assert!(proves(
            &with_deadline("2026-10-13T00:05:00Z"),
            Some("node-r")
        ));
        assert!(
            !proves(&with_deadline("2026-10-13T00:05:01Z"), Some("node-r")),
            "past the window"
        );
        assert!(
            !proves(&with_deadline("2026-10-12T23:59:59Z"), Some("node-r")),
            "already past"
        );
        let mut claims = good.clone();
        claims.insert("requester_id".into(), json!("node-z"));
        assert!(!proves(&claims, Some("node-r")), "a false claim");
    }

    /// The asker signs only once its key is announced, and then signs every
    /// request it sends.
    #[test]
    fn an_asker_signs_only_once_its_key_is_announced() {
        let asker = AskerKey::default();
        let mut request = json!({"subject": {"checkpoints": null}});
        asker.sign_outgoing(Channel::EvidenceRequest, &mut request, "node-r");
        assert_eq!(form(request.as_object().unwrap()), Form::Unsigned);
        asker.set_announced(key(3));
        asker.sign_outgoing(Channel::EvidenceRequest, &mut request, "node-r");
        assert_eq!(
            request[AUDIENCE],
            json!("node-r"),
            "addressed to the node it goes to"
        );
        let Form::Signed { key_id, sig } = form(request.as_object().unwrap()) else {
            panic!("not signed: {request}");
        };
        assert_eq!(key_id, hex::encode(key(3).verifying_key().to_bytes()));
        assert!(verifies(
            Channel::EvidenceRequest,
            request.as_object().unwrap(),
            &key_id,
            &sig
        ));
    }
}
