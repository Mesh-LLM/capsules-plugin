//! The join switch (loop step 12, Mesh-LLM/capsules-plugin#53): a node joins
//! the evidence network's list with one signed statement, and leaves it by
//! turning the switch off.
//!
//! **The switch.** `join_network` in the capsules configuration pane, off by
//! default. The pane shows the switch statement under it word for word: loop's
//! `joins/SWITCH_CONSENT.txt`, copied byte for byte into `loop/` at
//! [`LOOP_REVISION`] (Steven's yes on the text, 2026-10-28). Only an explicit
//! on joins; a value the plugin does not know is off, and a config file that
//! does not parse leaves it off (`settings::narrowest`).
//!
//! **The records.** A join is loop's `join/1` exactly (`joins/README.md`):
//! `kind`, `node_id` (the mesh node id), `key_id` and `spki` (this node's
//! plugin key), `consent_sha256` (the statement's sha256), `at`, and `sig`,
//! Ed25519 over the JCS form without `sig`, the same signing as the
//! commitment. A leave is the same object with `leave/1`. Neither carries a
//! handle, an operator or any other personal data.
//!
//! **Who receives them.** The reporter node that loop's `reporter/reporter.json`
//! names, at the pinned revision; `CAPSULES_JOIN_REPORTER` (console
//! `join_reporter`) overrides it, for a lab mesh. While the id is all zeros,
//! as it is today, nothing is sent.
//!
//! **The channel.** `join/1`, a plugin mesh channel like `commitment/1`, tagged
//! in `metadata_json`. The node writes the record and half-closes; the reporter
//! writes `{"ok": true}` or `{"error": "<why>"}`.
//!
//! **When the node sends.** A task checks the switch every minute. On, it sends
//! a join unless the reporter already acknowledged one under this key and this
//! statement under its current mesh id; so a node joins once, and again only
//! when the statement, the key, the reporter or its id changes (a client
//! node's id is new each start: the old id's join is left first, when it is
//! at the reporter in force). Off after a
//! join was sent, acknowledged or not, it sends a leave to that reporter. A
//! join that fails is tried again after each
//! wait in `retry_after_s` in turn, then not until the switch changes or the
//! plugin restarts. A leave is never given up: after the last wait it is tried
//! again at that wait until the reporter takes it, since the statement promises
//! that turning the switch off stops the asks. The last record is kept in the
//! data directory ([`STATE_FILE`]) before it is sent, with whether the reporter
//! acknowledged it, so a join whose reply was lost is still left; the `join`
//! operation reports what was acknowledged and what is still owed.
//!
//! **The reporter's side.** The reporter node runs this plugin too. A node
//! takes `join/1` only when it is the reporter (its own id is the reporter id
//! above), checks each record as loop's `scripts/check_join.py` does, and keeps
//! the latest join of each node and the leave that ends it, if any, in
//! [`JOINS_DIR`] for the daily reporter to commit. A directory of these passes
//! `check_join.py`'s order check: a leave is kept only beside the join it ends
//! (a leave of a node not joined there is acknowledged and kept apart, in
//! [`ENDED_DIR`], never listed, so the join it ends is refused if it arrives
//! later).
//! The mesh does not tell the reporter which node sent a record, so the key is
//! what binds it: a record is refused when its key is not the one the host
//! announced for its `node_id`, and a node held under one key moves to another
//! only when the host announced the new one. With no announced key, a join
//! that names someone else's node only gets that node asked what it answers
//! any stranger, under its own key. The reporter holds at most [`MAX_NODES`].

use evidence_request::registry::is_digest;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use ed25519_dalek::SigningKey;
use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{bind_side_stream, LocalListener, PluginContext, PluginError, PluginResult};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::commitment;
use crate::mesh_evidence_bridge::{env_millis, next_stream_id, read_to_end_bounded};
use crate::self_peer::SelfPeer;

/// The mesh channel, declared on both ends, and the tag the sender puts in
/// its open's `metadata_json`.
pub const JOIN_CHANNEL: &str = "join/1";

pub const KIND_JOIN: &str = "join/1";
pub const KIND_LEAVE: &str = "leave/1";

/// The evidence-network/loop revision `loop/` was copied from (and
/// `loop/README.md` names).
#[cfg(test)]
pub const LOOP_REVISION: &str = "9e45b3aad5655b041c5ee2079923870dcb6514f0";

/// The statement shown under the switch, byte for byte (no trailing newline).
pub const SWITCH_CONSENT: &str = include_str!("../../../loop/joins/SWITCH_CONSENT.txt");

/// loop's `reporter/reporter.json` at [`LOOP_REVISION`].
const PINNED_REPORTER: &str = include_str!("../../../loop/reporter/reporter.json");

/// The switch: console key and environment name.
pub const JOIN_NETWORK_KEY: &str = "join_network";
pub const ENV_JOIN_NETWORK: &str = "CAPSULES_JOIN_NETWORK";

/// The reporter node id, over the pinned one.
pub const ENV_JOIN_REPORTER: &str = "CAPSULES_JOIN_REPORTER";

/// The last record sent and whether it was acknowledged, in the data directory.
pub const STATE_FILE: &str = "network-join.json";

/// The reporter's joins and leaves, in the data directory.
pub const JOINS_DIR: &str = "joins";

/// Leaves of nodes not joined there, in the data directory: never listed.
pub const ENDED_DIR: &str = "joins-ended";

/// How far in the future a record's `at` may be (`check_join.py`'s `SKEW`).
const SKEW: chrono::Duration = chrono::Duration::minutes(5);

/// The members of a record and whether each is a string (`sig` is an object).
const FIELDS: [(&str, bool); 7] = [
    ("kind", true),
    ("node_id", true),
    ("key_id", true),
    ("consent_sha256", true),
    ("at", true),
    ("spki", true),
    ("sig", false),
];

/// The sha256 of the switch statement's bytes: what a join signs.
pub fn consent_sha256() -> String {
    hex::encode(Sha256::digest(SWITCH_CONSENT.as_bytes()))
}

/// Whether the operator turned the switch on.
pub fn switch_on() -> bool {
    crate::share_policy::switched_on(crate::settings::var(ENV_JOIN_NETWORK).ok().as_deref())
}

// ---------------------------------------------------------------------
// The reporter
// ---------------------------------------------------------------------

/// The pinned reporter's id and its waits between tries, in seconds.
fn pinned() -> (String, Vec<u64>) {
    let doc: Value =
        serde_json::from_str(PINNED_REPORTER).expect("loop/reporter/reporter.json is JSON");
    let id = doc["node_id"].as_str().unwrap_or_default().to_string();
    let waits = doc["retry_after_s"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    (id, waits)
}

/// The waits between tries of one send.
pub fn retry_after() -> Vec<u64> {
    pinned().1
}

/// The reporter node id in force, from `overridden` (the setting) or the
/// pinned file; `None` while it is all zeros or not a node id.
pub fn reporter_from(overridden: Option<&str>) -> Option<String> {
    let id = match overridden.map(str::trim).filter(|s| !s.is_empty()) {
        Some(set) => set.to_ascii_lowercase(),
        None => pinned().0,
    };
    (is_digest(&id) && id.bytes().any(|b| b != b'0')).then_some(id)
}

/// [`reporter_from`] this process's setting.
pub fn reporter() -> Option<String> {
    reporter_from(crate::settings::var(ENV_JOIN_REPORTER).ok().as_deref())
}

// ---------------------------------------------------------------------
// The records
// ---------------------------------------------------------------------

/// A signed `kind` record of `node_id` under `key`, at `at`.
pub fn record(kind: &str, node_id: &str, key: &SigningKey, at: &str) -> Value {
    commitment::sign(
        json!({
            "kind": kind,
            "node_id": node_id,
            "key_id": commitment::key_id(key),
            "consent_sha256": consent_sha256(),
            "at": at,
            "spki": commitment::spki_b64(&key.verifying_key()),
        }),
        key,
    )
}

fn parse_at(s: &str) -> Option<DateTime<Utc>> {
    let shaped = s.len() == 20
        && s.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            10 => b == b'T',
            13 | 16 => b == b':',
            19 => b == b'Z',
            _ => b.is_ascii_digit(),
        });
    shaped
        .then(|| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ").ok())
        .flatten()
        .map(|t| t.and_utc())
}

fn at_of(doc: &Value) -> DateTime<Utc> {
    parse_at(doc["at"].as_str().unwrap_or_default()).unwrap_or_default()
}

/// Why `doc` is refused, as `check_join.py`'s `verify` says it: empty when it
/// passes. `now` bounds `at`.
pub fn problems(doc: &Value, now: DateTime<Utc>) -> Vec<String> {
    let Some(map) = doc.as_object() else {
        return vec!["not a JSON object".into()];
    };
    let mut errs: Vec<String> = FIELDS
        .iter()
        .filter(|(name, _)| !map.contains_key(*name))
        .map(|(name, _)| format!("missing {name}"))
        .collect();
    let mut unknown: Vec<&String> = map
        .keys()
        .filter(|k| !FIELDS.iter().any(|(name, _)| name == k))
        .collect();
    unknown.sort();
    errs.extend(unknown.into_iter().map(|k| format!("unknown field {k}")));
    for (name, string) in FIELDS {
        match map.get(name) {
            Some(v) if string && !v.is_string() => errs.push(format!("{name} must be a str")),
            Some(v) if !string && !v.is_object() => errs.push(format!("{name} must be a dict")),
            _ => {}
        }
    }
    if !errs.is_empty() {
        return errs;
    }
    let text = |name: &str| map[name].as_str().unwrap_or_default();
    if ![KIND_JOIN, KIND_LEAVE].contains(&text("kind")) {
        errs.push(format!("kind must be one of {KIND_JOIN}, {KIND_LEAVE}"));
    }
    for name in ["node_id", "key_id", "consent_sha256"] {
        if !is_digest(text(name)) {
            errs.push(format!("{name} is not 64 lowercase hex"));
        }
    }
    let at = parse_at(text("at"));
    if at.is_none() {
        errs.push("at must be YYYY-MM-DDTHH:MM:SSZ (UTC), a real time".into());
    }
    if !errs.is_empty() {
        return errs;
    }
    match commitment::key_of(doc) {
        Err(why) => errs.push(why),
        Ok(key) if !commitment::signature_verifies(doc, &key) => {
            errs.push("signature does not verify under spki".into())
        }
        Ok(_) => {}
    }
    if text("consent_sha256") != consent_sha256() {
        errs.push(
            "consent_sha256 is not the digest of the switch statement in joins/SWITCH_CONSENT.txt"
                .into(),
        );
    }
    if at.is_some_and(|at| at > now + SKEW) {
        errs.push(format!("at {} is in the future", text("at")));
    }
    errs
}

// ---------------------------------------------------------------------
// The node's side
// ---------------------------------------------------------------------

/// The last record this node sent, which reporter it went to, and whether
/// that reporter acknowledged it. A record is kept before it is sent, so a
/// join the reporter took whose reply was lost is still left when the switch
/// goes off.
#[derive(Clone, Debug, PartialEq)]
pub struct Acked {
    pub record: Value,
    pub reporter: String,
    pub acknowledged: bool,
}

/// What is due now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Due {
    Nothing,
    /// A join, to this reporter.
    Join(String),
    /// A leave, to the reporter that took the join.
    Leave(String),
}

/// What the node owes the reporter, from the switch, the last acknowledged
/// record, this node's key and mesh id, and the reporter in force. A client
/// node's mesh id is new each time it starts (`self_peer`): the join of an
/// earlier id is left first, so no id the node no longer has stays listed.
pub fn due(
    switch_on: bool,
    acked: Option<&Acked>,
    key_id: &str,
    node_id: &str,
    reporter: Option<&str>,
) -> Due {
    // A join sent, acknowledged or not, may be held; so may the join an
    // unacknowledged leave was ending.
    let joined = acked.filter(|a| a.record["kind"] == KIND_JOIN || !a.acknowledged);
    match (switch_on, joined) {
        // The old id is left at the reporter in force; a former reporter is
        // not chased, as for a join (it may be gone for good).
        (true, Some(a))
            if a.record["node_id"] != node_id && Some(a.reporter.as_str()) == reporter =>
        {
            Due::Leave(a.reporter.clone())
        }
        (true, Some(a))
            if a.acknowledged
                && a.record["kind"] == KIND_JOIN
                && a.record["key_id"] == key_id
                && a.record["consent_sha256"] == consent_sha256().as_str()
                && Some(a.reporter.as_str()) == reporter =>
        {
            Due::Nothing
        }
        (true, _) => reporter.map_or(Due::Nothing, |r| Due::Join(r.to_string())),
        (false, Some(a)) => Due::Leave(a.reporter.clone()),
        (false, None) => Due::Nothing,
    }
}

fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATE_FILE)
}

/// The last record sent, when there is one.
pub fn load(data_dir: &Path) -> Option<Acked> {
    let raw = std::fs::read(state_path(data_dir)).ok()?;
    let doc: Value = serde_json::from_slice(&raw).ok()?;
    Some(Acked {
        record: doc.get("record")?.clone(),
        reporter: doc.get("reporter")?.as_str()?.to_string(),
        acknowledged: doc.get("acknowledged")?.as_bool()?,
    })
}

fn save(data_dir: &Path, acked: &Acked) -> std::io::Result<()> {
    let doc = json!({
        "record": acked.record,
        "reporter": acked.reporter,
        "acknowledged": acked.acknowledged,
    });
    write_atomically(&state_path(data_dir), &doc)
}

pub(crate) fn write_atomically(path: &Path, doc: &Value) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut bytes = serde_json::to_vec_pretty(doc).expect("a JSON value serializes");
    bytes.push(b'\n');
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// The tries of one send: what is being sent, how many failed, and when the
/// next may go.
#[derive(Debug, Default)]
pub struct Tries {
    sending: Option<Due>,
    failed: usize,
    next: Option<std::time::Instant>,
}

impl Tries {
    /// Whether `due` may be sent at `now`; a new `due` starts its tries over.
    pub fn may_send(&mut self, due: &Due, now: std::time::Instant) -> bool {
        if self.sending.as_ref() != Some(due) {
            *self = Tries {
                sending: Some(due.clone()),
                ..Tries::default()
            };
        }
        let leave = matches!(due, Due::Leave(_));
        (leave || self.failed <= retry_after().len()) && self.next.is_none_or(|next| now >= next)
    }

    /// A send failed at `now`: the next waits `retry_after_s` in turn. None
    /// follows a join's last try; a leave's tries go on at the last wait.
    pub fn failed(&mut self, now: std::time::Instant) -> bool {
        let waits = retry_after();
        let mut wait = waits.get(self.failed).copied();
        if matches!(self.sending, Some(Due::Leave(_))) {
            wait = wait.or(waits.last().copied());
        }
        self.failed += 1;
        self.next = wait.map(|s| now + Duration::from_secs(s));
        wait.is_some()
    }
}

/// How often the switch is checked.
fn tick() -> Duration {
    env_millis("CAPSULES_JOIN_TICK_MS", 60_000)
}

/// How long the node waits for the reporter's reply once the stream is open.
fn requester_timeout() -> Duration {
    env_millis("CAPSULES_JOIN_TIMEOUT_MS", 8_000)
}

/// Check the switch every [`tick`] for as long as the plugin runs, and send
/// what is due.
pub fn start(
    context: PluginContext<'static>,
    signing_key: SigningKey,
    self_peer: SelfPeer,
    data_dir: PathBuf,
) {
    tokio::spawn(async move {
        let mut context = context;
        let mut tries = Tries::default();
        loop {
            step(
                &mut context,
                &signing_key,
                &self_peer,
                &data_dir,
                &mut tries,
            )
            .await;
            tokio::time::sleep(tick()).await;
        }
    });
}

async fn step(
    context: &mut PluginContext<'static>,
    key: &SigningKey,
    self_peer: &SelfPeer,
    data_dir: &Path,
    tries: &mut Tries,
) {
    let Some(node_id) = self_peer.current() else {
        return;
    };
    let now = Now {
        instant: std::time::Instant::now(),
        utc: Utc::now(),
    };
    let reporter = reporter();
    let registry = crate::peer_keys::registry();
    let node = Node {
        key,
        node_id: &node_id,
        data_dir,
    };
    let send = |to: String, doc: Value| async move { send(context, &to, &doc).await };
    tick_once(
        &node,
        switch_on(),
        reporter.as_deref(),
        registry.as_deref(),
        tries,
        now,
        send,
    )
    .await;
}

/// The node a tick is for.
struct Node<'a> {
    key: &'a SigningKey,
    node_id: &'a str,
    data_dir: &'a Path,
}

/// When a tick runs.
#[derive(Clone, Copy)]
struct Now {
    instant: std::time::Instant,
    utc: DateTime<Utc>,
}

/// One tick with everything it reads given: what is due, if it may go now,
/// signed and sent with `send` (or taken here when this node is the
/// reporter), and the acknowledgement recorded. Returns what was sent.
async fn tick_once<F, Fut>(
    node: &Node<'_>,
    switch_on: bool,
    reporter: Option<&str>,
    registry: Option<&str>,
    tries: &mut Tries,
    now: Now,
    send: F,
) -> Option<Result<(), String>>
where
    F: FnOnce(String, Value) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let acked = load(node.data_dir);
    let key_id = commitment::key_id(node.key);
    let due = due(switch_on, acked.as_ref(), &key_id, node.node_id, reporter);
    let (kind, to, node_id, at) = match &due {
        Due::Nothing => {
            // A switch turned off and on again starts a join's tries over.
            *tries = Tries::default();
            return None;
        }
        Due::Join(to) => (KIND_JOIN, to.clone(), node.node_id.to_string(), now.utc),
        Due::Leave(to) => {
            // A leave names the id its join named, and is never older than it
            // (nor than an earlier try of the same leave).
            let joined = &acked.as_ref().expect("a leave follows a join").record;
            let id = joined["node_id"].as_str().unwrap_or_default().to_string();
            (KIND_LEAVE, to.clone(), id, now.utc.max(at_of(joined)))
        }
    };
    if !tries.may_send(&due, now.instant) {
        return None;
    }
    let doc = record(
        kind,
        &node_id,
        node.key,
        &at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    );
    let mut kept = Acked {
        record: doc.clone(),
        reporter: to.clone(),
        acknowledged: false,
    };
    if let Err(error) = save(node.data_dir, &kept) {
        // Unkept, a join whose reply was lost could never be left.
        tracing::warn!(%error, kind, "could not keep the record before sending it; not sent");
        return None;
    }
    let sent = if to == node.node_id {
        // This node is the reporter: it takes its own record.
        intake(
            &serde_json::to_vec(&doc).unwrap_or_default(),
            Some(node.node_id),
            reporter,
            registry,
            node.data_dir,
            now.utc,
        )
    } else {
        send(to.clone(), doc.clone()).await
    };
    match &sent {
        Ok(()) => {
            tries.sending = None;
            kept.acknowledged = true;
            match save(node.data_dir, &kept) {
                Ok(()) => {
                    tracing::info!(kind, reporter = %to, "the reporter acknowledged this node's {kind}")
                }
                Err(error) => {
                    tracing::warn!(%error, kind, "the reporter acknowledged, but it could not be recorded")
                }
            }
        }
        Err(error) => {
            let again = tries.failed(now.instant);
            tracing::warn!(%error, kind, reporter = %to, again, "the reporter did not take this node's {kind}");
        }
    }
    Some(sent)
}

/// Send `doc` to `reporter` over [`JOIN_CHANNEL`]: `Ok` only on `{"ok": true}`.
async fn send(
    context: &mut PluginContext<'static>,
    reporter: &str,
    doc: &Value,
) -> Result<(), String> {
    let open_request = OpenMeshStreamRequest {
        stream_id: next_stream_id("join"),
        target_peer_id: reporter.to_string(),
        plugin_id: String::new(), // the host fills this in.
        channel: JOIN_CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some("application/json".to_string()),
        correlation_id: Some(next_stream_id("join-correlation")),
        metadata_json: Some(JOIN_CHANNEL.to_string()),
        expected_bytes: None,
        idle_timeout_ms: Some(requester_timeout().as_millis() as u64),
    };
    let stream = context
        .connect_mesh_stream(open_request)
        .await
        .map_err(|e| format!("could not reach the reporter: {e}"))?;
    let (read_half, mut write_half) = stream.into_split();
    let body = serde_json::to_vec(doc).map_err(|e| e.to_string())?;
    let bytes = tokio::time::timeout(requester_timeout(), async {
        write_half.write_all(&body).await?;
        write_half.shutdown().await?;
        read_to_end_bounded(read_half, "reporter join reply").await
    })
    .await
    .map_err(|_| "the reporter did not reply in time".to_string())?
    .map_err(|e| format!("the reporter's reply could not be read: {e}"))?;
    let reply: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("the reporter's reply is not JSON: {e}"))?;
    match (reply.get("ok"), reply.get("error")) {
        (Some(Value::Bool(true)), _) => Ok(()),
        (_, Some(why)) => Err(format!(
            "the reporter refused it: {}",
            why.as_str().unwrap_or_default()
        )),
        _ => Err("the reporter's reply is neither ok nor an error".into()),
    }
}

/// The `network` part of the `join` operation: the switch, the reporter,
/// what the reporter last acknowledged, and what this node, with `key_id` and
/// mesh id `node_id` (if known yet), still has to send it (`join/1`,
/// `leave/1`, or null).
pub fn status(data_dir: &Path, key_id: &str, node_id: Option<&str>) -> Value {
    let acked = load(data_dir);
    let reporter = reporter();
    // Before the host names this node, judge by the id last sent.
    let node_id = node_id
        .map(str::to_string)
        .or_else(|| {
            acked
                .as_ref()
                .and_then(|a| a.record["node_id"].as_str().map(str::to_string))
        })
        .unwrap_or_default();
    let unsent = match due(
        switch_on(),
        acked.as_ref(),
        key_id,
        &node_id,
        reporter.as_deref(),
    ) {
        Due::Nothing => None,
        Due::Join(_) => Some(KIND_JOIN),
        Due::Leave(_) => Some(KIND_LEAVE),
    };
    json!({
        "switch": if switch_on() { "on" } else { "off" },
        "reporter": reporter,
        "unacknowledged": unsent,
        "acknowledged": acked.filter(|a| a.acknowledged).map(|a| json!({
            "kind": a.record["kind"],
            "at": a.record["at"],
            "reporter": a.reporter,
        })),
    })
}

// ---------------------------------------------------------------------
// The reporter's side
// ---------------------------------------------------------------------

/// True exactly when an inbound `OpenStreamRequest` is this module's.
pub fn is_join_request(request: &OpenStreamRequest) -> bool {
    request.metadata_json.as_deref() == Some(JOIN_CHANNEL)
}

/// The key the keys this node holds give `node_id`: `None` when there is
/// none. An entry that is not one key (the host's announcement and the
/// configured key disagree, `peer_keys::merged`), or keys that are not a JSON
/// object, refuse the record: that is "cannot check", not "no key known".
fn known_key(registry: Option<&str>, node_id: &str) -> Result<Option<String>, String> {
    let Some(raw) = registry.filter(|raw| !raw.is_empty()) else {
        return Ok(None);
    };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else {
        return Err("the keys this node holds cannot be read".into());
    };
    match map.get(node_id) {
        None => Ok(None),
        Some(Value::String(key)) if is_digest(key) => Ok(Some(key.clone())),
        Some(_) => Err("the keys this node holds for node_id disagree".into()),
    }
}

/// The most nodes the reporter holds a join of: every one costs a file, and
/// any mesh peer can sign a join.
pub const MAX_NODES: usize = 10_000;

/// How many nodes `dir` holds a join of.
fn held_nodes(dir: &Path) -> usize {
    held_nodes_in(dir, ".join.json")
}

/// How many files in `dir` end with `suffix`.
fn held_nodes_in(dir: &Path, suffix: &str) -> usize {
    std::fs::read_dir(dir).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(suffix))
            .count()
    })
}

/// One writer of [`JOINS_DIR`] at a time.
static INTAKE: Mutex<()> = Mutex::new(());

/// Take one record's bytes as the reporter: check it and keep it.
pub fn intake_bytes(bytes: &[u8], self_id: Option<&str>, data_dir: &Path) -> Result<(), String> {
    intake(
        bytes,
        self_id,
        reporter().as_deref(),
        crate::peer_keys::registry().as_deref(),
        data_dir,
        Utc::now(),
    )
}

/// [`intake_bytes`] with everything it reads from the process given.
pub fn intake(
    bytes: &[u8],
    self_id: Option<&str>,
    reporter: Option<&str>,
    registry: Option<&str>,
    data_dir: &Path,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let dir = &data_dir.join(JOINS_DIR);
    if self_id.is_none() || self_id != reporter {
        return Err("this node is not the reporter".into());
    }
    let doc: Value = serde_json::from_slice(bytes).map_err(|_| "not valid JSON".to_string())?;
    let errs = problems(&doc, now);
    if !errs.is_empty() {
        return Err(errs.join("; "));
    }
    let node_id = doc["node_id"].as_str().unwrap_or_default();
    let announced = known_key(registry, node_id)?;
    if announced
        .as_ref()
        .is_some_and(|key| doc["key_id"] != key.as_str())
    {
        return Err("key_id is not the key the host announced for node_id".into());
    }
    let _one = INTAKE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::fs::create_dir_all(dir).map_err(|e| format!("could not keep it: {e}"))?;
    let join_path = dir.join(format!("{node_id}.join.json"));
    let leave_path = dir.join(format!("{node_id}.leave.json"));
    // A leave that arrived before any join here: kept apart from the list, one
    // per node and key (another key's leave never replaces it), so a join it
    // ends that arrives later, late or replayed, is refused.
    let key_id = doc["key_id"].as_str().unwrap_or_default();
    let ended_path = data_dir
        .join(ENDED_DIR)
        .join(format!("{node_id}.{key_id}.json"));
    let held =
        |path: &Path| -> Option<Value> { serde_json::from_slice(&std::fs::read(path).ok()?).ok() };
    let at = at_of(&doc);
    let keep =
        |path: &Path| write_atomically(path, &doc).map_err(|e| format!("could not keep it: {e}"));
    if doc["kind"] == KIND_JOIN {
        match held(&join_path) {
            Some(join) if join == doc => return Ok(()),
            Some(join) if at_of(&join) > at => {
                return Err("a later join of this node is held".into())
            }
            // The mesh does not say who sent a record, so a node held under
            // one key moves to another only when the host announced it.
            Some(join) if join["key_id"] != doc["key_id"] && announced.is_none() => {
                return Err(
                    "this node is held under another key, and the host announced none for it"
                        .into(),
                )
            }
            Some(_) => {}
            None if held_nodes(dir) >= MAX_NODES => {
                return Err(format!(
                    "the reporter holds {MAX_NODES} nodes, the most it takes"
                ))
            }
            None => {}
        }
        let ends = |leave: &Value| at_of(leave) >= at;
        if held(&leave_path).is_some_and(|leave| ends(&leave))
            || held(&ended_path)
                .is_some_and(|leave| ends(&leave) && leave["key_id"] == doc["key_id"])
        {
            return Err("a later leave of this node is held".into());
        }
        // The earlier leave goes first: stopped between the two steps, the
        // directory holds the earlier join alone, never a leave older than
        // its join.
        match std::fs::remove_file(&leave_path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("could not drop the earlier leave: {e}"))
            }
            _ => {}
        }
        keep(&join_path)
    } else {
        // A leave of a node not joined here is taken, so a node whose join
        // never arrived can still leave, and kept apart from the list.
        let Some(join) = held(&join_path) else {
            if held(&ended_path).is_some_and(|leave| at_of(&leave) >= at) {
                return Ok(());
            }
            if !ended_path.exists()
                && held_nodes_in(&data_dir.join(ENDED_DIR), ".json") >= MAX_NODES
            {
                return Err(format!(
                    "the reporter holds {MAX_NODES} nodes, the most it takes"
                ));
            }
            std::fs::create_dir_all(data_dir.join(ENDED_DIR))
                .map_err(|e| format!("could not keep it: {e}"))?;
            return keep(&ended_path);
        };
        if at_of(&join) > at {
            return Err(format!(
                "the leave at {} is older than its join",
                doc["at"].as_str().unwrap_or_default()
            ));
        }
        if join["key_id"] != doc["key_id"] {
            return Err("the leave is signed by another key than its join".into());
        }
        if let Some(leave) = held(&leave_path) {
            if leave == doc {
                return Ok(());
            }
            if at_of(&leave) > at {
                return Err("a later leave of this node is held".into());
            }
        }
        keep(&leave_path)
    }
}

/// How long the reporter waits at each step of an open stream.
fn responder_timeout() -> Duration {
    env_millis("CAPSULES_JOIN_HTTP_TIMEOUT_MS", 10_000)
}

pub async fn handle_open_stream(
    request: OpenStreamRequest,
    self_peer: SelfPeer,
    data_dir: Arc<PathBuf>,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);
    tokio::spawn(async move {
        if let Err(error) = bridge_inbound(listener, self_peer, data_dir).await {
            tracing::warn!(%error, "join intake bridge failed");
        }
    });
    Ok(Some(response))
}

async fn bridge_inbound(
    listener: LocalListener,
    self_peer: SelfPeer,
    data_dir: Arc<PathBuf>,
) -> anyhow::Result<()> {
    let local = tokio::time::timeout(responder_timeout(), listener.accept()).await??;
    let (mut read_half, mut write_half) = local.into_split();
    let bytes = tokio::time::timeout(
        responder_timeout(),
        read_to_end_bounded(&mut read_half, "inbound join"),
    )
    .await??;
    let self_id = self_peer.current();
    let taken =
        tokio::task::spawn_blocking(move || intake_bytes(&bytes, self_id.as_deref(), &data_dir))
            .await?;
    let reply = match &taken {
        Ok(()) => json!({"ok": true}),
        Err(why) => json!({"error": why}),
    };
    if let Err(why) = &taken {
        tracing::info!(%why, "refused a join/1 record");
    }
    let bytes = serde_json::to_vec(&reply)?;
    tokio::time::timeout(responder_timeout(), async {
        write_half.write_all(&bytes).await?;
        write_half.shutdown().await
    })
    .await??;
    Ok(())
}

#[cfg(test)]
mod tests;
