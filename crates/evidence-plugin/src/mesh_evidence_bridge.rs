//! Ask #5's carrier, minus ask #5's own build: mesh-llm's *existing*
//! `OpenMeshStreamRequest`/`connect_stream` plugin-mesh-stream mechanism
//! (`crates/mesh-llm-host-runtime/src/mesh/plugin_streams.rs`, verified on
//! `main` at `cae3620` and reconfirmed against a fresh `mesh-llm` checkout for
//! this task) already lets a plugin open a bidirectional QUIC stream to the
//! *same plugin* on a target peer, gated on both ends declaring the channel
//! in their manifest (`plugin_event_channel_declared`). This module declares
//! `evidence-request/1` and bridges bytes on both ends -- mesh never parses
//! either side. Zero upstream (`mesh-llm`) code.
//!
//! **Responder role** (`on_open_stream`): the host already gated this call on
//! the channel being declared before `connect_stream` ever reaches us. This
//! plugin also declares `ledger-fetch/1` and `record-push/1`; `main.rs`
//! dispatches an inbound `OpenStreamRequest` to whichever module owns it
//! before `handle_open_stream` below is called, so it only ever receives a
//! mesh-inbound evidence request. We bind a local listener, hand its
//! endpoint back, and once the host bridges the remote bytes to it, read the
//! whole request (bounded in bytes and in time) and answer it **in-process**
//! (`evidence_answer`, over the `evidence-request` crate): an
//! artifact or a signed refusal. At most [`MAX_IN_FLIGHT_ANSWERS`] requests
//! whose signature proves a principal ([`requester_auth::proves_principal`])
//! and at most [`MAX_IN_FLIGHT_STRANGERS`] others (unsigned, or signed by a
//! key no host binds) are answered at once, each from its own pool, so
//! strangers cannot crowd a counterparty out; and one key holds at most
//! [`MAX_IN_FLIGHT_PER_KEY`] of the first pool, so one counterparty cannot
//! crowd out the others (evidencebook#206 row 3). One more is declined with a
//! signed `capacity_exceeded` (`policy_declined` to an `evidence-interop/0`
//! request) before the ledger is read. Every answer is logged to
//! the "asked of you" log (`evidence_answer::log_received`).
//!
//! An `adjudicate` request (a requester asking this node to referee two
//! twins) is not a -00 subject: it is plugin-internal, carried on the same
//! stream, and answered by the referee's door (`crate::referee::service`)
//! with a signed verdict or a signed refusal. A verdict's
//! `adjudication_issued` record is sealed on this node's chain before the
//! reply leaves; if that seal fails, nothing is sent.
//!
//! **Requester role**: the streamed-HTTP-binding path mesh-llm ships
//! (`handle_streamed_http_binding`) forwards a binding's *static* manifest
//! path/method into `OpenStreamRequest.metadata_json` before any request body
//! exists -- it cannot carry a caller-chosen `target_peer_id`, so it cannot
//! drive an outbound `OpenMeshStreamRequest` on this plugin's behalf. The
//! mechanism that CAN -- `mesh_llm_plugin`'s tool/operation router
//! (`ToolRouter`/`invoke_operation`, reachable locally over
//! `POST /api/plugins/capsules/tools/mesh_evidence_request`) -- hands
//! its handler the full JSON arguments AND a `&mut PluginContext` in the same
//! call, so a local client drives this tool;
//! the handler opens the mesh stream, writes the E14 request bytes, and
//! returns whatever the peer's own responder wrote back (Artifact or signed
//! Refusal, untouched) as the tool's JSON result. A peer that never declared
//! the channel drops the stream at the host with no reply; bounded by
//! `REQUESTER_IDLE_TIMEOUT` so that reads a clean failure, never a hang.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{bind_side_stream, LocalStream, PluginContext, PluginError, PluginResult};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The mesh channel this plugin declares on both ends -- gates both the
/// outbound `open_outbound_plugin_mesh_stream` call (checked against THIS
/// plugin's own manifest) and the inbound `handle_plugin_mesh_stream` call
/// (checked against the responder's manifest).
pub const EVIDENCE_REQUEST_CHANNEL: &str = "evidence-request/1";

/// The tool name a local client calls
/// (`POST /api/plugins/<plugin_id>/tools/mesh_evidence_request`).
pub const EVIDENCE_REQUEST_OPERATION: &str = "mesh_evidence_request";

/// How long the RESPONDER waits at each step of an already-open mesh stream:
/// the requester's connection, its request bytes, and writing the answer.
/// Bounds a silent peer; mesh-llm's own `idle_timeout_ms` on the
/// `OpenMeshStreamRequest` bounds the mesh stream separately, host-side.
/// Overridable so a test proving the bound is actually enforced does not
/// have to wait out the production default.
fn responder_http_timeout() -> Duration {
    env_millis("CAPSULES_EVIDENCE_HTTP_TIMEOUT_MS", 10_000)
}

/// How long the REQUESTER waits for a response once the mesh stream is open
/// -- covers exactly the "peer never declared the channel, host drops the
/// stream with no reply" case the acceptance check requires read as a clean
/// failure, never a hang.
pub(crate) fn requester_idle_timeout_ms() -> u64 {
    env_millis("CAPSULES_MESH_REQUEST_TIMEOUT_MS", 8_000).as_millis() as u64
}

/// Shared with `ledger_fetch_bridge`, the other plugin-mesh-stream carrier --
/// same env-var-with-default shape, no reason for two copies.
pub(crate) fn env_millis(var: &str, default_ms: u64) -> Duration {
    Duration::from_millis(
        crate::settings::var(var)
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(default_ms),
    )
}

static STREAM_NONCE: AtomicU64 = AtomicU64::new(1);

/// Shared with `ledger_fetch_bridge` -- one nonce space for every
/// plugin-mesh-stream this process opens, so stream ids never collide
/// between the two carriers.
pub(crate) fn next_stream_id(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        STREAM_NONCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// Cap on every peer-controlled side-stream read this plugin performs (both
/// bridges, both roles). The SDK's 16 MiB frame cap does NOT apply to raw
/// side-stream bytes and `expected_bytes` is never enforced, so an unbounded
/// `read_to_end` here was a remote OOM: a peer could stream gigabytes into
/// this process's memory. A capsule / E14 request / E15 answer is a few KB
/// -- 1 MiB is generous headroom, not a constraint anyone legitimate hits.
pub(crate) const MAX_SIDE_STREAM_BYTES: u64 = 1024 * 1024;

/// Bounded replacement for `read_to_end` on a side-stream: reads at most
/// [`MAX_SIDE_STREAM_BYTES`] and errors -- naming `what` -- when the peer
/// sends more, instead of buffering an attacker-chosen amount of memory.
pub(crate) async fn read_to_end_bounded<R>(reader: R, what: &str) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    // Read ONE byte past the cap so "exactly at the cap" and "over the cap"
    // are distinguishable without trusting the peer to half-close honestly.
    let mut bounded = reader.take(MAX_SIDE_STREAM_BYTES + 1);
    bounded.read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > MAX_SIDE_STREAM_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{what} exceeded the {MAX_SIDE_STREAM_BYTES}-byte side-stream cap -- refusing \
                 an unbounded peer-controlled read"
            ),
        ));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------
// Responder role: mesh-inbound `evidence-request/1` stream -> answered in-process
// ---------------------------------------------------------------------

/// Registered as this plugin's `on_open_stream` handler. Never fabricates an
/// Artifact/Refusal itself -- a transport failure (the peer went silent)
/// just drops the stream; only `evidence_answer` ever produces a signed
/// response, so nothing unsigned is ever returned in its place.
pub async fn handle_open_stream(
    request: OpenStreamRequest,
    _context: &mut PluginContext<'_>,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    self_peer: crate::self_peer::SelfPeer,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);
    // The id askers address this node by: what the host reports, the id a
    // peer opens the stream to. Never the operator's override, which names
    // this node to pushes, not to the mesh. Until the host reports it, no
    // signed request is addressed to this node and each is refused.
    let own_node = self_peer.learned();
    if own_node.is_none() {
        tracing::warn!(
            "this node's own mesh id is not known yet: signed evidence requests are refused \
             until the host reports it"
        );
    }

    tokio::spawn(async move {
        if let Err(error) = bridge_inbound_evidence_stream(listener, capsules, own_node).await {
            tracing::warn!(%error, "mesh evidence-request responder bridge failed");
        }
    });

    Ok(Some(response))
}

/// The most evidence requests from a proven principal answered at once; see
/// the module doc.
pub const MAX_IN_FLIGHT_ANSWERS: usize = 8;

/// The most requests from anyone else answered at once, apart from the pool
/// above.
pub const MAX_IN_FLIGHT_STRANGERS: usize = 2;

/// The most of the proven pool one key holds at once: half of it, so a
/// counterparty flooding this node leaves room for the others. The key is
/// the one its nonces draw on (`requester_auth::proves_principal`), so keys
/// a declaration binds share their anchor's.
pub const MAX_IN_FLIGHT_PER_KEY: usize = MAX_IN_FLIGHT_ANSWERS / 2;

/// The two in-flight pools. A request draws from its own pool only, so a
/// full stranger pool never declines a proven principal; a proven one also
/// draws on its key's share.
struct InFlight {
    proven: tokio::sync::Semaphore,
    strangers: tokio::sync::Semaphore,
    /// Proven permits held, per key; a key holding none is absent.
    held: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

/// A permit from [`InFlight`], and the key's share it holds, if proven.
struct Permit<'a> {
    _pool: tokio::sync::SemaphorePermit<'a>,
    share: Option<(&'a InFlight, String)>,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Some((pools, key)) = self.share.take() {
            let mut held = pools
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(count) = held.get_mut(&key) {
                *count -= 1;
                if *count == 0 {
                    held.remove(&key);
                }
            }
        }
    }
}

impl InFlight {
    fn new() -> Self {
        Self {
            proven: tokio::sync::Semaphore::new(MAX_IN_FLIGHT_ANSWERS),
            strangers: tokio::sync::Semaphore::new(MAX_IN_FLIGHT_STRANGERS),
            held: Default::default(),
        }
    }

    /// A permit from the pool `proven` names (the proven key, or `None` for
    /// a stranger), where `proven` is only worked out when some pool has
    /// room: with both full the request is declined without classifying it.
    /// A proven key already holding [`MAX_IN_FLIGHT_PER_KEY`] is declined
    /// too.
    fn try_acquire_with(&self, proven: impl FnOnce() -> Option<String>) -> Result<Permit<'_>, ()> {
        if self.proven.available_permits() == 0 && self.strangers.available_permits() == 0 {
            return Err(());
        }
        let Some(key) = proven() else {
            let pool = self.strangers.try_acquire().map_err(|_| ())?;
            return Ok(Permit {
                _pool: pool,
                share: None,
            });
        };
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.get(&key).copied().unwrap_or(0) >= MAX_IN_FLIGHT_PER_KEY {
            return Err(());
        }
        let pool = self.proven.try_acquire().map_err(|_| ())?;
        *held.entry(key.clone()).or_default() += 1;
        Ok(Permit {
            _pool: pool,
            share: Some((self, key)),
        })
    }
}

/// The key whose share the parsed request draws on, when it proves a
/// principal as of `now` on the channel its door checks it under
/// ([`requester_auth::proves_principal`]).
fn proves_principal(
    parsed: Option<&serde_json::Value>,
    adjudicate: bool,
    now: &str,
    own_node: Option<&str>,
    own_key: &str,
) -> Option<String> {
    let (Some(serde_json::Value::Object(map)), Some(now)) =
        (parsed, evidence_request::time::parse_utc(now))
    else {
        return None;
    };
    let channel = if adjudicate {
        crate::requester_auth::Channel::RefereeAdjudicate
    } else {
        crate::requester_auth::Channel::EvidenceRequest
    };
    let announced = crate::peer_keys::announced::snapshot();
    let configured = crate::settings::var(crate::peer_keys::ENV_PEER_KEYS).ok();
    crate::requester_auth::proves_principal(
        channel,
        map,
        now,
        crate::requester_auth::Keys {
            announced: &announced,
            configured: configured.as_deref(),
            own_key: Some(own_key),
        },
        own_node,
    )
}

static IN_FLIGHT: std::sync::OnceLock<InFlight> = std::sync::OnceLock::new();

async fn bridge_inbound_evidence_stream(
    listener: mesh_llm_plugin::LocalListener,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    own_node: Option<String>,
) -> anyhow::Result<()> {
    let bound = responder_http_timeout();
    let local = tokio::time::timeout(bound, listener.accept()).await??;
    let (mut read_half, mut write_half) = local.into_split();

    // The remote requester writes the whole request then half-closes
    // (mesh-llm's own streamed-http-binding convention: a full write
    // followed by `shutdown()`, never a length prefix) -- read to EOF, but
    // BOUNDED in bytes (see `read_to_end_bounded`) and in time: the
    // requester controls these bytes and must never control this process's
    // memory, or hold a stream open by going silent.
    let request_bytes = tokio::time::timeout(
        bound,
        read_to_end_bounded(&mut read_half, "mesh-inbound evidence request"),
    )
    .await??;

    let response_bytes = match answer_in_process(capsules, request_bytes, own_node).await {
        Some(bytes) => bytes,
        // Nothing this node can sign: send nothing, never an unsigned
        // stand-in. The requester records an absence.
        None => return Ok(()),
    };

    tokio::time::timeout(bound, async {
        write_half.write_all(&response_bytes).await?;
        write_half.shutdown().await
    })
    .await??;
    Ok(())
}

/// Answer in-process, on the blocking pool (the answer reads the ledger and
/// signs), and log it. `None` when there is nothing to send.
async fn answer_in_process(
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    request_bytes: Vec<u8>,
    own_node: Option<String>,
) -> Option<Vec<u8>> {
    let for_rule = capsules.clone();
    let answered = tokio::task::spawn_blocking(move || {
        let now = crate::evidence_answer::now_utc();
        let parsed = serde_json::from_slice::<serde_json::Value>(&request_bytes).ok();
        // A verdict this node issues lands on its own counts: the opt-in
        // stop-routing rule looks again (it does nothing while off).
        let adjudicate = parsed
            .as_ref()
            .is_some_and(crate::referee::service::is_adjudicate_request);
        // The pool is chosen by what the request proves; classifying costs a
        // signature check, so it is skipped when both pools are full.
        let permit = IN_FLIGHT.get_or_init(InFlight::new).try_acquire_with(|| {
            proves_principal(
                parsed.as_ref(),
                adjudicate,
                &now,
                own_node.as_deref(),
                &hex::encode(capsules.public_key()),
            )
        });
        // Past the in-flight cap, an adjudicate request is declined like any
        // other (below), before any work on it.
        if permit.is_ok() {
            if let Some(verdict_or_refusal) =
                referee_answer(&capsules, &request_bytes, &now, own_node.as_deref())
            {
                drop(permit);
                return (verdict_or_refusal, adjudicate);
            }
        }
        let log_dir = capsules
            .ledger_dir()
            .parent()
            .and_then(crate::evidence_routes::EvidenceSource::received_log_dir);
        let outcome = crate::commitment::with_responder(
            &capsules,
            &now,
            own_node.as_deref(),
            |responder, _| {
                crate::evidence_answer::answer_and_log(
                    &request_bytes,
                    permit.is_err(),
                    responder,
                    log_dir.as_deref(),
                )
            },
        );
        drop(permit);
        if let crate::evidence_answer::Outcome::Unanswerable(why) = &outcome {
            tracing::warn!(%why, "an evidence request was not answered");
        }
        (outcome.wire_bytes(), adjudicate)
    })
    .await;
    let Ok((answered, adjudicate)) = answered else {
        return None;
    };
    if adjudicate {
        drop(for_rule);
        crate::routing_rule::mark_due();
    }
    answered
}

/// Why an evidence request got no answer.
#[derive(Debug)]
pub(crate) enum SendError {
    /// The request could not be recorded, so it was not sent.
    NotRecorded(String),
    /// The stream to the peer's plugin could not be opened (unreachable, or
    /// it runs no plugin that takes the channel).
    NotOpened(String),
    /// Opened, but nothing came back in time (the text says why, with a
    /// leading ": " when there is detail).
    NoAnswer(String),
    /// Something came back that is not JSON.
    Malformed(String),
}

/// What came back for a request: the bytes sent, the peer's JSON, and, for
/// a request recorded in this node's book of asks, its check under the
/// peer's announced key ([`verify_announced`]), the one the response record
/// holds.
#[derive(Debug)]
pub(crate) struct Answered {
    pub sent: Vec<u8>,
    pub answer: serde_json::Value,
    pub verification: Option<serde_json::Value>,
}

/// Send `request` to `peer_id` over the evidence stream and read the answer.
/// Signed as this node (`requester_auth::sign_outgoing`) once its key is
/// announced: under the referee's tag when it is an `adjudicate` request,
/// which the referee's door on the far end checks it against, and the
/// Evidence Request's otherwise.
///
/// With `asks`, an evidence request (never an `adjudicate` one, which
/// `requested-adjudications` records) is first sealed in this node's book
/// of asks (`crate::ask_book`), exactly as sent (its JCS bytes); if that
/// fails nothing is sent. The stream then stays open until the request's waiting window
/// closes, past the transport's wait: a reply inside the window is sealed
/// as the response, and none by its close as a recorded absence. The caller
/// still hears within the transport's wait.
///
/// An evidence request that names no `profile` asks under
/// `evidence-interop/1` (IP v1). A peer that implements only
/// `evidence-interop/0`, as plugin releases before /1 do, refuses that with
/// `request_malformed` before reading anything else (IP §3.3 step 4); the
/// request is then sent once more under /0 ([`fallback_to_v0`]), and the
/// book of asks holds both, each with the identifier it asked under.
pub(crate) async fn send_evidence_request(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    request: &serde_json::Value,
    asks: Option<&std::sync::Arc<crate::capsule_emit::CapsuleState>>,
) -> Result<Answered, SendError> {
    let Some(v1) = under_v1(request) else {
        return send_once(context, peer_id, request, asks).await;
    };
    let answered = send_once(context, peer_id, &v1, asks).await?;
    match fallback_to_v0(&v1, &answered.answer) {
        Some(v0) => send_once(context, peer_id, &v0, asks).await,
        None => Ok(answered),
    }
}

/// `request` asking under `evidence-interop/1`, or `None` to send it as
/// given: an `adjudicate` request, one that names its profile, one the
/// caller signed (a profile added here would break its signature), and
/// anything that is not a map (refused as before).
pub(crate) fn under_v1(request: &serde_json::Value) -> Option<serde_json::Value> {
    let map = request.as_object()?;
    if crate::referee::service::is_adjudicate_request(request)
        || map.contains_key("profile")
        || map.contains_key(crate::requester_auth::MEMBER)
    {
        return None;
    }
    let mut v1 = map.clone();
    v1.insert(
        "profile".into(),
        serde_json::json!(evidence_request::envelope::PROFILE_V1),
    );
    Some(serde_json::Value::Object(v1))
}

/// The `evidence-interop/0` retry of `asked`, a request this node sent under
/// `evidence-interop/1`, when `answer` refuses it `request_malformed`: the
/// refusal a /0-only responder gives an identifier it does not implement.
/// The retry names /0 and, so the book of asks takes it as a new request,
/// carries a new nonce: the nonce with `/evidence-interop-0` appended, or,
/// where that would pass [`requester_auth::MAX_NONCE_BYTES`], the nonce's
/// SHA-256 in hex with it. `None` for any other answer.
pub(crate) fn fallback_to_v0(
    asked: &serde_json::Value,
    answer: &serde_json::Value,
) -> Option<serde_json::Value> {
    let refused_malformed = answer.get("reason").and_then(serde_json::Value::as_str)
        == Some(evidence_request::registry::Reason::RequestMalformed.token())
        && answer.get("artifact_digest").is_none();
    if !refused_malformed
        || asked.get("profile").and_then(serde_json::Value::as_str)
            != Some(evidence_request::envelope::PROFILE_V1)
    {
        return None;
    }
    let mut v0 = asked.clone();
    v0["profile"] = serde_json::json!(evidence_request::envelope::PROFILE);
    if let Some(nonce) = asked.get("nonce").and_then(serde_json::Value::as_str) {
        const SUFFIX: &str = "/evidence-interop-0";
        let retry = if nonce.len() + SUFFIX.len() <= crate::requester_auth::MAX_NONCE_BYTES {
            format!("{nonce}{SUFFIX}")
        } else {
            use sha2::Digest as _;
            format!(
                "{}{SUFFIX}",
                hex::encode(sha2::Sha256::digest(nonce.as_bytes()))
            )
        };
        v0["nonce"] = serde_json::json!(retry);
    }
    // `send_once` signs what it sends; a signature carried over from the
    // caller covers the /1 profile and nonce, so it goes.
    if let Some(map) = v0.as_object_mut() {
        map.remove(crate::requester_auth::MEMBER);
    }
    Some(v0)
}

async fn send_once(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    request: &serde_json::Value,
    asks: Option<&std::sync::Arc<crate::capsule_emit::CapsuleState>>,
) -> Result<Answered, SendError> {
    // The host reads a hex id in either case; a node's own id is lowercase.
    // One form, for the stream and for the audience it is signed for.
    let peer_id = peer_id.trim();
    let peer_id = if peer_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        peer_id.to_ascii_lowercase()
    } else {
        peer_id.to_string()
    };
    let mut request = request.clone();
    let channel = if crate::referee::service::is_adjudicate_request(&request) {
        crate::requester_auth::Channel::RefereeAdjudicate
    } else {
        crate::requester_auth::Channel::EvidenceRequest
    };
    crate::requester_auth::sign_outgoing(channel, &mut request, &peer_id);
    let wait = Duration::from_millis(requester_idle_timeout_ms());
    let asked = match asks {
        Some(capsules) if channel == crate::requester_auth::Channel::EvidenceRequest => {
            let commitment = capsules
                .ledger_dir()
                .parent()
                .and_then(|data_dir| crate::peer_commitments::pinned(data_dir, &peer_id));
            let asked = crate::ask_book::record_request(
                capsules,
                &request,
                &peer_id,
                commitment,
                &crate::evidence_answer::now_utc(),
            )
            .map_err(|error| SendError::NotRecorded(error.to_string()))?;
            Some((capsules.clone(), asked))
        }
        _ => None,
    };
    // A recorded ask goes as its JCS bytes, so the record's digest is the
    // wire digest (`check_request` has already written it so). Anything
    // else goes as before: an `adjudicate` request carries non-integer
    // numbers, which have no JCS form in `evidence_request::jcs`.
    let request_bytes = match &asked {
        Some(_) => evidence_request::jcs::to_string(&request)
            .map_err(|error| SendError::Malformed(error.to_string()))?
            .into_bytes(),
        None => {
            serde_json::to_vec(&request).map_err(|error| SendError::Malformed(error.to_string()))?
        }
    };
    // A recorded ask's window closes at one fixed instant, which bounds
    // opening the stream and reading from it alike; anything else is bounded
    // by the transport's wait.
    let closes_at = asked
        .as_ref()
        .map(|(_, asked)| tokio::time::Instant::now() + until(&asked.window_closes));
    let listen = closes_at.map_or(wait, |at| {
        at.saturating_duration_since(tokio::time::Instant::now())
    });
    let open_request = OpenMeshStreamRequest {
        stream_id: next_stream_id("evidence-request"),
        target_peer_id: peer_id.clone(),
        plugin_id: String::new(), // host fills this in from the connection.
        channel: EVIDENCE_REQUEST_CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some("application/json".to_string()),
        correlation_id: Some(next_stream_id("evidence-correlation")),
        metadata_json: None,
        expected_bytes: None,
        idle_timeout_ms: Some(u64::try_from(listen.max(wait).as_millis()).unwrap_or(u64::MAX)),
    };
    let Some(((capsules, asked), closes_at)) = asked.zip(closes_at) else {
        let stream: LocalStream = context
            .connect_mesh_stream(open_request)
            .await
            .map_err(|error| SendError::NotOpened(error.to_string()))?;
        let (_, answer) = read_answer(
            tokio::time::timeout(wait, write_and_read(stream, request_bytes.clone())).await,
        )?;
        return Ok(Answered {
            sent: request_bytes,
            answer,
            verification: None,
        });
    };
    let stream: LocalStream =
        match tokio::time::timeout_at(closes_at, context.connect_mesh_stream(open_request)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                tokio::spawn(absence_when_window_closes(capsules, asked));
                return Err(SendError::NotOpened(error.to_string()));
            }
            Err(_) => {
                tokio::spawn(absence_when_window_closes(capsules, asked));
                return Err(SendError::NotOpened(
                    "no stream before the window closed".into(),
                ));
            }
        };
    // The window outlives the caller's wait: the rest runs on its own, so a
    // reply after the caller has been told "no answer yet" is still sealed.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let pending = asked.record_id.clone();
    let closes = asked.window_closes.clone();
    tokio::spawn(settle_ask(
        capsules,
        asked,
        move |sent: &[u8], answer: &serde_json::Value| verify_announced(sent, answer, &peer_id),
        request_bytes.clone(),
        write_and_read(stream, request_bytes.clone()),
        closes_at,
        tx,
    ));
    match tokio::time::timeout(wait, rx).await {
        Ok(Ok(Ok((answer, verification)))) => Ok(Answered {
            sent: request_bytes,
            answer,
            verification: Some(verification),
        }),
        Ok(Ok(Err(error))) => Err(error),
        _ => Err(SendError::NoAnswer(format!(
            " yet: the ask is recorded as {pending} and is pending until {closes}"
        ))),
    }
}

/// Write `sent` on `stream`, half-close it, and read the reply to its end.
async fn write_and_read(stream: LocalStream, sent: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let (mut read_half, mut write_half) = stream.into_split();
    write_half.write_all(&sent).await?;
    write_half.shutdown().await?;
    // Bounded: the peer's answer is peer-controlled bytes too.
    read_to_end_bounded(&mut read_half, "peer evidence-request response").await
}

/// What a bounded read came to: the peer's bytes as read and their JSON,
/// or why there is none.
fn read_answer(
    result: Result<std::io::Result<Vec<u8>>, tokio::time::error::Elapsed>,
) -> Result<(Vec<u8>, serde_json::Value), SendError> {
    let bytes = result
        .map_err(|_| SendError::NoAnswer(String::new()))?
        .map_err(|error| SendError::NoAnswer(format!(": {error}")))?;
    let answer =
        serde_json::from_slice(&bytes).map_err(|error| SendError::Malformed(error.to_string()))?;
    Ok((bytes, answer))
}

/// The answer to a recorded ask, or its error, as [`settle_ask`] hands it
/// to the caller still waiting.
type Settled = Result<(serde_json::Value, serde_json::Value), SendError>;

/// Read the reply to the recorded `asked` from `exchange` until the window
/// closes at `closes_at`. A reply is checked by `verify` (under the peer's
/// announced key, [`verify_announced`]) and sealed as the response, its
/// bytes kept with it (`ask_book::record_response`); none (or one that is not JSON) is sealed as
/// the absence once the window has closed. The caller hears through `tx`,
/// if it is still listening.
async fn settle_ask(
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    asked: crate::ask_book::Asked,
    verify: impl FnOnce(&[u8], &serde_json::Value) -> serde_json::Value,
    sent: Vec<u8>,
    exchange: impl std::future::Future<Output = std::io::Result<Vec<u8>>>,
    closes_at: tokio::time::Instant,
    tx: tokio::sync::oneshot::Sender<Settled>,
) {
    let read = tokio::time::timeout_at(closes_at, exchange).await;
    // `timeout_at` polls the read before its deadline, so a reply read once
    // the window has closed (a task resumed late) is checked here: it is no
    // reply, and the absence stands.
    let read = if tokio::time::Instant::now() < closes_at {
        read_answer(read)
    } else {
        Err(SendError::NoAnswer(" by the window's close".into()))
    };
    match read {
        Ok((reply, answer)) => {
            let checked = verify(&sent, &answer);
            let verification = match crate::ask_book::record_response(
                &capsules,
                &asked.record_id,
                &evidence_request::digest::request_digest(&sent),
                &reply,
                &checked,
                &crate::evidence_answer::now_utc(),
            ) {
                Ok((_, recorded)) => recorded,
                Err(error) => {
                    tracing::warn!(%error, request_record = %asked.record_id, "a reply could not be recorded");
                    checked
                }
            };
            let _ = tx.send(Ok((answer, verification)));
        }
        Err(error) => {
            let _ = tx.send(Err(error));
            absence_when_window_closes(capsules, asked).await;
        }
    }
}

/// How long from now until `at` (RFC 3339), zero once it has passed.
fn until(at: &str) -> Duration {
    chrono::DateTime::parse_from_rfc3339(at)
        .ok()
        .and_then(|at| (at.to_utc() - chrono::Utc::now()).to_std().ok())
        .unwrap_or_default()
}

/// Wait for the ask's window to close, then seal its recorded absence.
pub(crate) async fn absence_when_window_closes(
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    asked: crate::ask_book::Asked,
) {
    // A second past the close, so the book's whole-second clock reads it as
    // passed.
    tokio::time::sleep(until(&asked.window_closes) + Duration::from_secs(1)).await;
    if let Err(error) = crate::ask_book::record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        &crate::evidence_answer::now_utc(),
    ) {
        tracing::warn!(%error, request_record = %asked.record_id, "an absence could not be recorded");
    }
}

/// `answer` checked as the reply to `sent` under `peer_id`'s announced key
/// (`evidence_answer::verify_response`), or `no_announced_key`.
fn verify_announced(sent: &[u8], answer: &serde_json::Value, peer_id: &str) -> serde_json::Value {
    let registry = crate::peer_keys::registry();
    match crate::peer_keys::announced_key_in(registry.as_deref(), peer_id)
        .and_then(|key_id| verifying_key(&key_id))
    {
        Some(key) => crate::evidence_answer::verify_response(
            sent,
            answer,
            &key,
            &crate::checkpoint_cadence::active_witness_keys(),
        ),
        None => serde_json::json!({"state": "no_announced_key"}),
    }
}

/// The referee's answer to an `adjudicate` request, as wire bytes; `None`
/// for any other request. `Some(None)` sends nothing: a verdict whose
/// `adjudication_issued` record did not seal is never sent.
fn referee_answer(
    capsules: &crate::capsule_emit::CapsuleState,
    request_bytes: &[u8],
    now: &str,
    own_node: Option<&str>,
) -> Option<Option<Vec<u8>>> {
    let parsed: serde_json::Value = serde_json::from_slice(request_bytes).ok()?;
    if !crate::referee::service::is_adjudicate_request(&parsed) {
        return None;
    }
    let peer_keys = crate::peer_keys::registry();
    let referee = crate::referee::service::Referee {
        ledger_dir: capsules.ledger_dir(),
        signing_key: capsules.signing_key(),
        peer_keys: peer_keys.as_deref(),
    };
    let announced = crate::peer_keys::announced::snapshot();
    let configured = crate::settings::var(crate::peer_keys::ENV_PEER_KEYS).ok();
    let own_key = hex::encode(capsules.public_key());
    let asked = crate::referee::service::Asked {
        keys: crate::requester_auth::Keys {
            announced: &announced,
            configured: configured.as_deref(),
            own_key: Some(&own_key),
        },
        replay: crate::requester_auth::replay_cache(),
        own_node,
    };
    let reply = match crate::referee::service::handle_asked_adjudicate_request(
        &referee,
        request_bytes,
        now,
        &asked,
    ) {
        Ok(reply) => reply,
        Err(error) => {
            tracing::warn!(%error, "an adjudicate request was not answered: the verdict could not be held");
            return Some(None);
        }
    };
    if reply
        .get(crate::referee::service::ADJUDICATION_VERDICT_MARKER)
        .is_some()
    {
        if let Err(error) = seal_issued_verdict(capsules, &reply) {
            tracing::warn!(%error, "a verdict was issued but its record did not seal; nothing sent");
            return Some(None);
        }
    } else {
        // The refusal is signed and sent; the operator also sees why here.
        tracing::info!(
            reason = reply
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("none"),
            detail = reply
                .get("detail")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "an adjudicate request was refused"
        );
    }
    Some(serde_json::to_vec(&reply).ok())
}

/// Seal this node's `adjudication_issued` record of the verdict in `reply`.
/// Keyed on the verdict id: a repeated request seals nothing more.
fn seal_issued_verdict(
    capsules: &crate::capsule_emit::CapsuleState,
    reply: &serde_json::Value,
) -> anyhow::Result<()> {
    use serde_json::Value;
    let text = |key: &str| reply.get(key).and_then(Value::as_str);
    let pair = |key: &str| -> Option<[&str; 2]> {
        match reply.get(key)?.as_array()?.as_slice() {
            [a, b] => Some([a.as_str()?, b.as_str()?]),
            _ => None,
        }
    };
    let (Some(verdict), Some(id), Some(referee), Some(halves), Some(nodes)) = (
        text("verdict"),
        text("verdict_capsule_id"),
        text("referee_node_id"),
        pair("halves"),
        pair("half_node_ids"),
    ) else {
        anyhow::bail!("the issued verdict's facts are incomplete");
    };
    let model_hash = reply
        .pointer("/verdict_capsule/model_attestation/compute_attestation/adjudication/model_hash")
        .and_then(Value::as_str);
    let facts = crate::capsule_emit::VerdictFacts {
        verdict,
        verdict_capsule_id: id,
        referee_node_id: referee,
        halves,
        half_node_ids: nodes,
        twin_bracket_id: text("twin_bracket_id"),
        model_hash,
    };
    capsules.emit_adjudication_issued(
        &facts,
        text("referee_capsule_id"),
        text("issued_at").unwrap_or_default(),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------
// Requester role: local tool call -> outbound `evidence-request/1` stream
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MeshEvidenceRequestArgs {
    /// Hex-encoded mesh peer id to ask, e.g. `iroh::EndpointId::to_string()`.
    pub peer_id: String,
    /// The request map (draft-mih-agent-evidence-request-00), sent as given.
    /// When it names no `profile`, it asks under `evidence-interop/1`, and
    /// once more under /0 when the peer refuses that `request_malformed`
    /// ([`send_evidence_request`]).
    /// When it names no `requester_id`, this node's own mesh id is added (it
    /// is this node's word). Once this node's key is announced, the request
    /// is also signed (`requester_auth`): its `audience` is set to `peer_id`,
    /// a `nonce` and a `deadline` are added unless it carries them, then
    /// `requester_auth` over the whole map. The responder answers what
    /// depends on who asks only to a signed request addressed to it. It is
    /// sealed in this node's book of asks before it is sent
    /// (`crate::ask_book`); a request that is not well formed, or reuses a
    /// nonce, is refused there and never sent.
    pub request: serde_json::Value,
    /// Check what comes back against the peer's announced key
    /// (`CAPSULES_PEER_KEYS`). **On unless the caller turns it off**
    /// with an explicit `"verify": false`. The result is
    /// `{"answer": <the peer's JSON>, "request_digest", "verification"}`
    /// (`evidence_answer::verify_response`, or `no_announced_key` when the
    /// registry names no key for the peer), and `held`: the `capsule_id` of
    /// the record now held on this node when the request named one exchange
    /// by its digests and exactly that record verified, else empty. With
    /// `"verify": false` it is the peer's JSON alone, for a caller that
    /// verifies it itself.
    #[serde(default = "verify_by_default")]
    pub verify: bool,
}

/// `verify` is on unless a caller names the opt-out.
fn verify_by_default() -> bool {
    true
}

/// Registered as the `mesh_evidence_request` tool/operation handler
/// (`ToolRouter::add_json`). Returns the peer's Artifact-or-Refusal JSON,
/// unchanged, beside its verification (or alone with `"verify": false`); any
/// failure (unroutable peer, channel undeclared on the peer, response never
/// arrives) surfaces as a tool error -- `PluginError` -- which the host's
/// `/tools/` HTTP route reports as a `502`, never a hang.
pub async fn handle_mesh_evidence_request(
    mut args: MeshEvidenceRequestArgs,
    context: &mut PluginContext<'_>,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
    self_id: Option<String>,
) -> PluginResult<serde_json::Value> {
    let ledger_dir = capsules.ledger_dir().to_path_buf();
    if args.peer_id.trim().is_empty() {
        return Err(PluginError::invalid_params("peer_id must not be empty"));
    }
    // An adjudicate request names the referee this node CHOSE for a pair:
    // recorded before it is sent, so a verdict about that pair is only ever
    // taken from that referee.
    if let Some(asked) = requested_adjudication(&args.peer_id, &args.request) {
        record_requested_adjudication(&ledger_dir, &asked).map_err(|e| {
            PluginError::internal(format!("could not record the adjudication request: {e}"))
        })?;
    } else {
        add_requester_id(&mut args.request, self_id.as_deref());
    }

    let answered =
        match send_evidence_request(context, &args.peer_id, &args.request, Some(&capsules)).await {
            Ok(answered) => answered,
            Err(SendError::NotRecorded(error)) => {
                return Err(PluginError::internal(format!(
                    "could not record the request, so it was not sent: {error}"
                )))
            }
            Err(SendError::NotOpened(error)) => {
                return Err(PluginError::internal(format!(
                    "could not reach peer: {error}"
                )))
            }
            Err(SendError::NoAnswer(error)) => {
                return Err(PluginError::internal(format!(
                    "peer does not answer evidence requests{error}"
                )))
            }
            Err(SendError::Malformed(error)) => {
                return Err(PluginError::internal(format!(
                    "peer returned malformed response: {error}"
                )))
            }
        };
    let Answered {
        sent: request_bytes,
        answer,
        verification,
    } = answered;
    if !args.verify {
        return Ok(answer);
    }
    let verification =
        verification.unwrap_or_else(|| verify_announced(&request_bytes, &answer, &args.peer_id));
    let held = hold_asked_records(
        &capsules,
        &args.peer_id,
        &args.request,
        &answer,
        &verification,
    )
    .await;
    Ok(serde_json::json!({
        "answer": answer,
        "request_digest": evidence_request::digest::request_digest(&request_bytes),
        "verification": verification,
        "held": held,
    }))
}

/// The record this node asked for, held on this node
/// (`record_push_bridge::hold_asked_record`) so it counts as saved like a
/// pushed one: the `capsule_id` now held, or none. Only the one record of
/// the exchange the ask names is held ([`asked_digests`], [`asked_record`]).
/// A record the receiver refuses, or a store that fails, is left out and
/// logged; the answer itself still goes back.
async fn hold_asked_records(
    capsules: &std::sync::Arc<crate::capsule_emit::CapsuleState>,
    peer_id: &str,
    request: &serde_json::Value,
    answer: &serde_json::Value,
    verification: &serde_json::Value,
) -> Vec<String> {
    let Some(digests) = asked_digests(request, capsules.ledger_dir()) else {
        return Vec::new();
    };
    let Some(record) = asked_record(request, &digests, answer, verification) else {
        return Vec::new();
    };
    let id = serde_json::from_slice::<serde_json::Value>(&record)
        .ok()
        .and_then(|r| {
            r.get("capsule_id")
                .and_then(|i| i.as_str())
                .map(str::to_string)
        });
    match crate::record_push_bridge::hold_asked_record(capsules, peer_id, &record).await {
        Ok(true) => id.into_iter().collect(),
        Ok(false) => {
            tracing::info!(peer_id, capsule_id = ?id, "an asked record was not held: the receiver refused it");
            Vec::new()
        }
        Err(error) => {
            tracing::warn!(%error, peer_id, capsule_id = ?id, "an asked record could not be held");
            Vec::new()
        }
    }
}

/// The two digests of the exchange a record ask names: from the request
/// itself (`exchange-digests:<request>:<response>`), or, for an ask by
/// client nonce, from this node's own one record carrying that nonce. `None`
/// for any other request (a derivation, a record id, a history), or a nonce
/// on no own record or on more than one.
fn asked_digests(
    request: &serde_json::Value,
    ledger_dir: &std::path::Path,
) -> Option<(String, String)> {
    if request.get("derivation").is_some() {
        return None;
    }
    let correlation = request.pointer("/subject/correlation")?.as_str()?;
    if let Some(digests) = correlation.strip_prefix("exchange-digests:") {
        let (request_digest, response_digest) = digests.split_once(':')?;
        return Some((request_digest.to_string(), response_digest.to_string()));
    }
    let mut own = crate::evidence_panes::read_capsule_records(ledger_dir)
        .into_iter()
        .filter(|record| {
            crate::evidence_log::record_correlation_ids(record)
                .iter()
                .any(|id| id == correlation)
        })
        .filter_map(|record| {
            let digest = |d: &str| record.pointer(d)?.as_str().map(str::to_string);
            Some((
                digest("/effect/request_digest")?,
                digest("/effect/response_digest")?,
            ))
        });
    let one = own.next()?;
    own.next().is_none().then_some(one)
}

/// The bytes of the one record a verified answer to a record request serves
/// with both `digests`, or `None`: an answer that did not verify as an
/// artifact, or one proving no such record or more than one.
fn asked_record(
    request: &serde_json::Value,
    (request_digest, response_digest): &(String, String),
    answer: &serde_json::Value,
    verification: &serde_json::Value,
) -> Option<Vec<u8>> {
    if request.get("derivation").is_some()
        || verification.get("state").and_then(|s| s.as_str()) != Some("artifact")
    {
        return None;
    }
    let proven: Vec<u64> = verification
        .get("records")
        .and_then(|r| r.as_array())
        .map(|r| r.iter().filter_map(|i| i.as_u64()).collect())
        .unwrap_or_default();
    let mut matching = served_records(answer, &proven).into_iter().filter(|bytes| {
        serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|record| {
            record
                .pointer("/effect/request_digest")
                .and_then(|d| d.as_str())
                == Some(request_digest.as_str())
                && record
                    .pointer("/effect/response_digest")
                    .and_then(|d| d.as_str())
                    == Some(response_digest.as_str())
        })
    });
    let one = matching.next()?;
    matching.next().is_none().then_some(one)
}

/// The bodies of the records an answer serves at the `proven` leaf indices:
/// the envelope's `artifact` is the artifact's JSON as unpadded base64url,
/// and each of its `records` carries its ledger line hex-encoded (`body`).
fn served_records(answer: &serde_json::Value, proven: &[u64]) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    let Some(artifact) = answer
        .get("artifact")
        .and_then(|a| a.as_str())
        .and_then(|a| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(a)
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    else {
        return Vec::new();
    };
    artifact
        .get("records")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
        .filter(|r| {
            r.get("leaf_index")
                .and_then(|i| i.as_u64())
                .is_some_and(|i| proven.contains(&i))
        })
        .filter_map(|r| hex::decode(r.get("body")?.as_str()?).ok())
        .collect()
}

/// Add this node's id as the request's `requester_id`, unless the request
/// already names one (or is not a map, or this node does not know its id).
fn add_requester_id(request: &mut serde_json::Value, self_id: Option<&str>) {
    if let (Some(map), Some(id)) = (request.as_object_mut(), self_id) {
        map.entry("requester_id")
            .or_insert_with(|| serde_json::json!(id));
    }
}

/// An announced `key_id` (raw Ed25519 public key, lowercase hex) as a key.
pub(crate) fn verifying_key(key_id: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(key_id).ok()?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
}

/// The file beside the ledger that lists every adjudicate request this node
/// sent (`crate::verdict_counts::REQUESTED_FILENAME`).
pub const REQUESTED_ADJUDICATIONS_FILENAME: &str = "requested-adjudications.jsonl";

/// `{referee, halves, twin_bracket_id, selection_tier, asked_at}` for an
/// adjudicate request (the tier it was asked at: a verdict that seals another
/// is refused when delivered, `crate::referee::hold`),
/// or `None` for any other evidence request.
pub fn requested_adjudication(
    peer_id: &str,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    if request.pointer("/subject/kind").and_then(|k| k.as_str()) != Some("adjudicate") {
        return None;
    }
    let halves: Vec<&str> = request
        .get("halves")?
        .as_array()?
        .iter()
        .map(|h| h.pointer("/capsule/capsule_id").and_then(|id| id.as_str()))
        .collect::<Option<_>>()?;
    if halves.len() != 2 {
        return None;
    }
    Some(serde_json::json!({
        "referee": peer_id,
        "halves": halves,
        "twin_bracket_id": request.get("twin_bracket_id").cloned().unwrap_or(serde_json::Value::Null),
        "selection_tier": request.get("selection_tier").cloned().unwrap_or(serde_json::Value::Null),
        "asked_at": crate::producer::timestamp::utc_now_minute(),
    }))
}

pub(crate) fn record_requested_adjudication(
    ledger_dir: &std::path::Path,
    asked: &serde_json::Value,
) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(ledger_dir)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_dir.join(REQUESTED_ADJUDICATIONS_FILENAME))?;
    writeln!(file, "{asked}")?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the records whose leaf indices were proven are taken from an
    /// answer, each decoded from its hex line; an answer with no artifact, or
    /// one that does not decode, gives none.
    #[test]
    fn served_records_takes_only_the_proven_leaves() {
        use base64::Engine as _;
        let artifact = serde_json::json!({"records": [
            {"leaf_index": 3, "body": hex::encode(br#"{"capsule_id":"a"}"#)},
            {"leaf_index": 4, "body": hex::encode(br#"{"capsule_id":"b"}"#)},
            {"leaf_index": 5, "body": "not hex"},
        ]});
        let answer = serde_json::json!({
            "artifact": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&artifact).unwrap()),
        });
        assert_eq!(
            served_records(&answer, &[3, 5]),
            vec![br#"{"capsule_id":"a"}"#.to_vec()]
        );
        assert!(served_records(&answer, &[]).is_empty());
        assert!(served_records(&serde_json::json!({}), &[3]).is_empty());
        assert!(served_records(&serde_json::json!({"artifact": "%%"}), &[3]).is_empty());
    }

    /// Only the one record an exchange-digests ask names is held: not for a
    /// nonce or derivation request, not for an answer that did not verify,
    /// and not when the answer proves no matching record or more than one.
    #[test]
    fn asked_record_is_only_the_one_record_the_ask_names() {
        use base64::Engine as _;
        let (req, resp) = ("1".repeat(64), "2".repeat(64));
        let record = |id: &str, rq: &str, rs: &str| {
            serde_json::to_vec(&serde_json::json!({
                "capsule_id": id, "effect": {"request_digest": rq, "response_digest": rs},
            }))
            .unwrap()
        };
        let answer = |records: &[(u64, Vec<u8>)]| {
            let artifact = serde_json::json!({"records": records.iter().map(|(i, b)| {
                serde_json::json!({"leaf_index": i, "body": hex::encode(b)})
            }).collect::<Vec<_>>()});
            serde_json::json!({"artifact": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&artifact).unwrap())})
        };
        let ask = serde_json::json!({"subject": {"correlation": format!("exchange-digests:{req}:{resp}")}});
        let digests = (req.clone(), resp.clone());
        let verified = |leaves: &[u64]| serde_json::json!({"state": "artifact", "records": leaves});
        let theirs = record("theirs", &req, &resp);
        let other = record("other", &req, &"3".repeat(64));

        // The one matching record, beside one for another exchange: held.
        let both = answer(&[(4, theirs.clone()), (5, other.clone())]);
        assert_eq!(
            asked_record(&ask, &digests, &both, &verified(&[4, 5])),
            Some(theirs.clone())
        );
        // Two records carrying both digests: neither is held.
        let twice = answer(&[(4, theirs.clone()), (6, record("again", &req, &resp))]);
        assert_eq!(
            asked_record(&ask, &digests, &twice, &verified(&[4, 6])),
            None
        );
        // None proven, or not an artifact: nothing.
        assert_eq!(asked_record(&ask, &digests, &both, &verified(&[5])), None);
        let refusal = serde_json::json!({"state": "refusal", "reason": "not_authorized"});
        assert_eq!(asked_record(&ask, &digests, &both, &refusal), None);
        // A derivation: nothing, even with a matching record.
        let mut derived = ask.clone();
        derived["derivation"] = serde_json::json!("history_card/1");
        assert_eq!(
            asked_record(&derived, &digests, &both, &verified(&[4])),
            None
        );
    }

    /// The exchange an ask names: by its digests in the request, or by a
    /// client nonce on exactly one of this node's own records; nothing for a
    /// derivation, a nonce on no own record, or one on two.
    #[test]
    fn asked_digests_come_from_the_request_or_our_one_record_with_the_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let capsules = crate::capsule_emit::CapsuleState::open(dir.path(), "me").unwrap();
        let exchange =
            |nonce: &'static str, body: &'static [u8]| crate::capsule_emit::ExchangeRecord {
                model: "m",
                client_nonce: Some(nonce),
                request_bytes: body,
                response_bytes:
                    br#"{"id":"x","choices":[{"message":{"role":"assistant","content":"y"}}]}"#,
                latency_ms: 1.0,
                exchange_id: None,
                requesting_party: None,
                host_provenance: None,
            };
        let once = capsules
            .emit_for_exchange(&exchange("nonce-once", br#"{"a":1}"#))
            .unwrap()
            .capsule;
        capsules
            .emit_for_exchange(&exchange("nonce-twice", br#"{"a":2}"#))
            .unwrap();
        capsules
            .emit_for_exchange(&exchange("nonce-twice", br#"{"a":3}"#))
            .unwrap();
        let ask = |c: &str| serde_json::json!({"subject": {"correlation": c}});
        let ledger = capsules.ledger_dir();

        assert_eq!(
            asked_digests(&ask("exchange-digests:aa:bb"), ledger),
            Some(("aa".into(), "bb".into()))
        );
        assert_eq!(
            asked_digests(&ask("nonce-once"), ledger),
            Some((
                once["effect"]["request_digest"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                once["effect"]["response_digest"]
                    .as_str()
                    .unwrap()
                    .to_string()
            ))
        );
        assert_eq!(asked_digests(&ask("nonce-twice"), ledger), None);
        assert_eq!(asked_digests(&ask("nonce-never"), ledger), None);
        let mut derived = ask("nonce-once");
        derived["derivation"] = serde_json::json!("history_card/1");
        assert_eq!(asked_digests(&derived, ledger), None);
    }

    /// The remote-OOM bound: bytes up to the cap pass through untouched; one
    /// byte over is a descriptive error, never an unbounded buffer.
    #[tokio::test]
    async fn read_to_end_bounded_accepts_at_cap_and_refuses_over_cap() {
        let at_cap = vec![7u8; MAX_SIDE_STREAM_BYTES as usize];
        let ok = read_to_end_bounded(at_cap.as_slice(), "test bytes")
            .await
            .expect("exactly-at-cap must be accepted");
        assert_eq!(ok.len() as u64, MAX_SIDE_STREAM_BYTES);

        let over_cap = vec![7u8; MAX_SIDE_STREAM_BYTES as usize + 1];
        let err = read_to_end_bounded(over_cap.as_slice(), "test bytes")
            .await
            .expect_err("over-cap must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("side-stream cap"), "{err}");
    }

    fn proven(key: &str) -> impl FnOnce() -> Option<String> + '_ {
        move || Some(key.to_string())
    }

    /// A full stranger pool declines strangers only: a proven principal still
    /// gets a permit, and the reverse holds too.
    #[test]
    fn strangers_cannot_exhaust_the_pool_a_proven_principal_draws_from() {
        let pools = InFlight::new();
        let held: Vec<_> = (0..MAX_IN_FLIGHT_STRANGERS)
            .map(|_| pools.try_acquire_with(|| None).expect("a stranger permit"))
            .collect();
        assert!(
            pools.try_acquire_with(|| None).is_err(),
            "the stranger pool is full"
        );
        let keys: Vec<String> = (0..MAX_IN_FLIGHT_ANSWERS)
            .map(|i| format!("k{i}"))
            .collect();
        let proven_held: Vec<_> = keys
            .iter()
            .map(|key| {
                pools
                    .try_acquire_with(proven(key))
                    .expect("a proven permit")
            })
            .collect();
        assert!(
            pools.try_acquire_with(proven("another")).is_err(),
            "the proven pool is full"
        );
        drop(held);
        assert!(
            pools.try_acquire_with(|| None).is_ok(),
            "a released permit is reused"
        );
        drop(proven_held);
    }

    /// One key holds at most its share of the proven pool: past it, that key
    /// is declined while another key is still answered, and a released
    /// permit gives the key its room back (evidencebook#206 row 3).
    #[test]
    fn one_key_cannot_hold_the_whole_proven_pool() {
        let pools = InFlight::new();
        let flood: Vec<_> = (0..MAX_IN_FLIGHT_PER_KEY)
            .map(|_| {
                pools
                    .try_acquire_with(proven("flood"))
                    .expect("inside its share")
            })
            .collect();
        assert!(
            pools.try_acquire_with(proven("flood")).is_err(),
            "past its share, though the pool has room"
        );
        let other = pools
            .try_acquire_with(proven("other"))
            .expect("another key is still answered");
        drop(flood);
        assert!(
            pools.try_acquire_with(proven("flood")).is_ok(),
            "its room comes back"
        );
        assert!(
            pools.held.lock().unwrap().get("flood").is_none(),
            "dropped permits release the share"
        );
        drop(other);
        assert!(pools.held.lock().unwrap().is_empty());
    }

    /// With both pools full the request is declined before it is classified.
    #[test]
    fn a_request_is_not_classified_while_both_pools_are_full() {
        let pools = InFlight::new();
        let keys: Vec<String> = (0..MAX_IN_FLIGHT_ANSWERS)
            .map(|i| format!("k{i}"))
            .collect();
        let held: Vec<_> = (0..MAX_IN_FLIGHT_STRANGERS)
            .map(|_| pools.try_acquire_with(|| None).unwrap())
            .chain(
                keys.iter()
                    .map(|key| pools.try_acquire_with(proven(key)).unwrap()),
            )
            .collect();
        assert!(pools
            .try_acquire_with(|| unreachable!("classified with both pools full"))
            .is_err());
        drop(held);
    }

    /// The stream's referee door is the one that checks who asks: a signed
    /// adjudicate request addressed to another node is refused
    /// `not_authorized`, and so is one addressed here but signed under the
    /// Evidence Request's tag; the same request unsigned, or signed under the
    /// referee's tag, gets past that check and is refused for something else
    /// (this node is named by no key here).
    #[test]
    fn the_stream_checks_an_adjudicate_requests_signature() {
        let dir = tempfile::tempdir().unwrap();
        let capsules = crate::capsule_emit::CapsuleState::open(dir.path(), "referee-door").unwrap();
        let request = serde_json::json!({
            "subject": {"kind": "adjudicate"},
            "selection_tier": 2,
            "halves": [{"capsule": {"capsule_id": "a"}}, {"capsule": {"capsule_id": "b"}}],
        });
        let now = crate::evidence_answer::now_utc();
        let at = chrono::DateTime::parse_from_rfc3339(&now).unwrap().into();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let unsigned = serde_json::to_vec(&request).unwrap();
        let signed = |channel, audience| {
            let mut request = request.clone();
            crate::requester_auth::sign(channel, &mut request, &key, at, audience);
            serde_json::to_vec(&request).unwrap()
        };
        use crate::requester_auth::Channel;
        let relayed = signed(Channel::RefereeAdjudicate, "node-x");
        let mistagged = signed(Channel::EvidenceRequest, "node-r");
        let tagged = signed(Channel::RefereeAdjudicate, "node-r");
        let reason = |bytes: &[u8]| {
            let reply = referee_answer(&capsules, bytes, &now, Some("node-r"))
                .flatten()
                .expect("a signed reply");
            serde_json::from_slice::<serde_json::Value>(&reply).unwrap()["reason"].clone()
        };
        assert_eq!(
            reason(&relayed),
            crate::referee::service::REASON_NOT_AUTHORIZED
        );
        assert_eq!(
            reason(&mistagged),
            crate::referee::service::REASON_NOT_AUTHORIZED
        );
        assert_ne!(
            reason(&unsigned),
            crate::referee::service::REASON_NOT_AUTHORIZED
        );
        assert_ne!(
            reason(&tagged),
            crate::referee::service::REASON_NOT_AUTHORIZED
        );
    }

    #[test]
    fn an_adjudicate_request_is_recorded_with_its_referee_and_pair() {
        let dir = tempfile::tempdir().unwrap();
        let request = serde_json::json!({
            "subject": {"kind": "adjudicate"},
            "twin_bracket_id": "bracket-1",
            "selection_tier": 2,
            "halves": [{"capsule": {"capsule_id": "a"}}, {"capsule": {"capsule_id": "b"}}],
        });
        let asked =
            requested_adjudication("referee-node", &request).expect("an adjudicate request");
        record_requested_adjudication(dir.path(), &asked).unwrap();
        let line =
            std::fs::read_to_string(dir.path().join(REQUESTED_ADJUDICATIONS_FILENAME)).unwrap();
        let recorded: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(recorded["referee"], serde_json::json!("referee-node"));
        assert_eq!(recorded["halves"], serde_json::json!(["a", "b"]));
        assert_eq!(recorded["twin_bracket_id"], serde_json::json!("bracket-1"));
        assert_eq!(recorded["selection_tier"], serde_json::json!(2));
    }

    #[test]
    fn any_other_evidence_request_is_not_an_adjudication() {
        let request =
            serde_json::json!({"subject": {"kind": "correlation", "by": "nonce", "value": "n"}});
        assert!(requested_adjudication("peer", &request).is_none());
        let one_half = serde_json::json!({"subject": {"kind": "adjudicate"}, "halves": [{"capsule": {"capsule_id": "a"}}]});
        assert!(requested_adjudication("peer", &one_half).is_none());
    }

    /// What checking a reply finds with no key announced for the peer.
    fn unverified(_: &[u8], _: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({"state": "no_announced_key"})
    }

    /// A recorded ask, its window closing `window` from now, on a fresh
    /// ledger.
    fn recorded_ask(
        window: Duration,
    ) -> (
        std::sync::Arc<crate::capsule_emit::CapsuleState>,
        crate::ask_book::Asked,
        tokio::time::Instant,
        Vec<u8>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let capsules = std::sync::Arc::new(
            crate::capsule_emit::CapsuleState::open(dir.path(), "node-under-test").unwrap(),
        );
        let request =
            serde_json::json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 1}});
        let asked = crate::ask_book::record_request(
            &capsules,
            &request,
            "peer",
            None,
            &crate::evidence_answer::now_utc(),
        )
        .unwrap();
        let sent = evidence_request::jcs::to_string(&request)
            .unwrap()
            .into_bytes();
        (
            capsules,
            asked,
            tokio::time::Instant::now() + window,
            sent,
            dir,
        )
    }

    fn record_types(capsules: &crate::capsule_emit::CapsuleState) -> Vec<serde_json::Value> {
        crate::evidence_panes::read_capsule_records(capsules.ledger_dir())
            .into_iter()
            .filter_map(|r| {
                r.pointer("/model_attestation/compute_attestation")?
                    .get(crate::ask_book::BLOCK)?
                    .get("record_type")
                    .cloned()
            })
            .collect()
    }

    #[tokio::test]
    async fn a_reply_after_the_callers_wait_but_inside_the_window_is_sealed() {
        let (capsules, asked, closes_at, sent, _dir) = recorded_ask(Duration::from_secs(60));
        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(rx); // the caller has already been told "no answer yet".
        let reply = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(br#"{"reason":"policy_declined"}"#.to_vec())
        };
        settle_ask(
            capsules.clone(),
            asked,
            unverified,
            sent.clone(),
            reply,
            closes_at,
            tx,
        )
        .await;
        assert_eq!(
            record_types(&capsules),
            ["evidence_request", "evidence_response"]
        );
    }

    #[tokio::test]
    async fn the_caller_hears_the_verification_the_response_records() {
        let (capsules, asked, closes_at, sent, _dir) = recorded_ask(Duration::from_secs(60));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let reply = async { Ok(br#"{"reason":"no_such_subject"}"#.to_vec()) };
        let signed_refusal = |_: &[u8], _: &serde_json::Value| serde_json::json!({"state": "refusal", "reason": "no_such_subject"});
        settle_ask(
            capsules.clone(),
            asked,
            signed_refusal,
            sent,
            reply,
            closes_at,
            tx,
        )
        .await;
        let (_, verification) = rx.await.unwrap().expect("an answer");
        // The ask held no commitment for the peer.
        assert_eq!(verification["policy_check"]["status"], "NOT_CHECKED");
        let recorded = crate::evidence_panes::read_capsule_records(capsules.ledger_dir())
            .into_iter()
            .filter_map(|r| {
                r.pointer("/model_attestation/compute_attestation")?
                    .get(crate::ask_book::BLOCK)
                    .cloned()
            })
            .find(|e| e["record_type"] == "evidence_response")
            .expect("the response record");
        assert_eq!(recorded["statement"]["verification"], verification);
        let response_record = crate::evidence_panes::read_capsule_records(capsules.ledger_dir())
            .into_iter()
            .rev()
            .find_map(|r| r["capsule_id"].as_str().map(str::to_string))
            .expect("a record");
        assert_eq!(
            crate::ask_book::kept_reply(capsules.ledger_dir(), &response_record).unwrap(),
            br#"{"reason":"no_such_subject"}"#,
            "the reply's bytes, as read, are kept with its response"
        );
    }

    #[tokio::test]
    async fn a_reply_after_the_window_closes_is_never_read() {
        let (capsules, asked, closes_at, sent, _dir) = recorded_ask(Duration::from_millis(20));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let late = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok(br#"{"artifact":"AAAA"}"#.to_vec())
        };
        // The task goes on to wait out the recorded window for the absence.
        let task = tokio::spawn(settle_ask(
            capsules.clone(),
            asked,
            unverified,
            sent,
            late,
            closes_at,
            tx,
        ));
        let settled = rx.await.expect("the caller hears");
        assert!(
            matches!(settled, Err(SendError::NoAnswer(_))),
            "{settled:?}"
        );
        task.abort();
        assert_eq!(record_types(&capsules), ["evidence_request"], "no response");
    }

    #[tokio::test]
    async fn a_reply_ready_only_once_the_window_has_closed_is_no_reply() {
        let (capsules, asked, _, sent, _dir) = recorded_ask(Duration::ZERO);
        let closed = tokio::time::Instant::now() - Duration::from_millis(1);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let ready = async { Ok(br#"{"artifact":"AAAA"}"#.to_vec()) };
        let task = tokio::spawn(settle_ask(
            capsules.clone(),
            asked,
            unverified,
            sent,
            ready,
            closed,
            tx,
        ));
        let settled = rx.await.expect("the caller hears");
        assert!(
            matches!(settled, Err(SendError::NoAnswer(_))),
            "{settled:?}"
        );
        task.abort();
        assert_eq!(record_types(&capsules), ["evidence_request"], "no response");
    }

    /// A /0-only peer refuses a /1 request `request_malformed` (IP §3.3 step
    /// 4); the retry asks under /0 with a nonce the book of asks has not
    /// seen. Any other answer, or a request this node did not send under
    /// /1, is not retried.
    #[test]
    fn a_v1_ask_refused_malformed_is_retried_under_v0() {
        use serde_json::json;
        let asked = json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 1},
                           "nonce": "n-1", "profile": "evidence-interop/1",
                           "requester_auth": {"key_id": "k", "sig": "s"}});
        let malformed = json!({"reason": "request_malformed", "request_digest": "ab", "issued_at": "t",
                               "key_id": "k", "sig": "s"});
        let v0 = fallback_to_v0(&asked, &malformed).expect("retried");
        assert_eq!(v0["profile"], json!("evidence-interop/0"));
        assert_eq!(v0["nonce"], json!("n-1/evidence-interop-0"));
        assert!(v0.get("requester_auth").is_none(), "signed anew when sent");
        assert_eq!(v0["subject"], asked["subject"]);

        let declined = json!({"reason": "policy_declined"});
        assert_eq!(fallback_to_v0(&asked, &declined), None);
        let answer = json!({"artifact_digest": "ab", "profile": "evidence-interop/1"});
        assert_eq!(fallback_to_v0(&asked, &answer), None);
        let mut sent_v0 = asked.clone();
        sent_v0["profile"] = json!("evidence-interop/0");
        assert_eq!(fallback_to_v0(&sent_v0, &malformed), None, "never twice");

        // A nonce the suffix would push past the limit is replaced by its
        // digest, so the retry is still a well-formed signed request.
        let mut long = asked.clone();
        long["nonce"] = json!("n".repeat(crate::requester_auth::MAX_NONCE_BYTES));
        let retry = fallback_to_v0(&long, &malformed).unwrap();
        let nonce = retry["nonce"].as_str().unwrap();
        assert!(nonce.len() <= crate::requester_auth::MAX_NONCE_BYTES);
        assert!(nonce.ends_with("/evidence-interop-0") && nonce.len() == 64 + 19);
    }

    /// What is sent as given, and what asks under /1.
    #[test]
    fn only_an_unsigned_map_naming_no_profile_is_asked_under_v1() {
        use serde_json::json;
        let plain = json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 1}});
        assert_eq!(
            under_v1(&plain).unwrap()["profile"],
            json!("evidence-interop/1")
        );
        let mut named = plain.clone();
        named["profile"] = json!("evidence-interop/0");
        let mut signed = plain.clone();
        signed["requester_auth"] = json!({"key_id": "k", "sig": "s"});
        for given in [named, signed, json!([]), json!("x"), json!(1)] {
            assert_eq!(under_v1(&given), None, "{given}");
        }
    }
}
