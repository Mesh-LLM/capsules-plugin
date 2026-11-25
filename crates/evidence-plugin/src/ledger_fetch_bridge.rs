//! `ledger-fetch/1`: the plugin-mesh-stream carrier for the E9/E10 two-sided
//! ledger's peer fetch -- on demand, off the request hot path, a
//! peer reads back ONE of THIS node's own sealed ledger entries by
//! `capsule_id` (the join key `lifecycle_channel::peer_capsule_id_for_seal`
//! already threads onto the requester's own sealed row). Modeled directly on
//! `mesh_evidence_bridge`'s responder/requester shape -- same
//! `OpenMeshStreamRequest`/`connect_mesh_stream` mechanism, zero new
//! mesh-llm-host-runtime protocol code -- but answers from
//! `CapsuleState::lookup`, in-process: this channel carries no Bundle
//! semantics and no checkpoint-coverage requirement, so a capsule sealed
//! seconds ago is fetchable immediately.
//!
//! **Plugin-internal, not a standardized wire.** This stream and its message
//! shape are this plugin's own behaviour between two copies of itself. No
//! public specification defines them, they are not a protocol other
//! implementations should target, and they may change between releases.
//! Nothing here stores and forwards a record or promises delivery.
//!
//! **Witness-level recompute only, never a second attestation.** The
//! responder returns the raw, *unsigned* `{capsule, signed_statement_b64,
//! node_pub_key_pem}` for a found entry -- nothing here signs, endorses, or
//! judges it. The requester (and, upstream, the browser's own
//! `recompute-identity.ts`) independently recomputes and verifies; this
//! bridge only carries bytes.
//!
//! **Sharing the plugin's one `on_open_stream` slot.** `DeclarativePluginBuilder`
//! keeps a single responder-side stream handler, and `OpenStreamRequest` (the
//! shape actually delivered to it) carries no channel name -- the mesh host
//! resolves channel gating before the plugin ever sees the request. `main.rs`
//! tells the two carriers apart by `OpenStreamRequest.metadata_json`: this
//! module's requester tags its open with `LEDGER_FETCH_METADATA_TAG`;
//! `mesh_evidence_bridge`'s requester always sends `None`. Anything other
//! than the exact tag falls through to the evidence-request path, so this is
//! purely additive -- no existing behavior changes.
//!
//! **Who asks** is proven as for an evidence request: the asker signs its
//! request (`requester_auth`, once its host took its key), addressed to the
//! node it fetches from, and the responder checks that signature, its
//! `audience`, its deadline and nonce, and the key's binding before it looks
//! anything up ([`answer`]). A record goes only to the node the signature
//! proves, never to the `requester_id` an asker states; an unsigned request
//! is refused before the ledger is read, under every setting (the
//! evidencebook#114 ruling: `peers` opens records to any proven node, never
//! to a stranger).
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{
    bind_side_stream, LocalListener, LocalStream, PluginContext, PluginError, PluginResult,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::AsyncWriteExt;

use crate::capsule_emit::CapsuleState;
use crate::mesh_evidence_bridge::{env_millis, next_stream_id, read_to_end_bounded};

/// The mesh channel this plugin declares on both ends, alongside
/// `mesh_evidence_bridge::EVIDENCE_REQUEST_CHANNEL`.
pub const LEDGER_FETCH_CHANNEL: &str = "ledger-fetch/1";

/// The tool name the requester side calls locally
/// (`POST /api/plugins/<plugin_id>/tools/mesh_ledger_fetch`).
pub const LEDGER_FETCH_OPERATION: &str = "mesh_ledger_fetch";

/// Tags an outbound `OpenMeshStreamRequest.metadata_json` as a ledger-fetch
/// open -- see module doc for why this, and not the channel name, is what
/// `main.rs`'s shared `on_open_stream` handler dispatches on.
const LEDGER_FETCH_METADATA_TAG: &str = "ledger-fetch/1";

/// True exactly when an inbound `OpenStreamRequest` is this module's; the
/// requester below is the only code in this plugin that ever sets this tag.
pub fn is_ledger_fetch_request(request: &OpenStreamRequest) -> bool {
    request.metadata_json.as_deref() == Some(LEDGER_FETCH_METADATA_TAG)
}

/// How long the RESPONDER waits for the mesh stream to actually deliver a
/// request (and separately, once it has one, to write the reply) before
/// giving up -- bounds a peer that opens the stream and then goes silent.
/// Overridable so a test proving the bound is enforced does not have to wait
/// out the production default.
fn responder_timeout() -> Duration {
    env_millis("CAPSULES_LEDGER_FETCH_HTTP_TIMEOUT_MS", 10_000)
}

/// How long the REQUESTER waits for a response once the mesh stream is open
/// -- mirrors `mesh_evidence_bridge::requester_idle_timeout_ms`'s contract:
/// a peer that never declared the channel has its stream dropped by the host
/// with no reply, and this bound turns that into a clean failure, not a hang.
fn requester_idle_timeout_ms() -> u64 {
    env_millis("CAPSULES_LEDGER_FETCH_TIMEOUT_MS", 8_000).as_millis() as u64
}

// ---------------------------------------------------------------------
// Responder role: mesh-inbound `ledger-fetch/1` stream -> local ledger lookup
// ---------------------------------------------------------------------

/// Registered (via `main.rs`'s shared dispatcher) as the ledger-fetch half
/// of this plugin's `on_open_stream` handler. Never fabricates a capsule --
/// a lookup miss or a malformed request both produce an honest, explicit
/// response variant (see [`LedgerFetchResponse`]); only a real
/// `CapsuleState::lookup` hit ever carries capsule bytes.
pub async fn handle_open_stream(
    request: OpenStreamRequest,
    _context: &mut PluginContext<'_>,
    capsules: Arc<CapsuleState>,
    self_peer: crate::self_peer::SelfPeer,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);
    // The id askers address this node by, as for an evidence request
    // (`mesh_evidence_bridge::handle_open_stream`).
    let own_node = self_peer.learned();
    if own_node.is_none() {
        tracing::warn!(
            "this node's own mesh id is not known yet: signed ledger-fetch requests are refused \
             until the host reports it"
        );
    }

    tokio::spawn(async move {
        if let Err(error) = bridge_inbound_ledger_fetch_stream(listener, capsules, own_node).await {
            tracing::warn!(%error, "mesh ledger-fetch responder bridge failed");
        }
    });

    Ok(Some(response))
}

#[derive(Debug, Deserialize)]
struct LedgerFetchRequest {
    capsule_id: String,
}

/// Every shape the responder can answer with -- deliberately explicit rather
/// than a bare `Option`/error string, so a caller (and a test) can tell
/// "no such entry" from "your request was malformed" from "here are the
/// bytes" without guessing at string contents.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
enum LedgerFetchResponse {
    Found {
        capsule: Value,
        /// Raw COSE_Sign1 bytes, base64-standard-encoded for the JSON
        /// carrier -- the same bytes `Ledger::lookup` returns, untouched.
        signed_statement_b64: String,
        node_pub_key_pem: String,
    },
    NotFound {
        capsule_id: String,
    },
    /// The record exists or not; either way this node does not give it to
    /// this asker (see [`may_serve`]), or the asker proved nothing where it
    /// had to ([`answer`]).
    NotAuthorized {
        capsule_id: String,
    },
    /// The record belongs to an earlier history of this node, set aside when
    /// its owner started a new one: it exists, it is not served from here.
    Archived {
        capsule_id: String,
    },
    Error {
        message: String,
    },
}

async fn bridge_inbound_ledger_fetch_stream(
    listener: LocalListener,
    capsules: Arc<CapsuleState>,
    own_node: Option<String>,
) -> anyhow::Result<()> {
    let local = tokio::time::timeout(responder_timeout(), listener.accept()).await??;
    let (mut read_half, mut write_half) = local.into_split();

    // The requester writes the whole `{"capsule_id": ...}` request then
    // half-closes (same convention `mesh_evidence_bridge` uses) -- read to
    // EOF to get exactly the request bytes, bounded in bytes as well as in
    // time: these are peer-controlled bytes read before the request is
    // authenticated. An oversized request gets no answer.
    let request_bytes = tokio::time::timeout(
        responder_timeout(),
        read_to_end_bounded(&mut read_half, "inbound ledger-fetch request"),
    )
    .await??;

    let now = crate::evidence_answer::now_utc();
    let announced = crate::peer_keys::announced::snapshot();
    let configured = crate::settings::var(crate::peer_keys::ENV_PEER_KEYS).ok();
    let own_key = hex::encode(capsules.public_key());
    let door = Door {
        now: &now,
        keys: crate::requester_auth::Keys {
            announced: &announced,
            configured: configured.as_deref(),
            own_key: Some(&own_key),
        },
        replay: crate::requester_auth::replay_cache(),
        own_node: own_node.as_deref(),
    };
    let response = answer(
        &capsules,
        &request_bytes,
        crate::share_policy::history_segments(),
        &door,
    );

    let response_bytes = serde_json::to_vec(&response)?;
    tokio::time::timeout(responder_timeout(), async {
        write_half.write_all(&response_bytes).await?;
        write_half.shutdown().await
    })
    .await??;
    Ok(())
}

/// Whether the record `capsule_id` goes to the asker under the node's
/// `history_segments` switch: the evidence-request responder's own rule
/// (`evidence_answer::may_serve_all_to`) over the same index, so the two
/// responders never decide a record differently (#371). `off` serves
/// nothing; a record that never leaves (a local block, an ask, a deal's
/// report, an owner-maintenance record) is never served; under `peers` any
/// other record goes to any proven node; otherwise only to the other side
/// of its exchange, by the node id it names or by the key its cited half
/// verified under (#172). A record the index does not hold (past a line the
/// index stopped at) is not served, as the evidence-request path does not
/// serve it either. `requester` and `requester_key` are what the request's
/// signature proved ([`answer`]).
pub(crate) fn may_serve(
    capsules: &CapsuleState,
    capsule_id: &str,
    requester: &[String],
    requester_key: Option<&str>,
    history_segments: &str,
) -> std::io::Result<bool> {
    let key_id = hex::encode(capsules.public_key());
    crate::evidence_log::with_index(capsules.ledger_dir(), &key_id, |index| {
        index.leaf_index_of(capsule_id).is_some_and(|leaf| {
            crate::evidence_answer::may_serve_all_to(
                index,
                &[leaf],
                requester,
                requester_key,
                history_segments,
            )
        })
    })
}

/// What a request is checked against before the ledger is read.
struct Door<'a> {
    /// Now, RFC 3339 UTC.
    now: &'a str,
    keys: crate::requester_auth::Keys<'a>,
    replay: &'a crate::requester_auth::ReplayCache,
    /// This node's own mesh id, as the host reported it.
    own_node: Option<&'a str>,
}

#[cfg(test)]
thread_local! {
    static LOOKUPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many times this thread has looked a record up: a test shows a
/// refusal came before the ledger was read.
#[cfg(test)]
fn lookups() -> u64 {
    LOOKUPS.with(std::cell::Cell::get)
}

/// The pure request-to-response step, split out of the async I/O wrapper
/// so it is directly unit-testable without a live mesh stream. In order:
/// parse; the switch `off` serves nothing; who asks
/// (`requester_auth::principal`: a signature that fails its deadline,
/// window, key, `audience`, nonce or stated id is refused, and so is an
/// unsigned request or one under a key no host binds); and only then the
/// lookup, served to the proven node alone.
fn answer(
    capsules: &CapsuleState,
    request_bytes: &[u8],
    history_segments: &str,
    door: &Door<'_>,
) -> LedgerFetchResponse {
    let malformed = |error: &dyn std::fmt::Display| LedgerFetchResponse::Error {
        message: format!("malformed ledger-fetch request: {error}"),
    };
    let parsed = match serde_json::from_slice::<LedgerFetchRequest>(request_bytes) {
        Ok(parsed) => parsed,
        Err(error) => return malformed(&error),
    };
    let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(request_bytes) else {
        return malformed(&"not a JSON object");
    };
    if crate::requester_auth::form(&map) == crate::requester_auth::Form::Malformed {
        return malformed(&crate::requester_auth::MEMBER);
    }
    let not_authorized = LedgerFetchResponse::NotAuthorized {
        capsule_id: parsed.capsule_id.clone(),
    };
    if history_segments == "off" {
        return not_authorized;
    }
    let Some(now) = evidence_request::time::parse_utc(door.now) else {
        return LedgerFetchResponse::Error {
            message: "this node's clock is not an RFC 3339 UTC time".into(),
        };
    };
    let principal = match crate::requester_auth::principal(
        crate::requester_auth::Channel::LedgerFetch,
        &map,
        now,
        door.keys,
        door.replay,
        door.own_node,
        true,
    ) {
        Ok(principal) => principal,
        Err(crate::requester_auth::Refused::Malformed) => {
            return malformed(&crate::requester_auth::MEMBER)
        }
        Err(crate::requester_auth::Refused::NotAuthorized) => return not_authorized,
    };
    // Every node the asker's key is bound to (D-34).
    let requester = principal.as_ref().map_or(&[][..], |p| &p.node_ids[..]);
    let requester_key = principal.as_ref().map(|p| p.key_id.as_str());

    #[cfg(test)]
    LOOKUPS.with(|n| n.set(n.get() + 1));
    match capsules.lookup(&parsed.capsule_id) {
        Ok(Some(entry)) => match may_serve(
            capsules,
            &parsed.capsule_id,
            requester,
            requester_key,
            history_segments,
        ) {
            Ok(true) => LedgerFetchResponse::Found {
                capsule: entry.capsule,
                signed_statement_b64: base64::engine::general_purpose::STANDARD
                    .encode(&entry.signed_statement),
                node_pub_key_pem: capsules.public_key_pem(),
            },
            Ok(false) => LedgerFetchResponse::NotAuthorized {
                capsule_id: parsed.capsule_id,
            },
            Err(error) => LedgerFetchResponse::Error {
                message: format!("ledger index unreadable: {error}"),
            },
        },
        Ok(None)
            if capsules.ledger_dir().parent().is_some_and(|data_dir| {
                crate::owner_maintenance::is_archived(data_dir, &parsed.capsule_id)
            }) =>
        {
            LedgerFetchResponse::Archived {
                capsule_id: parsed.capsule_id,
            }
        }
        Ok(None) => LedgerFetchResponse::NotFound {
            capsule_id: parsed.capsule_id,
        },
        Err(error) => LedgerFetchResponse::Error {
            message: format!("ledger lookup failed: {error}"),
        },
    }
}

// ---------------------------------------------------------------------
// Requester role: local tool call -> outbound `ledger-fetch/1` stream
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MeshLedgerFetchArgs {
    /// Hex-encoded mesh peer id whose ledger to fetch from, e.g.
    /// `iroh::EndpointId::to_string()`.
    pub peer_id: String,
    /// The peer-asserted `capsule_id` to fetch -- the join key piece 1
    /// (`lifecycle_channel::peer_capsule_id_for_seal`) threads onto this
    /// node's own sealed row for a `RemoteMesh` exchange.
    pub capsule_id: String,
}

/// Registered as the `mesh_ledger_fetch` tool/operation handler. Returns the
/// peer's raw `LedgerFetchResponse` JSON unchanged on success; any transport
/// failure (unroutable peer, channel undeclared on the peer, response never
/// arrives) surfaces as a tool error, which the host's `/tools/` HTTP route
/// reports as a `502`, never a hang.
pub async fn handle_mesh_ledger_fetch(
    args: MeshLedgerFetchArgs,
    context: &mut PluginContext<'_>,
    self_id: Option<String>,
) -> PluginResult<Value> {
    if args.peer_id.trim().is_empty() {
        return Err(PluginError::invalid_params("peer_id must not be empty"));
    }
    if args.capsule_id.trim().is_empty() {
        return Err(PluginError::invalid_params("capsule_id must not be empty"));
    }

    // One form of the id, for the stream and for the audience it is signed
    // for (`mesh_evidence_bridge::send_evidence_request`).
    let peer_id = args.peer_id.trim();
    let peer_id = if peer_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        peer_id.to_ascii_lowercase()
    } else {
        peer_id.to_string()
    };
    let open_request = OpenMeshStreamRequest {
        stream_id: next_stream_id("ledger-fetch"),
        target_peer_id: peer_id.clone(),
        plugin_id: String::new(), // host fills this in from the connection.
        channel: LEDGER_FETCH_CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some("application/json".to_string()),
        correlation_id: Some(next_stream_id("ledger-fetch-correlation")),
        metadata_json: Some(LEDGER_FETCH_METADATA_TAG.to_string()),
        expected_bytes: None,
        idle_timeout_ms: Some(requester_idle_timeout_ms()),
    };

    let stream: LocalStream = context
        .connect_mesh_stream(open_request)
        .await
        .map_err(|error| PluginError::internal(format!("could not reach peer: {error}")))?;
    let (mut read_half, mut write_half) = stream.into_split();

    // Signed as this node once its key is announced; the responder serves a
    // record only to the node the signature proves.
    let mut request = serde_json::json!({ "capsule_id": args.capsule_id, "requester_id": self_id });
    crate::requester_auth::sign_outgoing(
        crate::requester_auth::Channel::LedgerFetch,
        &mut request,
        &peer_id,
    );
    let request_bytes = serde_json::to_vec(&request).expect("a map of strings always serializes");

    let response_bytes = tokio::time::timeout(
        Duration::from_millis(requester_idle_timeout_ms()),
        exchange(&mut read_half, &mut write_half, &request_bytes),
    )
    .await
    .map_err(|_| PluginError::internal("peer does not answer ledger-fetch requests"))?
    .map_err(|error| {
        PluginError::internal(format!(
            "peer does not answer ledger-fetch requests: {error}"
        ))
    })?;

    serde_json::from_slice(&response_bytes).map_err(|error| {
        PluginError::internal(format!(
            "peer returned malformed ledger-fetch response: {error}"
        ))
    })
}

/// Send `request_bytes`, half-close, and read the peer's whole response,
/// bounded in bytes: the response is peer-controlled too.
async fn exchange<R, W>(read: R, write: &mut W, request_bytes: &[u8]) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    write.write_all(request_bytes).await?;
    write.shutdown().await?;
    read_to_end_bounded(read, "peer ledger-fetch response").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule_emit::ExchangeRecord;
    use crate::evidence_request_parity::{announced_keys, asker_key, RESPONDER_NODE};
    use crate::requester_auth::{Keys, ReplayCache};
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    const NOW: &str = "2026-10-14T00:00:00Z";

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().into()
    }

    /// `request` signed with `key` at [`NOW`], addressed to `audience`.
    fn signed_with(key: &SigningKey, audience: &str, request: Value) -> Vec<u8> {
        let mut request = request;
        crate::requester_auth::sign(
            crate::requester_auth::Channel::LedgerFetch,
            &mut request,
            key,
            at(NOW),
            audience,
        );
        serde_json::to_vec(&request).unwrap()
    }

    /// A fetch of `capsule_id` by `node`, stating its id, signed by it.
    fn signed_by(node: &str, capsule_id: &str) -> Vec<u8> {
        signed_with(
            &asker_key(node),
            RESPONDER_NODE,
            json!({"capsule_id": capsule_id, "requester_id": node}),
        )
    }

    /// `bytes` asked at `now` of a node switched to `tier`, with `replay`.
    fn answer_at(
        state: &CapsuleState,
        bytes: &[u8],
        tier: &str,
        now: &str,
        replay: &ReplayCache,
    ) -> LedgerFetchResponse {
        let announced = announced_keys();
        let door = Door {
            now,
            keys: Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay,
            own_node: Some(RESPONDER_NODE),
        };
        answer(state, bytes, tier, &door)
    }

    /// `bytes` asked at [`NOW`] with a fresh replay cache.
    fn answer_now(state: &CapsuleState, bytes: &[u8], tier: &str) -> LedgerFetchResponse {
        answer_at(state, bytes, tier, NOW, &ReplayCache::default())
    }

    /// `answer_now`, and whether it looked anything up.
    fn answer_counted(
        state: &CapsuleState,
        bytes: &[u8],
        tier: &str,
    ) -> (LedgerFetchResponse, bool) {
        let before = lookups();
        let response = answer_now(state, bytes, tier);
        (response, lookups() != before)
    }

    /// Same convention `capsule_emit`'s own tests use -- a process-id-suffixed
    /// dir under the OS temp root, wiped before open -- rather than adding a
    /// `tempfile` dependency for one test module.
    fn open_state(label: &str) -> CapsuleState {
        let dir = std::env::temp_dir().join(format!("ledger-fetch-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CapsuleState::open(&dir, "ledger-fetch-test").expect("open capsule state")
    }

    /// The record's other side: a node whose key the host announced.
    const ASKER: &str = "node-a";

    fn seal_one(state: &CapsuleState) -> String {
        seal_for(state, Some(ASKER))
    }

    fn seal_for(state: &CapsuleState, requesting_party: Option<&str>) -> String {
        let emitted = state
            .emit_for_exchange(&ExchangeRecord {
                model: "test-model",
                client_nonce: None,
                request_bytes: b"{}",
                response_bytes: b"{}",
                latency_ms: 1.0,
                exchange_id: Some("exchange-1"),
                requesting_party,
                host_provenance: None,
            })
            .expect("seal one capsule");
        emitted.capsule_id
    }

    /// (positive) A real hit round-trips the exact capsule bytes and this
    /// node's real pubkey -- proves the responder answers from the ledger,
    /// not from thin air.
    #[test]
    fn found_entry_carries_the_real_capsule_and_pubkey() {
        let state = open_state("found");
        let capsule_id = seal_one(&state);

        let response = answer_now(&state, &signed_by(ASKER, &capsule_id), "counterparties");

        match response {
            LedgerFetchResponse::Found {
                capsule,
                signed_statement_b64,
                node_pub_key_pem,
            } => {
                assert_eq!(capsule["capsule_id"], capsule_id);
                assert!(!signed_statement_b64.is_empty());
                assert_eq!(node_pub_key_pem, state.public_key_pem());
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    /// (negative, R4 other half) A capsule_id this node never sealed must
    /// come back `NotFound`, never a fabricated/empty `Found`.
    #[test]
    fn unknown_capsule_id_is_reported_not_found_never_fabricated() {
        let state = open_state("not-found");
        seal_one(&state); // ledger is non-empty, but the id below is not in it.

        let response = answer_now(&state, &signed_by(ASKER, "not-a-real-id"), "counterparties");

        assert_eq!(
            response,
            LedgerFetchResponse::NotFound {
                capsule_id: "not-a-real-id".to_string()
            }
        );
    }

    /// A fetch signed by `node`, or unsigned with no stated id.
    fn ask(
        state: &CapsuleState,
        capsule_id: &str,
        node: Option<&str>,
        tier: &str,
    ) -> LedgerFetchResponse {
        let request = match node {
            Some(node) => signed_by(node, capsule_id),
            None => serde_json::to_vec(&json!({ "capsule_id": capsule_id })).unwrap(),
        };
        answer_now(state, &request, tier)
    }

    fn is_found(response: &LedgerFetchResponse) -> bool {
        matches!(response, LedgerFetchResponse::Found { .. })
    }

    fn is_refused(response: &LedgerFetchResponse) -> bool {
        matches!(response, LedgerFetchResponse::NotAuthorized { .. })
    }

    /// Only the other side of the exchange gets the record: another node, or
    /// an asker that names no one, is declined. MUTANT: drop the
    /// counterparty check and any node reads any record.
    #[test]
    fn a_record_goes_only_to_the_node_it_names_as_the_other_side() {
        let state = open_state("counterparty");
        let id = seal_one(&state);
        {
            let tier = "counterparties";
            assert!(is_found(&ask(&state, &id, Some(ASKER), tier)));
            let other = ask(&state, &id, Some("node-y"), tier);
            assert_eq!(
                other,
                LedgerFetchResponse::NotAuthorized {
                    capsule_id: id.clone()
                }
            );
            assert!(is_refused(&ask(&state, &id, None, tier)));
        }
    }

    /// Seal a record citing a half this node accepted on `sender`'s key,
    /// pushed under the id `pushed_under` (no `x-mesh-poc-v1` block, so it
    /// names no other side by id).
    fn seal_citing(state: &CapsuleState, sender: &str, pushed_under: &str) -> String {
        let sender_key = hex::encode(asker_key(sender).verifying_key().to_bytes());
        let foreign_id = "d".repeat(64);
        let prov = crate::producer::capsule::ReceivedHalfProvenance {
            foreign_capsule_id: &foreign_id,
            received_from: pushed_under,
            via: "push",
            received_at: "2026-10-13T00:00:00Z",
            signature_ok: true,
            digest_match: None,
            foreign_agent_input_digest: None,
            foreign_agent_output_digest: None,
            sender_key_id: Some(&sender_key),
            accepted_via: Some(&crate::peer_keys::AcceptedVia::HostAnnounced),
            controller_binding: None,
            same_controller_as_receiver: None,
            own_half_capsule_id: None,
        };
        state
            .emit_citing_record(&prov)
            .expect("seal citing record")
            .expect("not cited before")
            .capsule_id
    }

    /// The fetch and the evidence-request responder decide by one rule
    /// (#371): under `counterparties` a citing record goes to the holder of
    /// the key its half verified under, whatever id the push named (#172),
    /// and to no one else. Before #371 the fetch read only the record's
    /// `x-mesh-poc-v1` side and refused the key holder.
    #[test]
    fn a_citing_record_goes_to_the_holder_of_the_key_its_half_verified_under() {
        let state = open_state("key-holder");
        let id = seal_citing(&state, "node-b", "node-pushed-under");
        assert!(is_found(&ask(
            &state,
            &id,
            Some("node-b"),
            "counterparties"
        )));
        for other in [ASKER, "node-pushed-under"] {
            assert!(
                is_refused(&ask(&state, &id, Some(other), "counterparties")),
                "{other} holds no key the half verified under"
            );
        }
        assert!(is_found(&ask(&state, &id, Some(ASKER), "peers")));
    }

    /// For each record kind and switch, the fetch serves exactly what the
    /// evidence-request rule over the same index serves (#371).
    #[test]
    fn the_fetch_and_the_evidence_request_rule_agree() {
        let state = open_state("agree");
        let exchange = seal_one(&state);
        let no_side = seal_for(&state, None);
        let citing = seal_citing(&state, "node-b", "node-pushed-under");
        let block = state
            .emit_local_routing_choice(
                crate::producer::capsule::RoutingChoiceChange::Block,
                ASKER,
                None,
                &[3u8; 32],
                None,
            )
            .expect("seal block")
            .capsule_id;
        let dealt = state
            .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange(ASKER))
            .expect("seal the dealt exchange")
            .capsule_id;
        crate::deal_receipt::tests::seal_deal(&state, &dealt, true);
        let key_id = hex::encode(state.public_key());
        let deal_records: Vec<String> =
            crate::evidence_log::with_index(state.ledger_dir(), &key_id, |i| {
                i.deal_capsules_of(&dealt)
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap();
        assert!(!deal_records.is_empty(), "the deal sealed its records");
        // A deal's step names its other side through the exchange it is
        // about (the index's `deal_counterparty`), which the fetch's old
        // copy of the rule did not read: the step now goes to that side.
        assert!(
            deal_records
                .iter()
                .any(|id| is_found(&ask(&state, id, Some(ASKER), "counterparties"))),
            "a deal record goes to the deal's other side"
        );
        let ids = [&exchange, &no_side, &citing, &block, &dealt]
            .into_iter()
            .cloned()
            .chain(deal_records);
        for id in ids {
            let id = &id;
            for asker in [ASKER, "node-b", "node-y"] {
                let principal = vec![asker.to_string()];
                let asker_key = hex::encode(asker_key(asker).verifying_key().to_bytes());
                for tier in ["off", "peers", "counterparties"] {
                    let rule = crate::evidence_log::with_index(state.ledger_dir(), &key_id, |i| {
                        let leaf = i.leaf_index_of(id).expect("indexed");
                        crate::evidence_answer::may_serve_all_to(
                            i,
                            &[leaf],
                            &principal,
                            Some(&asker_key),
                            tier,
                        )
                    })
                    .unwrap();
                    let fetched = is_found(&ask(&state, id, Some(asker), tier));
                    assert_eq!(fetched, rule, "{id} {asker} {tier}");
                }
            }
        }
    }

    #[test]
    fn the_sharing_switch_decides_off_serves_nothing_and_peers_serves_any_proven_node() {
        let state = open_state("switch");
        let id = seal_one(&state);
        assert!(is_refused(&ask(&state, &id, Some(ASKER), "off")));
        // Refused before the lookup: a record it never sealed gets the same.
        assert_eq!(
            ask(&state, "never-sealed", Some(ASKER), "off"),
            LedgerFetchResponse::NotAuthorized {
                capsule_id: "never-sealed".into()
            }
        );
        assert!(is_found(&ask(&state, &id, Some("node-y"), "peers")));
        // A stranger gets nothing under any setting, before the lookup.
        for tier in ["counterparties", "peers", "off"] {
            let bytes = serde_json::to_vec(&json!({ "capsule_id": id })).unwrap();
            let (response, looked) = answer_counted(&state, &bytes, tier);
            assert!(is_refused(&response), "{tier}: {response:?}");
            assert!(!looked, "{tier}: the ledger was read");
        }
    }

    /// A local block names no other side of an exchange: it never leaves this
    /// node, not even under `peers`, not even to the blocked node itself.
    #[test]
    fn a_local_block_record_is_never_served() {
        let state = open_state("block");
        let block = state
            .emit_local_routing_choice(
                crate::producer::capsule::RoutingChoiceChange::Block,
                ASKER,
                None,
                &[3u8; 32],
                None,
            )
            .expect("seal block");
        for tier in ["counterparties", "peers"] {
            let response = ask(&state, &block.capsule_id, Some(ASKER), tier);
            assert_eq!(
                response,
                LedgerFetchResponse::NotAuthorized {
                    capsule_id: block.capsule_id.clone()
                }
            );
        }
    }

    /// A record that names no other side (no requesting party) is never
    /// served under the default.
    #[test]
    fn a_record_naming_no_other_side_is_declined() {
        let state = open_state("no-side");
        let id = seal_for(&state, None);
        assert!(is_refused(&ask(&state, &id, Some(ASKER), "counterparties")));
    }

    /// (negative) Malformed request bytes must produce an explicit `Error`,
    /// never be mistaken for a `NotFound` (which would look like "the ledger
    /// doesn't have anything with this key" instead of "your request was
    /// unreadable").
    #[test]
    fn malformed_request_bytes_are_reported_as_error_not_not_found() {
        let state = open_state("malformed");

        let response = answer_now(&state, b"not json at all", "counterparties");

        match response {
            LedgerFetchResponse::Error { message } => {
                assert!(message.contains("malformed"), "message was: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// R-13 on this channel (PRD T3): node-y fetches node-a's record
    /// claiming to be node-a, unsigned, with its own key, or with node-a's
    /// key id over its own signature. Each is `not_authorized` before
    /// anything is looked up. The same fetch signed by node-a is served.
    /// MUTANT: serve on the stated `requester_id` and node-y reads it.
    #[test]
    fn a_node_claiming_to_be_the_other_side_is_refused_before_the_ledger_is_read() {
        let state = open_state("claims-other-side");
        let id = seal_one(&state);
        let request = json!({"capsule_id": id, "requester_id": ASKER});
        let unsigned = serde_json::to_vec(&request).unwrap();
        let own_key_claims_a = signed_with(&asker_key("node-y"), RESPONDER_NODE, request);
        let mut a_key_y_sig: Value = serde_json::from_slice(&own_key_claims_a).unwrap();
        a_key_y_sig["requester_auth"]["key_id"] =
            json!(hex::encode(asker_key(ASKER).verifying_key().to_bytes()));
        let a_key_y_sig = serde_json::to_vec(&a_key_y_sig).unwrap();
        {
            let tier = "counterparties";
            for bytes in [&unsigned, &own_key_claims_a, &a_key_y_sig] {
                let (response, looked) = answer_counted(&state, bytes, tier);
                assert_eq!(
                    response,
                    LedgerFetchResponse::NotAuthorized {
                        capsule_id: id.clone()
                    },
                    "{tier}"
                );
                assert!(!looked, "the ledger was read ({tier})");
            }
            assert!(is_found(&answer_now(&state, &signed_by(ASKER, &id), tier)));
        }
    }

    /// A fetch node-a signed for another node, relayed here, is refused
    /// before anything is looked up: the signature covers its `audience`.
    #[test]
    fn a_fetch_addressed_to_another_node_is_refused_before_the_ledger_is_read() {
        let state = open_state("audience");
        let id = seal_one(&state);
        let relayed = signed_with(
            &asker_key(ASKER),
            "node-x",
            json!({"capsule_id": id, "requester_id": ASKER}),
        );
        for tier in ["counterparties", "peers"] {
            let (response, looked) = answer_counted(&state, &relayed, tier);
            assert_eq!(
                response,
                LedgerFetchResponse::NotAuthorized {
                    capsule_id: id.clone()
                }
            );
            assert!(!looked, "the ledger was read ({tier})");
        }
    }

    /// A fetch the record's other side signed for another channel (an
    /// Evidence Request, a referee's `adjudicate`) is refused before anything
    /// is looked up, though its body is a fetch addressed here: the door
    /// checks it under `ledger-fetch/1`'s tag (ruling u338). MUTANT: one
    /// tag shared by every channel and it is served.
    #[test]
    fn a_fetch_signed_for_another_channel_is_refused_before_the_ledger_is_read() {
        use crate::requester_auth::Channel;
        let state = open_state("channel");
        let id = seal_one(&state);
        for channel in [Channel::EvidenceRequest, Channel::RefereeAdjudicate] {
            let mut request = json!({"capsule_id": id, "requester_id": ASKER});
            crate::requester_auth::sign(
                channel,
                &mut request,
                &asker_key(ASKER),
                at(NOW),
                RESPONDER_NODE,
            );
            let bytes = serde_json::to_vec(&request).unwrap();
            for tier in ["counterparties", "peers"] {
                let (response, looked) = answer_counted(&state, &bytes, tier);
                assert_eq!(
                    response,
                    LedgerFetchResponse::NotAuthorized {
                        capsule_id: id.clone()
                    },
                    "{channel:?} ({tier})"
                );
                assert!(!looked, "the ledger was read: {channel:?} ({tier})");
            }
        }
        assert!(is_found(&ask(&state, &id, Some(ASKER), "counterparties")));
    }

    /// A signed fetch is answered once: the same bytes again before their
    /// deadline, or any time after it, are refused before the ledger is read.
    #[test]
    fn a_replayed_or_late_fetch_is_refused_before_the_ledger_is_read() {
        let state = open_state("replay");
        let id = seal_one(&state);
        let bytes = signed_by(ASKER, &id);
        let replay = ReplayCache::default();
        assert!(is_found(&answer_at(
            &state,
            &bytes,
            "counterparties",
            NOW,
            &replay
        )));
        let before = lookups();
        assert!(is_refused(&answer_at(
            &state,
            &bytes,
            "counterparties",
            NOW,
            &replay
        )));
        let late = "2026-10-14T00:02:01Z";
        let fresh = ReplayCache::default();
        assert!(is_refused(&answer_at(
            &state,
            &bytes,
            "counterparties",
            late,
            &fresh
        )));
        assert_eq!(lookups(), before, "the ledger was read");
    }

    /// Under `peers` a signature that fails is refused, and so is a valid one
    /// under a key no host binds: it proves no node, so it is a stranger's,
    /// as an unsigned fetch is.
    #[test]
    fn under_peers_a_failed_signature_and_an_unbound_key_are_refused() {
        let state = open_state("peers-signed");
        let id = seal_one(&state);
        let mut tampered: Value = serde_json::from_slice(&signed_by(ASKER, &id)).unwrap();
        tampered["capsule_id"] = json!("another-id");
        let tampered = serde_json::to_vec(&tampered).unwrap();
        let (response, looked) = answer_counted(&state, &tampered, "peers");
        assert!(matches!(
            response,
            LedgerFetchResponse::NotAuthorized { .. }
        ));
        assert!(!looked, "the ledger was read");
        let unbound = signed_with(
            &SigningKey::from_bytes(&[9; 32]),
            RESPONDER_NODE,
            json!({"capsule_id": id}),
        );
        for tier in ["counterparties", "peers"] {
            let (response, looked) = answer_counted(&state, &unbound, tier);
            assert!(is_refused(&response), "{tier}: {response:?}");
            assert!(!looked, "{tier}: the ledger was read");
        }
    }

    /// A malformed `requester_auth` is an `Error`, never served.
    #[test]
    fn a_malformed_signature_member_is_an_error() {
        let state = open_state("malformed-auth");
        let id = seal_one(&state);
        let bytes = serde_json::to_vec(&json!({"capsule_id": id, "requester_auth": "x"})).unwrap();
        for tier in ["counterparties", "peers", "off"] {
            let (response, looked) = answer_counted(&state, &bytes, tier);
            assert!(
                matches!(response, LedgerFetchResponse::Error { .. }),
                "{response:?}"
            );
            assert!(!looked);
        }
    }

    /// (positive) `is_ledger_fetch_request` is what `main.rs`'s shared
    /// `on_open_stream` dispatcher relies on to route inbound streams to
    /// this module instead of `mesh_evidence_bridge` -- prove the tag it
    /// checks is exactly the tag the requester above actually sends.
    #[test]
    fn dispatch_tag_matches_the_requesters_own_metadata_json() {
        let tagged = OpenStreamRequest {
            stream_id: "s".to_string(),
            purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
            mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
            bidirectional: true,
            content_type: None,
            correlation_id: None,
            metadata_json: Some(LEDGER_FETCH_METADATA_TAG.to_string()),
            expected_bytes: None,
            idle_timeout_ms: None,
        };
        assert!(is_ledger_fetch_request(&tagged));
    }

    /// (negative, R4 other half) The evidence-request carrier's own
    /// `metadata_json: None` open (and any other untagged open) must NOT be
    /// claimed by this module -- otherwise every existing evidence-request
    /// stream would silently misroute into the ledger-fetch responder.
    #[test]
    fn untagged_or_differently_tagged_requests_are_never_claimed() {
        let untagged = OpenStreamRequest {
            stream_id: "s".to_string(),
            purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
            mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
            bidirectional: true,
            content_type: None,
            correlation_id: None,
            metadata_json: None,
            expected_bytes: None,
            idle_timeout_ms: None,
        };
        assert!(!is_ledger_fetch_request(&untagged));

        let mut other_tag = untagged;
        other_tag.metadata_json = Some("some-other-carrier/1".to_string());
        assert!(!is_ledger_fetch_request(&other_tag));
    }

    /// An inbound request over the side-stream cap is refused before it is
    /// authenticated or answered: the responder errors and writes nothing
    /// back. Peer-controlled bytes never control this process's memory.
    #[tokio::test]
    async fn an_oversized_inbound_request_is_refused_unanswered() {
        use crate::mesh_evidence_bridge::MAX_SIDE_STREAM_BYTES;
        use tokio::io::AsyncReadExt;
        let state = Arc::new(open_state("oversized-request"));
        // Short ids: the socket path must fit the platform limit (104 bytes
        // on macOS).
        let listener = bind_side_stream("c", &next_stream_id("lf")).await.unwrap();
        let (endpoint, kind) = (listener.endpoint(), listener.transport_kind());
        let responder = tokio::spawn(bridge_inbound_ledger_fetch_stream(listener, state, None));
        let stream = mesh_llm_plugin::connect_side_stream(&endpoint, kind)
            .await
            .unwrap();
        let (mut read, mut write) = stream.into_split();
        write
            .write_all(&vec![b' '; MAX_SIDE_STREAM_BYTES as usize + 1])
            .await
            .unwrap();
        // The responder may already have dropped the stream.
        let _ = write.shutdown().await;
        let err = responder.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("side-stream cap"), "{err}");
        let mut answer = Vec::new();
        let _ = read.read_to_end(&mut answer).await;
        assert!(answer.is_empty());
    }

    /// The requester reads a peer's response up to the cap and refuses one
    /// byte more.
    #[tokio::test]
    async fn an_oversized_peer_response_is_refused() {
        use crate::mesh_evidence_bridge::MAX_SIDE_STREAM_BYTES;
        use tokio::io::AsyncReadExt;
        for (len, accepted) in [
            (MAX_SIDE_STREAM_BYTES as usize, true),
            (MAX_SIDE_STREAM_BYTES as usize + 1, false),
        ] {
            let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
            let peer = tokio::spawn(async move {
                let mut request = Vec::new();
                theirs.read_to_end(&mut request).await.unwrap();
                let _ = theirs.write_all(&vec![b' '; len]).await;
                let _ = theirs.shutdown().await;
                request
            });
            let (read, mut write) = tokio::io::split(ours);
            let response = exchange(read, &mut write, b"{}").await;
            assert_eq!(peer.await.unwrap(), b"{}");
            match response {
                Ok(bytes) => assert!(accepted && bytes.len() == len, "{len}"),
                Err(e) => assert!(
                    !accepted && e.to_string().contains("side-stream cap"),
                    "{len}: {e}"
                ),
            }
        }
    }
}
