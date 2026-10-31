//! The record-push-at-completion transport: the `record-push/1` mesh
//! channel, a sibling of `mesh_evidence_bridge.rs` over the same
//! `OpenMeshStreamRequest`/`connect_stream` mechanism. Plugin-internal
//! behaviour, not a standardized wire; it may change. Zero upstream
//! (`mesh-llm`) code.
//!
//! **Plugin-internal, not a standardized wire.** This stream and its message
//! shape are this plugin's own behaviour between two copies of itself. No
//! public specification defines them, they are not a protocol other
//! implementations should target, and they may change between releases.
//! Nothing here stores and forwards a record or promises delivery.
//!
//! **Receiving.** An inbound push is received in-process by
//! [`crate::record_push_receive`], which verifies it (the sender's announced
//! key, the signature, the claims, a bundle's proof and checkpoint) and holds
//! it. This module carries the bytes, then seals the citing records for what
//! was received. A referee's verdict delivered over the same channel is
//! refused, signed: this node has no referee yet.
//!
//! **Wire shape.** The body is the pushed capsule's own JSON bytes, opaque at
//! the transport level. On the stream, never inside the body, one line comes
//! before it: the pusher's self-declared mesh peer id, then `\n`, then the
//! body unchanged. The responder splits on the first `\n`. The receiver
//! checks the record's signature under a key it accepts, whatever id was
//! declared (D-34), before it holds anything; this module never itself
//! authenticates anything, it only carries the claim and the bytes.
//!
//! **Why a self-declared id, not a mesh-authenticated one.** `mesh-llm-plugin
//! 0.76.2`'s `OpenStreamRequest` (verified against the vendored crate
//! source) carries no sender/requester identity field at all, and
//! `PluginContext` exposes no "who is this connection from" accessor -- the
//! RESPONDER genuinely cannot learn the sender's peer id from the mesh
//! transport itself in this SDK version. Self-declaration on the wire, then
//! a REAL cryptographic check against an announced key on the receiving
//! side, is the same discipline `/evidence-request`'s existing
//! `X-Mesh-Requester-Id` self-attestation already uses -- this module does
//! not invent a weaker trust model, it reuses the one already shipped.
//!
//! **The pushing peer's mesh node id is NOT capturable here either
//! (re-verified against both the 0.76.2 proto and the mesh-llm host source).** Every
//! `OpenStreamRequest` field the responder sees (`stream_id`,
//! `content_type`, `correlation_id`, `metadata_json`, ...) is copied
//! VERBATIM from the requester's own `OpenMeshStreamRequest` by the host's
//! `open_stream_request_from_mesh_request` -- all requester-controlled, so
//! anything carried there (including a node id tucked into `metadata_json`)
//! would be one more self-declaration, not a transport attestation. The
//! receiving host DOES hold the transport-authenticated remote identity --
//! its inbound handler is `handle_plugin_mesh_stream(_remote:
//! iroh::EndpointId, ..)` off the QUIC connection -- but it discards
//! `_remote` and never surfaces it to the plugin. Until the SDK grows a
//! host-filled source-peer field on `OpenStreamRequest`, a
//! `received_from_node_id` cannot be recorded honestly, so it is not
//! recorded at all (never synthesized); the ledger carries only the
//! verified self-declared `received_from`.
//!
//! **Push-a-bundle.** When the sender's
//! checkpoint cadence is on, the JSON body is a bundle instead of the bare
//! capsule: `{"record_push_bundle": 1, "capsule": <the half, unchanged>,
//! "inclusion": {"leaf_index", "proof"}, "checkpoint": <signed checkpoint>}`
//! (~2.5 KB). The receiver verifies all three and its success
//! reply names the verified inclusion; this bridge then seals the
//! `counterparty_half` citing record AND a second, `counterparty_inclusion`
//! citing record -- the row reaches "in their log" in one step. A receiver
//! that predates bundles refuses one `request_malformed` (no top-level
//! `capsule_id`); the sender then re-pushes the bare capsule once. A bundle
//! also carries this node's own controller binding, whole, while it holds
//! one that applies ([`own_binding`]); a receiver that does not take that
//! member refuses `bundle_malformed`, and the bundle goes again without it.
//!
//! **Single `on_open_stream` slot.** The plugin SDK gives a plugin exactly
//! ONE `on_open_stream` handler slot (`SimplePlugin::open_stream_handler:
//! Option<OpenStreamHandler>`, verified against the 0.76.2 crate source) and
//! `OpenStreamRequest` carries no channel name to dispatch on -- `main.rs`'s
//! single registered handler dispatches between this module and
//! `mesh_evidence_bridge` by `content_type`, the one field both sides set to
//! a distinct, stable value for exactly this purpose.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{
    bind_side_stream, LocalListener, LocalStream, PluginContext, PluginError, PluginResult,
};
use tokio::io::AsyncWriteExt;

use crate::producer::checkpoint::{inclusion_proof_json, Coverage};

use crate::capsule_emit::{CapsuleState, InclusionCitation, ReceivedHalfProvenance};

/// The top-level member that marks a push body as a bundle (a capsule never
/// carries it), and the one bundle version this plugin speaks.
pub const BUNDLE_MARKER: &str = "record_push_bundle";
pub const BUNDLE_VERSION: u64 = 1;

/// The push body for `capsule_json` covered by `coverage`: the half itself,
/// unchanged, beside its inclusion proof and the covering checkpoint.
pub fn bundle_body(capsule_json: &serde_json::Value, coverage: &Coverage) -> serde_json::Value {
    serde_json::json!({
        BUNDLE_MARKER: BUNDLE_VERSION,
        "capsule": capsule_json,
        "inclusion": {
            "leaf_index": coverage.leaf_index,
            "proof": inclusion_proof_json(&coverage.proof),
        },
        "checkpoint": coverage.checkpoint,
    })
}

/// The bundle member that carries a split's stage records from the
/// coordinator to the requester (`docs/DESIGN-split-stage-records.md` §6.3).
/// The receiver checks each one and holds it; the requester's hop check then runs
/// offline, without contacting any stage.
pub const SPLIT_STAGE_RECORDS: &str = "split_stage_records";

/// [`bundle_body`] plus the stage records a split's main record cites.
pub fn split_bundle_body(
    capsule_json: &serde_json::Value,
    coverage: &Coverage,
    stage_records: &[serde_json::Value],
) -> serde_json::Value {
    let mut body = bundle_body(capsule_json, coverage);
    body[SPLIT_STAGE_RECORDS] = serde_json::Value::Array(stage_records.to_vec());
    body
}

/// [`split_bundle_body`] (or [`bundle_body`] with no stage records) plus
/// this node's own controller binding, whole, as
/// [`crate::record_push_receive::CONTROLLER_BINDING`] when given.
pub fn carrying_bundle_body(
    capsule_json: &serde_json::Value,
    coverage: &Coverage,
    stage_records: &[serde_json::Value],
    controller_binding: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut body = if stage_records.is_empty() {
        bundle_body(capsule_json, coverage)
    } else {
        split_bundle_body(capsule_json, coverage, stage_records)
    };
    if let Some(binding) = controller_binding {
        body[crate::controller_binding::MEMBER] = binding.clone();
    }
    body
}

/// The pushed half inside a push body: the bundle's `capsule`, or the body
/// itself for a bare push.
fn pushed_half(body: &serde_json::Value) -> &serde_json::Value {
    if body.get(BUNDLE_MARKER).is_some() {
        body.get("capsule").unwrap_or(&serde_json::Value::Null)
    } else {
        body
    }
}

/// The mesh channel this module declares on both ends, distinct from
/// `mesh_evidence_bridge::EVIDENCE_REQUEST_CHANNEL`.
pub const RECORD_PUSH_CHANNEL: &str = "record-push/1";

/// The `content_type` both sides of a record-push stream set -- the ONE
/// signal `main.rs`'s single `on_open_stream` handler dispatches on, since
/// `OpenStreamRequest` carries no channel name (see module doc).
pub const RECORD_PUSH_CONTENT_TYPE: &str = "application/x-admission-policy-record-push+json";

fn requester_idle_timeout_ms() -> u64 {
    env_millis("CAPSULES_MESH_REQUEST_TIMEOUT_MS", 8_000).as_millis() as u64
}

fn env_millis(var: &str, default_ms: u64) -> Duration {
    Duration::from_millis(
        crate::settings::var(var)
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(default_ms),
    )
}

static STREAM_NONCE: AtomicU64 = AtomicU64::new(1);

fn next_stream_id(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        STREAM_NONCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// Splits the wire bytes into `(sender_peer_id, capsule_json_bytes)` on the
/// first `\n` -- see module doc's "wire shape" note. `None` when the bytes
/// carry no newline at all (malformed, never a partial/guessed split).
fn split_wire(wire: &[u8]) -> Option<(&str, &[u8])> {
    let newline_at = wire.iter().position(|&b| b == b'\n')?;
    let sender_peer_id = std::str::from_utf8(&wire[..newline_at]).ok()?;
    Some((sender_peer_id, &wire[newline_at + 1..]))
}

// ---------------------------------------------------------------------
// Responder role: mesh-inbound `record-push/1` stream -> received in-process
// ---------------------------------------------------------------------

/// Registered (via `main.rs`'s dispatching `on_open_stream`) for every
/// inbound stream whose `content_type` is [`RECORD_PUSH_CONTENT_TYPE`].
///
/// REPLY CONTRACT (revised for the ack-before-seal fix): a transport failure
/// just drops the stream, and the receiver's reply -- success or signed
/// refusal -- is sent as it is, with ONE exception this bridge mints: when
/// the half was verified and stored but this node could NOT seal its citing
/// record (see [`SEAL_FAILED_REFUSAL_REASON`]), the peer gets an unsigned
/// `{"reason": ...}` refusal INSTEAD of the success reply. "received" on
/// this wire therefore always implies "cited" -- the success ack is only ever
/// written AFTER the citing record is durably on our chain, so a
/// crash/cancel can no longer leave the held store and our chain divergent
/// behind an ack the peer will never retry.
///
/// `capsules` -- this node's own `CapsuleState` (the SAME single-writer
/// ledger every other local capsule is sealed onto). Once the receiver has
/// verified the pushed half and stored it in the held-artifact store
/// `received-capsules.jsonl`, this responder seals a LOCAL CITING record of
/// the receiving event onto OUR chain -- the foreign body NEVER enters
/// `capsules.jsonl`.
pub async fn handle_open_stream(
    request: OpenStreamRequest,
    _context: &mut PluginContext<'_>,
    capsules: Arc<CapsuleState>,
    splits: Arc<
        crate::split_stage::SplitCollector<crate::lifecycle_channel::OpenAiExchangeEnvelope>,
    >,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);

    // The bridge itself must run off this handler (the host needs the
    // OpenStreamResponse back before it will bridge any bytes to the
    // listener), so ONE task is spawned per stream -- but the citing-record
    // seal is AWAITED INSIDE the bridge BEFORE the success ack is written
    // (see `bridge_inbound_record_push`), never re-detached: a seal failure
    // (or a shutdown that drops this task mid-bridge) can only ever leave
    // the peer WITHOUT an ack -- so it retries -- never with an ack for a
    // half our chain did not cite.
    tokio::spawn(async move {
        if let Err(error) = bridge_inbound_record_push(listener, capsules, splits).await {
            tracing::warn!(%error, "mesh record-push responder bridge failed");
        }
    });

    Ok(Some(response))
}

/// True when a reply is a success (`{"status": "received"}`),
/// false for a signed `Refusal` (carries `reason`). Mirrors
/// `push_capsule_to_peer`'s own `response.get("reason").is_some()` convention.
fn accepted(response: &serde_json::Value) -> bool {
    response.get("reason").is_none()
        && response.get("status").and_then(|s| s.as_str()) == Some("received")
}

/// The `reason` of the ONE reply this bridge mints itself (unsigned -- the
/// receiver signs its own refusals; this one is the bridge's, see
/// `handle_open_stream`'s reply contract): the half was verified and stored
/// but the local citing-record seal failed, so the peer must NOT be told
/// "received" (it would never retry, leaving the held store and our chain
/// divergent). The peer's next push retries the seal; a bare half is stored
/// again, a bundle is answered from what is held, and the citing dedup seals
/// at most one record.
const SEAL_FAILED_REFUSAL_REASON: &str = "citing_record_seal_failed";

fn seal_failed_refusal() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "reason": SEAL_FAILED_REFUSAL_REASON }))
        .expect("static refusal shape is always serializable")
}

/// A verified push that is a payer's settlement terms leg: hand it to the
/// settlement-records state ([`crate::settlement_legs`]), which holds it only
/// for one of this node's own invoices and may seal a waiting payee leg.
/// Best-effort; the ack does not depend on it.
async fn hold_settlement_terms(capsules: &Arc<CapsuleState>, body_bytes: &[u8]) {
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
        return;
    };
    let capsule = pushed_half(&body).clone();
    if capsule.get("settlement").is_none() {
        return;
    }
    let capsules = capsules.clone();
    let _ = tokio::task::spawn_blocking(move || {
        capsules.settlement_legs().on_received(&capsules, &capsule)
    })
    .await;
}

fn is_verdict_delivery(body_bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body_bytes)
        .map(|body| crate::adjudication_records::is_delivery_body(&body))
        .unwrap_or(false)
}

/// `compute_attestation.agent_input_digest` / `agent_output_digest` off a
/// received foreign capsule body -- carried onto the citing record so the
/// pane's digest-first `exchange_key_for` correlator can group it with this
/// node's own half of the same exchange. `None` when the field is absent
/// (never fabricated).
fn foreign_digest<'a>(capsule: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    capsule
        .pointer("/model_attestation/compute_attestation")
        .and_then(|ca| ca.get(field))
        .and_then(|v| v.as_str())
}

async fn bridge_inbound_record_push(
    listener: LocalListener,
    capsules: Arc<CapsuleState>,
    splits: Arc<
        crate::split_stage::SplitCollector<crate::lifecycle_channel::OpenAiExchangeEnvelope>,
    >,
) -> anyhow::Result<()> {
    let local = listener.accept().await?;
    let (mut read_half, mut write_half) = local.into_split();

    // BOUNDED read: the wire bytes are peer-controlled and the SDK's frame
    // cap does not apply to raw side-streams -- see
    // `mesh_evidence_bridge::read_to_end_bounded` (remote-OOM guard).
    let wire = crate::mesh_evidence_bridge::read_to_end_bounded(
        &mut read_half,
        "mesh-inbound record-push wire bytes",
    )
    .await?;
    let (sender_peer_id, capsule_bytes) = split_wire(&wire)
        .ok_or_else(|| anyhow::anyhow!("record-push wire bytes carry no sender-peer-id line"))?;
    let sender_peer_id = sender_peer_id.to_string();
    let capsule_bytes = capsule_bytes.to_vec();

    // A pushed record is received here, in-process (`record_push_receive`).
    // A referee's verdict delivered over the same stream goes through the
    // same door (`crate::referee::hold`); when it is held, this node's
    // `adjudication_received` record is sealed before the courier is told.
    if is_verdict_delivery(&capsule_bytes) {
        let (reply, _) = receive_pushed_record(&capsules, &sender_peer_id, &capsule_bytes).await?;
        let reply_bytes = match reply.get("adjudication") {
            Some(held) if reply.get("status").and_then(|s| s.as_str()) == Some("received") => {
                match seal_received_verdict(&capsules, held) {
                    Ok(()) => {
                        crate::routing_rule::mark_due();
                        serde_json::to_vec(&reply)?
                    }
                    Err(error) => {
                        tracing::warn!(%error, received_from = %sender_peer_id, "a delivered verdict was held but its record did not seal -- refusing instead of acking");
                        seal_failed_refusal()
                    }
                }
            }
            _ => serde_json::to_vec(&reply)?,
        };
        write_half.write_all(&reply_bytes).await?;
        write_half.shutdown().await?;
        return Ok(());
    }
    let (reply, accepted_key) =
        receive_pushed_record(&capsules, &sender_peer_id, &capsule_bytes).await?;
    let response_bytes = serde_json::to_vec(&reply)?;

    // SEAL BEFORE ACK (the ack-before-seal window fix): the receiver is the
    // ONE authority on whether the half verified + stored, and its refusal
    // bytes are forwarded untouched -- but on SUCCESS the citing record is
    // sealed FIRST, and only then is the success reply written, so
    // "received" always implies "cited". A seal failure replies with this
    // bridge's own refusal (`SEAL_FAILED_REFUSAL_REASON`) instead of the
    // success bytes: the peer sees a refusal and retries, instead of
    // trusting an ack for a half our chain never cited. Awaited inline (no
    // detached task), so a failure is handled before any reply exists.
    let reply_bytes = if accepted(&reply) {
        match seal_citing_records_for_push(
            &capsules,
            &sender_peer_id,
            &capsule_bytes,
            &reply,
            accepted_key.as_ref(),
        )
        .await
        {
            Ok(()) => {
                collect_stage_record(&splits, &sender_peer_id, &capsule_bytes);
                hold_settlement_terms(&capsules, &capsule_bytes).await;
                response_bytes
            }
            Err(error) => {
                tracing::warn!(%error, received_from = %sender_peer_id, "the pushed half was stored but a citing-record seal failed -- refusing instead of acking");
                seal_failed_refusal()
            }
        }
    } else {
        // A signed refusal: sent as it is; a refusal never chains anything.
        response_bytes
    };
    write_half.write_all(&reply_bytes).await?;
    write_half.shutdown().await?;
    Ok(())
}

/// Seal this node's `adjudication_received` record of a verdict its door
/// held (`held`: the reply's `adjudication` facts). Keyed on the verdict id,
/// so a repeat delivery seals nothing more.
pub(crate) fn seal_received_verdict(
    capsules: &CapsuleState,
    held: &serde_json::Value,
) -> anyhow::Result<()> {
    let text = |key: &str| held.get(key).and_then(|v| v.as_str());
    let pair = |key: &str| -> Option<[&str; 2]> {
        match held.get(key)?.as_array()?.as_slice() {
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
        anyhow::bail!("the held verdict's facts are incomplete");
    };
    let model_hash = crate::referee::hold::held_model_hash(capsules.ledger_dir(), id);
    let facts = crate::capsule_emit::VerdictFacts {
        verdict,
        verdict_capsule_id: id,
        referee_node_id: referee,
        halves,
        half_node_ids: nodes,
        twin_bracket_id: text("twin_bracket_id"),
        model_hash: model_hash.as_deref(),
    };
    capsules.emit_adjudication_received(
        &facts,
        text("held_half_capsule_id").unwrap_or(halves[0]),
        text("received_from").unwrap_or_default(),
        text("received_at").unwrap_or_default(),
    )?;
    Ok(())
}

/// Receive a pushed record in-process: `record_push_receive::receive` against
/// this node's ledger directory and key, the peer-key registry and sharing
/// policy as this process has them. Runs on the blocking pool: every stored
/// line is synced to disk before the reply exists. An `Err` is a local write
/// that failed; the caller then acks nothing, and the peer retries.
async fn receive_pushed_record(
    capsules: &Arc<CapsuleState>,
    sender_peer_id: &str,
    body: &[u8],
) -> anyhow::Result<Received> {
    receive_record_via(capsules, sender_peer_id, body, "push").await
}

/// The receiver's reply, and how the half's key was accepted when it was.
type Received = (serde_json::Value, Option<crate::peer_keys::Accepted>);

/// [`receive_pushed_record`] for a record that came by `via`.
async fn receive_record_via(
    capsules: &Arc<CapsuleState>,
    sender_peer_id: &str,
    body: &[u8],
    via: &'static str,
) -> anyhow::Result<Received> {
    let capsules = capsules.clone();
    let sender_peer_id = sender_peer_id.to_string();
    let body = body.to_vec();
    // One read of each source: the receiver merges them, so a host answer
    // landing between two reads cannot pose as an operator entry.
    let peer_keys = crate::settings::var(crate::peer_keys::ENV_PEER_KEYS).ok();
    let announced = crate::peer_keys::announced::snapshot();
    // `share_record_at_completion` governs records pushed at completion; a
    // record this node asked for is held because its operator asked.
    let record_at_completion_off =
        via != "ask" && crate::share_policy::record_at_completion_is_off();
    tokio::task::spawn_blocking(move || {
        let receiver = crate::record_push_receive::Receiver {
            ledger_dir: capsules.ledger_dir(),
            signing_key: capsules.signing_key(),
            peer_keys: peer_keys.as_deref(),
            announced: &announced,
            record_at_completion_off,
            rejected_log_limit: crate::record_push_receive::MAX_REJECTED_LOG_BYTES,
        };
        crate::record_push_receive::receive_via(
            &receiver,
            &body,
            Some(&sender_peer_id),
            &crate::producer::timestamp::utc_now_iso8601(),
            via,
        )
    })
    .await
    .map_err(|join_error| {
        anyhow::anyhow!("record-push receive task did not complete: {join_error}")
    })?
    .map_err(|io_error| {
        anyhow::anyhow!("record-push receive could not store what it verified: {io_error}")
    })
}

/// A received stage record of a split this node coordinates goes to the
/// collector as well: its stage-exchange record will cite it. Its ordinary
/// citing record is already on the chain (seal-before-ack), and is the
/// follow-up when the split was sealed before it arrived.
fn collect_stage_record(
    splits: &crate::split_stage::SplitCollector<crate::lifecycle_channel::OpenAiExchangeEnvelope>,
    sender_peer_id: &str,
    body_bytes: &[u8],
) {
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
        return;
    };
    match splits.on_stage_record(
        pushed_half(&body),
        sender_peer_id,
        crate::split_stage::now_ms(),
    ) {
        crate::split_stage::Arrival::Late => {
            tracing::info!("stage record arrived after its split was sealed -- its citing record is the follow-up")
        }
        crate::split_stage::Arrival::Refused => tracing::warn!(
            received_from = %sender_peer_id,
            refused = splits.refused(),
            "stage record refused: not from the node assigned that stage, or past a holding cap"
        ),
        _ => {}
    }
}

/// On success: the half's `counterparty_half` citing record, then -- for a
/// verified bundle -- the `counterparty_inclusion` one. Both
/// must be on our chain before the ack is written (seal-before-ack); a
/// retried push re-runs both, and each dedups on its own.
async fn seal_citing_records_for_push(
    capsules: &Arc<CapsuleState>,
    sender_peer_id: &str,
    body_bytes: &[u8],
    reply: &serde_json::Value,
    accepted_key: Option<&crate::peer_keys::Accepted>,
) -> anyhow::Result<()> {
    let body: serde_json::Value = serde_json::from_slice(body_bytes)
        .map_err(|e| anyhow::anyhow!("an unparseable body was received: {e}"))?;
    let half = pushed_half(&body);
    let half_bytes = serde_json::to_vec(half)?;
    seal_citing_record(capsules, sender_peer_id, &half_bytes, "push", accepted_key).await?;
    if let Some(inclusion) = received_inclusion(reply)? {
        let half_id = half
            .get("capsule_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("pushed half carries no capsule_id"))?;
        seal_inclusion_citing_record_for_push(capsules, sender_peer_id, half_id, inclusion).await?;
    }
    Ok(())
}

/// On success, seal OUR OWN citing record of the receiving event onto OUR
/// chain. The receiver already verified the signature (it returns success
/// only when it did) and stored the foreign body in the held-artifact store
/// -- so `signature_ok = true` here is its recorded verdict, read, never a
/// second check. This
/// never touches the foreign body except to lift its own digests (for the
/// pane's correlator); the bytes stay in `received-capsules.jsonl`.
///
/// Runs the seal on `spawn_blocking`: `emit_citing_record` holds the std
/// ledger mutex across two `sync_all()`s, which must not stall a tokio
/// worker thread. A duplicate push (already-cited half, `Ok(None)`) is
/// SUCCESS -- the half is received/held; there is just nothing new to cite.
async fn seal_citing_record(
    capsules: &Arc<CapsuleState>,
    sender_peer_id: &str,
    capsule_bytes: &[u8],
    via: &'static str,
    accepted_key: Option<&crate::peer_keys::Accepted>,
) -> anyhow::Result<()> {
    let foreign: serde_json::Value = serde_json::from_slice(capsule_bytes)
        // A received body that does not parse? The receiver refuses
        // request_malformed first, so it never happens -- but if that ever
        // changed, we must not ack a half we cannot cite.
        .map_err(|e| anyhow::anyhow!("an unparseable body was received: {e}"))?;
    let Some(foreign_capsule_id) = foreign.get("capsule_id").and_then(|v| v.as_str()) else {
        anyhow::bail!("a body with no capsule_id was received -- nothing citable");
    };
    let foreign_capsule_id = foreign_capsule_id.to_string();
    let received_from = sender_peer_id.to_string();
    let received_at = crate::producer::timestamp::utc_now_minute();
    let foreign_input = foreign_digest(&foreign, "agent_input_digest").map(str::to_string);
    let foreign_output = foreign_digest(&foreign, "agent_output_digest").map(str::to_string);
    let sender_key_id = accepted_key
        .and_then(|_| foreign.get("key_id"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let accepted_via = accepted_key.map(|a| a.via.clone());
    let controller_binding = accepted_key.and_then(|a| a.binding.clone());
    let tied = own_half_tie(capsules, &foreign, sender_peer_id, via).await;
    let capsules = capsules.clone();

    let sealed = tokio::task::spawn_blocking(move || {
        let prov = ReceivedHalfProvenance {
            foreign_capsule_id: &foreign_capsule_id,
            received_from: &received_from,
            via,
            received_at: &received_at,
            signature_ok: true,
            // digest_match is the pane's authoritative structural grade
            // (mine vs theirs); at live receive this node has not paired it
            // against a local half here, so it is an honest absent rather
            // than a fabricated "verified". The pane recomputes it from the
            // citing record's digests + our own half.
            digest_match: None,
            foreign_agent_input_digest: foreign_input.as_deref(),
            foreign_agent_output_digest: foreign_output.as_deref(),
            sender_key_id: sender_key_id.as_deref(),
            accepted_via: accepted_via.as_ref(),
            controller_binding: controller_binding.as_ref(),
            same_controller_as_receiver: same_controller_as_receiver(
                &capsules,
                controller_binding.as_ref(),
                sender_key_id.as_deref(),
                &crate::producer::timestamp::utc_now_iso8601(),
            ),
            own_half_capsule_id: tied.as_deref(),
        };
        capsules
            .emit_citing_record_checked(&prov, |own| {
                own_half(&capsules, &foreign, &received_from) == OwnHalf::Tied(own.to_string())
            })
            .map(|emitted| (foreign_capsule_id, received_from, emitted))
    })
    .await
    .map_err(|join_error| {
        anyhow::anyhow!("citing-record seal task did not complete: {join_error}")
    })??;

    let (foreign_capsule_id, received_from, emitted) = sealed;
    match emitted {
        Some(_) => {
            tracing::info!(%foreign_capsule_id, %received_from, "SEALED citing record for received counterparty half");
        }
        None => {
            tracing::info!(%foreign_capsule_id, %received_from, "duplicate push of an already-cited half -- received/held, nothing new sealed");
        }
    }
    Ok(())
}

/// This node's own controller binding, whole, when it holds one that binds
/// its key and applies now (`controller_binding::held_applying`): what a
/// push bundle carries to the exchange's counterparty.
pub fn own_binding(capsules: &CapsuleState) -> Option<serde_json::Value> {
    let own_key = hex::encode(capsules.signing_key().verifying_key().to_bytes());
    let now = crate::producer::timestamp::utc_now_iso8601();
    crate::controller_binding::held_applying(
        capsules.ledger_dir().parent()?,
        &own_key,
        evidence_request::time::parse_utc(&now)?,
    )
    .map(|(record, _)| record)
}

/// [`crate::controller_binding::same_controller`] for a carried binding of
/// `sender_key`, against this node's own binding at `now`.
pub(crate) fn same_controller_as_receiver(
    capsules: &CapsuleState,
    carried: Option<&crate::controller_binding::Applied>,
    sender_key: Option<&str>,
    now: &str,
) -> Option<bool> {
    let own_key = hex::encode(capsules.signing_key().verifying_key().to_bytes());
    crate::controller_binding::same_controller(
        carried?,
        sender_key?,
        capsules.ledger_dir().parent()?,
        &own_key,
        evidence_request::time::parse_utc(now)?,
    )
}

/// How long a pushed half waits for this node's own half of the same
/// exchange to seal. Each side pushes within moments of sealing, so the
/// other side's half can arrive first; the citing record is sealed before
/// the ack, so the wait stays well inside the pusher's reply timeout
/// (`CAPSULES_MESH_REQUEST_TIMEOUT_MS`, 8 s by default).
const OWN_HALF_WAIT: Duration = Duration::from_secs(2);
const OWN_HALF_POLL: Duration = Duration::from_millis(50);

/// Whether this node's own half of `foreign`'s exchange can be named.
#[derive(Debug, PartialEq, Eq)]
enum OwnHalf {
    /// Exactly one own half with the sender binds the nonce, and no other
    /// held half does.
    Tied(String),
    /// No own half binds it yet.
    NotYet,
    /// No usable nonce, more than one own half with the sender or another
    /// held half binds it (a client-set nonce can repeat, and a wrong pair is
    /// worse than none), or the half is already cited.
    Untied,
}

/// This node's own half of `foreign`'s exchange with `sender`, for the
/// citing record's `own_half_capsule_id`. A pushed half waits up to
/// [`OWN_HALF_WAIT`] for the own half to seal; an asked one never waits (its
/// exchange is over).
async fn own_half_tie(
    capsules: &Arc<CapsuleState>,
    foreign: &serde_json::Value,
    sender: &str,
    via: &str,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + OWN_HALF_WAIT;
    loop {
        let (capsules, foreign, sender) = (capsules.clone(), foreign.clone(), sender.to_string());
        let look = tokio::task::spawn_blocking(move || own_half(&capsules, &foreign, &sender));
        // The deadline bounds the look too: a tie found after it is not taken.
        match tokio::time::timeout_at(deadline, look).await {
            Ok(Ok(OwnHalf::Tied(id))) => return Some(id),
            Ok(Ok(OwnHalf::NotYet))
                if via == "push" && tokio::time::Instant::now() + OWN_HALF_POLL < deadline =>
            {
                tokio::time::sleep(OWN_HALF_POLL).await;
            }
            _ => return None,
        }
    }
}

/// One look for `foreign`'s own half: the own records binding its client
/// nonce (`evidence_log`'s nonce index, which only exchange halves enter)
/// whose counterparty is `sender` -- a push or an ask comes from the node the
/// own half names (`main.rs`'s `push_counterparty`), so an own half of an
/// earlier exchange with another peer under a reused nonce is never taken --
/// then, once exactly one is, the other held halves binding the nonce.
fn own_half(capsules: &CapsuleState, foreign: &serde_json::Value, sender: &str) -> OwnHalf {
    let (Some(nonce), Some(foreign_id)) = (
        crate::evidence_log::client_nonce_digest(foreign),
        foreign.get("capsule_id").and_then(|v| v.as_str()),
    ) else {
        return OwnHalf::Untied;
    };
    let own = crate::evidence_log::with_index(
        capsules.ledger_dir(),
        &crate::commitment::key_id(capsules.signing_key()),
        |index| {
            // Already cited: nothing will be sealed, so there is nothing to
            // wait for.
            if !index.citing(foreign_id).is_empty() {
                return None;
            }
            Some(
                index
                    .by_client_nonce(&nonce)
                    .iter()
                    .filter_map(|&leaf| index.leaves.get(usize::try_from(leaf).ok()?))
                    .filter(|leaf| leaf.counterparty.as_deref() == Some(sender))
                    .map(|leaf| leaf.capsule_id.clone())
                    .collect::<Vec<_>>(),
            )
        },
    );
    match own.as_ref().map(|own| own.as_deref()) {
        Ok(Some([])) => OwnHalf::NotYet,
        Ok(Some([one])) if !held_half_shares_nonce(capsules.ledger_dir(), &nonce, foreign_id) => {
            OwnHalf::Tied(one.clone())
        }
        _ => OwnHalf::Untied,
    }
}

/// Whether a held half other than `foreign_id` binds the client nonce whose
/// digest is `nonce`. A torn or garbled line is skipped, as the receiver
/// skips one; a store that cannot be read at all counts as shared, since the
/// check could not be made.
fn held_half_shares_nonce(ledger_dir: &std::path::Path, nonce: &str, foreign_id: &str) -> bool {
    let bytes = match std::fs::read(
        ledger_dir.join(crate::record_push_receive::RECEIVED_CAPSULES_FILENAME),
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    bytes
        .split(|&b| b == b'\n')
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .any(|held| {
            held.get("capsule_id").and_then(|v| v.as_str()) != Some(foreign_id)
                && crate::evidence_log::client_nonce_digest(&held).as_deref() == Some(nonce)
        })
}

/// Hold a record this node asked `peer_id` for (`mesh_evidence_request`)
/// the way a pushed one is held: the same receiver checks it under the
/// peer's announced key and stores it, then this node seals its citing
/// record, both marked `via: "ask"`. So an asked record that matches ours
/// counts as saved, like a pushed one. `Ok(false)` when the receiver refused
/// it (its signed refusal is not kept: nothing was sent to the peer).
pub(crate) async fn hold_asked_record(
    capsules: &Arc<CapsuleState>,
    peer_id: &str,
    record_bytes: &[u8],
) -> anyhow::Result<bool> {
    let (reply, accepted_key) = receive_record_via(capsules, peer_id, record_bytes, "ask").await?;
    if !accepted(&reply) {
        return Ok(false);
    }
    seal_citing_record(
        capsules,
        peer_id,
        record_bytes,
        "ask",
        accepted_key.as_ref(),
    )
    .await?;
    Ok(true)
}

/// The verified inclusion facts for a bundle push, lifted from the
/// receiver's success reply (its `inclusion` member). `Ok(None)` when the
/// reply has no `inclusion` (a bare push); an `inclusion` member that is
/// present but incomplete or mistyped is an ERROR, never a silent downgrade
/// to "half only" -- the caller then refuses to ack, and the push is retried.
/// The receiver is the one authority on whether the proof and checkpoint
/// verified -- this reads its verdict, same as `signature_ok`.
#[derive(Debug, PartialEq, Eq)]
struct ReceivedInclusion {
    half_capsule_id: String,
    leaf_index: u64,
    mmr_size: u64,
    checkpoint_digest: String,
    inclusion_proof_digest: String,
    received_at: String,
}

fn received_inclusion(reply: &serde_json::Value) -> anyhow::Result<Option<ReceivedInclusion>> {
    let Some(inclusion) = reply.get("inclusion") else {
        return Ok(None);
    };
    let text = |k: &str| {
        inclusion
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("reply inclusion.{k} missing or not a string"))
    };
    let num = |k: &str| {
        inclusion
            .get(k)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("reply inclusion.{k} missing or not a count"))
    };
    Ok(Some(ReceivedInclusion {
        half_capsule_id: text("half_capsule_id")?,
        leaf_index: num("leaf_index")?,
        mmr_size: num("mmr_size")?,
        checkpoint_digest: text("checkpoint_digest")?,
        inclusion_proof_digest: text("inclusion_proof_digest")?,
        received_at: text("received_at")?,
    }))
}

/// After the half's own citing record: seal the `counterparty_inclusion`
/// citing record for the bundle's verified proof + checkpoint. A reply
/// whose inclusion names a different half than the one pushed is refused
/// (never cited) -- the two records must be about the same half.
async fn seal_inclusion_citing_record_for_push(
    capsules: &Arc<CapsuleState>,
    sender_peer_id: &str,
    pushed_capsule_id: &str,
    inclusion: ReceivedInclusion,
) -> anyhow::Result<()> {
    if inclusion.half_capsule_id != pushed_capsule_id {
        anyhow::bail!(
            "the reply's inclusion names half {} but the pushed half is {pushed_capsule_id}",
            inclusion.half_capsule_id
        );
    }
    let capsules = capsules.clone();
    let received_from = sender_peer_id.to_string();
    let emitted = tokio::task::spawn_blocking(move || {
        capsules.emit_inclusion_citing_record(&InclusionCitation {
            half_capsule_id: &inclusion.half_capsule_id,
            received_from: &received_from,
            via: "push",
            received_at: &inclusion.received_at,
            leaf_index: inclusion.leaf_index,
            mmr_size: inclusion.mmr_size,
            checkpoint_digest: &inclusion.checkpoint_digest,
            inclusion_proof_digest: &inclusion.inclusion_proof_digest,
        })
    })
    .await
    .map_err(|join_error| {
        anyhow::anyhow!("inclusion citing-record seal task did not complete: {join_error}")
    })??;
    match emitted {
        Some(_) => {
            tracing::info!(half = %pushed_capsule_id, %sender_peer_id, "SEALED counterparty_inclusion citing record")
        }
        None => {
            tracing::info!(half = %pushed_capsule_id, %sender_peer_id, "inclusion for this half already cited -- nothing new sealed")
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Requester role: push this node's own sealed capsule to a peer
// ---------------------------------------------------------------------

/// Opens a `record-push/1` mesh stream to `peer_id` and pushes
/// `capsule_json` (this node's own just-sealed capsule, unmodified -- a
/// receiver holds it as transmitted, never re-signed), self-
/// declaring `self_peer_id` as the sender (see module doc's "wire shape").
/// With `coverage` the body is the bundle (module doc, "push-a-bundle"),
/// carrying `split_stage_records` and `controller_binding` when given; a
/// `request_malformed` refusal of a bundle is read as a receiver that
/// predates bundles, and the bare capsule is pushed once more.
/// Best-effort by design -- the caller (`main.rs`'s seal-on-observe path)
/// logs success/failure and never lets a push failure disturb sealing or
/// channel-message processing, same discipline as
/// `seal_observed_host_exchange`'s own producer-error handling.
///
/// `controller_binding` is this node's own binding, whole
/// (`controller_binding::held_applying`). It names the operator's Nostr key,
/// so it goes only to `peer_id`, the exchange's counterparty, and only in a
/// bundle: Steven's loop step 12 ruling has counterparties verify the full
/// record while the public commitment names it by digest alone
/// (Mesh-LLM/capsules-plugin#113).
///
/// Returns the receiver's acceptance: for a bundle it held, the inclusion it
/// verified (`record_push_receive`'s reply).
pub async fn push_capsule_to_peer(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    self_peer_id: &str,
    capsule_json: &serde_json::Value,
    coverage: Option<&Coverage>,
    split_stage_records: &[serde_json::Value],
    controller_binding: Option<&serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let response = match coverage {
        Some(coverage) => {
            push_bundle(
                context,
                peer_id,
                self_peer_id,
                capsule_json,
                coverage,
                split_stage_records,
                controller_binding,
            )
            .await?
        }
        None if !split_stage_records.is_empty() => {
            tracing::warn!(%peer_id, "no checkpoint coverage, so the split's stage records cannot be carried -- pushing the bare record");
            send_push(context, peer_id, self_peer_id, capsule_json).await?
        }
        None => send_push(context, peer_id, self_peer_id, capsule_json).await?,
    };
    if response.get("reason").is_some() {
        anyhow::bail!("peer {peer_id} refused record-push: {response}");
    }
    Ok(response)
}

/// The bundle with what it carries beside the half. A receiver that reads
/// bundles but not one of those members refuses `bundle_malformed`: the
/// half still goes, first without the controller binding (the newer
/// member), then without the split's stage records, which the requester
/// then reads as not received. Stage records are as old as the receiver,
/// so one that takes the binding refuses stages only when they are
/// malformed; the half then goes without either, and its citing record
/// reads as holding no binding rather than a wrong one. A receiver that
/// predates bundles refuses `request_malformed` and gets the bare record.
async fn push_bundle(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    self_peer_id: &str,
    capsule_json: &serde_json::Value,
    coverage: &Coverage,
    mut split_stage_records: &[serde_json::Value],
    mut controller_binding: Option<&serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    while controller_binding.is_some() || !split_stage_records.is_empty() {
        let bundle = carrying_bundle_body(
            capsule_json,
            coverage,
            split_stage_records,
            controller_binding,
        );
        let response = send_push(context, peer_id, self_peer_id, &bundle).await?;
        match retry_after(&response, controller_binding.is_some()) {
            Retry::Final => return Ok(response),
            Retry::Bare => {
                tracing::info!(%peer_id, "peer's receiver predates bundles -- re-pushing the bare record");
                return send_push(context, peer_id, self_peer_id, capsule_json).await;
            }
            Retry::WithoutBinding => {
                tracing::info!(%peer_id, "peer does not take a controller binding -- re-pushing the bundle without it");
                controller_binding = None;
            }
            Retry::WithoutSplits => {
                tracing::info!(%peer_id, "peer does not take split stage records -- re-pushing the plain bundle");
                split_stage_records = &[];
            }
        }
    }
    push_plain_bundle(context, peer_id, self_peer_id, capsule_json, coverage).await
}

/// What [`push_bundle`] sends after a carrying bundle's reply.
#[derive(Debug, PartialEq)]
enum Retry {
    /// The reply stands, accepted or refused.
    Final,
    /// The receiver predates bundles ([`refused_as_older_door`]).
    Bare,
    /// The receiver reads bundles but not a member: the newer one goes first.
    WithoutBinding,
    WithoutSplits,
}

fn retry_after(response: &serde_json::Value, carries_binding: bool) -> Retry {
    if refused_as_older_door(response) {
        Retry::Bare
    } else if !refused_as_bundle_malformed(response) {
        Retry::Final
    } else if carries_binding {
        Retry::WithoutBinding
    } else {
        Retry::WithoutSplits
    }
}

fn refused_as_bundle_malformed(response: &serde_json::Value) -> bool {
    response.get("reason").and_then(|r| r.as_str()) == Some("bundle_malformed")
}

/// Push the half as a bundle; a receiver that predates bundles gets the bare
/// record once more.
async fn push_plain_bundle(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    self_peer_id: &str,
    capsule_json: &serde_json::Value,
    coverage: &Coverage,
) -> anyhow::Result<serde_json::Value> {
    let bundle = bundle_body(capsule_json, coverage);
    let response = send_push(context, peer_id, self_peer_id, &bundle).await?;
    if refused_as_older_door(&response) {
        tracing::info!(%peer_id, "peer's receiver predates bundles -- re-pushing the bare record");
        return send_push(context, peer_id, self_peer_id, capsule_json).await;
    }
    Ok(response)
}

/// A bundle refused `request_malformed` came from a receiver that reads the
/// body as a bare capsule and found no `capsule_id` at its top level. A
/// receiver that reads bundles refuses a malformed one `bundle_malformed`
/// instead ([`crate::record_push_receive`]), so that reason -- like every
/// other refusal -- is final, never a trigger to re-push the bare record.
fn refused_as_older_door(response: &serde_json::Value) -> bool {
    response.get("reason").and_then(|r| r.as_str()) == Some("request_malformed")
}

/// One `record-push/1` stream: write `sender\n<body>`, read the peer's reply.
pub(crate) async fn send_push(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    self_peer_id: &str,
    body: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let open_request = OpenMeshStreamRequest {
        stream_id: next_stream_id("record-push"),
        target_peer_id: peer_id.to_string(),
        plugin_id: String::new(), // host fills this in from the connection.
        channel: RECORD_PUSH_CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some(RECORD_PUSH_CONTENT_TYPE.to_string()),
        correlation_id: Some(next_stream_id("record-push-correlation")),
        metadata_json: None,
        expected_bytes: None,
        idle_timeout_ms: Some(requester_idle_timeout_ms()),
    };

    let stream: LocalStream = context
        .connect_mesh_stream(open_request)
        .await
        .map_err(|error| anyhow::anyhow!("could not reach peer {peer_id}: {error}"))?;
    let (mut read_half, mut write_half) = stream.into_split();

    let mut wire = Vec::with_capacity(self_peer_id.len() + 1);
    wire.extend_from_slice(self_peer_id.as_bytes());
    wire.push(b'\n');
    serde_json::to_writer(&mut wire, body)?;

    let write_and_read = async {
        write_half.write_all(&wire).await?;
        write_half.shutdown().await?;
        // Bounded: the peer's ack/refusal is peer-controlled bytes too.
        crate::mesh_evidence_bridge::read_to_end_bounded(
            &mut read_half,
            "peer record-push response",
        )
        .await
    };

    let response_bytes = tokio::time::timeout(
        Duration::from_millis(requester_idle_timeout_ms()),
        write_and_read,
    )
    .await
    .map_err(|_| anyhow::anyhow!("peer {peer_id} did not acknowledge record-push"))?
    .map_err(|error| anyhow::anyhow!("peer {peer_id} did not acknowledge record-push: {error}"))?;

    serde_json::from_slice(&response_bytes).map_err(|error| {
        anyhow::anyhow!("peer {peer_id} returned malformed record-push response: {error}")
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn split_wire_separates_sender_id_from_capsule_bytes() {
        let wire = b"peer-abc\n{\"capsule_id\":\"x\"}";
        let (sender, body) = split_wire(wire).expect("wire has a newline");
        assert_eq!(sender, "peer-abc");
        assert_eq!(body, b"{\"capsule_id\":\"x\"}");
    }

    #[test]
    fn split_wire_rejects_bytes_with_no_newline() {
        assert!(split_wire(b"no-newline-here").is_none());
    }

    #[test]
    fn split_wire_allows_an_empty_capsule_body() {
        let (sender, body) = split_wire(b"peer-abc\n").expect("wire has a newline");
        assert_eq!(sender, "peer-abc");
        assert!(body.is_empty());
    }

    fn sample_coverage() -> Coverage {
        use crate::producer::anchor::AnchorClient;
        use crate::producer::checkpoint::{CheckpointCadenceConfig, CheckpointState};
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("bundle-body-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let id = "a".repeat(64);
        let mut f = std::fs::File::create(dir.join("capsules.jsonl")).unwrap();
        writeln!(f, "{}", serde_json::json!({"capsule_id": id})).unwrap();
        let (mut state, _) =
            CheckpointState::load(&dir, "log", CheckpointCadenceConfig::default()).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let coverage = state
            .checkpoint_covering(&id, &key, &AnchorClient::new("http://127.0.0.1:1"))
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        coverage
    }

    /// The node's own binding rides whole in the binding member, beside
    /// split stage records or without them, and only when given.
    #[test]
    fn a_bundle_carries_the_held_binding_whole_only_when_given() {
        let coverage = sample_coverage();
        let half =
            serde_json::json!({"capsule_id": "a".repeat(64), "signature": "s", "key_id": "k"});
        let binding = serde_json::json!({"binding_version": "controller-binding/0"});
        let member = crate::record_push_receive::CONTROLLER_BINDING;
        assert_eq!(
            carrying_bundle_body(&half, &coverage, &[], None),
            bundle_body(&half, &coverage)
        );
        let carried = carrying_bundle_body(&half, &coverage, &[], Some(&binding));
        assert_eq!(carried[member], binding);
        assert_eq!(carried.as_object().unwrap().len(), 5);
        let stages = [serde_json::json!({"stage": 1})];
        let both = carrying_bundle_body(&half, &coverage, &stages, Some(&binding));
        assert_eq!(both[member], binding);
        assert_eq!(both[SPLIT_STAGE_RECORDS], serde_json::json!(stages));
        assert_eq!(pushed_half(&both), &half);
    }

    /// What a push carries is the node's own binding while it applies,
    /// never another node's.
    #[test]
    fn own_binding_is_the_held_binding_of_this_nodes_key_while_it_applies() {
        let dir = tempfile::tempdir().unwrap();
        let capsules = CapsuleState::open(dir.path(), "rust-node").unwrap();
        assert_eq!(own_binding(&capsules), None);
        let operator = k256::schnorr::SigningKey::from_bytes(&[7; 32]).unwrap();
        let now = crate::producer::timestamp::utc_now_iso8601();
        let at = evidence_request::time::parse_utc(&now).unwrap();
        let until = chrono::Utc::now() + chrono::Duration::days(1);
        let binding = crate::controller_binding::bind_to_nostr_for_test(
            capsules.signing_key(),
            &operator,
            "0123456789abcdef0123456789abcdef",
            "2026-01-01T00:00:00Z",
            &until.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );
        let own = hex::encode(capsules.signing_key().verifying_key().to_bytes());
        crate::controller_binding::store_held(dir.path(), &binding, &own, at).unwrap();
        assert_eq!(own_binding(&capsules), Some(binding));
    }

    #[test]
    fn bundle_body_carries_the_half_unchanged_beside_proof_and_checkpoint() {
        let coverage = sample_coverage();
        let half =
            serde_json::json!({"capsule_id": "a".repeat(64), "signature": "s", "key_id": "k"});
        let body = bundle_body(&half, &coverage);
        assert_eq!(body[BUNDLE_MARKER], serde_json::json!(1));
        assert_eq!(body["capsule"], half, "the half is carried as transmitted");
        assert_eq!(body["inclusion"]["leaf_index"], serde_json::json!(0));
        assert_eq!(
            body["inclusion"]["proof"]["kind"],
            serde_json::json!("inclusion")
        );
        assert_eq!(
            body["inclusion"]["proof"]["size"],
            serde_json::json!(coverage.checkpoint.mmr_size)
        );
        assert_eq!(
            body["checkpoint"]["root"],
            serde_json::json!(coverage.checkpoint.root)
        );
        assert!(
            body.get("capsule_id").is_none(),
            "an older receiver must see no top-level capsule_id"
        );
        assert_eq!(pushed_half(&body), &half);
        assert_eq!(pushed_half(&half), &half);
    }

    /// A carrying bundle's reply decides the next push: a receiver that
    /// predates bundles gets the bare record, as a plain bundle's would
    /// (Mesh-LLM/capsules-plugin#113 carries the binding on every push).
    #[test]
    fn a_carrying_bundle_falls_back_by_its_reply() {
        let reply = |reason: &str| serde_json::json!({"reason": reason});
        let received = serde_json::json!({"status": "received"});
        for carries_binding in [true, false] {
            assert_eq!(
                retry_after(&reply("request_malformed"), carries_binding),
                Retry::Bare
            );
            assert_eq!(retry_after(&received, carries_binding), Retry::Final);
            assert_eq!(
                retry_after(&reply("signature_unverified"), carries_binding),
                Retry::Final
            );
        }
        assert_eq!(
            retry_after(&reply("bundle_malformed"), true),
            Retry::WithoutBinding
        );
        assert_eq!(
            retry_after(&reply("bundle_malformed"), false),
            Retry::WithoutSplits
        );
    }

    #[test]
    fn only_request_malformed_reads_as_an_older_door() {
        assert!(refused_as_older_door(
            &serde_json::json!({"reason": "request_malformed"})
        ));
        assert!(!refused_as_older_door(
            &serde_json::json!({"reason": "inclusion_unverified"})
        ));
        assert!(!refused_as_older_door(
            &serde_json::json!({"reason": "bundle_malformed"})
        ));
        assert!(!refused_as_older_door(
            &serde_json::json!({"reason": "checkpoint_stale"})
        ));
        assert!(!refused_as_older_door(
            &serde_json::json!({"reason": "checkpoint_equivocation"})
        ));
        assert!(!refused_as_older_door(
            &serde_json::json!({"reason": "signature_unverified"})
        ));
        assert!(!refused_as_older_door(
            &serde_json::json!({"status": "received"})
        ));
    }

    #[test]
    fn received_inclusion_is_read_only_when_every_fact_is_present() {
        let reply = serde_json::json!({
            "status": "received",
            "inclusion": {
                "half_capsule_id": "h", "leaf_index": 4, "mmr_size": 8,
                "checkpoint_digest": "c", "inclusion_proof_digest": "p",
                "received_at": "2026-09-27T00:00:00Z"
            }
        });
        let inclusion = received_inclusion(&reply)
            .unwrap()
            .expect("complete inclusion facts");
        assert_eq!(inclusion.leaf_index, 4);
        assert_eq!(inclusion.mmr_size, 8);
        assert!(
            received_inclusion(&serde_json::json!({"status": "received"}))
                .unwrap()
                .is_none()
        );
        // N1 (EM review): a present-but-broken inclusion is an error (no ack,
        // the sender retries), never a silent "half only".
        let mut partial = reply.clone();
        partial["inclusion"]
            .as_object_mut()
            .unwrap()
            .remove("checkpoint_digest");
        assert!(
            received_inclusion(&partial).is_err(),
            "a partial verdict is an error"
        );
        let mut mistyped = reply.clone();
        mistyped["inclusion"]["leaf_index"] = serde_json::json!("4");
        assert!(received_inclusion(&mistyped).is_err());
        let mut not_an_object = reply;
        not_an_object["inclusion"] = serde_json::json!("verified");
        assert!(received_inclusion(&not_an_object).is_err());
    }

    /// A record this node asked a peer for is held like a pushed one: stored
    /// with `via: "ask"` provenance and cited on this node's own chain, so the
    /// panes count it as saved. A record from a peer whose key this node does
    /// not know is not held.
    #[tokio::test]
    async fn an_asked_record_is_held_and_cited_like_a_pushed_one() {
        let theirs_dir = tempfile::tempdir().unwrap();
        let mine_dir = tempfile::tempdir().unwrap();
        let theirs = CapsuleState::open(theirs_dir.path(), "their-node").unwrap();
        let mine = Arc::new(CapsuleState::open(mine_dir.path(), "my-node").unwrap());
        let exchange = crate::capsule_emit::ExchangeRecord {
            model: "m",
            client_nonce: Some("asked-nonce"),
            request_bytes: br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
            response_bytes:
                br#"{"id":"x","choices":[{"message":{"role":"assistant","content":"y"}}]}"#,
            latency_ms: 1.0,
            exchange_id: Some("e-ask"),
            requesting_party: Some("my-node"),
            host_provenance: None,
        };
        let record = theirs.emit_for_exchange(&exchange).unwrap().capsule;
        let record_bytes = serde_json::to_vec(&record).unwrap();
        let id = record["capsule_id"].as_str().unwrap();

        // Unknown peer: refused, nothing held.
        assert!(!hold_asked_record(&mine, "peer-ask-unknown", &record_bytes)
            .await
            .unwrap());

        let peer = "peer-ask-known";
        crate::peer_keys::announced::announce_for_test(peer, record["key_id"].as_str().unwrap());
        assert!(hold_asked_record(&mine, peer, &record_bytes).await.unwrap());
        // Asking again holds nothing new and is still a success.
        assert!(hold_asked_record(&mine, peer, &record_bytes).await.unwrap());

        let lines = |name: &str| -> Vec<serde_json::Value> {
            std::fs::read_to_string(mine.ledger_dir().join(name))
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };
        let provenance = lines(crate::record_push_receive::RECEIVED_PROVENANCE_FILENAME);
        assert_eq!(provenance.len(), 1, "held once: {provenance:?}");
        assert_eq!(provenance[0]["capsule_id"], id);
        assert_eq!(provenance[0]["received_from"], peer);
        assert_eq!(provenance[0]["via"], "ask");
        let citing: Vec<_> = lines("capsules.jsonl")
            .into_iter()
            .filter_map(|r| {
                r.pointer("/model_attestation/compute_attestation/received_half")
                    .cloned()
            })
            .collect();
        assert_eq!(citing.len(), 1, "cited once: {citing:?}");
        assert_eq!(citing[0]["cited_capsule_id"], id);
        assert_eq!(citing[0]["via"], "ask");
    }

    /// One exchange half sealed by `state` under `nonce`, served to
    /// `counterparty`.
    fn half(
        state: &CapsuleState,
        nonce: &str,
        exchange_id: &str,
        counterparty: &str,
    ) -> serde_json::Value {
        state
            .emit_for_exchange(&crate::capsule_emit::ExchangeRecord {
                model: "m",
                client_nonce: Some(nonce),
                request_bytes: br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
                response_bytes:
                    br#"{"id":"x","choices":[{"message":{"role":"assistant","content":"y"}}]}"#,
                latency_ms: 1.0,
                exchange_id: Some(exchange_id),
                requesting_party: Some(counterparty),
                host_provenance: None,
            })
            .unwrap()
            .capsule
    }

    /// A push answered as `bridge_inbound_record_push` answers one, past the
    /// stream and the split collector: received, then on success the citing
    /// records sealed and a terms leg handed on. The reply the sender reads.
    pub(crate) async fn answer_push(
        capsules: &Arc<CapsuleState>,
        sender: &str,
        body: &[u8],
    ) -> serde_json::Value {
        let (reply, accepted_key) = receive_pushed_record(capsules, sender, body).await.unwrap();
        if accepted(&reply) {
            seal_citing_records_for_push(capsules, sender, body, &reply, accepted_key.as_ref())
                .await
                .unwrap();
            hold_settlement_terms(capsules, body).await;
        }
        reply
    }

    /// The `received_half` blocks of `state`'s citing records, oldest first.
    fn received_halves(state: &CapsuleState) -> Vec<serde_json::Value> {
        std::fs::read_to_string(state.ledger_dir().join("capsules.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .unwrap()
                    .pointer("/model_attestation/compute_attestation/received_half")
                    .cloned()
            })
            .collect()
    }

    /// Two nodes for one test: `theirs` seals the halves pushed or asked
    /// for, and `peer` is announced with its key so `mine` holds them.
    fn two_nodes(
        peer: &str,
    ) -> (
        tempfile::TempDir,
        tempfile::TempDir,
        CapsuleState,
        Arc<CapsuleState>,
    ) {
        let theirs_dir = tempfile::tempdir().unwrap();
        let mine_dir = tempfile::tempdir().unwrap();
        let theirs = CapsuleState::open(theirs_dir.path(), "their-node").unwrap();
        let mine = Arc::new(CapsuleState::open(mine_dir.path(), "my-node").unwrap());
        crate::peer_keys::announced::announce_for_test(
            peer,
            &crate::commitment::key_id(theirs.signing_key()),
        );
        (theirs_dir, mine_dir, theirs, mine)
    }

    /// The citing record names this node's own half of the exchange, found by
    /// the client nonce both halves bind (capsules-plugin#130), and the
    /// member is part of the record's recomputed `capsule_id`.
    #[tokio::test]
    async fn a_citing_record_names_the_own_half_of_the_same_exchange() {
        let peer = "peer-own-half-tied";
        let (_t, _m, theirs, mine) = two_nodes(peer);
        let own = half(&mine, "nonce-tied", "e-mine", peer);
        let other = half(&mine, "nonce-elsewhere", "e-other", peer);
        let foreign = half(&theirs, "nonce-tied", "e-theirs", "my-node");
        let bytes = serde_json::to_vec(&foreign).unwrap();
        assert!(hold_asked_record(&mine, peer, &bytes).await.unwrap());

        let cited = received_halves(&mine);
        assert_eq!(cited.len(), 1, "{cited:?}");
        assert_eq!(cited[0]["cited_capsule_id"], foreign["capsule_id"]);
        assert_eq!(cited[0]["own_half_capsule_id"], own["capsule_id"]);
        assert_ne!(cited[0]["own_half_capsule_id"], other["capsule_id"]);
        let record = std::fs::read_to_string(mine.ledger_dir().join("capsules.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .next_back()
            .unwrap();
        assert_eq!(
            record["capsule_id"].as_str().unwrap(),
            crate::producer::jcs::compute_capsule_id(&record).unwrap()
        );
    }

    /// No own half under the nonce: the half is still held and cited, with
    /// no `own_half_capsule_id` (an asked half never waits).
    #[tokio::test]
    async fn a_half_with_no_own_half_is_cited_untied() {
        let peer = "peer-own-half-none";
        let (_t, _m, theirs, mine) = two_nodes(peer);
        half(&mine, "nonce-mine-only", "e-mine", peer);
        let foreign = half(&theirs, "nonce-theirs-only", "e-theirs", "my-node");
        let bytes = serde_json::to_vec(&foreign).unwrap();
        assert!(hold_asked_record(&mine, peer, &bytes).await.unwrap());
        let cited = received_halves(&mine);
        assert_eq!(cited.len(), 1);
        assert!(cited[0].get("own_half_capsule_id").is_none(), "{cited:?}");
    }

    /// A client-set nonce can repeat. Two own halves under it: no tie, since
    /// a wrong pair is worse than none.
    #[tokio::test]
    async fn two_own_halves_under_one_nonce_tie_nothing() {
        let peer = "peer-own-half-two-own";
        let (_t, _m, theirs, mine) = two_nodes(peer);
        half(&mine, "nonce-reused", "e-mine-1", peer);
        half(&mine, "nonce-reused", "e-mine-2", peer);
        let foreign = half(&theirs, "nonce-reused", "e-theirs", "my-node");
        let bytes = serde_json::to_vec(&foreign).unwrap();
        assert!(hold_asked_record(&mine, peer, &bytes).await.unwrap());
        let cited = received_halves(&mine);
        assert_eq!(cited.len(), 1);
        assert!(cited[0].get("own_half_capsule_id").is_none(), "{cited:?}");
    }

    /// Two held halves under one nonce: the second ties nothing, even though
    /// one own half binds it.
    #[tokio::test]
    async fn a_second_held_half_under_the_nonce_ties_nothing() {
        let peer = "peer-own-half-two-held";
        let (_t, _m, theirs, mine) = two_nodes(peer);
        let own = half(&mine, "nonce-shared", "e-mine", peer);
        let first = half(&theirs, "nonce-shared", "e-theirs-1", "my-node");
        let second = half(&theirs, "nonce-shared", "e-theirs-2", "my-node");
        for foreign in [&first, &second] {
            let bytes = serde_json::to_vec(foreign).unwrap();
            assert!(hold_asked_record(&mine, peer, &bytes).await.unwrap());
        }
        let cited = received_halves(&mine);
        assert_eq!(cited.len(), 2, "{cited:?}");
        assert_eq!(cited[0]["own_half_capsule_id"], own["capsule_id"]);
        assert!(cited[1].get("own_half_capsule_id").is_none(), "{cited:?}");
    }

    /// A reused nonce: this node's only own half under it is of an earlier
    /// exchange with another peer, whose half never arrived. A half from
    /// this peer under the nonce is not tied to it.
    #[tokio::test]
    async fn an_own_half_with_another_peer_is_never_tied() {
        let peer = "peer-own-half-other-peer";
        let (_t, _m, theirs, mine) = two_nodes(peer);
        half(
            &mine,
            "nonce-reused-across-peers",
            "e-mine",
            "some-other-peer",
        );
        let foreign = half(&theirs, "nonce-reused-across-peers", "e-theirs", "my-node");
        let bytes = serde_json::to_vec(&foreign).unwrap();
        assert!(hold_asked_record(&mine, peer, &bytes).await.unwrap());
        let cited = received_halves(&mine);
        assert_eq!(cited.len(), 1);
        assert!(cited[0].get("own_half_capsule_id").is_none(), "{cited:?}");
    }

    /// The wait is bounded: a pushed half whose own half never seals is cited
    /// untied once `OWN_HALF_WAIT` has passed, well inside the pusher's reply
    /// timeout, and an asked half does not wait at all.
    #[tokio::test]
    async fn a_pushed_half_waits_at_most_the_bound_and_an_asked_one_not_at_all() {
        let peer = "peer-own-half-bound";
        let (_t, _m, theirs, mine) = two_nodes(peer);
        let pushed = half(&theirs, "nonce-never-mine-1", "e-theirs-1", "my-node");
        let asked = half(&theirs, "nonce-never-mine-2", "e-theirs-2", "my-node");

        let started = std::time::Instant::now();
        seal_citing_record(
            &mine,
            peer,
            &serde_json::to_vec(&pushed).unwrap(),
            "push",
            None,
        )
        .await
        .unwrap();
        let waited = started.elapsed();
        assert!(waited >= OWN_HALF_WAIT - OWN_HALF_POLL, "{waited:?}");
        assert!(
            waited < OWN_HALF_WAIT + Duration::from_secs(1),
            "{waited:?}"
        );

        let started = std::time::Instant::now();
        assert!(
            hold_asked_record(&mine, peer, &serde_json::to_vec(&asked).unwrap())
                .await
                .unwrap()
        );
        assert!(
            started.elapsed() < OWN_HALF_WAIT / 2,
            "{:?}",
            started.elapsed()
        );

        let cited = received_halves(&mine);
        assert_eq!(cited.len(), 2, "{cited:?}");
        assert!(
            cited.iter().all(|c| c.get("own_half_capsule_id").is_none()),
            "{cited:?}"
        );

        // A re-push of the half already cited does not wait again.
        let started = std::time::Instant::now();
        seal_citing_record(
            &mine,
            peer,
            &serde_json::to_vec(&pushed).unwrap(),
            "push",
            None,
        )
        .await
        .unwrap();
        assert!(
            started.elapsed() < OWN_HALF_WAIT / 2,
            "{:?}",
            started.elapsed()
        );
    }

    /// The look and the seal are not one step: an own half sealed between
    /// them makes the nonce ambiguous, and the check made again under the
    /// ledger lock seals the record untied.
    #[tokio::test]
    async fn an_own_half_sealed_after_the_look_unties_the_record() {
        let peer = "peer-own-half-race";
        let (_t, _m, theirs, mine) = two_nodes(peer);
        let own = half(&mine, "nonce-race", "e-mine-1", peer);
        let foreign = half(&theirs, "nonce-race", "e-theirs", "my-node");
        let tied = own_half_tie(&mine, &foreign, peer, "ask").await;
        assert_eq!(tied.as_deref(), own["capsule_id"].as_str());
        half(&mine, "nonce-race", "e-mine-2", peer);

        let foreign_id = foreign["capsule_id"].as_str().unwrap();
        let prov = ReceivedHalfProvenance {
            foreign_capsule_id: foreign_id,
            received_from: peer,
            via: "ask",
            received_at: "2026-10-30T06:00:00Z",
            signature_ok: true,
            digest_match: None,
            foreign_agent_input_digest: None,
            foreign_agent_output_digest: None,
            sender_key_id: None,
            accepted_via: None,
            controller_binding: None,
            same_controller_as_receiver: None,
            own_half_capsule_id: tied.as_deref(),
        };
        mine.emit_citing_record_checked(&prov, |own| {
            own_half(&mine, &foreign, peer) == OwnHalf::Tied(own.to_string())
        })
        .unwrap()
        .expect("a new citing record");
        let cited = received_halves(&mine);
        assert_eq!(cited.len(), 1);
        assert!(cited[0].get("own_half_capsule_id").is_none(), "{cited:?}");
    }

    /// A garbled line in the held store is skipped, not taken as "no other
    /// held half": a conflicting half after it still unties.
    #[test]
    fn a_garbled_held_line_does_not_hide_a_held_half_under_the_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let theirs = CapsuleState::open(dir.path(), "their-node").unwrap();
        let other = half(&theirs, "nonce-held", "e-1", "my-node");
        let nonce = crate::evidence_log::client_nonce_digest(&other).unwrap();
        let store = dir
            .path()
            .join(crate::record_push_receive::RECEIVED_CAPSULES_FILENAME);
        let mut bytes = b"{\"capsule_id\":\"\xff\xfe torn\n".to_vec();
        bytes.extend(serde_json::to_vec(&other).unwrap());
        bytes.push(b'\n');
        std::fs::write(&store, bytes).unwrap();
        assert!(held_half_shares_nonce(
            dir.path(),
            &nonce,
            "some-other-half"
        ));
        assert!(!held_half_shares_nonce(
            dir.path(),
            &nonce,
            other["capsule_id"].as_str().unwrap()
        ));
    }

    /// The other side pushed first: the pushed half waits for this node's
    /// own half to seal, then the citing record names it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pushed_half_that_arrives_first_is_tied_when_the_own_half_seals() {
        let peer = "peer-own-half-late";
        let (_t, _m, theirs, mine) = two_nodes(peer);
        let foreign = half(&theirs, "nonce-late", "e-theirs", "my-node");
        let bytes = serde_json::to_vec(&foreign).unwrap();
        let receiving = {
            let mine = mine.clone();
            tokio::spawn(async move { seal_citing_record(&mine, peer, &bytes, "push", None).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        let own = half(&mine, "nonce-late", "e-mine", peer);
        receiving.await.unwrap().unwrap();
        let cited = received_halves(&mine);
        assert_eq!(cited.len(), 1, "{cited:?}");
        assert_eq!(cited[0]["own_half_capsule_id"], own["capsule_id"]);
    }

    /// After an ask, the held record is read back from disk like any other:
    /// the Peers pane (what the page loads on a reload) gives the row a
    /// confirmed sibling `via: "ask"` whose digests match ours, which is what
    /// "Saved as confirmed" counts. The record is asked for here, not pushed,
    /// so the result does not depend on `share_record_at_completion`; the
    /// declined push under `off` is pinned in `record_push_receive`.
    #[tokio::test]
    async fn an_asked_record_survives_a_reload_as_saved_confirmed() {
        use crate::capsule_emit::{HostProvenance, ObservedHostExchange};
        use crate::lifecycle_channel::DispatchPath;
        let my_id = "a".repeat(64);
        let their_id = "b".repeat(64);
        let (request_digest, response_digest) = ("c".repeat(64), "d".repeat(64));
        let observed = |dispatch_path, host_provenance| ObservedHostExchange {
            model: "m",
            exchange_id: Some("e-reload"),
            request_digest: Some(&request_digest),
            response_digest: Some(&response_digest),
            tool_calls_digest: None,
            reasoning_digest: None,
            usage: None,
            host_provenance,
            dispatch_path,
            nonce: Some("reload-nonce"),
            peer_capsule_id: None,
            peer_capsule_id_provenance: None,
            twin_bracket_id: None,
            response_text_digest: None,
        };
        let mine_dir = tempfile::tempdir().unwrap();
        let theirs_dir = tempfile::tempdir().unwrap();
        let mine = Arc::new(CapsuleState::open(mine_dir.path(), "my-node").unwrap());
        let theirs = CapsuleState::open(theirs_dir.path(), "their-node").unwrap();
        mine.emit_for_observed_host_exchange(&observed(
            DispatchPath::RemoteMesh,
            HostProvenance {
                served_by_node_id: Some(their_id.clone()),
                ..Default::default()
            },
        ))
        .unwrap();
        let record = theirs
            .emit_for_observed_host_exchange(&observed(
                DispatchPath::TypedFrontend,
                HostProvenance {
                    requested_by_node_id: Some(my_id.clone()),
                    ..Default::default()
                },
            ))
            .unwrap()
            .capsule;
        let record_bytes = serde_json::to_vec(&record).unwrap();
        crate::peer_keys::announced::announce_for_test(
            &their_id,
            record["key_id"].as_str().unwrap(),
        );

        assert!(hold_asked_record(&mine, &their_id, &record_bytes)
            .await
            .unwrap());

        // A reload reads the panes from disk.
        let pane =
            crate::evidence_panes::build_pane_json("pane-b", mine.ledger_dir(), None).unwrap();
        let row = pane["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["identity"]["node_id"] == serde_json::json!(their_id))
            .unwrap_or_else(|| panic!("a row for the peer: {pane}"));
        let siblings = row["confirmed_siblings"].as_array().unwrap();
        assert_eq!(siblings.len(), 1, "{row}");
        assert_eq!(siblings[0]["theirs"]["via"], "ask");
        assert_eq!(siblings[0]["theirs"]["signature_ok"], true);
        assert_eq!(siblings[0]["digest_match"]["state"], "verified");
    }

    /// The whole sender flow over a REAL sealed half: seal through
    /// `CapsuleState`, cover it with a push-time checkpoint over the same
    /// ledger, build the bundle -- and the bundle's proof verifies against its
    /// checkpoint, which is signed by the half's own key.
    pub(crate) fn real_bundle(dir: &std::path::Path) -> serde_json::Value {
        use crate::producer::anchor::AnchorClient;
        use crate::producer::checkpoint::{CheckpointCadenceConfig, CheckpointState};
        let capsules = CapsuleState::open(dir, "rust-node").expect("open capsule state");
        let exchange = crate::capsule_emit::ExchangeRecord {
            model: "m",
            client_nonce: Some("n"),
            request_bytes: br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
            response_bytes:
                br#"{"id":"x","choices":[{"message":{"role":"assistant","content":"y"}}]}"#,
            latency_ms: 1.0,
            exchange_id: Some("e-1"),
            requesting_party: Some("party-1"),
            host_provenance: None,
        };
        capsules
            .emit_for_exchange(&exchange)
            .expect("seal an earlier record");
        let half = capsules
            .emit_for_exchange(&exchange)
            .expect("seal the pushed half");
        let (mut state, _) = CheckpointState::load(
            &dir.join("ledger"),
            "rust-node",
            CheckpointCadenceConfig::default(),
        )
        .expect("load checkpoint state");
        let coverage = state
            .checkpoint_covering(
                &half.capsule_id,
                capsules.signing_key(),
                &AnchorClient::new("http://127.0.0.1:1"),
            )
            .expect("cover the half");
        assert_eq!(coverage.leaf_index, 1);
        assert_eq!(
            coverage.checkpoint.key_id,
            half.capsule["key_id"].as_str().unwrap()
        );
        assert!(coverage.checkpoint.verify_signature_offline());
        bundle_body(&half.capsule, &coverage)
    }

    #[test]
    fn a_real_bundle_proves_the_half_under_a_checkpoint_signed_by_its_key() {
        let dir = std::env::temp_dir().join(format!("bundle-real-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let body = real_bundle(&dir);
        let root: [u8; 32] = hex::decode(body["checkpoint"]["root"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let leaf: [u8; 32] = hex::decode(body["capsule"]["capsule_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let p = &body["inclusion"]["proof"];
        let strings = |k: &str| {
            p[k].as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        let proof = crate::producer::checkpoint::InclusionProof {
            v: p["v"].as_u64().unwrap() as u32,
            kind: p["kind"].as_str().unwrap().to_string(),
            size: p["size"].as_u64().unwrap(),
            leaf_index: p["leaf_index"].as_u64().unwrap(),
            witness: strings("witness"),
            peaks_left: strings("peaks_left"),
            peaks_right: strings("peaks_right"),
        };
        assert!(cll_verify_inclusion(
            &root,
            body["checkpoint"]["mmr_size"].as_u64().unwrap(),
            1,
            &leaf,
            &proof
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cll_verify_inclusion(
        root: &[u8; 32],
        size: u64,
        leaf_index: u64,
        body: &[u8; 32],
        proof: &crate::producer::checkpoint::InclusionProof,
    ) -> bool {
        crate::producer::checkpoint::verify_inclusion(root, size, leaf_index, body, proof)
    }

    /// Writes `vectors/record_push_bundle_rust.json`, the bundle the
    /// Python reference's cross-language test verifies. Run to regenerate:
    ///   cargo test writes_the_cross_language_bundle_fixture -- --ignored
    #[test]
    #[ignore = "regenerates a committed fixture"]
    fn writes_the_cross_language_bundle_fixture() {
        let dir = std::env::temp_dir().join(format!("bundle-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let body = real_bundle(&dir);
        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/record_push_bundle_rust.json");
        std::fs::write(&out, serde_json::to_string_pretty(&body).unwrap() + "\n").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
