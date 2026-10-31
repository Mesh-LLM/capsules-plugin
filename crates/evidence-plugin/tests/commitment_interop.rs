//! Two plugin processes over the real plugin wire: node B fetches node A's
//! commitment over the `commitment/1` mesh channel and checks it, and A's
//! refusals name the policy digest A's commitment commits to (loop step 3,
//! Mesh-LLM/capsules-plugin#51).
//!
//! Same fake-host approach as `tests/ledger_fetch_bridge_interop.rs`: this
//! repository's CI cannot build `mesh-llm-host-runtime`, so the test plays
//! both hosts. It answers B's outbound `OpenMeshStreamRequest` with a socket
//! it bridges, byte for byte, to the stream A's responder opened for the
//! same channel, as the real hosts do once their channel gates have passed.

use mesh_llm_plugin::proto::{self, envelope::Payload};
use mesh_llm_plugin::{
    connect_side_stream, read_envelope, write_envelope, LocalListener, LocalStream,
    PROTOCOL_VERSION,
};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::time::timeout;

const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_capsules");
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const COMMITMENT_CHANNEL: &str = "commitment/1";
const NODE_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const NODE_B: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

struct Harness {
    child: tokio::process::Child,
    stream: LocalStream,
    next_request_id: u64,
    data_dir: std::path::PathBuf,
}

impl Harness {
    async fn spawn(node_id: &str) -> Self {
        let socket_path = std::env::temp_dir().join(format!("commitment-interop-{}.sock", nonce()));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind fake-host socket");
        let data_dir = std::env::temp_dir().join(format!("commitment-interop-data-{}", nonce()));
        std::fs::create_dir_all(&data_dir).expect("create the data dir");
        let mut cmd = Command::new(PLUGIN_BIN);
        cmd.env("MESH_LLM_PLUGIN_ENDPOINT", &socket_path)
            .env("MESH_LLM_PLUGIN_TRANSPORT", "unix")
            .env("CAPSULES_BLOCKED_MODELS", "blocked-test-model")
            .env("CAPSULES_DATA_DIR", &data_dir)
            .env("CAPSULES_SELF_PEER_ID", node_id)
            // A checkpoint soon after the first record: the commitment
            // commits to one.
            .env("CAPSULES_CHECKPOINT_CADENCE_SECONDS", "1")
            .env("CAPSULES_COMMITMENT_TIMEOUT_MS", "3000")
            // Never the operator's mesh config or sharing switches.
            .env("MESH_LLM_CONFIG", data_dir.join("no-mesh-config.toml"))
            .env_remove("CAPSULES_SHARE_HISTORY_SEGMENTS")
            .env_remove("CAPSULES_SHARE_STANDARD_HISTORY")
            .env_remove("CAPSULES_SHARE_EXCHANGE_CORROBORATION")
            // Keeps the side-stream socket path under `sun_path`'s limit on
            // macOS (`mesh_evidence_bridge_interop.rs`).
            .env("TMPDIR", "/tmp");
        let child = cmd.spawn().expect("spawn the capsules plugin");
        let stream = timeout(
            TEST_TIMEOUT,
            LocalListener::Unix(listener, socket_path).accept(),
        )
        .await
        .expect("plugin connected before timeout")
        .expect("accept plugin connection");
        Self {
            child,
            stream,
            next_request_id: 1,
            data_dir,
        }
    }

    async fn send(&mut self, payload: Payload) -> u64 {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        write_envelope(
            &mut self.stream,
            &proto::Envelope {
                protocol_version: PROTOCOL_VERSION,
                plugin_id: "capsules".to_string(),
                request_id,
                payload: Some(payload),
            },
        )
        .await
        .expect("write envelope to plugin");
        request_id
    }

    async fn recv(&mut self) -> proto::Envelope {
        timeout(TEST_TIMEOUT, read_envelope(&mut self.stream))
            .await
            .expect("plugin responded before timeout")
            .expect("read envelope from plugin")
    }

    async fn initialize(&mut self) -> proto::PluginManifest {
        let request_id = self
            .send(Payload::InitializeRequest(proto::InitializeRequest {
                host_protocol_version: PROTOCOL_VERSION,
                host_capabilities: Vec::new(),
                host_version: "commitment-interop-test".to_string(),
                host_info_json: "{}".to_string(),
                mesh_visibility: proto::MeshVisibility::Private as i32,
            }))
            .await;
        let envelope = self.recv().await;
        assert_eq!(envelope.request_id, request_id);
        let Some(Payload::InitializeResponse(response)) = envelope.payload else {
            panic!("expected InitializeResponse");
        };
        let manifest = response.manifest.expect("plugin declares a manifest");
        assert!(
            manifest
                .mesh_channels
                .iter()
                .any(|c| c.name == COMMITMENT_CHANNEL),
            "manifest must declare {COMMITMENT_CHANNEL}"
        );
        manifest
    }

    /// One record, through the plugin's own inference endpoint, then the
    /// checkpoint the cadence cuts over it.
    async fn seal_and_checkpoint(&self, manifest: &proto::PluginManifest) {
        let address = manifest
            .endpoints
            .iter()
            .find(|e| e.kind == proto::EndpointKind::Inference as i32)
            .and_then(|e| e.address.clone())
            .expect("manifest declares an inference endpoint");
        let resp = reqwest::Client::new()
            .post(format!("{address}/v1/chat/completions"))
            .json(&json!({"model": "an-allowed-model", "messages": [{"role": "user", "content": "hi"}]}))
            .send()
            .await
            .expect("POST /v1/chat/completions");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let checkpoints = self.data_dir.join("ledger").join("checkpoints.jsonl");
        timeout(TEST_TIMEOUT, async {
            while std::fs::metadata(&checkpoints).map_or(true, |m| m.len() == 0) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the cadence cut a checkpoint");
    }

    /// The responder side of a stream the host opened for this plugin.
    async fn open_stream(&mut self, metadata: Option<&str>) -> LocalStream {
        let request_id = self
            .send(Payload::OpenStreamRequest(proto::OpenStreamRequest {
                stream_id: format!("test-stream-{}", nonce()),
                purpose: proto::StreamPurpose::Generic as i32,
                mode: proto::StreamMode::RawBytes as i32,
                bidirectional: true,
                content_type: Some("application/json".to_string()),
                correlation_id: None,
                metadata_json: metadata.map(str::to_string),
                expected_bytes: None,
                idle_timeout_ms: None,
            }))
            .await;
        let envelope = self.recv().await;
        assert_eq!(envelope.request_id, request_id);
        let Some(Payload::OpenStreamResponse(response)) = envelope.payload else {
            panic!("expected OpenStreamResponse");
        };
        assert!(response.accepted);
        let endpoint = response
            .endpoint
            .expect("an accepted stream has an endpoint");
        connect_side_stream(&endpoint, response.transport_kind)
            .await
            .expect("dial the plugin's local listener")
    }

    /// Call a tool; when it opens a mesh stream, answer the open with
    /// `endpoint` and check it is for `channel`.
    async fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        mesh: Option<(&str, &str)>,
    ) -> Value {
        let call_id = self
            .send(Payload::RpcRequest(proto::RpcRequest {
                method: "tools/call".to_string(),
                params_json: json!({"name": name, "arguments": arguments}).to_string(),
            }))
            .await;
        if let Some((channel, endpoint)) = mesh {
            let envelope = self.recv().await;
            let Some(Payload::OpenMeshStreamRequest(open)) = envelope.payload else {
                panic!("expected an outbound OpenMeshStreamRequest");
            };
            assert_eq!(open.channel, channel);
            assert_eq!(open.metadata_json.as_deref(), Some(channel));
            write_envelope(
                &mut self.stream,
                &proto::Envelope {
                    protocol_version: PROTOCOL_VERSION,
                    plugin_id: "capsules".to_string(),
                    request_id: envelope.request_id,
                    payload: Some(Payload::OpenMeshStreamResponse(
                        proto::OpenMeshStreamResponse {
                            stream_id: open.stream_id,
                            accepted: true,
                            transport_kind: proto::StreamTransportKind::StreamUnixSocket as i32,
                            endpoint: Some(endpoint.to_string()),
                            token: None,
                            expires_at_unix_ms: None,
                            message: None,
                        },
                    )),
                },
            )
            .await
            .expect("write OpenMeshStreamResponse");
        }
        let envelope = self.recv().await;
        assert_eq!(envelope.request_id, call_id);
        let Some(Payload::RpcResponse(response)) = envelope.payload else {
            panic!("expected RpcResponse, got {:?}", envelope.payload);
        };
        let result: rmcp::model::CallToolResult =
            serde_json::from_str(&response.result_json).expect("decode CallToolResult");
        assert_eq!(result.is_error, Some(false), "{name} failed: {result:?}");
        result.structured_content.expect("structured JSON")
    }

    async fn shutdown_process(mut self) {
        let request_id = self
            .send(Payload::ShutdownRequest(proto::ShutdownRequest {
                reason: "commitment interop test complete".to_string(),
            }))
            .await;
        let envelope = self.recv().await;
        assert_eq!(envelope.request_id, request_id);
        let status = timeout(TEST_TIMEOUT, self.child.wait())
            .await
            .expect("plugin exited before timeout")
            .expect("wait on plugin process");
        assert!(status.success(), "plugin process exited with {status:?}");
    }
}

fn nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Accept one connection on a fresh socket and copy bytes both ways between
/// it and `peer` until both sides close: the mesh between two hosts.
async fn relay_to(peer: LocalStream) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("commitment-relay-{}.sock", nonce()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind relay");
    tokio::spawn(async move {
        let (asker, _) = listener.accept().await.expect("accept the asker");
        let (mut asker_read, mut asker_write) = asker.into_split();
        let (mut peer_read, mut peer_write) = peer.into_split();
        let up = async {
            tokio::io::copy(&mut asker_read, &mut peer_write).await?;
            peer_write.shutdown().await
        };
        let down = async {
            tokio::io::copy(&mut peer_read, &mut asker_write).await?;
            asker_write.shutdown().await
        };
        let _ = tokio::join!(up, down);
    });
    path
}

#[tokio::test]
async fn a_second_node_fetches_the_commitment_and_a_refusal_names_its_policy_digest() {
    let mut a = Harness::spawn(NODE_A).await;
    let manifest = a.initialize().await;
    a.seal_and_checkpoint(&manifest).await;
    let mut b = Harness::spawn(NODE_B).await;
    b.initialize().await;

    // A's own pair, as the operator would publish it.
    let own = a.call_tool("commitment", json!({}), None).await;

    // B fetches A's over the channel, through the relay, a second later.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let a_side = a.open_stream(Some(COMMITMENT_CHANNEL)).await;
    let relay = relay_to(a_side).await;
    let fetched = b
        .call_tool(
            "mesh_commitment_fetch",
            json!({"peer_id": NODE_A}),
            Some((COMMITMENT_CHANNEL, relay.to_str().unwrap())),
        )
        .await;
    assert_eq!(fetched["problems"], json!([]), "{fetched}");
    assert_eq!(fetched["announced_key"], "not_announced");
    let commitment = &fetched["commitment"];
    assert_eq!(commitment["node_id"], NODE_A);
    assert_eq!(commitment["profile"], "evidence-commitment/0");
    // The same bytes A handed its operator a second earlier: nothing it was
    // built from changed, so A did not build or sign it again.
    assert_eq!(fetched["policy"], own["policy"]);
    assert_eq!(*commitment, own["commitment"]);

    // A stranger asking A for its Service History (named by its definition
    // digest, `derivations/service-history-1.json`) is refused, and the
    // refusal names the digest A's signed commitment advertises.
    let (mut read, mut write) = a.open_stream(None).await.into_split();
    write
        .write_all(br#"{"subject":{"full_history":null},"coverage":{"min_freshness":1},"derivation":"cbc96d800ad206791db7e0793b80a2720c1908468ba99692b739aa8e74aab2d8"}"#)
        .await
        .unwrap();
    write.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(TEST_TIMEOUT, read.read_to_end(&mut reply))
        .await
        .expect("A answered")
        .unwrap();
    let refusal: Value = serde_json::from_slice(&reply).expect("a JSON refusal");
    assert!(
        refusal["reason"].is_string() && refusal["sig"].is_string(),
        "{refusal}"
    );
    assert_eq!(
        refusal["policy_digest"],
        commitment["lcap"]["policy_digest"]
    );

    a.shutdown_process().await;
    b.shutdown_process().await;
}

#[tokio::test]
async fn a_node_with_no_checkpoint_says_so_over_the_channel() {
    let mut a = Harness::spawn(NODE_A).await;
    a.initialize().await;
    let mut b = Harness::spawn(NODE_B).await;
    b.initialize().await;
    let a_side = a.open_stream(Some(COMMITMENT_CHANNEL)).await;
    let relay = relay_to(a_side).await;
    let fetched = b
        .call_tool(
            "mesh_commitment_fetch",
            json!({"peer_id": NODE_A}),
            Some((COMMITMENT_CHANNEL, relay.to_str().unwrap())),
        )
        .await;
    let error = fetched["error"].as_str().expect("an error frame");
    assert!(error.contains("no checkpoint"), "{error}");
    a.shutdown_process().await;
    b.shutdown_process().await;
}
