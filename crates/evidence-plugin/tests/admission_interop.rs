//! Basic admission over mesh-llm's real plugin wire protocol: this test is the
//! host side of the OpenAI exchange lifecycle (mesh-llm#2226), as in
//! `tests/interop.rs`. It reads the hook the plugin declares at Initialize,
//! then invokes it the way the host's routing does just before an attempt to
//! a mesh peer (`backend_selected`, `provider: "mesh"`, the target's `Debug`
//! form), and checks the answer and the record the plugin sealed for it.
//!
//! No mesh-llm release carries the lifecycle yet, so the two-node e2e on the
//! pinned release cannot reach this hook; this test is the proof until one
//! does.

use mesh_llm_plugin::proto::{self, envelope::Payload};
use mesh_llm_plugin::{
    read_envelope, write_envelope, LocalListener, LocalStream, PROTOCOL_VERSION,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::time::timeout;

const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_capsules");
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

const ALLOWED: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
const DENIED: &str = "dd00000000000000000000000000000000000000000000000000000000000002";
const STRANGER: &str = "5500000000000000000000000000000000000000000000000000000000000003";

struct Host {
    child: tokio::process::Child,
    stream: LocalStream,
    next_request_id: u64,
    data_dir: PathBuf,
    /// What the plugin sent that answered none of this host's requests.
    others: Vec<Payload>,
}

impl Host {
    async fn spawn(env: &[(&str, &str)]) -> Self {
        let tag = format!("{}-{}", std::process::id(), rand_tag());
        let socket_path = std::env::temp_dir().join(format!("capsules-admission-{tag}.sock"));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind fake-host socket");
        let data_dir = std::env::temp_dir().join(format!("capsules-admission-data-{tag}"));
        let mut cmd = Command::new(PLUGIN_BIN);
        cmd.env("MESH_LLM_PLUGIN_ENDPOINT", &socket_path)
            .env("MESH_LLM_PLUGIN_TRANSPORT", "unix")
            .env("CAPSULES_DATA_DIR", &data_dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        for (key, value) in env {
            cmd.env(key, value);
        }
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
            others: Vec::new(),
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

    /// The plugin's answer to `request_id`, skipping anything else it sends.
    async fn answer(&mut self, request_id: u64) -> Payload {
        loop {
            let envelope = timeout(TEST_TIMEOUT, read_envelope(&mut self.stream))
                .await
                .expect("plugin answered before timeout")
                .expect("read envelope from plugin");
            if envelope.request_id == request_id {
                return envelope.payload.expect("an answer carries a payload");
            }
            self.others.extend(envelope.payload);
        }
    }

    async fn initialize(&mut self) -> proto::InitializeResponse {
        let id = self
            .send(Payload::InitializeRequest(proto::InitializeRequest {
                host_protocol_version: PROTOCOL_VERSION,
                host_capabilities: vec!["openai_exchange.v1".into()],
                host_version: "admission-interop".to_string(),
                host_info_json: "{}".to_string(),
                mesh_visibility: proto::MeshVisibility::Private as i32,
            }))
            .await;
        match self.answer(id).await {
            Payload::InitializeResponse(response) => response,
            other => panic!("expected InitializeResponse, got {other:?}"),
        }
    }

    /// The host's `backend_selected` call for an attempt to `target`.
    async fn select(&mut self, handler: &str, target: &str, attempt: u64) -> Value {
        let event = json!({
            "exchange_id": format!("req-{attempt}"),
            "request_id": format!("req-{attempt}"),
            "phase": "backend_selected",
            "endpoint": "chat_completions",
            "provider": "mesh",
            "target": target,
            "attempt": attempt,
            "model": "e2e-model",
        });
        let id = self
            .send(Payload::InvokeServiceRequest(proto::InvokeServiceRequest {
                kind: proto::ServiceKind::OpenaiExchange as i32,
                service_name: handler.to_string(),
                input_json: event.to_string(),
            }))
            .await;
        match self.answer(id).await {
            Payload::InvokeServiceResponse(response) => {
                assert!(!response.is_error, "{response:?}");
                serde_json::from_str(&response.output_json).expect("the answer is JSON")
            }
            other => panic!("expected InvokeServiceResponse, got {other:?}"),
        }
    }

    async fn shutdown(mut self) -> PathBuf {
        let id = self
            .send(Payload::ShutdownRequest(proto::ShutdownRequest {
                reason: "admission interop complete".to_string(),
            }))
            .await;
        assert!(matches!(
            self.answer(id).await,
            Payload::ShutdownResponse(_)
        ));
        let status = timeout(TEST_TIMEOUT, self.child.wait())
            .await
            .expect("plugin exited before timeout")
            .expect("wait on plugin process");
        assert!(status.success(), "plugin process exited with {status:?}");
        self.data_dir
    }
}

fn rand_tag() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64;
    nanos ^ (NEXT.fetch_add(1, Ordering::Relaxed) << 32)
}

fn remote(id: &str) -> String {
    format!("Remote(PublicKey({id}))")
}

/// The node's chain as `capsules chain-lines` prints it: one record per
/// line, in the `capsules.jsonl` line format, read from the chain's stores.
fn chain_lines(data_dir: &std::path::Path) -> String {
    let out = std::process::Command::new(PLUGIN_BIN)
        .args(["chain-lines", "--data-dir"])
        .arg(data_dir)
        .output()
        .expect("run capsules chain-lines");
    assert!(
        out.status.success(),
        "chain-lines: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("chain-lines prints UTF-8")
}

/// Every `admission_decision` block the plugin sealed, in ledger order: the
/// chain's records, and any file under `ledger/` that holds records.
fn sealed_decisions(data_dir: &std::path::Path) -> Vec<Value> {
    let mut decisions = Vec::new();
    let texts = walk(&data_dir.join("ledger"))
        .iter()
        .filter_map(|entry| std::fs::read_to_string(entry).ok())
        .chain([chain_lines(data_dir)])
        .collect::<Vec<_>>();
    for text in texts {
        for line in text.lines() {
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let capsule = record.get("capsule").unwrap_or(&record);
            let block = &capsule["model_attestation"]["compute_attestation"]["admission_decision"];
            if !block.is_null() {
                decisions.push(block.clone());
            }
        }
    }
    decisions
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out.sort();
    out
}

#[tokio::test]
async fn a_denied_peer_gets_no_and_an_allowed_peer_gets_go_through_the_wire_protocol() {
    let mut host = Host::spawn(&[
        ("CAPSULES_ADMISSION_ALLOW", ALLOWED),
        ("CAPSULES_ADMISSION_DENY", DENIED),
        ("CAPSULES_ADMISSION_DEFAULT", "no"),
    ])
    .await;
    let init = host.initialize().await;
    let hook = init
        .manifest
        .as_ref()
        .and_then(|m| m.openai_exchange_hook.as_deref())
        .expect("the plugin declares the lifecycle hook");
    assert!(hook.admission, "{hook:?}");
    assert_eq!(hook.phases, vec!["backend_selected".to_string()]);
    assert!(!hook.required);
    let handler = hook.handler.clone();

    let denied = host.select(&handler, &remote(DENIED), 1).await;
    assert_eq!(denied["decision"], "deny", "{denied}");
    let allowed = host.select(&handler, &remote(ALLOWED), 2).await;
    assert_eq!(allowed["decision"], "allow", "{allowed}");
    let stranger = host.select(&handler, &remote(STRANGER), 3).await;
    assert_eq!(
        stranger["decision"], "deny",
        "the default is no: {stranger}"
    );
    let local = host.select(&handler, "Local(9337)", 4).await;
    assert_eq!(
        local["decision"], "abstain",
        "this node is not a peer: {local}"
    );

    let data_dir = host.shutdown().await;
    let decisions = sealed_decisions(&data_dir);
    let seen: Vec<(String, String)> = decisions
        .iter()
        .map(|b| {
            (
                b["verdict"].as_str().unwrap_or_default().to_string(),
                b["source"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [("NO", "deny_list"), ("GO", "allow_list"), ("NO", "default")]
            .map(|(v, s)| (v.to_string(), s.to_string())),
        "one sealed decision per peer attempt, none for the local one"
    );
    for block in &decisions {
        assert_eq!(block["reads"][0]["kind"], "operator_policy", "{block}");
    }
    let ledger_text: String = walk(&data_dir.join("ledger"))
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .chain([chain_lines(&data_dir)])
        .collect();
    for id in [ALLOWED, DENIED, STRANGER] {
        assert!(!ledger_text.contains(id), "no peer id is sealed in clear");
    }
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[tokio::test]
async fn a_setting_that_does_not_parse_fails_closed_and_the_plugin_keeps_running() {
    // Under a `best_effort` grant, stopping would refuse no one: a host
    // routes to every peer past a plugin it has no manifest for.
    let mut host = Host::spawn(&[
        ("CAPSULES_ADMISSION_ALLOW", ALLOWED),
        ("CAPSULES_ADMISSION_DENY", "not-a-node-id"),
    ])
    .await;
    let init = host.initialize().await;
    let handler = init
        .manifest
        .as_ref()
        .and_then(|m| m.openai_exchange_hook.as_deref())
        .expect("the plugin still declares the hook")
        .handler
        .clone();
    for (attempt, peer) in [ALLOWED, STRANGER].into_iter().enumerate() {
        let answer = host
            .select(&handler, &remote(peer), attempt as u64 + 1)
            .await;
        assert_eq!(answer["decision"], "deny", "{peer}: {answer}");
        assert_eq!(answer["reason"], "admission NO (unreadable_policy)");
    }
    let data_dir = host.shutdown().await;
    let sources: Vec<Value> = sealed_decisions(&data_dir)
        .iter()
        .map(|b| b["source"].clone())
        .collect();
    assert_eq!(
        sources,
        [json!("unreadable_policy"), json!("unreadable_policy")]
    );
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// R11's hook path over the wire protocol. With a hold set, a request
/// admitted to a peer that the host's status lists with one model is held
/// while the agreement set-up starts, and released at the hold although the
/// provider never answers; the set-up goes on and asks the host for an
/// agreement stream. A denied request is answered at once and reads no
/// status.
#[tokio::test]
async fn an_admitted_request_is_held_for_its_agreement_set_up_and_a_denied_one_is_not() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    let status = json!({
        "node_id": "c5e7af08d8",
        "serving_models": [],
        "peers": [{"id": &ALLOWED[..10], "serving_models": ["local-gguf/sha256-74a4da8c"]}],
    });
    let app = axum::Router::new().route(
        "/api/status",
        axum::routing::get(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            let status = status.clone();
            async move { axum::Json(status) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let console = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let peer_keys = json!({ ALLOWED: "ab".repeat(32) }).to_string();

    let mut host = Host::spawn(&[
        ("CAPSULES_ADMISSION_ALLOW", ALLOWED),
        ("CAPSULES_ADMISSION_DENY", DENIED),
        ("CAPSULES_ADMISSION_DEFAULT", "no"),
        ("CAPSULES_AGREEMENT_SPEND_CAP_MSAT", "3000"),
        ("CAPSULES_AGREEMENT_HOOK_WAIT_MS", "600"),
        ("CAPSULES_HOST_CONSOLE_URL", &console),
        ("CAPSULES_PEER_KEYS", &peer_keys),
    ])
    .await;
    let init = host.initialize().await;
    let hook = init
        .manifest
        .as_ref()
        .and_then(|m| m.openai_exchange_hook.as_deref())
        .expect("the plugin declares the lifecycle hook");
    assert_eq!(hook.deadline_ms, 2_000, "room for the hold: {hook:?}");
    let handler = hook.handler.clone();

    let started = Instant::now();
    let denied = host.select(&handler, &remote(DENIED), 1).await;
    assert_eq!(denied["decision"], "deny", "{denied}");
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        0,
        "a denied request reads no status"
    );

    let started = Instant::now();
    let allowed = host.select(&handler, &remote(ALLOWED), 2).await;
    let held = started.elapsed();
    assert_eq!(allowed["decision"], "allow", "{allowed}");
    assert!(
        held >= Duration::from_millis(450) && held < Duration::from_millis(1_750),
        "held for the set-up, released at the hold: {held:?}"
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "the provider's model was read"
    );
    let agreement_streams = host
        .others
        .iter()
        .filter(|payload| {
            matches!(payload, Payload::OpenMeshStreamRequest(open)
                if open.channel == "x-capsules-agreement/1" && open.target_peer_id == ALLOWED)
        })
        .count();
    assert_eq!(
        agreement_streams, 1,
        "the set-up asked for an agreement stream: {:?}",
        host.others
    );

    host.shutdown().await;
}
