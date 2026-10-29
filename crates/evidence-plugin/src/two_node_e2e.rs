//! Tier 2: the checks run over a real two-node run.
//!
//! `scripts/e2e-two-node.sh` starts two unmodified `mesh-llm` nodes on one
//! machine, each running this plugin: the provider serves a small model, the
//! requester serves nothing and sends its chat completions to the provider
//! over the mesh. A third node, the corroborator, then asks each of them for
//! its half of one exchange. After the nodes have stopped, the script copies
//! each node's plugin data directory and runs these tests over the copies:
//!
//! ```sh
//! E2E_REQUESTER_DIR=<copy> E2E_PROVIDER_DIR=<copy> E2E_EXCHANGES=<n> \
//!   E2E_JOIN_DIR=<out> E2E_CORROBORATOR_DIR=<copy> \
//!   cargo test --locked --bin capsules -- --ignored --test-threads=1 two_node_e2e::
//! ```
//!
//! Every check calls the plugin's own code (the ledger reload, the receiver,
//! the Evidence pane builder) on what the two nodes actually wrote. Every
//! mutation happens on a scratch copy; the collected directories are never
//! changed.
//!
//! **The host names the other side** (mesh-llm 0.78 and later): the
//! provider's events carry `requested_by_node_id`, the requester's carry
//! `served_by_node_id`, with matching digests. The script turns record push
//! on at both ends and gives the requester the provider's key, so
//! [`the_host_names_both_sides_and_the_requester_holds_the_providers_record`]
//! checks the confirmed rows on the requester. The provider cannot hold the
//! requester's record: the requester is a client node, whose id is new each
//! time it starts, so no key can be configured for it; that test checks the
//! provider refused it for exactly that reason.
//!
//! Ignored by default: they need the data directories of a real run.

use std::path::{Path, PathBuf};

use capsule_emit_lib::ledger::LedgerError;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use crate::record_push_receive::{
    receive, Receiver, MAX_REJECTED_LOG_BYTES, REASON_MODEL_MISMATCH, REASON_REQUEST_MALFORMED,
    REASON_SERVED_BY_MISMATCH, REASON_SIGNATURE_UNVERIFIED,
};

const NOW: &str = "2026-01-01T00:00:00Z";
const OTHER_WEIGHTS: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// A third node's id, which neither node knows a key for: a relay.
const RELAY_PEER_ID: &str = "relay-node-with-no-announced-key";

/// One node's plugin data directory, as the run left it.
struct Node {
    data_dir: PathBuf,
}

impl Node {
    fn from_env(var: &str) -> Self {
        let dir = std::env::var(var)
            .unwrap_or_else(|_| panic!("{var} must name a node's plugin data directory"));
        let data_dir = PathBuf::from(dir);
        assert!(
            data_dir.join("ledger").join("capsules.jsonl").is_file(),
            "{var}: no ledger/capsules.jsonl under {}",
            data_dir.display()
        );
        Self { data_dir }
    }

    fn ledger_dir(&self) -> PathBuf {
        self.data_dir.join("ledger")
    }

    /// Every line of this node's own chained log, padding included.
    fn ledger_lines(&self) -> Vec<Value> {
        read_jsonl(&self.ledger_dir().join("capsules.jsonl"))
    }

    /// This node's own sealed halves of exchanges with `role`.
    fn halves(&self, role: &str) -> Vec<Value> {
        self.ledger_lines()
            .into_iter()
            .filter(|record| role_of(record) == Some(role))
            .collect()
    }

    fn signing_key(&self) -> SigningKey {
        let pem = std::fs::read_to_string(self.data_dir.join("keys").join("node-key.pem"))
            .expect("the node's signing key");
        capsule_emit_lib::keys::load_signing_key_pem(&pem).expect("parse the node's signing key")
    }

    /// The raw Ed25519 public key, lowercase hex: the `key_id` a record
    /// carries and the value the announced-key map ([`crate::peer_keys`])
    /// gives a peer.
    fn key_id(&self) -> String {
        hex::encode(self.signing_key().verifying_key().to_bytes())
    }

    fn peer_id(&self) -> String {
        let id = std::fs::read_to_string(self.data_dir.join("self-peer-id"))
            .expect("the node wrote its own peer id");
        let id = id.trim().to_string();
        assert!(!id.is_empty(), "empty self-peer-id");
        id
    }

    fn lifecycle_events(&self) -> Vec<Value> {
        read_jsonl(&self.data_dir.join("lifecycle-events.jsonl"))
    }
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("a JSON line"))
        .collect()
}

fn write_jsonl(path: &Path, lines: &[Value]) {
    let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
    std::fs::write(path, text).expect("write a scratch ledger");
}

fn role_of(record: &Value) -> Option<&str> {
    record
        .pointer("/model_attestation/compute_attestation/x-mesh-poc-v1/role")
        .and_then(Value::as_str)
}

fn serving_provenance_mut(record: &mut Value) -> &mut Value {
    record
        .pointer_mut("/model_attestation/compute_attestation/x-mesh-poc-v1/serving_provenance")
        .expect("a mesh half carries serving_provenance")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// A scratch copy of `node`'s ledger directory.
fn scratch_ledger(node: &Node) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_dir(&node.ledger_dir(), dir.path());
    dir
}

/// Give a changed record a fresh `capsule_id` and sign it again with `key`,
/// so it verifies on its own bytes: what the holder of that key can do.
fn reseal(record: &mut Value, key: &SigningKey) {
    let id = capsule_emit_lib::jcs::compute_capsule_id(record).expect("recompute capsule_id");
    record["capsule_id"] = json!(id);
    capsule_emit_lib::capsule::attach_producer_envelope(record, key).expect("sign the record");
}

/// Push `body` from `sender` to the requester, as a scratch copy of its
/// ledger that knows `peer_keys`. Returns the refusal reason, or `None` when
/// the record was received.
fn push_to_requester(
    requester: &Node,
    peer_keys: &str,
    sender: &str,
    body: &Value,
) -> Option<String> {
    let reply = push_reply(requester, peer_keys, sender, body);
    match reply.get("reason").and_then(Value::as_str) {
        Some(reason) => Some(reason.to_string()),
        None => {
            assert_eq!(reply["status"], json!("received"), "reply: {reply}");
            None
        }
    }
}

/// Push a record the requester must refuse as `signature_unverified`, and
/// check the refusal is what #69 asks of one: it names the refused half's
/// key and is signed by the requester's key over its members, that name
/// included.
fn assert_refused_naming_its_key(requester: &Node, peer_keys: &str, sender: &str, body: &Value) {
    let reply = push_reply(requester, peer_keys, sender, body);
    assert_eq!(
        reply["reason"],
        json!(REASON_SIGNATURE_UNVERIFIED),
        "from {sender}: {reply}"
    );
    assert_eq!(
        reply["refused_key_id"], body["key_id"],
        "the refusal names the refused half's key: {reply}"
    );
    assert!(
        crate::evidence_key_acceptance::refusal_verifies(&reply, &requester.key_id()),
        "the refusal is signed by the requester: {reply}"
    );
}

fn push_reply(requester: &Node, peer_keys: &str, sender: &str, body: &Value) -> Value {
    let scratch = scratch_ledger(requester);
    let key = requester.signing_key();
    let node = Receiver {
        ledger_dir: scratch.path(),
        signing_key: &key,
        peer_keys: Some(peer_keys),
        record_at_completion_off: false,
        rejected_log_limit: MAX_REJECTED_LOG_BYTES,
        announced: crate::peer_keys::NONE_ANNOUNCED,
    };
    receive(&node, body.to_string().as_bytes(), Some(sender), NOW)
        .expect("the receiver's own writes succeed")
}

struct Run {
    requester: Node,
    provider: Node,
    exchanges: usize,
}

impl Run {
    fn from_env() -> Self {
        let exchanges = std::env::var("E2E_EXCHANGES")
            .expect("E2E_EXCHANGES must give the number of exchanges the run sent")
            .parse()
            .expect("E2E_EXCHANGES is a count");
        Self {
            requester: Node::from_env("E2E_REQUESTER_DIR"),
            provider: Node::from_env("E2E_PROVIDER_DIR"),
            exchanges,
        }
    }

    /// The provider's announced key, as the requester's operator would
    /// configure it.
    fn peer_keys(&self) -> String {
        json!({ self.provider.peer_id(): self.provider.key_id() }).to_string()
    }

    /// One of the provider's served halves, with a later record chained
    /// after it (so dropping or replacing it breaks a link).
    fn served_half_inside_the_chain(&self) -> (usize, Value) {
        let lines = self.provider.ledger_lines();
        let last_chained = lines
            .iter()
            .rposition(|line| !crate::producer::padding::is_padding(line))
            .expect("the provider's ledger has chained records");
        lines
            .into_iter()
            .enumerate()
            .find(|(at, line)| *at < last_chained && role_of(line) == Some("served"))
            .expect("a served half with a record chained after it")
    }
}

fn open_ledger(dir: &Path) -> Result<usize, LedgerError> {
    crate::producer::index::open_ledger(dir).map(|(_, report)| report.valid_entries)
}

/// Each node sealed its own record of every exchange: the requester one
/// `requested` half per exchange, the provider one `served` half. Both logs
/// reload clean through the ledger's own checks (every `capsule_id`
/// recomputes, the chain is unbroken, every signed statement verifies), and
/// every half verifies offline under its own node's key.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn each_side_sealed_its_own_record_of_every_exchange() {
    let run = Run::from_env();
    for (node, role) in [(&run.requester, "requested"), (&run.provider, "served")] {
        open_ledger(&node.ledger_dir())
            .unwrap_or_else(|error| panic!("{role} side: the ledger does not reload: {error}"));
        let (ledger, _) = crate::producer::index::open_ledger(&node.ledger_dir()).unwrap();
        let key = node.signing_key().verifying_key();
        let key_id = node.key_id();
        let halves = node.halves(role);
        assert!(
            halves.len() >= run.exchanges,
            "{role} side sealed {} halves for {} exchanges",
            halves.len(),
            run.exchanges
        );
        for half in &halves {
            let id = half["capsule_id"].as_str().expect("capsule_id");
            let entry = ledger
                .lookup(id)
                .unwrap()
                .expect("the half is in the ledger");
            let report = capsule_emit_lib::verify::verify_offline(
                &entry.capsule,
                &entry.signed_statement,
                &key,
                None,
            );
            assert!(report.ok(), "{role} half {id}: {:?}", report.findings);
            assert_eq!(
                capsule_emit_lib::cose::verify_producer_envelope(half).as_deref(),
                Ok(key_id.as_str()),
                "{role} half {id} is signed by its own node"
            );
        }
    }
}

/// A record that did not come, unchanged, from the provider's announced key
/// is refused, whatever sender id carries it: the key is the identity and
/// the sender id a hint (D-34). The control first: the provider's real half
/// is received, from the provider and relayed by a third node.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn a_forged_record_is_refused() {
    let run = Run::from_env();
    let keys = run.peer_keys();
    let provider = run.provider.peer_id();
    let relay = RELAY_PEER_ID.to_string();
    let (_, honest) = run.served_half_inside_the_chain();

    assert_eq!(
        push_to_requester(&run.requester, &keys, &provider, &honest),
        None,
        "control: the provider's real half is received"
    );
    assert_eq!(
        push_to_requester(&run.requester, &keys, &relay, &honest),
        None,
        "control: the real half, relayed by a third node with no announced key, is received"
    );

    // Changed after signing: the capsule_id no longer recomputes.
    let mut edited = honest.clone();
    edited["effect"]["response_digest"] = json!(OTHER_WEIGHTS);
    assert_eq!(
        push_to_requester(&run.requester, &keys, &provider, &edited).as_deref(),
        Some(REASON_REQUEST_MALFORMED),
        "a record changed after signing"
    );

    // Changed and signed again by a key the requester does not accept, from
    // the provider's id and from the relay's.
    let mut forged = edited.clone();
    reseal(&mut forged, &SigningKey::from_bytes(&[7; 32]));
    for sender in [&provider, &relay] {
        assert_refused_naming_its_key(&run.requester, &keys, sender, &forged);
    }
}

/// Attack A: tamper with a sealed record in the provider's own log. Changed
/// in place, its `capsule_id` no longer recomputes. Changed and sealed again
/// with the provider's own key (an insider), with a new signed statement,
/// it verifies on its own, but the next record's chain link still names the
/// original.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn attack_a_a_tampered_record_breaks_the_providers_log() {
    let run = Run::from_env();
    let (at, honest) = run.served_half_inside_the_chain();
    let key = run.provider.signing_key();
    let mut lines = run.provider.ledger_lines();

    let naive = scratch_ledger(&run.provider);
    lines[at]["model_attestation"]["compute_attestation"]["agent_output_digest"] =
        json!(OTHER_WEIGHTS);
    write_jsonl(&naive.path().join("capsules.jsonl"), &lines);
    assert!(
        matches!(
            open_ledger(naive.path()),
            Err(LedgerError::CapsuleIdMismatch { .. })
        ),
        "A1: a record changed in place"
    );

    let insider = scratch_ledger(&run.provider);
    reseal(&mut lines[at], &key);
    let id = lines[at]["capsule_id"].as_str().unwrap().to_string();
    assert_ne!(Some(id.as_str()), honest["capsule_id"].as_str());
    let payload = capsule_emit_lib::capsule::payload_bytes(&lines[at]);
    let statement = capsule_emit_lib::cose::build_signed_statement(
        &capsule_emit_lib::cose::SignedStatementInput {
            payload: &payload,
            issuer: &run.provider.key_id(),
            subject: &id,
            content_type: "application/json",
        },
        &key,
    );
    std::fs::write(
        insider
            .path()
            .join("signed-statements")
            .join(format!("{id}.cose")),
        statement,
    )
    .unwrap();
    write_jsonl(&insider.path().join("capsules.jsonl"), &lines);
    assert!(
        matches!(
            open_ledger(insider.path()),
            Err(LedgerError::ChainBroken { .. })
        ),
        "A2: a record replaced by its own key holder"
    );
}

/// Attack B: the provider lies about who served. It changes its own served
/// half to name another node and signs it again with its own (announced)
/// key; the requester refuses it.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn attack_b_a_half_naming_another_server_is_refused() {
    let run = Run::from_env();
    let (_, mut lying) = run.served_half_inside_the_chain();
    serving_provenance_mut(&mut lying)["served_by_node_id"] = json!(run.requester.peer_id());
    reseal(&mut lying, &run.provider.signing_key());
    assert_eq!(
        push_to_requester(
            &run.requester,
            &run.peer_keys(),
            &run.provider.peer_id(),
            &lying
        )
        .as_deref(),
        Some(REASON_SERVED_BY_MISMATCH)
    );
}

/// Attack C: drop one served exchange from the provider's log. The record
/// chained after it names the dropped one, so the log no longer reloads.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn attack_c_a_dropped_record_breaks_the_providers_log() {
    let run = Run::from_env();
    let (at, _) = run.served_half_inside_the_chain();
    let mut lines = run.provider.ledger_lines();
    lines.remove(at);
    let scratch = scratch_ledger(&run.provider);
    write_jsonl(&scratch.path().join("capsules.jsonl"), &lines);
    assert!(matches!(
        open_ledger(scratch.path()),
        Err(LedgerError::ChainBroken { .. })
    ));
}

/// Attack D: the provider claims other model weights. The served half names
/// the weights twice (the producer's `weights_digest` and the host's
/// `serving_provenance.model.weights_digest`); a half that changes one and
/// is signed again with the provider's own key names two models, and is
/// refused.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn attack_d_a_half_naming_other_weights_is_refused() {
    let run = Run::from_env();
    let (_, mut swapped) = run.served_half_inside_the_chain();
    let real = swapped
        .pointer("/model_attestation/compute_attestation/weights_digest/digest")
        .and_then(Value::as_str)
        .expect("the served half names the weights it loaded")
        .to_string();
    assert_ne!(real, OTHER_WEIGHTS);
    serving_provenance_mut(&mut swapped)["model"]["weights_digest"] = json!(OTHER_WEIGHTS);
    reseal(&mut swapped, &run.provider.signing_key());
    assert_eq!(
        push_to_requester(
            &run.requester,
            &run.peer_keys(),
            &run.provider.peer_id(),
            &swapped
        )
        .as_deref(),
        Some(REASON_MODEL_MISMATCH)
    );
}

/// What a run on a host that names the other side holds:
///
/// - the host named both sides: every served event on the provider names the
///   requester (`requested_by_node_id`), every routed event on the requester
///   names the provider (`served_by_node_id`), and the two sides' request and
///   response digests are the same;
/// - the requester holds the provider's record of every exchange, and its
///   Evidence page shows each as confirmed, the digests verified;
/// - the provider holds nothing from the requester: a client node's id is new
///   each start, so no key names it, and every push from it was refused
///   `signature_unverified`;
/// - a provider that lies consistently about its weights is still not caught
///   at receipt: the requester's own half names no weights to compare with.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn the_host_names_both_sides_and_the_requester_holds_the_providers_record() {
    let run = Run::from_env();
    let exchanges = run.exchanges;
    let (requester_id, provider_id) = (run.requester.peer_id(), run.provider.peer_id());
    let terminal = |events: Vec<Value>, path: &str| -> Vec<Value> {
        events
            .into_iter()
            .filter(|e| e["phase"] == json!("terminal") && e["dispatch_path"] == json!(path))
            .collect()
    };
    let served = terminal(run.provider.lifecycle_events(), "raw_proxy");
    let routed = terminal(run.requester.lifecycle_events(), "remote_mesh");
    assert!(served.len() >= exchanges && routed.len() >= exchanges);
    for event in &served {
        assert_eq!(
            event["serving_provenance"]["requested_by_node_id"],
            json!(requester_id),
            "the provider's event names the requester"
        );
    }
    for event in &routed {
        assert_eq!(
            event["serving_provenance"]["served_by_node_id"],
            json!(provider_id),
            "the requester's event names the provider"
        );
    }
    let digests = |events: &[Value]| -> std::collections::BTreeSet<(String, String)> {
        events
            .iter()
            .map(|e| {
                (
                    e["request_digest"].as_str().unwrap_or_default().to_string(),
                    e["response_digest"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                )
            })
            .collect()
    };
    assert_eq!(
        digests(&served),
        digests(&routed),
        "both sides saw the same exchanges"
    );

    // The referee step's two twin halves are held beside the provider's
    // records; everything else held counts.
    let is_twin = |record: &Value| {
        crate::referee::half::served_by(record)
            .is_some_and(|server| crate::referee_e2e_setup::TWINS.contains(&server))
    };
    let (twins, held): (Vec<Value>, Vec<Value>) =
        read_jsonl(&run.requester.ledger_dir().join("received-capsules.jsonl"))
            .into_iter()
            .partition(is_twin);
    assert_eq!(twins.len(), 2, "the requester holds the two twins' halves");
    assert_eq!(
        held.len(),
        exchanges,
        "the requester holds the provider's record of each exchange"
    );
    let pane = crate::evidence_panes::build_pane_json("pane-b", &run.requester.ledger_dir(), None)
        .expect("the requester's peers pane");
    let confirmed: Vec<&Value> = pane["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|row| row["confirmed_siblings"].as_array().into_iter().flatten())
        .collect();
    assert_eq!(
        confirmed.len(),
        exchanges,
        "each exchange is confirmed on the requester's page"
    );
    for sibling in confirmed {
        assert_eq!(
            sibling["digest_match"]["state"],
            json!("verified"),
            "{sibling}"
        );
    }

    assert!(
        read_jsonl(&run.provider.ledger_dir().join("received-capsules.jsonl")).is_empty(),
        "the provider holds nothing from a client node"
    );
    let refused = read_jsonl(
        &run.provider
            .ledger_dir()
            .join(crate::record_push_receive::REJECTED_PUSHES_FILENAME),
    );
    assert_eq!(
        refused.len(),
        exchanges,
        "every push from the requester was refused"
    );
    for line in &refused {
        assert_eq!(line["reason"], json!(REASON_SIGNATURE_UNVERIFIED), "{line}");
        assert_eq!(
            line["claimed_sender_peer_id"],
            json!(requester_id),
            "{line}"
        );
    }

    for half in run.requester.halves("requested") {
        assert!(
            crate::record_push_receive::weights_claims(&half).is_empty(),
            "the requester's own half names weights: a consistent liar can now be caught at receipt; check this note"
        );
    }
}

/// The settlement adapter reads each real ledger through the ledger's own
/// reload, and its denominator is every settlement record on disk. The run
/// is free traffic, so there may be none; then no exchange is reported at
/// all, never one reported "unpaid".
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn the_settlement_adapter_counts_every_settlement_record() {
    let run = Run::from_env();
    for node in [&run.requester, &run.provider] {
        let (ledger, _) = crate::producer::index::open_ledger(&node.ledger_dir()).unwrap();
        let records: Vec<Value> = ledger
            .capsule_ids_in_order()
            .iter()
            .map(|id| ledger.lookup(id).unwrap().expect("listed").capsule)
            .collect();
        let on_disk = node
            .ledger_lines()
            .iter()
            .filter(|line| {
                line.pointer(crate::producer::capsule::SETTLEMENT_BLOCK_POINTER)
                    .is_some()
            })
            .count();
        let report = crate::settlement_adapter::report(records, None);
        assert_eq!(report["settlement_records"], json!(on_disk), "{report:#}");
        assert_eq!(
            report["public_ledger_count"]["status"],
            json!("NOT_CHECKED"),
            "Lightning has no public ledger"
        );
        assert!(
            report["disclosed_count"]["settlements"].as_u64().unwrap() <= on_disk as u64,
            "{report:#}"
        );
        for book in report["exchanges"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|e| e["books"].as_array().unwrap())
        {
            assert!(
                ["PASS", "FAIL", "INCONCLUSIVE"]
                    .contains(&book["settled"]["status"].as_str().unwrap()),
                "{book:#}"
            );
        }
    }
}

/// What `join` returned on the requester, saved by the script as `name`.
fn join_output(name: &str) -> Value {
    let dir =
        std::env::var("E2E_JOIN_DIR").expect("E2E_JOIN_DIR must name the run's output directory");
    let raw = std::fs::read(Path::new(&dir).join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    serde_json::from_slice(&raw).expect("join returns JSON")
}

/// Sherlock2's acceptance of #53: `join` on a fresh node names the missing
/// first checkpoint, and run again after the first exchange it has joined.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn join_on_a_fresh_node_completes_after_its_first_exchange() {
    let before = join_output("join-before.json");
    assert_eq!(before["joined"], false, "{before:#}");
    assert!(
        before["pending"][0]
            .as_str()
            .unwrap_or_default()
            .starts_with("the first checkpoint"),
        "{before:#}"
    );
    let after = join_output("join-after.json");
    assert_eq!(after["joined"], true, "{after:#}");
    assert_eq!(after["pending"], json!([]), "{after:#}");
    assert!(after["commitment"].is_object(), "{after:#}");
    // The switch was on, and the reporter had taken the join by then.
    assert_eq!(after["network"]["switch"], "on", "{after:#}");
    assert_eq!(
        after["network"]["acknowledged"]["kind"], "join/1",
        "{after:#}"
    );
}

/// The switch over the real mesh: on, the requester signed a join and the
/// provider, as the reporter, kept it; off, a leave under the same key.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn the_switch_joins_over_the_mesh_and_off_leaves() {
    use crate::network_join::{self, JOINS_DIR, KIND_JOIN, KIND_LEAVE};
    let run = Run::from_env();
    let (requester_id, provider_id) = (run.requester.peer_id(), run.provider.peer_id());
    let joins = run.provider.data_dir.join(JOINS_DIR);
    let held = |kind: &str| -> Value {
        let path = joins.join(format!("{requester_id}.{kind}.json"));
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("{path:?}: {e}")))
            .unwrap()
    };
    let (join, leave) = (held("join"), held("leave"));
    let now = chrono::Utc::now();
    for (doc, kind) in [(&join, KIND_JOIN), (&leave, KIND_LEAVE)] {
        assert_eq!(
            network_join::problems(doc, now),
            Vec::<String>::new(),
            "{doc:#}"
        );
        assert_eq!(doc["kind"], kind);
        assert_eq!(doc["node_id"], json!(requester_id));
        assert_eq!(doc["key_id"], json!(run.requester.key_id()));
        assert_eq!(doc["consent_sha256"], json!(network_join::consent_sha256()));
    }
    assert!(
        join["at"].as_str() <= leave["at"].as_str(),
        "the leave follows its join"
    );
    // The requester recorded the leave as the reporter's last acknowledgement.
    let acked = network_join::load(&run.requester.data_dir).expect("the requester's join state");
    assert_eq!(acked.record, leave);
    assert!(acked.acknowledged);
    assert_eq!(acked.reporter, provider_id);
    // Nothing else reached the reporter's list.
    assert_eq!(std::fs::read_dir(&joins).unwrap().count(), 2);
}

/// The referee step (`crate::referee_e2e_setup`): the requester put a twin
/// pair to the provider over the mesh, and the provider, as referee, signed
/// the verdict, sealed `adjudication_issued` and delivered the verdict back.
/// Both chains still reload clean, each records the same verdict, the verdict
/// verifies under the provider's key on both nodes, and the requester's own
/// counts (`verdict_counts::fold`, which the admission pack's disputes row
/// reads) carry it for both twins.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn the_referees_verdict_is_sealed_on_both_nodes() {
    use crate::producer::capsule::{ADJUDICATION_ISSUED_BLOCK, ADJUDICATION_RECEIVED_BLOCK};
    use crate::referee_e2e_setup::{TWINS, TWIN_BRACKET_ID};
    let run = Run::from_env();
    let provider_id = run.provider.peer_id();
    let block = |node: &Node, name: &str| -> Value {
        let found: Vec<Value> = node
            .ledger_lines()
            .into_iter()
            .filter_map(|r| {
                r.pointer(&format!("/model_attestation/compute_attestation/{name}"))
                    .cloned()
            })
            .collect();
        assert_eq!(found.len(), 1, "one {name} record: {found:#?}");
        found[0].clone()
    };
    let issued = block(&run.provider, ADJUDICATION_ISSUED_BLOCK);
    let received = block(&run.requester, ADJUDICATION_RECEIVED_BLOCK);
    let verdict_id = issued["verdict_capsule_id"]
        .as_str()
        .expect("the issued verdict's id");
    for (side, record) in [("issued", &issued), ("received", &received)] {
        assert_eq!(
            record["verdict_capsule_id"],
            json!(verdict_id),
            "{side}: {record:#}"
        );
        assert_eq!(
            record["referee_node_id"],
            json!(provider_id),
            "{side}: {record:#}"
        );
        assert_eq!(record["half_node_ids"], json!(TWINS), "{side}: {record:#}");
        assert_eq!(
            record["twin_bracket_id"],
            json!(TWIN_BRACKET_ID),
            "{side}: {record:#}"
        );
    }
    let contradicted = format!(
        "{}{}",
        crate::referee::verdict::VERDICT_CONTRADICTED_PREFIX,
        TWINS[1]
    );
    assert_eq!(
        issued["verdict"],
        json!(contradicted),
        "the referee's answer is twin A's"
    );
    assert_eq!(received["verdict"], issued["verdict"]);
    for (node, role) in [(&run.requester, "requester"), (&run.provider, "provider")] {
        open_ledger(&node.ledger_dir())
            .unwrap_or_else(|error| panic!("{role}: the ledger does not reload: {error}"));
    }

    // The verdict each node holds beside its chain: the referee's signature,
    // under its announced key.
    let keys = run.peer_keys();
    for (node, file) in [
        (
            &run.provider,
            crate::adjudication_records::ISSUED_ADJUDICATIONS_FILENAME,
        ),
        (
            &run.requester,
            crate::adjudication_records::RECEIVED_ADJUDICATIONS_FILENAME,
        ),
    ] {
        let held: Vec<Value> = read_jsonl(&node.ledger_dir().join(file))
            .into_iter()
            .filter(|h| h["verdict_capsule_id"] == json!(verdict_id))
            .collect();
        assert_eq!(held.len(), 1, "{file}: {held:#?}");
        let facts = crate::referee::hold::verdict_facts(&held[0]["verdict_capsule"], Some(&keys))
            .unwrap_or_else(|| {
                panic!("{file}: the verdict does not verify under the referee's key")
            });
        assert_eq!(facts.referee_node_id, provider_id);
        assert_eq!(facts.selection_tier, Some(2));
    }

    // The requester asked for it, so its own counts carry it for each twin.
    let records: Vec<Value> = run.requester.ledger_lines();
    let asked = crate::verdict_counts::read_requested(&run.requester.ledger_dir());
    let by_peer = crate::verdict_counts::fold(&records, &asked);
    // The ruling the admission pack's disputes row reads: twin B contradicted.
    let buckets = [
        crate::verdict_counts::CORROBORATED,
        crate::verdict_counts::CONTRADICTED,
    ];
    for (twin, bucket) in TWINS.into_iter().zip(buckets) {
        let verdicts = by_peer
            .get(twin)
            .unwrap_or_else(|| panic!("no verdict counted for {twin}"));
        assert!(
            verdicts.iter().any(|v| v.verdict_capsule_id == verdict_id
                && v.referee_node_id == provider_id
                && v.bucket == bucket),
            "{twin} is {bucket}: {verdicts:?}"
        );
    }
}

/// evidencebook#47's T1: the corroborator, party to no exchange, asked the
/// requester (X) for its half of the run's first exchange and then the
/// provider (Y) for Y's, each once per run, keyed on the client nonce X's
/// record binds. Declining, Y's outcome is its signed refusal, not an
/// absence; answering, the two halves agree, each verified under its own
/// node's key. Independence is never derived.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn a_third_node_corroborates_an_exchange_with_both_sides() {
    use crate::exchange_corroboration::RUNS_FILENAME;
    let run = Run::from_env();
    let (requester_id, provider_id) = (run.requester.peer_id(), run.provider.peer_id());
    let dir = std::env::var("E2E_CORROBORATOR_DIR")
        .expect("E2E_CORROBORATOR_DIR must name the corroborator's plugin data directory");
    let logged: Vec<Value> = read_jsonl(&Path::new(&dir).join("ledger").join(RUNS_FILENAME))
        .into_iter()
        .map(|line| line["result"].clone())
        .collect();
    let declined = join_output("corroboration-declined.json");
    let agreed = join_output("corroboration-agreed.json");
    assert!(logged.contains(&declined), "the declined run is in Z's log");
    assert_eq!(logged.last(), Some(&agreed), "the agreeing run is Z's last");

    // The key is the nonce X's record binds, and nothing else.
    let x_record = &run.requester.halves("requested")[0];
    let key = crate::evidence_log::client_nonce_digest(x_record).expect("X's half binds a nonce");
    let effect = |record: &Value, member: &str| record["effect"][member].clone();
    let y_record = run
        .provider
        .halves("served")
        .into_iter()
        .find(|r| crate::evidence_log::client_nonce_digest(r).as_deref() == Some(key.as_str()))
        .expect("the provider's half binds the same nonce");

    for result in [&declined, &agreed] {
        assert_eq!(
            result["join_key"],
            json!({"kind": "client_nonce_sha256", "value": key}),
            "{result:#}"
        );
        let x = &result["x"];
        assert_eq!(x["peer_id"], json!(requester_id), "{result:#}");
        assert_eq!(x["outcome"]["state"], "half_obtained", "{result:#}");
        assert_eq!(x["half"]["role"], "requested", "{result:#}");
        for member in ["request_digest", "response_digest"] {
            assert_eq!(x["half"][member], effect(x_record, member), "{result:#}");
        }
        // One entry per Y, and nothing summarized across them.
        let ys = result["ys"].as_array().expect("ys");
        assert_eq!(ys.len(), 1, "{result:#}");
        assert_eq!(
            result.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["join_key", "x", "ys"],
            "{result:#}"
        );
        assert_eq!(ys[0]["peer_id"], json!(provider_id), "{result:#}");
        assert_eq!(ys[0]["frame"], json!({"basis": "x_record_names_y"}));
        assert_eq!(ys[0]["independence"], json!({"state": "not_established"}));
    }

    assert_eq!(
        declined["ys"][0]["outcome"],
        json!({"state": "signed_refusal", "reason": "policy_declined"}),
        "{declined:#}"
    );
    let y = &agreed["ys"][0]["outcome"];
    assert_eq!(y["state"], "agree", "{agreed:#}");
    let y_half = &y["y_half"];
    assert_eq!(y_half["role"], "served", "{agreed:#}");
    assert_eq!(y_half["client_nonce_sha256"], json!(key), "{agreed:#}");
    for member in ["request_digest", "response_digest"] {
        assert!(y_half[member].is_string(), "{agreed:#}");
        assert_eq!(y_half[member], effect(&y_record, member), "{agreed:#}");
        assert_eq!(y_half[member], agreed["x"]["half"][member], "{agreed:#}");
    }
}
