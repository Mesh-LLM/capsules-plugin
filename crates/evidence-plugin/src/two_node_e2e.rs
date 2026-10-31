//! Tier 2: the checks run over a real two-node run.
//!
//! `scripts/e2e-two-node.sh` starts two unmodified `mesh-llm` nodes on one
//! machine, each running this plugin: the provider serves a small model, the
//! requester serves nothing and sends its chat completions to the provider
//! over the mesh. After both nodes have stopped, the script copies each
//! node's plugin data directory and runs these tests over the copies:
//!
//! ```sh
//! E2E_REQUESTER_DIR=<copy> E2E_PROVIDER_DIR=<copy> E2E_EXCHANGES=<n> \
//!   E2E_JOIN_DIR=<run dir> E2E_UNANSWERED_PEER=<id> CAPSULES_TEST_PERIOD_LENGTH_S=120 \
//!   cargo test --locked --bin capsules --features test-period-policy -- \
//!   --ignored --test-threads=1 two_node_e2e::
//! ```
//!
//! With the run's two-minute Service History definition, as the nodes had it.
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
        let report = crate::settlement_adapter::report(records, None, None);
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

/// The controller binding step (`crate::controller_binding_e2e_setup`): the
/// provider's `join`, through its ceremony, signed its own half, took the
/// event the operator's Nostr key signed, stored the binding and reported it
/// `bound`, refused a binding of another node's key, and
/// the commitment the requester fetched over the mesh names the binding by
/// its digest alone, never the Nostr key.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn the_providers_binding_is_held_bound_and_named_by_its_digest() {
    let run = Run::from_env();
    let binding = crate::controller_binding::read_held(&run.provider.data_dir)
        .expect("the provider holds a binding");
    let digest = crate::controller_binding::evaluate(&binding, &[])
        .digest
        .expect("the binding has a digest");
    let nostr = crate::controller_binding_e2e_setup::nostr_key();
    let nostr = hex::encode(nostr.verifying_key().to_bytes());

    let begun = join_output("binding-begin.json");
    assert_eq!(
        begun["controller_binding_ceremony"]["event"]["content"],
        json!(format!("controller-binding/0:{digest}")),
        "the operator signed the record the provider holds"
    );
    assert!(
        !run.provider
            .data_dir
            .join(crate::controller_binding::PENDING_FILE)
            .exists(),
        "the ceremony finished"
    );
    let joined = join_output("binding-join.json");
    let finding = joined["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["check"] == crate::doctor::CONTROLLER_BINDING)
        .unwrap();
    assert_eq!(finding["state"], crate::doctor::STATE_BOUND, "{finding:#}");
    assert_eq!(finding["records"], json!([digest]));

    let refused = std::fs::read_to_string(
        Path::new(&std::env::var("E2E_JOIN_DIR").unwrap()).join("binding-refused.json"),
    )
    .unwrap();
    assert!(
        refused.contains("does not bind this node's key"),
        "{refused}"
    );

    let fetched = join_output("fetched-commitment.json");
    assert_eq!(fetched["problems"], json!([]), "{fetched:#}");
    assert_eq!(
        fetched["commitment"]["controller_binding"],
        json!({ "digest": digest })
    );
    for out in [&fetched, &joined] {
        assert!(
            !out.to_string().contains(&nostr),
            "the Nostr key is never shown"
        );
    }
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

/// The requester's book of asks (`crate::ask_book`), in ledger order: each
/// record's id and its entry.
fn asks(node: &Node) -> Vec<(String, Value)> {
    node.ledger_lines()
        .into_iter()
        .filter_map(|r| {
            let entry = r
                .pointer("/model_attestation/compute_attestation")?
                .get(crate::ask_book::BLOCK)?
                .clone();
            Some((r["capsule_id"].as_str()?.to_string(), entry))
        })
        .collect()
}

fn cites(entry: &Value, request_id: &str) -> bool {
    entry["links"].as_array().is_some_and(|links| {
        links
            .iter()
            .any(|l| l["type"] == "cites" && l["target"] == request_id)
    })
}

/// Loop step 7, Ask. The history card ask was sealed as `evidence_request`
/// before its answer, with the provider's commitment the requester held: the request record comes first in the requester's
/// chain, and the response citing it verified as an artifact the provider
/// signed for exactly the sealed request's digest, so the bytes sent were
/// the bytes sealed. The ask nobody answered ended in a `recorded_absence`
/// citing its request, its window at least the minimum long.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn each_ask_is_sealed_before_it_is_sent_and_an_unanswered_one_ends_in_absence() {
    use sha2::Digest as _;
    let run = Run::from_env();
    let provider_id = run.provider.peer_id();
    let book = asks(&run.requester);
    let digest = |request: &Value| {
        hex::encode(sha2::Sha256::digest(
            evidence_request::jcs::to_string(request).expect("JCS"),
        ))
    };

    let answered = book.iter().enumerate().find_map(|(at, (id, entry))| {
        let statement = &entry["statement"];
        if entry["record_type"] != "evidence_request"
            || statement["responder_ref"] != json!(provider_id)
            || statement["request"]["derivation"] != "history_card/1"
        {
            return None;
        }
        let (after, (_, response)) = book
            .iter()
            .enumerate()
            .find(|(_, (_, r))| r["record_type"] == "evidence_response" && cites(r, id))?;
        (response["statement"]["outcome"] == "artifact").then_some((at, after, entry, response))
    });
    let (at, after, request, response) = answered.unwrap_or_else(|| {
        panic!("no history card ask to the provider answered with an artifact: {book:#?}")
    });
    assert!(at < after, "the request record comes before its response");
    assert_eq!(
        response["statement"]["request_digest"],
        json!(digest(&request["statement"]["request"])),
        "the answer is to the request as sealed"
    );
    assert_eq!(response["statement"]["verification"]["state"], "artifact");
    let pinned = &request["statement"]["commitment"];
    assert_eq!(
        pinned["policy_digest"].as_str().map(str::len),
        Some(64),
        "the ask recorded the provider's commitment it held: {pinned:#}"
    );
    assert!(pinned["policy"]["stranger_safe"].is_array(), "{pinned:#}");

    let unanswered = std::env::var("E2E_UNANSWERED_PEER")
        .expect("E2E_UNANSWERED_PEER must name the peer the run asked and nobody answered for");
    let (request_id, request) = book
        .iter()
        .find(|(_, e)| {
            e["record_type"] == "evidence_request"
                && e["statement"]["responder_ref"] == json!(unanswered)
        })
        .expect("the unanswered ask was sealed");
    let outcomes: Vec<&Value> = book
        .iter()
        .map(|(_, e)| e)
        .filter(|e| cites(e, request_id))
        .collect();
    assert_eq!(outcomes.len(), 1, "one outcome: {outcomes:#?}");
    let absence = outcomes[0];
    assert_eq!(absence["record_type"], "recorded_absence");
    let statement = &absence["statement"];
    assert_eq!(statement["outcome"], "recorded_absence");
    assert_eq!(
        statement["request_digest"],
        json!(digest(&request["statement"]["request"]))
    );
    let time = |v: &Value| {
        chrono::DateTime::parse_from_rfc3339(v.as_str().expect("a time")).expect("RFC 3339")
    };
    let (opened, closed) = (
        time(&statement["window"]["opened"]),
        time(&statement["window"]["closed"]),
    );
    assert!(
        (closed - opened).num_seconds() >= evidencebook::ask::MINIMUM_ABSENCE_WINDOW_SECONDS,
        "{statement:#}"
    );
    assert!(time(&statement["recorded_at"]) >= closed, "{statement:#}");
    open_ledger(&run.requester.ledger_dir()).expect("the requester's ledger reloads");
}

/// What a node's `history-page` route served while the run was live, saved by
/// the script as `history-page-<name>.json` (Mesh-LLM/capsules-plugin#122),
/// and its `reply` parsed.
fn history_page(name: &str) -> (Value, Value) {
    let page = join_output(&format!("history-page-{name}.json"));
    let reply = serde_json::from_str(page["reply"].as_str().expect("`reply` is text"))
        .unwrap_or_else(|e| panic!("history-page-{name}: `reply` is not JSON: {e}"));
    (page, reply)
}

/// The `history-page` route on live nodes gave each node's own answer under
/// its own key: the requester, before its first checkpoint, a refusal it
/// signed for the stranger's history card request, and later the card; the
/// provider, which shares its Service History, that History. The History page
/// built from each `reply` and opened offline is checked by
/// `web-ui/src/features/capsules/lib/history-page.e2e.test.ts`, which the
/// script runs next. This checks what that page does not: that each reply
/// verifies under that node's own key for the request the route made (the
/// stranger's card request; for the Service History, the request pinned to
/// the anchor the reply names), signatures included. The Service History is
/// checked against the run's two-minute definition, so this runs in a build
/// with the `test-period-policy` feature, as the script runs it.
#[test]
#[ignore = "needs the data directories of a real two-node run (scripts/e2e-two-node.sh)"]
fn the_history_page_route_served_each_nodes_own_answer() {
    let run = Run::from_env();
    let (_, card_request) = crate::doctor::probe_requests()
        .into_iter()
        .find(|(name, _)| *name == crate::doctor::PROBE_HISTORY_CARD)
        .expect("doctor asks for the history card");
    let no_witness_keys = std::collections::BTreeMap::new();
    let verified_for = |request: &[u8], reply: &Value, node: &Node| {
        crate::evidence_answer::verify_response(
            request,
            reply,
            &node.signing_key().verifying_key(),
            &no_witness_keys,
        )
    };
    let verified = |reply: &Value, node: &Node| verified_for(&card_request, reply, node);

    let (fresh, refusal) = history_page("fresh");
    assert_eq!(fresh["form"], crate::history_page::FORM_HISTORY_CARD);
    assert_eq!(fresh["outcome"], "refused", "{fresh:#}");
    assert_eq!(fresh["node_key_id"], json!(run.requester.key_id()));
    let check = verified(&refusal, &run.requester);
    assert_eq!(check["state"], "refusal", "{check:#}");

    let (card_page, card) = history_page("requester");
    assert_eq!(card_page["form"], crate::history_page::FORM_HISTORY_CARD);
    assert_eq!(card_page["outcome"], "answered", "{card_page:#}");
    assert_eq!(card_page["node_key_id"], json!(run.requester.key_id()));
    assert_eq!(card["responder"], card_page["node_key_id"]);
    let check = verified(&card, &run.requester);
    assert_eq!(check["state"], "artifact", "{check:#}");

    let (service_page, service_history) = history_page("provider");
    assert_eq!(
        service_page["form"],
        crate::history_page::FORM_SERVICE_HISTORY
    );
    assert_eq!(service_page["outcome"], "answered", "{service_page:#}");
    assert_eq!(service_page["node_key_id"], json!(run.provider.key_id()));
    assert_eq!(service_history["responder"], service_page["node_key_id"]);
    // The request the route asked of the provider's responder
    // (`history_page::serve`), pinned to the anchor it answered at: the one
    // the reply names, not whichever boundary checkpoint is latest now.
    assert_eq!(
        service_history["derivation"],
        json!(crate::service_history::definition_digest()),
        "the provider's Service History is the run's definition (run with the \
         test-period-policy feature and CAPSULES_TEST_PERIOD_LENGTH_S)"
    );
    let pin = service_history["anchor"]["digest"]
        .as_str()
        .expect("the Service History names its anchor");
    let service_request = serde_json::to_vec(&json!({
        "profile": evidence_request::envelope::PROFILE,
        "subject": {"full_history": null},
        "coverage": {"expected_pin": pin},
        "derivation": crate::service_history::definition_digest(),
    }))
    .unwrap();
    let check = verified_for(&service_request, &service_history, &run.provider);
    assert_eq!(check["state"], "artifact", "{check:#}");
}
