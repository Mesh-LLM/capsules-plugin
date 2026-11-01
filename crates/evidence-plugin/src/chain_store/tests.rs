//! Tests of the chain stores, their lock-free readers and the import of a
//! flat ledger (ledger plan step 6).
//!
//! The flat fixture is written by the flat layout's own code: its lines and
//! statements are a node's sealed records, and its checkpoints are cut by
//! capsule-emit's flat `CheckpointState::load` over that `capsules.jsonl`,
//! as a node on the current release cuts them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;
use crate::capsule_emit::CapsuleState;
use crate::producer::checkpoint::{CheckpointState, WitnessBackfill};

const LOG_ID: &str = "chain-store-test-log";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("chain-store-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn exchange(n: usize) -> (String, String) {
    (
        format!(r#"{{"model":"m","messages":[{{"role":"user","content":"hi {n}"}}]}}"#),
        format!(
            r#"{{"id":"x{n}","choices":[{{"message":{{"role":"assistant","content":"y"}}}}]}}"#
        ),
    )
}

fn seal(state: &CapsuleState, n: usize) -> String {
    let (req, resp) = exchange(n);
    state
        .emit_for_exchange(&crate::capsule_emit::ExchangeRecord {
            model: "m",
            client_nonce: Some("n"),
            request_bytes: req.as_bytes(),
            response_bytes: resp.as_bytes(),
            latency_ms: 1.0,
            exchange_id: None,
            requesting_party: Some("node-b"),
            host_provenance: None,
        })
        .unwrap()
        .capsule_id
}

/// A node's sealed records, padding included: written on the stores of a
/// scratch node, then laid out flat by [`flat_node`].
fn records(dir: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let state = CapsuleState::open(dir, "node-under-test").unwrap();
    seal(&state, 0);
    seal(&state, 1);
    state.pad_ledger_to_bucket(4).unwrap();
    seal(&state, 2);
    seal(&state, 3);
    seal(&state, 4);
    state.pad_ledger_to_bucket(4).unwrap();
    seal(&state, 5);
    let ledger = state.ledger_dir().to_path_buf();
    chain_lines(&ledger)
        .unwrap()
        .into_iter()
        .map(|line| {
            let id = serde_json::from_slice::<Value>(&line).unwrap()["capsule_id"]
                .as_str()
                .unwrap()
                .to_string();
            let statement = statement(&ledger, &id).unwrap();
            (line, statement)
        })
        .collect()
}

/// A data directory in the flat layout an earlier release wrote: its key,
/// `capsules.jsonl` and `signed-statements/`, and the flat checkpoint
/// state's `checkpoints.jsonl` and `mmr_nodes.dat` with a checkpoint cut
/// after each of `cuts` lines, and a witness receipt for the first cut
/// backfilled into `witness-backfill.jsonl`.
fn flat_node(tag: &str, cuts: &[usize]) -> PathBuf {
    let scratch = temp_dir(&format!("{tag}-scratch"));
    let lines = records(&scratch);
    let dir = temp_dir(tag);
    copy_dir(&scratch.join("keys"), &dir.join("keys"));
    let ledger = dir.join("ledger");
    fs::create_dir_all(ledger.join("signed-statements")).unwrap();
    let key = crate::producer::keys::load_or_create(&dir.join("keys"))
        .unwrap()
        .signing_key;
    let mut text = Vec::new();
    for (i, (line, statement)) in lines.iter().enumerate() {
        let id = serde_json::from_slice::<Value>(line).unwrap()["capsule_id"]
            .as_str()
            .unwrap()
            .to_string();
        fs::write(
            ledger.join("signed-statements").join(format!("{id}.cose")),
            statement,
        )
        .unwrap();
        text.extend_from_slice(line);
        text.push(b'\n');
        fs::write(ledger.join(FLAT_CAPSULES_FILE), &text).unwrap();
        if cuts.contains(&(i + 1)) {
            let (mut cp_state, _) =
                CheckpointState::load(&ledger, LOG_ID, CheckpointCadenceConfig::default()).unwrap();
            cp_state
                .reconnect(&key, &crate::checkpoint_cadence::anchor_for())
                .unwrap()
                .expect("a cut");
        }
    }
    // A receipt for the first checkpoint, recorded after it was written.
    let first: Value = serde_json::from_str(
        fs::read_to_string(ledger.join(FLAT_CHECKPOINTS_FILE))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let mut cp: crate::producer::checkpoint::CheckpointRecord =
        serde_json::from_value(first.clone()).unwrap();
    cp.witnesses.clear();
    let entry_hash = hex::encode(Sha256::digest(hex::decode(cp.digest()).unwrap()));
    let backfill = WitnessBackfill {
        mmr_size: cp.mmr_size,
        root: cp.root.clone(),
        witness: crate::producer::checkpoint::CheckpointWitness {
            ts_url: "https://witness.example/ts".into(),
            entry_hash,
            receipt_b64: base64::engine::general_purpose::STANDARD.encode(b"a receipt"),
            leaf_index: 0,
            tree_size: 1,
            is_stub: false,
        },
    };
    fs::write(
        ledger.join("witness-backfill.jsonl"),
        format!("{}\n", serde_json::to_string(&backfill).unwrap()),
    )
    .unwrap();
    let _ = fs::remove_dir_all(&scratch);
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Every file under `dir`, by relative path, with its bytes.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

/// What `ledger-fetch/1` serves for each record (`ledger_fetch_bridge`
/// answers `CapsuleState::lookup` as it is): the capsule's JSON bytes and the
/// signed statement.
type Served = Vec<(String, String, Vec<u8>)>;

fn served_flat(ledger_dir: &Path) -> Served {
    let (ledger, _) =
        Ledger::open_with_indexer(ledger_dir, crate::producer::index::record_index_keys).unwrap();
    ledger
        .lines()
        .iter()
        .filter(|l| !l.padding)
        .map(|l| {
            let entry = ledger.lookup(&l.capsule_id).unwrap().unwrap();
            (
                l.capsule_id.clone(),
                serde_json::to_string(&entry.capsule).unwrap(),
                entry.signed_statement,
            )
        })
        .collect()
}

fn served(state: &CapsuleState, ids: &[String]) -> Served {
    ids.iter()
        .map(|id| {
            let entry = state.lookup(id).unwrap().expect("still served");
            (
                id.clone(),
                serde_json::to_string(&entry.capsule).unwrap(),
                entry.signed_statement,
            )
        })
        .collect()
}

fn root_at(ids: &[String], size: u64) -> String {
    let mut nodes = MemoryNodeStore::new();
    for id in ids {
        let raw: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
        add_leaf(&mut nodes, leaf_hash(&raw)).unwrap();
    }
    let peak_hashes: Vec<_> = peaks(size)
        .unwrap()
        .iter()
        .map(|&p| nodes.node(p))
        .collect();
    hex::encode(root_from_peaks(&peak_hashes))
}

fn ids_of(ledger_dir: &Path) -> Vec<String> {
    chain_lines(ledger_dir)
        .unwrap()
        .iter()
        .map(|l| {
            serde_json::from_slice::<Value>(l).unwrap()["capsule_id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

fn checkpoint_lines_of(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// A fixture node imports: every line moves as stored (the chain's lines are
/// the flat `capsules.jsonl` byte for byte), only the chain's five flat
/// files move to `archive/pre-store/`, and the node's other files stay.
#[test]
fn a_fixture_node_imports_and_only_the_chain_files_move() {
    let dir = flat_node("fixture", &[4, 8]);
    let ledger = dir.join("ledger");
    fs::write(ledger.join("deal-links.jsonl"), b"{}\n").unwrap();
    let flat_text = fs::read(ledger.join(FLAT_CAPSULES_FILE)).unwrap();
    let before = tree(&ledger);

    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    assert_eq!(
        chain_text(&ledger).unwrap().unwrap().as_slice(),
        flat_text.as_slice()
    );
    for name in FLAT_CHAIN_FILES {
        assert!(!ledger.join(name).exists(), "{name} moved");
        assert!(
            dir.join("archive/pre-store").join(name).exists(),
            "{name} kept"
        );
    }
    assert!(!ledger.join(IMPORT_JOURNAL).exists());
    assert!(
        ledger.join("deal-links.jsonl").exists(),
        "the plugin's own files stay"
    );
    // Nothing deleted: every flat byte is in the archive.
    let archived = tree(&dir.join("archive/pre-store"));
    for (path, bytes) in &before {
        if path == Path::new("deal-links.jsonl") {
            continue;
        }
        assert_eq!(
            archived.get(path),
            Some(bytes),
            "{} archived as it was",
            path.display()
        );
    }
    // The node goes on sealing on the stores, chained to the imported head.
    let head = state.chain_head().unwrap();
    let next = seal(&state, 9);
    let line = chain_lines(&ledger).unwrap().pop().unwrap();
    let next_line: Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(next_line["capsule_id"], next.as_str());
    assert_eq!(next_line["chain"]["parent_capsule_id"], head.as_str());
    drop(state);
    // A restart opens the stores, with nothing left to import.
    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    assert_eq!(state.chain_head().as_deref(), Some(next.as_str()));
    let _ = fs::remove_dir_all(&dir);
}

/// Door condition 1: every old checkpoint's root is the root of the new log
/// at its size, and the chain's checkpoints read back as the flat ones (the
/// same records, signatures, statements and receipts).
#[test]
fn old_checkpoint_roots_equal_the_new_logs_roots() {
    let dir = flat_node("roots", &[4, 8]);
    let ledger = dir.join("ledger");
    let flat = flat_checkpoints(&ledger).unwrap();
    assert_eq!(flat.len(), 2);
    let flat_lines =
        checkpoint_lines_of(&fs::read_to_string(ledger.join(FLAT_CHECKPOINTS_FILE)).unwrap());

    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    let ids = ids_of(&ledger);
    for (cp, _) in &flat {
        assert_eq!(root_at(&ids, cp.mmr_size), cp.root, "size {}", cp.mmr_size);
    }
    let stored = checkpoint_lines_of(&checkpoints_string(&ledger));
    assert_eq!(stored.len(), flat_lines.len());
    for ((stored, flat_line), (merged, _)) in stored.iter().zip(&flat_lines).zip(&flat) {
        let mut want = flat_line.clone();
        // The receipt the flat state backfilled is the checkpoint's own here.
        want["witnesses"] = serde_json::to_value(&merged.witnesses).unwrap();
        if merged.witnesses.is_empty() {
            want.as_object_mut().unwrap().remove("witnesses");
        }
        assert_eq!(stored, &want);
        let record: CheckpointRecord = serde_json::from_value(stored.clone()).unwrap();
        assert!(record.verify_signature_offline());
    }
    assert_eq!(
        flat[0].0.witnesses.len(),
        1,
        "the backfilled receipt is a witness row"
    );

    // The checkpoint state loads over the moved log and cuts the next
    // checkpoint chained to the last flat one.
    seal(&state, 9);
    let mut cp_state = load_checkpoint_state(
        state.chain_stores().unwrap(),
        LOG_ID,
        CheckpointCadenceConfig::default(),
        &state.node_signing_keys(),
    )
    .unwrap()
    .0;
    let last = flat.last().unwrap().0.clone();
    assert_eq!(cp_state.last_checkpoint().unwrap().root, last.root);
    let next = cp_state
        .reconnect(
            state.signing_key(),
            &crate::checkpoint_cadence::anchor_for(),
        )
        .unwrap()
        .expect("a cut over the new record");
    assert_eq!(next.prev_size, last.mmr_size);
    assert_eq!(next.prev_root, last.root);
    assert_eq!(checkpoint_lines_of(&checkpoints_string(&ledger)).len(), 3);
    let _ = fs::remove_dir_all(&dir);
}

/// Door condition 1: every record and statement `ledger-fetch/1` returned
/// before the import is returned identically after it.
#[test]
fn ledger_fetch_returns_the_same_records_before_and_after_the_import() {
    let dir = flat_node("fetch", &[4]);
    let before = served_flat(&dir.join("ledger"));
    assert!(before.len() >= 6);
    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    let ids: Vec<String> = before.iter().map(|(id, _, _)| id.clone()).collect();
    assert_eq!(served(&state, &ids), before);
    let _ = fs::remove_dir_all(&dir);
}

/// Door condition 2: an import killed after some appends leaves the flat
/// files where they were, and the next start finishes it: the result is the
/// clean import's.
#[test]
fn an_import_killed_midway_resumes() {
    let dir = flat_node("resume", &[4, 8]);
    let ledger = dir.join("ledger");
    let flat_text = fs::read(ledger.join(FLAT_CAPSULES_FILE)).unwrap();
    let before = served_flat(&ledger);
    let flat_tree: BTreeMap<_, _> = tree(&ledger);

    import_faults::FAIL_AFTER_APPENDS.with(|f| f.set(Some(3)));
    let killed = CapsuleState::open(&dir, "node-under-test");
    import_faults::FAIL_AFTER_APPENDS.with(|f| f.set(None));
    let error = format!("{:#}", killed.err().expect("the import stopped"));
    assert!(error.contains("injected fault"), "{error}");
    assert!(ledger.join(IMPORT_JOURNAL).exists(), "the journal stays");
    for (path, bytes) in &flat_tree {
        assert_eq!(
            fs::read(ledger.join(path)).ok().as_ref(),
            Some(bytes),
            "{} untouched",
            path.display()
        );
    }
    assert!(!dir.join("archive/pre-store").exists());

    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    assert!(!ledger.join(IMPORT_JOURNAL).exists());
    assert_eq!(
        chain_text(&ledger).unwrap().unwrap().as_slice(),
        flat_text.as_slice()
    );
    let ids: Vec<String> = before.iter().map(|(id, _, _)| id.clone()).collect();
    assert_eq!(served(&state, &ids), before);
    assert_eq!(checkpoint_lines_of(&checkpoints_string(&ledger)).len(), 2);
    let _ = fs::remove_dir_all(&dir);
}

/// A start killed after the flat files began to move finishes the move.
#[test]
fn an_import_killed_while_moving_finishes_the_move() {
    let dir = flat_node("moving", &[4]);
    let ledger = dir.join("ledger");
    let flat_text = fs::read(ledger.join(FLAT_CAPSULES_FILE)).unwrap();
    {
        let stores = ChainStores::open(&ledger, LOG_ID, &keys_beside(&ledger)).unwrap();
        write_import_journal(
            &ledger,
            &ImportJournal {
                v: 1,
                phase: "copy".into(),
                started_at: "t".into(),
            },
        )
        .unwrap();
        copy_flat(&ledger, &stores, &keys_beside(&ledger)).unwrap();
        write_import_journal(
            &ledger,
            &ImportJournal {
                v: 1,
                phase: "move".into(),
                started_at: "t".into(),
            },
        )
        .unwrap();
        // Two of the five moved before the stop.
        let archive = dir.join("archive/pre-store");
        fs::create_dir_all(&archive).unwrap();
        for name in &FLAT_CHAIN_FILES[..2] {
            fs::rename(ledger.join(name), archive.join(name)).unwrap();
        }
    }
    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    assert!(!ledger.join(IMPORT_JOURNAL).exists());
    for name in FLAT_CHAIN_FILES {
        assert!(dir.join("archive/pre-store").join(name).exists(), "{name}");
    }
    assert_eq!(
        chain_text(&ledger).unwrap().unwrap().as_slice(),
        flat_text.as_slice()
    );
    drop(state);
    let _ = fs::remove_dir_all(&dir);
}

/// Door condition 2: stores that do not match the flat ledger refuse the
/// start, saying why, and nothing is deleted or moved.
#[test]
fn a_mismatch_refuses_to_start_and_deletes_nothing() {
    // The chain log already holds another node's record at line 1.
    let dir = flat_node("mismatch", &[4]);
    let ledger = dir.join("ledger");
    let other = temp_dir("mismatch-other");
    {
        let state = CapsuleState::open(&other, "node-under-test").unwrap();
        seal(&state, 42);
    }
    // The other node's shelf, closed, so its WAL is folded back in.
    fs::copy(
        other.join("ledger").join(SHELF_FILE),
        ledger.join(SHELF_FILE),
    )
    .unwrap();
    copy_dir(&other.join("keys"), &dir.join("keys"));
    let before = tree(&dir);
    let error = format!(
        "{:#}",
        CapsuleState::open(&dir, "node-under-test")
            .err()
            .expect("refused")
    );
    assert!(
        error.contains("cannot move onto the chain stores"),
        "{error}"
    );
    assert!(error.contains("Nothing was deleted"), "{error}");
    let after = tree(&dir);
    for (path, bytes) in &before {
        assert_eq!(after.get(path), Some(bytes), "{} kept", path.display());
    }
    assert!(!dir.join("archive").exists(), "nothing moved");
    let _ = fs::remove_dir_all(&other);
    let _ = fs::remove_dir_all(&dir);

    // A checkpoint whose root is not the log's root at its size.
    let dir = flat_node("mismatch-root", &[4]);
    let ledger = dir.join("ledger");
    let text = fs::read_to_string(ledger.join(FLAT_CHECKPOINTS_FILE)).unwrap();
    let mut line: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    line["root"] = Value::String("00".repeat(32));
    fs::write(ledger.join(FLAT_CHECKPOINTS_FILE), format!("{line}\n")).unwrap();
    let flat = tree(&ledger);
    let error = format!(
        "{:#}",
        CapsuleState::open(&dir, "node-under-test")
            .err()
            .expect("refused")
    );
    assert!(error.contains("root"), "{error}");
    for (path, bytes) in &flat {
        assert_eq!(fs::read(ledger.join(path)).ok().as_ref(), Some(bytes));
    }
    assert!(!dir.join("archive").exists());
    let _ = fs::remove_dir_all(&dir);
}

/// The kind of owner-maintenance record every release up to 0.1.8 sealed
/// after `head`: `approver: "owner"`, which fails AAC Class 1 as
/// `approver_invalid` (#208), with its producer envelope and statement.
fn old_owner_record(head: &str, key: &ed25519_dalek::SigningKey) -> (Value, Vec<u8>) {
    use crate::producer::capsule::{
        attach_producer_envelope, payload_bytes, seal_owner_maintenance_record, Disposer,
        OwnerMaintenance,
    };
    let action = OwnerMaintenance {
        kind: "index_rebuilt",
        facts: serde_json::Map::new(),
        prior_history_head: None,
        disposer: Disposer::Person,
    };
    let sealed = seal_owner_maintenance_record(&action, Some(head), key).unwrap();
    let mut body = sealed.as_object().unwrap().clone();
    for member in ["capsule_id", "signature", "key_id"] {
        body.remove(member);
    }
    body["disposition"]["approver"] = Value::String("owner".into());
    let mut capsule = capsule_emit_lib::capsule::finish_seal(body).unwrap();
    attach_producer_envelope(&mut capsule, key).unwrap();
    let id = capsule["capsule_id"].as_str().unwrap().to_string();
    let statement = crate::producer::cose::build_signed_statement(
        &crate::producer::cose::SignedStatementInput {
            payload: &payload_bytes(&capsule),
            issuer: "node-under-test",
            subject: &id,
            content_type: "application/vnd.agent-action-capsule+json",
        },
        key,
    );
    (capsule, statement)
}

/// A node whose flat history holds an owner-maintenance record that fails
/// Class 1 only as `approver_invalid` stays on the flat ledger, its files
/// untouched, serving the same records; the owner's actions there seal
/// records that pass Class 1; and its next history opens on the stores.
#[test]
fn a_node_with_an_old_owner_record_stays_flat_until_a_new_history() {
    use crate::owner_maintenance::{
        finish_pending_after_open, is_archived, resolve_log_id, Maintenance, StartNewHistoryArgs,
    };
    let dir = flat_node("stays-flat", &[4]);
    let ledger = dir.join("ledger");
    let key = crate::producer::keys::load_or_create(&dir.join("keys"))
        .unwrap()
        .signing_key;
    {
        let (mut flat, _) =
            Ledger::open_with_indexer(&ledger, crate::producer::index::record_index_keys).unwrap();
        let head = flat.chain_head().unwrap().to_string();
        let (capsule, statement) = old_owner_record(&head, &key);
        flat.append(&capsule, &statement).unwrap();
    }
    let reason = stays_flat(&ledger).unwrap().expect("it stays flat");
    assert!(reason.contains("approver_invalid"), "{reason}");
    let before_files = tree(&ledger);
    let before = served_flat(&ledger);
    let ids: Vec<String> = before.iter().map(|(id, _, _)| id.clone()).collect();

    let key_id = hex::encode(key.verifying_key().to_bytes());
    let log_id = resolve_log_id(&dir, "node-under-test", "old-shared", &key_id, None).unwrap();
    let state = Arc::new(CapsuleState::open(&dir, "node-under-test").unwrap());
    assert!(state.chain_stores().is_none());
    assert!(!ledger.join(SHELF_FILE).exists());
    assert_eq!(tree(&ledger), before_files, "the flat files are untouched");
    assert_eq!(served(&state, &ids), before);
    // The flat checkpoint state, as today.
    let (cp_state, _) = state
        .load_checkpoint_state(LOG_ID, CheckpointCadenceConfig::default())
        .unwrap();
    assert!(cp_state.last_checkpoint().is_some());
    drop(cp_state);

    // An owner action on the flat node seals a record that passes Class 1.
    let maintenance = Maintenance::new(dir.clone(), state.clone(), log_id.clone());
    maintenance.rebuild_index().unwrap();
    let last: Value =
        serde_json::from_slice(&chain_lines(&ledger).unwrap().pop().unwrap()).unwrap();
    assert_eq!(last["disposition"]["approver"], "human");
    maintenance
        .start_new_history(StartNewHistoryArgs { confirm: true })
        .unwrap();
    drop(maintenance);
    drop(state);

    let log_id = resolve_log_id(&dir, "node-under-test", "old-shared", &key_id, None).unwrap();
    assert!(log_id.ends_with("/h2"), "{log_id}");
    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    finish_pending_after_open(&dir, &state, &log_id).unwrap();
    assert!(
        state.chain_stores().is_some(),
        "the new history is on the stores"
    );
    assert!(ledger.join(SHELF_FILE).exists());
    assert!(dir.join("archive/1").join(FLAT_CAPSULES_FILE).exists());
    assert!(
        !dir.join("archive").join(PRE_STORE_ARCHIVE).exists(),
        "nothing imported"
    );
    let first: Value = serde_json::from_slice(&chain_lines(&ledger).unwrap()[0]).unwrap();
    assert_eq!(first["disposition"]["approver"], "human");
    assert!(ids.iter().all(|id| is_archived(&dir, id)));
    let _ = fs::remove_dir_all(&dir);
}

/// The first new history after an import is `/h2`: `pre-store/` is no
/// archive slot. Before it, no imported record reads as archived; after it,
/// the earlier history's records do.
#[test]
fn the_first_new_history_after_an_import_is_h2() {
    use crate::owner_maintenance::{
        finish_pending_after_open, is_archived, resolve_log_id, Maintenance, StartNewHistoryArgs,
    };
    let dir = flat_node("history", &[4]);
    let ids = ids_of(&dir.join("ledger"));
    let key_id = crate::producer::keys::load_or_create(&dir.join("keys"))
        .unwrap()
        .key_id();
    let log_id = resolve_log_id(&dir, "node-under-test", "old-shared", &key_id, None).unwrap();
    let state = Arc::new(CapsuleState::open(&dir, "node-under-test").unwrap());
    assert!(dir.join("archive/pre-store/capsules.jsonl").exists());
    assert!(
        ids.iter().all(|id| !is_archived(&dir, id)),
        "the current history"
    );
    Maintenance::new(dir.clone(), state.clone(), log_id.clone())
        .start_new_history(StartNewHistoryArgs { confirm: true })
        .unwrap();
    drop(state);

    let log_id = resolve_log_id(&dir, "node-under-test", "old-shared", &key_id, None).unwrap();
    assert!(log_id.ends_with("/h2"), "{log_id}");
    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    finish_pending_after_open(&dir, &state, &log_id).unwrap();
    assert!(dir.join("archive/1").join(SHELF_FILE).exists());
    assert!(
        ids.iter().all(|id| is_archived(&dir, id)),
        "an earlier history now"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The readers serve a node on the stores: the chain's lines are the kept
/// `Ledger`'s lines, and a checkpoint the cadence cuts reads back signed,
/// with its own statement.
#[test]
fn the_readers_serve_the_lines_and_checkpoints_of_a_node_on_the_stores() {
    let dir = temp_dir("readers");
    let state = CapsuleState::open(&dir, "node-under-test").unwrap();
    let ledger = state.ledger_dir().to_path_buf();
    assert!(chain_lines(&ledger).unwrap().is_empty());
    assert_eq!(checkpoints_string(&ledger), "");
    let a = seal(&state, 0);
    let b = seal(&state, 1);
    let lines = chain_lines(&ledger).unwrap();
    assert_eq!(ids_of(&ledger), vec![a.clone(), b.clone()]);
    let (ledger_view, _) = state.chain_stores().unwrap().open_ledger().unwrap();
    for (line, l) in lines.iter().zip(ledger_view.lines()) {
        let read = serde_json::to_vec(&ledger_view.read_line(l.offset).unwrap()).unwrap();
        assert_eq!(line, &read);
    }
    drop(ledger_view);
    assert_eq!(
        statement(&ledger, &a),
        Some(state.lookup(&a).unwrap().unwrap().signed_statement)
    );
    let mut cp_state = load_checkpoint_state(
        state.chain_stores().unwrap(),
        LOG_ID,
        CheckpointCadenceConfig::default(),
        &state.node_signing_keys(),
    )
    .unwrap()
    .0;
    let cut = cp_state
        .reconnect(
            state.signing_key(),
            &crate::checkpoint_cadence::anchor_for(),
        )
        .unwrap()
        .unwrap();
    let stored = checkpoint_lines_of(&checkpoints_string(&ledger));
    let [line] = stored.as_slice() else {
        panic!("one checkpoint: {stored:?}");
    };
    let record: CheckpointRecord = serde_json::from_value(line.clone()).unwrap();
    assert_eq!(record.signature, cut.signature, "the record first cut");
    assert!(record.verify_signature_offline());
    let cose = hex::decode(line["checkpoint_cose"].as_str().unwrap()).unwrap();
    assert!(crate::evidence_log::states(&cose, &record));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn chain_lines_selects_an_inclusive_range_of_leaf_indices() {
    assert_eq!(select(0, None, None), Ok(None));
    assert_eq!(select(5, None, None), Ok(Some((0, 4))));
    assert_eq!(select(5, Some(2), None), Ok(Some((2, 4))));
    assert_eq!(select(5, None, Some(1)), Ok(Some((0, 1))));
    assert_eq!(select(5, Some(3), Some(3)), Ok(Some((3, 3))));
    assert!(select(5, Some(3), Some(2)).is_err());
    assert!(select(5, None, Some(5)).is_err());
    assert!(select(0, Some(0), None).is_err());
    let usage = |args: &[&str]| cli(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>());
    assert_eq!(usage(&["--from"]), 2);
    assert_eq!(usage(&["--to", "x"]), 2);
    assert_eq!(usage(&["--bogus"]), 2);
    let dir = temp_dir("cli");
    let dir_arg = dir.display().to_string();
    assert_eq!(usage(&["--data-dir", &dir_arg]), 0, "an empty chain");
    assert_eq!(usage(&["--data-dir", &dir_arg, "--to", "0"]), 2);
    let _ = fs::remove_dir_all(&dir);
}

/// Nodes written by earlier releases' own code import (the per-release
/// check): `CAPSULES_RELEASE_NODES` names a directory holding, per release
/// tag, the data directories that release wrote. Each is copied, imported,
/// and checked as the fixture is: the chain's lines are the flat file's,
/// `ledger-fetch/1` serves the same records, and every checkpoint's root is
/// the new log's. Prints one line per node and fails on any node that does
/// not import.
#[test]
#[ignore = "needs CAPSULES_RELEASE_NODES: data directories written by each release tag"]
fn nodes_written_by_each_release_import() {
    let root =
        PathBuf::from(std::env::var("CAPSULES_RELEASE_NODES").expect("CAPSULES_RELEASE_NODES"));
    let mut failed = Vec::new();
    let mut tags: Vec<PathBuf> = fs::read_dir(&root)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    tags.sort();
    for tag in tags {
        let mut nodes = Vec::new();
        find_nodes(&tag, &mut nodes);
        nodes.sort();
        let (mut ok, mut lines, mut cps, mut corrupt) = (0usize, 0usize, 0usize, 0usize);
        let mut stayed_flat = 0usize;
        let mut reasons: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for node in &nodes {
            let copy = temp_dir("release-node");
            copy_dir(node, &copy);
            let ledger = copy.join("ledger");
            let flat_text = fs::read(ledger.join(FLAT_CAPSULES_FILE)).unwrap();
            let complete = flat_text
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |i| i + 1);
            let flat_cps = flat_checkpoints(&ledger).unwrap_or_default();
            let before = std::panic::catch_unwind(|| served_flat(&ledger));
            let node_key = crate::producer::keys::load_or_create(&copy.join("keys"))
                .ok()
                .map(|k| hex::encode(k.signing_key.verifying_key().to_bytes()));
            let Some(node_key) = node_key.filter(|_| before.is_ok()) else {
                // A test's unreadable key or ledger: no node's history.
                corrupt += 1;
                let _ = fs::remove_dir_all(&copy);
                continue;
            };
            if flat_cps.iter().any(|(cp, _)| cp.key_id != node_key) {
                // A test's deliberately corrupt ledger, which the release
                // itself refuses to open, or a test's checkpoint cut under
                // another key than the node's: no node's history.
                corrupt += 1;
                let _ = fs::remove_dir_all(&copy);
                continue;
            }
            let flat = stays_flat(&ledger).unwrap().is_some();
            let result = CapsuleState::open(&copy, "release-node");
            let outcome = match (&result, &before) {
                (Err(e), _) => Err(format!("{e:#}")),
                (Ok(_), Err(_)) => Err("the flat ledger does not open".into()),
                (Ok(state), Ok(before)) if flat => {
                    let ids: Vec<String> = before.iter().map(|(id, _, _)| id.clone()).collect();
                    if is_store_layout(&ledger) || state.chain_stores().is_some() {
                        Err("a node that stays flat opened the stores".into())
                    } else if fs::read(ledger.join(FLAT_CAPSULES_FILE)).unwrap() != flat_text {
                        Err("the flat capsules.jsonl changed".into())
                    } else if served(state, &ids) != *before {
                        Err("ledger-fetch/1 serves other records".into())
                    } else {
                        stayed_flat += 1;
                        Ok(())
                    }
                }
                (Ok(state), Ok(before)) => {
                    let ids: Vec<String> = before.iter().map(|(id, _, _)| id.clone()).collect();
                    let new_ids = ids_of(&ledger);
                    if chain_text(&ledger).unwrap().unwrap().as_slice() != &flat_text[..complete] {
                        Err("the chain's lines are not the flat file's".into())
                    } else if served(state, &ids) != *before {
                        Err("ledger-fetch/1 serves other records".into())
                    } else if let Some((cp, _)) = flat_cps
                        .iter()
                        .find(|(cp, _)| root_at(&new_ids, cp.mmr_size) != cp.root)
                    {
                        Err(format!("checkpoint {} has another root", cp.mmr_size))
                    } else {
                        Ok(())
                    }
                }
            };
            let rel = node.strip_prefix(&root).unwrap().display().to_string();
            match outcome {
                Ok(()) => {
                    ok += 1;
                    lines += flat_text[..complete]
                        .iter()
                        .filter(|&&b| b == b'\n')
                        .count();
                    cps += flat_cps.len();
                }
                Err(why) => {
                    // Group by the reason without the record ids in it.
                    let key: String = why
                        .split_whitespace()
                        .map(|w| {
                            if w.len() >= 32 && w.chars().all(|c| c.is_ascii_hexdigit()) {
                                "<id>"
                            } else {
                                w
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    reasons.entry(key).or_default().push(rel.clone());
                    failed.push(format!("{rel}: {why}"));
                }
            }
            drop(result);
            let _ = fs::remove_dir_all(&copy);
        }
        println!(
            "{}: {ok}/{} nodes passed ({} imported: {lines} lines, {cps} checkpoints; \
             {stayed_flat} stayed flat, serving the same records); {corrupt} skipped: test \
             fixtures with a ledger or key the release itself refuses, or a checkpoint cut under \
             another key",
            tag.file_name().unwrap().to_string_lossy(),
            nodes.len() - corrupt,
            ok - stayed_flat
        );
        for (why, nodes) in &reasons {
            println!("  {} nodes: {why}\n    e.g. {}", nodes.len(), nodes[0]);
        }
    }
    assert!(
        failed.is_empty(),
        "{} nodes did not import:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

/// The data directories under `dir`: each holding `ledger/capsules.jsonl`
/// and `keys/node-key.pem`.
fn find_nodes(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join("ledger").join(FLAT_CAPSULES_FILE).is_file()
        && dir.join("keys/node-key.pem").is_file()
    {
        out.push(dir.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            find_nodes(&entry.path(), out);
        }
    }
}

/// Change one byte of the first stored record's capsule in the shelf under
/// `ledger_dir`, in place, as a tamper on disk would.
pub(crate) fn tamper_first_record(ledger_dir: &Path) {
    let conn = rusqlite::Connection::open(ledger_dir.join(SHELF_FILE)).unwrap();
    let (id, mut bytes): (String, Vec<u8>) = conn
        .query_row(
            "SELECT capsule_id, capsule_bytes FROM capsule_store_capsules ORDER BY rowid LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let at = bytes.len() / 2;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    conn.execute(
        "UPDATE capsule_store_capsules SET capsule_bytes=? WHERE capsule_id=?",
        rusqlite::params![bytes, id],
    )
    .unwrap();
}

/// While this lives, the shelf under its ledger directory refuses every new
/// record (a trigger aborts the insert), so a seal fails as a full or broken
/// disk would make it.
pub(crate) struct RefuseRecords(rusqlite::Connection);

pub(crate) fn refuse_records(ledger_dir: &Path) -> RefuseRecords {
    let conn = rusqlite::Connection::open(ledger_dir.join(SHELF_FILE)).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER refuse_records BEFORE INSERT ON capsule_store_capsules \
         BEGIN SELECT RAISE(ABORT, 'refused by the test'); END",
    )
    .unwrap();
    RefuseRecords(conn)
}

impl Drop for RefuseRecords {
    fn drop(&mut self) {
        self.0.execute_batch("DROP TRIGGER refuse_records").unwrap();
    }
}

/// Cut a checkpoint of the chain `state` keeps, as the cadence does on a
/// reconnect.
fn cut(state: &CapsuleState) -> crate::producer::checkpoint::CheckpointRecord {
    let mut cp_state = load_checkpoint_state(
        state.chain_stores().unwrap(),
        LOG_ID,
        CheckpointCadenceConfig::default(),
        &state.node_signing_keys(),
    )
    .unwrap()
    .0;
    cp_state
        .reconnect(
            state.signing_key(),
            &crate::checkpoint_cadence::anchor_for(),
        )
        .unwrap()
        .expect("a cut")
}

/// CLL's SQLite backend keeps only the latest checkpoint; the shelf's
/// history keeps every one the chain committed, linked from the first, and
/// a history row a crash left out (the latest) is added again on the next
/// open.
#[test]
fn the_shelf_keeps_every_checkpoint_and_restores_a_lost_latest_row() {
    let dir = temp_dir("history");
    let ledger = dir.join("ledger");
    let (first, second) = {
        let state = CapsuleState::open(&dir, "node-under-test").unwrap();
        seal(&state, 0);
        let first = cut(&state);
        seal(&state, 1);
        seal(&state, 2);
        let second = cut(&state);
        (first, second)
    };
    let read = |ledger: &Path| -> Vec<crate::producer::checkpoint::CheckpointRecord> {
        checkpoint_lines_of(&checkpoints_string(ledger))
            .into_iter()
            .map(|line| serde_json::from_value(line).unwrap())
            .collect()
    };
    let held = read(&ledger);
    assert_eq!(held.len(), 2, "{held:?}");
    assert_eq!(held[0].mmr_size, first.mmr_size);
    assert_eq!((held[0].prev_size, held[0].prev_root.as_str()), (0, ""));
    assert_eq!(held[1].mmr_size, second.mmr_size);
    assert_eq!(
        (held[1].prev_size, held[1].prev_root.as_str()),
        (first.mmr_size, first.root.as_str())
    );
    // CLL itself holds only the latest.
    let conn = rusqlite::Connection::open(ledger.join(SHELF_FILE)).unwrap();
    let log_id = chain_log_id(&conn).unwrap().unwrap();
    let latest = LogSqlite::open(ledger.join(SHELF_FILE), &log_id)
        .unwrap()
        .load_cll()
        .unwrap()
        .checkpoint
        .unwrap();
    assert_eq!(latest.size, second.mmr_size);

    // A crash between CLL's commit and the history row.
    conn.execute(
        &format!("DELETE FROM {HISTORY_TABLE} WHERE size=?"),
        [second.mmr_size as i64],
    )
    .unwrap();
    drop(conn);
    assert_eq!(read(&ledger).len(), 1);
    drop(CapsuleState::open(&dir, "node-under-test").unwrap());
    let restored = read(&ledger);
    assert_eq!(
        restored.iter().map(|c| c.mmr_size).collect::<Vec<_>>(),
        vec![first.mmr_size, second.mmr_size]
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A reader opened on a shelf that is then moved away (a new history moves
/// the whole `ledger/`) reads the new shelf, not the moved one.
#[test]
fn a_reader_follows_a_new_shelf_at_the_same_path() {
    let dir = temp_dir("reader-moved");
    let ledger = dir.join("ledger");
    {
        let state = CapsuleState::open(&dir, "node-under-test").unwrap();
        seal(&state, 0);
        seal(&state, 1);
    }
    assert_eq!(chain_lines(&ledger).unwrap().len(), 2);
    let archived = dir.join("archived-ledger");
    fs::rename(&ledger, &archived).unwrap();
    {
        let state = CapsuleState::open(&dir, "node-under-test").unwrap();
        seal(&state, 7);
    }
    let lines = chain_lines(&ledger).unwrap();
    assert_eq!(lines.len(), 1, "the new shelf's chain only");
    assert_eq!(chain_lines(&archived).unwrap().len(), 2);
    let _ = fs::remove_dir_all(&dir);
}
