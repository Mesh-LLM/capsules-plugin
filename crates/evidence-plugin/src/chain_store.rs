//! Where this node's chain is kept: one host log on the node's EvidenceBook
//! shelf, `ledger/shelf.db` (evidencebook `docs/design/254-shelf.md` §7). The
//! file holds the chain's Checkpointed Local Log (CLL's SQLite tables: each
//! line's `capsule_id` in log order, the MMR nodes, the current checkpoint and
//! the witness rows) and capsule-emit's SQLite artifact store under the
//! namespace [`NAMESPACE`] (each line as a record: the line without its
//! inline `signature`/`key_id`, its producer envelope, and its signed
//! statement). capsule-emit's [`Ledger`] (`Ledger::open_stores_with_indexer`)
//! and checkpoint state (`CheckpointState::load_log`) run on them.
//!
//! **Checkpoint history.** CLL's SQLite backend keeps only the latest
//! checkpoint, and the chain's readers need every one from the first (the
//! evidence index's checkpoint chain, the Evidence pages, `witness_status`).
//! So the chain's log is wrapped in [`ChainLog`], which records every
//! checkpoint the backend commits in the host table [`HISTORY_TABLE`] beside
//! CLL's (§2.2: host tables live beside the shelf's).
//!
//! **One writer, readers without the lock.** The writer is this process,
//! under the data directory's lock (`data_dir::lock`), which is the shelf's
//! writer lock too: the shelf takes none of its own on a host-held lock
//! (§2.4). In this process the stores are opened once, by
//! [`ChainStores::open`], and the node's [`Ledger`] and checkpoint state share
//! them. Every other reader (the Evidence pages, the evidence responder's
//! index, `capsules chain-lines` in another process) reads the file through
//! its own SQLite connections, which WAL lets run beside the writer without
//! any lock: [`chain_text`] gives the chain's lines in today's
//! `capsules.jsonl` line format (the kept `Ledger` lines: the stored record
//! with `signature` and `key_id` put back, padding included), and
//! [`checkpoints_text`] the chain's checkpoints in today's `checkpoints.jsonl`
//! line format. Nothing here keeps a second copy: both are read from the
//! file on demand.
//!
//! **Either layout.** A ledger directory that holds no `shelf.db` is read in
//! the flat layout (`capsules.jsonl`, `checkpoints.jsonl`), as an archived
//! history from before the shelf, or a node not yet imported, is.
//!
//! **Import.** A node written by an earlier release keeps its chain in the flat
//! layout. [`import_flat`] moves it onto the shelf on the first start of this
//! one, journalled and resumable, and archives only the chain's flat files to
//! `archive/pre-store/` (see the function).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use capsule_emit_artifact::{Record, Store};
use cll::checkpoint::{
    try_sign_checkpoint_digest, verify_checkpoint_cose_offline, CheckpointRecord,
    WitnessRecord as CheckpointWitness,
};
use cll::log::sqlite::SqliteStore as LogSqlite;
use cll::log::{
    AppendInput, AppendOutcome, AppendResult, CheckpointState as LogCheckpointState,
    CheckpointStateStore, Entry, EntrySource, EntryStore, State as LogState, StateAppend,
    Timestamp, WitnessReceiptState, WitnessState, WitnessStateStore, MAX_SCAN_LIMIT,
};
use cll::mmr::{
    add_leaf, leaf_count, leaf_hash, peaks, root_from_peaks, MemoryNodeStore, NodeReader,
};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::producer::checkpoint::{CheckpointCadenceConfig, CheckpointLog, CheckpointSigner};
use crate::producer::ledger::{Ledger, LedgerError, RecoveryReport};

/// The node's shelf: the chain's log, its records and its checkpoint history.
pub const SHELF_FILE: &str = "shelf.db";
/// The shelf's artifact store namespace (a host parameter, §2.5).
pub const NAMESPACE: &str = "chain";
/// The host table that keeps every checkpoint the chain's log committed, in
/// size order (see the module docs).
pub const HISTORY_TABLE: &str = "chain_checkpoints";
/// The flat layout's chain: one JSON record per line.
pub const FLAT_CAPSULES_FILE: &str = "capsules.jsonl";
/// The flat layout's checkpoints: one checkpoint record per line, with its
/// `checkpoint_cose`.
pub const FLAT_CHECKPOINTS_FILE: &str = "checkpoints.jsonl";
/// The flat layout's chain files, as [`import_flat`] archives them:
/// `capsules.jsonl` last, so its presence alone says the move is not done.
pub const FLAT_CHAIN_FILES: [&str; 5] = [
    "signed-statements",
    FLAT_CHECKPOINTS_FILE,
    "mmr_nodes.dat",
    "witness-backfill.jsonl",
    FLAT_CAPSULES_FILE,
];
/// The import's journal, beside the shelf while an import runs.
pub const IMPORT_JOURNAL: &str = "import-pending.json";
/// Where an import keeps the flat files it moved, under the data directory's
/// `archive/`. Not numeric, so it is never an archive slot of an earlier
/// history (`owner_maintenance::next_archive_slot`).
pub const PRE_STORE_ARCHIVE: &str = "pre-store";

/// How long one connection waits for another's write (the shelf's busy
/// timeout, §2.2).
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5000);

/// Whether `ledger_dir` keeps its chain on the shelf: it has one, and no
/// import onto it is unfinished. While an import runs, or after one was
/// refused, the flat `capsules.jsonl` still holds the whole chain and the
/// shelf only part of it, so readers read the flat files.
pub fn is_store_layout(ledger_dir: &Path) -> bool {
    ledger_dir.join(SHELF_FILE).exists()
        && !ledger_dir.join(FLAT_CAPSULES_FILE).exists()
        && !ledger_dir.join(IMPORT_JOURNAL).exists()
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The node's signing keys under `keys_dir`: `node-key.pem`, then every key
/// `keys::rotate` archived (`archive/node-key.<key_id>.pem`). The artifact
/// store trusts each one's public key, and a stored checkpoint signed under
/// any of them loads.
pub fn node_signing_keys(keys_dir: &Path) -> Vec<SigningKey> {
    let read = |path: &Path| {
        fs::read_to_string(path)
            .ok()
            .and_then(|pem| crate::producer::keys::load_signing_key_pem(&pem).ok())
    };
    let mut keys: Vec<SigningKey> = read(&keys_dir.join("node-key.pem")).into_iter().collect();
    if let Ok(archived) = fs::read_dir(keys_dir.join("archive")) {
        let mut paths: Vec<PathBuf> = archived
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    n.starts_with("node-key.") && n.ends_with(".pem") && !n.ends_with(".pub.pem")
                })
            })
            .collect();
        paths.sort();
        keys.extend(paths.iter().filter_map(|p| read(p)));
    }
    keys
}

/// The keys of the node whose ledger directory is `ledger_dir`: at
/// `<data dir>/keys` for its `<data dir>/ledger`, and for an archived history
/// `<data dir>/archive/<slot>`.
pub(crate) fn keys_beside(ledger_dir: &Path) -> Vec<SigningKey> {
    #[allow(unused_mut)]
    let mut keys = ledger_dir
        .ancestors()
        .skip(1)
        .take(2)
        .map(|dir| dir.join("keys"))
        .find(|keys| keys.join("node-key.pem").exists())
        .map(|keys| node_signing_keys(&keys))
        .unwrap_or_default();
    // The fixed keys tests seal with when a test node keeps no key on disk.
    #[cfg(test)]
    for seed in [3u8, 9u8] {
        keys.push(SigningKey::from_bytes(&[seed; 32]));
    }
    keys
}

fn trusted(keys: &[SigningKey]) -> Vec<[u8; 32]> {
    keys.iter().map(|k| k.verifying_key().to_bytes()).collect()
}

// ---------------------------------------------------------------------------
// The shelf file
// ---------------------------------------------------------------------------

/// A connection to the shelf at `path` with the shelf's settings (§2.2):
/// WAL, a 5000 ms busy timeout, `synchronous=FULL`, foreign keys on.
/// `create` makes the file when it is absent.
fn connect(path: &Path, create: bool) -> io::Result<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let conn = Connection::open_with_flags(path, flags).map_err(other)?;
    conn.busy_timeout(BUSY_TIMEOUT).map_err(other)?;
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL")
        .map_err(other)?;
    if create {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(other)?;
    }
    Ok(conn)
}

/// The id of the one CLL log the shelf at `path` holds, `None` when it holds
/// none yet. The node's shelf holds exactly one: its chain (§7.1).
fn chain_log_id(conn: &Connection) -> io::Result<Option<String>> {
    let has_meta: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cll_meta'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(other)?
        > 0;
    if !has_meta {
        return Ok(None);
    }
    let mut statement = conn
        .prepare("SELECT log_id FROM cll_meta ORDER BY log_id")
        .map_err(other)?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(other)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(other)?;
    match ids.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(id.clone())),
        _ => Err(other(format!(
            "the shelf holds {} logs ({}); a node's shelf holds only its chain",
            ids.len(),
            ids.join(", ")
        ))),
    }
}

fn history_schema(conn: &Connection) -> io::Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {HISTORY_TABLE} (
  log_id TEXT NOT NULL,
  size INTEGER NOT NULL,
  checkpoint BLOB NOT NULL,
  PRIMARY KEY(log_id, size)
)"
    ))
    .map_err(other)
}

/// Every checkpoint the history holds for `log_id`, in size order. A shelf
/// without the table holds none.
fn history(conn: &Connection, log_id: &str) -> io::Result<Vec<Vec<u8>>> {
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
            [HISTORY_TABLE],
            |row| row.get(0),
        )
        .map_err(other)?;
    if exists == 0 {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(&format!(
            "SELECT checkpoint FROM {HISTORY_TABLE} WHERE log_id=? ORDER BY size"
        ))
        .map_err(other)?;
    let rows = statement
        .query_map([log_id], |row| row.get::<_, Vec<u8>>(0))
        .map_err(other)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(other);
    rows
}

// ---------------------------------------------------------------------------
// The chain's log: CLL's SQLite backend, recording every checkpoint
// ---------------------------------------------------------------------------

/// The chain's CLL log on the shelf, as capsule-emit's [`Ledger`] and
/// checkpoint state use it: CLL's SQLite backend, unchanged, plus the
/// checkpoint history. After each commit that leaves a checkpoint, that
/// checkpoint is added to [`HISTORY_TABLE`] (an identical row again is a
/// no-op). The row is a second write after CLL's own transaction, so a crash
/// between them leaves the latest checkpoint out; [`ChainLog::open`] and the
/// next commit add it first, and since commits are sequential no checkpoint
/// but the latest can ever be missing.
pub struct ChainLog {
    log: Arc<LogSqlite>,
    history: Mutex<Connection>,
    log_id: String,
    /// A commit succeeded but its history row did not: added before the next
    /// commit.
    behind: AtomicBool,
    /// The shelf the chain is a host log of, open while this lives; `None`
    /// for a shelf this process does not hold (an archived history read
    /// back), which is opened as it is: no schema, history or shelf rows are
    /// written to it.
    _shelf: Option<evidencebook::shelf::Shelf>,
}

impl std::fmt::Debug for ChainLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainLog")
            .field("log_id", &self.log_id)
            .finish_non_exhaustive()
    }
}

impl ChainLog {
    /// `log` is the chain's CLL log on the shelf at `path`.
    fn open(
        path: &Path,
        log: Arc<LogSqlite>,
        log_id: &str,
        shelf: Option<evidencebook::shelf::Shelf>,
    ) -> anyhow::Result<Self> {
        let history = connect(path, false)?;
        // Only the shelf's writer adds to it; an unheld shelf is read as it is.
        let writer = shelf.is_some();
        if writer {
            history_schema(&history)?;
        }
        let chain = Self {
            log,
            history: Mutex::new(history),
            log_id: log_id.to_owned(),
            behind: AtomicBool::new(writer),
            _shelf: shelf,
        };
        chain.catch_up()?;
        Ok(chain)
    }

    fn record(&self, checkpoint: &LogCheckpointState) -> io::Result<()> {
        let conn = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        conn.execute(
            &format!("INSERT OR IGNORE INTO {HISTORY_TABLE}(log_id,size,checkpoint) VALUES(?,?,?)"),
            params![self.log_id, checkpoint.size as i64, checkpoint.bytes],
        )
        .map_err(other)?;
        let held: Option<Vec<u8>> = conn
            .query_row(
                &format!("SELECT checkpoint FROM {HISTORY_TABLE} WHERE log_id=? AND size=?"),
                params![self.log_id, checkpoint.size as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(other)?;
        if held.as_deref() != Some(checkpoint.bytes.as_slice()) {
            return Err(other(format!(
                "{HISTORY_TABLE} holds another checkpoint at size {}",
                checkpoint.size
            )));
        }
        Ok(())
    }

    /// Add the stored checkpoint to the history if a commit left it out.
    fn catch_up(&self) -> io::Result<()> {
        if !self.behind.load(Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(checkpoint) = self.log.load_cll().map_err(other)?.checkpoint {
            self.record(&checkpoint)?;
        }
        self.behind.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// After a commit that succeeded: record its checkpoint, or remember to.
    fn committed(&self, checkpoint: Option<&LogCheckpointState>) {
        if let Some(checkpoint) = checkpoint {
            if let Err(error) = self.record(checkpoint) {
                tracing::warn!(%error, size = checkpoint.size, "the chain's checkpoint history is behind; it is added before the next commit");
                self.behind.store(true, Ordering::SeqCst);
            }
        }
    }

    fn before_commit(&self) -> cll::log::Result<()> {
        self.catch_up()
            .map_err(|e| cll::log::Error::with_source(cll::log::ErrorCode::Storage, "history", e))
    }
}

impl EntrySource for ChainLog {
    fn scan_entries(&self, after_seq: u64, limit: usize) -> cll::log::Result<Vec<Entry>> {
        self.log.scan_entries(after_seq, limit)
    }
}

impl cll::log::EntryCounter for ChainLog {
    fn entry_count(&self) -> cll::log::Result<u64> {
        self.log.entry_count()
    }
}

impl EntryStore for ChainLog {
    fn append(&self, input: &AppendInput) -> cll::log::Result<AppendResult> {
        self.log.append(input)
    }

    fn get_entry(&self, value: &[u8]) -> cll::log::Result<Entry> {
        self.log.get_entry(value)
    }
}

impl CheckpointStateStore for ChainLog {
    fn load_cll(&self) -> cll::log::Result<LogState> {
        self.log.load_cll()
    }

    fn commit_cll(
        &self,
        expected_size: u64,
        expected_checkpoint: Option<&[u8]>,
        next: &LogState,
    ) -> cll::log::Result<()> {
        self.before_commit()?;
        self.log
            .commit_cll(expected_size, expected_checkpoint, next)?;
        self.committed(next.checkpoint.as_ref());
        Ok(())
    }

    fn append_cll(
        &self,
        expected_size: u64,
        expected_checkpoint: Option<&[u8]>,
        update: &StateAppend,
    ) -> cll::log::Result<()> {
        self.before_commit()?;
        self.log
            .append_cll(expected_size, expected_checkpoint, update)?;
        self.committed(update.checkpoint.as_ref());
        Ok(())
    }
}

impl WitnessStateStore for ChainLog {
    fn pending_witnesses(
        &self,
        now: Timestamp,
        limit: usize,
    ) -> cll::log::Result<Vec<WitnessState>> {
        self.log.pending_witnesses(now, limit)
    }

    fn get_witness(
        &self,
        witness_id: &str,
        checkpoint_size: u64,
    ) -> cll::log::Result<Option<WitnessState>> {
        self.log.get_witness(witness_id, checkpoint_size)
    }

    fn commit_witness(&self, expected_attempts: u32, next: &WitnessState) -> cll::log::Result<()> {
        self.log.commit_witness(expected_attempts, next)
    }
}

// ---------------------------------------------------------------------------
// The writer's stores
// ---------------------------------------------------------------------------

/// The chain's two stores on the shelf, opened once per process: the node's
/// [`Ledger`] and its checkpoint state share them.
#[derive(Clone)]
pub struct ChainStores {
    log: Arc<ChainLog>,
    artifacts: Arc<capsule_emit_artifact::sqlite::SqliteStore>,
}

/// The data directory's writer lock, as the shelf asks for it (§2.4): held
/// while this process holds the `DataDirLock` covering the ledger directory.
struct HeldLedger(PathBuf);

impl evidencebook::shelf::HeldLock for HeldLedger {
    fn held(&self) -> Result<(), String> {
        if crate::data_dir::holds_ledger(&self.0) {
            Ok(())
        } else {
            Err(format!(
                "this process does not hold the writer lock of {}",
                self.0.display()
            ))
        }
    }
}

impl std::fmt::Debug for ChainStores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainStores")
            .field("log", &self.log)
            .finish_non_exhaustive()
    }
}

/// The stores this process holds open, by ledger directory: a second open of
/// a directory whose stores are live shares them, since the [`Ledger`] keeps
/// its index in memory and two handles on one log could give two records one
/// position (§2.3).
type OpenStores = (
    std::sync::Weak<ChainLog>,
    std::sync::Weak<capsule_emit_artifact::sqlite::SqliteStore>,
);
static OPEN: Mutex<Option<HashMap<PathBuf, OpenStores>>> = Mutex::new(None);

impl ChainStores {
    /// Provision (first start) or open the shelf under `ledger_dir`, the
    /// artifact store trusting `keys`. The caller holds the data directory's
    /// writer lock (`data_dir::lock`), which the shelf takes as its own
    /// (§2.4). A shelf that already holds the chain's log opens it under its
    /// id; a new one starts it under `log_id`, the node's log id. In this
    /// process a second open shares these stores.
    pub fn open(ledger_dir: &Path, log_id: &str, keys: &[SigningKey]) -> anyhow::Result<Self> {
        let mut open = OPEN.lock().unwrap_or_else(PoisonError::into_inner);
        let open = open.get_or_insert_with(HashMap::new);
        open.retain(|_, (log, artifacts)| log.strong_count() > 0 && artifacts.strong_count() > 0);
        // Keyed by the directory as it really is, so every spelling of one
        // ledger shares one set of stores.
        fs::create_dir_all(ledger_dir)?;
        let key = fs::canonicalize(ledger_dir)?;
        if let Some((log, artifacts)) = open.get(&key) {
            if let (Some(log), Some(artifacts)) = (log.upgrade(), artifacts.upgrade()) {
                return Ok(Self { log, artifacts });
            }
        }
        let stores = Self::open_new(ledger_dir, log_id, keys)?;
        open.insert(
            key,
            (
                Arc::downgrade(&stores.log),
                Arc::downgrade(&stores.artifacts),
            ),
        );
        Ok(stores)
    }

    fn open_new(ledger_dir: &Path, log_id: &str, keys: &[SigningKey]) -> anyhow::Result<Self> {
        fs::create_dir_all(ledger_dir)?;
        let path = ledger_dir.join(SHELF_FILE);
        // The node's own shelf, on the data directory's lock; anything else is
        // read as it is.
        let held = crate::data_dir::holds_ledger(ledger_dir);
        if !held && !path.exists() {
            anyhow::bail!(
                "{} holds no chain, and this process does not hold its lock to start one",
                path.display()
            );
        }
        let conn =
            connect(&path, held).map_err(|e| anyhow::anyhow!("shelf {}: {e}", path.display()))?;
        let held_id = chain_log_id(&conn)?;
        if let Some(held) = held_id.as_deref().filter(|held| *held != log_id) {
            tracing::info!(
                held,
                log_id,
                "the shelf keeps the chain under the id it was started with"
            );
        }
        let log_id = held_id.as_deref().unwrap_or(log_id);
        let artifacts = Arc::new(
            capsule_emit_artifact::sqlite::SqliteStore::new(conn, NAMESPACE, trusted(keys))
                .map_err(|e| anyhow::anyhow!("chain records {}: {e}", path.display()))?,
        );
        if held {
            artifacts
                .init()
                .map_err(|e| anyhow::anyhow!("chain records {}: {e}", path.display()))?;
        }
        let (shelf, log) = if held {
            // The node's own shelf, on the data directory's lock: the chain
            // is its one host log, outside any cadence (§7.1).
            let key = keys
                .first()
                .ok_or_else(|| anyhow::anyhow!("no node key to open the shelf with"))?
                .clone();
            let shelf = evidencebook::shelf::Shelf::open_sqlite(evidencebook::shelf::ShelfConfig {
                path: path.clone(),
                lock_path: None,
                held_lock: Some(Box::new(HeldLedger(ledger_dir.to_path_buf()))),
                lock_timeout: None,
                random: None,
                operator: "capsules".into(),
                developer: String::new(),
                signer: Arc::new(key.clone()),
                checkpoint_key: key,
                originals: artifacts.clone(),
                now: None,
                authenticated_indexes: None,
                // A host log carries no book headers to correlate.
                correlation_members: Vec::new(),
            })
            .map_err(|e| anyhow::anyhow!("shelf {}: {e}", path.display()))?;
            let stores = shelf
                .host_log(log_id, false)
                .and_then(|host| host.stores())
                .map_err(|e| anyhow::anyhow!("chain log {}: {e}", path.display()))?;
            (Some(shelf), stores.log)
        } else {
            // A ledger this process holds no lock on (an archived history
            // read back): its shelf as it is, never provisioned.
            if held_id.is_none() {
                anyhow::bail!(
                    "{} holds no chain, and this process does not hold its lock to start one",
                    path.display()
                );
            }
            let log = LogSqlite::open(&path, log_id)
                .map_err(|e| anyhow::anyhow!("chain log {}: {e}", path.display()))?;
            (None, Arc::new(log))
        };
        Ok(Self {
            log: Arc::new(ChainLog::open(&path, log, log_id, shelf)?),
            artifacts,
        })
    }

    /// The chain as capsule-emit's [`Ledger`] over these stores, under this
    /// plugin's index (`producer::index::record_index_keys`).
    pub fn open_ledger(&self) -> Result<(Ledger, RecoveryReport), LedgerError> {
        Ledger::open_stores_with_indexer(
            self.log.clone(),
            self.artifacts.clone(),
            crate::producer::index::record_index_keys,
        )
    }

    /// The CLL backend the checkpoint state is kept in: the chain's log.
    pub fn checkpoint_log(&self) -> Arc<dyn CheckpointLog> {
        self.log.clone()
    }
}

/// The checkpoint state over `stores`, as the cadence loads it: every key in
/// `keys` may have signed the stored checkpoint.
pub fn load_checkpoint_state(
    stores: &ChainStores,
    log_id: impl Into<String>,
    cfg: CheckpointCadenceConfig,
    keys: &[SigningKey],
) -> Result<
    (
        crate::producer::checkpoint::CheckpointState,
        crate::producer::checkpoint::LoadReport,
    ),
    crate::producer::checkpoint::CheckpointStateError,
> {
    let signers: Vec<&dyn CheckpointSigner> =
        keys.iter().map(|k| k as &dyn CheckpointSigner).collect();
    crate::producer::checkpoint::CheckpointState::load_log(
        stores.checkpoint_log(),
        log_id,
        cfg,
        &signers,
    )
}

// ---------------------------------------------------------------------------
// Readers (no lock)
// ---------------------------------------------------------------------------

/// The line of a stored record, as the kept `Ledger` reads it back
/// (`Ledger::read_line`): the record's capsule with `signature` (the producer
/// envelope, hex) and `key_id` (its signer, hex) put back.
pub fn line_of(record: &Record) -> io::Result<Vec<u8>> {
    let mut parsed = crate::producer::jcs::decode_record(&record.capsule).map_err(other)?;
    let envelope =
        agent_action_capsule::envelope::verify(&record.capsule_id, &record.producer_envelope);
    let object = parsed
        .as_object_mut()
        .ok_or_else(|| other("a stored record is not a JSON object"))?;
    object.insert(
        "signature".into(),
        Value::String(hex::encode(&record.producer_envelope)),
    );
    object.insert(
        "key_id".into(),
        Value::String(hex::encode(&envelope.public_key)),
    );
    serde_json::to_vec(&parsed).map_err(other)
}

fn b64(text: &str) -> io::Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(other)
}

/// A reader's view of one shelf, opened for one read: its own connections,
/// so it never waits on the writer (WAL) and never holds a file the writer
/// has since moved (a new history moves the whole `ledger/`).
struct ShelfView {
    log: LogSqlite,
    artifacts: capsule_emit_artifact::sqlite::SqliteStore,
    history: Connection,
    log_id: String,
}

impl ShelfView {
    /// `None` when the shelf holds no chain yet.
    fn open(ledger_dir: &Path) -> io::Result<Option<Self>> {
        let path = ledger_dir.join(SHELF_FILE);
        let conn = connect(&path, false)?;
        let Some(log_id) = chain_log_id(&conn)? else {
            return Ok(None);
        };
        let log = LogSqlite::open(&path, &log_id).map_err(other)?;
        let keys = keys_beside(ledger_dir);
        let artifacts = capsule_emit_artifact::sqlite::SqliteStore::new(
            connect(&path, false)?,
            NAMESPACE,
            trusted(&keys),
        )
        .map_err(|e| {
            other(format!(
                "the shelf's record store needs the node's keys: {e}"
            ))
        })?;
        Ok(Some(Self {
            log,
            artifacts,
            history: conn,
            log_id,
        }))
    }
}

/// What a reader has taken from one ledger directory's shelf so far.
#[derive(Default)]
struct Snapshot {
    /// The log's entries, in order.
    ids: Vec<String>,
    /// The chain's lines, each with its `\n`, for `ids`.
    text: Arc<Vec<u8>>,
}

impl Snapshot {
    /// Bring this up to date with the shelf under `ledger_dir`. A shelf whose
    /// log no longer starts with what this holds (a new history) is read
    /// again from the start.
    fn refresh(&mut self, view: &ShelfView) -> io::Result<()> {
        if let Some(last) = self.ids.last() {
            let held = view
                .log
                .scan_entries(self.ids.len() as u64 - 1, 1)
                .map_err(other)?;
            let first = view.log.scan_entries(0, 1).map_err(other)?;
            let same = |entries: &[Entry], id: &str| {
                entries.first().is_some_and(|e| hex::encode(&e.value) == id)
            };
            if !same(&held, last) || !same(&first, &self.ids[0]) {
                *self = Snapshot::default();
            }
        }
        // An entry is appended only after its record is stored, so every
        // entry read here has its record.
        loop {
            let page = view
                .log
                .scan_entries(self.ids.len() as u64, MAX_SCAN_LIMIT)
                .map_err(other)?;
            if page.is_empty() {
                break;
            }
            let text = Arc::make_mut(&mut self.text);
            for entry in page {
                if entry.seq != self.ids.len() as u64 + 1 {
                    return Err(other(format!(
                        "the chain log gives entry {} after {}",
                        entry.seq,
                        self.ids.len()
                    )));
                }
                let id = hex::encode(&entry.value);
                let record = view.artifacts.get(&id).map_err(|e| {
                    other(format!(
                        "the chain log names {id} but the shelf holds no readable record of it: {e}"
                    ))
                })?;
                text.extend_from_slice(&line_of(&record)?);
                text.push(b'\n');
                self.ids.push(id);
            }
        }
        Ok(())
    }
}

/// The checkpoint lines, as `checkpoints.jsonl` holds them: each recorded
/// checkpoint (its JSON signature made again with the key that signed its
/// COSE, which is deterministic Ed25519, so it is the record first cut), its
/// witnesses from the rows with a receipt, and its `checkpoint_cose`.
fn checkpoint_lines(view: &ShelfView, keys: &[SigningKey]) -> io::Result<Vec<Value>> {
    let checkpoints = history(&view.history, &view.log_id)?;
    let rows = view.log.load_cll().map_err(other)?.witnesses;
    let mut lines = Vec::new();
    for cose in &checkpoints {
        let verified = verify_checkpoint_cose_offline(cose);
        let Some(decoded) = verified.decoded else {
            tracing::warn!(
                log_id = view.log_id,
                "a checkpoint in the chain's history does not decode; it is left out"
            );
            continue;
        };
        let mut record = decoded.to_checkpoint_record();
        if let Some(key) = keys
            .iter()
            .find(|k| hex::encode(k.verifying_key().to_bytes()) == record.key_id)
        {
            if let Ok(signature) = try_sign_checkpoint_digest(&record, key) {
                record.signature = signature;
            }
        }
        record.witnesses = rows
            .iter()
            .filter(|r| r.checkpoint_size == record.mmr_size)
            .filter_map(|r| {
                let receipt = r.receipt.as_ref()?;
                Some(CheckpointWitness {
                    ts_url: r.witness_id.clone(),
                    entry_hash: receipt.entry_hash.clone().unwrap_or_default(),
                    receipt_b64: {
                        use base64::Engine as _;
                        base64::engine::general_purpose::STANDARD.encode(&receipt.bytes)
                    },
                    leaf_index: receipt.leaf_index.unwrap_or_default(),
                    tree_size: receipt.tree_size.unwrap_or_default(),
                    is_stub: false,
                })
            })
            .collect();
        let Ok(mut line) = serde_json::to_value(&record) else {
            continue;
        };
        line["checkpoint_cose"] = Value::String(hex::encode(cose));
        lines.push(line);
    }
    Ok(lines)
}

/// One snapshot per ledger directory, kept current across reads.
/// Most recently read first, at most [`SNAPSHOTS_KEPT`]: the node's own
/// ledger stays, and an archived history read once (`is_archived`) is let go.
static SNAPSHOTS: Mutex<Vec<(PathBuf, Snapshot)>> = Mutex::new(Vec::new());
const SNAPSHOTS_KEPT: usize = 4;

fn with_snapshot<T>(
    ledger_dir: &Path,
    view: &ShelfView,
    f: impl FnOnce(&Snapshot) -> T,
) -> io::Result<T> {
    let key = fs::canonicalize(ledger_dir)?;
    let mut snapshots = SNAPSHOTS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut snapshot = match snapshots.iter().position(|(dir, _)| *dir == key) {
        Some(at) => snapshots.remove(at).1,
        None => Snapshot::default(),
    };
    snapshot.refresh(view)?;
    let out = f(&snapshot);
    snapshots.insert(0, (key, snapshot));
    snapshots.truncate(SNAPSHOTS_KEPT);
    Ok(out)
}

/// The chain's lines under `ledger_dir`, each ended by `\n`, in today's
/// `capsules.jsonl` line format: from the shelf (committed lines only), or
/// the flat `capsules.jsonl` as it is, a torn last line included, where
/// there is none, so a flat reader sees what it always did. `None` when the
/// directory holds no chain.
pub fn chain_text(ledger_dir: &Path) -> io::Result<Option<Arc<Vec<u8>>>> {
    if is_store_layout(ledger_dir) {
        let Some(view) = ShelfView::open(ledger_dir)? else {
            return Ok(Some(Arc::new(Vec::new())));
        };
        return with_snapshot(ledger_dir, &view, |s| Some(s.text.clone()));
    }
    match fs::read(ledger_dir.join(FLAT_CAPSULES_FILE)) {
        Ok(bytes) => Ok(Some(Arc::new(bytes))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// [`chain_text`] as a string, `NotFound` when there is no chain.
#[cfg(test)]
pub fn read_chain_string(ledger_dir: &Path) -> io::Result<String> {
    chain_text(ledger_dir)?
        .map(|t| String::from_utf8_lossy(&t).into_owned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no chain in this directory"))
}

/// [`checkpoints_text`] as a string, `NotFound` when there are none.
#[cfg(test)]
pub fn read_checkpoints_string(ledger_dir: &Path) -> io::Result<String> {
    checkpoints_text(ledger_dir)?
        .map(|t| String::from_utf8_lossy(&t).into_owned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no checkpoints in this directory"))
}

/// [`chain_text`] as a string; empty when there is no chain or it cannot be
/// read (the readers that read `capsules.jsonl` with `unwrap_or_default`).
pub fn chain_string(ledger_dir: &Path) -> String {
    chain_text(ledger_dir)
        .ok()
        .flatten()
        .map(|t| String::from_utf8_lossy(&t).into_owned())
        .unwrap_or_default()
}

/// The chain's complete lines under `ledger_dir`, each without its `\n`.
pub fn chain_lines(ledger_dir: &Path) -> io::Result<Vec<Vec<u8>>> {
    Ok(chain_text(ledger_dir)?
        .map(|text| {
            // Complete lines only: a torn last line of a flat file is no leaf.
            let complete = text.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            text[..complete]
                .split(|&b| b == b'\n')
                .filter(|l| !l.is_empty())
                .map(<[u8]>::to_vec)
                .collect()
        })
        .unwrap_or_default())
}

/// The chain's checkpoints under `ledger_dir`, each ended by `\n`, in today's
/// `checkpoints.jsonl` line format: from the shelf's checkpoint history, or
/// the flat `checkpoints.jsonl` where there is no shelf. `None` when there
/// are none.
pub fn checkpoints_text(ledger_dir: &Path) -> io::Result<Option<Vec<u8>>> {
    if is_store_layout(ledger_dir) {
        let Some(view) = ShelfView::open(ledger_dir)? else {
            return Ok(Some(Vec::new()));
        };
        let keys = keys_beside(ledger_dir);
        let mut text = Vec::new();
        for line in checkpoint_lines(&view, &keys)? {
            text.extend_from_slice(line.to_string().as_bytes());
            text.push(b'\n');
        }
        return Ok(Some(text));
    }
    match fs::read(ledger_dir.join(FLAT_CHECKPOINTS_FILE)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// [`checkpoints_text`] as a string; empty when there are none.
pub fn checkpoints_string(ledger_dir: &Path) -> String {
    checkpoints_text(ledger_dir)
        .ok()
        .flatten()
        .map(|t| String::from_utf8_lossy(&t).into_owned())
        .unwrap_or_default()
}

/// How many lines the chain under `ledger_dir` holds, padding included.
pub fn line_count(ledger_dir: &Path) -> usize {
    chain_lines(ledger_dir).map(|l| l.len()).unwrap_or(0)
}

/// Whether the chain under `ledger_dir` holds a line whose `capsule_id` is
/// `capsule_id`.
pub fn holds_record(ledger_dir: &Path, capsule_id: &str) -> bool {
    chain_lines(ledger_dir).is_ok_and(|lines| {
        lines.iter().any(|line| {
            serde_json::from_slice::<Value>(line)
                .is_ok_and(|r| r.get("capsule_id").and_then(Value::as_str) == Some(capsule_id))
        })
    })
}

/// The signed statement (the detached COSE_Sign1) stored for `capsule_id`
/// under `ledger_dir`: the record's unbound `signed-statement` attachment, or
/// the flat `signed-statements/<capsule_id>.cose`. `None` when there is none.
/// On the shelf only a committed line's record counts (a record stored but
/// not yet in the log is pending, §2.3).
pub fn statement(ledger_dir: &Path, capsule_id: &str) -> Option<Vec<u8>> {
    if !is_store_layout(ledger_dir) {
        return fs::read(
            ledger_dir
                .join("signed-statements")
                .join(format!("{capsule_id}.cose")),
        )
        .ok();
    }
    let view = ShelfView::open(ledger_dir).ok()??;
    let value = hex::decode(capsule_id).ok()?;
    view.log.get_entry(&value).ok()?;
    view.artifacts
        .get(capsule_id)
        .ok()?
        .artifacts
        .into_iter()
        .find(|a| a.name == crate::producer::ledger::STATEMENT && a.binding.is_empty())
        .and_then(|a| a.content)
}

// ---------------------------------------------------------------------------
// `capsules chain-lines`
// ---------------------------------------------------------------------------

/// `capsules chain-lines [--data-dir DIR] [--from N] [--to M]`: write the
/// chain's lines `N..=M` (0-based leaf indices, padding included, the
/// indices `/ledger-checkpoint`'s `from`/`to` and its range proof use) to
/// stdout, one per line, in today's `capsules.jsonl` line format. Without
/// `--from` the range starts at 0; without `--to` it ends at the last line.
/// Reads the stores without their writer lock, so it runs beside a running
/// node. Exit 0 on success (an empty chain writes nothing), 2 for a usage
/// error or a range outside the chain, 1 when the chain cannot be read.
pub fn cli(args: &[String]) -> i32 {
    const USAGE: &str = "usage: capsules chain-lines [--data-dir DIR] [--from N] [--to M]";
    let mut from: Option<u64> = None;
    let mut to: Option<u64> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let value = rest.next();
        let index = |v: Option<&String>| -> Option<u64> {
            v.filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse().ok())
        };
        match arg.as_str() {
            "--from" => match index(value) {
                Some(n) => from = Some(n),
                None => {
                    eprintln!("chain-lines: --from takes a leaf index\n{USAGE}");
                    return 2;
                }
            },
            "--to" => match index(value) {
                Some(n) => to = Some(n),
                None => {
                    eprintln!("chain-lines: --to takes a leaf index\n{USAGE}");
                    return 2;
                }
            },
            "--data-dir" => match value {
                Some(dir) if !dir.is_empty() => data_dir = Some(PathBuf::from(dir)),
                _ => {
                    eprintln!("chain-lines: --data-dir takes a directory\n{USAGE}");
                    return 2;
                }
            },
            _ => {
                eprintln!("chain-lines: unknown argument {arg:?}\n{USAGE}");
                return 2;
            }
        }
    }
    let data_dir = match data_dir.map_or_else(crate::data_dir::data_dir, Ok) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("chain-lines: {e:#}");
            return 1;
        }
    };
    let ledger_dir = data_dir.join("ledger");
    let lines = match chain_lines(&ledger_dir) {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("chain-lines: {}: {e}", ledger_dir.display());
            return 1;
        }
    };
    match select(lines.len() as u64, from, to) {
        Ok(None) => 0,
        Ok(Some((first, last))) => {
            use std::io::Write;
            let mut out = io::stdout().lock();
            for line in &lines[first as usize..=last as usize] {
                if out
                    .write_all(line)
                    .and_then(|()| out.write_all(b"\n"))
                    .is_err()
                {
                    return 1;
                }
            }
            if out.flush().is_err() {
                return 1;
            }
            0
        }
        Err(why) => {
            eprintln!("chain-lines: {why}");
            2
        }
    }
}

/// `capsules chain-checkpoints [--data-dir DIR]`: write the chain's
/// checkpoints to stdout, oldest first, one per line, in today's
/// `checkpoints.jsonl` line format (each with its `checkpoint_cose` and the
/// witness receipts held for it). Reads the shelf without its writer lock, so
/// it runs beside a running node. Exit 0 on success (no checkpoint writes
/// nothing), 2 for a usage error, 1 when the checkpoints cannot be read.
pub fn checkpoints_cli(args: &[String]) -> i32 {
    const USAGE: &str = "usage: capsules chain-checkpoints [--data-dir DIR]";
    let data_dir = match args {
        [] => crate::data_dir::data_dir(),
        [flag, dir] if flag == "--data-dir" && !dir.is_empty() => Ok(PathBuf::from(dir)),
        _ => {
            eprintln!("chain-checkpoints: {USAGE}");
            return 2;
        }
    };
    let data_dir = match data_dir {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("chain-checkpoints: {e:#}");
            return 1;
        }
    };
    let ledger_dir = data_dir.join("ledger");
    match checkpoints_text(&ledger_dir) {
        Ok(text) => {
            use std::io::Write;
            let mut out = io::stdout().lock();
            if out
                .write_all(text.as_deref().unwrap_or_default())
                .and_then(|()| out.flush())
                .is_err()
            {
                return 1;
            }
            0
        }
        Err(e) => {
            eprintln!("chain-checkpoints: {}: {e}", ledger_dir.display());
            1
        }
    }
}

/// The inclusive range `--from`/`--to` select from a chain of `count` lines:
/// `None` for an empty chain asked for everything.
fn select(count: u64, from: Option<u64>, to: Option<u64>) -> Result<Option<(u64, u64)>, String> {
    if count == 0 && from.is_none() && to.is_none() {
        return Ok(None);
    }
    let first = from.unwrap_or(0);
    let last = match to {
        Some(to) => to,
        None if count > 0 => count - 1,
        None => return Err("the chain holds no line".into()),
    };
    if first > last || last >= count {
        return Err(format!(
            "the range must be 0 <= from <= to < {count} (the chain holds {count} lines)"
        ));
    }
    Ok(Some((first, last)))
}

// ---------------------------------------------------------------------------
// Import of a flat ledger
// ---------------------------------------------------------------------------

/// Why the flat ledger under `ledger_dir` stays flat, when it does: its
/// history holds an owner-maintenance record that fails AAC Class 1 only as
/// `approver_invalid` (every release up to 0.1.8 sealed those with
/// `approver: "owner"`, Mesh-LLM/capsules-plugin#208). The artifact store
/// admits only records that pass Class 1 and old records are never
/// rewritten, so such a history cannot move without loss: the node keeps
/// the flat ledger (`Ledger::open_with_indexer`, `CheckpointState::load`)
/// as before, its flat files untouched, until its owner starts a new
/// history, which opens on the stores. Any other record that fails is left
/// to [`import_flat`], which refuses it, saying why.
///
/// End condition: this flat path is removed once no supported release can
/// create such a node. When that is decided is Ethan's call.
pub fn stays_flat(ledger_dir: &Path) -> anyhow::Result<Option<String>> {
    let path = ledger_dir.join(FLAT_CAPSULES_FILE);
    // An import under way, or a node already on the stores, goes on there.
    if !path.exists()
        || ledger_dir.join(IMPORT_JOURNAL).exists()
        || ledger_dir.join(SHELF_FILE).exists()
    {
        return Ok(None);
    }
    let text = fs::read(&path)?;
    for (i, line) in text.split(|&b| b == b'\n').enumerate() {
        let Ok(Value::Object(mut record)) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        let owner = record
            .get("model_attestation")
            .and_then(|m| m.get("compute_attestation"))
            .and_then(|c| c.get(crate::producer::capsule::OWNER_MAINTENANCE_BLOCK))
            .is_some();
        if !owner {
            continue;
        }
        record.remove("signature");
        record.remove("key_id");
        let verdict = agent_action_capsule::verify::verify(&Value::Object(record), None);
        let errors: Vec<&str> = verdict
            .findings
            .iter()
            .filter(|f| f.severity == "error")
            .map(|f| f.code.as_str())
            .collect();
        if !verdict.ok && !errors.is_empty() && errors.iter().all(|c| *c == "approver_invalid") {
            return Ok(Some(format!(
                "the ledger stays flat: line {} is an owner-maintenance record that fails AAC \
                 Class 1 as approver_invalid, which the chain stores cannot hold; a new history \
                 starts on them",
                i + 1
            )));
        }
    }
    Ok(None)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ImportJournal {
    v: u32,
    /// `copy` while the records and checkpoints are being written to the
    /// stores; `move` once they are checked and the flat files are moving.
    phase: String,
    started_at: String,
}

/// What [`import_flat`] did.
#[derive(Debug, PartialEq, Eq)]
pub struct ImportReport {
    pub entries: u64,
    pub checkpoints: usize,
    pub tip: Option<String>,
}

fn read_import_journal(ledger_dir: &Path) -> anyhow::Result<Option<ImportJournal>> {
    match fs::read(ledger_dir.join(IMPORT_JOURNAL)) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
            anyhow::anyhow!("{IMPORT_JOURNAL} is not an import journal: {e}")
        })?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_import_journal(ledger_dir: &Path, journal: &ImportJournal) -> anyhow::Result<()> {
    crate::owner_maintenance::write_atomically(
        &ledger_dir.join(IMPORT_JOURNAL),
        &serde_json::to_vec_pretty(journal)?,
    )?;
    Ok(())
}

/// Test seam: a fault injected after this many entries are appended by an
/// import, to show a killed import resumes.
#[cfg(test)]
pub(crate) mod import_faults {
    use std::cell::Cell;
    thread_local! {
        pub(crate) static FAIL_AFTER_APPENDS: Cell<Option<u64>> = const { Cell::new(None) };
    }
}

/// Move a flat ledger (`capsules.jsonl`, `signed-statements/`,
/// `checkpoints.jsonl`, `mmr_nodes.dat`, `witness-backfill.jsonl`) under
/// `ledger_dir` onto `stores`. Called under the data directory's writer lock
/// before the node's [`Ledger`] is opened. `Ok(None)` when there is nothing
/// to import.
///
/// 1. Journal the import ([`IMPORT_JOURNAL`]).
/// 2. Read the flat ledger through capsule-emit's `legacy_ledger::LegacyLedger`
///    and, for each line in order, `put` its record exactly as the legacy
///    store returns it (padding lines as they are, never padded again) and
///    `append` its entry. An entry the log already holds (a resumed import)
///    must name the same record, byte for byte.
/// 3. Commit every flat checkpoint, in order, with its MMR nodes, into the
///    chain log's checkpoint state, and its witness receipts (inline and
///    backfilled) as witness rows.
/// 4. Check the stores against the flat ledger: the same entries, tip and
///    chain head, every checkpoint's root the new log's root at its size, and
///    the checkpoint state loads. Any mismatch is an error naming it: the
///    flat files stay where they are and nothing is deleted.
/// 5. Move only the chain's flat files to `<data dir>/archive/pre-store/`,
///    `capsules.jsonl` last, then clear the journal.
///
/// A crash anywhere resumes from the journal on the next start.
pub fn import_flat(
    ledger_dir: &Path,
    stores: &ChainStores,
    keys: &[SigningKey],
) -> anyhow::Result<Option<ImportReport>> {
    let flat = ledger_dir.join(FLAT_CAPSULES_FILE).exists();
    let journal = read_import_journal(ledger_dir)?;
    match (&journal, flat) {
        (None, false) => return Ok(None),
        (Some(j), _) if j.phase == "move" => {
            move_flat_files(ledger_dir)?;
            fs::remove_file(ledger_dir.join(IMPORT_JOURNAL))?;
            return Ok(None);
        }
        (Some(_), false) => anyhow::bail!(
            "{} says an import of the flat ledger is under way, but {} is gone; refusing to \
             start until it is back",
            ledger_dir.join(IMPORT_JOURNAL).display(),
            ledger_dir.join(FLAT_CAPSULES_FILE).display()
        ),
        _ => {}
    }
    if journal.is_none() {
        write_import_journal(
            ledger_dir,
            &ImportJournal {
                v: 1,
                phase: "copy".into(),
                started_at: crate::producer::timestamp::utc_now_iso8601(),
            },
        )?;
    }
    let refuse = |why: String| {
        anyhow::anyhow!(
            "the flat ledger in {} cannot move onto the chain stores: {why}. Nothing was deleted: \
             {} and its files are where they were. Every start tries again; to run this node on \
             an earlier release instead, stop it and remove {} and {} (they hold only a partial \
             copy)",
            ledger_dir.display(),
            FLAT_CAPSULES_FILE,
            SHELF_FILE,
            IMPORT_JOURNAL
        )
    };
    let report = copy_flat(ledger_dir, stores, keys).map_err(|e| refuse(format!("{e:#}")))?;
    let mut journal = read_import_journal(ledger_dir)?
        .ok_or_else(|| anyhow::anyhow!("{IMPORT_JOURNAL} went missing during the import"))?;
    journal.phase = "move".into();
    write_import_journal(ledger_dir, &journal)?;
    move_flat_files(ledger_dir)?;
    fs::remove_file(ledger_dir.join(IMPORT_JOURNAL))?;
    tracing::info!(
        entries = report.entries,
        checkpoints = report.checkpoints,
        "imported the flat ledger onto the chain stores; its files are in archive/{PRE_STORE_ARCHIVE}"
    );
    Ok(Some(report))
}

/// Steps 2 to 4 of [`import_flat`].
fn copy_flat(
    ledger_dir: &Path,
    stores: &ChainStores,
    keys: &[SigningKey],
) -> anyhow::Result<ImportReport> {
    use capsule_emit_lib::legacy_ledger::LegacyLedger;
    let trusted: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let legacy = LegacyLedger::new(ledger_dir, NAMESPACE, &trusted)?;
    legacy.init()?;

    // 2. The records and entries.
    let mut legacy_ids: Vec<Vec<u8>> = Vec::new();
    let mut after = 0u64;
    loop {
        let page = legacy.scan_entries(after, MAX_SCAN_LIMIT)?;
        if page.is_empty() {
            break;
        }
        for entry in page {
            after = entry.seq;
            let capsule_id = hex::encode(&entry.value);
            let record = legacy.get(&capsule_id).map_err(|e| {
                anyhow::anyhow!(
                    "line {}: the legacy store refuses record {capsule_id}: {e}",
                    entry.seq
                )
            })?;
            let held = stores
                .log
                .scan_entries(entry.seq - 1, 1)?
                .into_iter()
                .next()
                .filter(|e| e.seq == entry.seq);
            match held {
                Some(held) => {
                    if held.value != entry.value {
                        anyhow::bail!(
                            "line {}: the chain log already holds {} there, not {capsule_id}",
                            entry.seq,
                            hex::encode(&held.value)
                        );
                    }
                    let stored = stores.artifacts.get(&capsule_id)?;
                    if capsule_emit_artifact::encode_record(&stored)
                        != capsule_emit_artifact::encode_record(&record)
                    {
                        anyhow::bail!(
                            "line {}: the stored record of {capsule_id} is not the flat one",
                            entry.seq
                        );
                    }
                }
                None => {
                    stores.artifacts.put(&record).map_err(|e| {
                        anyhow::anyhow!("line {}: record {capsule_id}: {e}", entry.seq)
                    })?;
                    let appended = stores.log.append(&AppendInput {
                        value: entry.value.clone(),
                        appended_at: entry.appended_at,
                    })?;
                    if appended.outcome != AppendOutcome::Inserted
                        || appended.entry.seq != entry.seq
                    {
                        anyhow::bail!(
                            "line {}: {capsule_id} is already in the chain log, at {}",
                            entry.seq,
                            appended.entry.seq
                        );
                    }
                    #[cfg(test)]
                    if import_faults::FAIL_AFTER_APPENDS.with(|f| f.get()) == Some(entry.seq) {
                        anyhow::bail!("injected fault after {} appends", entry.seq);
                    }
                }
            }
            legacy_ids.push(entry.value);
        }
    }
    let total = legacy_ids.len() as u64;
    if let Some(extra) = stores.log.scan_entries(total, 1)?.into_iter().next() {
        anyhow::bail!(
            "the chain log holds entry {} past the flat ledger's {total} lines",
            extra.seq
        );
    }

    // The new log's MMR.
    let mut nodes = MemoryNodeStore::new();
    for id in &legacy_ids {
        let id: [u8; 32] = id
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("an entry is not 32 bytes"))?;
        add_leaf(&mut nodes, leaf_hash(&id))?;
    }
    let root_at = |size: u64| -> anyhow::Result<String> {
        let peak_hashes: Vec<_> = peaks(size)?.iter().map(|&p| nodes.node(p)).collect();
        Ok(hex::encode(root_from_peaks(&peak_hashes)))
    };

    // 3. The checkpoints.
    let checkpoints = flat_checkpoints(ledger_dir)?;
    for (cp, cose) in &checkpoints {
        let leaves = leaf_count(cp.mmr_size)?;
        if leaves > total {
            anyhow::bail!(
                "checkpoint at size {} covers {leaves} lines, past the flat ledger's {total}",
                cp.mmr_size
            );
        }
        // 4, per checkpoint: the old checkpoint's root is the new log's root
        // at its size.
        if root_at(cp.mmr_size)? != cp.root {
            anyhow::bail!(
                "checkpoint at size {} has root {} but the moved log's root there is {}",
                cp.mmr_size,
                cp.root,
                root_at(cp.mmr_size)?
            );
        }
        let current = stores.log.load_cll()?;
        if let Some(held) = &current.checkpoint {
            if held.size > cp.mmr_size {
                continue;
            }
            if held.size == cp.mmr_size {
                if held.bytes != *cose {
                    anyhow::bail!(
                        "the chain log already holds another checkpoint at size {}",
                        cp.mmr_size
                    );
                }
                continue;
            }
        }
        let mut rows = Vec::new();
        for witness in &cp.witnesses {
            if witness.is_stub {
                anyhow::bail!(
                    "checkpoint at size {} carries a stub receipt from {}, which a witness row \
                     cannot hold",
                    cp.mmr_size,
                    witness.ts_url
                );
            }
            cll::log::validate_identifier(&witness.ts_url).map_err(|e| {
                anyhow::anyhow!(
                    "checkpoint at size {}: witness {:?} cannot key a witness row: {e}",
                    cp.mmr_size,
                    witness.ts_url
                )
            })?;
            if rows
                .iter()
                .any(|r: &WitnessState| r.witness_id == witness.ts_url)
            {
                // The flat merge keeps one receipt per witness URL.
                continue;
            }
            rows.push(WitnessState {
                witness_id: witness.ts_url.clone(),
                checkpoint_size: cp.mmr_size,
                checkpoint: cose.clone(),
                attempts: 1,
                next_attempt_at: Timestamp::now(),
                receipt: Some(WitnessReceiptState {
                    bytes: b64(&witness.receipt_b64)?,
                    entry_hash: Some(witness.entry_hash.clone()),
                    entry_hash_scheme: Some("legacy".into()),
                    leaf_index: Some(witness.leaf_index),
                    tree_size: Some(witness.tree_size),
                }),
                permanent: false,
                last_error: None,
            });
        }
        let next = LogState {
            size: cp.mmr_size,
            nodes: (0..cp.mmr_size).map(|p| nodes.node(p).to_vec()).collect(),
            indexed_seq: leaves,
            first_pending_at: None,
            checkpoint: Some(LogCheckpointState {
                bytes: cose.clone(),
                size: cp.mmr_size,
                indexed_seq: leaves,
                peaks: peaks(cp.mmr_size)?
                    .iter()
                    .map(|&p| nodes.node(p).to_vec())
                    .collect(),
            }),
            witnesses: rows,
        };
        stores.log.commit_cll(
            current.size,
            current.checkpoint.as_ref().map(|c| c.bytes.as_slice()),
            &next,
        )?;
    }

    // 4. The whole: entries, tip and head; the checkpoint state loads.
    let (ledger, _) = stores.open_ledger()?;
    let (flat_ledger, _) =
        Ledger::open_with_indexer(ledger_dir, crate::producer::index::record_index_keys)?;
    if ledger.lines().len() as u64 != total || flat_ledger.lines().len() as u64 != total {
        anyhow::bail!(
            "the moved chain holds {} lines, the flat ledger {}",
            ledger.lines().len(),
            flat_ledger.lines().len()
        );
    }
    if ledger.lines().last().map(|l| &l.capsule_id)
        != flat_ledger.lines().last().map(|l| &l.capsule_id)
        || ledger.chain_head() != flat_ledger.chain_head()
    {
        anyhow::bail!(
            "the moved chain ends at {:?} (head {:?}), the flat ledger at {:?} (head {:?})",
            ledger.lines().last().map(|l| &l.capsule_id),
            ledger.chain_head(),
            flat_ledger.lines().last().map(|l| &l.capsule_id),
            flat_ledger.chain_head()
        );
    }
    for (moved, flat) in ledger.lines().iter().zip(flat_ledger.lines()) {
        if ledger.read_line(moved.offset)? != flat_ledger.read_line(flat.offset)? {
            anyhow::bail!(
                "line {} does not read back as the flat line",
                moved.capsule_id
            );
        }
    }
    drop(ledger);
    if let Some((latest, _)) = checkpoints.last() {
        load_checkpoint_state(
            stores,
            latest.log_id.clone(),
            CheckpointCadenceConfig::default(),
            keys,
        )
        .map_err(|e| anyhow::anyhow!("the moved checkpoint state does not load: {e}"))?;
    }
    legacy.close();
    Ok(ImportReport {
        entries: total,
        checkpoints: checkpoints.len(),
        tip: legacy_ids.last().map(hex::encode),
    })
}

/// The flat ledger's checkpoints in file order, each with its COSE and its
/// witness receipts merged with the backfilled ones bound to it, as the flat
/// checkpoint state reads them. A line without its COSE statement (the flat
/// cadence writes it best-effort) is left out: the chain log's checkpoint
/// state cannot hold one, and no peer could have pinned it (the evidence
/// index ends its chain there, and no witness can register it). It stays in
/// the archived `checkpoints.jsonl`.
fn flat_checkpoints(ledger_dir: &Path) -> anyhow::Result<Vec<(CheckpointRecord, Vec<u8>)>> {
    let path = ledger_dir.join(FLAT_CHECKPOINTS_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let backfills = crate::producer::checkpoint::read_witness_backfills(&path);
    let mut out = Vec::new();
    // Only complete lines: a torn last line was never a checkpoint.
    let complete = text.rfind('\n').map_or("", |i| &text[..i]);
    for (i, line) in complete.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut value: Value = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("{FLAT_CHECKPOINTS_FILE} line {}: {e}", i + 1))?;
        let Some(cose) = value
            .as_object_mut()
            .and_then(|o| o.remove("checkpoint_cose"))
            .and_then(|v| v.as_str().and_then(|h| hex::decode(h).ok()))
        else {
            tracing::warn!(
                line = i + 1,
                "a flat checkpoint without its COSE statement stays in the archive only"
            );
            continue;
        };
        let record: crate::producer::checkpoint::CheckpointRecord =
            serde_json::from_value(value)
                .map_err(|e| anyhow::anyhow!("{FLAT_CHECKPOINTS_FILE} line {}: {e}", i + 1))?;
        let witnesses = crate::producer::checkpoint::effective_witnesses(&record, &backfills);
        let record = CheckpointRecord {
            v: record.v,
            kind: record.kind,
            log_id: record.log_id,
            mmr_size: record.mmr_size,
            root: record.root,
            prev_size: record.prev_size,
            prev_root: record.prev_root,
            key_id: record.key_id,
            timestamp: record.timestamp,
            signature: record.signature,
            witnesses: witnesses
                .into_iter()
                .map(|w| CheckpointWitness {
                    ts_url: w.ts_url,
                    entry_hash: w.entry_hash,
                    receipt_b64: w.receipt_b64,
                    leaf_index: w.leaf_index,
                    tree_size: w.tree_size,
                    is_stub: w.is_stub,
                })
                .collect(),
        };
        out.push((record, cose));
    }
    Ok(out)
}

/// Step 5 of [`import_flat`]: move each of [`FLAT_CHAIN_FILES`] still under
/// `ledger_dir` to `<data dir>/archive/pre-store/`. One already there and
/// gone from `ledger_dir` is a move a start made before it died.
fn move_flat_files(ledger_dir: &Path) -> anyhow::Result<()> {
    let data_dir = ledger_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no data directory", ledger_dir.display()))?;
    let archive = data_dir
        .join(crate::owner_maintenance::ARCHIVE_DIR)
        .join(PRE_STORE_ARCHIVE);
    fs::create_dir_all(&archive)?;
    for name in FLAT_CHAIN_FILES {
        let from = ledger_dir.join(name);
        if !from.exists() {
            continue;
        }
        let to = archive.join(name);
        if to.exists() {
            anyhow::bail!(
                "{} is already in {}; refusing to overwrite it",
                name,
                archive.display()
            );
        }
        fs::rename(&from, &to)?;
    }
    Ok(())
}

/// A checkpoint state over the chain under `ledger_dir`, for tests: the
/// stores live in this process are shared. Loads a checkpoint signed by the
/// node's keys or by the fixed keys tests sign with.
#[cfg(test)]
pub(crate) fn test_checkpoint_state(
    ledger_dir: &Path,
    log_id: &str,
) -> crate::producer::checkpoint::CheckpointState {
    let keys = keys_beside(ledger_dir);
    if !is_store_layout(ledger_dir) {
        return crate::producer::checkpoint::CheckpointState::load(
            ledger_dir,
            log_id,
            CheckpointCadenceConfig::default(),
        )
        .expect("load the flat checkpoint state")
        .0;
    }
    let stores = ChainStores::open(ledger_dir, log_id, &keys).expect("open the chain stores");
    load_checkpoint_state(&stores, log_id, CheckpointCadenceConfig::default(), &keys)
        .expect("load the checkpoint state")
        .0
}

/// [`test_checkpoint_state`] in the shape `CheckpointState::load` returns.
#[cfg(test)]
pub(crate) fn test_load(
    ledger_dir: &Path,
    log_id: impl AsRef<str>,
) -> anyhow::Result<(crate::producer::checkpoint::CheckpointState, ())> {
    Ok((test_checkpoint_state(ledger_dir, log_id.as_ref()), ()))
}

#[cfg(test)]
pub(crate) mod tests;
