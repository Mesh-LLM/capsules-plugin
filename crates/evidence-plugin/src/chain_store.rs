//! Where this node's chain is kept: a Checkpointed Local Log entry log
//! (`ledger/log.jsonl`, CLL's JSONL v4 journal) plus capsule-emit's artifact
//! store (`ledger/artifacts.jsonl`), the two standard layers capsule-emit's
//! [`Ledger`] keeps a ledger on (`Ledger::open_stores_with_indexer`). The
//! journal holds each line's `capsule_id` in log order and, in the same file,
//! the checkpoint state (`CheckpointState::load_log`): the MMR nodes, every
//! committed checkpoint and the witness rows. The artifact store holds each
//! line as a record: the line without its inline `signature`/`key_id`, its
//! producer envelope, and its signed statement.
//!
//! **One writer, readers without the lock.** The journal is opened once, by
//! [`ChainStores::open`], under CLL's writer lock (`flock`), and the node's
//! [`Ledger`] and checkpoint state share that handle. Every other reader (the
//! Evidence pages, the evidence responder's index, `capsules chain-lines`)
//! reads the two files as they are, complete lines only, without the lock:
//! [`chain_text`] gives the chain's lines in today's `capsules.jsonl` line
//! format (the kept `Ledger` lines: the stored record with `signature` and
//! `key_id` put back, padding included), and [`checkpoints_text`] the chain's
//! checkpoints in today's `checkpoints.jsonl` line format. Nothing here keeps
//! a second copy on disk: both are read from the stores on demand.
//!
//! **Either layout.** A ledger directory that holds no `log.jsonl` is read in
//! the flat layout (`capsules.jsonl`, `checkpoints.jsonl`), as an archived
//! history from before the stores, or a node not yet imported, is.
//!
//! **Import.** A node written by an earlier release keeps its chain in the flat
//! layout. [`import_flat`] moves it onto the stores on the first start of this
//! one, journalled and resumable, and archives only the chain's flat files to
//! `archive/pre-store/` (see the function).

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use capsule_emit_artifact::{Record, Store};
use cll::checkpoint::{
    try_sign_checkpoint_digest, verify_checkpoint_cose_offline, CheckpointRecord,
    WitnessRecord as CheckpointWitness,
};
use cll::log::{
    AppendInput, AppendOutcome, CheckpointState as LogCheckpointState, CheckpointStateStore,
    EntrySource, EntryStore, State as LogState, Timestamp, WitnessReceiptState, WitnessState,
    MAX_SCAN_LIMIT,
};
use cll::mmr::{
    add_leaf, leaf_count, leaf_hash, peaks, root_from_peaks, MemoryNodeStore, NodeReader,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::producer::checkpoint::{CheckpointCadenceConfig, CheckpointLog, CheckpointSigner};
use crate::producer::ledger::{Ledger, LedgerError, RecoveryReport};

/// The CLL entry log (and checkpoint state) of the chain.
pub const LOG_FILE: &str = "log.jsonl";
/// The artifact store of the chain's records.
pub const ARTIFACTS_FILE: &str = "artifacts.jsonl";
/// The artifact store's namespace. A JSONL store keeps none per line; it only
/// has to be a valid name.
pub const NAMESPACE: &str = "chain";
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
/// The import's journal, beside the stores while an import runs.
pub const IMPORT_JOURNAL: &str = "import-pending.json";
/// Where an import keeps the flat files it moved, under the data directory's
/// `archive/`. Not numeric, so it is never an archive slot of an earlier
/// history (`owner_maintenance::next_archive_slot`).
pub const PRE_STORE_ARCHIVE: &str = "pre-store";

/// Whether `ledger_dir` keeps its chain on the stores.
pub fn is_store_layout(ledger_dir: &Path) -> bool {
    ledger_dir.join(LOG_FILE).exists()
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
    ledger_dir
        .ancestors()
        .skip(1)
        .take(2)
        .map(|dir| dir.join("keys"))
        .find(|keys| keys.join("node-key.pem").exists())
        .map(|keys| node_signing_keys(&keys))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The writer's stores
// ---------------------------------------------------------------------------

/// The chain's two stores, opened once per process: the node's [`Ledger`]
/// and its checkpoint state share them.
#[derive(Clone)]
pub struct ChainStores {
    log: Arc<cll::log::jsonl::JsonlStore>,
    artifacts: Arc<capsule_emit_artifact::jsonl::JsonlStore>,
    /// The journal's length cut back by `init`, when its last line was torn.
    torn_write_cut_at: Option<u64>,
}

impl std::fmt::Debug for ChainStores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainStores").finish_non_exhaustive()
    }
}

/// The stores this process holds open, by ledger directory: a second open of
/// a directory whose stores are live shares them, since the journal admits
/// one writer handle (`flock`) and two artifact-store handles would each keep
/// their own index.
type OpenStores = (
    std::sync::Weak<cll::log::jsonl::JsonlStore>,
    std::sync::Weak<capsule_emit_artifact::jsonl::JsonlStore>,
);
static OPEN: Mutex<Option<HashMap<PathBuf, OpenStores>>> = Mutex::new(None);

impl ChainStores {
    /// Provision (first start) or open the stores under `ledger_dir`, the
    /// artifact store trusting `keys`. Takes the journal's writer lock, so
    /// another process cannot open them while these live; in this process a
    /// second open shares these.
    pub fn open(ledger_dir: &Path, keys: &[SigningKey]) -> anyhow::Result<Self> {
        let mut open = OPEN.lock().unwrap_or_else(PoisonError::into_inner);
        let open = open.get_or_insert_with(HashMap::new);
        open.retain(|_, (log, artifacts)| log.strong_count() > 0 && artifacts.strong_count() > 0);
        if let Some((log, artifacts)) = open.get(ledger_dir) {
            if let (Some(log), Some(artifacts)) = (log.upgrade(), artifacts.upgrade()) {
                return Ok(Self {
                    log,
                    artifacts,
                    torn_write_cut_at: None,
                });
            }
        }
        let stores = Self::open_new(ledger_dir, keys)?;
        open.insert(
            ledger_dir.to_path_buf(),
            (
                Arc::downgrade(&stores.log),
                Arc::downgrade(&stores.artifacts),
            ),
        );
        Ok(stores)
    }

    fn open_new(ledger_dir: &Path, keys: &[SigningKey]) -> anyhow::Result<Self> {
        fs::create_dir_all(ledger_dir)?;
        let log_path = ledger_dir.join(LOG_FILE);
        let before = fs::metadata(&log_path).map(|m| m.len()).ok();
        cll::log::jsonl::JsonlStore::init(&log_path)
            .map_err(|e| anyhow::anyhow!("chain log {}: {e}", log_path.display()))?;
        let after = fs::metadata(&log_path).map(|m| m.len()).ok();
        let torn_write_cut_at = match (before, after) {
            (Some(before), Some(after)) if after < before => Some(after),
            _ => None,
        };
        let log = cll::log::jsonl::JsonlStore::open(&log_path)
            .map_err(|e| anyhow::anyhow!("chain log {}: {e}", log_path.display()))?;
        let trusted: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let artifacts = capsule_emit_artifact::jsonl::JsonlStore::new(
            ledger_dir.join(ARTIFACTS_FILE),
            NAMESPACE,
            trusted,
        )
        .map_err(|e| anyhow::anyhow!("chain records {}: {e}", ARTIFACTS_FILE))?;
        artifacts
            .init()
            .map_err(|e| anyhow::anyhow!("chain records {}: {e}", ARTIFACTS_FILE))?;
        Ok(Self {
            log: Arc::new(log),
            artifacts: Arc::new(artifacts),
            torn_write_cut_at,
        })
    }

    /// The chain as capsule-emit's [`Ledger`] over these stores, under this
    /// plugin's index (`producer::index::record_index_keys`).
    pub fn open_ledger(&self) -> Result<(Ledger, RecoveryReport), LedgerError> {
        let (ledger, mut report) = Ledger::open_stores_with_indexer(
            self.log.clone(),
            self.artifacts.clone(),
            crate::producer::index::record_index_keys,
        )?;
        report.truncated_torn_write_at = self.torn_write_cut_at;
        Ok((ledger, report))
    }

    /// The CLL backend the checkpoint state is kept in: the same journal.
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

/// One event of the journal, as far as a reader needs it (CLL
/// docs/backend-contract.md, "JSONL v4").
#[derive(Deserialize)]
struct JournalEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    entry: Option<JournalEntry>,
    #[serde(default)]
    state: Option<JournalState>,
    #[serde(default)]
    witness: Option<JournalWitness>,
}

#[derive(Deserialize)]
struct JournalEntry {
    seq: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JournalState {
    #[serde(default)]
    checkpoint: Option<String>,
    #[serde(default)]
    witnesses: Vec<JournalWitness>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct JournalWitness {
    witness_id: String,
    checkpoint_size: String,
    #[serde(default)]
    receipt: Option<String>,
    #[serde(default)]
    entry_hash: Option<String>,
    #[serde(default)]
    leaf_index: Option<i64>,
    #[serde(default)]
    tree_size: Option<i64>,
}

fn b64(text: &str) -> io::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(other)
}

/// What a reader has taken from one ledger directory's two files so far.
#[derive(Default)]
struct Snapshot {
    /// The journal file this was read from (dev, inode), so a replaced
    /// directory (a new history) is read again from the start.
    identity: Option<(u64, u64)>,
    journal_consumed: u64,
    artifacts_consumed: u64,
    /// The log's entries, in order.
    ids: Vec<String>,
    /// Each committed checkpoint's COSE, in commit order.
    checkpoints: Vec<Vec<u8>>,
    /// Witness rows by (witness_id, checkpoint size), in insertion order.
    rows: Vec<JournalWitness>,
    /// capsule_id to (offset, length) of its record line in the artifacts file.
    spans: HashMap<String, (u64, usize)>,
    /// The chain's lines, each with its `\n`, for `ids[..text_lines]`.
    text: Arc<Vec<u8>>,
    text_lines: usize,
}

#[cfg(unix)]
fn identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn identity(_: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// The complete lines of `path` from byte `from`, each with its offset, and
/// where the last complete line ends. A missing file is an empty one.
/// Complete lines, each with its offset.
type Lines = Vec<(u64, Vec<u8>)>;

fn complete_lines_from(path: &Path, from: u64) -> io::Result<(Lines, u64)> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), from)),
        Err(e) => return Err(e),
    };
    file.seek(SeekFrom::Start(from))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut lines = Vec::new();
    let mut start = 0usize;
    while let Some(relative) = bytes[start..].iter().position(|&b| b == b'\n') {
        let end = start + relative;
        lines.push((from + start as u64, bytes[start..end].to_vec()));
        start = end + 1;
    }
    Ok((lines, from + start as u64))
}

impl Snapshot {
    /// Bring this up to date with the files under `ledger_dir`.
    fn refresh(&mut self, ledger_dir: &Path) -> io::Result<()> {
        let journal = ledger_dir.join(LOG_FILE);
        let artifacts = ledger_dir.join(ARTIFACTS_FILE);
        let meta = fs::metadata(&journal)?;
        let artifacts_len = fs::metadata(&artifacts).map(|m| m.len()).unwrap_or(0);
        if identity(&meta) != self.identity
            || meta.len() < self.journal_consumed
            || artifacts_len < self.artifacts_consumed
        {
            *self = Snapshot {
                identity: identity(&meta),
                ..Snapshot::default()
            };
        }
        // Records first: an entry is appended only after its record is
        // written, so every entry read below has its record by then.
        let (lines, consumed) = complete_lines_from(&artifacts, self.artifacts_consumed)?;
        for (offset, line) in lines {
            #[derive(Deserialize)]
            struct Peek {
                capsule_id: String,
            }
            if let Ok(peek) = serde_json::from_slice::<Peek>(&line) {
                // The first line of an id is its record: the store admits
                // an id once (`put` accepts only an identical retry).
                self.spans
                    .entry(peek.capsule_id)
                    .or_insert((offset, line.len()));
            }
        }
        self.artifacts_consumed = consumed;
        let (events, consumed) = complete_lines_from(&journal, self.journal_consumed)?;
        for (offset, line) in events {
            let event: JournalEvent = serde_json::from_slice(&line)
                .map_err(|e| other(format!("{LOG_FILE} at byte {offset}: {e}")))?;
            match event.kind.as_str() {
                "entry.append" => {
                    let entry = event
                        .entry
                        .ok_or_else(|| other(format!("{LOG_FILE} at byte {offset}: no entry")))?;
                    let seq: usize = entry.seq.parse().map_err(other)?;
                    if seq != self.ids.len() + 1 {
                        return Err(other(format!(
                            "{LOG_FILE} at byte {offset}: entry {seq} after {}",
                            self.ids.len()
                        )));
                    }
                    self.ids.push(hex::encode(b64(&entry.value)?));
                }
                "cll.commit" => {
                    let state = event
                        .state
                        .ok_or_else(|| other(format!("{LOG_FILE} at byte {offset}: no state")))?;
                    if let Some(cose) = state.checkpoint.as_deref() {
                        let cose = b64(cose)?;
                        if self.checkpoints.last() != Some(&cose) {
                            self.checkpoints.push(cose);
                        }
                    }
                    self.rows.extend(state.witnesses);
                }
                "witness.commit" => {
                    if let Some(row) = event.witness {
                        match self.rows.iter_mut().find(|r| {
                            r.witness_id == row.witness_id
                                && r.checkpoint_size == row.checkpoint_size
                        }) {
                            Some(stored) => *stored = row,
                            None => self.rows.push(row),
                        }
                    }
                }
                _ => {}
            }
        }
        self.journal_consumed = consumed;
        // The chain's text, for the entries not yet in it.
        if self.text_lines < self.ids.len() {
            let mut file = fs::File::open(&artifacts)?;
            let text = Arc::make_mut(&mut self.text);
            for id in &self.ids[self.text_lines..] {
                let &(offset, len) = self.spans.get(id).ok_or_else(|| {
                    other(format!(
                        "the chain log names {id} but {ARTIFACTS_FILE} holds no record of it"
                    ))
                })?;
                let mut bytes = vec![0u8; len];
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(&mut bytes)?;
                let record = capsule_emit_artifact::decode_record(&bytes).map_err(other)?;
                text.extend_from_slice(&line_of(&record)?);
                text.push(b'\n');
            }
            self.text_lines = self.ids.len();
        }
        Ok(())
    }

    /// The checkpoint lines, as `checkpoints.jsonl` holds them: each record
    /// (its JSON signature made again with the key that signed its COSE,
    /// which is deterministic Ed25519, so it is the record first cut), its
    /// witnesses from the rows with a receipt, and its `checkpoint_cose`.
    fn checkpoint_lines(&self, keys: &[SigningKey]) -> Vec<Value> {
        let mut lines = Vec::new();
        for cose in &self.checkpoints {
            let verified = verify_checkpoint_cose_offline(cose);
            let Some(decoded) = verified.decoded else {
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
            let size = record.mmr_size.to_string();
            record.witnesses = self
                .rows
                .iter()
                .filter(|r| r.checkpoint_size == size)
                .filter_map(|r| {
                    let receipt = r.receipt.as_deref()?;
                    Some(CheckpointWitness {
                        ts_url: r.witness_id.clone(),
                        entry_hash: r.entry_hash.clone().unwrap_or_default(),
                        receipt_b64: receipt.to_string(),
                        leaf_index: r.leaf_index.unwrap_or_default(),
                        tree_size: r.tree_size.unwrap_or_default(),
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
        lines
    }
}

/// One snapshot per ledger directory, kept current across reads.
static SNAPSHOTS: Mutex<Option<HashMap<PathBuf, Snapshot>>> = Mutex::new(None);

fn with_snapshot<T>(ledger_dir: &Path, f: impl FnOnce(&Snapshot) -> T) -> io::Result<T> {
    let mut guard = SNAPSHOTS.lock().unwrap_or_else(PoisonError::into_inner);
    let snapshots = guard.get_or_insert_with(HashMap::new);
    let snapshot = snapshots.entry(ledger_dir.to_path_buf()).or_default();
    if let Err(e) = snapshot.refresh(ledger_dir) {
        snapshots.remove(ledger_dir);
        return Err(e);
    }
    Ok(f(snapshot))
}

/// The chain's lines under `ledger_dir`, each ended by `\n`, in today's
/// `capsules.jsonl` line format: from the stores (complete lines only), or
/// the flat `capsules.jsonl` as it is, a torn last line included, where
/// there are none, so a flat reader sees what it always did. `None` when the
/// directory holds no chain.
pub fn chain_text(ledger_dir: &Path) -> io::Result<Option<Arc<Vec<u8>>>> {
    if is_store_layout(ledger_dir) {
        return with_snapshot(ledger_dir, |s| Some(s.text.clone()));
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
/// `checkpoints.jsonl` line format: from the chain log's commits, or the flat
/// `checkpoints.jsonl` where there are no stores. `None` when there are none.
pub fn checkpoints_text(ledger_dir: &Path) -> io::Result<Option<Vec<u8>>> {
    if is_store_layout(ledger_dir) {
        let keys = keys_beside(ledger_dir);
        let lines = with_snapshot(ledger_dir, |s| s.checkpoint_lines(&keys))?;
        let mut text = Vec::new();
        for line in lines {
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
pub fn statement(ledger_dir: &Path, capsule_id: &str) -> Option<Vec<u8>> {
    if !is_store_layout(ledger_dir) {
        return fs::read(
            ledger_dir
                .join("signed-statements")
                .join(format!("{capsule_id}.cose")),
        )
        .ok();
    }
    let span = with_snapshot(ledger_dir, |s| s.spans.get(capsule_id).copied()).ok()??;
    let mut file = fs::File::open(ledger_dir.join(ARTIFACTS_FILE)).ok()?;
    let mut bytes = vec![0u8; span.1];
    file.seek(SeekFrom::Start(span.0)).ok()?;
    file.read_exact(&mut bytes).ok()?;
    capsule_emit_artifact::decode_record(&bytes)
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
    if !path.exists() || ledger_dir.join(IMPORT_JOURNAL).exists() || is_store_layout(ledger_dir) {
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
             {} and its files are where they were",
            ledger_dir.display(),
            FLAT_CAPSULES_FILE
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
    let mut keys = keys_beside(ledger_dir);
    for seed in [3u8, 9u8] {
        keys.push(SigningKey::from_bytes(&[seed; 32]));
    }
    if !is_store_layout(ledger_dir) {
        return crate::producer::checkpoint::CheckpointState::load(
            ledger_dir,
            log_id,
            CheckpointCadenceConfig::default(),
        )
        .expect("load the flat checkpoint state")
        .0;
    }
    let stores = ChainStores::open(ledger_dir, &keys).expect("open the chain stores");
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
