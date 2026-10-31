//! Signed checkpoints and range proofs over this node's ledger files, so a
//! copy of one can be shown complete offline (`docs/LEDGER-CHECKPOINTS.md`).
//!
//! **Nothing here is a new proof format.** Each file is a Checkpointed Local
//! Log MMR; a checkpoint is cll's `CheckpointRecord` and its `cll-checkpoint`
//! COSE statement, signed with the node key; a range proof is cll's CLL #13
//! range proof. The chain (`capsules.jsonl`) keeps its own checkpoints
//! (`checkpoints.jsonl`, cut by the cadence, which a chain ask has cut one
//! over the tip); only its range proof is built here. Every other file in [`CHECKPOINTED_FILES`] is checkpointed here, into
//! [`FILE_CHECKPOINTS`].
//!
//! **What a leaf is.** Every complete (newline-ended) line, in file order,
//! whether or not it parses: its body digest is the SHA-256 of the line's
//! bytes without the `\n` ([`LEAF_SHA256_LINE`]). A final fragment with no
//! newline is a write cut short and is not a leaf until a later append ends
//! it, so the files stay append-only as sequences of leaves. In the chain the
//! body digest is the line's `capsule_id` ([`LEAF_CAPSULE_ID`]), as the
//! cadence folds it.
//!
//! **Cuts.** A file's checkpoint is cut when the route asks for it and the
//! file has grown since its last one, and at each cadence tick ([`cut_all`]).
//! Each chains from the one before under the same log id. The MMR is rebuilt
//! from the file in memory each time; there is no node store per file.
//! Checkpoints of these files are not offered to witnesses.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use cll::checkpoint::{checkpoint_to_cose, try_sign_checkpoint_digest, CheckpointRecord};
use cll::mmr::{
    add_leaf, consistency_proof, leaf_count, leaf_hash, peaks, root_from_peaks, Hash,
    MemoryNodeStore, NodeReader,
};
use cll::range_proof::{range_proof, verify_range, RangeProof};
use ed25519_dalek::SigningKey;
use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::evidence_log::{self, CAPSULES_FILE};

/// The checkpoints this module cuts, one line per cut, shaped like a
/// `checkpoints.jsonl` line: the record plus its `checkpoint_cose` (hex).
pub const FILE_CHECKPOINTS: &str = "file-checkpoints.jsonl";

/// The ledger files checkpointed here, beside `capsules.jsonl`.
/// `referee-pairs.jsonl` is not one yet.
pub const CHECKPOINTED_FILES: [&str; 6] = [
    crate::record_push_receive::RECEIVED_CAPSULES_FILENAME,
    crate::record_push_receive::RECEIVED_PROVENANCE_FILENAME,
    crate::record_push_receive::RECEIVED_INCLUSION_FILENAME,
    crate::adjudication_records::ISSUED_ADJUDICATIONS_FILENAME,
    crate::adjudication_records::RECEIVED_ADJUDICATIONS_FILENAME,
    crate::verdict_counts::REQUESTED_FILENAME,
];

/// The reply's version member.
pub const REPLY_VERSION: u64 = 1;
/// A leaf's body digest is the line's `capsule_id` (the chain only).
pub const LEAF_CAPSULE_ID: &str = "capsule_id";
/// A leaf's body digest is the SHA-256 of the line's bytes.
pub const LEAF_SHA256_LINE: &str = "sha256-line";

const CHECKPOINT_KIND: &str = "mmr_checkpoint";

/// One writer of [`FILE_CHECKPOINTS`] per process: the route and the cadence
/// tick both cut.
static CUT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeafRule {
    CapsuleId,
    Sha256Line,
}

impl LeafRule {
    fn for_file(file: &str) -> Option<Self> {
        if file == CAPSULES_FILE {
            Some(Self::CapsuleId)
        } else if CHECKPOINTED_FILES.contains(&file) {
            Some(Self::Sha256Line)
        } else {
            None
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::CapsuleId => LEAF_CAPSULE_ID,
            Self::Sha256Line => LEAF_SHA256_LINE,
        }
    }
}

/// The log id of a checkpointed file: `<node log id>/ledger/<file>`.
pub fn file_log_id(node_log_id: &str, file: &str) -> String {
    format!("{node_log_id}/ledger/{file}")
}

/// The complete lines of `bytes`, each without its `\n`, and whether a final
/// fragment with no newline follows them.
fn complete_lines(bytes: &[u8]) -> (Vec<&[u8]>, bool) {
    let mut lines: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    // `split` yields what follows the last `\n`: empty for a file that ends
    // in one, a fragment otherwise.
    let tail = lines.pop().unwrap_or_default();
    (lines, !tail.is_empty())
}

fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

fn hex_hash(text: &str) -> Option<Hash> {
    hex::decode(text).ok()?.try_into().ok()
}

/// The body digest of line `index` as this node folds it. The chain's is
/// the `capsule_id` the line states, as the cadence folds it.
fn node_body_digest(rule: LeafRule, index: usize, line: &[u8]) -> Result<Hash, String> {
    match rule {
        LeafRule::Sha256Line => Ok(sha256(line)),
        LeafRule::CapsuleId => serde_json::from_slice::<Value>(line)
            .ok()
            .and_then(|v| v.get("capsule_id")?.as_str().and_then(hex_hash))
            .ok_or_else(|| format!("line {} states no capsule_id", index + 1)),
    }
}

/// The body digest of copied line `index` as a checker computes it. The
/// chain's is the line's recomputed `capsule_id`, which must be the one it
/// states.
fn checker_body_digest(rule: LeafRule, index: usize, line: &[u8]) -> Result<Hash, String> {
    match rule {
        LeafRule::Sha256Line => Ok(sha256(line)),
        LeafRule::CapsuleId => evidence_log::record_digest(line)
            .as_deref()
            .and_then(hex_hash)
            .ok_or_else(|| {
                format!(
                    "copied line {} is not a record whose capsule_id recomputes",
                    index + 1
                )
            }),
    }
}

/// A file's MMR, rebuilt from its complete lines. A chain line that states
/// no `capsule_id` ends it: the cadence folds nothing past it either.
struct Tree {
    nodes: MemoryNodeStore,
}

impl Tree {
    fn build(path: &Path, rule: LeafRule) -> std::io::Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        let mut nodes = MemoryNodeStore::new();
        for (index, line) in complete_lines(&bytes).0.into_iter().enumerate() {
            let Ok(digest) = node_body_digest(rule, index, line) else {
                break;
            };
            add_leaf(&mut nodes, leaf_hash(&digest)).map_err(std::io::Error::other)?;
        }
        Ok(Self { nodes })
    }

    fn size(&self) -> u64 {
        self.nodes.size()
    }

    fn peak_hashes(&self, size: u64) -> Result<Vec<Hash>, String> {
        Ok(peaks(size)
            .map_err(|e| e.to_string())?
            .iter()
            .map(|&p| self.nodes.node(p))
            .collect())
    }

    fn root(&self, size: u64) -> Result<String, String> {
        Ok(hex::encode(root_from_peaks(&self.peak_hashes(size)?)))
    }
}

/// The newest cut for `log_id` in [`FILE_CHECKPOINTS`], with its statement.
fn last_cut(
    ledger_dir: &Path,
    log_id: &str,
) -> std::io::Result<Option<(CheckpointRecord, Vec<u8>)>> {
    let text = match std::fs::read(ledger_dir.join(FILE_CHECKPOINTS)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut last = None;
    for line in complete_lines(&text).0 {
        let Ok(mut value) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        let cose = value
            .as_object_mut()
            .and_then(|o| o.remove("checkpoint_cose"))
            .and_then(|v| hex::decode(v.as_str()?).ok());
        let (Some(cose), Ok(cp)) = (cose, serde_json::from_value::<CheckpointRecord>(value)) else {
            continue;
        };
        if cp.log_id == log_id {
            last = Some((cp, cose));
        }
    }
    Ok(last)
}

/// The latest checkpoint of `file` (one in [`CHECKPOINTED_FILES`]), cut now
/// if the file has grown since the last one. `Ok(None)` while the file holds
/// no complete line.
pub fn cut(
    ledger_dir: &Path,
    file: &str,
    node_log_id: &str,
    signer: &SigningKey,
) -> Result<Option<(CheckpointRecord, Vec<u8>)>, String> {
    if LeafRule::for_file(file) != Some(LeafRule::Sha256Line) {
        return Err(format!("{file} is not a file checkpointed here"));
    }
    let _guard = CUT_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let log_id = file_log_id(node_log_id, file);
    let tree =
        Tree::build(&ledger_dir.join(file), LeafRule::Sha256Line).map_err(|e| e.to_string())?;
    let last = last_cut(ledger_dir, &log_id).map_err(|e| e.to_string())?;
    if let Some((prev, _)) = &last {
        // A file that no longer holds what its last checkpoint committed
        // was rewritten: no checkpoint extends that.
        if prev.mmr_size > tree.size() || tree.root(prev.mmr_size)? != prev.root {
            return Err(format!(
                "{file} no longer holds the {} nodes its last checkpoint committed",
                prev.mmr_size
            ));
        }
        if prev.mmr_size == tree.size() {
            return Ok(last);
        }
    }
    let size = tree.size();
    if size == 0 {
        return Ok(None);
    }
    let (prev_size, prev_root) = last
        .as_ref()
        .map_or((0, String::new()), |(p, _)| (p.mmr_size, p.root.clone()));
    let mut cp = CheckpointRecord {
        v: 1,
        kind: CHECKPOINT_KIND.to_string(),
        log_id,
        mmr_size: size,
        root: tree.root(size)?,
        prev_size,
        prev_root,
        key_id: crate::commitment::key_id(signer),
        timestamp: crate::producer::timestamp::utc_now_minute(),
        signature: String::new(),
        witnesses: Vec::new(),
    };
    cp.signature = try_sign_checkpoint_digest(&cp, signer).map_err(|e| e.to_string())?;
    let (prev_peaks, consistency) = if prev_size > 0 {
        (
            Some(tree.peak_hashes(prev_size)?),
            Some(consistency_proof(&tree.nodes, prev_size, size).map_err(|e| e.to_string())?),
        )
    } else {
        (None, None)
    };
    let cose = checkpoint_to_cose(
        &cp,
        signer,
        &tree.peak_hashes(size)?,
        prev_peaks.as_deref(),
        consistency.as_ref(),
        None,
    )
    .map_err(|e| e.to_string())?;
    let mut line = serde_json::to_value(&cp).map_err(|e| e.to_string())?;
    line["checkpoint_cose"] = Value::String(hex::encode(&cose));
    append_line(&ledger_dir.join(FILE_CHECKPOINTS), &line).map_err(|e| e.to_string())?;
    Ok(Some((cp, cose)))
}

fn append_line(path: &Path, line: &Value) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    let mut text = String::new();
    // End a fragment a torn write left, so this line starts on its own.
    if file.metadata()?.len() > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::End(-1))?;
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            text.push('\n');
        }
    }
    text.push_str(&line.to_string());
    text.push('\n');
    file.write_all(text.as_bytes())?;
    file.sync_data()
}

/// Cut every checkpointed file that has grown: the cadence tick's work.
/// A file that cannot be cut is logged, never fatal.
pub fn cut_all(ledger_dir: &Path, node_log_id: &str, signer: &SigningKey) {
    for file in CHECKPOINTED_FILES {
        if let Err(why) = cut(ledger_dir, file, node_log_id, signer) {
            tracing::warn!(file, %why, "no ledger checkpoint cut for this file");
        }
    }
}

fn proof_json(proof: &RangeProof) -> Value {
    json!({
        "v": proof.v,
        "kind": proof.kind,
        "size": proof.size,
        "from_index": proof.from_index,
        "to_index": proof.to_index,
        "witness": proof.witness,
    })
}

fn proof_from_json(value: &Value) -> Option<RangeProof> {
    let obj = value.as_object()?;
    if obj.len() != 6 {
        return None;
    }
    Some(RangeProof {
        v: u32::try_from(obj.get("v")?.as_u64()?).ok()?,
        kind: obj.get("kind")?.as_str()?.to_string(),
        size: obj.get("size")?.as_u64()?,
        from_index: obj.get("from_index")?.as_u64()?,
        to_index: obj.get("to_index")?.as_u64()?,
        witness: obj
            .get("witness")?
            .as_array()?
            .iter()
            .map(|w| w.as_str().map(str::to_string))
            .collect::<Option<_>>()?,
    })
}

/// Why a reply was not built.
#[derive(Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// The asker's fault: an unknown file or a bad range.
    Invalid(String),
    /// Nothing to serve yet: the file holds no complete line, or no chain
    /// checkpoint covers what the chain held when asked. Ask again later.
    NotYet(String),
    /// This node's fault: a file it cannot read or sign over, or one that no
    /// longer holds what its checkpoint committed.
    Node(String),
}

/// The route's reply for `file`: its latest checkpoint and a range proof of
/// leaves `from..=to` (the whole file when both are `None`). A file's
/// checkpoint is cut now, so it covers every complete line. For the chain,
/// `covering` is how many records the chain held when asked: a newest chain
/// checkpoint short of it is refused rather than served stale.
pub fn reply(
    ledger_dir: &Path,
    node_log_id: &str,
    signer: &SigningKey,
    file: &str,
    from: Option<u64>,
    to: Option<u64>,
    covering: Option<u64>,
) -> Result<Value, ReplyError> {
    let rule = LeafRule::for_file(file).ok_or_else(|| {
        ReplyError::Invalid(format!("{file:?} is not a checkpointed ledger file"))
    })?;
    let (cp, cose) = match rule {
        LeafRule::Sha256Line => cut(ledger_dir, file, node_log_id, signer)
            .map_err(ReplyError::Node)?
            .ok_or_else(|| ReplyError::NotYet(format!("{file} holds no complete line yet")))?,
        LeafRule::CapsuleId => {
            let key_id = crate::commitment::key_id(signer);
            evidence_log::with_index(ledger_dir, &key_id, |index| index.chain.last().cloned())
                .map_err(|e| ReplyError::Node(e.to_string()))?
                .map(|c| (c.record, c.statement))
                .ok_or_else(|| ReplyError::NotYet("no checkpoint covers the chain yet".into()))?
        }
    };
    let tree =
        Tree::build(&ledger_dir.join(file), rule).map_err(|e| ReplyError::Node(e.to_string()))?;
    if cp.mmr_size > tree.size() || tree.root(cp.mmr_size).map_err(ReplyError::Node)? != cp.root {
        return Err(ReplyError::Node(format!(
            "{file} no longer holds what its checkpoint committed"
        )));
    }
    let leaves = leaf_count(cp.mmr_size).map_err(|e| ReplyError::Node(e.to_string()))?;
    if let Some(held) = covering.filter(|&held| held > leaves) {
        return Err(ReplyError::NotYet(format!(
            "the newest chain checkpoint covers {leaves} of the {held} records the chain held \
             when asked (the checkpoint cadence is off, or its cut failed)"
        )));
    }
    let (from, to) = match (from, to) {
        (None, None) => (0, leaves - 1),
        (Some(from), Some(to)) if from <= to && to < leaves => (from, to),
        (Some(_), Some(_)) => {
            return Err(ReplyError::Invalid(format!(
                "the range must be 0 <= from <= to < {leaves}"
            )))
        }
        _ => {
            return Err(ReplyError::Invalid(
                "give both from and to, or neither".into(),
            ))
        }
    };
    let proof = range_proof(&tree.nodes, from, to, cp.mmr_size)
        .map_err(|e| ReplyError::Node(e.to_string()))?;
    Ok(json!({
        "ledger_checkpoint": REPLY_VERSION,
        "file": file,
        "leaf_digest": rule.name(),
        "checkpoint": cp,
        "checkpoint_cose": hex::encode(&cose),
        "range_proof": proof_json(&proof),
    }))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LedgerCheckpointArgs {
    /// The ledger file's name, e.g. `received-provenance.jsonl`.
    pub file: Value,
    /// The first leaf index of the range (0-based), with `to`.
    #[serde(default)]
    pub from: Option<Value>,
    /// The last leaf index of the range (inclusive), with `from`.
    #[serde(default)]
    pub to: Option<Value>,
}

/// A leaf index given as a JSON number or a decimal string (a query value).
fn index_arg(value: Option<&Value>, name: &str) -> Result<Option<u64>, PluginError> {
    let parsed = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        _ => None,
    };
    parsed
        .map(Some)
        .ok_or_else(|| PluginError::invalid_params(format!("{name} must be a leaf index")))
}

/// The chain's last indexed record and how many records it holds: the tip
/// a fresh chain checkpoint must reach. `None` while it holds none.
fn chain_tip(ledger_dir: &Path, node_key_id: &str) -> std::io::Result<Option<(String, u64)>> {
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        let tip = index.leaves.last()?;
        Some((tip.capsule_id.clone(), index.leaves.len() as u64))
    })
}

/// Before a chain reply, have the cadence cut a checkpoint over the chain's
/// tip if none covers it yet (a cut pads the chain like any other; it waits
/// out the push window rather than fall back). Returns how many records the
/// chain held when asked, which the reply's checkpoint must reach; a chain
/// this node cannot read is refused, so the reply is never left unguarded.
async fn cover_chain_tip(
    checkpoints: Option<&crate::checkpoint_cadence::CheckpointHandle>,
    ledger_dir: &Path,
    signer: &SigningKey,
) -> Result<Option<u64>, ReplyError> {
    let (dir, key) = (ledger_dir.to_path_buf(), crate::commitment::key_id(signer));
    let Some((tip, held)) = tokio::task::spawn_blocking(move || chain_tip(&dir, &key))
        .await
        .map_err(|e| ReplyError::Node(format!("chain tip task did not complete: {e}")))?
        .map_err(|e| ReplyError::Node(e.to_string()))?
    else {
        return Ok(None);
    };
    if let Some(handle) = checkpoints {
        if let Err(why) = handle.coverage_for(&tip).await {
            tracing::warn!(%why, "no chain checkpoint cut for a ledger-checkpoint ask");
        }
    }
    Ok(Some(held))
}

fn plugin_error(error: ReplyError) -> PluginError {
    match error {
        ReplyError::Invalid(why) => PluginError::invalid_params(why),
        ReplyError::NotYet(why) => PluginError::invalid_request(why),
        ReplyError::Node(why) => PluginError::internal(why),
    }
}

/// `GET /ledger-checkpoint?file=<name>[&from=<i>&to=<j>]`. `checkpoints` is
/// the cadence's handle, which cuts the chain's checkpoints.
pub fn with_route(
    builder: DeclarativePluginBuilder,
    ledger_dir: std::path::PathBuf,
    node_log_id: String,
    signer: SigningKey,
    checkpoints: Option<crate::checkpoint_cadence::CheckpointHandle>,
) -> DeclarativePluginBuilder {
    builder.http_item(
        http::get("/ledger-checkpoint")
            .binding_id("evidence_ledger_checkpoint")
            .description(
                "A signed checkpoint over one of this node's ledger files and a range proof \
                 of a span of its lines, for checking a copy of the file offline. Cuts a \
                 checkpoint when the file has grown since its last one; for the chain, when \
                 no checkpoint covers its last record yet.",
            )
            .input::<LedgerCheckpointArgs>()
            .handle(move |args, _context| {
                let (dir, log_id, signer, checkpoints) = (
                    ledger_dir.clone(),
                    node_log_id.clone(),
                    signer.clone(),
                    checkpoints.clone(),
                );
                Box::pin(async move {
                    let file = args
                        .file
                        .as_str()
                        .ok_or_else(|| PluginError::invalid_params("file must be a file name"))?
                        .to_string();
                    let from = index_arg(args.from.as_ref(), "from")?;
                    let to = index_arg(args.to.as_ref(), "to")?;
                    let covering = if file == CAPSULES_FILE {
                        cover_chain_tip(checkpoints.as_ref(), &dir, &signer)
                            .await
                            .map_err(plugin_error)?
                    } else {
                        None
                    };
                    tokio::task::spawn_blocking(move || {
                        reply(&dir, &log_id, &signer, &file, from, to, covering)
                    })
                    .await
                    .map_err(|e| {
                        PluginError::internal(format!(
                            "ledger checkpoint task did not complete: {e}"
                        ))
                    })?
                    .map_err(plugin_error)
                })
            }),
    )
}

/// Check offline that `copy` holds exactly leaves `from..=to` (the whole
/// file when `range` is `None`) of the ledger file `reply` (a route reply)
/// commits to, under the node key `key_id` (raw Ed25519 public key, hex).
/// `Ok` says what was shown; `Err` says why not.
pub fn check(
    copy: &[u8],
    reply: &Value,
    key_id: &str,
    range: Option<(u64, u64)>,
) -> Result<String, String> {
    if reply.get("ledger_checkpoint").and_then(Value::as_u64) != Some(REPLY_VERSION) {
        return Err("not a ledger_checkpoint reply of version 1".into());
    }
    let file = reply
        .get("file")
        .and_then(Value::as_str)
        .ok_or("the reply names no file")?;
    let rule = LeafRule::for_file(file)
        .ok_or_else(|| format!("{file:?} is not a checkpointed ledger file"))?;
    if reply.get("leaf_digest").and_then(Value::as_str) != Some(rule.name()) {
        return Err(format!("{file}'s leaves are digested as {}", rule.name()));
    }
    // The statement is the authority: it must verify under the given key and
    // state exactly the checkpoint the reply shows.
    let cose = reply
        .get("checkpoint_cose")
        .and_then(Value::as_str)
        .and_then(|h| hex::decode(h).ok())
        .ok_or("the reply carries no checkpoint statement")?;
    let cp: CheckpointRecord =
        serde_json::from_value(reply.get("checkpoint").cloned().unwrap_or_default())
            .map_err(|e| format!("the reply's checkpoint is malformed: {e}"))?;
    if cp.key_id != key_id {
        return Err(format!(
            "the checkpoint is signed by {}, not by the given key",
            cp.key_id
        ));
    }
    if !evidence_log::states(&cose, &cp) || !cp.verify_signature_offline() {
        return Err(
            "the checkpoint statement does not verify, or does not state the reply's checkpoint"
                .into(),
        );
    }
    // A file's checkpoint is of that file's log; the chain's is of the
    // node's own log, never a file's.
    let file_log = match rule {
        LeafRule::Sha256Line => cp.log_id.ends_with(&format!("/ledger/{file}")),
        LeafRule::CapsuleId => !cp.log_id.contains("/ledger/"),
    };
    if !file_log {
        return Err(format!(
            "the checkpoint's log {} is not {file}'s",
            cp.log_id
        ));
    }
    let proof = reply
        .get("range_proof")
        .and_then(proof_from_json)
        .ok_or("the reply carries no range proof")?;
    let leaves = leaf_count(cp.mmr_size).map_err(|e| format!("mmr_size: {e}"))?;
    let (from, to) = range.unwrap_or((0, leaves.saturating_sub(1)));
    if (proof.from_index, proof.to_index) != (from, to) {
        return Err(format!(
            "the range proof covers leaves {}..={}, not {from}..={to}",
            proof.from_index, proof.to_index
        ));
    }
    let (lines, fragment) = complete_lines(copy);
    if fragment {
        return Err("the copy ends in a line with no newline".into());
    }
    let expected = to
        .checked_sub(from)
        .map(|n| n + 1)
        .ok_or("the range is empty")?;
    if lines.len() as u64 != expected {
        return Err(format!(
            "the copy holds {} lines, but leaves {from}..={to} are {expected}",
            lines.len()
        ));
    }
    let digests = lines
        .iter()
        .enumerate()
        .map(|(i, line)| checker_body_digest(rule, i, line))
        .collect::<Result<Vec<_>, _>>()?;
    let root = hex_hash(&cp.root).ok_or("the checkpoint's root is not a digest")?;
    if !verify_range(&root, cp.mmr_size, from, to, &digests, &proof) {
        return Err(format!(
            "the copied lines are not leaves {from}..={to} of the checkpointed {file}"
        ));
    }
    Ok(if range.is_none() {
        format!(
            "{file}: the copy is the whole file at the checkpoint ({leaves} lines, log {}, cut {})",
            cp.log_id, cp.timestamp
        )
    } else {
        format!(
            "{file}: the copy is exactly lines {}..={} of {leaves} at the checkpoint (log {}, cut {})",
            from + 1,
            to + 1,
            cp.log_id,
            cp.timestamp
        )
    })
}

/// `capsules ledger-check --file <copy> --checkpoint <reply.json> --key
/// <key_id> [--from <i> --to <j>]`: 0 when the copy checks, 1 when it does
/// not, 2 for a usage error. The reason goes to stderr.
pub fn cli(args: &[String]) -> i32 {
    const USAGE: &str = "usage: capsules ledger-check --file <copy> --checkpoint <reply.json> \
                         --key <node key id> [--from <i> --to <j>]";
    let mut file = None;
    let mut checkpoint = None;
    let mut key = None;
    let mut from = None;
    let mut to = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let Some(value) = it.next() else {
            eprintln!("{flag} needs a value\n{USAGE}");
            return 2;
        };
        let slot = match flag.as_str() {
            "--file" => &mut file,
            "--checkpoint" => &mut checkpoint,
            "--key" => &mut key,
            "--from" => &mut from,
            "--to" => &mut to,
            _ => {
                eprintln!("unknown argument {flag}\n{USAGE}");
                return 2;
            }
        };
        *slot = Some(value.clone());
    }
    let (Some(file), Some(checkpoint), Some(key)) = (file, checkpoint, key) else {
        eprintln!("{USAGE}");
        return 2;
    };
    let range = match (from.map(|s| s.parse::<u64>()), to.map(|s| s.parse::<u64>())) {
        (None, None) => None,
        (Some(Ok(from)), Some(Ok(to))) => Some((from, to)),
        _ => {
            eprintln!("--from and --to are leaf indices, given together\n{USAGE}");
            return 2;
        }
    };
    let result = std::fs::read(&file)
        .map_err(|e| format!("cannot read {file}: {e}"))
        .and_then(|copy| {
            let text =
                std::fs::read(&checkpoint).map_err(|e| format!("cannot read {checkpoint}: {e}"))?;
            let reply: Value = serde_json::from_slice(&text)
                .map_err(|e| format!("{checkpoint} is not JSON: {e}"))?;
            check(&copy, &reply, &key, range)
        });
    match result {
        Ok(what) => {
            println!("ok: {what}");
            0
        }
        Err(why) => {
            eprintln!("fail: {why}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record_push_receive::RECEIVED_PROVENANCE_FILENAME as PROVENANCE;
    use std::io::Write;

    const LOG: &str = "capsules/node";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn key_id() -> String {
        crate::commitment::key_id(&key())
    }

    fn lines(n: std::ops::Range<usize>) -> String {
        n.map(|i| format!("{{\"capsule_id\":\"{i:064x}\",\"received_from\":\"peer-{i}\"}}\n"))
            .collect()
    }

    fn write(dir: &Path, text: &str) {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(PROVENANCE))
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }

    fn whole(dir: &Path) -> Value {
        reply(dir, LOG, &key(), PROVENANCE, None, None, None).unwrap()
    }

    #[test]
    fn a_route_reply_verifies_and_a_whole_file_copy_passes() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &lines(0..5));
        let reply = whole(dir.path());
        assert_eq!(reply["leaf_digest"], LEAF_SHA256_LINE);
        assert_eq!(reply["checkpoint"]["log_id"], file_log_id(LOG, PROVENANCE));
        assert_eq!(reply["checkpoint"]["key_id"], key_id());
        let copy = std::fs::read(dir.path().join(PROVENANCE)).unwrap();
        let ok = check(&copy, &reply, &key_id(), None).unwrap();
        assert!(ok.contains("whole file"), "{ok}");
    }

    #[test]
    fn a_copy_with_a_line_dropped_or_altered_fails() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &lines(0..5));
        let reply = whole(dir.path());
        let full = lines(0..5);
        let all: Vec<&str> = full.split_inclusive('\n').collect();
        let dropped: String = all
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 2)
            .map(|(_, l)| *l)
            .collect();
        assert!(check(dropped.as_bytes(), &reply, &key_id(), None).is_err());
        let altered = full.replace("peer-3", "peer-9");
        let why = check(altered.as_bytes(), &reply, &key_id(), None).unwrap_err();
        assert!(why.contains("not leaves"), "{why}");
        // The same number of lines, one swapped for a line from elsewhere.
        let swapped = full.replace("peer-4", "peer-0");
        assert!(check(swapped.as_bytes(), &reply, &key_id(), None).is_err());
    }

    #[test]
    fn a_range_extract_passes_and_fails_missing_a_line() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &lines(0..9));
        let reply = reply(dir.path(), LOG, &key(), PROVENANCE, Some(2), Some(5), None).unwrap();
        let extract = lines(2..6);
        let ok = check(extract.as_bytes(), &reply, &key_id(), Some((2, 5))).unwrap();
        assert!(ok.contains("lines 3..=6"), "{ok}");
        let missing: String = lines(2..4) + &lines(5..6);
        assert!(check(missing.as_bytes(), &reply, &key_id(), Some((2, 5))).is_err());
        // The right count, the wrong lines: positions 3..6 claimed as 2..5.
        assert!(check(lines(3..7).as_bytes(), &reply, &key_id(), Some((2, 5))).is_err());
        // A proof of 2..5 shows nothing about the whole file.
        assert!(check(extract.as_bytes(), &reply, &key_id(), None).is_err());
    }

    #[test]
    fn a_stale_checkpoint_after_growth_still_verifies_for_its_own_size() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &lines(0..3));
        let old = whole(dir.path());
        // Asking again without growth reuses the cut.
        assert_eq!(whole(dir.path())["checkpoint"], old["checkpoint"]);
        write(dir.path(), &lines(3..7));
        let new = whole(dir.path());
        assert_eq!(
            new["checkpoint"]["prev_size"],
            old["checkpoint"]["mmr_size"]
        );
        assert_eq!(new["checkpoint"]["prev_root"], old["checkpoint"]["root"]);
        assert!(check(lines(0..3).as_bytes(), &old, &key_id(), None).is_ok());
        assert!(check(lines(0..7).as_bytes(), &new, &key_id(), None).is_ok());
        // The grown file is not the file at the old checkpoint.
        assert!(check(lines(0..7).as_bytes(), &old, &key_id(), None).is_err());
    }

    #[test]
    fn another_key_or_another_files_checkpoint_fails() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &lines(0..4));
        let reply = whole(dir.path());
        let copy = lines(0..4);
        let other = crate::commitment::key_id(&SigningKey::from_bytes(&[8u8; 32]));
        assert!(check(copy.as_bytes(), &reply, &other, None).is_err());
        let mut relabelled = reply.clone();
        relabelled["file"] = json!(crate::record_push_receive::RECEIVED_CAPSULES_FILENAME);
        assert!(check(copy.as_bytes(), &relabelled, &key_id(), None).is_err());
        let mut edited = reply.clone();
        edited["checkpoint"]["mmr_size"] = json!(1);
        assert!(check(copy.as_bytes(), &edited, &key_id(), None).is_err());
    }

    #[test]
    fn a_torn_fragment_is_not_a_leaf_until_it_is_ended() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &(lines(0..2) + "{\"torn"));
        let reply = whole(dir.path());
        assert!(check(lines(0..2).as_bytes(), &reply, &key_id(), None).is_ok());
        write(dir.path(), "\n");
        let grown = whole(dir.path());
        let copy = std::fs::read(dir.path().join(PROVENANCE)).unwrap();
        assert!(check(&copy, &grown, &key_id(), None).is_ok());
    }

    #[test]
    fn an_unknown_file_a_bad_range_and_an_empty_file_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let r = |file: &str, from, to| reply(dir.path(), LOG, &key(), file, from, to, None);
        assert!(matches!(
            r("../secret", None, None),
            Err(ReplyError::Invalid(_))
        ));
        assert!(matches!(
            r("referee-pairs.jsonl", None, None),
            Err(ReplyError::Invalid(_))
        ));
        assert!(matches!(
            r(PROVENANCE, None, None),
            Err(ReplyError::NotYet(_))
        ));
        write(dir.path(), &lines(0..3));
        assert!(matches!(
            r(PROVENANCE, Some(2), Some(3)),
            Err(ReplyError::Invalid(_))
        ));
        assert!(matches!(
            r(PROVENANCE, Some(2), Some(1)),
            Err(ReplyError::Invalid(_))
        ));
        assert!(matches!(
            r(PROVENANCE, Some(0), None),
            Err(ReplyError::Invalid(_))
        ));
    }

    #[test]
    fn a_rewritten_file_gets_no_new_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &lines(0..3));
        whole(dir.path());
        std::fs::write(dir.path().join(PROVENANCE), lines(1..5)).unwrap();
        let err = reply(dir.path(), LOG, &key(), PROVENANCE, None, None, None).unwrap_err();
        assert!(
            matches!(err, ReplyError::Node(ref why) if why.contains("no longer holds")),
            "{err:?}"
        );
    }

    #[test]
    fn the_chain_is_served_under_its_own_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let state =
            crate::capsule_emit::CapsuleState::open(dir.path(), "ledger-checkpoint-test").unwrap();
        // A paid exchange's deal records (real capsules), then padding.
        let deals = state.deals();
        let h = |c: char| c.to_string().repeat(64);
        deals.on_invoice(&state, "exchange-1", &h('a'), 1000, 1_790_000_000);
        deals.on_exchange(
            &state,
            "exchange-1",
            &crate::deal_flow::SealedExchange {
                capsule_id: &h('e'),
                peer: "peer-node",
                request_digest: &h('d'),
                model: "model-x",
            },
            1_790_000_001,
        );
        state.pad_one().unwrap();
        crate::deal_receipt::tests::cut(&state);
        let ledger = state.ledger_dir();
        let reply = reply(
            ledger,
            LOG,
            state.signing_key(),
            CAPSULES_FILE,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(reply["leaf_digest"], LEAF_CAPSULE_ID);
        assert_eq!(reply["checkpoint"]["log_id"], "test-log");
        let node = crate::commitment::key_id(state.signing_key());
        let copy = std::fs::read(ledger.join(CAPSULES_FILE)).unwrap();
        assert!(check(&copy, &reply, &node, None).is_ok());
        let (all, _) = complete_lines(&copy);
        let dropped: Vec<u8> = all[1..].iter().flat_map(|l| [*l, b"\n"].concat()).collect();
        assert!(check(&dropped, &reply, &node, None).is_err());
    }

    #[tokio::test]
    async fn a_chain_ask_cuts_a_checkpoint_over_records_sealed_since_the_last() {
        let dir = tempfile::tempdir().unwrap();
        let state = std::sync::Arc::new(
            crate::capsule_emit::CapsuleState::open(dir.path(), "ledger-checkpoint-test").unwrap(),
        );
        let deals = state.deals();
        let h = |c: char| c.to_string().repeat(64);
        deals.on_invoice(&*state, "exchange-1", &h('a'), 1000, 1_790_000_000);
        deals.on_exchange(
            &*state,
            "exchange-1",
            &crate::deal_flow::SealedExchange {
                capsule_id: &h('e'),
                peer: "peer-node",
                request_digest: &h('d'),
                model: "model-x",
            },
            1_790_000_001,
        );
        crate::deal_receipt::tests::cut(&state);
        let ledger = state.ledger_dir().to_path_buf();
        let node = crate::commitment::key_id(state.signing_key());
        // A record sealed after the last checkpoint, as step 07's outcome is.
        state.pad_one().unwrap();
        let read = std::fs::read(ledger.join(CAPSULES_FILE)).unwrap();
        let stale = reply(
            &ledger,
            LOG,
            state.signing_key(),
            CAPSULES_FILE,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(check(&read, &stale, &node, None).is_err());
        // With no cadence to cut one, the ask is refused, not served stale.
        let held = cover_chain_tip(None, &ledger, state.signing_key())
            .await
            .unwrap();
        assert_eq!(held, Some(complete_lines(&read).0.len() as u64));
        let refused = reply(
            &ledger,
            LOG,
            state.signing_key(),
            CAPSULES_FILE,
            None,
            None,
            held,
        );
        assert!(matches!(refused, Err(ReplyError::NotYet(ref why)) if why.contains("cadence")));

        let handle =
            crate::checkpoint_cadence::CheckpointHandle::for_tests(state.clone(), "test-log");
        let held = cover_chain_tip(Some(&handle), &ledger, state.signing_key())
            .await
            .unwrap();
        let fresh = reply(
            &ledger,
            LOG,
            state.signing_key(),
            CAPSULES_FILE,
            None,
            None,
            held,
        )
        .unwrap();
        assert!(
            fresh["checkpoint"]["mmr_size"].as_u64() > stale["checkpoint"]["mmr_size"].as_u64()
        );
        // The cut padded the chain: the copy is read after the ask, up to the
        // checkpoint's last leaf, and holds the record read before it.
        let leaves = fresh["range_proof"]["to_index"].as_u64().unwrap() as usize + 1;
        let after = std::fs::read(ledger.join(CAPSULES_FILE)).unwrap();
        let (all, _) = complete_lines(&after);
        assert!(all.len() >= leaves && leaves >= complete_lines(&read).0.len());
        let copy: Vec<u8> = all[..leaves]
            .iter()
            .flat_map(|l| [*l, b"\n"].concat())
            .collect();
        assert!(
            check(&copy, &fresh, &node, None).is_ok(),
            "{:?}",
            check(&copy, &fresh, &node, None)
        );
        // Asked again with nothing new sealed, the same checkpoint serves.
        let held = cover_chain_tip(Some(&handle), &ledger, state.signing_key())
            .await
            .unwrap();
        let again = reply(
            &ledger,
            LOG,
            state.signing_key(),
            CAPSULES_FILE,
            None,
            None,
            held,
        )
        .unwrap();
        assert_eq!(again["checkpoint"], fresh["checkpoint"]);
    }

    #[test]
    fn a_cadence_tick_cuts_each_grown_file_once() {
        let dir = tempfile::tempdir().unwrap();
        let cuts = || {
            std::fs::read_to_string(dir.path().join(FILE_CHECKPOINTS))
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str::<Value>(l).unwrap()["log_id"].clone())
                .collect::<Vec<_>>()
        };
        write(dir.path(), &lines(0..3));
        std::fs::write(dir.path().join(CHECKPOINTED_FILES[0]), lines(0..2)).unwrap();
        cut_all(dir.path(), LOG, &key());
        assert_eq!(cuts().len(), 2);
        // Only the file that grew is cut again; an untouched one is not.
        write(dir.path(), &lines(3..4));
        cut_all(dir.path(), LOG, &key());
        let all = cuts();
        assert_eq!(all.len(), 3);
        assert_eq!(all[2], json!(file_log_id(LOG, PROVENANCE)));
        let reply = whole(dir.path());
        assert!(check(lines(0..4).as_bytes(), &reply, &key_id(), None).is_ok());
        assert_eq!(cuts().len(), 3, "the ask reuses the tick's cut");
    }

    #[test]
    fn a_file_checkpoint_relabelled_as_the_chain_fails() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &lines(0..3));
        let mut reply = whole(dir.path());
        reply["file"] = json!(CAPSULES_FILE);
        reply["leaf_digest"] = json!(LEAF_CAPSULE_ID);
        let err = check(lines(0..3).as_bytes(), &reply, &key_id(), None).unwrap_err();
        assert!(err.contains("is not capsules.jsonl's"), "{err}");
    }

    #[test]
    fn the_cli_exits_0_on_a_good_copy_1_on_a_bad_one_and_2_on_misuse() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &lines(0..6));
        let reply_path = dir.path().join("reply.json");
        std::fs::write(&reply_path, whole(dir.path()).to_string()).unwrap();
        let copy = dir.path().join("copy.jsonl");
        std::fs::write(&copy, lines(0..6)).unwrap();
        let args = |extra: &[&str]| -> Vec<String> {
            [
                "--file",
                copy.to_str().unwrap(),
                "--checkpoint",
                reply_path.to_str().unwrap(),
                "--key",
                &key_id(),
            ]
            .iter()
            .chain(extra)
            .map(|s| s.to_string())
            .collect()
        };
        assert_eq!(cli(&args(&[])), 0);
        std::fs::write(&copy, lines(0..5)).unwrap();
        assert_eq!(cli(&args(&[])), 1);
        assert_eq!(cli(&args(&["--from", "0"])), 2);
        assert_eq!(cli(&["--file".to_string()]), 2);
    }
}
