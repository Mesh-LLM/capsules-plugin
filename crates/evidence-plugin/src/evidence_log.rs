//! This node's ledger as the evidence-request responder sees it: the index
//! an answer is built from (`evidence_answer`) and a [`Responder`] (what a
//! request is resolved against).
//!
//! **Read-only, and its own MMR.** The plugin's checkpoint cadence owns the
//! durable node store (`mmr_nodes.dat`) and is its only writer; opening it a
//! second time would run its torn-write recovery from here. So this index
//! folds `capsules.jsonl` into an in-memory MMR of its own (the same leaves:
//! each line's `capsule_id`, padding included, in file order) and keeps it
//! current incrementally: each answer reads only the complete lines appended
//! since the last one. A file that was replaced or rewritten under the index
//! (its last indexed line no longer matches) is re-indexed from the start.
//!
//! **Only checkpoints this index re-derives.** A checkpoint from
//! `checkpoints.jsonl` joins the chain only if it is signed by this node's
//! key, chains from the stream's first checkpoint, its root is the root
//! this index computes at its size, and its line carries its own COSE wire
//! statement (below). The first checkpoint that fails any of these ends the
//! chain: nothing after it is served, so an answer is never signed under a
//! root its proofs would not reach, and every checkpoint an answer lists
//! extends the one listed before it. A line that is not a
//! well-formed record (no 64-hex `capsule_id`) ends the index the same way,
//! as the checkpointer refuses to fold one.
//!
//! **Anchors are identified by their statement.** Each chain checkpoint is
//! an anchor, identified by the SHA-256 of its COSE wire statement
//! (`checkpoint_cose`): the `cll-checkpoint` item of the interop profile
//! (agent-action-capsule `spec/interop-profile-v0.md` §6.2.1), the value a
//! requester pins, as evidencebook and the Go responder identify one. The
//! statement must verify under this node's key and state exactly the
//! checkpoint on its line. The checkpointer writes it best-effort, so a line
//! without one, or with another, ends the chain like any other failure.
//!
//! **What a record is here.** A record's digest is its `capsule_id` (the leaf
//! the checkpoints commit to) and its body is its line in `capsules.jsonl`,
//! byte for byte, producer envelope included. A requester checks one with
//! [`record_digest`]: the body's recomputed `capsule_id`, which must equal the
//! one it states. The body is not the `capsule_id` preimage, so its SHA-256 is
//! not its digest: the interop profile's Checkpointed Local Log check reports
//! such a record `NOT_CHECKED` (profile §6.2.1 step 5), and this node's
//! requester checks it instead (`evidence_artifact`).
//!
//! **Padding** (Evidence Layer -00 §12.1) is a leaf, so a range carries it,
//! but it is never a record: it is not found by digest, correlation or
//! exchange.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cll::checkpoint::{verify_checkpoint_cose_offline, CheckpointRecord};
use cll::mmr::{
    add_leaf, leaf_count, leaf_hash, peaks, root_from_peaks, Hash, MemoryNodeStore, NodeReader,
};
use evidence_request::registry::{SubjectForm, DERIVATION_HISTORY_CARD};
use evidence_request::request::Derivation;
use evidence_request::resolve::{Anchor, Responder};
use serde_json::Value;
use sha2::{Digest, Sha256};

use evidencebook::served_summary::{
    latency, LeafFacts, Outcome, ServedFacts, DERIVATION as SERVED_SUMMARY_DERIVATION_TOKEN,
};

pub const CAPSULES_FILE: &str = "capsules.jsonl";
pub const CHECKPOINTS_FILE: &str = "checkpoints.jsonl";
/// Which exchange record each deal capsule (a step or a report of an
/// `x-deal-v0` deal) is of: one `{"capsule_id", "exchange_capsule_id"}` line
/// per capsule, written by the node before it seals the capsule. A deal
/// capsule names no counterparty itself, so the share gate takes the one of
/// the exchange record it is of (Mesh-LLM/capsules-plugin#96).
pub const DEAL_LINKS_FILE: &str = "deal-links.jsonl";

/// The longest correlation identifier indexed. A longer value in a record is
/// not an identifier anyone asks by; not indexing it bounds the index.
const MAX_CORRELATION_ID_LEN: usize = 256;

/// The members whose text values identify an exchange a record belongs to
/// (a `correlation` subject), wherever they appear in the record. The same
/// correlators the Python reference matched by nonce and exchange id; a
/// counterparty's id is an identity, not a correlation, and is not one.
const CORRELATION_KEYS: [&str; 3] = ["nonce", "client_nonce", "exchange_id"];

/// The `client_nonce` a host-served record carries when the host forwarded
/// none. Every such record carries it, so it names no exchange and is never
/// indexed: asking by it would answer with unrelated records.
pub const HOST_SERVED_NO_NONCE: &str = "host-served-no-nonce";

/// The prefix of an exchange's digest binding (see [`exchange_binding`]).
const EXCHANGE_BINDING_PREFIX: &str = "exchange-digests:";

/// The correlation identifier that names an exchange by both of its digests:
/// `exchange-digests:<request digest>:<response digest>`, the two `effect`
/// digests both sides' records carry. A record is found by it only when both
/// digests are exactly its own. It is how a requester finds the other side's
/// record when that record carries no nonce of its own (a host-served half,
/// [`HOST_SERVED_NO_NONCE`]): the requester knows both digests from its own
/// half.
pub fn exchange_binding(request_digest: &str, response_digest: &str) -> String {
    format!("{EXCHANGE_BINDING_PREFIX}{request_digest}:{response_digest}")
}

/// A record's digest binding, when its `effect` carries both digests.
fn record_exchange_binding(record: &Value) -> Option<String> {
    let effect = record.get("effect")?;
    let request = effect
        .get("request_digest")?
        .as_str()
        .filter(|d| is_digest(d))?;
    let response = effect
        .get("response_digest")?
        .as_str()
        .filter(|d| is_digest(d))?;
    Some(exchange_binding(request, response))
}

/// One line of the ledger.
#[derive(Clone, Debug)]
pub struct Leaf {
    pub capsule_id: String,
    offset: u64,
    len: u64,
    pub padding: bool,
    /// The other side of the exchange this record is of, if it names one
    /// (`evidence_panes::full_counterparty_node_id`).
    pub counterparty: Option<String>,
    /// For a citing record, the key the cited half verified under
    /// (`citing_key`): a request signed under it is from the other side of
    /// that exchange.
    pub counterparty_key: Option<String>,
    /// A local routing choice, a record of this node's asks
    /// (`crate::ask_book`), an owner-maintenance record or a deal's report:
    /// it never leaves this node, whoever asks.
    pub never_leaves: bool,
    pub facts: LeafFacts,
}

/// Test seam: a writer that acts between `refresh`'s read of the capsules
/// and its read of the links.
#[cfg(test)]
pub(crate) mod tests_between_reads {
    use std::cell::RefCell;

    thread_local! {
        static WRITER: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    pub(crate) fn set(writer: impl FnOnce() + 'static) {
        WRITER.with(|w| *w.borrow_mut() = Some(Box::new(writer)));
    }

    pub(super) fn run() {
        if let Some(writer) = WRITER.with(|w| w.borrow_mut().take()) {
            writer();
        }
    }
}

/// The key a citing record (`CapsuleState::emit_citing_record`) holds a
/// half under: `received_half.sender_key_id`, which the receiver seals only
/// for a push it accepted on that key (`accepted_via`), so it is the key the
/// half verified under. The node holding that key is the other side of the
/// exchange the half is of, so a request signed under it may have the
/// citing record (Mesh-LLM/capsules-plugin#172). The record's
/// `received_from` is the pusher's own word (`record_push_receive`) and
/// names no one.
fn citing_key(record: &Value) -> Option<String> {
    if cfg!(feature = "mutant-citing-record-names-no-counterparty") {
        return None;
    }
    if counterparty_half_citations(record).is_empty() {
        return None;
    }
    let half = record.pointer("/model_attestation/compute_attestation/received_half")?;
    half.get("accepted_via")?;
    half.get("sender_key_id")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
        .map(str::to_string)
}

/// A deal capsule: one of a deal's steps (`deal_id`) or its report. A link
/// names a counterparty for these and for no other record.
fn is_deal_capsule(record: &Value) -> bool {
    record.get("deal_id").is_some() || is_deal_report(record)
}

/// Whether `record` never leaves this node, whoever asks: a local routing
/// choice, a record of the node's asks, a deal's report or an owner-maintenance
/// record. Every path that serves a ledger record to another node checks this
/// one predicate (the index's [`Leaf::never_leaves`] is it).
pub(crate) fn never_leaves(record: &Value) -> bool {
    crate::evidence_panes::is_local_routing_choice(record)
        || crate::ask_book::is_ask_record(record)
        || is_deal_report(record)
        || record
            .pointer("/model_attestation/compute_attestation")
            .and_then(|c| c.get(crate::producer::capsule::OWNER_MAINTENANCE_BLOCK))
            .is_some()
}

/// A deal's in-log report. It is the owner's own (audience `keep`): a copy
/// for the counterparty is made only by a share path, so this one never
/// leaves the node (Mesh-LLM/capsules-plugin#146).
pub(crate) fn is_deal_report(record: &Value) -> bool {
    record.get("action_id").and_then(Value::as_str) == Some("capsulectl-deal-report")
}

/// One line of [`DEAL_LINKS_FILE`]: the deal capsule and the exchange record
/// it is of, both full capsule ids.
fn parse_deal_link(line: &[u8]) -> Option<(String, String)> {
    let value: Value = serde_json::from_slice(line).ok()?;
    let id = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|id| is_digest(id))
            .map(str::to_string)
    };
    Some((id("capsule_id")?, id("exchange_capsule_id")?))
}

/// A position in an append-only file: how much has been read, and the last
/// complete line read (its offset and digest), to tell an append from a
/// rewrite.
#[derive(Clone, Debug, Default)]
struct Tail {
    consumed: u64,
    last_line: Option<(u64, [u8; 32])>,
}

impl Tail {
    /// Call `f` on each complete line appended since the last call, with its
    /// offset, in order, until `f` returns `false`. Returns `Ok(false)`
    /// without calling `f` when the file no longer continues what was read
    /// (replaced, truncated or rewritten): read it again from the start. A
    /// missing file is an empty one. A line still being written (no newline
    /// yet) is left for the next call.
    fn read_new(
        &self,
        path: &Path,
        mut f: impl FnMut(u64, &[u8]) -> bool,
    ) -> std::io::Result<bool> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(self.consumed == 0),
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        if len < self.consumed {
            return Ok(false);
        }
        if let Some((offset, digest)) = self.last_line {
            let mut line = vec![0u8; (self.consumed - offset) as usize];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut line)?;
            if <[u8; 32]>::from(Sha256::digest(&line)) != digest {
                return Ok(false);
            }
        }
        file.seek(SeekFrom::Start(self.consumed))?;
        let mut reader = std::io::BufReader::new(file.take(len - self.consumed));
        let mut offset = self.consumed;
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = reader.read_until(b'\n', &mut line)?;
            if n == 0 || line.last() != Some(&b'\n') || !f(offset, &line) {
                return Ok(true);
            }
            offset += n as u64;
        }
    }

    fn advance(&mut self, offset: u64, line: &[u8]) {
        self.consumed = offset + line.len() as u64;
        self.last_line = Some((offset, Sha256::digest(line).into()));
    }
}

/// What a consistency proof is made of: the old peaks, each one's path into
/// the new MMR, and the new peaks.
pub type ConsistencyParts = (Vec<Hash>, Vec<Vec<Hash>>, Vec<Hash>);

/// One checkpoint of the chain, with its COSE wire statement.
#[derive(Clone, Debug)]
pub struct ChainCheckpoint {
    pub record: CheckpointRecord,
    /// The `cll-checkpoint` octets: a statement that verifies under this
    /// node's key and states exactly `record`.
    pub statement: Vec<u8>,
}

impl ChainCheckpoint {
    /// The digest an anchor is pinned by: the SHA-256 of its statement.
    pub fn anchor_digest(&self) -> String {
        hex::encode(Sha256::digest(&self.statement))
    }
}

/// The index of one ledger directory.
pub struct LedgerIndex {
    ledger_dir: PathBuf,
    /// This node's key (`key_id` form: raw public key, lowercase hex). Only
    /// checkpoints it signed are anchors.
    node_key_id: String,
    capsules: Tail,
    checkpoints: Tail,
    deal_links: Tail,
    /// Deal capsule id to the id of the exchange record it is of
    /// ([`DEAL_LINKS_FILE`]).
    deal_exchange: HashMap<String, String>,
    pub leaves: Vec<Leaf>,
    nodes: MemoryNodeStore,
    by_id: HashMap<String, u64>,
    correlations: HashMap<String, Vec<u64>>,
    /// SHA-256 (lowercase hex) of each record's bound client nonce, to the
    /// records that carry it: the only key `exchange_corroboration/1`
    /// resolves against ([`LedgerIndex::by_client_nonce`]).
    client_nonces: HashMap<String, Vec<u64>>,
    citations: HashMap<String, Vec<u64>>,
    /// Why indexing stopped, if it did: nothing after this line is a leaf.
    capsules_stopped: Option<String>,
    /// The valid checkpoint chain, oldest first.
    pub chain: Vec<ChainCheckpoint>,
    /// Why the chain ended, if it did.
    chain_stopped: Option<String>,
}

impl LedgerIndex {
    fn new(ledger_dir: &Path, node_key_id: &str) -> Self {
        Self {
            ledger_dir: ledger_dir.to_path_buf(),
            node_key_id: node_key_id.to_string(),
            capsules: Tail::default(),
            checkpoints: Tail::default(),
            deal_links: Tail::default(),
            deal_exchange: HashMap::new(),
            leaves: Vec::new(),
            nodes: MemoryNodeStore::new(),
            by_id: HashMap::new(),
            correlations: HashMap::new(),
            client_nonces: HashMap::new(),
            citations: HashMap::new(),
            capsules_stopped: None,
            chain: Vec::new(),
            chain_stopped: None,
        }
    }

    /// Bring the index up to date with the capsules, the deal links and the
    /// checkpoints.
    pub fn refresh(&mut self) -> std::io::Result<()> {
        // The capsules to index are read first and the links second: the node
        // writes a deal capsule's link before the capsule, so a capsule seen
        // here has its link on disk by the time the links are read.
        let mut pending: Vec<(u64, Vec<u8>)> = Vec::new();
        let start = self.capsules.clone();
        if self.capsules_stopped.is_none() {
            let path = self.ledger_dir.join(CAPSULES_FILE);
            let continues = start.read_new(&path, |offset, line| {
                pending.push((offset, line.to_vec()));
                true
            })?;
            if !continues {
                *self = Self::new(&self.ledger_dir, &self.node_key_id);
                return self.refresh();
            }
        }
        #[cfg(test)]
        tests_between_reads::run();
        let links = self.deal_links.clone();
        let mut links_tail = links.clone();
        let continues =
            links.read_new(&self.ledger_dir.join(DEAL_LINKS_FILE), |offset, line| {
                if let Some((capsule, exchange)) = parse_deal_link(trim_newline(line)) {
                    // The first link of a capsule stands.
                    self.deal_exchange.entry(capsule).or_insert(exchange);
                }
                links_tail.advance(offset, line);
                true
            })?;
        if !continues {
            *self = Self::new(&self.ledger_dir, &self.node_key_id);
            return self.refresh();
        }
        self.deal_links = links_tail;
        let mut tail = start;
        for (offset, line) in pending {
            if let Err(why) = self.index_line(offset, &line) {
                tracing::warn!(line_at = offset, %why, "evidence index stops at a ledger line it cannot fold");
                self.capsules_stopped = Some(why);
                break;
            }
            tail.advance(offset, &line);
        }
        self.capsules = tail;
        let path = self.ledger_dir.join(CHECKPOINTS_FILE);
        if !self.take_checkpoints(&path)? {
            self.checkpoints = Tail::default();
            self.chain.clear();
            self.chain_stopped = None;
            self.take_checkpoints(&path)?;
        }
        Ok(())
    }

    /// The counterparty of the exchange record a deal capsule is of, if the
    /// capsule is linked to one that is already indexed (an exchange record
    /// is sealed before its deal).
    fn deal_counterparty(&self, capsule_id: &str) -> Option<String> {
        let exchange = self.deal_exchange.get(capsule_id)?;
        let at = *self.by_id.get(exchange)?;
        self.leaves.get(at as usize)?.counterparty.clone()
    }

    fn index_line(&mut self, offset: u64, line: &[u8]) -> Result<(), String> {
        let body = trim_newline(line);
        let record: Value = serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
        let capsule_id = record
            .get("capsule_id")
            .and_then(Value::as_str)
            .filter(|id| is_digest(id))
            .ok_or("no 64-hex capsule_id")?
            .to_string();
        let raw: [u8; 32] = hex::decode(&capsule_id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or("capsule_id is not 32 bytes")?;
        add_leaf(&mut self.nodes, leaf_hash(&raw)).map_err(|e| e.to_string())?;
        let index = self.leaves.len() as u64;
        let padding = crate::producer::padding::is_padding(&record);
        if !padding {
            self.by_id.entry(capsule_id.clone()).or_insert(index);
            for id in record_correlation_ids(&record) {
                self.correlations.entry(id).or_default().push(index);
            }
            if let Some(digest) = client_nonce_digest(&record) {
                self.client_nonces.entry(digest).or_default().push(index);
            }
            for half in counterparty_half_citations(&record) {
                self.citations.entry(half).or_default().push(index);
            }
        }
        let counterparty =
            crate::evidence_panes::full_counterparty_node_id(&record).or_else(|| {
                is_deal_capsule(&record)
                    .then(|| self.deal_counterparty(&capsule_id))
                    .flatten()
            });
        let counterparty_key = citing_key(&record);
        self.leaves.push(Leaf {
            capsule_id,
            offset,
            len: body.len() as u64,
            padding,
            counterparty,
            counterparty_key,
            never_leaves: never_leaves(&record),
            facts: leaf_facts(&record),
        });
        Ok(())
    }

    /// Extend the chain from the checkpoint lines appended since the last
    /// call. `Ok(false)` when the file was rewritten.
    fn take_checkpoints(&mut self, path: &Path) -> std::io::Result<bool> {
        let start = self.checkpoints.clone();
        let mut tail = start.clone();
        let continues = start.read_new(path, |offset, line| {
            if self.chain_stopped.is_some() {
                return false;
            }
            match self.check_checkpoint(trim_newline(line)) {
                // The ledger has not reached it yet: read it again next time.
                Ok(None) => return false,
                Ok(Some(cp)) => self.chain.push(cp),
                Err(why) => {
                    tracing::warn!(line_at = offset, %why, "evidence anchors stop at a checkpoint this index cannot re-derive");
                    self.chain_stopped = Some(why);
                }
            }
            tail.advance(offset, line);
            true
        })?;
        if continues {
            self.checkpoints = tail;
        }
        Ok(continues)
    }

    /// `Some` for a checkpoint that extends the chain; `None` for one past
    /// what the index holds yet; `Err` for one that ends the chain.
    fn check_checkpoint(&self, body: &[u8]) -> Result<Option<ChainCheckpoint>, String> {
        let mut value: Value =
            serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
        let cose_hex = value
            .as_object_mut()
            .and_then(|obj| obj.remove("checkpoint_cose"));
        let cp: CheckpointRecord =
            serde_json::from_value(value).map_err(|e| format!("not a checkpoint: {e}"))?;
        if cp.key_id != self.node_key_id || !cp.verify_signature_offline() {
            return Err("not signed by this node's key".into());
        }
        match self.chain.last().map(|c| &c.record) {
            None if cp.prev_size != 0 || !cp.prev_root.is_empty() => {
                return Err("the first checkpoint does not start the stream".into())
            }
            Some(prev)
                if cp.prev_size != prev.mmr_size
                    || cp.prev_root != prev.root
                    || cp.mmr_size <= prev.mmr_size
                    || cp.log_id != prev.log_id =>
            {
                return Err("does not chain from the previous checkpoint".into())
            }
            _ => {}
        }
        leaf_count(cp.mmr_size).map_err(|e| format!("mmr_size: {e}"))?;
        if cp.mmr_size > self.nodes.size() {
            return if self.capsules_stopped.is_some() {
                Err("covers leaves past where the ledger index stopped".into())
            } else {
                Ok(None)
            };
        }
        let peak_hashes: Vec<_> = peaks(cp.mmr_size)
            .map_err(|e| e.to_string())?
            .iter()
            .map(|&p| self.nodes.node(p))
            .collect();
        if hex::encode(root_from_peaks(&peak_hashes)) != cp.root {
            return Err("its root is not this ledger's root at its size".into());
        }
        let statement = cose_hex
            .as_ref()
            .and_then(Value::as_str)
            .and_then(|h| hex::decode(h).ok())
            .filter(|s| states(s, &cp))
            .ok_or("its line carries no COSE statement of its own")?;
        Ok(Some(ChainCheckpoint {
            record: cp,
            statement,
        }))
    }

    /// The inclusion path (sibling hashes, leaf upward) of `leaf_index` in
    /// the MMR of `size` nodes.
    pub fn inclusion_path(&self, leaf_index: u64, size: u64) -> Option<Vec<Hash>> {
        let proof = cll::mmr::inclusion_proof(&self.nodes, leaf_index, size).ok()?;
        hashes(&proof.witness)
    }

    /// What a consistency proof from the MMR of `from` nodes to the MMR of
    /// `to` nodes is made of: the old peaks, each one's path into the new
    /// MMR, and the new peaks.
    pub fn consistency_parts(&self, from: u64, to: u64) -> Option<ConsistencyParts> {
        let proof = cll::mmr::consistency_proof(&self.nodes, from, to).ok()?;
        Some((
            hashes(&proof.old_peaks)?,
            proof
                .witness
                .iter()
                .map(|p| hashes(p))
                .collect::<Option<_>>()?,
            hashes(&proof.new_peaks)?,
        ))
    }

    /// The deal capsules linked to `exchange_capsule_id`, in log order.
    pub fn deal_capsules_of(&self, exchange_capsule_id: &str) -> Vec<&str> {
        let mut found: Vec<(u64, &str)> = self
            .deal_exchange
            .iter()
            .filter(|(_, exchange)| exchange.as_str() == exchange_capsule_id)
            .filter_map(|(id, _)| Some((self.leaf_index_of(id)?, id.as_str())))
            .collect();
        found.sort_unstable();
        found.into_iter().map(|(_, id)| id).collect()
    }

    /// The inclusion proof of `leaf_index` in the MMR of `size` nodes, in
    /// the form a Bundle carries it.
    pub fn inclusion_proof(
        &self,
        leaf_index: u64,
        size: u64,
    ) -> Result<cll::mmr::InclusionProof, cll::mmr::MmrError> {
        cll::mmr::inclusion_proof(&self.nodes, leaf_index, size)
    }

    pub fn leaf_index_of(&self, capsule_id: &str) -> Option<u64> {
        self.by_id.get(capsule_id).copied()
    }

    pub fn correlated(&self, id: &str) -> &[u64] {
        self.correlations.get(id).map_or(&[], Vec::as_slice)
    }

    pub fn citing(&self, half: &str) -> &[u64] {
        self.citations.get(half).map_or(&[], Vec::as_slice)
    }

    /// The records whose bound client nonce hashes to `digest` (64 lowercase
    /// hex). Never the wider [`LedgerIndex::correlated`] index: an
    /// `exchange_id`, a request nonce or a digest binding equal to `digest`
    /// finds nothing here.
    pub fn by_client_nonce(&self, digest: &str) -> &[u64] {
        if cfg!(feature = "mutant-corroboration-wide-index") {
            return self.correlated(digest);
        }
        self.client_nonces.get(digest).map_or(&[], Vec::as_slice)
    }

    /// A view that reads record bodies from the ledger file.
    pub fn view(&self) -> std::io::Result<LogView<'_>> {
        Ok(LogView {
            index: self,
            file: File::open(self.ledger_dir.join(CAPSULES_FILE)).ok(),
        })
    }
}

/// One process-wide index per ledger directory, kept current across answers.
static INDEXES: Mutex<Option<HashMap<PathBuf, LedgerIndex>>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    static INDEX_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many times this thread has read an index ([`with_index`]): a test
/// shows a refusal came before the ledger was read.
#[cfg(test)]
pub fn index_reads() -> u64 {
    INDEX_READS.with(std::cell::Cell::get)
}

/// Run `f` over the up-to-date index of `ledger_dir`. Answers are serialized
/// per process by this lock: the work under it is bounded by the answer
/// limits, and the index is shared state.
pub fn with_index<T>(
    ledger_dir: &Path,
    node_key_id: &str,
    f: impl FnOnce(&LedgerIndex) -> T,
) -> std::io::Result<T> {
    #[cfg(test)]
    INDEX_READS.with(|n| n.set(n.get() + 1));
    let mut guard = INDEXES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let indexes = guard.get_or_insert_with(HashMap::new);
    let index = indexes
        .entry(ledger_dir.to_path_buf())
        .or_insert_with(|| LedgerIndex::new(ledger_dir, node_key_id));
    if index.node_key_id != node_key_id {
        *index = LedgerIndex::new(ledger_dir, node_key_id);
    }
    index.refresh()?;
    Ok(f(index))
}

/// The index plus the ledger file, for reading bodies.
pub struct LogView<'a> {
    pub index: &'a LedgerIndex,
    file: Option<File>,
}

impl LogView<'_> {
    /// The record at `leaf_index`, its body read from the ledger. `None`
    /// when the line is no longer the one indexed.
    pub fn record_at(&self, leaf_index: u64) -> Option<Record> {
        let leaf = self.index.leaves.get(usize::try_from(leaf_index).ok()?)?;
        let mut body = vec![0u8; usize::try_from(leaf.len).ok()?];
        let mut file = self.file.as_ref()?;
        file.seek(SeekFrom::Start(leaf.offset)).ok()?;
        file.read_exact(&mut body).ok()?;
        let parsed: Value = serde_json::from_slice(&body).ok()?;
        (parsed.get("capsule_id").and_then(Value::as_str) == Some(leaf.capsule_id.as_str())).then(
            || Record {
                leaf_index,
                digest: leaf.capsule_id.clone(),
                body,
            },
        )
    }
}

/// One record, as an answer serves it: evidencebook's, its `digest` the
/// line's `capsule_id` and its `body` the line.
pub use evidencebook::store::Record;

/// A record's digest as a requester computes it from the body it was sent:
/// the body's recomputed `capsule_id`, when that is the id the body states.
/// `None` for a body that is not a record of this format.
pub fn record_digest(body: &[u8]) -> Option<String> {
    let record = crate::producer::jcs::decode_record(body).ok()?;
    let stated = record.get("capsule_id").and_then(Value::as_str)?;
    let recomputed = crate::producer::jcs::compute_capsule_id(&record).ok()?;
    (recomputed == stated).then_some(recomputed)
}

/// Whether `statement` is this checkpoint's own COSE wire statement: it
/// verifies under its `kid`, which is the checkpoint's key, and it states
/// exactly the checkpoint's log, sizes, roots and time.
pub(crate) fn states(statement: &[u8], cp: &CheckpointRecord) -> bool {
    let verified = verify_checkpoint_cose_offline(statement);
    let Some(decoded) = verified.decoded.filter(|_| verified.ok) else {
        return false;
    };
    decoded.key_id == cp.key_id
        && decoded.to_checkpoint_record().signing_body() == cp.signing_body()
}

fn hashes(hex_list: &[String]) -> Option<Vec<Hash>> {
    hex_list
        .iter()
        .map(|h| hex::decode(h).ok()?.try_into().ok())
        .collect()
}

/// `cp` as evidencebook's checkpoint type: the same fields and witness
/// records, member for member.
pub fn book_checkpoint(cp: &CheckpointRecord) -> evidencebook::substrate::Checkpoint {
    evidencebook::substrate::Checkpoint {
        v: cp.v,
        kind: cp.kind.clone(),
        log_id: cp.log_id.clone(),
        mmr_size: cp.mmr_size,
        root: cp.root.clone(),
        prev_size: cp.prev_size,
        prev_root: cp.prev_root.clone(),
        key_id: cp.key_id.clone(),
        timestamp: cp.timestamp.clone(),
        signature: cp.signature.clone(),
        witnesses: cp
            .witnesses
            .iter()
            .map(|w| evidencebook::substrate::WitnessEntry {
                ts_url: w.ts_url.clone(),
                entry_hash: w.entry_hash.clone(),
                receipt_b64: w.receipt_b64.clone(),
                leaf_index: w.leaf_index,
                tree_size: w.tree_size,
                is_stub: w.is_stub,
            })
            .collect(),
    }
}

/// The record side of evidencebook's store, over this index (evidencebook#35):
/// the crate reads the plugin's ledger through it and never opens a file the
/// checkpointer owns. A line's committed entry is the `capsule_id` it states,
/// the id this index keys it by.
impl evidencebook::store::RecordSource for LogView<'_> {
    fn record_by_digest(&self, digest: &str) -> Option<evidencebook::store::Record> {
        LogView::record_at(self, self.index.leaf_index_of(digest)?)
    }
    fn record_at(&self, leaf_index: u64) -> Option<evidencebook::store::Record> {
        LogView::record_at(self, leaf_index)
    }
    fn leaf_index_of(&self, digest: &str) -> Option<u64> {
        self.index.leaf_index_of(digest)
    }
    fn correlation(&self, id: &str) -> Vec<u64> {
        self.index.correlated(id).to_vec()
    }
    fn citing(&self, half_digest: &str) -> Vec<u64> {
        self.index.citing(half_digest).to_vec()
    }
    /// The `capsule_id` the line states, as [`LogView::record_at`] checks a
    /// line against the one indexed; `None` for octets that are no JSON
    /// object stating one.
    fn entry_of(&self, body: &[u8]) -> Option<String> {
        let parsed: Value = serde_json::from_slice(body).ok()?;
        parsed
            .get("capsule_id")
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

/// The commitment side of evidencebook's store: this index's re-derived
/// chain and its own MMR, never the checkpointer's node store.
impl evidencebook::store::CheckpointedLog for LogView<'_> {
    fn leaf_count(&self) -> Result<u64, evidencebook::substrate::SubstrateError> {
        Ok(self.index.leaves.len() as u64)
    }
    fn stated_checkpoints(
        &self,
    ) -> Result<
        Vec<evidencebook::substrate::StatedCheckpoint>,
        evidencebook::substrate::SubstrateError,
    > {
        Ok(self
            .index
            .chain
            .iter()
            .map(|cp| evidencebook::substrate::StatedCheckpoint {
                checkpoint: book_checkpoint(&cp.record),
                statement: cp.statement.clone(),
            })
            .collect())
    }
    fn inclusion_path(
        &self,
        leaf_index: u64,
        mmr_size: u64,
    ) -> Result<Vec<[u8; 32]>, evidencebook::substrate::SubstrateError> {
        self.index
            .inclusion_path(leaf_index, mmr_size)
            .ok_or_else(|| {
                evidencebook::substrate::SubstrateError::Mmr(format!(
                    "no inclusion path for leaf {leaf_index} in an MMR of {mmr_size} nodes"
                ))
            })
    }
    fn consistency_parts(
        &self,
        from: u64,
        to: u64,
    ) -> Result<evidencebook::store::ConsistencyParts, evidencebook::substrate::SubstrateError>
    {
        self.index.consistency_parts(from, to).ok_or_else(|| {
            evidencebook::substrate::SubstrateError::Mmr(format!(
                "no consistency proof from {from} to {to} nodes"
            ))
        })
    }
}

impl Responder for LogView<'_> {
    fn holds_record(&self, digest: &str) -> bool {
        self.index.leaf_index_of(digest).is_some()
    }
    fn holds_correlation(&self, id: &str) -> bool {
        !self.index.correlated(id).is_empty()
    }
    fn cites_exchange(&self, half_digest: &str) -> bool {
        !self.index.citing(half_digest).is_empty()
    }
    fn positional_ordering(&self) -> bool {
        true
    }
    fn anchors(&self) -> Vec<Anchor> {
        self.index
            .chain
            .iter()
            .filter_map(|cp| {
                Some(Anchor {
                    digest: cp.anchor_digest(),
                    size: leaf_count(cp.record.mmr_size).ok()?,
                    issued_at: cp.record.timestamp.clone(),
                })
            })
            .collect()
    }
    fn derivation_forms(&self, derivation: &Derivation) -> Option<Vec<SubjectForm>> {
        match derivation {
            Derivation::Token(t) if t == DERIVATION_HISTORY_CARD => {
                Some(vec![SubjectForm::FullHistory, SubjectForm::Checkpoints])
            }
            Derivation::Token(t) if t == SERVED_SUMMARY_DERIVATION_TOKEN => {
                Some(vec![SubjectForm::FullHistory])
            }
            d if crate::service_history::is_derivation(Some(d)) => {
                Some(vec![SubjectForm::FullHistory])
            }
            _ => None,
        }
    }
}

fn trim_newline(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The correlation identifiers a record carries: every `nonce`,
/// `client_nonce` and `exchange_id` in it, and its exchange binding. The
/// index keys `correlation` answers on these, and the requester checks a
/// `correlation` answer's records against them.
pub(crate) fn record_correlation_ids(record: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    collect_correlations(record, &mut ids);
    ids.extend(record_exchange_binding(record));
    ids.sort();
    ids.dedup();
    ids
}

fn collect_correlations(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if CORRELATION_KEYS.contains(&k.as_str()) {
                    if let Some(id) = v.as_str().filter(|s| {
                        !s.is_empty()
                            && s.len() <= MAX_CORRELATION_ID_LEN
                            && *s != HOST_SERVED_NO_NONCE
                    }) {
                        out.push(id.to_string());
                    }
                }
                collect_correlations(v, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| collect_correlations(v, out)),
        _ => {}
    }
}

/// The SHA-256 (lowercase hex) of the client nonce a record binds, over the
/// nonce's UTF-8 octets: `x-mesh-poc-v1.client_nonce` and nothing else. `None`
/// when the record binds none, binds the host-served placeholder (which every
/// nonce-less host-served record carries, so it names no exchange), or one
/// out of the indexed bounds.
pub fn client_nonce_digest(record: &Value) -> Option<String> {
    record
        .pointer("/model_attestation/compute_attestation/x-mesh-poc-v1/client_nonce")
        .and_then(Value::as_str)
        .filter(|nonce| {
            !nonce.is_empty()
                && nonce.len() <= MAX_CORRELATION_ID_LEN
                && *nonce != HOST_SERVED_NO_NONCE
        })
        .map(|nonce| hex::encode(Sha256::digest(nonce.as_bytes())))
}

/// The exchange halves a record cites as its counterparty's half
/// (`references[].citation_purpose == "counterparty_half"`), the citation the
/// ledger itself keys on.
pub(crate) fn counterparty_half_citations(record: &Value) -> Vec<String> {
    record
        .get("references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|r| r.get("citation_purpose").and_then(Value::as_str) == Some("counterparty_half"))
        .filter_map(|r| r.get("digest").and_then(Value::as_str))
        .filter(|d| is_digest(d))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_request_parity::{
        corpus_checkpoints, corpus_ledger, write_jsonl, NODE_KEY_SEED,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn key_id() -> String {
        hex::encode(
            SigningKey::from_bytes(&NODE_KEY_SEED)
                .verifying_key()
                .to_bytes(),
        )
    }

    fn checkpoint_lines(ledger: &[Value], key: &SigningKey) -> Vec<Value> {
        corpus_checkpoints(ledger, key)
            .iter()
            .map(|cp| cp.line())
            .collect()
    }

    /// The record `emit_citing_record` seals for a half it accepted on a key
    /// carries that key in the index (`counterparty_key`, #172), and names no
    /// counterparty from `received_from`, the pusher's own word. A citing
    /// record of a push accepted on no key carries none.
    #[test]
    fn a_sealed_citing_record_carries_the_key_its_half_verified_under() {
        use crate::capsule_emit::{CapsuleState, ReceivedHalfProvenance};
        let dir = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(dir.path(), "node-under-test").unwrap();
        let key = "b".repeat(64);
        let via = crate::peer_keys::AcceptedVia::HostAnnounced;
        let prov = |foreign: &'static str, accepted: bool| ReceivedHalfProvenance {
            foreign_capsule_id: foreign,
            received_from: "any-id-the-pusher-names",
            via: "push",
            received_at: "2026-09-25T00:00:00Z",
            signature_ok: true,
            digest_match: None,
            foreign_agent_input_digest: None,
            foreign_agent_output_digest: None,
            sender_key_id: accepted.then_some(key.as_str()),
            accepted_via: accepted.then_some(&via),
            controller_binding: None,
            same_controller_as_receiver: None,
            own_half_capsule_id: None,
        };
        let accepted: &'static str = "d".repeat(64).leak();
        let unkeyed: &'static str = "e".repeat(64).leak();
        let citing = state
            .emit_citing_record(&prov(accepted, true))
            .unwrap()
            .unwrap()
            .capsule;
        state
            .emit_citing_record(&prov(unkeyed, false))
            .unwrap()
            .unwrap();
        assert!(
            crate::evidence_panes::full_counterparty_node_id(&citing).is_none(),
            "the sealed shape carries no x-mesh-poc-v1 block"
        );
        let leaves = with_index(state.ledger_dir(), &key_id(), |index| {
            [accepted, unkeyed].map(|half| {
                let leaf = &index.leaves[index.citing(half)[0] as usize];
                (leaf.counterparty.clone(), leaf.counterparty_key.clone())
            })
        })
        .unwrap();
        assert_eq!(leaves[0], (None, Some(key.clone())));
        assert_eq!(leaves[1], (None, None));
    }

    #[test]
    fn a_line_still_being_written_is_indexed_once_it_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = corpus_ledger();
        let path = dir.path().join(CAPSULES_FILE);
        let mut text: String = ledger[..3].iter().map(|l| format!("{l}\n")).collect();
        text.push_str(&ledger[3].to_string());
        std::fs::write(&path, &text).unwrap();
        let mut index = LedgerIndex::new(dir.path(), &key_id());
        index.refresh().unwrap();
        assert_eq!(index.leaves.len(), 3);
        text.push('\n');
        std::fs::write(&path, &text).unwrap();
        index.refresh().unwrap();
        assert_eq!(index.leaves.len(), 4);
    }

    #[test]
    fn a_rewritten_ledger_is_indexed_again_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = corpus_ledger();
        let path = dir.path().join(CAPSULES_FILE);
        write_jsonl(&path, &ledger[..4]);
        let mut index = LedgerIndex::new(dir.path(), &key_id());
        index.refresh().unwrap();
        // Same length or longer, different lines: not an append.
        let mut rewritten = ledger[4..8].to_vec();
        rewritten.push(ledger[8].clone());
        write_jsonl(&path, &rewritten);
        index.refresh().unwrap();
        let ids: Vec<&str> = index.leaves.iter().map(|l| l.capsule_id.as_str()).collect();
        let want: Vec<&str> = rewritten
            .iter()
            .map(|l| l["capsule_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, want);
    }

    #[test]
    fn only_checkpoints_this_index_re_derives_are_anchors() {
        let ledger = corpus_ledger();
        let key = SigningKey::from_bytes(&NODE_KEY_SEED);

        // Both checkpoints re-derive.
        let dir = tempfile::tempdir().unwrap();
        write_jsonl(&dir.path().join(CAPSULES_FILE), &ledger);
        write_jsonl(
            &dir.path().join(CHECKPOINTS_FILE),
            &checkpoint_lines(&ledger, &key),
        );
        let mut index = LedgerIndex::new(dir.path(), &key_id());
        index.refresh().unwrap();
        assert_eq!(index.chain.len(), 2);

        // Signed by another key: no anchors.
        let other = SigningKey::from_bytes(&[7u8; 32]);
        write_jsonl(
            &dir.path().join(CHECKPOINTS_FILE),
            &checkpoint_lines(&ledger, &other),
        );
        let mut index = LedgerIndex::new(dir.path(), &key_id());
        index.refresh().unwrap();
        assert!(index.chain.is_empty());

        // Over a different ledger (one leaf changed): the chain ends before
        // the checkpoint whose root no longer matches.
        let mut tampered = ledger.clone();
        tampered[20] = ledger[19].clone();
        write_jsonl(&dir.path().join(CAPSULES_FILE), &tampered);
        write_jsonl(
            &dir.path().join(CHECKPOINTS_FILE),
            &checkpoint_lines(&ledger, &key),
        );
        let mut index = LedgerIndex::new(dir.path(), &key_id());
        index.refresh().unwrap();
        assert_eq!(
            index.chain.len(),
            1,
            "checkpoint 0 re-derives; checkpoint 1 does not"
        );
    }

    #[test]
    fn a_checkpoint_ahead_of_the_ledger_waits_for_it() {
        let ledger = corpus_ledger();
        let key = SigningKey::from_bytes(&NODE_KEY_SEED);
        let dir = tempfile::tempdir().unwrap();
        write_jsonl(&dir.path().join(CAPSULES_FILE), &ledger[..100]);
        write_jsonl(
            &dir.path().join(CHECKPOINTS_FILE),
            &checkpoint_lines(&ledger, &key),
        );
        let mut index = LedgerIndex::new(dir.path(), &key_id());
        index.refresh().unwrap();
        assert_eq!(index.chain.len(), 1);
        write_jsonl(&dir.path().join(CAPSULES_FILE), &ledger);
        index.refresh().unwrap();
        assert_eq!(index.chain.len(), 2);
    }

    /// A host-served half carries the placeholder nonce, never the one the
    /// requester forwarded: it is found by its two digests, only both
    /// exactly, and never by the placeholder every such half shares.
    #[test]
    fn a_host_served_half_is_found_by_its_digests_not_its_placeholder_nonce() {
        let (req, resp) = ("a".repeat(64), "b".repeat(64));
        let half = |req: &str, resp: &str| {
            crate::evidence_request_parity::sealed(json!({
                "effect": {"status": "confirmed", "request_digest": req, "response_digest": resp},
                "model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {
                    "role": "served",
                    "client_nonce": HOST_SERVED_NO_NONCE,
                    "client_nonce_source": "host_served_observed",
                }}},
            }))
        };
        let ours = half(&req, &resp);
        let other = half(&"c".repeat(64), &resp);
        let dir = tempfile::tempdir().unwrap();
        write_jsonl(&dir.path().join(CAPSULES_FILE), &[other, ours.clone()]);
        let mut index = LedgerIndex::new(dir.path(), &key_id());
        index.refresh().unwrap();
        assert_eq!(index.correlated(&exchange_binding(&req, &resp)), &[1]);
        assert!(index.correlated(HOST_SERVED_NO_NONCE).is_empty());
        assert!(index.correlated(&exchange_binding(&req, &req)).is_empty());
        assert!(index.correlated(&exchange_binding(&resp, &req)).is_empty());
        assert!(
            index.correlated(&req).is_empty(),
            "one digest alone is no binding"
        );
    }

    #[test]
    fn padding_is_a_leaf_but_never_a_record() {
        let ledger = corpus_ledger();
        let dir = tempfile::tempdir().unwrap();
        write_jsonl(&dir.path().join(CAPSULES_FILE), &ledger);
        let mut index = LedgerIndex::new(dir.path(), &key_id());
        index.refresh().unwrap();
        let padding_id = ledger[9]["capsule_id"].as_str().unwrap();
        assert!(index.leaves[9].padding);
        assert_eq!(index.leaf_index_of(padding_id), None);
        let view = index.view().unwrap();
        assert!(view.record_at(9).is_some());
        assert_eq!(
            record_digest(&view.record_at(9).unwrap().body).as_deref(),
            Some(padding_id)
        );
    }
}

/// What the served summary (evidencebook's `served_summary`) reads from one
/// ledger line, in this plugin's record shape: a served record's model,
/// quantization, outcome, latency and whether it states a weights digest,
/// and an adjudication verdict's two halves. Padding reads as nothing.
/// Never a requester-identity field (`cross_party.initiator_ref`,
/// `serving_provenance.requesting_party`/`counterparty_ref`): the summary
/// answers what was served, never who asked.
pub fn leaf_facts(record: &Value) -> LeafFacts {
    if crate::producer::padding::is_padding(record) {
        return LeafFacts::default();
    }
    let served = (crate::evidence_panes::label_role(record) == "served").then(|| {
        let poc = record.pointer("/model_attestation/compute_attestation/x-mesh-poc-v1");
        let provenance = poc.and_then(|p| p.get("serving_provenance"));
        let text_or_unknown = |key: &str| {
            provenance
                .and_then(|sp| sp.get(key))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("unknown")
                .to_string()
        };
        ServedFacts {
            group: text_or_unknown("model_canonical_ref"),
            variant: text_or_unknown("quantization"),
            outcome: match record.pointer("/effect/status").and_then(Value::as_str) {
                Some("confirmed") => Outcome::Completed,
                Some("failed" | "reverted") => Outcome::Failed,
                _ => Outcome::Unknown,
            },
            latency_ms: poc.and_then(|p| p.get("latency_ms")).and_then(latency),
            digest_present: provenance
                .and_then(|sp| sp.get("weights_digest"))
                .is_some_and(|w| !w.is_null()),
        }
    });
    let adjudicated_halves = crate::producer::capsule::is_adjudication(record)
        .then(|| record.pointer("/model_attestation/compute_attestation/adjudication"))
        .flatten()
        .filter(|a| is_truthy(a))
        .map(|a| {
            let half = |k: &str| a.get(k).and_then(Value::as_str).map(str::to_string);
            (half("half_a_capsule_id"), half("half_b_capsule_id"))
        });
    LeafFacts {
        served,
        adjudicated_halves,
    }
}

/// Python truthiness of a JSON value, as `if not adjudication` reads it.
fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[cfg(test)]
mod leaf_facts_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_verdict_is_read_whether_it_writes_confirms_or_the_legacy_adjudicates() {
        for relation in ["confirms", "adjudicates"] {
            let record = json!({"chain": {"relation": relation},
                "model_attestation": {"compute_attestation": {"epistemic_type": "adjudication",
                    "adjudication": {"half_a_capsule_id": "a", "half_b_capsule_id": "b"}}}});
            assert_eq!(
                leaf_facts(&record).adjudicated_halves,
                Some((Some("a".into()), Some("b".into()))),
                "{relation}"
            );
        }
        let plain = json!({"chain": {"relation": "confirms"},
            "model_attestation": {"compute_attestation": {"adjudication": {"half_a_capsule_id": "a"}}}});
        assert_eq!(leaf_facts(&plain).adjudicated_halves, None);
    }

    #[test]
    fn a_served_record_reads_its_model_quantization_outcome_and_latency() {
        let record = json!({
            "effect": {"status": "reverted"},
            "model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {
                "role": "served", "latency_ms": " 12.5 ",
                "serving_provenance": {"model_canonical_ref": "m", "quantization": "",
                                       "weights_digest": "w", "requesting_party": "someone"}
            }}}
        });
        assert_eq!(
            leaf_facts(&record).served,
            Some(ServedFacts {
                group: "m".into(),
                variant: "unknown".into(),
                outcome: Outcome::Failed,
                latency_ms: Some(12.5),
                digest_present: true,
            })
        );
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use crate::evidence_request_parity::{corpus_ledger, corpus_ledger_dir, NODE_KEY_SEED};
    use evidencebook::store::{CheckpointedLog, RecordSource};

    /// The corpus ledger's index, with `f` run over its view.
    fn over_corpus<T>(f: impl FnOnce(&LogView<'_>) -> T) -> T {
        let dir = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&NODE_KEY_SEED);
        corpus_ledger_dir(dir.path(), &key);
        let key_id = hex::encode(key.verifying_key().to_bytes());
        with_index(dir.path(), &key_id, |index| f(&index.view().unwrap())).unwrap()
    }

    /// The crate reads every record as this index serves it: by position,
    /// by its `capsule_id` (padding by none), and through the correlation
    /// and citation sets.
    #[test]
    fn the_record_side_is_the_index() {
        over_corpus(|view| {
            let ledger = corpus_ledger();
            assert_eq!(view.leaf_count().unwrap(), ledger.len() as u64);
            for (i, line) in ledger.iter().enumerate() {
                let i = i as u64;
                let id = line["capsule_id"].as_str().unwrap();
                let book = RecordSource::record_at(view, i).unwrap();
                assert_eq!((book.leaf_index, book.digest.as_str()), (i, id));
                assert_eq!(view.entry_of(&book.body).as_deref(), Some(id));
                if crate::producer::padding::is_padding(line) {
                    assert_eq!(RecordSource::leaf_index_of(view, id), None, "padding {i}");
                    assert_eq!(view.record_by_digest(id), None, "padding {i}");
                } else {
                    assert_eq!(RecordSource::leaf_index_of(view, id), Some(i), "{i}");
                    assert_eq!(view.record_by_digest(id), Some(book), "{i}");
                }
            }
            assert_eq!(view.correlation("n-1"), view.index.correlated("n-1"));
            let half = crate::evidence_request_parity::foreign_half();
            assert_eq!(view.citing(&half), vec![6]);
            assert_eq!(view.citing(&"00".repeat(32)), Vec::<u64>::new());
            assert!(view.record_by_digest(&"00".repeat(32)).is_none());
            assert_eq!(view.entry_of(b"not json"), None);
            assert_eq!(view.entry_of(b"{\"no\":\"id\"}"), None);
        });
    }

    /// A `capsule_id` committed twice is found at its first leaf and read at
    /// both; a line whose stated id is not the one its body recomputes to
    /// is served by its stated id, as the index serves it today.
    #[test]
    fn a_repeated_line_and_a_stated_id_are_served_as_the_index_serves_them() {
        use crate::evidence_request_parity::{corpus_checkpoints, write_jsonl};
        let mut ledger = corpus_ledger();
        ledger[20] = ledger[2].clone();
        ledger[5]["extra"] = serde_json::json!("not in the capsule_id");
        let dir = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&NODE_KEY_SEED);
        write_jsonl(&dir.path().join(CAPSULES_FILE), &ledger);
        let lines: Vec<Value> = corpus_checkpoints(&ledger, &key)
            .iter()
            .map(|c| c.line())
            .collect();
        write_jsonl(&dir.path().join(CHECKPOINTS_FILE), &lines);
        let key_id = hex::encode(key.verifying_key().to_bytes());
        with_index(dir.path(), &key_id, |index| {
            let view = index.view().unwrap();
            let twice = ledger[2]["capsule_id"].as_str().unwrap();
            assert_eq!(RecordSource::leaf_index_of(&view, twice), Some(2));
            assert_eq!(view.record_by_digest(twice).unwrap().leaf_index, 2);
            assert_eq!(RecordSource::record_at(&view, 20).unwrap().digest, twice);

            let stated = ledger[5]["capsule_id"].as_str().unwrap();
            let served = view.record_by_digest(stated).unwrap();
            assert_eq!(served.leaf_index, 5);
            assert_eq!(view.entry_of(&served.body).as_deref(), Some(stated));
            assert_eq!(
                record_digest(&served.body),
                None,
                "the recomputed id differs"
            );
        })
        .unwrap();
    }

    /// The crate's checkpoints are this index's chain, statement and fields
    /// unchanged, and its proofs are the index's own.
    #[test]
    fn the_commitment_side_is_the_index() {
        over_corpus(|view| {
            let stated = view.stated_checkpoints().unwrap();
            assert_eq!(stated.len(), view.index.chain.len());
            for (book, ours) in stated.iter().zip(&view.index.chain) {
                assert_eq!(book.statement, ours.statement);
                assert_eq!(
                    serde_json::to_value(&book.checkpoint).unwrap(),
                    serde_json::to_value(&ours.record).unwrap(),
                    "every field and witness record"
                );
            }
            let (first, last) = (&stated[0].checkpoint, &stated[stated.len() - 1].checkpoint);
            assert_eq!(
                view.inclusion_path(3, last.mmr_size).unwrap(),
                view.index.inclusion_path(3, last.mmr_size).unwrap()
            );
            assert_eq!(
                view.consistency_parts(first.mmr_size, last.mmr_size)
                    .unwrap(),
                view.index
                    .consistency_parts(first.mmr_size, last.mmr_size)
                    .unwrap()
            );
            assert!(view.inclusion_path(10_000, last.mmr_size).is_err());
            assert!(view
                .consistency_parts(last.mmr_size, first.mmr_size)
                .is_err());
        });
    }
}
