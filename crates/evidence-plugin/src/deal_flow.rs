//! When a paid exchange's `x-deal-v0` deal is sealed, and what survives a
//! restart (Mesh-LLM/capsules-plugin#96, the payer's side).
//!
//! A deal exists only for an exchange with at least one invoice issued: a
//! free exchange keeps its `x-mesh-poc-v1` record and gets none. One deal per
//! exchange, `deal_id` random, never derived from an id of the exchange.
//!
//! - **baseline** once the exchange's record is sealed and an invoice was
//!   issued for it. It asks for the exchange by its request digest and model,
//!   committed under a nonce this node keeps, and names the serving peer by
//!   fingerprint only.
//! - **outcome** then **close** once the payer's legs show the deal is done
//!   (every invoice paid and the response received: `completed`), or when no
//!   settlement came within [`OPEN_AFTER`] of the first invoice or the node
//!   restarted first (`open`: the record is not final, never "pending").
//! - **report**, an in-log `deal_report` for the owner (audience `keep`), after
//!   the close, citing the Mesh records each of its lines is about.
//! - **a later outcome, close and report** when a payment or delivery leg is
//!   sealed after a close `open` (PROFILE §6 rule 7: an `open` close pauses
//!   the record): the new outcome says `completed` once the legs settle the
//!   deal, else `open` again, and the new report's lines cite the late leg.
//!   The latest report is the deal's; the earlier ones stay in the log.
//!
//! **The share gate.** Every deal capsule is linked to the exchange record it
//! is of in `deal-links.jsonl` ([`crate::evidence_log`]) *before* it is
//! sealed, so each step goes to that exchange's counterparty and to nobody
//! else. The report never leaves the node (`never_leaves`): a counterparty's
//! copy would be made by a share path, which is not built.
//!
//! **What survives a restart.** The deal's state is `deals.json`; the
//! payload each Capsule commits is journaled in `deal-payloads.jsonl` before
//! the Capsule is appended. A step counts as sealed only if its Capsule is in
//! the ledger, so a crash between the journal and the append reseals the same
//! step, and one between the append and the state file is found again from
//! the journal.
//!
//! Best-effort like the settlement legs: a deal that cannot be sealed is
//! missing evidence, never a failed exchange.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use capsule_emit_lib::produce::BuiltPayload;
use evidencebook::deal;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::deal_records::{self as records, After, Deal, Encoded};

/// How long after its first invoice a deal waits for settlement before its
/// record is closed `open`. The settlement legs are held no longer
/// ([`crate::settlement_legs::MAX_AGE`]).
pub const OPEN_AFTER: i64 = 15 * 60;
/// How many deals the state keeps; the oldest are dropped first.
const MAX_DEALS: usize = if cfg!(test) { 8 } else { 1024 };

const STATE_FILE: &str = "deals.json";
const SECRET_FILE: &str = "deal-store-secret";
/// One line per sealed Capsule: the payload it commits, in the order sealed.
pub const PAYLOADS_FILE: &str = "deal-payloads.jsonl";

/// What the exchange's own sealed record says: its id, the serving peer, and
/// what was asked (the request digest) of which model.
pub struct SealedExchange<'a> {
    pub capsule_id: &'a str,
    pub peer: &'a str,
    pub request_digest: &'a str,
    pub model: &'a str,
}

/// Which step of which deal is being sealed, and of which exchange.
struct StepOf<'a> {
    deal_id: &'a str,
    exchange_capsule_id: &'a str,
    seq: i64,
    /// The baseline's: the opening of its committed ask.
    nonce: Option<&'a str>,
}

/// What seals a deal's Capsules: the node's ledger.
pub trait Sealer {
    /// Seal the Capsule `build` makes on the ledger's head. `before` runs with
    /// the Capsule's id after it is built and before it is appended, under the
    /// ledger's one writer lock; if it fails nothing is appended.
    fn seal(
        &self,
        build: &dyn Fn(Option<&str>) -> Result<BuiltPayload, records::Error>,
        before: &dyn Fn(&str) -> std::io::Result<()>,
    ) -> anyhow::Result<String>;

    /// Whether the ledger holds `capsule_id`.
    fn holds(&self, capsule_id: &str) -> bool;
}

/// A deal capsule sealed, as the deal keeps it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Sealed {
    record_type: String,
    seq: i64,
    digest: String,
    capsule_id: String,
    at: String,
    /// On an outcome: it says `completed`. A close copies it, but closes
    /// sealed before it did say `false`, so the latest outcome is read.
    #[serde(default)]
    completed: bool,
}

/// One paid exchange's deal.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Entry {
    deal_id: String,
    /// The intent's nonce (64 hex), kept so the committed ask can be opened.
    nonce: String,
    /// When the first invoice was seen, seconds since the Unix epoch.
    started: i64,
    peer: Option<String>,
    exchange_capsule_id: Option<String>,
    request_digest: Option<String>,
    model: Option<String>,
    /// Capsule ids of this node's settlement legs for the exchange.
    terms_legs: Vec<String>,
    paid_legs: Vec<String>,
    delivered_leg: Option<String>,
    billed_msat: u64,
    paid_msat: u64,
    steps: Vec<Sealed>,
    /// The report of the latest close; `None` while a later outcome waits
    /// for its close and report.
    report: Option<String>,
    /// A payment or delivery leg came after the latest outcome, which said
    /// `open`: a later outcome and close are due once that one is closed.
    #[serde(default)]
    late: bool,
}

impl Entry {
    fn step(&self, record_type: &str) -> Option<&Sealed> {
        self.steps.iter().find(|s| s.record_type == record_type)
    }

    /// The latest step of `record_type`.
    fn latest(&self, record_type: &str) -> Option<&Sealed> {
        self.steps
            .iter()
            .rev()
            .find(|s| s.record_type == record_type)
    }

    /// A leg came: after an outcome `open`, the record takes a later one.
    fn leg_came(&mut self) {
        self.late |= self
            .latest(deal::TYPE_OUTCOME)
            .is_some_and(|o| !o.completed);
    }

    /// The latest outcome said `open` and a leg came after it, or the legs
    /// settle the deal now. The second covers a state saved before `late`
    /// was kept, whose late legs were stored with nothing sealed: an outcome
    /// says `open` only when the legs did not settle the deal then.
    fn later_round_due(&self) -> bool {
        self.latest(deal::TYPE_OUTCOME)
            .is_some_and(|o| !o.completed)
            && (self.late || self.settled())
    }

    /// Every invoice seen is paid and the response is in.
    fn settled(&self) -> bool {
        self.delivered_leg.is_some()
            && !self.terms_legs.is_empty()
            && self.paid_legs.len() >= self.terms_legs.len()
    }
}

#[derive(Default)]
struct Inner {
    loaded: bool,
    secret: Option<[u8; 32]>,
    /// By the host's exchange id.
    entries: BTreeMap<String, Entry>,
    /// The state on disk is not the state in memory (a save failed), or the
    /// state file could not be read and kept: nothing is sealed until a save
    /// succeeds, since a Capsule sealed past it could not be recovered.
    unsaved: bool,
    /// The state file is there but could neither be read nor be moved aside:
    /// it is left alone, and nothing is sealed or saved this run.
    blocked: bool,
    /// Sealed exchanges not (yet) known to be paid, in memory only: an
    /// invoice may come after the exchange's record, and a free exchange
    /// never gets one. The oldest are dropped first.
    recent: VecDeque<(String, OwnedExchange)>,
}

/// How many sealed exchanges `recent` holds.
const MAX_RECENT: usize = 256;

#[derive(Clone)]
struct OwnedExchange {
    capsule_id: String,
    peer: String,
    request_digest: String,
    model: String,
}

impl OwnedExchange {
    fn of(sealed: &SealedExchange) -> Self {
        Self {
            capsule_id: sealed.capsule_id.to_string(),
            peer: sealed.peer.to_string(),
            request_digest: sealed.request_digest.to_string(),
            model: sealed.model.to_string(),
        }
    }

    fn put_in(&self, e: &mut Entry) {
        e.exchange_capsule_id = Some(self.capsule_id.clone());
        e.peer = Some(self.peer.clone());
        e.request_digest = Some(self.request_digest.clone());
        e.model = Some(self.model.clone());
    }
}

/// This node's deals (held by `CapsuleState`).
pub struct Deals {
    dir: PathBuf,
    /// Where the store secret lives, beside the keys and away from the ledger.
    data_dir: PathBuf,
    inner: Mutex<Inner>,
}

impl Deals {
    pub fn new(ledger_dir: &Path, data_dir: &Path) -> Self {
        Self {
            dir: ledger_dir.to_path_buf(),
            data_dir: data_dir.to_path_buf(),
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// An invoice for `exchange_id` was issued (the first makes the deal) and this
    /// node sealed its terms leg `leg`, for `amount_msat`.
    pub fn on_invoice(
        &self,
        sealer: &dyn Sealer,
        exchange_id: &str,
        leg: &str,
        amount_msat: u64,
        now: i64,
    ) {
        self.update(sealer, exchange_id, now, true, |e| {
            if !e.terms_legs.iter().any(|l| l == leg) {
                e.terms_legs.push(leg.to_string());
                e.billed_msat = e.billed_msat.saturating_add(amount_msat);
            }
        });
    }

    /// The exchange's own record is sealed.
    pub fn on_exchange(
        &self,
        sealer: &dyn Sealer,
        exchange_id: &str,
        sealed: &SealedExchange,
        now: i64,
    ) {
        let owned = OwnedExchange::of(sealed);
        {
            let mut inner = self.lock();
            inner.recent.retain(|(id, _)| id != exchange_id);
            inner
                .recent
                .push_back((exchange_id.to_string(), owned.clone()));
            while inner.recent.len() > MAX_RECENT {
                inner.recent.pop_front();
            }
        }
        self.update(sealer, exchange_id, now, false, |e| owned.put_in(e));
    }

    /// This node sealed the payer's `payer_observed` leg `leg` (`amount_msat`
    /// paid) for the exchange.
    pub fn on_paid(
        &self,
        sealer: &dyn Sealer,
        exchange_id: &str,
        leg: &str,
        amount_msat: u64,
        now: i64,
    ) {
        self.update(sealer, exchange_id, now, false, |e| {
            if !e.paid_legs.iter().any(|l| l == leg) {
                e.paid_legs.push(leg.to_string());
                e.paid_msat = e.paid_msat.saturating_add(amount_msat);
                e.leg_came();
            }
        });
    }

    /// This node sealed the payer's `delivered` leg `leg`.
    pub fn on_delivered(&self, sealer: &dyn Sealer, exchange_id: &str, leg: &str, now: i64) {
        self.update(sealer, exchange_id, now, false, |e| {
            if e.delivered_leg.is_none() {
                e.delivered_leg = Some(leg.to_string());
                e.leg_came();
            }
        });
    }

    /// Time passed: close deals whose settlement did not come.
    pub fn tick(&self, sealer: &dyn Sealer, now: i64) {
        let mut inner = self.lock();
        self.load(&mut inner, sealer);
        let before = progress(&inner);
        inner
            .entries
            .retain(|_, e| e.step(deal::TYPE_BASELINE).is_some() || now - e.started < OPEN_AFTER);
        if inner.unsaved {
            self.save(&mut inner);
        }
        let ids: Vec<String> = inner.entries.keys().cloned().collect();
        for id in ids {
            self.advance(&mut inner, sealer, &id, now, false);
        }
        if progress(&inner) != before {
            self.save(&mut inner);
        }
    }

    /// At start: a deal with a baseline and no close is closed `open` (its
    /// legs were held in memory, which a restart lost), and a deal that never
    /// got a baseline within [`OPEN_AFTER`] is dropped.
    pub fn recover(&self, sealer: &dyn Sealer, now: i64) {
        let mut inner = self.lock();
        self.load(&mut inner, sealer);
        let before = progress(&inner);
        inner
            .entries
            .retain(|_, e| e.step(deal::TYPE_BASELINE).is_some() || now - e.started < OPEN_AFTER);
        let ids: Vec<String> = inner.entries.keys().cloned().collect();
        if inner.unsaved {
            self.save(&mut inner);
        }
        for id in ids {
            self.advance(&mut inner, sealer, &id, now, true);
        }
        if progress(&inner) != before {
            self.save(&mut inner);
        }
    }

    fn update(
        &self,
        sealer: &dyn Sealer,
        exchange_id: &str,
        now: i64,
        creates: bool,
        change: impl FnOnce(&mut Entry),
    ) {
        let mut inner = self.lock();
        self.load(&mut inner, sealer);
        if !inner.entries.contains_key(exchange_id) {
            if !creates {
                return;
            }
            let Some(mut entry) = new_entry(now) else {
                return;
            };
            if let Some((_, owned)) = inner.recent.iter().find(|(id, _)| id == exchange_id) {
                owned.put_in(&mut entry);
            }
            inner.entries.insert(exchange_id.to_string(), entry);
            // Reported deals go first, `completed` before `open`, oldest
            // first; a deal still to be closed, or due a later round, is
            // never dropped for room.
            while inner.entries.len() > MAX_DEALS {
                let oldest = inner
                    .entries
                    .iter()
                    .filter(|(_, e)| e.report.is_some() && !e.later_round_due())
                    .min_by_key(|(_, e)| {
                        let completed = e.latest(deal::TYPE_OUTCOME).is_some_and(|o| o.completed);
                        (!completed, e.started)
                    })
                    .map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => inner.entries.remove(&k),
                    None => break,
                };
            }
        }
        let before = progress(&inner);
        let snapshot = |inner: &Inner| {
            inner
                .entries
                .get(exchange_id)
                .and_then(|e| serde_json::to_string(e).ok())
        };
        let was = snapshot(&inner);
        if let Some(entry) = inner.entries.get_mut(exchange_id) {
            change(entry);
        }
        // The entry (with the exchange it is of) is on disk before its first
        // Capsule, so a crash after the append can still be recovered from.
        if inner.unsaved || snapshot(&inner) != was {
            self.save(&mut inner);
        }
        self.advance(&mut inner, sealer, exchange_id, now, false);
        if progress(&inner) != before {
            self.save(&mut inner);
        }
    }

    /// Seal what is due for `exchange_id`, in order, stopping at the first
    /// step that cannot be sealed (tried again at the next event).
    fn advance(
        &self,
        inner: &mut Inner,
        sealer: &dyn Sealer,
        exchange_id: &str,
        now: i64,
        restarted: bool,
    ) {
        let Some(secret) = inner.secret else {
            return;
        };
        if inner.unsaved || inner.blocked {
            return;
        }
        let Some(entry) = inner.entries.get_mut(exchange_id) else {
            return;
        };
        let deal_id = entry.deal_id.clone();
        let nonce = entry.nonce.clone();
        let (Some(peer), Some(exchange), Some(digest), Some(model)) = (
            entry.peer.clone(),
            entry.exchange_capsule_id.clone(),
            entry.request_digest.clone(),
            entry.model.clone(),
        ) else {
            return;
        };
        let asked = format!("inference request {digest} for {model}");
        let d = Deal {
            key: deal::deal_key(&secret, &deal_id),
            local_values: vec![peer.clone(), asked.clone()],
            deal_id: deal_id.clone(),
        };
        let seal = |entry: &mut Entry, enc: Encoded, seq: i64, completed: bool| -> bool {
            match self.seal_step(
                sealer,
                &StepOf {
                    deal_id: &deal_id,
                    exchange_capsule_id: &exchange,
                    seq,
                    nonce: (seq == 1).then_some(nonce.as_str()),
                },
                &enc,
                now,
            ) {
                Some(capsule_id) => {
                    entry.steps.push(Sealed {
                        record_type: enc.record_type.to_string(),
                        seq,
                        digest: enc.digest,
                        capsule_id,
                        at: enc.at,
                        completed,
                    });
                    true
                }
                None => false,
            }
        };
        if entry.step(deal::TYPE_BASELINE).is_none() {
            if entry.terms_legs.is_empty() {
                return;
            }
            let Ok(enc) = d
                .baseline(&records::at(now), &peer, &entry.nonce, &asked, &model)
                .inspect_err(|error| tracing::warn!(%error, "deal baseline not built"))
            else {
                return;
            };
            if !seal(entry, enc, 1, false) {
                return;
            }
        }
        let baseline = entry.step(deal::TYPE_BASELINE).map(|s| s.digest.clone());
        let Some(baseline) = baseline else { return };
        // One step at a time, each after the latest: outcome, close, report,
        // and after a close `open` that a leg came after, the next round.
        loop {
            let Some(last) = entry.steps.last().cloned() else {
                return;
            };
            let after = After {
                seq: last.seq + 1,
                prev: last.digest.clone(),
                baseline: baseline.clone(),
            };
            // What the latest outcome said, which its close says too.
            let completed = entry
                .latest(deal::TYPE_OUTCOME)
                .is_some_and(|o| o.completed);
            match last.record_type.as_str() {
                deal::TYPE_CLOSE if entry.report.is_none() => {
                    entry.report = self.seal_report(sealer, entry, &exchange, completed, now);
                    if entry.report.is_none() {
                        return;
                    }
                }
                deal::TYPE_BASELINE | deal::TYPE_CLOSE => {
                    let due = if last.record_type == deal::TYPE_BASELINE {
                        entry.settled() || restarted || now - entry.started >= OPEN_AFTER
                    } else {
                        // PROFILE §6 rule 7: a close `open` may be followed
                        // by a later outcome and close; a terminal one never.
                        entry.later_round_due()
                    };
                    if !due {
                        return;
                    }
                    let settled = entry.settled();
                    let Ok(enc) = d
                        .outcome(&records::at(now), &after, settled)
                        .inspect_err(|error| tracing::warn!(%error, "deal outcome not built"))
                    else {
                        return;
                    };
                    if !seal(entry, enc, after.seq, settled) {
                        return;
                    }
                    // The legs so far are in this outcome; the report of
                    // the close before it is no longer the latest.
                    entry.late = false;
                    entry.report = None;
                }
                deal::TYPE_OUTCOME => {
                    // The close says what the outcome said, whatever the
                    // legs say now.
                    let Ok(enc) = d
                        .close(&records::at(now), &after, last.completed)
                        .inspect_err(|error| tracing::warn!(%error, "deal close not built"))
                    else {
                        return;
                    };
                    if !seal(entry, enc, after.seq, last.completed) {
                        return;
                    }
                }
                _ => return,
            }
        }
    }

    /// Link, journal, then seal one step.
    fn seal_step(
        &self,
        sealer: &dyn Sealer,
        of: &StepOf,
        enc: &Encoded,
        now: i64,
    ) -> Option<String> {
        let StepOf {
            deal_id,
            exchange_capsule_id,
            seq,
            nonce,
        } = *of;
        let record: Value = serde_json::from_slice(&enc.payload).ok()?;
        let result = sealer.seal(
            &|head| {
                records::step_capsule(
                    deal_id,
                    seq,
                    enc,
                    head,
                    crate::producer::capsule::LOCAL_RECORD_OPERATOR,
                    crate::producer::capsule::LOCAL_RECORD_DEVELOPER,
                    now,
                )
            },
            &|capsule_id| {
                self.link(capsule_id, exchange_capsule_id)?;
                let mut line = json!({
                    "capsule_id": capsule_id, "deal_id": deal_id, "record_type": enc.record_type,
                    "seq": seq, "digest": enc.digest, "at": enc.at, "payload": record,
                });
                // The opening of the baseline's committed ask: the nonce
                // (the text is the exchange's request digest and model).
                if let Some(nonce) = nonce {
                    line["nonce"] = json!(nonce);
                }
                self.journal(&line)
            },
        );
        match result {
            Ok(capsule_id) => Some(capsule_id),
            Err(error) => {
                tracing::warn!(%error, record_type = enc.record_type, "deal step not sealed");
                None
            }
        }
    }

    fn seal_report(
        &self,
        sealer: &dyn Sealer,
        entry: &Entry,
        exchange_capsule_id: &str,
        settled: bool,
        now: i64,
    ) -> Option<String> {
        let nonce = random_hex()?;
        let body = report_body(entry, exchange_capsule_id, settled, now);
        let payload = deal::report_payload(&deal::Report {
            deal_id: entry.deal_id.clone(),
            audience: deal::AUDIENCE_KEEP.into(),
            nonce,
            body,
            checkpoint: None,
        })
        .map_err(|error| tracing::warn!(%error, "deal report not built"))
        .ok()?;
        let record: Value = serde_json::from_slice(&payload).ok()?;
        // Which close the report reads, so a restart tells the latest
        // close's report from an earlier one's.
        let close_seq = entry.steps.last().map_or(0, |s| s.seq);
        let result = sealer.seal(
            &|head| {
                records::report_capsule(
                    &payload,
                    head,
                    crate::producer::capsule::LOCAL_RECORD_OPERATOR,
                    crate::producer::capsule::LOCAL_RECORD_DEVELOPER,
                    now,
                )
            },
            &|capsule_id| {
                self.link(capsule_id, exchange_capsule_id)?;
                self.journal(&json!({
                    "capsule_id": capsule_id, "deal_id": entry.deal_id,
                    "record_type": deal::REPORT_TYPE, "close_seq": close_seq, "payload": record,
                }))
            },
        );
        match result {
            Ok(capsule_id) => Some(capsule_id),
            Err(error) => {
                tracing::warn!(%error, "deal report not sealed");
                None
            }
        }
    }

    fn link(&self, capsule_id: &str, exchange_capsule_id: &str) -> std::io::Result<()> {
        append_line(
            &self.dir.join(crate::evidence_log::DEAL_LINKS_FILE),
            &json!({"capsule_id": capsule_id, "exchange_capsule_id": exchange_capsule_id}),
        )
    }

    fn journal(&self, line: &Value) -> std::io::Result<()> {
        append_line(&self.dir.join(PAYLOADS_FILE), line)
    }

    /// Read the state and the store secret once; fold in the steps the journal
    /// holds that the ledger holds too but the state does not, in the order
    /// sealed, and the report of the latest close.
    fn load(&self, inner: &mut Inner, sealer: &dyn Sealer) {
        if inner.loaded {
            return;
        }
        inner.loaded = true;
        inner.secret = read_or_make_secret(&self.data_dir.join(SECRET_FILE));
        match std::fs::read(self.dir.join(STATE_FILE)) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(entries) => inner.entries = entries,
                Err(error) => {
                    // Kept for a person to read; a later save must not
                    // overwrite it. If it cannot be kept, nothing is sealed.
                    tracing::warn!(%error, "deal state unreadable; moved to deals.json.bad");
                    if std::fs::rename(self.dir.join(STATE_FILE), self.dir.join("deals.json.bad"))
                        .is_err()
                    {
                        inner.blocked = true;
                    }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, "deal state not readable; moved to deals.json.bad");
                if std::fs::rename(self.dir.join(STATE_FILE), self.dir.join("deals.json.bad"))
                    .is_err()
                {
                    inner.blocked = true;
                }
            }
        }
        // By bytes: a line cut short inside a multi-byte character must not
        // make the lines before it unreadable.
        let Ok(journal) = std::fs::read(self.dir.join(PAYLOADS_FILE)) else {
            return;
        };
        for line in journal.split(|b| *b == b'\n') {
            let Ok(v) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
            let (Some(capsule_id), Some(deal_id)) = (text("capsule_id"), text("deal_id")) else {
                continue;
            };
            if !sealer.holds(&capsule_id) {
                continue;
            }
            let Some(entry) = inner.entries.values_mut().find(|e| e.deal_id == deal_id) else {
                continue;
            };
            if v.get("record_type").and_then(Value::as_str) == Some(deal::REPORT_TYPE) {
                // A report journaled before later rounds were sealed read the
                // first close, seq 3.
                let close_seq = v.get("close_seq").and_then(Value::as_i64).unwrap_or(3);
                let latest = entry.steps.last();
                if latest.is_some_and(|s| s.record_type == deal::TYPE_CLOSE && s.seq == close_seq) {
                    entry.report.get_or_insert(capsule_id);
                }
                continue;
            }
            let (Some(record_type), Some(digest), Some(at), Some(seq)) = (
                text("record_type"),
                text("digest"),
                text("at"),
                v.get("seq").and_then(Value::as_i64),
            ) else {
                continue;
            };
            let completed =
                v.pointer("/payload/body/outcome").and_then(Value::as_str) == Some("completed");
            if !entry.steps.iter().any(|s| s.seq == seq) {
                // A step past what the state holds: the state's report is of
                // an earlier close, and an outcome took in the legs so far.
                if entry.steps.last().is_none_or(|s| s.seq < seq) {
                    entry.report = None;
                    if record_type == deal::TYPE_OUTCOME {
                        entry.late = false;
                    }
                }
                entry.steps.push(Sealed {
                    record_type,
                    seq,
                    digest,
                    capsule_id,
                    at,
                    completed,
                });
                entry.steps.sort_by_key(|s| s.seq);
            }
        }
    }

    fn save(&self, inner: &mut Inner) {
        if inner.blocked {
            return;
        }
        let path = self.dir.join(STATE_FILE);
        let tmp = self.dir.join("deals.json.tmp");
        let write = || -> std::io::Result<()> {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(&serde_json::to_vec(&inner.entries).map_err(std::io::Error::other)?)?;
            file.sync_all()?;
            std::fs::rename(&tmp, &path)
        };
        let result = write();
        if let Err(error) = &result {
            tracing::warn!(%error, "deal state not saved; no deal is sealed until it is");
        }
        inner.unsaved = result.is_err();
    }
}

/// How far the deals have got: entries, sealed steps and reports.
fn progress(inner: &Inner) -> (usize, usize, usize) {
    (
        inner.entries.len(),
        inner.entries.values().map(|e| e.steps.len()).sum(),
        inner
            .entries
            .values()
            .filter(|e| e.report.is_some())
            .count(),
    )
}

fn new_entry(now: i64) -> Option<Entry> {
    Some(Entry {
        deal_id: format!("deal-{}", &random_hex()?[..32]),
        nonce: random_hex()?,
        started: now,
        ..Entry::default()
    })
}

/// 256 random bits as 64 lowercase hex.
fn random_hex() -> Option<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| tracing::warn!(%error, "no randomness for a deal"))
        .ok()?;
    Some(hex::encode(bytes))
}

/// The node's `store_secret`: 32 random bytes in a file only the owner reads,
/// made on first use. The deal keys derive from it, so a leaked record
/// reveals no raw identifier.
fn read_or_make_secret(path: &Path) -> Option<[u8; 32]> {
    let read = || -> Option<[u8; 32]> {
        let text = std::fs::read_to_string(path)
            .map_err(
                |error| tracing::warn!(%error, "deal store secret unreadable; no deal is sealed"),
            )
            .ok()?;
        let secret = hex::decode(text.trim())
            .ok()
            .and_then(|b| b.try_into().ok());
        if secret.is_none() {
            tracing::warn!("deal store secret is not 32 bytes of hex; no deal is sealed");
        }
        secret
    };
    if path.exists() {
        return read();
    }
    let secret: [u8; 32] = hex::decode(random_hex()?).ok()?.try_into().ok()?;
    let write = || -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(hex::encode(secret).as_bytes())?;
        file.sync_all()
    };
    match write() {
        Ok(()) => Some(secret),
        // Another writer made it first: theirs is the secret, read once.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read(),
        Err(error) => {
            tracing::warn!(%error, "deal store secret not written; no deal is sealed");
            None
        }
    }
}

/// Append `line`. A last line a crash cut short (no newline) is ended first,
/// so the new line is not glued to it and lost with it.
pub(crate) fn append_line(path: &Path, line: &Value) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    let len = file.metadata()?.len();
    if len > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::Start(len - 1))?;
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            file.write_all(b"\n")?;
        }
    }
    writeln!(file, "{line}")?;
    file.sync_all()
}

/// The report's lines. `audience`, `did`, `money`, `lifecycle`, `steps`,
/// `told` and `scope` are the members the receipt reads
/// (capsule-viewer `receipt/model.py`). Money lines are msat text. A close
/// `open` says what this node saw: payment seen with no delivery, or no
/// payment seen, never "not delivered".
fn report_body(
    entry: &Entry,
    exchange_capsule_id: &str,
    settled: bool,
    now: i64,
) -> serde_json::Map<String, Value> {
    let model = entry.model.as_deref().unwrap_or("a model");
    let mut did = vec![json!({
        "text": format!("Asked a mesh node for {model}."),
        "steps": [exchange_capsule_id],
    })];
    if !entry.terms_legs.is_empty() {
        did.push(json!({
            "text": format!("Invoiced {} msat.", entry.billed_msat),
            "steps": entry.terms_legs,
        }));
    }
    if !entry.paid_legs.is_empty() {
        did.push(json!({
            "text": format!("Paid {} msat.", entry.paid_msat),
            "steps": entry.paid_legs,
        }));
    }
    if let Some(leg) = &entry.delivered_leg {
        did.push(json!({"text": "Received the response.", "steps": [leg]}));
    }
    let (state, text) = if settled {
        (
            "closed",
            "Every invoice was paid and the response was received.",
        )
    } else if entry.paid_legs.is_empty() {
        ("open", "Payment not seen.")
    } else if entry.delivered_leg.is_none() {
        ("open", "Payment seen; delivery not recorded.")
    } else {
        ("open", "Not every invoice was seen paid.")
    };
    let steps: Vec<Value> = entry
        .steps
        .iter()
        .map(|s| json!({"capsule_id": s.capsule_id}))
        .collect();
    let mut body = serde_json::Map::new();
    body.insert("audience".into(), json!(deal::AUDIENCE_KEEP));
    body.insert(
        "scope".into(),
        json!("This node's own record of the exchange."),
    );
    body.insert("did".into(), Value::Array(did));
    body.insert("told".into(), json!([]));
    body.insert(
        "lifecycle".into(),
        json!({"state": state, "text": text, "as_of": records::at(now), "later": []}),
    );
    body.insert("steps".into(), Value::Array(steps));
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule_emit::CapsuleState;

    const PEER: &str = "9c1f0a2be45d7388a6b0c1d2e3f40516273849a5b6c7d8e9f00112233445566a";
    const EXCHANGE: &str = "host-exchange-1";

    fn hex64(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn sealed_exchange() -> SealedExchange<'static> {
        SealedExchange {
            capsule_id: Box::leak(hex64('e').into_boxed_str()),
            peer: PEER,
            request_digest: Box::leak(hex64('d').into_boxed_str()),
            model: "model-x",
        }
    }

    fn open(dir: &Path) -> CapsuleState {
        CapsuleState::open(dir, "deal-test").unwrap()
    }

    fn ledger(dir: &Path) -> PathBuf {
        dir.join("ledger")
    }

    fn lines(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The deal capsules in the ledger, in order.
    fn deal_capsules(dir: &Path) -> Vec<Value> {
        lines(&ledger(dir).join("capsules.jsonl"))
            .into_iter()
            .filter(|c| c.get("deal_id").is_some() || c["action_id"] == deal::REPORT_ACTION_ID)
            .collect()
    }

    fn payload(dir: &Path, capsule_id: &str) -> Value {
        lines(&ledger(dir).join(PAYLOADS_FILE))
            .into_iter()
            .find(|l| l["capsule_id"] == capsule_id)
            .map(|l| l["payload"].clone())
            .unwrap()
    }

    fn paid_exchange(state: &CapsuleState, now: i64) {
        let deals = state.deals();
        deals.on_invoice(state, EXCHANGE, &hex64('a'), 1000, now);
        deals.on_exchange(state, EXCHANGE, &sealed_exchange(), now + 1);
    }

    #[test]
    fn a_paid_and_delivered_exchange_seals_baseline_outcome_close_and_report() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        paid_exchange(&state, 1_790_000_000);
        // Invoiced and asked: the baseline, nothing more.
        let types = |dir: &Path| -> Vec<String> {
            deal_capsules(dir)
                .iter()
                .map(|c| c["action_id"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(types(dir.path()).len(), 1);
        let deals = state.deals();
        deals.on_paid(&state, EXCHANGE, &hex64('b'), 1000, 1_790_000_030);
        assert_eq!(types(dir.path()).len(), 1, "not delivered yet");
        deals.on_delivered(&state, EXCHANGE, &hex64('c'), 1_790_000_040);

        let capsules = deal_capsules(dir.path());
        assert_eq!(capsules.len(), 4);
        let kinds: Vec<_> = capsules
            .iter()
            .map(|c| {
                payload(dir.path(), c["capsule_id"].as_str().unwrap())
                    .pointer("/x-deal-v0/record_type")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| "report".into())
            })
            .collect();
        assert_eq!(kinds, ["baseline", "outcome", "close", "report"]);
        let outcome = payload(dir.path(), capsules[1]["capsule_id"].as_str().unwrap());
        assert_eq!(outcome["body"]["outcome"], "completed");
        let report = payload(dir.path(), capsules[3]["capsule_id"].as_str().unwrap());
        assert_eq!(report["report"]["lifecycle"]["state"], "closed");
        assert_eq!(report["audience"], "keep");
        // The raw peer id is in no record.
        let journal = std::fs::read_to_string(ledger(dir.path()).join(PAYLOADS_FILE)).unwrap();
        assert!(!journal.contains(PEER));
        // Each deal capsule is chained on the ledger and linked to the exchange.
        let links = lines(&ledger(dir.path()).join(crate::evidence_log::DEAL_LINKS_FILE));
        assert_eq!(links.len(), 4);
        for c in &capsules {
            assert!(links
                .iter()
                .any(|l| l["capsule_id"] == c["capsule_id"]
                    && l["exchange_capsule_id"] == hex64('e')));
        }
    }

    #[test]
    fn an_invoice_never_settled_closes_open_when_the_time_has_passed() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let t = 1_790_000_000;
        paid_exchange(&state, t);
        state.deals().tick(&state, t + OPEN_AFTER - 1);
        assert_eq!(deal_capsules(dir.path()).len(), 1, "still waiting");
        state.deals().tick(&state, t + OPEN_AFTER);
        let capsules = deal_capsules(dir.path());
        assert_eq!(capsules.len(), 4);
        let outcome = payload(dir.path(), capsules[1]["capsule_id"].as_str().unwrap());
        assert_eq!(outcome["body"]["outcome"], "open");
        let close = payload(dir.path(), capsules[2]["capsule_id"].as_str().unwrap());
        assert_eq!(close["body"]["outcome"], "open");
        let report = payload(dir.path(), capsules[3]["capsule_id"].as_str().unwrap());
        assert_eq!(report["report"]["lifecycle"]["state"], "open");
        assert_eq!(report["report"]["lifecycle"]["text"], "Payment not seen.");
        // A tick again seals nothing more.
        state.deals().tick(&state, t + 10 * OPEN_AFTER);
        assert_eq!(deal_capsules(dir.path()).len(), 4);
    }

    /// What the closed-open report says depends on what this node saw.
    #[test]
    fn an_open_report_says_only_what_the_node_saw() {
        let t = 1_790_000_000;
        // (paid legs, delivered, expected wording)
        let cases: [(usize, bool, &str); 3] = [
            (0, false, "Payment not seen."),
            (1, false, "Payment seen; delivery not recorded."),
            (1, true, "Not every invoice was seen paid."),
        ];
        for (paid, delivered, text) in cases {
            let dir = tempfile::tempdir().unwrap();
            let state = open(dir.path());
            let deals = state.deals();
            // Two invoices, so one paid leg plus delivery is still not settled.
            deals.on_invoice(&state, EXCHANGE, &hex64('a'), 1000, t);
            deals.on_invoice(&state, EXCHANGE, &hex64('f'), 500, t);
            deals.on_exchange(&state, EXCHANGE, &sealed_exchange(), t + 1);
            if paid > 0 {
                deals.on_paid(&state, EXCHANGE, &hex64('b'), 1000, t + 2);
            }
            if delivered {
                deals.on_delivered(&state, EXCHANGE, &hex64('c'), t + 3);
            }
            deals.tick(&state, t + OPEN_AFTER);
            let capsules = deal_capsules(dir.path());
            assert_eq!(capsules.len(), 4, "{text}");
            let report = payload(dir.path(), capsules[3]["capsule_id"].as_str().unwrap());
            assert_eq!(report["report"]["lifecycle"]["state"], "open");
            assert_eq!(report["report"]["lifecycle"]["text"], text);
        }
    }

    /// Wraps the node's ledger and checks, when a Capsule is about to be
    /// sealed, that the deal it is of is already on disk with the exchange it
    /// is of: a crash after the append is then recoverable.
    struct Spy<'a>(&'a CapsuleState, PathBuf);

    impl Sealer for Spy<'_> {
        fn seal(
            &self,
            build: &dyn Fn(Option<&str>) -> Result<BuiltPayload, records::Error>,
            before: &dyn Fn(&str) -> std::io::Result<()>,
        ) -> anyhow::Result<String> {
            let saved: Value =
                serde_json::from_slice(&std::fs::read(self.1.join(STATE_FILE)).unwrap()).unwrap();
            assert_eq!(saved[EXCHANGE]["peer"], PEER);
            assert_eq!(saved[EXCHANGE]["model"], "model-x");
            self.0.seal(build, before)
        }
        fn holds(&self, capsule_id: &str) -> bool {
            self.0.holds(capsule_id)
        }
    }

    #[test]
    fn a_deal_is_on_disk_before_its_first_capsule() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let spy = Spy(&state, ledger(dir.path()));
        let deals = state.deals();
        deals.on_exchange(&spy, EXCHANGE, &sealed_exchange(), 1_790_000_000);
        deals.on_invoice(&spy, EXCHANGE, &hex64('a'), 1000, 1_790_000_001);
        assert_eq!(deal_capsules(dir.path()).len(), 1);
    }

    #[test]
    fn a_line_cut_short_by_a_crash_does_not_swallow_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.jsonl");
        append_line(&path, &json!({"a": 1})).unwrap();
        std::fs::write(&path, format!("{}\n{{\"b\":", json!({"a": 1}))).unwrap();
        append_line(&path, &json!({"c": 3})).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let good: Vec<Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert_eq!(good, [json!({"a": 1}), json!({"c": 3})]);
    }

    #[test]
    fn an_unreadable_store_secret_stops_the_deal_and_does_not_loop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRET_FILE);
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert!(read_or_make_secret(&path).is_none());
        std::fs::write(&path, "abcd").unwrap();
        assert!(read_or_make_secret(&path).is_none());
        let made = dir.path().join("fresh");
        let secret = read_or_make_secret(&made).unwrap();
        assert_eq!(read_or_make_secret(&made), Some(secret));
    }

    #[test]
    fn an_unreadable_deal_state_is_kept_aside_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        std::fs::write(ledger(dir.path()).join(STATE_FILE), "{ not json").unwrap();
        paid_exchange(&state, 1_790_000_000);
        let aside = std::fs::read_to_string(ledger(dir.path()).join("deals.json.bad")).unwrap();
        assert_eq!(aside, "{ not json");
    }

    /// A save that fails stops the sealing (a Capsule past it could not be
    /// recovered); the next tick that can save carries on.
    #[test]
    fn nothing_is_sealed_while_the_state_cannot_be_saved() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let tmp = ledger(dir.path()).join("deals.json.tmp");
        std::fs::create_dir(&tmp).unwrap();
        paid_exchange(&state, 1_790_000_000);
        assert!(deal_capsules(dir.path()).is_empty());
        std::fs::remove_dir(&tmp).unwrap();
        state.deals().tick(&state, 1_790_000_005);
        assert_eq!(deal_capsules(dir.path()).len(), 1);
    }

    /// A state file that cannot be read as text is kept aside, and one that
    /// cannot even be moved is left alone with nothing sealed.
    #[test]
    fn a_state_file_that_cannot_be_kept_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let path = ledger(dir.path()).join(STATE_FILE);
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        paid_exchange(&state, 1_790_000_000);
        assert_eq!(
            std::fs::read(ledger(dir.path()).join("deals.json.bad")).unwrap(),
            [0xff, 0xfe, 0x00]
        );
        assert_eq!(deal_capsules(dir.path()).len(), 1);

        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let ledger_dir = ledger(dir.path());
        // The state is a directory holding a file, and the aside name is
        // taken by a non-empty directory: neither read nor rename works.
        std::fs::create_dir_all(ledger_dir.join(STATE_FILE).join("x")).unwrap();
        std::fs::create_dir_all(ledger_dir.join("deals.json.bad").join("x")).unwrap();
        paid_exchange(&state, 1_790_000_000);
        assert!(deal_capsules(dir.path()).is_empty());
        assert!(ledger_dir.join(STATE_FILE).join("x").exists());
    }

    /// A journal line cut inside a multi-byte character costs only that line.
    #[test]
    fn a_journal_cut_mid_character_still_recovers_the_lines_before_it() {
        let dir = tempfile::tempdir().unwrap();
        {
            let state = open(dir.path());
            paid_exchange(&state, 1_790_000_000);
        }
        let journal = ledger(dir.path()).join(PAYLOADS_FILE);
        let mut bytes = std::fs::read(&journal).unwrap();
        bytes.extend_from_slice(b"{\"capsule_id\":\"x\",\"model\":\"caf\xc3");
        std::fs::write(&journal, bytes).unwrap();
        let path = ledger(dir.path()).join(STATE_FILE);
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        saved[EXCHANGE]["steps"] = json!([]);
        std::fs::write(&path, saved.to_string()).unwrap();
        let state = open(dir.path());
        state.deals().recover(&state, 1_790_000_100);
        let baselines = deal_capsules(dir.path())
            .iter()
            .filter(|c| c["action_id"].as_str().is_some_and(|a| a.ends_with("/1")))
            .count();
        assert_eq!(baselines, 1);
    }

    #[test]
    fn the_baseline_journals_the_opening_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        paid_exchange(&state, 1_790_000_000);
        let line = &lines(&ledger(dir.path()).join(PAYLOADS_FILE))[0];
        assert_eq!(line["nonce"].as_str().map(str::len), Some(64));
    }

    #[test]
    fn room_is_made_by_dropping_finished_deals_never_unfinished_ones() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let deals = state.deals();
        let t = 1_790_000_000;
        for i in 0..MAX_DEALS + 3 {
            deals.on_invoice(&state, &format!("ex-{i}"), &hex64('a'), 1, t + i as i64);
        }
        let saved: Value =
            serde_json::from_slice(&std::fs::read(ledger(dir.path()).join(STATE_FILE)).unwrap())
                .unwrap();
        assert_eq!(
            saved.as_object().unwrap().len(),
            MAX_DEALS + 3,
            "none finished, none dropped"
        );
    }

    #[test]
    fn an_invoice_after_the_exchange_record_still_makes_the_deal() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let t = 1_790_000_000;
        state
            .deals()
            .on_exchange(&state, EXCHANGE, &sealed_exchange(), t);
        assert!(deal_capsules(dir.path()).is_empty(), "no invoice yet");
        state
            .deals()
            .on_invoice(&state, EXCHANGE, &hex64('a'), 1000, t + 5);
        assert_eq!(deal_capsules(dir.path()).len(), 1);
    }

    #[test]
    fn a_free_exchange_gets_no_deal() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let deals = state.deals();
        deals.on_exchange(&state, EXCHANGE, &sealed_exchange(), 1_790_000_000);
        deals.on_delivered(&state, EXCHANGE, &hex64('c'), 1_790_000_010);
        deals.tick(&state, 1_790_000_000 + 10 * OPEN_AFTER);
        assert!(deal_capsules(dir.path()).is_empty());
        assert!(!ledger(dir.path()).join(PAYLOADS_FILE).exists());
    }

    #[test]
    fn a_restart_closes_a_baselined_deal_open_and_does_not_repeat_the_baseline() {
        let dir = tempfile::tempdir().unwrap();
        {
            let state = open(dir.path());
            paid_exchange(&state, 1_790_000_000);
            assert_eq!(deal_capsules(dir.path()).len(), 1);
        }
        let state = open(dir.path());
        state.deals().recover(&state, 1_790_000_100);
        let capsules = deal_capsules(dir.path());
        assert_eq!(
            capsules.len(),
            4,
            "baseline, outcome open, close open, report"
        );
        let outcome = payload(dir.path(), capsules[1]["capsule_id"].as_str().unwrap());
        assert_eq!(outcome["body"]["outcome"], "open");
        // And another restart changes nothing.
        let state = open(dir.path());
        state.deals().recover(&state, 1_790_000_200);
        assert_eq!(deal_capsules(dir.path()).len(), 4);
    }

    /// The Capsule was appended and journaled, then the node died before the
    /// state was saved: the next start finds the step again from the journal
    /// and the ledger instead of sealing a second baseline.
    #[test]
    fn a_crash_between_the_append_and_the_state_is_found_again_from_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        {
            let state = open(dir.path());
            paid_exchange(&state, 1_790_000_000);
        }
        let path = ledger(dir.path()).join(STATE_FILE);
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        saved[EXCHANGE]["steps"] = json!([]);
        std::fs::write(&path, saved.to_string()).unwrap();
        let state = open(dir.path());
        state.deals().recover(&state, 1_790_000_100);
        let capsules = deal_capsules(dir.path());
        assert_eq!(
            capsules.len(),
            4,
            "one baseline, then outcome, close and report"
        );
        let baselines = capsules
            .iter()
            .filter(|c| c["action_id"].as_str().is_some_and(|a| a.ends_with("/1")))
            .count();
        assert_eq!(baselines, 1);
    }

    /// What each deal capsule is, in log order: its record type, or "report".
    fn kinds(dir: &Path) -> Vec<String> {
        deal_capsules(dir)
            .iter()
            .map(|c| {
                payload(dir, c["capsule_id"].as_str().unwrap())
                    .pointer("/x-deal-v0/record_type")
                    .and_then(Value::as_str)
                    .unwrap_or("report")
                    .to_string()
            })
            .collect()
    }

    /// The payload of the `n`th deal capsule (from 0, in log order).
    fn nth(dir: &Path, n: usize) -> Value {
        payload(dir, deal_capsules(dir)[n]["capsule_id"].as_str().unwrap())
    }

    /// Every capsule id the report's `did` lines cite.
    fn cited(report: &Value) -> Vec<String> {
        report["report"]["did"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|d| d["steps"].as_array().unwrap())
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    }

    const ROUND: [&str; 3] = ["outcome", "close", "report"];

    /// PROFILE §6 rule 7: legs sealed after a close `open` seal a later
    /// outcome and close, chained on the close, and a new report citing them.
    #[test]
    fn a_leg_after_an_open_close_seals_a_later_outcome_close_and_report() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let t = 1_790_000_000;
        paid_exchange(&state, t);
        state.deals().tick(&state, t + OPEN_AFTER);
        assert_eq!(
            kinds(dir.path()),
            ["baseline", "outcome", "close", "report"]
        );

        // The payment, late: the record takes it, still `open` (no delivery).
        let deals = state.deals();
        deals.on_paid(&state, EXCHANGE, &hex64('b'), 1000, t + OPEN_AFTER + 30);
        let mut want = vec!["baseline", "outcome", "close", "report"];
        want.extend(ROUND);
        assert_eq!(kinds(dir.path()), want);
        let outcome = nth(dir.path(), 4);
        assert_eq!(outcome["x-deal-v0"]["seq"], 4);
        assert_eq!(outcome["body"]["outcome"], "open");
        // Chained on the close before it.
        let journal = lines(&ledger(dir.path()).join(PAYLOADS_FILE));
        let close = journal.iter().find(|l| l["seq"] == 3).unwrap();
        assert_eq!(outcome["x-deal-v0"]["prev"]["digest"], close["digest"]);
        let report = nth(dir.path(), 6);
        assert_eq!(
            report["report"]["lifecycle"]["text"],
            "Payment seen; delivery not recorded."
        );
        assert!(cited(&report).contains(&hex64('b')), "cites the late leg");

        // Then the delivery: settled, so the record is `completed`.
        deals.on_delivered(&state, EXCHANGE, &hex64('c'), t + OPEN_AFTER + 40);
        want.extend(ROUND);
        assert_eq!(kinds(dir.path()), want);
        let outcome = nth(dir.path(), 7);
        assert_eq!(outcome["x-deal-v0"]["seq"], 6);
        assert_eq!(outcome["body"]["outcome"], "completed");
        assert_eq!(nth(dir.path(), 8)["body"]["outcome"], "completed");
        let report = nth(dir.path(), 9);
        assert_eq!(report["report"]["lifecycle"]["state"], "closed");
        let cites = cited(&report);
        assert!(cites.contains(&hex64('b')) && cites.contains(&hex64('c')));
        // The report lists every step, the later ones too.
        assert_eq!(report["report"]["steps"].as_array().unwrap().len(), 7);
        // Every capsule is linked to the exchange, the later ones too.
        let links = lines(&ledger(dir.path()).join(crate::evidence_log::DEAL_LINKS_FILE));
        assert_eq!(links.len(), 10);
        // Each report, the later ones too, never leaves the node.
        let reports: Vec<Value> = deal_capsules(dir.path())
            .into_iter()
            .filter(|c| c.get("deal_id").is_none())
            .collect();
        assert_eq!(reports.len(), 3);
        assert!(reports.iter().all(crate::evidence_log::never_leaves));

        // A completed close is terminal: nothing more, whatever comes.
        deals.on_paid(&state, EXCHANGE, &hex64('9'), 1, t + OPEN_AFTER + 50);
        deals.tick(&state, t + 10 * OPEN_AFTER);
        assert_eq!(deal_capsules(dir.path()).len(), 10);
    }

    /// A restart closed the deal `open`; the settlement that comes after
    /// seals the later rounds, which a further restart does not repeat.
    #[test]
    fn a_settlement_after_a_restart_seals_a_later_completed_close() {
        let dir = tempfile::tempdir().unwrap();
        let t = 1_790_000_000;
        {
            let state = open(dir.path());
            paid_exchange(&state, t);
        }
        let state = open(dir.path());
        state.deals().recover(&state, t + 100);
        assert_eq!(
            kinds(dir.path()),
            ["baseline", "outcome", "close", "report"]
        );
        let deals = state.deals();
        deals.on_delivered(&state, EXCHANGE, &hex64('c'), t + 110);
        deals.on_paid(&state, EXCHANGE, &hex64('b'), 1000, t + 120);
        let mut want = vec!["baseline", "outcome", "close", "report"];
        want.extend(ROUND);
        want.extend(ROUND);
        assert_eq!(kinds(dir.path()), want);
        assert_eq!(nth(dir.path(), 4)["body"]["outcome"], "open");
        assert_eq!(nth(dir.path(), 7)["body"]["outcome"], "completed");
        assert_eq!(nth(dir.path(), 9)["report"]["lifecycle"]["state"], "closed");

        drop(state);
        let state = open(dir.path());
        state.deals().recover(&state, t + 200);
        state.deals().tick(&state, t + 10 * OPEN_AFTER);
        assert_eq!(deal_capsules(dir.path()).len(), 10);
    }

    /// The later round was sealed and journaled, then the node died before
    /// the state was saved: the next start finds the round again from the
    /// journal, and its report as the latest, instead of sealing another.
    #[test]
    fn a_later_round_lost_from_the_state_is_found_again_from_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let t = 1_790_000_000;
        let first_report = {
            let state = open(dir.path());
            paid_exchange(&state, t);
            state.deals().tick(&state, t + OPEN_AFTER);
            let first = deal_capsules(dir.path())[3]["capsule_id"].clone();
            state
                .deals()
                .on_paid(&state, EXCHANGE, &hex64('b'), 1000, t + OPEN_AFTER + 30);
            first
        };
        assert_eq!(deal_capsules(dir.path()).len(), 7);
        // The state as saved when the leg came: three steps, the first
        // report, and a later round due.
        let path = ledger(dir.path()).join(STATE_FILE);
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let steps = saved[EXCHANGE]["steps"].as_array().unwrap()[..3].to_vec();
        saved[EXCHANGE]["steps"] = json!(steps);
        saved[EXCHANGE]["report"] = first_report;
        saved[EXCHANGE]["late"] = json!(true);
        std::fs::write(&path, saved.to_string()).unwrap();

        let state = open(dir.path());
        state.deals().recover(&state, t + OPEN_AFTER + 100);
        assert_eq!(deal_capsules(dir.path()).len(), 7, "nothing sealed again");
        // The delivery seals the next round on top of the one found.
        state
            .deals()
            .on_delivered(&state, EXCHANGE, &hex64('c'), t + OPEN_AFTER + 110);
        assert_eq!(deal_capsules(dir.path()).len(), 10);
        assert_eq!(nth(dir.path(), 7)["x-deal-v0"]["seq"], 6);
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            saved[EXCHANGE]["report"],
            deal_capsules(dir.path())[9]["capsule_id"]
        );
    }

    /// A deal closed `open`, then a late leg sealed outcome 4, close 5 and
    /// report R2. Returns the ids of the report R1 and of steps 4 and 5 and R2.
    fn late_round(dir: &Path, t: i64) -> (Value, [Value; 3]) {
        let state = open(dir);
        paid_exchange(&state, t);
        state.deals().tick(&state, t + OPEN_AFTER);
        state
            .deals()
            .on_paid(&state, EXCHANGE, &hex64('b'), 1000, t + OPEN_AFTER + 30);
        let ids: Vec<Value> = deal_capsules(dir)
            .iter()
            .map(|c| c["capsule_id"].clone())
            .collect();
        assert_eq!(ids.len(), 7);
        (
            ids[3].clone(),
            [ids[4].clone(), ids[5].clone(), ids[6].clone()],
        )
    }

    /// As if `ids` had never been journaled (nor, so, appended).
    fn unjournal(dir: &Path, ids: &[&Value]) {
        let path = ledger(dir).join(PAYLOADS_FILE);
        let kept: Vec<String> = lines(&path)
            .into_iter()
            .filter(|l| !ids.contains(&&l["capsule_id"]))
            .map(|l| l.to_string())
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
    }

    fn journaled(dir: &Path, record_type: &str) -> Vec<Value> {
        lines(&ledger(dir).join(PAYLOADS_FILE))
            .into_iter()
            .filter(|l| l["record_type"] == record_type)
            .collect()
    }

    /// Close 5 sealed, its report not (the state saved with no report): the
    /// next start must not take the first close's report for it, and seals
    /// the report of close 5.
    #[test]
    fn a_report_of_an_earlier_close_is_not_taken_for_the_latest() {
        let dir = tempfile::tempdir().unwrap();
        let t = 1_790_000_000;
        let (first_report, [_, _, second_report]) = late_round(dir.path(), t);
        unjournal(dir.path(), &[&second_report]);
        let path = ledger(dir.path()).join(STATE_FILE);
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved[EXCHANGE]["steps"].as_array().unwrap().len(), 5);
        saved[EXCHANGE]["report"] = Value::Null;
        std::fs::write(&path, saved.to_string()).unwrap();

        let state = open(dir.path());
        state.deals().recover(&state, t + OPEN_AFTER + 100);
        let reports = journaled(dir.path(), deal::REPORT_TYPE);
        assert_eq!(reports.len(), 2, "R1 and one new report");
        let new = &reports[1];
        assert_ne!(new["capsule_id"], first_report);
        assert_eq!(new["close_seq"], 5);
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved[EXCHANGE]["report"], new["capsule_id"]);
        state.deals().recover(&state, t + OPEN_AFTER + 200);
        assert_eq!(journaled(dir.path(), deal::REPORT_TYPE).len(), 2);
    }

    /// A crash mid-round: outcome 4 journaled and appended, close 5 not, the
    /// state still at the first close with the leg due. The next start finds
    /// outcome 4 and seals close 5 and its report once, with no second outcome.
    #[test]
    fn a_round_cut_after_its_outcome_is_closed_once_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let t = 1_790_000_000;
        let (first_report, [_, close, second_report]) = late_round(dir.path(), t);
        unjournal(dir.path(), &[&close, &second_report]);
        let path = ledger(dir.path()).join(STATE_FILE);
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let steps = saved[EXCHANGE]["steps"].as_array().unwrap()[..3].to_vec();
        saved[EXCHANGE]["steps"] = json!(steps);
        saved[EXCHANGE]["report"] = first_report;
        saved[EXCHANGE]["late"] = json!(true);
        std::fs::write(&path, saved.to_string()).unwrap();

        for _ in 0..2 {
            let state = open(dir.path());
            state.deals().recover(&state, t + OPEN_AFTER + 100);
            let seqs = |record_type| -> Vec<i64> {
                journaled(dir.path(), record_type)
                    .iter()
                    .map(|l| l["seq"].as_i64().unwrap())
                    .collect()
            };
            assert_eq!(seqs(deal::TYPE_OUTCOME), [2, 4], "no second outcome 4");
            assert_eq!(seqs(deal::TYPE_CLOSE), [3, 5]);
            let reports = journaled(dir.path(), deal::REPORT_TYPE);
            assert_eq!(reports.len(), 2);
            assert_eq!(reports[1]["close_seq"], 5);
        }
    }

    /// A state saved by 0.1.6: the late legs were stored after the close
    /// `open` and nothing more sealed, and there is no `late`. The next start
    /// seals the one round they settle, and only once.
    #[test]
    fn a_deal_left_open_with_settled_legs_by_an_older_build_gets_its_round() {
        let dir = tempfile::tempdir().unwrap();
        let t = 1_790_000_000;
        {
            let state = open(dir.path());
            paid_exchange(&state, t);
            state.deals().tick(&state, t + OPEN_AFTER);
        }
        assert_eq!(deal_capsules(dir.path()).len(), 4);
        let path = ledger(dir.path()).join(STATE_FILE);
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let entry = saved[EXCHANGE].as_object_mut().unwrap();
        entry.remove("late");
        entry.insert("paid_legs".into(), json!([hex64('b')]));
        entry.insert("paid_msat".into(), json!(1000));
        entry.insert("delivered_leg".into(), json!(hex64('c')));
        std::fs::write(&path, saved.to_string()).unwrap();

        let state = open(dir.path());
        state.deals().recover(&state, t + OPEN_AFTER + 100);
        let mut want = vec!["baseline", "outcome", "close", "report"];
        want.extend(ROUND);
        assert_eq!(kinds(dir.path()), want);
        assert_eq!(nth(dir.path(), 4)["body"]["outcome"], "completed");
        assert_eq!(nth(dir.path(), 6)["report"]["lifecycle"]["state"], "closed");
        state.deals().tick(&state, t + OPEN_AFTER + 200);
        drop(state);
        let state = open(dir.path());
        state.deals().recover(&state, t + OPEN_AFTER + 300);
        assert_eq!(deal_capsules(dir.path()).len(), 7);
    }

    /// Room is made from `completed` deals before `open` ones, however old.
    #[test]
    fn room_is_made_from_completed_deals_before_open_ones() {
        let dir = tempfile::tempdir().unwrap();
        let state = open(dir.path());
        let deals = state.deals();
        let t = 1_790_000_000;
        let deal = |id: &str, now: i64| {
            deals.on_invoice(&state, id, &hex64('a'), 1000, now);
            deals.on_exchange(&state, id, &sealed_exchange(), now + 1);
        };
        deal("ex-open", t);
        deals.tick(&state, t + OPEN_AFTER);
        deal("ex-done", t + OPEN_AFTER + 10);
        deals.on_paid(&state, "ex-done", &hex64('b'), 1000, t + OPEN_AFTER + 20);
        deals.on_delivered(&state, "ex-done", &hex64('c'), t + OPEN_AFTER + 30);
        for i in 0..MAX_DEALS - 1 {
            deals.on_invoice(
                &state,
                &format!("ex-{i}"),
                &hex64('a'),
                1,
                t + OPEN_AFTER + 40,
            );
        }
        let saved: Value =
            serde_json::from_slice(&std::fs::read(ledger(dir.path()).join(STATE_FILE)).unwrap())
                .unwrap();
        let saved = saved.as_object().unwrap();
        assert_eq!(saved.len(), MAX_DEALS);
        assert!(saved.contains_key("ex-open"), "the open deal is kept");
        assert!(
            !saved.contains_key("ex-done"),
            "the completed one made room"
        );
    }

    #[test]
    fn the_built_chain_passes_the_reference_checker() {
        let Some(profile) = std::env::var_os("EVIDENCEBOOK_DEAL_PROFILE_DIR") else {
            eprintln!("EVIDENCEBOOK_DEAL_PROFILE_DIR not set; check_profile.py not run");
            return;
        };
        // Settled at once, and settled after a close `open` (rule 7).
        for late in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let state = open(dir.path());
            let t = 1_790_000_000;
            paid_exchange(&state, t);
            if late {
                state.deals().tick(&state, t + OPEN_AFTER);
            }
            let after = if late { OPEN_AFTER } else { 0 };
            state
                .deals()
                .on_paid(&state, EXCHANGE, &hex64('b'), 1000, t + after + 30);
            state
                .deals()
                .on_delivered(&state, EXCHANGE, &hex64('c'), t + after + 40);
            check_chain(&profile, dir.path());
        }
    }

    /// `check_profile.py` over the deal's steps sealed in `dir`.
    fn check_chain(profile: &std::ffi::OsStr, dir: &Path) {
        let chain: Vec<String> = deal_capsules(dir)
            .iter()
            .filter(|c| c.get("deal_id").is_some())
            .map(|c| payload(dir, c["capsule_id"].as_str().unwrap()).to_string())
            .collect();
        let path = dir.join("chain.json");
        std::fs::write(&path, format!("[{}]", chain.join(","))).unwrap();
        let out = std::process::Command::new("python3")
            .arg("-I")
            .arg(Path::new(profile).join("check_profile.py"))
            .arg(&path)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        eprintln!("check_profile.py: {text}");
        assert!(out.status.success() && !text.contains("FAIL"), "{text}");
    }
}
