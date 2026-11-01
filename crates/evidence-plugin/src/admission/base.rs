//! The base policy's five rows (`base/1`, #64): what admission reads about
//! any peer an attempt names, listed or not, and seals with its decision.
//!
//! - **identity**: the peer's history card verifies under the record key it
//!   announces now, with that key as its responder. A card read under another
//!   key, or a later answer that fails to verify, is no longer read; with no
//!   key known yet, the row is `not_read`, not `fail`.
//! - **key age**: the card's first checkpoint is at least [`KEY_AGE_DAYS`]
//!   old. A checkpoint's time counts as stated, witnessed or not, so a peer
//!   can backdate it: a `pass` here is not proof of age.
//! - **performed-and-settled**: this node's own book holds at least
//!   [`MIN_SETTLED`] exchange with the peer whose book reads `settled`.
//! - **disputes**: `not_read` until this node holds a verdict about the peer;
//!   then no adverse adjudication about it in the last
//!   [`DISPUTE_PERIOD_DAYS`] days. The verdicts are the ones
//!   `verdict_counts::fold` counts (verified, asked for by this node, once
//!   per referee and pair), each with its sealed time, and the evaluator
//!   windows them. Adverse is a `contradicted` verdict naming the peer.
//! - **corroboration**: this node holds the peer's pushed half for at least
//!   [`MIN_HELD_HALVES`] exchange ("no half, no deal above T0").
//!
//! The rows decide nothing (Steven, 10-29): each decision seals them as read,
//! and the verdict stays the operator's config's (the lists and the default).
//! An adverse adjudication is a `fail` in the disputes row and never blocks on
//! its own; the operator makes it a NO in config. A card not read yet is asked
//! for in the background, and its rows read `not_read` until it comes. Every
//! threshold is a placeholder, fixed here and cited by the policy digest.
//!
//! The rows are decided by capsule-engine's admission evaluator
//! (`capsule_engine::admission`, #178), never by a second evaluator here,
//! under the Mesh base pack this plugin ships
//! (`policies/admission/mesh-base/`): the operator's lists as its two NO rows,
//! then these five as `record` rows, each with today's id and threshold. This
//! module gathers what the rows read and hands it to the evaluator as
//! `Inputs`. The pack yields GO and NO only and its missing default is NO, so
//! nothing but a list may reach NO: the deal is always passed as
//! [`DEAL_AMOUNT`] [`DEAL_CURRENCY`] (free, in the one tier), the tier is as
//! wide as the profile allows, and an operator row never reads `not_read`.
//!
//! Nothing here is read while a request waits: the card comes from a
//! background ask ([`Base::start`]), and the three local rows from a snapshot
//! a background refresh recomputes from this node's own chain every
//! [`REFRESH`].

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use capsule_engine::admission as engine;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub const KEY_AGE_DAYS: i64 = 7;
pub const MIN_SETTLED: usize = 1;
pub const DISPUTE_PERIOD_DAYS: i64 = 30;
pub const MIN_HELD_HALVES: usize = 1;
/// A card is asked for again once it is this old.
const CARD_TTL: Duration = Duration::from_secs(24 * 3600);
/// The least time between two asks of one peer.
const ASK_RETRY: Duration = Duration::from_secs(3600);
pub const REFRESH: Duration = Duration::from_secs(60);

/// The base pack this plugin ships, as a decision cites it.
pub const PACK_ID: &str = "asg/mesh_admission_base/1.0.0";
/// The SHA-256 of [`DEFINITION`]. Recompiling the pack changes it, and the
/// pinned load then fails until this is updated with it
/// (`policies/admission/mesh-base/README.md`).
pub const DEFINITION_DIGEST: &str =
    "d7cdf88f0c6c401ad35039a10686f1b68adf08334c1bf04bd419302caf31b09b";
/// The pack's compiled `pack-definition.json`, embedded as committed.
pub const DEFINITION: &[u8] =
    include_bytes!("../../../../policies/admission/mesh-base/pack-definition.json");

/// The deal every decision passes: admission is asked before an attempt and
/// knows no amount, so the deal is free, which sits in the pack's one tier.
/// Never empty: a missing amount would reach the pack's missing default, NO.
pub const DEAL_AMOUNT: &str = "0";
/// A currency the pack's `accept` names.
pub const DEAL_CURRENCY: &str = "msat";

/// The base pack, loaded once from [`DEFINITION`] and pinned by
/// [`PACK_ID`] and [`DEFINITION_DIGEST`]. A file that changed without its
/// digest fails loudly; a test loads it.
pub fn pack() -> &'static engine::Pack {
    static PACK: LazyLock<engine::Pack> = LazyLock::new(|| {
        engine::Pack::load_pinned(DEFINITION, PACK_ID, DEFINITION_DIGEST)
            .unwrap_or_else(|error| panic!("the embedded base pack does not load: {error}"))
    });
    &PACK
}

/// `at` as the evaluator's instant, to the nanosecond.
fn timestamp(at: DateTime<Utc>) -> engine::Timestamp {
    engine::Timestamp::from_unix_nanos(
        i128::from(at.timestamp()) * 1_000_000_000 + i128::from(at.timestamp_subsec_nanos()),
    )
}

/// The thresholds, as the policy digest covers them.
pub fn thresholds() -> Value {
    json!({
        "key_age_days": KEY_AGE_DAYS,
        "min_settled": MIN_SETTLED,
        "dispute_period_days": DISPUTE_PERIOD_DAYS,
        "min_held_halves": MIN_HELD_HALVES,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowResult {
    Pass,
    Fail,
    NotRead,
}

impl RowResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotRead => "not_read",
        }
    }

    fn from_status(status: engine::RowStatus) -> Self {
        match status {
            engine::RowStatus::Pass => Self::Pass,
            engine::RowStatus::Fail => Self::Fail,
            engine::RowStatus::NotRead => Self::NotRead,
        }
    }
}

/// The rows in the order a record lists them.
pub const ROWS: [&str; 5] = [
    "identity",
    "key_age",
    "performed_and_settled",
    "disputes",
    "corroboration",
];

/// A verified history card, as the rows read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    /// The answer's `artifact_digest`; a record cites it only by commitment.
    pub artifact_digest: String,
    /// The time its first checkpoint states. `None` when it doesn't parse.
    pub first_checkpoint_at: Option<DateTime<Utc>>,
    /// The record key it verified under. The card speaks for that key only:
    /// once the peer's announced key changes, it is no longer read.
    pub key_id: String,
}

/// What one ask of a peer's card came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardOutcome {
    Read(Card),
    /// The answer did not verify, or there is no key to verify it under.
    Unverifiable,
    /// A refusal, no answer, or bytes that are not an answer.
    NotRead,
}

#[derive(Default)]
struct CardEntry {
    /// The peer's announced key when this entry was last read.
    key: Option<String>,
    card: Option<(Card, Instant)>,
    last: Option<CardOutcome>,
    asked_at: Option<Instant>,
    in_flight: bool,
}

/// One adjudication about a peer that this node holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldVerdict {
    /// Its sealed time; `None` when it does not read, which counts as in the
    /// period.
    pub at: Option<DateTime<Utc>>,
    /// A `contradicted` verdict naming the peer.
    pub adverse: bool,
}

/// This node's own book with one peer, as its records name the peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalFacts {
    /// The exchanges, by exchange id, of this node's records that name the
    /// peer, settled or not.
    pub exchanges: BTreeSet<String>,
    /// Those of [`LocalFacts::exchanges`] whose book reads `settled`.
    pub settled: BTreeSet<String>,
    /// Every verdict about the peer, of any kind.
    pub verdicts: Vec<HeldVerdict>,
}

/// The local rows' inputs from one read of this node's chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Per peer node id (lowercase).
    pub by_peer: HashMap<String, LocalFacts>,
    /// The halves held, by the key the receiver verified each under
    /// (`sender_key_id`): for each, the exchange it is a half of (the
    /// exchange id of this node's own half, else the half's capsule id). A
    /// receiver records no transport-attested node id (`record_push_bridge`),
    /// so a half is the peer's when its key is the peer's announced key.
    pub halves_by_key: HashMap<String, BTreeSet<String>>,
}

/// What the rows read for one attempt.
#[derive(Debug)]
pub struct Read {
    pub rows: [RowResult; 5],
    /// The card cited: `Some(artifact digest)` when one was read.
    pub card: Option<String>,
    /// The evaluator's decision under the base pack, its rows included.
    pub decision: engine::Decision,
}

pub struct Base {
    ledger_dir: PathBuf,
    cards: Mutex<HashMap<String, CardEntry>>,
    /// `None` until a refresh read the chain whole: the local rows are then
    /// not read.
    facts: RwLock<Option<Facts>>,
    /// What the refreshes have read of the chain so far.
    scan: Mutex<ChainScan>,
    asks: OnceLock<tokio::sync::mpsc::UnboundedSender<String>>,
}

impl Base {
    pub fn new(ledger_dir: PathBuf) -> Self {
        Self {
            ledger_dir,
            cards: Mutex::default(),
            facts: RwLock::new(None),
            scan: Mutex::default(),
            asks: OnceLock::new(),
        }
    }

    /// The rows for `peer` (a lowercase 64-hex node id) at `now`, and the base
    /// pack's decision with `operator`'s lists, queueing an ask of its card
    /// when one is due.
    pub fn read(
        &self,
        peer: &str,
        operator: engine::Operator,
        at: Instant,
        now: DateTime<Utc>,
    ) -> Read {
        let registry = crate::peer_keys::registry();
        let key = crate::peer_keys::announced_key_in(registry.as_deref(), peer);
        self.read_with(peer, key.as_deref(), operator, at, now)
    }

    /// [`Base::read`] with `key`, the peer's announced record key now, and no
    /// list.
    #[cfg(test)]
    fn read_with_key(
        &self,
        peer: &str,
        key: Option<&str>,
        at: Instant,
        now: DateTime<Utc>,
    ) -> Read {
        self.read_with(peer, key, engine::Operator::default(), at, now)
    }

    /// [`Base::read`] with `key`, the peer's announced record key now.
    fn read_with(
        &self,
        peer: &str,
        key: Option<&str>,
        operator: engine::Operator,
        at: Instant,
        now: DateTime<Utc>,
    ) -> Read {
        let key = key.map(str::to_ascii_lowercase);
        let (card, card_input) = self.card(peer, key.as_deref(), at);
        let own = self
            .facts
            .read()
            .expect("the facts lock is never poisoned")
            .as_ref()
            .map(|facts| {
                let none = BTreeSet::new();
                let held = key
                    .as_ref()
                    .and_then(|key| facts.halves_by_key.get(key))
                    .unwrap_or(&none);
                own_history(facts.by_peer.get(peer), held, now)
            });
        let mut inputs = engine::Inputs::at(timestamp(now));
        inputs.amount = DEAL_AMOUNT.into();
        inputs.currency = DEAL_CURRENCY.into();
        inputs.card = card_input;
        inputs.own = own;
        inputs.operator = operator;
        let decision = engine::evaluate(pack(), &inputs);
        let rows = ROWS.map(|id| {
            decision
                .rows
                .iter()
                .find(|row| row.row == id)
                .map_or(RowResult::NotRead, |row| RowResult::from_status(row.result))
        });
        Read {
            rows,
            card,
            decision,
        }
    }

    /// The card the identity and key-age rows read, and the card cited.
    /// `key` is the peer's announced record key now; a card read under
    /// another key is not read.
    fn card(&self, peer: &str, key: Option<&str>, at: Instant) -> (Option<String>, engine::Card) {
        let mut cards = self.cards.lock().expect("the card lock is never poisoned");
        let entry = cards.entry(peer.to_string()).or_default();
        // A new key starts over: neither an old card nor an old failure
        // speaks for it.
        if entry.key.is_some() && entry.key.as_deref() != key
            || entry
                .card
                .as_ref()
                .is_some_and(|(card, _)| Some(card.key_id.as_str()) != key)
        {
            entry.card = None;
            entry.last = None;
            entry.asked_at = None;
        }
        entry.key = key.map(str::to_string);
        let stale = entry
            .card
            .as_ref()
            .is_none_or(|(_, read_at)| at.duration_since(*read_at) >= CARD_TTL);
        let retry_due = entry
            .asked_at
            .is_none_or(|asked| at.duration_since(asked) >= ASK_RETRY);
        if stale && retry_due && !entry.in_flight {
            if let Some(asks) = self.asks.get() {
                if asks.send(peer.to_string()).is_ok() {
                    entry.in_flight = true;
                    entry.asked_at = Some(at);
                }
            }
        }
        if let Some((card, _)) = &entry.card {
            return (
                Some(card.artifact_digest.clone()),
                engine::Card {
                    state: engine::CARD_VERIFIED.into(),
                    first_checkpoint_at: card.first_checkpoint_at.map(timestamp),
                    ..engine::Card::default()
                },
            );
        }
        match entry.last {
            Some(CardOutcome::Unverifiable) => (
                None,
                engine::Card {
                    state: engine::CARD_UNVERIFIABLE.into(),
                    ..engine::Card::default()
                },
            ),
            // No card yet, or a refusal or silence: absent.
            _ => (None, engine::Card::default()),
        }
    }

    /// What an ask of `peer`'s card came to. A card once read is kept until
    /// a newer one is read or one fails to verify: a later refusal or silence
    /// does not unread it.
    pub fn record_card(&self, peer: &str, outcome: CardOutcome, at: Instant) {
        let mut cards = self.cards.lock().expect("the card lock is never poisoned");
        let entry = cards.entry(peer.to_string()).or_default();
        entry.in_flight = false;
        match &outcome {
            CardOutcome::Read(card) => entry.card = Some((card.clone(), at)),
            CardOutcome::Unverifiable => entry.card = None,
            CardOutcome::NotRead => {}
        }
        entry.last = Some(outcome);
    }

    /// Set `peer`'s book: `settled` settled exchanges of
    /// `max(settled, held_halves)`, `held_halves` of them with a half held
    /// under `key`, and `verdicts`.
    #[cfg(test)]
    pub fn set_facts_for_test(
        &self,
        peer: &str,
        key: &str,
        settled: usize,
        held_halves: usize,
        verdicts: Vec<HeldVerdict>,
    ) {
        let ids = |n: usize| (0..n).map(|i| format!("ex-{i}")).collect::<BTreeSet<_>>();
        let mut all = self
            .facts
            .write()
            .expect("the facts lock is never poisoned");
        let all = all.get_or_insert_with(Facts::default);
        all.by_peer.insert(
            peer.to_string(),
            LocalFacts {
                exchanges: ids(settled.max(held_halves)),
                settled: ids(settled),
                verdicts,
            },
        );
        all.halves_by_key
            .insert(key.to_ascii_lowercase(), ids(held_halves));
    }

    /// Recompute the local rows' inputs from this node's own chain. A chain
    /// that doesn't read whole leaves them not read rather than empty.
    ///
    /// Only what was appended to the chain since the last refresh is read; a
    /// chain that shrank or was replaced is read again whole ([`ChainScan`]).
    pub fn refresh(&self) {
        let facts = self
            .scan
            .lock()
            .expect("the scan lock is never poisoned")
            .facts(&self.ledger_dir);
        if facts.is_none() {
            tracing::warn!(
                "admission could not read this node's chain whole; the local rows read not_read"
            );
        }
        *self
            .facts
            .write()
            .expect("the facts lock is never poisoned") = facts;
    }

    /// Start the background ask of peers' cards and the local refresh, for
    /// the life of the process.
    pub fn start(self: &Arc<Self>, context: mesh_llm_plugin::PluginContext<'static>) {
        let (sender, mut asks) = tokio::sync::mpsc::unbounded_channel::<String>();
        if self.asks.set(sender).is_err() {
            return;
        }
        let base = self.clone();
        tokio::spawn(async move {
            let mut context = context;
            while let Some(peer) = asks.recv().await {
                let outcome = ask_card(&mut context, &peer).await;
                let read = match &outcome {
                    CardOutcome::Read(_) => "read",
                    CardOutcome::Unverifiable => "unverifiable",
                    CardOutcome::NotRead => "not_read",
                };
                tracing::info!(%peer, card = read, "admission asked a peer for its history card");
                base.record_card(&peer, outcome, Instant::now());
            }
        });
        let base = self.clone();
        tokio::spawn(async move {
            loop {
                let refreshing = base.clone();
                let _ = tokio::task::spawn_blocking(move || refreshing.refresh()).await;
                tokio::time::sleep(REFRESH).await;
            }
        });
    }
}

/// The Evidence Request the identity and key-age rows read: the peer's
/// history card.
pub fn card_request() -> Value {
    json!({
        "subject": {"full_history": null},
        "coverage": {"min_freshness": 1},
        "derivation": "history_card/1",
    })
}

async fn ask_card(context: &mut mesh_llm_plugin::PluginContext<'_>, peer: &str) -> CardOutcome {
    // No book of asks (`None`): this is the behavior the call had before
    // #110 added that argument; whether an admission card ask belongs in
    // the book is for #116's owner.
    let Ok(crate::mesh_evidence_bridge::Answered { sent, answer, .. }) =
        crate::mesh_evidence_bridge::send_evidence_request(context, peer, &card_request(), None)
            .await
    else {
        return CardOutcome::NotRead;
    };
    let registry = crate::peer_keys::registry();
    read_card(
        &sent,
        &answer,
        crate::peer_keys::announced_key_in(registry.as_deref(), peer).as_deref(),
        &crate::checkpoint_cadence::active_witness_keys(),
    )
}

/// The card in `answer` to the request `sent`, verified under `key_id` (the
/// peer's announced record key, hex).
pub fn read_card(
    sent: &[u8],
    answer: &Value,
    key_id: Option<&str>,
    witness_keys: &std::collections::BTreeMap<String, String>,
) -> CardOutcome {
    if answer.get("reason").is_some() {
        return CardOutcome::NotRead;
    }
    // No usable key yet (not announced, or announced two ways): nothing can
    // be checked, which is not a card that failed to verify.
    let Some((key_id, key)) = key_id.and_then(|key_id| {
        crate::mesh_evidence_bridge::verifying_key(key_id).map(|key| (key_id, key))
    }) else {
        return CardOutcome::NotRead;
    };
    let Ok(request) = evidence_request::request::parse_json(sent) else {
        return CardOutcome::Unverifiable;
    };
    let witness_key =
        |ts_url: &str| crate::evidence_answer::configured_witness_key(witness_keys, ts_url);
    match crate::evidence_artifact::check(sent, &request, answer, &key, &witness_key) {
        Ok(checked) if checked.checkpoints > 0 => CardOutcome::Read(Card {
            artifact_digest: checked.artifact_digest,
            first_checkpoint_at: checked
                .first_checkpoint_at
                .and_then(|at| DateTime::parse_from_rfc3339(&at).ok())
                .map(|at| at.with_timezone(&Utc)),
            key_id: key_id.to_ascii_lowercase(),
        }),
        _ => CardOutcome::Unverifiable,
    }
}

/// The local rows' inputs from this node's own chain at `ledger_dir`, read
/// whole, or `None` when the chain, or the list of adjudications it asked for,
/// is there but doesn't read whole: a torn or unreadable line could hide an
/// adverse verdict, so it is never read as "none".
#[cfg(test)]
pub fn local_facts(ledger_dir: &Path) -> Option<Facts> {
    ChainScan::default().facts(ledger_dir)
}

/// The chain's records as far as they have been read, so a refresh parses
/// only the lines appended since (the chain is append-only; #118). The text
/// itself comes from `chain_store::chain_text`, whose snapshot is already
/// shared and incremental on the store layout. The parsed records stay in
/// memory for the life of the scan (settlement records twice, once in the
/// settled index): the facts are derived from all of them each refresh.
#[derive(Default)]
struct ChainScan {
    /// The bytes of the chain read: through the end of the last line taken.
    consumed: usize,
    /// The first line taken, and the last with where it starts. A chain that
    /// no longer holds them at those places is not this one grown, and is
    /// read again from the start.
    first_line: Vec<u8>,
    last_line: Vec<u8>,
    last_line_at: usize,
    /// The last line taken had no `\n` yet. Whatever follows it must start
    /// with one, or it is glued to it and the line was never whole.
    open_tail: bool,
    /// A complete line did not parse. Nothing later undoes that, so the
    /// local rows stay not read until the chain is read again whole.
    unreadable: bool,
    /// The records (padding left out), in chain order.
    records: Vec<Value>,
    settled: crate::evidence_panes::SettledIndex,
}

impl ChainScan {
    /// Take in what was appended since the last call. `false` when the chain
    /// does not read whole.
    fn advance(&mut self, ledger_dir: &Path) -> bool {
        let text = match crate::chain_store::chain_text(ledger_dir) {
            Ok(Some(text)) => text,
            // No chain is an empty book.
            Ok(None) => {
                *self = Self::default();
                return true;
            }
            Err(_) => {
                *self = Self::default();
                return false;
            }
        };
        if !self.continues(&text) {
            *self = Self::default();
        }
        let rest = &text[self.consumed..];
        if self.open_tail
            && !rest.is_empty()
            && !rest.starts_with(b"\n")
            && !rest.starts_with(b"\r")
        {
            self.unreadable = true;
        }
        // A last line with no `\n` yet may be torn: it is taken only when it
        // is a whole object, which no further bytes can extend into another
        // value.
        let complete = rest.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        let mut end = complete;
        let tail = String::from_utf8_lossy(&rest[complete..]);
        let tail = tail.trim();
        let mut torn = false;
        if !tail.is_empty() {
            match serde_json::from_str::<Value>(tail) {
                Ok(value) if value.is_object() => end = rest.len(),
                _ => torn = true,
            }
        }
        for line in String::from_utf8_lossy(&rest[..end]).lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match crate::evidence_panes::parse_record_line(line) {
                Ok(Some(record)) => {
                    self.settled.push(&record);
                    self.records.push(record);
                }
                Ok(None) => {}
                Err(()) => self.unreadable = true,
            }
        }
        if end > 0 {
            let taken = &rest[..end];
            let body = taken.strip_suffix(b"\n").unwrap_or(taken);
            let from = body.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            if self.consumed == 0 {
                let first = taken
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(end, |i| i + 1);
                self.first_line = taken[..first].to_vec();
            }
            self.last_line_at = self.consumed + from;
            self.last_line = body[from..].to_vec();
            self.open_tail = !taken.ends_with(b"\n");
            self.consumed += end;
        }
        !self.unreadable && !torn
    }

    /// Whether `text` is the chain read so far with more after it.
    fn continues(&self, text: &[u8]) -> bool {
        self.consumed == 0
            || (text.len() >= self.consumed
                && text.starts_with(&self.first_line)
                && text[self.last_line_at..].starts_with(&self.last_line)
                && self.last_line_at + self.last_line.len() <= self.consumed)
    }

    /// The local rows' inputs from the chain as it stands, or `None` when it
    /// does not read whole.
    fn facts(&mut self, ledger_dir: &Path) -> Option<Facts> {
        // Every line must read: `read_requested` skips a request line that
        // doesn't parse or lacks its referee and two halves, and the verdict
        // it asked for would then count nowhere.
        let request_line = |line: &Value| {
            line.get("referee").and_then(Value::as_str).is_some()
                && line
                    .get("halves")
                    .and_then(Value::as_array)
                    .is_some_and(|halves| halves.len() == 2 && halves.iter().all(Value::is_string))
        };
        let requests_whole = match std::fs::read_to_string(
            ledger_dir.join(crate::verdict_counts::REQUESTED_FILENAME),
        ) {
            Ok(text) => text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .all(|line| serde_json::from_str::<Value>(line).is_ok_and(|v| request_line(&v))),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        };
        if !self.advance(ledger_dir) || !requests_whole {
            return None;
        }
        Some(self.derive(ledger_dir))
    }

    fn derive(&self, ledger_dir: &Path) -> Facts {
        let records = &self.records;
        let settled_ids = self.settled.settled_exchange_ids();
        // This node's own records by capsule id, for the exchange a held
        // half is the counterpart of.
        let exchange_of: HashMap<&str, &str> = records
            .iter()
            .filter_map(|record| {
                Some((
                    record.get("capsule_id")?.as_str()?,
                    crate::evidence_panes::record_exchange_id(record)?,
                ))
            })
            .collect();
        let mut facts = Facts::default();
        for record in records {
            if let (Some(peer), Some(exchange)) = (
                crate::evidence_panes::full_counterparty_node_id(record),
                crate::evidence_panes::record_exchange_id(record),
            ) {
                let book = facts.by_peer.entry(peer.to_ascii_lowercase()).or_default();
                book.exchanges.insert(exchange.to_string());
                if settled_ids.contains(exchange) {
                    book.settled.insert(exchange.to_string());
                }
            }
            if let Some((key, half, own)) = held_half(record) {
                let exchange = own
                    .and_then(|own| exchange_of.get(own.as_str()).copied())
                    .map_or(half, str::to_string);
                facts.halves_by_key.entry(key).or_default().insert(exchange);
            }
        }
        let verdicts = crate::verdict_counts::fold(
            records,
            &crate::verdict_counts::read_requested(ledger_dir),
        );
        for (peer, verdicts) in verdicts {
            facts
                .by_peer
                .entry(peer.to_ascii_lowercase())
                .or_default()
                .verdicts = verdicts
                .iter()
                .map(|v| HeldVerdict {
                    at: v.recorded_at.as_deref().and_then(parse_minute),
                    adverse: v.bucket == crate::verdict_counts::CONTRADICTED,
                })
                .collect();
        }
        facts
    }
}

/// The evaluator's view of this node's own book with a peer: `local` as its
/// records name the peer, and `held`, the exchanges whose half this node
/// holds under the peer's announced key. The denominator is every exchange
/// either names, so neither count exceeds it. The evaluator windows the
/// verdicts to the pack's `window_days`, which equals
/// [`DISPUTE_PERIOD_DAYS`]; a verdict whose time does not read is in the
/// period, and so is one stated after `now`: both are read at `now`.
fn own_history(
    local: Option<&LocalFacts>,
    held: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> engine::OwnHistory {
    let count = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    let empty = LocalFacts::default();
    let local = local.unwrap_or(&empty);
    engine::OwnHistory {
        exchanges: count(local.exchanges.union(held).count()),
        settled: count(local.settled.len()),
        held_halves: count(held.len()),
        conflicting: 0,
        verdicts: local
            .verdicts
            .iter()
            .map(|v| engine::AdjudicationVerdict {
                at: timestamp(v.at.map_or(now, |at| at.min(now))),
                adverse: v.adverse,
            })
            .collect(),
    }
}

/// `(the key the half verified under, the half's capsule id, this node's own
/// half's capsule id)` from a citing record whose receiver checked the half's
/// signature.
fn held_half(record: &Value) -> Option<(String, String, Option<String>)> {
    let received = record.pointer("/model_attestation/compute_attestation/received_half")?;
    if received.get("signature_ok").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let key = received
        .get("sender_key_id")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())?;
    let half = record
        .get("references")
        .and_then(Value::as_array)?
        .iter()
        .find(|r| r.get("citation_purpose").and_then(Value::as_str) == Some("counterparty_half"))
        .and_then(|r| r.get("digest"))
        .and_then(Value::as_str)?;
    let own = received
        .get("own_half_capsule_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some((key.to_ascii_lowercase(), half.to_string(), own))
}

/// A sealed time, RFC 3339 or minute-granular (`2026-10-29T16:30Z`).
fn parse_minute(at: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(at)
        .ok()
        .or_else(|| {
            at.strip_suffix('Z')
                .and_then(|minute| DateTime::parse_from_rfc3339(&format!("{minute}:00Z")).ok())
        })
        .map(|at| at.with_timezone(&Utc))
}

#[cfg(test)]
mod tests;
