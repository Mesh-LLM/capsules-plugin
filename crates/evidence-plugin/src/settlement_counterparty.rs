//! The counterparty cross-check of the Lightning denominator
//! (Mesh-LLM/capsules-plugin#83): Lightning has no public ledger, so the
//! count of settlements a node discloses is checked against the other side's
//! book instead.
//!
//! **The other side's half.** `GET settlement-bundle?peer=<id>` gives this
//! node's own terminal settlement records (`payment.lifecycle.v1`, either
//! side) for exchanges with that one peer, as an Evidence Bundle proven
//! against one signed checkpoint, built by the same producer-selected builder
//! as the receipt bundles ([`crate::deal_receipt::selected_bundle`]). Only
//! terminal settlements are carried: no invoice, terms, accounting or
//! exchange record, and nothing about payments with anyone else. A
//! settlement belongs to the peer its exchange's record names
//! ([`settlements_with`]). The route is the owner's; the owner hands the file
//! to the counterparty, and it is never served to peers.
//!
//! **The check.** `settlement_check` given that bundle as
//! `counterparty_bundle` verifies it strictly (every record and the
//! checkpoint signed by one key, accepted for a peer through
//! [`crate::peer_keys::accepted_via`] and not this node's own; every record
//! proven under the checkpoint), takes this node's own settlements for
//! exchanges with those peers, and pairs payment hashes across the two books
//! with loop#183's rule (`steps/06-settle`, `crosscheck`): a hash pairs when
//! all its payer observations are in one book with one `amount_msat`, all its
//! provider observations are in the other with one
//! `credited_msat + fee_msat`, and the two amounts are equal. Every other hash
//! is unpaired, with its reason.
//!
//! Both books holding a hash and contradicting each other is `FAIL`. A hash
//! in one book only, a settlement with no hash, or one of this node's that
//! names no peer leaves the result `INCONCLUSIVE`. `public_ledger_count`
//! stays `NOT_CHECKED`; this result never stands in for it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::checkpoint_cadence::CheckpointHandle;
use crate::deal_receipt::{selected_bundle, Error, Selection};
use crate::evidence_log::{self, LedgerIndex};
use crate::settlement_adapter::{Kind, Observation, Side, Status};

/// The method a `counterparty_count` result names.
pub const METHOD: &str = "payment_hash pairs across the two books by role and amount (loop#183)";

/// This node's terminal settlement records for exchanges with `peers`, in
/// log order.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Attributed {
    pub ids: Vec<String>,
    /// Terminal settlements whose exchange names no counterparty this node
    /// can read, or two, so they belong to no peer: never carried, and they
    /// keep a cross-check from passing.
    pub unattributed: u64,
}

/// A settlement names its exchange by the host's `exchange_id`; the
/// exchange's own record, correlated under the same id, names the peer
/// (`Leaf::counterparty`). A settlement for another peer's exchange is
/// neither carried nor counted, so a bundle never shows a counterparty this
/// node's payments with anyone else.
pub fn settlements_with(index: &LedgerIndex, peers: &[String]) -> std::io::Result<Attributed> {
    let view = index.view()?;
    let mut out = Attributed::default();
    for (i, leaf) in index.leaves.iter().enumerate() {
        if leaf.padding {
            continue;
        }
        let Some(record) = view.record_at(i as u64) else {
            continue;
        };
        let Ok(capsule) = serde_json::from_slice::<Value>(&record.body) else {
            continue;
        };
        let Some(observation) = Observation::from_lifecycle_record(&capsule)
            .filter(|o| o.kind == Kind::Settlement && o.terminal)
        else {
            continue;
        };
        // The index correlates nonces too, so each candidate's own
        // `exchange_id` is read back; an exchange naming two peers belongs to
        // neither.
        let mut named: BTreeSet<String> = BTreeSet::new();
        for &j in index.correlated(&observation.exchange_id) {
            let Some(peer) = index
                .leaves
                .get(usize::try_from(j).unwrap_or(usize::MAX))
                .and_then(|l| l.counterparty.clone())
            else {
                continue;
            };
            let binds = view
                .record_at(j)
                .and_then(|r| serde_json::from_slice::<Value>(&r.body).ok())
                .is_some_and(|exchange| {
                    crate::evidence_panes::record_exchange_id(&exchange)
                        == Some(observation.exchange_id.as_str())
                });
            if binds {
                named.insert(peer);
            }
        }
        match named.iter().next() {
            Some(peer) if named.len() == 1 => {
                if peers.iter().any(|want| want == peer) {
                    out.ids.push(record.digest);
                }
            }
            _ => out.unattributed += 1,
        }
    }
    Ok(out)
}

/// Why no bundle is given.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NoSettlement,
    NotCheckpointed,
}

impl Refusal {
    fn why(&self) -> &'static str {
        match self {
            Refusal::NoSettlement => {
                "this node holds no terminal settlement record for an exchange with that peer"
            }
            Refusal::NotCheckpointed => "no signed checkpoint covers the records yet",
        }
    }
}

#[derive(Debug)]
pub enum Failure {
    Refused(Refusal),
    Failed(String),
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        match e {
            Error::Refused(_) => Failure::Refused(Refusal::NotCheckpointed),
            Error::Failed(why) => Failure::Failed(why),
        }
    }
}

fn unreadable(e: std::io::Error) -> Failure {
    Failure::Failed(format!("the ledger is not readable: {e}"))
}

/// The terminal settlements for exchanges with `peer`, chosen once so the
/// checkpoint cut for them and the bundle built over them are the same set.
pub fn select(ledger_dir: &Path, node_key_id: &str, peer: &str) -> Result<Attributed, Failure> {
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        settlements_with(index, &[peer.to_string()]).map_err(unreadable)
    })
    .map_err(unreadable)?
}

/// `ids` as a producer-selected bundle, proven against the earliest
/// checkpoint that reaches them all.
pub fn bundle(ledger_dir: &Path, node_key_id: &str, ids: &[String]) -> Result<Value, Failure> {
    let Some(root) = ids.last().cloned() else {
        return Err(Failure::Refused(Refusal::NoSettlement));
    };
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        Ok(selected_bundle(
            index,
            node_key_id,
            Selection {
                root: &root,
                ids,
                disclosures: BTreeMap::new(),
                extensions: Map::new(),
            },
        )?)
    })
    .map_err(unreadable)?
}

pub fn answer(ledger_dir: &Path, node_key_id: &str, ids: &[String]) -> Result<Value, String> {
    match bundle(ledger_dir, node_key_id, ids) {
        Ok(bundle) => Ok(json!({"state": "bundle", "bundle": bundle})),
        Err(Failure::Refused(r)) => Ok(json!({"state": "refused", "why": r.why()})),
        Err(Failure::Failed(why)) => Err(why),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SettlementBundleArgs {
    /// The counterparty's peer id: only settlements for exchanges with it
    /// are carried.
    pub peer: Value,
}

pub fn with_route(
    builder: DeclarativePluginBuilder,
    capsules: Arc<crate::capsule_emit::CapsuleState>,
    checkpoints: Option<CheckpointHandle>,
) -> DeclarativePluginBuilder {
    builder.http_item(
        http::get("/settlement-bundle")
            .binding_id("evidence_settlement_bundle")
            .description(
                "This node's own terminal Lightning settlement records for exchanges with one \
                 peer, proven against a signed checkpoint, for that peer's settlement_check to \
                 cross-check its count against. Owner-only; the owner hands it over. Cuts a \
                 signed checkpoint when none covers the records yet.",
            )
            .input::<SettlementBundleArgs>()
            .handle(move |args, _context| {
                let capsules = capsules.clone();
                let checkpoints = checkpoints.clone();
                Box::pin(async move {
                    let Some(peer) = args
                        .peer
                        .as_str()
                        .filter(|s| !s.is_empty() && s.len() <= 256)
                        .map(str::to_string)
                    else {
                        return Err(PluginError::invalid_params(
                            "peer must be a non-empty string",
                        ));
                    };
                    let ledger_dir = capsules.ledger_dir().to_path_buf();
                    let node_key_id = crate::commitment::key_id(capsules.signing_key());
                    let selected = {
                        let (dir, key) = (ledger_dir.clone(), node_key_id.clone());
                        tokio::task::spawn_blocking(move || select(&dir, &key, &peer))
                            .await
                            .map_err(|e| {
                                PluginError::internal(format!(
                                    "settlement bundle task did not complete: {e}"
                                ))
                            })?
                    };
                    let ids = match selected {
                        Ok(a) => a.ids,
                        Err(Failure::Refused(r)) => {
                            return Ok(json!({"state": "refused", "why": r.why()}))
                        }
                        Err(Failure::Failed(why)) => return Err(PluginError::internal(why)),
                    };
                    if let (Some(handle), Some(last)) = (checkpoints.as_ref(), ids.last()) {
                        let _ = handle.coverage_for(last).await;
                    }
                    tokio::task::spawn_blocking(move || answer(&ledger_dir, &node_key_id, &ids))
                        .await
                        .map_err(|error| {
                            PluginError::internal(format!(
                                "settlement bundle task did not complete: {error}"
                            ))
                        })?
                        .map_err(PluginError::internal)
                })
            }),
    )
}

/// The counterparty's settlement observations, once its bundle verified, and
/// the peers its key is accepted for.
pub struct Verified {
    pub key_id: String,
    pub peers: Vec<String>,
    pub observations: Vec<Observation>,
}

/// Verify a counterparty's `settlement-bundle`. `accept` returns the peers a
/// key is accepted for (`None`: not accepted, or this node's own).
pub fn verify(
    bundle: &Value,
    accept: impl Fn(&str) -> Option<Vec<String>>,
) -> Result<Verified, String> {
    use agent_action_capsule::bundle::{verify_bundle_strict, StrictOptions};
    let result = verify_bundle_strict(
        bundle,
        &StrictOptions {
            require_signature: true,
            witness_directory: None,
            ..Default::default()
        },
    );
    if !result.ok() {
        return Err(format!("the bundle is {}", result.verdict()));
    }
    // Producer-selected, so interval coverage is withheld; each record must
    // still be signed and proven under the signed checkpoint.
    for claim in ["signatures", "checkpoint", "per_record_membership"] {
        let status = result.claim(claim).map(|c| c.status.as_str());
        if status != Some("pass") {
            return Err(format!(
                "the bundle's {claim} claim is {status:?}, not pass"
            ));
        }
    }
    let key_id = result
        .signed_checkpoint
        .as_ref()
        .map(|c| c.key_id.clone())
        .ok_or("the bundle's checkpoint is not authenticated")?;
    if result.signer_matches_checkpoint != Some(true) {
        return Err("a record is signed by a key other than the checkpoint's".into());
    }
    let records = bundle
        .get("records")
        .and_then(Value::as_array)
        .ok_or("the bundle carries no records")?;
    let observations = records
        .iter()
        .filter_map(Observation::from_lifecycle_record)
        .filter(|o| o.kind == Kind::Settlement && o.terminal)
        .collect();
    let peers = accept(&key_id).ok_or("the bundle's key is not accepted for any peer")?;
    Ok(Verified {
        key_id,
        peers,
        observations,
    })
}

/// Both books, ready to pair: the counterparty's verified one, and this
/// node's terminal settlements for exchanges with that counterparty.
pub struct Books {
    pub counterparty: Verified,
    pub own: Vec<Observation>,
    /// This node's terminal settlements it cannot attribute to any peer.
    pub own_unattributed: u64,
}

/// Verify `bundle` as the counterparty's, its key accepted the way every
/// peer key is ([`crate::peer_keys::accepted_via`]: never this node's own),
/// and gather this node's settlements for exchanges with the peers that key
/// is accepted for.
pub fn books(
    capsules: &crate::capsule_emit::CapsuleState,
    configured: Option<&str>,
    announced: &BTreeMap<String, String>,
    bundle: &Value,
) -> Result<Books, String> {
    let own_key = hex::encode(capsules.signing_key().verifying_key().to_bytes());
    let counterparty = verify(bundle, |key| {
        crate::peer_keys::accepted_via(configured, announced, key, &own_key, None, None)
            .map(|accepted| accepted.peers)
    })?;
    let node_key_id = crate::commitment::key_id(capsules.signing_key());
    let attributed = evidence_log::with_index(capsules.ledger_dir(), &node_key_id, |index| {
        settlements_with(index, &counterparty.peers)
    })
    .and_then(|r| r)
    .map_err(|e| format!("the ledger is not readable: {e}"))?;
    let mut own = Vec::new();
    for id in &attributed.ids {
        let entry = capsules
            .lookup(id)
            .map_err(|e| format!("the ledger could not be read: {e}"))?;
        if let Some(o) = entry.and_then(|e| Observation::from_lifecycle_record(&e.capsule)) {
            own.push(o);
        }
    }
    Ok(Books {
        counterparty,
        own,
        own_unattributed: attributed.unattributed,
    })
}

/// Which book an observation is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Book {
    Own,
    Counterparty,
}

impl Book {
    fn wire(self) -> &'static str {
        match self {
            Book::Own => "this node",
            Book::Counterparty => "the counterparty",
        }
    }
}

/// One payment hash's verdict across the two books: paired, unpaired with
/// a reason, and whether the books contradict each other.
fn pair(seen: &[(Book, &Observation)]) -> Option<(String, bool)> {
    let books: BTreeSet<Book> = seen.iter().map(|(b, _)| *b).collect();
    if books.len() < 2 {
        let only = books.iter().next().map_or("", |b| b.wire());
        return Some((format!("recorded by {only} only"), false));
    }
    let mut payers: BTreeSet<(Book, u64)> = BTreeSet::new();
    let mut payees: BTreeSet<(Book, u64)> = BTreeSet::new();
    let mut payer_books: BTreeSet<Book> = BTreeSet::new();
    let mut payee_books: BTreeSet<Book> = BTreeSet::new();
    let mut incomplete = false;
    for (book, o) in seen {
        // Roles come from every observation; amounts only from complete ones.
        match o.side {
            Side::Payer => payer_books.insert(*book),
            Side::Provider => payee_books.insert(*book),
        };
        match o.side {
            Side::Payer => {
                payers.insert((*book, o.amount_msat));
            }
            Side::Provider => match o
                .credited_msat
                .zip(o.fee_msat)
                .and_then(|(c, f)| c.checked_add(f))
            {
                Some(sum) => {
                    payees.insert((*book, sum));
                }
                None => incomplete = true,
            },
        }
    }
    let payer_amounts: BTreeSet<u64> = payers.iter().map(|(_, a)| *a).collect();
    let payee_amounts: BTreeSet<u64> = payees.iter().map(|(_, a)| *a).collect();
    // A contradiction among the complete observations stands whatever an
    // incomplete one would have said.
    if payer_books.len() > 1
        || payee_books.len() > 1
        || (!payer_books.is_empty() && payer_books == payee_books)
    {
        return Some((
            "both books observed the same role: one book of each role is needed".into(),
            true,
        ));
    }
    if !payers.is_empty()
        && !payees.is_empty()
        && (payer_amounts.len() > 1 || payee_amounts.len() > 1 || payer_amounts != payee_amounts)
    {
        return Some((
            format!(
                "conflicting amounts: payer {payer_amounts:?}, provider credited plus fee {payee_amounts:?}"
            ),
            true,
        ));
    }
    if incomplete {
        return Some((
            "a provider observation has no wallet-reported credited_msat and fee_msat".into(),
            false,
        ));
    }
    None
}

/// Pair payment hashes across the two books (loop#183's rule). A settlement
/// with no payment hash cannot be paired, and a settlement of this node's
/// that names no peer cannot be scoped: either keeps the result from `PASS`.
pub fn cross_check(books: &Books) -> Value {
    let mut by_hash: BTreeMap<&str, Vec<(Book, &Observation)>> = BTreeMap::new();
    let mut hashless: BTreeMap<Book, u64> =
        BTreeMap::from([(Book::Own, 0), (Book::Counterparty, 0)]);
    let tagged = books
        .own
        .iter()
        .map(|o| (Book::Own, o))
        .chain(
            books
                .counterparty
                .observations
                .iter()
                .map(|o| (Book::Counterparty, o)),
        )
        .filter(|(_, o)| o.kind == Kind::Settlement && o.terminal);
    for (book, o) in tagged {
        match o.payment_hash.as_deref() {
            Some(h) => by_hash.entry(h).or_default().push((book, o)),
            None => *hashless.entry(book).or_default() += 1,
        }
    }
    let mut paired = 0u64;
    let mut unpaired = Vec::new();
    let mut conflicting = false;
    for (hash, seen) in &by_hash {
        match pair(seen) {
            None => paired += 1,
            Some((reason, conflict)) => {
                conflicting |= conflict;
                unpaired.push(json!({"payment_hash": hash, "reason": reason}));
            }
        }
    }
    let uncheckable = hashless.values().sum::<u64>() + books.own_unattributed;
    let status = if conflicting {
        Status::Fail
    } else if unpaired.is_empty() && uncheckable == 0 && paired > 0 {
        Status::Pass
    } else {
        Status::Inconclusive
    };
    json!({
        "status": status.wire(),
        "method": METHOD,
        "counterparty_key": books.counterparty.key_id,
        "counterparty_peers": books.counterparty.peers,
        "paired": paired,
        "unpaired": unpaired,
        "settlements_without_payment_hash": {
            "this_node": hashless[&Book::Own],
            "counterparty": hashless[&Book::Counterparty],
        },
        "settlements_unattributed": books.own_unattributed,
    })
}

/// The result when no counterparty bundle was given (`NOT_PRESENT`), or it
/// did not verify (`NOT_CHECKED`: the input is there, the pairing not run).
pub fn not_run(status: Status, reason: &str) -> Value {
    json!({"status": status.wire(), "reason": reason})
}

#[cfg(test)]
mod tests;
