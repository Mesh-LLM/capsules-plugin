//! Settlement-records legs (draft-mih-agent-settlement-records-00) for paid
//! exchanges, beside the `payment.lifecycle.v1` trail
//! ([`crate::settlement_channel`]), which seals what it did before.
//!
//! One terms leg per invoice. Mesh pays per invoice, each with its own payment
//! hash: a deposit invoice (segment 0, the `input_*` phases) when the seller
//! asks for one, and a final invoice (segment 1, the `output_*` phases) only
//! when the bill exceeds the deposit (hosts before token metering issued an
//! input and an output invoice on these segments). An exchange can have
//! either, both or neither. -00 joins one payer-observed and one
//! payee-observed leg per terms leg.
//!
//! **Who seals what.**
//! - The payer seals the terms leg when it sees an invoice issued (the
//!   invoice amount, `payment_ref` = `ln.payment_hash`) and pushes it to the
//!   provider over `record-push/1`. -00 lets either party seal the terms leg
//!   (§3 item 4); the payer does here because only it can address the other
//!   side: its lifecycle events carry the host exchange id, which joins to the
//!   exchange event naming the serving peer, while a provider's lifecycle
//!   events name no requester.
//! - The payer seals `payer_observed` when its wallet reports the payment
//!   settled: `amount` is the wallet transaction's own amount (the host's
//!   payer settlement event carries it), and `routing_fee` is the wallet's fee
//!   when the host passes it.
//! - The provider seals `payee_observed` citing the payer's terms leg, when
//!   its wallet reported what it credited and deducted (`received`,
//!   `receive_fee`). A host that does not pass those numbers gets no payee
//!   leg: the invoice amount is not what the wallet credited, and a missing
//!   fee never reconciles. The provider cites only the first pushed terms leg
//!   for one of its own invoices whose amount is that invoice's amount; any
//!   other pushed terms leg is ignored.
//! - The payer seals `delivered` (`received`) with the exchange's response
//!   digest once its host reports the bill accounted (`final_accounted`), so
//!   no final invoice is still to come. It cites the final invoice's terms
//!   leg, or the deposit's when the deposit covered the bill; an exchange
//!   with no invoice has no terms leg to cite and gets no delivered leg. The
//!   provider's own delivered leg needs its exchange event joined to its
//!   lifecycle events, which the host does not do yet, so it is not sealed.
//!
//! `observed_at` is when this node received the host's event, coarsened to
//! the minute like every committed time here; the host's events carry no
//! wallet time.
//!
//! **Bounded and best-effort.** What waits (a terms leg not yet pushed, a
//! payee observation waiting for its terms leg, this node's invoices) is held
//! in memory, bounded by count (at most [`MAX_HELD`] entries per kind, oldest
//! dropped first) and by time (an entry older than [`MAX_AGE`] is dropped,
//! with a log line, checked on each event), and lost on restart. A push that
//! fails is queued again and retried with the next settlement event while it
//! is held. A leg that cannot be sealed is missing evidence, never a failed
//! exchange.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use capsule_emit_lib::settlement::{amount, build_leg};
use serde_json::{json, Map, Value};

use crate::capsule_emit::{CapsuleState, EmittedCapsule};
use crate::settlement_channel::{PaymentLifecycleEvent, Phase, Role};

/// How many entries each waiting kind holds.
pub const MAX_HELD: usize = 512;

/// How long an entry is held. A paid exchange's events arrive within
/// seconds to minutes of each other; anything older is not coming.
pub const MAX_AGE: Duration = Duration::from_secs(15 * 60);

/// A sealed terms leg to push to `peer`.
#[derive(Debug, Clone)]
pub struct Push {
    pub peer: String,
    pub capsule: Value,
    exchange_id: String,
    hash: String,
}

/// A map that keeps at most [`MAX_HELD`] entries, dropping the oldest, each
/// stamped with when it was inserted (for [`MAX_AGE`]).
struct Bounded<V> {
    map: HashMap<String, (Instant, V)>,
    order: VecDeque<String>,
}

impl<V> Default for Bounded<V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<V> Bounded<V> {
    fn insert(&mut self, key: String, value: V) {
        if self
            .map
            .insert(key.clone(), (Instant::now(), value))
            .is_none()
        {
            self.order.push_back(key);
            while self.order.len() > MAX_HELD {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
    fn get(&self, key: &str) -> Option<&V> {
        self.map.get(key).map(|(_, value)| value)
    }
    fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }
    fn remove(&mut self, key: &str) -> Option<V> {
        let (_, value) = self.map.remove(key)?;
        self.order.retain(|k| k != key);
        Some(value)
    }
    /// Drop the entries inserted before `cutoff`; returns how many.
    fn expire(&mut self, cutoff: Instant) -> usize {
        let before = self.map.len();
        self.map.retain(|_, (at, _)| *at >= cutoff);
        let map = &self.map;
        self.order.retain(|k| map.contains_key(k));
        before - self.map.len()
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// A terms leg this node (as payer) sealed.
#[derive(Clone)]
struct OwnTerms {
    capsule: Value,
    capsule_id: String,
    /// The invoice's amount (msat), and whether it is the final invoice.
    amount_msat: u64,
    final_invoice: bool,
}

#[derive(Default)]
struct Inner {
    /// Payer: its terms legs, by payment hash.
    own_terms: Bounded<OwnTerms>,
    /// Payer: the payment hash whose terms leg the delivered leg cites, by
    /// exchange id: the final invoice's, else the deposit's.
    cited_hash: Bounded<String>,
    /// Payer: the bill (msat) the host accounted (`final_accounted`), by
    /// exchange id.
    accounted: Bounded<u64>,
    /// Payer: the serving peer, by exchange id.
    peer: Bounded<String>,
    /// Payer: payment hashes whose terms leg is not pushed yet, by exchange id.
    unpushed: Bounded<Vec<String>>,
    /// Payer: the response digest, by exchange id.
    response: Bounded<String>,
    /// Provider: its own invoices' amounts (msat), by payment hash.
    invoices: Bounded<u64>,
    /// Provider: the terms leg it cites, by payment hash (first valid wins).
    received_terms: Bounded<String>,
    /// Provider: payee observations waiting for their terms leg.
    waiting_payee: Bounded<PaymentLifecycleEvent>,
    /// Payer: the agreement this exchange cites, decided once when the
    /// exchange's terminal event is seen and before any session is set up
    /// from it, so the exchange never cites a session it triggered (R11,
    /// R12). `None` inside is a decision too: it cites nothing.
    citation: Bounded<Option<String>>,
    /// Provider: the agreement its exchange cites, by its host's exchange
    /// id, decided at the exchange's terminal event (`decide_served_citation`):
    /// the served half and the payee leg both use it (R12).
    served_citation: Bounded<Option<String>>,
    /// Provider: the key that signed the terms leg it cites, by payment
    /// hash: whose agreement the payee leg cites (R12).
    received_from: Bounded<String>,
}

/// A payer's delivered leg that is due: the terms leg and the agreement it
/// cites, and the delivered content's digest.
struct Delivered {
    exchange_id: String,
    terms_ref: String,
    digest: String,
    acceptance: Option<String>,
}

/// This node's settlement-records state (held by [`CapsuleState`]).
#[derive(Default)]
pub struct Legs {
    inner: Mutex<Inner>,
}

fn msat(value: u64) -> Value {
    amount(u128::from(value), "BTC", 11)
}

fn ln(hash: &str) -> Value {
    json!({"type": "ln.payment_hash", "value": hash})
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn now() -> String {
    capsule_emit_lib::timestamp::utc_now_minute()
}

fn built(leg: &str, role: &str, pairs: Vec<(&str, Value)>) -> anyhow::Result<Value> {
    let members: Map<String, Value> = pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    build_leg(leg, role, members).map_err(|e| anyhow::anyhow!("{e}"))
}

/// The blocks a leg carries: an agreement citation when it has one (R5).
fn citation_blocks(acceptance: Option<String>) -> Map<String, Value> {
    acceptance
        .map(|d| crate::producer::capsule::leg_acceptance_blocks(&d))
        .unwrap_or_default()
}

fn seal(
    capsules: &CapsuleState,
    action: &str,
    member: anyhow::Result<Value>,
) -> Option<EmittedCapsule> {
    seal_with(capsules, action, member, Map::new())
}

fn seal_with(
    capsules: &CapsuleState,
    action: &str,
    member: anyhow::Result<Value>,
    blocks: Map<String, Value>,
) -> Option<EmittedCapsule> {
    let member = match member {
        Ok(member) => member,
        Err(error) => {
            tracing::warn!(%error, %action, "settlement leg not built");
            return None;
        }
    };
    match capsules.emit_settlement_leg(format!("mesh/settlement/{action}"), member, blocks, None) {
        Ok(Some(sealed)) => {
            tracing::debug!(capsule_id = %sealed.capsule_id, %action, "sealed settlement leg");
            Some(sealed)
        }
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, %action, "settlement leg not sealed");
            None
        }
    }
}

impl Legs {
    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drop every entry held longer than [`MAX_AGE`] as of `now`, with one log
    /// line per kind that lost entries. Run on each event.
    fn expire(&self, now: Instant) {
        let Some(cutoff) = now.checked_sub(MAX_AGE) else {
            return;
        };
        let mut inner = self.inner();
        let dropped = [
            ("terms legs", inner.own_terms.expire(cutoff)),
            ("cited invoices", inner.cited_hash.expire(cutoff)),
            ("accounted exchanges", inner.accounted.expire(cutoff)),
            ("serving peers", inner.peer.expire(cutoff)),
            ("unpushed terms legs", inner.unpushed.expire(cutoff)),
            ("response digests", inner.response.expire(cutoff)),
            ("own invoices", inner.invoices.expire(cutoff)),
            ("received terms legs", inner.received_terms.expire(cutoff)),
            ("exchange citations", inner.citation.expire(cutoff)),
            ("served citations", inner.served_citation.expire(cutoff)),
            ("terms leg signers", inner.received_from.expire(cutoff)),
            (
                "waiting payee observations",
                inner.waiting_payee.expire(cutoff),
            ),
        ];
        for (kind, count) in dropped {
            if count > 0 {
                tracing::info!(
                    count,
                    kind,
                    "settlement legs: dropped entries held longer than the time bound"
                );
            }
        }
    }

    /// A checked lifecycle event. Returns the terms legs to push now.
    pub fn on_lifecycle(
        &self,
        capsules: &CapsuleState,
        event: &PaymentLifecycleEvent,
    ) -> Vec<Push> {
        self.expire(Instant::now());
        let role = event.role.unwrap_or(Role::Payer);
        if role == Role::Payer && event.phase == Phase::FinalAccounted {
            self.payer_accounted(capsules, &event.exchange_id, event.amount_msat);
            return Vec::new();
        }
        let Some(hash) = event.payment_hash.as_deref() else {
            return Vec::new();
        };
        let invoice = matches!(
            event.phase,
            Phase::InputInvoiceIssued | Phase::OutputInvoiceIssued
        );
        let settled = matches!(
            event.phase,
            Phase::InputSettlementObserved | Phase::OutputSettlementObserved
        );
        match role {
            Role::Payer if invoice => return self.payer_terms(capsules, event, hash),
            Role::Payer if settled => self.payer_observed(capsules, event, hash),
            Role::Provider if invoice => self
                .inner()
                .invoices
                .insert(hash.to_string(), event.amount_msat),
            Role::Provider if settled => {
                if event.credited_msat.is_none() || event.fee_msat.is_none() {
                    tracing::debug!("host passes no wallet amounts; no payee leg");
                    return Vec::new();
                }
                // One lock: a terms leg arriving between the check and the
                // insert would otherwise leave this observation waiting.
                let terms = {
                    let mut inner = self.inner();
                    let terms = inner.received_terms.get(hash).cloned();
                    if terms.is_none() {
                        inner.waiting_payee.insert(hash.to_string(), event.clone());
                    }
                    terms
                };
                if let Some(terms_ref) = terms {
                    self.payee_observed(capsules, event, hash, &terms_ref);
                }
            }
            _ => {}
        }
        Vec::new()
    }

    fn payer_terms(
        &self,
        capsules: &CapsuleState,
        event: &PaymentLifecycleEvent,
        hash: &str,
    ) -> Vec<Push> {
        let leg = built(
            "terms",
            "payer",
            vec![
                ("amount", msat(event.amount_msat)),
                ("payment_ref", ln(hash)),
            ],
        );
        let exchange_id = event.exchange_id.clone();
        // The final invoice is cited over the deposit, and recorded before
        // sealing: if its terms leg is not sealed there is nothing to cite,
        // rather than the deposit's.
        if event.phase == Phase::OutputInvoiceIssued {
            self.inner()
                .cited_hash
                .insert(exchange_id.clone(), hash.to_string());
        }
        let Some(sealed) = seal(capsules, "terms", leg) else {
            return Vec::new();
        };
        capsules.deals().on_invoice(
            capsules,
            &exchange_id,
            &sealed.capsule_id,
            event.amount_msat,
            unix_now(),
        );
        let (push, delivered) = {
            let mut inner = self.inner();
            inner.own_terms.insert(
                hash.to_string(),
                OwnTerms {
                    capsule: sealed.capsule.clone(),
                    capsule_id: sealed.capsule_id.clone(),
                    amount_msat: event.amount_msat,
                    final_invoice: event.phase == Phase::OutputInvoiceIssued,
                },
            );
            if !inner.cited_hash.contains(&exchange_id) {
                inner
                    .cited_hash
                    .insert(exchange_id.clone(), hash.to_string());
            }
            let push = match inner.peer.get(&exchange_id).cloned() {
                Some(peer) => Some(Push {
                    peer,
                    capsule: sealed.capsule,
                    exchange_id: exchange_id.clone(),
                    hash: hash.to_string(),
                }),
                None => {
                    let mut waiting = inner.unpushed.remove(&exchange_id).unwrap_or_default();
                    waiting.push(hash.to_string());
                    inner.unpushed.insert(exchange_id.clone(), waiting);
                    None
                }
            };
            (push, Self::delivered_due(&mut inner, &exchange_id))
        };
        if let Some(due) = delivered {
            self.seal_payer_delivered(capsules, due);
        }
        push.into_iter().collect()
    }

    fn payer_observed(&self, capsules: &CapsuleState, event: &PaymentLifecycleEvent, hash: &str) {
        let Some(terms) = self.inner().own_terms.get(hash).cloned() else {
            tracing::debug!(%hash, "payer settlement before its terms leg; no payer leg");
            return;
        };
        let mut pairs = vec![
            ("terms_ref", json!(terms.capsule_id)),
            ("amount", msat(event.amount_msat)),
            ("payment_ref", ln(hash)),
            ("status", json!("settled")),
            ("observed_at", json!(now())),
        ];
        if let Some(fee) = event.fee_msat {
            pairs.push(("routing_fee", msat(fee)));
        }
        if let Some(sealed) = seal(
            capsules,
            "payer_observed",
            built("payer_observed", "payer", pairs),
        ) {
            capsules.deals().on_paid(
                capsules,
                &event.exchange_id,
                &sealed.capsule_id,
                event.amount_msat,
                unix_now(),
            );
        }
    }

    fn payee_observed(
        &self,
        capsules: &CapsuleState,
        event: &PaymentLifecycleEvent,
        hash: &str,
        terms_ref: &str,
    ) {
        let (Some(credited), Some(fee)) = (event.credited_msat, event.fee_msat) else {
            return;
        };
        // The leg names no exchange. The payment is noted for this one before
        // the leg is sealed, so a crash between the two (or a replay that finds
        // the leg already sealed) leaves the note, and the provider's receipt
        // finds the leg by its payment hash.
        if let Err(error) =
            crate::provider_receipt::note_payment(capsules.ledger_dir(), &event.exchange_id, hash)
        {
            tracing::warn!(%error, "payment not noted for its exchange; the leg is not sealed");
            return;
        }
        let leg = built(
            "payee_observed",
            "payee",
            vec![
                ("terms_ref", json!(terms_ref)),
                ("received", msat(credited)),
                ("receive_fee", msat(fee)),
                ("payment_ref", ln(hash)),
                ("status", json!("settled")),
                ("observed_at", json!(now())),
            ],
        );
        // The provider's decision for the exchange, made when it was served,
        // and only for the session of the payer whose key signed the terms
        // leg. A payment settled before the exchange was served (a deposit)
        // has no decision yet and cites nothing.
        let (payer_key, decided) = {
            let inner = self.inner();
            (
                inner.received_from.get(hash).cloned(),
                inner
                    .served_citation
                    .get(&event.exchange_id)
                    .cloned()
                    .flatten(),
            )
        };
        let acceptance = match (payer_key, decided) {
            (Some(key), Some(digest))
                if crate::agreement_bridge::session_proposer(capsules, &digest).as_deref()
                    == Some(key.as_str()) =>
            {
                Some(digest)
            }
            _ => None,
        };
        seal_with(capsules, "payee_observed", leg, citation_blocks(acceptance));
    }

    /// Payer: the agreement `exchange_id` cites, decided by `decide` the
    /// first time it is asked and kept, so a session set up after this
    /// point (from this very exchange) is never cited by it.
    pub fn decide_citation(
        &self,
        exchange_id: &str,
        decide: impl FnOnce() -> Option<String>,
    ) -> Option<String> {
        if let Some(decided) = self.inner().citation.get(exchange_id) {
            return decided.clone();
        }
        let decided = decide();
        self.inner()
            .citation
            .insert(exchange_id.to_string(), decided.clone());
        decided
    }

    /// Payer: the citation decided for `exchange_id`, if one was.
    pub fn citation_of(&self, exchange_id: &str) -> Option<Option<String>> {
        self.inner().citation.get(exchange_id).cloned()
    }

    /// Provider: the agreement its exchange `exchange_id` cites, decided by
    /// `decide` at the exchange's terminal event the first time it is asked
    /// and kept, so a session set up later never reaches the served half or
    /// a payee leg sealed after it.
    pub fn decide_served_citation(
        &self,
        exchange_id: &str,
        decide: impl FnOnce() -> Option<String>,
    ) -> Option<String> {
        if let Some(decided) = self.inner().served_citation.get(exchange_id) {
            return decided.clone();
        }
        let decided = decide();
        self.inner()
            .served_citation
            .insert(exchange_id.to_string(), decided.clone());
        decided
    }

    /// Provider: the citation decided for its exchange `exchange_id`.
    pub fn served_citation_of(&self, exchange_id: &str) -> Option<Option<String>> {
        self.inner().served_citation.get(exchange_id).cloned()
    }

    /// Payer: the exchange event for `exchange_id` named its serving `peer`
    /// and, on a terminal event, the `response_digest`. Returns the terms
    /// legs that were waiting for the peer.
    pub fn on_exchange(
        &self,
        capsules: &CapsuleState,
        exchange_id: &str,
        peer: Option<&str>,
        response_digest: Option<&str>,
    ) -> Vec<Push> {
        self.expire(Instant::now());
        let (pushes, delivered) = {
            let mut inner = self.inner();
            if let Some(peer) = peer {
                inner.peer.insert(exchange_id.to_string(), peer.to_string());
            }
            let pushes = Self::take_ready(&mut inner, exchange_id);
            if let Some(digest) = response_digest {
                inner
                    .response
                    .insert(exchange_id.to_string(), digest.to_string());
            }
            (pushes, Self::delivered_due(&mut inner, exchange_id))
        };
        if let Some(due) = delivered {
            self.seal_payer_delivered(capsules, due);
        }
        pushes
    }

    /// The terms legs not yet pushed whose serving peer is known: retried
    /// after a push failed or was skipped.
    pub fn retry(&self) -> Vec<Push> {
        self.expire(Instant::now());
        let mut inner = self.inner();
        let ready: Vec<String> = inner
            .unpushed
            .order
            .iter()
            .filter(|ex| inner.peer.contains(ex))
            .cloned()
            .collect();
        ready
            .iter()
            .flat_map(|ex| Self::take_ready(&mut inner, ex))
            .collect()
    }

    fn take_ready(inner: &mut Inner, exchange_id: &str) -> Vec<Push> {
        let Some(peer) = inner.peer.get(exchange_id).cloned() else {
            return Vec::new();
        };
        let hashes = inner.unpushed.remove(exchange_id).unwrap_or_default();
        hashes
            .into_iter()
            .filter_map(|hash| {
                let terms = inner.own_terms.get(&hash)?;
                Some(Push {
                    peer: peer.clone(),
                    capsule: terms.capsule.clone(),
                    exchange_id: exchange_id.to_string(),
                    hash,
                })
            })
            .collect()
    }

    /// A push that failed or was skipped: queue its terms leg again.
    pub fn requeue(&self, push: &Push) {
        let mut inner = self.inner();
        let mut waiting = inner.unpushed.remove(&push.exchange_id).unwrap_or_default();
        if !waiting.contains(&push.hash) {
            waiting.push(push.hash.clone());
        }
        inner.unpushed.insert(push.exchange_id.clone(), waiting);
        inner
            .peer
            .insert(push.exchange_id.clone(), push.peer.clone());
    }

    /// Payer: the host accounted the exchange's bill (`final_accounted`), so
    /// every invoice it will issue for the exchange has been seen.
    fn payer_accounted(&self, capsules: &CapsuleState, exchange_id: &str, bill_msat: u64) {
        let delivered = {
            let mut inner = self.inner();
            inner.accounted.insert(exchange_id.to_string(), bill_msat);
            Self::delivered_due(&mut inner, exchange_id)
        };
        if let Some(due) = delivered {
            self.seal_payer_delivered(capsules, due);
        }
    }

    /// The payer's delivered leg is due once the bill is accounted and the
    /// response digest is known. It cites the final invoice's terms leg, or
    /// the deposit's when the deposit covered the bill; with neither there is
    /// nothing to cite and no leg. The host's lifecycle events are best
    /// effort, so a final invoice's event can be lost: the deposit is cited
    /// only when the accounted bill is within its amount. The exchange's
    /// entries are then cleared, so a later event for the same id starts
    /// afresh.
    fn delivered_due(inner: &mut Inner, exchange_id: &str) -> Option<Delivered> {
        let bill_msat = *inner.accounted.get(exchange_id)?;
        let digest = inner.response.get(exchange_id)?.clone();
        let acceptance = inner.citation.get(exchange_id).cloned().flatten();
        let terms = inner
            .cited_hash
            .get(exchange_id)
            .and_then(|hash| inner.own_terms.get(hash))
            .filter(|terms| {
                let covered = terms.final_invoice || bill_msat <= terms.amount_msat;
                if !covered {
                    tracing::debug!(
                        %exchange_id,
                        "the bill exceeds the deposit and no final invoice was seen; no delivered leg"
                    );
                }
                covered
            })
            .map(|terms| terms.capsule_id.clone());
        inner.accounted.remove(exchange_id);
        inner.cited_hash.remove(exchange_id);
        inner.response.remove(exchange_id);
        // The decision stays (it expires with the other entries): the
        // requested half, sealed after this, still reads it.
        if !inner.unpushed.contains(exchange_id) {
            inner.peer.remove(exchange_id);
        }
        if terms.is_none() {
            tracing::debug!(%exchange_id, "no terms leg for this exchange; no delivered leg");
        }
        Some(Delivered {
            exchange_id: exchange_id.to_string(),
            terms_ref: terms?,
            digest,
            acceptance,
        })
    }

    fn seal_payer_delivered(&self, capsules: &CapsuleState, due: Delivered) {
        let Delivered {
            exchange_id,
            terms_ref,
            digest,
            acceptance,
        } = due;
        let leg = built(
            "delivered",
            "payer",
            vec![
                ("terms_ref", json!(terms_ref)),
                ("observed_at", json!(now())),
                (
                    "delivery",
                    json!({"direction": "received", "content_digest": digest}),
                ),
            ],
        );
        if let Some(sealed) = seal_with(capsules, "delivered", leg, citation_blocks(acceptance)) {
            capsules
                .deals()
                .on_delivered(capsules, &exchange_id, &sealed.capsule_id, unix_now());
        }
    }

    /// Provider: a peer's pushed record was received and verified. It is held
    /// as the terms this node cites only when it is a payer's terms leg for
    /// one of this node's own invoices, at that invoice's amount, and no
    /// terms leg is held for that invoice yet. A waiting payee leg is sealed.
    pub fn on_received(&self, capsules: &CapsuleState, capsule: &Value) {
        let Some(member) = capsule.get("settlement") else {
            return;
        };
        let text = |pointer: &str| member.pointer(pointer).and_then(Value::as_str);
        if text("/leg") != Some("terms")
            || text("/sealer_role") != Some("payer")
            || text("/payment_ref/type") != Some("ln.payment_hash")
        {
            return;
        }
        let (Some(hash), Some(capsule_id)) = (
            text("/payment_ref/value"),
            capsule.get("capsule_id").and_then(Value::as_str),
        ) else {
            return;
        };
        let waiting = {
            let mut inner = self.inner();
            let Some(invoiced) = inner.invoices.get(hash).copied() else {
                tracing::debug!(%hash, "pushed terms leg for an invoice this node did not issue; ignored");
                return;
            };
            if member.get("amount") != Some(&msat(invoiced)) {
                tracing::warn!(%hash, "pushed terms leg does not state this invoice's amount; ignored");
                return;
            }
            if inner.received_terms.contains(hash) {
                return;
            }
            inner
                .received_terms
                .insert(hash.to_string(), capsule_id.to_string());
            if let Some(key) = capsule.get("key_id").and_then(Value::as_str) {
                inner
                    .received_from
                    .insert(hash.to_string(), key.to_string());
            }
            inner.waiting_payee.remove(hash)
        };
        if let Some(event) = waiting {
            self.payee_observed(capsules, &event, hash, capsule_id);
        }
    }

    /// How many entries each kind holds, in field order.
    #[cfg(test)]
    fn held(&self) -> [usize; 12] {
        let inner = self.inner();
        [
            inner.own_terms.len(),
            inner.cited_hash.len(),
            inner.accounted.len(),
            inner.peer.len(),
            inner.unpushed.len(),
            inner.response.len(),
            inner.invoices.len(),
            inner.received_terms.len(),
            inner.waiting_payee.len(),
            inner.citation.len(),
            inner.served_citation.len(),
            inner.received_from.len(),
        ]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::settlement_channel::{host_shaped_event, parse_and_check};
    use serde_json::Value;
    use std::path::Path;

    const INPUT: &str = "8437d5a5e0c5aa3304c0e0d17288cd504593ca7e560e3691a30739f1725ee7c5";
    const OUTPUT: &str = "59c0c4d2859c994004ad65ce13831b9cdaf688828d6c9f08cdb06f1bda9f15dd";
    const RESPONSE: &str = "33e3aff1f39db84ca6bc2e4a8d19703c57566b215e2fa5282dcfefc983bf4ebf";
    pub(crate) const PROVIDER_PEER: &str =
        "284a8bb62c0491b1a27f57425ce585626f7dc9a1495de4519a869a8c11d9f478";
    pub(crate) const WALLET: &[(&str, u64)] = &[("credited_msat", 995), ("fee_msat", 5)];

    /// A host-shaped event, with role and the wallet's numbers as given.
    pub(crate) fn event(
        role: &str,
        exchange_id: &str,
        phase: Phase,
        segment: u32,
        hash: &str,
        amount_msat: u64,
        wallet: &[(&str, u64)],
    ) -> PaymentLifecycleEvent {
        let mut body =
            host_shaped_event(exchange_id, phase, Some(segment), Some(hash), amount_msat);
        body["role"] = json!(role);
        if role == "provider"
            && matches!(
                phase,
                Phase::InputInvoiceIssued | Phase::OutputInvoiceIssued
            )
        {
            body["source"] = json!("provider_asserted");
        }
        for (k, v) in wallet {
            body[*k] = json!(v);
        }
        body["event_ref"] = json!("");
        body["event_ref"] = json!(crate::producer::jcs::json_digest(&body).unwrap());
        parse_and_check(&serde_json::to_vec(&body).unwrap()).expect("a host-shaped event")
    }

    /// The payer host's `final_accounted` for `exchange_id`, a bill of 1000.
    fn accounted(exchange_id: &str) -> PaymentLifecycleEvent {
        accounted_bill(exchange_id, 1000)
    }

    fn accounted_bill(exchange_id: &str, bill_msat: u64) -> PaymentLifecycleEvent {
        let mut body = host_shaped_event(exchange_id, Phase::FinalAccounted, None, None, bill_msat);
        body["role"] = json!("payer");
        body["event_ref"] = json!("");
        body["event_ref"] = json!(crate::producer::jcs::json_digest(&body).unwrap());
        parse_and_check(&serde_json::to_vec(&body).unwrap()).expect("a host-shaped event")
    }

    fn legs_of(dir: &Path) -> Vec<Value> {
        std::fs::read_to_string(dir.join("ledger").join("capsules.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|c| c.get("settlement").is_some())
            .collect()
    }

    fn kinds(legs: &[Value]) -> Vec<&str> {
        legs.iter()
            .map(|c| c["settlement"]["leg"].as_str().unwrap())
            .collect()
    }

    struct Pair {
        payer: CapsuleState,
        provider: CapsuleState,
    }

    impl Pair {
        fn open(a: &Path, b: &Path) -> Self {
            Pair {
                payer: CapsuleState::open(a, "payer-node").unwrap(),
                provider: CapsuleState::open(b, "provider-node").unwrap(),
            }
        }
        fn payer_event(
            &self,
            phase: Phase,
            seg: u32,
            hash: &str,
            wallet: &[(&str, u64)],
        ) -> Vec<Push> {
            self.payer.settlement_legs().on_lifecycle(
                &self.payer,
                &event("payer", "ex", phase, seg, hash, 1000, wallet),
            )
        }
        fn provider_event(&self, phase: Phase, seg: u32, hash: &str, wallet: &[(&str, u64)]) {
            self.provider.settlement_legs().on_lifecycle(
                &self.provider,
                &event("provider", "p-ex", phase, seg, hash, 1000, wallet),
            );
        }
        fn payer_accounted(&self) {
            self.payer
                .settlement_legs()
                .on_lifecycle(&self.payer, &accounted("ex"));
        }
        fn deliver(&self, pushes: &[Push]) {
            for push in pushes {
                assert_eq!(push.peer, PROVIDER_PEER);
                self.provider
                    .settlement_legs()
                    .on_received(&self.provider, &push.capsule);
            }
        }
    }

    /// Both nodes of one paid exchange, in the order a live run sees it:
    /// invoices, then each wallet's settlement and the payer's accounted
    /// bill, then the payer's exchange event naming the provider (when the
    /// terms legs are pushed).
    pub(crate) fn two_nodes(
        a: &Path,
        b: &Path,
        provider_wallet: &[(&str, u64)],
    ) -> (Vec<Value>, Vec<Value>) {
        let pair = Pair::open(a, b);
        for (phase, seg, hash) in [
            (Phase::InputInvoiceIssued, 0, INPUT),
            (Phase::OutputInvoiceIssued, 1, OUTPUT),
        ] {
            pair.provider_event(phase, seg, hash, &[]);
            assert!(
                pair.payer_event(phase, seg, hash, &[]).is_empty(),
                "no peer known yet"
            );
        }
        for (phase, seg, hash) in [
            (Phase::InputSettlementObserved, 0, INPUT),
            (Phase::OutputSettlementObserved, 1, OUTPUT),
        ] {
            pair.provider_event(phase, seg, hash, provider_wallet);
            pair.payer_event(phase, seg, hash, &[("fee_msat", 0)]);
        }
        pair.payer_accounted();
        let pushes = pair.payer.settlement_legs().on_exchange(
            &pair.payer,
            "ex",
            Some(PROVIDER_PEER),
            Some(RESPONSE),
        );
        assert_eq!(pushes.len(), 2);
        pair.deliver(&pushes);
        (legs_of(a), legs_of(b))
    }

    pub(crate) fn dirs() -> (tempfile::TempDir, tempfile::TempDir) {
        (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
    }

    /// The payer's deal follows the legs the settlement trail seals: the
    /// events a live run sees, with the exchange's own record arriving after
    /// the invoices, end in a baseline, a `completed` outcome, a close and a
    /// report that cites those very legs.
    #[test]
    fn the_payers_legs_drive_the_payers_deal() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        for (phase, seg, hash) in [
            (Phase::InputInvoiceIssued, 0, INPUT),
            (Phase::OutputInvoiceIssued, 1, OUTPUT),
        ] {
            pair.payer_event(phase, seg, hash, &[]);
        }
        for (phase, seg, hash) in [
            (Phase::InputSettlementObserved, 0, INPUT),
            (Phase::OutputSettlementObserved, 1, OUTPUT),
        ] {
            pair.payer_event(phase, seg, hash, &[("fee_msat", 0)]);
        }
        let sealed = crate::deal_flow::SealedExchange {
            capsule_id: &"e".repeat(64),
            peer: PROVIDER_PEER,
            request_digest: &"d".repeat(64),
            model: "model-x",
        };
        pair.payer
            .deals()
            .on_exchange(&pair.payer, "ex", &sealed, unix_now());
        pair.payer_accounted();
        pair.payer.settlement_legs().on_exchange(
            &pair.payer,
            "ex",
            Some(PROVIDER_PEER),
            Some(RESPONSE),
        );
        let capsules: Vec<Value> = std::fs::read_to_string(a.path().join("ledger/capsules.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let report_id = capsules
            .iter()
            .find(|c| c["action_id"] == "capsulectl-deal-report")
            .expect("a report")["capsule_id"]
            .as_str()
            .unwrap()
            .to_string();
        let journal = std::fs::read_to_string(a.path().join("ledger/deal-payloads.jsonl")).unwrap();
        let line: Value = journal
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .find(|l| l["capsule_id"] == report_id.as_str())
            .unwrap();
        assert_eq!(line["payload"]["report"]["lifecycle"]["state"], "closed");
        let leg_ids: Vec<&str> = capsules
            .iter()
            .filter(|c| c.get("settlement").is_some())
            .map(|c| c["capsule_id"].as_str().unwrap())
            .collect();
        let cited: Vec<&str> = line["payload"]["report"]["did"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|d| d["steps"].as_array().unwrap())
            .filter_map(Value::as_str)
            .collect();
        for leg in &leg_ids {
            assert!(cited.contains(leg), "the report cites {leg}");
        }
        let outcome = journal
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .find(|l| l["record_type"] == "outcome")
            .unwrap();
        assert_eq!(outcome["payload"]["body"]["outcome"], "completed");
    }

    /// The provider notes a payment for its exchange before it seals the leg;
    /// when the note cannot be written no leg is sealed, so the ledger and the
    /// provider's receipt never disagree about which payments were received.
    #[test]
    fn a_payment_that_cannot_be_noted_seals_no_leg() {
        let (a, b) = dirs();
        // A directory where the notes file goes: appending to it fails.
        std::fs::create_dir_all(
            b.path()
                .join("ledger")
                .join(crate::provider_receipt::PROVIDER_LINKS_FILE),
        )
        .unwrap();
        let (_payer, provider) = two_nodes(a.path(), b.path(), WALLET);
        assert!(
            kinds(&provider).is_empty(),
            "no payee_observed leg was sealed"
        );
    }

    #[test]
    fn a_paid_exchange_yields_both_sides_legs() {
        let (a, b) = dirs();
        let (payer, provider) = two_nodes(a.path(), b.path(), WALLET);
        assert_eq!(
            kinds(&payer),
            [
                "terms",
                "terms",
                "payer_observed",
                "payer_observed",
                "delivered"
            ]
        );
        assert_eq!(kinds(&provider), ["payee_observed", "payee_observed"]);
        let terms: Vec<&str> = payer[..2]
            .iter()
            .map(|c| c["capsule_id"].as_str().unwrap())
            .collect();
        for leg in provider.iter().chain(&payer[2..4]) {
            assert!(terms.contains(&leg["settlement"]["terms_ref"].as_str().unwrap()));
        }
        assert_eq!(provider[0]["settlement"]["received"]["value"], json!("995"));
        assert_eq!(
            provider[0]["settlement"]["receive_fee"]["value"],
            json!("5")
        );
        assert_eq!(payer[2]["settlement"]["routing_fee"]["value"], json!("0"));
        assert_eq!(
            payer[4]["settlement"]["terms_ref"],
            json!(terms[1]),
            "delivery cites the output invoice"
        );
        assert_eq!(
            payer[4]["settlement"]["delivery"]["content_digest"],
            json!(RESPONSE)
        );
        assert_eq!(payer[0]["settlement"]["sealer_role"], json!("payer"));
    }

    #[test]
    fn a_host_without_wallet_amounts_gets_no_payee_leg() {
        let (a, b) = dirs();
        let (payer, provider) = two_nodes(a.path(), b.path(), &[]);
        assert!(provider.is_empty());
        assert_eq!(payer.len(), 5);
    }

    #[test]
    fn a_terms_leg_that_arrives_first_is_cited_when_the_wallet_reports() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        pair.provider_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.payer
            .settlement_legs()
            .on_exchange(&pair.payer, "ex", Some(PROVIDER_PEER), None);
        let pushes = pair.payer_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        assert_eq!(pushes.len(), 1, "the peer was known: pushed at once");
        pair.deliver(&pushes);
        assert!(legs_of(b.path()).is_empty());
        pair.provider_event(Phase::InputSettlementObserved, 0, INPUT, WALLET);
        let provider = legs_of(b.path());
        assert_eq!(kinds(&provider), ["payee_observed"]);
        assert_eq!(
            provider[0]["settlement"]["terms_ref"],
            pushes[0].capsule["capsule_id"]
        );
    }

    #[test]
    fn the_provider_cites_only_a_payers_terms_leg_for_its_own_invoice_at_its_amount() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        pair.provider_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.provider_event(Phase::InputSettlementObserved, 0, INPUT, WALLET);
        let forged = |amount_msat: u64, role: &str, hash: &str| {
            let member = build_leg(
                "terms",
                role,
                [("amount", msat(amount_msat)), ("payment_ref", ln(hash))]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            )
            .unwrap();
            // signed by a fresh key each time, like any peer could
            let key = ed25519_dalek::SigningKey::from_bytes(
                &[amount_msat as u8 ^ hash.as_bytes()[0]; 32],
            );
            crate::producer::capsule::seal_settlement_leg(
                format!("t/{amount_msat}/{role}/{hash}"),
                member,
                Map::new(),
                None,
                None,
                &key,
            )
            .unwrap()
        };
        let legs = pair.provider.settlement_legs();
        legs.on_received(&pair.provider, &forged(1, "payer", INPUT));
        legs.on_received(&pair.provider, &forged(1000, "payer", OUTPUT));
        assert!(
            legs_of(b.path()).is_empty(),
            "a wrong amount, or an invoice not issued here, is never cited"
        );
        let genuine = forged(1000, "payer", INPUT);
        legs.on_received(&pair.provider, &genuine);
        let provider = legs_of(b.path());
        assert_eq!(provider.len(), 1);
        assert_eq!(
            provider[0]["settlement"]["terms_ref"],
            genuine["capsule_id"]
        );
        // a later, different terms leg for the same invoice changes nothing
        let mut later = genuine.clone();
        later["capsule_id"] = json!("f".repeat(64));
        legs.on_received(&pair.provider, &later);
        assert_eq!(
            legs.inner().received_terms.get(INPUT),
            genuine["capsule_id"].as_str().map(String::from).as_ref()
        );
    }

    #[test]
    fn a_push_that_failed_is_retried() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        pair.payer
            .settlement_legs()
            .on_exchange(&pair.payer, "ex", Some(PROVIDER_PEER), None);
        let pushes = pair.payer_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        assert!(pair.payer.settlement_legs().retry().is_empty());
        pair.payer.settlement_legs().requeue(&pushes[0]);
        let again = pair.payer.settlement_legs().retry();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].capsule, pushes[0].capsule);
        assert!(
            pair.payer.settlement_legs().retry().is_empty(),
            "taken once"
        );
    }

    #[test]
    fn an_exchanges_entries_are_cleared_once_its_delivery_is_sealed() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        let legs = pair.payer.settlement_legs();
        pair.payer_event(Phase::OutputInvoiceIssued, 1, OUTPUT, &[]);
        pair.payer_accounted();
        legs.on_exchange(&pair.payer, "ex", Some(PROVIDER_PEER), Some(RESPONSE));
        assert_eq!(kinds(&legs_of(a.path())), ["terms", "delivered"]);
        let [_, cited_hash, accounted, peer, unpushed, response, ..] = legs.held();
        assert_eq!(
            (cited_hash, accounted, peer, unpushed, response),
            (0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn a_deposit_that_covers_the_bill_gets_a_delivered_leg_once_accounted() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        let legs = pair.payer.settlement_legs();
        pair.payer_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.payer_event(Phase::InputSettlementObserved, 0, INPUT, &[("fee_msat", 0)]);
        legs.on_exchange(&pair.payer, "ex", Some(PROVIDER_PEER), Some(RESPONSE));
        assert_eq!(
            kinds(&legs_of(a.path())),
            ["terms", "payer_observed"],
            "a final invoice may still come"
        );
        pair.payer_accounted();
        let payer = legs_of(a.path());
        assert_eq!(kinds(&payer), ["terms", "payer_observed", "delivered"]);
        assert_eq!(
            payer[2]["settlement"]["terms_ref"], payer[0]["capsule_id"],
            "delivery cites the deposit"
        );
        assert_eq!(
            payer[2]["settlement"]["delivery"]["content_digest"],
            json!(RESPONSE)
        );
        let [_, cited_hash, accounted, _, _, response, ..] = legs.held();
        assert_eq!((cited_hash, accounted, response), (0, 0, 0));
    }

    /// Since token metering the host issues no final invoice when the
    /// deposit covers the bill. Both sides still seal: the payer its terms,
    /// payer_observed and delivered legs, the provider its payee_observed leg
    /// citing the payer's deposit terms leg, whether the exchange event
    /// naming the provider comes before or after the accounted bill, and
    /// whether the bill equals the deposit or is below it.
    #[test]
    fn a_deposit_that_covers_the_bill_seals_both_sides() {
        for (exchange_first, bill_msat) in [(false, 1000), (true, 1000), (false, 600), (true, 600)]
        {
            let (a, b) = dirs();
            let pair = Pair::open(a.path(), b.path());
            pair.provider_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
            pair.payer_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
            pair.provider_event(Phase::InputSettlementObserved, 0, INPUT, WALLET);
            pair.payer_event(Phase::InputSettlementObserved, 0, INPUT, &[("fee_msat", 0)]);
            let exchange = || {
                pair.payer.settlement_legs().on_exchange(
                    &pair.payer,
                    "ex",
                    Some(PROVIDER_PEER),
                    Some(RESPONSE),
                )
            };
            let accounted = || {
                pair.payer
                    .settlement_legs()
                    .on_lifecycle(&pair.payer, &accounted_bill("ex", bill_msat))
            };
            let pushes = if exchange_first {
                let pushes = exchange();
                accounted();
                pushes
            } else {
                accounted();
                exchange()
            };
            assert_eq!(pushes.len(), 1, "only the deposit's terms leg is pushed");
            pair.deliver(&pushes);

            let (payer, provider) = (legs_of(a.path()), legs_of(b.path()));
            assert_eq!(
                kinds(&payer),
                ["terms", "payer_observed", "delivered"],
                "exchange first: {exchange_first}, bill: {bill_msat}"
            );
            assert_eq!(kinds(&provider), ["payee_observed"]);
            let deposit_terms = &payer[0]["capsule_id"];
            assert_eq!(&pushes[0].capsule["capsule_id"], deposit_terms);
            for leg in [&payer[1], &payer[2], &provider[0]] {
                assert_eq!(&leg["settlement"]["terms_ref"], deposit_terms);
            }
            assert_eq!(
                payer[2]["settlement"]["delivery"]["content_digest"],
                json!(RESPONSE)
            );
            assert_eq!(provider[0]["settlement"]["received"]["value"], json!("995"));
            assert_eq!(provider[0]["settlement"]["sealer_role"], json!("payee"));
            let [_, cited_hash, accounted, _, _, response, ..] =
                pair.payer.settlement_legs().held();
            assert_eq!((cited_hash, accounted, response), (0, 0, 0));
        }
    }

    /// The host drops a lifecycle event it cannot deliver in time, so the
    /// final invoice's event can be lost while the deposit's and the
    /// accounted bill arrive. A bill above the deposit was not covered by
    /// it, so the deposit is not cited.
    #[test]
    fn a_bill_above_the_deposit_with_its_final_invoice_lost_gets_no_delivered_leg() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        let legs = pair.payer.settlement_legs();
        pair.payer_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.payer_event(Phase::InputSettlementObserved, 0, INPUT, &[("fee_msat", 0)]);
        legs.on_exchange(&pair.payer, "ex", Some(PROVIDER_PEER), Some(RESPONSE));
        legs.on_lifecycle(&pair.payer, &accounted_bill("ex", 1500));
        assert_eq!(kinds(&legs_of(a.path())), ["terms", "payer_observed"]);
        let [_, cited_hash, accounted, _, _, response, ..] = legs.held();
        assert_eq!(
            (cited_hash, accounted, response),
            (0, 0, 0),
            "the exchange's entries are cleared"
        );
    }

    #[test]
    fn a_final_invoice_whose_terms_leg_is_not_sealed_is_never_replaced_by_the_deposit() {
        let dir = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(dir.path(), "payer-node").unwrap();
        let payer = |legs: &Legs, phase, seg, hash| {
            legs.on_lifecycle(&state, &event("payer", "ex", phase, seg, hash, 1000, &[]));
        };
        // The final invoice's terms leg is already in the ledger (sealed
        // before a restart), so sealing it again seals nothing.
        payer(&Legs::default(), Phase::OutputInvoiceIssued, 1, OUTPUT);
        let legs = Legs::default();
        payer(&legs, Phase::InputInvoiceIssued, 0, INPUT);
        payer(&legs, Phase::OutputInvoiceIssued, 1, OUTPUT);
        legs.on_lifecycle(&state, &accounted("ex"));
        legs.on_exchange(&state, "ex", Some(PROVIDER_PEER), Some(RESPONSE));
        assert_eq!(kinds(&legs_of(dir.path())), ["terms", "terms"]);
    }

    #[test]
    fn an_exchange_with_no_invoice_gets_no_delivered_leg() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        let legs = pair.payer.settlement_legs();
        pair.payer_accounted();
        legs.on_exchange(&pair.payer, "ex", Some(PROVIDER_PEER), Some(RESPONSE));
        assert!(legs_of(a.path()).is_empty());
        assert_eq!(legs.held(), [0; 12], "the exchange's entries are cleared");
    }

    #[test]
    fn entries_older_than_the_time_bound_are_dropped() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        pair.payer_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.provider_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.provider_event(Phase::InputSettlementObserved, 0, INPUT, WALLET);
        let (payer, provider) = (
            pair.payer.settlement_legs(),
            pair.provider.settlement_legs(),
        );
        payer.expire(Instant::now());
        assert_ne!(payer.held(), [0; 12], "fresh entries stay");
        let later = Instant::now() + MAX_AGE + Duration::from_secs(1);
        payer.expire(later);
        provider.expire(later);
        assert_eq!(payer.held(), [0; 12]);
        assert_eq!(provider.held(), [0; 12]);
        assert!(payer.retry().is_empty());
    }

    #[test]
    fn a_repeated_event_seals_nothing_more() {
        let dir = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(dir.path(), "payer-node").unwrap();
        let invoice = event("payer", "x", Phase::InputInvoiceIssued, 0, INPUT, 1000, &[]);
        state.settlement_legs().on_lifecycle(&state, &invoice);
        state.settlement_legs().on_lifecycle(&state, &invoice);
        assert_eq!(legs_of(dir.path()).len(), 1);
    }

    #[test]
    fn waiting_entries_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let state = CapsuleState::open(dir.path(), "provider-node").unwrap();
        let legs = Legs::default();
        for i in 0..(MAX_HELD + 10) {
            let hash = format!("{i:064x}");
            legs.on_lifecycle(
                &state,
                &event(
                    "provider",
                    "p",
                    Phase::InputInvoiceIssued,
                    0,
                    &hash,
                    1000,
                    &[],
                ),
            );
            legs.on_lifecycle(
                &state,
                &event(
                    "provider",
                    "p",
                    Phase::InputSettlementObserved,
                    0,
                    &hash,
                    1000,
                    WALLET,
                ),
            );
        }
        let [.., invoices, _, waiting, _, _, _] = legs.held();
        assert_eq!((invoices, waiting), (MAX_HELD, MAX_HELD));
    }

    /// `requester` and `provider` agree a session for `model` at `now` (the
    /// agreement bridge in process); the acceptance digest.
    fn agree(requester: &CapsuleState, provider: &CapsuleState, model: &str, now: i64) -> String {
        use crate::agreement::{Proposal, SessionTerms, Store};
        use crate::agreement_bridge::{conclude, respond, Outcome};
        let (rstore, pstore) = (
            Store::open(requester.ledger_dir()),
            Store::open(provider.ledger_dir()),
        );
        let proposal = Proposal::new(
            requester.signing_key(),
            &hex::encode(provider.public_key()),
            &crate::agreement::new_session_id(),
            &SessionTerms {
                spend_cap_msat: 3_000,
                max_exchanges: None,
                window_seconds: 3_600,
            },
            &[model.to_string()],
            now,
        );
        let reply = respond(provider, &pstore, &proposal.to_message(), &|_| true, now);
        let Outcome::Accepted { session, receipt } = conclude(
            requester,
            &rstore,
            &proposal,
            &serde_json::to_vec(&reply).unwrap(),
            now,
        ) else {
            panic!("accepted: {reply}")
        };
        let frame = serde_json::to_vec(&json!({ "receipt": receipt })).unwrap();
        assert_eq!(
            respond(provider, &pstore, &frame, &|_| true, now),
            json!({"ok": true})
        );
        session.acceptance_digest
    }

    fn citation(leg: &Value) -> Option<&str> {
        leg["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["acceptance"]["target"]
            .as_str()
    }

    /// Which sessions the payer and provider hold when the exchange runs.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Sessions {
        /// One, for the model served.
        One,
        /// Two at once, both for the model served.
        TwoForTheModel,
        /// One, for another model only.
        OtherModelOnly,
    }

    const SERVED_MODEL: &str = "hf:example/model@main";

    /// Two nodes that hold `sessions`, then one paid exchange whose deposit
    /// covers the bill, run as a live host orders the events: the payer's
    /// and the provider's legs, and the acceptance the payer's session for
    /// the served model has (if any).
    fn agreed_exchange(
        sessions: Sessions,
        a: &Path,
        b: &Path,
    ) -> (Vec<Value>, Vec<Value>, Option<String>) {
        let pair = Pair::open(a, b);
        let now = chrono::Utc::now().timestamp();
        let tag = sessions as u64 + 1;
        let (payer_peer, provider_peer) = (
            format!("{:064x}", 0xa11ce0 + tag),
            format!("{:064x}", 0xb0b0 + tag),
        );
        crate::peer_keys::announced::announce_for_test(
            &payer_peer,
            &hex::encode(pair.payer.public_key()),
        );
        crate::peer_keys::announced::announce_for_test(
            &provider_peer,
            &hex::encode(pair.provider.public_key()),
        );
        let digest = match sessions {
            Sessions::One => Some(agree(&pair.payer, &pair.provider, SERVED_MODEL, now)),
            Sessions::TwoForTheModel => {
                agree(&pair.payer, &pair.provider, SERVED_MODEL, now - 60);
                Some(agree(&pair.payer, &pair.provider, SERVED_MODEL, now))
            }
            Sessions::OtherModelOnly => {
                agree(&pair.payer, &pair.provider, "hf:other/model@main", now);
                None
            }
        };
        pair.provider_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.payer_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.provider_event(Phase::InputSettlementObserved, 0, INPUT, WALLET);
        pair.payer_event(Phase::InputSettlementObserved, 0, INPUT, &[("fee_msat", 0)]);
        pair.payer_accounted();
        // The terminal events: the provider notes the model it served; the
        // payer decides the exchange's citation (main.rs does both).
        pair.provider
            .settlement_legs()
            .decide_served_citation("p-ex", || {
                crate::agreement_bridge::served_citation(
                    &pair.provider,
                    &payer_peer,
                    &[SERVED_MODEL.into()],
                    now,
                )
            });
        pair.payer.settlement_legs().decide_citation("ex", || {
            crate::agreement_bridge::delivered_citation(
                &pair.payer,
                &provider_peer,
                SERVED_MODEL,
                now,
            )
        });
        let pushes = pair.payer.settlement_legs().on_exchange(
            &pair.payer,
            "ex",
            Some(&provider_peer),
            Some(RESPONSE),
        );
        for push in &pushes {
            pair.provider
                .settlement_legs()
                .on_received(&pair.provider, &push.capsule);
        }
        // The delivered leg is sealed (the bill was accounted first) and the
        // decision is still there for the requested half, sealed after it.
        assert_eq!(
            pair.payer.settlement_legs().citation_of("ex"),
            Some(digest.clone()),
            "the requested half still reads the decision"
        );
        (legs_of(a), legs_of(b), digest)
    }

    /// A payee leg sealed late (its terms leg's push failed, a session was
    /// set up, the retry arrived) takes the decision made when the exchange
    /// was served, so it never cites the session that appeared later.
    #[test]
    fn a_late_payee_leg_never_cites_a_session_set_up_after_its_exchange() {
        let (a, b) = dirs();
        let pair = Pair::open(a.path(), b.path());
        let now = chrono::Utc::now().timestamp();
        let payer_peer = format!("{:064x}", 0x1a7e);
        crate::peer_keys::announced::announce_for_test(
            &payer_peer,
            &hex::encode(pair.payer.public_key()),
        );
        pair.provider_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.provider_event(Phase::InputSettlementObserved, 0, INPUT, WALLET);
        // Served, with no session yet: the decision is "none".
        let decided = pair
            .provider
            .settlement_legs()
            .decide_served_citation("p-ex", || {
                crate::agreement_bridge::served_citation(
                    &pair.provider,
                    &payer_peer,
                    &[SERVED_MODEL.into()],
                    now,
                )
            });
        assert_eq!(decided, None);
        // The requester sets up a session from that exchange...
        agree(&pair.payer, &pair.provider, SERVED_MODEL, now);
        // ...then its terms leg arrives late.
        pair.payer
            .settlement_legs()
            .on_exchange(&pair.payer, "ex", Some(PROVIDER_PEER), None);
        let pushes = pair.payer_event(Phase::InputInvoiceIssued, 0, INPUT, &[]);
        pair.deliver(&pushes);
        let provider = legs_of(b.path());
        assert_eq!(kinds(&provider), ["payee_observed"]);
        assert_eq!(citation(&provider[0]), None);
    }

    /// An exchange's citation is decided once: a session that appears later
    /// (set up from this very exchange) never changes it, and the delivered
    /// leg uses the decision.
    #[test]
    fn an_exchange_cites_what_was_decided_before_any_session_was_set_up() {
        let legs = Legs::default();
        assert_eq!(legs.citation_of("ex"), None, "not decided yet");
        assert_eq!(legs.decide_citation("ex", || None), None);
        assert_eq!(
            legs.decide_citation("ex", || Some("ab".repeat(32))),
            None,
            "the first decision stands"
        );
        assert_eq!(legs.citation_of("ex"), Some(None));
        assert_eq!(
            legs.decide_citation("other", || Some("cd".repeat(32))),
            Some("cd".repeat(32))
        );
    }

    /// Under an agreement, the payer's delivered leg and the provider's
    /// payee_observed leg cite it (R12); the payer's terms and payer_observed
    /// legs, sealed before the provider is known, cite nothing. The payee
    /// leg cites only the one session for the model served: with two for it,
    /// or one for another model only, it cites nothing rather than guess.
    #[test]
    fn under_an_agreement_one_leg_per_side_cites_it() {
        for sessions in [
            Sessions::One,
            Sessions::TwoForTheModel,
            Sessions::OtherModelOnly,
        ] {
            let (a, b) = dirs();
            let (payer, provider, digest) = agreed_exchange(sessions, a.path(), b.path());
            assert_eq!(
                kinds(&payer),
                ["terms", "payer_observed", "delivered"],
                "{sessions:?}"
            );
            assert_eq!(kinds(&provider), ["payee_observed"], "{sessions:?}");
            assert_eq!(
                citation(&payer[0]),
                None,
                "terms: sealed before the provider is known"
            );
            assert_eq!(citation(&payer[1]), None, "payer_observed: likewise");
            assert_eq!(
                citation(&payer[2]),
                digest.as_deref(),
                "delivered, {sessions:?}"
            );
            let payee = if sessions == Sessions::One {
                digest.as_deref()
            } else {
                None
            };
            assert_eq!(
                citation(&provider[0]),
                payee,
                "payee_observed, {sessions:?}"
            );
        }
    }

    /// The legs [`agreed_exchange`] seals under one session, as the plugin
    /// seals them (node keys, chained, the real acceptance digest), written
    /// to `$AGREEMENT_LEGS_OUT` for the reference verifiers: the R5
    /// seal-and-verify gate of evidencebook#48 PR 4.
    #[test]
    #[ignore]
    fn cited_legs_for_the_reference_verifiers() {
        let Ok(out) = std::env::var("AGREEMENT_LEGS_OUT") else {
            panic!("AGREEMENT_LEGS_OUT not set (this test is run on purpose, so fail loudly)");
        };
        let (a, b) = dirs();
        let (payer, provider, digest) = agreed_exchange(Sessions::One, a.path(), b.path());
        assert!(
            digest.is_some() && citation(&payer[2]).is_some() && citation(&provider[0]).is_some()
        );
        let all: Vec<Value> = payer.into_iter().chain(provider).collect();
        std::fs::write(out, serde_json::to_vec(&all).unwrap()).unwrap();
    }

    /// Both nodes' legs, checked by the Python reference verifier:
    /// AAC_PYTHON=python3 AAC_SETTLEMENT_VERIFY_SCRIPT=<capsule-emit>/rust/capsule-emit/tests/scripts/verify_rust_settlement.py
    #[test]
    #[ignore]
    fn the_reference_derives_agreed_for_both_invoices() {
        let (Ok(python), Ok(script)) = (
            std::env::var("AAC_PYTHON"),
            std::env::var("AAC_SETTLEMENT_VERIFY_SCRIPT"),
        ) else {
            panic!("AAC_PYTHON / AAC_SETTLEMENT_VERIFY_SCRIPT not set (this test is run on purpose, so fail loudly)");
        };
        let (a, b) = dirs();
        let (payer, provider) = two_nodes(a.path(), b.path(), WALLET);
        let all: Vec<Value> = payer.into_iter().chain(provider).collect();
        let path = a.path().join("legs.json");
        std::fs::write(&path, serde_json::to_vec(&all).unwrap()).unwrap();
        let out = std::process::Command::new(python)
            .arg(script)
            .arg(&path)
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&out.stdout).expect("one JSON line");
        eprintln!("{report}");
        assert_eq!(report["conforming"], json!(true));
        let field = |name: &str| -> Vec<String> {
            report["settlements"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s[name].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(field("payment_state"), ["agreed", "agreed"]);
        assert_eq!(
            field("delivery_state"),
            ["none", "stated"],
            "only the payer's delivered leg is sealed yet"
        );
    }
}
