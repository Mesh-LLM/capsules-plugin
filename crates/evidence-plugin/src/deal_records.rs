//! The payer's `x-deal-v0` deal for a paid exchange, as records
//! (Mesh-LLM/capsules-plugin#96): the baseline, the outcome and the close,
//! and the sealed report that reads them. Pure: nothing here touches the
//! ledger or the clock. [`crate::deal_flow`] decides when each is sealed and
//! seals it.
//!
//! A deal's records are built as JSON and passed through
//! `evidencebook::deal::encode`, which refuses a record the profile's
//! schema, personal-data, wording or canonicalization stage would refuse, so
//! nothing malformed reaches the ledger. The Capsule a record is sealed in is
//! the one `evidencebook::deal::step_capsule` states, built by
//! `capsule_emit::produce::build` (Go-identical bytes, capsule-emit#383).

use capsule_emit_lib::produce;
use chrono::{DateTime, Utc};
use evidencebook::deal;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The record header's `channel`: a Mesh inference exchange.
pub const CHANNEL: &str = "org.mesh.inference";
/// The settlement rail `recourse` names.
pub const RAIL: &str = "lightning";
/// The `deal_type` of a paid inference exchange.
pub const DEAL_TYPE: &str = "service";

/// Why a record could not be built or sealed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Deal(#[from] deal::Error),
    #[error("{0}")]
    Produce(#[from] produce::ProduceError),
    #[error("{0}")]
    Invalid(String),
}

/// A step encoded and checked: its payload (the JCS bytes the Capsule
/// commits), its digest and the record's `at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub record_type: &'static str,
    pub payload: Vec<u8>,
    pub digest: String,
    pub at: String,
}

/// What every step of one deal shares.
#[derive(Clone, Debug)]
pub struct Deal {
    pub deal_id: String,
    /// `deal_key(store_secret, deal_id)`: the counterparty fingerprints' key.
    pub key: [u8; 32],
    /// The raw values the personal-data stage scans every record for: the
    /// peer's node id and the committed texts.
    pub local_values: Vec<String>,
}

fn digest_ref(digest: &str) -> Value {
    json!({"type": deal::RECORD_REF, "digest_alg": "SHA-256", "digest": digest})
}

fn block(deal_id: &str, record_type: &str, seq: i64, at: &str) -> Map<String, Value> {
    let mut b = Map::new();
    b.insert("profile".into(), json!(deal::PROFILE));
    b.insert("canonicalization".into(), json!(deal::CANONICALIZATION));
    b.insert("deal_id".into(), json!(deal_id));
    b.insert("record_type".into(), json!(record_type));
    b.insert("seq".into(), json!(seq));
    b.insert("at".into(), json!(at));
    b
}

/// The `at` of a record: `unix` seconds as RFC 3339 UTC, to the second.
pub fn at(unix: i64) -> String {
    DateTime::<Utc>::from_timestamp(unix, 0)
        .expect("a clock time")
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Where a step stands in its deal: the step before it, and the deal's
/// baseline once there is one.
#[derive(Clone, Debug)]
pub struct After {
    pub seq: i64,
    pub prev: String,
    pub baseline: String,
}

impl Deal {
    fn encode(&self, record_type: &'static str, at: &str, record: Value) -> Result<Encoded, Error> {
        let bytes = serde_json::to_vec(&record).map_err(|e| Error::Invalid(e.to_string()))?;
        let local: Vec<&str> = self.local_values.iter().map(String::as_str).collect();
        let (payload, digest) = deal::encode(&bytes, &local)?;
        Ok(Encoded {
            record_type,
            payload,
            digest,
            at: at.to_string(),
        })
    }

    /// The baseline: what was asked (a request, known by its digest and the
    /// model it named, committed under `nonce`), of whom (the serving peer,
    /// fingerprinted), and the way back (a Lightning payment, not
    /// refundable). No price: an invoice's amount is msat, which the profile
    /// has no unit for.
    pub fn baseline(
        &self,
        at: &str,
        peer: &str,
        nonce: &str,
        asked_text: &str,
        model: &str,
    ) -> Result<Encoded, Error> {
        let ids = |kinds: &[&str]| -> Result<Value, Error> {
            let mut m = Map::new();
            for kind in kinds {
                let fp = deal::fingerprint(&self.key, kind, peer)
                    .map_err(|_| Error::Invalid(format!("the peer is not a {kind}")))?;
                m.insert((*kind).into(), json!(fp));
            }
            Ok(Value::Object(m))
        };
        let mut b = block(&self.deal_id, deal::TYPE_BASELINE, 1, at);
        b.insert("channel".into(), json!(CHANNEL));
        b.insert(
            "counterparty".into(),
            json!({"fp_alg": deal::FP_ALG, "ids": ids(&["payee", "profile_id"])?}),
        );
        b.insert("commit_alg".into(), json!(deal::COMMIT_ALG));
        let record = json!({
            "x-deal-v0": b,
            "body": {
                "deal_type": DEAL_TYPE,
                "intent": {
                    "verbatim_commitment": deal::commit_text(nonce, asked_text),
                    "asked": {"item": model},
                },
                "terms": {"item": model},
                "recourse": {"rail": RAIL, "refundable": false},
            },
        });
        self.encode(deal::TYPE_BASELINE, at, record)
    }

    fn after(
        &self,
        record_type: &'static str,
        at: &str,
        after: &After,
        refs: Option<Value>,
        body: Value,
    ) -> Result<Encoded, Error> {
        let mut b = block(&self.deal_id, record_type, after.seq, at);
        b.insert("prev".into(), digest_ref(&after.prev));
        b.insert("baseline_ref".into(), digest_ref(&after.baseline));
        if let Some(refs) = refs {
            b.insert("refs".into(), refs);
        }
        self.encode(record_type, at, json!({"x-deal-v0": b, "body": body}))
    }

    /// What was observed: the bill paid and the response received
    /// (`completed`), or an invoice issued whose settlement this node did not
    /// see (`open`: the deal's record is not final).
    pub fn outcome(&self, at: &str, after: &After, settled: bool) -> Result<Encoded, Error> {
        let (status, outcome) = if settled {
            ("received", "completed")
        } else {
            ("pending", "open")
        };
        self.after(
            deal::TYPE_OUTCOME,
            at,
            after,
            None,
            json!({"status": status, "outcome": outcome, "differences": []}),
        )
    }

    /// The close, its outcome equal to the outcome's. `open` pauses the
    /// deal's record (a later outcome and close may follow, PROFILE rule 7).
    pub fn close(&self, at: &str, after: &After, settled: bool) -> Result<Encoded, Error> {
        let outcome = if settled { "completed" } else { "open" };
        self.after(
            deal::TYPE_CLOSE,
            at,
            after,
            // The close rests on the outcome just before it.
            Some(json!([{
                "rel": "outcome", "type": deal::RECORD_REF, "digest_alg": "SHA-256",
                "digest": after.prev,
            }])),
            json!({"outcome": outcome, "unchecked_actions": 0}),
        )
    }
}

/// The Capsule `step` is sealed in, signature-free, chained to `parent` (the
/// ledger's head when there is one): built by `produce::build` from the
/// members `deal::step_capsule` states, committing the payload's digest as
/// the agent input.
pub fn step_capsule(
    deal_id: &str,
    seq: i64,
    step: &Encoded,
    parent: Option<&str>,
    operator: &str,
    developer: &str,
    unix: i64,
) -> Result<produce::BuiltPayload, Error> {
    let input = deal::StepInput {
        deal_id: deal_id.into(),
        seq,
        operator: operator.into(),
        developer: developer.into(),
        at: unix,
        parent: parent.map(|p| deal::Chain {
            parent_capsule_id: p.into(),
            relation: deal::RELATION_FOLLOWS.into(),
        }),
        settlement: None,
        decide: None,
        local: String::new(),
        amount: String::new(),
        currency: String::new(),
    };
    let (capsule, _) = deal::step_capsule(&input)?;
    build(&capsule, &step.digest)
}

/// The report's Capsule: not a step, not chained to a deal step.
pub fn report_capsule(
    payload: &[u8],
    parent: Option<&str>,
    operator: &str,
    developer: &str,
    unix: i64,
) -> Result<produce::BuiltPayload, Error> {
    let mut capsule = deal::report_capsule(operator, developer, unix)?;
    capsule.chain = parent.map(|p| deal::Chain {
        parent_capsule_id: p.into(),
        relation: deal::RELATION_FOLLOWS.into(),
    });
    let digest = hex::encode(Sha256::digest(payload));
    build(&capsule, &digest)
}

/// `produce::build` over a deal Capsule's members, as capsule-emit's own
/// parity test does for Go's frozen Capsules.
fn build(
    capsule: &deal::Capsule,
    agent_input_digest: &str,
) -> Result<produce::BuiltPayload, Error> {
    let timestamp = DateTime::parse_from_rfc3339(&capsule.timestamp)
        .map_err(|e| Error::Invalid(e.to_string()))?
        .with_timezone(&Utc);
    let input = produce::Input {
        action_id: capsule.action_id.clone(),
        action_type: capsule.action_type.clone(),
        operator: capsule.operator.clone(),
        developer: capsule.developer.clone(),
        timestamp: Some(timestamp),
        chain: capsule.chain.as_ref().map(|c| produce::Chain {
            parent_capsule_id: c.parent_capsule_id.clone(),
            relation: c.relation.clone(),
        }),
        compute: Some(produce::ComputeAttestation {
            agent_input_digest: agent_input_digest.to_string(),
            ..Default::default()
        }),
        extensions: capsule
            .extensions
            .iter()
            .map(|x| {
                Ok(produce::Extension {
                    name: x.name.clone(),
                    value: serde_json::to_vec(&x.value)
                        .map_err(|e| Error::Invalid(e.to_string()))?,
                })
            })
            .collect::<Result<_, Error>>()?,
        ..Default::default()
    };
    if capsule.disposition.is_some() || capsule.effect.is_some() {
        return Err(Error::Invalid("a Mesh deal seals fyi Capsules only".into()));
    }
    Ok(produce::build(input)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7; 32];
    // A mesh node id: 64 lowercase hex.
    const PEER: &str = "9c1f0a2be45d7388a6b0c1d2e3f40516273849a5b6c7d8e9f00112233445566a";

    fn deal() -> Deal {
        let deal_id = "deal-0123456789abcdef0123456789abcdef".to_string();
        Deal {
            key: deal::deal_key(&SECRET, &deal_id),
            deal_id,
            local_values: vec![PEER.into(), "inference request d for m".into()],
        }
    }

    /// Baseline, outcome and close, each passing the record stages, chained
    /// by digest, and sealed in a Capsule that commits the payload.
    pub(super) fn chain(settled: bool) -> Vec<Encoded> {
        let d = deal();
        let nonce = "ab".repeat(32);
        let baseline = d
            .baseline(
                &at(1_790_000_000),
                PEER,
                &nonce,
                "inference request d for m",
                "model-x",
            )
            .unwrap();
        let mut after = After {
            seq: 2,
            prev: baseline.digest.clone(),
            baseline: baseline.digest.clone(),
        };
        let outcome = d.outcome(&at(1_790_000_060), &after, settled).unwrap();
        after.seq = 3;
        after.prev = outcome.digest.clone();
        let close = d.close(&at(1_790_000_061), &after, settled).unwrap();
        vec![baseline, outcome, close]
    }

    #[test]
    fn a_paid_deal_is_three_records_that_pass_the_profile() {
        for settled in [true, false] {
            let chain = chain(settled);
            assert_eq!(
                chain.iter().map(|e| e.record_type).collect::<Vec<_>>(),
                ["baseline", "outcome", "close"]
            );
            for step in &chain {
                deal::check(&step.payload, &[PEER]).unwrap();
                // The raw peer id is nowhere in a record.
                assert!(!String::from_utf8_lossy(&step.payload).contains(PEER));
            }
        }
        assert_ne!(chain(true)[1].digest, chain(false)[1].digest);
    }

    /// Real node ids go through the name rule (casefold, punctuation to
    /// spaces): they stay distinct and non-empty, so two peers never share a
    /// fingerprint and a peer never fingerprints to nothing.
    #[test]
    fn node_ids_fingerprint_distinctly_through_the_name_rule() {
        let d = deal();
        let ids = [
            PEER,
            "9c1f0a2be45d7388a6b0c1d2e3f40516273849a5b6c7d8e9f00112233445566b",
            "node-a_1",
            "node-a_2",
            "node-a-1",
            "NODE-A_1",
        ];
        let mut seen = std::collections::BTreeMap::new();
        for id in ids {
            for kind in ["payee", "profile_id"] {
                let fp = deal::fingerprint(&d.key, kind, id).unwrap();
                assert_eq!(fp.len(), 64);
                if let Some(other) = seen.insert((kind, fp), id) {
                    // The rule folds case and punctuation: only ids that
                    // differ by those alone may meet.
                    assert_eq!(
                        other.to_lowercase().replace('_', "-"),
                        id.to_lowercase().replace('_', "-")
                    );
                }
            }
        }
        // A baseline builds for each of them.
        for id in ids {
            d.baseline(&at(1_790_000_000), id, &"ab".repeat(32), "t", "model-x")
                .unwrap();
        }
    }

    #[test]
    fn a_step_is_sealed_in_a_capsule_that_commits_its_payload() {
        let d = deal();
        let chain = chain(true);
        let mut parent: Option<String> = Some("11".repeat(32));
        for (i, step) in chain.iter().enumerate() {
            let built = step_capsule(
                &d.deal_id,
                i as i64 + 1,
                step,
                parent.as_deref(),
                "op",
                "dev",
                1_790_000_000 + i as i64,
            )
            .unwrap();
            let v = &built.value;
            assert_eq!(v["action_id"], format!("{}/{}", d.deal_id, i + 1));
            assert_eq!(v["deal_id"], d.deal_id);
            assert_eq!(v["action_type"], "fyi");
            assert_eq!(
                v["model_attestation"]["compute_attestation"]["agent_input_digest"],
                step.digest
            );
            assert_eq!(v["chain"]["parent_capsule_id"].as_str(), parent.as_deref());
            parent = Some(built.capsule_id);
        }
    }

    /// The reference checks over the built chains, settled and not: each
    /// record passes x-deal-v0's record checks and the chain passes its §6
    /// rules, with evidencebook's `deal::check` and `deal::check_chain` (the
    /// ports of `check_profile.py`), so they run on every test run.
    #[test]
    fn the_reference_checker_accepts_the_built_chains() {
        for settled in [true, false] {
            let built = chain(settled);
            for e in &built {
                evidencebook::deal::check(&e.payload, &[])
                    .unwrap_or_else(|err| panic!("settled {settled}: {err}"));
            }
            let records: Vec<&[u8]> = built.iter().map(|e| e.payload.as_slice()).collect();
            evidencebook::deal::check_chain(&records)
                .unwrap_or_else(|err| panic!("settled {settled}: {err}"));
        }
    }
}
