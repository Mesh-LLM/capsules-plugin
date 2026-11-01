//! `GET history-page`: what this node answers a stranger who asks for its
//! history, for the Exchanges tab's "Stamped: History page" download.
//!
//! The page that download makes carries the node's answer and nothing else,
//! so it can show no more than the node's disclosure policy sends to that
//! party (Mesh-LLM/capsules-plugin#96, Steven's 10-29 ruling). The answer is
//! asked of this node's own responder in process, exactly as `doctor
//! --probe` does it: an unsigned `history_card/1` request, which is
//! stranger-safe (the same artifact for every requester, no record in it).
//! The reply is not logged as a request made of this node, because nobody
//! made one.
//!
//! With `share_standard_history` on, a stranger may also be given the Service
//! History, so the page carries that instead: the same request the card gets,
//! plus the derivation of the Service History pinned to the latest checkpoint
//! at a period boundary. The page says which form it holds. A node with the
//! switch on but no boundary checkpoint yet gives the card, and says so in
//! `form`.
//!
//! The route answers `{form, outcome, reply, node_key_id}`. `reply` is the
//! reply's wire bytes as text, unchanged, which the page embeds as it got
//! them. `outcome` is `answered` or `refused`; a node that cannot sign an
//! answer (an unreadable ledger or clock) answers a route error instead,
//! never a page of nothing.

use std::sync::Arc;

use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use serde_json::{json, Value};

use crate::capsule_emit::CapsuleState;
use crate::evidence_answer::{self, Outcome};
use crate::evidence_routes::NoArgs;

/// The form of answer the page carries when the node shares only its card.
pub const FORM_HISTORY_CARD: &str = "history_card/1";

/// The form it carries when `share_standard_history` is on: the Service
/// History, which embeds the card byte for byte.
pub const FORM_SERVICE_HISTORY: &str = "service_history/1";

/// This node's answer to a stranger asking for its history card.
pub fn served(capsules: &CapsuleState, node_id: Option<&str>) -> Result<Value, String> {
    let now = evidence_answer::now_utc();
    crate::commitment::with_responder(capsules, &now, node_id, |responder, _| serve(responder))
}

/// The anchor of the latest checkpoint whose time is a period boundary (ISH
/// §6.1 items 2 and 5): the only anchor a Service History is answered for.
fn latest_boundary_anchor(responder: &evidence_answer::Responder<'_>) -> Option<String> {
    crate::evidence_log::with_index(
        responder.ledger_dir,
        &crate::commitment::key_id(responder.signing_key),
        |index| {
            index
                .chain
                .iter()
                .rev()
                .find(|c| {
                    !crate::service_history::Definition::active()
                        .declines_anchor(&c.record.timestamp)
                })
                .map(|c| c.anchor_digest())
        },
    )
    .ok()
    .flatten()
}

/// [`served`], from the responder it would use.
pub(crate) fn serve(responder: &evidence_answer::Responder<'_>) -> Result<Value, String> {
    if responder.share_standard_history {
        if let Some(pin) = latest_boundary_anchor(responder) {
            let request = serde_json::to_vec(&json!({
                "profile": evidence_request::envelope::PROFILE,
                "subject": {"full_history": null},
                "coverage": {"expected_pin": pin},
                "derivation": crate::service_history::definition_digest(),
            }))
            .expect("a JSON value serializes");
            return outcome_json(
                FORM_SERVICE_HISTORY,
                evidence_answer::answer(&request, responder),
                responder,
            );
        }
    }
    let request = crate::doctor::probe_requests()
        .into_iter()
        .find(|(name, _)| *name == crate::doctor::PROBE_HISTORY_CARD)
        .map(|(_, bytes)| bytes)
        .expect("doctor asks for the history card");
    outcome_json(
        FORM_HISTORY_CARD,
        evidence_answer::answer(&request, responder),
        responder,
    )
}

fn outcome_json(
    form: &str,
    outcome: Outcome,
    responder: &evidence_answer::Responder<'_>,
) -> Result<Value, String> {
    let (label, bytes) = match &outcome {
        Outcome::Answered { .. } => ("answered", outcome.wire_bytes()),
        Outcome::Refused { .. } => ("refused", outcome.wire_bytes()),
        Outcome::Unanswerable(why) => return Err(format!("this node cannot answer: {why}")),
    };
    let reply = bytes
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| "the answer could not be written".to_string())?;
    Ok(json!({
        "form": form,
        "outcome": label,
        "reply": reply,
        "node_key_id": crate::commitment::key_id(responder.signing_key),
    }))
}

/// `builder` with the `history-page` route declared.
pub fn with_route(
    builder: DeclarativePluginBuilder,
    capsules: Arc<CapsuleState>,
    self_peer: crate::self_peer::SelfPeer,
) -> DeclarativePluginBuilder {
    builder.http_item(
        http::get("/history-page")
            .binding_id("evidence_history_page")
            .description(
                "What this node answers a stranger who asks for its history, for the Evidence \
                 page's History download.",
            )
            .input::<NoArgs>()
            .handle(move |_args, _context| {
                let capsules = capsules.clone();
                let node_id = self_peer.current();
                Box::pin(async move {
                    tokio::task::spawn_blocking(move || served(&capsules, node_id.as_deref()))
                        .await
                        .map_err(|error| {
                            PluginError::internal(format!(
                                "history page task did not complete: {error}"
                            ))
                        })?
                        .map_err(PluginError::internal)
                })
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_is_the_one_doctor_probes() {
        let (_, request) = crate::doctor::probe_requests()
            .into_iter()
            .find(|(name, _)| *name == crate::doctor::PROBE_HISTORY_CARD)
            .unwrap();
        let request: Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(request["derivation"], FORM_HISTORY_CARD);
        assert!(
            request.get("requester_auth").is_none(),
            "an unsigned request"
        );
    }

    /// A node with no checkpoint yet has no card to give a stranger: it gives
    /// the refusal it signed, as the reply text, never an empty page.
    #[test]
    fn a_node_with_no_checkpoint_serves_its_signed_refusal() {
        let dir = std::env::temp_dir().join(format!("history-page-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let capsules = CapsuleState::open(&dir, "node-under-test").unwrap();
        capsules
            .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("node-a"))
            .unwrap();
        let served = served(&capsules, None).unwrap();
        assert_eq!(served["form"], FORM_HISTORY_CARD);
        assert_eq!(served["outcome"], "refused");
        let reply: Value = serde_json::from_str(served["reply"].as_str().unwrap()).unwrap();
        assert!(reply["reason"].is_string() && reply["sig"].is_string());
        assert_eq!(
            served["node_key_id"],
            crate::commitment::key_id(capsules.signing_key())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The card a node gives a stranger is the answer the page embeds: it
    /// names the node's own key as its responder, which the page shows and
    /// the Evidence page compares with `node_key_id` before saving.
    #[test]
    fn a_node_with_checkpoints_serves_its_card_under_its_own_key() {
        use crate::evidence_request_parity::{corpus_ledger_dir, NODE_KEY_SEED};
        let key = ed25519_dalek::SigningKey::from_bytes(&NODE_KEY_SEED);
        let dir = tempfile::tempdir().unwrap();
        corpus_ledger_dir(dir.path(), &key);
        let announced = std::collections::BTreeMap::new();
        let replay = crate::requester_auth::ReplayCache::default();
        let responder = evidence_answer::Responder {
            ledger_dir: dir.path(),
            signing_key: &key,
            now: "2026-10-28T00:00:00Z",
            history_segments: "none",
            share_standard_history: false,
            share_exchange_corroboration: false,
            keys: crate::requester_auth::Keys {
                announced: &announced,
                configured: None,
                own_key: None,
            },
            replay: &replay,
            node_id: None,
            policy_digest: None,
        };
        let served = serve(&responder).unwrap();
        assert_eq!(served["outcome"], "answered");
        let reply: Value = serde_json::from_str(served["reply"].as_str().unwrap()).unwrap();
        assert_eq!(reply["derivation"], FORM_HISTORY_CARD);
        assert_eq!(reply["responder"], served["node_key_id"]);
        assert_eq!(served["node_key_id"], crate::commitment::key_id(&key));
    }
}
