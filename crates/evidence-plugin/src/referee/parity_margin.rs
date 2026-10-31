//! The referee's split-margin vectors (#155), written in this repository.
//!
//! The copied corpus (`vectors/parity/referee/`, pinned to capsule-emit-mesh)
//! predates the margin rule: none of its answers carries logprobs. The cases
//! here are built from its `service/contradicts_b` case, with logprobs added
//! and every changed record signed again under the corpus's test keys
//! (`parity::test_key`), then run through the referee's service path, so the
//! margin is read from an answer the referee's own signed record covers.
//!
//! `writes_the_split_margin_corpus` (ignored) writes `corpus/split_margin.json`
//! and `rule_answers/split_margin.json`; the parity run then holds the
//! referee to them like any other path. Each case states the ruling the rule
//! requires, and the writer refuses to write an answer that differs from it.

use serde_json::{json, Value};

use super::parity::{referee_dir, test_key, NOW};
use super::verdict::{
    split_margin_threshold, INCONCLUSIVE_SPLIT_MARGIN_UNAVAILABLE, INCONCLUSIVE_SPLIT_WITHIN_MARGIN,
};

/// The logprob every token here is chosen at.
const CHOSEN: f64 = -0.05;
/// A margin far above any threshold: what an answer the request path's
/// simulated referee gives (`parity::run_request`).
pub(crate) const DECISIVE_NATS: f64 = 30.0;

/// One sampled token of `text` whose runner-up (`alt`) is `margin` nats
/// behind it.
fn token(text: &str, margin: f64, alt: &str) -> Value {
    let chosen = json!({"token": text, "logprob": CHOSEN, "bytes": text.as_bytes()});
    let runner_up = json!({"token": alt, "logprob": CHOSEN - margin, "bytes": alt.as_bytes()});
    json!({
        "token": text,
        "logprob": CHOSEN,
        "bytes": text.as_bytes(),
        "top_logprobs": [chosen, runner_up],
    })
}

/// `logprobs.content` for `tokens`, each `(text, margin)`.
fn logprobs(tokens: &[(&str, f64)]) -> Value {
    json!({
        "content": tokens.iter().map(|(t, m)| token(t, *m, "\u{2016}")).collect::<Vec<_>>(),
        "refusal": null,
    })
}

/// An answer body as a server returns it, with `logprobs` when given.
fn answer(text: &str, logprobs: Option<Value>) -> Value {
    let mut choice = json!({"message": {"role": "assistant", "content": text}});
    if let Some(logprobs) = logprobs {
        choice["logprobs"] = logprobs;
    }
    json!({"choices": [choice]})
}

/// The logprobs of an answer the request path's referee gives: one token
/// per character, each [`DECISIVE_NATS`] ahead of its runner-up. That path
/// judges the requester's book, not the referee's margin.
pub(crate) fn decisive_logprobs(text: &str) -> Value {
    let chars: Vec<String> = text.chars().map(String::from).collect();
    let tokens: Vec<(&str, f64)> = chars.iter().map(|c| (c.as_str(), DECISIVE_NATS)).collect();
    logprobs(&tokens)
}

/// The threshold in nats, as the cases state their margins.
fn threshold() -> f64 {
    split_margin_threshold() as f64 / 1_000_000.0
}

/// The referee's answer "1, 2, 3, 4, 5" (twin A's), with `split` nats at its
/// fourth word, " 4": the token where it departs from twin B's "999".
fn counting(split: f64) -> Vec<(&'static str, f64)> {
    vec![
        ("1", DECISIVE_NATS),
        (",", DECISIVE_NATS),
        (" 2", DECISIVE_NATS),
        (",", DECISIVE_NATS),
        (" 3", DECISIVE_NATS),
        (",", DECISIVE_NATS),
        (" 4", split),
        (",", DECISIVE_NATS),
        (" 5", DECISIVE_NATS),
    ]
}

/// One case, as built: the answers and what the rule says of them.
struct Spec {
    name: &'static str,
    covers: &'static str,
    a_text: &'static str,
    b_text: &'static str,
    a_logprobs: Option<Value>,
    b_logprobs: Option<Value>,
    referee_text: &'static str,
    referee_logprobs: Option<Value>,
    /// The ruling the rule requires.
    verdict: &'static str,
    inconclusive_because: Option<&'static str>,
    /// The referee margin sealed, as a decimal string (`None`: `null`).
    referee_margin: Option<String>,
    referee_token_index: Option<u64>,
}

fn decimal(nats: f64) -> String {
    super::margin::decimal(super::margin::micro(nats))
}

fn specs() -> Vec<Spec> {
    let t = threshold();
    let one_micro = 0.000_001;
    let a = "1, 2, 3, 4, 5";
    let b = "1, 2, 3, 999 5";
    let base = |name, covers, split: Option<f64>, verdict, because, margin: Option<f64>| Spec {
        name,
        covers,
        a_text: a,
        b_text: b,
        a_logprobs: None,
        b_logprobs: None,
        referee_text: a,
        referee_logprobs: split.map(|s| logprobs(&counting(s))),
        verdict,
        inconclusive_because: because,
        referee_margin: margin.map(decimal),
        referee_token_index: margin.map(|_| 6),
    };
    vec![
        base(
            "margin_well_above",
            "the referee's margin at the split is far above the threshold: B is contradicted, as before #155",
            Some(3.0 * t),
            "contradicted:node-b",
            None,
            Some(3.0 * t),
        ),
        base(
            "margin_well_below",
            "a near-tie at the split: honest backends could have split there, so no twin is named",
            Some(t / 10.0),
            "inconclusive",
            Some(INCONCLUSIVE_SPLIT_WITHIN_MARGIN),
            Some(t / 10.0),
        ),
        base(
            "margin_exactly_at_the_threshold",
            "a margin equal to the threshold names the twin",
            Some(t),
            "contradicted:node-b",
            None,
            Some(t),
        ),
        base(
            "margin_one_micronat_below",
            "one micro-nat under the threshold is under it",
            Some(t - one_micro),
            "inconclusive",
            Some(INCONCLUSIVE_SPLIT_WITHIN_MARGIN),
            Some(t - one_micro),
        ),
        base(
            "referee_answer_without_logprobs",
            "a referee whose server returned no logprobs (mesh-llm releases without Mesh-LLM/mesh-llm#2565, 0.78.1 and earlier; split serving): no margin, never a charge",
            None,
            "inconclusive",
            Some(INCONCLUSIVE_SPLIT_MARGIN_UNAVAILABLE),
            None,
        ),
        Spec {
            b_logprobs: Some(logprobs(&[
                ("1", DECISIVE_NATS),
                (",", DECISIVE_NATS),
                (" 2", DECISIVE_NATS),
                (",", DECISIVE_NATS),
                (" 3", DECISIVE_NATS),
                (",", DECISIVE_NATS),
                (" 999", 0.001),
                (" 5", DECISIVE_NATS),
            ])),
            a_logprobs: Some(logprobs(&counting(2.0 * t))),
            ..base(
                "twin_claims_a_near_tie",
                "twin B reports a near-tie of its own at the split; the referee's wide margin decides, and both twins' margins are sealed as evidence",
                Some(3.0 * t),
                "contradicted:node-b",
                None,
                Some(3.0 * t),
            )
        },
        Spec {
            a_text: "the deep sea",
            b_text: "the deer sea",
            referee_text: "the deep sea",
            referee_logprobs: Some(logprobs(&[
                ("the", DECISIVE_NATS),
                (" de", t / 10.0),
                ("ep", 3.0 * t),
                (" sea", DECISIVE_NATS),
            ])),
            referee_token_index: Some(2),
            ..base(
                "multi_token_word_departing_token_counts",
                "\"deep\" against \"deer\": the margin is read at \"ep\", where the referee departs, not at the word's first token \" de\" (a near-tie there both twins passed)",
                None,
                "contradicted:node-b",
                None,
                Some(3.0 * t),
            )
        },
        Spec {
            a_text: "the deep sea",
            b_text: "the deer sea",
            referee_text: "the deep sea",
            referee_logprobs: Some(logprobs(&[
                ("the", DECISIVE_NATS),
                (" de", 3.0 * t),
                ("ep", t / 10.0),
                (" sea", DECISIVE_NATS),
            ])),
            referee_token_index: Some(2),
            ..base(
                "multi_token_word_near_tie_at_the_departure",
                "a wide margin at the word's first token does not hide a near-tie at the token where the referee departs",
                None,
                "inconclusive",
                Some(INCONCLUSIVE_SPLIT_WITHIN_MARGIN),
                Some(t / 10.0),
            )
        },
        Spec {
            referee_logprobs: Some(logprobs(&[
                ("<think>", DECISIVE_NATS),
                ("1", DECISIVE_NATS),
                (", 2, 3,", DECISIVE_NATS),
                (" 4", 3.0 * t),
                (", 5", DECISIVE_NATS),
            ])),
            ..base(
                "tokens_do_not_spell_the_answer",
                "logprobs whose tokens do not spell the answer's text (here a reasoning prefix) give no margin",
                None,
                "inconclusive",
                Some(INCONCLUSIVE_SPLIT_MARGIN_UNAVAILABLE),
                None,
            )
        },
        Spec {
            referee_logprobs: Some({
                let mut lp = logprobs(&counting(3.0 * t));
                // At the split the runner-up was the more likely token:
                // something other than greedy decoding chose " 4".
                let top = &mut lp["content"][6]["top_logprobs"];
                let (first, second) = (top[0].clone(), top[1].clone());
                top[0] = json!({"token": second["token"], "logprob": CHOSEN, "bytes": second["bytes"]});
                top[1] = json!({"token": first["token"], "logprob": CHOSEN - 3.0 * t, "bytes": first["bytes"]});
                lp["content"][6]["logprob"] = json!(CHOSEN - 3.0 * t);
                lp
            }),
            ..base(
                "chosen_token_is_not_the_top_one",
                "a split token that was not the most likely one gives no margin",
                None,
                "inconclusive",
                Some(INCONCLUSIVE_SPLIT_MARGIN_UNAVAILABLE),
                None,
            )
        },
    ]
}

/// The template the cases are built from: the copied corpus's
/// `service/contradicts_b`.
fn template() -> Value {
    let corpus = crate::record_push_parity::read_json(&referee_dir().join("corpus/service.json"));
    corpus["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == json!("contradicts_b"))
        .expect("the template case")
        .clone()
}

/// Seal `record` again after a change, under `node`'s corpus key.
fn reseal(record: &mut Value, node: &str) {
    let id = capsule_emit_lib::jcs::compute_capsule_id(record).expect("recompute capsule_id");
    record["capsule_id"] = json!(id);
    capsule_emit_lib::capsule::attach_producer_envelope(record, &test_key(node))
        .expect("sign the record");
}

/// A record that served `body`, signed again.
fn served(mut record: Value, body: &Value, node: &str) -> Value {
    record["effect"]["response_digest"] =
        json!(crate::capsule_emit::digest_json(body).expect("a body digest"));
    reseal(&mut record, node);
    record
}

fn build(spec: &Spec) -> Value {
    let template = template();
    let request: Value =
        serde_json::from_str(template["requests"][0]["body"].as_str().expect("body")).unwrap();
    let mut halves = request["halves"].as_array().expect("halves").clone();
    for (half, (text, logprobs, node)) in halves.iter_mut().zip([
        (spec.a_text, &spec.a_logprobs, "node-a"),
        (spec.b_text, &spec.b_logprobs, "node-b"),
    ]) {
        let body = answer(text, logprobs.clone());
        half["capsule"] = served(half["capsule"].clone(), &body, node);
        half["response_body"] = body;
    }
    let referee_body = answer(spec.referee_text, spec.referee_logprobs.clone());
    let mut node = template["node"].clone();
    let own = node["files"]["capsules.jsonl"][0].clone();
    node["files"]["capsules.jsonl"] = json!([served(own, &referee_body, "node-c")]);
    let mut request = request;
    request["halves"] = json!(halves);
    request["referee_answer"]["response_body"] = referee_body;
    json!({
        "covers": spec.covers,
        "name": spec.name,
        "node": node,
        "requests": [{"body": request.to_string()}],
        "rule": "split_margin (#155)",
    })
}

/// The ruling the answer seals, held to what the case states.
fn check(spec: &Spec, answer: &Value) {
    let block = &answer[0]["appended"]["issued-adjudications.jsonl"][0]["verdict_capsule"]["block"];
    assert_eq!(
        block["verdict"],
        json!(spec.verdict),
        "{}: {answer}",
        spec.name
    );
    assert_eq!(
        block.get("inconclusive_because").and_then(Value::as_str),
        spec.inconclusive_because,
        "{}",
        spec.name
    );
    let margin = &block["split_margin"];
    assert_eq!(margin["unit"], json!("nats"), "{}", spec.name);
    assert_eq!(
        margin["threshold"],
        json!(super::margin::decimal(split_margin_threshold())),
        "{}",
        spec.name
    );
    assert_eq!(
        margin["referee"]["margin"].as_str().map(str::to_string),
        spec.referee_margin,
        "{}",
        spec.name
    );
    assert_eq!(
        margin["referee"]["token_index"].as_u64(),
        spec.referee_token_index,
        "{}",
        spec.name
    );
    assert_eq!(
        margin.get("twin_a").is_some(),
        spec.a_logprobs.is_some(),
        "{}",
        spec.name
    );
    assert_eq!(
        margin.get("twin_b").is_some(),
        spec.b_logprobs.is_some(),
        "{}",
        spec.name
    );
}

#[test]
#[ignore = "writes vectors/parity/referee/{corpus,rule_answers}/split_margin.json"]
fn writes_the_split_margin_corpus() {
    let specs = specs();
    let cases: Vec<Value> = specs.iter().map(build).collect();
    let mut answers = serde_json::Map::new();
    for (spec, case) in specs.iter().zip(&cases) {
        let answer = Value::Array(super::parity::run_service(case));
        check(spec, &answer);
        answers.insert(spec.name.to_string(), answer);
    }
    let corpus = json!({
        "built_with": "this repository: referee::parity_margin::writes_the_split_margin_corpus, from service/contradicts_b under the corpus test keys",
        "note": "The referee's top-2 margin at the split (#155): adjudicate requests to a referee node whose answers carry logprobs. Judged against the rule; there is no reference implementation of it.",
        "now": NOW,
        "path": "split_margin",
        "v": 1,
        "cases": cases,
    });
    let rule_answers = json!({
        "path": "split_margin",
        "source": "rule (#155): stated per case in referee::parity_margin and checked before writing",
        "v": 1,
        "answers": answers,
    });
    let write = |rel: &str, value: &Value| {
        let text = serde_json::to_string_pretty(value).unwrap() + "\n";
        std::fs::write(referee_dir().join(rel), text).expect("write a vector file");
    };
    write("corpus/split_margin.json", &corpus);
    write("rule_answers/split_margin.json", &rule_answers);
}

/// Every case states a ruling the rule requires, and the files hold them.
#[test]
fn the_split_margin_cases_say_what_the_rule_requires() {
    let corpus =
        crate::record_push_parity::read_json(&referee_dir().join("corpus/split_margin.json"));
    let cases = corpus["cases"].as_array().expect("cases");
    let specs = specs();
    assert_eq!(cases.len(), specs.len(), "one case per stated ruling");
    for (spec, case) in specs.iter().zip(cases) {
        assert_eq!(case["name"], json!(spec.name));
        check(spec, &Value::Array(super::parity::run_service(case)));
    }
}
