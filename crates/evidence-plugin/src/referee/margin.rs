//! The top-2 margin at the token where an answer departs from another
//! (#155): how far ahead its chosen token was of the runner-up, in nats.
//!
//! Honest backends (Metal, CUDA, CPU, other thread or batch settings) move
//! next-token scores a little, so at a near-tie greedy decoding can choose
//! differently on two honest nodes. A referee's word then says nothing about
//! honesty unless its own margin at the split is wider than that drift.
//!
//! The margin is read from the answer's OpenAI `logprobs` (`choices[0].
//! logprobs.content[]`: each sampled token with its `logprob` and
//! `top_logprobs`), at the token that holds the byte where the answer first
//! departs. It is `None`, never a guess, when that cannot be read: no
//! logprobs, tokens that do not spell the answer's text, fewer than two
//! alternatives, or a chosen token that is not the top one (something other
//! than greedy decoding chose it).
//!
//! Numbers are kept as whole micro-nats and sealed as exact decimal strings,
//! since a signed record carries no floats (spec §5.1); the rule compares
//! the same rounded value that is sealed.

use serde_json::{json, Value};

/// Micro-nats in one nat.
const MICRO: f64 = 1_000_000.0;

/// `nats`, rounded to the nearest micro-nat.
pub fn micro(nats: f64) -> i64 {
    (nats * MICRO).round() as i64
}

/// A micro-nat count as the exact decimal string a record seals: six
/// decimals, as in `-0.410000`.
pub fn decimal(micro: i64) -> String {
    let sign = if micro < 0 { "-" } else { "" };
    let abs = micro.unsigned_abs();
    format!("{sign}{}.{:06}", abs / 1_000_000, abs % 1_000_000)
}

/// One candidate token: its text and its logprob in micro-nats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub token: String,
    pub logprob: i64,
}

/// The top two candidates at one sampled token, and the gap between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Margin {
    /// The token's index in `logprobs.content`.
    pub token_index: usize,
    pub top1: Candidate,
    pub top2: Candidate,
    /// `top1.logprob - top2.logprob`, micro-nats, never negative.
    pub margin: i64,
}

impl Margin {
    pub fn to_json(&self) -> Value {
        let candidate = |c: &Candidate| json!({"token": c.token, "logprob": decimal(c.logprob)});
        json!({
            "token_index": self.token_index,
            "top1": candidate(&self.top1),
            "top2": candidate(&self.top2),
            "margin": decimal(self.margin),
        })
    }
}

fn candidate(entry: &Value) -> Option<Candidate> {
    let logprob = entry.get("logprob")?.as_f64().filter(|l| l.is_finite())?;
    Some(Candidate {
        token: entry.get("token")?.as_str()?.to_string(),
        logprob: micro(logprob),
    })
}

/// The bytes a token spells: its `bytes` when it has them (a token can end
/// inside a UTF-8 character), its text otherwise.
fn token_bytes(entry: &Value) -> Option<Vec<u8>> {
    match entry.get("bytes") {
        Some(Value::Array(bytes)) => bytes
            .iter()
            .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
            .collect(),
        Some(Value::Null) | None => Some(entry.get("token")?.as_str()?.as_bytes().to_vec()),
        Some(_) => None,
    }
}

/// The margin at the token of `body` that holds byte `at` of `text`, the
/// answer's own text. The tokens must spell `text` from its first byte; they
/// may run past its end (a stop sequence is cut from the text, not from the
/// tokens).
pub fn margin_at(body: &Value, text: &str, at: usize) -> Option<Margin> {
    if at >= text.len() {
        return None;
    }
    let entries = body.pointer("/choices/0/logprobs/content")?.as_array()?;
    let mut spelled = Vec::new();
    let mut ends = Vec::with_capacity(entries.len());
    for entry in entries {
        spelled.extend(token_bytes(entry)?);
        ends.push(spelled.len());
    }
    if !spelled.starts_with(text.as_bytes()) {
        return None;
    }
    let token_index = ends.iter().position(|&end| end > at)?;
    let entry = &entries[token_index];
    let top = entry.get("top_logprobs")?.as_array()?;
    let (top1, top2) = (candidate(top.first()?)?, candidate(top.get(1)?)?);
    if candidate(entry)? != top1 || top2.logprob > top1.logprob {
        return None;
    }
    Some(Margin {
        token_index,
        margin: top1.logprob - top2.logprob,
        top1,
        top2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(text: &str, logprob: f64, alternatives: &[(&str, f64)]) -> Value {
        json!({
            "token": text,
            "logprob": logprob,
            "bytes": text.as_bytes(),
            "top_logprobs": alternatives
                .iter()
                .map(|(t, l)| json!({"token": t, "logprob": l, "bytes": t.as_bytes()}))
                .collect::<Vec<_>>(),
        })
    }

    fn body(content: &str, tokens: Vec<Value>) -> Value {
        json!({"choices": [{"message": {"content": content}, "logprobs": {"content": tokens}}]})
    }

    #[test]
    fn decimals_are_exact_and_signed() {
        assert_eq!(decimal(micro(-0.41)), "-0.410000");
        assert_eq!(decimal(micro(0.7)), "0.700000");
        assert_eq!(decimal(micro(-0.0000004)), "0.000000");
        assert_eq!(decimal(12_345_678), "12.345678");
        assert_eq!(decimal(-5), "-0.000005");
    }

    #[test]
    fn the_margin_is_read_at_the_token_holding_the_split_byte() {
        let answer = body(
            "the deep sea",
            vec![
                token("the", -0.01, &[("the", -0.01), ("a", -4.0)]),
                token(" de", -0.3, &[(" de", -0.3), (" big", -2.0)]),
                token("ep", -0.41, &[("ep", -0.41), ("er", -1.12)]),
                token(" sea", -0.1, &[(" sea", -0.1), (" lake", -3.0)]),
            ],
        );
        // Byte 7 ("p" of "deep") is in the third token.
        let margin = margin_at(&answer, "the deep sea", 7).expect("a margin");
        assert_eq!(margin.token_index, 2);
        assert_eq!(margin.margin, 710_000);
        assert_eq!(margin.to_json()["margin"], "0.710000");
        assert_eq!(margin.to_json()["top2"]["token"], "er");
        // Byte 4 (the "d") is in the second.
        assert_eq!(
            margin_at(&answer, "the deep sea", 4).unwrap().token_index,
            1
        );
    }

    #[test]
    fn no_margin_without_a_readable_split_token() {
        let good = vec![
            token("one", -0.1, &[("one", -0.1), ("two", -3.0)]),
            token(" two", -0.2, &[(" two", -0.2), (" too", -0.9)]),
        ];
        let text = "one two";
        assert!(margin_at(&body(text, good.clone()), text, 4).is_some());
        // No logprobs at all.
        assert_eq!(
            margin_at(
                &json!({"choices": [{"message": {"content": text}}]}),
                text,
                4
            ),
            None
        );
        // Tokens that spell something else (a reasoning prefix, a rewrite).
        assert_eq!(margin_at(&body(text, good.clone()), "one tw0", 4), None);
        // Past the text's end.
        assert_eq!(margin_at(&body(text, good.clone()), text, 7), None);
        // One alternative only.
        let one = vec![good[0].clone(), token(" two", -0.2, &[(" two", -0.2)])];
        assert_eq!(margin_at(&body(text, one), text, 4), None);
        // The chosen token is not the top one: not greedy at that token.
        let penalised = vec![
            good[0].clone(),
            token(" two", -0.9, &[(" too", -0.2), (" two", -0.9)]),
        ];
        assert_eq!(margin_at(&body(text, penalised), text, 4), None);
        // An unreadable logprob.
        let unreadable = vec![
            good[0].clone(),
            json!({"token": " two", "logprob": null, "top_logprobs": []}),
        ];
        assert_eq!(margin_at(&body(text, unreadable), text, 4), None);
    }

    #[test]
    fn tokens_may_run_past_the_text_and_split_a_character() {
        // A stop sequence cut from the text but not from the tokens.
        let text = "ok";
        let answer = body(
            text,
            vec![
                token("ok", -0.05, &[("ok", -0.05), ("no", -2.0)]),
                token("STOP", -0.01, &[("STOP", -0.01), ("x", -5.0)]),
            ],
        );
        assert_eq!(margin_at(&answer, text, 1).unwrap().token_index, 0);
        // "é" spelled by two tokens of one byte each.
        let split = json!({"choices": [{"logprobs": {"content": [
            {"token": "", "bytes": [0xc3], "logprob": -0.1,
             "top_logprobs": [{"token": "", "bytes": [0xc3], "logprob": -0.1}, {"token": "e", "logprob": -2.5}]},
            {"token": "", "bytes": [0xa9], "logprob": -0.01,
             "top_logprobs": [{"token": "", "bytes": [0xa9], "logprob": -0.01}, {"token": "x", "logprob": -6.0}]}
        ]}}]});
        assert_eq!(margin_at(&split, "é", 1).unwrap().token_index, 1);
        assert_eq!(margin_at(&split, "é", 0).unwrap().margin, 2_400_000);
    }
}
