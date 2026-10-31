//! Two halves compared, and the ruling a referee's re-answer gives.
//!
//! The order of the checks is fixed: each half's record, a half with no
//! answer held, each answer against its signature, sampled twins, then the
//! weights, then who served them, and only then the words. Answers with the
//! same words are corroborated. Any difference is a difference: there is no
//! similarity threshold, and without a referee it is inconclusive. Only a
//! referee's re-answer can name a twin, and only the twin the referee did
//! not agree with, and only when the referee's own top-2 margin at the split
//! is at least [`SPLIT_MARGIN_THRESHOLD_NATS`] (#155): below it, honest
//! backends could have split there, so the ruling is inconclusive.

use serde_json::{json, Map, Value};

use super::half::{Half, HalfError};
use super::margin::{self, least_margin, Margin};

pub const VERDICT_CORROBORATED: &str = "corroborated";
pub const VERDICT_INCONCLUSIVE: &str = "inconclusive";
pub const VERDICT_NOT_COMPARABLE: &str = "not_comparable";
pub const VERDICT_CONTRADICTED_PREFIX: &str = "contradicted:";

pub const STATUS_SATISFIED: &str = "SATISFIED";
pub const STATUS_CONTRADICTED: &str = "CONTRADICTED";
pub const STATUS_UNKNOWN: &str = "UNKNOWN";

/// Why two halves have no ruling. None of these counts against either twin.
pub const NO_VERDICT_NO_REQUESTER_TRANSCRIPT: &str = "no_requester_transcript";
pub const NO_VERDICT_NOT_COMPARABLE: &str = "not_comparable";
pub const NO_VERDICT_WEIGHTS_MISMATCH: &str = "weights_mismatch";
pub const NO_VERDICT_OWNER_ABSENT: &str = "owner_absent";
pub const NO_VERDICT_SAME_OWNER_TWIN: &str = "same_owner_twin";
pub const NO_VERDICT_REFEREE_NOT_INDEPENDENT: &str = "referee_not_independent";
pub const NO_VERDICT_REFEREE_UNREACHABLE: &str = "referee_unreachable";

/// Why a referee whose word matched one twin still rules `inconclusive`
/// (`inconclusive_because`, #155). Neither counts against either twin.
pub const INCONCLUSIVE_SPLIT_WITHIN_MARGIN: &str = "split_within_margin";
pub const INCONCLUSIVE_SPLIT_MARGIN_UNAVAILABLE: &str = "split_margin_unavailable";

/// Decided (#155): the least top-2 margin, in nats, at which a referee's
/// word at the split names a twin. Below it, or with no margin, the ruling
/// is `inconclusive`. A margin equal to it names the twin. It is at least
/// twice the largest referee-side margin (read over the word window, as
/// [`least_margin`] reads it) at any top-1 disagreement between honest
/// backends measured, and no gap shrink seen between them at a gap of at
/// least it reaches it (`vectors/parity/referee/margin-measurement/README.md`,
/// "The rule"; Sherlock2 on #159). A change is a CHANGELOG line. There is no
/// operator setting: a lower value charges honest nodes more readily.
pub const SPLIT_MARGIN_THRESHOLD_NATS: f64 = 4.4;

/// [`SPLIT_MARGIN_THRESHOLD_NATS`] in the micro-nats the rule compares.
pub fn split_margin_threshold() -> i64 {
    margin::micro(SPLIT_MARGIN_THRESHOLD_NATS)
}

/// The fixed members of the sealed ruling block.
pub const ADJUDICATION_SCHEMA: &str = "capsule-emit-mesh/adjudication/v1";
pub const SOURCE_TWIN_COMPARISON: &str = "twin_comparison";
pub const CAPTURE_METHOD_DETERMINISTIC_REPLAY: &str = "deterministic_replay";

pub fn contradicted(node_id: &str) -> String {
    format!("{VERDICT_CONTRADICTED_PREFIX}{node_id}")
}

/// The status a ruling carries beside it. `None` for a ruling this module
/// does not know: it is never rounded to one it does.
pub fn status_for_verdict(verdict: &str) -> Option<&'static str> {
    match verdict {
        VERDICT_CORROBORATED => Some(STATUS_SATISFIED),
        VERDICT_INCONCLUSIVE | VERDICT_NOT_COMPARABLE => Some(STATUS_UNKNOWN),
        v if v.starts_with(VERDICT_CONTRADICTED_PREFIX) => Some(STATUS_CONTRADICTED),
        _ => None,
    }
}

/// The whitespace a word ends at: Unicode white space, and the four ASCII
/// separators (0x1C-0x1F) the reference implementation also splits on.
fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// The words of a text: its whitespace-separated tokens.
pub fn words(text: &str) -> Vec<&str> {
    text.split(is_space).filter(|w| !w.is_empty()).collect()
}

/// Each word of a text with the byte it starts at.
fn word_spans(text: &str) -> Vec<(usize, &str)> {
    let mut spans = Vec::new();
    let mut start = None;
    for (at, c) in text.char_indices() {
        match (is_space(c), start) {
            (true, Some(s)) => {
                spans.push((s, &text[s..at]));
                start = None;
            }
            (false, None) => start = Some(at),
            _ => {}
        }
    }
    if let Some(s) = start {
        spans.push((s, &text[s..]));
    }
    spans
}

/// The word at `index` of `text`, `None` past its end.
pub fn token_at(text: &str, index: usize) -> Option<&str> {
    words(text).get(index).copied()
}

/// Where `text`'s word `index` departs from `other`'s word `other_index`:
/// `(from, at)`, the first byte after `text`'s previous word (0 for its
/// first) and the first byte at which the two words differ (the word's
/// start plus the bytes they share). The margin is read over `from..=at`
/// (`margin::least_margin`). `None` when `text` has no word `index`.
pub(crate) fn departure(
    text: &str,
    index: usize,
    other: &str,
    other_index: usize,
) -> Option<(usize, usize)> {
    let spans = word_spans(text);
    let (start, word) = *spans.get(index)?;
    let from = index
        .checked_sub(1)
        .and_then(|before| spans.get(before))
        .map_or(0, |(s, w)| s + w.len());
    let theirs = token_at(other, other_index).unwrap_or_default();
    let shared = word
        .bytes()
        .zip(theirs.bytes())
        .take_while(|(x, y)| x == y)
        .count();
    Some((from, start + shared))
}

/// Where two answers first differ, and the digest of the words they share
/// before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// The first word at which they differ; `None` when the words are the same.
    pub divergence_index: Option<usize>,
    /// JSON-DIGEST of `{"prefix_tokens": [the shared words]}`; `None` when
    /// they share none.
    pub prefix_digest: Option<String>,
}

pub fn compare_transcripts(text_a: &str, text_b: &str) -> Comparison {
    let (a, b) = (words(text_a), words(text_b));
    let shared = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let same = shared == a.len() && shared == b.len();
    let prefix_digest = (shared > 0).then(|| {
        crate::capsule_emit::digest_json(&json!({ "prefix_tokens": &a[..shared] }))
            .expect("a list of strings always has a digest")
    });
    Comparison {
        divergence_index: (!same).then_some(shared),
        prefix_digest,
    }
}

/// A referee's ruling on two twins that differ.
#[derive(Debug, Clone, PartialEq)]
pub struct Ruling {
    pub verdict: String,
    /// Why the referee's word did not name a twin though it matched one
    /// ([`INCONCLUSIVE_SPLIT_WITHIN_MARGIN`], [`INCONCLUSIVE_SPLIT_MARGIN_UNAVAILABLE`]).
    pub inconclusive_because: Option<&'static str>,
    /// The sealed `split_margin` block, when the margin was weighed.
    pub split_margin: Option<Value>,
}

impl Ruling {
    fn inconclusive() -> Self {
        Self {
            verdict: VERDICT_INCONCLUSIVE.to_string(),
            inconclusive_because: None,
            split_margin: None,
        }
    }
}

/// The ruling a referee's re-answer gives on two twins that differ. A
/// re-answer of a request with messages counts only when it repeats the
/// agreed words exactly; its word at the difference then names the twin it
/// agrees with, and the other twin is contradicted, when the referee's own
/// margin at the split (read from `referee_body`, its answer with logprobs)
/// reaches [`SPLIT_MARGIN_THRESHOLD_NATS`]. Anything else is inconclusive,
/// never a guess. The twins' own margins, when their answers carry them,
/// are sealed beside it and never change the ruling.
pub fn referee_verdict(
    a: &Half,
    b: &Half,
    comparison: &Comparison,
    referee_text: &str,
    referee_body: Option<&Value>,
) -> Ruling {
    let at = comparison.divergence_index.unwrap_or(0);
    // The referee's word read at the difference: `at` when it re-answered the
    // twins' messages, its first word otherwise.
    let referee_index = if a.request_has_messages() {
        let agreed: Vec<&str> = words(a.text()).into_iter().take(at).collect();
        let theirs = words(referee_text);
        if theirs.iter().take(at).copied().collect::<Vec<_>>() != agreed {
            return Ruling::inconclusive();
        }
        at
    } else {
        0
    };
    let referee_token = token_at(referee_text, referee_index);
    let matches =
        |half: &Half| referee_token.is_some() && referee_token == token_at(half.text(), at);
    let (matches_a, matches_b) = (matches(a), matches(b));
    // The twin the referee did NOT agree with is the one contradicted.
    let (agreed, other) = match (matches_a, matches_b) {
        (true, false) => (a, b),
        (false, true) => (b, a),
        _ => return Ruling::inconclusive(),
    };
    let named = if cfg!(feature = "mutant-referee-verdict-names-wrong-twin") {
        agreed
    } else {
        other
    };
    let Some(node) = named.node_id.as_deref().filter(|n| !n.is_empty()) else {
        return Ruling::inconclusive();
    };
    // The referee's least margin from the space before its word through the
    // token where it departs from the twin it did not agree with: a choice
    // there is what an honest backend could have flipped.
    let referee_margin = departure(referee_text, referee_index, other.text(), at)
        .zip(referee_body)
        .and_then(|((from, split), body)| least_margin(body, referee_text, from, split));
    let because = match &referee_margin {
        None => Some(INCONCLUSIVE_SPLIT_MARGIN_UNAVAILABLE),
        Some(m) if m.margin < split_margin_threshold() => Some(INCONCLUSIVE_SPLIT_WITHIN_MARGIN),
        Some(_) => None,
    };
    let because = because.filter(|_| !cfg!(feature = "mutant-referee-ignores-split-margin"));
    Ruling {
        verdict: match because {
            Some(_) => VERDICT_INCONCLUSIVE.to_string(),
            None => contradicted(node),
        },
        inconclusive_because: because,
        split_margin: Some(split_margin_block(referee_margin.as_ref(), a, b, at)),
    }
}

/// The sealed `split_margin` block: the threshold, the referee's margin
/// (`null` when it had none), and each twin's own margin where its answer
/// departs from the other's, read the same way, when that twin's answer
/// carries logprobs.
fn split_margin_block(referee: Option<&Margin>, a: &Half, b: &Half, at: usize) -> Value {
    let mut block = Map::new();
    block.insert("unit".into(), json!("nats"));
    block.insert(
        "threshold".into(),
        json!(margin::decimal(split_margin_threshold())),
    );
    block.insert(
        "referee".into(),
        referee.map_or(Value::Null, Margin::to_json),
    );
    let twin = |own: &Half, other: &Half| {
        let body = own.response_body.as_ref()?;
        let (from, split) = departure(own.text(), at, other.text(), at)?;
        least_margin(body, own.text(), from, split)
    };
    for (key, own, other) in [("twin_a", a, b), ("twin_b", b, a)] {
        if let Some(m) = twin(own, other) {
            block.insert(key.into(), m.to_json());
        }
    }
    Value::Object(block)
}

/// What a referee that was asked answered.
#[derive(Debug, Clone)]
pub struct RefereeAnswer {
    pub verdict: String,
    /// [`Ruling::inconclusive_because`].
    pub inconclusive_because: Option<&'static str>,
    /// [`Ruling::split_margin`].
    pub split_margin: Option<Value>,
    /// The referee's own record of its answer, when it has one.
    pub capsule_id: Option<String>,
    /// Who the referee is.
    pub referee_id: String,
}

/// The referee did not answer.
#[derive(Debug, Clone, Copy)]
pub struct Unreachable;

/// Asked with both halves and where they differ.
pub type Referee<'r> =
    &'r mut dyn FnMut(&Half, &Half, &Comparison) -> Result<RefereeAnswer, Unreachable>;

/// Twins with an unknown weights digest: not comparable (the rule), or
/// compared with no shared digest claimed (the referee's door, which states
/// the reason itself, `service`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownWeights {
    NotComparable,
    Compare,
}

/// A ruling, or why there is none. Never both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: Option<String>,
    pub no_verdict_reason: Option<&'static str>,
    /// Why an `inconclusive` referee ruling named no twin (#155).
    pub inconclusive_because: Option<&'static str>,
    /// The referee's sealed `split_margin` block (#155).
    pub split_margin: Option<Value>,
    pub divergence_index: Option<usize>,
    pub prefix_digest: Option<String>,
    pub twin_owner_distinct: Option<bool>,
    /// The weights both halves name; `None` unless both name the same.
    pub weights_digest: Option<String>,
    pub half_a_capsule_id: String,
    pub half_b_capsule_id: String,
    pub referee_called: bool,
    pub referee_capsule_id: Option<String>,
    pub referee_id: Option<String>,
}

impl Outcome {
    fn none(a: &Half, b: &Half, reason: &'static str) -> Self {
        Self {
            verdict: None,
            no_verdict_reason: Some(reason),
            inconclusive_because: None,
            split_margin: None,
            divergence_index: None,
            prefix_digest: None,
            twin_owner_distinct: None,
            weights_digest: None,
            half_a_capsule_id: a.capsule_id().to_string(),
            half_b_capsule_id: b.capsule_id().to_string(),
            referee_called: false,
            referee_capsule_id: None,
            referee_id: None,
        }
    }

    /// The answer the parity corpus compares (`adjudicate` path).
    #[cfg(test)]
    pub fn to_answer(&self) -> serde_json::Value {
        let mut answer = json!({
            "verdict": self.verdict,
            "status": self.verdict.as_deref().and_then(status_for_verdict),
            "no_verdict_reason": self.no_verdict_reason,
            "divergence_index": self.divergence_index,
            "prefix_digest": self.prefix_digest,
            "twin_owner_distinct": self.twin_owner_distinct,
            "weights_digest": self.weights_digest,
            "referee_called": self.referee_called,
        });
        // Only when the margin was weighed (#155): answers from before it
        // have neither member.
        if let Some(because) = self.inconclusive_because {
            answer["inconclusive_because"] = json!(because);
        }
        if let Some(block) = &self.split_margin {
            answer["split_margin"] = block.clone();
        }
        answer
    }
}

/// Compare two halves; call `referee` only when they differ. `Err` when a
/// half cannot be read at all.
pub fn adjudicate(
    a: &Half,
    b: &Half,
    referee: Option<Referee<'_>>,
    referee_node_id: Option<&str>,
    unknown_weights: UnknownWeights,
) -> Result<Outcome, HalfError> {
    a.check_record()?;
    b.check_record()?;
    if a.no_answer_held() || b.no_answer_held() {
        return Ok(Outcome::none(a, b, NO_VERDICT_NO_REQUESTER_TRANSCRIPT));
    }
    a.check_answer()?;
    b.check_answer()?;
    if a.sampled() || b.sampled() {
        return Ok(Outcome::none(a, b, NO_VERDICT_NOT_COMPARABLE));
    }
    let (weights_a, weights_b) = (a.weights_digest.as_deref(), b.weights_digest.as_deref());
    let known = |w: Option<&str>| w.is_some_and(|w| !w.is_empty());
    if unknown_weights == UnknownWeights::NotComparable && !(known(weights_a) && known(weights_b)) {
        return Ok(Outcome::none(a, b, NO_VERDICT_NOT_COMPARABLE));
    }
    if let (Some(x), Some(y)) = (weights_a, weights_b) {
        if x != y {
            return Ok(Outcome::none(a, b, NO_VERDICT_WEIGHTS_MISMATCH));
        }
    }
    let shared = match (weights_a, weights_b) {
        (Some(x), Some(_)) => Some(x.to_string()),
        _ => None,
    };
    let with_shared = |mut outcome: Outcome| {
        outcome.weights_digest = shared.clone();
        outcome
    };
    let (Some(owner_a), Some(owner_b)) = (a.node_id.as_deref(), b.node_id.as_deref()) else {
        return Ok(with_shared(Outcome::none(a, b, NO_VERDICT_OWNER_ABSENT)));
    };
    if owner_a == owner_b {
        let mut outcome = with_shared(Outcome::none(a, b, NO_VERDICT_SAME_OWNER_TWIN));
        outcome.twin_owner_distinct = Some(false);
        return Ok(outcome);
    }

    let comparison = compare_transcripts(a.text(), b.text());
    let compared = |verdict: Option<String>, reason: Option<&'static str>| Outcome {
        verdict,
        no_verdict_reason: reason,
        inconclusive_because: None,
        split_margin: None,
        divergence_index: comparison.divergence_index,
        prefix_digest: comparison.prefix_digest.clone(),
        twin_owner_distinct: Some(true),
        weights_digest: shared.clone(),
        half_a_capsule_id: a.capsule_id().to_string(),
        half_b_capsule_id: b.capsule_id().to_string(),
        referee_called: false,
        referee_capsule_id: None,
        referee_id: None,
    };
    if comparison.divergence_index.is_none() {
        return Ok(compared(Some(VERDICT_CORROBORATED.to_string()), None));
    }
    let Some(referee) = referee else {
        return Ok(compared(Some(VERDICT_INCONCLUSIVE.to_string()), None));
    };
    if referee_node_id.is_some_and(|r| r == owner_a || r == owner_b) {
        return Ok(compared(None, Some(NO_VERDICT_REFEREE_NOT_INDEPENDENT)));
    }
    match referee(a, b, &comparison) {
        Err(Unreachable) => Ok(compared(None, Some(NO_VERDICT_REFEREE_UNREACHABLE))),
        Ok(answer) => Ok(Outcome {
            referee_called: true,
            referee_capsule_id: answer.capsule_id,
            referee_id: Some(answer.referee_id),
            inconclusive_because: answer.inconclusive_because,
            split_margin: answer.split_margin,
            ..compared(Some(answer.verdict), None)
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_split_on_any_whitespace() {
        assert_eq!(words(" a\tb\u{a0}c\u{1f}d \n"), ["a", "b", "c", "d"]);
        assert_eq!(token_at("a b", 1), Some("b"));
        assert_eq!(token_at("a b", 2), None);
    }

    #[test]
    fn the_first_difference_and_the_shared_words() {
        let same = compare_transcripts("a b c", "a  b c");
        assert_eq!(same.divergence_index, None);
        assert!(same.prefix_digest.is_some());
        let differ = compare_transcripts("a b c", "a b d");
        assert_eq!(differ.divergence_index, Some(2));
        let prefix = compare_transcripts("a b", "a b c");
        assert_eq!(prefix.divergence_index, Some(2), "one answer stops early");
        let none = compare_transcripts("x", "y");
        assert_eq!((none.divergence_index, none.prefix_digest), (Some(0), None));
        let empty = compare_transcripts("", " ");
        assert_eq!((empty.divergence_index, empty.prefix_digest), (None, None));
    }

    #[test]
    fn every_ruling_has_a_status_and_no_other_does() {
        assert_eq!(status_for_verdict("corroborated"), Some(STATUS_SATISFIED));
        assert_eq!(
            status_for_verdict("contradicted:node-b"),
            Some(STATUS_CONTRADICTED)
        );
        assert_eq!(status_for_verdict("not_comparable"), Some(STATUS_UNKNOWN));
        assert_eq!(status_for_verdict("something_else"), None);
    }
}
