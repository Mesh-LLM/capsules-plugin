//! The rule behind `SPLIT_MARGIN_THRESHOLD_NATS` (#155, Sherlock2 on #159),
//! over scored runs: every honest answer read by two referees on different
//! backends, both on the same answer tokens, so both always share the
//! context. One row per answer position (`margin-measurement/cuda-cpu/`).
//!
//! At a top-1 disagreement, the position where the two referees' top-1
//! tokens differ, either referee could be the one that re-answers, and an
//! honest twin computing like the other one parted from it there. Its margin
//! is what [`least_margin`] would read: the least top-2 gap over its tokens
//! from the space before the departing word through the token where they
//! part. The rule: T is at least twice the largest such margin
//! (`threshold_2x_referee_margin`), and no gap seen at T or above shrinks,
//! from one referee to the other, by T or more below 2T, nor by its whole
//! size anywhere (`shrink`).
//!
//! `writes_the_scored_margin_results` (ignored) reads the rows from
//! `SPLIT_MARGIN_SCORED` and writes `results.json` beside them.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::margin::least_margin;
use super::verdict::{compare_transcripts, departure};

fn round6(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

/// One answer position, read by referees `a` and `b`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Position {
    /// The answer's token text.
    pub token: String,
    /// Each referee's top-1 token text.
    pub top1: [String; 2],
    /// Each referee's own top-1 minus top-2 logprob, nats.
    pub gap: [f64; 2],
    /// The same two tokens' gap read in the other referee, when its top 5
    /// holds both.
    pub gap_in_other: [Option<f64>; 2],
}

/// One answer, by which backend generated it and its prompt.
#[derive(Debug, Clone, Default)]
pub(crate) struct Answer {
    pub answers: String,
    pub prompt: String,
    pub positions: Vec<Position>,
}

/// An OpenAI `logprobs` body for referee `side` re-answering `positions`
/// with `last` as its token at the final one: its chosen token, its top-1
/// (at logprob 0) and a runner-up `gap` below. A chosen token that is not
/// its top-1 is then unreadable, as [`least_margin`] reads a real one.
fn body(positions: &[Position], side: usize, last: &str) -> Value {
    let n = positions.len();
    let content: Vec<Value> = positions
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let token = if i + 1 == n { last } else { &p.token };
            let chosen = if *token == p.top1[side] {
                0.0
            } else {
                -p.gap[side] - 1.0
            };
            json!({
                "token": token,
                "logprob": chosen,
                "top_logprobs": [
                    {"token": p.top1[side], "logprob": 0.0},
                    {"token": "\u{0}runner-up", "logprob": -p.gap[side]},
                ],
            })
        })
        .collect();
    json!({"choices": [{"logprobs": {"content": content}}]})
}

/// What a disagreement at the end of `positions` gives referee `side`.
enum Read {
    /// Its margin, nats, and whether the departure ran past its own token
    /// (the other's token starts with all of it), so the window stops there:
    /// an upper bound, since later tokens could only lower it.
    Margin(f64, bool),
    /// The two texts differ only in whitespace: no word departs.
    SameWords,
    /// A token in the window was not the referee's own top-1.
    Unreadable,
}

fn read(positions: &[Position], side: usize) -> Read {
    let (last, prefix) = positions.split_last().expect("a position");
    let prefix: String = prefix.iter().map(|p| p.token.as_str()).collect();
    let mine = format!("{prefix}{}", last.top1[side]);
    let theirs = format!("{prefix}{}", last.top1[1 - side]);
    let Some(index) = compare_transcripts(&mine, &theirs).divergence_index else {
        return Read::SameWords;
    };
    let Some((from, split)) = departure(&mine, index, &theirs, index) else {
        // `mine` ends where `theirs` has another word: the choice was at
        // its end, read at its last token.
        return read_window(positions, side, &mine, prefix.len(), mine.len() - 1, true);
    };
    let past = split >= mine.len();
    read_window(
        positions,
        side,
        &mine,
        from,
        split.min(mine.len() - 1),
        past,
    )
}

fn read_window(
    positions: &[Position],
    side: usize,
    mine: &str,
    from: usize,
    at: usize,
    past: bool,
) -> Read {
    let last = &positions[positions.len() - 1];
    match least_margin(
        &body(positions, side, &last.top1[side]),
        mine,
        from.min(at),
        at,
    ) {
        Some(m) => Read::Margin(m.margin as f64 / 1e6, past),
        None => Read::Unreadable,
    }
}

/// The least T, to 0.01 nat, at least twice `margin`.
fn twice(margin: f64) -> f64 {
    (2.0 * margin * 100.0 - 1e-6).ceil() / 100.0
}

/// The report over every answer given.
pub(crate) fn analyse(answers: &[Answer]) -> Value {
    let mut by_answers: BTreeMap<&str, Vec<&Answer>> = BTreeMap::new();
    for a in answers {
        by_answers.entry(&a.answers).or_default().push(a);
    }
    let (mut worst_token, mut worst_window): (Option<Value>, Option<Value>) = (None, None);
    let (mut max_token, mut max_window) = (0.0_f64, 0.0_f64);
    let mut sets = Vec::new();
    let mut shrinks = Vec::new();
    for (name, list) in &by_answers {
        let (mut disagreements, mut same_words, mut unreadable, mut stopped) = (0, 0, 0, 0);
        let (mut set_token, mut set_window) = (0.0_f64, 0.0_f64);
        for answer in list {
            for (i, p) in answer.positions.iter().enumerate() {
                for side in 0..2 {
                    if let Some(other) = p.gap_in_other[side] {
                        shrinks.push((p.gap[side], p.gap[side] - other));
                    }
                }
                if p.top1[0] == p.top1[1] {
                    continue;
                }
                disagreements += 1;
                let at = json!({"answers": name, "prompt": answer.prompt, "position": i});
                for side in 0..2 {
                    let g = p.gap[side];
                    set_token = set_token.max(g);
                    if g > max_token {
                        max_token = g;
                        worst_token = Some(json!({"at": at, "referee": side, "margin": round6(g)}));
                    }
                    match read(&answer.positions[..=i], side) {
                        Read::Margin(m, past) => {
                            stopped += usize::from(past);
                            set_window = set_window.max(m);
                            if m > max_window {
                                max_window = m;
                                worst_window =
                                    Some(json!({"at": at, "referee": side, "margin": round6(m)}));
                            }
                        }
                        Read::SameWords => same_words += 1,
                        Read::Unreadable => unreadable += 1,
                    }
                }
            }
        }
        sets.push(json!({
            "answers": name,
            "answer_count": list.len(),
            "top1_disagreements": disagreements,
            "referee_reads": {
                "whitespace_only": same_words,
                "window_unreadable": unreadable,
                "window_stops_at_the_split_token": stopped,
            },
            "referee_margin_per_token_max": round6(set_token),
            "referee_margin_word_window_max": round6(set_window),
        }));
    }
    let threshold = twice(max_window);
    let shrink_below_2t = shrinks
        .iter()
        .filter(|(g, _)| (threshold..2.0 * threshold).contains(g))
        .map(|(_, s)| *s)
        .fold(0.0, f64::max);
    let flips = shrinks
        .iter()
        .filter(|(g, s)| *g >= threshold && s >= g)
        .count();
    json!({
        "unit": "nats",
        "sets": sets,
        "referee_margin_per_token_max": worst_token,
        "referee_margin_word_window_max": worst_window,
        "threshold_2x_referee_margin": threshold,
        "shrink": {
            "largest_at_gaps_from_t_to_2t": round6(shrink_below_2t),
            "flips_at_gaps_from_t": flips,
            "holds": shrink_below_2t < threshold && flips == 0,
        },
    })
}

/// The fields of one CSV line (RFC 4180: quoted fields may hold commas,
/// doubled quotes and line breaks), and the rest of the input.
fn fields(mut input: &str) -> Option<(Vec<String>, &str)> {
    if input.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    loop {
        let mut field = String::new();
        if let Some(rest) = input.strip_prefix('"') {
            let mut chars = rest.char_indices();
            loop {
                let (i, c) = chars.next().expect("a closing quote");
                if c != '"' {
                    field.push(c);
                } else if rest[i + 1..].starts_with('"') {
                    field.push('"');
                    chars.next();
                } else {
                    input = &rest[i + 1..];
                    break;
                }
            }
        } else {
            let end = input.find([',', '\n']).unwrap_or(input.len());
            field.push_str(input[..end].trim_end_matches('\r'));
            input = &input[end..];
        }
        out.push(field);
        match input.chars().next() {
            Some(',') => input = &input[1..],
            Some('\r') if input.starts_with("\r\n") => return Some((out, &input[2..])),
            Some('\n') => return Some((out, &input[1..])),
            None => return Some((out, input)),
            Some(c) => panic!("unexpected {c:?} after a field"),
        }
    }
}

/// The answers of a positions file, in file order.
pub(crate) fn parse(csv: &str) -> Vec<Answer> {
    let (header, mut rest) = fields(csv).expect("a header");
    let col = |name: &str| {
        header
            .iter()
            .position(|h| h == name)
            .unwrap_or_else(|| panic!("no column {name}"))
    };
    let c = [
        "answers",
        "prompt",
        "position",
        "token",
        "top1_a",
        "top1_b",
        "gap_a",
        "gap_b",
        "a_top2_in_b",
        "b_top2_in_a",
    ]
    .map(col);
    let num = |s: &str| {
        s.parse::<f64>()
            .unwrap_or_else(|_| panic!("not a number: {s:?}"))
    };
    let opt = |s: &str| (!s.is_empty()).then(|| num(s));
    let mut answers: Vec<Answer> = Vec::new();
    while let Some((row, next)) = fields(rest) {
        rest = next;
        let (name, prompt) = (&row[c[0]], &row[c[1]]);
        let position: usize = row[c[2]].parse().expect("a position");
        if answers
            .last()
            .is_none_or(|a| a.answers != *name || a.prompt != *prompt)
        {
            answers.push(Answer {
                answers: name.clone(),
                prompt: prompt.clone(),
                positions: Vec::new(),
            });
        }
        let answer = answers.last_mut().unwrap();
        assert_eq!(answer.positions.len(), position, "positions in order");
        answer.positions.push(Position {
            token: row[c[3]].clone(),
            top1: [row[c[4]].clone(), row[c[5]].clone()],
            gap: [num(&row[c[6]]), num(&row[c[7]])],
            gap_in_other: [opt(&row[c[8]]), opt(&row[c[9]])],
        });
    }
    answers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(token: &str, top1: [&str; 2], gap: [f64; 2]) -> Position {
        Position {
            token: token.into(),
            top1: top1.map(String::from),
            gap,
            gap_in_other: [Some(gap[1]), Some(gap[0])],
        }
    }

    fn answer(positions: Vec<Position>) -> Answer {
        Answer {
            answers: "x".into(),
            prompt: "0".into(),
            positions,
        }
    }

    #[test]
    fn the_window_lowers_a_token_whose_word_began_at_a_near_tie() {
        // "|--" then a dash: a chooses "-" (margin 3.3), b "|" — but the
        // earlier "-" of the same word sits at 1.2 in a, so a reads 1.2.
        let report = analyse(&[answer(vec![
            at("a", ["a", "a"], [9.0, 9.0]),
            at(" |", [" |", " |"], [8.0, 8.0]),
            at("-", ["-", "-"], [1.2, 1.5]),
            at("-", ["-", "|"], [3.3, 0.1]),
        ])]);
        assert_eq!(report["referee_margin_per_token_max"]["margin"], json!(3.3));
        assert_eq!(
            report["referee_margin_word_window_max"]["margin"],
            json!(1.2)
        );
        assert_eq!(report["threshold_2x_referee_margin"], json!(2.4));
        assert_eq!(report["sets"][0]["top1_disagreements"], json!(1));
    }

    #[test]
    fn a_new_word_is_read_from_its_space() {
        // " sea" against " lake" departs at the space's next byte; the
        // window is the token alone, so a reads its own 2.2.
        let report = analyse(&[answer(vec![
            at("The", ["The", "The"], [0.5, 0.5]),
            at(" sea", [" sea", " lake"], [2.2, 0.3]),
        ])]);
        assert_eq!(
            report["referee_margin_word_window_max"]["margin"],
            json!(2.2)
        );
        assert_eq!(report["threshold_2x_referee_margin"], json!(4.4));
    }

    #[test]
    fn whitespace_only_and_unreadable_reads_are_counted_not_used() {
        let report = analyse(&[answer(vec![
            // The answer went on with b's "x"; a's top-1 there was "y".
            at("x", ["y", "x"], [0.4, 0.6]),
            // Same word: a's window holds "x", a token a did not choose, so
            // a is unreadable here; b reads min(0.6, 0.9).
            at("z", ["z", "w"], [5.0, 0.9]),
            // Space against line break: no word departs, for either side.
            at(" ", [" ", "\n"], [7.0, 7.0]),
        ])]);
        let reads = &report["sets"][0]["referee_reads"];
        assert_eq!(reads["whitespace_only"], json!(2));
        assert_eq!(reads["window_unreadable"], json!(1));
        assert_eq!(report["sets"][0]["top1_disagreements"], json!(3));
        assert_eq!(
            report["referee_margin_word_window_max"]["margin"],
            json!(0.6)
        );
    }

    #[test]
    fn a_shrink_that_reaches_t_below_2t_fails_the_rule() {
        let mut p = at("a", ["a", "a"], [2.0, 2.0]);
        let mut q = at(" b", [" b", " c"], [1.0, 0.2]);
        q.gap_in_other = [Some(0.9), Some(0.1)];
        p.gap_in_other = [Some(2.0), Some(2.0)];
        // T = 2.0; a 3.0 gap shrinking by 2.5 at 2.0..4.0 breaks it.
        let mut r = at("d", ["d", "d"], [3.0, 3.0]);
        r.gap_in_other = [Some(0.5), Some(3.0)];
        let report = analyse(&[answer(vec![p, q, r])]);
        assert_eq!(report["threshold_2x_referee_margin"], json!(2.0));
        assert_eq!(report["shrink"]["largest_at_gaps_from_t_to_2t"], json!(2.5));
        assert_eq!(report["shrink"]["holds"], json!(false));
    }

    #[test]
    fn csv_fields_may_quote_commas_quotes_and_line_breaks() {
        let csv =
            "answers,prompt,position,token,top1_a,top1_b,gap_a,gap_b,a_top2_in_b,b_top2_in_a\n\
                   cuda,7,0,\"a,\"\"b\"\"\",\"\n\",x,1.5,2,,0.5\r\n";
        let answers = parse(csv);
        let p = &answers[0].positions[0];
        assert_eq!(p.token, "a,\"b\"");
        assert_eq!(p.top1, ["\n".to_string(), "x".to_string()]);
        assert_eq!(p.gap_in_other, [None, Some(0.5)]);
    }

    /// The analysis behind the committed `results.json` of the scored runs.
    #[test]
    #[ignore = "reads SPLIT_MARGIN_SCORED and writes results.json beside it"]
    fn writes_the_scored_margin_results() {
        let path = std::path::PathBuf::from(
            std::env::var("SPLIT_MARGIN_SCORED").expect("SPLIT_MARGIN_SCORED"),
        );
        let report = analyse(&parse(&std::fs::read_to_string(&path).unwrap()));
        std::fs::write(
            path.with_file_name("results.json"),
            serde_json::to_string_pretty(&report).unwrap() + "\n",
        )
        .unwrap();
    }
}
