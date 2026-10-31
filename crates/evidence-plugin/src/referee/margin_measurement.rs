//! The analysis behind `SPLIT_MARGIN_THRESHOLD_NATS` (#155): how far honest
//! backends move the top-2 gap, from the raw runs
//! `vectors/parity/referee/margin-measurement/measure.sh` writes.
//!
//! For every pair of configurations of one model, along the tokens both runs
//! share (same context, so the same question), it compares at each position
//! the gap between one run's top-2 tokens `(t1, t2)`, `logprob(t1) -
//! logprob(t2)`, in both runs, when the other run's top 5 holds both: that
//! change is the drift. It stops at the first token the runs chose
//! differently, the split, and records each run's own margin there.
//!
//! A drift only matters where it can flip the choice, that is where it is at
//! least the gap itself: a 4-nat drift of a 15-nat gap changes nothing. So
//! the drift is also reported by the gap it moved (`gap_drift_by_margin`),
//! and the threshold rule (Sherlock2's note on #155) is the least T from
//! which on every T' is at least twice the largest drift among positions
//! whose gap is under T' (`threshold_2x_self_consistent`). The largest split margin is reported
//! beside it, never the basis alone.
//!
//! `writes_the_margin_measurement_results` (ignored) reads the raw runs from
//! `SPLIT_MARGIN_RAW` and writes `results.json` there.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Map, Value};

/// How many alternatives per token the runs read.
const TOP: usize = 5;
/// The gap bounds `gap_drift_by_margin` reports under.
const BOUNDS: [f64; 7] = [0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 8.0];

fn round6(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

/// One sampled token: its text and its top alternatives `(text, logprob)`.
struct Token {
    token: String,
    top: Vec<(String, f64)>,
}

struct Run {
    prompt: String,
    tokens: Vec<Token>,
}

struct Config {
    label: String,
    model: String,
    config: String,
    flags: Value,
    max_tokens: Value,
    runs: Vec<Run>,
}

fn parse(raw: &Value) -> Config {
    let text = |v: &Value| v.as_str().expect("a string").to_string();
    let runs = raw["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .map(|run| Run {
            prompt: text(&run["prompt"]),
            tokens: run["tokens"]
                .as_array()
                .expect("tokens")
                .iter()
                .map(|t| Token {
                    token: text(&t["token"]),
                    top: t["top"]
                        .as_array()
                        .expect("top")
                        .iter()
                        .map(|c| (text(&c[0]), c[1].as_f64().expect("a logprob")))
                        .collect(),
                })
                .collect(),
        })
        .collect();
    Config {
        label: text(&raw["label"]),
        model: text(&raw["model"]),
        config: text(&raw["config"]),
        flags: raw["flags"].clone(),
        max_tokens: raw["max_tokens"].clone(),
        runs,
    }
}

#[derive(Default)]
struct Skipped {
    shared_text: usize,
    not_in_other_top: usize,
}

/// Drifts `(gap, drift)` and the split, if any, between two runs of one
/// prompt, counting the positions not read.
fn compare(a: &Run, b: &Run, skipped: &mut Skipped) -> (Vec<(f64, f64)>, Option<Value>) {
    let distinct =
        |t: &Token| t.top.iter().map(|(s, _)| s).collect::<HashSet<_>>().len() == t.top.len();
    let mut drifts = Vec::new();
    for (i, (ta, tb)) in a.tokens.iter().zip(&b.tokens).enumerate() {
        for (own, other) in [(ta, tb), (tb, ta)] {
            // Two token ids can share a text; such a position is ambiguous
            // by text, so it is not read.
            if !distinct(own) || !distinct(other) {
                skipped.shared_text += 1;
                continue;
            }
            let theirs: HashMap<&str, f64> =
                other.top.iter().map(|(s, l)| (s.as_str(), *l)).collect();
            let ((t1, l1), (t2, l2)) = (&own.top[0], &own.top[1]);
            match (theirs.get(t1.as_str()), theirs.get(t2.as_str())) {
                (Some(o1), Some(o2)) => drifts.push((l1 - l2, ((l1 - l2) - (o1 - o2)).abs())),
                _ => skipped.not_in_other_top += 1,
            }
        }
        if ta.token != tb.token {
            let margin = |t: &Token| round6(t.top[0].1 - t.top[1].1);
            let split = json!({
                "position": i,
                "tokens": [ta.token, tb.token],
                "margins": [margin(ta), margin(tb)],
                "prompt": a.prompt.chars().take(60).collect::<String>(),
            });
            return (drifts, Some(split));
        }
    }
    (drifts, None)
}

/// The largest drift among positions whose gap is under `bound`.
fn max_under(points: &[(f64, f64)], bound: f64) -> f64 {
    points
        .iter()
        .filter(|(gap, _)| *gap < bound)
        .map(|(_, d)| *d)
        .fold(0.0, f64::max)
}

/// The least T, to 0.01 nat, from which on every T' is at least twice the
/// largest drift over gaps under T' (up to 100 nats): no T' at or above it
/// has a drift of a gap under it that comes within half of T'.
fn self_consistent(points: &[(f64, f64)]) -> Option<f64> {
    let holds = |k: u32| {
        let t = f64::from(k) / 100.0;
        t >= 2.0 * max_under(points, t)
    };
    let top = 10_000;
    if !holds(top) {
        return None;
    }
    let mut least = top;
    while least > 1 && holds(least - 1) {
        least -= 1;
    }
    Some(f64::from(least) / 100.0)
}

/// The nearest-rank quantile of `values`.
fn quantile(values: &[f64], q: f64) -> f64 {
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    ordered
        .get(((q * ordered.len() as f64) as usize).min(ordered.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0.0)
}

fn by_margin(points: &[(f64, f64)]) -> Value {
    BOUNDS
        .iter()
        .map(|b| (format!("under_{b}"), json!(round6(max_under(points, *b)))))
        .collect::<Map<_, _>>()
        .into()
}

/// The report over every raw run given.
pub(crate) fn analyse(raw: &[Value]) -> Value {
    let mut by_label: BTreeMap<String, Vec<Config>> = BTreeMap::new();
    for config in raw.iter().map(parse) {
        by_label
            .entry(config.label.clone())
            .or_default()
            .push(config);
    }
    let (mut every, mut worst_drift, mut worst_split) = (Vec::new(), 0.0_f64, 0.0_f64);
    let mut models = Vec::new();
    for (label, mut configs) in by_label {
        configs.sort_by(|a, b| a.config.cmp(&b.config));
        let mut pairs = Vec::new();
        for (i, a) in configs.iter().enumerate() {
            for b in &configs[i + 1..] {
                let (mut gaps, mut splits, mut skipped, mut identical) =
                    (Vec::new(), Vec::new(), Skipped::default(), 0);
                for (ra, rb) in a.runs.iter().zip(&b.runs) {
                    let (d, split) = compare(ra, rb, &mut skipped);
                    gaps.extend(d);
                    identical += usize::from(split.is_none() && ra.tokens.len() == rb.tokens.len());
                    splits.extend(split);
                }
                let drifts: Vec<f64> = gaps.iter().map(|(_, d)| *d).collect();
                let split_max = splits
                    .iter()
                    .flat_map(|s| {
                        s["margins"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter_map(Value::as_f64)
                    })
                    .fold(0.0, f64::max);
                let drift_max = round6(drifts.iter().copied().fold(0.0, f64::max));
                worst_drift = worst_drift.max(drift_max);
                worst_split = worst_split.max(split_max);
                pairs.push(json!({
                    "configs": [a.config, b.config],
                    "prompts": a.runs.len(),
                    "prompts_identical": identical,
                    "positions_compared": gaps.len(),
                    "positions_skipped": {
                        "shared_text": skipped.shared_text,
                        "not_in_other_top": skipped.not_in_other_top,
                    },
                    "gap_drift_max": drift_max,
                    "gap_drift_p999": round6(quantile(&drifts, 0.999)),
                    "gap_drift_p99": round6(quantile(&drifts, 0.99)),
                    "gap_drift_by_margin": by_margin(&gaps),
                    "threshold_2x_self_consistent": self_consistent(&gaps),
                    "split_count": splits.len(),
                    "split_margin_max": split_max,
                    "splits": splits,
                }));
                every.extend(gaps);
            }
        }
        models.push(json!({
            "label": label,
            "model": configs[0].model,
            "configs": configs.iter().map(|c| (c.config.clone(), c.flags.clone())).collect::<Map<_, _>>(),
            "max_tokens": configs[0].max_tokens,
            "pairs": pairs,
        }));
    }
    json!({
        "unit": "nats",
        "top_k_read": TOP,
        "models": models,
        "gap_drift_max": worst_drift,
        "split_margin_max": worst_split,
        "gap_drift_by_margin": by_margin(&every),
        "threshold_2x_self_consistent": self_consistent(&every),
        "threshold_2x_any_gap": round6(2.0 * worst_drift),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(tokens: &[(&str, &[(&str, f64)])]) -> Value {
        json!({"prompt": "p", "tokens": tokens.iter().map(|(t, top)| json!({
            "token": t, "logprob": top[0].1,
            "top": top.iter().map(|(s, l)| json!([s, l])).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()})
    }

    fn config(name: &str, runs: Vec<Value>) -> Value {
        json!({"model": "m.gguf", "label": "m", "config": name, "flags": [], "max_tokens": 4, "runs": runs})
    }

    #[test]
    fn drift_is_read_along_the_shared_tokens_and_stops_at_the_split() {
        let a = config(
            "a",
            vec![run(&[
                ("x", &[("x", -0.1), ("y", -0.5)]),
                ("p", &[("p", -0.2), ("q", -0.3)]),
                ("z", &[("z", -0.1), ("w", -9.0)]),
            ])],
        );
        let b = config(
            "b",
            vec![run(&[
                ("x", &[("x", -0.1), ("y", -0.7)]),
                ("q", &[("q", -0.25), ("p", -0.26)]),
                ("w", &[("w", -0.1), ("z", -9.0)]),
            ])],
        );
        let report = analyse(&[a, b]);
        let pair = &report["models"][0]["pairs"][0];
        // Two positions read both ways; the third, after the split, never.
        assert_eq!(pair["positions_compared"], json!(4));
        assert_eq!(pair["split_count"], json!(1));
        assert_eq!(pair["splits"][0]["position"], json!(1));
        assert_eq!(pair["splits"][0]["margins"], json!([0.1, 0.01]));
        // At the split, p-q is 0.1 in a and -0.01 in b: a drift of 0.11. At
        // the first token, a gap of 0.4 moved to 0.6: 0.2, but on a wider gap.
        assert_eq!(pair["gap_drift_max"], json!(0.2));
        assert_eq!(report["gap_drift_by_margin"]["under_0.25"], json!(0.11));
        assert_eq!(report["gap_drift_by_margin"]["under_1"], json!(0.2));
        // Every T from 0.4 on is twice the drift of gaps under it (0.2 at
        // most); at 0.39 the 0.2 drift of the 0.6 gap is not under it, but
        // 0.11 is, and 0.39 >= 0.22, so the scan goes on down to 0.22. Below
        // it, the 0.11 drift of the 0.01 and 0.1 gaps is more than half.
        assert_eq!(report["threshold_2x_self_consistent"], json!(0.22));
    }

    #[test]
    fn ambiguous_positions_are_counted_not_read() {
        let a = config(
            "a",
            vec![run(&[
                ("x", &[("x", -0.1), ("x", -0.5)]),
                ("y", &[("y", -0.1), ("k", -3.0)]),
            ])],
        );
        let b = config(
            "b",
            vec![run(&[
                ("x", &[("x", -0.1), ("u", -0.5)]),
                ("y", &[("y", -0.1), ("v", -3.0)]),
            ])],
        );
        let pair = &analyse(&[a, b])["models"][0]["pairs"][0];
        assert_eq!(
            pair["positions_skipped"],
            json!({"shared_text": 2, "not_in_other_top": 2})
        );
        assert_eq!(pair["positions_compared"], json!(0));
    }

    /// The analysis behind the committed `results.json`.
    #[test]
    #[ignore = "reads SPLIT_MARGIN_RAW and writes results.json beside measure.sh"]
    fn writes_the_margin_measurement_results() {
        let dir =
            std::path::PathBuf::from(std::env::var("SPLIT_MARGIN_RAW").expect("SPLIT_MARGIN_RAW"));
        let mut paths: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        let raw: Vec<Value> = paths
            .iter()
            .map(|p| serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
            .collect();
        let out =
            crate::record_push_parity::parity_dir().join("referee/margin-measurement/results.json");
        std::fs::write(
            out,
            serde_json::to_string_pretty(&analyse(&raw)).unwrap() + "\n",
        )
        .unwrap();
    }
}
