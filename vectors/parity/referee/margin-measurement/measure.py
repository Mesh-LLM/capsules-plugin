#!/usr/bin/env python3
"""Measure how far honest backends move the referee's top-2 margin (#155).

Runs the same GGUF, greedy, on several honest configurations of one
llama-server build (Metal or CPU, thread counts, batch sizes, flash
attention), and compares them token by token. Standard library only.

    python3 -I measure.py run --server BIN --model GGUF --label NAME \
        --config metal=-ngl,99 --config cpu-t8=-dev,none,-t,8 ... --out DIR
    python3 -I measure.py analyse DIR... > results.json

`run` writes one raw file per configuration (every token's logprob and its
top 5 alternatives). `analyse` reads raw files of one model and reports, for
every pair of configurations:

- `gap_drift`: along the tokens both runs share (same context, so the same
  question), the change in the top-2 gap. At each position, take one run's
  top-2 tokens (t1, t2) and compare logprob(t1) - logprob(t2) in both runs,
  when the other run's top 5 holds both. A split at temperature 0 needs the
  drift at that position to exceed the referee's margin there, so its
  maximum bounds the margin an honest split can show.
- `splits`: every position where the two runs chose different tokens, with
  each run's own top-2 margin there (what a referee on that backend seals).

A drift only matters where it can flip the choice, that is where it is at
least the gap itself: a 4-nat drift of a 15-nat gap changes nothing. So the
drift is also reported by the gap it moved (`gap_drift_by_margin`: the
largest drift among positions whose gap is under each bound), and the
threshold rule (#155, Sherlock2's note) is the least T with T at least twice
the largest drift among positions whose gap is under T
(`threshold_2x_self_consistent`). The largest split margin is reported
beside it, never the basis alone.
"""

import argparse
import itertools
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

PROMPTS = pathlib.Path(__file__).with_name("prompts.json")
TOP = 5


def post(url, body, timeout=600):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def wait_healthy(url, proc, limit=600):
    start = time.time()
    while time.time() - start < limit:
        if proc.poll() is not None:
            raise SystemExit(f"server exited with {proc.returncode}")
        try:
            with urllib.request.urlopen(url + "/health", timeout=5) as resp:
                if resp.status == 200:
                    return
        except Exception:
            pass
        time.sleep(1)
    raise SystemExit("server did not become healthy")


def run(args):
    prompts = json.loads(PROMPTS.read_text())["prompts"]
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for spec in args.config:
        name, _, flags = spec.partition("=")
        flags = [f for f in flags.split(",") if f]
        target = out / f"{args.label}.{name}.json"
        if target.exists():
            print(f"skip {target}: already measured", file=sys.stderr)
            continue
        port = str(args.port)
        cmd = [args.server, "-m", args.model, "--port", port, "-c", "4096",
               "-np", "1", "--no-warmup", "--seed", "0", *flags]
        log = open(out / f"{args.label}.{name}.log", "w")
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        url = f"http://127.0.0.1:{port}"
        try:
            wait_healthy(url, proc)
            runs = []
            for prompt in prompts:
                body = {
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "seed": 0,
                    "max_tokens": args.max_tokens,
                    "logprobs": True,
                    "top_logprobs": TOP,
                    "cache_prompt": False,
                    "chat_template_kwargs": {"enable_thinking": False},
                }
                reply = post(url + "/v1/chat/completions", body)
                content = reply["choices"][0]["logprobs"]["content"]
                runs.append({
                    "prompt": prompt,
                    "tokens": [
                        {
                            "token": t["token"],
                            "logprob": t["logprob"],
                            "top": [[c["token"], c["logprob"]] for c in t["top_logprobs"]],
                        }
                        for t in content
                    ],
                })
                print(f"{args.label}.{name}: {len(content)} tokens", file=sys.stderr)
        finally:
            proc.terminate()
            proc.wait(timeout=60)
            log.close()
        target.write_text(json.dumps({
            "model": os.path.basename(args.model),
            "label": args.label,
            "config": name,
            "flags": flags,
            "max_tokens": args.max_tokens,
            "runs": runs,
        }))


def quantile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


BOUNDS = [0.25, 0.5, 1, 2, 3, 5, 8]


def self_consistent(points):
    """The least T (to 0.01 nat) with T >= 2 * max drift over gaps under T."""
    t = 0.01
    while t < 100:
        if t >= 2 * max((d for g, d in points if g < t), default=0.0):
            return round(t, 2)
        t += 0.01
    return None


def compare(ra, rb):
    """Drifts (gap, drift) and splits between two runs of one prompt."""
    drifts, splits = [], []
    for i, (ta, tb) in enumerate(zip(ra["tokens"], rb["tokens"])):
        for own, other in ((ta, tb), (tb, ta)):
            # Two token ids can share a text; such a position is ambiguous
            # by text, so it is not read.
            if len(set(tok for tok, _ in own["top"])) < len(own["top"]) or \
               len(set(tok for tok, _ in other["top"])) < len(other["top"]):
                continue
            top = dict(other["top"])
            (t1, l1), (t2, l2) = own["top"][0], own["top"][1]
            if t1 in top and t2 in top:
                drifts.append((l1 - l2, abs((l1 - l2) - (top[t1] - top[t2]))))
        if ta["token"] != tb["token"]:
            margin = lambda t: t["top"][0][1] - t["top"][1][1]
            splits.append({"position": i, "tokens": [ta["token"], tb["token"]],
                           "margins": [round(margin(ta), 6), round(margin(tb), 6)]})
            break
    return drifts, splits


def analyse(args):
    files = [json.loads(pathlib.Path(p).read_text()) for p in args.raw]
    by_label = {}
    for f in files:
        by_label.setdefault(f["label"], []).append(f)
    report = {"unit": "nats", "top_k_read": TOP, "models": []}
    worst_drift = worst_split = 0.0
    every = []
    for label, configs in sorted(by_label.items()):
        pairs = []
        for a, b in itertools.combinations(sorted(configs, key=lambda c: c["config"]), 2):
            drifts, splits = [], []
            identical = 0
            for ra, rb in zip(a["runs"], b["runs"]):
                d, s = compare(ra, rb)
                drifts += d
                splits += [dict(x, prompt=ra["prompt"][:60]) for x in s]
                identical += not s and len(ra["tokens"]) == len(rb["tokens"])
            split_margins = [m for s in splits for m in s["margins"]]
            every += drifts
            gaps, drifts = drifts, [d for _, d in drifts]
            pair = {
                "configs": [a["config"], b["config"]],
                "prompts": len(a["runs"]),
                "prompts_identical": identical,
                "positions_compared": len(drifts),
                "gap_drift_max": round(max(drifts, default=0.0), 6),
                "gap_drift_p999": round(quantile(drifts, 0.999) or 0.0, 6),
                "gap_drift_p99": round(quantile(drifts, 0.99) or 0.0, 6),
                "gap_drift_by_margin": {
                    f"under_{b}": round(max((d for g, d in gaps if g < b), default=0.0), 6)
                    for b in BOUNDS
                },
                "threshold_2x_self_consistent": self_consistent(gaps),
                "split_count": len(splits),
                "split_margin_max": round(max(split_margins, default=0.0), 6),
                "splits": splits,
            }
            worst_drift = max(worst_drift, pair["gap_drift_max"])
            worst_split = max(worst_split, pair["split_margin_max"])
            pairs.append(pair)
        report["models"].append({
            "label": label,
            "model": configs[0]["model"],
            "configs": {c["config"]: c["flags"] for c in configs},
            "max_tokens": configs[0]["max_tokens"],
            "pairs": pairs,
        })
    report["gap_drift_max"] = round(worst_drift, 6)
    report["split_margin_max"] = round(worst_split, 6)
    report["gap_drift_by_margin"] = {
        f"under_{b}": round(max((d for g, d in every if g < b), default=0.0), 6) for b in BOUNDS
    }
    report["threshold_2x_self_consistent"] = self_consistent(every)
    report["threshold_2x_any_gap"] = round(2 * worst_drift, 6)
    json.dump(report, sys.stdout, indent=1)
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--server", required=True)
    r.add_argument("--model", required=True)
    r.add_argument("--label", required=True)
    r.add_argument("--config", action="append", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--port", type=int, default=18931)
    r.add_argument("--max-tokens", type=int, default=384)
    a = sub.add_parser("analyse")
    a.add_argument("raw", nargs="+")
    args = parser.parse_args()
    run(args) if args.cmd == "run" else analyse(args)


if __name__ == "__main__":
    main()
