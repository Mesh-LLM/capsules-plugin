# Split-margin measurement (#155)

This is where `SPLIT_MARGIN_THRESHOLD_NATS` (`crates/evidence-plugin/src/referee/verdict.rs`) comes from.

The question it answers: on honest nodes serving the same weights, how far can a backend move the gap between the top two next tokens? A referee's word names a twin only when its own gap at the split is wider than any such move.

## What was run (2026-10-30)

- **Build:** `llama-server`, built from mesh-llm's patched llama.cpp (`.deps/llama.cpp` at `94682e7`, which holds Skippy's patches on upstream `620d222`). These are the same ggml kernels Skippy serves with.
- **Request:** chat completions at temperature 0 and seed 0, with `logprobs` and `top_logprobs: 5`, no prompt cache, and thinking off.
- **Prompts:** the 24 in `prompts.json`, which are the referee corpus's prompt plus long generations.
- **Answer length:** 384 tokens for the 0.5B models, 256 for the 9B.

| Machine | Backends and settings |
| --- | --- |
| Apple M5 Pro laptop | Metal (default; ubatch 64; flash attention off), ARM CPU (6 and 12 threads; ubatch 64) |
| GCP c3-standard-8 VM, Intel Xeon Platinum 8481C (AVX-512) | x86 CPU (4 and 8 threads; ubatch 64) |

| Model | File (sha256) | Backends |
| --- | --- | --- |
| Qwen2.5-0.5B-Instruct Q8_0 | Hugging Face `Qwen/Qwen2.5-0.5B-Instruct-GGUF` (`ca59ca7f…`) | Mac Metal, Mac CPU, x86 CPU |
| Qwen2.5-0.5B-Instruct Q4_K_M | Hugging Face `Qwen/Qwen2.5-0.5B-Instruct-GGUF` | Mac Metal, Mac CPU |
| Qwen3.5-9B Q4_K_M | Hugging Face `unsloth/Qwen3.5-9B-GGUF` | Mac Metal, Mac CPU |

To reproduce, from the repository root, run `measure.sh` once per model, then the plugin's analysis:

```
vectors/parity/referee/margin-measurement/measure.sh <llama-server> <gguf> <label> raw <max-tokens> metal=-ngl,99 cpu-t6=-dev,none,-ngl,0,-t,6 ...
SPLIT_MARGIN_RAW="$PWD/raw" cargo test --manifest-path crates/evidence-plugin/Cargo.toml --bin capsules writes_the_margin_measurement_results -- --ignored
```

The analysis is `crates/evidence-plugin/src/referee/margin_measurement.rs`. It writes `results.json` here. The raw runs (about 1.6 MB per configuration) are not committed. `results.json` is their analysis, every split included.

## What it shows (`results.json`)

- **The same backend with the same thread count is bit-identical**, whatever the batch size: drift 0, no splits.
- **Splits are common across backends.** Metal against CPU split in 20 to 22 of 24 prompts. Even two CPU thread counts split in 8 to 12. The largest margin seen at an honest split is **0.648 nats** (9B, CPU against Metal).
- **Drift by gap.** A drift matters only where it can flip the choice, that is where it reaches the gap itself; a near-certain token (gap 15 nats) can drift by 4.8 nats and still not flip.

  | Model | Largest drift where gap < 0.5 | gap < 3 | gap < 8 | Any gap |
  | --- | --- | --- | --- | --- |
  | Qwen2.5-0.5B Q8_0 (with x86) | 0.38 | 0.58 | 0.58 | 0.63 |
  | Qwen2.5-0.5B Q4_K_M | 0.50 | 0.55 | 0.60 | 0.60 |
  | Qwen3.5-9B Q4_K_M | 1.18 | 1.18 | 1.40 | 4.76 |

- **Positions not read.** A position is skipped when two of its top-5 tokens share a text (they cannot be told apart by text) or when the other run's top 5 lacks one of this run's top 2: 60 of 201,260 on the 0.5B Q8_0, none on the 0.5B Q4_K_M, 115 of 35,144 on the 9B (`positions_skipped` per pair).
- **The old drift rule.** The least T from which on every T' is at least twice the largest drift among positions whose gap is under T' comes out at **2.37 nats** (9B), 1.11 (0.5B Q4_K_M) and 0.8 (0.5B Q8_0). It is replaced by "The rule" below: on the CUDA data it asks for 19.19, set by one 9.6-nat drift on a 19-nat gap that could never flip a choice.

## CUDA against CPU: scored runs (`cuda-cpu/`)

Virgile-pct measured CUDA (RTX 4070 Ti) against CPU (Ryzen 7 7800X3D) on Qwen3-8B Q4_K_M (the file of Mesh-LLM/mesh-llm#2548), on #159:

- 194 prompts, greedy answers of at most 200 tokens generated on CUDA, on CPU and (prompts 0 to 47) on a second x86 CPU: 436 answers.
- Every answer scored by both referees, CUDA and CPU, on the same answer tokens, so both always share the context: one row per answer position, 81,249 rows, with each referee's top-1 token, its top-2 gap, and the same two tokens' gap read in the other referee.
- The data, the tool that made it (`genscore.cpp`, on the llama.cpp C API with mesh-llm's patches) and its README are the gist [`Virgile-pct/798f1fcd`](https://gist.github.com/Virgile-pct/798f1fcd3fdc90704d39175dd3ff08ae), commit `086ed7303e39e16aae63914dbbd7262329ff3e3b`; `qwen3-8b-q4km_cuda-vs-cpu_positions.csv` has sha256 `c54617a67caec21618ec867c1720d0701ca4c41a5fc0a2464ab067aec124de1a`. It is not copied here.

`cuda-cpu/results.json` is the plugin's analysis of that file (`crates/evidence-plugin/src/referee/margin_scored.rs`); from the repository root:

```
SPLIT_MARGIN_SCORED="$PWD/vectors/parity/referee/margin-measurement/cuda-cpu/qwen3-8b-q4km_cuda-vs-cpu_positions.csv" cargo test --manifest-path crates/evidence-plugin/Cargo.toml --bin capsules writes_the_scored_margin_results -- --ignored
```

with the CSV downloaded there first. It shows:

- **1,696 top-1 disagreements** between the two referees (737 on the CUDA answers, 771 on the CPU ones, 188 on the second CPU's).
- **The largest margin a referee read at one, over the word window, is 2.202012 nats** (CPU referee, CUDA answer, prompt 154, position 71). Per token alone it is 3.33 (a dash whose word began at a near-tie, which the window reads instead).
- Not used: reads where the two texts differ only in whitespace (68), where a window token was not that referee's own top-1 (34), and 37 reads whose split token cuts a UTF-8 character, whose own gaps (at most 0.40) bound them. 112 reads stop at the split token, since the other side's token runs on: those are upper bounds.
- **No gap of 4.41 nats or more shrinks by 4.41 between the two referees** at gaps up to 8.82 (the largest is 3.32), and no gap of at least 4.41 flips.

## The rule

The value T must satisfy both, on every backend pair measured:

1. T is at least twice the largest margin a referee reads, over the word window (as `least_margin` reads it), at any top-1 disagreement between honest backends.
2. No gap of at least T is seen to shrink, from one honest backend to another, by T or more below 2T, nor by its whole size anywhere.

The first bounds what an honest split can look like to a referee; the second, how far a confident choice moves between honest backends. Sherlock2 set it on #159 after the old drift rule failed on the CUDA data.

## The value: 4.41 nats

- **CUDA against CPU** (scored runs): the rule asks for 4.41 (twice 2.202012, to 0.01 nat up). The shrink part holds at 4.41 (3.32 below 8.82, no flip).
- **Metal and CPU** (the generation runs above): the first part holds, since the widest honest split margin is 0.648 (per token, which bounds the word window). The second part is shown only up to a gap of 8 nats, where the largest drift is 1.40 (`under_8`), and no gap of at least 4.41 flips, since every drift above 1.40 sits at a gap of 8 or more and the largest drift at any gap is 4.76. `results.json` does not report the band from 8 to 8.82 on its own, and the raw runs are not committed, so a drift of 4.41 or more there is not ruled out: adding 8.82 to `BOUNDS` in `margin_measurement.rs`, then rerunning `measure.sh` and `writes_the_margin_measurement_results`, settles it.
- **What it catches** (Virgile-pct's count on the same file, CUDA referee, first split per answer, word window, of 194 prompts): Q2_K 43 (40 to 43: three are upper bounds), Q3_K_M 7, Q4_K_S 1. The counts are the same at 4.4 and 4.41.
- **What it costs.** A split at a token whose gap is under 4.41 nats is never charged: 42 % of the referee positions in the CUDA file (68,842 of 162,498). A near-identical model (another quantization of the same weights) mostly comes out `inconclusive`; telling those apart needs many tokens pooled (Mesh-LLM/mesh-llm#2548). The twin referee catches only confident divergences.
- **Only these models are measured:** dense families, 9B and under, at Q4_K_M and Q8_0, on Metal, CUDA and CPU. Metal against CUDA directly, larger or mixture-of-experts models, and runs generated by Skippy itself are not. For those, rerun one of the measurements above and raise the value if the rule asks for more. A change is a CHANGELOG line.
