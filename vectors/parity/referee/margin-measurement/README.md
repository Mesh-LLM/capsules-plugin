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
| Apple M5 Pro (Ethan's Mac) | Metal (default; ubatch 64; flash attention off), ARM CPU (6 and 12 threads; ubatch 64) |
| GCP c3-standard-8, Intel Xeon Platinum 8481C (AVX-512), lab VM `mc53-u755-payer`, own directory only, lab skip rule checked | x86 CPU (4 and 8 threads; ubatch 64) |

| Model | File (sha256) | Backends |
| --- | --- | --- |
| Qwen2.5-0.5B-Instruct Q8_0 | `ca59ca7f…` (the S08 demo's model) | Mac Metal, Mac CPU, x86 CPU |
| Qwen2.5-0.5B-Instruct Q4_K_M | Hugging Face `Qwen/Qwen2.5-0.5B-Instruct-GGUF` | Mac Metal, Mac CPU |
| Qwen3.5-9B Q4_K_M | Hugging Face `unsloth/Qwen3.5-9B-GGUF` | Mac Metal, Mac CPU |

To reproduce:

```
python3 -I measure.py run --server <llama-server> --model <gguf> --label <name> --out raw --config metal=-ngl,99 --config cpu-t6=-dev,none,-ngl,0,-t,6 ...
python3 -I measure.py analyse raw/*.json > results.json
```

The raw runs (about 1.6 MB per configuration) are not committed. `results.json` is their analysis, every split included.

## What it shows (`results.json`)

- **The same backend with the same thread count is bit-identical**, whatever the batch size: drift 0, no splits.
- **Splits are common across backends.** Metal against CPU split in 20 to 22 of 24 prompts. Even two CPU thread counts split in 8 to 12. The largest margin seen at an honest split is **0.648 nats** (9B, CPU against Metal).
- **Drift by gap.** A drift matters only where it can flip the choice, that is where it reaches the gap itself; a near-certain token (gap 15 nats) can drift by 4.8 nats and still not flip.

  | Model | Largest drift where gap < 0.5 | gap < 3 | gap < 8 | Any gap |
  | --- | --- | --- | --- | --- |
  | Qwen2.5-0.5B Q8_0 (with x86) | 0.38 | 0.58 | 0.58 | 0.63 |
  | Qwen2.5-0.5B Q4_K_M | 0.50 | 0.55 | 0.60 | 0.60 |
  | Qwen3.5-9B Q4_K_M | 1.18 | 1.18 | 1.40 | 4.76 |

- **The 2x rule.** The least T that is at least twice the largest drift among positions whose gap is under T comes out at **2.37 nats** (9B), 1.0 (0.5B Q4_K_M) and 0.8 (0.5B Q8_0).

## The value: 3.0 nats

- 3.0 is above the 2.37 the 2x rule needs on every backend measured. It is 2.5x the largest drift seen at any gap under 5 nats (1.18), and 4.6x the widest honest split margin (0.648).
- **CUDA is not measured here.** We had no GPU machine, and making one would be spend. Mesh-LLM/mesh-llm#2548 measured CUDA (RTX 4070 Ti, with batch, flash-attention and offload variants), CPU and Vulkan on Qwen3-8B Q4_K_M:
  - 96 to 98.7 % of top choices were identical across honest variants;
  - mean KL from the reference was 0.002 to 0.007 per token;
  - one honest CPU token reached KL 1.97.

  That shows the same picture: drift is mostly small, with rare large single tokens. The extra headroom above 2.37 is for that gap.
- Rerun `measure.py` on CUDA when a GPU box exists, add its output here, and raise the value if the rule asks for more. A change is a CHANGELOG line.
- **What it costs.** At 3.0 nats, a split at a token whose gap is under 3 nats is never charged. On the 9B that is about 41 % of positions (14,457 of 35,029 read), so a near-identical model (another quantization of the same weights) mostly comes out `inconclusive`. A single split cannot tell those apart; it needs many tokens pooled (Mesh-LLM/mesh-llm#2548). The twin referee catches only confident divergences.
