#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run one GGUF, greedy, on several honest configurations of one llama-server
# build, and keep every token's logprob and its top 5 alternatives (#155).
#
#   measure.sh <llama-server> <gguf> <label> <out-dir> <max-tokens> name=flag,flag,... ...
#
# e.g. measure.sh build/bin/llama-server qwen.gguf qwen2.5-0.5b-q8_0 raw 384 \
#        metal=-ngl,99 cpu-t6=-dev,none,-ngl,0,-t,6
#
# Each configuration writes <out-dir>/<label>.<name>.json; one already
# written is skipped. The analysis is the plugin's ignored test
# `referee::margin_measurement::writes_the_margin_measurement_results`
# (SPLIT_MARGIN_RAW=<out-dir>), which writes results.json here.
set -euo pipefail
server=$1 model=$2 label=$3 out=$4 max_tokens=$5
shift 5
here=$(cd "$(dirname "$0")" && pwd)
port=${PORT:-18931}
mkdir -p "$out"
for spec in "$@"; do
  name=${spec%%=*}
  IFS=, read -r -a flags <<< "${spec#*=}"
  target="$out/$label.$name.json"
  if [ -e "$target" ]; then echo "skip $target: already measured" >&2; continue; fi
  "$server" -m "$model" --port "$port" -c 4096 -np 1 --no-warmup --seed 0 "${flags[@]}" \
    > "$out/$label.$name.log" 2>&1 < /dev/null &
  pid=$!
  trap 'kill $pid 2>/dev/null || true' EXIT
  for _ in $(seq 600); do
    curl -fs "http://127.0.0.1:$port/health" > /dev/null 2>&1 && break
    kill -0 "$pid" 2> /dev/null || { echo "server exited" >&2; exit 1; }
    sleep 1
  done
  runs="$out/$label.$name.runs"
  : > "$runs"
  jq -c '.prompts[]' "$here/prompts.json" | while read -r prompt; do
    jq -n --argjson p "$prompt" --argjson n "$max_tokens" '{
      messages: [{role: "user", content: $p}], temperature: 0, seed: 0, max_tokens: $n,
      logprobs: true, top_logprobs: 5, cache_prompt: false,
      chat_template_kwargs: {enable_thinking: false}}' |
      curl -fs --max-time 600 -H 'Content-Type: application/json' -d @- \
        "http://127.0.0.1:$port/v1/chat/completions" |
      jq -c --argjson p "$prompt" '{prompt: $p, tokens: [.choices[0].logprobs.content[] |
        {token, logprob, top: [.top_logprobs[] | [.token, .logprob]]}]}' >> "$runs"
    echo "$label.$name: $(tail -1 "$runs" | jq '.tokens | length') tokens" >&2
  done
  kill "$pid"; wait "$pid" 2> /dev/null || true
  trap - EXIT
  jq -s --arg model "$(basename "$model")" --arg label "$label" --arg config "$name" \
    --arg flags "${spec#*=}" --argjson n "$max_tokens" \
    '{model: $model, label: $label, config: $config, flags: ($flags | split(",") | map(select(. != ""))),
      max_tokens: $n, runs: .}' "$runs" > "$target"
  rm "$runs"
done
