#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Admission between two real mesh-llm nodes (loop step 4, #64). The provider
# serves the model; the requester routes to it, and its admission hook decides
# each attempt. The run asserts, from the requester's own book:
#
#   1. its first attempt to the provider is GO (the default) and seals the
#      five rows, the card ones `not_read`, with the card asked for in the
#      background;
#   2. once the card is read, the next attempt is still GO (the rows decide
#      nothing), cites the card by commitment, and reads identity `pass` and
#      key age `fail` (the provider's key is minutes old);
#   3. restarted with the provider on its deny list, the requester refuses
#      the attempt (403) and seals a NO from the deny list, with its rows;
#      corroboration reads `pass`, from the provider's pushed half, which
#      the requester holds under the provider's key.
#
# It needs a mesh-llm with the OpenAI exchange lifecycle (Mesh-LLM/mesh-llm
# #2226): main, or a lab build. A release up to 0.78 has no admission hook, so
# CI's stock-release e2e can't run this.
#
# Usage: scripts/e2e-admission.sh MESH_LLM_BIN PLUGIN_BIN MODEL_GGUF OUT_DIR
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 MESH_LLM_BIN PLUGIN_BIN MODEL_GGUF OUT_DIR" >&2
  exit 2
fi
mesh_llm=$(realpath "$1")
plugin=$(realpath "$2")
model=$(realpath "$3")
out=$4

MODEL_NAME=e2e-model
PROVIDER_API=9421 PROVIDER_CONSOLE=9431
REQUESTER_API=9422 REQUESTER_CONSOLE=9432

mkdir -p "$out/logs" "$out/nodes"
out=$(realpath "$out")
logs=$out/logs
pids=()
token=

node_home() { echo "$out/nodes/$1"; }
# A node's chain and its checkpoints, in the capsules.jsonl and
# checkpoints.jsonl line formats, read from its shelf while it runs.
chain() { "$plugin" chain-lines --data-dir "$(node_home "$1")/.local/share/capsules" 2>/dev/null; }
checkpoints() { "$plugin" chain-checkpoints --data-dir "$(node_home "$1")/.local/share/capsules" 2>/dev/null; }

on_exit() {
  status=$?
  for pid in ${pids[@]+"${pids[@]}"}; do kill -TERM "$pid" 2>/dev/null || true; done
  sleep 3
  for pid in ${pids[@]+"${pids[@]}"}; do kill -KILL "$pid" 2>/dev/null || true; done
  if [ -n "$token" ]; then
    TOKEN=$token perl -pi -e 's/\Q$ENV{TOKEN}\E/<invite-token>/g' "$logs"/*.log
  fi
  if [ "$status" -ne 0 ]; then
    for log in "$logs"/*.log; do
      echo "--- $(basename "$log") (last 60 lines)"
      tail -n 60 "$log"
    done
  fi
  exit "$status"
}
trap on_exit EXIT

# start_node NAME API CONSOLE GRANT ARGS...: GRANT is extra TOML for the
# plugin's entry (the requester's admission grant).
start_node() {
  local name=$1 api=$2 console=$3 grant=$4
  shift 4
  local home
  home=$(node_home "$name")
  mkdir -p "$home"
  cat > "$home/config.toml" <<EOF
version = 1

[[plugin]]
name = "capsules"
enabled = true
command = "$plugin"
args = []
$grant
[plugin.settings]
EOF
  env ${NODE_ENV[@]+"${NODE_ENV[@]}"} HOME="$home" XDG_DATA_HOME="$home/.local/share" \
    MESH_LLM_CONFIG="$home/config.toml" \
    "$mesh_llm" serve --config "$home/config.toml" \
    --port "$api" --console "$console" --headless \
    --disable-iroh-relays --log-format json "$@" \
    > "$logs/$name.log" 2>&1 &
  pids+=("$!")
}

wait_for() {
  local seconds=$1 what=$2
  shift 2
  local deadline=$((SECONDS + seconds))
  until "$@" > /dev/null 2>&1; do
    for pid in "${pids[@]}"; do
      kill -0 "$pid" 2>/dev/null || { echo "a node exited while waiting for: $what" >&2; return 1; }
    done
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "timed out after ${seconds}s waiting for: $what" >&2
      return 1
    fi
    sleep 2
  done
  echo "ready: $what"
}

status_field() { curl -fsS "http://127.0.0.1:$1/api/status" | jq -er "$2"; }
lists_model() { curl -fsS "http://127.0.0.1:$1/v1/models" | jq -e --arg m "$MODEL_NAME" 'any(.data[]; .id == $m)'; }
has_checkpoint() { [ -n "$(checkpoints provider)" ]; }
chat() {
  curl -sS -o "$out/chat-$2.json" -w '%{http_code}' "http://127.0.0.1:$1/v1/chat/completions" \
    -H 'content-type: application/json' \
    -d "{\"model\":\"$MODEL_NAME\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hi.\"}],\"max_tokens\":8}"
}
# The requester's admission decisions, in ledger order.
decisions() {
  chain requester | jq -c '.model_attestation.compute_attestation.admission_decision // empty'
}
decision_count() { decisions | wc -l | tr -d ' '; }
# The plugin's log line once a card ask came back read (colors stripped).
card_read() { perl -pe 's/\e\[[0-9;]*m//g' "$logs/requester.log" | grep 'admission asked a peer for its history card' | grep -q 'card="read"'; }

# Each side pushes its half to the other at completion, so the requester holds
# the provider's half (the corroboration row).
export CAPSULES_SHARE_RECORD_AT_COMPLETION=counterparty

# --- the provider: serves the model, and has a checkpoint to answer under ----
NODE_ENV=(CAPSULES_CHECKPOINT_CADENCE_SECONDS=5)
start_node provider "$PROVIDER_API" "$PROVIDER_CONSOLE" "" --gguf "$model" --model "$MODEL_NAME"
wait_for 600 "the provider has loaded the model" status_field "$PROVIDER_CONSOLE" '.llama_ready == true'
token=$(status_field "$PROVIDER_CONSOLE" '.token')
provider_id=$(curl -fsS "http://127.0.0.1:$PROVIDER_CONSOLE/api/diagnostics/network" | jq -er '.node_id')
echo "provider node id: $provider_id"
# One exchange of its own, so it has a record and then a checkpoint: a node
# with neither has no history card to give.
[ "$(chat "$PROVIDER_API" provider-own)" = 200 ] || { echo "the provider's own exchange failed" >&2; exit 1; }
wait_for 60 "the provider has cut a checkpoint" has_checkpoint
provider_key=$(openssl pkey -pubin -in "$(node_home provider)/.local/share/capsules/keys/node-key.pub.pem" -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n')
[ ${#provider_key} = 64 ] || { echo "could not read the provider's public key" >&2; exit 1; }

# --- the requester: routes to the provider, admission granted ----------------
# It knows the provider's record key, so the card can verify (identity).
NODE_ENV=(RUST_LOG=capsules=info CAPSULES_PEER_KEYS="$(jq -cn --arg id "$provider_id" --arg k "$provider_key" '{($id): $k}')")
grant='
[plugin.openai_exchange_grant]
endpoints = ["chat_completions", "completions", "responses"]
phases = ["backend_selected"]
admission = true
deadline_ms = 2000
max_body_bytes = 1048576
max_queue_bytes = 4194304
max_in_flight = 32
failure_policy = "required"
'
start_node requester "$REQUESTER_API" "$REQUESTER_CONSOLE" "$grant" --client --join "$token"
wait_for 300 "the requester can route to the provider's model" lists_model "$REQUESTER_API"

# --- 1. the first attempt: GO, the rows sealed --------------------------------
code=$(chat "$REQUESTER_API" 1)
[ "$code" = 200 ] || { echo "the first request was refused: HTTP $code $(cat "$out/chat-1.json")" >&2; exit 1; }
first=$(decisions | head -n 1)
echo "first decision: $first"
echo "$first" | jq -e '.verdict == "GO" and .source == "default"
  and .reads[1] == {"kind": "history_card", "state": "not_read"}
  and (.rows | length) == 5 and (.rows[0] | {row, result}) == {"row": "identity", "result": "not_read"}
  and (has("limit") | not)' > /dev/null \
  || { echo "the first decision is not a GO with its rows sealed" >&2; exit 1; }

# --- 2. the card is read in the background; the next attempt cites it -------
wait_for 60 "the requester read the provider's history card" card_read
before=$(decision_count)
code=$(chat "$REQUESTER_API" 2)
[ "$code" = 200 ] || { echo "the second request was refused: HTTP $code $(cat "$out/chat-2.json")" >&2; exit 1; }
second=$(decisions | sed -n "$((before + 1))p")
echo "second decision: $second"
echo "$second" | jq -e '.verdict == "GO" and .source == "default"
  and .reads[1].kind == "history_card" and .reads[1].derivation == "history_card/1"
  and (.reads[1].commitment.digest | test("^[0-9a-f]{64}$"))
  and (.rows[0] | {row, result}) == {"row": "identity", "result": "pass"}
  and (.rows[1] | {row, result}) == {"row": "key_age", "result": "fail"}' > /dev/null \
  || { echo "the second decision is not a GO citing the card" >&2; exit 1; }
# --- 3. the provider on the deny list: NO, with its rows ---------------------
# The settings are read at start, so the requester restarts with the list.
held_half() { [ "$(chain requester | jq -c 'select(.model_attestation.compute_attestation.received_half.signature_ok == true)' | wc -l)" -gt 0 ]; }
wait_for 60 "the requester holds the provider's half" held_half
requester_pid=${pids[${#pids[@]}-1]}
kill -TERM "$requester_pid"
for _ in $(seq 60); do kill -0 "$requester_pid" 2>/dev/null || break; sleep 0.5; done
kill -KILL "$requester_pid" 2>/dev/null || true
unset 'pids[${#pids[@]}-1]'
mv "$logs/requester.log" "$logs/requester-1.log"
NODE_ENV+=(CAPSULES_ADMISSION_DENY="$provider_id")
start_node requester "$REQUESTER_API" "$REQUESTER_CONSOLE" "$grant" --client --join "$token"
wait_for 300 "the restarted requester can route to the provider's model" lists_model "$REQUESTER_API"
before=$(decision_count)
code=$(chat "$REQUESTER_API" 3)
[ "$code" = 403 ] || { echo "the denied request was not refused: HTTP $code $(cat "$out/chat-3.json")" >&2; exit 1; }
third=$(decisions | sed -n "$((before + 1))p")
echo "third decision: $third"
echo "$third" | jq -e '.verdict == "NO" and .source == "deny_list"
  and (.rows | length) == 5 and .reads[1].kind == "history_card"
  and (.rows[4] | {row, result}) == {"row": "corroboration", "result": "pass"}' > /dev/null \
  || { echo "the third decision is not a deny-list NO with its rows" >&2; exit 1; }

# The provider's id never appears in clear in the requester's admission records.
if decisions | grep -q "$provider_id"; then
  echo "an admission record names the provider in clear" >&2
  exit 1
fi
echo "PASS: GO with the rows sealed, GO citing the history card, then a deny-list NO with its rows, between two real nodes"
