#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tier 2: two unmodified mesh-llm nodes on this machine, each running the
# plugin. The provider serves the model; the requester serves nothing, joins
# the provider's mesh, and sends it chat completions over the mesh. A third
# node, the corroborator, joins afterwards, is party to no exchange, and asks
# each of the two for its half of one of them. Once the nodes have stopped,
# the scenario checks (crates/evidence-plugin/src/two_node_e2e.rs) run over
# what each node wrote.
#
# Usage: scripts/e2e-two-node.sh MESH_LLM_BIN PLUGIN_BIN MODEL_GGUF OUT_DIR
#
# Run from the repository root, on a machine that may load the model. The node
# logs go to OUT_DIR/logs with the mesh's invite token removed. The nodes'
# homes (their keys and the plugin's data) stay under OUT_DIR/nodes and are
# never printed.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 MESH_LLM_BIN PLUGIN_BIN MODEL_GGUF OUT_DIR" >&2
  exit 2
fi
mesh_llm=$(realpath "$1")
plugin=$(realpath "$2")
model=$(realpath "$3")
out=$4
repo=$(pwd)

EXCHANGES=${E2E_EXCHANGES:-3}
MODEL_NAME=e2e-model
PROVIDER_API=9401 PROVIDER_CONSOLE=9411
REQUESTER_API=9402 REQUESTER_CONSOLE=9412
CORROBORATOR_API=9403 CORROBORATOR_CONSOLE=9413

mkdir -p "$out/logs" "$out/nodes"
out=$(realpath "$out")
logs=$out/logs
pids=()
token=

node_home() { echo "$out/nodes/$1"; }
plugin_data() { echo "$(node_home "$1")/.local/share/capsules"; }

# The token lets anyone join the mesh while it runs; it never reaches a log
# anyone reads. Matched by value, wherever it appears.
redact_logs() {
  [ -n "$token" ] || return 0
  TOKEN=$token perl -pi -e 's/\Q$ENV{TOKEN}\E/<invite-token>/g' "$logs"/*.log
}

stop_nodes() {
  # Already stopped (bash 3.2 cannot expand an empty array under set -u).
  [ "${#pids[@]}" -gt 0 ] || return 0
  for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  # The plugin writes a checkpoint on shutdown: give it time.
  for _ in $(seq 60); do
    alive=0
    for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null && alive=1; done
    [ "$alive" = 0 ] && break
    sleep 0.5
  done
  for pid in "${pids[@]}"; do kill -KILL "$pid" 2>/dev/null || true; done
  pids=()
}

on_exit() {
  status=$?
  stop_nodes
  redact_logs
  if [ "$status" -ne 0 ]; then
    for log in "$logs"/*.log; do
      echo "::group::$(basename "$log") (last 80 lines)"
      tail -n 80 "$log"
      echo "::endgroup::"
    done
  fi
  exit "$status"
}
trap on_exit EXIT

# One node: its own HOME (mesh-llm keeps its key, config and sockets under
# it), and the plugin's data under the same HOME. The plugin reads its console
# settings from the same config file (MESH_LLM_CONFIG), per use; they are
# added with `setting` once the node runs, since mesh-llm refuses to start
# with settings it cannot check against an installed plugin's schema.
# NODE_ENV holds the node's extra environment.
NODE_ENV=()
start_node() {
  local name=$1 api=$2 console=$3
  shift 3
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

# wait_for SECONDS DESCRIPTION COMMAND...: retry COMMAND until it succeeds.
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
halves() {
  local file
  file=$(plugin_data "$1")/ledger/capsules.jsonl
  [ -f "$file" ] || { echo 0; return; }
  jq -c --arg r "$2" 'select(.model_attestation.compute_attestation["x-mesh-poc-v1"].role? == $r)' "$file" | wc -l
}
has_halves() { [ "$(halves "$1" "$2")" -ge "$EXCHANGES" ]; }
# node_key NODE: the node plugin's raw Ed25519 public key, hex.
node_key() {
  openssl pkey -pubin -in "$(plugin_data "$1")/keys/node-key.pub.pem" -outform DER \
    | tail -c 32 | od -An -v -tx1 | tr -d ' \n'
}
# setting NODE LINE: add a line to the node's [plugin.settings] (the last table).
setting() { printf '%s\n' "$2" >> "$(node_home "$1")/config.toml"; }
# tool CONSOLE OPERATION BODY: POST to one of the plugin's operations.
tool() {
  curl -fsS -X POST -H 'content-type: application/json' -d "$3" \
    "http://127.0.0.1:$1/api/plugins/capsules/tools/$2"
}
joined() { tool "$REQUESTER_CONSOLE" join '{}' > "$out/join-after.json" && jq -e '.joined == true' "$out/join-after.json"; }
# holds KIND: the provider, as the reporter, keeps the requester's record.
holds() { [ -f "$(plugin_data provider)/joins/$requester_id.$1.json" ]; }

# The referee step's two twins are test keys that both nodes' operators
# announce (crates/evidence-plugin/src/referee_e2e_setup.rs).
# setup TEST: run one of the referee step's setup tests.
setup() {
  (cd "$repo/crates/evidence-plugin" &&
    cargo test --locked --bin capsules -- --ignored --exact "referee_e2e_setup::$1" > "$logs/setup-$1.log" 2>&1) \
    || { cat "$logs/setup-$1.log" >&2; return 1; }
}
E2E_TWIN_KEYS=$out/twin-keys.json setup write_twin_keys
twin_keys=$(cat "$out/twin-keys.json")

# Record push is on by default; set explicitly at both ends here (a node with it
# off does not take the other side's push either), so the run shows what a
# node holds once the host names the other side.
export CAPSULES_SHARE_RECORD_AT_COMPLETION=counterparty

# --- the provider: serves the model -----------------------------------------
# It cuts a checkpoint every 5 s once it has a record, so it has one to answer
# a history card under.
NODE_ENV=(CAPSULES_CHECKPOINT_CADENCE_SECONDS=5)
start_node provider "$PROVIDER_API" "$PROVIDER_CONSOLE" --gguf "$model" --model "$MODEL_NAME"
wait_for 600 "the provider has loaded the model" status_field "$PROVIDER_CONSOLE" '.llama_ready == true'
token=$(status_field "$PROVIDER_CONSOLE" '.token')
provider_id=$(curl -fsS "http://127.0.0.1:$PROVIDER_CONSOLE/api/diagnostics/network" | jq -er '.node_id')
echo "provider node id: $provider_id"
# The provider is this mesh's reporter: it takes joins once its console names
# it (read per use, so no restart).
setting provider "join_reporter = \"$provider_id\""
# The requester accepts the provider's record under the provider's own key
# (its raw Ed25519 public key, hex). The provider cannot be given the
# requester's: a client node's id is new each time it starts.
provider_key=$(node_key provider)
[ ${#provider_key} = 64 ] || { echo "could not read the provider's public key" >&2; exit 1; }
CAPSULES_PEER_KEYS=$(jq -cn --arg id "$provider_id" --arg k "$provider_key" --argjson twins "$twin_keys" \
  '{($id): $k} + $twins')
export CAPSULES_PEER_KEYS
# The provider, as referee, names itself by its own key and checks each twin's
# half under that twin's key (read per use, so no restart).
setting provider "peer_keys = '$CAPSULES_PEER_KEYS'"

# --- the requester: serves nothing, joins the provider's mesh ---------------
# The provider is its reporter; it checks its join switch every second and
# cuts a checkpoint every 5 s once it has a record.
NODE_ENV=(CAPSULES_JOIN_REPORTER="$provider_id" CAPSULES_JOIN_TICK_MS=1000
  CAPSULES_CHECKPOINT_CADENCE_SECONDS=5)
start_node requester "$REQUESTER_API" "$REQUESTER_CONSOLE" --client --join "$token"
wait_for 300 "the requester can route to the provider's model" lists_model "$REQUESTER_API"
requester_id=$(curl -fsS "http://127.0.0.1:$REQUESTER_CONSOLE/api/diagnostics/network" | jq -er '.node_id')
echo "requester node id: $requester_id"
setting requester 'join_network = "on"'

# --- join on a fresh node: the first checkpoint is still missing ------------
tool "$REQUESTER_CONSOLE" join '{}' > "$out/join-before.json"
jq -e '.joined == false' "$out/join-before.json" > /dev/null \
  || { echo "join said a fresh node had joined" >&2; exit 1; }
wait_for 120 "the reporter holds the requester's signed join" holds join

# --- the exchanges: each asked of the provider by id ------------------------
for n in $(seq "$EXCHANGES"); do
  body=$(jq -cn --arg m "$MODEL_NAME" --arg p "Reply with the number $n and nothing else." \
    '{model: $m, messages: [{role: "user", content: $p}], max_tokens: 8, temperature: 0}')
  code=$(curl -sS -o "$out/response-$n.json" -D "$out/headers-$n.txt" -w '%{http_code}' \
    --max-time 120 -H 'content-type: application/json' -H "x-mesh-target: $provider_id" \
    -d "$body" "http://127.0.0.1:$REQUESTER_API/v1/chat/completions")
  served_by=$(tr -d '\r' < "$out/headers-$n.txt" | awk -F': ' 'tolower($1) == "x-mesh-served-by" {print $2}')
  echo "exchange $n: HTTP $code, served by ${served_by:-<not said>}"
  [ "$code" = 200 ] || { echo "exchange $n failed" >&2; exit 1; }
  [ "$served_by" = "$provider_id" ] || { echo "exchange $n was not served by the provider" >&2; exit 1; }
  if [ "$n" = 1 ]; then
    jq -cn --argjson q "$body" --slurpfile a "$out/response-1.json" \
      '{request_body: $q, response_body: $a[0]}' > "$out/first-exchange.json"
  fi
done

# --- each side seals its own half -------------------------------------------
wait_for 120 "the requester sealed $EXCHANGES requested halves" has_halves requester requested
wait_for 120 "the provider sealed $EXCHANGES served halves" has_halves provider served
holds_providers_record() {
  local file
  file=$(plugin_data requester)/ledger/received-capsules.jsonl
  [ -f "$file" ] && [ "$(wc -l < "$file")" -ge "$EXCHANGES" ]
}
wait_for 120 "the requester holds the provider's record of each exchange" holds_providers_record

# --- node to node: the requester asks the provider for its history card -----
# Answered by evidencebook's builder on the provider (evidencebook#35) and
# checked on the requester under the provider's announced key.
provider_checkpointed() { [ -s "$(plugin_data provider)/ledger/checkpoints.jsonl" ]; }
wait_for 120 "the provider has cut a checkpoint" provider_checkpointed
history_card() {
  tool "$REQUESTER_CONSOLE" mesh_evidence_request "$(jq -cn --arg p "$provider_id" '{peer_id: $p,
    request: {subject: {full_history: null}, coverage: {min_freshness: 1}, derivation: "history_card/1"}}')" \
    > "$out/history-card.json" \
    && jq -e '.verification.state == "artifact" and .answer.derivation == "history_card/1"' "$out/history-card.json"
}
wait_for 60 "the provider served its history card, verified under its key" history_card

# --- the referee: a twin pair put to the provider, its verdict on both chains
# The requester holds two twins' halves of the first exchange and puts the pair
# to the provider over the mesh; the provider's answer to that exchange is the
# referee answer. The provider signs the verdict, seals adjudication_issued,
# and delivers the verdict to the requester, which seals adjudication_received.
E2E_PROVIDER_DIR=$(plugin_data provider) E2E_REQUESTER_DIR=$(plugin_data requester) \
  E2E_FIRST_EXCHANGE=$out/first-exchange.json E2E_ADJUDICATE_REQUEST=$out/adjudicate.json \
  setup put_twin_halves_on_the_requester
tool "$REQUESTER_CONSOLE" mesh_evidence_request "$(jq -cn --arg p "$provider_id" \
  --slurpfile r "$out/adjudicate.json" '{peer_id: $p, request: $r[0], verify: false}')" > "$out/verdict.json"
jq -e '.adjudication_verdict == 1 and (.verdict_capsule.capsule_id | type == "string")' "$out/verdict.json" > /dev/null \
  || { echo "the provider issued no verdict:" >&2; cat "$out/verdict.json" >&2; exit 1; }
echo "referee verdict: $(jq -r .verdict "$out/verdict.json")"
tool "$PROVIDER_CONSOLE" deliver_adjudication "$(jq -cn --arg p "$requester_id" \
  --slurpfile v "$out/verdict.json" '{peer_id: $p, verdict_capsule: $v[0].verdict_capsule}')" > "$out/delivered.json"
jq -e '.status == "received"' "$out/delivered.json" > /dev/null \
  || { echo "the requester did not hold the verdict:" >&2; cat "$out/delivered.json" >&2; exit 1; }
sealed() { grep -q '"adjudication_received"' "$(plugin_data requester)/ledger/capsules.jsonl"; }
wait_for 30 "the requester sealed its adjudication_received record" sealed

# --- a third node corroborates one exchange with both sides -----------------
# The corroborator (Z) asks the requester (X) for its half of the run's first
# exchange, keyed on the client nonce X's record binds, then the provider (Y)
# for Y's half, and checks each answer under that node's key. It is given
# X's record and both nodes' keys; both nodes now run, so the requester's id
# is known. First with the provider declining (the default), then with it
# answering.
requester_key=$(node_key requester)
[ ${#requester_key} = 64 ] || { echo "could not read the requester's public key" >&2; exit 1; }
setting requester 'share_exchange_corroboration = "on"'
NODE_ENV=(CAPSULES_PEER_KEYS="$(jq -cn --arg p "$provider_id" --arg pk "$provider_key" \
  --arg r "$requester_id" --arg rk "$requester_key" '{($p): $pk, ($r): $rk}')")
start_node corroborator "$CORROBORATOR_API" "$CORROBORATOR_CONSOLE" --client --join "$token"
wait_for 300 "the corroborator has joined the mesh" lists_model "$CORROBORATOR_API"
jq -c 'select(.model_attestation.compute_attestation["x-mesh-poc-v1"].role? == "requested")' \
  "$(plugin_data requester)/ledger/capsules.jsonl" | head -n 1 > "$out/x-record.json"
# corroborate NAME Y_STATE: one historical reference, kept as NAME.json; it
# passes when X's half was obtained and the provider's outcome is Y_STATE.
corroborate() {
  tool "$CORROBORATOR_CONSOLE" historical_reference "$(jq -cn --arg x "$requester_id" \
    --arg y "$provider_id" --slurpfile rec "$out/x-record.json" '{x_peer: $x, x_record: $rec[0],
    ys: [{peer_id: $y, frame: {basis: "x_record_names_y"}}]}')" > "$out/$1.json" \
    && jq -e --arg s "$2" '.x.outcome.state == "half_obtained" and .ys[0].outcome.state == $s' \
      "$out/$1.json"
}
wait_for 60 "the provider declines, under its key" corroborate corroboration-declined signed_refusal
setting provider 'share_exchange_corroboration = "on"'
wait_for 60 "both halves agree, each under its node's key" corroborate corroboration-agreed agree

# --- join again after the first exchange: now it is complete ----------------
wait_for 120 "join on the requester says it has joined" joined

# --- the switch off: a signed leave -----------------------------------------
sed -i.bak 's/^join_network = "on"$/join_network = "off"/' "$(node_home requester)/config.toml"
wait_for 120 "the reporter holds the requester's signed leave" holds leave
left() { tool "$REQUESTER_CONSOLE" join '{}' | jq -e '.network.acknowledged.kind == "leave/1"'; }
wait_for 60 "the requester recorded the reporter's acknowledgement of its leave" left

stop_nodes

# --- the scenario checks, over copies of what each node wrote ---------------
mkdir -p "$out/data"
cp -a "$(plugin_data requester)" "$out/data/requester"
cp -a "$(plugin_data provider)" "$out/data/provider"
cp -a "$(plugin_data corroborator)" "$out/data/corroborator"
cd "$repo/crates/evidence-plugin"
E2E_REQUESTER_DIR=$out/data/requester E2E_PROVIDER_DIR=$out/data/provider E2E_EXCHANGES=$EXCHANGES \
  E2E_JOIN_DIR=$out E2E_CORROBORATOR_DIR=$out/data/corroborator \
  cargo test --locked --bin capsules -- --ignored --test-threads=1 two_node_e2e::
