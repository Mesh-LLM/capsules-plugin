#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tier 2: two unmodified mesh-llm nodes on this machine, each running the
# plugin. The provider serves the model; the requester serves nothing, joins
# the provider's mesh, and sends it chat completions over the mesh. A third
# node, the corroborator, joins afterwards, is party to no exchange, and asks
# each of the two for its half of one of them. Once all the nodes have
# stopped, the scenario checks (crates/evidence-plugin/src/two_node_e2e.rs)
# run over what each node wrote, and the History pages built from what each
# node's history-page route served are opened offline
# (web-ui/src/features/capsules/lib/history-page.e2e.test.ts).
#
# Usage: scripts/e2e-two-node.sh MESH_LLM_BIN PLUGIN_BIN MODEL_GGUF OUT_DIR
#
# Run from the repository root, on a machine that may load the model, with
# web-ui's dependencies installed (`pnpm install` in web-ui): the History
# pages the nodes served are opened by web-ui's own test runner. The node
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
  for pid in ${pids[@]+"${pids[@]}"}; do kill -TERM "$pid" 2>/dev/null || true; done
  # The plugin writes a checkpoint on shutdown: give it time.
  for _ in $(seq 60); do
    alive=0
    for pid in ${pids[@]+"${pids[@]}"}; do kill -0 "$pid" 2>/dev/null && alive=1; done
    [ "$alive" = 0 ] && break
    sleep 0.5
  done
  for pid in ${pids[@]+"${pids[@]}"}; do kill -KILL "$pid" 2>/dev/null || true; done
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
    for pid in ${pids[@]+"${pids[@]}"}; do
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
# history_page CONSOLE NAME: save what the node's history-page route serves,
# the body the Evidence page builds its saved History page from, as
# history-page-NAME.json.
history_page() {
  curl -fsS "http://127.0.0.1:$1/api/plugins/capsules/http/history-page" > "$out/history-page-$2.json"
}
history_page_answered() { history_page "$1" "$2" && jq -e '.outcome == "answered"' "$out/history-page-$2.json"; }
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

# A Service History counts closed periods and is answered at a period
# boundary. The policy's weekly periods would put a live run's boundary at the
# next Monday 00:00 UTC, so the plugin (built with the test-period-policy
# feature) is given two-minute periods from the same epoch: another
# definition, with its own digest. Both nodes read it, since the requester
# checks the answer against the definition it names.
E2E_PERIOD_S=120
export CAPSULES_TEST_PERIOD_LENGTH_S=$E2E_PERIOD_S
SERVICE_HISTORY=$(jq -cS --argjson n "$E2E_PERIOD_S" \
  '.period_policy.length_s = $n | .period_policy.min_length_s = $n' derivations/service-history-1.json \
  | tr -d '\n' | openssl dgst -sha256 -r | cut -d' ' -f1)
echo "service history definition at ${E2E_PERIOD_S}s periods: $SERVICE_HISTORY"

# Record push is on by default; set explicitly at both ends here (a node with it
# off does not take the other side's push either), so the run shows what a
# node holds once the host names the other side.
export CAPSULES_SHARE_RECORD_AT_COMPLETION=counterparty

# --- the provider: serves the model -----------------------------------------
# It cuts a checkpoint every 5 s once it has a record, so it has one to answer
# a history card under.
# A Service History is Standard History: with share_standard_history off it
# goes only to a proven counterparty, and the requester is a client node whose
# key the provider cannot hold. So the provider shares it with anyone here.
NODE_ENV=(CAPSULES_CHECKPOINT_CADENCE_SECONDS=5 CAPSULES_SHARE_STANDARD_HISTORY=on)
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

# --- the History page of a node with no checkpoint: its signed refusal ------
# Saved before anything is exchanged, so the requester has no checkpoint yet
# (join, next, checks the same). Checked once the run is over, with the
# History pages saved below, by two_node_e2e.rs and by web-ui's
# history-page.e2e.test.ts, which builds each page and opens it offline.
wait_for 60 "the requester's history-page route answers" history_page "$REQUESTER_CONSOLE" fresh

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
# The requester holds the provider's commitment first, so its ask records the
# policy a refusal would be checked against.
commitment_held() {
  tool "$REQUESTER_CONSOLE" mesh_commitment_fetch "$(jq -cn --arg p "$provider_id" '{peer_id: $p}')" \
    > "$out/provider-commitment.json" \
    && jq -e '.problems == []' "$out/provider-commitment.json"
}
wait_for 60 "the requester holds the provider's commitment" commitment_held
history_card() {
  tool "$REQUESTER_CONSOLE" mesh_evidence_request "$(jq -cn --arg p "$provider_id" '{peer_id: $p,
    request: {subject: {full_history: null}, coverage: {min_freshness: 1}, derivation: "history_card/1"}}')" \
    > "$out/history-card.json" \
    && jq -e '.verification.state == "artifact" and .answer.derivation == "history_card/1"' "$out/history-card.json"
}
wait_for 60 "the provider served its history card, verified under its key" history_card

# --- node to node: a Service History is declined off a period boundary and
# --- answered on one (PRD T6) ------------------------------------------------
# A Service History (docs/SERVICE-HISTORY.md) is a run of whole closed periods
# at one pinned anchor. The newest checkpoint is pinned first: off a period
# boundary it is a signed policy_declined, on one it is answered. Then a
# checkpoint on a boundary is waited for, a Service History is asked at it,
# and the card it embeds is compared with the direct history_card/1 answer
# at the same pin, byte for byte.
# checkpoint_pin KIND: the digest of the provider's newest checkpoint that is
# on a period boundary (KIND boundary), or its newest checkpoint (KIND newest),
# and its time.
checkpoint_pin() {
  python3 -I - "$(plugin_data provider)/ledger/checkpoints.jsonl" "$1" "$E2E_PERIOD_S" <<'PY'
import calendar, hashlib, json, sys, time
path, kind, period = sys.argv[1], sys.argv[2], int(sys.argv[3])
pin = None
for line in open(path):
    cp = json.loads(line)
    at = calendar.timegm(time.strptime(cp["timestamp"].split(".")[0].rstrip("Z"), "%Y-%m-%dT%H:%M:%S"))
    # The epoch, 2026-01-05T00:00:00Z, is a whole number of periods.
    if kind == "newest" or at % period == 0:
        pin = (hashlib.sha256(bytes.fromhex(cp["checkpoint_cose"])).hexdigest(), at)
if pin is None:
    sys.exit(1)
print(pin[0], pin[1])
PY
}
service_history_at() {
  tool "$REQUESTER_CONSOLE" mesh_evidence_request "$(jq -cn --arg p "$provider_id" --arg pin "$1" \
    --arg d "$SERVICE_HISTORY" '{peer_id: $p,
    request: {subject: {full_history: null}, coverage: {expected_pin: $pin}, derivation: $d}}')" \
    > "$2"
}
service_history_newest() {
  local pin at
  read -r pin at < <(checkpoint_pin newest) || return 1
  service_history_at "$pin" "$out/service-history.json" || return 1
  if [ $((at % E2E_PERIOD_S)) = 0 ]; then
    jq -e '.verification.state == "artifact"' "$out/service-history.json"
  else
    jq -e '.verification.state == "refusal" and .verification.reason == "policy_declined"' \
      "$out/service-history.json"
  fi
}
wait_for 60 "the provider answered or declined a Service History at its newest checkpoint, signed" service_history_newest

# A boundary comes within one period; the cadence cuts a checkpoint in its
# minute, with the boundary as its time.
boundary_checkpointed() { checkpoint_pin boundary > "$out/boundary-pin.txt"; }
wait_for $((E2E_PERIOD_S + 60)) "the provider cut a checkpoint on a period boundary" boundary_checkpointed
read -r boundary_pin _ < "$out/boundary-pin.txt"
service_history_at "$boundary_pin" "$out/service-history-boundary.json"
jq -e '.verification.state == "artifact" and (.verification.lines | length > 0)' \
  "$out/service-history-boundary.json" > /dev/null \
  || { echo "no Service History at the boundary checkpoint:" >&2; cat "$out/service-history-boundary.json" >&2; exit 1; }
tool "$REQUESTER_CONSOLE" mesh_evidence_request "$(jq -cn --arg p "$provider_id" --arg pin "$boundary_pin" \
  '{peer_id: $p, request: {subject: {full_history: null}, coverage: {expected_pin: $pin},
  derivation: "history_card/1"}}')" > "$out/history-card-boundary.json"
jq -e '.verification.state == "artifact"' "$out/history-card-boundary.json" > /dev/null \
  || { echo "no history card at the boundary checkpoint:" >&2; cat "$out/history-card-boundary.json" >&2; exit 1; }
# T6: the card inside the Service History is the direct card, byte for byte.
python3 -I - "$out/service-history-boundary.json" "$out/history-card-boundary.json" <<'PY'
import base64, hashlib, json, sys
def octets(path):
    # The envelope's byte fields are unpadded base64url.
    text = json.load(open(path))["answer"]["artifact"]
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
def jcs(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
history_octets, card_octets = octets(sys.argv[1]), octets(sys.argv[2])
history = json.loads(history_octets)
# Byte for byte: the direct card's octets are the embedded card's canonical
# form, and the History's digest of the card is the digest of those octets.
assert jcs(history["history_card"]) == card_octets, "the embedded card is not the direct card"
assert history["history_card_digest"] == hashlib.sha256(card_octets).hexdigest(), \
    "history_card_digest is not the digest of the direct card"
assert history["period_counts"]["periods"], "the Service History lists no closed period"
print("T6: the Service History embeds the direct history card, and lists",
      len(history["period_counts"]["periods"]), "closed period(s)")
PY

# --- the History page of each node, once it has checkpoints ---------------
# The requester shares only its card; the provider, which shares Standard
# History and now has a checkpoint on a period boundary, its Service History.
requester_checkpointed() { [ -s "$(plugin_data requester)/ledger/checkpoints.jsonl" ]; }
wait_for 120 "the requester has cut a checkpoint" requester_checkpointed
wait_for 30 "the requester's history-page route serves its card" history_page_answered "$REQUESTER_CONSOLE" requester
wait_for 30 "the provider's history-page route serves its history" history_page_answered "$PROVIDER_CONSOLE" provider

# --- the ask, recorded: one that nobody answers ends in a sealed absence ----
# Each ask above was sealed as evidence_request before it was sent. Now the
# requester asks a node that is not on the mesh. With its deadline already
# passed, the window closes 60 s after the ask is recorded (the minimum), and
# the requester then seals recorded_absence citing it. The tool call itself
# fails: nothing can be reached. The window does not wait for it.
unanswered_peer=$(printf '%064d' 7)
curl -sS --max-time 90 -X POST -H 'content-type: application/json' \
  "http://127.0.0.1:$REQUESTER_CONSOLE/api/plugins/capsules/tools/mesh_evidence_request" \
  -d "$(jq -cn --arg p "$unanswered_peer" \
  --arg d "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{peer_id: $p,
    request: {subject: {full_history: null}, coverage: {min_freshness: 1}, derivation: "history_card/1", deadline: $d}}')" \
  > "$out/unanswered.json" 2>&1 || true

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

absent() { grep -q '"recorded_absence"' "$(plugin_data requester)/ledger/capsules.jsonl"; }
wait_for 180 "the requester sealed the absence of its unanswered ask" absent

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
jq -cn 'first(inputs | select(.model_attestation.compute_attestation["x-mesh-poc-v1"].role? == "requested"))' \
  "$(plugin_data requester)/ledger/capsules.jsonl" > "$out/x-record.json"
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

# --- the provider binds its node key to its operator's Nostr key -----------
# join's ceremony, with a test Nostr key standing in for the operator's signer
# (crates/evidence-plugin/src/controller_binding_e2e_setup.rs): join with the
# operator's key returns the event to sign, and join with the signed event
# stores the binding. join refuses a binding of another node's key; the
# requester then finds the binding in the provider's commitment by its
# digest alone.
binding_setup() {
  (cd "$repo/crates/evidence-plugin" &&
    E2E_BINDINGS=$out cargo test --locked --bin capsules -- --ignored --exact \
      "controller_binding_e2e_setup::$1" > "$logs/setup-$1.log" 2>&1) \
    || { cat "$logs/setup-$1.log" >&2; return 1; }
}
binding_setup write_controller
tool "$PROVIDER_CONSOLE" join "$(jq -cn --arg c "$(cat "$out/controller.txt")" '{controller: $c}')" \
  > "$out/binding-begin.json"
jq -e '.controller_binding_ceremony.event' "$out/binding-begin.json" > "$out/ceremony-event.json"
binding_setup sign_event
tool "$PROVIDER_CONSOLE" join "$(jq -cn --slurpfile e "$out/signed-event.json" '{controller_event: $e[0]}')" \
  > "$out/binding-join.json"
code=$(curl -sS -o "$out/binding-refused.json" -w '%{http_code}' -X POST -H 'content-type: application/json' \
  -d "$(jq -cn --slurpfile b "$out/binding-other.json" '{controller_binding: $b[0]}')" \
  "http://127.0.0.1:$PROVIDER_CONSOLE/api/plugins/capsules/tools/join")
[ "$code" != 200 ] || { echo "join took a binding of another node's key" >&2; exit 1; }
fetched() {
  tool "$REQUESTER_CONSOLE" mesh_commitment_fetch "$(jq -cn --arg p "$provider_id" '{peer_id: $p}')" \
    > "$out/fetched-commitment.json" \
    && jq -e '.commitment.controller_binding.digest | type == "string"' "$out/fetched-commitment.json"
}
wait_for 60 "the requester fetched the provider's commitment, naming its binding" fetched

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
# Built with test-period-policy (CAPSULES_TEST_PERIOD_LENGTH_S is exported
# above), so the checks know the Service History definition the nodes ran.
cd "$repo/crates/evidence-plugin"
E2E_REQUESTER_DIR=$out/data/requester E2E_PROVIDER_DIR=$out/data/provider E2E_EXCHANGES=$EXCHANGES \
  E2E_JOIN_DIR=$out E2E_UNANSWERED_PEER=$unanswered_peer E2E_CORROBORATOR_DIR=$out/data/corroborator \
  cargo test --locked --bin capsules --features test-period-policy -- --ignored --test-threads=1 two_node_e2e::

# --- the History pages the live nodes served, built and opened offline ------
cd "$repo/web-ui"
E2E_HISTORY_PAGES=$out pnpm exec vitest run src/features/capsules/lib/history-page.e2e.test.ts
