#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Check what this plugin does on a mesh-llm node, using only public pieces: a PUBLISHED release archive
# (checked against the release's SHA256SUMS), a mesh-llm binary you built from stock main (or any build you
# want to check), and a fresh HOME. No account, no credentials. Prints PASS/FAIL per check.
#
#   scripts/reviewer-check.sh --version 0.1.3 --mesh-llm /path/to/mesh-llm [--model model.gguf] [--keep]
#   scripts/reviewer-check.sh --archive local.tar.gz --mesh-llm ...   # a LOCAL archive, labelled as such
#   add --name capsule-emit-mesh for a release from before the plugin was renamed (0.1.2 and earlier)
#
# Needs: bash, curl, jq, sha256sum (or shasum), and strace (Linux) for the network check, which is NOT CHECKED
# without it (macOS has no strace: run it on Linux). With no --model it downloads
# SmolLM2-135M-Instruct Q8_0 (145 MB, pinned revision and SHA-256) into the work directory.
#
# Checks:
#   1. /v1/models is identical with the plugin disabled and running (same node, same HOME).
#   2. The plugin is absent from GET /api/plugins/providers and GET /api/plugins/endpoints.
#   3. Idle for 60 s (no requests): the plugin process opens no connection and sends no datagram to anything but
#      loopback (every connect/sendto, traced with strace, including name lookups), and writes no records or
#      checkpoints.
#   4. One chat request: exactly one record is sealed, and it holds digests, not the prompt or the answer.
#   5. Prints how to run mesh-llm's four Linux smokes against a node with this plugin installed.
set -uo pipefail

PLUGIN=capsules
REPO=Mesh-LLM/capsules
MODEL_URL=https://huggingface.co/unsloth/SmolLM2-135M-Instruct-GGUF/resolve/9e6855bc4be717fca1ef21360a1db4b29d5c559a/SmolLM2-135M-Instruct-Q8_0.gguf
MODEL_SHA256=c4a3dd037301b6ecea31d6da37f5cd793ead920dd5ddfe6d589294628d6ce66a
IDLE_SECONDS=${IDLE_SECONDS:-60}

usage() { sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
VERSION='' ARCHIVE='' MESH='' MODEL='' KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION=${2#v}; shift 2 ;;
    --archive) ARCHIVE=$2; shift 2 ;;
    --mesh-llm) MESH=$2; shift 2 ;;
    --model) MODEL=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --name) PLUGIN=$2; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$MESH" ] && [ -x "$MESH" ] || { echo "--mesh-llm must name an executable mesh-llm" >&2; exit 2; }
[ -n "$VERSION" ] || [ -n "$ARCHIVE" ] || { echo "give --version (published) or --archive (local)" >&2; exit 2; }
for tool in curl jq; do command -v $tool >/dev/null || { echo "needs $tool" >&2; exit 2; }; done
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/reviewer-check.XXXXXX")
H=$WORK/home; mkdir -p "$H"
FAILS=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
# A check that cannot be made is never a PASS: it is NOT CHECKED, and counts as a failure.
notchecked() { echo "NOT CHECKED  $*"; FAILS=$((FAILS + 1)); }
info() { echo "      $*"; }
NODE=''
cleanup() {
  [ -n "$NODE" ] && kill -TERM "$NODE" 2>/dev/null && sleep 3 && kill -KILL "$NODE" 2>/dev/null
  if [ "$KEEP" = 1 ]; then echo "work directory kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# ---- the archive: published (checked against SHA256SUMS) or local (labelled) ------------------------------
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TRIPLE=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) TRIPLE=aarch64-unknown-linux-gnu ;;
  Darwin-arm64) TRIPLE=aarch64-apple-darwin ;;
  *) echo "no release archive for $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
if [ -n "$ARCHIVE" ]; then
  echo "== LOCAL ARCHIVE (not a published release): $ARCHIVE  sha256 $(sha256 "$ARCHIVE")"
  LABEL=local
else
  NAME=$PLUGIN-$VERSION-$TRIPLE.tar.gz
  BASE=https://github.com/$REPO/releases/download/v$VERSION
  curl -fsSL -o "$WORK/$NAME" "$BASE/$NAME" || { echo "cannot download $BASE/$NAME" >&2; exit 1; }
  curl -fsSL -o "$WORK/SHA256SUMS" "$BASE/SHA256SUMS" || { echo "cannot download $BASE/SHA256SUMS" >&2; exit 1; }
  want=$(awk -v n="$NAME" '$2 == n {print $1}' "$WORK/SHA256SUMS")
  got=$(sha256 "$WORK/$NAME")
  if [ -n "$want" ] && [ "$want" = "$got" ]; then pass "archive $NAME matches the release's SHA256SUMS ($got)"
  else fail "archive $NAME does not match SHA256SUMS (want ${want:-missing}, got $got)"; exit 1; fi
  ARCHIVE=$WORK/$NAME LABEL=v$VERSION
fi

if [ -z "$MODEL" ]; then
  MODEL=$WORK/SmolLM2-135M-Instruct-Q8_0.gguf
  curl -fsSL -o "$MODEL" "$MODEL_URL" || { echo "cannot download the model" >&2; exit 1; }
  [ "$(sha256 "$MODEL")" = "$MODEL_SHA256" ] || { echo "model digest mismatch" >&2; exit 1; }
fi

# ---- a fresh HOME with the plugin installed ----------------------------------------------------------------
# No default-plugins step, so the node runs exactly this archive; XDG_DATA_HOME unset, so data lives in $H.
mesh() { env -u XDG_DATA_HOME HOME="$H" MESH_LLM_NO_DEFAULT_PLUGINS=1 "$MESH" "$@"; }
mesh plugins install --archive "$ARCHIVE" --name "$PLUGIN" --version "$LABEL" > "$WORK/install.log" 2>&1 \
  || { fail "plugin install (see $WORK/install.log)"; exit 1; }
echo "== mesh-llm: $("$MESH" --version 2>/dev/null | head -1)   plugin: $LABEL   HOME: $H"
DATA=$H/.local/share/$PLUGIN
lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
# Records and checkpoints, in either layout: a release with the shelf keeps them
# on its shelf (ledger/shelf.db), read with the plugin's own chain-lines and
# chain-checkpoints ($BIN, found below); an earlier one in the flat files.
records() {
  if [ -f "$DATA/ledger/shelf.db" ]; then "$BIN" chain-lines --data-dir "$DATA" 2>/dev/null | wc -l | tr -d ' '
  else lines "$DATA/ledger/capsules.jsonl"; fi
}
checkpoint_count() {
  if [ -f "$DATA/ledger/shelf.db" ]; then "$BIN" chain-checkpoints --data-dir "$DATA" 2>/dev/null | wc -l | tr -d ' '
  else lines "$DATA/ledger/checkpoints.jsonl"; fi
}

port() { echo $(( 20000 + RANDOM % 20000 )); }
API=$(port); CONSOLE=$(port)
# On Linux with strace, the node runs under `strace -ff`: every connect/sendto/sendmsg of every process and
# THREAD it starts is written to $WORK/trace.<thread id>, one file per thread, and every clone/fork too, so the
# plugin's threads (its async workers included) are found from its main thread. A short-lived connection is
# never missed.
TRACE=no
if [ "$(uname -s)" = Linux ] && command -v strace >/dev/null; then TRACE=yes; fi
TRACER=''
start() { # start LOG [trace]
  # Started through env (which execs), never a shell function, so $! is the node (or its tracer).
  if [ "${2:-}" = trace ] && [ "$TRACE" = yes ]; then
    env -u XDG_DATA_HOME HOME="$H" MESH_LLM_NO_DEFAULT_PLUGINS=1 \
      strace -ff -qq -ttt -e trace=connect,sendto,sendmsg,clone,clone3,fork,vfork,execve -o "$WORK/trace" \
      "$MESH" serve --port "$API" --console "$CONSOLE" --headless --log-format json --gguf "$MODEL" > "$1" 2>&1 &
    TRACER=$!
    T_START=$(date +%s.%6N)
    NODE=''
    for _ in $(seq 50); do NODE=$(cat "/proc/$TRACER/task/$TRACER/children" 2>/dev/null | awk '{print $1}'); [ -n "$NODE" ] && break; sleep 0.1; done
    [ -n "$NODE" ] || return 1
  else
    env -u XDG_DATA_HOME HOME="$H" MESH_LLM_NO_DEFAULT_PLUGINS=1 \
      "$MESH" serve --port "$API" --console "$CONSOLE" --headless --log-format json --gguf "$MODEL" > "$1" 2>&1 &
    NODE=$!
  fi
  for _ in $(seq 180); do
    curl -fsS "http://127.0.0.1:$CONSOLE/api/status" 2>/dev/null | jq -e '.llama_ready == true' >/dev/null 2>&1 && return 0
    kill -0 "$NODE" 2>/dev/null || return 1
    sleep 2
  done
  return 1
}
stop() {
  kill -TERM "$NODE" 2>/dev/null
  for _ in $(seq 40); do kill -0 "$NODE" 2>/dev/null || break; sleep 0.5; done
  kill -KILL "$NODE" 2>/dev/null; NODE=''
  if [ -n "$TRACER" ]; then for _ in $(seq 20); do kill -0 "$TRACER" 2>/dev/null || break; sleep 0.5; done; kill -KILL "$TRACER" 2>/dev/null; TRACER=''; fi
  # The next start must not find this node still answering on the same ports.
  for _ in $(seq 30); do curl -fsS "http://127.0.0.1:$CONSOLE/api/status" >/dev/null 2>&1 || return 0; sleep 1; done
  echo "the previous node is still answering on :$CONSOLE" >&2; exit 1
}
get() { curl -fsS "http://127.0.0.1:$1$2"; }

# A model list is valid only as JSON with a .data array; a failed request never compares equal to another.
models_ok() { jq -e '.data | type == "array"' "$1" >/dev/null 2>&1; }

# ---- 1. /v1/models, plugin disabled vs running ------------------------------------------------------------
mesh plugins disable "$PLUGIN" > "$WORK/disable.log" 2>&1 || info "plugins disable failed: $(tr '\n' ' ' < "$WORK/disable.log")"
start "$WORK/node-off.log" || { fail "node did not start with the plugin disabled (see $WORK/node-off.log)"; exit 1; }
sleep 5; get "$API" /v1/models > "$WORK/models-off.json" 2>/dev/null
off_status=$(get "$CONSOLE" /api/plugins 2>/dev/null | jq -r --arg n "$PLUGIN" '[.[] | select(.name == $n) | .status][0] // "absent"' 2>/dev/null)
info "plugin on the node in the off run: ${off_status:-unknown}"
stop
mesh plugins enable "$PLUGIN" > "$WORK/enable.log" 2>&1 || info "plugins enable failed: $(tr '\n' ' ' < "$WORK/enable.log")"
start "$WORK/node-on.log" trace || { fail "node did not start with the plugin enabled (see $WORK/node-on.log)"; exit 1; }
sleep 5; get "$API" /v1/models > "$WORK/models-on.json" 2>/dev/null
status=$(get "$CONSOLE" /api/plugins | jq -r --arg n "$PLUGIN" '.[] | select(.name == $n) | "\(.status) \(.version)"')
info "plugin on the node: ${status:-absent}"
RUNNING=no
if [ "${status%% *}" = running ]; then RUNNING=yes; pass "the plugin is running ($status)"
else fail "the plugin is not running (status: ${status:-absent}); checks 1-4 below are NOT CHECKED"; fi
if [ "$RUNNING" = no ]; then notchecked "1. /v1/models off vs on (the plugin never ran)"
elif [ "$off_status" != disabled ] && [ "$off_status" != absent ]; then notchecked "1. /v1/models off vs on (the off run's plugin was '$off_status', not disabled)"
elif ! models_ok "$WORK/models-off.json" || ! models_ok "$WORK/models-on.json"; then notchecked "1. /v1/models off vs on (a /v1/models answer was not a model list)"
elif cmp -s "$WORK/models-off.json" "$WORK/models-on.json"; then pass "/v1/models byte-identical, plugin disabled vs running"
elif diff <(jq -S 'del(.data[].created)' "$WORK/models-off.json") <(jq -S 'del(.data[].created)' "$WORK/models-on.json") >/dev/null; then
  pass "/v1/models identical, plugin disabled vs running (ignoring 'created')"
else fail "/v1/models differs: $(diff "$WORK/models-off.json" "$WORK/models-on.json" | grep '^[<>]' | head -3 | tr '\n' ' ')"; fi

# ---- 2. not a provider, not an endpoint -------------------------------------------------------------------
get "$CONSOLE" /api/plugins/providers > "$WORK/providers.json" 2>/dev/null; p_ok=$?
get "$CONSOLE" /api/plugins/endpoints > "$WORK/endpoints.json" 2>/dev/null; e_ok=$?
# Any string anywhere in either answer that names the plugin (alone or as "<plugin>:...").
names_plugin() { jq -e --arg n "$PLUGIN" '[.. | strings | select(. == $n or startswith($n + ":") or startswith("plugin:" + $n))] | length > 0' "$1" >/dev/null 2>&1; }
if [ "$RUNNING" = no ]; then notchecked "2. providers/endpoints (the plugin never ran)"
elif [ "$p_ok" != 0 ] || [ "$e_ok" != 0 ] || ! jq -e . "$WORK/providers.json" >/dev/null 2>&1 || ! jq -e . "$WORK/endpoints.json" >/dev/null 2>&1; then
  notchecked "2. providers/endpoints (a request failed or did not answer JSON)"
elif names_plugin "$WORK/providers.json" || names_plugin "$WORK/endpoints.json"; then fail "the plugin appears in /api/plugins/providers or /api/plugins/endpoints"
else pass "the plugin is absent from /api/plugins/providers and /api/plugins/endpoints"; fi
caps=$(get "$CONSOLE" /api/plugins | jq -c --arg n "$PLUGIN" '.[] | select(.name == $n) | .capabilities')
info "capabilities the host reports for it: $caps"

# ---- 3. idle: no outbound connections, nothing written ----------------------------------------------------
# The plugin process is found by its executable path (process names are cut to 15 characters).
BIN=$(find "$H/.mesh-llm/plugins" -type f -name "$PLUGIN" -perm -u+x 2>/dev/null | head -1)
PID=''
if [ -d /proc ]; then
  for p in /proc/[0-9]*; do [ "$(readlink "$p/exe" 2>/dev/null)" = "$BIN" ] && PID=${p#/proc/} && break; done
else
  PID=$(pgrep -f "^$BIN( |$)" | head -1)
fi
[ -n "$PID" ] || fail "cannot find the plugin process ($BIN)"
# The plugin's threads: every process that executed the plugin binary (the one running now, $PID, and any
# earlier instance the host restarted) and, transitively, every thread or process one of them cloned (each
# clone/fork line in a thread's trace file ends "= <new thread id>").
plugin_threads() {
  local queue="$PID" seen=" " tid child f
  for f in $(grep -l -F "execve(\"$BIN\"" "$WORK"/trace.* 2>/dev/null); do queue="$queue ${f##*.}"; done
  while [ -n "$queue" ]; do
    tid=${queue%% *}; queue=${queue#"$tid"}; queue=${queue# }
    case "$seen" in *" $tid "*) continue ;; esac
    seen="$seen$tid "
    [ -f "$WORK/trace.$tid" ] || continue
    for child in $(grep -E '(clone3?|v?fork)\(' "$WORK/trace.$tid" | sed -n -E 's/.*= ([0-9]+)$/\1/p'); do
      queue="$queue $child"
    done
  done
  echo "$seen"
}
# Every connect/sendto/sendmsg any plugin thread made whose address is not loopback, or that goes to a name
# server on either family (a lookup is outbound intent even through a local resolver on 127.0.0.53).
outbound() { # outbound FROM_TIME TO_TIME (seconds since the epoch, the trace's -ttt clock, so midnight is no edge)
  [ -f "$WORK/trace.$PID" ] || return 2
  local files=() tid
  for tid in $(plugin_threads); do [ -f "$WORK/trace.$tid" ] && files+=("$WORK/trace.$tid"); done
  echo "THREADS ${#files[@]}" >&2
  awk -v from="$1" -v to="$2" '$1 + 0 >= from + 0 && $1 + 0 <= to + 0' "${files[@]}" \
    | grep -E 'connect\(|sendto\(|sendmsg\(' \
    | grep -E 'sin6?_addr|inet_(addr|pton)' \
    | grep -v -E 'inet_addr\("127\.|inet_pton\(AF_INET6, "::1"' \
    | sed -E 's/^([0-9:.]+) .*(inet_addr\("[^"]+"\)|inet_pton\([^)]*\)).*(sin6?_port=htons\([0-9]+\)).*/\1 \2 \3/' | sort -u
  awk -v from="$1" -v to="$2" '$1 + 0 >= from + 0 && $1 + 0 <= to + 0' "${files[@]}" | grep -E 'sin6?_port=htons\(53\)' | grep -q . && echo "a name lookup (port 53)"
  return 0
}
r0=$(records); c0=$(checkpoint_count); t0=$(date +%s.%6N)
sleep "$IDLE_SECONDS"
r1=$(records); c1=$(checkpoint_count); t1=$(date +%s.%6N)
if [ -z "$PID" ]; then notchecked "3. idle network (no plugin process)"
elif [ "$TRACE" != yes ]; then notchecked "3. idle network (needs Linux with strace: every connect/sendto is traced)"
else
  out=$(outbound "${T_START:-$t0}" "$t1" 2>"$WORK/outbound.err"); rc=$?
  info "measured: every connect/sendto/sendmsg of every plugin thread ($(sed -n 's/^THREADS //p' "$WORK/outbound.err") threads, pid $PID) from node start through ${IDLE_SECONDS} s idle, traced with strace"
  if [ "$rc" = 2 ]; then notchecked "3. idle network (no trace for the plugin process)"
  elif [ -z "$out" ]; then pass "start + idle ${IDLE_SECONDS} s: no connection or datagram from the plugin to anything but loopback, and no name lookup"
  else fail "idle: the plugin reached out: $(echo "$out" | head -5 | tr '\n' ';')"; fi
fi
if [ "$RUNNING" = no ]; then notchecked "3. idle writes (the plugin never ran)"
elif [ ! -d "$DATA" ]; then notchecked "3. idle writes (no data directory at $DATA)"
elif [ "$r0" = "$r1" ] && [ "$c0" = "$c1" ]; then pass "idle ${IDLE_SECONDS} s: no record and no checkpoint written ($r1 records, $c1 checkpoint lines)"
else fail "idle: records $r0 -> $r1, checkpoint lines $c0 -> $c1"; fi

# ---- 4. one request -> exactly one record, digests only ---------------------------------------------------
TOKEN=reviewer-check-$RANDOM$RANDOM
MODEL_ID=$(jq -r '[.data[].id | select(. != "mesh")][0]' "$WORK/models-on.json")
code=$(curl -s -o "$WORK/response.json" -w '%{http_code}' -H 'content-type: application/json' \
  -d "$(jq -cn --arg m "$MODEL_ID" --arg t "$TOKEN" '{model: $m, messages: [{role: "user", content: ("Repeat this word: " + $t)}], max_tokens: 8}')" \
  "http://127.0.0.1:$API/v1/chat/completions")
r2=$r1
for _ in $(seq 30); do r2=$(records); [ "$r2" -gt "$r1" ] && break; sleep 1; done
sleep 2; r2=$(records)
info "request to $MODEL_ID: HTTP $code"
if [ "$code" = 200 ] && [ $((r2 - r1)) = 1 ]; then pass "one request sealed exactly one record ($r1 -> $r2)"
else fail "one request: HTTP $code, records $r1 -> $r2 (expected exactly one more)"; fi
ANSWER=$(jq -r '.choices[0].message.content // ""' "$WORK/response.json" 2>/dev/null)
if [ "$RUNNING" = no ]; then notchecked "4. stored text (the plugin never ran)"
elif [ "$code" != 200 ]; then notchecked "4. stored prompt (the request failed: HTTP $code)"
elif [ "$(records)" = 0 ]; then notchecked "4. stored prompt (no record under $DATA to look in)"
elif grep -r -q -F "$TOKEN" "$DATA"; then fail "the prompt text is stored under $DATA"
else pass "the prompt text is not stored anywhere under the plugin's data directory"; fi
if [ "$RUNNING" = no ]; then :
elif [ "$code" != 200 ] || [ -z "$ANSWER" ] || [ "${#ANSWER}" -lt 8 ]; then
  notchecked "4. stored answer (no answer of 8 or more characters to look for)"
elif [ "$(records)" = 0 ]; then notchecked "4. stored answer (no record under $DATA to look in)"
# The answer as written, and as it would sit inside a JSON string (quotes and backslashes escaped).
elif grep -r -q -F "$ANSWER" "$DATA" || grep -r -q -F "$(jq -cn --arg a "$ANSWER" '$a' | sed 's/^"//; s/"$//')" "$DATA"; then
  fail "the answer text is stored under $DATA"
else pass "the answer text is not stored (digests only)"; fi
stop

# ---- 5. mesh-llm's four Linux smokes ----------------------------------------------------------------------
cat <<EOF

== mesh-llm's Linux smokes against this plugin (run from a mesh-llm checkout, CPU)
Install this archive into a plugin store every node will find, then run each smoke from a fresh HOME:

  export MESH_LLM_PLUGIN_DIR=\$(mktemp -d)        # one store for every node a smoke starts
  MESH_LLM_PLUGIN_DIR=\$MESH_LLM_PLUGIN_DIR $MESH plugins install --archive $ARCHIVE --name $PLUGIN --version $LABEL
  export HOME=\$(mktemp -d)                       # fresh HOME per smoke
  # Core inference (dense):   SmolLM2-135M-Instruct-Q8_0.gguf (keep that file name)
  scripts/ci-smoke-test.sh $MESH <bin-dir> <SmolLM2-135M-Instruct-Q8_0.gguf>
  # Core inference (recurrent): granite-4.0-h-350m-Q4_K_M.gguf
  MESH_CI_CTX_SIZE=128 MESH_CI_BATCH_SIZE=128 MESH_CI_UBATCH_SIZE=128 scripts/ci-smoke-test.sh $MESH <bin-dir> <granite-4.0-h-350m-Q4_K_M.gguf>
  # Two-node client
  scripts/ci-two-node-client-serving-smoke.sh $MESH <bin-dir> <SmolLM2-135M-Instruct-Q8_0.gguf>
  # KV caching, dense + recurrent
  MESH_TWO_NODE_SPLIT_DURABLE_L3=1 MESH_TWO_NODE_SPLIT_ALLOW_UNCERTIFIED=1 \\
  MESH_TWO_NODE_SPLIT_RECURRENT_MODEL=<granite-4.0-h-350m-Q4_K_M.gguf> MESH_TWO_NODE_SPLIT_RECURRENT_CTX_SIZE=4096 \\
  MESH_TWO_NODE_SPLIT_RECURRENT_EXPECTED_EXACT_PAYLOAD_KIND=kv-recurrent \\
    scripts/ci-two-node-split-smoke.sh $MESH <bin-dir> <SmolLM2-135M-Instruct-Q8_0.gguf>
  # Laya CPU
  python3 scripts/ci-laya-smoke.py --mesh-binary $MESH --model <laya-multilingual-F16.gguf> --device CPU

The model files, revisions and SHA-256s are in mesh-llm's ci/model-artifacts/manifests/product-smoke.json
(ids smollm2-q8-inference, family-granite-hybrid, family-laya-multilingual).
EOF

echo
if [ "$FAILS" = 0 ]; then echo "RESULT: all checks passed ($LABEL)"; else echo "RESULT: $FAILS check(s) failed ($LABEL)"; fi
exit $(( FAILS > 0 ))
