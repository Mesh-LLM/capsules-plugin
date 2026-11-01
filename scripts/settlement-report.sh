#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The node's EvidenceBook settlement report (Mesh-LLM/capsules-plugin#96,
# button 2): run by the node's owner on the node's machine, by hand or on a
# schedule, while the node runs. The Exchanges tab's "EvidenceBook report
# (sealed and checked)" hands over the page this leaves; the node never
# builds one itself.
#
#   1. Read the node's chain with `capsules chain-lines` (no lock; the node's
#      shelf is never written).
#   2. Publish each record not yet in the reporting book into it: a capsulectl
#      `jsonl` book under the node's own key, one `capsule-seal-request/v1` per
#      record, its payload the record unchanged (the path evidencebook-skills'
#      tests/fresh_env_deals.sh runs, so the inference-deals evaluator reads it
#      as a Mesh node seals it).
#   3. Run evidencebook-skills' report.sh over the inference-deals pack with
#      --seal: the Result and the page's digest are sealed in that book, and
#      report.sh hands over a page only when `book report check` says match.
#   4. Keep the page as <report dir>/settlement.html, with settlement.json
#      naming when it was sealed and the day it reports on.
#
# Usage:
#   scripts/settlement-report.sh --report-dir DIR --capsulectl PATH --skills DIR \
#       [--capsules PATH] [--data-dir DIR] [--date YYYY-MM-DD] [--period-policy FILE] [--now TIME]
#       [--wording FILE --wording-digest SHA256]
#
#   --report-dir   the reporting book's directory; the node's CAPSULES_SETTLEMENT_REPORT_DIR
#   --capsulectl   a capsulectl that loads capsulectl-book; the node's CAPSULES_CAPSULECTL
#   --skills       an evidencebook-skills checkout (scripts/report.sh, packs/inference-deals)
#   --capsules     the plugin binary (default: capsules on PATH)
#   --data-dir     the node's data directory (default: CAPSULES_DATA_DIR)
#   --date         the day the report covers up to (default: yesterday, UTC)
#   --period-policy the node's own period_policy, when it is not the pack's default
#   --now          report.sh's clock (default: the wall clock); for tests
#   --wording, --wording-digest
#                  the 9b wording pack, passed to report.sh when it takes one
#                  (action-state-group/evidencebook-skills#102)
set -euo pipefail

usage() { sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2; exit 2; }
fail() { echo "settlement-report: $*" >&2; exit 1; }

REPORT_DIR=${CAPSULES_SETTLEMENT_REPORT_DIR:-}
CAPSULECTL=${CAPSULES_CAPSULECTL:-}
SKILLS="" CAPSULES=capsules DATA_DIR=${CAPSULES_DATA_DIR:-} DATE="" WORDING="" WORDING_DIGEST="" PERIOD_POLICY="" NOW=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report-dir) REPORT_DIR=$2; shift 2 ;;
    --capsulectl) CAPSULECTL=$2; shift 2 ;;
    --skills) SKILLS=$2; shift 2 ;;
    --capsules) CAPSULES=$2; shift 2 ;;
    --data-dir) DATA_DIR=$2; shift 2 ;;
    --date) DATE=$2; shift 2 ;;
    --wording) WORDING=$2; shift 2 ;;
    --wording-digest) WORDING_DIGEST=$2; shift 2 ;;
    --period-policy) PERIOD_POLICY=$2; shift 2 ;;
    --now) NOW=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$REPORT_DIR" ] && [ -n "$CAPSULECTL" ] && [ -n "$SKILLS" ] || usage
if { [ -n "$WORDING" ] && [ -z "$WORDING_DIGEST" ]; } || { [ -z "$WORDING" ] && [ -n "$WORDING_DIGEST" ]; }; then
  fail "--wording and --wording-digest go together"
fi
[ -x "$CAPSULECTL" ] || fail "no capsulectl at $CAPSULECTL"
[ -f "$SKILLS/scripts/report.sh" ] || fail "$SKILLS is not an evidencebook-skills checkout (no scripts/report.sh)"
SPEC="$SKILLS/packs/inference-deals/compiled/compiled.json"
[ -f "$SPEC" ] || fail "$SKILLS has no inference-deals pack ($SPEC)"
DATE=${DATE:-$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).date())')}

[ -n "$DATA_DIR" ] || fail "set --data-dir (or CAPSULES_DATA_DIR) to the node's data directory"
KEY="$DATA_DIR/keys/node-key.pem"
[ -r "$KEY" ] || fail "the node's key is not readable at $KEY"

mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"
REPORT_DIR=$(cd "$REPORT_DIR" && pwd)
# One run at a time: two runs would publish the same records twice
# (capsulectl publish does not refuse a repeat). mkdir is atomic everywhere.
LOCK="$REPORT_DIR/.lock"
mkdir "$LOCK" 2>/dev/null || fail "another run holds $LOCK (remove it if no run is going)"
WORK=""
trap 'rm -rf "$LOCK" ${WORK:+"$WORK"}' EXIT
WORK=$(mktemp -d "$REPORT_DIR/run.XXXXXX")

# capsulectl keeps its profiles under XDG_CONFIG_HOME, and finds capsulectl-book
# under CAPSULECTL_PLUGIN_ROOTS. The node's route runs `book report check` with
# the same two, read from book.json, so both open the same book the same way.
export XDG_CONFIG_HOME="$REPORT_DIR/config"
export CAPSULECTL_PLUGIN_ROOTS=${CAPSULECTL_PLUGIN_ROOTS:-$(cd "$(dirname "$CAPSULECTL")" && pwd)}
PROFILE=settlement
BOOK="$REPORT_DIR/book.json"
# The book's signing seed, the node's own key, as the profile names it. It
# stays (0600, in this 0700 directory) because capsulectl-book's `book report
# check`, which the node runs at hand-over, opens the profile only with its
# signing secret (action-state-group/evidencebook#324).
SEED="$REPORT_DIR/node.seed"

# book.json's fields, read and written in one place.
book() { python3 "$WORK/book.py" "$BOOK" "$@"; }
cat >"$WORK/book.py" <<'EOF'
import json, os, sys
path, op, args = sys.argv[1], sys.argv[2], sys.argv[3:]
book = json.load(open(path)) if os.path.exists(path) else {}
if op == "get":
    value = book.get(args[0])
    print("" if value is None else (json.dumps(value) if isinstance(value, dict) else value))
    sys.exit(0)
# set KEY=JSON or KEY:=TEXT (stored as a string) ...: the file is replaced
# whole, so a run killed mid-write leaves the old one.
for pair in args:
    key, value = pair.split("=", 1)
    if key.endswith(":"):
        book[key[:-1]] = value
    else:
        book[key] = json.loads(value)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(book, f, sort_keys=True)
os.replace(tmp, path)
EOF

# The node's key as the 32-byte seed capsulectl reads, first in the run's own
# directory: it replaces the book's seed only once it is the book's key.
python3 - "$KEY" "$WORK/node.seed" <<'EOF'
import base64, os, sys
body = "".join(l for l in open(sys.argv[1]).read().splitlines() if l and not l.startswith("-----"))
der = base64.b64decode(body)
if len(der) != 48:
    sys.exit("settlement-report: the node's key is not an Ed25519 PKCS#8 key")
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(der[16:].hex())
EOF
NODE_PUB=$("$CAPSULECTL" key show-public "$WORK/node.seed" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')
BOOK_KEY=$(book get node_key)
if [ -n "$BOOK_KEY" ] && [ "$BOOK_KEY" != "$NODE_PUB" ]; then
  fail "this reporting book is under key ${BOOK_KEY:0:12}, not this node's (${NODE_PUB:0:12}); use a new --report-dir"
fi
mv "$WORK/node.seed" "$SEED"

if [ -z "$BOOK_KEY" ]; then
  # First run. book.json names the key first, so a run cut short here resumes:
  # an existing profile is kept and `store init` is idempotent.
  book set node_key:="$NODE_PUB" published_lines=0 last_capsule_id=null book_sequence=0 pending=null
fi
book set plugin_roots:="$CAPSULECTL_PLUGIN_ROOTS"
if ! "$CAPSULECTL" profile list | python3 -c 'import json,sys; sys.exit(sys.argv[1] not in json.load(sys.stdin)["profiles"])' "$PROFILE"; then
  "$CAPSULECTL" profile create --name "$PROFILE" --type jsonl --jsonl-path "$REPORT_DIR/book" \
    --namespace settlement --log-id "settlement-$NODE_PUB" --log book --operator "$NODE_PUB" \
    --signing-key-file "$SEED" --trusted-key "$NODE_PUB" \
    --checkpoint-signing-key-file "$SEED" --checkpoint-trusted-key "$NODE_PUB" >/dev/null \
    || fail "capsulectl profile create failed"
fi
"$CAPSULECTL" store init --profile "$PROFILE" >/dev/null || fail "capsulectl store init failed"

# A run killed between a publish and its watermark: find out from the book
# whether that record was published, by its ActionID, before going on.
PENDING=$(book get pending)
if [ -n "$PENDING" ]; then
  python3 - "$CAPSULECTL" "$PROFILE" "$(book get book_sequence)" "$PENDING" "$WORK/resolved" <<'EOF' || exit 1
import json, subprocess, sys
ctl, profile, after, pending, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), json.loads(sys.argv[4]), sys.argv[5]
want = "urn:mesh-record:" + pending["capsule_id"]
found = None
while found is None:
    page = json.loads(subprocess.run([ctl, "cll", "list", "--profile", profile, "--after", str(after), "--limit", "1000"],
                                     check=True, capture_output=True, text=True).stdout)
    for entry in page["entries"]:
        if entry.get("record_type") != "own_capsule":
            continue
        got = json.loads(subprocess.run([ctl, "get", "--profile", profile, "--capsule-id", entry["capsule_id"]],
                                        check=True, capture_output=True, text=True).stdout)
        if got.get("capsule", {}).get("action_id") == want:
            found = entry["sequence"]
            break
    if found is None and not page.get("next_after"):
        break
    after = page.get("next_after") or after
with open(out, "w") as f:
    f.write("" if found is None else str(found))
EOF
  if [ -s "$WORK/resolved" ]; then
    book set published_lines="$(( $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["line"])' "$PENDING") + 1 ))" \
      last_capsule_id="$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["capsule_id"]))' "$PENDING")" \
      book_sequence="$(cat "$WORK/resolved")" pending=null
  else
    book set pending=null
  fi
fi

# Publish the chain's new records, in order, from the watermark on.
"$CAPSULES" chain-lines --data-dir "$DATA_DIR" >"$WORK/chain.jsonl" || fail "capsules chain-lines could not read the node's chain"
python3 - "$WORK/chain.jsonl" "$BOOK" "$WORK/requests" "$NODE_PUB" <<'EOF' || exit 1
import json, os, sys
lines = [l for l in open(sys.argv[1], encoding="utf-8").read().splitlines() if l]
book = json.load(open(sys.argv[2]))
done, last = book["published_lines"], book["last_capsule_id"]
if len(lines) < done:
    sys.exit(f"settlement-report: the chain has {len(lines)} records but {done} are published; the node started a new history, so use a new --report-dir")
prior = [c for c in (json.loads(l).get("capsule_id") for l in lines[:done]) if isinstance(c, str)]
if last is not None and (not prior or prior[-1] != last):
    sys.exit("settlement-report: the chain's record at the watermark is not the one published; use a new --report-dir")
os.makedirs(sys.argv[3])
for i, line in enumerate(lines[done:], start=done):
    capsule = json.loads(line)
    if not isinstance(capsule.get("capsule_id"), str) or not isinstance(capsule.get("timestamp"), str):
        continue  # a padding record: no capsule to report on
    request = {"spec_version": "capsule-seal-request/v1",
               "capsule": {"ActionID": f"urn:mesh-record:{capsule['capsule_id']}", "ActionType": "fyi",
                           "Operator": sys.argv[4], "Developer": "capsules-plugin/settlement-report",
                           "Timestamp": capsule["timestamp"]},
               "payload": capsule}
    with open(os.path.join(sys.argv[3], f"{i:09d}.json"), "w") as f:
        json.dump(request, f, sort_keys=True)
with open(sys.argv[3] + ".total", "w") as f:
    f.write(str(len(lines)))
EOF
for request in "$WORK/requests"/*.json; do
  [ -e "$request" ] || break
  line=$((10#$(basename "$request" .json)))
  id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["payload"]["capsule_id"])' "$request")
  # The watermark moves one record at a time, around a pending marker, so a
  # run cut short resumes after the last record it published, never twice.
  book set pending="{\"line\": $line, \"capsule_id\": \"$id\"}"
  sequence=$("$CAPSULECTL" publish --profile "$PROFILE" --request "$request" \
    | python3 -c 'import json,sys; print(json.loads(sys.stdin.read().strip().splitlines()[-1])["sequence"])') \
    || fail "capsulectl publish refused record $line; the next run checks whether it landed"
  book set published_lines=$((line + 1)) last_capsule_id:="$id" book_sequence="$sequence" pending=null
done
# Padding records after the last capsule move the watermark too.
book set published_lines="$(cat "$WORK/requests.total")"

# The report, sealed and checked by report.sh; it leaves no page unless
# `book report check` said match.
extra=()
[ -z "$WORDING" ] || extra+=(--wording "$WORDING" --wording-digest "$WORDING_DIGEST")
[ -z "$PERIOD_POLICY" ] || extra+=(--period-policy "$PERIOD_POLICY")
[ -z "$NOW" ] || extra+=(--now "$NOW")
bash "$SKILLS/scripts/report.sh" --spec "$SPEC" --profile "$PROFILE" --date "$DATE" \
  --out "$WORK/settlement.html" --capsulectl "$CAPSULECTL" --work "$WORK/report" --seal ${extra[@]+"${extra[@]}"} \
  || fail "report.sh did not hand over a checked page (its output above says why)"
"$CAPSULECTL" book report check --profile "$PROFILE" --page "$WORK/settlement.html" >"$WORK/check.json" \
  || fail "book report check did not pass on the new page"
python3 - "$WORK/check.json" "$DATE" "$WORK/settlement.json" <<'EOF'
import datetime, json, sys
check = json.load(open(sys.argv[1]))
meta = {"date": sys.argv[2],
        "sealed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "check": check}
json.dump(meta, open(sys.argv[3], "w"), sort_keys=True)
EOF
# The note first, then the page. The route takes the note's fields only when
# its page digest is the one it just checked, so a page and an older note are
# never shown together.
mv "$WORK/settlement.json" "$REPORT_DIR/settlement.json"
mv "$WORK/settlement.html" "$REPORT_DIR/settlement.html"
echo "settlement-report: sealed and checked, $REPORT_DIR/settlement.html (report up to $DATE)"
