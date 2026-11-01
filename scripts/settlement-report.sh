#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The node's EvidenceBook settlement report (Mesh-LLM/capsules-plugin#96,
# button 2): run by the node's owner on the node's machine, by hand or on a
# schedule, while the node runs. The Evidence page's "Save Settlement page"
# hands over the page this leaves; the node never builds one itself.
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
# capsulectl keeps its profiles under XDG_CONFIG_HOME; the node's route reads
# the same one, so both name the book the same way.
export XDG_CONFIG_HOME="$REPORT_DIR/config"
export CAPSULECTL_PLUGIN_ROOTS=${CAPSULECTL_PLUGIN_ROOTS:-$(dirname "$CAPSULECTL")}
PROFILE=settlement
WORK=$(mktemp -d "$REPORT_DIR/run.XXXXXX")
# The book's signing seed, the node's own key, as the profile names it. It
# stays (0600, in this 0700 directory) because capsulectl-book's `book report
# check`, which the node runs at hand-over, opens the profile only with its
# signing secret (action-state-group/evidencebook#324).
SEED="$REPORT_DIR/node.seed"
trap 'rm -rf "$WORK"' EXIT

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
if [ -f "$REPORT_DIR/book.json" ]; then
  python3 - "$REPORT_DIR/book.json" "$NODE_PUB" <<'EOF' || exit 1
import json, sys
book = json.load(open(sys.argv[1]))
if book["node_key"] != sys.argv[2]:
    sys.exit(f"settlement-report: this reporting book is under key {book['node_key'][:12]}, not this node's ({sys.argv[2][:12]}); use a new --report-dir")
EOF
fi
mv "$WORK/node.seed" "$SEED"

if [ ! -f "$REPORT_DIR/book.json" ]; then
  # First run: a book under the node's key, for its records and checkpoints.
  "$CAPSULECTL" profile create --name "$PROFILE" --type jsonl --jsonl-path "$REPORT_DIR/book" \
    --namespace settlement --log-id "settlement-$NODE_PUB" --log book --operator "$NODE_PUB" \
    --signing-key-file "$SEED" --trusted-key "$NODE_PUB" \
    --checkpoint-signing-key-file "$SEED" --checkpoint-trusted-key "$NODE_PUB" >/dev/null
  "$CAPSULECTL" store init --profile "$PROFILE" >/dev/null
  printf '{"node_key":"%s","published_lines":0,"last_capsule_id":null}\n' "$NODE_PUB" >"$REPORT_DIR/book.json"
fi

# Publish the chain's new records, in order, from the watermark on.
"$CAPSULES" chain-lines --data-dir "$DATA_DIR" >"$WORK/chain.jsonl" || fail "capsules chain-lines could not read the node's chain"
python3 - "$WORK/chain.jsonl" "$REPORT_DIR/book.json" "$WORK/requests" "$NODE_PUB" <<'EOF' || exit 1
import json, os, sys
lines = [l for l in open(sys.argv[1], encoding="utf-8").read().splitlines() if l]
book = json.load(open(sys.argv[2]))
done, last = book["published_lines"], book["last_capsule_id"]
if len(lines) < done:
    sys.exit(f"settlement-report: the chain has {len(lines)} records but {done} are published; the node started a new history, so use a new --report-dir")
if done and json.loads(lines[done - 1]).get("capsule_id") != last:
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
print(len(lines), json.loads(lines[-1]).get("capsule_id") if lines else None, file=open(sys.argv[3] + ".next", "w"))
EOF
for request in "$WORK/requests"/*.json; do
  [ -e "$request" ] || break
  "$CAPSULECTL" publish --profile "$PROFILE" --request "$request" >/dev/null \
    || fail "capsulectl publish refused $(basename "$request"); the watermark is unchanged"
  # The watermark moves one record at a time, so a run cut short resumes
  # after the last record it published.
  python3 - "$REPORT_DIR/book.json" "$request" <<'EOF'
import json, os, sys
book = json.load(open(sys.argv[1]))
request = json.load(open(sys.argv[2]))
book["published_lines"] = int(os.path.basename(sys.argv[2]).split(".")[0]) + 1
book["last_capsule_id"] = request["payload"]["capsule_id"]
tmp = sys.argv[1] + ".tmp"
json.dump(book, open(tmp, "w"))
os.replace(tmp, sys.argv[1])
EOF
done
# Padding records after the last capsule move the watermark too.
python3 - "$REPORT_DIR/book.json" "$WORK/requests.next" <<'EOF'
import json, os, sys
book = json.load(open(sys.argv[1]))
total, last = open(sys.argv[2]).read().split()
book["published_lines"], book["last_capsule_id"] = int(total), (None if last == "None" else last)
json.dump(book, open(sys.argv[1] + ".tmp", "w"))
os.replace(sys.argv[1] + ".tmp", sys.argv[1])
EOF

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
# The page first, then its note, each replaced whole.
mv "$WORK/settlement.html" "$REPORT_DIR/settlement.html"
mv "$WORK/settlement.json" "$REPORT_DIR/settlement.json"
echo "settlement-report: sealed and checked, $REPORT_DIR/settlement.html (report up to $DATE)"
