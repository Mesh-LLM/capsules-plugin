#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# scripts/settlement-report.sh against evidencebook-skills' inference-deals
# payer fixture, with a stand-in `capsules chain-lines`. Needs a capsulectl
# that loads capsulectl-book and an evidencebook-skills checkout, so it runs
# only when both are named:
#
#   CAPSULECTL=PATH EVIDENCEBOOK_SKILLS=DIR scripts/settlement-report.test.sh
#
# It checks that:
#   - a first run over part of the chain seals and checks a page;
#   - a later run publishes only the records added since, a padding line
#     moves the watermark without a publish, and a run with nothing new seals
#     again;
#   - a run killed between a publish and its watermark resumes without
#     publishing that record twice;
#   - a chain shorter than what was published, a node key other than the
#     book's, and a second run while one holds the lock are refused, leaving
#     the page and the book's seed as they were.
set -euo pipefail

if [ -z "${CAPSULECTL:-}" ] || [ -z "${EVIDENCEBOOK_SKILLS:-}" ]; then
  echo "settlement-report.test: skipped (set CAPSULECTL and EVIDENCEBOOK_SKILLS)"
  exit 0
fi
here=$(cd "$(dirname "$0")" && pwd)
fixture="$EVIDENCEBOOK_SKILLS/tests/fixtures/inference-deals/payer.jsonl"
total=$(wc -l <"$fixture" | tr -d ' ')
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "settlement-report.test: FAIL: $*" >&2; exit 1; }

mkdir -p "$work/data/keys" "$work/bin"
openssl genpkey -algorithm ed25519 -out "$work/data/keys/node-key.pem" 2>/dev/null
cat >"$work/bin/capsules" <<EOF
#!/usr/bin/env bash
[ "\$1" = chain-lines ] && cat "$work/chain.jsonl"
EOF
chmod +x "$work/bin/capsules"

run() {
  "$here/settlement-report.sh" --report-dir "$work/report" --capsulectl "$CAPSULECTL" \
    --skills "$EVIDENCEBOOK_SKILLS" --capsules "$work/bin/capsules" --data-dir "$work/data" \
    --date 2026-11-01 --now 2026-11-02T00:00:00Z </dev/null >"$work/run.log" 2>&1
}
field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print("" if v is None else v)' "$work/report/book.json" "$1"; }
# How many times the book holds the record with this capsule id (capsulectl's
# jsonl store; read only by this test).
copies() { grep -o "urn:mesh-record:$1" "$work/report/book/book/records/records.jsonl" | wc -l | tr -d ' '; }
id_at() { sed -n "$1p" "$fixture" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capsule_id"])'; }

# Part of the chain first.
head -n 10 "$fixture" >"$work/chain.jsonl"
run || { cat "$work/run.log"; fail "the first run did not seal a page"; }
[ -s "$work/report/settlement.html" ] || fail "no page after the first run"
[ "$(field published_lines)" = 10 ] || fail "the watermark is not the partial chain's length"

# A run killed after publishing record 11 but before moving the watermark.
export XDG_CONFIG_HOME="$work/report/config"
export CAPSULECTL_PLUGIN_ROOTS=${CAPSULECTL_PLUGIN_ROOTS:-$(dirname "$CAPSULECTL")}
eleventh=$(id_at 11)
sed -n 11p "$fixture" | python3 -c '
import json, sys
c = json.load(sys.stdin)
json.dump({"spec_version": "capsule-seal-request/v1",
           "capsule": {"ActionID": "urn:mesh-record:" + c["capsule_id"], "ActionType": "fyi", "Operator": sys.argv[1],
                       "Developer": "capsules-plugin/settlement-report", "Timestamp": c["timestamp"]},
           "payload": c}, open(sys.argv[2], "w"), sort_keys=True)' "$(field node_key)" "$work/eleventh.json"
python3 - "$work/report/book.json" "$eleventh" <<'EOF'
import json, sys
book = json.load(open(sys.argv[1]))
book["pending"] = {"line": 10, "capsule_id": sys.argv[2]}
json.dump(book, open(sys.argv[1], "w"))
EOF
"$CAPSULECTL" publish --profile settlement --request "$work/eleventh.json" >/dev/null

# The rest of the chain, and a padding line after it.
{ cat "$fixture"; echo '{"padding":"0000"}'; } >"$work/chain.jsonl"
run || { cat "$work/run.log"; fail "the run after a cut-short one did not seal"; }
[ "$(copies "$eleventh")" = 1 ] || fail "the record published before the cut was published again"
[ "$(copies "$(id_at 12)")" = 1 ] || fail "a record added since the last run was not published once"
[ "$(field published_lines)" = $((total + 1)) ] || fail "the padding line did not move the watermark"
[ -z "$(field pending)" ] || fail "the pending marker was left behind"

run || { cat "$work/run.log"; fail "a run with nothing new did not seal"; }
grep -q '"page": *"match"' "$work/report/settlement.json" || fail "the note does not record a match"
[ "$(copies "$(id_at 1)")" = 1 ] || fail "a run with nothing new published a record again"

before=$(shasum -a 256 "$work/report/settlement.html")
seed_before=$(shasum -a 256 "$work/report/node.seed")

head -n 5 "$fixture" >"$work/chain.jsonl"
if run; then fail "a chain shorter than what was published was accepted"; fi
grep -q "new history" "$work/run.log" || fail "the shrunk chain's refusal does not say why"

{ cat "$fixture"; echo '{"padding":"0000"}'; } >"$work/chain.jsonl"
mkdir "$work/report/.lock"
if run; then fail "a run was accepted while another held the lock"; fi
grep -q "another run holds" "$work/run.log" || fail "the lock's refusal does not say why"
rmdir "$work/report/.lock"

openssl genpkey -algorithm ed25519 -out "$work/data/keys/node-key.pem" 2>/dev/null
if run; then fail "a node key other than the book's was accepted"; fi
grep -q "not this node's" "$work/run.log" || fail "the foreign key's refusal does not say why"

[ "$before" = "$(shasum -a 256 "$work/report/settlement.html")" ] || fail "a refused run changed the page"
[ "$seed_before" = "$(shasum -a 256 "$work/report/node.seed")" ] || fail "a refused run replaced the book's seed"
echo "settlement-report.test: ok"
