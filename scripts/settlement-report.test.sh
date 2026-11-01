#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# scripts/settlement-report.sh against evidencebook-skills' inference-deals
# payer fixture, with a stand-in `capsules chain-lines`. Needs a capsulectl
# that loads capsulectl-book and an evidencebook-skills checkout, so it runs
# only when both are named:
#
#   CAPSULECTL=PATH EVIDENCEBOOK_SKILLS=DIR scripts/settlement-report.test.sh
#
# It checks: a first run seals and checks a page; a second run publishes
# nothing new and seals again; a chain shorter than what was published, and a
# node key other than the book's, are refused and leave the page, and the
# book's seed, as they were.
set -euo pipefail

if [ -z "${CAPSULECTL:-}" ] || [ -z "${EVIDENCEBOOK_SKILLS:-}" ]; then
  echo "settlement-report.test: skipped (set CAPSULECTL and EVIDENCEBOOK_SKILLS)"
  exit 0
fi
here=$(cd "$(dirname "$0")" && pwd)
fixture="$EVIDENCEBOOK_SKILLS/tests/fixtures/inference-deals/payer.jsonl"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "settlement-report.test: FAIL: $*" >&2; exit 1; }

mkdir -p "$work/data/keys" "$work/bin"
openssl genpkey -algorithm ed25519 -out "$work/data/keys/node-key.pem" 2>/dev/null
cp "$fixture" "$work/chain.jsonl"
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
published() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["published_lines"])' "$work/report/book.json"; }

run || { cat "$work/run.log"; fail "the first run did not seal a page"; }
[ -s "$work/report/settlement.html" ] || fail "no page after the first run"
[ "$(published)" = "$(wc -l <"$fixture" | tr -d ' ')" ] || fail "the watermark is not the chain's length"

run || { cat "$work/run.log"; fail "a second run with nothing new did not seal"; }
grep -q '"page": *"match"' "$work/report/settlement.json" || fail "the second run's note does not record a match"

head -n 5 "$fixture" >"$work/chain.jsonl"
before=$(shasum -a 256 "$work/report/settlement.html")
if run; then fail "a chain shorter than what was published was accepted"; fi
grep -q "new history" "$work/run.log" || fail "the shrunk chain's refusal does not say why"
[ "$before" = "$(shasum -a 256 "$work/report/settlement.html")" ] || fail "a refused run changed the page"

cp "$fixture" "$work/chain.jsonl"
seed_before=$(shasum -a 256 "$work/report/node.seed")
openssl genpkey -algorithm ed25519 -out "$work/data/keys/node-key.pem" 2>/dev/null
if run; then fail "a node key other than the book's was accepted"; fi
grep -q "not this node's" "$work/run.log" || fail "the foreign key's refusal does not say why"
[ "$seed_before" = "$(shasum -a 256 "$work/report/node.seed")" ] || fail "a foreign key replaced the book's seed"
echo "settlement-report.test: ok"
