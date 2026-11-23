#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# scripts/settlement-report.sh --with-receipts (Mesh-LLM/capsules-plugin#336),
# against stand-ins for capsulectl, `capsules` and evidencebook-skills'
# report.sh, so it needs none of them installed:
#
#   scripts/settlement-report-receipts.test.sh
#
# It checks that:
#   - without --with-receipts report.sh is given no --receipts, and
#     `capsules deal-receipts` is never run (the report is built as before);
#   - with it, a carried receipt and a policy-held deal reach report.sh in one
#     JSON list, each as `capsules deal-receipts` printed it, keyed by the
#     exchange capsule id, the held one with no bundle;
#   - with it and no deal line, report.sh is given no file;
#   - a failing `capsules deal-receipts` fails the run and leaves no page.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "settlement-report-receipts.test: FAIL: $*" >&2; exit 1; }
command -v openssl >/dev/null || { echo "settlement-report-receipts.test: skipped (no openssl)"; exit 0; }

mkdir -p "$work/data/keys" "$work/bin" "$work/skills/scripts" "$work/skills/packs/inference-deals/compiled"
openssl genpkey -algorithm ed25519 -out "$work/data/keys/node-key.pem" 2>/dev/null
echo '{}' >"$work/skills/packs/inference-deals/compiled/compiled.json"
echo '{"entries":{}}' >"$work/pack.json"
digest=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$work/pack.json")
for i in 1 2 3; do
  printf '{"capsule_id":"%064d","timestamp":"2026-11-01T00:00:0%dZ"}\n' "$i" "$i"
done >"$work/chain.jsonl"

# capsulectl: just enough for the publish loop and the final check.
cat >"$work/bin/capsulectl" <<'EOF'
#!/usr/bin/env bash
case "$1 $2" in
  "key show-public") echo '{"public_key":"abc123"}' ;;
  "profile list") echo '{"profiles":["settlement"]}' ;;
  "store init") echo '{}' ;;
  "book report") echo '{"page":"match"}' ;;
  "publish --profile") echo "{\"sequence\": $((++n))}" ;;
  *) echo "capsulectl stand-in: unexpected $*" >&2; exit 1 ;;
esac
EOF
# `capsules`: the chain, and deal-receipts as the node prints it.
cat >"$work/bin/capsules" <<EOF
#!/usr/bin/env bash
case "\$1" in
  chain-lines) cat "$work/chain.jsonl" ;;
  deal-receipts)
    echo deal-receipts >>"$work/capsules.calls"
    [ ! -e "$work/deal-receipts.fail" ] || { echo "deal-receipts: the ledger is not readable" >&2; exit 1; }
    # The chain snapshot must be the one the run read, and the report's day is passed.
    case " \$* " in *" --through 2026-11-01 "*) ;; *) echo "deal-receipts: no --through" >&2; exit 8 ;; esac
    cmp -s "\$(printf '%s\n' "\$@" | sed -n '/^--chain\$/{n;p;}')" "$work/chain.jsonl" || exit 7
    cat "$work/deal-receipts.out" ;;
esac
EOF
# report.sh: records what it was given and leaves a page.
cat >"$work/skills/scripts/report.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$work/report.argv"
out=""; receipts=""
while [ "\$#" -gt 0 ]; do
  case "\$1" in --out) out=\$2; shift 2 ;; --receipts) receipts=\$2; shift 2 ;; *) shift ;; esac
done
[ -z "\$receipts" ] || cp "\$receipts" "$work/report.receipts"
echo '<html></html>' >"\$out"
EOF
chmod +x "$work/bin/capsulectl" "$work/bin/capsules" "$work/skills/scripts/report.sh"

run() {
  rm -rf "$work/report" "$work/report.argv" "$work/report.receipts" "$work/capsules.calls"
  "$here/settlement-report.sh" "$@" --report-dir "$work/report" --capsulectl "$work/bin/capsulectl" \
    --skills "$work/skills" --capsules "$work/bin/capsules" --data-dir "$work/data" \
    --wording "$work/pack.json" --wording-digest "$digest" \
    --date 2026-11-01 --now 2026-11-02T00:00:00Z </dev/null >"$work/run.log" 2>&1
}

held="$(printf '%064d' 1)"
carried="$(printf '%064d' 2)"
python3 - "$work/deal-receipts.out" "$held" "$carried" <<'EOF'
import json, sys
with open(sys.argv[1], "w") as f:
    f.write(json.dumps({"exchange_capsule_id": sys.argv[2], "held": True}) + "\n")
    f.write(json.dumps({"exchange_capsule_id": sys.argv[3], "receipt": json.dumps({"bundle": "text"})}) + "\n")
EOF

# 1. Off by default: nothing is asked of the node and report.sh gets no file.
run || { cat "$work/run.log"; fail "the default run did not seal a page"; }
[ -s "$work/report/settlement.html" ] || fail "no page without --with-receipts"
grep -q -- '--receipts' "$work/report.argv" && fail "report.sh was given --receipts without --with-receipts"
[ ! -e "$work/capsules.calls" ] || fail "deal-receipts ran without --with-receipts"

# 2. Carried and held reach report.sh as printed.
run --with-receipts || { cat "$work/run.log"; fail "the run with receipts did not seal a page"; }
grep -qx -- '--receipts' "$work/report.argv" || fail "report.sh was not given --receipts"
python3 - "$work/report.receipts" "$held" "$carried" <<'EOF' || fail "the receipts file is not what deal-receipts printed"
import json, sys
got = json.load(open(sys.argv[1]))
want = [{"exchange_capsule_id": sys.argv[2], "held": True},
        {"exchange_capsule_id": sys.argv[3], "receipt": json.dumps({"bundle": "text"})}]
assert got == want, got
assert "receipt" not in got[0], "the held deal carries a bundle"
EOF

# 3. No deal line: no file.
: >"$work/deal-receipts.out"
run --with-receipts || { cat "$work/run.log"; fail "a run with no deals did not seal a page"; }
grep -q -- '--receipts' "$work/report.argv" && fail "report.sh was given a receipts file with no deal"
[ -s "$work/report/settlement.html" ] || fail "no page when no deal has a receipt"

# 4. deal-receipts failing fails the run, with no page.
touch "$work/deal-receipts.fail"
if run --with-receipts; then fail "a failing deal-receipts was accepted"; fi
grep -q "deal-receipts failed" "$work/run.log" || fail "the refusal does not say why"
[ ! -e "$work/report/settlement.html" ] || fail "a failed run left a page"
echo "settlement-report-receipts.test: ok"
