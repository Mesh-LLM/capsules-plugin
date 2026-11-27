#!/usr/bin/env bash
# Every plugin mutant in gates/mutants.json must fail its tests, and print
# what the table says it must: an exact line, or a named test reported FAILED.
# Each mutant is built first, so a compile error never passes as "caught".
# cargo gets no stdin: the loop reads the rows from it.
#
#   scripts/mutants.sh [--shard K/N] [--list] [feature ...]
#
# With no feature, every mutant listed. --shard K/N keeps only shard K of N
# (CI runs the N shards as parallel jobs, scripts/check.sh as parallel
# processes). Every row that names an integration test (`test`) is in shard
# 1: those tests start the plugin on fixed ports, so two of them must never
# run at once. The binary's own rows go round-robin over shards 2..N (over
# shard 1 when N is 1). The N shards together hold every row exactly once
# (scripts/mutant-shards.test.sh). --list prints the kept rows (table index,
# tab, feature) and runs nothing.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
table="$root/gates/mutants.json"
cd "$root/crates/evidence-plugin"

shard=1/1
list=0
while [ $# -gt 0 ]; do
  case "$1" in
    --shard) shard=${2:?--shard needs K/N}; shift 2 ;;
    --list) list=1; shift ;;
    *) break ;;
  esac
done

# One mutant per line, fields split by \x1f (never whitespace, so an empty
# field is kept): row index in the table, feature, test target ("" for the binary's own tests),
# test filter, expectation kind, expected text. An empty table would pass with
# nothing checked.
rows=$(python3 - "$table" "$shard" <<'EOF'
import json, re, sys
mutants = json.load(open(sys.argv[1]))["mutants"]
if not mutants:
    sys.exit(f"{sys.argv[1]} lists no mutant")
s = re.fullmatch(r"([1-9][0-9]*)/([1-9][0-9]*)", sys.argv[2])
if not s or int(s[1]) > int(s[2]):
    sys.exit(f"--shard {sys.argv[2]}: want K/N with 1 <= K <= N")
k, n = int(s[1]), int(s[2])
first, spread = (2, n - 1) if n > 1 else (1, 1)
i = 0
for row, m in enumerate(mutants):
    if m.get("test"):
        mine = k == 1
    else:
        mine = k == first + i % spread
        i += 1
    if mine:
        (kind, text), = m["must_print"].items()
        print("\x1f".join([str(row), m["feature"], m.get("test", ""), m["tests"], kind, text]))
EOF
)

if [ $# -gt 0 ] && [ "$shard" != 1/1 ]; then
  echo "--shard applies to the whole table, not to named features" >&2
  exit 2
fi
if [ $# -gt 0 ]; then
  for feature in "$@"; do
    cut -d $'\x1f' -f2 <<<"$rows" | grep -qxF -- "$feature" \
      || { echo "::error::$feature is not in $table"; exit 1; }
  done
  rows=$(awk -F'\037' 'NR == FNR { want[$0] = 1; next } $2 in want' <(printf '%s\n' "$@") <(printf '%s\n' "$rows"))
fi

if [ "$list" = 1 ]; then
  [ -z "$rows" ] || cut -d $'\x1f' -f1,2 <<<"$rows" | tr '\037' '\t'
  exit 0
fi
# More shards than rows leaves a shard empty: nothing to run.
[ -n "$rows" ] || { echo "shard $shard: no mutant"; exit 0; }

status=0
while IFS=$'\x1f' read -r _row feature test filter kind text; do
  if [ -n "$test" ]; then
    # Integration tests start the plugin process; they run one at a time.
    target=(--test "$test")
    threads=(--test-threads=1)
  else
    target=(--bin capsules)
    threads=()
  fi
  cargo test --locked "${target[@]}" --features "$feature" --no-run -q </dev/null
  if out=$(cargo test --locked "${target[@]}" --features "$feature" -- "$filter" ${threads[@]+"${threads[@]}"} </dev/null 2>&1); then
    echo "::error::the tests passed a build with $feature"
    status=1
    continue
  fi
  case "$kind" in
    line) grep -qxF -- "$text" <<<"$out" && found=1 || found=0 ;;
    failed_test) grep -qE "^test (.*::)?${text} \.\.\. FAILED$" <<<"$out" && found=1 || found=0 ;;
    *) echo "::error::$feature: unknown expectation $kind"; status=1; continue ;;
  esac
  if [ "$found" = 1 ]; then
    echo "caught: $feature"
  else
    echo "$out"
    echo "::error::$feature failed, but did not print its $kind: $text"
    status=1
  fi
done <<<"$rows"
exit $status
