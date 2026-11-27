#!/usr/bin/env bash
# Every referee implementation mutant must fail the referee parity run, and
# fail it on every case vectors/parity/referee/mutants.json lists for it.
# Each mutant is built first, so a compile error never passes as "caught".
#
#   scripts/referee-mutants.sh [--shard K/N] [--list] [feature ...]
#
# With no feature, every mutant listed. --shard K/N keeps only shard K of N:
# row i (from 0) is in shard i mod N + 1, so the N shards together hold every
# row exactly once (scripts/mutant-shards.test.sh). --list prints the kept
# rows (table index, tab, feature) and runs nothing.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mutants="$root/vectors/parity/referee/mutants.json"
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

features=("$@")
rows=()
if [ ${#features[@]} -eq 0 ]; then
  listed=$(python3 - "$mutants" "$shard" <<'EOF'
import json, re, sys
rows = json.load(open(sys.argv[1]))["mutants"]
if not rows:
    sys.exit(f"{sys.argv[1]} lists no mutant")
s = re.fullmatch(r"([1-9][0-9]*)/([1-9][0-9]*)", sys.argv[2])
if not s or int(s[1]) > int(s[2]):
    sys.exit(f"--shard {sys.argv[2]}: want K/N with 1 <= K <= N")
k, n = int(s[1]), int(s[2])
for i, m in enumerate(rows):
    if i % n + 1 == k:
        print(f"{i}\t{m['feature']}")
EOF
)
  while IFS=$'\t' read -r i f; do
    [ -z "$f" ] || { rows+=("$i"); features+=("$f"); }
  done <<<"$listed"
elif [ "$shard" != 1/1 ]; then
  echo "--shard applies to the whole table, not to named features" >&2
  exit 2
fi

if [ "$list" = 1 ]; then
  for i in "${!features[@]}"; do
    printf '%s\t%s\n' "${rows[$i]:-?}" "${features[$i]}"
  done
  exit 0
fi
# More shards than rows leaves a shard empty: nothing to run.
[ ${#features[@]} -gt 0 ] || { echo "shard $shard: no mutant"; exit 0; }

run_output=$(mktemp)
trap 'rm -f "$run_output"' EXIT
status=0
for feature in "${features[@]}"; do
  cargo test --locked --bin capsules --features "$feature" --no-run -q
  if out=$(cargo test --locked --bin capsules --features "$feature" -- referee::parity::the_referee_answers_the_corpus_as_expected 2>&1); then
    echo "::error::the referee parity run passed a build with $feature"
    status=1
    continue
  fi
  # The run's output goes through a file: it can exceed the size of one
  # environment variable or argument (128 KiB on Linux).
  printf '%s\n' "$out" > "$run_output"
  missing=$(python3 - "$mutants" "$feature" "$run_output" <<'EOF'
import json, re, sys
mutant = next(m for m in json.load(open(sys.argv[1]))["mutants"] if m["feature"] == sys.argv[2])
reported = set(re.findall(r"^differs: (\S+)$", open(sys.argv[3]).read(), re.M))
print(" ".join(sorted(set(mutant["must_fail"]) - reported)))
EOF
)
  if [ -n "$missing" ]; then
    echo "::error::$feature failed the run, but not on: $missing"
    status=1
  else
    echo "caught: $feature"
  fi
done
exit $status
