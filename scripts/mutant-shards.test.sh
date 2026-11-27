#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The mutant shards (scripts/mutants.sh and scripts/referee-mutants.sh,
# --shard K/N) together hold every table row exactly once, for every N from
# 1 to one more than the table's rows; every row that names an
# integration test is in shard 1; and a bad K/N or a shard combined with
# named features is refused. A row in no shard would be a mutant CI never
# runs; a row in two would run twice.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
fail() { echo "FAIL: $*" >&2; exit 1; }

count_rows() { python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["mutants"]))' "$1"; }

check_script() {
  local script=$1 table=$2 rows n k got want
  rows=$(count_rows "$table")
  [ "$rows" -gt 0 ] || fail "$table lists no mutant"
  want=$(seq 0 $((rows - 1)))
  for n in $(seq 1 $((rows + 1))); do
    got=$(for k in $(seq 1 "$n"); do bash "$root/scripts/$script" --shard "$k/$n" --list | cut -f1; done | sort -n)
    [ "$got" = "$want" ] || fail "$script: the $n shards do not hold each of the $rows rows exactly once"
  done
  for bad in 0/1 2/1 1/0 x 1/ /1 1/2/3; do
    if bash "$root/scripts/$script" --shard "$bad" --list >/dev/null 2>&1; then
      fail "$script accepted --shard $bad"
    fi
  done
  if bash "$root/scripts/$script" --shard 1/2 "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["mutants"][0]["feature"])' "$table")" >/dev/null 2>&1; then
    fail "$script accepted --shard with a named feature"
  fi
}

check_script mutants.sh "$root/gates/mutants.json"
check_script referee-mutants.sh "$root/vectors/parity/referee/mutants.json"

# Integration-test rows start the plugin on fixed ports: all in shard 1, so
# parallel shards never run two of them at once.
integration=$(python3 -c 'import json,sys; [print(i) for i, m in enumerate(json.load(open(sys.argv[1]))["mutants"]) if m.get("test")]' "$root/gates/mutants.json")
for n in 2 3 5 8; do
  first=$(bash "$root/scripts/mutants.sh" --shard "1/$n" --list | cut -f1)
  for i in $integration; do
    grep -qx "$i" <<<"$first" || fail "integration row $i is not in shard 1 of $n"
  done
  for k in $(seq 2 "$n"); do
    others=$(bash "$root/scripts/mutants.sh" --shard "$k/$n" --list | cut -f1)
    for i in $integration; do
      ! grep -qx "$i" <<<"$others" || fail "integration row $i is in shard $k of $n"
    done
  done
done

echo "mutant shards: ok"
