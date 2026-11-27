#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The pre-push check: every step the pull request's CI jobs run, on this
# machine. The jobs in .github/workflows/ci.yml and e2e.yml call these same
# steps, so a local pass covers what the pull request's run checks, and a push
# never waits on GitHub to find out.
#
#   scripts/check.sh             every step below, timed; e2e when the change
#                                needs it (scripts/e2e-scope.sh)
#   scripts/check.sh STEP [ARG]  one step, as a CI job runs it
#
# Steps:
#   rust          fmt, clippy, the binary's unit tests (all threads), the
#                 integration tests (one at a time: they share ports and
#                 directories), and serde_json's nesting limit
#   mutants K/N   shard K of N of both mutant tables (scripts/mutants.sh,
#                 scripts/referee-mutants.sh); with no K/N, every shard of
#                 MUTANT_JOBS (default 4) at once, each in its own target
#                 directory cloned from the main one
#   web-ui        typecheck, unit tests, the bundle build
#   repo          no keys, vector checksums, the scanner's and the scripts'
#                 own tests
#   package       the reproducible package, .tar.gz and .zip, each built twice
#   e2e           scripts/e2e.sh: the two-node run with the pinned mesh-llm
#
# Environment: CHECK_E2E=1 runs the e2e step whatever the scope says, 0
# skips it (reported as NOT RUN); CHECK_BASE names the ref the change is
# measured against for the scope (default: main of the remote that points at
# Mesh-LLM/capsules-plugin, fetched first).
#
# Needs: rustup's pinned toolchain, pnpm and Node 24, python3, jq, GNU tar and
# GNU touch (gtar, gtouch on macOS), zip and unzip; for e2e, curl and about
# 1 GB for the cached inputs.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
crate=$root/crates/evidence-plugin

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

step_rust() (
  cd "$crate"
  cargo fmt --check
  cargo clippy --locked --all-targets -- -D warnings
  # The binary's own tests bind 127.0.0.1:0 and use their own temporary
  # directories, so they run on every thread.
  cargo test --locked --bins
  # The interop tests start the compiled plugin against a stand-in host over
  # mesh-llm's real plugin wire protocol; they share ports and data
  # directories, so they run one at a time. This includes the conformance
  # vectors (tests/aac_canonical_vectors.rs, the split-stage cases).
  cargo test --locked --test '*' -- --test-threads=1
  # serde_json's `unbounded_depth` is for the parity runner's fixture reader
  # only (a dev-dependency). It must never reach the plugin binary, where a
  # pushed body is parsed under the default nesting limit.
  if cargo tree --locked -e normal,features -i serde_json | grep -q unbounded_depth; then
    echo "::error::serde_json/unbounded_depth is enabled outside the tests"
    exit 1
  fi
)

# One shard of each mutant table: each build with one deliberate fault must
# fail the tests its table names (gates/mutants.json,
# vectors/parity/referee/mutants.json).
step_mutant_shard() {
  bash scripts/mutants.sh --shard "$1"
  bash scripts/referee-mutants.sh --shard "$1"
}

# Every shard at once. Each shard builds in its own target directory, a
# copy-on-write clone of the main one (APFS clonefile, or a reflink where the
# filesystem has one), so the dependencies are not rebuilt and the shards do
# not wait on each other's cargo lock. Integration-test rows are all in shard
# 1, so two of them never bind the same ports at once.
step_mutants_local() {
  local jobs=${MUTANT_JOBS:-4} k pids=() status=0 base=$crate/target/shards
  (cd "$crate" && cargo test --locked --bins --tests --no-run -q)
  rm -rf "$base"
  for k in $(seq 1 "$jobs"); do
    mkdir -p "$base/$k"
    if [ "$(uname -s)" = Darwin ]; then
      cp -c -R "$crate/target/debug" "$base/$k/debug"
    else
      cp -R --reflink=auto "$crate/target/debug" "$base/$k/debug"
    fi
    CARGO_TARGET_DIR=$base/$k step_mutant_shard "$k/$jobs" > "$base/$k.log" 2>&1 &
    pids+=($!)
  done
  for k in $(seq 1 "$jobs"); do
    if wait "${pids[$((k - 1))]}"; then
      echo "mutant shard $k/$jobs: ok"
    else
      status=1
      echo "mutant shard $k/$jobs: FAILED"
      cat "$base/$k.log"
    fi
  done
  [ "$status" = 1 ] || rm -rf "$base"
  return "$status"
}

step_mutants() {
  if [ $# -gt 0 ]; then step_mutant_shard "$1"; else step_mutants_local; fi
}

step_web_ui() (
  cd web-ui
  pnpm install --frozen-lockfile
  pnpm typecheck
  pnpm test
  pnpm build
  test "$(ls ../bundle)" = "register-mesh-plugin-ui.js"
)

step_repo() {
  scripts/no-keys.sh
  (cd vectors && sha256 -c --quiet SHA256SUMS)
  node scripts/neutrality-scan.mjs --self-test
  # The test files are named: a bare directory argument is read as a module
  # path by some Node versions (24 fails with "Cannot find module"), and as a
  # directory to search by others.
  node --test scripts/*.test.mjs
  bash scripts/mutant-shards.test.sh
}

# The release packaging, end to end on a debug build, twice per archive
# format: the two archives must be byte-identical.
step_package() {
  local version bin out
  cargo build --locked --manifest-path crates/evidence-plugin/Cargo.toml --bin capsules
  (cd web-ui && pnpm install --frozen-lockfile && pnpm build)
  scripts/plugin-toml.test.sh
  scripts/settlement-report-receipts.test.sh
  version=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' plugin.toml)
  bin=crates/evidence-plugin/target/debug/capsules
  out=$(mktemp -d "${TMPDIR:-/tmp}/capsules-package.XXXXXX")
  SOURCE_DATE_EPOCH=0 scripts/package.sh "$version" x86_64-unknown-linux-gnu "$bin" "$out/a"
  SOURCE_DATE_EPOCH=0 scripts/package.sh "$version" x86_64-unknown-linux-gnu "$bin" "$out/b"
  cmp "$out"/a/*.tar.gz "$out"/b/*.tar.gz
  tar -tzf "$out"/a/*.tar.gz | sort
  # The Windows .zip path, with this build standing in for the Windows
  # executable (only the archive format differs).
  SOURCE_DATE_EPOCH=0 scripts/package.sh "$version" x86_64-pc-windows-msvc "$bin" "$out/zip-a"
  SOURCE_DATE_EPOCH=0 scripts/package.sh "$version" x86_64-pc-windows-msvc "$bin" "$out/zip-b"
  cmp "$out"/zip-a/*.zip "$out"/zip-b/*.zip
  unzip -Z1 "$out"/zip-a/*.zip
  rm -rf "$out"
}

step_e2e() { scripts/e2e.sh; }

# The ref the change is measured against for the e2e scope: main of the
# remote that points at this repository, fetched, unless CHECK_BASE names it.
e2e_base() {
  if [ -n "${CHECK_BASE:-}" ]; then echo "$CHECK_BASE"; return; fi
  local remote
  remote=$(git remote -v | awk '$2 ~ /github\.com[:\/]Mesh-LLM\/capsules-plugin(\.git)?$/ && $3 == "(fetch)" { print $1; exit }')
  [ -n "$remote" ] || { echo "check: no remote points at Mesh-LLM/capsules-plugin; set CHECK_BASE" >&2; return 1; }
  git fetch -q "$remote" main
  echo "$remote/main"
}

if [ $# -gt 0 ]; then
  step=$1
  shift
  case "$step" in
    rust|mutants|web-ui|repo|package|e2e) "step_${step//-/_}" "$@" ;;
    *) echo "check: unknown step $step" >&2; exit 2 ;;
  esac
  exit
fi

# Every step, timed, then a summary. A failing step does not stop the rest,
# so one run shows every failure; the exit status is non-zero if any failed.
# Each step runs as its own process, so `set -e` holds inside it (a function
# called on the left of `||` would run with errexit off).
summary=()
failed=0
run() {
  local name=$1 start=$SECONDS rc=0
  echo "=== $name"
  bash "$root/scripts/check.sh" "$name" || rc=$?
  local took=$((SECONDS - start))
  if [ "$rc" = 0 ]; then
    summary+=("$(printf '%-8s %4ss  ok' "$name" "$took")")
  else
    summary+=("$(printf '%-8s %4ss  FAILED (exit %s)' "$name" "$took" "$rc")")
    failed=1
  fi
}

total_start=$SECONDS
run repo
run web-ui
run rust
run mutants
run package
case "${CHECK_E2E:-}" in
  1) run e2e ;;
  0) summary+=("$(printf '%-8s %5s  NOT RUN (CHECK_E2E=0)' e2e -)") ;;
  *)
    if base=$(e2e_base) && [ "$(scripts/e2e-scope.sh "$base")" = true ]; then
      run e2e
    elif [ -n "${base:-}" ]; then
      summary+=("$(printf '%-8s %5s  not needed (no change against %s that it covers)' e2e - "$base")")
    else
      summary+=("$(printf '%-8s %5s  FAILED (no base for the scope)' e2e -)")
      failed=1
    fi
    ;;
esac

echo
echo "=== summary"
printf '%s\n' "${summary[@]}"
echo "total    $((SECONDS - total_start))s"
exit "$failed"
