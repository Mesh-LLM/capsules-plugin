#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tier 2, the whole run: everything .github/workflows/e2e.yml's two-node job
# checks, in the same order, on this machine. CI and scripts/check.sh both run
# this script, so a local pass covers what the pull request's run checks.
#
#   scripts/e2e.sh [INPUTS_DIR [OUT_DIR]]
#
# INPUTS_DIR (default $E2E_INPUTS, else ~/.cache/capsules-plugin-e2e) keeps the
# pinned mesh-llm release for this host and the model (scripts/e2e-inputs.env);
# what is missing is downloaded, and both are checked against their SHA-256
# every run, so a cached file can never stand in for a different one.
# OUT_DIR (default $E2E_OUT, else a new temporary directory) gets the node
# logs (logs/) and their homes (nodes/, data/, holding each node's signing
# key: never upload it). Needs web-ui's dependencies (`pnpm install`).
# The nodes bind fixed ports (9401-9413): one run per machine at a time.
#
# Linux x86_64 (CI's runner) and macOS arm64 have a pinned release.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
# shellcheck source=e2e-inputs.env
. "$root/scripts/e2e-inputs.env"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) asset=$MESH_LLM_ASSET_LINUX_X86_64 sha=$MESH_LLM_SHA256_LINUX_X86_64 ;;
  Darwin/arm64) asset=$MESH_LLM_ASSET_DARWIN_ARM64 sha=$MESH_LLM_SHA256_DARWIN_ARM64 ;;
  *) echo "e2e: no pinned mesh-llm release for $(uname -s)/$(uname -m)" >&2; exit 2 ;;
esac

inputs=${1:-${E2E_INPUTS:-$HOME/.cache/capsules-plugin-e2e}}
out=${2:-${E2E_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/capsules-e2e.XXXXXX")}}
mkdir -p "$inputs" "$out"
echo "e2e: inputs $inputs, output $out"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

# Download what is missing, then check both digests.
if [ ! -f "$inputs/$asset" ]; then
  curl -fsSL --retry 3 -o "$inputs/$asset.part" \
    "https://github.com/Mesh-LLM/mesh-llm/releases/download/v$MESH_LLM_VERSION/$asset"
  mv "$inputs/$asset.part" "$inputs/$asset"
fi
if [ ! -f "$inputs/$MODEL_FILE" ]; then
  curl -fsSL --retry 3 -o "$inputs/$MODEL_FILE.part" "$MODEL_URL"
  mv "$inputs/$MODEL_FILE.part" "$inputs/$MODEL_FILE"
fi
(cd "$inputs" && printf '%s  %s\n%s  %s\n' "$sha" "$asset" "$MODEL_SHA256" "$MODEL_FILE" | sha256 -c -)

# Unpack mesh-llm. The archive holds one directory, mesh-bundle/: the binary
# and the native runtime it finds beside itself. Keep them together.
rm -rf "$out/mesh-llm"
mkdir -p "$out/mesh-llm"
tar -xzf "$inputs/$asset" -C "$out/mesh-llm"
mesh_llm=$out/mesh-llm/mesh-bundle/mesh-llm
test -x "$mesh_llm"

# Build the plugin and the scenario checks. test-period-policy: the Service
# History step runs two-minute periods instead of weekly ones. No release
# build enables it.
(
  cd crates/evidence-plugin
  cargo build --locked --features test-period-policy --bin capsules
  cargo test --locked --bin capsules --no-run
  cargo test --locked --bin capsules --features test-period-policy --no-run
)

# Two nodes, three exchanges, a third node corroborates, then the scenario
# checks; the History pages the nodes served are opened by web-ui's runner.
scripts/e2e-two-node.sh "$mesh_llm" crates/evidence-plugin/target/debug/capsules \
  "$inputs/$MODEL_FILE" "$out"

cd crates/evidence-plugin

# The same checks over the same run, against a receiver built without its
# claim checks: attacks B and D must then FAIL, which shows they test the
# receiver and not only the data. The mutant must build first, so a compile
# error can never pass as "the mutant was caught".
cargo test --locked --bin capsules --features mutant-record-push-skips-claims --no-run
if out_text=$(E2E_REQUESTER_DIR="$out/data/requester" E2E_PROVIDER_DIR="$out/data/provider" E2E_EXCHANGES=3 \
    cargo test --locked --bin capsules --features mutant-record-push-skips-claims \
    -- --ignored --test-threads=1 two_node_e2e::attack_ 2>&1); then
  echo "::error::the attack checks passed a receiver that skips the claim checks"
  exit 1
fi
for attack in attack_b_ attack_d_; do
  grep -q "two_node_e2e::${attack}[a-z_]* \.\.\. FAILED" <<<"$out_text" \
    || { echo "$out_text"; echo "::error::the mutant was not caught by ${attack%_}"; exit 1; }
done

# The plugin under the real host (tests/host_runtime_e2e.rs, ignored unless
# MESH_LLM_HOST_BIN is set), then a build that serves a blocked model, which
# the real host's routing must not hide: the blocked-model case must FAIL.
# Last, because the mutant build replaces the executable the steps above ran.
export MESH_LLM_HOST_BIN="$mesh_llm"
cargo test --locked --test host_runtime_e2e -- --ignored --test-threads=1
cargo test --locked --test host_runtime_e2e --features mutant-blocked-model-served --no-run
if out_text=$(cargo test --locked --test host_runtime_e2e --features mutant-blocked-model-served \
    -- --ignored --test-threads=1 denies_blocked_model_end_to_end_through_real_host 2>&1); then
  echo "::error::the real-host tests passed a build that serves a blocked model"
  exit 1
fi
grep -q "denies_blocked_model_end_to_end_through_real_host \.\.\. FAILED" <<<"$out_text" \
  || { echo "$out_text"; echo "::error::the mutant failed, but not on the blocked-model case"; exit 1; }

echo "e2e: ok"
