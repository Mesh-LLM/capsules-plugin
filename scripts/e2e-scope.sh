#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Whether a change needs the two-node run: prints `true` or `false`.
#
#   scripts/e2e-scope.sh BASE_REF   (the change is BASE_REF...HEAD)
#
# Yes when it changes what a node serves or what the History page reads: the
# plugin's source, tests and dependencies, the web UI and its dependencies,
# the policy files and the join texts the binary embeds, the run's scripts,
# pinned inputs and toolchain, the definition documents, the e2e workflow.
# The History page regression of #303 reached main because the run happened
# only on a label. Used by .github/workflows/e2e.yml with the pull request's
# base.
set -euo pipefail
base=${1:?usage: $0 BASE_REF}
# Read into a variable first: `grep -q` closing a pipe early would fail
# `git diff` with SIGPIPE under pipefail.
changed=$(git diff --name-only "$base...HEAD")
if grep -Eq '^(crates/evidence-plugin/(src/|tests/|Cargo\.(toml|lock)$)|web-ui/|policies/|loop/(joins|reporter)/|scripts/(e2e-two-node\.sh|e2e\.sh|e2e-scope\.sh|e2e-inputs\.env)$|rust-toolchain\.toml$|derivations/|\.github/workflows/e2e\.yml$)' <<< "$changed"; then
  echo true
else
  echo false
fi
