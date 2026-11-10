#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Check that a plugin.toml declares the oldest MeshLLM host its release works
# with: `min_host_version = "MAJOR.MINOR.PATCH"` (inclusive), the key mesh-llm
# reads from the packaged file (mesh-llm#2978, plugin_toml.rs). A package
# without it is `unknown` to the host's upgrade check.
#
# Usage: scripts/check-plugin-toml.sh [PLUGIN_TOML]   (default: ./plugin.toml)
# Prints the version on success; exits 1 with a message when it is missing or
# not a three-part version.
set -eu

KEY=min_host_version
file=${1:-plugin.toml}
[ -f "$file" ] || { echo "check-plugin-toml: no file $file" >&2; exit 1; }

# Only the top level counts: a key under a [table] is another key to TOML.
top=$(sed '/^[[:space:]]*\[/,$d' "$file")
n=$(printf '%s\n' "$top" | sed -n "s/^[[:space:]]*$KEY[[:space:]]*=.*/x/p" | wc -l)
[ "$n" -le 1 ] || { echo "check-plugin-toml: $file declares $KEY more than once" >&2; exit 1; }
value=$(printf '%s\n' "$top" | sed -n "s/^$KEY *= *\"\([^\"]*\)\" *\(#.*\)\{0,1\}\$/\1/p")
[ -n "$value" ] || { echo "check-plugin-toml: $file declares no top-level $KEY = \"MAJOR.MINOR.PATCH\"" >&2; exit 1; }
printf '%s\n' "$value" | grep -q '^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' ||
  { echo "check-plugin-toml: $KEY = \"$value\" in $file is not MAJOR.MINOR.PATCH" >&2; exit 1; }
printf '%s\n' "$value"
