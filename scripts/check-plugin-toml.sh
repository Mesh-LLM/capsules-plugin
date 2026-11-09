#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Check that a plugin.toml declares the MeshLLM host versions its release
# supports. The key is KEY below; the value is a semver range of
# comma-separated comparators on MAJOR.MINOR.PATCH, such as ">=0.78.0" or
# ">=0.78.0, <0.81.0". mesh-llm#2971 reads it to tell a compatible plugin from
# one a host upgrade must repair; a package without it is `unknown` there.
#
# Usage: scripts/check-plugin-toml.sh [PLUGIN_TOML]   (default: ./plugin.toml)
# Prints the range on success; exits 1 with a message when it is missing or
# not a range.
set -eu

KEY=mesh_llm
file=${1:-plugin.toml}
[ -f "$file" ] || { echo "check-plugin-toml: no file $file" >&2; exit 1; }

range=$(sed -n "s/^$KEY *= *\"\([^\"]*\)\" *\(#.*\)\{0,1\}\$/\1/p" "$file")
[ -n "$range" ] || { echo "check-plugin-toml: $file declares no $KEY = \"<range>\"" >&2; exit 1; }
[ "$(printf '%s\n' "$range" | wc -l)" -eq 1 ] || { echo "check-plugin-toml: $file declares $KEY more than once" >&2; exit 1; }

cmp='\(>=\|<=\|>\|<\|=\|\^\|~\) *[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*'
printf '%s\n' "$range" | grep -q "^ *$cmp\( *, *$cmp\)* *\$" ||
  { echo "check-plugin-toml: $KEY = \"$range\" in $file is not a range such as \">=0.78.0, <0.81.0\"" >&2; exit 1; }
printf '%s\n' "$range"
