#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# scripts/check-plugin-toml.sh on good and bad plugin.toml files, and the
# repository's own plugin.toml. package.sh runs the check, so a package that
# passes carries the key; CI also reads it back out of the built archive.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
check=$root/scripts/check-plugin-toml.sh
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fails=0

expect() { # want(ok|bad) value-line description
  printf 'name = "x"\nversion = "0.1.0"\n%s\n' "$2" > "$tmp/plugin.toml"
  if "$check" "$tmp/plugin.toml" >/dev/null 2>&1; then got=ok; else got=bad; fi
  [ "$got" = "$1" ] || { echo "FAIL: $3 (wanted $1, got $got)" >&2; fails=$((fails + 1)); }
}

expect ok  'min_host_version = "0.78.0"'            "plain version"
expect ok  'min_host_version = "0.81.2"  # note'     "trailing comment"
expect bad ''                                        "key missing"
expect bad 'min_host_version = ""'                   "empty value"
expect bad 'min_host_version = "0.78"'               "two-part version"
expect bad 'min_host_version = ">=0.78.0"'           "a range, not a version"
expect bad 'min_host_version = "v0.78.0"'            "v prefix"
expect bad 'mesh_llm = "0.78.0"'                     "the old key name"
expect bad "min_host_version = '0.78.0'"             "single quotes"

printf 'name = "x"\nmin_host_version = "0.1.0"\nmin_host_version = "0.2.0"\n' > "$tmp/plugin.toml"
if "$check" "$tmp/plugin.toml" >/dev/null 2>&1; then echo "FAIL: duplicate key accepted" >&2; fails=$((fails + 1)); fi

"$check" "$root/plugin.toml" >/dev/null || { echo "FAIL: the repository's plugin.toml" >&2; fails=$((fails + 1)); }

[ "$fails" -eq 0 ] && echo "plugin-toml: all checks passed"
exit "$fails"
