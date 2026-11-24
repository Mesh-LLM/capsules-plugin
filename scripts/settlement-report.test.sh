#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# scripts/settlement-report.sh against evidencebook-skills' inference-deals
# payer fixture, with a stand-in `capsules chain-lines`. It counts the book's
# records through capsulectl's own `cll list`, so it holds on capsulectl and
# capsulectl-book v0.1.0-rc49 (jsonl store) and v0.1.0-rc52 (shelf database).
# Needs a capsulectl that loads capsulectl-book and an evidencebook-skills checkout, so it runs
# only when both are named:
#
#   CAPSULECTL=PATH EVIDENCEBOOK_SKILLS=DIR scripts/settlement-report.test.sh
#
# It checks that:
#   - a first run over part of the chain seals and checks a page;
#   - a later run publishes only the records added since, a padding line
#     moves the watermark without a publish, and a run with nothing new seals
#     again;
#   - a run killed between a publish and its watermark resumes without
#     publishing that record twice;
#   - a pending record that is not in the book is dropped without a publish, and
#     the resume check ends instead of paging forever;
#   - a chain shorter than what was published, a node key other than the
#     book's, and a second run while one holds the lock are refused, leaving
#     the page as it was and no seed behind (a finished run leaves none either);
#   - the sealed page shows the 9b wording pack's words (its row label, group
#     title and verdict word, seen in the page's visible text in headless
#     Chrome, CHROME naming it when it is not in the usual places) and not the
#     viewer's "wording pack ... was refused" line, and a wording pack whose
#     digest is not the pinned one is refused before the book is touched.
set -euo pipefail

if [ -z "${CAPSULECTL:-}" ] || [ -z "${EVIDENCEBOOK_SKILLS:-}" ]; then
  echo "settlement-report.test: skipped (set CAPSULECTL and EVIDENCEBOOK_SKILLS)"
  exit 0
fi
here=$(cd "$(dirname "$0")" && pwd)
fixture="$EVIDENCEBOOK_SKILLS/tests/fixtures/inference-deals/payer.jsonl"
total=$(wc -l <"$fixture" | tr -d ' ')
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "settlement-report.test: FAIL: $*" >&2; exit 1; }

mkdir -p "$work/data/keys" "$work/bin"
openssl genpkey -algorithm ed25519 -out "$work/data/keys/node-key.pem" 2>/dev/null
cat >"$work/bin/capsules" <<EOF
#!/usr/bin/env bash
[ "\$1" = chain-lines ] && cat "$work/chain.jsonl"
EOF
chmod +x "$work/bin/capsules"

run() {
  "$here/settlement-report.sh" "$@" --report-dir "$work/report" --capsulectl "$CAPSULECTL" \
    --skills "$EVIDENCEBOOK_SKILLS" --capsules "$work/bin/capsules" --data-dir "$work/data" \
    --date 2026-11-01 --now 2026-11-02T00:00:00Z </dev/null >"$work/run.log" 2>&1
}
id_at() { sed -n "$1p" "$fixture" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capsule_id"])'; }
field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print("" if v is None else v)' "$work/report/book.json" "$1"; }
# How many records the book holds, counted through capsulectl's own list (its
# storage layout differs between releases: rc49 a jsonl file, rc52 a shelf
# database), without a get per record, which is too slow.
held() {
  python3 - "$CAPSULECTL" settlement <<'EOF4'
import json, subprocess, sys
ctl, profile = sys.argv[1], sys.argv[2]
after, n = 0, 0
while True:
    page = json.loads(subprocess.run([ctl, "cll", "list", "--profile", profile, "--after", str(after), "--limit", "1000"],
                                     check=True, capture_output=True, text=True).stdout)
    if not page["entries"]:
        break
    n += sum(1 for e in page["entries"] if e.get("record_type") == "own_capsule")
    after = max(e["sequence"] for e in page["entries"])
print(n)
EOF4
}

# Part of the chain first.
head -n 10 "$fixture" >"$work/chain.jsonl"
run || { cat "$work/run.log"; fail "the first run did not seal a page"; }
[ -s "$work/report/settlement.html" ] || fail "no page after the first run"
# The node checks the page with the capsulectl the run used, read from the book.
[ "$(field capsulectl)" = "$(cd "$(dirname "$CAPSULECTL")" && pwd)/$(basename "$CAPSULECTL")" ] \
  || fail "book.json does not record the capsulectl the run used"
[ "$(field published_lines)" = 10 ] || fail "the watermark is not the partial chain's length"

# A run killed after publishing record 11 but before moving the watermark.
export XDG_CONFIG_HOME="$work/report/config"
export CAPSULECTL_PLUGIN_ROOTS=${CAPSULECTL_PLUGIN_ROOTS:-$(dirname "$CAPSULECTL")}
sed -n 11p "$fixture" | python3 -c '
import json, sys
c = json.load(sys.stdin)
json.dump({"spec_version": "capsule-seal-request/v1",
           "capsule": {"ActionID": "urn:mesh-record:" + c["capsule_id"], "ActionType": "fyi", "Operator": sys.argv[1],
                       "Developer": "capsules-plugin/settlement-report", "Timestamp": c["timestamp"]},
           "payload": c}, open(sys.argv[2], "w"), sort_keys=True)' "$(field node_key)" "$work/eleventh.json"
eleventh=$(id_at 11)
python3 - "$work/report/book.json" "$eleventh" <<'EOF'
import json, sys
book = json.load(open(sys.argv[1]))
book["pending"] = {"line": 10, "capsule_id": sys.argv[2]}
json.dump(book, open(sys.argv[1], "w"))
EOF
# The seed the profile names exists only during a run, so this step makes it
# the way a run does and removes it again.
python3 - "$work/data/keys/node-key.pem" "$work/report/node.seed" <<'EOF2'
import base64, os, sys
body = "".join(l for l in open(sys.argv[1]).read().splitlines() if l and not l.startswith("-----"))
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(base64.b64decode(body)[16:].hex())
EOF2
"$CAPSULECTL" publish --profile settlement --request "$work/eleventh.json" >/dev/null
rm -f "$work/report/node.seed"

# The rest of the chain, and a padding line after it.
{ cat "$fixture"; echo '{"padding":"0000"}'; } >"$work/chain.jsonl"
run || { cat "$work/run.log"; fail "the run after a cut-short one did not seal"; }
# Ten records were held, the cut-short run added the eleventh, and the fixture
# has no padding record, so each of its records is held exactly once only if
# the eleventh was not published again and the rest were published once.
[ "$(held)" = "$total" ] || fail "the book does not hold each record once (the record published before the cut was published again, or one added since was not published)"
[ "$(field published_lines)" = $((total + 1)) ] || fail "the padding line did not move the watermark"
[ -z "$(field pending)" ] || fail "the pending marker was left behind"

run || { cat "$work/run.log"; fail "a run with nothing new did not seal"; }
grep -q '"page": *"match"' "$work/report/settlement.json" || fail "the note does not record a match"
[ "$(held)" = "$total" ] || fail "a run with nothing new published a record again"

# A pending record that is not in the book (a run killed before its publish
# landed): the resume check looks through the whole book, finds nothing, drops
# the marker and publishes nothing; it must end, not page forever.
python3 - "$work/report/book.json" <<'EOF5'
import json, sys
book = json.load(open(sys.argv[1]))
book["pending"] = {"line": book["published_lines"], "capsule_id": "0" * 64}
json.dump(book, open(sys.argv[1], "w"))
EOF5
TIMEOUT=$(command -v timeout || command -v gtimeout || true)
[ -n "$TIMEOUT" ] || fail "NOT RUN: no timeout or gtimeout to bound the absent-pending run"
held_absent=$(held)
"$TIMEOUT" 600 "$here/settlement-report.sh" --report-dir "$work/report" --capsulectl "$CAPSULECTL" \
  --skills "$EVIDENCEBOOK_SKILLS" --capsules "$work/bin/capsules" --data-dir "$work/data" \
  --date 2026-11-01 --now 2026-11-02T00:00:00Z </dev/null >"$work/run.log" 2>&1 \
  || { cat "$work/run.log"; fail "a run with a pending record absent from the book did not finish"; }
[ -z "$(field pending)" ] || fail "an absent pending record's marker was left behind"
[ "$held_absent" = "$(held)" ] || fail "an absent pending record changed what the book holds"

# The page as a person sees it: its visible text, in headless Chrome.
CHROME=${CHROME:-}
for c in "$CHROME" "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" google-chrome chromium chrome; do
  if [ -n "$c" ] && command -v "$c" >/dev/null 2>&1; then CHROME=$c; break; else CHROME=; fi
done
[ -n "$CHROME" ] || fail "NOT RUN: no Chrome to read the page's text (set CHROME)"
pack="$EVIDENCEBOOK_SKILLS/wording/inference-deals-settlement-en.json"
# The window size matters to the viewer (see evidencebook-skills tests/fresh_env_deals.sh).
"$CHROME" --headless=new --disable-gpu --use-mock-keychain --password-store=basic --user-data-dir="$work/chrome-profile" \
  --window-size=1280,2400 --virtual-time-budget=60000 \
  --dump-dom "file://$work/report/settlement.html" >"$work/page.dom" 2>/dev/null || true
[ -s "$work/page.dom" ] || fail "Chrome wrote no DOM for the page"
python3 - "$work/page.dom" "$pack" <<'EOF3' || fail "the sealed page does not show the wording pack"
import html, json, re, sys
text = open(sys.argv[1]).read()
text = re.sub(r"<script.*?</script>|<style.*?</style>", "", text, flags=re.S)
text = html.unescape(re.sub(r"<[^>]+>", "\n", text))
entries = json.load(open(sys.argv[2]))["entries"]
problems = []
if "wording pack supplied with this page was refused" in text:
    problems.append("the viewer refused the pack")
# The payer fixture's page: its own row, the group, the met verdict.
for key in ("row.come_through.paid_as_agreed.label", "group.come_through.title", "report.title"):
    if entries[key] not in text:
        problems.append(f"{key} not shown: {entries[key]!r}")
if not re.search(r"(?<![A-Za-z])" + re.escape(entries["verdict.met"]) + r"(?![A-Za-z])", text):
    problems.append("verdict.met word not shown")
if problems:
    print("; ".join(problems), file=sys.stderr)
    sys.exit(1)
EOF3

before=$(shasum -a 256 "$work/report/settlement.html")
[ ! -e "$work/report/node.seed" ] || fail "a finished run left the book's seed behind"
"$CAPSULECTL" book report check --profile settlement --page "$work/report/settlement.html" >/dev/null || fail "book report check needs the seed"

head -n 5 "$fixture" >"$work/chain.jsonl"
if run; then fail "a chain shorter than what was published was accepted"; fi
grep -q "new history" "$work/run.log" || fail "the shrunk chain's refusal does not say why"

{ cat "$fixture"; echo '{"padding":"0000"}'; } >"$work/chain.jsonl"
mkdir "$work/report/.lock"
if run; then fail "a run was accepted while another held the lock"; fi
grep -q "another run holds" "$work/run.log" || fail "the lock's refusal does not say why"
rmdir "$work/report/.lock"

openssl genpkey -algorithm ed25519 -out "$work/data/keys/node-key.pem" 2>/dev/null
if run; then fail "a node key other than the book's was accepted"; fi
grep -q "not this node's" "$work/run.log" || fail "the foreign key's refusal does not say why"

# A wording pack other than the pinned one is refused before the book is touched.
cp "$pack" "$work/other-pack.json"
printf ' ' >>"$work/other-pack.json"
held_before=$(held)
if run --wording "$work/other-pack.json" --wording-digest "$(shasum -a 256 "$pack" | cut -d' ' -f1)"; then fail "a pack whose bytes are not the digest's was accepted"; fi
grep -q "not the expected" "$work/run.log" || fail "the wrong pack's refusal does not say why"
[ "$held_before" = "$(held)" ] || fail "a refused pack still wrote to the book"

[ "$before" = "$(shasum -a 256 "$work/report/settlement.html")" ] || fail "a refused run changed the page"
[ ! -e "$work/report/node.seed" ] || fail "a refused run left the book's seed behind"
echo "settlement-report.test: ok"
