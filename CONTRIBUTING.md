# Contributing

Thanks for helping. This file covers how changes are made and what CI checks.

## Ground rules

- **Apache-2.0.** By contributing you agree your work is licensed under the
  repository's license.
- **DCO sign-off on every commit** (`git commit -s`). The `dco` check fails a
  pull request with any commit that lacks a `Signed-off-by:` line.
- **Pull requests only.** `main` is protected; every change needs a green CI
  run and one approving review.
- **No secrets in the tree.** Never commit private keys, tokens, node ledgers
  or data directories. CI fails on key or token material (`scripts/no-keys.sh`).
- **The plugin's id stays `capsules`.** Nodes key their data directory
  and installed plugin on it. (It was `capsule-emit-mesh` until 0.1.3; that
  rename keeps a node's existing data directory in place, see `INSTALL.md`.)

## Building and testing locally

```bash
# The plugin
cd crates/evidence-plugin
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --test-threads=1

# The Evidence page
cd web-ui
pnpm install --frozen-lockfile
pnpm typecheck && pnpm test && pnpm build   # writes ../bundle/register-mesh-plugin-ui.js

# Repository checks
scripts/no-keys.sh
scripts/mutants.sh            # each plugin mutant fails its tests (slow)
scripts/referee-mutants.sh    # each referee mutant fails its cases (slow)
node --test scripts/*.test.mjs
(cd vectors && shasum -a 256 -c SHA256SUMS)
```

The interop tests run the compiled plugin against a stand-in host over
mesh-llm's plugin wire protocol, and share ports and directories, so run them
with `--test-threads=1`. Tests that need a real `mesh-llm` binary are ignored by
default; [docs/REAL-HOST-VERIFICATION.md](docs/REAL-HOST-VERIFICATION.md)
explains how to run them.

To build and install the plugin from the repository root (needs GNU tar;
`make` lists the targets):

```bash
make package
make install MESH_LLM=/path/to/mesh-llm   # default: mesh-llm on PATH
```

## CI

### Tier 1: every pull request (target: under 10 minutes)

On Linux x86_64, Linux arm64 and macOS arm64 (`.github/workflows/ci.yml`):

- `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test` for the
  plugin, including the conformance vectors in `vectors/`.
- The mutants: each build with one deliberate fault must fail the tests named
  for it, in `gates/mutants.json` (`scripts/mutants.sh`) and
  `vectors/parity/referee/mutants.json` (`scripts/referee-mutants.sh`); and
  serde_json's `unbounded_depth` must not reach the plugin binary.
- The web UI: typecheck, unit tests, and the bundle build.

Once, on Linux:

- `scripts/no-keys.sh`: no private key or token material in any tracked file,
  and no file that never belongs here (Python, demo or red-team material, key
  or token files, node ledgers or data directories, a NOTICE file).
- The vector checksums in `vectors/SHA256SUMS`.
- The release packaging, run twice on one build; the two archives must be
  byte-identical.
- The neutrality check (`.github/workflows/neutrality.yml`): the repository
  carries none of a reserved vocabulary, supplied as a repository secret. On a
  pull request from a fork, a failing run says only that it failed, with no
  term, file or line; a maintainer re-runs it on a trusted event to see the
  details. The scanner's own tests (`node --test scripts/*.test.mjs`) run on every pull
  request in `ci.yml`. The neutrality check runs on
  `pull_request_target` so that fork pull requests get the secret; that is
  safe only because the workflow never runs, builds or installs anything
  from the pull request (it reads the files as text with the base branch's
  scanner). The rules are written at the top of the workflow file.

Changes to the sealing crates (`capsule-emit`, `checkpointed-local-log`) are
tested in their own repositories and reach this one as version bumps.

### Tier 2: nightly, and on the `run-e2e` label

`.github/workflows/e2e.yml` runs two nodes of a pinned, unmodified mesh-llm
release on one Linux runner, each with this plugin: one serves a small model,
the other joins its mesh and sends it three chat completions.
`scripts/e2e-two-node.sh` runs the nodes; once they have stopped, the checks
in `crates/evidence-plugin/src/two_node_e2e.rs` run over what each node wrote:

- each side sealed its own record of every exchange, and both logs verify;
- a forged record is refused: one changed after signing is malformed, and
  one signed by a key this node does not accept is refused from any sender
  id with a signed refusal naming that key; the real record is received
  under another sender id too;
- attack A, a tampered record, and attack C, a dropped one, break the
  provider's log;
- attack B, a record naming another server, and attack D, a record naming
  other model weights, are refused, and the run repeats both against a
  receiver built without its claim checks, which must fail them;
- the host names both sides (mesh-llm 0.78 and later): with record push on
  at both ends, the requester holds the provider's record of every exchange
  and its Evidence page shows each one confirmed; the provider holds none
  from the requester, because the requester is a client node, whose id is new
  each start and so cannot be given a key, and each of its pushes is refused
  for that reason.
- the referee's verdict is sealed on both nodes: while they run, the
  requester holds two test twins' halves of the first exchange and puts the
  pair to the provider over the mesh; the provider signs the verdict, seals
  `adjudication_issued` and delivers it, and the requester seals
  `adjudication_received` for the same verdict, which its own verdict counts
  carry (`src/referee_e2e_setup.rs`). The live trigger, which assembles a
  pair from real twin traffic and chooses the referee, needs three serving
  nodes and is not run here.
- T6, a Service History across a period boundary (PRD T6): the plugin is built
  with the test-only `test-period-policy` feature, and both nodes run it with
  two-minute periods (`CAPSULES_TEST_PERIOD_LENGTH_S`), which is another
  definition with its own digest. The requester asks the provider for a Service
  History at its newest checkpoint (declined off a boundary, answered on one),
  then at a boundary checkpoint, verifies it under the provider's key, and
  compares the card it embeds with the provider's direct `history_card/1`
  answer at the same pin, byte for byte. No release build enables the feature.
- each ask is sealed before it is sent (loop step 7): the requester's
  history-card ask is an `evidence_request` record ahead of the
  `evidence_response` citing it, which verified for exactly the sealed
  request's digest; and an ask to a node not on the mesh ends, once its
  window closes, in a `recorded_absence` citing that request.
- the History page from a live node: while the nodes run, the script saves
  what each node's `history-page` route serves (the requester before its first
  checkpoint, a refusal; later its card; the provider, its Service History).
  `two_node_e2e.rs` checks the refusal and the card verify under the
  requester's own key and the Service History under the provider's, for the
  request the route made (built with `test-period-policy`, as the nodes were),
  and
  `web-ui/src/features/capsules/lib/history-page.e2e.test.ts` builds the
  History page from each `reply`, opens it offline, and checks it verifies
  (or shows the refusal) and hands back the served bytes unchanged.
- the real-host tests (`tests/host_runtime_e2e.rs`, see
  [docs/REAL-HOST-VERIFICATION.md](docs/REAL-HOST-VERIFICATION.md)) pass, and
  fail on a build that serves a blocked model.

The mesh-llm release and the model are pinned by SHA-256 in the workflow and
cached. Add the `run-e2e` label to a pull request to run it before merge.

## Test vectors

`vectors/` holds pinned copies of external test vectors. Don't edit them here:
regenerate at the source, copy unchanged, update the pin in
`vectors/SOURCES.md`, and regenerate `vectors/SHA256SUMS`.

## Reporting a security issue

See [SECURITY.md](SECURITY.md). Please don't open a public issue for a
vulnerability.
