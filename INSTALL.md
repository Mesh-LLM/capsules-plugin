# Install the capsules plugin on a mesh-llm node

`capsules` is a mesh-llm plugin. It keeps a signed, hash-chained
record of every exchange this node serves or asks for, on this node's disk,
and adds an **Evidence** page to the console: the peers you exchanged with,
each exchange, and whether this node's log still verifies. It installs and
runs on an unmodified mesh-llm release (0.77 or newer). No other runtime is
needed.

## What's new in 0.1.9

**Upgrading from 0.1.8 needs nothing installed on the other node.** One answer changes for peers:
`served_summary/1` is retired (first item). A provider answers an asked exchange half as an Evidence
Bundle only from 0.1.9.

- **Two sharing settings now default to on (#163).** `share_adjudications` defaults to
  `deliver_to_subjects` and `share_exchange_corroboration` to `on`: a node that never set either now
  delivers a referee's verdict to the node it judges (a delivered verdict cannot be recalled) and
  answers a node that asks whether it holds its half of one exchange. Set either to `off` to keep the
  old behavior.
- **`served_summary/1` is no longer answered.** Now that the weekly Service History cells are
  published, the summary minus those cells would reveal a withheld week's count. Every requester is
  refused it: `derivation_unsupported`, or `policy_declined` (as for any gated derivation) from a
  non-counterparty while `share_standard_history` is off. The commitment lists
  `service_history/1` in its place, and `share_standard_history` covers `service_history/1` and no
  longer `served_summary/1`.
  A 0.1.8 or older peer's `served_summary/1` answer is no longer checked here.
- **A provider can answer an asked exchange half as an Evidence Bundle,** and a payer can compose a
  deal's two-sided receipt from its own records and the provider's bundle. The payer keeps each
  ask reply's bytes, with their digest sealed in the `evidence_response` record, so a refusal or
  artifact member carries the reply as it was received. A composition whose interval crosses a
  padding leaf is still refused, until `non_record_leaves` emission is enabled.
- **Serving a half no longer refuses `not_authorized` when another record lands at the same
  moment.** Each served half is sealed and its checkpoint cut under one hold of the ledger.
- **A refused asker can no longer tell how many records match.** The sharing gate now runs before
  the record limit on every answer path, and a record that never leaves the node is in no keyed
  answer's matched set.
- **A deal closed `open` can be completed later:** a payment that settles after the close seals a
  second outcome, close and report. After a node restart, a settlement for an exchange from before it
  cannot arrive yet.
- **Built with agent-action-capsule 0.7.0.**

Details in [CHANGELOG.md](https://github.com/Mesh-LLM/capsules-plugin/blob/main/CHANGELOG.md).

## What's new in 0.1.8

**Upgrading from 0.1.7 needs nothing installed on the other node.** For a pushed terms leg to
carry its proof there, the provider needs a version that reads bundles (any release since bundles
shipped); an older one keeps the leg bare.

- **With the checkpoint cadence on, a payer's settlement terms leg is pushed with its checkpoint
  and inclusion proof,** as other pushed records are, so a provider holds the proof that each leg
  it received was in the payer's log. Legs an earlier version pushed without one are pushed once
  more, under a checkpoint, soon after the payer starts with the cadence on and sending records at
  completion on (at the host's first mesh event or its first channel message, whichever comes
  first): at most 64 per start, to the peer each leg's sealed exchange record names. It re-sends
  sealed records only and moves no money. A provider that reads bundles adds the proof to the leg
  it already holds; an older one keeps the leg bare (recorded as `no_inclusion`), and that leg is
  not re-sent. Each leg also carries this node's controller binding, as its chat halves to that
  peer do.
- **Signed checkpoints over the ledger files.** received-capsules, received-provenance,
  received-inclusion, the three adjudication files and the chain itself each have a node-signed
  checkpoint with a range proof, on the owner console at
  `GET …/http/ledger-checkpoint?file=<name>[&from=i&to=j]`; `capsules ledger-check` checks a copy
  offline. See [docs/LEDGER-CHECKPOINTS.md](docs/LEDGER-CHECKPOINTS.md).
- **The Evidence tab is redesigned** around the three ways a stranger could cheat: the header and
  attack cards, the Peers table and drawer, the Integrity tab, "How we checked", and a paid
  Exchanges row's receipt, checked in the browser.
- **Configuration is regrouped** into "What you show others", "When answers differ" and "Keeping
  records"; no setting changes meaning. The Witnesses field suggests the agentactioncapsule.org
  witness and stores it only when you set it.

Details in [CHANGELOG.md](https://github.com/Mesh-LLM/capsules-plugin/blob/main/CHANGELOG.md).

## What's new in 0.1.7

**Upgrading from 0.1.6 needs nothing on the other node.**

- **An `exchange` request is answered to the node whose half it asks about.** In 0.1.6 a node
  refused it `not_authorized` to every asker under `share_history_segments = counterparties`,
  the half's own sender included. Now the record citing a received half goes to a request signed
  under the key that half verified under, and to no one else. Records already in the ledger are
  read as they are; nothing is re-pushed.
- **Admission's price rule.** With `CAPSULES_ADMISSION_PROFILE` set, a peer the admission lists
  admit is then checked against the input and output rate caps in that `policy-profile/v0` file:
  a rate over a cap, or one that cannot be read, is NO, and the reason names the rule. With no
  profile, shipped caps apply as an outlier guard, and a request that carries no rate is recorded
  `not_checked` rather than refused. The host must list `openai_exchange.backend_pricing.v1` to
  send the rates; no mesh-llm release does yet, and `doctor` flags a host that does not. Until
  one does, a profile you set gives every peer NO, free ones included (it fails closed).

Details in [CHANGELOG.md](https://github.com/Mesh-LLM/capsules-plugin/blob/main/CHANGELOG.md).

## What's new in 0.1.6

**Upgrading from 0.1.5 needs nothing on the other node.** This version answers both interop profile
identifiers and asks under `evidence-interop/1`; a 0.1.5 node refuses that, and the ask is sent once
more under `evidence-interop/0`, which 0.1.5 answers.

- **A refusal says whether it was policy.** Under `evidence-interop/1` (Evidence Request -02) a node
  declines for a limit of its own with `capacity_exceeded`, and refuses a request whose signature
  does not check with `request_unauthenticated`; `policy_declined` and `not_authorized` are then
  policy only, and are checked against the policy the peer's commitment pins.
- **Each ask is recorded,** before it is sent: the request, then the answer, the refusal, or that
  nothing came back in its window.
- **The payer seals a paid exchange as a deal;** the payer's deal and the provider's own receipt
  can each be exported as an Evidence Bundle. The deal's steps go to the counterparty of the
  exchange; the payer's deal report stays on this node.
- **The Service History** (`service_history/1`): what this node served, per period, as a Standard
  History.
- **Service evidence agreements** and their coverage on the Exchanges rows, and the **join switch,
  `doctor` and the operator binding** (loop steps 6, 7 and 12).
- **The Evidence tab says when a peer's answer is not witnessed.**

**Changed defaults and readings:**

- **`share_record_at_completion` is now on by default (`counterparty`).** An upgraded node pushes
  its sealed record of a completed exchange to the counterparty, and accepts the counterparty's,
  without any setting changed. Set `share_record_at_completion = "off"` to keep 0.1.5's behaviour.
- **Pushes and evidence requests are accepted on the sender's evidence key,** not the peer id they
  arrive from.
- **`served_summary/1` counts only witness receipts it can verify:** `coverage.witnessed` can drop,
  and a receipt this node cannot check reads `NOT_CHECKED`.

Details in [CHANGELOG.md](https://github.com/Mesh-LLM/capsules-plugin/blob/main/CHANGELOG.md).

## What's new in 0.1.5

**Upgrade both nodes:** a node on 0.1.4 cannot read this version's evidence answers, and under the
default settings this version refuses its unsigned requests for records and `served_summary/1`.

**Requests are signed only on a host that announces plugin keys** (`plugin_keys.v1`,
Mesh-LLM/mesh-llm#2299, expected in mesh-llm 0.79.0; no release has it yet). On mesh-llm 0.78.1 or older, requests
go out unsigned, and two upgraded nodes answer each other no record, and with the default settings
no `served_summary/1`; see the CHANGELOG for the setting that keeps answering the latter.

**Updating from mesh-llm 0.78.x.** The default `capsules` comes from the mesh-llm release's own
bundled copy. Upgrade mesh-llm to the release that pins capsules 0.1.5, then run:

```bash
mesh-llm plugins install-defaults
```

It installs from that release's bundled copy and never downloads. A `capsules` that the operator
installed themselves (`mesh-llm plugins install`, which is what the steps below
do, or a `[[plugin]]` entry with a `command` or `url`) is operator-managed and is left as it is:
install the 0.1.5 package below instead.

- **Who asks for evidence is proven, not stated.** On a host that announces plugin keys, each
  request is signed with the key mesh-llm announces for the node, and a node that claims to be
  another is refused before anything is looked up.
- **A node gets back the record of the exchange it asked for,** and counts as that record's
  counterparty. On `share_history_segments = peers`, records now also show which node asked.
- **Evidence answers are the interop profile's signed envelope** (`evidence-request` 0.2.0), the
  same envelope the Go, Python and evidencebook implementations sign.
- **Checkpoints and `history_card/1` are answered to any requester;** the rest of Standard History
  (`served_summary/1`) goes only to counterparties by default (`share_standard_history`).
- **Exchange corroboration,** off by default (`share_exchange_corroboration`): another node can ask
  whether this node holds a half of one earlier exchange.

Details in [CHANGELOG.md](https://github.com/Mesh-LLM/capsules-plugin/blob/main/CHANGELOG.md).

## What's new in 0.1.4

- **Paid exchanges on the Evidence page:** what each one charged and who paid, from the records
  this node sealed, and "outcome not reported" where the host reported none. An exchange this node
  served for pay shows its own book as the provider.
- **The referee can take a twin pair's texts from the client,** and **peers' keys from the host**
  when mesh-llm announces them (`CAPSULES_PEER_KEYS` stays the fallback). Neither has run yet on a
  stock mesh-llm release: see the CHANGELOG.
- **The console's navigation stays on the Evidence page,** a served exchange with no other side
  reads LOCAL, and twin pairs show on Peers.

Details in [CHANGELOG.md](https://github.com/Mesh-LLM/capsules-plugin/blob/main/CHANGELOG.md).

## What's new in 0.1.3

- **The plugin is now called `capsules`** (it was `capsule-emit-mesh`), and so is its repository,
  `Mesh-LLM/capsules`. Its settings are `CAPSULES_*`, its page is `/plugins/capsules/evidence`, and
  its data directory is `~/.local/share/capsules`. A node upgrading keeps its key and records: see
  [Upgrading from capsule-emit-mesh](#upgrading-from-capsule-emit-mesh).
- **Settings saved in the console reach the plugin.** mesh-llm keeps them in its config file and
  does not pass them to the plugin, so the plugin reads them there. A node started with
  `--config <path>` must also have
  `MESH_LLM_CONFIG=<path>` in its environment, or the plugin reads `~/.mesh-llm/config.toml`.

- **Quiet by default.** Pushing this node's record to the counterparty, delivering verdicts, and
  asking a referee are now **off by default** (record push is on by default again since #68); turn each on under Configuration › Plugins (see
  [What it sends](#what-it-sends-and-where-it-listens)). Answering a peer that asks for a record is
  unchanged.
- **Stop routing after N goes through the host's plugin path.** The rule now asks mesh-llm to block
  the peer as this plugin's request, which the host refuses unless you set `allow_peer_blocks =
  true` for this plugin. The plugin no longer calls the console's own route.
- **Several witnesses.** **Witnesses** in the console is a list: each witness's URL and, if you have
  it, its public key (still none by default, and no witness is contacted until you add one). The
  Evidence page shows what each witness holds, and counts a witness only once its receipt checks
  against the witness's key. A key you don't give is fetched from the witness once and kept, and
  the page says so. Every witness is contacted at exactly the URL you give, and no redirect is
  followed.
- **On mesh-llm 0.78 and later:** the Evidence page can be a primary console tab (your choice, under
  Configuration › Plugins), and a chat answer this node sealed shows "Sealed on this node" with a
  link to its record. An exchange can be confirmed by the other side once you turn record push on
  (see [What works today](#what-works-today)).

## What's new in 0.1.2

- **No models, no provider by default.** 0.1.1 registered an OpenAI-compatible provider on every
  node and listed `blocked-test-model` (it always answers 403) unless `CAPSULE_EMIT_MESH_BLOCKED_MODELS`
  was set. From 0.1.2 the plugin registers no provider and serves no models unless you name blocked
  models in that variable.

## What's new in 0.1.1

- **Settlement-record legs for paid exchanges** (draft-mih-agent-settlement-records-00): both
  sides seal their own legs for each invoice. The provider's leg needs a mesh-llm host whose
  settlement events carry the wallet's credited amount and fee (Mesh-LLM/mesh-llm#2169).
- **A node-unique log id** by default, so a witness accepts every node's checkpoints (see
  [The log's id](#the-logs-id)).
- **A served half is found by its digests** when the host forwarded no nonce. Both nodes need
  0.1.1 for this.
- **The witness indicator** says "off" only when no witness is set.

Details in [CHANGELOG.md](https://github.com/Mesh-LLM/capsules-plugin/blob/main/CHANGELOG.md).

## What it sends, and where it listens

Records are kept on this node. **With the default settings the only thing the
plugin sends to a peer on its own is this node's sealed record of a completed
exchange, to the other side of that exchange**, and, when a referee has judged a
pair, that verdict to the nodes it judges; it also accepts that peer's record
the same way. It sends nothing else while idle or serving, and answers a peer
that asks it for one of its records, or whether it holds its half of one
exchange. Everything else that reaches a peer is off until you turn it on. Set `share_record_at_completion = "off"` to send
and accept no pushed record. The public checkpoint list shows when this node's
exchanges ended; the record itself goes only to the counterparty:

| What | To whom | Default | To turn it on (or off) |
| --- | --- | --- | --- |
| This node's own sealed record of a completed exchange (a push) | the peer in that exchange | **on** | `share_record_at_completion = "off"` |
| A verdict a referee signed, delivered to the nodes it judges (a delivered verdict cannot be recalled) | those nodes | **on** | `share_adjudications = "off"` |
| Whether this node holds its half of one exchange, when any node asks by the exchange's nonce (ids and digests only, never the other side) | the asking node | **on** | `share_exchange_corroboration = "off"` |
| Asking a referee when two twins of a client-marked pair answered differently. **This sends the twins' request (the prompt's `messages`) and both twins' answers to the referee peer**, which answers the request with its own inference | one eligible peer | **off** | `adjudicate_differing_twins = "on"` |
| Stopping routing to a peer after N contradictions | (a request to your own host) | **off** | set `stop_routing_after_contradictions`, and `allow_peer_blocks = true` for this plugin in mesh-llm's config |
| One of this node's records, when a peer asks for it by id | the peer that record names as the other side | on: an answer, never a push | `share_history_segments = "off"` |
| This node's Service History (`service_history/1`: exchanges served per model and week, a count under 5 withheld), when a node asks | a counterparty always; any other node only when on | **off** for any other node | `share_standard_history = "on"` |
| A signed checkpoint of the log | the witness services you name | **off**: none by default | add witnesses under **Witnesses** |

The value this node is acting on is written to `sharing-effective.json` in
its data directory (`share_record_at_completion`: `counterparty` or `off`,
plus `source`: `env`, `console` or `default`, and `written_at`). A value the
plugin does not know is `off`, with the value you set shown as `raw_value`.
The file is the node's own report, unsigned, and is never sent to a peer.

The referee also needs the pair's text on this node. Stock mesh-llm passes no
exchange text to plugins, so the client that marked the pair supplies it
(`referee_supply_twin_texts`: the request and both answers). They are kept
only when the referee is on, each is the body this node's own records sealed,
and the answers differ. Turning the referee on, and supplying a pair's text,
is the decision to send a prompt to a third node.

All peer traffic uses mesh-llm's own peer connections. Nothing goes to any
third party unless you name a witness. The switches are under Configuration ›
Plugins › Capsules, and [`docs/SHARING-POLICY.md`](docs/SHARING-POLICY.md)
explains each one. The plugin reads what you save there from mesh-llm's
config file: `~/.mesh-llm/config.toml`, or the file `MESH_LLM_CONFIG` names.
**If you start the node with `--config <path>`, also set
`MESH_LLM_CONFIG=<path>`** in its environment, or the plugin reads the default
file and your console settings don't reach it. Settings in the environment win
over the console. The witness and the checkpoint cadence are read when the
plugin starts: restart the node after changing them.

The plugin listens only on `127.0.0.1`, at a random port the node reaches it
through.

## Install

One path, the same on macOS 11 or newer (Apple Silicon) and on Linux with
glibc 2.35 or newer (x86_64 or arm64).

**1. Download the package for your machine and the checksum file** from the
[releases page](https://github.com/Mesh-LLM/capsules/releases),
and set `VERSION` to the release (without the leading `v`):

```bash
VERSION=0.1.10
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  TARGET=aarch64-apple-darwin ;;
  Linux-x86_64)  TARGET=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
BASE=https://github.com/Mesh-LLM/capsules/releases/download/v$VERSION
curl -fLO "$BASE/capsules-$VERSION-$TARGET.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
```

**2. Check the download.** This must print `OK` for your file:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
```

With the GitHub CLI you can also check where it was built:

```bash
gh attestation verify "capsules-$VERSION-$TARGET.tar.gz" \
  --repo Mesh-LLM/capsules
```

The checksum proves your file is the one published. The attestation proves it
was built by this repository's release workflow from the tagged commit.
Neither says the code is safe to run; that is a judgement about the source,
which is public here.

**3. Install it.**

```bash
mesh-llm plugins install --archive "capsules-$VERSION-$TARGET.tar.gz" \
  --name capsules --version "$VERSION"
```

`mesh-llm plugins install Mesh-LLM/capsules` installs a release straight
from GitHub instead, without your own checks in steps 1 and 2. Either way the
command unpacks the
package into the node's plugin directory (`~/.mesh-llm/plugins`, or
`MESH_LLM_PLUGIN_DIR`) and enables it. `mesh-llm plugins info
capsules` shows what was installed.

**4. Restart the node.** An installed, enabled plugin starts with the node; no
config entry is needed.

**5. Open the console.** The plugin adds a page labelled **Evidence**. After
the node serves or asks for an exchange, the page shows the peer, the
exchange, and the log's integrity.

## What works today

| | |
| --- | --- |
| Install, start, the Evidence page | works |
| Each node seals its own record of each exchange | works |
| An exchange confirmed by the other side | works on mesh-llm 0.78 and later, once turned on (below); not on 0.77 |

A confirmed exchange is the serving node's record and the requesting node's
record, matched and each held by the other side. Since mesh-llm 0.78 the
exchange event names both nodes: `requested_by_node_id` on the event the
serving node sees (which peer asked), and `served_by_node_id` with the request
and response digests on the event the requesting node sees for a request
another peer served. mesh-llm 0.77 has neither, so there each node holds only
its own record, and nothing is shown as confirmed.

Confirmation needs each node to send its record to the other side, which
`share_record_at_completion` (`counterparty`) does by default: leave it on, on
both nodes, and give each node the other's key (below).

**Each node must know the other node's public key.** The plugin accepts a
record only when it knows the key that signed it, and refuses the rest. The
key is what counts, not the peer id the record arrives under: a known key is
accepted under any id, and a known id with an unknown key is refused. It knows
a key from any of three places:

- **The host,** when mesh-llm announces plugin keys (it lists the
  `plugin_keys.v1` capability): each directly-connected peer's key for this
  plugin, bound to that peer by its node key, read from the host's
  `GET /api/plugin-keys` (`CAPSULES_HOST_CONSOLE_URL`, default
  `http://127.0.0.1:3131`). This plugin announces its own key there at start,
  on a host that lists `plugin_keys.v1`.
- **You:** set `CAPSULES_PEER_KEYS` in the node's environment to a JSON object
  mapping a name to a raw Ed25519 public key in hex. The name is a peer's id,
  or any label for a node with no stable id. A node writes its own id to
  `<data dir>/self-peer-id` and its public key to
  `<data dir>/keys/node-key.pub.pem`. This is a stopgap: it rests on your
  word alone, with no host or key vouching for it, and the record of what
  was accepted says so (`accepted_via: operator_stopgap`). A key a host
  announces is known by the host's peer id, not by your label.
- **A controller declaration** the sender carries: a `controller-binding/0`
  record (Controller Binding v0) that both keys signed, binding the sender's
  key to a key known one of the other two ways. Only `same_controller_asserted`
  under `dual_signature/0` is used, and only inside its window. A key that a
  carried declaration binds to this node's own key is refused, however else
  it is known: it is this node's side, never a counterparty.

If the host and `CAPSULES_PEER_KEYS` give a peer different keys, nothing
signed by either key for that peer verifies until you remove the stale entry.

**A client-only node (`mesh-llm client`)** gets a new peer id each time it
starts. Name its key in `CAPSULES_PEER_KEYS` under any label, and its pushed
records are accepted whatever id they arrive under.

## Get your node ready to join

<!-- join-quickstart: generated by `capsules --print-join-quickstart`; do not edit -->
`CONSOLE` is your mesh-llm console, for example `http://127.0.0.1:3131`.

1. **Get ready.** Nothing to set up by hand: the plugin creates its key and its book on
first start, and cuts its first checkpoint after the node's first exchange. `join`
checks all of it and lists what is in place and what is not:

```bash
curl -s -X POST -H 'content-type: application/json' -d '{}' $CONSOLE/api/plugins/capsules/tools/join
```

`joined` is true once this node is ready to be listed: the book has a checkpoint, the
commitment it serves on `commitment/1` verifies, and both stranger probes match. Before
the first exchange, `pending` names the missing checkpoint; run `join` again after it.
Running it again changes nothing.

2. **Check.** `doctor` lists what is self-attested, unwitnessed, unchecked, unbound or
not shared, one finding per line, never a score. With `probe`, it also asks the
node's own responder `checkpoints`, then `history_card/1`, as a stranger, in process (no
network), and checks that each answer verifies under the key the commitment
advertises (the node's own key when it serves no commitment yet) and that the node
answers under the policy the commitment signs:

```bash
curl -s -X POST -H 'content-type: application/json' -d '{"probe": true}' $CONSOLE/api/plugins/capsules/tools/doctor
```

3. **Bind the node to you (optional).** Give `join` your Nostr public key (64 hex,
the key behind your npub). It signs the node's half and returns, under
`controller_binding_ceremony.event`, a Nostr event for you to sign with your own
signer; the node never sees your secret key:

```bash
curl -s -X POST -H 'content-type: application/json' -d '{"controller": "<your key>"}' $CONSOLE/api/plugins/capsules/tools/join
```

Sign it, do not publish it: never send this event to a relay, which would link your
key to the node. Then pass the signed event back:

```bash
curl -s -X POST -H 'content-type: application/json' -d '{"controller_event": <signed event>}' $CONSOLE/api/plugins/capsules/tools/join
```

`doctor` then reports `controller_binding: bound`, and the commitment names the
binding by its digest alone, never your key. Show the binding record only to the
parties that need it. The binding holds for a year: the plugin does not yet send or
read revocations (Controller Binding §5), so it holds until its `not_after` or until
you run the ceremony again.

4. **Publish the commitment.** This returns the signed commitment and its policy; then
add it to the commitment list by pull request:
https://github.com/evidence-network/loop/blob/main/nodes/README.md

```bash
curl -s -X POST -H 'content-type: application/json' -d '{}' $CONSOLE/api/plugins/capsules/tools/commitment
```

5. **Join the list.** In the console (Configuration, Plugins, capsules), turn on
"Join the evidence network". The statement under the switch is what you agree to. The node then
signs one join with its plugin key, with no handle and no operator name, and sends
it to the network's reporter node; `join` shows under `network` whether the reporter
has it. While no reporter is named yet (`network.reporter` is null), nothing is sent.
To leave, turn the switch off.

`join` and `doctor` seal nothing and contact nobody; `join` writes only a binding or a pending one.
<!-- /join-quickstart -->

## Admit or refuse peers

When this node routes a request to a mesh peer, it can first decide GO or NO for that peer from
your lists, and seal the decision in its book:

- `CAPSULES_ADMISSION_ALLOW`: peers to admit, as comma-separated 64-hex mesh node ids.
- `CAPSULES_ADMISSION_DENY`: peers to refuse, in the same form. A peer on both lists is refused.
- `CAPSULES_ADMISSION_DEFAULT`: `go` (the default) or `no`, for a peer on neither list.

A peer your lists admit then meets the price rule, decided by capsule-engine's `asg/inference`
terms pack (the same evaluator and vectors Muse uses). It compares the input and output rates the
peer advertised for the model, in msat per million tokens, with your caps:

- `CAPSULES_ADMISSION_PROFILE`: the path of a `policy-profile/v0` JSON file. For example:

  ```json
  {"format":"policy-profile/v0","packs":[{"pack":"asg/inference","parameters":{
    "rate_cap":{"max_input_msat_per_million":2000000,"max_output_msat_per_million":8000000}}}]}
  ```

  It may also set the pack's `counterparty_list`. A rate over a cap, a rate the peer did not
  state, or a peer that list refuses gets NO, naming the rule. A free route (no price) is GO.
  With no file set, the shipped caps apply: 500,000 and 1,500,000 msat per million, far above
  any real price, so they only stop an outlier. A file that does not read gives every peer NO
  until you fix it and restart mesh-llm. Your file is yours: an upgrade never rewrites it.

The rates are the ones mesh-llm routed on, which a host sends with each attempt once it lists
`openai_exchange.backend_pricing.v1`. When the price is not known (an older host, or a request that
names no model, whose route mesh-llm never prices): with your profile set, the peer gets NO,
failing closed; with only the shipped caps, the rule is recorded as not checked, and on an older
host `doctor` warns that it is inactive. Each
decision cites the pack, its definition digest and a salted commitment to your profile's digest
(the profile holds your list in clear), and `doctor` shows the digest with your values. A profile
that sets no `rate_cap` keeps the shipped caps.

Each decision also records what the base policy's five rows (policy `base/1`) read about the peer,
from its history card and this node's own book. The rows decide nothing: only your settings give a
NO. They record:

- **identity**: the card verifies under the record key the peer announced;
- **key age**: the card's first checkpoint is at least 7 days old. That time is the peer's own
  statement, witnessed or not, so a peer can backdate it: `pass` is not proof of age;
- **performed and settled**: this node has at least one settled exchange with the peer;
- **disputes**: no referee has ruled against the peer (`contradicted`) in the last 30 days, counting
  only verdicts this node asked for or issued; `not_read` while this node holds no verdict about the
  peer at all;
- **corroboration**: this node holds the peer's pushed half of at least one exchange.

A row that fails stays a record; to refuse such a peer, add it to your deny list. The thresholds
are placeholders, fixed in this version.

The lists and these rows are decided by capsule-engine's admission evaluator under the base pack
the plugin ships, `asg/mesh_admission_base/1.0.0` (`policies/admission/mesh-base/`): your deny
and allow lists are its only rows that can give NO, and the five rows are recorded. With
`CAPSULES_ADMISSION_DEFAULT=no` the allow row refuses a peer on neither list; otherwise no allow
list refuses anyone. The decisions are the ones the lists gave before.

The settings are read once at start; restart mesh-llm after changing them. Nothing is fetched
while a request waits: a peer's card is asked for in the background (at most once an hour per
peer, and again daily), and the book is re-read every minute. Until then the rows read `not_read`.

If a setting does not parse, the plugin keeps running and refuses every
peer (`unreadable_policy` in the log and the records) until you fix it and restart, so a typo
never admits a peer you meant to refuse.

mesh-llm asks the plugin only on a build with the OpenAI exchange lifecycle
(Mesh-LLM/mesh-llm#2226; no release carries it yet), and only when your host config grants it,
under the plugin's `[[plugin]]` entry:

```toml
[plugin.openai_exchange_grant]
endpoints = ["chat_completions", "completions", "responses"]
phases = ["backend_selected"]
admission = true
deadline_ms = 250
max_body_bytes = 1048576
max_queue_bytes = 4194304
max_in_flight = 32
failure_policy = "required"
```

For a service evidence agreement to cover the exchange the hook admits, raise `deadline_ms`
(the plugin declares at most 2000) and set `CAPSULES_AGREEMENT_HOOK_WAIT_MS` below it, with
room for the decision itself (`docs/AGREEMENTS.md`).

A NO refuses the request with 403 `plugin_policy_denied`; trying the next peer instead waits on
Mesh-LLM/mesh-llm#2061. With `failure_policy = "required"`, a hook that errors or misses
`deadline_ms` also refuses the request (503). With the default, `best_effort`, mesh-llm routes
the request anyway. The same holds while the plugin is stopped or not loaded: with `required`,
mesh-llm refuses every request (503) until the plugin is back; with `best_effort`, it routes to
every peer, deny list included.

Each decision is an `admission_decision` record: the verdict, which list or the default
gave it, each row's result (`pass`, `fail` or `not_read`) with the evaluator's effect and, where
the row counts, its count and denominator, the digest of the policy it read, the base pack and its
definition digest, and the history card it read, by a commitment like the peer's. The record never names the peer in clear, since records can
be shared with others; it names the peer by a commitment only this node's key can open, so a peer
cannot check a record about itself unless you open it. If the key is lost, so is the way to say
which peer an old record names. If a decision cannot be sealed, the answer is NO and the log says
`admission_seal_failed`, so a broken book stops peer traffic visibly rather than admitting peers
unrecorded.

## Where the records are kept

Under the plugin's data directory: `CAPSULES_DATA_DIR` if set in the
node's environment (an absolute path), else `$XDG_DATA_HOME/capsules`,
else `~/.local/share/capsules`. The sealed log is kept in one SQLite file,
`<data dir>/ledger/shelf.db`: the node's EvidenceBook shelf, which holds each
record's `capsule_id` in order, the log's checkpoints, and each record with its
signed statement. The node's signing key is under `<data dir>/keys/`; it never
leaves the node.

To read the sealed log as one record per line, run
`capsules chain-lines [--data-dir <dir>] [--from <i>] [--to <j>]`. It prints
lines `i` to `j` (0-based, padding records included; the whole log by
default) in the `capsules.jsonl` line format earlier releases wrote, and can
run while the node runs. It exits 0 on success, 2 for a bad argument or a range
outside the log, and 1 when the log cannot be read. `capsules chain-checkpoints
[--data-dir <dir>]` prints the log's checkpoints, oldest first, in the
`checkpoints.jsonl` line format, the same way: it exits 0 (printing nothing
when there is no checkpoint yet), 2 for a bad argument and 1 when they cannot
be read.

**A node from an earlier release** kept its log in
`<data dir>/ledger/capsules.jsonl`, with `signed-statements/`,
`checkpoints.jsonl`, `mmr_nodes.dat` and `witness-backfill.jsonl` beside it.
At its first start on this release the plugin moves those records and
checkpoints into `shelf.db`, as they were (nothing is signed again),
checks that they match, and then moves only those five to
`<data dir>/archive/pre-store/`. Nothing is deleted. A start cut short
during the move finishes it at the next start. Each start spends at most a
few seconds on the move, so the node starts within mesh-llm's deadline: on a
node with a long log the move takes more than one start, and until it is done
the node keeps using its old files, which still hold every record. If the
files do not match, the node refuses to start, says why, and leaves the old
files where they were;
every start tries again. To run the node on an earlier release instead, stop
it and remove `ledger/shelf.db` and `ledger/import-pending.json`, which hold
only a partial copy. This works only while `archive/pre-store/` holds none of
those five files. If it holds any, start this release again so it finishes the
move. From then on the move is one way.

Once the move has finished, do not start an earlier release on that data
directory: it finds no `capsules.jsonl`, starts a new, empty log under the
same log id, and its first checkpoints contradict the ones peers already hold
for that log. Copying the files back from `archive/pre-store/` is not a way
back either: records sealed since the move are only in `shelf.db`.

So before the first start of this release, stop the node and back up
`<data dir>/ledger/`. To go back to an earlier release later, stop the node
and restore that backup; every record sealed since the upgrade is lost. A
command that exports the shelf back to the flat files an earlier release
reads, losing nothing, is planned
([#218](https://github.com/Mesh-LLM/capsules-plugin/issues/218)).

**Owner-maintenance records from earlier releases.** Releases up to 0.1.8
sealed each owner cleanup (delete stored text, rebuild index, start a new log)
with `disposition.approver: "owner"`, which the Agent Action Capsule format
does not allow. Those records stay as they were sealed and never change, so
an Agent Action Capsule Class 1 check reports them as `approver_invalid`. The shelf only holds
records that pass that check, so a node whose log holds such a record keeps
its log in `capsules.jsonl` as before, and says so at start. The next log
it starts (Start a new log) uses the shelf. Cleanups sealed from this
release on name `approver: "human"` when you ask for them.

## The log's id

Every checkpoint names the log it covers, and a witness keeps one history per
log id, so no two nodes may share one. A node's log id is
`capsules/<key id>`, where the key id is the first 16 hex characters
of the SHA-256 of its public key. It is chosen at the first start and kept in
`<data dir>/log_id`; a later change of key does not change it. To name it
yourself, set `CAPSULES_LOG_ID` before the node's first checkpoint.

A log keeps the id its checkpoints were cut under: changing it would break the
log's checkpoint chain. So the plugin never changes the id of a log that has a
checkpoint, and refuses to start when `CAPSULES_LOG_ID` names a
different one.

**A node from an earlier release** whose log was checkpointed under the old
default, `capsule-emit-mesh` (the same on every node), keeps that id and logs
a warning at start. A witness accepts that id from one node only and refuses
the others' checkpoints as a fork. To take a log id of the node's own, start a
new log (Evidence › Clean up records › Start a new log) and restart the
node: the old log is kept whole under `<data dir>/archive/<n>/` with its old
id, and the new history runs under `capsules/<key id>/h<n+1>` (or
`<CAPSULES_LOG_ID>/h<n+1>` when that is set).

## Upgrading from capsule-emit-mesh

Until 0.1.3 the plugin was called `capsule-emit-mesh`. To upgrade, install
`capsules` as above, then remove the old one: `mesh-llm plugins delete
capsule-emit-mesh` (this leaves its data directory alone). Then restart the
node.

- **Records and key.** `capsules` keeps using the old default directory
  (`$XDG_DATA_HOME/capsule-emit-mesh` or `~/.local/share/capsule-emit-mesh`)
  where it is, under its old name: nothing is moved or copied. A directory you
  chose with `CAPSULES_DATA_DIR` (or the old `CAPSULE_EMIT_MESH_DATA_DIR`) is
  used as it is.
- **Stop the old plugin first.** On Linux the plugin refuses to start while
  another process has the log open (capsule-emit-mesh before 0.1.3 takes no
  lock), and says which process; two writers on one log would break its chain.
- **Both directories present.** If the node has a key or a log under both
  names, the plugin refuses to start and names both. Keep the one that is this
  node's, move the other out of the way, and start again.
- **The log id.** A log keeps the id it was checkpointed under, so an existing
  node's witness history continues. A new node's log id is
  `capsules/<key id>`.
- **Settings.** Every setting in the node's environment is now named
  `CAPSULES_*`. For this release the plugin still reads the old
  `CAPSULE_EMIT_MESH_*` name of a setting whose new name is unset, and logs a
  warning naming both; when both are set, the new name wins. Console settings
  saved under the old plugin name are read the same way. Rename yours now: the
  old names stop working in the next release.
- **Bookmarks.** The page moved from `/plugins/capsule-emit-mesh/evidence` to
  `/plugins/capsules/evidence`.

## Turn it off or remove it

```bash
mesh-llm plugins disable capsules   # keeps it installed
mesh-llm plugins delete capsules    # removes the installed files
```

Removing the plugin does not delete its data directory.

## What is in the package

```text
capsules/
  capsules                   the plugin executable
  plugin.toml                         package marker (name, version)
  plugin-manifest.json                settings schema and web UI declaration
  bundle/register-mesh-plugin-ui.js   the Evidence page
  README.md                           this file
  LICENSE
```

## Build it yourself

Only packages built by `.github/workflows/release.yml` are published. The
packaging step (`scripts/package.sh`) is deterministic, so the same executable
always gives the same archive digest. To build a package for your own machine
from a checkout of a release tag (the packaging step needs GNU tar):

```bash
cargo build --locked --release --manifest-path crates/evidence-plugin/Cargo.toml
(cd web-ui && pnpm install --frozen-lockfile && pnpm build)
scripts/package.sh "$VERSION" "$TARGET" crates/evidence-plugin/target/release/capsules dist
```

With `make` installed, one command does the same, from any checkout (it needs
`pnpm`, `cargo`, `jq` and GNU tar, which is `gtar` on macOS):

```bash
make package    # builds the page and the plugin, writes dist/capsules-<version>-<target>.tar.gz
make install    # package, then `mesh-llm plugins install --archive ...`
make install MESH_LLM=~/Github/mesh-llm/target/debug/mesh-llm   # a locally built mesh-llm
```

`make` alone lists the targets.

A different compiler or build machine can give a different executable and so a
different digest; `SHA256SUMS` covers the published packages.
