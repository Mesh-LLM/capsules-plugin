<!-- SPDX-License-Identifier: Apache-2.0 -->
# Sharing policy

Every sharing decision the plugin makes is one of seven switches, and every
default keys on **relationship** (whether this node has exchanged with the
other node), never on proximity, latency, or any computed standing. Nothing
here is a score, and nothing here ranks anyone.

```
share_record_at_completion:  counterparty | off                    # default: counterparty
share_history_segments:      counterparties | peers | off          # default: counterparties
share_standard_history:      on | off                              # default: off
share_exchange_corroboration: on | off                             # default: off
advertise_evidence_requests: on | off                              # default: off
share_adjudications:         deliver_to_subjects | off             # default: off
witness:                     [] | [{endpoint, public_key?}, ...]   # default: [] (off)
```

With these defaults the only thing a node sends to a peer on its own is its
sealed record of a completed exchange, and only to the other side of that
exchange (`share_record_at_completion`): it delivers no verdict and advertises
nothing. Set `off` to send nothing. It answers any node that
asks for its checkpoint list or `history_card/1` (below), and otherwise only
a counterparty that asks: for one of its records (`share_history_segments`)
or for the rest of its Standard History (`share_standard_history`). The
referee (`adjudicate_differing_twins`) is off by default too.

`share_history_segments` also accepts `prospective`, its default before
0.1.5. It is deprecated: it always served exactly whom `counterparties`
serves, so it is now read as `counterparties`, and a log line says so. Set
`counterparties` instead.

The plugin declares the seven switches in its `config_schema`
(`crates/evidence-plugin/src/share_policy.rs`), so the console shows them under
Configuration › Plugins › Capsules. mesh-llm keeps what you save there in
its config file and does not pass it to the plugin, so the plugin reads it
there (`~/.mesh-llm/config.toml`, or the file `MESH_LLM_CONFIG` names). The
same settings can be set in the plugin's environment, which wins over the
console: `CAPSULES_SHARE_RECORD_AT_COMPLETION`,
`CAPSULES_SHARE_HISTORY_SEGMENTS`, `CAPSULES_SHARE_STANDARD_HISTORY`,
`CAPSULES_SHARE_EXCHANGE_CORROBORATION`,
`CAPSULES_ADVERTISE_EVIDENCE_REQUESTS`, `CAPSULES_SHARE_ADJUDICATIONS` and
`CAPSULES_CHECKPOINT_WITNESS_URLS` (a comma list of witness URLs) with
`CAPSULES_CHECKPOINT_WITNESS_KEYS` (a JSON object from witness URL to its key
in hex). An unset value means the default; an unknown value means `off` for the
switches that reach a peer.

## The record at completion (`share_record_at_completion`)

On by default (`counterparty`; this reverses the 0.1.3 default, which was off).
Every node sends its record to the counterparty and accepts the counterparty's
push; set `off` to do neither. When it is on and an exchange ends, each side
sends its own **sealed record** to the other side over the plugin's
`record-push/1` mesh stream: the provider's record to
the requester, and the requester's to the provider. With the checkpoint
cadence on (the default), the record goes out as a **bundle**: the record, a
signed checkpoint of the sender's log, and the record's inclusion proof under
it.

The record contains nothing the other side can't already compute (they hold
the bytes, so both digests are theirs to derive). What it adds is the time it
was sealed, the signature, and, in a bundle, the size and root of the sender's
log and the record's position in it. No other record's content leaves: the
proof is hashes only. With both records exchanged, each side holds the other's
signed statement about the same exchange.

**What it reveals:** the record goes only to the other side of that exchange,
never to any other peer. The public checkpoint list (see Standard History)
shows when exchanges ended, as the next paragraph says.

**Symmetric:** a node with this switch `off` neither sends its
record nor accepts the other side's push.

**It shows when exchanges end:** with the checkpoint cadence on (the
default), each push cuts a checkpoint (at most one per 100 ms), and any node
can read the checkpoint list (see Standard History), so the checkpoint times
show when this node's exchanges ended.

**Pushes only:** a record this node asks the other side for ("Ask them for
their record" on the Evidence page) is checked the same way and held either
way, because its operator asked for it. Its provenance says `via: "ask"`.

**In this build:** the plugin sends its record when an exchange ends and
mesh-llm has told it who the other side is. A pushed record is received and
checked in-process (the sender's announced key, the signature, the claims, and
a bundle's proof and checkpoint) and held only if every check passes; anything
else gets a signed refusal. The key that signed the record must be known:
announced by some peer's host, listed in `CAPSULES_PEER_KEYS` (a stopgap, see
INSTALL.md), or bound to such a key by a controller declaration the sender
carries (a `controller-binding/0` record both keys signed). The key is the
sender's identity, not the peer id the push arrives under: a known key is
accepted under any id, and a known id with an unknown key is refused. A
refusal for an unknown key names that key under this node's signature. A
key that a carried declaration binds to this node's own key is refused,
however else it is known.
The citing record this node seals for a held record names the sender's key
and how it was accepted (`accepted_via`: `host_announced`,
`operator_stopgap` or `controller_declaration`). That is provenance only:
nothing decides on it.

A sender that holds a binding of its key to its operator's Nostr key (loop
step 12) carries it whole in the bundles it pushes to the exchange's
counterparty, and nowhere else. The receiver checks that it applies and
binds the half's key, and its citing record then names the binding by its
digest (`controller_binding_digest`) however the key was accepted. When the
receiver holds its own binding, the record also says whether both bindings
name the same operator key (`same_controller_as_receiver`). The record never
names the operator's Nostr key: a declaration anchored on one records no
`controller_anchor_key_id`.

## Reading records back (`share_history_segments`)

A peer can ask this node for one of its records by id, over the plugin's
`ledger-fetch/1` mesh stream. The switch decides who gets an answer:

| value | counterparty (a node this record names as the other side) | any other proven node |
| --- | :---: | :---: |
| `off` | | |
| `counterparties` (default) | ✓ | |
| `peers` | ✓ | ✓ |

A local block and an owner-maintenance record are never served. A declined
request is answered `not_authorized`. The counterparty is the node the
request's signature proves it came from, checked as for an evidence request
(below) before anything is looked up: the id a request states is never
trusted. Under every setting an unsigned request, one whose signature fails,
or one signed under a key no host announced, is refused before the record is
looked up: `peers` opens records to any node a signature proves, never to a
stranger.

A record of an exchange this node served for a peer names that peer as the
other side (mesh-llm reports it from the mesh connection, never from the
request). That is what makes the peer its counterparty, and under `peers` it
also means any peer that reads the record learns which node asked.

**Evidence requests** (`evidence-request/1`, draft-mih-agent-evidence-request-00)
are answered in-process by `evidence_answer.rs`, with the protocol from the
`evidence-request` crate. The same rule applies to every record
an answer would carry, for every subject that carries record bodies (`record`,
`correlation`, `exchange`). A `correlation` subject is an exact key (a
client nonce, an exchange id, or `exchange-digests:<request>:<response>`),
never a prefix or a pattern. An answer is served whole or refused
`not_authorized` whole, never filtered per asker, because an artifact is the
same for every requester.

A `record` subject with the `evidence_bundle/1` derivation names one of this
node's exchange halves and asks for it as an Evidence Bundle: every record from
the half to the checkpoint it is served under, each as sealed with its payload
withheld, under a range proof. That is the earliest checkpoint covering the
half that the request's coverage allows. Withholding the payload does not
withhold the content: a record of this node carries its content in its
header, so the answer shows each record of the interval as fully as fetching
that record would, and the gate below lets out only records the asker could
already fetch whole. The rule above applies to every
record in that interval: one record the asker may not have refuses the whole
answer `not_authorized`, and so does a record that never leaves this node
(an ask, a routing choice, owner maintenance, a deal's report), whatever the
switch says. Padding names no one and is not held against the asker, but an
Evidence Bundle cannot carry it yet
([agent-action-capsule#339](https://github.com/action-state-group/agent-action-capsule/issues/339)),
so an interval with padding in it is declined as a limit of this node's own.
This derivation is not in the commitment's `answers.derivations`, which lists
only what every counterparty gets under every setting.

`range` and `full_history` with no derivation reach records no single
requester is party to. They are refused `not_authorized` under every setting
and to every asker, a counterparty that every record in the range names
included. The refusal comes before anything is looked up, so it is the same
whether or not the range exists. Only a derivation prepared for one recipient
could grant them, and this node has none.

**Who asks is proven, not stated.** The asking node signs its request with
the key its host announces for it (mesh-llm `plugin_keys.v1`), in a
`requester_auth` member: `{"key_id", "sig"}`, where `sig` is Ed25519 over
`evidence-request/1/requester-auth`, a zero byte, and the canonical JSON (RFC
8785, as the `evidence-request` crate encodes it) of the rest of
the request. A signed request also carries an `audience` (the mesh id of the
node it is sent to), a `nonce` and a `deadline`.

Each kind of request signs under its own tag, so a request signed as one never
verifies as another: `ledger-fetch/1/requester-auth` for a record fetched by
id, `referee-adjudicate/1/requester-auth` for a referee's `adjudicate` request
(it travels on the evidence stream, and has no channel name of its own), and
`evidence-request/1/requester-auth` for every other evidence request. The
answering node picks the tag from where the request came in, never from a tag
the request names.

Before it looks anything up, the answering node checks, in order:

- the deadline is no more than 5 minutes ahead;
- the signature verifies;
- the `audience` is this node, so a request one node received cannot be
  forwarded to another;
- the nonce has not been used before its deadline. For a key bound to a node
  (below) this is strict: a replay is refused, and so is a request once that
  key holds 4,096 live nonces. Keys bound to no node share one pool of 16,384
  nonces, held until their deadlines, and the check there is best-effort: a
  replay found in the pool is refused, but while the pool is full of live
  nonces a new one is not held, and the request goes on unchecked (it can then
  only be answered as an unsigned request would be, below);
- the key is bound to a node: a host announced it for that node, or, when no
  host announced it, an entry in `CAPSULES_PEER_KEYS` gives it under that
  name (the stopgap), or the request carries a controller declaration
  (`controller_binding`, covered by the signature) binding it to a key bound
  one of those ways. An entry that disagrees with the host's vetoes both. A
  key that a carried declaration binds to this node's own key is bound to
  no node. If the key is bound to several nodes, the request's
  `requester_id` must be one of them. If to only one, the request's
  `requester_id`, when given, must be that node. The nonces of keys a
  declaration binds count against the 4,096 of the key it binds them to.

The asker is every node the key is bound to: the key, not the peer id it
asks under, is its identity. Under `counterparties`:

- a record goes only to the node it names, when that is one of the asker's
  nodes;
- an unsigned request is refused `not_authorized`;
- a proven node that no record names is refused `not_authorized` before the
  subject is resolved, the same refusal for any subject, so which refusal it
  gets tells it nothing about the log's size.

Under `peers` a record goes to any node proven this way, whether or not a
record names it. An unsigned request gets no record under any setting, and
neither does a valid signature under a key bound to no node: it proves no
node. That signature is the one failure answered as an unsigned request would
be, and only where an unsigned request is answered (the checkpoint list,
`history_card/1`, and Standard History when it is shared). Every other failed
check is refused.

Each request's digest is recorded in the "asked of you" log, with the key and
node it was proven to come from (or `unbound`), the audience it named, and
`replay`: `checked`, or `unchecked` when a key no host announced found the
pool full.

The checkpoint list, the `history_card/1` derivation and the `service_history/1`
derivation carry no record bodies: `share_history_segments` does not govern
them. The checkpoint list and `history_card/1` go to anyone, and
`share_standard_history` governs the rest (below). The cases and their
expected answers are in the plugin's evidence-request parity run
(`crates/evidence-plugin/src/evidence_request_parity.rs`).

## Standard History (`share_standard_history`)

Off by default. Standard History is what an evidence request can get that
carries no record bodies: the checkpoint list, `history_card/1` and
`service_history/1` (and any other derivation but `exchange_corroboration/1`,
below).

**The checkpoint list and `history_card/1` go to anyone who asks**, whatever
this switch and `share_history_segments` say: an unsigned request, any node's,
or one signed under a key no host announced (a signature that fails is still
refused). They carry only this node's signed checkpoints and the consistency
proofs between them, the same for every node, so a community reporter or
`doctor --probe` can read and check them without having exchanged with this
node. They show how much this node has recorded and when it cut each
checkpoint, and no record or counterparty. With `share_record_at_completion`
on and the checkpoint cadence on (the default), each push cuts a checkpoint
(at most one per 100 ms), so a checkpoint's time can be the time one exchange
ended.

The rest (the Service History `service_history/1`
([SERVICE-HISTORY.md](SERVICE-HISTORY.md)) and any other derivation) shows
what this node serves, so with this switch off it goes only to a
counterparty: a node that some record of this node names as the other side
of an exchange. Any other node is refused `policy_declined`. This node no
longer answers `served_summary/1` (Mesh-LLM/capsules-plugin#106): a
counterparty, and with this switch on anyone, is refused it
`derivation_unsupported`, as any derivation this node does not serve.

The refusal carries nothing about who asked. It is decided before the subject
is resolved, so it is the same whether or not what was asked for exists, and
it is signed over the request's digest, the reason and the time alone. Two
nodes sending the same request in the same second get the same bytes back;
two refusals differ only in the digest of the request each refuses (which
covers every member each carries), the time, and the signature over them.

With it on (`on`), every node that asks is answered, as before 0.1.5. It
never releases a record: record bodies stay under `share_history_segments`.

**A counterparty is the node a signed request proves it is**, as above.
These all get the same `policy_declined`, so trying ids teaches a node
nothing about who this one has exchanged with:

- an unsigned request, whatever id it states;
- a request stating another node's id;
- a proven node no record names.

## Exchange corroboration (`share_exchange_corroboration`)

Off by default. Another node can ask whether this node holds a half of one
exchange, naming the exchange by the SHA-256 of its client nonce
(`exchange_corroboration/1`). The answer carries each matching half's id,
role and two digests, never the record or who was on the other side, and it
is the same for every node it is given to.

- **Off:** only a node that every matching half names as the other side of
  its exchange is answered. A node that no record names gets a signed
  `policy_declined`; a node that other records name, but not these halves,
  gets `not_authorized`. Sharing Standard History does not change this.
- **On:** any node that asks is answered.

Either way, a half that never leaves this node is never answered.

A node that checks an earlier exchange between two others (the
`historical_reference` operation) asks each side for its half. If the node
has exchanged with neither of them, both sides must have this switch on;
otherwise both refuse it.

## Advertising evidence requests (`advertise_evidence_requests`)

Off by default: this node does not tell other nodes that it answers evidence
requests. It still answers a node that asks, under the switches above. This
version advertises nothing, so nothing reads the switch yet: the plugin's
`evidence-request/1` channel is declared only to its own host, so that a
request can reach it, and mesh-llm does not pass a plugin's channels on to
other nodes. Giving the commitment to a peer that asks for it, and the
operator publishing it, are not advertising either; the signed policy states
this switch's value (below).

## Verdicts (`share_adjudications`)

Off by default. When it is on (`deliver_to_subjects`) and a referee's verdict
about an exchange exists, it is delivered to every node it concerns, and each
seals its own record citing it. A node holds a
delivered verdict only when the referee it names signed it with its announced
key and the verdict concerns that node (it asked for it, or it judges one of
that node's own records). With `share_adjudications: off` the node that asked
still holds the verdict, and delivers it to no one. How a referee is chosen:
[TWIN-REFEREE-SELECTION.md](TWIN-REFEREE-SELECTION.md).

**Asking a referee sends a prompt to a third node.** With
`adjudicate_differing_twins` on (off by default), when two twins of a pair a
client marked (`x-mesh-twin-bracket`) answered differently, this node sends the
twins' own request, including the prompt's `messages`, to one eligible peer
(`x-mesh-target`), which answers it with its own inference; that answer and
both twins' halves then go to it to adjudicate. It needs the exchange text
kept on this node, a separate setting (`CAPSULES_KEEP_EXCHANGE_TEXT`, off)
that keeping text locally does not imply the other way round: keeping text
never sends it to a peer. The operator's "Ask again" is the same switch.

## Witness

`witness` is a list of witnesses, empty for off (the default). Each is an
`endpoint` (the witness's URL) and, if you have it, its `public_key` (its
Ed25519 key in hex, as its operator publishes it): the same endpoint-and-key
pair capsule-cli takes. There is no default witness: with the list empty the
plugin contacts no witness at all.

Each checkpoint is offered to every witness on the list. A witness that
accepts it returns a receipt, and the Evidence page lists every witness by
name with what it holds: the latest checkpoint, an earlier one, or none yet.

A receipt counts only once the plugin has **checked** it, offline. It
recomputes the checkpoint's digest from the checkpoint's own signed fields,
confirms the receipt is for exactly that entry, and verifies the receipt's
inclusion proof and signature under the witness's key: the key you gave, or,
when you gave none, a key fetched from that witness the first time it is
needed and kept (`<ledger>/witness-keys.json`). A different key later from the
same URL is not taken. The page says which: "key configured", or "key pinned
on first contact, not configured". A key you configure is the stronger choice:
you got it from the witness's operator, not from the witness's own answer.
"Witnessed" on the page means at least one checked receipt, from a witness it
names.

A named witness that does not hold the latest checkpoint is asked for its key
again, at most once a minute and only that witness, so its row can say why:
it did not answer in time, refused the connection, answered with an HTTP
error, or presents a different key than the one configured or pinned. A
witness that holds the latest checkpoint is not contacted for this.

Every request to a witness goes to the URL the operator gave, host, port and
path as written; no URL is mapped to another service. No request follows a
redirect. The plugin's own reads of a witness (its key, and what it holds of
this log) read at most 64 KiB; registering a checkpoint, through the
capsule-emit library's client, reads at most 1 MiB.

A witness holding a checkpoint means one thing: a later rewrite of this log is
detectable by someone other than this node. It does not make the records true.

## The signed policy and the commitment

The seven switches above, all but `witness`, are this node's
disclosure policy. The node signs it as a `disclosure-policy/0` document and
publishes it with its **commitment**, an `evidence-commitment/0` document
signed by the same key. The commitment says how the node can be asked and
what it can answer, never what it has done, and it carries no counts. Both
shapes are the ones evidence-network/loop's step 3 checks
(`steps/03-advertise.md` there).

With the defaults, the policy's `policy` member is exactly
[`policies/disclosure-default.json`](../policies/disclosure-default.json):

```json
{
  "advertise_evidence_requests": "off",
  "share_adjudications": "off",
  "share_exchange_corroboration": "off",
  "share_history_segments": "counterparties",
  "share_record_at_completion": "counterparty",
  "share_standard_history": "off",
  "stranger_safe": ["checkpoints", "history_card/1"]
}
```

Each switch appears as the plugin reads it, so an unknown value appears as
`off`. A test requires the default settings to give this file, so the file
and the code cannot differ. Change a switch and the policy, and its digest,
change with it.

- **The digest.** The commitment's `lcap.policy_digest` is the SHA-256 of the
  signed policy file's bytes (its RFC 8785 form), not of the pinned file. The
  signed file wraps the `policy` member with `profile`, `key_id` and `sig`, so
  two nodes with the same settings have different digests, and one node's
  digest changes only when its switches or its key do. The plugin computes it
  from the switches it is answering under; nobody writes it down.
- **What else the commitment says.** The ask goes to `mesh:<node_id>` over
  this plugin's evidence-request channel. The node answers `checkpoints`,
  `history_card/1`, `exchange_corroboration/1` and `service_history/1` (the
  last two by their definition digest), each to a counterparty under every setting; the
  policy says who else gets them. It answers the subjects `checkpoints` and
  `full_history` (`full_history` only through a derivation), plus `record`,
  `exchange` and `correlation` unless `share_history_segments` is `off`.
  It answers without a person in the loop (`human_gated: false`), within a
  minute (`answers_within: PT1M`). Its predicate class is
  `performed:counterparty_half`.
- **What it carries.** The node's latest signed checkpoint, whole, and the
  `history_card/1` answer this node gives any stranger at that checkpoint
  (the staple). A node has no commitment while it has no checkpoint, while
  its `history_card/1` is refused (past 1024 checkpoints, #76), or while the
  commitment would be larger than a peer reads (1 MiB).
- **A refusal names the policy.** Every signed refusal the evidence
  responder gives carries a `policy_digest` member (an `adjudicate` request,
  answered by the referee on the same channel, is not under this policy and
  its refusal carries none): the digest of the policy it was
  refused under, so it can be checked against the commitment. The member is
  **not signed**: the refusal's signature covers `issued_at`, `reason` and
  `request_digest` only, as the evidence-request profile defines it.
- **Where it is served.** A peer fetches the pair over the `commitment/1`
  mesh channel (`mesh_commitment_fetch` checks it). The `commitment`
  operation gives it to the operator, who publishes it to loop's
  `nodes/commitments/<node_id>.json`, with the policy bytes as
  `nodes/commitments/policies/<node_id>.json`, by pull request.

## The two mesh streams are plugin-internal

`record-push/1` (a record sent at completion) and `ledger-fetch/1` (a record
read back by id) are this plugin's own behaviour between two copies of
itself. No public specification defines them. They are not a standardized
wire, other implementations should not target them, and they may change
between releases. Neither stores and forwards a record, and neither promises
delivery.

## Three rules every switch follows

1. **Filter, never rank.** Every switch answers or refuses; none orders or
   weights a peer.
2. **Counts, not sums.** Where counts are reported, they are counts; nothing
   is totalled or averaged into a standing.
3. **Relationship, never proximity.** Every default keys on whether this node
   has actually exchanged with the other node.
