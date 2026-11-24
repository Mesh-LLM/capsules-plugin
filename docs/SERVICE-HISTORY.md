# `service_history/1`: a node's history card and weekly served counts, in one answer

This is the human-readable definition of the derivation whose definition document is
[`derivations/service-history-1.json`](../derivations/service-history-1.json). The document is what
the digest covers. This page explains it and changes nothing it says: a change of meaning is
`service_history/2`, with a new document and a new digest.

It is a Standard History under agent-action-capsule's inference-service history profile
(`spec/inference-service-history-profile-v0.md`, action-state-group/agent-action-capsule#315 at
f8c946ed, merged 2026-10-29, cited here as ISH). Section numbers below are that document's.

## Identifier

- **A request names it by the digest of its definition:**
  `cbc96d800ad206791db7e0793b80a2720c1908468ba99692b739aa8e74aab2d8`. That is SHA-256 over the RFC
  8785 bytes of `service-history-1.json`.
- `service_history/1` is the document's name, not a token. A request naming it is refused
  `derivation_unsupported`.
- It is not registered.

## The definition

It carries ISH §4.1's frame and no other member: `profile` `inference-service-history/0`, `level`
`standard`, `kind` `projection`, `embeds` `["history_card/1"]`, `subjects` `["full_history"]`, its
two members, `reads`, `excludes` (`requester identity` among them), the Standard
`coverage_declaration` (`stream_interval`, `all_records`), the `period_policy` and `spec`.

The period policy is Steven's ruling of 2026-10-22 (action-state-group/evidencebook#46):

| Member | Value |
|---|---|
| `epoch` | `2026-01-05T00:00:00Z`, a Monday |
| `length_s` | `604800`: one week |
| `min_length_s` | `86400` |
| `floor` | `5` |
| `suppression` | `complementary` |

Its digest, which the counts name, is
`0d4b28af7ebfca01a49c1ad59e74b7d9bff0e6712dd3478b4ee35b8ff6af5150`.

## What counts as served

`exchanges_served` counts exchanges this node served. A record with
`x-mesh-poc-v1.outcome: "failed"` is not one, even though a provider's has `role: "served"`: it
records a request that failed or was refused (action-state-group/evidencebook#205,
[FAILED-EXCHANGES.md](FAILED-EXCHANGES.md)), and an absent `outcome` means served. The definition
document is unchanged, and so is its digest: the node leaves such a record out when it reads its
records (`evidence_log::leaf_facts`), the one place the counts read them. The definition document
does not express that exclusion: a count recomputed from the records by that document alone would
run a failed provider record (role `served`) as served and differ from the node's.

## What is answered

- **The subject:** `full_history`. Any other subject is refused `policy_declined`.
- **The coverage:** an `expected_pin` naming a checkpoint whose time is a period boundary, a Monday
  at 00:00:00 UTC. Any other anchor, and `min_freshness`, is refused `policy_declined`, the same for
  every requester (ISH §6.1 items 2 and 5).
  - To find such a pin, ask for `history_card/1` and take a checkpoint whose `timestamp` is a
    boundary. Any boundary checkpoint is answered, not only the newest.
  - The node's checkpoint cadence cuts a checkpoint one second after each boundary, so its
    minute-granular time is the boundary. It first appends one padding record, so there is always
    a record to cut at, even when the last checkpoint covers every other. A node that is not
    running at a boundary, or reaches it more than a minute late (a host asleep, a clock off),
    has no anchor there, and the records it then commits count in the next week.
- **The gate:** it is Standard History, answered only as `share_standard_history` allows
  ([SHARING-POLICY.md](SHARING-POLICY.md)).
- **Answered whole or refused whole.** If either member cannot be served, the whole answer is
  refused. It is never sent with a member missing, and never filtered for the requester.

## The artifact

One JSON object, carried as its RFC 8785 octets (ISH §8.2):

| Key | Value |
|---|---|
| `anchor` | the anchor checkpoint's digest |
| `coverage_declaration` | `{"interval": {"from": null, "to": <anchor>}, "kind": "stream_interval", "live_set": [{"checkpoint": <anchor>, "count": <records under the anchor>, "start": 0, "stream": <stream>}], "rule": "all_records"}` |
| `declared` | `["history_card", "period_counts"]` |
| `derivation` | the definition digest above |
| `evidence_stream` | the node's stream |
| `history_card` | the `history_card/1` artifact this node serves directly for the same subject and anchor, as a JSON value |
| `history_card_digest` | SHA-256 of the card's RFC 8785 octets |
| `period_counts` | the weekly counts (below) |
| `subject` | `{"full_history": null}` |

No other key appears. The same subject, anchor and definition give the same bytes for every
requester. The envelope carries no verification material (ISH §8.1). The witness receipts of the
card's checkpoints ride beside the envelope in `witness_receipts`, as for a direct card.

## The counts

`period_counts` is `{"policy": <policy digest>, "periods": [...]}`, in the form of ISH §9's vectors.
There is one period per closed week, in order, from the week the stream's first checkpoint commits
into (the week that holds the stream's first record) to the week that ends at the anchor. Every
closed week is listed and none is left out; weeks with nothing served are listed too, their cells
suppressed below the floor like any other (ISH §6.1 item 3). A later answer never drops a week
(item 4).

- **Which week a record is in:** the week the first checkpoint that covers it commits into. A
  checkpoint commits into the week that holds its time, with one exception. The first checkpoint
  at a boundary commits into the week it ends, because it closes that week. A checkpoint time is
  never taken as earlier than the one before it. So no checkpoint after the one that closed a week
  adds to that week, and a week's cells are the same at every later anchor (ISH §6.1 item 4). The
  week the anchor opens is never counted.
- **The cells** of a week are `{"dimension", "label", "unit", "value"}`, one per model the
  provider states (`dimension` `{"model": ...}`), by name, then the total (`dimension` null). Every
  cell is in the unit `exchanges_served` and labelled `self_reported`.
- **The floor.** A cell under 5 is published with `value` null and `suppressed` `below_floor`.
  Where the total is published and exactly one model is suppressed, the smallest other model is
  suppressed too, with `complementary`, so the suppressed one cannot be worked out from the total.
- **What is never counted:** latency (Steven, 2026-10-22), requested exchanges, quantization,
  weights digests, referee verdicts (`service_history/2` counts them, below) and anything about who asked.

## Never beside `standard_history/1`

A node that serves Service History serves no `standard_history/1` card under its key (ISH §6.1
item 8): that card counts over a window ending at any anchor, with no floor, so two of its cards at
consecutive checkpoints could be subtracted to isolate one exchange these weeks protect. This node
refuses a request naming `standard_history/1` `derivation_unsupported` (`policy_declined` to a
requester it does not answer Standard History), and its commitment does not list it. For the same
reason it no longer answers `served_summary/1` (Mesh-LLM/capsules-plugin#106): that summary, less
the published weekly cells, would give the sum of a model's withheld weeks, and so one withheld
week's count. It is refused as `standard_history/1` is, and not listed.

## Checking a Service History

1. Check the envelope: the signature, the request digest, the artifact digest, and that it carries
   no verification material.
2. Check the card as a `history_card/1` answer: each checkpoint's signature under the responder's
   key, the list starting at the stream's first checkpoint and ending at the anchor, each
   consistency proof, and each witness receipt. Check that `history_card_digest` is its SHA-256 and
   that its `subject`, `anchor` and `evidence_stream` are the History's.
3. Check the keys, `declared`, and the coverage declaration against the anchor.
4. Check the anchor's time is a boundary (`period_anchor`).
5. Check the counts (`period_alignment`, `period_floor`): the policy digest; every closed week
   listed once, in order, with `from` and `to` in the `YYYY-MM-DDTHH:MM:SSZ` form; each cell in the
   unit and label above; one total and each model at most once; no published value under the
   floor; complementary suppression where it is due; and published models that add up to a
   published total.

`period_fixed`, whether two Histories agree on the weeks they share, needs two of them, and a
verifier holding one says it did not check it.

## How it reads

- Every count is the node's own statement.
- Checkpoints are this log's own continuity. A witness receipt means that a later rewrite of the
  log is detectable. With the witness set to `off`, the History says so.
- The model is shown as what the provider states.
- The coverage is every record of the stream up to the anchor, and completeness is not established,
  since the counts are not checked against records.
- Nothing in a Service History is shown as a model having run, or as a model verified, and nothing
  in it scores or ranks a node.
- The card shows each checkpoint's exact log size, which the weekly counts do not cover (ISH §12).

## `service_history/2`: the verdicts this node holds about itself

[`derivations/service-history-2.json`](../derivations/service-history-2.json) is `service_history/1`
with a third member, `verdict_counts`. It is a new derivation with its own digest,
`0f6cee6c5c2f57e7682137e4b40a9dcfad0f8db5a69d5bebaf99995936ea96f2`; `service_history/1` and its
digest are unchanged and still answered. The same frame, subject, coverage, pin and period policy
(week, floor 5, complementary suppression) apply, and a node that serves `service_history/2` serves no
`standard_history/1` or `/2` card for the same reason. It is Standard History under the same switch,
`share_standard_history`. Section numbers are the profile's (ISH §4.3, §5.3, as amended by
action-state-group/agent-action-capsule#614).

**What is counted.** A referee's signed verdict about one of this node's exchanges, delivered to it
(`share_adjudications`, #163) and sealed on its own chain as an `adjudication_received` record
(#102). The node counts what its log holds, not a list it keeps apart, whether this node or the
other party asked the referee (ISH §5.3). The pair is this node's served half and another provider's
half of the same request. This plugin counts a verdict once per (referee, pair), in the week the
first checkpoint that covers its record commits into (the same rule as the served counts); the
profile says "every verdict that qualifies", and the once-per-pair rule is this plugin's, so the same
delivery sealed twice is not counted twice. A verdict whose referee is one of the two nodes counts
nowhere. A verdict about another node's exchanges is not counted. The deciding node's own admission
reads the verdicts it asked for itself
(`verdict_counts::fold`), which is a different set.

**The four results** stay four separate counts, never added, in the unit `referee_verdicts`.
`corroborated` here means the referee's finding supports this node's half: the halves agree, or the
other provider's half was found wrong. A contradiction naming the other node therefore counts as
`corroborated` for this node, and one naming this node as `contradicted`. The profile does not
define the four results per node, so this is a host reading. It is not the label `corroborated` of
ISH §7.1 (halves from distinct controllers); the unit tells them apart. A verdict says nothing about
this node's other or later
answers, and "not adjudicated" is counted against no one.

**The cells.** `verdict_counts` is `{"check": "referee_verdict", "signed_by": "checker",
"policy": <policy digest>, "periods": [...]}` over the same closed weeks as `period_counts`. A
period lists, for each of the four results in the order above, one cell per model hash (the
`identity_hash` a verdict seals, `unknown` when it seals none, never the weights digest) and the
result's total, `{"dimension": {"model_hash": ..., "result": ...}}` or `{"dimension": {"result":
...}}`, each labelled `self_reported`. A cell under 5 is withheld, and complementary suppression
applies within each result's table. Where two or more models are each withheld and the published
total would give them away, the total is withheld too; that is the library's rule for these tables,
and the profile leaves the general case open (SH-8). `check` names the kind of check counted and
`signed_by` says its result is signed by the checker, never by the node it concerns: a later audit
result is another kind in the same member, counted separately.

**Omission, `verdict_held/1`.** A node that drops a delivered verdict shows a smaller count, and
nothing in the count shows it. A node that holds the referee's signed delivery can ask this node
whether it holds the verdict, by the verdict's capsule id (the id of the referee's verdict
capsule, a digest: the one `derivations/verdict-held-1.json` reads as `verdict_capsule_id`; ISH §5.3
names a held verdict by "the digest of the referee's signed delivery, in the form the host's
definition states", and this id is this host's form of it): the
existing `mesh_evidence_request` tool with
`{"subject": {"correlation": "<verdict capsule id>"}, "coverage": {"expected_pin": "<anchor>"},
"derivation": "f457ecb2cd0089c83129365593d3d4f8cf1e52a99424d85d1041c042fc5e0418"}`
(the digest of [`derivations/verdict-held-1.json`](../derivations/verdict-held-1.json); pin an
anchor from its `history_card/1`). Who is answered follows `share_standard_history`: a
counterparty always, any other node, the referee included, only where the switch is on (it is off
by default).

*Held.* The signed answer lists, for each record that holds the verdict, the verdict's id, the
record's digest and its inclusion proof under the anchor, and nothing else (never the ruling, the
referee, a record body or who asked), the same bytes for every requester; the result's
`verification` reads `artifact` with `held` the number of records. It is the node's signed
statement that the listed record holds the verdict. The proof shows only that the record's digest
is committed under the anchor: the entry names no record body, so it does not show that the record
carries the verdict, and an asker who needs that asks for the record under the ordinary record ask
and its own policy. Where the count is published (a count under 5 is withheld), a node that answers held and
counts nothing for the verdict is the omission this ask finds.

*Not held.* The signed `no_such_subject` refusal. It is the node's signed statement that it holds no
record counting that verdict about itself: a verdict this node holds only as a requester, or holds
unmarked with no served half of its own, is not counted and is answered not held. An asker holding
the delivery sets that refusal beside it: the node signed that it holds nothing counted for a
verdict it was sent. A delivery shows the verdict was sent, not that it arrived, so what follows is
the asker's to judge.

The check runs against the node's log, not against its counts. It is answered under
`share_standard_history`, like the counts.

**Limits.** The counts are this node's own statement. The signature on each verdict was checked
when the node sealed it. A node that does not seal a delivered verdict, or that drops one, shows a
smaller count, which `verdict_held/1` above checks against the delivery, not the counts. The floor
limits small counts; it does not hide who asked: where one party's own asks make up a count, that
party can tell (ISH §5.3, §12). The verdicts counted
here are a different set from the ones this node's own admission reads (`verdict_counts::fold`,
those it asked for). No admission reads `verdict_counts` yet, and the row that will read it never
refuses on it alone. The text of the profile that counts verdicts this node did not ask for is ISH
§5.3 (action-state-group/agent-action-capsule#614). The shared conformance vectors for the member
are
[`vectors/inference-service-history-verdicts-v0/`](https://github.com/action-state-group/agent-action-capsule/tree/main/vectors/inference-service-history-verdicts-v0)
in agent-action-capsule (#617); they do not cover the delivery or the ask by digest (SH-14, SH-15),
which this implementation tests by its own tests. The ask is the host's, not the profile's (SH-15):
one implementation cannot yet check
another's omissions, so do not assume any node can ask any other. Nothing here scores or ranks a node.
