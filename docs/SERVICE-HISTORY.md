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
  weights digests, referee verdicts and anything about who asked.

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
  log is detectable. With no witness named, the History says so.
- The model is shown as what the provider states.
- The coverage is every record of the stream up to the anchor, and completeness is not established,
  since the counts are not checked against records.
- Nothing in a Service History is shown as a model having run, or as a model verified, and nothing
  in it scores or ranks a node.
- The card shows each checkpoint's exact log size, which the weekly counts do not cover (ISH §12).
