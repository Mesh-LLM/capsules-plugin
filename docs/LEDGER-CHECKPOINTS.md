# Ledger checkpoints: showing a copied ledger file is complete

*For [#175](https://github.com/Mesh-LLM/capsules-plugin/issues/175). Code:
`crates/evidence-plugin/src/ledger_checkpoints.rs`.*

## The problem

Loop step 08 re-checks every record in copies of a node's ledger files, but nothing the node
signs covers a file as a whole, so a copy that dropped a record looks the same as one that did
not. Each ledger file now has a node-signed checkpoint (its size and root) and a range proof,
so an outsider can check offline that a copy is the whole file at a checkpoint, or that an
extract is exactly positions `i..j` of it.

## What is reused, and what is new

Nothing here is a new proof format. Every file gets what `capsules.jsonl` already has: a
Checkpointed Local Log (CLL) MMR, a `CheckpointRecord` signed by the node key, its
`cll-checkpoint` COSE_Sign1 statement (`cll::checkpoint::checkpoint_to_cose`, the same path the
cadence uses), and the CLL #13 range proof (`cll::range_proof::range_proof`, `{v: 1, kind:
"range", size, from_index, to_index, witness}`).

| File (all under `ledger/`) | Leaf body digest | Checkpoints |
|---|---|---|
| `capsules.jsonl` (the chain) | the line's `capsule_id` (unchanged) | `checkpoints.jsonl` (unchanged) |
| `received-capsules.jsonl`, `received-provenance.jsonl`, `received-inclusion.jsonl`, `issued-adjudications.jsonl`, `received-adjudications.jsonl`, `requested-adjudications.jsonl` | SHA-256 of the line's bytes, without its `\n` | `file-checkpoints.jsonl` |

No other file under `ledger/` is checkpointed, and the route refuses them: `referee-pairs.jsonl`,
`received-split-stage-records.jsonl`, `rejected-record-pushes.jsonl`,
`checkpoint-equivocations.jsonl`, `checkpoints.jsonl` and `file-checkpoints.jsonl` themselves,
and the plugin's other bookkeeping files. A copy of one of them cannot be shown complete.

A leaf is every complete (newline-ended) line, in file order, whether or not it parses. A torn
final fragment is not a leaf until a later append ends it, so each file stays append-only as a
sequence of leaves. Leaf index `k` is the file's line `k + 1`.

**`log_id`.** The chain keeps the node's log id (`<plugin_id>/<key_id>`, or its `/h<n>`
history). Each other file's log id is `<node log_id>/ledger/<file name>`, for example
`capsules/3b6a…e1/ledger/received-provenance.jsonl`. A new history gives every file a new log id.

**Cutting.** A file's checkpoint is cut when the route is asked for it and the file has grown
since its last one, and at each checkpoint cadence tick. Each cut chains from the previous one
for the same log id (`prev_size`, `prev_root`, and the consistency proof in its COSE
statement). Cuts go to `ledger/file-checkpoints.jsonl`, one line per cut, shaped like a
`checkpoints.jsonl` line (the record plus `checkpoint_cose` in hex). The MMR is rebuilt from
the file in memory; there is no node store per file. A file that no longer holds what its last
checkpoint committed (it was rewritten) gets no new checkpoint, and the route refuses it.

## The route

`GET /api/plugins/capsules/http/ledger-checkpoint?file=<name>[&from=<i>&to=<j>]`

`from` and `to` are 0-based leaf indices, inclusive, given together; without them the range is
the whole file at the checkpoint. A reply's checkpoint covers every complete line the file held
when asked. Refusals come in three kinds:

- **Invalid parameters:** an unknown file name or a bad range.
- **Invalid request, ask again later:** a file with no complete line yet, or a chain whose newest
  checkpoint does not reach the records it held when asked (below).
- **Internal error:** the node cannot read or sign over the file, or the file no longer holds
  what its last checkpoint committed (it was rewritten).

Save the reply as JSON for the check below.

```json
{
  "ledger_checkpoint": 1,
  "file": "received-provenance.jsonl",
  "leaf_digest": "sha256-line",
  "checkpoint": {
    "v": 1, "kind": "mmr_checkpoint",
    "log_id": "capsules/3b6a…e1/ledger/received-provenance.jsonl",
    "mmr_size": 79, "root": "9c1f…", "prev_size": 57, "prev_root": "40aa…",
    "key_id": "3b6a…e1", "timestamp": "2026-10-31T21:04:00Z", "signature": "…"
  },
  "checkpoint_cose": "<hex COSE_Sign1>",
  "range_proof": {
    "v": 1, "kind": "range", "size": 79, "from_index": 0, "to_index": 41,
    "witness": []
  }
}
```

For `capsules.jsonl`, `leaf_digest` is `"capsule_id"` and the checkpoint is the newest one of
the chain in `checkpoints.jsonl`. When no chain checkpoint covers the chain's last record yet,
the ask first has the cadence cut one, as a record push does: padded to the bucket like every
chain checkpoint, and at most one cut per push window, so an ask inside a used window waits
for the next. With the cadence off (`CAPSULES_CHECKPOINT_CADENCE=off`), or when that cut fails,
the ask is refused rather than served an older checkpoint.

**Taking a copy the reply covers.** Ask first, then read the file. The file only grows, so the
reply's checkpoint covers the copy's first `range_proof.to_index + 1` lines (for a whole-file
reply); keep exactly those as the copy. Every record the file held before the ask is among
them. A copy read before the ask can be shorter than the checkpoint, since the chain's cut pads
it and the other files may grow; ask for `from=0&to=<lines - 1>` in that case.

## Checking a copy offline: `capsules ledger-check`

```sh
capsules ledger-check --file <copy> --checkpoint <reply.json> --key <node key id> \
  [--from <i> --to <j>]
```

`--key` is the node's key id (raw Ed25519 public key, hex), taken from somewhere other than the
reply. Without `--from`/`--to` the copy must be the whole file at the checkpoint; with them it
must be exactly leaves `i..j`, and the reply must have been asked for the same range. The
command prints `ok: …` with the line count, the checkpoint's log id and its time, and exits 0
when the copy checks; it prints `fail: <reason>` to stderr and exits 1 when it does not, and
exits 2 on a usage error. It reads no data directory.

What it checks, in order:

1. The reply is a version 1 `ledger_checkpoint` reply, and its `leaf_digest` is the file's
   rule.
2. `checkpoint_cose` verifies (`cll::checkpoint::verify_checkpoint_cose_offline`), is signed by
   `--key`, and states exactly the reply's `checkpoint`, whose own signature verifies too. A
   non-chain file's checkpoint must be that file's log (`…/ledger/<file>`); the chain's must be
   the node's own log, never a file's.
3. The range proof covers exactly the range asked for (the whole file by default).
4. The copy ends in a newline and holds exactly `j - i + 1` lines.
5. Each copied line's body digest: the SHA-256 of its bytes, or for the chain its recomputed
   `capsule_id`, which must equal the one it states (`evidence_log::record_digest`).
6. The digests and the proof rebuild the checkpoint's root (`cll::range_proof::verify_range`).

The Go equivalent is the same two library calls in `checkpointed-local-log/go`:
`checkpoint.ParseRecord` and `VerifySignature`, then `mmr.VerifyRange` over the body digests.
aac-go `bundle.VerifyBundle` checks the same range proof only inside an AAC bundle's
`completeness_certificate`, which holds AAC capsule records and must end at the checkpoint's
tip, so it covers whole-file copies of `capsules.jsonl` only.

**What `ok` shows, and what it does not.** It shows the copy is the whole file at *that*
checkpoint. Every reply the node ever gave keeps checking a copy of the file at its own size,
including a reply under an earlier history's log id, so an older genuine reply paired with a
shorter copy checks too. Whoever relies on the copy holding certain records checks that every
one of them (for loop step 07, the ask's evidence_request and its outcome) sits at a position
below the copy's line count. The checkpoint's time is not a freshness test: it is floored to
the minute, and an ask reuses the last cut while the file has not grown, so a correct reply
can be hours older than the ask.

**A filtered extract** (records picked by time, by type or by what they cite) is shown complete
by keeping the whole-file copy and its reply, then picking the records again from the copy. A
range proof shows only that the given lines are positions `i..j`; it cannot show that no
matching record lies outside them, since the files are not sorted by any time field.

## `received-provenance.jsonl`

A checkpoint over it is enough for completeness: the node then signs every provenance line and
cannot drop one without its checkpoints disagreeing. Sealing each line as a capsule would add
no evidence the checkpoint does not, so lines stay as they are. What neither can prove is
`received_from`: a push carries no signature of its sender (the half's own key is the identity,
D-34), so who delivered a half stays the node's signed word, while who produced it is proven by
the half itself. Making the sender provable would take a sender-signed push envelope, a
separate change.

## One-way doors

1. The leaf rule per file (SHA-256 of the line bytes; `capsule_id` for the chain): fixed once an
   outsider keeps a checkpoint.
2. The per-file `log_id` form `<node log_id>/ledger/<file>`.
3. The route path and reply members (`ledger_checkpoint: 1` versions them).
4. `file-checkpoints.jsonl` as durable state beside the ledger.

The checkpoint and proof formats are CLL's and do not change.

## Limits

- **No witnessing.** The checkpoints of these files are not offered to witnesses, so a node
  could show different askers different checkpoints for the same log id. Each checkpoint chains
  from the one before (`prev_size`, `prev_root`), so two replies from the same node that do not
  extend each other are signed evidence of equivocation; but only askers who compare their
  replies find it.
- **Counts.** A checkpoint states how many lines the file holds. Unlike the chain, these files
  are not padded.
- **Growth.** `file-checkpoints.jsonl` gains one line, with its COSE statement, for each file
  that grew since its last cut, at each cadence tick and ask. Like `checkpoints.jsonl`, nothing
  shortens it.
