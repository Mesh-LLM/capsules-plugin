# Failed exchanges

A request that fails leaves a record on each side that saw it (action-state-group/evidencebook#205).
This is the same exchange record under `x-mesh-poc-v1`, not a new record kind. A failed record says
that the exchange failed and why. It never says what was asked or answered.

## What is sealed

The host (Mesh-LLM/mesh-llm#2852) puts `failure_class` on the terminal `openai.exchange.v1` event of
an exchange that did not complete: `payment_required`, `refused`, `upstream_error`, `timeout` or
`dropped`. The class, not the `status`, says the exchange failed: a stream cut after its 200
headers has status 200 and a class. A failed exchange that came over the mesh to a node that was to
serve it also carries `requested_by_node_id`, the asking peer from the connection's authenticated
remote id.

| Where | Sealed |
|---|---|
| The requester's node (`dispatch_path: remote_mesh`) | Every failure. The node chose to send the request. |
| A provider's node (`raw_proxy`, `typed_frontend`) | A failure for an identified mesh peer (`requested_by_node_id`), up to the cap below. A failure with no named peer is observed and not sealed. |

The record's members, beside the ones every exchange record has:

| Member | Value |
|---|---|
| `x-mesh-poc-v1.outcome` | `failed`. **An absent `outcome` means served**, so a record sealed before this member existed reads as served. |
| `x-mesh-poc-v1.failure_class` | The class above. Absent when the host sent a class this plugin predates. |
| `effect.status` | `failed` |
| `x-mesh-poc-v1.role` | As for any exchange: `requested` on the requester's node, `served` on the provider's. |

It carries the model name, the role and the asking peer (`serving_provenance.requesting_party`, on
the provider's record). It carries no request, response, tool-call, reasoning or response-text digest,
no usage and no body, even when the event carried them. No price is sealed yet: the quoted price
comes from the payer's `terms_accepted` rates (Mesh-LLM/ln-payments-plugin#12, not merged), and a
refused 402 has no accepted terms, so it has none.

A failed record is never pushed to the counterparty. The share gate is unchanged: each side keeps its
half, and a counterparty gets only what the gate already gives it.

## The provider's cap

A provider that sealed every refusal would let anyone grow its log for free. So a provider seals at
most **20 failures per peer per hour** (`failure_window.rs`, fixed windows aligned to the Unix
epoch). Past that it seals nothing more for the peer in that window. When the window closes it seals
**one summary record per peer**: the same failed exchange record with no class, the model `unknown`,
the asking peer, and

```json
"unsealed_failures": {"count": 3, "window_start": "2026-11-04T10:00:00Z", "window_s": 3600}
```

so the gap is on the record. Counts are in memory: a restart forgets the open window, which can
seal at most one more window's worth for a peer and loses that window's summary. The requester
side is not capped.

## What does not count it

- **The Evidence tab** labels a failed record `failed` (`label_role`, row tag `FAILED`), never
  `served` or `requested`, and counts it on neither side.
- **Service History** (`service_history/1`) counts served exchanges: a failed record is not one. The
  definition document is unchanged, so its digest is too; the exclusion is in how the node reads its
  records (`evidence_log::leaf_facts`), which is the only place the counts read records.
- **Provider receipts** root at the record of an exchange the node served: a failed record is not
  that record, so a failed exchange has no receipt bundle.
- **Exchange corroboration** (`exchange_corroboration/1`) answers with the halves that bind digests: a
  failed half binds none, so it is not listed, and a nonce with only failed halves is
  `no_such_subject`.

A timeout is the requester's view and the provider may have finished. The two records then disagree
(a failed half and a served half), and evidencebook's `ReconcileHalves` reports that rather than
hiding it.
