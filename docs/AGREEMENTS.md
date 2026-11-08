# Service evidence agreements

A paid session with a provider can run under one signed agreement: the
requester proposes what the provider is to produce evidence for, the
provider accepts, and later exchanges in the session cite that acceptance.
The agreement is the interop profile's acceptance record
(`evidence-interop/0` §11.1), session-scoped. This page describes what this
plugin sends, keeps and cites, and how the Evidence page shows which
exchanges an agreement covers.

## Turning it on

Agreements are off until the operator sets a spend cap. With no cap set,
nothing is proposed and nothing changes.

| Setting | Meaning |
| --- | --- |
| `CAPSULES_AGREEMENT_SPEND_CAP_MSAT` | The cumulative settled amount a session covers, in msat. Setting it turns agreements on. |
| `CAPSULES_AGREEMENT_MAX_EXCHANGES` | Optional: how many exchanges a session covers. |
| `CAPSULES_AGREEMENT_WINDOW_SECONDS` | Optional: how long a session lasts, from its proposal. Default 3600; 60 to 86400. |
| `CAPSULES_AGREEMENT_TIMEOUT_MS` | Optional: how long the requester waits for each round trip with the provider, connecting included. Default 8000. |
| `CAPSULES_AGREEMENT_RESPONDER_TIMEOUT_MS` | Optional: how long a provider waits at each step of an inbound agreement stream. Default 10000. |
| `CAPSULES_AGREEMENT_HOOK_WAIT_MS` | Optional: with the admission hook granted, how long a request may be held for its session to be set up, counted from when the hook is called. Off (0) by default. Set it below the grant's `deadline_ms`; at most 1750, under the 2000 the plugin declares. |

The spend cap is the requester's own statement of what it expects to spend,
an agent-origin assertion. It is not a signed authorization by a person, and
the provider's acceptance never authorizes spend. The host's wallet budget
still bounds what is actually paid.

## When a session is set up

The plugin learns of an exchange after the host has sent the request. So the
requester proposes a session on its first exchange with a provider for a
model, once agreements are on, and again after the session's window ends.
That first exchange is outside the agreement; later exchanges in the window
with that model are under it. The set-up runs beside the exchange and never
holds it up.

Where the operator granted the plugin's admission hook, the requester
starts the set-up when the host has selected the provider
(`backend_selected`), before the request goes out. With
`CAPSULES_AGREEMENT_HOOK_WAIT_MS` set, it holds the request that long at
most, so that exchange can be under the agreement too. That works when the
provider serves one model and the set-up finishes within the hold. A set-up
that takes longer finishes in the background and the request goes on;
whether that exchange cites the session is decided when it ends, from the
complete sessions each side holds then. An exchange set up this way usually
falls in the same minute as the receipt, so it reads covered with
"agreement present; ordering not established", not "accepted before".

The session names the provider's own model id. When the host's exchange
events don't name it (mesh-llm 0.78 doesn't), the plugin reads the
host's `GET /api/status`, on the console it already reads announced keys
from: its own `serving_models` on the provider, the provider's on the
requester. A node serving exactly one model gives that model. A provider
serving several, or a status that lists the provider twice or not at all,
gives none: the requester proposes no session for that exchange, and the
provider cites one only by its weights digest (below). The
status is read only where a session can be proposed or cited, and not
again for 30 seconds after a read fails.

The provider's own exchange events state a digest of the weights it served
(`weights_digest`, the SHA-256 of the GGUF file) even when they name no
model. A single-file GGUF loaded from disk has that digest as its model id
(`local-gguf/sha256-` and the digest), so the provider first cites a session
that names this id, and only then one for the model its status gives. A
provider serving several single-file local GGUFs therefore still cites the
session for the one that served the exchange. A split GGUF's id, or one
resolved from a Hugging Face ref, hashes more than the file, so it matches
no digest and the provider falls back to the status's model. The
requester's events carry no digest, so a requester still proposes only to
a provider serving one model.

A provider whose plugin predates agreements answers the proposal with
something else at once, and the requester goes on without an agreement.
After a set-up that does not end in an agreement, the requester waits ten
minutes before proposing to that provider again.

A provider answers only a requester whose plugin key a peer announced, works
on at most four agreement messages at once, and holds at most eight unexpired
sessions, and accepts at most 48 sessions a day, per requester. It accepts a
session window that starts when it is proposed and lasts a minute to a day,
allowing five minutes of clock difference between the two nodes. A proposal sent
again gets the same answer back.

## What is sent

Each message is one stream on the private mesh channel
`x-capsules-agreement/1`. Records travel as JSON text, so both sides keep the
exact octets the other signed.

1. The requester sends its signed `proposed` record with three documents:
   the Evidence Contract, the model policy (the model the requester expects
   the provider to state it serves, by the provider's own canonical
   reference) and the terms (`spend_cap`, `unit` `msat`, `payment_ref_type`
   `ln.payment_hash`, `inference_deals_digest`, and `max_exchanges` when set). The digest names the inference-deals pack the judge applies; the provider accepts only its own. The record names each
   document by its digest.
2. The provider checks the documents against their digests and their shapes,
   and the records with the interop profile's own verifier, then answers with
   a signed `accepted` record.
3. The requester checks the answer and signs a receipt (§11.1.4) saying when
   it held the acceptance. The receipt is the evidence that the agreement came
   before the exchanges it covers. It sends the receipt to the provider, which
   keeps it.

No agreement digest goes into a Lightning invoice description, which routing
nodes and wallets can read.

## What cites the agreement

A record under a session names the session's accepted record by its digest,
as an EL `cites` link in its `x-mesh-poc-v1` block:
`"acceptance": {"type": "cites", "target": "<digest>"}`, beside `"inference_deals_digest": "<digest>"` (the same digest the terms cite, so a judge reading only the chain can check it). It is committed into
the record's `capsule_id` like every other member. A record under no session
has no such member.

- The requester's requested half and the provider's served half cite the
  session between the two nodes for the model the host states was served.
  Each side decides this once, at the exchange's terminal event. The
  provider cites a session only when it holds exactly one for that requester
  and model.
- In settlement records, one leg per side cites it. The payer's `delivered`
  leg, sealed once the provider and model are known, cites the payer's session.
  The provider's `payee_observed` leg cites what the provider decided for
  that payment's exchange when it served it, and only when that session's
  requester is the payer whose key signed the terms leg the payee leg
  answers. A payment settled before the provider has served the exchange (a
  deposit, often) has no decision yet and cites nothing. The payment and the
  exchange are matched by the host's exchange id. The
  payer's `terms` and `payer_observed` legs are sealed before the provider is
  known and cite nothing.
- An exchange's citation is decided at its terminal event, before a session
  can be set up from it, so the exchange that sets up a session never cites
  it, and a record of that exchange sealed later never cites a session that
  appeared after it.

A leg carries the link in the same block, beside the settlement member, so
the settlement record's own checks are unchanged; the interop profile's and
the settlement records' reference verifiers both accept such a leg.

## The Evidence Contract

Every session names one contract, fixed in this plugin:

- `contract_ref`: `x-capsules/paid-session@1`
- `contract_digest` (SHA-256 of its RFC 8785 form):
  `5f54aa7816d9ca9f469b8c4a8c79a0a67eadf475a0de4734368aa61f74efcc01`

```json
{"id":"x-capsules/paid-session","requirements":[{"id":"R-prior","statement":"the agreement was accepted before the exchange"},{"id":"R-served","statement":"the provider's served half is present and verifies"},{"id":"R-model-stated","statement":"the model the served half states is one the session's model policy names (stated, not verified)"}],"version":"1"}
```

A change to its content is a new version (`@2`); `@1` never changes. Payment
is not a requirement: the cap and the count say which exchanges a session
covers, and an exchange over the cap is "not covered", never a failure.

## Coverage on the Evidence page

Each Exchanges row whose own half this node sealed gets `agreement`, computed
by this node alone for its own side (`side`: `requester` or `provider`). The
other side keeps its own figures on its own node, and the two can differ: the
requester counts every exchange it asked for, so its count can be higher than
the provider's. A node that keeps no complete session adds nothing, except
`not_evaluated` on a half that cites one.

`coverage` is the first of these that applies:

| Label | Meaning |
|---|---|
| `not_evaluated` | The half cites a session this node does not keep, so nothing is said about it here. |
| `set_up_after` | Not covered: the half cites nothing, and the first session with this counterparty started after it. |
| `outside_window` | Not covered: the half cites a session whose window does not hold the half's time. |
| `over_count` | Not covered: counting this exchange, more exchanges cite the session than the terms' `max_exchanges` allow. |
| `over_cap` | Not covered: the observed spend, through this exchange, exceeds the spend cap. |
| `cap_not_evaluable` | A payment of this or an earlier exchange under the session has no observation held, and the known sum does not exceed the cap. |
| `not_cited` | A session with this counterparty holds the half's time, but the half cites none. |
| `covered` | Inside the window, the count and the cap. |
| `no_agreement` | No session with this counterparty bears on the half, or the half does not name a counterparty this node knows. |

None of these is a failed exchange.

- **Count and cap** run per session in this node's own log order. The count
  is the half's position among this side's halves citing the session. The cap
  sums, over every payment of every citing exchange, this side's own
  observation: the payer's `payer_observed.amount` without the routing fee, or
  the provider's `payee_observed.received`. An exchange's payments are the
  invoices this node's own payment lifecycle records name under the exchange's
  id, joined to a leg by its `payment_ref`, so a leg that cites nothing still
  counts. `spend` gives the observed sum, whether it is only a lower bound, the
  cap and its basis: the cap is the requester's own assertion
  (`agent_origin_assertion`).
- **`finding`** is the interop profile's finding (§11.1.8) over the
  provider's served half, read as the provider's execution record: its issuer
  is the key its producer envelope verifies under, its action time is its own
  `timestamp`, and its citation is its `acceptance` member. The requester has
  it only once it holds the provider's half; until then `finding` is null and
  `finding_not_evaluated` is `served_half_not_held`. `evaluation_failed`
  there means the evaluation itself erred. Every committed time is to the
  minute, so an exchange in the same minute as the receipt reads "accepted,
  the execution cites it" (`accepted_execution_cites`) rather than "accepted
  before".
- **`requirements`** gives each requirement of the contract a result: `R-prior`
  is `met` on `accepted_before_action`, `not_met` on `accepted_after_action`,
  and `not_evaluable` otherwise, with the accepted record and the receipt it
  relies on as evidence; `R-served` is `met` when the served half is held and
  verifies; `R-model-stated` is `met` when the model that half states is one
  the session's policy names, as stated, not verified. A half that states no
  model id but a weights digest D (mesh-llm 0.78) states the local GGUF
  `local-gguf/sha256-D`; `stated_as` says which form the result rests on
  (`canonical_ref` or `weights_digest`), and `stated_weights_digest` gives D.

## What is kept

Under the ledger directory, `agreements/`:

- `records/<digest>.json`: the `proposed` and `accepted` records, as sent;
- `receipts/<digest>.json`: receipts;
- `documents/<digest>.json`: the contract, model policy and terms.

Each object is kept as the octets it travelled as. Each file is named by its
digest (SHA-256 over the RFC 8785 form of the parsed object), so a second copy
of the same object is the same file, and the first octets kept stay.

Nothing under `agreements/` is removed yet. How long agreements are kept is an
open item.
