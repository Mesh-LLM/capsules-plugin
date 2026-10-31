# Changelog

## Unreleased

### Changed

- **Configuration page regrouped.** The plugin's settings are declared in three groups, "What
  you show others", "When answers differ" and "Keeping records", with the labels and one-line
  descriptions of the Configuration design, and a single rising row order, so a console that
  shows one flat list still follows the design's order. Labels, order and descriptions only: every key,
  choice and default is unchanged, so no saved config changes meaning. The old "Sharing policy",
  "Referee" and "Routing rule" groups are gone; "Evidence network" stays as its own group.

### Fixed

- **A payer's settlement terms leg is pushed under a checkpoint, with its inclusion proof.** It
  went bare, unlike every other pushed half, so the provider held it with no checkpoint or proof
  and its book could not show it was pushed under one (loop step 05 `pushed_under_checkpoint`).
  With the checkpoint cadence off it is pushed bare, as before. A leg an earlier version pushed
  bare is pushed once more, under a checkpoint, once per start with the cadence on: at the host's
  first mesh event, which names this node's peer id, or its first channel message, whichever comes
  first. It goes to the peer the leg's sealed exchange record names; the provider, already holding
  the leg, adds its checkpoint and inclusion proof. Each push's outcome is kept in
  `ledger/covered-terms-legs.jsonl` (`covered`, or `no_inclusion` from a receiver that predates
  bundles), and a leg with an outcome is not pushed again; one that did not arrive, or that the
  receiver refused, is retried at the next start. At most 64 pushes per start, and a peer that
  cannot be reached is skipped for the rest of that start. It re-sends sealed records only and
  moves no money. Mesh-LLM/capsules-plugin#187.

## 0.1.7

### Added

- **Admission's price rule (#105).** A peer the admission lists admit is then decided by
  capsule-engine's guard with its `asg/inference` terms pack (`capsule-engine` crate, pinned at
  3663fbf), not by a second evaluator here. Its input and output rates, in msat per million tokens,
  are checked against the caps in the operator's `policy-profile/v0` file
  (`CAPSULES_ADMISSION_PROFILE`), which may also set the pack's counterparty list. A rate over a
  cap, an unreadable rate, or a peer that list refuses or asks about gets NO, and the reason names
  the rule. A free route is GO.
  - The rates come from the host's `backend_selected` event (`pricing`), which a host sends once it
    lists `openai_exchange.backend_pricing.v1`. When an attempt carries no price it can trust (an
    older host, or a request naming no model), the operator's profile fails closed and the
    shipped caps alone record the price as not checked; `doctor` flags an older host.
  - The sealed `admission_decision` gains a `price` member (the rates and each check's result,
    never the peer's id) and a `terms_pack` read citing the pack, its definition digest and a salted
    commitment to the profile's digest (the profile holds the counterparty list in clear). `doctor` shows them with the profile's values.
  - With no profile, shipped caps apply as an outlier guard: 500,000 input and 1,500,000 output
    msat per million (`DEFAULT_RATE_CAPS`), 1000x mesh-llm's CLI default price.
- **Admission's lists and base rows through capsule-engine's admission evaluator (#178).** The
  allow and deny lists (#55) and the five base rows (#64) are decided by
  `capsule_engine::admission` (`capsule-engine` crate, now pinned at c770138) under a base pack
  the plugin ships, `asg/mesh_admission_base/1.0.0` (`policies/admission/mesh-base/`, embedded and
  pinned by its definition digest), not by a second evaluator here. The pack yields GO and NO only:
  the lists are its two NO rows and the five rows are recorded and decide nothing, with today's ids
  and thresholds. Every verdict and `source` is the one the lists gave before, and the price rule
  still runs after them.
  - Each sealed row gains the evaluator's `effect` and, for the three rows from this node's own
    book, `count` and `denominator`. The denominator is the peer's exchanges, every one this
    node's records name it in or holds its half of, so no count exceeds it; for disputes it is the
    verdicts in the 30-day period.
    `reads` gains a `terms_pack` entry with `role: "base"` citing the pack and its definition
    digest; the price rule's entry now says `role: "price"`.
  - A verified card whose first checkpoint does not parse now records `key_age` as `fail` (the
    evaluator reads it as showing no age), where it read `not_read`.

### Fixed

- **An `exchange` request is answered to the node whose half it asks about.** The receiver's
  citing record carries no `x-mesh-poc-v1` block, so the evidence index named no counterparty for
  it, and under `share_history_segments = counterparties` it was refused `not_authorized` to every
  asker, the half's own sender included (loop step 07). A citing record now goes to a request
  signed under the key its cited half verified under (`received_half.sender_key_id`, sealed for a
  push accepted on that key). The id a push names (`received_from`) is the pusher's own word and
  grants nothing. Under
  `evidence-interop/1`, `policy_check` reads a policy refusal of record bodies the pinned policy
  gives no one (`range`, `full_history`, or any record subject while `share_history_segments` is
  `off`) as `MATCH` instead of `NOT_CHECKED`. Mesh-LLM/capsules-plugin#172.

## 0.1.6

### Changed

- **Evidence requests speak `evidence-interop/1` (Evidence Request -02), and a refusal says
  whether it was policy.** The node answers a request under `evidence-interop/0` or `/1`,
  whichever it names (a request with none asks for /0), and asks under /1. Under /1 it declines for
  a limit or fault of its own with `capacity_exceeded`: a full stranger pool, a request, answer, or
  record or checkpoint count over its limit, a Service History older than its period limit, an
  answer it cannot build. A request whose signature, key binding, audience, deadline window or
  replay check fails gets `request_unauthenticated` (`capacity_exceeded` while the node does not
  know its own id). `not_authorized` and `policy_declined` are then policy only. A /0 request
  gets the tokens it got before.
  - On the asking side, `policy_check` judges a /1 refusal's `policy_declined` and
    `not_authorized` against the policy the peer's commitment pins: withholding what the policy
    gives any asker is a `MISMATCH`. `capacity_exceeded` reads `NOT_CHECKED` and
    `request_unauthenticated` `MATCH`; a /0 refusal reads as before.
  - A peer that implements only /0 (every release before this one) refuses a /1 ask
    `request_malformed`, so the ask is sent once more under /0, with its nonce suffixed
    `/evidence-interop-0`. The book of asks holds both.
  - A Service History is served under either identifier with the same artifact
    (agent-action-capsule#484).
  - The commitment and its `history_card` staple do not change.
  - `evidence-request` 0.3.0 and `evidencebook` 0.0.11 (its move to 0.3, and the envelope signed
    under the profile the request names).
  - A refusal is read by its request's profile: an -02 reason answering a /0 ask is not a
    conforming refusal. A full replay cache is `capacity_exceeded` under /1, not
    `request_unauthenticated`. A request the caller signed is sent as given.
  - Mesh-LLM/capsules-plugin#114.
- **The Evidence tab says when a peer's answer is not witnessed.** A history or record that checks
  only against the peer's own signatures is no longer shown as verified (no ✓, no "checks out"):
  it says no witness this node trusts has vouched for that log, or that this node has no witness
  configured, so it could be a private copy. Only an answer with a verified witness receipt keeps
  "verified". A remembered history keeps its witness standing; one remembered before this says its
  standing was not recorded. A record row still closes as Confirmed. Mesh-LLM/capsules-plugin#154.
- **The payer's deal report is sealed for the owner (`keep`) and never leaves the node.** It was
  sealed for the counterparty audience, so capsule-viewer rendered the owner's own receipt as the
  other party's copy and refused it as `keep`. A copy for the counterparty is made only by a share
  path, which is not built; until then the counterparty is served the deal's steps, not the report.
  A counterparty's range or full-history request that covers the report is refused whole (a range
  is answered in full or refused in full, as for an ask record); it can still ask for the steps one
  record at a time. Mesh-LLM/capsules-plugin#146.
- **`evidencebook` 0.0.10 (with `agent-action-capsule` 0.5.0).** The `deal` git-rev patch is gone. `capsule-emit` 0.0.9 still takes `agent-action-capsule` 0.4.1, so the
  tree holds both until a `capsule-emit` release moves to 0.5.0.
  0.5.0 reads a witness receipt with an empty `receipt_b64` as malformed, so the served summary's
  `witness_check` for the pinned baseline's synthetic stub receipt (empty `receipt_b64`,
  `is_stub: true`) is now `FAIL` with no per-receipt rows, not `NOT_CHECKED`. The three
  `served_summary` forms in `tests/fixtures/evidence_answers_5d2d102.json` are rewritten for it
  (nothing else changes); the node's own witness client sets `is_stub: false`, so no served
  checkpoint carries such a stub.

- **`capsule-emit` 0.0.9.** It adds `produce`, the Go-identical Capsule build the deal records are
  sealed with, and drops `structure`: the Class 1 check of a received half (record push, the
  referee, an agreement half) now runs through `agent_action_capsule::verify::verify`.

- **Evidence answers, the served summary and the received log come from the `evidencebook` crate
  (0.0.9).** The plugin's own copies are deleted. evidencebook builds and signs every artifact
  answer over the plugin's ledger index, and never opens the MMR node store the checkpointer
  writes. The plugin keeps how a ledger line is read, which requests it answers to whom, and the
  witness keys.
  Every answer is byte for byte what it was, except one change for readers of
  `served_summary/1`. A witness receipt now counts toward `coverage.witnessed` and
  `coverage.witnesses` only if it verifies under the key this node configures for that witness.
  Each receipt is also listed in `coverage.witness_receipts` with `PASS`, `NOT_CHECKED` or
  `FAIL`, and the overall result is in `coverage.witness_check`. A receipt the node cannot check,
  such as one with no configured key, now reads `NOT_CHECKED` instead of counting as witnessed.
  Refusals are still signed by `evidence-request`. The build now carries a second
  `agent-action-capsule` (0.4.1, evidencebook's witness verifier) beside the 0.1.0 the plugin
  already had. action-state-group/evidencebook#35, Mesh-LLM/capsules-plugin#84, #87, #89, #90,
  #91, #92, #93.
- **`share_record_at_completion` is on by default (`counterparty`), reversing the 0.1.3 default.**
  Every node now pushes its sealed record of a completed exchange to the counterparty and accepts
  the counterparty's push, with no setting; `off` still does neither. The record goes only to the
  other side of that exchange; the public checkpoint list shows when exchanges ended.
  `share_adjudications`, `adjudicate_differing_twins`, `share_standard_history` and
  `share_history_segments` keep their defaults. Mesh-LLM/capsules-plugin#68.
- **Pushes and evidence requests are accepted on the sender's evidence key, not the peer id they
  arrive under (D-34).** A half signed by a key this node knows is held whatever peer id the push
  declares, and a push under a known peer id signed by an unknown key is refused
  `signature_unverified`; that refusal now names the refused key (`refused_key_id`) under the
  node's signature. A signed request's asker is every node its key is bound to, so a counterparty
  whose transport id rotated still gets its records. A key is known when a host announced it for
  some peer, when `CAPSULES_PEER_KEYS` lists it under any name (a stopgap for a node with no stable
  peer id, such as a client-only node; it now authenticates requests too), or when the sender
  carries a controller declaration: a `controller-binding/0` record (Controller Binding v0,
  `same_controller_asserted` under `dual_signature/0`, inside its window) binding its key to a key
  known one of the other two ways, in a push bundle's or a signed request's `controller_binding`
  member. A key that a carried declaration binds to the receiving node's own key is refused,
  however else it is known. A served half's named server must be a peer its key is bound to.
  The `counterparty_half` citing record names the sender's key and how it was accepted
  (`sender_key_id`, `accepted_via`: `host_announced`, `operator_stopgap` or
  `controller_declaration`, with the binding's digest); nothing decides on it. A receiver on an
  earlier release refuses a bundle that carries a declaration `bundle_malformed`. Fixtures for each
  case are in `vectors/evidence-key-acceptance/`. Mesh-LLM/capsules-plugin#69.

### Added

- **`provider-receipt-bundle`: the provider's own receipt for a paid exchange it served.** A local
  route, given the host's exchange id, returns an `evidence-bundle/v2` of the exchange record the
  node served and the `payee_observed` legs it sealed for it (what it received, in the amount's own
  unit), proven against the earliest checkpoint that covers them. It is not a deal: the typed
  seller deal the profile asks of a seller needs an offer, an acceptance and an authority the node
  does not make, so none is sealed. Owner-only and producer-selected (`capsulectl verify` reads it
  INCOMPLETE, `selection_not_checkable`, as for the payer's), with no payload disclosed: the
  digests stay, the inference content is not in it. A leg names no exchange, so the node now notes
  the payment's hash for its exchange in `provider-links.jsonl` before it seals the leg, and the
  receipt finds the legs by that hash; a payment sealed before this change has no note and is not
  found. capsule-viewer renders the bundle as the provider's own
  half. Steven's ruling on Mesh-LLM/capsules-plugin#146; Mesh-LLM/capsules-plugin#134.
- **`deal-receipt-bundle`: the payer's deal as an Evidence Bundle.** A local route, given an exchange
  record's capsule id, returns an `evidence-bundle/v2` of this node's `x-deal-v0` records for it
  (baseline, outcome, close, report) with their payloads disclosed and
  `extensions["x-deal-v0"].sealed_report` naming the report, each proven against one signed
  checkpoint of the node's log. Nothing else of the ledger is carried, and the baseline's intent
  stays closed (no nonce, no opening, no raw peer id), since the file can be forwarded past the
  share gate. A deal with no report yet, an unknown or free exchange, or no covering checkpoint gets
  a refusal. The selection is the node's, so `capsulectl verify` reads the bundle INCOMPLETE
  (`selection_not_checkable`); capsule-viewer shows nothing for it until it renders such a bundle.
  Takes `agent-action-capsule` feature `strict`. Mesh-LLM/capsules-plugin#96.
- **A paid exchange is sealed as an `x-deal-v0` deal (payer side).** For an exchange with at
  least one invoice issued, the node seals a `baseline` (what was asked: the request digest and
  model, committed under a nonce the node keeps; the serving peer by fingerprint only; paid over
  Lightning, not refundable; no price, since an invoice's msat has no unit in the profile), then an
  `outcome` and a `close`, then an in-log `deal_report` for the owner (audience `keep`). `completed` once
  every invoice is paid and the response received; `open` when no settlement came within 15
  minutes of the first invoice or the node restarted first (the record is not final, never
  "pending"). A free exchange gets no deal. The Capsules are built by `capsule_emit::produce`
  (bytes identical to Go's) from `evidencebook::deal`, each linked to its exchange in
  `deal-links.jsonl` before it is sealed; the payload each commits is journaled in
  `deal-payloads.jsonl`, and a step counts as sealed only if its Capsule is in the ledger, so a
  restart neither repeats a step nor loses one. The provider seals no deal (its receipt is
  "your receipt only", Mesh-LLM/capsules-plugin#134). `check_profile.py` accepts the built chains
  (`EVIDENCEBOOK_DEAL_PROFILE_DIR` runs it in the tests). Takes `evidencebook` (feature `deal`)
  from crates.io. Mesh-LLM/capsules-plugin#96.
- **Counterparties receive and check the operator binding (loop step 12).** A node holding a
  controller binding of its key to its operator's Nostr key carries it whole in the bundles it
  pushes to an exchange's counterparty, in the existing `controller_binding` member, and never in
  a request or an answer. A receiver that does not take the member refuses `bundle_malformed`, and
  the bundle goes again without it. The receiver checks the binding applies and binds the half's
  key, and its citing record's `received_half` carries `controller_binding_digest` however the key
  was accepted, plus `same_controller_as_receiver` when the receiver holds its own binding (true
  when both name the same operator key). The operator's Nostr key is never sealed: a declaration
  anchored on a `bip340` key no longer records `controller_anchor_key_id`. Nothing new is gated.
  `vectors/evidence-key-acceptance/cases.json` gains four operator-binding cases, covering
  `same_controller_as_receiver` true, false and absent.
  Mesh-LLM/capsules-plugin#113.
- **A deal capsule goes to the counterparty of the exchange it is of.** A step of an
  `x-deal-v0` deal (not its report, which stays on the node: Mesh-LLM/capsules-plugin#146) names no counterparty itself, so under `share_history_segments=counterparties`
  it would have gone to nobody. The node now writes `deal-links.jsonl` in the ledger directory,
  one `{"capsule_id", "exchange_capsule_id"}` line per deal capsule, before it seals the capsule,
  and the share gate takes the counterparty of the exchange record the capsule is linked to: the
  counterparty can read the steps, an unrelated node cannot, and a deal capsule
  with no link goes to nobody. Nothing seals a deal yet; this is the gate the Mesh receipt
  (Mesh-LLM/capsules-plugin#96) needs first. No release.
- **The saved History page carries the Service History when the node shares it.** With
  `share_standard_history` on and a checkpoint at a period boundary, the `history-page` route
  answers what a stranger would get: the Service History pinned to the latest such checkpoint, and
  the saved page checks the history card inside (its digest, the checkpoint signatures, the chain
  and the anchor) and shows the node's own per-week counts as it states them, saying the counts
  were not checked. Otherwise the page holds the card, as before. Mesh-LLM/capsules-plugin#96.
- **Service evidence agreements on hosts that name no model, and before the request (M4).** When
  the host's exchange events carry no model id, the plugin takes the provider's from the host's
  `/api/status` (only when that node serves exactly one model). Without this, a requester on
  mesh-llm 0.78 never proposed a session. With the admission hook granted, the requester starts the
  set-up at `backend_selected`. With `CAPSULES_AGREEMENT_HOOK_WAIT_MS` set below the grant's
  `deadline_ms` (off by default), it holds the request that long at most, so that exchange can be
  under the agreement too, when the provider serves one model and the set-up finishes within the
  hold. See `docs/AGREEMENTS.md`.
  action-state-group/evidencebook#48.
- **A provider serving several single-file local GGUFs cites the session for the one it served.**
  With no model id in the exchange event, the provider matches the session by the event's
  `weights_digest`: a single-file GGUF's id is `local-gguf/sha256-` and that digest. Then, as
  before, it falls back to the one model its `/api/status` lists, which is what a split or Hugging
  Face-loaded GGUF gets. On the Exchanges pane, `R-model-stated` counts such a half as stating that
  GGUF, met when the session names it, and says so (`stated_as: "weights_digest"`).
  action-state-group/evidencebook#48.
- **Service evidence agreements on the Evidence page (M4, fourth part).** An Exchanges row shows
  the agreement's coverage label for this node's side, the ordering finding ("accepted before the
  exchange", or "agreement present; ordering not established" for an exchange in the receipt's
  minute), the exchange count and the observed spend against the cap, marked "spend cap:
  agent-origin assertion". "Covered" is shown in the good tone only when the agreement is shown
  to come before the exchange. A paid exchange under no agreement says "no agreement"; one citing
  an agreement this node does not keep says it is not evaluated here.
  action-state-group/evidencebook#48.
- **Service evidence agreements: coverage on the Exchanges rows (M4, third part).** Each row whose
  own half this node sealed carries `agreement`: its side's coverage label (covered, outside the
  window, over the count, over the cap, cap not evaluable, agreement present but not cited,
  agreement set up after the exchange, no agreement, or not evaluated when the half cites a
  session this node does not keep), the count and the observed spend against
  the cap, the interop profile's §11.1.8 finding over the provider's served half, and the
  contract's requirement results. A requester states no finding until it holds the provider's
  served half. Agreement records and receipts now commit their times to the
  minute, like every other committed time. See `docs/AGREEMENTS.md`.
  action-state-group/evidencebook#48.
- **Service evidence agreements: records cite the session (M4, second part).** A requested half,
  a served half, the payer's `delivered` leg and the provider's `payee_observed` leg under a
  session carry `"acceptance": {"type": "cites", "target": <digest>}` in their `x-mesh-poc-v1`
  block, committed into the record's `capsule_id`. A leg carries the block beside its settlement
  member, so the settlement checks are unchanged. A record under no session is as before. See
  `docs/AGREEMENTS.md`. action-state-group/evidencebook#48.
- **Each ask is recorded (loop step 7).** Every evidence request this node sends is sealed as an
  `evidence_request` record, holding the request exactly as sent, before it is sent; a request
  that is not well formed, or reuses a nonce, is refused and never sent. A reply inside the
  waiting window (the later of the request's deadline and 60 s) is sealed as `evidence_response`
  citing the request; none by the close is sealed as `recorded_absence`. A late reply never
  replaces an absence. A node that restarts seals the absences it owes and closes the windows
  still open. The records are evidencebook's (`evidencebook::ask`) and never leave the node in an
  answer. `mesh_commitment_fetch` now holds a peer's commitment that passed every check; an ask
  records the commitment held for the peer, and a signed refusal is checked against the policy
  it pins (`policy_check`: `MISMATCH` when the policy answers it to any asker and the refusal
  withholds it, `MATCH` when the refusal blames the request or the policy does not answer that
  subject, `NOT_CHECKED` with no commitment held, for `policy_declined` or `not_authorized`,
  which honest responders also send for load, size and signature limits, or where the answer
  depends on who asks). Mesh-LLM/capsules-plugin#56.
- **The Exchanges tab saves a History page and a Settlement page, each one .html file that checks
  itself when it opens (Mesh-LLM/capsules-plugin#96, Steven's 10-29 ruling).** They replace the
  tab's "Save evidence file" JSON download for an outside party. The History page is what the node
  answers a stranger who asks for its history (`history_card/1`, new route `history-page`), so it
  carries no more than the node's disclosure policy sends to that party. It embeds the reply byte for
  byte, checks it on open with `@action-state-group/cll`'s browser build (the artifact is the bytes
  its digest names, every checkpoint is signed by the key that answered, each consistency proof
  holds, the log starts at its beginning, the last checkpoint is the anchor), shows nothing from a
  reply that does not check, shows the key id the checkpoints were checked under, and lists what it
  could not check: witness receipts, the signature on the reply, that the key is the node's, and
  which request it answers. "Save the JSON" returns the embedded bytes unchanged. The
  Settlement page says it holds no evidence from the node, with the dashboard's own note, until the settlement terms pack exists
  (action-state-group/evidencebook-skills#71). The per-exchange receipt page, the Service History
  form when `share_standard_history` is on, and the 9b wording are not in this change. The CSV and
  the integrity, peers, twin-bracket and "Your records" JSON exports are unchanged. No release.
- **The node key bound to its operator (loop step 12).** `join` takes an optional
  `controller_binding`: a Controller Binding record (AAC `spec/controller-binding-v0.md`) that binds
  this node's key to its operator's, which may be the operator's Nostr key (`bip340`, signed with a
  Nostr event). `join` stores it only when it binds this node's key and applies, and refuses it
  otherwise. `join` also runs the ceremony itself: given the operator's Nostr key (`controller`),
  it signs the node's half and returns the Nostr event the operator signs with their own signer;
  given that event back (`controller_event`), it stores the binding, in effect for a year. The
  join quickstart in `INSTALL.md` gains this step. `doctor` reports `controller_binding: bound` with the binding digest, or `unbound` with
  the reason. The commitment names the binding by its digest alone (`controller_binding.digest`),
  never the operator's key, and the binding stays optional (Steven's ruling). Verification of the
  `bip340` key type uses `k256`. Mesh-LLM/capsules-plugin#54, #97.
- **The Service History checks against the period policy of the definition it is handed, and the
  #315 vectors run.** `period_alignment`, `period_anchor` and `period_floor` read the epoch, length
  and floor from the definition's `period_policy` (checked as `definition_form`) instead of fixed
  weekly values; this node's own definition, its digests and its answers are unchanged. A test runs
  the 19 Standard-level cases of the `inference-service-history-v0` vectors
  (action-state-group/agent-action-capsule#315 at f8c946ed), whose policy is daily from
  2026-10-01; the 8 Detailed-level cases are listed by id, not run. The new test-only cargo feature
  `test-period-policy` overrides the epoch and length from the environment, for the two-node e2e,
  which now runs a Service History across a period boundary on two nodes and compares the embedded
  card with the direct one (action-state-group/evidencebook#46).
- **The Service History (`service_history/1`), a Standard History under the inference-service
  history profile.** A requester asks for it by the digest of
  `derivations/service-history-1.json` (`cbc96d80…`), for `full_history`, pinned to a checkpoint
  whose time is a period boundary: Mondays 00:00 UTC from 2026-01-05. The answer embeds this node's
  `history_card/1` artifact byte for byte, with its SHA-256, and counts the exchanges it served in
  each closed week, per model it states and in total. A count under 5 is withheld, and so is the
  smallest other model when the total would give a withheld one away. Latency is never counted.
  Any other subject, coverage or anchor is refused `policy_declined`, the same for every
  requester. The checkpoint cadence now appends one padding record and cuts a checkpoint
  at each boundary. It is Standard History
  (`share_standard_history`), and this node checks a Service History it is sent, the card as a
  direct one and every period rule one History shows. The definition follows
  action-state-group/agent-action-capsule#315 at f8c946ed and the period policy Steven ruled under
  action-state-group/evidencebook#46; `served_summary/1` is unchanged. Ported from
  Mesh-LLM/mesh-llm#2506 (Steven's M2). Mesh-LLM/capsules-plugin#39.
- **Service evidence agreements (M4, first part).** With `CAPSULES_AGREEMENT_SPEND_CAP_MSAT` set,
  a requester proposes a session-scoped agreement to a provider on its first exchange with it for
  a model, beside the exchange and never holding it up, on the new private mesh channel
  `x-capsules-agreement/1`. The agreement is the interop
  profile's acceptance record (§11.1). The provider checks the session's Evidence Contract
  (`x-capsules/paid-session@1`), model policy and terms against their digests and accepts. The
  requester signs the §11.1.4 receipt and sends it back. Both sides keep the records, the
  receipt and the documents byte-exact under `agreements/` in the ledger directory. The spend
  cap is an agent-origin assertion, never a spend authorization. With no cap set, nothing
  changes. Citing the agreement in halves and legs, and the coverage labels, follow.
  `evidence-request` is taken at agent-action-capsule's merge of #454 (feature `acceptance`)
  until a release carries it. See `docs/AGREEMENTS.md`. action-state-group/evidencebook#48.
- **`settlement_check` and the Lightning adapter declaration (loop step 6).** The new read-only tool
  checks the Lightning settlement records this node holds for a paid exchange, under
  `adapters/lightning-v0.md`. Each check (object held, invoice join, amount, finality, preimage,
  payee credit) reports `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED` or `INCONCLUSIVE` with its
  method. A `finality` `PASS` is the wallet's own report (`wallet_reported`), not a proof, and
  `preimage` is `NOT_PRESENT` because the host never passes one. Each side of an exchange also gets
  the declared predicate `settled` and one value band, `BTC` with a signed decade. The tool reports
  the disclosed count (distinct settlements by payment hash), and the public-ledger count reads
  `NOT_CHECKED`, since Lightning has none. `adapters/x402-v0.md` re-declares x402 under the same
  five items. The tool seals nothing and contacts nobody. Mesh-LLM/capsules-plugin#57.
- **`doctor` and `join` (loop step 12).** `doctor` lists what this node's evidence is: what is
  self-attested, unwitnessed, unchecked, unbound or not shared, one finding each with
  evidencebook's check names and states (`Book.Doctor`), never a score. With `probe`, it asks the
  node's own responder `checkpoints`, then `history_card/1`, as a stranger, in process, and checks
  that each answer verifies under the key the node's commitment advertises (its own key when it
  serves no commitment yet) and that the node answers under the policy that commitment signs. `join` checks that the node is ready to join:
  the key, the book, the first checkpoint, the commitment served on `commitment/1` and both
  probes, listing what is in place and what is not; it is idempotent. Listing the node is still a
  pull request to the evidence network's commitment list. Neither seals, writes or contacts anything; a fresh node's
  first checkpoint follows its first exchange. The quickstart in INSTALL.md is printed by
  `capsules --print-join-quickstart`, and a test holds the two together.
  Mesh-LLM/capsules-plugin#53.
- **The join switch (`join_network`, off by default).** Turned on in the capsules configuration
  pane, under the statement the evidence network publishes (shown word for word), the node signs
  one `join/1` with its plugin key, exactly as evidence-network/loop's `joins/README.md` defines
  it, with no handle or operator name, and sends it to the network's reporter node over the new
  `join/1` plugin channel. Turned off, it sends a signed `leave/1`. It joins once, and again only
  when the statement, the key or the reporter changes. A join that fails is tried again after
  each of the reporter's waits, then not until the switch changes or the plugin restarts; a leave
  is tried again at the last wait until the reporter takes it. The
  reporter is the node loop's `reporter/reporter.json` names (`CAPSULES_JOIN_REPORTER`
  overrides it); while that is all zeros, as now, nothing is sent. A node that is the reporter
  checks each record as loop's `check_join.py` does and keeps each node's latest join and the
  leave that ends it. `join` now shows under `network` the switch, what the reporter
  acknowledged and what it has not yet. Mesh-LLM/capsules-plugin#53.

## 0.1.5

**Milestone M1: who asks for evidence is proven, and a node gets back the record of the exchange it
asked for** (PRD-SERVICE-EVIDENCE §6, R-7 to R-14). **Upgrade both nodes.** Evidence answers are now
the interop profile's signed envelope, which a node on 0.1.4 cannot read, and anchor pins taken from
0.1.4 no longer reproduce. A node on 0.1.4 also sends unsigned requests, which this version refuses
for records (under every setting) and for `served_summary/1` under the default settings. Checkpoints
and `history_card/1` are still answered to anyone.

**Signing needs a host that announces plugin keys (`plugin_keys.v1`, Mesh-LLM/mesh-llm#2299).** No mesh-llm
release has it yet: it is on mesh-llm main and is expected in 0.79.0. On 0.78.1 or older, this
version's requests go out unsigned, so two upgraded nodes answer each other no record, and with the
default settings no `served_summary/1`. Only `share_standard_history = on` keeps answering unsigned
requests for `served_summary/1`; records need a signed request. The records status
(`requests_signed`) shows which case a node is in.

**Updating from mesh-llm 0.78.x:** upgrade mesh-llm to the release that pins capsules 0.1.5, then
run `mesh-llm plugins install-defaults`. It installs from that release's bundled copy and never
downloads; a node whose `capsules` the operator installed themselves (with `mesh-llm plugins
install`, as INSTALL.md describes, or a `[[plugin]]` `command` or `url`) is left as it is and
installs the 0.1.5 package from INSTALL.md.

### Verified on live hosts, and not

- **T3 and T7 passed at PR commit 3902731, whose code is this release's (later commits changed only
  docs), on a lab host built from mesh-llm main
  (b5ed6bd8) plus Mesh-LLM/mesh-llm#2620, not on a stock release.** The signed counterparty record
  came back verified; a node that signed for itself while stating another node's id got a signed
  refusal, with 0 ledger reads; and T7 answers were the same for the counterparty and a stranger.
- **An earlier run, on 2026-10-22, passed on three nodes built from mesh-llm main (95f9b48),** with
  an earlier plugin build (265ede5) and default settings. It predates Mesh-LLM/capsules#50, so its T7 result (a
  signed `policy_declined` for checkpoints and `history_card/1`) no longer describes this version.
- **Not run on a stock mesh-llm release.** No release has `plugin_keys.v1` yet (see above), so a
  stock 0.78.1 host cannot run T3.
- **A referee verdict on live hosts,** which 0.1.4 said would wait on 0.1.5, has still not run. It is
  covered by tests only.
- **Exchange corroboration and the payer's delivered leg for a deposit-covered bill** are covered by
  tests only. Matching both halves of a host-served exchange by client nonce also needs the host to
  pass the nonce on its served terminal event (Mesh-LLM/mesh-llm#2536, on mesh-llm main and in no
  release yet).

### Changed

- **Strangers get no record under `share_history_segments = peers`, and nobody gets an underived
  range or full history.** Under `peers`, a record now goes only to a node whose signature proves
  it, on both `evidence-request/1` and `ledger-fetch/1`. An unsigned request, or one signed by a key
  no host binds, is refused `not_authorized` before the ledger is read, for every subject that
  carries records (`record`, `correlation`, `exchange`, and a fetch by id). Under `peers`, an
  unsigned "Ask them for their record" was answered before and is refused now: the asking node's
  host must announce its key. A `range` or `full_history`
  subject with no derivation is refused `not_authorized` under every setting, to every asker,
  including a counterparty that every record in it names. Checkpoints, `history_card/1`, Standard
  History and `exchange_corroboration/1` are unchanged. This applies evidencebook#114's ruling to
  the plugin.

- **Strangers no longer crowd counterparties out of the evidence answer cap.** A node answers at
  most 8 evidence requests at once from requesters whose signature proves a node, and at most 2
  at once from anyone else (unsigned, or signed by a key no host binds). Each group has its own
  pool, so a full stranger pool declines only strangers, with the same signed `policy_declined`
  as before.

- **A record of an exchange this node served for a peer now names the peer that asked, so that peer
  gets its record back. Operators on `share_history_segments = peers`: your records now show which
  node asked.** mesh-llm reports the node that asked for a host-served exchange
  (`requested_by_node_id`, from the mesh connection, never from the request), but the plugin
  sealed `requesting_party: "unknown"`, so under the default `counterparties` no node could get the
  record of an exchange it asked for.
  - **Now, under the default settings,** the node that asked is that record's counterparty: it gets
    the record (by evidence request or ledger fetch), and it counts as a counterparty for Standard
    History (`served_summary/1`).
  - **Behaviour change under `peers`,** which already serves records to any peer: those records now
    also say which node asked. Nothing named the asker before, so this changes what a node on
    `peers` shares without any setting changing.
  - A node that signs for itself while stating another node's id is still refused `not_authorized`
    before anything is looked up. A record of an exchange this node asked for, one that reached its
    local API, or one from a host that does not report the field still names `"unknown"`.

- **An evidence answer is now the interop profile's signed envelope. Upgrade both nodes.** The
  protocol crate is `evidence-request` `=0.2.0` (what `capsule-emit-evidence-request` became when it
  moved to agent-action-capsule), which signs and checks the envelope of agent-action-capsule's
  `spec/interop-profile-v0.md` §6.2 (`evidence-interop/0`), as the Go, Python and evidencebook
  implementations do. Before, the answer was a pre-profile `{artifact, material, envelope}` that
  no other implementation signed. A node on an older version cannot read the new answer, and this
  node cannot read the old one.
  - **What an anchor is.** A checkpoint is pinned by the SHA-256 of its COSE wire statement (the
    `checkpoint_cose` the checkpointer already writes beside each checkpoint), not by the digest of
    its JSON form. A checkpoint line without its own statement ends the evidence chain there, as
    any checkpoint the index cannot take does: nothing after it is served.
  - **Earlier digests and pins no longer reproduce.** The artifact octets and the anchor both
    changed, so every `artifact_digest` and every anchor pin taken from an earlier version stops
    reproducing. An old anchor names none of this node's checkpoints, so a request pinned to one,
    which would otherwise have been answered, is refused `coverage_unsatisfiable`.
  - **A record answer** is now the record's ledger line itself, with the profile's Checkpointed
    Local Log material for its `capsule_id` (the anchor's statement, the inclusion proof, and the
    consistency proof when the checkpoint extends another). The line is not the `capsule_id`
    preimage, so a profile verifier reports that check `NOT_CHECKED`, never `FAIL`; this node's
    requester recomputes the `capsule_id` and checks the proofs, and also accepts a record served as
    its own octets, which the profile's check passes. The line keeps the producer's signature, which
    the page's "Ask them for their record" checks. The page reads the artifact as the profile
    carries it, unpadded base64url. Before, a record answer was the canonical JSON (RFC 8785) of
    `{anchor, evidence_stream, records, subject}`.
  - **The other answers** take evidencebook's artifact forms (record sets, the checkpoint list,
    `history_card/1`) and `served_summary/1` the same shape. The profile has no material for them
    and no carrier for witness receipts, so this node also sends, where a profile verifier reads
    nothing: the anchor's statement and one inclusion proof per record for a record set, and the
    witness receipts of the checkpoints it carries in a `witness_receipts` member beside the
    envelope. The requester checks all of it as before.
  - The builder stays in the plugin (`evidence_artifact`): evidencebook's builder works over its
    own `CllSubstrate`, which would open the node store the checkpointer owns.
  - A `served_summary/1` answer's verification now reports `records: []`, like every other
    answer, not `0`.
- **`capsule-emit` 0.0.8 and `checkpointed-local-log` 0.3.1**, one CLL line in the build, and no
  `evidencebook`. capsule-emit 0.0.8 turns on `serde_json`'s `arbitrary_precision` for the whole
  binary; the strict parser for pushed bodies (`strict_json`) now reads numbers in that form, still
  refuses a float that overflows, and refuses a key that spells `serde_json`'s private number
  token.
- **The evidence-request parity run is judged by agent-action-capsule's vectors.** The
  self-generated corpus and golden answers are gone from `vectors/parity/evidence_request/`; the
  draft's conformance vectors are copied into `vectors/aac-evidence-request/` (tag
  `crates/evidence-request-v0.2.0`), and the responder and requester are run against them. The
  sharing-policy cases, which no vector states, keep their reviewed expected answers in the
  runner.
- **Who asks for evidence is now proven, not stated. Upgrade both nodes.** Each evidence request
  this node sends is signed with the key its host announces for it. The request carries
  `requester_auth` (`key_id`, `sig`), an `audience` (the node it is sent to), a `nonce` and a
  `deadline`.
  - **Before it looks anything up, a node answering checks:**
    - the signature;
    - that the request is addressed to it;
    - that the nonce is new;
    - that a host announced the key for the node the request comes from.
  - Records and `served_summary/1` are then answered only to that node. The id a request states is
    no longer trusted; if several nodes announced the same key, it picks between them.
  - **Refused:**
    - a request stating one node's id while signed by another;
    - a request addressed to another node, so a node cannot forward a request it received and
      read the answer;
    - a replayed nonce;
    - a deadline more than 5 minutes ahead.
  - **An unsigned request now gets a signed refusal wherever the answer depends on who asks:**
    `not_authorized` for a record, `policy_declined` for `served_summary/1`. It never gets
    silence.
  - **One setting still answers unsigned requests:** `share_standard_history = on`, for
    `served_summary/1`. Under it, a valid signature under a key no host announced is answered as an
    unsigned request, and nothing more. Any other failed check is still refused. No setting answers
    an unsigned request for a record.
  - **A node on 0.1.4 or older sends unsigned requests,** so after you upgrade, its requests for
    your records or `served_summary/1` are refused until it upgrades too.
  - **A node signs only once its host has taken its key.** On a host without `plugin_keys.v1` its
    requests go out unsigned, so an upgraded node no longer answers it any record, and with the
    default settings no `served_summary/1`.
  - **A node that no record names is refused a record before the subject is looked up,** with the
    same refusal for any subject, so the refusal no longer shows how large the log is.
  - **The replay check is held in memory,** so a restart forgets it: a request can be repeated to
    the same node, before its deadline, across a restart.
  - **Keys no host announced share one replay pool** of 16,384 nonces, each held until its
    deadline, and their replay check is best-effort. While the pool is full of live nonces, their
    signed requests are answered as unsigned requests would be, not refused, and logged as
    `replay` `unchecked`; a replay that is detected is still refused. Keys a host announced each
    have their own room, and their replays are always refused.
  - **The "asked of you" log records each request's digest,** the key and node it was proven to
    come from (or `unbound`), the audience it named, and whether its nonce was checked for
    replay.
- **Fetching a record by id (`ledger-fetch/1`) is proven the same way.** The asker signs the
  fetch, and the node answering checks it before it looks the record up. Unless records go to
  any peer (`peers`), a record goes only to the node the signature proves, never to the id the
  fetch states. Under the default
  `share_history_segments` an unsigned fetch, from a node on 0.1.4 or older, is now refused
  `not_authorized`, and so is one under `peers` (see the entry on strangers under `peers`). With
  sharing `off`, a fetch is refused
  before the lookup, so the refusal no longer shows whether the record exists.
- **A referee checks the signature on an `adjudicate` request** before it reads anything. A
  request addressed to another node, changed after signing, past its deadline or replayed is
  refused `not_authorized`. A verdict does not depend on who asks, so an unsigned request is
  answered as before.
- **Each kind of signed request has its own domain tag:** `ledger-fetch/1/requester-auth` for a
  fetch and `referee-adjudicate/1/requester-auth` for an `adjudicate` request, so a signature
  made for one is refused on any other, even where its body would be read there. An evidence
  request's tag is unchanged (`evidence-request/1/requester-auth`).
- **The records status (`evidence_records_status`) says whether this node's requests are
  signed** (`requests_signed`). They are not when its host refused its key or lacks
  `plugin_keys.v1`; its requests then go out unsigned.
- **Standard History is no longer answered to every node that asks; checkpoints and
  `history_card/1` are.** Checkpoints and `history_card/1` are answered to any requester, signed or
  not (Mesh-LLM/capsules#50); `share_standard_history` now governs only `served_summary/1` and other derivations.
  With record push and the checkpoint cadence on, checkpoint times can show when exchanges ended.
  `served_summary/1` goes only to a counterparty (a node one of its records names as the other side
  of an exchange); every other node gets a signed `policy_declined` that carries nothing about the
  asker: it is signed over the request's digest, the reason and the time, so the same request gets
  the same refusal whoever sends it. Before 0.1.5 any node could read it. **After upgrading, a node
  you have never exchanged with can no longer read your served summary** until you set the new
  `share_standard_history` switch to `on` (console: Sharing policy › Standard history; or
  `CAPSULES_SHARE_STANDARD_HISTORY=on`). Your records are unaffected: they stay under
  `share_history_segments`. A counterparty is the node a signed request proves it came from
  (see above).
- **`share_history_segments` defaults to `counterparties`.** `prospective`, the old default, is
  deprecated and read as `counterparties`: it always served exactly the same nodes, so nothing
  changes for a node using it. A log line says when it is read. Set `counterparties` instead.
- **Evidence requests use `capsule-emit-evidence-request` 0.0.4 (was 0.0.3), and witness receipts
  are checked by `scitt-cose-receipt` 0.1.1 from crates.io instead of a git pin.** 0.0.4 changes
  only how a request sent as CBOR is read. This plugin reads requests as JSON, so its answers do not
  change. The receipt check now tries every well-formed inclusion proof in a receipt, not only the
  first, so a receipt that was refused only because of the order of its proofs can now count as
  witnessed on the Evidence page. A proof with an impossible tree size, index or path is refused
  as malformed before any is tried.

### Added

- **Exchange corroboration (`exchange_corroboration/1`), behind a new switch that is off by
  default.** A node can ask whether this node holds a half of one earlier exchange, named by the
  SHA-256 of its client nonce. The answer carries each matching half's id, role and two digests,
  never the record or who was on the other side, and is the same for every node it is given to.
  The new `historical_reference` operation uses it to compare two nodes' halves of one exchange.
  `share_exchange_corroboration` (`CAPSULES_SHARE_EXCHANGE_CORROBORATION`) releases it to a node
  no record names as a counterparty; turning on Standard History does not. See
  `docs/SHARING-POLICY.md`.
- **Witness receipts on an answer are checked under the witness keys you configured:** when this
  node asks another for evidence, each witness receipt carried on the answer's checkpoints is
  checked under the key set for that witness's URL in `CAPSULES_CHECKPOINT_WITNESS_KEYS` (URLs
  matched as for your own checkpoints; only keys you set, not keys pinned on first contact). A
  receipt that does not verify under its witness's key makes the answer not evidence, with reason
  `witness_receipt_unverified`. Receipts on a `served_summary/1` answer are not checked yet. With
  keys set, the result also says how many receipts were verified and each receipt's status. A
  key set for one witness is never used for another. With no keys set, nothing changes: receipts
  are checked for form and for the checkpoint they are on, and none counts as witnessed.
- **`advertise_evidence_requests`, off by default.** Whether this node tells other nodes that it
  answers evidence requests. This version advertises nothing, so nothing reads it yet. A node
  with it off still answers a node that asks.
- The plugin's records status (`sharing`) reports both new switches. The Evidence page does not
  show them yet.
- **A TDX quote in the record, on a TDX host:** when the plugin can take a quote (the kernel's
  configfs-tsm report interface, writable by the plugin's user), each record's `tee_attestation`
  slot carries the quote, its SHA-256 and the 64-byte REPORT_DATA. REPORT_DATA is
  `SHA-512("x-mesh-poc-v1/tee-binding/v1" || 0x00 || request digest || answer digest ||
  SHA-256(client nonce) || the record's signing key)`, each input 32 bytes, the nonce hashed
  exactly as recorded. A quote is taken only for a real client nonce (a host-forwarded one or one
  the client sent to capsules' own `/v1`), never for a placeholder; otherwise the slot says "no
  client nonce". The context says the quote is bound to the exchange's nonce, and fresh against
  the client's challenge only when the record shows the client chose that nonce. A host whose report interface is not TDX, or not usable by the
  plugin's user, records the slot empty exactly as before (the latter is said once in the log).
- **What the node checks before it calls a quote bound, all offline:** the quote's SHA-256; that
  it parses as a TDX DCAP v4 quote; that its REPORT_DATA is the one recomputed from the record; that
  the bound key signs the record; the quote's signature by its attestation key; the QE report's
  signature by the PCK key; that the QE report binds the attestation key; and the PCK certificate
  chain to the Intel SGX Root CA, pinned in the code by its SHA-256, at the record's own time. Any
  failure shows as failed. The Evidence page then says "Quote signed by a TDX quoting enclave and
  bound to this exchange (checked here)", and on its own line that platform status, revocation and
  measurements are not checked here. The checks use `p256` 0.13 (ECDSA P-256) and `x509-cert` 0.2.
- **Each node's key is announced by capsules itself:** on a host that lists `plugin_keys.v1`,
  capsules asks the host at start to announce the public key its records are signed with, so a
  peer verifies this node's pushed records without `CAPSULES_PEER_KEYS` naming it. On an older
  host nothing is sent, and the log says the key was not announced. `CAPSULES_PEER_KEYS` stays the fallback; a peer
  the two sources give different keys still verifies nothing until the stale entry is removed.
- **Built against mesh-llm-plugin from mesh-llm main (a39211e),** which has the announce call;
  no published release has it yet.

### Fixed

- **A paid exchange's CLOSED row no longer reads "served by: not recorded" on the payer's
  Evidence page when the payer's own record names the provider.** The row read the node id the
  page is sent only while the other side's record is still to be fetched, so once that record was
  held the row lost it. It now reads the payer's own record (`served_by_node_id`, the same rule the
  plugin uses), and says "not recorded" only when the record names no server.
- **A half from a model served by a Hugging Face reference is no longer refused `model_mismatch`.**
  The digest inside a `local-gguf/sha256-…` model id is the file's own SHA-256 only for a single
  local file. For a Hugging Face GGUF it hashes the repository, revision and file list, so it was
  read as a second, different weights claim. Weights fields are now held to weights fields and
  model ids to model ids. A half whose two weights fields disagree, or that names another model id
  than the one asked for, is still refused, and the Evidence page applies the same rule.
- **Two providers that gave the same answer to one request are no longer crossed.** Their halves
  were paired by answer alone, so when one provider's half arrived first it could close the record
  of the other, and both exchanges showed as open. A half now first closes the record of its own
  serving node, and the result is the same whatever order the halves arrive in.
- **A ledger fetch reads at most 1 MiB each way.** The node answering read a whole request into
  memory before checking it, and the node asking read a whole answer. An oversized request is now
  dropped unanswered, and an oversized answer is an error.
- **A start that stopped while moving the ledger to a new history finishes the same move next
  time.** It used to pick the next archive slot and seal `history_started` with the wrong archive
  path and a prior record count of zero.
- **A `served_summary/1` answer no longer changes as the log grows past its checkpoint.**
  `adjudications_received` counted every verdict in the log, and took a record as this node's own
  wherever it sat, so a verdict appended after the newest checkpoint changed the summary answered
  for that checkpoint. It now counts only verdicts the checkpoint covers that name a record it
  covers, as the Python reference does. Its note also now reads as the reference's does, so the
  two answer the same bytes.
- **A paid exchange whose deposit covers the bill now gets the payer's delivered settlement leg,**
  citing the deposit invoice (action-state-group/evidencebook#83). The deposit is cited only when
  the bill the host accounted is within it, so a final invoice whose event was lost is never
  replaced by the deposit; that exchange gets no delivered leg.

## 0.1.4

### Verified on live hosts, and not

- **Paid exchanges across two nodes: verified.** Four paid exchanges between two nodes built from
  this release, the requesting node serving no model. In each, the response's `x-mesh-served-by`
  and the record's `served_by` named the serving node, and each node sealed its own half.
- **Peers' keys announced by the host:** exercised only against a test build of the host, not on a
  stock mesh-llm release. `CAPSULES_PEER_KEYS` remains the fallback.
- **The referee with texts the client supplies:** stock hosts now name the node that asked
  (`requested_by_node_id`, from mesh-llm a39211e), so nothing is missing on the host side. A
  referee verdict on live hosts waits on 0.1.5; until then it is covered by tests only.

### Added

- **Each paid exchange on the Evidence page shows what it charged and who paid, from the records
  this node sealed:** the wallet's amount and fee on each settlement (and what it credited, on the
  provider side), the payer's own recorded total, and the provider's delivered-token watermark.
  Each value says who stated it; nothing is summed, and no balance is shown.
- **An exchange this node served for pay shows its own book as the provider,** joined by the
  exchange id the host names a provider's payment events with: who paid, what its wallet reported
  receiving, and what it delivered.
- **"Outcome not reported":** an invoice with no settlement the wallet reported and no final amount
  says so. The host emits no event when a payment's outcome is uncertain or it failed, so the page
  doesn't say which, and never says "unpaid". A paid request refused before any payment (for
  example a payment protocol version the other node doesn't speak) leaves no payment records,
  and the page says that this can happen.
- **Settlement records carry the wallet's `credited_msat` and `fee_msat`** when the host's event
  does; a record from an event without them is unchanged.
- **The referee can take a twin pair's texts from the client** (`referee_supply_twin_texts`: the
  request and both answers), since stock mesh-llm passes no exchange text to plugins. They are
  kept only when the referee is on, the request and each answer are the bodies this node's own
  records sealed, and the answers differ.
- **Peers' keys from the host:** when mesh-llm lists `plugin_keys.v1`, the keys it announces for
  this plugin (`GET /api/plugin-keys`) are merged with `CAPSULES_PEER_KEYS`, which stays the
  fallback. A peer the two give different keys verifies nothing until the stale entry is removed.
- **Twin pairs on Peers:** each peer row states its twin pairs as facts ("Twin pairs: N · answers
  differed: M · not adjudicated"), so a peer whose twin answers differed no longer reads clean
  there.

### Changed

- **The plugin reads and hashes its own executable once per process**, at the first record it
  seals, instead of for every record. Each record still carries that measurement, signed with the
  node key and stamped with the record's own time, so records are unchanged. On macOS the kernel's
  code-signing status is still asked for every record, because it can change while the process
  runs. Replacing the plugin's executable on disk while it runs is measured only after a restart,
  which is also when the new binary starts running.
- **A served exchange with no other side reads LOCAL** ("this node only"), not OPEN, and the state
  filter counts it under "This node only".
- **Each choice setting lists its default first,** so mesh-llm 0.78's console, which does not
  receive declared defaults, shows what the plugin actually does for an unset setting.
- **`capsule-emit-evidence-request` is pinned to `=0.0.3`** from crates.io. An answer to an
  evidence request this node sent is now refused when a witness receipt it carries is malformed or
  not bound to its checkpoint, or when an exchange answer's anchor is not the earliest checkpoint
  covering it. This node holds no witness keys for this check, so no receipt in an answer is
  counted as witnessed. 0.0.3 also signs a refusal over a deterministic encoding, so a refusal
  from a 0.1.3 node may not verify on 0.1.4: upgrade both nodes.

### Fixed

- **The console's top navigation stays on the Evidence page.** The page's stylesheet applies only
  to the page's own elements; a global `.hidden` rule had hidden the console's nav.
- **An exchange this node served for pay is not shown as local.** With no payer recorded, its row
  read "Local — no other side"; it now reads "Served for pay — payer not recorded" and counts as
  open. With no payer recorded there is no node to ask for its record, so such a row may stay open
  until the payer sends its own, and its (i) says so.

## 0.1.3

### Changed

- **Nothing reaches a peer on its own by default.** `share_record_at_completion` (push this node's
  record to the counterparty), `share_adjudications` (deliver verdicts) and
  `adjudicate_differing_twins` (ask a referee, which sends the twins' request to a third node) are
  **off by default**; each turns on only on its explicit value. Answering a peer that asks for a
  record (`share_history_segments`) is unchanged.
- **The stop-routing rule asks the host through the plugin protocol** (`PeerBlockRequest`), so the
  host records the block as this plugin's and refuses it unless the operator set
  `allow_peer_blocks = true` for this plugin. The plugin no longer calls the console's
  `/api/peer-blocks` route (as the operator) for this or for choosing a referee; it learns blocks
  from the host's `routing.choice.v1` publications, and seals its own record of a rule block.
- **The twin pair says what happened:** "A client marked these two requests as one pair", not that
  a comparison ran automatically.
- **Renamed to `capsules`** (plugin id, repository `Mesh-LLM/capsules`, release assets
  `capsules-<version>-<target>.tar.gz`, page `/plugins/capsules/evidence`). Settings are
  `CAPSULES_*`; the old `CAPSULE_EMIT_MESH_*` names are read for this release, with a warning. The
  `ADMISSION_POLICY_*` names are no longer read.
- **An upgraded node keeps its data directory in place** under the old name
  (`capsule-emit-mesh`); nothing is moved, so an upgrade never races a writer that is still
  running. A node with both directories refuses to start and says why. Existing logs keep their
  log id. On Linux the plugin refuses a log another process has open.

### Added

- **A list of witnesses.** The console's `witness` setting is a list of `{ endpoint, public_key }`
  rows, the key optional (the environment's `CAPSULES_CHECKPOINT_WITNESS_URLS` stays a comma list,
  with keys in `CAPSULES_CHECKPOINT_WITNESS_KEYS`, a JSON object from URL to key). There is still no default witness, and no
  witness is contacted until one is named. The Evidence page lists each witness by name with what
  it holds.
- **Receipts are checked before they count.** A witness's receipt counts only when it verifies
  offline: the entry recomputed from the checkpoint's signed fields, and the receipt's inclusion
  proof and signature under the witness's key: the one configured, else one fetched once from that
  witness and kept, which the page labels "pinned on first contact, not configured". An
  unchecked or failing receipt is shown, with the reason, and never counted. A witness that does
  not hold the latest checkpoint (or whose receipt for it does not check) says why: timed out,
  refused, an HTTP error, or a different key.
- **The Evidence page can be a primary tab** (mesh-llm 0.78 and later). The page asks for primary
  placement; the operator turns it on in the console's plugin settings ("Primary tab"), and with it
  off the page stays a navigation item. The page draws its own header, so the host's header is
  turned off for it.
- **Under a chat answer and in the Logs request inspector** (mesh-llm 0.78 and later): whether
  this node sealed that exchange, with a link to its record on the Evidence page. The lookup is
  local (`GET /lookup?exchange_id=` or `?client_nonce=`); nothing is shown when it fails or finds
  no record. It works on the node that asked a peer for the answer. For an exchange this node
  served itself, mesh-llm 0.78 does not give the plugin the ids those views hold, so nothing is
  shown there. On mesh-llm 0.77 the plugin installs and runs as before, without these.

### Fixed

- **The log of requests made of this node never stops the plugin starting.** It is written only to
  a directory that exists when the plugin starts (`CAPSULES_RECEIVED_LOG_DIR`, else
  `<data dir>/received-log`) and that this process holds a lock on; never the ledger directory. A
  directory another node holds, or one that cannot be locked, turns that log off for the run, with
  a warning.
- **A witness is dialled at the URL given.** With capsule-emit 0.0.4, one public witness URL
  (`https://witness.agentactioncapsule.org`) was sent to a different host
  (`anchor.agentactioncapsule.org`). capsule-emit 0.0.6, now required, dials every witness exactly as configured and
  follows no redirect, and the plugin's own witness reads do the same.
- **Settings saved in the console reach the plugin.** The plugin reads its `[plugin.settings]`
  from mesh-llm's config file (`MESH_LLM_CONFIG`, or `~/.mesh-llm/config.toml`); the environment
  still wins. The console's `witness` is the checkpoint witness, and the witness client uses it.
- **One plugin process per data directory.** A second process on the same directory refuses to
  start instead of interleaving appends and breaking the chain.

## 0.1.2

### Fixed

- **The plugin serves no models unless asked.** 0.1.1 registered an OpenAI-compatible inference
  provider on every node and, with `CAPSULE_EMIT_MESH_BLOCKED_MODELS` unset or empty, advertised
  `blocked-test-model` through it. That model always answers 403, so a client that takes the first
  model `/v1/models` lists, or "Mesh automatic" routing, could pick it. From 0.1.2 the admission
  endpoint is opt-in: only when `CAPSULE_EMIT_MESH_BLOCKED_MODELS` names models does the plugin
  register the provider and declare `admission_policy.v1`. Unset, empty, `none` or `off`: no
  provider, no admission capability, no models. The plugin seals records and serves the Evidence
  page.

## 0.1.1

### Added

- **Settlement-record legs for paid exchanges** (draft-mih-agent-settlement-records-00). For each
  invoice of a paid exchange, both sides now seal the draft's legs beside the existing payment
  lifecycle trail. The payer seals the terms leg (invoice amount, `ln.payment_hash`) and pushes it
  to the serving peer, then seals `payer_observed` (the amount, plus `routing_fee` when the host
  passes the wallet's fee) and a delivered leg with the response digest. The provider seals
  `payee_observed` (`received`, `receive_fee`), citing the payer's terms leg.
  - **Host requirement:** the provider's leg needs a mesh-llm host whose settlement events carry
    the wallet's credited amount and fee (Mesh-LLM/mesh-llm#2169). On a host without it, the
    provider seals no payee leg; the payer's legs and pushed terms work either way.
  - `routing_fee` and `receive_fee` are new on ledger records. Peers may read them back under the
    default share policy, like the amounts the trail already carried.

### Fixed

- **A node-unique default log id.** Every node's checkpoints used the same log id, so a witness
  accepted the first node and refused the rest as a fork. The default is now
  `capsule-emit-mesh/<key id>`, chosen at first start and kept in `<data dir>/log_id`;
  `CAPSULE_EMIT_MESH_LOG_ID` overrides it. A log that already holds checkpoints keeps its id, and
  starting a new log moves the node to its own id (see INSTALL.md, "The log's id").
- **Finding a served half by its digests.** When the host forwarded no nonce, the serving node's
  half couldn't be found by the requester's nonce, so the exchange showed as open. The responder
  now also indexes each record by its exchange's two effect digests, and the page asks by those
  after a signed "no such record". Both nodes need 0.1.1 for this.
- **The witness indicator.** The Evidence page could say "witness off" on a node whose checkpoints
  carried witness receipts. It now reads how many checkpoints a witness holds and whether a
  witness is configured, and says "off" only when no witness is set.

## 0.1.0

- First release.
