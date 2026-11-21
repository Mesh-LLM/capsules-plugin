# Evidence request conformance vectors (draft-mih-agent-evidence-request-00 to -03)

Conformance vectors for the evidence request interaction defined in
`spec/draft-mih-agent-evidence-request-00.md`,
`spec/draft-mih-agent-evidence-request-01.md`,
`spec/draft-mih-agent-evidence-request-02.md` and
`spec/draft-mih-agent-evidence-request-03.md`: the request map, the six subject
forms, which record members carry a correlation identifier or cite an exchange
half, coverage, the request digest, the signed refusal, the three outcomes and
the pending state, caller invariance, retention commitments, the `categories`
request field, A2A and MCP carriage, unavailable-window statements, the
two refusal reasons -02 adds, and -03's `history_card/2` and
`checkpoint_range` subject.

Each corpus names the revision it is written from in its `draft` member.
`carries.json`, `categories.json` and `carriage.json` follow text that first
appears in -01, and name -01; `unavailable-window.json` and `refusal-02.json`
follow text that first appears in -02, and name -02; `history-card-2.json` and
`checkpoints-range.json` follow text that first appears in -03, and name -03; every other corpus
names -00, and every -00, -01 and -02 case also holds under -03. Section numbers below are those of the revision the
corpus names.

**Derived from the draft text, not from any implementation.** Every expected
result is written by hand in the generator from the section it cites. The
generator only encodes inputs, hashes them and signs the refusal and statement
cases; it runs
no responder or verifier. Every case is marked `"provenance": "spec-derived"`.
Where -00 leaves a choice open, the case carries an `ambiguity` note with the
section and the reading used (the most literal one); the list is below, for -01.

## Files

| File | What it pins |
|---|---|
| `registry.json` | The exact strings -00 fixes: request fields and their presence, the six subject forms, the two coverage members, the eight refusal reasons, the `history_card/1` derivation, the three outcomes, the pending state, the `evidence-request/1` subprotocol identifier. |
| `request.json` | Request map validation. Each case gives the request as JSON (RFC 8785 text, `request_json`) and, where it is a CBOR value, as a deterministic CBOR frame (`request_cbor_hex`), with the SHA-256 of each. Expect `well_formed: true`, or `false` with the exact refusal reason. |
| `resolution.json` | Exact-match resolution against one declared responder state (`responder`, with per-case `responder_overrides`). Expect `artifact` or a refusal with the most specific reason (§4.2). |
| `categories.json` | The OPTIONAL `categories` request field (-01 §3.9). `kind` `request` cases are request maps as in `request.json`; expect `well_formed: true`, or `false` with `request_malformed`. `kind` `invariance` cases are observations as in `invariance.json`, with `categories` in each request: categories is an input of the artifact when honored (-01 §5). |
| `carriage.json` | A2A and MCP carriage (-01 §10.1-§10.3) and the envelope's request digest (-01 §4.1). `kind` `digest`: decode `carried_text` as the `carriage` writes bytes (A2A: base64 with padding; MCP: base64url without padding); `candidate_digest` is the request digest only if it is SHA-256 over the decoded octets. `kind` `binding`: an envelope answers the request only if `envelope_request_digest` is SHA-256 of `retained_request_hex`. `kind` `media_type`: exact-string comparison. `kind` `classify`: what the requester received, classified by the reply alone. |
| `carries.json` | Which members of a record carry a correlation identifier or cite an exchange half (§3.1.1): a positive and a negative case per subject form, plus a `counterparty_half` entry naming another half. Each case gives `record_format`, the `record` reduced to the members the designation reads, and the `subject`. Expect `carries` (correlation) or `cites` (exchange), true or false. |
| `digest.json` | The request digest is over the bytes as received (§4.2 item 1): JSON and CBOR, deterministic and not, and a refusal carrying the digest of a re-canonicalized form. |
| `refusal.json` | Signed refusals: one per registered reason, a CBOR response frame, tampering, and objects that are signed but not conforming. Carries the signature profile and both fixed keys (seed and public key). |
| `refusal-imported.json` | An existing cross-implementation refusal vector, byte for byte (SHA-256 `885d7981…a66e`). It conforms to -00: a request digest, a registered reason, an issuance time, and a signature over all three. |
| `outcomes.json` | The three outcomes and pending, as facts in and one state out, with the states each case must never be recorded as (§4.5). |
| `invariance.json` | Caller invariance (§5): observations of the same subject under the same anchor must carry byte-identical artifacts. |
| `retention.json` | Retention commitments (§9): every reason inside and after `until`, absence with and without a commitment, and which subject forms a commitment may name. |
| `unavailable-window.json` | Unavailable-window statements (-02 §4.7). `kind` `statement`: whether a reader recognizes the statement (well formed, signed by `responder_key`, registered) and its registration time, the earliest of its `receipts` marked `accepted` (from a transparency service the reader accepts as independent of the responder). `kind` `display`: an absence (`sent_at` to `closed_at`) and statements; expect the ids of the statements that cover it, `shown_as`, and per covering statement its `reason_class`, `stated_period`, registration time and `stated_afterwards`. `must_not_show_as` lists what the reader must never show. Statements are signed with the primary key of `refusal.json` under the profile in the file. |
| `refusal-02.json` | The two refusal reasons -02 adds (§4.2, §13): `capacity_exceeded` and `request_unauthenticated`. `refusal_reasons` is the -02 registry; `registry.json` stays the -00 one, under which both are unregistered. A case with `refusal` checks the signature (profile of `refusal.json`) and registration against `refusal_reasons`; one with `facts.commitment` is the retention classification (§9); `facts.cause` is the reason load shedding uses (§11, §3.4); `facts.refusal_reason` alone is the illustrative status mapping (§4.6). |
| `history-card-2.json` | `history_card/2` (-03 §8.1.2) in Checkpointed Local Log form. `positions`: P(n, W) for each `n` and `window`. `cases`: a `card`, the `anchor` the response resolved (SHA-256 of the anchor checkpoint's octets) and the corpus's `log_keys`; expect `valid`, or the first `finding` in `findings` order. `notes` fixes each check, the receipt form (for these vectors only) and the unit of `log_size` (MMR nodes). The stream is 1,100 checkpoints, so the valid card spans more than 1,024. |
| `checkpoints-range.json` | The `checkpoint_range` subject (-03 §3.1, §8.1.3), the content-free `checkpoints` subject beside it, and `history_card/2` resolution. `request_cases` are request maps as in `request.json`; `cases` resolve against `responder`, whose `anchors` are its checkpoints in issue order, at the `checkpoint_positions` given. `derivations` is the -03 derivation registry. |
| `manifest.json` | SHA-256 and case count of every generated file, and the ambiguity list. |
| `SHA256SUMS` | SHA-256 of every file in this directory except itself. |
| `DIFFS.md` | Known differences between one existing Python responder and -00. |

## Conventions

- Digests are SHA-256, 64 lowercase hex characters, as text in both bindings
  (**A2**).
- A subject is a map with one member named by the form token (**A1**):
  `{"full_history": null}`, `{"checkpoints": null}`, `{"record": <digest>}`,
  `{"range": [a, b]}`, `{"correlation": "<id>"}`, `{"exchange": <digest>}`.
- Coverage is `{"expected_pin": <digest>}` or `{"min_freshness": <size or time>}`
  (**A3**).
- Refusals use the signature profile in `refusal.json` (**A7**): Ed25519 over
  the RFC 8785 serialization of `{issued_at, reason, request_digest}`, with
  `key_id` (raw public key) and `sig` in lowercase hex. The keys are derived
  from fixed seeds, so every signature is reproducible.
- `issued_at`, `deadline` and `min_freshness` times are RFC 3339 UTC strings
  (**A5**).
- Resolution cases expect the most specific reason (§4.2). The one case with a
  uniform `policy_declined` posture (§4.2, §12) says so in `responder_overrides`.

## How to consume them

1. Check the pinned hashes first: `sha256sum -c SHA256SUMS` in this directory,
   or compare each file with `manifest.json`. A copy vendored into another
   repository should be checked against this `SHA256SUMS` in its CI.
2. `request.json`: feed `request_json` (UTF-8 bytes) to a JSON-binding parser,
   and the bytes of `request_cbor_hex` to a CBOR-binding parser. Both must give
   the expected result. The digest of the bytes fed must equal
   `request_json_digest` / `request_cbor_digest`.
3. `resolution.json`: load `responder` (plus any `responder_overrides`) as the
   responder's holdings, and check the answer's form and reason.
4. `carries.json`: read `record` under the designation §3.1.1 gives its
   `record_format`, and check whether it carries the `correlation` identifier,
   or cites the `exchange` half. The answer must equal `expect`. A requester
   that does not implement the format treats the record as unchecked, never as
   not carrying (§3.1.1).
5. `refusal.json`: verify each `refusal` object (or the `file`) offline.
   `expect.signature` is the signature check alone, `expect.reason_registered`
   the registry check alone, and `expect.conformant` both plus the presence and
   form of every member §4.2 requires. Keep the two checks separate: a valid
   signature over an unregistered token is still the responder's signed act.
6. `outcomes.json`: map `facts` to a state; it must equal `expect.state` and
   must not be any of `expect.must_not_record_as`.
7. `invariance.json`: for observations with the same `resolved_anchor`, the
   `artifact_hex` values must be identical. Differing verification material is
   allowed. Different anchors are `not_comparable`.
8. `retention.json`: classify each `facts` pair, and check each `commitment` for
   well-formedness.
9. `categories.json`: feed `request` cases as in step 2, and check
   `invariance` cases as in step 7.
10. `carriage.json`: check each case by its `kind` (table above). A
   `classify` result must equal `expect.classified_as` and must not be any of
   `expect.must_not_classify_as`.
11. `unavailable-window.json`: for a `statement` case, recognize the
   statement against `responder_key` and its `receipts` marked `accepted`; for a
   `display` case, find the covering statements, show the absence, and check
   each label. The result must equal `expect` and must not be any of
   `expect.must_not_show_as`.
12. `refusal-02.json`: verify each `refusal` case as in step 5, but against
   the corpus's own `refusal_reasons`; classify each `facts.commitment` case
   as in step 8; the other cases state what the -02 text requires.
13. `history-card-2.json`: compute P(n, W) for each `positions` row, and
   check each card against its `anchor` and `log_keys`. The result must be
   `expect.valid`, and on failure exactly `expect.finding`.
14. `checkpoints-range.json`: feed `request_cases` as in step 2 and resolve
   `cases` as in step 3 against the corpus's `responder`.

Regenerate from the repository root with
`python3 python/scripts/generate_evidence_request_vectors.py`. The output is a
pure function of that script (no clock, no randomness);
`python/tests/test_evidence_request_vectors.py` re-runs it and requires
byte-identical files. `README.md` and `DIFFS.md` are hand-written; the
generator hashes them into `SHA256SUMS` but never rewrites them.

## Cases

### `request.json` (33 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `pos-subject-full_history` | 3, 3.1, 3.2 | well formed | A1 |
| `pos-subject-checkpoints` | 3, 3.1, 3.2 | well formed | A1 |
| `pos-subject-record` | 3, 3.1, 3.2 | well formed | A1 |
| `pos-subject-range` | 3, 3.1, 3.2 | well formed | A1, A3 |
| `pos-subject-correlation` | 3, 3.1, 3.2 | well formed | A1, A3 |
| `pos-subject-exchange` | 3, 3.1, 3.2, 6 | well formed | A1 |
| `pos-nonce-absent` | 3, 3.5 | well formed |  |
| `pos-all-optional-fields` | 3, 3.3, 3.4, 3.5, 3.6 | well formed | A5 |
| `pos-unknown-field-ignored` | 3 | well formed |  |
| `pos-derivation-history-card` | 3.3, 8.1, 13 | well formed |  |
| `pos-derivation-by-digest` | 3.3 | well formed | A14 |
| `neg-not-a-map` | 3 | refuse `request_malformed` |  |
| `neg-not-well-formed` | 3 | refuse `request_malformed` |  |
| `neg-subject-missing` | 3 | refuse `request_malformed` |  |
| `neg-subject-unknown-form` | 3, 3.1 | refuse `request_malformed` | A1 |
| `neg-subject-two-forms` | 3, 3.1 | refuse `request_malformed` | A1 |
| `neg-subject-kind-member` | 3, 3.1 | refuse `request_malformed` | A1 |
| `neg-subject-none-form-with-content` | 3, 3.1 | refuse `request_malformed` | A1 |
| `neg-record-digest-malformed` | 3, 3.1 | refuse `request_malformed` | A2 |
| `neg-record-digest-prefix` | 3, 3.1 | refuse `request_malformed` | A2 |
| `neg-range-reversed` | 3, 3.1 | refuse `request_malformed` | A6 |
| `neg-range-not-a-pair` | 3, 3.1 | refuse `request_malformed` | A1 |
| `neg-derivation-not-text` | 3, 3.3 | refuse `request_malformed` | A14 |
| `neg-expected-pin-malformed-digest` | 3, 3.2 | refuse `request_malformed` | A4 |
| `neg-expected-pin-map` | 3, 3.2 | refuse `request_malformed` | A4 |
| `neg-min-freshness-max-age` | 3, 3.2 | refuse `request_malformed` | A3, A4 |
| `neg-coverage-not-a-map` | 3, 3.2 | refuse `request_malformed` | A4 |
| `neg-coverage-both` | 3, 3.2 | refuse `coverage_unsatisfiable` |  |
| `neg-coverage-neither` | 3, 3.2 | refuse `coverage_unsatisfiable` |  |
| `neg-coverage-missing` | 3, 3.2 | refuse `coverage_unsatisfiable` | A4 |
| `neg-coverage-both-pin-malformed` | 3, 3.2 | refuse `request_malformed` | A4 |
| `neg-coverage-both-freshness-malformed` | 3, 3.2 | refuse `request_malformed` | A3, A4 |
| `neg-coverage-both-both-malformed` | 3, 3.2 | refuse `request_malformed` | A3, A4 |

### `resolution.json` (19 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `res-record-exact` | 3.1 | artifact |  |
| `res-record-not-held` | 3.1, 4.2 | refuse `no_such_subject` |  |
| `res-record-prefix` | 3.1 | refuse `request_malformed` | A2 |
| `res-correlation-exact` | 3.1 | artifact |  |
| `res-correlation-prefix` | 3.1 | refuse `no_such_subject` |  |
| `res-correlation-case-folded` | 3.1 | refuse `no_such_subject` |  |
| `res-exchange-cited` | 3.1, 6 | artifact |  |
| `res-exchange-not-cited` | 3.1, 6 | refuse `no_such_subject` |  |
| `res-range-positional` | 3.1 | artifact |  |
| `res-range-no-positional-ordering` | 3.1 | refuse `coverage_unsatisfiable` |  |
| `res-pin-unknown-anchor` | 3.2 | refuse `coverage_unsatisfiable` |  |
| `res-min-freshness-size-met` | 3.2 | artifact | A3 |
| `res-min-freshness-size-unmet` | 3.2, 12 | refuse `coverage_unsatisfiable` | A3 |
| `res-min-freshness-time-met` | 3.2 | artifact | A3 |
| `res-min-freshness-time-unmet` | 3.2 | refuse `coverage_unsatisfiable` | A3 |
| `res-derivation-unsupported` | 3.3 | refuse `derivation_unsupported` |  |
| `res-derivation-not-for-subject` | 3.3 | refuse `no_such_subject` |  |
| `res-derivation-history-card` | 3.3, 8.1 | artifact |  |
| `res-uniform-policy-declined` | 4.2, 12 | refuse `policy_declined` |  |

### `carries.json` (5 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `carries-correlation-subject-ref` | 3.1.1 | carries |  |
| `carries-correlation-undesignated-member` | 3.1.1 | does not carry |  |
| `cites-exchange-counterparty-half` | 3.1.1 | cites |  |
| `cites-exchange-responds-to` | 3.1.1 | does not cite |  |
| `cites-exchange-counterparty-half-other-digest` | 3.1.1 | does not cite |  |

### `categories.json` (14 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `cat-two-names` | 3.9 | well formed |  |
| `cat-one-name` | 3.9 | well formed |  |
| `cat-names-any-order` | 3.9 | well formed | B2 |
| `neg-cat-not-a-map` | 3.9 | refuse `request_malformed` | B1 |
| `neg-cat-missing-set` | 3.9 | refuse `request_malformed` | B1 |
| `neg-cat-missing-names` | 3.9 | refuse `request_malformed` | B1 |
| `neg-cat-names-empty` | 3.9 | refuse `request_malformed` | B1 |
| `neg-cat-names-duplicate` | 3.9 | refuse `request_malformed` | B1 |
| `neg-cat-names-not-array` | 3.9 | refuse `request_malformed` | B1 |
| `neg-cat-set-not-text` | 3.9 | refuse `request_malformed` | B1 |
| `neg-cat-name-not-text` | 3.9 | refuse `request_malformed` | B1 |
| `cat-inv-same-categories` | 5, 3.9 | holds |  |
| `cat-inv-different-categories-not-comparable` | 5, 3.9 | not_comparable |  |
| `neg-cat-inv-same-categories-divergent` | 5, 3.9 | violated |  |

### `carriage.json` (21 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `carry-a2a-raw-part` | 10.1, 10.2 | is the request digest |  |
| `carry-mcp-request-argument` | 10.1, 10.3 | is the request digest |  |
| `neg-carry-digest-over-text` | 10.1 | is not the request digest |  |
| `neg-carry-digest-over-reencoding` | 10.1 | is not the request digest |  |
| `bind-envelope-answers-own-request` | 4.1 | answers |  |
| `neg-bind-envelope-other-request` | 4.1 | does not answer |  |
| `media-cbor` | 10.1 | accepted |  |
| `media-json` | 10.1 | accepted |  |
| `neg-media-parameter` | 10.1 | not accepted |  |
| `neg-media-case` | 10.1 | not accepted |  |
| `classify-a2a-completed-with-reply` | 10.2 | reply |  |
| `neg-classify-a2a-reply-two-parts` | 10.2 | no_reply |  |
| `neg-classify-a2a-reply-other-media-type` | 10.2, 10.1 | no_reply |  |
| `neg-classify-a2a-reply-text-part` | 10.2 | no_reply |  |
| `neg-classify-a2a-rejected-no-reply` | 10.2, 10.1 | no_reply |  |
| `classify-a2a-working-no-reply` | 10.2, 4.3 | pending |  |
| `classify-a2a-unspecified-no-reply` | 10.2, 4.3 | pending |  |
| `classify-mcp-error-flag-with-reply` | 10.3, 10.1 | reply |  |
| `neg-classify-mcp-reply-other-media-type` | 10.3 | no_reply |  |
| `neg-classify-mcp-reply-not-base64url` | 10.3 | no_reply |  |
| `neg-classify-mcp-error-text-no-reply` | 10.3, 10.1 | no_reply |  |

### `digest.json` (7 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `digest-json-jcs` | 4.2, 3.8 | digest 8f5e0250575f… | A2 |
| `digest-json-as-received` | 4.2 | digest 5d5fd71bef55… | A2 |
| `digest-cbor-deterministic` | 4.2, 3.8, 10 | digest 0a4b2bbcd793… | A2 |
| `digest-cbor-as-received` | 4.2, 10 | digest a6fca795b66e… | A2 |
| `digest-nonce-distinguishes` | 3.5, 4.2 | digest 109c87c4ee97… | A2 |
| `neg-refusal-digest-recanonicalized` | 4.2 | does not identify | A2 |
| `pos-refusal-digest-as-received` | 4.2 | identifies | A2 |

### `refusal.json` (22 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `pos-reason-not_authorized` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-reason-no_such_subject` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-reason-coverage_unsatisfiable` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-reason-derivation_unsupported` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-reason-policy_declined` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-reason-deadline_unmet` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-reason-request_malformed` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-reason-retention_expired` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-imported-interop-vector` | 4.2, 13 | conformant (sig valid) | A7 |
| `pos-cbor-frame` | 4.2, 10 | conformant (sig valid) | A7 |
| `pos-detail-outside-signature` | 4.2, 10 | conformant (sig valid); optional `detail` (profile P-6) outside the signed members, in JSON and CBOR | A7 |
| `neg-tamper-reason` | 4.2 | not conformant (sig invalid) | A7 |
| `neg-tamper-issued_at` | 4.2 | not conformant (sig invalid) | A7 |
| `neg-tamper-request_digest` | 4.2 | not conformant (sig invalid) | A7 |
| `neg-tamper-key_id` | 4.2, 11 | not conformant (sig invalid) | A7 |
| `neg-unsigned` | 4.2 | not conformant (sig invalid) | A7 |
| `neg-unregistered-reason-no_such_record` | 4.2, 13 | not conformant (sig valid) | A13 |
| `neg-reason-recorded_absence` | 4.2, 4.5, 13 | not conformant (sig valid) | A13 |
| `neg-reason-wrong-case` | 4.2, 13 | not conformant (sig valid) | A13 |
| `neg-two-reasons` | 4.2 | not conformant (sig valid) | A13 |
| `neg-missing-issued_at` | 4.2 | not conformant (sig valid) | A7 |
| `neg-malformed-request_digest` | 4.2 | not conformant (sig valid) | A2, A7 |

### `outcomes.json` (13 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `out-artifact-verified` | 4, 4.1, 4.6 | `artifact_verified`; never `refusal`, `recorded_absence`, `pending` |  |
| `out-artifact-verification-failed` | 4.1, 4.5 | `artifact_verification_failed`; never `artifact_verified`, `recorded_absence`, `refusal` |  |
| `out-refusal-signed` | 4.2, 4.5 | `refusal`; never `recorded_absence`, `pending`, `artifact_verified` |  |
| `neg-refusal-as-absence` | 4.5 | `refusal`; never `recorded_absence` |  |
| `out-refusal-over-http` | 10, 4.5 | `refusal`; never `recorded_absence` |  |
| `out-pending` | 4.3, 4.5 | `pending`; never `recorded_absence`, `refusal` |  |
| `out-absence` | 4.4, 4.5 | `recorded_absence`; never `refusal`, `pending` |  |
| `neg-timeout-as-refusal` | 4.5 | `recorded_absence`; never `refusal` |  |
| `neg-transport-error-as-refusal` | 10, 4.5 | `recorded_absence`; never `refusal` |  |
| `out-transport-error-inside-window` | 4.3, 10 | `pending`; never `recorded_absence`, `refusal` | A8 |
| `neg-subprotocol-not-offered` | 10 | `recorded_absence`; never `refusal` |  |
| `neg-commitment-makes-refusal` | 4.4, 4.5, 9 | `recorded_absence`; never `refusal` |  |
| `neg-unregistered-reason-as-absence` | 4.2, 4.5 | `refusal_nonconformant`; never `recorded_absence`, `refusal` | A13 |

### `invariance.json` (6 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `inv-same-pin-byte-identical` | 5, 3.5, 3.6 | holds | A12 |
| `inv-verification-material-may-differ` | 5 | holds | A12 |
| `inv-min-freshness-same-selected-anchor` | 5 | holds | A12 |
| `inv-different-anchor-not-comparable` | 5 | not_comparable | A12 |
| `neg-inv-divergent-artifacts` | 5 | violated | A12 |
| `neg-inv-nondeterministic-serialization` | 5 | violated | A12 |

### `retention.json` (25 cases)

| Case | § | Expect | Ambiguity |
|---|---|---|---|
| `ret-inside-not_authorized` | 9 | no_breach |  |
| `ret-inside-no_such_subject` | 9 | breach |  |
| `ret-inside-coverage_unsatisfiable` | 9 | no_breach |  |
| `ret-inside-derivation_unsupported` | 9 | no_breach |  |
| `ret-inside-policy_declined` | 9 | breach |  |
| `ret-inside-deadline_unmet` | 9 | breach |  |
| `ret-inside-request_malformed` | 9 | no_breach |  |
| `ret-inside-retention_expired` | 9 | breach | A9 |
| `ret-after-not_authorized` | 9, 4.2 | no_breach | A10 |
| `ret-after-no_such_subject` | 9, 4.2 | wrong_token | A10 |
| `ret-after-coverage_unsatisfiable` | 9, 4.2 | no_breach | A10 |
| `ret-after-derivation_unsupported` | 9, 4.2 | no_breach | A10 |
| `ret-after-policy_declined` | 9, 4.2 | no_breach | A10 |
| `ret-after-deadline_unmet` | 9, 4.2 | no_breach | A10 |
| `ret-after-request_malformed` | 9, 4.2 | no_breach | A10 |
| `ret-after-retention_expired` | 9, 4.2 | correct |  |
| `ret-absence-inside` | 9, 4.4 | attributable_absence |  |
| `ret-absence-without-commitment` | 4.4 | attempt_only |  |
| `ret-commitment-subject-record` | 9, 3.1 | well formed | A1 |
| `ret-commitment-subject-exchange` | 9, 3.1 | well formed | A1 |
| `ret-commitment-subject-range` | 9, 3.1 | well formed | A1, A11 |
| `ret-commitment-subject-correlation` | 9, 3.1 | malformed | A1, A11 |
| `ret-commitment-subject-full_history` | 9, 3.1 | malformed | A1, A11 |
| `ret-commitment-subject-checkpoints` | 9, 3.1 | malformed | A1, A11 |
| `ret-commitment-missing-until` | 9 | malformed | A1 |

### `unavailable-window.json` (35 cases)

| Case | Kind | § | Expect |
|---|---|---|---|
| `uw-class-flood` | statement | 4.7 | recognized, registered 10:06 |
| `uw-class-maintenance` | statement | 4.7 | recognized, registered 10:06 |
| `uw-class-outage` | statement | 4.7 | recognized, registered 10:06 |
| `uw-class-other_declared` | statement | 4.7 | recognized, registered 10:06 |
| `uw-neg-class-unlisted` | statement | 4.7 | not recognized (malformed) |
| `uw-neg-class-free-text` | statement | 4.7 | not recognized (malformed) |
| `uw-neg-class-wrong-case` | statement | 4.7 | not recognized (malformed) |
| `uw-neg-class-missing` | statement | 4.7 | not recognized (malformed) |
| `uw-extra-member-not-the-reason` | statement | 4.7 | recognized, registered 10:06 |
| `uw-neg-start-missing` | statement | 4.7 | not recognized (malformed) |
| `uw-neg-end-missing` | statement | 4.7 | not recognized (malformed) |
| `uw-neg-time-unparseable` | statement | 4.7 | not recognized (malformed) |
| `uw-neg-end-before-start` | statement | 4.7 | not recognized (malformed) |
| `uw-end-equals-start` | statement | 4.7 | recognized, registered 10:06 |
| `uw-neg-bad-signature` | statement | 4.7 | not recognized (not_signed_by_responder) |
| `uw-neg-other-key` | statement | 4.7 | not recognized (not_signed_by_responder) |
| `uw-neg-unregistered` | statement | 4.7 | not recognized (not_registered) |
| `uw-neg-receipt-not-accepted` | statement | 4.7 | not recognized (not_registered) |
| `uw-registration-earliest-receipt` | statement | 4.7 | recognized, registered 10:06 |
| `uw-show-stated-before-close` | display | 4.7, 4.4, 4.5, 4.6 | holder states unavailability: flood |
| `uw-show-stated-afterwards` | display | 4.7, 4.4, 4.5, 4.6 | holder states unavailability: outage, stated afterwards |
| `uw-backdated-receipt-not-accepted` | display | 4.7, 4.4, 4.6 | holder states unavailability: outage, stated afterwards |
| `uw-registered-at-close` | display | 4.7, 4.4, 4.6 | holder states unavailability: flood |
| `uw-registered-after-close-by-a-second` | display | 4.7, 4.4, 4.6 | holder states unavailability: flood, stated afterwards |
| `uw-long-period-shown` | display | 4.7, 4.4, 4.6 | holder states unavailability: flood |
| `uw-partial-overlap` | display | 4.7, 4.4, 4.6 | holder states unavailability: maintenance |
| `uw-touching-boundary` | display | 4.7, 4.4, 4.6 | holder states unavailability: outage |
| `uw-no-overlap` | display | 4.7, 4.4 | not covered; shown as recorded_absence |
| `uw-other-key-does-not-cover` | display | 4.7, 4.4 | not covered; shown as recorded_absence |
| `uw-unregistered-does-not-cover` | display | 4.7, 4.4 | not covered; shown as recorded_absence |
| `uw-malformed-does-not-cover` | display | 4.7, 4.4 | not covered; shown as recorded_absence |
| `uw-two-statements-cover` | display | 4.7, 4.4, 4.6 | holder states unavailability: flood; maintenance, stated afterwards |
| `uw-commitment-unchanged` | display | 4.7, 4.4, 9, 4.6 | holder states unavailability: flood |
| `uw-refusal-not-affected` | display | 4.7, 4.5 | not covered; shown as refusal |
| `uw-pending-not-absence` | display | 4.7, 4.3, 4.5 | not covered; shown as pending |

### `refusal-02.json` (11 cases)

| Case | § | Expect |
|---|---|---|
| `r02-reason-capacity_exceeded` | 4.2, 13 | signature valid, registered, conformant |
| `r02-reason-request_unauthenticated` | 4.2, 13 | signature valid, registered, conformant |
| `r02-neg-unregistered-rate_limited` | 4.2, 13 | signature valid, not registered, not conformant |
| `r02-ret-inside-capacity_exceeded` | 9 | no breach |
| `r02-ret-after-capacity_exceeded` | 9 | no breach |
| `r02-ret-inside-request_unauthenticated` | 9 | no breach |
| `r02-ret-after-request_unauthenticated` | 9 | no breach |
| `r02-load-shedding-is-capacity_exceeded` | 11, 4.2 | `capacity_exceeded`, never `policy_declined` or `not_authorized` |
| `r02-deadline-missed-under-load` | 3.4, 11 | `capacity_exceeded`, never `deadline_unmet` |
| `r02-map-capacity_exceeded` | 4.6 | status unknown; not withheld by policy, not evidence of non-satisfaction |
| `r02-map-request_unauthenticated` | 4.6 | status unknown; not withheld by policy, not evidence of non-satisfaction |
### `history-card-2.json` (37 cases)

| Case | Expect |
|---|---|
| `valid-1100-checkpoints` | valid |
| `valid-single-checkpoint` | valid |
| `valid-window-covers-stream` | valid |
| `valid-window-cap` | valid |
| `valid-no-receipts` | valid |
| `valid-profile-members` | valid |
| `malformed-card-not-a-map` | `card_malformed` |
| `malformed-entry-missing-receipts` | `card_malformed` |
| `malformed-position-text` | `card_malformed` |
| `window-zero` | `window_out_of_range` |
| `window-over-cap` | `window_out_of_range` |
| `history-empty` | `positions_not_increasing_from_zero` |
| `first-checkpoint-missing` | `positions_not_increasing_from_zero` |
| `positions-repeat` | `positions_not_increasing_from_zero` |
| `sample-position-missing` | `position_missing` |
| `window-position-missing` | `position_missing` |
| `extra-position` | `position_unexpected` |
| `window-mismatch` | `position_unexpected` |
| `checkpoint-unaccepted-key` | `checkpoint_invalid` |
| `checkpoint-bad-signature` | `checkpoint_invalid` |
| `checkpoint-not-cose` | `checkpoint_invalid` |
| `checkpoint-shrinks` | `checkpoint_shrinks` |
| `proof-broken` | `proof_invalid` |
| `proof-tampered` | `proof_invalid` |
| `proof-absent` | `proof_invalid` |
| `first-entry-has-proof` | `proof_invalid` |
| `receipt-other-checkpoint` | `receipt_invalid` |
| `receipt-bad-signature` | `receipt_invalid` |
| `hex-with-spaces` | `card_malformed` |
| `hex-uppercase` | `card_malformed` |
| `first-checkpoint-has-predecessor` | `first_checkpoint_has_predecessor` |
| `issued-at-lowercase` | valid |
| `issued-at-offset` | valid |
| `issued-at-not-a-date` | `checkpoint_invalid` |
| `checkpoint-claim-float` | `checkpoint_invalid` |
| `checkpoint-tag-long-form` | valid |
| `anchor-mismatch` | `anchor_mismatch` |

`positions` holds 42 rows: n in 0, 1, 2, 3, 7, 8, 9, 63, 64, 65, 1023, 1024, 1099 and 1000000, each with window 1, 8 and 64.

### `checkpoints-range.json` (9 cases, 11 request cases)

| Case | Expect |
|---|---|
| `pos-checkpoint-range` | well formed |
| `pos-checkpoint-range-one` | well formed |
| `pos-checkpoints-unranged` | well formed |
| `neg-checkpoint-range-reversed` | `request_malformed` |
| `neg-checkpoint-range-negative` | `request_malformed` |
| `neg-checkpoint-range-text` | `request_malformed` |
| `neg-checkpoint-range-one-bound` | `request_malformed` |
| `neg-checkpoint-range-three-bounds` | `request_malformed` |
| `neg-checkpoints-content-text` | `request_malformed` |
| `neg-checkpoints-content-range` | `request_malformed` |
| `neg-checkpoint-range-null` | `request_malformed` |
| `res-checkpoint-range-served` | artifact |
| `res-checkpoint-range-past-anchor` | refusal `coverage_unsatisfiable` |
| `res-checkpoint-range-at-anchor` | artifact |
| `res-checkpoint-range-beyond-stream` | refusal `coverage_unsatisfiable` |
| `res-history-card-2` | artifact |
| `res-history-card-2-full-history` | artifact |
| `res-history-card-2-record` | refusal `no_such_subject` |
| `res-history-card-2-checkpoint-range` | refusal `no_such_subject` |
| `res-history-card-1-checkpoint-range` | refusal `no_such_subject` |

## Readings in the -01 corpora

`categories.json` carries these in its `notes` member.

- **B1** §3.9: the request cases apply to a responder that implements categories. A responder that does not implement it ignores the field, malformed or not, and answers as if it were absent.
- **B2** §3.9 leaves open whether the order of names carries meaning. No case compares two requests whose names differ only in order.
- **B3** §3.9 does not say whether a member other than set and names is malformed. No case has one.

## Ambiguities in -00 (for -01)

Each is marked on the cases it affects. The vectors follow the reading given.

- **A1** §3.1 Subject: -00 gives six forms and their content but no wire shape. Vectors use a map with exactly one member, named by the form token, whose value is the content: null for full_history and checkpoints, a digest for record and exchange, [a, b] (two unsigned integers) for range, a text string for correlation.
- **A2** §3.1, §3.2, §4.2: -00 names digests but not the hash algorithm or representation. Vectors use SHA-256 as 64 lowercase hex characters, as text in both the JSON and CBOR bindings.
- **A3** §3.2 Coverage: min_freshness is 'size or time' with no shape. Vectors read the value itself: an unsigned integer is a log size, a text string is an RFC 3339 UTC time. Any other type is not a conforming value.
- **A4** §3 / §3.2: coverage_unsatisfiable is assigned for 'both, or neither'. Vectors read an absent coverage field as 'neither' (coverage_unsatisfiable), and a coverage value that is not a map, or a member whose value does not conform, as request_malformed. *Amended 2026-10-06 (spec ruling):* -00 does not state which refusal wins when coverage carries both members and one of them does not conform. Ruling: request_malformed wins. A responder first checks that each member present in `coverage` has a conforming value; a non-conforming value is refused request_malformed, whether or not the other member is present. Only then is coverage carrying both members, or neither, refused coverage_unsatisfiable. The normative sentence goes into -01 §3.2; the posted -00 text is unchanged. Cases: `neg-coverage-both-pin-malformed`, `neg-coverage-both-freshness-malformed`, `neg-coverage-both-both-malformed`. (The A4 note embedded in the cases and manifest shipped in 0.6.0 is left as it was so those bytes do not change; the three new cases carry the amended text.)
- **A5** §3.4-§3.6: deadline, nonce and route have no stated type. Vectors use text strings (deadline as an RFC 3339 UTC time).
- **A6** §3.1 range: -00 does not say whether a > b is malformed. Vectors treat it as a value that does not conform (request_malformed).
- **A7** §4.2 / §10: -00 names the refusal's contents but no member names or signature format. Vectors use request_digest, reason, issued_at, key_id and sig with the signature profile in refusal.json. In the CBOR binding the same map is the frame; the signature is still over the RFC 8785 body.
- **A8** §4.3 / §10: the stream binding says absence is 'the stream closed or timed out without a response frame'; §4.3 says only the close of the waiting window resolves a request. Vectors follow §4.3: a transport failure inside the window leaves the request pending.
- **A9** §9: -00 lists retention_expired only as the correct refusal after until. Inside until, vectors apply the literal 'any other refusal reason' rule: it is a breach.
- **A10** §9: after until, -00 names only retention_expired as correct. Vectors class the four request/capability reasons, policy_declined and deadline_unmet as no breach, and no_such_subject as the wrong token (the lapsed promise must not read as never held, §4.2 item 2).
- **A11** §9: 'a digest or a position under a checkpoint'. Vectors read full_history, checkpoints and correlation subjects in a commitment as malformed.
- **A12** §4.1: the artifact envelope has no member names. Invariance cases compare artifact bytes only; the observation members are local to these vectors.
- **A13** §4.2 item 2 / §4.5: -00 does not say what a correctly signed object with an unregistered reason is. Vectors: not a conforming refusal, and still never recorded as absence.
- **A14** §3.3: a registered derivation token and the digest of a definition share one field. Vectors tell them apart by form: a token has a '/N' suffix, a digest is 64 lowercase hex.
