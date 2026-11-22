# Evidence Bundle `composed/v1`: History member vectors

These vectors cover the History member and the `same_key` join basis that
`draft-mih-zhang-agent-disclosure-bundle-03` defines in its `composed/v1`
section: "History Members" (the `history` body, its digest, its five checks
and its join view) and "Joins" (`same_key`, `controller_binding` with a
History member, History times, and Histories under two keys). The -03
revision is held for ratification; the text and these vectors are reviewed
together.

A History is a responder's answer to one Evidence Request for its
`full_history` subject. As a member it is an `artifact` member whose body is
`history`: the evidence-interop envelope as received (artifact octets
included) and the CLL COSE checkpoint its `anchor.digest` names. Its member
digest is

    lowercase hex SHA-256( UTF-8( JCS( history.envelope ) ) )

so the composed digest binds the responder key and the anchor. Each History
card here is illustrative: no verifier of these vectors reads its counts.

The reference composition has four members: responder-a's and responder-b's
Evidence Bundles of their halves of one exchange, joined on the exchange
identifier (`pre_agreed_identifier`), and history-a and history-b, each
party's History answer, each joined to its own party's half on `same_key`.
Each History is signed by its party's key, and its anchor is a checkpoint of
that party's own log, signed by the same key. A `same_key` join reads a
member Bundle's key only from its root record's producer signature, never
through a pointer, and a History's key from its envelope's `responder`. A
derived `agree` is always `redundant` with reason `same_key`.

For every join between a History and a member with a root record, the
verifier reports `history_times`: the History's anchor time, the record's
`timestamp`, and whether the History's time is `before`, `equal` to or
`after` the record's. These are facts with no join state. A `same_key` join
that derives `unjoined` also reports both keys (`keys`).

## Cases (`vectors.json`)

| id | what changes from the reference | joins of note | block |
|---|---|---|---|
| `history-two-parties` | nothing | every join `agree`; same_key `redundant` | `pass` |
| `history-anchored-before-exchange` | history-b's anchor before responder-b's record | still `agree`; times `before` | `pass` |
| `history-key-mismatch-declared-agree` | history-a joined to responder-b, declared `agree` | `unjoined`, both keys | `fail` (`join_state_mismatch`) |
| `history-key-mismatch-unjoined` | the same, declared `unjoined` | `unjoined`, both keys | `pass` |
| `history-record-names-key-not-signed` | responder-b's record states responder-a's `key_id` but was signed by responder-b | not derivable | `withheld` |
| `history-record-unsigned` | responder-a's record carries no signature | not derivable | `withheld` |
| `history-member-missing` | history-a declared missing | not derivable; same composed digest as the reference | `withheld` |
| `history-anchor-checkpoint-mismatch` | history-a carries another checkpoint | not derivable | `fail` |
| `history-envelope-signature-invalid` | history-a's envelope signed by another key | not derivable | `fail` |
| `history-artifact-anchor-mismatch` | history-a's card states another anchor | not derivable | `fail` |
| `history-profile-not-implemented` | history-a's envelope names `x-example-profile/0` | signature unverified; not derivable | `withheld` |
| `history-artifact-digest-mismatch` | history-a's envelope signs a wrong `artifact_digest` | not derivable | `fail` |
| `history-request-digest-mismatch` | history-a's envelope answers another request | not derivable | `fail` |
| `history-anchor-checkpoint-invalid` | history-a's anchor checkpoint signature does not verify | not derivable | `fail` |
| `history-anchor-checkpoint-unprotected-header` | history-a's anchor checkpoint has an unprotected header entry (not the one form) | not derivable | `fail` |
| `history-artifact-not-jcs` | history-a's card is not in JCS form | not derivable | `fail` |
| `history-profile-not-a-string` | history-a's envelope profile is an array | signature unverified; not derivable | `withheld` |
| `history-envelope-digest-mismatch` | history-a's envelope passes every check but is not the declared member digest | not derivable | `fail` (closure) |
| `history-empty-history-half-other-key` | history-b joined to responder-a's empty-history Bundle | `unjoined`, both keys | `pass` |
| `history-member-listed-missing-carries-body` | history-a listed missing but carrying its body | joins derive | `fail` (closure) |
| `history-refused-half` | responder-a refused | same_key `one_sided` | `withheld` (refusal signature unverified) |
| `history-empty-history-half` | responder-a is an empty-history Bundle | same_key `one_sided` | `pass` |
| `history-pre-agreed-identifier-not-derivable` | a `pre_agreed_identifier` join naming history-a | not derivable | `withheld` |
| `history-histories-controller-binding` | history-a and history-b joined by `controller_binding` | `agree`; `redundant` (`controller_binding`) | `pass` |
| `history-compare-mismatch` | a `controller_binding` join of history-a and responder-b with `compare` | `mismatch` | `pass` |
| `history-malformed-subject` | history-a's envelope subject is a record | malformed | `fail` |
| `history-malformed-with-response` | history-a carries `response` | malformed | `fail` |
| `history-malformed-with-bundle` | history-a carries `history` and `bundle` | malformed | `fail` |
| `history-malformed-noncanonical-base64url` | a base64url text with nonzero pad bits | malformed | `fail` |
| `history-malformed-same-key-pointer` | a `same_key` join with `pointer` | malformed | `fail` |

An anchor checkpoint this verifier cannot check (no CLL verifier installed) is
`unverified`: withheld, no join view; no vector covers it, since every
verifier of these vectors has one. A malformed block reports no composition
result; its `expect` is
`{"status": "fail", "malformed": true}`.

The Python test (`python/tests/test_bundle_composed_history_vectors.py`)
rederives the History checks, join states, keys and times independently of
the generator and the verifiers. Every implementation runs every case: Go
(`go/bundle`), Python (`agent_action_capsule.composed`), TypeScript
(`ts/src/composed.ts`) and Rust (`agent-action-capsule::bundle::composed`),
and `scripts/cross-language-interlock.sh` has all four print the same result
line for every case.

## Regenerating

```bash
python3 python/scripts/generate_bundle_composed_history_vectors.py
```

The run is deterministic. The keys are the test-only seeds of
`vectors/bundle/composed/`, listed in `vectors.json`.
