# Inference-Service History: `inference-service-history/1` vectors

These vectors exercise `inference-service-history/1` of
`spec/inference-service-history-profile-v0.md`: `/0` with one more complementary rule (§6.2 item 5,
SH-8). Where two or more of a table's cells are withheld, every one `below_floor`, and the total less
its published cells is the number of those cells or that number times (`floor` − 1), the total fixes
each of them, so it is withheld `complementary`, even when it is under the floor too. A cell is
listed only for a value the period counted.

They are built on the Standard History of `vectors/inference-service-history-v0-interop-v1/`
(`evidence-interop/1`): the same node stream, card, period policy (floor 5) and envelopes, with the
definitions `service_history_example/1` and `service_history_verdicts_example/1` naming
`inference-service-history/1`, and 2 October's cells replaced by the table each case is about. A
count carries no records (§4.2), so a table need not match the card's log sizes. The `/0` sets are
unchanged.

## Cases

Five positives: the base History (one model withheld and its partner, as under `/0`); models 4 and
4 and five models of 1, each total withheld; models 1 and 1, whose total of 2 is under the floor
and withheld `complementary`, not `below_floor`, so the reason does not tell it from a total of 8;
models 3 and 4, whose total of 7 fixes neither and stays published. Six negatives, each failing
`period_floor`: the totals of 8 and 5 published; a published model of 10 beside two of 4 withheld
under a published total of 18; a published model of 10 beside three withheld under a published
total of 12, short of one per withheld model (the listing rule), and beside two withheld under a
published total of 19, more than they can hold; a total withheld `complementary`
beside one model under the floor.
Two cases add the verdict counts member of `vectors/inference-service-history-verdicts-v0/`, whose
2 October contradicted table holds 4 and 4: its total withheld (accepted), and published
(`period_floor` `FAIL`).

## Not covered

- The residuals §12 names: a withheld cell and its `complementary` partner bounded by the smallest
  published cell, and a floor of 2.
- The envelope, the card, the Detailed level and the other History properties:
  `vectors/inference-service-history-v0-interop-v1/`.
- Go does not read the verdict counts member; its test lists the two verdict cases by id.

## Derivation

`python/scripts/generate_inference_service_history_v1_vectors.py` writes every file except this
README and states every expected status by hand from the profile text.
`python/tests/test_inference_service_history_v1_vectors.py` evaluates every case from its inputs
alone with the evaluator of `test_inference_service_history_v0_vectors.py`, requires the result to
equal the case's `expected` block, and regenerates the directory byte for byte. The Rust test
`rust/agent-action-capsule/tests/inference_history_vectors.rs` and the Go test
`go/inferencehistory/vectors_test.go` check the cases with their own libraries.
