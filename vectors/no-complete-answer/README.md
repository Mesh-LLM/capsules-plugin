# No producer-selected answer reads COMPLETE

evidencebook#206 row 7 (Mesh-LLM/capsules-plugin#233). One case per answer
kind this node gives: `record`, `correlation`, `exchange`, `checkpoints`,
`history_card/1`, `served_summary/1` and `exchange_corroboration/1`, each the
node's own signed reply to the request beside it, under the fixed test key
`node_key_seed` at `issued_at`.

`reading` is what a requester takes from the reply, with the anchor's size from
the node's own checkpoint list: a verified answer is
`COMPLETE` only when it shows every record of the log up to its anchor
(`shown.records` against `shown.anchor_leaves`); otherwise `INCOMPLETE`; a
signed refusal (verified, not just a `reason` member) is `REFUSED`.
`checkpoints` and `history_card/1` carry no records, so they read `INCOMPLETE`
because they show none; that they state no interval is checked separately: no
member name of any artifact, at any depth, holds `interval`, `complete`,
`coverage`, `range`, `cover`, `span`, `certificate` or `size` (`shown.members`
lists them). Every case is asked of the node ungated; the sharing policy only
refuses more. No answer carries an interval claim a verifier could certify, so
the node's choice among records is never read as complete.
`served_summary/1` is retired and refused to every asker.

`control:full_history` shows the reading can say `COMPLETE`: a whole-history
answer does. The node serves it to no asker (refused `not_authorized` in every
sharing setting); the vector is built ungated only to run the control.

Written by `the_vectors_are_the_nodes_answers`
(`crates/evidence-plugin/src/evidence_artifact/tests/no_complete_answers.rs`),
which also fails when the node's answer changes; `no_selected_answer_reads_complete`
reads each reply afresh from the file.
