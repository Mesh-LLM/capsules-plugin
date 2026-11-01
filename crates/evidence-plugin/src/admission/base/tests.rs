use super::*;

const PEER: &str = "5500000000000000000000000000000000000000000000000000000000000003";
const OTHER: &str = "6600000000000000000000000000000000000000000000000000000000000004";
const REFEREE: &str = "7700000000000000000000000000000000000000000000000000000000000005";
/// The peer's announced record key in these tests.
const KEY: &str = "ab00000000000000000000000000000000000000000000000000000000000006";

fn card(age_days: i64) -> CardOutcome {
    CardOutcome::Read(Card {
        artifact_digest: "c".repeat(64),
        first_checkpoint_at: Some(Utc::now() - chrono::Duration::days(age_days)),
        key_id: KEY.to_string(),
    })
}

impl Base {
    /// [`Base::read`] with [`KEY`] announced for the peer.
    fn read_keyed(&self, peer: &str, at: Instant, now: DateTime<Utc>) -> Read {
        self.read_with_key(peer, Some(KEY), at, now)
    }
}

/// A peer's book as a test sets it: counts of settled exchanges and of
/// exchanges whose half is held under [`KEY`], and the verdicts held.
#[derive(Clone, Debug, Default)]
struct Book {
    settled: usize,
    held_halves: usize,
    verdicts: Vec<HeldVerdict>,
}

impl Book {
    fn set(&self, base: &Base) {
        base.set_facts_for_test(
            PEER,
            KEY,
            self.settled,
            self.held_halves,
            self.verdicts.clone(),
        );
    }
}

/// A verdict whose time does not read: in the period.
fn held(adverse: bool) -> HeldVerdict {
    HeldVerdict { at: None, adverse }
}

fn passing() -> Book {
    Book {
        settled: 1,
        held_halves: 1,
        verdicts: vec![held(false)],
    }
}

fn base() -> (Base, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    (Base::new(dir.path().to_path_buf()), dir)
}

#[test]
fn no_card_read_yet_is_not_read_and_queues_one_ask() {
    let (base, _dir) = base();
    let (sender, mut asks) = tokio::sync::mpsc::unbounded_channel();
    base.asks.set(sender).unwrap();
    let at = Instant::now();
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.card, None);
    assert_eq!(read.rows, [RowResult::NotRead; 5], "nothing read yet");
    assert_eq!(asks.try_recv().as_deref(), Ok(PEER));
    base.read_keyed(PEER, at, Utc::now());
    assert!(asks.try_recv().is_err(), "one ask in flight per peer");
}

#[test]
fn a_failed_ask_leaves_the_card_rows_not_read_and_is_retried_only_after_an_hour() {
    let (base, _dir) = base();
    let (sender, mut asks) = tokio::sync::mpsc::unbounded_channel();
    base.asks.set(sender).unwrap();
    let at = Instant::now();
    base.read_keyed(PEER, at, Utc::now());
    asks.try_recv().unwrap();
    base.record_card(PEER, CardOutcome::NotRead, at);
    passing().set(&base);

    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.rows[..2], [RowResult::NotRead; 2]);
    assert_eq!(read.rows[2..], [RowResult::Pass; 3]);
    assert!(asks.try_recv().is_err(), "not asked again within the hour");

    base.read_keyed(PEER, at + ASK_RETRY, Utc::now());
    assert_eq!(asks.try_recv().as_deref(), Ok(PEER));
}

#[test]
fn a_card_that_does_not_verify_fails_identity() {
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, CardOutcome::Unverifiable, at);
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.rows[0], RowResult::Fail);
    assert_eq!(read.rows[1], RowResult::NotRead);
}

#[test]
fn each_row_fails_on_its_own_input_alone() {
    let cases: [(CardOutcome, Book, usize); 4] = [
        (card(KEY_AGE_DAYS - 1), passing(), 1),
        (
            card(30),
            Book {
                settled: 0,
                ..passing()
            },
            2,
        ),
        (
            card(30),
            Book {
                verdicts: vec![held(true)],
                ..passing()
            },
            3,
        ),
        (
            card(30),
            Book {
                held_halves: 0,
                ..passing()
            },
            4,
        ),
    ];
    for (card, facts, failing) in cases {
        let (base, _dir) = base();
        let at = Instant::now();
        base.record_card(PEER, card, at);
        facts.set(&base);
        let read = base.read_keyed(PEER, at, Utc::now());
        for (i, row) in read.rows.iter().enumerate() {
            let expected = if i == failing {
                RowResult::Fail
            } else {
                RowResult::Pass
            };
            assert_eq!(*row, expected, "{} while {} fails", ROWS[i], ROWS[failing]);
        }
    }
}

#[test]
fn a_card_old_enough_passes_every_row_and_is_cited() {
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, card(KEY_AGE_DAYS), at);
    passing().set(&base);
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.rows, [RowResult::Pass; 5]);
    assert_eq!(read.card.as_deref(), Some("c".repeat(64).as_str()));
}

#[test]
fn before_the_first_refresh_the_local_rows_are_not_read() {
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, card(30), at);
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(
        read.rows[2..],
        [RowResult::NotRead; 3],
        "an unread dispute row never passes"
    );
}

#[test]
fn a_later_refusal_keeps_the_card_already_read() {
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, card(30), at);
    base.record_card(PEER, CardOutcome::NotRead, at + CARD_TTL);
    let read = base.read_keyed(PEER, at + CARD_TTL, Utc::now());
    assert_eq!(read.rows[..2], [RowResult::Pass; 2]);
    assert!(read.card.is_some());
}

fn write_ledger(dir: &Path, records: &[Value]) {
    let lines: Vec<String> = records.iter().map(Value::to_string).collect();
    std::fs::write(dir.join("capsules.jsonl"), lines.join("\n")).unwrap();
}

fn exchange(peer: &str, exchange_id: &str) -> Value {
    json!({"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {
        "role": "requested",
        "serving_provenance": {"exchange_id": exchange_id, "served_by_node_id": peer},
    }}}})
}

fn settlement(exchange_id: &str, phase: &str) -> Value {
    let source = if phase.ends_with("_settlement_observed") {
        "wallet_reported"
    } else {
        "provider_asserted"
    };
    json!({"model_attestation": {"compute_attestation": {"x-mesh-settlement-v1": {
        "v": 1, "observed_by": "payer", "exchange_id": exchange_id,
        "phase": phase, "source": source, "segment": 0, "payment_hash": "aa",
    }}}})
}

/// A citing record as `producer::capsule` seals one: the sender's verified
/// key, no node id.
fn citing(key: &str, half: &str, signature_ok: bool) -> Value {
    json!({
        "references": [{"citation_purpose": "counterparty_half", "digest": half}],
        "model_attestation": {"compute_attestation": {"received_half": {
            "cited_capsule_id": half, "received_from": "some-peer", "via": "record_push",
            "signature_ok": signature_ok, "sender_key_id": key,
        }}},
    })
}

fn verdict(verdict: &str, id: &str, at: &str) -> Value {
    json!({"model_attestation": {"compute_attestation": {"adjudication_issued": {
        "verdict": verdict, "verdict_capsule_id": id, "referee_node_id": REFEREE,
        "halves": [format!("{id}-a"), format!("{id}-b")], "half_node_ids": [PEER, OTHER],
        "issued_at": at,
    }}}})
}

#[test]
fn local_facts_count_settled_exchanges_held_halves_and_adverse_verdicts_in_the_period() {
    let dir = tempfile::tempdir().unwrap();
    let now = DateTime::parse_from_rfc3339("2026-10-29T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    write_ledger(
        dir.path(),
        &[
            exchange(PEER, "ex-paid"),
            exchange(PEER, "ex-unpaid"),
            exchange(OTHER, "ex-other"),
            settlement("ex-paid", "input_invoice_issued"),
            settlement("ex-paid", "input_settlement_observed"),
            settlement("ex-unpaid", "input_invoice_issued"),
            citing(KEY, "half-1", true),
            citing(KEY, "half-1", true),
            citing(KEY, "half-2", false),
            // This node issued both (it is the referee's own judgment, so it
            // counts with no request on file).
            verdict(
                &format!("contradicted:{PEER}"),
                "v-recent",
                "2026-10-20T00:00Z",
            ),
            verdict(
                &format!("contradicted:{PEER}"),
                "v-old",
                "2026-09-01T00:00Z",
            ),
        ],
    );
    let facts = local_facts(dir.path()).expect("the chain reads whole");
    let ids = |ids: &[&str]| ids.iter().map(|id| id.to_string()).collect::<BTreeSet<_>>();
    let at = |t: &str| parse_minute(t);
    assert_eq!(
        facts.by_peer.get(PEER),
        Some(&LocalFacts {
            exchanges: ids(&["ex-paid", "ex-unpaid"]),
            settled: ids(&["ex-paid"]),
            verdicts: vec![
                HeldVerdict {
                    at: at("2026-10-20T00:00Z"),
                    adverse: true
                },
                HeldVerdict {
                    at: at("2026-09-01T00:00Z"),
                    adverse: true
                },
            ],
        }),
        "two exchanges, one settled, and both verdicts with their times"
    );
    assert_eq!(
        facts.halves_by_key.get(KEY).map(BTreeSet::len),
        Some(1),
        "one verified half, counted once, under the key it verified under"
    );
    assert!(
        facts
            .by_peer
            .get(OTHER)
            .is_some_and(|f| f.verdicts.iter().all(|v| !v.adverse)),
        "a contradiction naming the other twin corroborates this one"
    );
    assert_eq!(facts.by_peer.get(OTHER).map(|f| f.settled.len()), Some(0));

    // The rows resolve the half to the peer through its announced key.
    let base = Base::new(dir.path().to_path_buf());
    base.refresh();
    let at = Instant::now();
    base.record_card(PEER, card(30), at);
    assert_eq!(base.read_keyed(PEER, at, now).rows[4], RowResult::Pass);
    assert_eq!(
        base.read_with_key(PEER, Some(&"ef".repeat(32)), at, now)
            .rows[4],
        RowResult::Fail,
        "a half under another key is not this peer's"
    );
}

#[test]
fn a_chain_that_does_not_read_whole_leaves_the_local_rows_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let now = Utc::now();
    assert!(local_facts(dir.path()).is_some(), "an empty book reads");
    std::fs::write(
        dir.path().join("capsules.jsonl"),
        format!(
            "{}\n{{torn",
            verdict(&format!("contradicted:{PEER}"), "v", "2026-10-29T00:00Z")
        ),
    )
    .unwrap();
    assert!(
        local_facts(dir.path()).is_none(),
        "a torn line could hide an adverse verdict"
    );
    let base = Base::new(dir.path().to_path_buf());
    base.refresh();
    assert_eq!(
        base.read_keyed(PEER, Instant::now(), now).rows[2..],
        [RowResult::NotRead; 3]
    );
}

#[test]
fn a_torn_line_in_the_asked_for_adjudications_leaves_the_rows_not_read() {
    let dir = tempfile::tempdir().unwrap();
    write_ledger(
        dir.path(),
        &[verdict(
            &format!("contradicted:{PEER}"),
            "v",
            "2026-10-29T00:00Z",
        )],
    );
    std::fs::write(
        dir.path().join(crate::verdict_counts::REQUESTED_FILENAME),
        "{\"referee\":",
    )
    .unwrap();
    assert!(
        local_facts(dir.path()).is_none(),
        "the request it tore could be the one an adverse verdict needs"
    );
    std::fs::write(
        dir.path().join(crate::verdict_counts::REQUESTED_FILENAME),
        "{\"referee\":\"r\"}\n",
    )
    .unwrap();
    assert!(
        local_facts(dir.path()).is_none(),
        "a request line without its halves is skipped by read_requested too"
    );
    std::fs::write(
        dir.path().join(crate::verdict_counts::REQUESTED_FILENAME),
        "{\"referee\":\"r\",\"halves\":[\"a\",\"b\"],\"asked_at\":\"2026-10-29T00:00Z\"}\n",
    )
    .unwrap();
    assert!(
        local_facts(dir.path()).is_some(),
        "a whole request line reads"
    );
}

#[test]
fn disputes_is_not_read_until_this_node_holds_a_verdict_about_the_peer() {
    let (base, _dir) = base();
    let at = Instant::now();
    Book {
        verdicts: vec![],
        ..passing()
    }
    .set(&base);
    assert_eq!(
        base.read_keyed(PEER, at, Utc::now()).rows[3],
        RowResult::NotRead
    );
    passing().set(&base);
    assert_eq!(
        base.read_keyed(PEER, at, Utc::now()).rows[3],
        RowResult::Pass
    );
}

#[test]
fn a_card_read_under_another_key_or_failing_later_is_no_longer_read() {
    let (base, _dir) = base();
    let (sender, mut asks) = tokio::sync::mpsc::unbounded_channel();
    base.asks.set(sender).unwrap();
    let at = Instant::now();
    base.record_card(PEER, card(30), at);
    let rotated = "cd".repeat(32);
    let read = base.read_with_key(PEER, Some(&rotated), at, Utc::now());
    assert_eq!(read.card, None, "the old card speaks for the old key only");
    assert_eq!(read.rows[..2], [RowResult::NotRead; 2]);
    assert_eq!(
        asks.try_recv().as_deref(),
        Ok(PEER),
        "and the new key's card is asked for"
    );

    let (base, _dir) = self::base();
    base.record_card(PEER, card(30), at);
    base.record_card(PEER, CardOutcome::Unverifiable, at);
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.card, None);
    assert_eq!(
        read.rows[0],
        RowResult::Fail,
        "the newer answer did not verify"
    );
    let read = base.read_with_key(PEER, Some(&rotated), at, Utc::now());
    assert_eq!(
        read.rows[0],
        RowResult::NotRead,
        "a failure under the old key says nothing about the new one"
    );
}

#[test]
fn a_refusal_or_an_answer_with_no_key_is_never_a_card() {
    let sent = serde_json::to_vec(&card_request()).unwrap();
    assert_eq!(
        read_card(
            &sent,
            &json!({"reason": "policy_declined"}),
            None,
            &Default::default()
        ),
        CardOutcome::NotRead
    );
    assert_eq!(
        read_card(&sent, &json!({"artifact": {}}), None, &Default::default()),
        CardOutcome::NotRead,
        "no key known yet is not a failed check"
    );
    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    );
    assert_eq!(
        read_card(
            &sent,
            &json!({"artifact": {}}),
            Some(&key),
            &Default::default()
        ),
        CardOutcome::Unverifiable
    );
}

#[test]
fn minute_granular_times_parse() {
    assert!(parse_minute("2026-10-20T00:00Z").is_some());
    assert!(parse_minute("2026-10-20T00:00:00Z").is_some());
    assert!(parse_minute("yesterday").is_none());
}

// The base pack (#178).

#[test]
fn the_embedded_pack_is_the_one_pinned() {
    use sha2::{Digest, Sha256};
    assert_eq!(hex::encode(Sha256::digest(DEFINITION)), DEFINITION_DIGEST);
    let pack = pack();
    assert_eq!(pack.id(), PACK_ID);
    assert_eq!(pack.digest(), DEFINITION_DIGEST);
    // A changed file is refused, never loaded under the old pin.
    let mut changed = DEFINITION.to_vec();
    let at = changed.iter().position(|b| *b == b'7').expect("min_days 7");
    changed[at] = b'8';
    assert!(engine::Pack::load_pinned(&changed, PACK_ID, DEFINITION_DIGEST).is_err());
}

#[test]
fn the_packs_rows_are_base_1s_with_its_thresholds() {
    let definition: Value = serde_json::from_slice(DEFINITION).unwrap();
    let rows = definition["rows"].as_array().unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
    let mut expected = vec!["deny_list", "allow_list"];
    expected.extend(ROWS);
    assert_eq!(
        ids, expected,
        "the lists first, then the five rows in order"
    );
    let row = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap();
    for id in ["deny_list", "allow_list"] {
        assert_eq!(row(id)["on_fail"], "NO");
        assert_eq!(row(id)["source"], "operator");
    }
    for id in ROWS {
        assert_eq!(row(id)["on_fail"], "record", "{id} decides nothing");
        assert_eq!(row(id)["from"], "T0");
    }
    assert_eq!(row("key_age")["params"]["min_days"], KEY_AGE_DAYS);
    assert_eq!(row("performed_and_settled")["params"]["min"], MIN_SETTLED);
    assert_eq!(
        row("disputes")["params"]["window_days"],
        DISPUTE_PERIOD_DAYS
    );
    assert_eq!(row("corroboration")["params"]["min"], MIN_HELD_HALVES);
    assert_eq!(definition["outcomes"], json!(["GO", "NO"]));
    assert_eq!(definition["missing"], "NO");
    assert_eq!(
        definition["accept"][DEAL_CURRENCY]["band"], "sat",
        "the deal's currency is one the pack accepts"
    );
    assert_eq!(
        definition["tiers"],
        json!([{"id": "T0", "max_decade": {"sat": 60}}]),
        "one tier, as wide as the profile allows"
    );
}

/// The five rows as `Base::read` decided them before #178, kept as the
/// reference the evaluator's rows are held to. `card` is the last recorded
/// outcome of an ask (`None`: never answered) and `local` the peer's book
/// (`None`: no refresh read the chain whole). The disputes row counts the
/// adverse verdicts in the period itself, as `local_facts` did: a time that
/// does not read is in it, and so is one after `now`.
fn rows_before_178(
    card: Option<&CardOutcome>,
    local: Option<&Book>,
    now: DateTime<Utc>,
) -> [RowResult; 5] {
    let period = chrono::Duration::days(DISPUTE_PERIOD_DAYS);
    let of = |pass: bool| {
        if pass {
            RowResult::Pass
        } else {
            RowResult::Fail
        }
    };
    let card_rows = match card {
        Some(CardOutcome::Read(card)) => [
            RowResult::Pass,
            card.first_checkpoint_at
                .map_or(RowResult::NotRead, |first| {
                    of(now - first >= chrono::Duration::days(KEY_AGE_DAYS))
                }),
        ],
        Some(CardOutcome::Unverifiable) => [RowResult::Fail, RowResult::NotRead],
        _ => [RowResult::NotRead; 2],
    };
    let local_row = |pass: fn(&Book) -> bool| local.map_or(RowResult::NotRead, |f| of(pass(f)));
    [
        card_rows[0],
        card_rows[1],
        local_row(|f| f.settled >= MIN_SETTLED),
        match local {
            Some(facts) if !facts.verdicts.is_empty() => of(!facts
                .verdicts
                .iter()
                .any(|v| v.adverse && v.at.is_none_or(|at| now - at <= period))),
            _ => RowResult::NotRead,
        },
        local_row(|f| f.held_halves >= MIN_HELD_HALVES),
    ]
}

fn card_at(first: Option<DateTime<Utc>>) -> CardOutcome {
    CardOutcome::Read(Card {
        artifact_digest: "c".repeat(64),
        first_checkpoint_at: first,
        key_id: KEY.to_string(),
    })
}

#[test]
fn the_evaluators_rows_are_the_rows_base_1_read() {
    let now = DateTime::parse_from_rfc3339("2026-10-31T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let days = chrono::Duration::days;
    let cards: Vec<Option<CardOutcome>> = vec![
        None,
        Some(CardOutcome::NotRead),
        Some(CardOutcome::Unverifiable),
        Some(card_at(Some(now - days(30)))),
        Some(card_at(Some(now - days(KEY_AGE_DAYS)))),
        Some(card_at(Some(
            now - days(KEY_AGE_DAYS) + chrono::Duration::nanoseconds(1),
        ))),
        Some(card_at(Some(now - days(1)))),
        Some(card_at(Some(now + days(1)))),
    ];
    let facts = |settled, held_halves, verdicts: usize, adverse: usize| Book {
        settled,
        held_halves,
        verdicts: (0..verdicts).map(|i| held(i < adverse)).collect(),
    };
    let locals: Vec<Option<Book>> = vec![
        None,
        Some(Book::default()),
        Some(passing()),
        Some(facts(0, 1, 1, 0)),
        Some(facts(1, 0, 1, 0)),
        Some(facts(1, 1, 0, 0)),
        Some(facts(1, 1, 1, 1)),
        Some(facts(5, 3, 4, 2)),
        Some(facts(5, 3, 4, 0)),
    ];
    for card in &cards {
        for local in &locals {
            let (base, _dir) = base();
            let at = Instant::now();
            if let Some(card) = card {
                base.record_card(PEER, card.clone(), at);
            }
            if let Some(local) = local {
                local.set(&base);
            }
            let read = base.read_keyed(PEER, at, now);
            assert_eq!(
                read.rows,
                rows_before_178(card.as_ref(), local.as_ref(), now),
                "{card:?} {local:?}"
            );
            assert_eq!(
                read.decision.verdict,
                engine::Verdict::Go,
                "the rows decide nothing: {card:?} {local:?}"
            );
        }
    }
}

#[test]
fn a_card_whose_first_checkpoint_does_not_read_fails_key_age() {
    // The one row base/1 read otherwise: it read `not_read`, and the
    // evaluator reads a verified card that states no first checkpoint as
    // showing no age, a `fail`. Recorded only: the verdict is unchanged.
    let now = Utc::now();
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, card_at(None), at);
    let read = base.read_keyed(PEER, at, now);
    assert_eq!(
        rows_before_178(Some(&card_at(None)), None, now)[1],
        RowResult::NotRead
    );
    assert_eq!(read.rows[..2], [RowResult::Pass, RowResult::Fail]);
    assert_eq!(read.decision.verdict, engine::Verdict::Go);
}

#[test]
fn the_evaluator_windows_verdicts_as_base_1_did() {
    let now = DateTime::parse_from_rfc3339("2026-10-31T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    // Each case: one verdict about PEER, its time, and whether it is in the
    // period as base/1 counts it.
    for (at, kind, adverse_in_period) in [
        ("2026-10-20T00:00Z", "contradicted", true),
        ("2026-10-01T00:00Z", "contradicted", true), // exactly 30 days
        ("2026-09-30T23:59Z", "contradicted", false),
        ("2026-11-05T00:00Z", "contradicted", true), // stated after now
        ("not a time", "contradicted", true),
        ("2026-10-20T00:00Z", "corroborated", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let named = if kind == "contradicted" {
            format!("contradicted:{PEER}")
        } else {
            kind.to_string()
        };
        write_ledger(
            dir.path(),
            &[
                exchange(PEER, "ex-1"),
                exchange(PEER, "ex-2"),
                verdict(&named, "v", at),
            ],
        );
        let facts = local_facts(dir.path()).expect("reads whole");
        let local = facts.by_peer.get(PEER).cloned().unwrap_or_default();
        assert_eq!(local.verdicts.len(), 1, "the verdict is held: {at} {kind}");
        let local = Book {
            settled: local.settled.len(),
            held_halves: 0,
            verdicts: local.verdicts,
        };
        let base = Base::new(dir.path().to_path_buf());
        base.refresh();
        let read = base.read_keyed(PEER, Instant::now(), now);
        assert_eq!(
            read.rows,
            rows_before_178(None, Some(&local), now),
            "{at} {kind}"
        );
        assert_eq!(
            read.rows[3],
            if adverse_in_period {
                RowResult::Fail
            } else {
                RowResult::Pass
            },
            "{at} {kind}"
        );
        let settled = read
            .decision
            .rows
            .iter()
            .find(|r| r.row == "performed_and_settled")
            .unwrap();
        assert_eq!(
            settled.denominator,
            Some(2),
            "the peer's exchanges are the denominator"
        );
    }
}

// Nothing but a list reaches NO (Sherlock2's door condition on #178).

fn decide(inputs: &engine::Inputs) -> engine::Decision {
    engine::evaluate(pack(), inputs)
}

fn deal(amount: &str) -> engine::Inputs {
    let mut inputs = engine::Inputs::at(timestamp(Utc::now()));
    inputs.amount = amount.into();
    inputs.currency = DEAL_CURRENCY.into();
    inputs
}

#[test]
fn a_peer_with_no_card_and_no_book_is_go() {
    let (base, _dir) = base();
    let read = base.read_keyed(PEER, Instant::now(), Utc::now());
    assert_eq!(read.rows, [RowResult::NotRead; 5]);
    assert_eq!(read.decision.verdict, engine::Verdict::Go);
    assert_eq!(read.decision.source, "rows");
    assert_eq!(read.decision.tier.as_deref(), Some("T0"));
}

#[test]
fn the_deal_is_always_free_and_free_is_go() {
    // Admission states no amount, so the plugin always passes "0" msat.
    assert_eq!((DEAL_AMOUNT, DEAL_CURRENCY), ("0", "msat"));
    let decision = decide(&deal(DEAL_AMOUNT));
    assert_eq!(decision.verdict, engine::Verdict::Go);
    assert_eq!(decision.band, None, "free: no band");
    assert_eq!(decision.tier.as_deref(), Some("T0"));
    // Why it is never left empty: an amount that does not read is a
    // missing input, which this pack's default makes NO.
    for unreadable in ["", "-1", "1e3"] {
        let decision = decide(&deal(unreadable));
        assert_eq!(decision.verdict, engine::Verdict::No, "{unreadable:?}");
        assert_eq!(decision.source, "missing");
    }
}

#[test]
fn a_deal_as_large_as_the_profile_allows_is_go() {
    // 10^63 msat is 10^60 sat, decade 60: the one tier's ceiling.
    let largest = format!("9{}", "9".repeat(63));
    for amount in ["1".to_string(), "21000000000000000000".to_string(), largest] {
        let decision = decide(&deal(&amount));
        assert_eq!(decision.verdict, engine::Verdict::Go, "{amount}");
        assert_eq!(decision.tier.as_deref(), Some("T0"));
    }
}

#[test]
fn with_no_list_the_operator_rows_pass() {
    let decision = decide(&deal(DEAL_AMOUNT));
    for id in ["deny_list", "allow_list"] {
        let row = decision.rows.iter().find(|r| r.row == id).unwrap();
        assert_eq!(
            row.result,
            engine::RowStatus::Pass,
            "{id} is never not_read"
        );
    }
    let mut listed = deal(DEAL_AMOUNT);
    listed.operator.deny_listed = true;
    let decision = decide(&listed);
    assert_eq!(
        (decision.verdict, decision.source.as_str()),
        (engine::Verdict::No, "deny_list")
    );
    let mut unlisted = deal(DEAL_AMOUNT);
    unlisted.operator.allow_listed = Some(false);
    let decision = decide(&unlisted);
    assert_eq!(
        (decision.verdict, decision.source.as_str()),
        (engine::Verdict::No, "allow_list")
    );
}

/// Each own-book row's count and denominator from a read of `ledger`, with
/// [`KEY`] as the peer's key.
fn own_counts(ledger: &[Value]) -> Vec<(String, i64, i64)> {
    let dir = tempfile::tempdir().unwrap();
    write_ledger(dir.path(), ledger);
    let base = Base::new(dir.path().to_path_buf());
    base.refresh();
    let read = base.read_keyed(PEER, Instant::now(), Utc::now());
    read.decision
        .rows
        .iter()
        .filter(|r| ["performed_and_settled", "corroboration"].contains(&r.row.as_str()))
        .map(|r| (r.row.clone(), r.count.unwrap(), r.denominator.unwrap()))
        .collect()
}

#[test]
fn no_count_exceeds_the_peers_exchanges() {
    let mut own = exchange(PEER, "ex-1");
    own["capsule_id"] = json!("own-1");
    let mut citing_own = citing(KEY, "half-1", true);
    citing_own["model_attestation"]["compute_attestation"]["received_half"]
        ["own_half_capsule_id"] = json!("own-1");
    for (ledger, expected) in [
        // A held half with no record of this node's naming the peer.
        (
            vec![citing(KEY, "half-1", true)],
            [("performed_and_settled", 0, 1), ("corroboration", 1, 1)],
        ),
        // The half's own counterpart names the exchange: counted once.
        (
            vec![own.clone(), citing_own.clone()],
            [("performed_and_settled", 0, 1), ("corroboration", 1, 1)],
        ),
        // A half for one exchange, and another exchange settled.
        (
            vec![
                own,
                citing_own,
                exchange(PEER, "ex-2"),
                settlement("ex-2", "input_invoice_issued"),
                settlement("ex-2", "input_settlement_observed"),
            ],
            [("performed_and_settled", 1, 2), ("corroboration", 1, 2)],
        ),
        // A settlement for an exchange no record of this node's names.
        (
            vec![
                settlement("ex-9", "input_invoice_issued"),
                settlement("ex-9", "input_settlement_observed"),
            ],
            [("performed_and_settled", 0, 0), ("corroboration", 0, 0)],
        ),
    ] {
        let counts = own_counts(&ledger);
        let expected: Vec<(String, i64, i64)> = expected
            .iter()
            .map(|(row, c, d)| (row.to_string(), *c, *d))
            .collect();
        assert_eq!(counts, expected);
        assert!(
            counts.iter().all(|(_, count, of)| count <= of),
            "{counts:?}"
        );
    }
}

/// A ledger as an appending writer leaves it: every line ended by `\n`.
fn append_lines(dir: &Path, records: &[Value]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("capsules.jsonl"))
        .unwrap();
    for record in records {
        writeln!(file, "{record}").unwrap();
    }
}

fn history() -> Vec<Value> {
    vec![
        exchange(PEER, "ex-paid"),
        exchange(PEER, "ex-unpaid"),
        settlement("ex-paid", "input_invoice_issued"),
        citing(KEY, "half-1", true),
        exchange(OTHER, "ex-other"),
        settlement("ex-paid", "input_settlement_observed"),
        verdict(
            &format!("contradicted:{PEER}"),
            "v-recent",
            "2026-10-20T00:00Z",
        ),
        citing(KEY, "half-2", true),
    ]
}

fn facts_of(base: &Base) -> Option<Facts> {
    base.facts.read().unwrap().clone()
}

#[test]
fn rows_after_incremental_refreshes_equal_one_full_read_of_the_same_chain() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::new(dir.path().to_path_buf());
    for record in history() {
        append_lines(dir.path(), &[record]);
        base.refresh();
        assert_eq!(
            facts_of(&base),
            local_facts(dir.path()),
            "after each append the incremental read equals a whole read"
        );
    }
    assert!(facts_of(&base).unwrap().by_peer[PEER]
        .settled
        .contains("ex-paid"));
    let scan = base.scan.lock().unwrap();
    assert_eq!(scan.records.len(), history().len(), "each line parsed once");
}

#[test]
fn a_refresh_parses_only_the_lines_appended_since() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::new(dir.path().to_path_buf());
    append_lines(dir.path(), &history()[..3]);
    base.refresh();
    // Damage the middle line, keeping its length, which the identity check does not look at: an
    // incremental read never parses it again, a whole read would fail on it.
    let path = dir.path().join("capsules.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let damaged = text.replacen("\"ex-unpaid\"", "\"ex-unpaid~", 1);
    assert_ne!(damaged, text);
    std::fs::write(&path, damaged).unwrap();
    append_lines(dir.path(), &history()[3..4]);
    base.refresh();
    assert!(
        facts_of(&base).is_some(),
        "only the appended line was parsed"
    );
    assert_eq!(
        local_facts(dir.path()),
        None,
        "a whole read does fail on it"
    );
}

#[test]
fn a_shrunk_or_replaced_chain_is_read_again_whole() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::new(dir.path().to_path_buf());
    append_lines(dir.path(), &history());
    base.refresh();
    std::fs::remove_file(dir.path().join("capsules.jsonl")).unwrap();
    append_lines(dir.path(), &history()[..2]);
    base.refresh();
    assert_eq!(facts_of(&base), local_facts(dir.path()), "shrunk");
    assert_eq!(base.scan.lock().unwrap().records.len(), 2);
    // Replaced by a chain that is longer than the one read.
    let other = vec![exchange(OTHER, "ex-1"); 5];
    std::fs::remove_file(dir.path().join("capsules.jsonl")).unwrap();
    append_lines(dir.path(), &other);
    base.refresh();
    assert_eq!(facts_of(&base), local_facts(dir.path()), "replaced");
    assert!(!facts_of(&base).unwrap().by_peer.contains_key(PEER));
}

#[test]
fn a_torn_last_line_leaves_the_rows_not_read_and_reads_once_it_is_whole() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::new(dir.path().to_path_buf());
    append_lines(dir.path(), &history()[..2]);
    base.refresh();
    let line = history()[2].to_string();
    let (head, rest) = line.split_at(line.len() / 2);
    let path = dir.path().join("capsules.jsonl");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(head);
    std::fs::write(&path, &text).unwrap();
    base.refresh();
    assert_eq!(facts_of(&base), None, "a torn line could hide a verdict");
    text.push_str(rest);
    text.push('\n');
    std::fs::write(&path, &text).unwrap();
    base.refresh();
    assert!(facts_of(&base).is_some());
    assert_eq!(facts_of(&base), local_facts(dir.path()));
    assert_eq!(base.scan.lock().unwrap().records.len(), 3);
}

#[test]
fn an_unparsable_complete_line_stays_unread_until_the_chain_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::new(dir.path().to_path_buf());
    append_lines(dir.path(), &history()[..1]);
    let path = dir.path().join("capsules.jsonl");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("{bad\n");
    std::fs::write(&path, &text).unwrap();
    base.refresh();
    assert_eq!(facts_of(&base), None);
    append_lines(dir.path(), &history()[1..2]);
    base.refresh();
    assert_eq!(facts_of(&base), None, "later lines do not undo it");
}

#[test]
fn a_record_glued_to_an_unterminated_one_does_not_read_whole() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::new(dir.path().to_path_buf());
    let path = dir.path().join("capsules.jsonl");
    std::fs::write(&path, history()[0].to_string()).unwrap();
    base.refresh();
    assert!(
        facts_of(&base).is_some(),
        "a whole object with no newline yet reads"
    );
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(&history()[1].to_string());
    text.push('\n');
    std::fs::write(&path, &text).unwrap();
    base.refresh();
    assert_eq!(
        local_facts(dir.path()),
        None,
        "a whole read sees one bad line"
    );
    assert_eq!(facts_of(&base), None, "so does the incremental read");
}

#[test]
fn a_bad_requested_file_leaves_the_rows_not_read_but_the_chain_is_still_taken_in() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::new(dir.path().to_path_buf());
    std::fs::write(
        dir.path().join(crate::verdict_counts::REQUESTED_FILENAME),
        "{not json\n",
    )
    .unwrap();
    append_lines(dir.path(), &history()[..2]);
    base.refresh();
    assert_eq!(facts_of(&base), None);
    assert_eq!(base.scan.lock().unwrap().records.len(), 2);
}
