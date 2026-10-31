//! Two nodes' books, sealed the way the plugin seals them: the provider's
//! `settlement-bundle`, verified and paired against the payer's records.

use super::*;
use crate::capsule_emit::CapsuleState;
use crate::deal_receipt::tests::cut;
use crate::producer::capsule::SETTLEMENT_BLOCK_POINTER;
use crate::producer::jcs;
use crate::settlement_channel::parse_and_check;

fn hash(b: &str) -> String {
    b.repeat(32)
}

/// The exchange record naming `peer`, under the host id `exchange_id`.
fn exchange(state: &CapsuleState, exchange_id: &str, peer: &str) {
    let mut served = crate::capsule_emit::tests::sample_exchange(peer);
    served.exchange_id = Some(exchange_id);
    state.emit_for_exchange(&served).unwrap();
}

/// Seal one host-shaped `payment.lifecycle.v1` event on `state`.
fn seal(
    state: &CapsuleState,
    exchange_id: &str,
    role: &str,
    phase: &str,
    h: Option<&str>,
    amount: u64,
    wallet: Option<(u64, u64)>,
) {
    let settlement = phase.ends_with("_settlement_observed");
    let mut event = json!({
        "exchange_id": exchange_id,
        "event_ref": "",
        "terms_digest": "7d".repeat(32),
        "role": role,
        "phase": phase,
        "source": if settlement { "wallet_reported" } else { "provider_asserted" },
        "settlement": settlement.then_some("terminal"),
        "segment": 0,
        "payment_hash": h,
        "amount_msat": amount,
        "tokens": null,
    });
    if let Some((credited, fee)) = wallet {
        event["credited_msat"] = json!(credited);
        event["fee_msat"] = json!(fee);
    }
    event["event_ref"] = json!(jcs::json_digest(&event).unwrap());
    let checked = parse_and_check(&serde_json::to_vec(&event).unwrap()).unwrap();
    state
        .emit_settlement_record(&checked.observation())
        .unwrap();
}

/// Node `a` pays under its exchange `a-ex` with `b`.
fn paid(a: &CapsuleState, h: Option<&str>, amount: u64) {
    seal(
        a,
        "a-ex",
        "payer",
        "input_settlement_observed",
        h,
        amount,
        None,
    );
}

/// Node `b` receives under its exchange `b-ex` with `a`.
fn received(b: &CapsuleState, h: Option<&str>, wallet: Option<(u64, u64)>) {
    let amount = wallet.map_or(1000, |(c, f)| c + f);
    seal(
        b,
        "b-ex",
        "provider",
        "input_settlement_observed",
        h,
        amount,
        wallet,
    );
}

/// Two nodes, `a` and `b`, each holding its record of one exchange with the
/// other.
fn pair_of_nodes() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    CapsuleState,
    CapsuleState,
) {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (
        CapsuleState::open(da.path(), "a").unwrap(),
        CapsuleState::open(db.path(), "b").unwrap(),
    );
    exchange(&a, "a-ex", "b");
    exchange(&b, "b-ex", "a");
    (da, db, a, b)
}

fn key(state: &CapsuleState) -> String {
    crate::commitment::key_id(state.signing_key())
}

/// `state`'s settlement bundle for `peer`, after a checkpoint covers it.
fn bundle_for(state: &CapsuleState, peer: &str) -> Value {
    cut(state);
    let ids = select(state.ledger_dir(), &key(state), peer).unwrap().ids;
    let bundle = bundle(state.ledger_dir(), &key(state), &ids).unwrap();
    // It goes to the peer: its selection only, never the whole interval.
    crate::deal_receipt::tests::assert_selection_only(&bundle);
    bundle
}

/// The operator's registry naming `b` with `key`.
fn registry(peer: &str, key: &str) -> String {
    json!({ peer: key }).to_string()
}

/// `settlement_check`'s cross-check on `a` with `b`'s bundle, through the
/// production acceptance path.
fn check(a: &CapsuleState, b: &CapsuleState) -> Value {
    let reg = registry("b", &key(b));
    let books = books(a, Some(&reg), &BTreeMap::new(), &bundle_for(b, "a")).unwrap();
    cross_check(&books)
}

const WALLET: Option<(u64, u64)> = Some((995, 5));

#[test]
fn a_payment_both_books_hold_with_equal_amounts_pairs() {
    let (_da, _db, a, b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    received(&b, Some(&hash("aa")), WALLET);
    let r = check(&a, &b);
    assert_eq!(r["status"], "PASS", "{r:#}");
    assert_eq!(r["paired"], 1);
    assert_eq!(r["unpaired"], json!([]));
    assert_eq!(r["counterparty_key"], json!(key(&b)));
    assert_eq!(r["counterparty_peers"], json!(["b"]));
}

#[test]
fn both_books_disagreeing_on_a_payment_fails() {
    let (_da, _db, a, b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    received(&b, Some(&hash("aa")), Some((900, 5)));
    let r = check(&a, &b);
    assert_eq!(r["status"], "FAIL", "{r:#}");
    assert!(r["unpaired"][0]["reason"]
        .as_str()
        .unwrap()
        .starts_with("conflicting amounts"));
}

#[test]
fn an_incomplete_observation_does_not_hide_a_contradiction() {
    let (_da, _db, a, b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    received(&b, Some(&hash("aa")), Some((900, 0)));
    // A second, wallet-silent provider observation of the same payment.
    seal(
        &b,
        "b-ex",
        "provider",
        "input_settlement_observed",
        Some(&hash("aa")),
        901,
        None,
    );
    assert_eq!(check(&a, &b)["status"], "FAIL");
}

#[test]
fn an_incomplete_observation_alone_is_inconclusive() {
    let (_da, _db, a, b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    received(&b, Some(&hash("aa")), None);
    let r = check(&a, &b);
    assert_eq!(r["status"], "INCONCLUSIVE", "{r:#}");
}

#[test]
fn both_books_naming_the_same_role_fails() {
    let (_da, _db, a, b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    seal(
        &b,
        "b-ex",
        "payer",
        "input_settlement_observed",
        Some(&hash("aa")),
        1000,
        None,
    );
    assert_eq!(check(&a, &b)["status"], "FAIL");
}

#[test]
fn a_payment_one_book_holds_is_unpaired_not_failed() {
    let (_da, _db, a, b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    received(&b, Some(&hash("aa")), WALLET);
    paid(&a, Some(&hash("cc")), 2000);
    received(&b, Some(&hash("dd")), Some((300, 0)));
    let r = check(&a, &b);
    assert_eq!(r["status"], "INCONCLUSIVE", "{r:#}");
    assert_eq!(r["paired"], 1);
    assert_eq!(
        r["unpaired"],
        json!([
            {"payment_hash": hash("cc"), "reason": "recorded by this node only"},
            {"payment_hash": hash("dd"), "reason": "recorded by the counterparty only"},
        ])
    );
}

#[test]
fn a_settlement_with_no_hash_keeps_the_count_from_passing() {
    let (_da, _db, a, b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    received(&b, Some(&hash("aa")), WALLET);
    paid(&a, None, 500);
    let r = check(&a, &b);
    assert_eq!(r["status"], "INCONCLUSIVE", "{r:#}");
    assert_eq!(
        r["settlements_without_payment_hash"],
        json!({"this_node": 1, "counterparty": 0})
    );
    received(&b, None, WALLET);
    let r = check(&a, &b);
    assert_eq!(r["settlements_without_payment_hash"]["counterparty"], 1);
}

#[test]
fn a_settlement_of_this_node_that_names_no_peer_keeps_the_count_from_passing() {
    let (_da, _db, a, b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    received(&b, Some(&hash("aa")), WALLET);
    seal(
        &a,
        "orphan-ex",
        "payer",
        "input_settlement_observed",
        Some(&hash("ee")),
        10,
        None,
    );
    let r = check(&a, &b);
    assert_eq!(r["status"], "INCONCLUSIVE", "{r:#}");
    assert_eq!(r["settlements_unattributed"], 1);
    assert_eq!(
        r["unpaired"],
        json!([]),
        "an orphan is never shown as one-sided"
    );
}

#[test]
fn the_bundle_carries_this_peers_terminal_settlements_only() {
    let (_da, _db, _a, b) = pair_of_nodes();
    exchange(&b, "c-ex", "c");
    seal(
        &b,
        "b-ex",
        "provider",
        "input_invoice_issued",
        Some(&hash("aa")),
        1000,
        None,
    );
    received(&b, Some(&hash("aa")), WALLET);
    seal(
        &b,
        "c-ex",
        "provider",
        "input_settlement_observed",
        Some(&hash("cc")),
        70,
        Some((70, 0)),
    );
    let bundle = bundle_for(&b, "a");
    let records = bundle["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{bundle:#}");
    let block = records[0].pointer(SETTLEMENT_BLOCK_POINTER).unwrap();
    assert_eq!(block["phase"], "input_settlement_observed");
    assert_eq!(block["payment_hash"], json!(hash("aa")));
}

#[test]
fn the_records_chosen_are_the_records_bundled_even_if_one_is_sealed_between() {
    let (_da, _db, _a, b) = pair_of_nodes();
    received(&b, Some(&hash("aa")), WALLET);
    let ids = select(b.ledger_dir(), &key(&b), "a").unwrap().ids;
    cut(&b);
    // Sealed after the selection and after the checkpoint: not carried, and
    // no refusal for want of a checkpoint over it.
    received(&b, Some(&hash("bb")), WALLET);
    let bundle = bundle(b.ledger_dir(), &key(&b), &ids).unwrap();
    assert_eq!(bundle["records"].as_array().unwrap().len(), 1);
}

#[test]
fn no_settlement_and_no_checkpoint_are_refusals() {
    let (_da, _db, _a, b) = pair_of_nodes();
    let none = select(b.ledger_dir(), &key(&b), "a").unwrap().ids;
    assert!(matches!(
        bundle(b.ledger_dir(), &key(&b), &none),
        Err(Failure::Refused(Refusal::NoSettlement))
    ));
    received(&b, Some(&hash("aa")), WALLET);
    let ids = select(b.ledger_dir(), &key(&b), "a").unwrap().ids;
    assert!(matches!(
        bundle(b.ledger_dir(), &key(&b), &ids),
        Err(Failure::Refused(Refusal::NotCheckpointed))
    ));
}

#[test]
fn this_nodes_own_bundle_is_refused_even_when_its_key_is_listed_as_a_peer() {
    let (_da, _db, a, _b) = pair_of_nodes();
    paid(&a, Some(&hash("aa")), 1000);
    let own = bundle_for(&a, "b");
    let reg = registry("b", &key(&a));
    assert!(books(&a, Some(&reg), &BTreeMap::new(), &own).is_err());
}

#[test]
fn a_bundle_under_a_key_no_peer_is_accepted_for_is_refused() {
    let (_da, _db, a, b) = pair_of_nodes();
    received(&b, Some(&hash("aa")), WALLET);
    let bundle = bundle_for(&b, "a");
    assert!(books(&a, None, &BTreeMap::new(), &bundle).is_err());
}

#[test]
fn a_tampered_record_is_refused() {
    let (_da, _db, a, b) = pair_of_nodes();
    received(&b, Some(&hash("aa")), WALLET);
    let mut bundle = bundle_for(&b, "a");
    bundle["records"][0]["model_attestation"]["compute_attestation"]["x-mesh-settlement-v1"]
        ["amount_msat"] = json!(1);
    let reg = registry("b", &key(&b));
    assert!(books(&a, Some(&reg), &BTreeMap::new(), &bundle).is_err());
}

#[test]
fn the_report_names_why_the_count_was_not_cross_checked() {
    let absent = crate::settlement_adapter::report(Vec::new(), None, None);
    assert_eq!(absent["counterparty_count"]["status"], "NOT_PRESENT");
    let failed =
        crate::settlement_adapter::report(Vec::new(), None, Some(Err("did not verify".into())));
    assert_eq!(failed["counterparty_count"]["status"], "NOT_CHECKED");
    assert_eq!(failed["counterparty_count"]["reason"], "did not verify");
    assert_eq!(failed["public_ledger_count"]["status"], "NOT_CHECKED");
}

#[test]
fn an_incomplete_observation_in_the_other_book_does_not_hide_a_role_contradiction() {
    let (_da, _db, a, b) = pair_of_nodes();
    // Both books claim to be the payee; only one has the wallet's numbers.
    seal(
        &a,
        "a-ex",
        "provider",
        "input_settlement_observed",
        Some(&hash("aa")),
        1000,
        WALLET,
    );
    received(&b, Some(&hash("aa")), None);
    assert_eq!(check(&a, &b)["status"], "FAIL");
}

#[test]
fn a_nonce_equal_to_another_exchange_id_does_not_move_a_settlement_to_its_peer() {
    let (_da, _db, _a, b) = pair_of_nodes();
    // b's exchange with c carries a client nonce equal to b's exchange id
    // with a: the settlement under `b-ex` is still a's, never c's.
    let mut with_c = crate::capsule_emit::tests::sample_exchange("c");
    with_c.exchange_id = Some("c-ex");
    with_c.client_nonce = Some("b-ex");
    b.emit_for_exchange(&with_c).unwrap();
    received(&b, Some(&hash("aa")), WALLET);
    let for_c = select(b.ledger_dir(), &key(&b), "c").unwrap();
    assert_eq!(for_c.ids, Vec::<String>::new());
    assert_eq!(select(b.ledger_dir(), &key(&b), "a").unwrap().ids.len(), 1);
}

#[test]
fn an_exchange_id_two_peers_name_belongs_to_neither() {
    let (_da, _db, _a, b) = pair_of_nodes();
    exchange(&b, "b-ex", "c");
    received(&b, Some(&hash("aa")), WALLET);
    let for_a = select(b.ledger_dir(), &key(&b), "a").unwrap();
    assert!(for_a.ids.is_empty());
    assert_eq!(for_a.unattributed, 1);
}
