//! This plugin's `config_schema` declaration for
//! the one sharing-policy object -- one key
//! (`docs/SHARING-POLICY.md`). Declaring it here
//! makes mesh's console render the switches under Configuration >
//! Plugins with the host's own controls -- nothing here is a score, and
//! nothing here ranks anyone.
//!
//! **How a console value reaches the plugin.** mesh-llm saves what the
//! operator sets in the console to its config file (this plugin's
//! `[plugin.settings]`) and does not pass it to the plugin process (no env,
//! no protocol message). `crate::settings::var` reads it there when the
//! environment does not set the setting. Each key is its env var's suffix
//! lower-cased (`share_record_at_completion` ->
//! `CAPSULES_SHARE_RECORD_AT_COMPLETION`), except `witness`, which
//! is `CAPSULES_CHECKPOINT_WITNESS_URLS`. The witness is read when
//! the plugin starts: restart mesh-llm after changing it.
//!
//! The same schema also declares the opt-in stop-routing rule's two settings,
//! under "When answers differ" with the referee's, on the same
//! env-var convention: `CAPSULES_STOP_ROUTING_AFTER_CONTRADICTIONS`
//! (off unless set) and `CAPSULES_STOP_ROUTING_WINDOW_DAYS`.

use mesh_llm_plugin::{
    config_array, config_enum, config_integer, config_object, config_object_property,
    config_schema, config_setting, config_string, config_url, ManifestEntry,
};

pub const RECORD_AT_COMPLETION_KEY: &str = "share_record_at_completion";
pub const HISTORY_SEGMENTS_KEY: &str = "share_history_segments";
pub const ADJUDICATIONS_KEY: &str = "share_adjudications";
pub const WITNESS_KEY: &str = "witness";

/// Shown greyed in the Witnesses field as a suggestion. Not a default: the
/// plugin contacts no witness until the user clicks Set (or types one).
pub const SUGGESTED_WITNESS_URL: &str = "https://witness.agentactioncapsule.org";
/// The rest of Standard Service History (`service_history/1` and other
/// derivations) to a requester that is not this node's counterparty.
/// Checkpoints and `history_card/1` are stranger-safe and not gated by it.
pub const STANDARD_HISTORY_KEY: &str = "share_standard_history";
/// `exchange_corroboration/1` (one exchange's half digests) to a requester
/// that no record of this node names as its counterparty.
pub const EXCHANGE_CORROBORATION_KEY: &str = "share_exchange_corroboration";
/// Whether this node advertises that it answers evidence requests at all.
pub const ADVERTISE_EVIDENCE_REQUESTS_KEY: &str = "advertise_evidence_requests";
/// The opt-in stop-routing rule (`routing_rule`): N, and D in days. Same
/// env-suffix convention (`CAPSULES_STOP_ROUTING_*`).
pub const STOP_ROUTING_AFTER_KEY: &str = "stop_routing_after_contradictions";
pub const STOP_ROUTING_WINDOW_KEY: &str = "stop_routing_window_days";
/// The referee (`crate::referee`): whether a differing twin pair asks one
/// (off unless set to on), and the bar window after a contradiction, in days.
/// Same env-suffix convention (`CAPSULES_ADJUDICATE_DIFFERING_TWINS`,
/// `CAPSULES_REFEREE_BAR_DAYS`).
pub const ADJUDICATE_DIFFERING_TWINS_KEY: &str = "adjudicate_differing_twins";
pub const REFEREE_BAR_DAYS_KEY: &str = "referee_bar_days";

/// This process's own runtime env var for `share_record_at_completion` --
/// see the module doc's "declarative only" note: no live host->plugin
/// config channel exists yet, so an operator sets this directly on the
/// node.
pub const ENV_RECORD_AT_COMPLETION: &str = "CAPSULES_SHARE_RECORD_AT_COMPLETION";

/// Whether this process's `share_record_at_completion` is off. Unset or
/// `counterparty` is the default, on (#68): a node pushes its
/// sealed record of a completed exchange to the counterparty, and accepts the
/// counterparty's push. `off`, and any value this plugin does not know, is off:
/// a typo never widens what is shared.
pub fn record_at_completion_is_off() -> bool {
    record_at_completion_is_off_from(crate::settings::var(ENV_RECORD_AT_COMPLETION))
}

pub(crate) fn record_at_completion_is_off_from(read: Result<String, std::env::VarError>) -> bool {
    match read {
        Ok(raw) => record_at_completion_is_off_for(Some(&raw)),
        Err(std::env::VarError::NotPresent) => record_at_completion_is_off_for(None),
        // A value that is not valid Unicode is a value the operator set and
        // this plugin cannot read: off, never the default.
        Err(std::env::VarError::NotUnicode(_)) => true,
    }
}

pub(crate) fn record_at_completion_is_off_for(raw: Option<&str>) -> bool {
    !matches!(normalized(raw).as_deref(), None | Some("counterparty"))
}

/// A switch's value as the operator meant it: trimmed and lower-cased;
/// empty is no value.
pub(crate) fn normalized(raw: Option<&str>) -> Option<String> {
    raw.map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty())
}

/// This process's own env var for `share_history_segments`.
pub const ENV_HISTORY_SEGMENTS: &str = "CAPSULES_SHARE_HISTORY_SEGMENTS";

/// `prospective`, deprecated: it never served anyone `counterparties` does
/// not, so it is read as `counterparties` and a log line says so. The one
/// place the old value is resolved.
const DEPRECATED_PROSPECTIVE: &str = "prospective";

/// Who may read one of this node's records back: `off`, `counterparties` or
/// `peers`. Unset is the documented default, `counterparties`; `prospective`
/// is read as `counterparties`; an unknown value is `off`, never wider.
pub fn history_segments() -> &'static str {
    history_segments_for(crate::settings::var(ENV_HISTORY_SEGMENTS).ok().as_deref())
}

pub(crate) fn history_segments_for(raw: Option<&str>) -> &'static str {
    match normalized(raw).as_deref() {
        None | Some("counterparties") => "counterparties",
        Some(DEPRECATED_PROSPECTIVE) => {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                tracing::warn!(
                    setting = ENV_HISTORY_SEGMENTS,
                    "prospective is deprecated and read as counterparties, which it always behaved as; set counterparties"
                );
            });
            "counterparties"
        }
        Some("peers") => "peers",
        // "off", and anything this plugin does not know: never wider than
        // the operator could have meant (`setting_problems` says so).
        Some(_) => "off",
    }
}

/// This process's own env var for `share_standard_history`.
pub const ENV_STANDARD_HISTORY: &str = "CAPSULES_SHARE_STANDARD_HISTORY";

/// Whether the rest of Standard Service History (not checkpoints or
/// `history_card/1`, which go to anyone) goes to a requester that is not
/// this node's counterparty: only when the operator turned it on. Off by
/// default; a counterparty is answered either way. This process's value is
/// `commitment::Policy::current`'s.
pub(crate) fn shares_standard_history_for(raw: Option<&str>) -> bool {
    switched_on(raw)
}

/// This process's own env var for `advertise_evidence_requests`: off unless
/// switched on (`on`, `1`, `true` or `yes`). This version has nothing that
/// advertises evidence requests, so nothing reads it yet: the plugin's
/// `evidence-request/1` channel is declared only to its own host, so that a
/// request can reach it, and mesh-llm does not pass a plugin's channels on to
/// other nodes. The signed disclosure policy states its value.
pub const ENV_ADVERTISE_EVIDENCE_REQUESTS: &str = "CAPSULES_ADVERTISE_EVIDENCE_REQUESTS";

/// Whether this node advertises that it answers evidence requests.
pub(crate) fn advertises_evidence_requests_for(raw: Option<&str>) -> bool {
    switched_on(raw)
}

/// Whether `exchange_corroboration/1` goes to a requester that is not this
/// node's counterparty: on by default (unset or empty), off when the operator
/// turned it off or set a value this plugin does not know. A setting of its
/// own: `share_standard_history` never releases it.
pub(crate) fn shares_exchange_corroboration_for(raw: Option<&str>) -> bool {
    normalized(raw).is_none() || switched_on(raw)
}

/// This process's own env var for `share_exchange_corroboration`.
pub const ENV_EXCHANGE_CORROBORATION: &str = "CAPSULES_SHARE_EXCHANGE_CORROBORATION";

/// An on/off switch: on only for `on` (or `1`, `true`, `yes`); unset and
/// anything else is off.
pub(crate) fn switched_on(raw: Option<&str>) -> bool {
    matches!(
        normalized(raw).as_deref(),
        Some("on" | "1" | "true" | "yes")
    )
}

/// The sharing switches set to a value this plugin does not know, each read
/// as off: for the page, so a typo is seen rather than silently obeyed.
pub fn setting_problems() -> Vec<String> {
    const ON_OFF: &[&str] = &["on", "off", "1", "0", "true", "false", "yes", "no"];
    let known: [(&str, &[&str]); 9] = [
        (ENV_RECORD_AT_COMPLETION, &["counterparty", "off"]),
        (
            ENV_HISTORY_SEGMENTS,
            &["counterparties", DEPRECATED_PROSPECTIVE, "peers", "off"],
        ),
        (ENV_STANDARD_HISTORY, ON_OFF),
        (ENV_EXCHANGE_CORROBORATION, ON_OFF),
        (ENV_ADVERTISE_EVIDENCE_REQUESTS, ON_OFF),
        (ENV_ADJUDICATIONS, &["deliver_to_subjects", "off"]),
        (
            crate::referee::request::ENV_ADJUDICATE_DIFFERING_TWINS,
            ON_OFF,
        ),
        (crate::checkpoint_cadence::ENV_ENABLE, ON_OFF),
        (crate::network_join::ENV_JOIN_NETWORK, ON_OFF),
    ];
    known
        .iter()
        .filter_map(|(env, values)| {
            let value = normalized(crate::settings::var(env).ok().as_deref())?;
            (!values.contains(&value.as_str())).then(|| {
                format!(
                    "{env} is {value:?}, which is not one of {}; it is read as off",
                    values.join(", ")
                )
            })
        })
        .collect()
}

/// This process's own env var for `share_adjudications`.
pub const ENV_ADJUDICATIONS: &str = "CAPSULES_SHARE_ADJUDICATIONS";

/// Deliver a verdict to the nodes it judges: the default (unset or empty), and
/// whenever the operator set `share_adjudications` to `deliver_to_subjects`;
/// `off` or an unknown value does not.
pub fn adjudications_delivered() -> bool {
    adjudications_delivered_for(crate::settings::var(ENV_ADJUDICATIONS).ok().as_deref())
}

pub(crate) fn adjudications_delivered_for(raw: Option<&str>) -> bool {
    normalized(raw).is_none_or(|v| v == "deliver_to_subjects")
}

// The console groups, in the order the Configuration page shows them. The
// Admission group is not declared: none of the admission settings the design
// shows (ask or require a peer's card, records or corroboration; what to do
// on a decline or a gap) has a reader in this plugin yet.
// `category_order` is the group's own place (the 4th argument of `.category`);
// `.order(n)` is the row's, rising through the whole list so the rows follow the
// design even where the console shows one flat list.
const SHOW_CATEGORY_ID: &str = "show";
const SHOW_CATEGORY_LABEL: &str = "What you show others";
const SHOW_CATEGORY_SUMMARY: &str = "What this node answers when a peer asks about you. \
     Peers can only admit you on what you let them see.";

const DIFFER_CATEGORY_ID: &str = "differ";
const DIFFER_CATEGORY_LABEL: &str = "When answers differ";
const DIFFER_CATEGORY_SUMMARY: &str = "A client can send one request to two machines. These \
    settings decide what happens when the two answers don't match.";

const RECORDS_CATEGORY_ID: &str = "records";
const RECORDS_CATEGORY_LABEL: &str = "Keeping records";
const RECORDS_CATEGORY_SUMMARY: &str = "Who else holds a copy of what you sealed. This is what \
    makes a later rewrite provable by someone other than you.";

/// The join switch's label in the console.
pub const JOIN_NETWORK_LABEL: &str = "Join the evidence network";

const NETWORK_CATEGORY_ID: &str = "network";
const NETWORK_CATEGORY_LABEL: &str = "Evidence network";
const NETWORK_CATEGORY_SUMMARY: &str =
    "Whether this node is on the evidence network's list. Off by default.";

/// The `config_schema` manifest entry naming the sharing switches and the other settings. Attach with
/// `DeclarativePluginBuilder::config_item`.
///
/// Every choice list names its default FIRST. mesh-llm 0.78's console does not
/// receive a plugin setting's declared default, so it takes the first choice
/// as the default: it shows that choice for an unset setting and leaves it out
/// of the saved config. With the default first, an unset setting shows its
/// real value and every other choice is saved. Pinned by
/// `every_choice_list_names_its_default_first`.
pub fn share_policy_config_schema(plugin_id: &str) -> ManifestEntry {
    config_schema(plugin_id)
        // What you show others.
        .setting(
            config_setting(
                HISTORY_SEGMENTS_KEY,
                config_enum(["counterparties", DEPRECATED_PROSPECTIVE, "peers", "off"]),
            )
            .default_value(&"counterparties")
            .description(
                "Who may read your records and correlations: past counterparties (the \
                 default), any peer, or nobody. prospective is deprecated and read as \
                 counterparties. A refusal says nothing about the peer asking.",
            )
            .label("History segments")
            .category(SHOW_CATEGORY_ID, SHOW_CATEGORY_LABEL, SHOW_CATEGORY_SUMMARY, 0)
                .order(0),
        )
        .setting(
            config_setting(STANDARD_HISTORY_KEY, config_enum(["off", "on"]))
                .default_value(&"off")
                .description(
                    "Answer a node you've never dealt with when it asks what you serve. No \
                     records are included. Checkpoints and the history card go to anyone who \
                     asks, whatever this is set to.",
                )
                .label("Service history to strangers")
                .category(SHOW_CATEGORY_ID, SHOW_CATEGORY_LABEL, SHOW_CATEGORY_SUMMARY, 0)
                .order(1),
        )
        .setting(
            config_setting(EXCHANGE_CORROBORATION_KEY, config_enum(["on", "off"]))
                .default_value(&"on")
                .description(
                    "Tell a stranger whether you hold your half of one exchange, by its nonce. \
                     Ids and digests only, never who was on the other side.",
                )
                .label("Exchange corroboration")
                .category(SHOW_CATEGORY_ID, SHOW_CATEGORY_LABEL, SHOW_CATEGORY_SUMMARY, 0)
                .order(2),
        )
        .setting(
            config_setting(ADVERTISE_EVIDENCE_REQUESTS_KEY, config_enum(["off", "on"]))
                .default_value(&"off")
                .description("Coming: this version advertises nothing and no node reads this yet, so it stays off.")
                .label("Advertise evidence requests")
                .category(SHOW_CATEGORY_ID, SHOW_CATEGORY_LABEL, SHOW_CATEGORY_SUMMARY, 0)
                .order(3),
        )
        // When answers differ.
        .setting(
            config_setting(ADJUDICATE_DIFFERING_TWINS_KEY, config_enum(["off", "on"]))
                .default_value(&"off")
                .description(
                    "Send the prompt and both answers to a third node to re-answer. Once per \
                     pair, never retried. Only you turn this on.",
                )
                .label("Ask a referee")
                .category(DIFFER_CATEGORY_ID, DIFFER_CATEGORY_LABEL, DIFFER_CATEGORY_SUMMARY, 1)
                .order(4),
        )
        .setting(
            config_setting(STOP_ROUTING_AFTER_KEY, config_integer())
                .description(
                    "Stop routing to a peer after this many contradictions (0 or empty: never, \
                     the default). Only verdicts you asked for and signature-checked count, \
                     once per referee and pair. With N of 2 or more, no single referee can \
                     trigger it. Needs `allow_peer_blocks = true` for this plugin in mesh-llm's config.",
                )
                .label("Stop routing after N contradictions")
                .category(DIFFER_CATEGORY_ID, DIFFER_CATEGORY_LABEL, DIFFER_CATEGORY_SUMMARY, 1)
                .order(5),
        )
        .setting(
            config_setting(STOP_ROUTING_WINDOW_KEY, config_integer())
                .default_value(&30)
                .description("The window, in days, the contradictions must fall in (default 30).")
                .label("In D days")
                .category(DIFFER_CATEGORY_ID, DIFFER_CATEGORY_LABEL, DIFFER_CATEGORY_SUMMARY, 1)
                .order(6),
        )
        .setting(
            config_setting(REFEREE_BAR_DAYS_KEY, config_integer())
                .default_value(&30)
                .description(
                    "After a referee-signed contradiction for a model, don't ask that node to \
                     referee that model for this many days (default 30).",
                )
                .label("Bar a contradicted referee for")
                .category(DIFFER_CATEGORY_ID, DIFFER_CATEGORY_LABEL, DIFFER_CATEGORY_SUMMARY, 1)
                .order(7),
        )
        .setting(
            config_setting(ADJUDICATIONS_KEY, config_enum(["deliver_to_subjects", "off"]))
                .default_value(&"deliver_to_subjects")
                .description(
                    "They ack or dispute on their own side. Delivery only, never a standing. \
                     A verdict already delivered cannot be recalled by turning this off.",
                )
                .label("Deliver verdicts to the nodes judged")
                .category(DIFFER_CATEGORY_ID, DIFFER_CATEGORY_LABEL, DIFFER_CATEGORY_SUMMARY, 1)
                .order(8),
        )
        // Keeping records.
        .setting(
            config_setting(RECORD_AT_COMPLETION_KEY, config_enum(["counterparty", "off"]))
                .default_value(&"counterparty")
                .description(
                    "Push your sealed record of each exchange to the counterparty. Symmetric: \
                     off means you don't receive theirs either. It governs pushes only: a \
                     record you ask the other side for is checked and held either way. With \
                     checkpointing on, the push carries a checkpoint, which shows your log's size and time; the \
                     public checkpoint list shows when your exchanges ended.",
                )
                .label("Send your record to the other side")
                .category(RECORDS_CATEGORY_ID, RECORDS_CATEGORY_LABEL, RECORDS_CATEGORY_SUMMARY, 2)
                .order(9),
        )
        .setting(
            config_setting(
                WITNESS_KEY,
                config_array(config_object([
                    config_object_property("endpoint", config_url())
                        .required(true)
                        .description("The witness service's URL.")
                        .into(),
                    config_object_property("public_key", config_string())
                        .description(
                            "The witness's Ed25519 public key in hex, as its operator publishes it. Leave empty to have the plugin fetch it from the witness once and keep it; the Evidence page then says the key was pinned on first contact, not configured.",
                        )
                        .into(),
                ])),
            )
            .description(
                "Witness services to offer this node's checkpoints to: each one's URL, and its public key if you have it. Empty is off (the default): there is no default witness, and the plugin contacts none until you add one. The Evidence page shows what each witness holds. Takes effect when mesh-llm is restarted.",
            )
                .label("Witnesses")
                // The console shows this greyed with a Set button (the generic
                // `set-value` renderer); nothing is stored until Set is clicked,
                // so there is still no default witness. The URL answers
                // `GET /anchor/authority-pubkey` with `pubkey_hex` and `key_id`,
                // which is what `witness_status::fetch_key` reads.
                .placeholder(SUGGESTED_WITNESS_URL)
                .renderer_id("set-value")
                .category(RECORDS_CATEGORY_ID, RECORDS_CATEGORY_LABEL, RECORDS_CATEGORY_SUMMARY, 2)
                .order(10),
        )
        .setting(
            // The statement, byte for byte, as Steven approved it (loop's
            // joins/SWITCH_CONSENT.txt); a join signs its digest.
            config_setting(crate::network_join::JOIN_NETWORK_KEY, config_enum(["off", "on"]))
                .default_value(&"off")
                .description(crate::network_join::SWITCH_CONSENT)
                .label(JOIN_NETWORK_LABEL)
                .category(NETWORK_CATEGORY_ID, NETWORK_CATEGORY_LABEL, NETWORK_CATEGORY_SUMMARY, 3)
                .order(11),
        )
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_llm_plugin::proto;

    fn as_config_schema(entry: ManifestEntry) -> proto::PluginConfigSchemaManifest {
        match entry {
            ManifestEntry::ConfigSchema(schema) => schema,
            other => panic!("expected ManifestEntry::ConfigSchema, got {other:?}"),
        }
    }

    #[test]
    fn declares_all_four_switches_under_the_plugin_id() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        assert_eq!(schema.plugin_name, "capsules");
        let keys: Vec<&str> = schema.settings.iter().map(|s| s.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                HISTORY_SEGMENTS_KEY,
                STANDARD_HISTORY_KEY,
                EXCHANGE_CORROBORATION_KEY,
                ADVERTISE_EVIDENCE_REQUESTS_KEY,
                ADJUDICATE_DIFFERING_TWINS_KEY,
                STOP_ROUTING_AFTER_KEY,
                STOP_ROUTING_WINDOW_KEY,
                REFEREE_BAR_DAYS_KEY,
                ADJUDICATIONS_KEY,
                RECORD_AT_COMPLETION_KEY,
                WITNESS_KEY,
                crate::network_join::JOIN_NETWORK_KEY
            ]
        );
    }

    /// The page's groups and labels, in the order the console shows them.
    /// Pinned on purpose: this is the regroup the Configuration design asks for.
    #[test]
    fn settings_are_grouped_and_labelled_as_the_configuration_design_shows() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        let rows: Vec<(String, String, String)> = schema
            .settings
            .iter()
            .map(|s| {
                let p = s.presentation.as_ref().expect("every setting is presented");
                (
                    p.category_label.clone().unwrap_or_default(),
                    p.label.clone().unwrap_or_default(),
                    s.key.clone(),
                )
            })
            .collect();
        let row = |c: &str, l: &str, k: &str| (c.to_string(), l.to_string(), k.to_string());
        assert_eq!(
            rows,
            vec![
                row(
                    "What you show others",
                    "History segments",
                    HISTORY_SEGMENTS_KEY
                ),
                row(
                    "What you show others",
                    "Service history to strangers",
                    STANDARD_HISTORY_KEY
                ),
                row(
                    "What you show others",
                    "Exchange corroboration",
                    EXCHANGE_CORROBORATION_KEY
                ),
                row(
                    "What you show others",
                    "Advertise evidence requests",
                    ADVERTISE_EVIDENCE_REQUESTS_KEY
                ),
                row(
                    "When answers differ",
                    "Ask a referee",
                    ADJUDICATE_DIFFERING_TWINS_KEY
                ),
                row(
                    "When answers differ",
                    "Stop routing after N contradictions",
                    STOP_ROUTING_AFTER_KEY
                ),
                row("When answers differ", "In D days", STOP_ROUTING_WINDOW_KEY),
                row(
                    "When answers differ",
                    "Bar a contradicted referee for",
                    REFEREE_BAR_DAYS_KEY
                ),
                row(
                    "When answers differ",
                    "Deliver verdicts to the nodes judged",
                    ADJUDICATIONS_KEY
                ),
                row(
                    "Keeping records",
                    "Send your record to the other side",
                    RECORD_AT_COMPLETION_KEY
                ),
                row("Keeping records", "Witnesses", WITNESS_KEY),
                row(
                    "Evidence network",
                    JOIN_NETWORK_LABEL,
                    crate::network_join::JOIN_NETWORK_KEY
                ),
            ]
        );
    }

    /// A console may show one flat list sorted by `category_order`, then
    /// `setting_order`: groups carry one fixed place each and rows one rising
    /// number, so both ways of showing the page follow the design.
    #[test]
    fn rows_carry_one_rising_order_and_each_group_one_place() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        let mut group_place = std::collections::BTreeMap::new();
        for (i, s) in schema.settings.iter().enumerate() {
            let p = s.presentation.as_ref().unwrap();
            assert_eq!(p.setting_order, Some(i as u32), "{}", s.key);
            let place = p.category_order.expect("a group place");
            let seen = group_place.entry(p.category_id.clone()).or_insert(place);
            assert_eq!(*seen, place, "{}: one place per group", s.key);
        }
        let places: Vec<u32> = schema
            .settings
            .iter()
            .map(|s| s.presentation.as_ref().unwrap().category_order.unwrap())
            .collect();
        assert!(places.windows(2).all(|w| w[0] <= w[1]), "{places:?}");
    }

    /// Wording that carries a disclosure or a requirement stays in the text.
    #[test]
    fn descriptions_keep_their_disclosures_and_requirements() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        let text = |k: &str| {
            schema
                .settings
                .iter()
                .find(|s| s.key == k)
                .and_then(|s| s.description.clone())
                .unwrap()
        };
        assert!(text(STOP_ROUTING_AFTER_KEY).contains("`allow_peer_blocks = true`"));
        assert!(!text(STOP_ROUTING_AFTER_KEY).contains("Peer block requests"));
        assert!(text(ADVERTISE_EVIDENCE_REQUESTS_KEY).contains("advertises nothing"));
        let record = text(RECORD_AT_COMPLETION_KEY);
        assert!(record.contains("With checkpointing on"));
        assert!(record.contains("when your exchanges ended"));
        assert!(
            text(STANDARD_HISTORY_KEY).contains("Checkpoints and the history card go to anyone")
        );
        let segments = text(HISTORY_SEGMENTS_KEY);
        assert!(segments.contains("prospective is deprecated"));
        assert!(!segments.contains("recent"));
        for s in &schema.settings {
            let summary = s.presentation.as_ref().unwrap().category_summary.clone();
            assert!(
                !summary.unwrap_or_default().contains("Admission"),
                "{}",
                s.key
            );
        }
    }

    /// No stored config changes meaning: every key keeps its default and its
    /// choices, and no key was added.
    #[test]
    fn keys_choices_and_defaults_are_unchanged() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        let got: Vec<(String, Option<String>, Vec<String>)> = schema
            .settings
            .iter()
            .map(|s| {
                (
                    s.key.clone(),
                    s.default_json.clone(),
                    s.value_schema
                        .as_ref()
                        .map(|v| v.enum_values.clone())
                        .unwrap_or_default(),
                )
            })
            .collect();
        let v = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let expected: Vec<(&str, Option<&str>, Vec<String>)> = vec![
            (
                HISTORY_SEGMENTS_KEY,
                Some("\"counterparties\""),
                v(&["counterparties", "prospective", "peers", "off"]),
            ),
            (STANDARD_HISTORY_KEY, Some("\"off\""), v(&["off", "on"])),
            (
                EXCHANGE_CORROBORATION_KEY,
                Some("\"on\""),
                v(&["on", "off"]),
            ),
            (
                ADVERTISE_EVIDENCE_REQUESTS_KEY,
                Some("\"off\""),
                v(&["off", "on"]),
            ),
            (
                ADJUDICATE_DIFFERING_TWINS_KEY,
                Some("\"off\""),
                v(&["off", "on"]),
            ),
            (STOP_ROUTING_AFTER_KEY, None, v(&[])),
            (STOP_ROUTING_WINDOW_KEY, Some("30"), v(&[])),
            (REFEREE_BAR_DAYS_KEY, Some("30"), v(&[])),
            (
                ADJUDICATIONS_KEY,
                Some("\"deliver_to_subjects\""),
                v(&["deliver_to_subjects", "off"]),
            ),
            (
                RECORD_AT_COMPLETION_KEY,
                Some("\"counterparty\""),
                v(&["counterparty", "off"]),
            ),
            (WITNESS_KEY, None, v(&[])),
            (
                crate::network_join::JOIN_NETWORK_KEY,
                Some("\"off\""),
                v(&["off", "on"]),
            ),
        ];
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(k, d, e)| (k.to_string(), d.map(str::to_string), e))
            .collect();
        assert_eq!(got, expected);
    }

    /// Missing capsules are never described with the word "chain", in any
    /// setting's label or text or any group's summary.
    #[test]
    fn no_description_says_chain() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        for s in &schema.settings {
            let p = s.presentation.as_ref().unwrap();
            let texts = [
                s.description.clone().unwrap_or_default(),
                p.category_summary.clone().unwrap_or_default(),
                p.label.clone().unwrap_or_default(),
            ];
            for text in texts {
                assert!(
                    !text.to_lowercase().contains("chain"),
                    "{}: {text:?}",
                    s.key
                );
            }
        }
    }

    /// mesh-llm 0.78's console takes a choice list's first value as the
    /// setting's default (it does not receive the declared one). Listing the
    /// declared default first keeps what the console shows and saves equal to
    /// what this plugin does.
    #[test]
    fn every_choice_list_names_its_default_first() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        let mut checked = 0;
        for setting in &schema.settings {
            let Some(values) = setting
                .value_schema
                .as_ref()
                .map(|v| &v.enum_values)
                .filter(|v| !v.is_empty())
            else {
                continue;
            };
            let default: String =
                serde_json::from_str(setting.default_json.as_deref().unwrap_or_else(|| {
                    panic!("{} is a choice with no declared default", setting.key)
                }))
                .expect("default_json is a JSON string");
            assert_eq!(
                values[0], default,
                "{}: the first choice must be the default",
                setting.key
            );
            checked += 1;
        }
        assert_eq!(checked, 8, "the eight choice settings were checked");
    }

    #[test]
    fn the_referee_settings_are_the_env_names_the_referee_reads() {
        assert_eq!(
            format!("CAPSULES_{}", ADJUDICATE_DIFFERING_TWINS_KEY.to_uppercase()),
            crate::referee::request::ENV_ADJUDICATE_DIFFERING_TWINS
        );
        assert_eq!(
            format!("CAPSULES_{}", REFEREE_BAR_DAYS_KEY.to_uppercase()),
            crate::referee::bar::ENV_REFEREE_BAR_DAYS
        );
    }

    #[test]
    fn history_segments_defaults_to_counterparties_reads_the_three_tiers_and_unknown_is_off() {
        assert_eq!(history_segments_for(None), "counterparties");
        assert_eq!(
            history_segments_for(Some("bogus")),
            "off",
            "an unknown value never widens"
        );
        for tier in ["off", "counterparties", "peers"] {
            assert_eq!(history_segments_for(Some(tier)), tier);
        }
    }

    /// `prospective` (R-10): still accepted, so a saved setting keeps working,
    /// and read as exactly `counterparties`.
    #[test]
    fn prospective_is_read_as_counterparties() {
        assert_eq!(history_segments_for(Some("prospective")), "counterparties");
        assert_eq!(
            history_segments_for(Some(" Prospective ")),
            "counterparties"
        );
    }

    #[test]
    fn setting_keys_match_the_python_env_var_suffix_convention() {
        // Each env var is the setting key with the shared
        // CAPSULES_ prefix -- this module's whole "no
        // re-naming exercise later" claim rests on this correspondence.
        let expected_env_suffix = [
            (RECORD_AT_COMPLETION_KEY, "SHARE_RECORD_AT_COMPLETION"),
            (HISTORY_SEGMENTS_KEY, "SHARE_HISTORY_SEGMENTS"),
            (ADJUDICATIONS_KEY, "SHARE_ADJUDICATIONS"),
            (WITNESS_KEY, "CHECKPOINT_WITNESS_URLS"),
            (STANDARD_HISTORY_KEY, "SHARE_STANDARD_HISTORY"),
            (EXCHANGE_CORROBORATION_KEY, "SHARE_EXCHANGE_CORROBORATION"),
            (
                ADVERTISE_EVIDENCE_REQUESTS_KEY,
                "ADVERTISE_EVIDENCE_REQUESTS",
            ),
            (ADJUDICATE_DIFFERING_TWINS_KEY, "ADJUDICATE_DIFFERING_TWINS"),
            (REFEREE_BAR_DAYS_KEY, "REFEREE_BAR_DAYS"),
            (STOP_ROUTING_AFTER_KEY, "STOP_ROUTING_AFTER_CONTRADICTIONS"),
            (STOP_ROUTING_WINDOW_KEY, "STOP_ROUTING_WINDOW_DAYS"),
        ];
        for (key, suffix) in expected_env_suffix {
            assert_eq!(
                crate::settings::console_key(&format!("CAPSULES_{suffix}")).as_deref(),
                Some(key),
                "env suffix {suffix} must map to the console key {key}"
            );
        }
    }

    #[test]
    fn only_the_record_at_completion_push_to_the_counterparty_is_on_by_default() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        let by_key = |k: &str| schema.settings.iter().find(|s| s.key == k).unwrap();
        assert_eq!(
            by_key(RECORD_AT_COMPLETION_KEY).default_json.as_deref(),
            Some("\"counterparty\"")
        );
        assert_eq!(
            by_key(HISTORY_SEGMENTS_KEY).default_json.as_deref(),
            Some("\"counterparties\"")
        );
        assert_eq!(
            by_key(STANDARD_HISTORY_KEY).default_json.as_deref(),
            Some("\"off\"")
        );
        assert_eq!(
            by_key(EXCHANGE_CORROBORATION_KEY).default_json.as_deref(),
            Some("\"on\"")
        );
        assert_eq!(
            by_key(ADVERTISE_EVIDENCE_REQUESTS_KEY)
                .default_json
                .as_deref(),
            Some("\"off\"")
        );
        assert_eq!(
            by_key(ADJUDICATIONS_KEY).default_json.as_deref(),
            Some("\"deliver_to_subjects\"")
        );
        assert_eq!(
            by_key(ADJUDICATE_DIFFERING_TWINS_KEY)
                .default_json
                .as_deref(),
            Some("\"off\"")
        );
        // Answering a request for a record is unchanged: `counterparties`
        // serves exactly whom `prospective` did.
        assert_eq!(history_segments_for(None), "counterparties");
        assert!(
            !switched_on(None),
            "standard history and advertising are off"
        );
        // Ruled defaults (#163): verdict delivery and corroboration are on.
        assert!(adjudications_delivered_for(None));
        assert!(shares_exchange_corroboration_for(None));
        assert!(!crate::referee::request::adjudicate_differing_twins_from(
            None
        ));
    }

    #[test]
    fn the_stop_routing_rule_is_off_by_default() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        let after = schema
            .settings
            .iter()
            .find(|s| s.key == STOP_ROUTING_AFTER_KEY)
            .unwrap();
        assert_eq!(after.default_json, None, "no N by default: the rule is off");
        assert_eq!(
            format!("CAPSULES_{}", STOP_ROUTING_AFTER_KEY.to_uppercase()),
            crate::routing_rule::ENV_AFTER
        );
        assert_eq!(
            format!("CAPSULES_{}", STOP_ROUTING_WINDOW_KEY.to_uppercase()),
            crate::routing_rule::ENV_WINDOW_DAYS
        );
    }

    #[test]
    fn witness_has_no_default_url_and_is_not_required() {
        // Design note S1: "witness: off | <url> # default: off" -- off IS
        // the absence of a default, never a magic sentinel string.
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        let witness = schema
            .settings
            .iter()
            .find(|s| s.key == WITNESS_KEY)
            .unwrap();
        assert_eq!(witness.default_json, None);
        assert!(!witness.required);
        // A list of witnesses, each an endpoint and, optionally, its key.
        let value = witness.value_schema.as_ref().unwrap();
        assert_eq!(value.kind, proto::PluginConfigValueKind::Array as i32);
        let row = value.items.as_ref().unwrap();
        assert_eq!(row.kind, proto::PluginConfigValueKind::Object as i32);
        let props: Vec<_> = row
            .object_properties
            .iter()
            .map(|p| (p.key.as_str(), p.required))
            .collect();
        assert_eq!(props, [("endpoint", true), ("public_key", false)]);
        // The suggestion is a hint, not a default: still nothing stored.
        let presentation = witness.presentation.as_ref().unwrap();
        assert_eq!(
            presentation.placeholder.as_deref(),
            Some(SUGGESTED_WITNESS_URL)
        );
        assert_eq!(presentation.renderer_id.as_deref(), Some("set-value"));
        assert_eq!(witness.default_json, None);
    }

    #[test]
    fn every_setting_is_optional_shipping_this_schema_flips_no_runtime_behavior() {
        let schema = as_config_schema(share_policy_config_schema("capsules"));
        assert!(schema.settings.iter().all(|s| !s.required));
    }

    #[test]
    fn an_unreadable_record_at_completion_value_is_off_not_the_default() {
        use std::env::VarError;
        use std::ffi::OsString;
        assert!(!record_at_completion_is_off_from(Err(VarError::NotPresent)));
        assert!(record_at_completion_is_off_from(Err(VarError::NotUnicode(
            OsString::from("x")
        ))));
        assert!(!record_at_completion_is_off_from(Ok("counterparty".into())));
        assert!(record_at_completion_is_off_from(Ok("off".into())));
    }

    #[test]
    fn record_at_completion_is_on_unless_off_or_unknown() {
        assert!(!record_at_completion_is_off_for(Some("counterparty")));
        assert!(!record_at_completion_is_off_for(Some(" counterparty ")));
        assert!(!record_at_completion_is_off_for(None));
        assert!(!record_at_completion_is_off_for(Some("  ")));
        assert!(record_at_completion_is_off_for(Some("off")));
        assert!(record_at_completion_is_off_for(Some("garbage")));
    }

    /// A typo, odd case, stray spaces or an empty value never widen who may
    /// read records back.
    #[test]
    fn history_segments_never_widen_on_a_typo() {
        assert_eq!(history_segments_for(None), "counterparties");
        assert_eq!(
            history_segments_for(Some("")),
            "counterparties",
            "empty is unset"
        );
        assert_eq!(history_segments_for(Some("Off ")), "off");
        assert_eq!(
            history_segments_for(Some(" COUNTERPARTIES")),
            "counterparties"
        );
        assert_eq!(
            history_segments_for(Some("counterparty")),
            "off",
            "unknown is off"
        );
        assert_eq!(history_segments_for(Some("peeers")), "off");
        assert!(!record_at_completion_is_off_for(Some(" Counterparty")));
    }

    #[test]
    fn an_on_off_switch_is_on_only_when_switched_on() {
        for on in ["on", " ON ", "1", "true", "yes"] {
            assert!(switched_on(Some(on)), "{on:?}");
        }
        for off in [
            None,
            Some(""),
            Some("off"),
            Some("0"),
            Some("no"),
            Some("onn"),
        ] {
            assert!(!switched_on(off), "{off:?}");
        }
    }

    #[test]
    fn verdict_delivery_is_on_unless_turned_off_or_unknown() {
        assert!(adjudications_delivered_for(None));
        assert!(adjudications_delivered_for(Some("  ")));
        assert!(adjudications_delivered_for(Some("deliver_to_subjects")));
        assert!(!adjudications_delivered_for(Some("off")));
        assert!(!adjudications_delivered_for(Some("garbage")));
    }

    #[test]
    fn exchange_corroboration_is_on_unless_turned_off_or_unknown() {
        assert!(shares_exchange_corroboration_for(None));
        assert!(shares_exchange_corroboration_for(Some("")));
        assert!(shares_exchange_corroboration_for(Some("on")));
        assert!(!shares_exchange_corroboration_for(Some("off")));
        assert!(!shares_exchange_corroboration_for(Some("onn")));
    }
}
