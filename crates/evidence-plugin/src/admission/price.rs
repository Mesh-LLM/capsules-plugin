//! The price rule (#105): before a paid attempt, the selected peer's
//! advertised input and output rates against the operator's caps, decided by
//! capsule-engine's guard with its `asg/inference` terms pack
//! (`capsule_engine::guard`, the crate Muse's Go guard shares vectors with),
//! never by a second evaluator here.
//!
//! The rates are the ones the host routed on: mesh-llm puts the selected
//! peer's `Pricing` on the `backend_selected` event as `pricing`, and says so
//! by listing [`PRICING_CAPABILITY`]. With the capability, an event without
//! `pricing` is a free route, rates 0, unless it names no model: the host's
//! no-model fallback never prices its pick, so that attempt is treated like
//! one from an older host (`no_price_without_model`). Without it the host never sends a
//! price, so a paid route cannot be told from a free one. Under the operator's
//! own profile that is NO ([`Read::Unavailable`], fail closed). Under the
//! shipped default alone, the pack is not run and the record says the price
//! was not checked (`host_lacks_backend_pricing`), and `doctor` warns that the
//! rule is inactive: failing closed on a default would deny every mesh peer,
//! free ones included, on every older host (Sherlock2's door check, buzz
//! 7520c4fa).
//!
//! The operator's values are a `policy-profile/v0` file ([`PROFILE_SETTING`]):
//! `rate_cap.max_input_msat_per_million`, `rate_cap.max_output_msat_per_million`,
//! and the pack's `counterparty_list`, with the console lists and default folded in. The sealed decision cites the pack, its
//! definition digest and the profile's digest. Every dedupe check reads an
//! empty history: a purchase is keyed on its exchange id, and the host pays
//! each attempt at most once, so nothing here could repeat one.

use capsule_engine::guard::{Action, ConstraintResult, Engine, History, Outcome, Profile};
use serde_json::{json, Value};

/// The setting naming the operator's `policy-profile/v0` file.
pub const PROFILE_SETTING: &str = "CAPSULES_ADMISSION_PROFILE";

/// The `fp_alg` of the peer fingerprints in a profile the plugin builds: the
/// algorithm (SHA-256 over salt then node id) and the key scope (a salt
/// derived from this install's signing key, so only this operator can say
/// which peer a fingerprint names). No clear node id enters the profile, its
/// digest or a sealed record.
pub const FP_ALG: &str = "sha256-install-salt-v1";

/// The host capability that says `backend_selected` carries the selected
/// peer's price (mesh-llm `host_capabilities`).
pub const PRICING_CAPABILITY: &str = "openai_exchange.backend_pricing.v1";

/// The rate caps, msat per million input and output tokens, that apply when
/// the operator gives no profile: an outlier guard, 1000x mesh-llm's CLI
/// default price of 500/1500 (`mesh-llm-commands` wallet), far above any real
/// price, so one absurdly priced peer cannot overshoot the daily budget in a
/// single request (a reply of 8,192 tokens costs at most about 12 sat here).
/// `None` would ship no bound. The value is Sherlock2's recommendation, taken
/// under the non-stop rule while Steven's ruling is open (buzz 3998d6d0); his
/// answer changes only this constant.
pub const DEFAULT_RATE_CAPS: Option<(u64, u64)> = Some((500_000, 1_500_000));

/// Whether the host sends the selected peer's price, learned at initialize
/// (for `doctor`).
static HOST_PRICES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Record what the host said at initialize.
pub(crate) fn set_host_prices(on: bool) {
    HOST_PRICES.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// What `doctor` shows of the rule this process loaded (set once, when the
/// admission hook is built); `None` before that or when its profile did not
/// read.
static LOADED: std::sync::OnceLock<Value> = std::sync::OnceLock::new();

/// The loaded rule's description for `doctor`: the pack, its definition
/// digest, the profile's digest and values. An unreadable profile says so.
pub fn loaded_description() -> Value {
    let mut described = LOADED.get().cloned().unwrap_or_else(
        || json!({"state": "unreadable_or_not_loaded", "profile_setting": PROFILE_SETTING}),
    );
    let deprecated: Vec<&str> = [
        super::ALLOW_SETTING,
        super::DENY_SETTING,
        super::DEFAULT_SETTING,
    ]
    .into_iter()
    .filter(|name| crate::settings::set_in_env(name))
    .collect();
    if !deprecated.is_empty() {
        described["deprecated_env_set"] = json!(deprecated);
    }
    let host_prices = HOST_PRICES.load(std::sync::atomic::Ordering::Relaxed);
    described["host_sends_prices"] = json!(host_prices);
    if !host_prices {
        described["warning"] = json!(format!(
            "this mesh-llm does not list {PRICING_CAPABILITY}: the price rule is inactive, \
             and under an operator profile every mesh peer gets NO"
        ));
    }
    described
}

/// Record the loaded rule for `doctor`; a second load (tests) keeps the first.
pub(crate) fn set_loaded(description: Value) -> Result<(), Value> {
    LOADED.set(description)
}

/// The pack's served id, as a profile names it.
const PACK: &str = "asg/inference";

/// What the price rule read for one attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    /// The guard decided: its outcome and each check's result, with the
    /// rates it read.
    Checked {
        outcome: Outcome,
        constraints: Vec<(String, &'static str)>,
        /// The check that refused: the first one not evaluated (it fails
        /// closed), else the first that failed.
        refused_by: Option<String>,
        /// The rates as read; `None` for one the host's `pricing` did not
        /// state as an integer (the guard then refuses it).
        input: Option<u64>,
        output: Option<u64>,
    },
    /// The host sends no price for this attempt and no operator profile is
    /// in force (the shipped default at most): the pack was not run, for the
    /// reason given (`host_lacks_backend_pricing`, or
    /// `no_price_without_model` on the host's no-model fallback).
    NotChecked(&'static str),
    /// NO, failing closed, for the reason given: `host_lacks_backend_pricing`
    /// or `no_price_without_model` (the operator's profile is in force but
    /// the attempt carries no price it can trust), or `guard_error` (the
    /// engine refused the action or the decision, logged).
    Unavailable(&'static str),
}

impl Read {
    /// NO when the guard did not allow (`deny` or `escalate`), or the price
    /// is unavailable under a cap.
    pub fn refuses(&self) -> bool {
        match self {
            Read::Checked { outcome, .. } => *outcome != Outcome::Allow,
            Read::NotChecked(_) => false,
            Read::Unavailable(_) => true,
        }
    }

    /// The check that refused, for the decision's `source`.
    pub fn source(&self) -> &str {
        match self {
            Read::Checked { refused_by, .. } => refused_by.as_deref().unwrap_or("price"),
            Read::NotChecked(_) => "price",
            Read::Unavailable(reason) => reason,
        }
    }
}

/// The pack, the operator's profile over it, and their digests.
pub struct PriceRule {
    engine: Engine,
    profile_digest: Option<String>,
    /// Whether the operator's own profile is in force (not the default).
    operator_profile: bool,
    /// The profile's values as read, for `doctor`.
    values: Value,
    /// Whether the plugin built the profile from the console settings: it then
    /// holds fingerprints, never a clear node id, so its digest is safe to
    /// cite as it is.
    built: bool,
}

impl PriceRule {
    /// The rule the operator's settings give. With [`PROFILE_SETTING`] set,
    /// the named file is the profile, with the console lists and default
    /// folded into it ([`Self::from_file`]), so the digest a decision cites
    /// covers every rule it applied. Otherwise the plugin builds a
    /// `policy-profile/v0` from the allow/deny lists and default in `policy`,
    /// holding peer fingerprints under `salt`, never clear ids. A file that
    /// does not read or decode is an error, never "unset": the caller fails
    /// closed.
    pub fn from_settings(policy: Option<&super::Policy>, salt: &[u8; 32]) -> anyhow::Result<Self> {
        match crate::settings::var(PROFILE_SETTING) {
            Ok(path) if !path.trim().is_empty() => {
                let raw = std::fs::read(path.trim())
                    .map_err(|e| anyhow::anyhow!("{PROFILE_SETTING}: {e}"))?;
                Self::from_file(&raw, policy, salt)
            }
            Ok(_) | Err(std::env::VarError::NotPresent) => Self::from_operator(policy, salt),
            Err(e) => Err(anyhow::anyhow!("{PROFILE_SETTING}: {e}")),
        }
    }

    /// The rule over the profile built from `policy`'s lists and default.
    /// Lists alone are decided by the base pack, so the profile is not the
    /// operator's own in the price rule's sense (an unpriced attempt is not
    /// failed closed on an older host); the shipped caps stay.
    pub fn from_operator(policy: Option<&super::Policy>, salt: &[u8; 32]) -> anyhow::Result<Self> {
        let Some(list) = policy.and_then(|p| p.list(salt)) else {
            return Self::from_profile(None);
        };
        let raw = serde_json::to_vec(&json!({
            "format": "policy-profile/v0",
            "packs": [{"pack": PACK, "parameters": {"counterparty_list": list}}],
        }))?;
        let mut rule = Self::build(Some(&raw), false)?;
        rule.built = true;
        Ok(rule)
    }

    /// The rule over the operator's profile file with the console lists and
    /// default folded in as the pack's `counterparty_list` (the same list
    /// [`Self::from_operator`] builds, fingerprints only). The effective
    /// profile is what the engine digests, so no new digest is defined. The
    /// pack has one list: a file that sets its own `counterparty_list` while
    /// the console lists refuse someone is an error (the caller fails
    /// closed), since merging two lists would be a rule neither names.
    pub fn from_file(
        raw: &[u8],
        policy: Option<&super::Policy>,
        salt: &[u8; 32],
    ) -> anyhow::Result<Self> {
        let Some(list) = policy.and_then(|p| p.list(salt)) else {
            return Self::from_profile(Some(raw));
        };
        let Ok(mut profile) = serde_json::from_slice::<Value>(raw) else {
            return Self::from_profile(Some(raw)); // decode reports it
        };
        let Some(packs) = profile.get_mut("packs").and_then(Value::as_array_mut) else {
            return Self::from_profile(Some(raw));
        };
        let entry = match packs.iter().position(|p| p["pack"] == PACK) {
            Some(i) => &mut packs[i],
            None => {
                packs.push(json!({"pack": PACK, "parameters": {}}));
                packs.last_mut().expect("just pushed")
            }
        };
        let Some(parameters) = entry.get_mut("parameters").and_then(Value::as_object_mut) else {
            return Self::from_profile(Some(raw));
        };
        if parameters
            .get("counterparty_list")
            .is_some_and(|l| !l.is_null())
        {
            anyhow::bail!(
                "{PROFILE_SETTING}: the file sets a counterparty_list for {PACK} and the \
                 console's admission lists refuse peers too; the pack takes one list, so \
                 remove one of them"
            );
        }
        parameters.insert("counterparty_list".into(), list);
        Self::from_profile(Some(&serde_json::to_vec(&profile)?))
    }

    /// The rule over `profile` (`policy-profile/v0` bytes), or over the
    /// shipped default when there is none.
    pub fn from_profile(profile: Option<&[u8]>) -> anyhow::Result<Self> {
        Self::build(profile, profile.is_some())
    }

    fn build(profile: Option<&[u8]>, operator_profile: bool) -> anyhow::Result<Self> {
        let base =
            Engine::inference().map_err(|e| anyhow::anyhow!("asg/inference: {}", e.message()))?;
        let raw = match (profile, DEFAULT_RATE_CAPS) {
            (Some(raw), Some(caps)) => Some(with_default_caps(raw, caps)?),
            (Some(raw), None) => Some(raw.to_vec()),
            (None, Some((input, output))) => Some(default_profile(input, output)),
            (None, None) => None,
        };
        let Some(raw) = raw else {
            return Ok(Self {
                engine: base,
                profile_digest: None,
                operator_profile: false,
                values: Value::Null,
                built: false,
            });
        };
        let profile = Profile::decode(&raw)
            .map_err(|e| anyhow::anyhow!("{PROFILE_SETTING}: {}", e.message()))?;
        let engine = base
            .with_profile(&profile)
            .map_err(|e| anyhow::anyhow!("{PROFILE_SETTING}: {}", e.message()))?;
        let values: Value = serde_json::from_slice(&raw)?;
        Ok(Self {
            engine,
            profile_digest: Some(profile.digest().to_string()),
            operator_profile,
            values,
            built: false,
        })
    }

    /// The pack the rule runs, as a decision cites it (`role: "price"`, beside
    /// the base pack's `role: "base"`). The profile is cited
    /// by `sha256(salt || profile digest)`: its digest is over the
    /// counterparty list in clear, so a clear digest would let a reader
    /// confirm a guessed list (the same reason #55 commits to its lists).
    pub fn reads(&self, salt: &[u8; 32]) -> Value {
        json!({
            "kind": "terms_pack",
            "role": "price",
            "pack": self.engine.pack_id(),
            "definition_digest": {"alg": "SHA-256", "digest": self.engine.definition_digest()},
            "profile": self.profile_cite(salt),
        })
    }

    /// The profile as a decision cites it: for a profile the plugin built,
    /// its digest as it is (it holds fingerprints under [`FP_ALG`], no clear
    /// id); for the operator's file, a salted commitment to the digest (the
    /// file may list clear ids). `None` when no profile is in force.
    pub fn profile_cite(&self, salt: &[u8; 32]) -> Option<Value> {
        self.profile_digest.as_ref().map(|d| {
            if self.built {
                json!({"alg": "SHA-256", "digest": d, "fp_alg": FP_ALG})
            } else {
                json!({
                    "alg": "SHA-256",
                    "commitment": crate::producer::capsule::peer_commitment(d, salt),
                })
            }
        })
    }

    /// What `doctor` shows: the pack, the profile digest and its values.
    pub fn describe(&self) -> Value {
        json!({
            "pack": self.engine.pack_id(),
            "definition_digest": self.engine.definition_digest(),
            "profile_setting": PROFILE_SETTING,
            "profile_digest": self.profile_digest,
            "profile": self.values,
            "default_rate_caps": DEFAULT_RATE_CAPS.map(|(i, o)| json!({"max_input_msat_per_million": i, "max_output_msat_per_million": o})),
            "operator_profile": self.operator_profile,
            "profile_source": if self.built { "console settings" } else { "profile file or shipped default" },
            "fp_alg": self.built.then_some(FP_ALG),
        })
    }

    /// The rule for one `backend_selected` attempt to `peer`. `host_prices`
    /// is whether the host listed [`PRICING_CAPABILITY`].
    pub fn check(
        &self,
        event: &Value,
        peer: &str,
        fingerprint: &str,
        host_prices: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Read {
        // With no price for this attempt, a paid route cannot be told from a
        // free one: the operator's profile fails closed, the shipped default
        // alone records the rule as not checked (as on an older host).
        let unpriced = |reason: &'static str| {
            if self.operator_profile {
                Read::Unavailable(reason)
            } else {
                Read::NotChecked(reason)
            }
        };
        let (input, output) = if host_prices {
            match event.get("pricing") {
                // No price on a request with no model is not "free": the
                // host's no-model fallback never prices its pick
                // (mesh-llm#2742).
                None | Some(Value::Null)
                    if event.get("model").and_then(Value::as_str).is_none() =>
                {
                    return unpriced("no_price_without_model");
                }
                None | Some(Value::Null) => (Some(0), Some(0)),
                Some(pricing) => (
                    pricing["input_msat_per_million"].as_u64(),
                    pricing["output_msat_per_million"].as_u64(),
                ),
            }
        } else {
            return unpriced("host_lacks_backend_pricing");
        };
        let mut action = json!({
            "operator": crate::settings::PLUGIN_NAME,
            "developer": concat!("capsules@", env!("CARGO_PKG_VERSION")),
            "action_type": "decide",
            "taxonomy_version": "6",
            "verb": "inference.purchase",
            "action_class": "money.purchase",
            "action_id": format!("admission/{}", event["exchange_id"].as_str().unwrap_or("")),
            "timestamp": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "target": peer,
            "equivalence_key": event["exchange_id"],
            // What a profile's fingerprint entries match: read by the list,
            // never sealed.
            "counterparty_ids": {"payee": fingerprint},
            "counterparty_fp_alg": FP_ALG,
        });
        // A rate that does not read is left out, and rate_cap refuses it.
        if let Some(input) = input {
            action["input_msat_per_million"] = json!(input);
        }
        if let Some(output) = output {
            action["output_msat_per_million"] = json!(output);
        }
        let raw =
            serde_json::to_vec(&action).expect("an action of strings and integers serializes");
        let decided =
            Action::decode(&raw).and_then(|action| self.engine.decide(&action, &History::new()));
        match decided {
            Ok(decision) => {
                let constraints: Vec<(String, &'static str)> = decision
                    .constraints()
                    .iter()
                    .map(|c| (c.id().to_string(), result_str(c.result())))
                    .collect();
                let refused_by = decision.not_evaluated().first().cloned().or_else(|| {
                    constraints
                        .iter()
                        .find(|(_, r)| *r == "fail")
                        .map(|(id, _)| id.clone())
                });
                Read::Checked {
                    outcome: decision.outcome(),
                    constraints,
                    refused_by,
                    input,
                    output,
                }
            }
            // The engine refused the action or failed to decide (for
            // example after a pin bump changed what it reads): refused,
            // never admitted, and said. The message names fields, never
            // the peer.
            Err(error) => {
                tracing::error!(
                    error = error.message(),
                    "the admission price rule could not decide; answering NO"
                );
                Read::Unavailable("guard_error")
            }
        }
    }
}

/// The peer's fingerprint as a profile's entries hold it ([`FP_ALG`]).
pub fn fingerprint(peer: &str, salt: &[u8; 32]) -> String {
    crate::producer::capsule::peer_commitment(peer, salt)
}

fn result_str(result: ConstraintResult) -> &'static str {
    result.as_str()
}

/// `raw` with the shipped caps filled in where it sets none for the pack: a
/// profile that sets only the counterparty list keeps the outlier guard, and
/// the digest covers the caps actually in force. A cap the operator set
/// stands.
fn with_default_caps(raw: &[u8], (input, output): (u64, u64)) -> anyhow::Result<Vec<u8>> {
    let mut profile: Value =
        serde_json::from_slice(raw).map_err(|e| anyhow::anyhow!("{PROFILE_SETTING}: {e}"))?;
    let Some(packs) = profile.get_mut("packs").and_then(Value::as_array_mut) else {
        return Ok(raw.to_vec()); // not a profile: decode reports it
    };
    let entry = match packs.iter().position(|p| p["pack"] == PACK) {
        Some(i) => &mut packs[i],
        None => {
            packs.push(json!({"pack": PACK, "parameters": {}}));
            packs.last_mut().expect("just pushed")
        }
    };
    let Some(parameters) = entry.get_mut("parameters").and_then(Value::as_object_mut) else {
        return Ok(raw.to_vec());
    };
    let caps = parameters.entry("rate_cap").or_insert_with(|| json!({}));
    // `"rate_cap": null` is "no values" to the profile decoder: it sets no
    // cap, so it gets the shipped ones too.
    if caps.is_null() {
        *caps = json!({});
    }
    if let Some(caps) = caps.as_object_mut() {
        caps.entry("max_input_msat_per_million")
            .or_insert(json!(input));
        caps.entry("max_output_msat_per_million")
            .or_insert(json!(output));
    }
    Ok(serde_json::to_vec(&profile)?)
}

/// The shipped default as a profile over the pack.
fn default_profile(input: u64, output: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "format": "policy-profile/v0",
        "packs": [{"pack": PACK, "parameters": {"rate_cap": {
            "max_input_msat_per_million": input,
            "max_output_msat_per_million": output,
        }}}],
    }))
    .expect("a profile of integers serializes")
}

/// The record's view of one read: the rates and each check, never the
/// peer's id (the record names it by commitment).
pub fn record(read: &Read) -> Value {
    match read {
        Read::Checked {
            outcome,
            constraints,
            input,
            output,
            ..
        } => json!({
            "state": "checked",
            "outcome": outcome.as_str(),
            "input_msat_per_million": input,
            "output_msat_per_million": output,
            "checks": constraints.iter().map(|(id, r)| json!({"check": id, "result": r})).collect::<Vec<_>>(),
        }),
        Read::NotChecked(reason) => json!({"state": "not_checked", "reason": reason}),
        Read::Unavailable(reason) => json!({"state": "unavailable", "reason": reason}),
    }
}
