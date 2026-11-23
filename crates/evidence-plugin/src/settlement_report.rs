//! `GET settlement-report`: the node's latest EvidenceBook settlement report,
//! for the Reports group's "EvidenceBook report (sealed and checked)"
//! (Mesh-LLM/capsules-plugin#96, button 2).
//!
//! The node never builds the report. Its owner runs
//! `scripts/settlement-report.sh`, which publishes the node's records into a
//! capsulectl book under the node's own key, runs evidencebook-skills'
//! `report.sh --seal` over the inference-deals pack, and leaves the page as
//! `<CAPSULES_SETTLEMENT_REPORT_DIR>/settlement.html` with
//! `settlement.json` (when it was sealed, the day it reports on). This route
//! only hands that page over. It writes nothing.
//!
//! At hand-over it asks the owner's capsulectl (`CAPSULES_CAPSULECTL`, with
//! capsulectl-book) `book report check` on the page, so the check is
//! capsulectl's own. It hands the page over only when the check says the page
//! matches its seal and the embedded evidence is `VALID`, and only when the
//! bytes it checked are the bytes it serves. Every other case is the honest
//! refusal, with its reason: no reporting book is set, no report is sealed
//! yet, or the page did not check.
//!
//! The note's `sealed_at` and `date` are given only when the note's own
//! check names the page digest this check found, so a page is never shown
//! with an older run's note.
//!
//! The route answers `{"state": "report", "page": "<the page, as text>",
//! "sealed_at", "date", "check"}` or `{"state": "refused", "why"}`.
use std::path::{Path, PathBuf};
use std::time::Duration;

use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use serde_json::{json, Value};

use crate::evidence_routes::NoArgs;

/// The reporting book's directory, as `scripts/settlement-report.sh` keeps it.
pub const ENV_REPORT_DIR: &str = "CAPSULES_SETTLEMENT_REPORT_DIR";
/// The owner's capsulectl, which loads capsulectl-book.
pub const ENV_CAPSULECTL: &str = "CAPSULES_CAPSULECTL";
/// The capsulectl profile the script makes for the reporting book.
pub const PROFILE: &str = "settlement";
/// The page and its note, in the reporting book's directory.
pub const PAGE_FILE: &str = "settlement.html";
pub const NOTE_FILE: &str = "settlement.json";
/// How long `book report check` may take before the page is refused.
const CHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// Where the report is, when the owner has set it up.
#[derive(Debug, Clone)]
pub struct Setup {
    pub report_dir: Option<PathBuf>,
    pub capsulectl: Option<PathBuf>,
}

impl Setup {
    /// The reporting book's folder from the console's "Settlement report
    /// folder" (or `CAPSULES_SETTLEMENT_REPORT_DIR`), and the capsulectl the
    /// script recorded in its `book.json` there (`CAPSULES_CAPSULECTL`
    /// overrides it). The console never names the program the plugin runs.
    pub fn from_settings() -> Self {
        let path = |name: &str| {
            crate::settings::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let report_dir = path(ENV_REPORT_DIR);
        let capsulectl =
            path(ENV_CAPSULECTL).or_else(|| report_dir.as_deref().and_then(recorded_capsulectl));
        Self {
            report_dir,
            capsulectl,
        }
    }

    /// Why this setup cannot hand over a report, in the owner's words, or
    /// `None` when it can try.
    fn problem(&self) -> Option<&'static str> {
        if self.report_dir.is_none() {
            return Some(NOT_SET_UP);
        }
        if self.capsulectl.is_none() {
            return Some(NO_CAPSULECTL);
        }
        None
    }
}

/// No reporting book is set.
pub const NOT_SET_UP: &str = "no settlement report is set up on this node: set \
     \"Settlement report folder\" under Configuration > Plugins > Capsules > Reports, then \
     make a report there with scripts/settlement-report.sh on the node's machine";
/// The book names no capsulectl to check its page with.
pub const NO_CAPSULECTL: &str = "the reporting book does not name the capsulectl that \
     checks its report: make the report again with scripts/settlement-report.sh, which \
     records it";
/// The folder holds no page yet.
pub const NO_REPORT_YET: &str = "no settlement report has been sealed yet: the node's \
     owner makes one with scripts/settlement-report.sh";

/// The capsulectl `scripts/settlement-report.sh` ran, as it records it in
/// `book.json`.
fn recorded_capsulectl(report_dir: &Path) -> Option<PathBuf> {
    let book: Value =
        serde_json::from_slice(&std::fs::read(report_dir.join("book.json")).ok()?).ok()?;
    book.get("capsulectl")?
        .as_str()
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
}

fn refused(why: impl Into<String>) -> Value {
    json!({"state": "refused", "why": why.into()})
}

/// The plugin roots the script ran capsulectl with, which it records in
/// `book.json`.
async fn plugin_roots(report_dir: &Path) -> Option<String> {
    let book: Value =
        serde_json::from_slice(&tokio::fs::read(report_dir.join("book.json")).await.ok()?).ok()?;
    book.get("plugin_roots")?.as_str().map(str::to_string)
}

/// `book report check` on `page`, run the way the script ran it: the
/// reporting book's capsulectl config and the script's plugin roots.
async fn report_check(capsulectl: &Path, report_dir: &Path, page: &Path) -> Result<Value, String> {
    let mut command = tokio::process::Command::new(capsulectl);
    command
        .args(["book", "report", "check", "--profile", PROFILE, "--page"])
        .arg(page)
        .env("XDG_CONFIG_HOME", report_dir.join("config"))
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    if let Some(roots) = plugin_roots(report_dir).await {
        command.env("CAPSULECTL_PLUGIN_ROOTS", roots);
    }
    let output = tokio::time::timeout(CHECK_TIMEOUT, command.output())
        .await
        .map_err(|_| "book report check did not finish in time".to_string())?
        .map_err(|e| format!("capsulectl could not be run: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last = stdout.lines().rev().find(|l| !l.trim().is_empty());
    match last.and_then(|l| serde_json::from_str::<Value>(l).ok()) {
        Some(check) => Ok(check),
        None => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "book report check answered nothing it could read: {}",
                stderr.trim().chars().take(400).collect::<String>()
            ))
        }
    }
}

/// The route's answer for `setup`.
pub async fn answer(setup: &Setup) -> Value {
    if let Some(why) = setup.problem() {
        return refused(why);
    }
    let (Some(report_dir), Some(capsulectl)) =
        (setup.report_dir.as_deref(), setup.capsulectl.as_deref())
    else {
        return refused(NOT_SET_UP);
    };
    let page_path = report_dir.join(PAGE_FILE);
    let page = match tokio::fs::read(&page_path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return refused(NO_REPORT_YET),
        Err(e) => return refused(format!("the settlement report could not be read: {e}")),
    };
    let check = match report_check(capsulectl, report_dir, &page_path).await {
        Ok(check) => check,
        Err(why) => return refused(why),
    };
    if check.get("page").and_then(Value::as_str) != Some("match")
        || check.get("verification").and_then(Value::as_str) != Some("VALID")
    {
        let field = |name: &str| {
            check
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or("not reported")
        };
        return refused(format!(
            "the settlement report did not check, so it is not handed over (page: {}, seal: {})",
            field("page"),
            field("verification")
        ));
    }
    // The bytes served are the bytes checked: a new report written in
    // between is checked on the next ask, never served unchecked.
    if tokio::fs::read(&page_path).await.ok().as_deref() != Some(page.as_slice()) {
        return refused("the settlement report changed while it was checked; ask again");
    }
    let Ok(page) = String::from_utf8(page) else {
        return refused("the settlement report is not text");
    };
    let note: Value = tokio::fs::read(report_dir.join(NOTE_FILE))
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .filter(|note: &Value| {
            note.pointer("/check/page_digest").is_some()
                && note.pointer("/check/page_digest") == check.get("page_digest")
        })
        .unwrap_or(Value::Null);
    json!({
        "state": "report",
        "page": page,
        "sealed_at": note.get("sealed_at").cloned().unwrap_or(Value::Null),
        "date": note.get("date").cloned().unwrap_or(Value::Null),
        "check": check,
    })
}

/// What the button can say before it is pressed, without running the check
/// (`GET settlement-report/status`): `not_set_up` or `no_report_yet` with
/// `why`, `unreadable` with `why` (a page there that cannot be read, or a
/// capsulectl that is not a file), or `ready`. `ready` gives `sealed_at` and
/// `date` only when the note's own `check.page_digest` is the page's sha256,
/// so a page is never dated by an older run's note. `ready` is not a promise:
/// pressing the button still runs `book report check`, and only `match VALID`
/// hands the page over.
pub async fn status(setup: &Setup) -> Value {
    if let Some(why) = setup.problem() {
        return json!({"state": "not_set_up", "why": why});
    }
    let (Some(report_dir), Some(capsulectl)) =
        (setup.report_dir.as_deref(), setup.capsulectl.as_deref())
    else {
        return json!({"state": "not_set_up", "why": NOT_SET_UP});
    };
    let page = match tokio::fs::read(report_dir.join(PAGE_FILE)).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return json!({"state": "no_report_yet", "why": NO_REPORT_YET})
        }
        Err(e) => {
            return json!({"state": "unreadable", "why": format!("the settlement report could not be read: {e}")})
        }
    };
    if !tokio::fs::metadata(capsulectl)
        .await
        .is_ok_and(|m| m.is_file())
    {
        return json!({"state": "unreadable", "why": NO_CAPSULECTL});
    }
    use sha2::Digest as _;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&page)));
    let note: Value = tokio::fs::read(report_dir.join(NOTE_FILE))
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .filter(|note: &Value| {
            note.pointer("/check/page_digest").and_then(Value::as_str) == Some(digest.as_str())
        })
        .unwrap_or(Value::Null);
    json!({
        "state": "ready",
        "sealed_at": note.get("sealed_at").cloned().unwrap_or(Value::Null),
        "date": note.get("date").cloned().unwrap_or(Value::Null),
    })
}

/// `builder` with the `settlement-report` route declared.
pub fn with_route(builder: DeclarativePluginBuilder) -> DeclarativePluginBuilder {
    let builder = builder.http_item(
        http::get("/settlement-report/status")
            .binding_id("evidence_settlement_report_status")
            .description(
                "Whether the node has a sealed EvidenceBook settlement report to hand over, \
                 and when it was sealed, without checking it: what the report button says \
                 before it is pressed.",
            )
            .input::<NoArgs>()
            .handle(move |_args, _context| {
                Box::pin(
                    async move { Ok::<Value, PluginError>(status(&Setup::from_settings()).await) },
                )
            }),
    );
    builder.http_item(
        http::get("/settlement-report")
            .binding_id("evidence_settlement_report")
            .description(
                "The node's latest sealed EvidenceBook settlement report, checked with the \
                 owner's capsulectl at hand-over, for the Reports group's EvidenceBook report.",
            )
            .input::<NoArgs>()
            .handle(move |_args, _context| {
                Box::pin(
                    async move { Ok::<Value, PluginError>(answer(&Setup::from_settings()).await) },
                )
            }),
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in capsulectl that prints `check` as `book report check` would,
    /// after checking it was asked the right thing.
    fn fake_capsulectl(dir: &Path, check: &str) -> PathBuf {
        let path = dir.join("capsulectl");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n[ \"$1 $2 $3 $4 $5\" = \"book report check --profile {PROFILE}\" ] || exit 9\n\
                 [ \"$XDG_CONFIG_HOME\" = \"{}\" ] || exit 8\necho '{check}'\n",
                dir.join("report").join("config").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn report_dir(dir: &Path) -> PathBuf {
        let report = dir.join("report");
        std::fs::create_dir_all(&report).unwrap();
        std::fs::write(report.join(PAGE_FILE), "<!doctype html><p>report</p>").unwrap();
        std::fs::write(
            report.join(NOTE_FILE),
            r#"{"date":"2026-11-01","sealed_at":"2026-11-01T19:45:33Z","check":{"page_digest":"sha256:00"}}"#,
        )
        .unwrap();
        report
    }

    const MATCH: &str = r#"{"page":"match","verification":"VALID","page_digest":"sha256:00"}"#;

    #[tokio::test]
    async fn hands_over_a_page_that_matches_its_seal() {
        let dir = tempfile::tempdir().unwrap();
        let setup = Setup {
            report_dir: Some(report_dir(dir.path())),
            capsulectl: Some(fake_capsulectl(dir.path(), MATCH)),
        };
        let answered = answer(&setup).await;
        assert_eq!(answered["state"], "report");
        assert_eq!(answered["page"], "<!doctype html><p>report</p>");
        assert_eq!(answered["sealed_at"], "2026-11-01T19:45:33Z");
        assert_eq!(answered["date"], "2026-11-01");
        assert_eq!(answered["check"]["page"], "match");
    }

    #[tokio::test]
    async fn an_older_note_is_not_shown_with_a_newer_page() {
        let dir = tempfile::tempdir().unwrap();
        let newer = r#"{"page":"match","verification":"VALID","page_digest":"sha256:11"}"#;
        let setup = Setup {
            report_dir: Some(report_dir(dir.path())),
            capsulectl: Some(fake_capsulectl(dir.path(), newer)),
        };
        let answered = answer(&setup).await;
        assert_eq!(answered["state"], "report");
        assert_eq!(answered["sealed_at"], Value::Null);
        assert_eq!(answered["date"], Value::Null);
    }

    #[tokio::test]
    async fn runs_capsulectl_with_the_plugin_roots_the_script_used() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_dir(dir.path());
        std::fs::write(
            report.join("book.json"),
            r#"{"plugin_roots":"/opt/capsulectl-plugins"}"#,
        )
        .unwrap();
        let ctl = dir.path().join("capsulectl");
        std::fs::write(
            &ctl,
            format!(
                "#!/bin/sh\n[ \"$CAPSULECTL_PLUGIN_ROOTS\" = /opt/capsulectl-plugins ] || exit 7\necho '{MATCH}'\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        let answered = answer(&Setup {
            report_dir: Some(report),
            capsulectl: Some(ctl),
        })
        .await;
        assert_eq!(answered["state"], "report", "{answered}");
    }

    #[tokio::test]
    async fn refuses_a_page_that_does_not_check() {
        let dir = tempfile::tempdir().unwrap();
        for check in [
            r#"{"page":"mismatch","verification":"VALID"}"#,
            r#"{"page":"match","verification":"INVALID"}"#,
        ] {
            let setup = Setup {
                report_dir: Some(report_dir(dir.path())),
                capsulectl: Some(fake_capsulectl(dir.path(), check)),
            };
            let answered = answer(&setup).await;
            assert_eq!(answered["state"], "refused", "{check}");
            let why = answered["why"].as_str().unwrap();
            assert!(why.contains("did not check"));
            assert!(!why.contains('{'), "no raw check JSON in the reason: {why}");
            assert!(answered.get("page").is_none());
        }
    }

    #[tokio::test]
    async fn refuses_when_nothing_is_set_up_or_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let none = answer(&Setup {
            report_dir: None,
            capsulectl: None,
        })
        .await;
        assert_eq!(none["why"], NOT_SET_UP);

        let no_ctl = answer(&Setup {
            report_dir: Some(report_dir(dir.path())),
            capsulectl: None,
        })
        .await;
        assert_eq!(no_ctl["why"], NO_CAPSULECTL);
        // The owner is told in console words, never an environment name.
        for why in [NOT_SET_UP, NO_CAPSULECTL, NO_REPORT_YET] {
            assert!(!why.contains("CAPSULES_"), "{why}");
        }

        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let unsealed = answer(&Setup {
            report_dir: Some(empty),
            capsulectl: Some(fake_capsulectl(dir.path(), MATCH)),
        })
        .await;
        assert_eq!(unsealed["state"], "refused");
        assert!(unsealed["why"]
            .as_str()
            .unwrap()
            .contains("scripts/settlement-report.sh"));

        let missing = answer(&Setup {
            report_dir: Some(report_dir(dir.path())),
            capsulectl: Some(dir.path().join("no-such-capsulectl")),
        })
        .await;
        assert!(missing["why"]
            .as_str()
            .unwrap()
            .contains("could not be run"));
    }

    #[tokio::test]
    async fn the_status_says_what_the_button_will_do_without_checking() {
        use sha2::Digest as _;
        let dir = tempfile::tempdir().unwrap();
        let status_of = |report_dir, capsulectl| async move {
            status(&Setup {
                report_dir,
                capsulectl,
            })
            .await
        };
        let none = status_of(None, None).await;
        assert_eq!(none, json!({"state": "not_set_up", "why": NOT_SET_UP}));
        let report = report_dir(dir.path());
        let no_ctl = status_of(Some(report.clone()), None).await;
        assert_eq!(no_ctl["state"], "not_set_up");

        // A capsulectl that would fail the check is never run: the status
        // only reads the folder.
        let never_run = fake_capsulectl(dir.path(), "not json");
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let unsealed = status_of(Some(empty), Some(never_run.clone())).await;
        assert_eq!(
            unsealed,
            json!({"state": "no_report_yet", "why": NO_REPORT_YET})
        );

        // The note names another page: ready, but undated.
        let undated = status_of(Some(report.clone()), Some(never_run.clone())).await;
        assert_eq!(
            undated,
            json!({"state": "ready", "sealed_at": null, "date": null})
        );

        // The note names this page: dated.
        let page = std::fs::read(report.join(PAGE_FILE)).unwrap();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&page)));
        std::fs::write(
            report.join(NOTE_FILE),
            json!({"date": "2026-11-22", "sealed_at": "2026-11-23T06:00:00Z", "check": {"page_digest": digest}})
                .to_string(),
        )
        .unwrap();
        let dated = status_of(Some(report.clone()), Some(never_run.clone())).await;
        assert_eq!(
            dated,
            json!({"state": "ready", "sealed_at": "2026-11-23T06:00:00Z", "date": "2026-11-22"})
        );

        // A capsulectl that is not there, and a page that cannot be read.
        let gone = status_of(Some(report.clone()), Some(dir.path().join("gone"))).await;
        assert_eq!(gone["state"], "unreadable");
        std::fs::set_permissions(
            report.join(PAGE_FILE),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        if std::fs::read(report.join(PAGE_FILE)).is_err() {
            let locked = status_of(Some(report.clone()), Some(never_run)).await;
            assert_eq!(locked["state"], "unreadable", "{locked}");
        }
    }

    #[test]
    fn the_capsulectl_is_the_one_the_book_records_unless_the_environment_names_one() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(recorded_capsulectl(dir.path()), None);
        std::fs::write(
            dir.path().join("book.json"),
            r#"{"capsulectl":"/opt/capsulectl/capsulectl","plugin_roots":"/opt/capsulectl"}"#,
        )
        .unwrap();
        assert_eq!(
            recorded_capsulectl(dir.path()),
            Some(PathBuf::from("/opt/capsulectl/capsulectl"))
        );
        std::fs::write(dir.path().join("book.json"), r#"{"capsulectl":""}"#).unwrap();
        assert_eq!(recorded_capsulectl(dir.path()), None);
    }

    /// Against a real capsulectl and a report `scripts/settlement-report.sh`
    /// made: `CAPSULES_TEST_CAPSULECTL` and `CAPSULES_TEST_SETTLEMENT_REPORT_DIR`.
    /// The page is handed over, then a page changed by one byte is refused.
    #[tokio::test]
    #[ignore = "needs capsulectl with capsulectl-book and a sealed report"]
    async fn a_real_report_checks_and_a_changed_one_does_not() {
        let ctl = PathBuf::from(std::env::var("CAPSULES_TEST_CAPSULECTL").unwrap());
        let source = PathBuf::from(std::env::var("CAPSULES_TEST_SETTLEMENT_REPORT_DIR").unwrap());
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("report");
        assert!(std::process::Command::new("cp")
            .args(["-R"])
            .arg(&source)
            .arg(&copy)
            .status()
            .unwrap()
            .success());
        let setup = Setup {
            report_dir: Some(copy.clone()),
            capsulectl: Some(ctl),
        };
        let answered = answer(&setup).await;
        assert_eq!(answered["state"], "report", "{answered}");
        assert_eq!(
            answered["page"].as_str().unwrap().as_bytes(),
            std::fs::read(source.join(PAGE_FILE)).unwrap()
        );

        // The note the script wrote names this page, so its seal time shows.
        assert!(answered["sealed_at"].is_string(), "{answered}");

        let mut page = std::fs::read(copy.join(PAGE_FILE)).unwrap();
        let at = page.len() - 20;
        page[at] = if page[at] == b' ' { b'\n' } else { b' ' };
        std::fs::write(copy.join(PAGE_FILE), page).unwrap();
        let answered = answer(&setup).await;
        assert_eq!(answered["state"], "refused", "{answered}");
    }
}
