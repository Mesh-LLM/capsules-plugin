//! `GET settlement-report`: the node's latest EvidenceBook settlement report,
//! for the Evidence page's "Save Settlement page" (Mesh-LLM/capsules-plugin#96,
//! button 2).
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
    pub fn from_settings() -> Self {
        let path = |name: &str| {
            crate::settings::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Self {
            report_dir: path(ENV_REPORT_DIR),
            capsulectl: path(ENV_CAPSULECTL),
        }
    }
}

fn refused(why: impl Into<String>) -> Value {
    json!({"state": "refused", "why": why.into()})
}

/// `book report check` on `page`, run the way the script ran it: the
/// reporting book's capsulectl config, the plugin roots beside capsulectl.
async fn report_check(capsulectl: &Path, report_dir: &Path, page: &Path) -> Result<Value, String> {
    let roots = capsulectl
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let output = tokio::time::timeout(
        CHECK_TIMEOUT,
        tokio::process::Command::new(capsulectl)
            .args(["book", "report", "check", "--profile", PROFILE, "--page"])
            .arg(page)
            .env("XDG_CONFIG_HOME", report_dir.join("config"))
            .env("CAPSULECTL_PLUGIN_ROOTS", roots)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
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
    let Some(report_dir) = setup.report_dir.as_deref() else {
        return refused(format!(
            "this node has no reporting book set ({ENV_REPORT_DIR}), so it has no settlement report to give"
        ));
    };
    let Some(capsulectl) = setup.capsulectl.as_deref() else {
        return refused(format!(
            "this node cannot check its settlement report: no capsulectl is set ({ENV_CAPSULECTL})"
        ));
    };
    let page_path = report_dir.join(PAGE_FILE);
    let page = match tokio::fs::read(&page_path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return refused(
                "no settlement report has been sealed yet: the node's owner makes one with scripts/settlement-report.sh",
            )
        }
        Err(e) => return refused(format!("the settlement report could not be read: {e}")),
    };
    let check = match report_check(capsulectl, report_dir, &page_path).await {
        Ok(check) => check,
        Err(why) => return refused(why),
    };
    if check.get("page").and_then(Value::as_str) != Some("match")
        || check.get("verification").and_then(Value::as_str) != Some("VALID")
    {
        return refused(format!(
            "the settlement report did not check, so it is not handed over: {check}"
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
        .unwrap_or(Value::Null);
    json!({
        "state": "report",
        "page": page,
        "sealed_at": note.get("sealed_at").cloned().unwrap_or(Value::Null),
        "date": note.get("date").cloned().unwrap_or(Value::Null),
        "check": check,
    })
}

/// `builder` with the `settlement-report` route declared.
pub fn with_route(builder: DeclarativePluginBuilder) -> DeclarativePluginBuilder {
    builder.http_item(
        http::get("/settlement-report")
            .binding_id("evidence_settlement_report")
            .description(
                "The node's latest sealed EvidenceBook settlement report, checked with the \
                 owner's capsulectl at hand-over, for the Evidence page's Settlement download.",
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
            r#"{"date":"2026-11-01","sealed_at":"2026-11-01T19:45:33Z"}"#,
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
            assert!(answered["why"].as_str().unwrap().contains("did not check"));
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
        assert!(none["why"].as_str().unwrap().contains(ENV_REPORT_DIR));

        let no_ctl = answer(&Setup {
            report_dir: Some(report_dir(dir.path())),
            capsulectl: None,
        })
        .await;
        assert!(no_ctl["why"].as_str().unwrap().contains(ENV_CAPSULECTL));

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

        let mut page = std::fs::read(copy.join(PAGE_FILE)).unwrap();
        let at = page.len() - 20;
        page[at] = if page[at] == b' ' { b'\n' } else { b' ' };
        std::fs::write(copy.join(PAGE_FILE), page).unwrap();
        let answered = answer(&setup).await;
        assert_eq!(answered["state"], "refused", "{answered}");
    }
}
