//! `capsules export-flat`: the shelf back to the flat layout earlier releases
//! read, losing nothing (Mesh-LLM/capsules-plugin#218).
//!
//! The move onto the shelf (`chain_store::import_flat`) is one way: a release
//! up to 0.1.8 finds no `capsules.jsonl` on a shelf node, starts a new, empty
//! log under the same log id and contradicts the checkpoints peers hold. This
//! writes the files that release reads from what the shelf keeps, with the
//! node stopped and no signing key needed to sign anything:
//!
//! - `capsules.jsonl`: `chain_store::chain_lines`, padding included;
//! - `signed-statements/<capsule_id>.cose`: each record's unbound
//!   `signed-statement` attachment (`chain_store::statement`);
//! - `checkpoints.jsonl`: `chain_store::checkpoints_text`, the witness
//!   receipts inline (so no `witness-backfill.jsonl` is needed);
//! - `mmr_nodes.dat`: written by the flat `CheckpointState::load` that checks
//!   the result.
//!
//! The files are written into `ledger/.flat-export/` and checked there with
//! the flat `Ledger::open_with_indexer` and `CheckpointState::load` against
//! the shelf's own ledger (same lines, entries and head; the latest
//! checkpoint). Only then do they move into `ledger/` and `shelf.db` (with its
//! `-wal` and `-shm`) moves to `<data dir>/archive/shelf-export-<time>/`, with
//! `archive/pre-store/` (the flat files the import archived, now older than the
//! export), so a later import onto a new shelf finds that archive free.
//! Nothing but the scratch directory of an earlier, unfinished run is ever
//! deleted. `capsules.jsonl` moves in last and the shelf is set aside after
//! it, so an earlier release reads the flat files at every point; a run cut
//! short finishes at the next run.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde_json::Value;

use crate::chain_store::{
    self, ChainStores, FLAT_CAPSULES_FILE, FLAT_CHECKPOINTS_FILE, IMPORT_JOURNAL, SHELF_FILE,
};
use crate::producer::checkpoint::{CheckpointCadenceConfig, CheckpointState};
use crate::producer::ledger::Ledger;

/// The scratch directory beside the shelf the flat files are built in.
const STAGING: &str = ".flat-export";
const STATEMENTS: &str = "signed-statements";
const MMR_FILE: &str = "mmr_nodes.dat";
/// In the scratch directory: the name of the `archive/` directory this run
/// sets the shelf aside in, written before anything moves in, so a cut-short
/// run finishes into the same directory and never into an earlier export's.
pub(crate) const ASIDE_NOTE: &str = "aside";
/// The staged files, in the order they move in.
const STAGED: [&str; 4] = [
    STATEMENTS,
    FLAT_CHECKPOINTS_FILE,
    MMR_FILE,
    FLAT_CAPSULES_FILE,
];
/// The shelf's SQLite files.
const SHELF_FILES: [&str; 3] = [SHELF_FILE, "shelf.db-wal", "shelf.db-shm"];

/// What an export did.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportReport {
    pub lines: usize,
    pub checkpoints: usize,
    pub head: Option<String>,
    /// Where `shelf.db` went.
    pub shelf_set_aside: PathBuf,
}

/// `capsules export-flat [--data-dir DIR]`. Exit 0 on success, 2 for a usage
/// error, 1 when the export is refused or fails (the shelf is then where it
/// was).
pub fn cli(args: &[String]) -> i32 {
    const USAGE: &str = "usage: capsules export-flat [--data-dir DIR]";
    let data_dir = match args {
        [] => crate::data_dir::data_dir(),
        [flag, dir] if flag == "--data-dir" && !dir.is_empty() => Ok(PathBuf::from(dir)),
        _ => {
            eprintln!("export-flat: {USAGE}");
            return 2;
        }
    };
    let result = data_dir.and_then(|dir| {
        let lock = crate::data_dir::lock(&dir)
            .context("stop the node before exporting: the data directory is in use")?;
        let report = export(&dir);
        drop(lock);
        report
    });
    match result {
        Ok(r) => {
            println!(
                "exported {} lines and {} checkpoints to the flat layout (head {}); shelf.db is \
                 in {}",
                r.lines,
                r.checkpoints,
                r.head.as_deref().unwrap_or("none"),
                r.shelf_set_aside.display()
            );
            0
        }
        Err(e) => {
            eprintln!("export-flat: {e:#}");
            1
        }
    }
}

/// Export the shelf under `data_dir` to the flat layout. The caller holds the
/// data directory's writer lock (`data_dir::lock`).
pub fn export(data_dir: &Path) -> anyhow::Result<ExportReport> {
    let ledger_dir = data_dir.join("ledger");
    let staging = ledger_dir.join(STAGING);

    // A run cut short after the flat files moved in (the scratch directory is
    // removed last): the flat ledger is complete and only the shelf is left to
    // set aside.
    if staging.exists()
        && !staging.join(FLAT_CAPSULES_FILE).exists()
        && ledger_dir.join(FLAT_CAPSULES_FILE).exists()
        && !ledger_dir.join(IMPORT_JOURNAL).exists()
    {
        let (lines, checkpoints, head) = summarize(&ledger_dir)?;
        let aside = set_shelf_aside(data_dir, &ledger_dir, &staging)?;
        return Ok(ExportReport {
            lines,
            checkpoints,
            head,
            shelf_set_aside: aside,
        });
    }
    if ledger_dir.join(FLAT_CAPSULES_FILE).exists() || ledger_dir.join(IMPORT_JOURNAL).exists() {
        bail!(
            "{} is not on the shelf: it holds {} or an unfinished import; there is nothing to \
             export",
            ledger_dir.display(),
            FLAT_CAPSULES_FILE
        );
    }
    if !chain_store::is_store_layout(&ledger_dir) {
        bail!("{} holds no {SHELF_FILE}", ledger_dir.display());
    }
    // A run cut short while the files moved in (it moves `capsules.jsonl`
    // last, after writing the note): those in `ledger/` that the scratch
    // directory no longer holds are its own, renamed. Put them back and build
    // afresh. Any other scratch directory proves nothing about `ledger/`'s
    // files, which the check below refuses.
    if staging.join(ASIDE_NOTE).exists() && staging.join(FLAT_CAPSULES_FILE).exists() {
        for name in STAGED {
            let (staged, moved) = (staging.join(name), ledger_dir.join(name));
            if !staged.exists() && moved.exists() {
                fs::rename(&moved, &staged)?;
            }
        }
    }
    // Refuse before anything is written, so a refusal leaves the shelf as it
    // was.
    for name in STAGED {
        if ledger_dir.join(name).exists() {
            bail!(
                "{} exists beside the shelf; move it away first",
                ledger_dir.join(name).display()
            );
        }
    }
    // Scratch of an earlier run that did not finish; the shelf is still here.
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(staging.join(STATEMENTS))?;

    let lines = chain_store::chain_lines(&ledger_dir)?;
    let mut text = Vec::new();
    let mut ids = Vec::with_capacity(lines.len());
    for line in &lines {
        let id = serde_json::from_slice::<Value>(line)?
            .get("capsule_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("a line of the chain has no capsule_id")?;
        let statement = chain_store::statement(&ledger_dir, &id)
            .with_context(|| format!("the shelf holds no signed statement for {id}"))?;
        write_synced(
            &staging.join(STATEMENTS).join(format!("{id}.cose")),
            &statement,
        )?;
        text.extend_from_slice(line);
        text.push(b'\n');
        ids.push(id);
    }
    write_synced(&staging.join(FLAT_CAPSULES_FILE), &text)?;
    let checkpoints = chain_store::checkpoints_text(&ledger_dir)?.unwrap_or_default();
    write_synced(&staging.join(FLAT_CHECKPOINTS_FILE), &checkpoints)?;
    let checkpoint_count = checkpoints.iter().filter(|&&b| b == b'\n').count();

    // Check the staged files the way the earlier release opens them, against
    // the shelf's own ledger.
    let log_id = check(&ledger_dir, data_dir, &staging, &ids, &checkpoints)?;
    tracing::info!(log_id, "the staged flat ledger opens");
    let head = {
        let (ledger, _) =
            Ledger::open_with_indexer(&staging, crate::producer::index::record_index_keys)?;
        ledger.chain_head().map(str::to_owned)
    };

    // The flat files go in first, `capsules.jsonl` last, then the shelf is set
    // aside. A crash in between leaves both: an earlier release reads the flat
    // files and ignores `shelf.db`, and the next run finishes.
    let aside_name = format!(
        "shelf-export-{}",
        crate::producer::timestamp::utc_now_iso8601().replace(':', "-")
    );
    write_synced(&staging.join(ASIDE_NOTE), aside_name.as_bytes())?;
    promote(&staging, &ledger_dir)?;
    let aside = set_shelf_aside(data_dir, &ledger_dir, &staging)?;
    Ok(ExportReport {
        lines: ids.len(),
        checkpoints: checkpoint_count,
        head,
        shelf_set_aside: aside,
    })
}

/// Move the shelf (and the import's `archive/pre-store/`) into the
/// `archive/` directory the scratch directory names ([`ASIDE_NOTE`]), then
/// remove the scratch directory. The import's archive of the flat files this
/// shelf replaced would make the next import refuse (`move_flat_files`
/// overwrites nothing), and its files are older than the ones just written,
/// so they go with the shelf. Nothing is moved onto an existing file.
fn set_shelf_aside(data_dir: &Path, ledger_dir: &Path, staging: &Path) -> anyhow::Result<PathBuf> {
    let archive = data_dir.join(crate::owner_maintenance::ARCHIVE_DIR);
    let name = fs::read_to_string(staging.join(ASIDE_NOTE))
        .context("the scratch directory does not say where the shelf goes")?;
    let aside = archive.join(name.trim());
    fs::create_dir_all(&aside)?;
    // The main file first, so a `-wal` is never left beside a new
    // `shelf.db`; the next run moves what a crash left.
    for name in SHELF_FILES {
        let from = ledger_dir.join(name);
        if from.exists() {
            move_to(&from, &aside.join(name))?;
        }
    }
    let pre_store = archive.join(chain_store::PRE_STORE_ARCHIVE);
    if pre_store.exists() {
        move_to(&pre_store, &aside.join(chain_store::PRE_STORE_ARCHIVE))?;
    }
    fs::remove_dir_all(staging)?;
    Ok(aside)
}

fn move_to(from: &Path, to: &Path) -> anyhow::Result<()> {
    if to.exists() {
        bail!("{} exists; refusing to overwrite it", to.display());
    }
    fs::rename(from, to)?;
    Ok(())
}

/// Open the staged files as the earlier release does and compare them with
/// the shelf. Returns the log id the checkpoints carry.
fn check(
    ledger_dir: &Path,
    data_dir: &Path,
    staging: &Path,
    ids: &[String],
    checkpoints: &[u8],
) -> anyhow::Result<String> {
    let checkpoint_values: Vec<Value> = checkpoints
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()?;
    let keys = chain_store::keys_beside(ledger_dir);
    let log_id = match checkpoint_values
        .first()
        .and_then(|c| c.get("log_id"))
        .and_then(Value::as_str)
    {
        Some(id) => id.to_owned(),
        None => {
            let key = keys
                .first()
                .map(|k| hex::encode(k.verifying_key().to_bytes()))
                .unwrap_or_default();
            crate::owner_maintenance::current_log_id(
                data_dir,
                &crate::owner_maintenance::default_log_id("capsules", &key),
            )
        }
    };

    let (flat, _) = Ledger::open_with_indexer(staging, crate::producer::index::record_index_keys)
        .context("the staged flat ledger does not open")?;
    let flat_ids: Vec<&str> = flat.lines().iter().map(|l| l.capsule_id.as_str()).collect();
    if flat_ids != ids.iter().map(String::as_str).collect::<Vec<_>>() {
        bail!("the staged flat ledger does not hold the shelf's lines in order");
    }
    {
        let stores = ChainStores::open(ledger_dir, &log_id, &keys)?;
        let (shelf, _) = stores.open_ledger()?;
        if shelf.entries() != flat.entries() || shelf.chain_head() != flat.chain_head() {
            bail!(
                "the staged flat ledger has {} entries and head {:?}; the shelf has {} and {:?}",
                flat.entries(),
                flat.chain_head(),
                shelf.entries(),
                shelf.chain_head()
            );
        }
    }
    let (state, _) =
        CheckpointState::load(staging, log_id.clone(), CheckpointCadenceConfig::default())
            .map_err(|e| anyhow::anyhow!("the staged checkpoint state does not load: {e}"))?;
    if state.leaf_count() != ids.len() as u64 {
        bail!(
            "the staged checkpoint state covers {} leaves, the chain {}",
            state.leaf_count(),
            ids.len()
        );
    }
    match (state.last_checkpoint(), checkpoint_values.last()) {
        (None, None) => {}
        (Some(loaded), Some(last)) => {
            if last.get("mmr_size").and_then(Value::as_u64) != Some(loaded.mmr_size)
                || last.get("root").and_then(Value::as_str) != Some(loaded.root.as_str())
            {
                bail!("the staged checkpoint state's latest checkpoint is not the shelf's");
            }
        }
        _ => bail!("the staged checkpoint state and the shelf disagree on having checkpoints"),
    }
    Ok(log_id)
}

/// Lines, checkpoints and head of the flat ledger in `dir`.
fn summarize(dir: &Path) -> anyhow::Result<(usize, usize, Option<String>)> {
    let (ledger, _) = Ledger::open_with_indexer(dir, crate::producer::index::record_index_keys)?;
    let checkpoints = fs::read(dir.join(FLAT_CHECKPOINTS_FILE))
        .map(|t| t.iter().filter(|&&b| b == b'\n').count())
        .unwrap_or(0);
    Ok((
        ledger.lines().len(),
        checkpoints,
        ledger.chain_head().map(str::to_owned),
    ))
}

/// Move the staged files into `ledger_dir`, `capsules.jsonl` last. The
/// scratch directory stays until the shelf is set aside: it marks the export
/// as unfinished.
fn promote(staging: &Path, ledger_dir: &Path) -> anyhow::Result<()> {
    for name in STAGED {
        let from = staging.join(name);
        let to = ledger_dir.join(name);
        if to.exists() {
            bail!("{} exists; refusing to overwrite it", to.display());
        }
        fs::rename(&from, &to)?;
    }
    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
