//! The ledger's format marker: `ledger/format`, one integer.
//!
//! A build that opens the ledger writes the number it writes ledgers in
//! ([`CURRENT`]) and refuses a ledger marked with a higher one, so a rollback
//! to a build that cannot read the ledger stops at a clear start error naming
//! the cause, not deep in the checkpoint check (#308: the build before the
//! checkpointed-local-log 0.6 stack reads the bare-id checkpoint `sub` as a
//! failed COSE check and takes a node with a required `capsules` down).
//!
//! Format 1 is the checkpointed-local-log 0.6 stack (#300): a checkpoint's CWT
//! `sub` is the bare log id. A ledger with no marker was written by a build
//! that predates this check; it is stamped on first open. Builds before this
//! one do not read the marker, so it cannot protect a rollback to them; the
//! changelog says to back the data directory up before upgrading.
//!
//! It is checked first, before a pending new history moves the ledger
//! (`owner_maintenance::resolve_log_id`), and again when the ledger opens.
//!
//! Raise [`CURRENT`] only for a change an older build cannot read.

use std::path::Path;

/// The marker's file name, in the ledger directory.
pub const FILE: &str = "format";
/// The format this build writes and the highest it reads.
pub const CURRENT: u32 = 1;

/// Refuse a ledger written in a newer format; otherwise stamp [`CURRENT`].
pub fn check_and_stamp(ledger_dir: &Path) -> anyhow::Result<()> {
    let path = ledger_dir.join(FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let found: u32 = text.trim().parse().map_err(|_| {
                anyhow::anyhow!(
                    "the ledger's format marker {} is not a number; this ledger was written by a newer or foreign plugin",
                    path.display()
                )
            })?;
            if found > CURRENT {
                anyhow::bail!(
                    "this ledger was written by a newer plugin (ledger format {found}, this build reads up to {CURRENT}); downgrade is not supported: run the newer plugin again, or restore a backup of the data directory taken before the upgrade ({})",
                    ledger_dir.display()
                );
            }
            if found == CURRENT {
                return Ok(());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    }
    std::fs::create_dir_all(ledger_dir)?;
    // Replaced whole (written, synced, renamed): a write cut short must not
    // leave an empty marker that refuses a sound ledger on every start.
    crate::owner_maintenance::write_atomically(&path, format!("{CURRENT}\n").as_bytes())
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_a_ledger_with_no_marker() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger");
        check_and_stamp(&ledger).unwrap();
        assert_eq!(
            std::fs::read_to_string(ledger.join(FILE)).unwrap().trim(),
            CURRENT.to_string()
        );
        check_and_stamp(&ledger).unwrap();
    }

    #[test]
    fn refuses_a_newer_format_and_names_the_cause() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), format!("{}\n", CURRENT + 1)).unwrap();
        let err = check_and_stamp(dir.path()).unwrap_err().to_string();
        assert!(err.contains("written by a newer plugin"), "{err}");
        assert!(err.contains("downgrade is not supported"), "{err}");
        // The marker is left as it was.
        assert_eq!(
            std::fs::read_to_string(dir.path().join(FILE))
                .unwrap()
                .trim(),
            (CURRENT + 1).to_string()
        );
    }

    #[test]
    fn refuses_an_unreadable_marker_and_keeps_an_older_one_updated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), "x").unwrap();
        assert!(check_and_stamp(dir.path()).is_err());
        std::fs::write(dir.path().join(FILE), "0\n").unwrap();
        check_and_stamp(dir.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(FILE))
                .unwrap()
                .trim(),
            CURRENT.to_string()
        );
    }
}
