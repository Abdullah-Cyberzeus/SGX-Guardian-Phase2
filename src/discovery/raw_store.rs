//! Persist raw NMAP XML to disk for forensic re-parsing, keeping only the
//! last N files. Called by both the scheduler and the CLI scan path.

use crate::discovery::error::{DiscoveryError, DiscoveryResult};
use std::path::Path;

pub struct RawXmlStore;

const KEEP_LAST_N: usize = 10;

impl RawXmlStore {
    /// Write XML to `<state_dir>/raw/<unix_timestamp>.xml` then prune to last N.
    /// Best-effort: failures are returned but the caller can choose to log+ignore
    /// rather than fail the whole scan.
    pub fn persist(state_dir: &Path, xml: &str) -> DiscoveryResult<()> {
        let raw_dir = state_dir.join("raw");
        std::fs::create_dir_all(&raw_dir)?;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = raw_dir.join(format!("{}.xml", ts));

        // Atomic write: tmp + rename.
        let tmp = path.with_extension("xml.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(xml.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;

        // Prune oldest beyond KEEP_LAST_N.
        let mut entries: Vec<_> = std::fs::read_dir(&raw_dir)?
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().map(|x| x == "xml").unwrap_or(false))
            .filter_map(|e| {
                let meta = e.metadata().ok()?;
                let mtime = meta.modified().ok()?;
                Some((e.path(), mtime))
            })
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1)); // newest first

        for (p, _) in entries.into_iter().skip(KEEP_LAST_N) {
            let _ = std::fs::remove_file(p);
        }

        Ok(())
    }

    pub fn list(state_dir: &Path) -> DiscoveryResult<Vec<std::path::PathBuf>> {
        let raw_dir = state_dir.join("raw");
        if !raw_dir.exists() {
            return Ok(vec![]);
        }
        let mut entries: Vec<_> = std::fs::read_dir(&raw_dir)
            .map_err(DiscoveryError::Io)?
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().map(|x| x == "xml").unwrap_or(false))
            .map(|e| e.path())
            .collect();
        entries.sort();
        Ok(entries)
    }
}
