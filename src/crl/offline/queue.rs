//! Outbound pending-revocation queue, persisted under the pre-allocated
//! CRL pending/ directory. One JSON file per entry; atomic writes.

use crate::crl::entry::CrlEntry;
use crate::crl::errors::CrlError;
use crate::crl::persistence;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A revocation awaiting confirmed delivery to peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRevocation {
    /// The signed revocation entry (self-contained; verifiable by peers).
    pub entry: CrlEntry,
    /// Delivery attempts made so far.
    pub attempts: u32,
    /// When first queued (RFC3339).
    pub queued_at: String,
    /// Last attempt time (RFC3339), if any.
    pub last_attempt_at: Option<String>,
    /// Last error observed while attempting delivery, if any.
    pub last_error: Option<String>,
    /// Set true once parked (retry budget exhausted); still retained.
    #[serde(default)]
    pub parked: bool,
}

fn id_to_filename(id: &str) -> String {
    id.replace([':', '/'], "_")
}

fn path_for(id: &str) -> PathBuf {
    persistence::pending_dir().join(format!("{}.json", id_to_filename(id)))
}

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<(), CrlError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Enqueue an entry. Returns Ok(true) if newly queued, Ok(false) if already
/// present (idempotent).
pub fn enqueue(entry: &CrlEntry) -> Result<bool, CrlError> {
    let path = path_for(&entry.id);
    if path.exists() {
        return Ok(false);
    }
    let pending = PendingRevocation {
        entry: entry.clone(),
        attempts: 0,
        queued_at: Utc::now().to_rfc3339(),
        last_attempt_at: None,
        last_error: None,
        parked: false,
    };
    write_atomic(&path, &serde_json::to_vec_pretty(&pending)?)?;
    Ok(true)
}

/// Load every pending revocation (ignoring temp files).
pub fn list() -> Result<Vec<PendingRevocation>, CrlError> {
    let dir = persistence::pending_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().map(|ext| ext == "tmp").unwrap_or(false) {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        if let Ok(pending) = serde_json::from_slice::<PendingRevocation>(&bytes) {
            out.push(pending);
        }
    }
    out.sort_by(|a, b| a.queued_at.cmp(&b.queued_at));
    Ok(out)
}

pub fn count() -> usize {
    list().map(|items| items.len()).unwrap_or(0)
}

/// Remove a pending entry (delivered or superseded).
pub fn dequeue(entry_id: &str) -> Result<(), CrlError> {
    let path = path_for(entry_id);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Record an attempt outcome for a pending entry (attempts += 1, timestamps).
pub fn record_attempt(
    entry_id: &str,
    error: Option<String>,
    max_retries: u32,
) -> Result<(), CrlError> {
    let path = path_for(entry_id);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(());
    };
    let mut pending: PendingRevocation = serde_json::from_slice(&bytes)?;
    pending.attempts = pending.attempts.saturating_add(1);
    pending.last_attempt_at = Some(Utc::now().to_rfc3339());
    pending.last_error = error;
    if max_retries > 0 && pending.attempts >= max_retries {
        pending.parked = true;
    }
    write_atomic(&path, &serde_json::to_vec_pretty(&pending)?)?;
    Ok(())
}

/// Reconcile the queue from local state: any locally-issued
/// (`revoker_did == self_did`) entry that is not yet `propagated` should be
/// tracked as pending. Covers CLI-issued revocations and restart recovery.
/// Returns the number of entries newly added.
pub fn reconcile_from_local(self_did: &str) -> Result<usize, CrlError> {
    let crl = match persistence::load_crl()? {
        Some(crl) => crl,
        None => return Ok(0),
    };
    let mut added = 0;
    for entry in &crl.entries {
        if entry.revoker_did == self_did && !entry.propagated && enqueue(entry)? {
            added += 1;
        }
    }
    Ok(added)
}
