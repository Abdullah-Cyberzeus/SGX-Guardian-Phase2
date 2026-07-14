//! Durable, queryable emergency-notification feed.
//!
//! "Send push notifications to users" — the backend does NOT hold Apple/
//! Google push credentials (that's the mobile app's job). Instead we persist
//! a compact, append-only feed of critical revocation events that the
//! frontend polls (`GET /api/v1/crl/emergency/notifications`) and converts
//! into APNs/FCM push. Also mirrored into the tamper-evident audit chain.
//!
//! Storage: newline-delimited JSON at
//! /var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl
//! (same identity/crl dir as crl.json). Bounded read for the API.

use crate::crl::entry::CrlEntry;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

pub const MAX_FEED_RETURN: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyNotification {
    pub notified_at: String,
    pub revoked_did: String,
    pub reason: String,
    pub severity: String,
    pub revoker_did: String,
    pub origin_did: String,
    pub sessions_terminated: usize,
    /// User-facing headline the app can render directly.
    pub headline: String,
}

fn feed_path() -> PathBuf {
    let base = std::env::var("SGX_GUARDIAN_CRL_DIR")
        .unwrap_or_else(|_| "/var/lib/sgx-guardian/identity/crl".to_string());
    PathBuf::from(base).join("emergency_notifications.jsonl")
}

/// Append one notification. Best-effort: failures are logged, never fatal
/// (a missed feed line must not break revocation propagation).
pub fn record(node_id: &str, entry: &CrlEntry, origin_did: &str, sessions_terminated: usize) {
    let note = EmergencyNotification {
        notified_at: chrono::Utc::now().to_rfc3339(),
        revoked_did: entry.revoked_did.clone(),
        reason: entry.reason.as_str().to_string(),
        severity: entry.severity.as_str().to_string(),
        revoker_did: entry.revoker_did.clone(),
        origin_did: origin_did.to_string(),
        sessions_terminated,
        headline: format!(
            "Security alert: a device was revoked ({}). Sessions with it were closed.",
            entry.reason.as_str()
        ),
    };
    if let Err(error) = append(&note) {
        tracing::warn!("emergency notification append failed: {}", error);
        return;
    }
    let _ = node_id;
}

fn append(note: &EmergencyNotification) -> std::io::Result<()> {
    let path = feed_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut line = serde_json::to_string(note).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    file.write_all(line.as_bytes())
}

/// Most-recent-first feed (bounded). Empty vec if the feed doesn't exist yet.
pub fn recent(limit: usize) -> Vec<EmergencyNotification> {
    let path = feed_path();
    let Ok(file) = std::fs::File::open(&path) else {
        return Vec::new();
    };
    let mut out: Vec<EmergencyNotification> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect();
    out.reverse();
    out.truncate(limit.min(MAX_FEED_RETURN));
    out
}
