//! Offline revocation sync for Guardians in disconnected environments.
//!
//! When a Guardian is offline it can still issue revocations (they land in
//! the local crl.json and the pending/ queue). A background loop measures
//! peer reachability; on reconnect it synchronously drives the existing
//! gossip anti-entropy exchange to (a) fetch revocations missed while
//! offline and (b) flush the outbound queue, tracking retry counts and
//! timestamps per pending entry. Conflict resolution reuses the shared
//! gossip merge (deterministic, timestamp-based), so offline-fetched and
//! gossip-fetched entries never diverge.
//!
//! No new port, no new listener: peers are reached via the existing gossip
//! exchange on TCP 50063.

pub mod queue;
pub mod sync;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[derive(Debug, Clone)]
pub struct OfflineConfig {
    pub enabled: bool,
    pub sync_interval_secs: u64,
    pub max_retries: u32,
    pub flush_rounds: u32,
    pub probe_timeout_ms: u64,
}

impl OfflineConfig {
    pub const DEFAULT_INTERVAL_SECS: u64 = 20;
    pub const DEFAULT_FLUSH_ROUNDS: u32 = 3;
    pub const DEFAULT_PROBE_TIMEOUT_MS: u64 = 1500;

    pub fn from_env() -> Self {
        Self {
            enabled: parse_enabled(std::env::var("SGX_CRL_OFFLINE_ENABLED").ok()),
            sync_interval_secs: parse_interval(
                std::env::var("SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS").ok(),
            ),
            max_retries: parse_max_retries(std::env::var("SGX_CRL_OFFLINE_MAX_RETRIES").ok()),
            flush_rounds: parse_flush_rounds(std::env::var("SGX_CRL_OFFLINE_FLUSH_ROUNDS").ok()),
            probe_timeout_ms: parse_probe_timeout(
                std::env::var("SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS").ok(),
            ),
        }
    }
}

pub(crate) fn parse_enabled(raw: Option<String>) -> bool {
    match raw {
        Some(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off"
        ),
        None => true,
    }
}

pub(crate) fn parse_interval(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(OfflineConfig::DEFAULT_INTERVAL_SECS)
        .clamp(5, 600)
}

pub(crate) fn parse_max_retries(raw: Option<String>) -> u32 {
    raw.and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .min(1000)
}

pub(crate) fn parse_flush_rounds(raw: Option<String>) -> u32 {
    raw.and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(OfflineConfig::DEFAULT_FLUSH_ROUNDS)
        .clamp(1, 20)
}

pub(crate) fn parse_probe_timeout(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(OfflineConfig::DEFAULT_PROBE_TIMEOUT_MS)
        .clamp(200, 10_000)
}

/// Entry point called from main.rs right after the gossip spawn. Spawns the
/// background sync loop. Returns immediately; safe on every node role.
pub fn spawn(node_id: String, resolver: crate::did::Resolver) {
    let config = OfflineConfig::from_env();
    if !config.enabled {
        println!("CRL-OFFLINE sync disabled via SGX_CRL_OFFLINE_ENABLED");
        return;
    }
    println!(
        "CRL-OFFLINE sync starting interval_secs={} flush_rounds={} max_retries={}",
        config.sync_interval_secs,
        config.flush_rounds,
        if config.max_retries == 0 {
            "unlimited".to_string()
        } else {
            config.max_retries.to_string()
        }
    );
    crate::audit::logger::log_audit(
        &node_id,
        crate::audit::event::AuditCategory::Crl,
        crate::audit::event::AuditSeverity::Info,
        crate::audit::event::AuditAction::Started,
        &format!(
            "CRL offline sync started interval_secs={} flush_rounds={}",
            config.sync_interval_secs, config.flush_rounds
        ),
    );
    tokio::spawn(sync::sync_loop(node_id, resolver, config));
}

/// Enqueue a just-issued revocation for guaranteed delivery. Called by the
/// REST revoke handler; idempotent (safe if the entry is already queued).
pub fn queue_pending(node_id: &str, entry: &crate::crl::entry::CrlEntry) {
    if !OfflineConfig::from_env().enabled {
        return;
    }
    match queue::enqueue(entry) {
        Ok(true) => {
            crate::audit::logger::log_audit(
                node_id,
                crate::audit::event::AuditCategory::Crl,
                crate::audit::event::AuditSeverity::Info,
                crate::audit::event::AuditAction::Created,
                &format!(
                    "CRL offline queued pending revocation revoked_did={} id={}",
                    entry.revoked_did, entry.id
                ),
            );
        }
        Ok(false) => {}
        Err(error) => {
            tracing::warn!("CRL-OFFLINE enqueue failed for {}: {}", entry.id, error);
        }
    }
}
