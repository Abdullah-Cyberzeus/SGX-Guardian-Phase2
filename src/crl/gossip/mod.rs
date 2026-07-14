//! Epidemic-style gossip protocol for decentralized CRL propagation
//! for decentralized revocation propagation.
//!
//! * Every Guardian keeps its local CRL copy (stored at
//!   /var/lib/sgx-guardian/identity/crl/). No central authority - nodeA
//!   participates as an ordinary peer.
//! * `round_task` fires every SGX_CRL_GOSSIP_INTERVAL_SECS (default 60 s,
//!   spec window 1-5 min) plus +/-20 % jitter, picks ONE random active peer
//!   from cached peer DID Documents, and runs a push-pull anti-entropy
//!   exchange with it.
//! * `listener_task` serves inbound exchanges on SGX_CRL_GOSSIP_PORT
//!   (default 50063) on every node.
//! * Received entries are individually re-verified
//!   (`crl::verify::verify_entry`) against the issuer's DID Document
//!   before merging - the TCP channel is never trusted (it rides the
//!   encrypted Nebula overlay, but authenticity comes from per-entry
//!   ECDSA-P256 proofs).
//! * After each successful exchange both sides record the counterpart in
//!   every entry's `peers_notified` and flip `propagated` once
//!   peers_notified >= ceil(threshold_pct% x other Circle members).
//! * Anti-entropy = full fingerprint-set diff each round, so nodes
//!   converge to identical Merkle roots even after partitions, restarts,
//!   or missed rounds (eventual consistency).

pub mod engine;
pub mod protocol;
pub mod store;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// Runtime configuration sourced from environment with safe defaults.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub enabled: bool,
    pub port: u16,
    pub interval_secs: u64,
    pub threshold_pct: u8,
}

impl GossipConfig {
    pub const DEFAULT_PORT: u16 = 50063;
    pub const DEFAULT_INTERVAL_SECS: u64 = 60;
    pub const DEFAULT_THRESHOLD_PCT: u8 = 80;

    pub fn from_env() -> Self {
        Self {
            enabled: parse_enabled(std::env::var("SGX_CRL_GOSSIP_ENABLED").ok()),
            port: parse_port(std::env::var("SGX_CRL_GOSSIP_PORT").ok()),
            interval_secs: parse_interval(std::env::var("SGX_CRL_GOSSIP_INTERVAL_SECS").ok()),
            threshold_pct: parse_threshold(std::env::var("SGX_CRL_GOSSIP_THRESHOLD_PCT").ok()),
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

pub(crate) fn parse_port(raw: Option<String>) -> u16 {
    raw.and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(GossipConfig::DEFAULT_PORT)
}

/// Spec window is 1-5 minutes; the 10 s floor is relaxed strictly as a
/// board-testing accelerator (documented in the verification log).
pub(crate) fn parse_interval(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(GossipConfig::DEFAULT_INTERVAL_SECS)
        .clamp(10, 300)
}

pub(crate) fn parse_threshold(raw: Option<String>) -> u8 {
    raw.and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(GossipConfig::DEFAULT_THRESHOLD_PCT)
        .clamp(1, 100)
}

/// Entry point called from `main.rs` right after the REST API spawn.
/// Spawns two background tokio tasks and returns immediately. Never
/// blocks, never panics, safe on every node role (CA and members alike).
pub fn spawn(node_id: String, resolver: crate::did::Resolver) {
    let config = GossipConfig::from_env();
    if !config.enabled {
        println!("🗣️ CRL-GOSSIP disabled via SGX_CRL_GOSSIP_ENABLED");
        return;
    }
    println!(
        "🗣️ CRL-GOSSIP engine starting port={} interval_secs={} threshold_pct={}",
        config.port, config.interval_secs, config.threshold_pct
    );
    crate::audit::logger::log_audit(
        &node_id,
        crate::audit::event::AuditCategory::Crl,
        crate::audit::event::AuditSeverity::Info,
        crate::audit::event::AuditAction::Started,
        &format!(
            "CRL gossip engine started port={} interval_secs={} threshold_pct={}",
            config.port, config.interval_secs, config.threshold_pct
        ),
    );
    tokio::spawn(engine::listener_task(
        node_id.clone(),
        resolver.clone(),
        config.clone(),
    ));
    tokio::spawn(engine::round_task(node_id, resolver, config));
}
