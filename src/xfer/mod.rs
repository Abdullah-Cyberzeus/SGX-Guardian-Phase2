//! Chunked in-Circle file transfer.

pub mod engine;
pub mod errors;
pub mod manifest;
pub mod persistence;
pub mod protocol;
pub mod store;
pub mod verify;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

pub const MAX_TRANSFER_FILE_BYTES: u64 = 52_428_800;

#[cfg(test)]
#[cfg(test)]
pub(crate) async fn lock_test_env() -> crate::test_support::EnvLockGuard {
    crate::test_support::env_lock()
}

/// Runtime configuration sourced from environment with safe defaults.
#[derive(Debug, Clone)]
pub struct XferConfig {
    pub enabled: bool,
    pub port: u16,
    pub chunk_bytes: u32,
    pub max_file_bytes: u64,
}

impl XferConfig {
    pub const DEFAULT_PORT: u16 = 50064;
    pub const DEFAULT_CHUNK_BYTES: u32 = 262_144;
    pub const DEFAULT_MAX_FILE_BYTES: u64 = MAX_TRANSFER_FILE_BYTES;

    pub fn from_env() -> Self {
        Self {
            enabled: parse_enabled(std::env::var("SGX_XFER_ENABLED").ok()),
            port: parse_port(std::env::var("SGX_XFER_PORT").ok()),
            chunk_bytes: parse_chunk_bytes(std::env::var("SGX_XFER_CHUNK_BYTES").ok()),
            max_file_bytes: parse_max_file_bytes(std::env::var("SGX_XFER_MAX_FILE_BYTES").ok()),
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
        .unwrap_or(XferConfig::DEFAULT_PORT)
}

pub(crate) fn parse_chunk_bytes(raw: Option<String>) -> u32 {
    raw.and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(XferConfig::DEFAULT_CHUNK_BYTES)
        .clamp(65_536, 524_288)
}

pub(crate) fn parse_max_file_bytes(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|size| *size > 0)
        .unwrap_or(XferConfig::DEFAULT_MAX_FILE_BYTES)
        .min(MAX_TRANSFER_FILE_BYTES)
}

/// Entry point called from `main.rs` after the REST API spawn.
/// Spawns one background listener task and returns immediately.
pub fn spawn(node_id: String, resolver: crate::did::Resolver) {
    let config = XferConfig::from_env();
    if !config.enabled {
        println!("📦 XFER disabled via SGX_XFER_ENABLED");
        return;
    }
    println!(
        "📦 XFER engine starting port={} chunk_bytes={} max_file_bytes={}",
        config.port, config.chunk_bytes, config.max_file_bytes
    );
    crate::audit::logger::log_audit(
        &node_id,
        crate::audit::event::AuditCategory::Xfer,
        crate::audit::event::AuditSeverity::Info,
        crate::audit::event::AuditAction::Started,
        &format!(
            "XFER engine started port={} chunk_bytes={} max_file_bytes={}",
            config.port, config.chunk_bytes, config.max_file_bytes
        ),
    );
    tokio::spawn(engine::listener_task(node_id, resolver, config));
}
