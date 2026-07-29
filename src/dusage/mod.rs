//! Data usage monitoring for Guardian boards.
//!
//! The core source is `/sys/class/net/<iface>/statistics/*`: cumulative
//! interface counters are sampled periodically and converted into
//! baseline-relative period usage. Optional nft named counters add
//! per-category visibility without changing firewall accept/drop behaviour.

pub mod counters;
pub mod devices;
pub mod errors;
pub mod model;
pub mod quota;
pub mod sampler;
pub mod state;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::dusage::errors::DusageResult;
use crate::dusage::model::{DusageQuota, UsageSnapshot};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DusageConfig {
    pub enabled: bool,
    pub sample_secs: u64,
    pub period: String,
    pub sys_class_net: PathBuf,
    pub enable_categories: bool,
    pub enable_devices: bool,
}

impl DusageConfig {
    pub const DEFAULT_SAMPLE_SECS: u64 = 60;

    pub fn from_env() -> Self {
        let period = std::env::var("SGX_DUSAGE_PERIOD")
            .ok()
            .and_then(|raw| quota::normalize_period(&raw).ok())
            .unwrap_or_else(|| quota::DEFAULT_PERIOD.to_string());
        Self {
            enabled: parse_enabled(std::env::var("SGX_DUSAGE_ENABLED").ok()),
            sample_secs: parse_sample_secs(std::env::var("SGX_DUSAGE_SAMPLE_SECS").ok()),
            period,
            sys_class_net: std::env::var(counters::SYS_CLASS_NET_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/sys/class/net")),
            enable_categories: parse_enabled(std::env::var("SGX_DUSAGE_CATEGORIES_ENABLED").ok()),
            enable_devices: parse_enabled(std::env::var(devices::CONNTRACK_ENABLED_ENV).ok()),
        }
    }
}

pub fn spawn(node_id: String) {
    let config = DusageConfig::from_env();
    if !config.enabled {
        println!("Data-usage sampler disabled via SGX_DUSAGE_ENABLED");
        return;
    }

    println!(
        "Data-usage sampler starting interval_secs={} period={} sys_root={}",
        config.sample_secs,
        config.period,
        config.sys_class_net.display()
    );
    log_audit(
        &node_id,
        AuditCategory::Dusage,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!(
            "Data-usage sampler started interval_secs={} period={}",
            config.sample_secs, config.period
        ),
    );
    tokio::spawn(sampler::run_loop(node_id, config));
}

pub async fn current_snapshot() -> DusageResult<UsageSnapshot> {
    sampler::sample_once(&DusageConfig::from_env()).await
}

pub async fn reset_now() -> DusageResult<UsageSnapshot> {
    sampler::reset_now(&DusageConfig::from_env()).await
}

pub async fn history() -> DusageResult<Vec<UsageSnapshot>> {
    state::load_history().await
}

pub async fn get_quota() -> DusageResult<Option<DusageQuota>> {
    let config = DusageConfig::from_env();
    state::load_quota()
        .await
        .map(|quota| quota.or_else(|| quota::env_default_quota(&config.period)))
}

pub async fn put_quota(quota_bytes: u64, period: String) -> DusageResult<DusageQuota> {
    let period = quota::normalize_period(&period)?;
    let sequence = state::load_quota()
        .await?
        .map(|quota| quota.sequence.saturating_add(1))
        .unwrap_or(1);
    let mut quota = DusageQuota::new(quota_bytes, period, sequence);
    state::save_quota(&mut quota).await?;
    Ok(quota)
}

fn parse_enabled(raw: Option<String>) -> bool {
    match raw {
        Some(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        None => true,
    }
}

fn parse_sample_secs(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DusageConfig::DEFAULT_SAMPLE_SECS)
        .clamp(5, 3600)
}
