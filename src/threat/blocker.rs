use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::{
    config::{BlockMode, SuricataConfig},
    error::{ThreatError, ThreatResult},
    threat_alert::{Severity, ThreatAlert},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockRecord {
    pub ip: String,
    pub expires_at: i64,
}

pub struct Blocker {
    cfg: Arc<Mutex<SuricataConfig>>,
    /// ip -> expiry epoch seconds
    active: Arc<Mutex<HashMap<String, i64>>>,
    node_id: String,
    state_path: PathBuf,
}

impl Blocker {
    pub fn new(cfg: Arc<Mutex<SuricataConfig>>, node_id: String, state_dir: PathBuf) -> Self {
        Self {
            cfg,
            active: Arc::new(Mutex::new(HashMap::new())),
            node_id,
            state_path: state_dir.join("blocked_ips.json"),
        }
    }

    /// Pure decision function - safe to unit test without nftables.
    pub fn should_block(cfg: &SuricataConfig, alert: &ThreatAlert) -> bool {
        if !matches!(cfg.block_mode, BlockMode::InlineBlock) {
            return false;
        }
        if !matches!(alert.severity, Severity::High | Severity::Critical) {
            return false;
        }

        for exempt in &cfg.block_exempt {
            if let Ok(net) = exempt.parse::<ipnet::IpNet>() {
                if let Ok(ip) = alert.src_ip.parse::<std::net::IpAddr>() {
                    if net.contains(&ip) {
                        return false;
                    }
                }
            } else if let Ok(addr) = exempt.parse::<std::net::IpAddr>() {
                if alert.src_ip == addr.to_string() {
                    return false;
                }
            }
        }

        true
    }

    pub async fn restore_state(&self) -> ThreatResult<usize> {
        let now = Utc::now().timestamp();
        let records = load_block_records(&self.state_path)?
            .into_iter()
            .filter(|record| record.expires_at > now)
            .collect::<Vec<_>>();

        if records.is_empty() {
            self.persist_records(&[]).await?;
            return Ok(0);
        }

        Self::ensure_threat_table().await?;
        Self::flush_chain().await?;

        let mut active = self.active.lock().await;
        active.clear();
        for record in &records {
            Self::insert_drop(&record.ip).await?;
            active.insert(record.ip.clone(), record.expires_at);
        }
        drop(active);

        self.persist_records(&records).await?;
        Ok(records.len())
    }

    pub async fn ensure_runtime_table(&self) -> ThreatResult<()> {
        let cfg = self.cfg.lock().await.clone();
        if matches!(cfg.block_mode, BlockMode::InlineBlock) {
            Self::ensure_threat_table().await?;
        }
        Ok(())
    }

    pub async fn maybe_block(&self, alert: &ThreatAlert) -> ThreatResult<bool> {
        let cfg = self.cfg.lock().await.clone();
        if !Self::should_block(&cfg, alert) {
            return Ok(false);
        }

        let mut active = self.active.lock().await;
        if active.contains_key(&alert.src_ip) {
            return Ok(false);
        }

        Self::ensure_threat_table().await?;
        Self::insert_drop(&alert.src_ip).await?;
        let expiry = Utc::now().timestamp() + cfg.block_ttl_secs as i64;
        active.insert(alert.src_ip.clone(), expiry);
        let records = map_to_records(&active);
        drop(active);

        self.persist_records(&records).await?;

        log_audit(
            &self.node_id,
            AuditCategory::Network,
            AuditSeverity::Warning,
            AuditAction::Blocked,
            &format!(
                "blocked {} (sig={} sev={} ttl={}s)",
                alert.src_ip,
                alert.signature_id,
                alert.severity.as_str(),
                cfg.block_ttl_secs
            ),
        );

        Ok(true)
    }

    pub async fn sweep_expired(&self) -> ThreatResult<usize> {
        let now = Utc::now().timestamp();
        let mut active = self.active.lock().await;
        let expired = active.values().filter(|expiry| **expiry <= now).count();
        if expired == 0 {
            return Ok(0);
        }

        active.retain(|_, expiry| *expiry > now);
        let records = map_to_records(&active);
        let ips = records
            .iter()
            .map(|record| record.ip.clone())
            .collect::<Vec<_>>();
        drop(active);

        Self::ensure_threat_table().await?;
        Self::flush_chain().await?;
        for ip in ips {
            Self::insert_drop(&ip).await?;
        }

        self.persist_records(&records).await?;
        log_audit(
            &self.node_id,
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!("expired {} threat block(s)", expired),
        );
        Ok(expired)
    }

    pub async fn unblock_ip(&self, ip: &str) -> ThreatResult<bool> {
        let mut active = self.active.lock().await;
        let existed = active.remove(ip).is_some();
        let records = map_to_records(&active);
        let ips = records
            .iter()
            .map(|record| record.ip.clone())
            .collect::<Vec<_>>();
        drop(active);

        Self::ensure_threat_table().await?;
        Self::flush_chain().await?;
        for current_ip in ips {
            Self::insert_drop(&current_ip).await?;
        }
        self.persist_records(&records).await?;

        if existed {
            log_audit(
                &self.node_id,
                AuditCategory::Network,
                AuditSeverity::Info,
                AuditAction::Updated,
                &format!("manually unblocked {}", ip),
            );
        }

        Ok(existed)
    }

    async fn persist_records(&self, records: &[BlockRecord]) -> ThreatResult<()> {
        if let Some(parent) = self.state_path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }

        let mut ordered = records.to_vec();
        ordered.sort_by(|lhs, rhs| lhs.ip.cmp(&rhs.ip));
        let tmp = self.state_path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(&ordered)?;
        tokio::fs::write(&tmp, json).await?;
        tokio::fs::rename(&tmp, &self.state_path).await?;
        Ok(())
    }

    async fn ensure_threat_table() -> ThreatResult<()> {
        run_nft_allow_exists(&["add", "table", "inet", "sgx_threat"]).await?;
        run_nft_allow_exists(&[
            "add",
            "chain",
            "inet",
            "sgx_threat",
            "input",
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "-10",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ])
        .await?;
        Ok(())
    }

    async fn insert_drop(ip: &str) -> ThreatResult<()> {
        let addr = ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| ThreatError::InvalidCidr(ip.into()))?;
        let family = if addr.is_ipv4() { "ip" } else { "ip6" };
        run_nft(&[
            "add",
            "rule",
            "inet",
            "sgx_threat",
            "input",
            family,
            "saddr",
            ip,
            "drop",
        ])
        .await
    }

    async fn flush_chain() -> ThreatResult<()> {
        let result = run_nft(&["flush", "chain", "inet", "sgx_threat", "input"]).await;
        match result {
            Ok(()) => Ok(()),
            Err(ThreatError::NftFailed(_, message))
                if message.contains("No such file") || message.contains("No chain") =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

pub fn load_block_records(path: &Path) -> ThreatResult<Vec<BlockRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let text = std::fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    Ok(serde_json::from_str(&text)?)
}

fn map_to_records(active: &HashMap<String, i64>) -> Vec<BlockRecord> {
    active
        .iter()
        .map(|(ip, expires_at)| BlockRecord {
            ip: ip.clone(),
            expires_at: *expires_at,
        })
        .collect()
}

async fn run_nft_allow_exists(args: &[&str]) -> ThreatResult<()> {
    match run_nft(args).await {
        Ok(()) => Ok(()),
        Err(ThreatError::NftFailed(_, message)) if message.contains("File exists") => Ok(()),
        Err(err) => Err(err),
    }
}

async fn run_nft(args: &[&str]) -> ThreatResult<()> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .await
        .map_err(map_spawn_error)?;

    if output.status.success() {
        return Ok(());
    }

    Err(ThreatError::NftFailed(
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

fn map_spawn_error(err: std::io::Error) -> ThreatError {
    if err.kind() == ErrorKind::NotFound {
        ThreatError::BinaryMissing
    } else {
        ThreatError::Io(err)
    }
}
