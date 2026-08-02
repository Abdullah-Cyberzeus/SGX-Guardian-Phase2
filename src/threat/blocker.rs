use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::nebula::overlay_registry::OverlayRegistry;
use crate::threat::{
    config::{BlockMode, SuricataConfig},
    error::{ThreatError, ThreatResult},
    threat_alert::{Severity, ThreatAlert},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::{Mutex as StdMutex, OnceLock};
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
        if !cfg.enabled {
            return false;
        }
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

        // Runtime guard: never block self, default gateway, or Circle peers.
        // This catches IPs that pass the config-level CIDR exempts but are still
        // system-critical (e.g. board IP changed, gateway changed since last deploy).
        if let Ok(ip) = alert.src_ip.parse::<IpAddr>() {
            if is_runtime_protected_host_ip(ip).await {
                tracing::warn!(
                    ip = %alert.src_ip,
                    sid = alert.signature_id,
                    "suppressed block: IP is self, gateway, or overlay-protected"
                );
                return Ok(false);
            }
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
        let parsed_ip = ip
            .parse::<IpAddr>()
            .map_err(|_| ThreatError::InvalidCidr(ip.to_string()))?;
        let ip_key = parsed_ip.to_string();

        let mut active = self.active.lock().await;
        let existed = active.remove(&ip_key).is_some();
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
                &format!("manually unblocked {}", ip_key),
            );
        }

        Ok(existed)
    }

    /// Manually block an IP address (Connected Devices enforcement).
    ///
    /// Unlike `maybe_block` (auto-block from threat alerts), this intentionally
    /// bypasses severity and `cfg.enabled` checks, but still preserves:
    ///   - runtime protected-host guard (self/gateway/overlay IPs only)
    ///   - TTL (`block_ttl_secs`)
    ///   - persistence to `blocked_ips.json`
    pub async fn block_ip_manual(&self, ip: &str) -> ThreatResult<bool> {
        let cfg = self.cfg.lock().await.clone();

        let parsed_ip = ip
            .parse::<IpAddr>()
            .map_err(|_| ThreatError::InvalidCidr(ip.to_string()))?;
        let ip_key = parsed_ip.to_string();

        if is_runtime_protected_host_ip(parsed_ip).await {
            return Err(ThreatError::ProtectedIp(ip_key));
        }

        let mut active = self.active.lock().await;
        if active.contains_key(&ip_key) {
            // Already blocked; treat as success.
            return Ok(false);
        }

        Self::ensure_threat_table().await?;
        Self::insert_drop(&ip_key).await?;

        let expiry = Utc::now().timestamp() + cfg.block_ttl_secs as i64;
        active.insert(ip_key.clone(), expiry);
        let records = map_to_records(&active);
        drop(active);

        self.persist_records(&records).await?;

        Ok(true)
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

/// Host IPs that must never be manually blocked: this device's interface
/// addresses, the active default gateway, and assigned Nebula overlay IPs.
/// Remote peer LAN IPs from node/lighthouse/relay config are not protected.
pub async fn is_runtime_protected_host_ip(target: IpAddr) -> bool {
    if target.is_loopback() || target.is_unspecified() {
        return true;
    }

    if overlay_protected_ips_from_registry(&overlay_registry_path()).contains(&target) {
        return true;
    }

    if local_interface_ips().await.contains(&target) {
        return true;
    }

    default_gateway_ips().await.contains(&target)
}

fn overlay_registry_path() -> PathBuf {
    let base = std::env::var("SGX_NEBULA_DIR")
        .or_else(|_| std::env::var("SGX_GUARDIAN_NEBULA_DIR"))
        .unwrap_or_else(|_| "/var/lib/sgx-guardian/nebula".to_string());
    PathBuf::from(base).join("overlay_registry.json")
}

fn overlay_protected_ips_from_registry(path: &Path) -> Vec<IpAddr> {
    let path_str = path.to_str().unwrap_or_default();
    OverlayRegistry::load(path_str)
        .map(|registry| {
            registry
                .allocations
                .values()
                .filter_map(|record| record.overlay_ip.parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default()
}

async fn local_interface_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(out) = Command::new("ip").args(["addr", "show"]).output().await {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().map(str::trim) {
            if line.starts_with("inet ") || line.starts_with("inet6 ") {
                if let Some(addr) = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|cidr| cidr.split('/').next())
                    .and_then(|addr| addr.parse::<IpAddr>().ok())
                {
                    ips.push(addr);
                }
            }
        }
    }
    ips
}

async fn default_gateway_ips() -> Vec<IpAddr> {
    let mut gateways = Vec::new();
    if let Ok(out) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .await
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(via_pos) = parts.iter().position(|&p| p == "via") {
                if let Some(gw_str) = parts.get(via_pos + 1) {
                    if let Ok(gw) = gw_str.parse::<IpAddr>() {
                        gateways.push(gw);
                    }
                }
            }
        }
    }
    gateways
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
    // Unit tests should not touch the host firewall. When enabled, record the
    // nft command and optionally simulate failures.
    if std::env::var_os("SGX_THREAT_MOCK_NFT").is_some() {
        record_mock_nft_call(args);
        maybe_fail_mock_nft_call(args)?;
        return Ok(());
    }

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

static MOCK_NFT_CALLS: OnceLock<StdMutex<Vec<Vec<String>>>> = OnceLock::new();
static MOCK_NFT_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);

fn mock_nft_calls() -> &'static StdMutex<Vec<Vec<String>>> {
    MOCK_NFT_CALLS.get_or_init(|| StdMutex::new(Vec::new()))
}

fn record_mock_nft_call(args: &[&str]) {
    let call: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    mock_nft_calls()
        .lock()
        .expect("mock_nft_calls lock")
        .push(call);
    let _ = MOCK_NFT_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn maybe_fail_mock_nft_call(args: &[&str]) -> ThreatResult<()> {
    if let Ok(substring) = std::env::var("SGX_THREAT_MOCK_NFT_FAIL_MATCH") {
        let joined = args.join(" ");
        if joined.contains(&substring) {
            return Err(ThreatError::NftFailed(
                -1,
                format!("mock nft failure for match={substring}"),
            ));
        }
    }

    if let Ok(at_call) = std::env::var("SGX_THREAT_MOCK_NFT_FAIL_AT_CALL") {
        let idx: usize = at_call.parse().unwrap_or(usize::MAX);
        let actual_idx = MOCK_NFT_CALL_COUNT.load(Ordering::SeqCst).saturating_sub(1);
        if idx != usize::MAX && actual_idx == idx {
            return Err(ThreatError::NftFailed(
                -1,
                format!("mock nft failure at call #{actual_idx}"),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn take_mock_nft_calls() -> Vec<Vec<String>> {
    let mut guard = mock_nft_calls().lock().expect("mock_nft_calls lock");
    std::mem::take(&mut *guard)
}

fn map_spawn_error(err: std::io::Error) -> ThreatError {
    if err.kind() == ErrorKind::NotFound {
        ThreatError::BinaryMissing
    } else {
        ThreatError::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::async_env_lock;
    use tempfile::tempdir;

    struct ScopedEnvStrVar {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl ScopedEnvStrVar {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for ScopedEnvStrVar {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[tokio::test]
    async fn block_ip_manual_persists_and_unblock_removes() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");

        let td = tempdir().expect("tempdir");
        let state_dir = td.path().to_path_buf();

        let cfg = SuricataConfig {
            enabled: false,
            block_mode: BlockMode::InlineBlock,
            block_ttl_secs: 60,
            block_exempt: Vec::new(),
            ..SuricataConfig::default()
        };

        let cfg_shared = Arc::new(tokio::sync::Mutex::new(cfg));
        let blocker = Blocker::new(cfg_shared, "nodeA".into(), state_dir.clone());
        blocker.restore_state().await.expect("restore_state");
        let _ = take_mock_nft_calls();

        let ip = "203.0.113.10";
        blocker.block_ip_manual(ip).await.expect("block_ip_manual");

        let records =
            load_block_records(&state_dir.join("blocked_ips.json")).expect("load records");
        assert!(records.iter().any(|r| r.ip == ip));
        let expires_at = records.iter().find(|r| r.ip == ip).unwrap().expires_at;
        assert!(
            expires_at > Utc::now().timestamp(),
            "expires_at should be in the future"
        );

        let calls = take_mock_nft_calls();
        let calls_joined = calls.concat().join(" ");
        assert!(calls_joined.contains("add rule"));
        assert!(calls_joined.contains("saddr"));
        assert!(calls_joined.contains(ip));

        blocker.unblock_ip(ip).await.expect("unblock_ip");
        let records = load_block_records(&state_dir.join("blocked_ips.json"))
            .expect("load records after unblock");
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn block_ip_manual_refuses_overlay_ip_from_registry() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");

        let td = tempdir().expect("tempdir");
        let nebula_dir = td.path().join("nebula");
        std::fs::create_dir_all(&nebula_dir).expect("nebula dir");
        let _nebula_env =
            ScopedEnvStrVar::set("SGX_NEBULA_DIR", nebula_dir.to_str().expect("nebula path"));

        let mut reg = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
        let overlay_cidr = reg.assign_ip("nodeB").expect("assign overlay");
        let overlay_ip = overlay_cidr.split('/').next().expect("overlay ip");
        reg.save(
            nebula_dir
                .join("overlay_registry.json")
                .to_str()
                .expect("registry path"),
        )
        .expect("save overlay registry");

        let state_dir = td.path().join("threat");
        let cfg = SuricataConfig {
            enabled: false,
            block_mode: BlockMode::InlineBlock,
            block_ttl_secs: 60,
            block_exempt: Vec::new(),
            ..SuricataConfig::default()
        };

        let cfg_shared = Arc::new(tokio::sync::Mutex::new(cfg));
        let blocker = Blocker::new(cfg_shared, "nodeA".into(), state_dir);
        blocker.restore_state().await.expect("restore_state");

        let err = blocker
            .block_ip_manual(overlay_ip)
            .await
            .expect_err("overlay IP should be protected");
        assert!(matches!(err, ThreatError::ProtectedIp(_)));
    }

    #[tokio::test]
    async fn block_ip_manual_does_not_persist_record_when_nft_fails() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");
        let _fail_match = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT_FAIL_MATCH", "203.0.113.12");

        let td = tempdir().expect("tempdir");
        let state_dir = td.path().to_path_buf();

        let cfg = SuricataConfig {
            enabled: false,
            block_mode: BlockMode::InlineBlock,
            block_ttl_secs: 60,
            block_exempt: Vec::new(),
            ..SuricataConfig::default()
        };

        let cfg_shared = Arc::new(tokio::sync::Mutex::new(cfg));
        let blocker = Blocker::new(cfg_shared, "nodeA".into(), state_dir.clone());
        blocker.restore_state().await.expect("restore_state");

        let err = blocker
            .block_ip_manual("203.0.113.12")
            .await
            .expect_err("expected nft mock failure");
        assert!(matches!(err, ThreatError::NftFailed(_, _)));

        let records =
            load_block_records(&state_dir.join("blocked_ips.json")).expect("load records");
        assert!(!records.iter().any(|r| r.ip == "203.0.113.12"));
    }
}
