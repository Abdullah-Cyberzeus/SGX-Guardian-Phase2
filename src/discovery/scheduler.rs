use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::discovery::{
    config::{NmapConfig, ScheduledScanKind},
    error::DiscoveryResult,
    inventory::Inventory,
    nmap_parser,
    nmap_runner::NmapRunner,
    vuln_trigger,
    whitelist::Whitelist,
    ScanIntensity,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration, Instant};

#[derive(Clone)]
pub struct DiscoveryScheduler {
    pub node_id: String,
    pub config_path: PathBuf,
    pub whitelist_path: PathBuf,
    pub inventory_path: PathBuf,
    pub state: Arc<Mutex<Inventory>>,
}

impl DiscoveryScheduler {
    /// Spawns background loops. Returns immediately.
    pub fn start(self) {
        seed_if_missing(&self.config_path, DEFAULT_NMAP_YAML);
        seed_if_missing(&self.whitelist_path, DEFAULT_WHITELIST_YAML);

        if let Ok(inv) = Inventory::load(&self.inventory_path) {
            if let Ok(mut guard) = self.state.try_lock() {
                *guard = inv;
            }
        }

        for kind in [ScheduledScanKind::Hourly, ScheduledScanKind::Daily] {
            let scheduler = self.clone();
            tokio::spawn(async move {
                scheduler.run_schedule_loop(kind).await;
            });
        }
    }

    async fn run_schedule_loop(&self, kind: ScheduledScanKind) {
        let period = schedule_period(kind);
        let mut poll = interval(Duration::from_secs(60));
        let mut next_run = Instant::now() + period;
        poll.tick().await;

        loop {
            poll.tick().await;

            let cfg = match NmapConfig::load(&self.config_path) {
                Ok(cfg) => cfg,
                Err(err) => {
                    tracing::warn!("discovery config load failed: {}", err);
                    next_run = Instant::now() + period;
                    continue;
                }
            };

            let Some(intensity) = cfg.scheduled_intensity(kind) else {
                next_run = Instant::now() + period;
                continue;
            };

            if !cfg.enabled {
                next_run = Instant::now() + period;
                continue;
            }

            if Instant::now() < next_run {
                continue;
            }

            next_run = Instant::now() + period;

            if let Err(err) = self.run_one(&cfg, kind, intensity).await {
                log_audit(
                    &self.node_id,
                    AuditCategory::Discovery,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("{} nmap scan failed: {}", schedule_name(kind), err),
                );
            }
        }
    }

    async fn run_one(
        &self,
        cfg: &NmapConfig,
        kind: ScheduledScanKind,
        intensity: ScanIntensity,
    ) -> DiscoveryResult<()> {
        let target = cfg.resolved_target_cidr();

        log_audit(
            &self.node_id,
            AuditCategory::Discovery,
            AuditSeverity::Info,
            AuditAction::Started,
            &format!(
                "{} nmap scan {} intensity={:?}",
                schedule_name(kind),
                target,
                intensity
            ),
        );

        let xml = NmapRunner::run_with_intensity(cfg, &target, intensity).await?;

        // Persist raw XML for forensic re-parsing (rotated last 10).
        if let Some(state_dir) = self.inventory_path.parent() {
            if let Err(err) = crate::discovery::raw_store::RawXmlStore::persist(state_dir, &xml) {
                tracing::warn!("raw_store persist failed: {}", err);
            }
        }

        let wl = Whitelist::load(&self.whitelist_path).unwrap_or_default();
        let devices = nmap_parser::parse(&xml)?;
        let semantics = cfg.scan_semantics_for_intensity(&target, intensity);

        let intensity_label = match intensity {
            ScanIntensity::Stealth => "stealth",
            ScanIntensity::Standard => "standard",
            ScanIntensity::Aggressive => "aggressive",
        };
        let mut inv = self.state.lock().await;
        let delta = inv.merge(devices, semantics);
        for id in delta.updated.iter().chain(delta.newly_seen.iter()) {
            if let Some(device) = inv.by_id.get_mut(id) {
                device.last_scan_intensity = Some(intensity_label.to_string());
                wl.classify(device);
            }
        }
        inv.save_atomic(&self.inventory_path)?;

        if !delta.newly_seen.is_empty() {
            vuln_trigger::queue_for_ai_review(&self.node_id, &delta.newly_seen);
            log_audit(
                &self.node_id,
                AuditCategory::Discovery,
                AuditSeverity::Warning,
                AuditAction::Detected,
                &format!(
                    "{} scan discovered {} new device(s) on subnet",
                    schedule_name(kind),
                    delta.newly_seen.len()
                ),
            );
        }
        Ok(())
    }

    /// Test hook for timeout-bounded integration checks in `tests/`.
    #[doc(hidden)]
    pub async fn run_one_for_test(
        &self,
        cfg: &NmapConfig,
        kind: ScheduledScanKind,
        intensity: ScanIntensity,
    ) -> DiscoveryResult<()> {
        self.run_one(cfg, kind, intensity).await
    }
}

fn schedule_period(kind: ScheduledScanKind) -> Duration {
    match kind {
        ScheduledScanKind::Hourly => Duration::from_secs(3600),
        ScheduledScanKind::Daily => Duration::from_secs(86_400),
    }
}

fn schedule_name(kind: ScheduledScanKind) -> &'static str {
    match kind {
        ScheduledScanKind::Hourly => "hourly",
        ScheduledScanKind::Daily => "daily",
    }
}

const DEFAULT_NMAP_YAML: &str = r#"# /etc/sgx-guardian/discovery/nmap.yaml
# Scheduled NMAP discovery - off by default. Admin opts in.
enabled: false
target_cidr: null         # auto-detect active LAN CIDR at runtime if null
timeout_secs: 600
exclude: []
schedules:
  hourly:
    intensity: standard   # stealth | standard | aggressive
  daily:
    intensity: aggressive # stealth | standard | aggressive
"#;

const DEFAULT_WHITELIST_YAML: &str = r#"# /etc/sgx-guardian/discovery/whitelist.yaml
# Sprint 6 NMAP whitelist. Empty by default - admin populates after first scan.
version: "1.0"
devices: []
# Example with strict IP binding (recommended on multi-subnet networks):
#  - mac: "AA:BB:CC:11:22:33"
#    label: "Office printer"
#    expected_os: "Linux"
#    expected_ports: [9100]
#    expected_ips: ["10.0.0.50/32"]
"#;

fn seed_if_missing(path: &std::path::Path, contents: &str) {
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp = path.with_extension("yaml.tmp");
    if std::fs::write(&tmp, contents).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}
