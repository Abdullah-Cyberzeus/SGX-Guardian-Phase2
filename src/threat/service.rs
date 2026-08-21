use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::task1_ai;
use crate::threat::{
    ai_bridge,
    blocker::Blocker,
    config::SuricataConfig,
    eve_tailer::EveTailer,
    inventory::{AlertInventory, IngestOutcome},
    rule_manager::RuleManager,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};

pub struct ThreatService {
    pub node_id: String,
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub inventory: Arc<Mutex<AlertInventory>>,
}

impl ThreatService {
    pub fn start(self) {
        tokio::spawn(async move {
            let cfg = match SuricataConfig::load(&self.config_path) {
                Ok(cfg) if cfg.enabled => cfg,
                Ok(_) => {
                    stop_suricata_when_disabled().await;
                    tracing::info!("Guardian integration disabled in config");
                    return;
                }
                Err(err) => {
                    tracing::warn!("failed to load threat config: {}", err);
                    return;
                }
            };

            let _ = tokio::fs::create_dir_all(&self.state_dir).await;
            if let Some(log_dir) = Path::new(&cfg.eve_path).parent() {
                let _ = tokio::fs::create_dir_all(log_dir).await;
            }
            let advisory_config = crate::advisory::AdvisoryConfig::from_state_dirs(&self.state_dir);
            match crate::advisory::AdvisoryRules::seed_default_if_missing(
                &advisory_config.rules_path(),
            ) {
                Ok(true) => tracing::info!(
                    node_id = %self.node_id,
                    path = %advisory_config.rules_path().display(),
                    "seeded default advisory rules"
                ),
                Ok(false) => {}
                Err(err) => tracing::warn!(
                    node_id = %self.node_id,
                    %err,
                    "failed to seed default advisory rules"
                ),
            }
            if let Err(err) = seed_demo_eve_if_requested(&cfg.eve_path, &self.node_id).await {
                tracing::warn!(
                    node_id = %self.node_id,
                    %err,
                    "failed to seed demo EVE burst"
                );
            }
            let inv_path = self.state_dir.join("alerts.jsonl");
            if let Ok(existing) = AlertInventory::load_from_path(&inv_path) {
                *self.inventory.lock().await = existing;
            }

            log_audit(
                &self.node_id,
                AuditCategory::Network,
                AuditSeverity::Info,
                AuditAction::Started,
                &format!(
                    "threat service starting (block_mode={})",
                    cfg.block_mode.as_str()
                ),
            );

            let cfg_shared = Arc::new(Mutex::new(cfg.clone()));
            let blocker = Arc::new(Blocker::new(
                cfg_shared.clone(),
                self.node_id.clone(),
                self.state_dir.clone(),
            ));

            if let Err(err) = blocker.ensure_runtime_table().await {
                tracing::warn!("failed to initialize threat nft table: {}", err);
            }

            if let Err(err) = blocker.restore_state().await {
                tracing::warn!("failed to restore threat blocks: {}", err);
            }

            let mut ai_state = task1_ai::AlertScorerState::default();

            let (tx, mut rx) = mpsc::channel(1024);
            let tailer = EveTailer {
                path: PathBuf::from(&cfg.eve_path),
                offset_file: self.state_dir.join("last_offset.json"),
                out: tx,
            };
            tokio::spawn(async move {
                if let Err(err) = tailer.run().await {
                    tracing::error!("eve tailer crashed: {}", err);
                }
            });

            {
                let blocker = blocker.clone();
                tokio::spawn(async move {
                    let mut tick = interval(Duration::from_secs(60));
                    loop {
                        tick.tick().await;
                        let _ = blocker.sweep_expired().await;
                    }
                });
            }

            if cfg.rule_update_hours > 0 {
                let node_id = self.node_id.clone();
                let period = Duration::from_secs(cfg.rule_update_hours * 3600);
                tokio::spawn(async move {
                    let mut tick = interval(period);
                    tick.tick().await;
                    loop {
                        tick.tick().await;
                        if let Err(err) = RuleManager::update_rules(&node_id).await {
                            tracing::warn!("Guardian update failed: {}", err);
                        }
                    }
                });
            }

            let mut persist_tick = interval(Duration::from_secs(30));
            let mut config_refresh_tick = interval(Duration::from_secs(5));
            let mut dirty = false;

            loop {
                tokio::select! {
                    Some(mut alert) = rx.recv() => {
                        log_audit(
                            &self.node_id,
                            AuditCategory::Network,
                            AuditSeverity::Warning,
                            AuditAction::Detected,
                            &format!(
                                "detected sid={} sev={} src={} dst={} sig={}",
                                alert.signature_id,
                                alert.severity.as_str(),
                                alert.src_ip,
                                alert.dst_ip,
                                alert.signature
                            ),
                        );

                        match blocker.maybe_block(&alert).await {
                            Ok(blocked) => {
                                alert.blocked = blocked;
                            }
                            Err(err) => tracing::warn!("blocker error: {}", err),
                        }

                        let mut inventory = self.inventory.lock().await;
                        match inventory.ingest(alert.clone()) {
                            IngestOutcome::Inserted => {
                                dirty = true;
                                let anomaly = {
                                    let feature = task1_ai::feature_from_alert(&alert);
                                    match task1_ai::process_feature(&feature, &mut ai_state) {
                                        Some(score) => {
                                            if let Some(plan) = task1_ai::generate_plan(score.clone()) {
                                                tracing::info!(
                                                    node_id = %self.node_id,
                                                    target = %plan.target_ip,
                                                    score = score.score,
                                                    "task1 remediation plan generated"
                                                );
                                            }
                                            Some(task1_ai::anomaly_context_from_score(&score))
                                        }
                                        None => None,
                                    }
                                };
                                ai_bridge::forward_to_ai(&self.node_id, &alert);
                                crate::advisory::generate_for_alert(
                                    self.node_id.clone(),
                                    alert.clone(),
                                    self.state_dir.clone(),
                                    std::env::var("SGX_GUARDIAN_DISCOVERY_STATE_DIR")
                                        .map(PathBuf::from)
                                        .unwrap_or_else(|_| {
                                            self.state_dir
                                                .parent()
                                                .map(|parent| parent.join("discovery"))
                                                .unwrap_or_else(|| {
                                                    PathBuf::from(
                                                        "/var/lib/sgx-guardian/discovery",
                                                    )
                                                })
                                        }),
                                    anomaly,
                                );
                                crate::notify::publish_alert(&self.node_id, &alert);
                                crate::rules::publish(crate::rules::RuleEvent::from_threat_alert(
                                    &self.node_id,
                                    &alert,
                                ));
                            }
                            IngestOutcome::Updated => {
                                dirty = true;
                            }
                            IngestOutcome::Duplicate => {}
                        }
                    }
                    _ = config_refresh_tick.tick() => {
                        if let Err(err) = refresh_runtime_config(
                            &self.config_path,
                            &cfg_shared,
                            &blocker,
                            &self.node_id,
                        ).await {
                            tracing::warn!("threat config refresh failed: {}", err);
                        }
                    }
                    _ = persist_tick.tick() => {
                        if dirty {
                            let inventory = self.inventory.lock().await;
                            if let Err(err) = inventory.save_atomic(&inv_path) {
                                tracing::warn!("inventory persist failed: {}", err);
                            } else {
                                dirty = false;
                            }
                        }
                    }
                }
            }
        });
    }
}

async fn stop_suricata_when_disabled() {
    let active = tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "suricata"])
        .status()
        .await;

    if matches!(active, Ok(status) if status.success()) {
        tracing::warn!(
            "Guardian service is running while Guardian threat config is disabled; stopping capture."
        );
        if let Err(error) = tokio::process::Command::new("systemctl")
            .args(["stop", "suricata"])
            .status()
            .await
        {
            tracing::warn!("Failed to stop disabled Guardian service: {}", error);
        }
    }
}

async fn refresh_runtime_config(
    config_path: &Path,
    cfg_shared: &Arc<Mutex<SuricataConfig>>,
    blocker: &Arc<Blocker>,
    node_id: &str,
) -> crate::threat::ThreatResult<()> {
    let next = SuricataConfig::load(config_path)?;
    let mut guard = cfg_shared.lock().await;
    if *guard == next {
        return Ok(());
    }

    let previous_mode = guard.block_mode;
    let next_mode = next.block_mode;
    let next_enabled = next.enabled;
    *guard = next;
    drop(guard);

    if next_enabled {
        blocker.ensure_runtime_table().await?;
    }

    log_audit(
        node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!(
            "threat config reloaded (block_mode={} -> {})",
            previous_mode.as_str(),
            next_mode.as_str()
        ),
    );

    Ok(())
}

fn demo_eve_seed_enabled() -> bool {
    std::env::var("SGX_SEED_DEMO_EVE")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn demo_eve_seed_lines(timestamp: &str) -> Vec<String> {
    let src_ip = "203.0.113.77";
    let src_port = 4444;
    let dst_port = 443;
    let protocol = "TCP";
    let signature_id = 9_100_001;
    let signature = "SGX AI anomaly burst";
    let destinations = [
        "192.168.100.10",
        "192.168.100.11",
        "192.168.100.12",
        "192.168.100.13",
        "192.168.100.14",
    ];

    destinations
        .iter()
        .map(|dst_ip| {
            serde_json::json!({
                "timestamp": timestamp,
                "event_type": "alert",
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "proto": protocol,
                "alert": {
                    "severity": 1,
                    "signature": signature,
                    "category": "Anomaly",
                    "signature_id": signature_id,
                    "rev": 1,
                    "gid": 1,
                },
            })
            .to_string()
        })
        .collect()
}

async fn seed_demo_eve_if_requested(
    eve_path: &str,
    node_id: &str,
) -> crate::threat::ThreatResult<()> {
    if !demo_eve_seed_enabled() {
        return Ok(());
    }

    match tokio::fs::metadata(eve_path).await {
        Ok(meta) if meta.len() > 0 => return Ok(()),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    if let Some(parent) = Path::new(eve_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let lines = demo_eve_seed_lines(&timestamp);
    let mut file = tokio::fs::File::create(eve_path).await?;
    for line in lines {
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
    }
    file.flush().await?;

    tracing::info!(
        node_id = %node_id,
        path = %eve_path,
        "seeded demo EVE burst for Task 1 AI"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task1_ai;
    use crate::threat::eve_parser;
    use std::collections::HashSet;

    #[test]
    fn demo_seed_burst_triggers_task1_anomaly_and_unique_alert_ids() {
        let lines = demo_eve_seed_lines("2026-08-20T00:00:00.000000+00:00");
        assert_eq!(lines.len(), 5);

        let mut seen_ids = HashSet::new();
        let mut scorer = task1_ai::AlertScorerState::default();
        let mut anomaly = None;

        for (idx, line) in lines.iter().enumerate() {
            let alert = eve_parser::parse_line(line, (idx + 1) as u64)
                .expect("seed line should parse")
                .expect("seed line should be an alert");
            assert_eq!(alert.src_ip, "203.0.113.77");
            assert_eq!(alert.signature_id, 9_100_001);
            assert_eq!(alert.signature, "SGX AI anomaly burst");
            assert!(seen_ids.insert(alert.alert_id.clone()));

            let feature = task1_ai::feature_from_alert(&alert);
            anomaly = task1_ai::process_feature(&feature, &mut scorer);
        }

        assert!(anomaly.is_some(), "burst should cross the Task 1 threshold");
    }
}
