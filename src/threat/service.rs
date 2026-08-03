use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::{
    advisory::{format_advisory, AdvisoryStore},
    ai_bridge,
    alert_scorer::{process_feature, AlertScorerState},
    blocker::Blocker,
    config::SuricataConfig,
    eve_tailer::EveTailer,
    inventory::{AlertInventory, IngestOutcome},
    remediation::generate_plan,
    rule_manager::RuleManager,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};

pub struct ThreatService {
    pub node_id: String,
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub inventory: Arc<Mutex<AlertInventory>>,
    pub advisory_store: Arc<Mutex<AdvisoryStore>>,
}

impl ThreatService {
    pub fn new(
        node_id: String,
        config_path: PathBuf,
        state_dir: PathBuf,
        inventory: Arc<Mutex<AlertInventory>>,
        advisory_store: Arc<Mutex<AdvisoryStore>>,
    ) -> Self {
        Self {
            node_id,
            config_path,
            state_dir,
            inventory,
            advisory_store,
        }
    }
    pub fn start(self) {
        tokio::spawn(async move {
            let cfg = match SuricataConfig::load(&self.config_path) {
                Ok(cfg) if cfg.enabled => cfg,
                Ok(_) => {
                    stop_suricata_when_disabled().await;
                    tracing::info!("Suricata integration disabled in config");
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

            // Subscribe to AI feature tap BEFORE spawning tailer to ensure no alerts are dropped at startup
            let mut ai_rx = ai_bridge::subscribe();

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

            // Spawn AI Anomaly Scoring & Remediation Advisory Task
            {
                let node_id_ai = self.node_id.clone();
                let advisory_store_ai = self.advisory_store.clone();

                tokio::spawn(async move {
                    let mut scorer_state = AlertScorerState::default();

                    while let Ok(feature) = ai_rx.recv().await {
                        if let Some(score) = process_feature(&feature, &mut scorer_state) {
                            if let Some(plan) = generate_plan(score) {
                                let advisory = format_advisory(plan.clone());

                                // System is advisory-only: no actions are executed automatically.
                                // All recommendations in requires_approval await admin approval
                                // via the REST API (POST /advisories/{id}/approve) or CLI.

                                let audit_sev = if advisory.severity_label == "critical" {
                                    AuditSeverity::Critical
                                } else {
                                    AuditSeverity::Warning
                                };

                                log_audit(
                                    &node_id_ai,
                                    AuditCategory::Network,
                                    audit_sev,
                                    AuditAction::Created,
                                    &format!(
                                        "security advisory {} generated: {} - {}",
                                        advisory.advisory_id,
                                        advisory.title,
                                        advisory.plan.justification
                                    ),
                                );

                                advisory_store_ai.lock().await.upsert_or_push(advisory);
                            }
                        }
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
                            tracing::warn!("suricata-update failed: {}", err);
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
                                crate::notify::publish_alert(&self.node_id, &alert);
                            }
                            IngestOutcome::Updated => {
                                dirty = true;
                            }
                            IngestOutcome::Duplicate => {}
                        }
                        ai_bridge::forward_to_ai(&self.node_id, &alert);
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
            "Suricata service is running while Guardian threat config is disabled; stopping capture."
        );
        if let Err(error) = tokio::process::Command::new("systemctl")
            .args(["stop", "suricata"])
            .status()
            .await
        {
            tracing::warn!("Failed to stop disabled Suricata service: {}", error);
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
