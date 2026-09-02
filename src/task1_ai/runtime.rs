use crate::advisory::AnomalyScoringRuntime;
use crate::metrics::Metrics;
use crate::task1_ai::baseline::{baseline_config_path, Task1RuntimeTracker};
use crate::task1_ai::telemetry::SgxTelemetrySource;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sgx_anomaly_engine::alert::{AlertSink, AlertTier, AnomalyAlert, Severity as MlSeverity};
use sgx_anomaly_engine::engine::AnomalyEngine;
use sgx_anomaly_engine::roles::NodeRole;
use sgx_anomaly_engine::rules::{ActionDefinition, PatternRule, RuleFile};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

const FULL_ML_ALERTS_FILE: &str = "task1_full_ml_alerts.jsonl";
const MODELS_DIR: &str = "task1_models";

const GLOBAL_MODEL_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/data/global_forest.json");
const NODE_A_MODEL_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/data/nodeA_forest.json");
const NODE_B_MODEL_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/data/nodeB_forest.json");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task1AdvisoryConfidence {
    pub value: f64,
    pub basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task1FullMlAlertRecord {
    pub ts: u64,
    pub node: String,
    pub role: NodeRole,
    pub score: f64,
    pub model_confidence: f64,
    pub advisory_confidence: Task1AdvisoryConfidence,
    pub severity: MlSeverity,
    pub topk: Vec<String>,
    pub reason: String,
    pub recommendation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionDefinition>,
    pub tier: AlertTier,
    pub runtime: AnomalyScoringRuntime,
}

pub fn spawn_full_ml_runtime(
    node_id: String,
    metrics: Arc<Mutex<Metrics>>,
    state_dir: PathBuf,
) -> Result<()> {
    std::fs::create_dir_all(&state_dir)?;
    let config_path = install_runtime_assets(&state_dir)?;

    let tracker = Task1RuntimeTracker::for_state_dir(&node_id, &state_dir);
    tracker
        .persist_full_ml_runtime()?
        .ok_or_else(|| anyhow!("full ML runtime could not be initialized for '{}'", node_id))?;

    let sink = Arc::new(SgxTask1AlertSink::new(&node_id, state_dir.clone()));
    let source = Box::new(SgxTelemetrySource::new(metrics));
    let config_str = config_path
        .to_str()
        .ok_or_else(|| anyhow!("baseline config path is not valid UTF-8"))?;
    let mut engine = AnomalyEngine::new(node_id.clone(), source, sink)
        .try_with_baseline_lifecycle(config_str)?;

    tokio::spawn(async move {
        engine.run().await;
    });

    tokio::spawn(async move {
        sync_runtime_status(node_id, state_dir).await;
    });

    Ok(())
}

pub fn load_recent_full_ml_alerts(
    state_dir: impl AsRef<Path>,
    limit: usize,
) -> Result<Vec<Task1FullMlAlertRecord>> {
    let path = full_ml_alerts_path(state_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let text = std::fs::read_to_string(path)?;
    let mut alerts = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Task1FullMlAlertRecord>(line).ok())
        .collect::<Vec<_>>();
    if alerts.len() > limit {
        alerts.drain(0..alerts.len() - limit);
    }
    Ok(alerts)
}

pub fn full_ml_alerts_path(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(FULL_ML_ALERTS_FILE)
}

async fn sync_runtime_status(node_id: String, state_dir: PathBuf) {
    let mut tracker = Task1RuntimeTracker::for_state_dir(&node_id, &state_dir);
    if let Err(error) = tracker.persist_full_ml_runtime() {
        tracing::warn!(
            node_id = %node_id,
            %error,
            "failed to persist initial Task 1 full ML runtime status"
        );
    }

    let mut tick = interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        match tracker.maybe_reload() {
            Ok(Some(_)) | Ok(None) => {
                if let Err(error) = tracker.persist_full_ml_runtime() {
                    tracing::warn!(
                        node_id = %node_id,
                        %error,
                        "failed to refresh Task 1 full ML runtime status"
                    );
                }
            }
            Err(error) => tracing::warn!(
                node_id = %node_id,
                %error,
                "failed to refresh Task 1 baseline lifecycle state for runtime metadata"
            ),
        }
    }
}

fn install_runtime_assets(state_dir: impl AsRef<Path>) -> Result<PathBuf> {
    let state_dir = state_dir.as_ref();
    let models_dir = state_dir.join(MODELS_DIR);
    std::fs::create_dir_all(&models_dir)?;

    let global_path = models_dir.join("global_forest.json");
    let node_a_path = models_dir.join("nodeA.json");
    let node_b_path = models_dir.join("nodeB.json");

    write_if_missing(&global_path, GLOBAL_MODEL_JSON)?;
    write_if_missing(&node_a_path, NODE_A_MODEL_JSON)?;
    write_if_missing(&node_b_path, NODE_B_MODEL_JSON)?;

    let config_path = baseline_config_path(state_dir);
    let config_json = serde_json::json!({
        "global_model": global_path.display().to_string(),
        "per_node_model_template": models_dir.join("{node}.json").display().to_string(),
        "reload_check_seconds": 5,
        "min_normal_days": 7,
        "refresh_days": 30,
        "evidence_dir": state_dir.join("task1_baseline_evidence").display().to_string(),
    });
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config_json)?)?;
    Ok(config_path)
}

fn write_if_missing(path: &Path, content: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    Ok(())
}

fn advisory_confidence_for(topk: &[String], rules: &RuleFile) -> Task1AdvisoryConfidence {
    let best = rules
        .rules
        .iter()
        .map(|rule| {
            let overlap = overlap_count(rule, topk);
            (rule, overlap)
        })
        .filter(|(rule, overlap)| *overlap >= rule.min_overlap)
        .max_by_key(|(_, overlap)| *overlap);

    match best {
        Some((rule, overlap)) => Task1AdvisoryConfidence {
            value: overlap as f64 / rule.signature.len() as f64,
            basis: format!(
                "configured rule '{}' matched {overlap}/{} evidence features",
                rule.name,
                rule.signature.len()
            ),
        },
        None => Task1AdvisoryConfidence {
            value: 0.0,
            basis: "fallback advisory has no configured rule-evidence match".to_string(),
        },
    }
}

fn overlap_count(rule: &PatternRule, topk: &[String]) -> usize {
    rule.signature
        .iter()
        .filter(|feature| topk.iter().any(|top| top == *feature))
        .count()
}

struct SgxTask1AlertSink {
    node_id: String,
    state_dir: PathBuf,
    rules: RuleFile,
    write_lock: StdMutex<()>,
}

impl SgxTask1AlertSink {
    fn new(node_id: &str, state_dir: PathBuf) -> Self {
        Self {
            node_id: node_id.to_string(),
            state_dir,
            rules: RuleFile::builtin_default(),
            write_lock: StdMutex::new(()),
        }
    }

    fn append_record(&self, record: &Task1FullMlAlertRecord) -> Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow!("Task 1 full ML alert sink lock poisoned"))?;
        let path = full_ml_alerts_path(&self.state_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }
}

impl AlertSink for SgxTask1AlertSink {
    fn emit(&self, alert: AnomalyAlert) {
        let advisory_confidence = advisory_confidence_for(&alert.topk, &self.rules);
        let runtime = Task1RuntimeTracker::for_state_dir(&self.node_id, &self.state_dir)
            .build_full_ml_runtime()
            .unwrap_or_else(|| {
                Task1RuntimeTracker::for_state_dir(&self.node_id, &self.state_dir).current_runtime()
            });
        let record = Task1FullMlAlertRecord {
            ts: alert.ts,
            node: alert.node,
            role: alert.role,
            score: alert.score,
            model_confidence: alert.confidence,
            advisory_confidence,
            severity: alert.severity,
            topk: alert.topk,
            reason: alert.reason,
            recommendation: alert.recommendation,
            action: alert.action,
            tier: alert.tier,
            runtime,
        };

        if let Err(error) = self.append_record(&record) {
            tracing::warn!(
                node_id = %self.node_id,
                %error,
                "failed to persist Task 1 full ML alert"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::{AnomalyBaselineSelectionMode, AnomalyScoringRuntimeModelKind};
    use sgx_anomaly_engine::rules::ActionDefinition;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sgx-task1-runtime-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn runtime_assets_seed_expected_models_and_config() {
        let dir = unique_temp_dir("assets");
        let config_path = install_runtime_assets(&dir).expect("install assets");
        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(config_path).expect("read config"))
                .expect("parse config");

        assert!(dir.join(MODELS_DIR).join("global_forest.json").exists());
        assert!(dir.join(MODELS_DIR).join("nodeA.json").exists());
        assert!(dir.join(MODELS_DIR).join("nodeB.json").exists());
        assert_eq!(config["reload_check_seconds"], 5);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sink_persists_model_and_advisory_confidence_separately() {
        let dir = unique_temp_dir("sink");
        install_runtime_assets(&dir).expect("install assets");
        let tracker = Task1RuntimeTracker::for_state_dir("nodeA", &dir);
        tracker.persist_full_ml_runtime().expect("persist runtime");

        let sink = SgxTask1AlertSink::new("nodeA", dir.clone());
        sink.emit(AnomalyAlert {
            ts: 42,
            node: "nodeA".into(),
            role: NodeRole::Member,
            score: 0.93,
            confidence: 0.81,
            severity: MlSeverity::High,
            topk: vec!["conn_rate".into(), "net_rx_pkts_rate".into()],
            reason: "reason".into(),
            recommendation: "recommendation".into(),
            action: Some(ActionDefinition {
                kind: "inspect_overlay_peers".into(),
                params: serde_json::json!({}),
            }),
            tier: AlertTier::Tier2,
        });

        let records = load_recent_full_ml_alerts(&dir, 10).expect("read alerts");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.model_confidence, 0.81);
        assert_eq!(record.advisory_confidence.value, 2.0 / 3.0);
        assert_eq!(
            record.runtime.model_kind,
            AnomalyScoringRuntimeModelKind::IsolationForest
        );
        assert_eq!(
            record
                .runtime
                .baseline
                .as_ref()
                .map(|baseline| baseline.selection_mode),
            Some(AnomalyBaselineSelectionMode::PerNode)
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
