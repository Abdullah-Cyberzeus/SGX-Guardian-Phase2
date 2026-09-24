use super::config::{ensure_runtime_dirs, Task4ThreatPredictionRuntimeConfig};
use crate::threat::ai_bridge::AlertFeature;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sgx_anomaly_engine::policy::{PolicyAction, PolicyTemplates};
use sgx_anomaly_engine::roles::RoleRegistry;
use sgx_anomaly_engine::threat_prediction::{
    assess_confidence, match_precursor_sequence, predict_peer_cascade,
    read_task3_degradation_events_at, recommend_predictive_hardening, BruteForcePredictor,
    ConfidenceContext, DdosPredictor, EventSeverity, EvidenceSource, ExploitationPredictor,
    ForecastSeverity, ForecastStatus, HardeningRecommendationConfig, PeerRelationship,
    PrecursorSequenceDefinition, PrecursorSequenceMatch, ProtocolAbusePredictor,
    ReconEscalationPredictor, SecurityEvent, SecurityEventType, Task3ContextConfig,
    TemporalFeatureConfig, TemporalFeatureEngine, TemporalFeatures, ThreatForecast,
    ThreatPredictor, ThreatPredictorInput, SECURITY_EVENT_SCHEMA_VERSION,
};
use sgx_anomaly_engine::virtual_shift::{
    AiRemediationAction, AiRemediationPlan, ReviewQueue, VS10_VS11_REVIEWS,
};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::time::{interval, sleep, MissedTickBehavior};

const STATUS_SCHEMA: &str = "task4-threat-prediction-runtime-status-v1";
const SOURCE_HEALTH_SCHEMA: &str = "task4-source-health-v1";
const D12_RUNTIME_EVALUATION_SCHEMA: &str = "task4-d12-runtime-evaluation-v1";
const POLICY_ACTION_TEMPLATES_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/policy_action_templates.json");
const NODE_ROLES_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/node_roles.json");

#[derive(Debug, Clone)]
pub struct Task4RuntimeHandle {
    state: Arc<RwLock<Task4RuntimeState>>,
    tx: mpsc::Sender<SecurityEvent>,
    scheduler_wake: watch::Sender<u64>,
}

impl Task4RuntimeHandle {
    pub async fn status(&self) -> Task4RuntimeStatus {
        self.state.read().await.status.clone()
    }

    pub async fn source_health(&self) -> BTreeMap<String, Task4SourceHealth> {
        self.state.read().await.source_health.clone()
    }

    pub fn try_publish(&self, event: SecurityEvent) -> Result<()> {
        self.tx
            .try_send(event)
            .map_err(|error| anyhow!("Task4 ingestion queue unavailable: {error}"))
    }

    pub async fn prediction_config(
        &self,
    ) -> sgx_anomaly_engine::threat_prediction::ThreatPredictionConfig {
        self.state.read().await.config.prediction.clone()
    }

    pub async fn set_enabled(&self, enabled: bool) -> Result<Task4RuntimeStatus> {
        let mut guard = self.state.write().await;

        let mut candidate = guard.config.prediction.clone();
        candidate.enabled = enabled;
        candidate.validate()?;

        persist_prediction_config_atomic(&guard.config.config_path, &candidate)?;

        guard.config.prediction = candidate;
        guard.config.config_error = None;
        guard.status.enabled = enabled;
        guard.status.degraded = false;
        guard.status.last_error = None;

        persist_status_and_health(&guard)?;
        let status = guard.status.clone();

        drop(guard);
        wake_scheduler(&self.scheduler_wake);

        Ok(status)
    }

    pub async fn update_prediction_config(
        &self,
        candidate: sgx_anomaly_engine::threat_prediction::ThreatPredictionConfig,
    ) -> Result<Task4RuntimeStatus> {
        candidate.validate()?;

        let mut guard = self.state.write().await;

        persist_prediction_config_atomic(&guard.config.config_path, &candidate)?;

        guard.config.prediction = candidate;
        guard.config.config_error = None;
        guard.status.enabled = guard.config.prediction.enabled;
        guard.status.degraded = false;
        guard.status.last_error = None;

        persist_status_and_health(&guard)?;
        let status = guard.status.clone();

        drop(guard);
        wake_scheduler(&self.scheduler_wake);

        Ok(status)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task4RuntimeStatus {
    pub schema_version: String,
    pub enabled: bool,
    pub degraded: bool,
    pub node_id: String,
    pub started_at_ms: u64,
    pub last_cycle_at_ms: Option<u64>,
    pub last_successful_cycle_at_ms: Option<u64>,
    pub last_error: Option<String>,
    pub events_ingested: u64,
    pub events_dropped: u64,
    pub active_forecast_count: usize,
    pub latest_forecast_probability: Option<f64>,
    pub latest_forecast_confidence: Option<f64>,
    pub task2_handoffs_created: u64,
    pub task2_handoffs_pending: u64,
    pub config_path: String,
    pub state_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task4SourceHealth {
    pub schema_version: String,
    pub source: String,
    pub enabled: bool,
    pub last_success_at_ms: Option<u64>,
    pub last_error: Option<String>,
    pub events_ingested: u64,
    pub events_dropped: u64,
    pub validation_failures: u64,
    pub lagged_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task4D12RuntimeEvaluation {
    pub schema_version: String,
    pub evaluation_id: String,
    pub node_id: String,
    pub evaluated_at_ms: u64,
    pub accepted_event_count: usize,
    pub bounded_event_capacity: usize,
    pub temporal_window_count: usize,
    pub forecast_count: usize,
    pub active_forecast_ids: Vec<String>,
    pub latest_forecast_probability: Option<f64>,
    pub latest_forecast_confidence: Option<f64>,
    pub task1_event_ids: Vec<String>,
    pub task3_event_ids: Vec<String>,
    pub task3_decision_ids: Vec<String>,
    pub source_event_counts: BTreeMap<String, usize>,
    pub sequence_id: String,
    pub sequence_matched_event_ids: Vec<String>,
    pub sequence_matched_steps: usize,
    pub sequence_total_steps: usize,
    pub sequence_fresh: bool,
    pub inference_latency_micros: u128,
    pub reused_existing_cycle_outputs: bool,
}

#[derive(Debug)]
struct Task4RuntimeState {
    config: Task4ThreatPredictionRuntimeConfig,
    events: VecDeque<SecurityEvent>,
    dedup: BTreeSet<String>,
    current_forecasts: Vec<ThreatForecast>,
    source_health: BTreeMap<String, Task4SourceHealth>,
    status: Task4RuntimeStatus,
    handoff_ids: BTreeSet<String>,
}

/// D7 process-local ingress used by the already-authenticated Guardian
/// gossip receiver to submit peer Task1 evidence into the canonical Task4
/// collector. ingest_event() remains the final dedup/persistence authority.
static TASK4_PEER_EVENT_INGRESS: std::sync::OnceLock<tokio::sync::mpsc::Sender<SecurityEvent>> =
    std::sync::OnceLock::new();

pub fn publish_peer_task1_event(event: SecurityEvent) -> Result<()> {
    event.validate_at(now_ms().saturating_add(30_000))?;

    if event.source != EvidenceSource::Task1Anomaly {
        return Err(anyhow!(
            "D7 peer ingress accepts only Task1Anomaly evidence"
        ));
    }

    let tx = TASK4_PEER_EVENT_INGRESS
        .get()
        .ok_or_else(|| anyhow!("Task4 peer-event ingress is not initialized"))?;

    tx.try_send(event)
        .map_err(|error| anyhow!("Task4 peer-event ingress unavailable: {error}"))
}

pub fn spawn_production_runtime(
    config: Task4ThreatPredictionRuntimeConfig,
) -> Result<Task4RuntimeHandle> {
    ensure_runtime_dirs(&config)?;
    let (tx, rx) = mpsc::channel(config.queue_capacity.max(1));
    let started_at_ms = now_ms();
    let status = Task4RuntimeStatus {
        schema_version: STATUS_SCHEMA.into(),
        enabled: config.prediction.enabled && config.config_error.is_none(),
        degraded: config.config_error.is_some(),
        node_id: config.node_id.clone(),
        started_at_ms,
        last_cycle_at_ms: None,
        last_successful_cycle_at_ms: None,
        last_error: config.config_error.clone(),
        events_ingested: 0,
        events_dropped: 0,
        active_forecast_count: 0,
        latest_forecast_probability: None,
        latest_forecast_confidence: None,
        task2_handoffs_created: 0,
        task2_handoffs_pending: 0,
        config_path: config.config_path.display().to_string(),
        state_dir: config.state_dir.display().to_string(),
    };
    let mut state = Task4RuntimeState {
        config,
        events: VecDeque::new(),
        dedup: BTreeSet::new(),
        current_forecasts: Vec::new(),
        source_health: BTreeMap::new(),
        status,
        handoff_ids: BTreeSet::new(),
    };
    restore_events(&mut state)?;
    let state = Arc::new(RwLock::new(state));
    let (scheduler_wake, scheduler_wake_rx) = watch::channel(0_u64);
    let handle = Task4RuntimeHandle {
        state: state.clone(),
        tx: tx.clone(),
        scheduler_wake,
    };

    // D7: gossip receiver feeds peer Task1 evidence through the same
    // canonical collector used by all other Task4 event sources.
    let _ = TASK4_PEER_EVENT_INGRESS.set(tx.clone());
    tokio::spawn(run_collector(state.clone(), rx));
    tokio::spawn(run_scheduler(state.clone(), scheduler_wake_rx));
    tokio::spawn(run_suricata_adapter(
        config_clone_state_dir(&state),
        tx.clone(),
        state.clone(),
    ));
    tokio::spawn(run_task1_adapter(tx, state.clone()));
    Ok(handle)
}

async fn run_collector(
    state: Arc<RwLock<Task4RuntimeState>>,
    mut rx: mpsc::Receiver<SecurityEvent>,
) {
    while let Some(event) = rx.recv().await {
        let mut state = state.write().await;
        if let Err(error) = ingest_event(&mut state, event) {
            state.status.events_dropped = state.status.events_dropped.saturating_add(1);
            state.status.last_error = Some(error.to_string());
        }
        let _ = persist_status_and_health(&state);
    }
}

async fn run_scheduler(
    state: Arc<RwLock<Task4RuntimeState>>,
    mut scheduler_wake: watch::Receiver<u64>,
) {
    eprintln!("[TASK4-SCHED] scheduler task started");

    {
        eprintln!("[TASK4-SCHED] acquiring initial read lock");
        let state_guard = state.read().await;
        eprintln!("[TASK4-SCHED] initial read lock acquired");
        let _ = persist_status_and_health(&state_guard);
    }

    eprintln!("[TASK4-SCHED] entering scheduler loop");

    loop {
        let (enabled, interval_duration) = {
            let guard = state.read().await;
            (
                guard.status.enabled,
                scheduler_interval_duration(&guard.config),
            )
        };

        if !enabled {
            if scheduler_wake.changed().await.is_err() {
                break;
            }
            continue;
        }

        // Run immediately after enable/start, then wait for either the next
        // configured interval or a live configuration change.
        {
            eprintln!("[TASK4-SCHED] waiting for cycle write lock");

            let mut guard = state.write().await;

            eprintln!("[TASK4-SCHED] cycle write lock acquired");

            if guard.status.enabled {
                eprintln!("[TASK4-SCHED] starting prediction cycle");

                if let Err(error) = run_prediction_cycle(&mut guard) {
                    eprintln!("[TASK4-SCHED] prediction cycle failed: {error}");
                    guard.status.degraded = true;
                    guard.status.last_error = Some(error.to_string());
                } else {
                    eprintln!("[TASK4-SCHED] prediction cycle completed");
                }

                let _ = persist_status_and_health(&guard);
            }
        }

        tokio::select! {
            _ = sleep(interval_duration) => {}
            changed = scheduler_wake.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
}

fn wake_scheduler(sender: &watch::Sender<u64>) {
    let next = sender.borrow().wrapping_add(1);
    let _ = sender.send(next);
}

fn scheduler_interval_duration(config: &Task4ThreatPredictionRuntimeConfig) -> std::time::Duration {
    if let Ok(raw) = std::env::var("SGX_TASK4_PREDICTION_INTERVAL_SECS") {
        if let Ok(secs) = raw.parse::<u64>() {
            if secs > 0 {
                return std::time::Duration::from_secs(secs);
            }
        }
    }

    #[cfg(test)]
    {
        if config.debounce > std::time::Duration::ZERO {
            return config.debounce;
        }
    }

    std::time::Duration::from_secs(
        u64::from(config.prediction.forecast_interval_minutes)
            .saturating_mul(60)
            .max(1),
    )
}

async fn run_suricata_adapter(
    state_dir: PathBuf,
    tx: mpsc::Sender<SecurityEvent>,
    state: Arc<RwLock<Task4RuntimeState>>,
) {
    let mut rx = crate::threat::ai_bridge::subscribe();
    loop {
        match rx.recv().await {
            Ok(feature) => {
                let node_id = {
                    let guard = state.read().await;
                    guard.config.node_id.clone()
                };
                match suricata_feature_to_event(&node_id, feature) {
                    Ok(event) => {
                        if tx.try_send(event).is_err() {
                            let mut guard = state.write().await;
                            guard.status.events_dropped =
                                guard.status.events_dropped.saturating_add(1);
                            source_health_mut(&mut guard, "suricata").events_dropped += 1;
                            let _ = persist_status_and_health(&guard);
                        }
                    }
                    Err(error) => {
                        let mut guard = state.write().await;
                        let health = source_health_mut(&mut guard, "suricata");
                        health.validation_failures += 1;
                        health.last_error = Some(error.to_string());
                        let _ = persist_status_and_health(&guard);
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                let mut guard = state.write().await;
                let health = source_health_mut(&mut guard, "suricata");
                health.lagged_events = health.lagged_events.saturating_add(count);
                health.last_error = Some(format!("lagged by {count} Suricata alert(s)"));
                let _ = persist_status_and_health(&guard);
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                let mut guard = state.write().await;
                source_health_mut(&mut guard, "suricata").last_error =
                    Some("Suricata feature tap closed".into());
                let _ = persist_status_and_health(&guard);
                break;
            }
        }
        let _ = state_dir.as_path();
    }
}

async fn run_task1_adapter(tx: mpsc::Sender<SecurityEvent>, state: Arc<RwLock<Task4RuntimeState>>) {
    const RECENT_ALERT_LIMIT: usize = 256;
    const POLL_SECS: u64 = 2;

    let mut tick = interval(std::time::Duration::from_secs(POLL_SECS));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // D7 gossip dedup is independent from local Task4 ingestion dedup.
    let mut gossiped_task1_events = std::collections::HashSet::<String>::new();

    loop {
        tick.tick().await;

        let task1_state_dir = { state.read().await.config.task1_state_dir.clone() };
        let alerts = match crate::task1_ai::runtime::load_recent_full_ml_alerts(
            &task1_state_dir,
            RECENT_ALERT_LIMIT,
        ) {
            Ok(alerts) => alerts,
            Err(error) => {
                let mut guard = state.write().await;
                let health = source_health_mut(&mut guard, "task1_anomaly");
                health.last_error = Some(format!("loading Task1 full-ML alerts: {error}"));
                let _ = persist_status_and_health(&guard);
                continue;
            }
        };

        for alert in alerts {
            let event = match task1_full_ml_alert_to_event(&alert) {
                Ok(event) => event,
                Err(error) => {
                    let mut guard = state.write().await;
                    let health = source_health_mut(&mut guard, "task1_anomaly");
                    health.validation_failures = health.validation_failures.saturating_add(1);
                    health.last_error = Some(error.to_string());
                    let _ = persist_status_and_health(&guard);
                    continue;
                }
            };

            // Avoid filling the queue with already-ingested records on every
            // polling cycle. ingest_event() remains the final dedup authority.
            let already_seen = {
                let guard = state.read().await;
                guard.dedup.contains(&event.deduplication_key())
            };
            // D7 peer distribution uses a separate dedup lifecycle.
            // Local Task4 ingestion must not suppress first-time gossip.
            if !gossiped_task1_events.contains(&event.event_id) {
                match crate::crl::gossip::task1_anomaly::broadcast_task1_anomaly(
                    &alert.node,
                    &alert,
                )
                .await
                {
                    Ok(()) => {
                        gossiped_task1_events.insert(event.event_id.clone());
                    }
                    Err(error) => {
                        tracing::warn!(
                            "D7 Task1 peer-evidence broadcast failed node={} ts={} error={}",
                            alert.node,
                            alert.ts,
                            error
                        );
                    }
                }
            }

            // Preserve the original local Task4 dedup behaviour.
            if already_seen {
                continue;
            }

            if let Err(error) = tx.try_send(event) {
                let mut guard = state.write().await;
                guard.status.events_dropped = guard.status.events_dropped.saturating_add(1);
                let health = source_health_mut(&mut guard, "task1_anomaly");
                health.events_dropped = health.events_dropped.saturating_add(1);
                health.last_error =
                    Some(format!("Task1 Task4 ingestion queue unavailable: {error}"));
                let _ = persist_status_and_health(&guard);
            }
        }
    }
}

pub(crate) fn task1_full_ml_alert_to_event(
    alert: &crate::task1_ai::runtime::Task1FullMlAlertRecord,
) -> Result<SecurityEvent> {
    if !alert.score.is_finite() || !(0.0..=1.0).contains(&alert.score) {
        return Err(anyhow!(
            "Task1 anomaly score outside [0,1]: {}",
            alert.score
        ));
    }

    if !alert.model_confidence.is_finite() || !(0.0..=1.0).contains(&alert.model_confidence) {
        return Err(anyhow!(
            "Task1 model confidence outside [0,1]: {}",
            alert.model_confidence
        ));
    }

    let severity_text = serde_json::to_value(&alert.severity)?
        .as_str()
        .unwrap_or("unknown")
        .to_ascii_lowercase();

    let severity = match severity_text.as_str() {
        "info" => EventSeverity::Info,
        "low" => EventSeverity::Low,
        "medium" => EventSeverity::Medium,
        "high" => EventSeverity::High,
        "critical" => EventSeverity::Critical,
        other => return Err(anyhow!("unsupported Task1 severity '{other}'")),
    };

    let tier = serde_json::to_value(&alert.tier)?
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let runtime_json = serde_json::to_string(&alert.runtime)?;

    let mut attributes = BTreeMap::new();
    attributes.insert("task1_anomaly_score".to_string(), alert.score.to_string());
    attributes.insert("task1_tier".to_string(), tier);
    attributes.insert("task1_reason".to_string(), alert.reason.clone());

    for (index, feature) in alert.topk.iter().take(3).enumerate() {
        attributes.insert(format!("task1_feature_{index}"), feature.clone());
    }

    attributes.insert("task1_model_metadata".to_string(), runtime_json);

    // The Task1 Full-ML record is already an anomaly. Task4 does not
    // recalculate or reinterpret its anomaly score.
    //
    // Use the existing Task1 timestamp + node + score + evidence as stable
    // source identity so polling the JSONL file cannot create duplicate
    // canonical events.
    let identity = format!(
        "{}|{}|{:.17}|{}",
        alert.ts,
        alert.node,
        alert.score,
        alert.topk.join(",")
    );

    let digest = sha2::Sha256::digest(identity.as_bytes());
    let event_id = format!("task4-task1:{digest:x}");

    let event = SecurityEvent {
        schema_version: SECURITY_EVENT_SCHEMA_VERSION,
        event_id,
        observed_at_ms: alert.ts,
        source: EvidenceSource::Task1Anomaly,
        node_id: alert.node.clone(),
        peer_id: None,
        source_ip: None,
        destination_ip: None,
        source_port: None,
        destination_port: None,
        event_type: SecurityEventType::TrafficAnomaly,
        severity,
        confidence: alert.model_confidence,
        attributes,
    };

    event.validate()?;
    Ok(event)
}

fn ingest_event(state: &mut Task4RuntimeState, event: SecurityEvent) -> Result<()> {
    event.validate_at(now_ms().saturating_add(30_000))?;
    let source = source_name(event.source);
    let key = event.deduplication_key();
    if !state.dedup.insert(key) {
        return Ok(());
    }
    append_jsonl(&events_path(&state.config.state_dir), &event)?;
    state.events.push_back(event);
    while state.events.len() > state.config.max_events {
        if let Some(old) = state.events.pop_front() {
            state.dedup.remove(&old.deduplication_key());
        }
    }
    state.status.events_ingested = state.status.events_ingested.saturating_add(1);
    let health = source_health_mut(state, source);
    health.events_ingested = health.events_ingested.saturating_add(1);
    health.last_success_at_ms = Some(now_ms());
    health.last_error = None;
    Ok(())
}

fn run_prediction_cycle(state: &mut Task4RuntimeState) -> Result<()> {
    let cycle_started = Instant::now();
    let evaluated_at_ms = now_ms();
    state.status.last_cycle_at_ms = Some(evaluated_at_ms);
    eprintln!("[TASK4-CYCLE] Task3 context START");
    let stage = Instant::now();
    ingest_task3_context(state, evaluated_at_ms)?;
    eprintln!(
        "[TASK4-CYCLE] Task3 context DONE elapsed_ms={}",
        stage.elapsed().as_millis()
    );

    eprintln!(
        "[TASK4-CYCLE] D4 temporal engine START events={}",
        state.events.len()
    );
    let stage = Instant::now();
    let mut temporal = TemporalFeatureEngine::new(TemporalFeatureConfig {
        max_events: state.config.max_events,
        ..TemporalFeatureConfig::default()
    })?;
    let replayed = temporal.ingest_replay(state.events.iter().cloned())?;
    eprintln!(
        "[TASK4-CYCLE] D4 replay DONE elapsed_ms={} accepted={}",
        stage.elapsed().as_millis(),
        replayed
    );

    let events = state.events.iter().cloned().collect::<Vec<_>>();

    eprintln!("[TASK4-CYCLE] D4 feature compute START");
    let stage = Instant::now();
    let features = temporal.features_for_node_at(&state.config.node_id, evaluated_at_ms);
    eprintln!(
        "[TASK4-CYCLE] D4 feature compute DONE elapsed_ms={}",
        stage.elapsed().as_millis()
    );

    // D4 runtime observability: persist the exact temporal feature set
    // produced from production Task4 events. This does not alter feature
    // calculation or predictor behavior.
    let temporal_features_path = state.config.state_dir.join("temporal_features.json");
    let temporal_features_json =
        serde_json::to_vec_pretty(&features).context("serialize Task4 temporal features")?;
    std::fs::write(&temporal_features_path, temporal_features_json).with_context(|| {
        format!(
            "persist Task4 temporal features to {}",
            temporal_features_path.display()
        )
    })?;
    eprintln!("[TASK4-CYCLE] D5 sequence START events={}", events.len());
    let stage = Instant::now();
    let sequence = match_precursor_sequence(
        &PrecursorSequenceDefinition::recon_to_compromise(),
        &state.config.node_id,
        &events,
        evaluated_at_ms,
    )
    .context("evaluate Task4 precursor sequence")?;
    eprintln!(
        "[TASK4-CYCLE] D5 sequence DONE elapsed_ms={}",
        stage.elapsed().as_millis()
    );

    // D5 runtime observability: persist the exact precursor-sequence result
    // produced from production Task4 events. This does not modify matching,
    // source events, ordering, scoring, or downstream predictor behavior.
    let sequence_path = state.config.state_dir.join("precursor_sequence.json");
    let sequence_json =
        serde_json::to_vec_pretty(&sequence).context("serialize Task4 precursor sequence")?;
    std::fs::write(&sequence_path, sequence_json).with_context(|| {
        format!(
            "persist Task4 precursor sequence to {}",
            sequence_path.display()
        )
    })?;

    let sequence = Some(sequence);

    let input = ThreatPredictorInput {
        node_id: &state.config.node_id,
        evaluated_at_ms,
        temporal_features: &features,
        events: &events,
        precursor_sequence: sequence.as_ref(),
        config: &state.config.prediction,
    };

    let predictors: [&dyn ThreatPredictor; 5] = [
        &DdosPredictor,
        &ReconEscalationPredictor,
        &BruteForcePredictor,
        &ExploitationPredictor,
        &ProtocolAbusePredictor,
    ];
    eprintln!("[TASK4-CYCLE] D6 predictors START");
    let stage = Instant::now();
    let mut forecasts = Vec::new();
    for predictor in predictors {
        if let Some(mut forecast) = predictor.predict(&input)? {
            // D8: calibration is model-bound. Never apply calibration
            // metadata belonging to a different predictor model.
            let calibration = &state.config.prediction.probability_calibration;

            if calibration.metadata.model_version == forecast.model_version {
                forecast.probability = calibration
                    .calibrate_probability(forecast.probability, &forecast.model_version)
                    .context("D8 calibrate forecast probability")?;

                let contributing_sources = forecast
                    .evidence_ids
                    .iter()
                    .filter_map(|evidence_id| {
                        events
                            .iter()
                            .find(|event| &event.event_id == evidence_id)
                            .map(|event| event.source)
                    })
                    .collect::<Vec<_>>();

                let geo_feed_available = events.iter().any(|event| {
                    event.source == EvidenceSource::GeoThreatIntel
                        && event.observed_at_ms <= evaluated_at_ms
                        && event.observed_at_ms.saturating_add(30 * 60 * 1_000) >= evaluated_at_ms
                });

                let assessment = assess_confidence(
                    &ConfidenceContext {
                        contributing_sources,
                        stale_sources: 0,
                        missing_sources: 0,
                        history_sufficient: !events.is_empty(),
                        source_health_degraded: state.status.degraded,
                        topology_complete: true,
                        geo_feed_available,
                        calibration_matches_model: true,
                    },
                    calibration.metadata.clone(),
                )
                .context("D8 assess forecast confidence")?;

                forecast.confidence = assessment.confidence;
                forecast.explanation.calibration = Some(assessment.calibration);
            }

            forecast.validate()?;
            forecasts.push(forecast);
        }
    }
    eprintln!(
        "[TASK4-CYCLE] D6 predictors DONE elapsed_ms={} forecasts={}",
        stage.elapsed().as_millis(),
        forecasts.len()
    );

    eprintln!("[TASK4-CYCLE] D7 cascade START");
    let stage = Instant::now();

    // D7: evaluate peer-compromise cascade only from production
    // Task3 relationship evidence plus fresh target Task1/Suricata evidence.
    // Circle membership/topology alone cannot create a cascade forecast.
    append_peer_cascade_forecasts(state, &events, evaluated_at_ms, &mut forecasts)?;
    eprintln!(
        "[TASK4-CYCLE] D7 cascade DONE elapsed_ms={} forecasts={}",
        stage.elapsed().as_millis(),
        forecasts.len()
    );

    eprintln!("[TASK4-CYCLE] D9 lifecycle START");
    let stage = Instant::now();

    forecasts.sort_by(|left, right| {
        right
            .probability
            .partial_cmp(&left.probability)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // D9 production lifecycle:
    // - a previous forecast whose horizon has elapsed becomes Expired;
    // - a still-valid previous forecast replaced by a new forecast for the
    //   same threat type and target set becomes Superseded;
    // - every newly generated forecast remains Active.
    //
    // Lifecycle records are appended to the existing canonical
    // forecast_history.jsonl so production has one audit history.
    let previous_forecasts = state.current_forecasts.clone();

    for previous in &previous_forecasts {
        if previous.status != ForecastStatus::Active {
            continue;
        }

        let next_status = if previous.horizon_end_ms <= evaluated_at_ms {
            Some(ForecastStatus::Expired)
        } else if forecasts.iter().any(|next| {
            next.threat_type == previous.threat_type
                && next.target_nodes == previous.target_nodes
                && next.forecast_id != previous.forecast_id
        }) {
            Some(ForecastStatus::Superseded)
        } else {
            None
        };

        if let Some(next_status) = next_status {
            let mut transitioned = previous.clone();
            transitioned.status = next_status;
            transitioned.validate()?;
            append_jsonl(
                &forecast_history_path(&state.config.state_dir),
                &transitioned,
            )?;
        }
    }

    for forecast in &forecasts {
        append_jsonl(&forecast_history_path(&state.config.state_dir), forecast)?;
    }

    eprintln!(
        "[TASK4-CYCLE] D9 lifecycle DONE elapsed_ms={}",
        stage.elapsed().as_millis()
    );

    eprintln!("[TASK4-CYCLE] persistence/handoff START");
    let stage = Instant::now();

    state.current_forecasts = forecasts;
    state.status.active_forecast_count = state.current_forecasts.len();
    state.status.latest_forecast_probability =
        state.current_forecasts.first().map(|f| f.probability);
    state.status.latest_forecast_confidence = state.current_forecasts.first().map(|f| f.confidence);
    state.status.last_successful_cycle_at_ms = Some(evaluated_at_ms);
    state.status.last_error = None;
    persist_current_forecasts(state)?;
    create_task2_handoffs(state)?;

    eprintln!(
        "[TASK4-CYCLE] persistence/handoff DONE elapsed_ms={}",
        stage.elapsed().as_millis()
    );
    persist_d12_runtime_evaluation(
        state,
        &events,
        &features,
        sequence
            .as_ref()
            .expect("Task4 D5 sequence is always evaluated before D12 persistence"),
        evaluated_at_ms,
        cycle_started.elapsed().as_micros(),
    )?;
    Ok(())
}

fn append_peer_cascade_forecasts(
    state: &Task4RuntimeState,
    events: &[SecurityEvent],
    evaluated_at_ms: u64,
    forecasts: &mut Vec<ThreatForecast>,
) -> Result<()> {
    let route_candidates_path = state.config.task3_runtime_dir.join("route_candidates.json");

    // D7 is additive. Missing Task3 topology must not break D1-D6.
    if !route_candidates_path.exists() {
        return Ok(());
    }

    let raw = std::fs::read(&route_candidates_path).with_context(|| {
        format!(
            "read D7 Task3 route candidates from {}",
            route_candidates_path.display()
        )
    })?;

    let document: serde_json::Value =
        serde_json::from_slice(&raw).context("parse D7 Task3 route candidates")?;

    let Some(candidates) = document
        .get("candidates")
        .and_then(|value| value.as_array())
    else {
        return Ok(());
    };

    // Prefer an existing D6 forecast for the local source node.
    // If D6 has no active forecast, D7 may derive source risk from a fresh,
    // authoritative local Task1 anomaly. This keeps D7 driven by real runtime
    // evidence without manufacturing a probability or depending on D6 output.
    let d6_source_probability = forecasts
        .iter()
        .filter(|forecast| {
            forecast
                .target_nodes
                .iter()
                .any(|node| node == &state.config.node_id)
        })
        .map(|forecast| forecast.probability)
        .filter(|probability| probability.is_finite() && (0.0..=1.0).contains(probability))
        .max_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));

    let task1_source_probability = events
        .iter()
        .filter(|event| {
            event.node_id == state.config.node_id
                && event.source == EvidenceSource::Task1Anomaly
                && event.observed_at_ms <= evaluated_at_ms
                && event.observed_at_ms.saturating_add(30 * 60 * 1_000) >= evaluated_at_ms
        })
        .filter_map(|event| {
            event
                .attributes
                .get("task1_anomaly_score")
                .and_then(|value| value.parse::<f64>().ok())
        })
        .filter(|probability| probability.is_finite() && (0.0..=1.0).contains(probability))
        .max_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));

    let Some(source_probability) = d6_source_probability.or(task1_source_probability) else {
        return Ok(());
    };

    for candidate in candidates {
        let source_node = candidate
            .get("source_node")
            .and_then(|value| value.as_str())
            .unwrap_or_default();

        let target_node = candidate
            .get("destination_node")
            .and_then(|value| value.as_str())
            .unwrap_or_default();

        let route_id = candidate
            .get("route_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default();

        let observed_available = candidate
            .get("observed_available")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);

        let observed_healthy = candidate
            .get("observed_healthy")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);

        let route_kind = candidate
            .get("kind")
            .and_then(|value| value.as_str())
            .unwrap_or_default();

        let relay_ids = candidate
            .get("relay_ids")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if source_node != state.config.node_id
            || target_node.is_empty()
            || target_node == state.config.node_id
            || route_id.is_empty()
            || !observed_available
        {
            continue;
        }

        let direct = route_kind == "DirectP2p";
        let relay = matches!(route_kind, "Relay" | "MultiHopRelay") && !relay_ids.is_empty();

        let mut reasons = Vec::new();

        if direct {
            reasons.push("live Task3 direct peer route".to_string());
        }

        if relay {
            reasons.push("live Task3 relay dependency".to_string());
        }

        if observed_healthy {
            reasons.push("Task3 route observed healthy".to_string());
        }

        if reasons.is_empty() {
            continue;
        }

        let relationship = PeerRelationship {
            relationship_id: format!("task3-route:{route_id}"),
            provenance: "task3-route-candidates".to_string(),
            reasons,

            // This relationship is derived during the current Task4 cycle
            // from Task3's production route inventory.
            observed_at_ms: evaluated_at_ms,
            expires_at_ms: evaluated_at_ms.saturating_add(30 * 60_000),

            source_node: source_node.to_string(),
            target_node: target_node.to_string(),

            // RouteCandidate does not prove same-segment membership.
            same_segment: false,

            // An available direct P2P route is explicit direct-peer evidence.
            recent_direct_communication: direct && observed_available,

            // Relay IDs explicitly prove relay dependency.
            shared_service_or_relay: relay,

            // An available Task3 route proves a topology relationship.
            topology_dependency: observed_available,

            // RouteCandidate contains no exposed-port evidence.
            relevant_exposed_port: false,
        };

        if let Some(cascade) = predict_peer_cascade(
            source_probability,
            &relationship,
            events,
            evaluated_at_ms,
            &state.config.prediction,
        )
        .context("evaluate D7 peer compromise cascade")?
        {
            cascade.validate()?;

            if !forecasts
                .iter()
                .any(|existing| existing.forecast_id == cascade.forecast_id)
            {
                forecasts.push(cascade);
            }
        }
    }

    Ok(())
}

fn ingest_task3_context(state: &mut Task4RuntimeState, evaluated_at_ms: u64) -> Result<()> {
    let path = state
        .config
        .task3_runtime_dir
        .join("degradation_events.jsonl");
    let events = read_task3_degradation_events_at(
        &path,
        &state.config.node_id,
        None,
        evaluated_at_ms,
        &Task3ContextConfig::default(),
    )?;
    for event in events {
        ingest_event(state, event)?;
    }
    Ok(())
}

fn create_task2_handoffs(state: &mut Task4RuntimeState) -> Result<()> {
    let templates: PolicyTemplates = serde_json::from_str(POLICY_ACTION_TEMPLATES_JSON)?;
    templates.validate()?;
    let hardening = HardeningRecommendationConfig::default();
    let roles = RoleRegistry::from_json_str(NODE_ROLES_JSON)?;
    let review_root = state.config.virtual_shift_root.join(VS10_VS11_REVIEWS);
    fs::create_dir_all(&review_root)?;
    let queue = ReviewQueue::new(review_root, roles);

    for forecast in &state.current_forecasts {
        if !matches!(
            forecast.severity,
            ForecastSeverity::Advisory
                | ForecastSeverity::UrgentReview
                | ForecastSeverity::Critical
        ) {
            continue;
        }
        let recommendation = match recommend_predictive_hardening(
            forecast,
            &state.config.prediction,
            &hardening,
            &templates,
        ) {
            Ok(recommendation) => recommendation,
            Err(_) => continue,
        };
        if !state
            .handoff_ids
            .insert(recommendation.recommendation_id.clone())
        {
            continue;
        }
        append_jsonl(
            &recommendations_path(&state.config.state_dir),
            &recommendation,
        )?;
        let plan = recommendation_to_plan(&state.config.node_id, forecast, &recommendation);
        let (_, handoff) = queue.enqueue_ai_remediation_plan(
            plan,
            format!(
                "{}/current_forecasts.json#{}",
                state.config.state_dir.display(),
                forecast.forecast_id
            ),
        )?;
        append_jsonl(&task2_handoffs_path(&state.config.state_dir), &handoff)?;
        if !handoff.duplicate {
            state.status.task2_handoffs_created =
                state.status.task2_handoffs_created.saturating_add(1);
        }
        state.status.task2_handoffs_pending = state.status.task2_handoffs_pending.saturating_add(1);
    }
    Ok(())
}

fn recommendation_to_plan(
    node_id: &str,
    forecast: &ThreatForecast,
    recommendation: &sgx_anomaly_engine::threat_prediction::PredictiveHardeningRecommendation,
) -> AiRemediationPlan {
    AiRemediationPlan {
        plan_id: recommendation.recommendation_id.clone(),
        anomaly_id: forecast.forecast_id.clone(),
        source_node: node_id.to_string(),
        anomaly_score: forecast.probability,
        model_confidence: forecast.confidence,
        severity: format!("{:?}", forecast.severity),
        anomaly_metadata: json!({
            "task": "task4_threat_prediction",
            "threat_type": forecast.threat_type,
            "forecast_id": forecast.forecast_id,
            "evidence_ids": forecast.evidence_ids,
            "feature_snapshot_id": forecast.feature_snapshot_id
        }),
        justification: recommendation.reason.clone(),
        created_at_ms: forecast.generated_at_ms,
        requires_approval: true,
        auto_execute: false,
        actions: recommendation
            .actions
            .iter()
            .map(|action| AiRemediationAction {
                action_type: policy_action_name(*action).into(),
                target: recommendation
                    .target_nodes
                    .first()
                    .cloned()
                    .unwrap_or_else(|| node_id.to_string()),
                parameters: json!({
                    "source": "task4_threat_prediction",
                    "forecast_id": forecast.forecast_id,
                    "threat_type": forecast.threat_type
                }),
                requires_approval: true,
                reason: recommendation.reason.clone(),
            })
            .collect(),
    }
}

fn policy_action_name(action: PolicyAction) -> &'static str {
    match action {
        PolicyAction::TightenFirewall => "tighten_firewall_rules",
        PolicyAction::IncreaseAttestationFrequency => "increase_attestation_frequency",
        PolicyAction::EnableAdditionalLogging => "enable_additional_logging",
        PolicyAction::QuarantinePeer => "quarantine_suspicious_peer",
    }
}

fn suricata_feature_to_event(node_id: &str, feature: AlertFeature) -> Result<SecurityEvent> {
    let observed_at_ms = u64::try_from(feature.ts.timestamp_millis())
        .map_err(|_| anyhow!("Suricata alert timestamp predates Unix epoch"))?;
    // Preserve the existing category-based normalization contract while
    // recognizing the Guardian TCP port-scan precursor used by Task4 D5.
    //
    // SID 19900001 is the SG-X Guardian repeated TCP SYN port-scan rule.
    // All other Suricata signatures retain their existing classification.
    let event_type = match (feature.signature_id, feature.category) {
        (19_900_001, crate::threat::threat_alert::ThreatCategory::Reconnaissance) => {
            SecurityEventType::PortDiscovery
        }

        (_, crate::threat::threat_alert::ThreatCategory::Reconnaissance) => {
            SecurityEventType::Reconnaissance
        }

        (
            _,
            crate::threat::threat_alert::ThreatCategory::Malware
            | crate::threat::threat_alert::ThreatCategory::Exploit,
        ) => SecurityEventType::ExposureDiscovery,

        (_, crate::threat::threat_alert::ThreatCategory::PolicyViolation) => {
            SecurityEventType::ProtocolViolation
        }

        (_, crate::threat::threat_alert::ThreatCategory::Anomaly) => {
            SecurityEventType::TrafficAnomaly
        }

        _ => SecurityEventType::ProtocolViolation,
    };
    let severity = match feature.severity_score {
        4 => EventSeverity::Critical,
        3 => EventSeverity::High,
        2 => EventSeverity::Medium,
        1 => EventSeverity::Low,
        _ => EventSeverity::Info,
    };
    let mut event = SecurityEvent {
        schema_version: SECURITY_EVENT_SCHEMA_VERSION,
        event_id: "task4-suricata-pending".into(),
        observed_at_ms,
        source: EvidenceSource::Suricata,
        node_id: node_id.to_string(),
        peer_id: None,
        source_ip: Some(feature.src_ip),
        destination_ip: Some(feature.dst_ip),
        source_port: None,
        destination_port: None,
        event_type,
        severity,
        confidence: (f64::from(feature.severity_score) / 4.0).clamp(0.0, 1.0),
        attributes: BTreeMap::from([
            (
                "suricata_signature_id".into(),
                feature.signature_id.to_string(),
            ),
            (
                "suricata_category".into(),
                format!("{:?}", feature.category),
            ),
        ]),
    };
    event.event_id = event.deterministic_event_id();
    event.validate()?;
    Ok(event)
}

fn restore_events(state: &mut Task4RuntimeState) -> Result<()> {
    let path = events_path(&state.config.state_dir);
    let Ok(raw) = fs::read_to_string(&path) else {
        return Ok(());
    };
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        if let Ok(event) = serde_json::from_str::<SecurityEvent>(line) {
            if event.validate().is_ok() && state.dedup.insert(event.deduplication_key()) {
                state.events.push_back(event);
            }
        }
    }
    while state.events.len() > state.config.max_events {
        state.events.pop_front();
    }
    Ok(())
}

fn persist_d12_runtime_evaluation(
    state: &Task4RuntimeState,
    events: &[SecurityEvent],
    features: &TemporalFeatures,
    sequence: &PrecursorSequenceMatch,
    evaluated_at_ms: u64,
    inference_latency_micros: u128,
) -> Result<()> {
    let mut source_event_counts = BTreeMap::new();
    let mut task1_event_ids = Vec::new();
    let mut task3_event_ids = Vec::new();
    let mut task3_decision_ids = Vec::new();

    for event in events {
        *source_event_counts
            .entry(source_name(event.source).to_string())
            .or_insert(0) += 1;

        match event.source {
            EvidenceSource::Task1Anomaly => task1_event_ids.push(event.event_id.clone()),
            EvidenceSource::NetworkAi => {
                task3_event_ids.push(event.event_id.clone());
                if let Some(decision_id) = event.attributes.get("task3_decision_id") {
                    task3_decision_ids.push(decision_id.clone());
                }
            }
            _ => {}
        }
    }

    let artifact = Task4D12RuntimeEvaluation {
        schema_version: D12_RUNTIME_EVALUATION_SCHEMA.into(),
        evaluation_id: format!("task4-d12-{}-{evaluated_at_ms}", state.config.node_id),
        node_id: state.config.node_id.clone(),
        evaluated_at_ms,
        accepted_event_count: events.len(),
        bounded_event_capacity: state.config.max_events,
        temporal_window_count: features.windows.len(),
        forecast_count: state.current_forecasts.len(),
        active_forecast_ids: state
            .current_forecasts
            .iter()
            .map(|forecast| forecast.forecast_id.clone())
            .collect(),
        latest_forecast_probability: state.status.latest_forecast_probability,
        latest_forecast_confidence: state.status.latest_forecast_confidence,
        task1_event_ids,
        task3_event_ids,
        task3_decision_ids,
        source_event_counts,
        sequence_id: sequence.sequence_id.clone(),
        sequence_matched_event_ids: sequence.matched_event_ids.clone(),
        sequence_matched_steps: sequence.matched_steps,
        sequence_total_steps: sequence.total_steps,
        sequence_fresh: sequence.fresh,
        inference_latency_micros,
        reused_existing_cycle_outputs: true,
    };

    write_json_atomic(
        &state
            .config
            .state_dir
            .join("d12_e2e_runtime_evaluation.json"),
        &artifact,
    )
}

fn persist_current_forecasts(state: &Task4RuntimeState) -> Result<()> {
    write_json_atomic(
        &state.config.state_dir.join("current_forecasts.json"),
        &json!({
            "schema_version": "task4-current-forecasts-v1",
            "node_id": state.config.node_id,
            "updated_at_ms": now_ms(),
            "forecasts": state.current_forecasts
        }),
    )
}

fn persist_status_and_health(state: &Task4RuntimeState) -> Result<()> {
    write_json_atomic(
        &state.config.state_dir.join("runtime_status.json"),
        &state.status,
    )?;
    write_json_atomic(
        &state.config.state_dir.join("source_health.json"),
        &json!({
            "schema_version": SOURCE_HEALTH_SCHEMA,
            "node_id": state.config.node_id,
            "updated_at_ms": now_ms(),
            "sources": state.source_health
        }),
    )
}

fn source_health_mut<'a>(
    state: &'a mut Task4RuntimeState,
    source: &str,
) -> &'a mut Task4SourceHealth {
    state
        .source_health
        .entry(source.to_string())
        .or_insert_with(|| Task4SourceHealth {
            schema_version: SOURCE_HEALTH_SCHEMA.into(),
            source: source.to_string(),
            enabled: true,
            last_success_at_ms: None,
            last_error: None,
            events_ingested: 0,
            events_dropped: 0,
            validation_failures: 0,
            lagged_events: 0,
        })
}

fn source_name(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::Task1Anomaly => "task1",
        EvidenceSource::Suricata => "suricata",
        EvidenceSource::NmapDiscovery => "discovery",
        EvidenceSource::GuardianThreat => "guardian_threat",
        EvidenceSource::Attestation => "attestation",
        EvidenceSource::CircleTrust => "circle",
        EvidenceSource::NetworkAi => "task3",
        EvidenceSource::GeoThreatIntel => "geo",
        EvidenceSource::PolicyLifecycle => "policy",
    }
}

fn config_clone_state_dir(state: &Arc<RwLock<Task4RuntimeState>>) -> PathBuf {
    state
        .try_read()
        .map(|state| state.config.state_dir.clone())
        .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/threat-prediction"))
}

fn events_path(root: &Path) -> PathBuf {
    root.join("events.jsonl")
}

fn forecast_history_path(root: &Path) -> PathBuf {
    root.join("forecast_history.jsonl")
}

fn recommendations_path(root: &Path) -> PathBuf {
    root.join("recommendations.jsonl")
}

fn task2_handoffs_path(root: &Path) -> PathBuf {
    root.join("task2_handoffs.jsonl")
}

fn append_jsonl(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", serde_json::to_string(value)?)?;
    Ok(())
}

fn persist_prediction_config_atomic(
    path: &Path,
    config: &sgx_anomaly_engine::threat_prediction::ThreatPredictionConfig,
) -> Result<()> {
    config.validate()?;
    write_json_atomic(path, config)
        .with_context(|| format!("persist Task4 prediction config {}", path.display()))
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&tmp, path).with_context(|| format!("atomically replace {}", path.display()))?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use sgx_anomaly_engine::threat_prediction::ThreatPredictionConfig;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::time::Duration;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_runtime_state(enabled: bool, interval_ms: u64) -> Arc<RwLock<Task4RuntimeState>> {
        let root = std::env::temp_dir().join(format!(
            "task4-runtime-scheduler-test-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let config_path = root.join("config.json");
        let threat_root = root.join("threat");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&threat_root).unwrap();

        let mut prediction = ThreatPredictionConfig::default();
        prediction.enabled = enabled;
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&prediction).unwrap(),
        )
        .unwrap();

        let mut config = Task4ThreatPredictionRuntimeConfig::for_tests(
            "nodeA",
            config_path,
            root.clone(),
            threat_root,
        );
        config.prediction.enabled = enabled;
        config.config_error = None;
        config.debounce = Duration::from_millis(interval_ms);
        ensure_runtime_dirs(&config).unwrap();

        Arc::new(RwLock::new(Task4RuntimeState {
            status: Task4RuntimeStatus {
                schema_version: STATUS_SCHEMA.into(),
                enabled,
                degraded: false,
                node_id: config.node_id.clone(),
                started_at_ms: now_ms(),
                last_cycle_at_ms: None,
                last_successful_cycle_at_ms: None,
                last_error: None,
                events_ingested: 0,
                events_dropped: 0,
                active_forecast_count: 0,
                latest_forecast_probability: None,
                latest_forecast_confidence: None,
                task2_handoffs_created: 0,
                task2_handoffs_pending: 0,
                config_path: config.config_path.display().to_string(),
                state_dir: config.state_dir.display().to_string(),
            },
            config,
            events: VecDeque::new(),
            dedup: BTreeSet::new(),
            current_forecasts: Vec::new(),
            source_health: BTreeMap::new(),
            handoff_ids: BTreeSet::new(),
        }))
    }

    async fn wait_for_successful_cycle_after(
        state: &Arc<RwLock<Task4RuntimeState>>,
        previous: Option<u64>,
    ) -> u64 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let current = state.read().await.status.last_successful_cycle_at_ms;
            if let Some(current) = current {
                if previous.is_none_or(|previous| current > previous) {
                    return current;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for Task4 scheduler cycle after {:?}",
                previous
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn last_successful_cycle(state: &Arc<RwLock<Task4RuntimeState>>) -> Option<u64> {
        state.read().await.status.last_successful_cycle_at_ms
    }

    fn precursor_sequence_path(state: &Task4RuntimeState) -> PathBuf {
        state.config.state_dir.join("precursor_sequence.json")
    }

    fn d12_runtime_evaluation_path(state: &Task4RuntimeState) -> PathBuf {
        state
            .config
            .state_dir
            .join("d12_e2e_runtime_evaluation.json")
    }

    fn runtime_recon_event(id: &str, observed_at_ms: u64) -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: id.into(),
            observed_at_ms,
            source: EvidenceSource::Suricata,
            node_id: "nodeA".into(),
            peer_id: None,
            source_ip: Some("10.0.0.10".into()),
            destination_ip: Some("10.0.0.20".into()),
            source_port: None,
            destination_port: Some(8443),
            event_type: SecurityEventType::Reconnaissance,
            severity: EventSeverity::High,
            confidence: 0.90,
            attributes: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn d12_runtime_evaluation_reuses_existing_cycle_outputs() {
        let state = test_runtime_state(true, 25);
        let path = {
            let mut guard = state.write().await;
            let observed_at_ms = now_ms().saturating_sub(1_000);
            ingest_event(
                &mut guard,
                runtime_recon_event("runtime-recon-1", observed_at_ms),
            )
            .unwrap();
            run_prediction_cycle(&mut guard).unwrap();
            d12_runtime_evaluation_path(&guard)
        };

        let raw = std::fs::read(&path).unwrap();
        let artifact: Task4D12RuntimeEvaluation = serde_json::from_slice(&raw).unwrap();
        assert_eq!(artifact.schema_version, D12_RUNTIME_EVALUATION_SCHEMA);
        assert_eq!(artifact.node_id, "nodeA");
        assert_eq!(artifact.accepted_event_count, 1);
        assert_eq!(artifact.source_event_counts["suricata"], 1);
        assert_eq!(artifact.sequence_total_steps, 6);
        assert!(artifact.reused_existing_cycle_outputs);
        assert!(artifact.inference_latency_micros > 0);
    }

    #[tokio::test]
    async fn scheduler_runs_initial_cycle_when_enabled() {
        let state = test_runtime_state(true, 25);
        let (_wake_tx, wake_rx) = watch::channel(0_u64);
        let task = tokio::spawn(run_scheduler(state.clone(), wake_rx));

        wait_for_successful_cycle_after(&state, None).await;
        let path = {
            let guard = state.read().await;
            assert!(guard.status.last_cycle_at_ms.is_some());
            precursor_sequence_path(&guard)
        };
        assert!(path.exists(), "precursor_sequence.json must be persisted");

        task.abort();
    }

    #[tokio::test]
    async fn scheduler_runs_repeated_cycle_after_interval() {
        let state = test_runtime_state(true, 25);
        let (_wake_tx, wake_rx) = watch::channel(0_u64);
        let task = tokio::spawn(run_scheduler(state.clone(), wake_rx));

        let first = wait_for_successful_cycle_after(&state, None).await;
        let second = wait_for_successful_cycle_after(&state, Some(first)).await;
        assert!(second > first);

        task.abort();
    }

    #[tokio::test]
    async fn disabled_scheduler_remains_alive_without_busy_loop() {
        let state = test_runtime_state(false, 20);
        let (wake_tx, wake_rx) = watch::channel(0_u64);
        let task = tokio::spawn(run_scheduler(state.clone(), wake_rx));

        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(last_successful_cycle(&state).await, None);

        {
            let mut guard = state.write().await;
            guard.config.prediction.enabled = true;
            guard.status.enabled = true;
        }
        wake_scheduler(&wake_tx);

        wait_for_successful_cycle_after(&state, None).await;
        task.abort();
    }

    #[tokio::test]
    async fn scheduler_reenable_resumes_cycles() {
        let state = test_runtime_state(true, 25);
        let (wake_tx, wake_rx) = watch::channel(0_u64);
        let task = tokio::spawn(run_scheduler(state.clone(), wake_rx));

        let first = wait_for_successful_cycle_after(&state, None).await;
        {
            let mut guard = state.write().await;
            guard.config.prediction.enabled = false;
            guard.status.enabled = false;
        }
        wake_scheduler(&wake_tx);
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(last_successful_cycle(&state).await, Some(first));

        {
            let mut guard = state.write().await;
            guard.config.prediction.enabled = true;
            guard.status.enabled = true;
        }
        wake_scheduler(&wake_tx);

        let resumed = wait_for_successful_cycle_after(&state, Some(first)).await;
        assert!(resumed > first);
        task.abort();
    }

    #[tokio::test]
    async fn scheduler_notifications_do_not_create_duplicate_immediate_loops() {
        let state = test_runtime_state(true, 80);
        let (wake_tx, wake_rx) = watch::channel(0_u64);
        let task = tokio::spawn(run_scheduler(state.clone(), wake_rx));

        let first = wait_for_successful_cycle_after(&state, None).await;
        wake_scheduler(&wake_tx);
        wake_scheduler(&wake_tx);
        wake_scheduler(&wake_tx);

        let notified = wait_for_successful_cycle_after(&state, Some(first)).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(last_successful_cycle(&state).await, Some(notified));

        task.abort();
    }

    #[test]
    fn suricata_feature_maps_to_bounded_security_event() {
        let feature = AlertFeature {
            ts: chrono::Utc::now(),
            severity_score: 4,
            signature_id: 1001,
            category: crate::threat::threat_alert::ThreatCategory::Reconnaissance,
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
        };
        let event = suricata_feature_to_event("nodeA", feature).unwrap();
        assert_eq!(event.source, EvidenceSource::Suricata);
        assert_eq!(event.event_type, SecurityEventType::Reconnaissance);
        assert_eq!(event.severity, EventSeverity::Critical);
        assert!(event.event_id.starts_with("task4-event-v1:"));
    }

    #[test]
    fn guardian_tcp_port_scan_maps_to_port_discovery() {
        let feature = AlertFeature {
            ts: chrono::Utc::now(),
            severity_score: 2,
            signature_id: 19_900_001,
            category: crate::threat::threat_alert::ThreatCategory::Reconnaissance,
            src_ip: "192.168.1.154".into(),
            dst_ip: "192.168.1.195".into(),
        };

        let event = suricata_feature_to_event("nodeA", feature).unwrap();

        assert_eq!(event.source, EvidenceSource::Suricata);
        assert_eq!(event.event_type, SecurityEventType::PortDiscovery);
        assert_eq!(event.severity, EventSeverity::Medium);
        assert_eq!(
            event.attributes.get("suricata_signature_id"),
            Some(&"19900001".to_string())
        );
        assert!(event.event_id.starts_with("task4-event-v1:"));
    }

    #[test]
    fn task4_plan_preserves_owner_approval_boundary() {
        let forecast = ThreatForecast {
            schema_version: sgx_anomaly_engine::threat_prediction::THREAT_FORECAST_SCHEMA_VERSION
                .into(),
            forecast_id: "forecast-nodeA-ddos".into(),
            model_version: "task4-test".into(),
            generated_at_ms: 1_000,
            horizon_start_ms: 1_000,
            horizon_end_ms: 301_000,
            threat_type: sgx_anomaly_engine::threat_prediction::PredictedThreatType::Ddos,
            target_nodes: vec!["nodeA".into()],
            probability: 0.90,
            confidence: 0.80,
            severity: ForecastSeverity::UrgentReview,
            evidence_ids: vec!["evidence-1".into()],
            feature_snapshot_id: "features".into(),
            explanation: sgx_anomaly_engine::threat_prediction::ForecastExplanation {
                summary: "evidence-backed forecast".into(),
                top_factors: vec![sgx_anomaly_engine::threat_prediction::ForecastFactor {
                    name: "traffic".into(),
                    contribution: 0.9,
                    evidence_ids: vec!["evidence-1".into()],
                }],
                precursor_sequence_ids: vec![],
                missing_evidence: vec![],
                relationship_reasons: vec![],
                calibration: None,
            },
            status: sgx_anomaly_engine::threat_prediction::ForecastStatus::Active,
        };
        let recommendation = sgx_anomaly_engine::threat_prediction::PredictiveHardeningRecommendation {
            schema_version: sgx_anomaly_engine::threat_prediction::PREDICTIVE_HARDENING_RECOMMENDATION_VERSION.into(),
            recommendation_id: "task4-task2-forecast-nodeA-ddos".into(),
            source: "task4_threat_prediction".into(),
            forecast_id: forecast.forecast_id.clone(),
            target_nodes: vec!["nodeA".into()],
            threat_type: forecast.threat_type,
            probability: forecast.probability,
            confidence: forecast.confidence,
            task2_template_version: 1,
            actions: vec![PolicyAction::TightenFirewall],
            requires_task2_review: true,
            evidence_ids: forecast.evidence_ids.clone(),
            reason: "owner review required".into(),
        };
        let plan = recommendation_to_plan("nodeA", &forecast, &recommendation);
        assert!(plan.requires_approval);
        assert!(!plan.auto_execute);
        assert_eq!(plan.actions[0].action_type, "tighten_firewall_rules");
        plan.validate().unwrap();
    }
}
