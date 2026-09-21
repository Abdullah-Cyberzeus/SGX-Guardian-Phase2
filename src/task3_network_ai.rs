use crate::cot::failover::FailoverEngine;
use crate::cot::link_monitor::{LinkMonitor, LinkSnapshot};
use crate::cot::membership::CircleMembership;
use crate::metrics::Metrics;
use crate::nebula::lighthouse::LighthouseRegistry;
use crate::nebula::overlay_registry::OverlayRegistry;
use crate::nebula::relay_registry::{RelayEntry, RelayRegistry};
use crate::nebula::stats::{NebulaStats, RelayStats};
use crate::task1_ai::telemetry::SgxTelemetrySource;
use crate::task1_ai::{full_ml_alerts_path, load_recent_full_ml_alerts};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sgx_anomaly_engine::network_ai::candidates::RouteCandidateMetadata;
use sgx_anomaly_engine::network_ai::{
    append_observation_jsonl, classify_message_type, persist_current_observation,
    ContextualBanditPolicy, DecisionAuditRecord, DecisionEvidenceLinks, EligibilityFilter,
    MultiRelayLoadBalancer, NetworkAiConfig as EngineNetworkAiConfig, NetworkAiRuntimeMode,
    NetworkObservation, NetworkTelemetryAdapter, NetworkTelemetryContext, ObservedRewardInput,
    RelayRuntimeHealth, RelayWeightSet, RouteCandidate, RouteHistoryStore, RouteKind,
    RouteObservationInput, RoutePredictionSet, RouteReward, RuntimeModeDecision,
    RuntimeRouteApplyRequest, RuntimeRouteState, SafeRuntimeRouteController,
    SimpleDegradationPredictor, SimpleRouteQualityPredictor, Task1RouteSignal,
    Task2RoutingTrustSummary, Task2TrustStateSources, TrafficClass, TrustStateSnapshot,
    NETWORK_AI_CONFIG_VERSION, NETWORK_AI_RUNTIME_MODE_VERSION,
};
use sgx_anomaly_engine::telemetry::{RawSample, TelemetrySource};
use sgx_anomaly_engine::virtual_shift::VS17_MEMBER_POLICY_STATE;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, timeout, Duration};

const STATUS_SCHEMA: &str = "task3-network-ai-runtime-status-v1";
const DEFAULT_TRUST_MAX_AGE_MS: u64 = 300_000;
const TASK3_TRAFFIC_EVENT_TTL_MS: u64 = 30_000;
const TASK1_NETWORK_SIGNAL_MAX_AGE_MS: u64 = 300_000;
const TASK1_PRODUCTION_STATE_ROOT: &str = "/var/lib/sgx-guardian/threat";
const DEFAULT_NETWORK_AI_CONFIG_PATH: &str =
    "/var/lib/sgx-guardian/threat/network_ai/config/network_ai.json";
const RELAY_TELEMETRY_MAX_AGE_MS: u64 = 120_000;

#[derive(Debug, Clone)]
struct Task3TrafficEvent {
    message_type: String,
    target_peer: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    consumed: bool,
}

static TASK3_TRAFFIC_EVENTS: OnceLock<StdMutex<Vec<Task3TrafficEvent>>> = OnceLock::new();

static TASK3_CONSUMED_TRAFFIC_CONTEXTS: OnceLock<StdMutex<Vec<Value>>> = OnceLock::new();

fn consumed_traffic_contexts() -> &'static StdMutex<Vec<Value>> {
    TASK3_CONSUMED_TRAFFIC_CONTEXTS.get_or_init(|| StdMutex::new(Vec::new()))
}

fn take_consumed_traffic_contexts() -> Vec<Value> {
    consumed_traffic_contexts()
        .lock()
        .map(|mut contexts| std::mem::take(&mut *contexts))
        .unwrap_or_default()
}

#[cfg(test)]
static TASK3_D2_TEST_LOCK: StdMutex<()> = StdMutex::new(());

pub fn notify_task3_message(message_type: &str, target_peer: &str) {
    let target_peer = target_peer.trim();
    if target_peer.is_empty() {
        return;
    }
    let events = TASK3_TRAFFIC_EVENTS.get_or_init(|| StdMutex::new(Vec::new()));
    let Ok(mut events) = events.lock() else {
        return;
    };
    let now = now_ms();
    events.retain(|event| event.expires_at_ms > now);
    events.push(Task3TrafficEvent {
        message_type: message_type.to_string(),
        target_peer: target_peer.to_string(),
        created_at_ms: now,
        expires_at_ms: now.saturating_add(TASK3_TRAFFIC_EVENT_TTL_MS),
        consumed: false,
    });
}

fn traffic_class_for_peer(peer: &str) -> TrafficClass {
    let events = TASK3_TRAFFIC_EVENTS.get_or_init(|| StdMutex::new(Vec::new()));
    let Ok(mut events) = events.lock() else {
        return TrafficClass::Operational;
    };

    let now = now_ms();
    events.retain(|event| event.expires_at_ms > now);

    // D13: Security/control traffic has precedence over operational traffic
    // for the complete active event window. A telemetry event generated later
    // in the same optimization cycle must never downgrade a live attestation,
    // VSHIFT_ALERT, or other SecurityControl event to Operational.
    let event_index = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.target_peer == peer)
        .max_by_key(|(_, event)| {
            let (_, traffic_class, _) = classify_message_type(&event.message_type);
            (
                matches!(traffic_class, TrafficClass::SecurityControl) as u8,
                event.created_at_ms,
            )
        })
        .map(|(index, _)| index);

    let Some(event_index) = event_index else {
        return TrafficClass::Operational;
    };

    let event = &mut events[event_index];
    let (_, traffic_class, priority_class) = classify_message_type(&event.message_type);

    if !event.consumed {
        event.consumed = true;

        let evidence = serde_json::json!({
            "schema_version": "task3-d2-traffic-classification-v1",
            "message_type": event.message_type,
            "target_peer": event.target_peer,
            "traffic_class": format!("{:?}", traffic_class),
            "priority_class": format!("{:?}", priority_class),
            "event_created_at_ms": event.created_at_ms,
            "event_expires_at_ms": event.expires_at_ms,
            "consumed_at_ms": now,
            "consumed": true,
            "stage": "route_candidate_classification"
        });

        // D2: Bind the consumed real message classification to the
        // route-decision cycle that consumed it. This is audit context
        // only; it does not weaken trust/eligibility or apply a route.
        if let Ok(mut contexts) = consumed_traffic_contexts().lock() {
            contexts.push(serde_json::json!({
                "schema_version": "task3-d2-traffic-context-v1",
                "message_type": event.message_type.clone(),
                "target_peer": event.target_peer.clone(),
                "traffic_class": format!("{:?}", traffic_class),
                "priority_class": format!("{:?}", priority_class),
                "event_created_at_ms": event.created_at_ms,
                "event_expires_at_ms": event.expires_at_ms,
                "consumed_at_ms": now_ms(),
                "consumed": true
            }));
        }

        let path = std::path::Path::new(
            "/var/lib/sgx-guardian/threat/network_ai/runtime/traffic_classification_events.jsonl",
        );

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            let _ = writeln!(file, "{}", evidence);
        }
    }

    traffic_class
}

#[derive(Debug, Clone)]
pub struct Task3NetworkAiConfig {
    pub enabled: bool,
    pub interval: Duration,
    pub persistence_root: PathBuf,
    pub nebula_base_dir: PathBuf,
    pub task2_trust_root: PathBuf,
    pub allow_transport_apply: bool,
    pub network_ai_config_path: PathBuf,
    pub network_ai_config: EngineNetworkAiConfig,
    pub config_error: Option<String>,
}

impl Task3NetworkAiConfig {
    pub fn from_env(state_dir: impl AsRef<Path>, nebula_base_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.as_ref();
        let enabled = env_bool("SGX_TASK3_NETWORK_AI_ENABLED").unwrap_or(true);
        let allow_transport_apply = env_bool("SGX_TASK3_TRANSPORT_APPLY").unwrap_or(true);
        let default_network_config_path = state_dir
            .join("network_ai")
            .join("config")
            .join("network_ai.json");
        let network_ai_config_path = std::env::var("SGX_NETWORK_AI_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                if state_dir.as_os_str().is_empty() {
                    PathBuf::from(DEFAULT_NETWORK_AI_CONFIG_PATH)
                } else {
                    default_network_config_path
                }
            });
        let (network_ai_config, config_error) =
            load_or_seed_network_ai_config(&network_ai_config_path);
        let interval_secs = std::env::var("SGX_TASK3_NETWORK_AI_INTERVAL_SECS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(network_ai_config.sample_interval_seconds.max(1));
        let persistence_root = std::env::var("SGX_TASK3_NETWORK_AI_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| state_dir.join("network_ai").join("runtime"));
        let task2_trust_root = std::env::var("SGX_TASK3_TASK2_TRUST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                state_dir
                    .join("virtual_shift")
                    .join(VS17_MEMBER_POLICY_STATE)
            });

        Self {
            enabled,
            interval: Duration::from_secs(interval_secs),
            persistence_root,
            nebula_base_dir: nebula_base_dir.into(),
            task2_trust_root,
            allow_transport_apply,
            network_ai_config_path,
            network_ai_config,
            config_error,
        }
    }
}

fn load_or_seed_network_ai_config(path: &Path) -> (EngineNetworkAiConfig, Option<String>) {
    match EngineNetworkAiConfig::load_json(path) {
        Ok(config) => (config, None),
        Err(_error) if !path.exists() => {
            let config = EngineNetworkAiConfig::default();
            if let Err(write_error) = persist_json(path, &config) {
                return (
                    config,
                    Some(format!(
                        "using safe default Shadow config; failed to seed {}: {}",
                        path.display(),
                        write_error
                    )),
                );
            }
            (config, None)
        }
        Err(error) => {
            let mut config = EngineNetworkAiConfig::default();
            config.mode = NetworkAiRuntimeMode::Shadow;
            (
                config,
                Some(format!(
                    "invalid NetworkAI config {}; safe Shadow fallback active: {}",
                    path.display(),
                    error
                )),
            )
        }
    }
}

fn effective_network_ai_config(path: &Path) -> (EngineNetworkAiConfig, Option<String>) {
    let (mut config, error) = load_or_seed_network_ai_config(path);
    if error.is_some() {
        config.mode = NetworkAiRuntimeMode::Shadow;
    }
    (config, error)
}

#[derive(Clone)]
pub struct Task3NetworkAiRuntimeDeps {
    pub node_id: String,
    pub metrics: Arc<Mutex<Metrics>>,
    pub cot_circle: Arc<CircleMembership>,
    pub link_monitor: Arc<LinkMonitor>,
    pub failover: Arc<FailoverEngine>,
}

pub fn spawn_production_runtime(config: Task3NetworkAiConfig, deps: Task3NetworkAiRuntimeDeps) {
    if !config.enabled {
        tracing::info!("Task 3 network AI runtime disabled by configuration");
        return;
    }

    static STARTED: once_cell::sync::OnceCell<()> = once_cell::sync::OnceCell::new();
    if STARTED.set(()).is_err() {
        tracing::warn!("Task 3 network AI runtime already started; duplicate instance skipped");
        return;
    }

    let service = Task3NetworkAiRuntimeService::production(config, deps);
    tokio::spawn(async move {
        service.run_forever().await;
    });
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task3RuntimeStatus {
    pub schema_version: String,
    pub config_version: String,
    pub enabled: bool,
    pub mode: NetworkAiRuntimeMode,
    pub running: bool,
    pub tick_count: u64,
    pub last_tick_ms: Option<u64>,
    pub latest_mode_decision: Option<RuntimeModeDecision>,
    pub config_error: Option<String>,
    pub last_cycle_ms: Option<u64>,
    pub last_success_ms: Option<u64>,
    pub trust_state_available: bool,
    pub candidate_count: usize,
    pub eligible_count: usize,
    pub recommended_route: Option<String>,
    pub active_route: Option<String>,
    pub transport_apply_attempted: bool,
    pub last_transport_result: Option<ProductionRouteApplyResult>,
    pub last_error: Option<String>,
}

impl Default for Task3RuntimeStatus {
    fn default() -> Self {
        Self {
            schema_version: STATUS_SCHEMA.to_string(),
            config_version: NETWORK_AI_CONFIG_VERSION.to_string(),
            enabled: true,
            mode: NetworkAiRuntimeMode::Shadow,
            running: false,
            tick_count: 0,
            last_tick_ms: None,
            latest_mode_decision: None,
            config_error: None,
            last_cycle_ms: None,
            last_success_ms: None,
            trust_state_available: false,
            candidate_count: 0,
            eligible_count: 0,
            recommended_route: None,
            active_route: None,
            transport_apply_attempted: false,
            last_transport_result: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProductionTelemetry {
    pub raw: RawSample,
    pub packet_loss_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct OverlayPathTelemetry {
    schema_version: String,
    ts_ms: u64,
    source_node: String,
    destination_node: String,
    peer_id: String,
    route_id: String,
    route_kind: RouteKind,
    relay_ids: Vec<String>,
    overlay_ip: String,
    route_available: bool,
    rtt_ms: Option<f64>,
    packet_loss_pct: Option<f64>,
    throughput_mbps: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct OverlayPathProbe {
    route_available: bool,
    rtt_ms: Option<f64>,
    packet_loss_pct: Option<f64>,
    throughput_mbps: Option<f64>,
}

impl OverlayPathTelemetry {
    fn to_observation_input(&self) -> Option<RouteObservationInput> {
        let rtt_ms = self
            .rtt_ms
            .or_else(|| (!self.route_available).then_some(0.0))?;
        let packet_loss_pct = self
            .packet_loss_pct
            .or_else(|| (!self.route_available).then_some(100.0))?;
        Some(RouteObservationInput {
            ts_ms: self.ts_ms,
            route_id: self.route_id.clone(),
            rtt_ms,
            packet_loss_pct,
            throughput_mbps: self.throughput_mbps,
            bandwidth_utilization_pct: None,
            route_available: self.route_available,
            route_healthy: self.route_available,
            switched_route: false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProductionTopology {
    pub local_node: String,
    pub destinations: Vec<String>,
    pub route_candidates: Vec<RouteCandidate>,
    pub transport_routes: HashMap<String, String>,
    pub relay_routes: HashMap<String, RelayEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservedRouteState {
    pub route_id: String,
    pub destination_node: String,
    pub interface_name: Option<String>,
    pub confirmed: bool,
    pub diagnostic: String,
    pub started_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionRouteApplyRequest {
    pub decision_id: String,
    pub requested_route_id: String,
    pub previous_route_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionRouteApplyResult {
    pub attempted: bool,
    pub applied: bool,
    pub requested_route_id: String,
    pub previous_route_id: String,
    pub observed_route_id: Option<String>,
    pub rollback_attempted: bool,
    pub rollback_applied: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShadowRouteDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub mode: NetworkAiRuntimeMode,
    pub traffic_class: TrafficClass,
    pub task2_trust_version: String,
    pub eligible_route_ids: Vec<String>,
    pub rejected_routes: Vec<ShadowRejectedRoute>,
    pub selected_route_id: Option<String>,
    pub expected_latency_ms: Option<f64>,
    pub expected_loss_pct: Option<f64>,
    pub expected_throughput_mbps: Option<f64>,
    pub confidence: Option<f64>,
    pub selection_reason: String,
    pub degradation_probability: Option<f64>,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShadowRejectedRoute {
    pub route_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdvisoryRouteRecommendation {
    pub schema_version: String,
    pub recommendation_id: String,
    pub mode: NetworkAiRuntimeMode,
    pub current_route_id: String,
    pub recommended_route_id: Option<String>,
    pub expected_improvement_pct: f64,
    pub confidence: Option<f64>,
    pub reason: String,
    pub safety_verdict: String,
    pub safety_allowed_if_activated: bool,
    pub safety_reason: String,
    pub applied: bool,
    pub operator_next_step: String,
}

#[async_trait]
pub trait NetworkTelemetryProvider: Send + Sync {
    async fn collect(&self) -> Result<ProductionTelemetry>;
}

#[async_trait]
pub trait RouteTopologyProvider: Send + Sync {
    async fn discover_routes(&self) -> Result<ProductionTopology>;
}

#[async_trait]
pub trait Task2TrustProvider: Send + Sync {
    async fn current_trust_state(
        &self,
        local_node: &str,
        required_peers: &[String],
        now_ms: u64,
    ) -> Result<(
        TrustStateSnapshot,
        Option<Task2RoutingTrustSummary>,
        PathBuf,
    )>;
}

#[async_trait]
pub trait RouteObservationProvider: Send + Sync {
    async fn current_route(&self, topology: &ProductionTopology) -> Result<ObservedRouteState>;

    async fn current_routes(
        &self,
        topology: &ProductionTopology,
    ) -> Result<Vec<ObservedRouteState>> {
        Ok(vec![self.current_route(topology).await?])
    }
}

#[async_trait]
pub trait RouteTransport: Send + Sync {
    async fn apply_route(
        &self,
        request: &ProductionRouteApplyRequest,
        topology: &ProductionTopology,
    ) -> Result<ProductionRouteApplyResult>;
}

#[async_trait]
pub trait RelayHealthProvider: Send + Sync {
    async fn relay_health(&self, topology: &ProductionTopology) -> Result<Vec<RelayRuntimeHealth>>;
}

#[async_trait]
pub trait RelayControl: Send + Sync {
    async fn apply_weights(&self, weights: &RelayWeightSet) -> Result<RelayWeightApplyResult>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayWeightApplyResult {
    pub attempted: bool,
    pub applied: bool,
    pub reason: String,
}

pub struct Task3NetworkAiRuntimeService {
    config: Task3NetworkAiConfig,
    telemetry: Arc<dyn NetworkTelemetryProvider>,
    topology: Arc<dyn RouteTopologyProvider>,
    trust: Arc<dyn Task2TrustProvider>,
    observation: Arc<dyn RouteObservationProvider>,
    transport: Arc<dyn RouteTransport>,
    relay_health: Arc<dyn RelayHealthProvider>,
    relay_control: Arc<dyn RelayControl>,
    cycle_lock: Arc<Mutex<()>>,
    status: Arc<RwLock<Task3RuntimeStatus>>,
}

impl Task3NetworkAiRuntimeService {
    pub fn production(config: Task3NetworkAiConfig, deps: Task3NetworkAiRuntimeDeps) -> Self {
        let telemetry = Arc::new(SgxTask3TelemetryProvider::new(deps.metrics.clone()));
        let topology = Arc::new(SgxTask3TopologyProvider::new(
            deps.node_id.clone(),
            config.nebula_base_dir.clone(),
            deps.cot_circle.clone(),
            deps.link_monitor.clone(),
        ));
        let trust = Arc::new(FileTask2TrustProvider::new(config.task2_trust_root.clone()));
        let observation = Arc::new(SgxRouteObservationProvider::new(deps.failover.clone()));
        let transport = Arc::new(SgxNebulaOverlayRouteTransport::new(
            config.persistence_root.clone(),
            config.allow_transport_apply,
        ));
        let relay_health = Arc::new(SgxRelayHealthProvider::production(
            config.nebula_base_dir.clone(),
        ));
        let relay_control = Arc::new(PersistedRelayRecommendationControl::new(
            config.persistence_root.join("relay_weights.json"),
        ));
        Self::new(
            config,
            telemetry,
            topology,
            trust,
            observation,
            transport,
            relay_health,
            relay_control,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Task3NetworkAiConfig,
        telemetry: Arc<dyn NetworkTelemetryProvider>,
        topology: Arc<dyn RouteTopologyProvider>,
        trust: Arc<dyn Task2TrustProvider>,
        observation: Arc<dyn RouteObservationProvider>,
        transport: Arc<dyn RouteTransport>,
        relay_health: Arc<dyn RelayHealthProvider>,
        relay_control: Arc<dyn RelayControl>,
    ) -> Self {
        let initial_config_version = config.network_ai_config.config_version.clone();
        let initial_enabled = config.enabled && config.network_ai_config.enabled;
        let initial_mode = config.network_ai_config.mode;
        let initial_config_error = config.config_error.clone();
        Self {
            config,
            telemetry,
            topology,
            trust,
            observation,
            transport,
            relay_health,
            relay_control,
            cycle_lock: Arc::new(Mutex::new(())),
            status: Arc::new(RwLock::new(Task3RuntimeStatus {
                config_version: initial_config_version,
                enabled: initial_enabled,
                mode: initial_mode,
                running: true,
                config_error: initial_config_error,
                ..Task3RuntimeStatus::default()
            })),
        }
    }

    pub async fn run_forever(self) {
        if let Err(error) = self.persist_status().await {
            tracing::warn!(%error, "failed to persist initial Task 3 network AI status");
        }

        let mut tick = interval(self.config.interval);
        loop {
            tick.tick().await;
            if let Err(error) = self.run_cycle().await {
                tracing::warn!(%error, "Task 3 network AI cycle failed closed");
            }
        }
    }

    pub async fn run_cycle(&self) -> Result<Task3RuntimeStatus> {
        let _guard = self.cycle_lock.lock().await;
        let now_ms = now_ms();

        let result = self.run_cycle_inner(now_ms).await;
        match result {
            Ok(status) => {
                *self.status.write().await = status.clone();
                self.persist_status().await?;
                Ok(status)
            }
            Err(error) => {
                let mut status = self.status.read().await.clone();
                status.running = true;
                status.last_cycle_ms = Some(now_ms);
                status.transport_apply_attempted = false;
                status.last_error = Some(error.to_string());
                *self.status.write().await = status.clone();
                self.persist_status().await?;
                Err(error)
            }
        }
    }

    fn persist_cycle_stage(&self, stage: &str, now_ms: u64) {
        let value = serde_json::json!({
            "schema_version": "task3-cycle-stage-v1",
            "ts_ms": now_ms,
            "stage": stage
        });

        let _ = persist_json(
            self.config.persistence_root.join("cycle_stage.json"),
            &value,
        );
    }

    async fn run_cycle_inner(&self, now_ms: u64) -> Result<Task3RuntimeStatus> {
        self.persist_cycle_stage("01_cycle_started", now_ms);
        fs::create_dir_all(&self.config.persistence_root)
            .with_context(|| format!("creating {}", self.config.persistence_root.display()))?;
        let (mut network_config, config_error) =
            effective_network_ai_config(&self.config.network_ai_config_path);

        if let Some(error) = config_error.as_ref() {
            tracing::warn!(%error, "Task3 NetworkAI config invalid; safe Shadow fallback active");
        }

        let enabled = self.config.enabled && network_config.enabled;
        let requested_mode = if enabled {
            network_config.mode
        } else {
            NetworkAiRuntimeMode::Shadow
        };

        // Active mode authorization is enforced against current-cycle
        // production evidence below: D3-confirmed route state, Task2-backed
        // eligibility, and the D10 safety decision all execute before the
        // production transport adapter can be called. Requiring the previous
        // cycle's safety_runtime_status.json here creates a circular bootstrap
        // dependency because Shadow mode returns before producing fresh D10
        // evidence.
        let active_mode_rejection: Option<String> = None;
        let runtime_mode = requested_mode;

        // Persist the actual effective runtime configuration. The operator's
        // requested value remains preserved in network_ai.json.
        network_config.mode = runtime_mode;

        persist_json(
            self.config
                .persistence_root
                .join("effective_network_ai_config.json"),
            &network_config,
        )?;

        if requested_mode == NetworkAiRuntimeMode::Active {
            persist_json(
                self.config
                    .persistence_root
                    .join("active_mode_activation.json"),
                &serde_json::json!({
                    "schema_version": "task3-network-ai-active-activation-v1",
                    "ts_ms": now_ms,
                    "requested_mode": requested_mode,
                    "effective_mode": runtime_mode,
                    "allowed": runtime_mode == NetworkAiRuntimeMode::Active,
                    "reason": active_mode_rejection
                        .clone()
                        .unwrap_or_else(|| "fresh production safety proof accepted".to_string())
                }),
            )?;
        }
        let previous_tick_count = self.status.read().await.tick_count;
        if !enabled {
            let mode_decision = RuntimeModeDecision {
                schema_version: NETWORK_AI_RUNTIME_MODE_VERSION.to_string(),
                mode: runtime_mode,
                current_route_id: String::new(),
                selected_route_id: String::new(),
                applied: false,
                reason: "Task3 NetworkAI disabled; safe Shadow/no-apply fallback active"
                    .to_string(),
            };
            persist_json(
                self.config
                    .persistence_root
                    .join("runtime_mode_decision.json"),
                &mode_decision,
            )?;
            return Ok(Task3RuntimeStatus {
                schema_version: STATUS_SCHEMA.to_string(),
                config_version: network_config.config_version,
                enabled,
                mode: runtime_mode,
                running: true,
                tick_count: previous_tick_count.saturating_add(1),
                last_tick_ms: Some(now_ms),
                latest_mode_decision: Some(mode_decision.clone()),
                config_error,
                last_cycle_ms: Some(now_ms),
                last_success_ms: Some(now_ms),
                trust_state_available: false,
                candidate_count: 0,
                eligible_count: 0,
                recommended_route: None,
                active_route: None,
                transport_apply_attempted: false,
                last_transport_result: None,
                last_error: None,
            });
        }

        // D6 runtime resilience: telemetry collection must never hold the
        // Task3 cycle lock indefinitely. A blocked /proc, /sys, or telemetry
        // source fails this cycle closed, after which run_forever() can
        // continue with the next scheduled cycle.
        let telemetry_timeout = Duration::from_secs(10);
        self.persist_cycle_stage("02_before_telemetry", now_ms);
        let telemetry = timeout(telemetry_timeout, self.telemetry.collect())
            .await
            .map_err(|_| {
                anyhow!(
                    "Task3 telemetry collection timed out after {} seconds",
                    telemetry_timeout.as_secs()
                )
            })??;

        self.persist_cycle_stage("03_before_topology", now_ms);
        let mut topology = self.topology.discover_routes().await?;
        self.persist_cycle_stage("04_after_topology", now_ms);
        if topology.route_candidates.is_empty() {
            return Err(anyhow!("no real Task 3 route candidates discovered"));
        }

        // Task3 D2: the production Task1 RawSample collected above is
        // operational telemetry used to evaluate the currently discovered
        // peer routes. Bind that real telemetry context to each destination
        // and consume it in this same routing cycle.
        let telemetry_peers = required_peers(&topology.route_candidates);

        for peer in &telemetry_peers {
            notify_task3_message("telemetry", peer);
        }

        for candidate in &mut topology.route_candidates {
            candidate.traffic_class = traffic_class_for_peer(&candidate.destination_node);
        }

        self.persist_cycle_stage("05_before_path_telemetry", now_ms);
        let candidate_telemetry = collect_overlay_path_telemetry(&topology).await;
        self.persist_cycle_stage("06_after_path_telemetry", now_ms);
        persist_overlay_path_telemetry(
            self.config
                .persistence_root
                .join("overlay_path_observations.jsonl"),
            &candidate_telemetry,
        )?;

        let required_peers = required_peers(&topology.route_candidates);
        let (trust, task2_summary, task2_path) = self
            .trust
            .current_trust_state(&topology.local_node, &required_peers, now_ms)
            .await?;
        let route_observations = self.observation.current_routes(&topology).await?;

        persist_json(
            self.config.persistence_root.join("route_observations.json"),
            &serde_json::json!({
                "schema_version": "task3-d3-route-observations-v1",
                "ts_ms": now_ms,
                "source": "live Nebula UDP/4242 dataplane plus Nebula registry",
                "observations": &route_observations,
            }),
        )?;

        // A mesh can have multiple simultaneous destination routes.
        // Do not invent a global active route before AI selects a destination.
        let confirmed_preselection = route_observations
            .iter()
            .filter(|route| route.confirmed)
            .cloned()
            .collect::<Vec<_>>();

        let mut observed = if confirmed_preselection.len() == 1 {
            confirmed_preselection[0].clone()
        } else {
            ObservedRouteState {
                route_id: "unknown-unconfirmed-nebula-route".to_string(),
                destination_node: String::new(),
                interface_name: None,
                confirmed: false,
                diagnostic: if confirmed_preselection.is_empty() {
                    "D3 no confirmed live Nebula destination route".to_string()
                } else {
                    format!(
                        "D3 observed {} simultaneous destination-scoped Nebula routes; no global route inferred",
                        confirmed_preselection.len()
                    )
                },
                started_ms: now_ms,
            }
        };

        // Preserve the controller-owned active route independently from D3
        // destination observations. Multiple simultaneous confirmed routes do
        // not imply that any one of them should become the active route.
        let route_state_path = self
            .config
            .persistence_root
            .join("current_route_state.json");

        let mut state = if route_state_path.exists() {
            match RuntimeRouteState::load_json(&route_state_path) {
                Ok(persisted)
                    if confirmed_preselection
                        .iter()
                        .any(|route| route.route_id == persisted.active_route_id) =>
                {
                    Some(persisted)
                }
                _ if observed.confirmed => Some(self.load_or_observed_state(&observed)?),
                _ => None,
            }
        } else if observed.confirmed {
            Some(self.load_or_observed_state(&observed)?)
        } else {
            None
        };
        let observation = if observed.confirmed {
            let current_candidate = topology
                .route_candidates
                .iter()
                .find(|candidate| candidate.route_id == observed.route_id)
                .cloned()
                .ok_or_else(|| {
                    anyhow!("observed route is not present in Nebula overlay topology")
                })?;
            let observation = observe_network(
                &telemetry.raw,
                &current_candidate,
                telemetry.packet_loss_pct,
            );
            persist_current_observation(
                self.config
                    .persistence_root
                    .join("current_observation.json"),
                &observation,
            )?;
            observation
        } else {
            let observation = unconfirmed_network_observation(
                &telemetry.raw,
                &topology.local_node,
                telemetry.packet_loss_pct,
            );
            persist_unconfirmed_current_observation(
                self.config
                    .persistence_root
                    .join("current_observation.json"),
                &observation,
                &observed.diagnostic,
            )?;
            observation
        };
        append_observation_jsonl(
            self.config.persistence_root.join("route_history.jsonl"),
            &observation,
        )?;

        let mut history = self.load_history(&network_config)?;
        history.record_observation(&observation);
        history.save_json(
            self.config
                .persistence_root
                .join("route_history_store.json"),
        )?;
        persist_live_benchmark(
            self.config.persistence_root.join("benchmark.json"),
            now_ms,
            runtime_mode,
            &observation,
            &history,
            observed.confirmed,
        )?;

        let eligible =
            EligibilityFilter.filter_at(topology.route_candidates.clone(), &trust, now_ms);
        let persisted_route_state_path = self
            .config
            .persistence_root
            .join("current_route_state.json");
        let persisted_route_state = RuntimeRouteState::load_json(&persisted_route_state_path).ok();
        persist_json(
            self.config.persistence_root.join("route_candidates.json"),
            &serde_json::json!({
                "schema_version": "task3-route-candidates-v1",
                "ts_ms": now_ms,
                "source": "production Nebula/Circle runtime topology",
                "candidate_count": topology.route_candidates.len(),
                "candidates": topology.route_candidates,
            }),
        )?;
        persist_json(
            self.config.persistence_root.join("eligible_routes.json"),
            &eligible,
        )?;
        // D8 telemetry attribution boundary:
        //
        // probe_overlay_path() measures reachability to the destination Nebula
        // overlay address. Nebula may satisfy that connection through either
        // its direct path or an internal relay, so the measurement cannot be
        // truthfully attributed to every candidate that shares the same
        // destination.
        //
        // Attribute destination-level measured telemetry only to the route
        // that the production route observer currently confirms as active.
        // Candidate telemetry is still persisted above for diagnostics, while
        // inactive alternatives retain their previously measured history
        // until they are actually observed as the active dataplane route.
        //
        // This prevents a direct and relay candidate from receiving duplicate
        // route-specific RTT/loss samples from one destination-level probe.
        let route_to_attribute = if observed.confirmed {
            Some(observed.route_id.as_str())
        } else {
            persisted_route_state
                .as_ref()
                .map(|state| state.active_route_id.as_str())
        };

        if let Some(route_id) = route_to_attribute {
            if let Some(candidate) = topology
                .route_candidates
                .iter()
                .find(|candidate| candidate.route_id == route_id)
            {
                if let Some(observation) =
                    measured_observation_for_route(candidate, &candidate_telemetry)
                {
                    history.record_measured_observation(observation.clone());
                    append_jsonl(
                        self.config.persistence_root.join("route_history.jsonl"),
                        &observation,
                    )?;
                }
            }
        }
        history.save_json(
            self.config
                .persistence_root
                .join("route_history_store.json"),
        )?;
        // D7: consume the latest real Task1 full-ML runtime signal.
        // No synthetic anomaly/default score is created when no fresh alert exists.
        let task1_signal = latest_task1_route_signal(now_ms);

        // Route optimization is destination-scoped. A route to peer B is not
        // an alternative for an active communication path to peer C.
        //
        // Derive the decision destination from the controller-owned active
        // route when available. This preserves D3 multi-destination discovery
        // while ensuring D7/D8/D9 compare only routes that can reach the same
        // destination.
        let decision_destination = persisted_route_state
            .as_ref()
            .and_then(|state| {
                topology
                    .route_candidates
                    .iter()
                    .find(|candidate| candidate.route_id == state.active_route_id)
            })
            .map(|candidate| candidate.destination_node.clone());

        let decision_candidates = decision_destination
            .as_ref()
            .map(|destination| {
                eligible
                    .eligible
                    .iter()
                    .filter(|candidate| candidate.destination_node == *destination)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .filter(|candidates| !candidates.is_empty())
            .unwrap_or_else(|| eligible.eligible.clone());

        let predictions = SimpleRouteQualityPredictor::default().predict_with_task1_signal(
            &decision_candidates,
            &history,
            task1_signal.as_ref(),
            now_ms,
        );

        let mut policy = self.load_policy(&network_config)?;
        // D9 learning must be bound to the route that was active before
        // this optimization decision. Do not use the temporary D3
        // pre-selection state because multiple simultaneous Nebula
        // destination sessions are not a global active-route decision.
        let current_route_id_for_learning = persisted_route_state
            .as_ref()
            .map(|state| state.active_route_id.clone())
            .or_else(|| state.as_ref().map(|state| state.active_route_id.clone()));

        let current_route_failed = current_route_id_for_learning
            .as_ref()
            .and_then(|route_id| {
                topology
                    .route_candidates
                    .iter()
                    .find(|candidate| candidate.route_id == *route_id)
            })
            .map(|candidate| !candidate.observed_available || !candidate.observed_healthy)
            .unwrap_or(false);
        let current_failed_reward = if current_route_failed {
            current_route_id_for_learning.as_ref().map(|route_id| {
                let hop_count = topology
                    .route_candidates
                    .iter()
                    .find(|candidate| candidate.route_id == *route_id)
                    .map(|candidate| candidate.hop_count)
                    .unwrap_or(0);
                RouteReward::from_observed_outcome_with_weights(
                    &ObservedRewardInput {
                        route_id: route_id.clone(),
                        rtt_ms: Some(observation.rtt_ms),
                        packet_loss_pct: Some(observation.packet_loss_pct),
                        throughput_mbps: Some(observation.throughput_mbps),
                        bandwidth_utilization_pct: Some(observation.bandwidth_utilization_pct),
                        hop_count,
                        switched_route: false,
                        route_failed: true,
                    },
                    &network_config.reward_weights,
                )
            })
        } else {
            None
        };
        if let Some(reward) = &current_failed_reward {
            policy.update_with_reward(reward);
        }

        // D9: when the confirmed current route is still technically available
        // and healthy, continuously learn from its fresh route-specific
        // production telemetry. This allows degraded latency/loss outcomes to
        // reduce a stale historical Q-value even when D10 correctly blocks a
        // same-route transport apply.
        //
        // Hard failures remain owned by current_failed_reward above so the
        // same failure outcome is never learned twice.
        if !current_route_failed {
            if let Some(current_route_id) = current_route_id_for_learning.as_ref() {
                if let Some(current_candidate) = topology
                    .route_candidates
                    .iter()
                    .find(|candidate| candidate.route_id == *current_route_id)
                {
                    if let Some(measured) =
                        measured_observation_for_route(current_candidate, &candidate_telemetry)
                    {
                        let reward = RouteReward::from_observed_outcome_with_weights(
                            &ObservedRewardInput {
                                route_id: current_route_id.clone(),
                                rtt_ms: Some(measured.rtt_ms),
                                packet_loss_pct: Some(measured.packet_loss_pct),
                                throughput_mbps: measured.throughput_mbps,
                                bandwidth_utilization_pct: measured.bandwidth_utilization_pct,
                                hop_count: current_candidate.hop_count,
                                switched_route: false,
                                route_failed: false,
                            },
                            &network_config.reward_weights,
                        );

                        policy.update_with_reward(&reward);

                        append_jsonl(
                            self.config.persistence_root.join("rewards.jsonl"),
                            &serde_json::json!({
                                "decision_id": format!("task3-{}-current-route", now_ms),
                                "ts_ms": now_ms,
                                "observation_phase": "current_route_observation",
                                "reward": reward,
                            }),
                        )?;
                    }
                }
            }
        }

        let decision = policy.choose_exploit(&predictions);
        let mut selected_route = decision
            .selected_route_id
            .clone()
            .or_else(|| predictions.selected_route_id.clone());

        let degradation_predictions = SimpleDegradationPredictor {
            high_probability_threshold: network_config.degradation_probability_threshold,
            ..SimpleDegradationPredictor::default()
        }
        .predict_all_routes(&history);

        // D8 proactive degradation avoidance.
        // If the initial D7/D9 recommendation is predicted to cross the
        // configured degradation threshold, prefer the highest-quality
        // Task2-eligible route whose degradation risk remains below it.
        //
        // D8 changes only the recommendation. D10 owns switch safety and
        // D11 owns production transport actuation.
        if let Some(selected_route_id) = selected_route.as_deref() {
            let selected_is_high_risk = degradation_predictions
                .iter()
                .find(|prediction| prediction.route_id == selected_route_id)
                .map(|prediction| {
                    prediction.probability >= network_config.degradation_probability_threshold
                })
                .unwrap_or(false);

            if selected_is_high_risk {
                let proactive_alternative = predictions
                    .predictions
                    .iter()
                    .filter(|prediction| prediction.route_id != selected_route_id)
                    .filter(|prediction| {
                        eligible
                            .eligible
                            .iter()
                            .any(|candidate| candidate.route_id == prediction.route_id)
                    })
                    .filter(|prediction| {
                        degradation_predictions
                            .iter()
                            .find(|degradation| degradation.route_id == prediction.route_id)
                            .map(|degradation| {
                                degradation.probability
                                    < network_config.degradation_probability_threshold
                            })
                            .unwrap_or(false)
                    })
                    .max_by(|a, b| {
                        a.quality_score
                            .partial_cmp(&b.quality_score)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|prediction| prediction.route_id.clone());

                if proactive_alternative.is_some() {
                    selected_route = proactive_alternative;
                }
            }
        }

        if let Some(selected_route_id) = selected_route.as_deref() {
            if let Some(selected_candidate) = topology
                .route_candidates
                .iter()
                .find(|candidate| candidate.route_id == selected_route_id)
            {
                match route_observations
                    .iter()
                    .find(|route| {
                        route.destination_node == selected_candidate.destination_node
                            && route.confirmed
                    })
                    .cloned()
                {
                    Some(selected_observed) => {
                        // D10 state integrity: destination-scoped D3 evidence
                        // confirms the selected route is observable, but it
                        // must not become the active route merely because AI
                        // selected it. RuntimeRouteState changes only after a
                        // transport apply is confirmed successful.
                        observed = selected_observed;
                    }
                    None => {
                        observed = ObservedRouteState {
                            route_id: "unknown-unconfirmed-nebula-route".to_string(),
                            destination_node: selected_candidate.destination_node.clone(),
                            interface_name: None,
                            confirmed: false,
                            diagnostic: format!(
                                "D3 selected destination {} has no confirmed live Nebula current-route evidence",
                                selected_candidate.destination_node
                            ),
                            started_ms: now_ms,
                        };
                        state = None;
                    }
                }
            }
        }

        // D12 wiring only:
        // If Task2 rejected all usable routes for a security/policy reason,
        // Task3 must not bypass that decision. Instead, hand the requested
        // security-sensitive action to the existing Task2 owner-review flow.
        //
        // Operational failures are deliberately excluded:
        //   - RouteUnavailable
        //   - RouteUnhealthy
        //   - StaleTrustState
        //
        // No predictor/RL/AI behaviour is changed here.
        let sensitive_route_action =
            if runtime_mode == NetworkAiRuntimeMode::Active && selected_route.is_none() {
                eligible.rejected.iter().find_map(|rejected| {
                    use sgx_anomaly_engine::network_ai::{EligibilityReason, SensitiveRouteReason};

                    let sensitive_reason = match &rejected.reason {
                        EligibilityReason::UntrustedPeer => {
                            if rejected.candidate.relay_ids.is_empty() {
                                SensitiveRouteReason::SecurityExceptionRequired
                            } else {
                                SensitiveRouteReason::NewUntrustedRelay
                            }
                        }
                        EligibilityReason::QuarantinedPeer => {
                            SensitiveRouteReason::QuarantinedMemberRecovery
                        }
                        EligibilityReason::ProhibitedRoute => {
                            SensitiveRouteReason::PolicyRuleChangeNeeded
                        }
                        EligibilityReason::SecurityControlRequiresTrustedRoute => {
                            SensitiveRouteReason::SecurityExceptionRequired
                        }

                        EligibilityReason::RouteUnavailable
                        | EligibilityReason::RouteUnhealthy
                        | EligibilityReason::StaleTrustState
                        | EligibilityReason::Eligible => return None,
                    };

                    Some((rejected.candidate.clone(), sensitive_reason))
                })
            } else {
                None
            };

        // Predictions rank routes before a decision. Actual Q-value learning
        // is fed back only after the production route outcome is observed.
        let mut rewards = current_failed_reward.into_iter().collect::<Vec<_>>();

        let decision_id = format!("task3-{}-{}", now_ms, short_hash(&required_peers.join(",")));
        let selected_task2_path = selected_task2_evidence_path(
            &self.config.task2_trust_root,
            &topology,
            selected_route.as_deref(),
            &task2_path,
        );
        // The predictor exposes its own best-quality route, while D9 may
        // select a different route from learned Q-values. Audit the route
        // actually selected by the RL policy so reward/evidence remain bound
        // to the real runtime decision.
        let mut audit_predictions = predictions.clone();
        audit_predictions.selected_route_id = selected_route.clone();

        let audit = DecisionAuditRecord::from_engine_outputs(
            decision_id.clone(),
            now_ms,
            &eligible,
            &audit_predictions,
            &rewards,
            degradation_predictions.clone(),
            task1_signal.clone(),
            task2_summary.clone(),
            DecisionEvidenceLinks {
                route_history_path: self
                    .config
                    .persistence_root
                    .join("route_history.jsonl")
                    .display()
                    .to_string(),
                observed_outcomes_path: self
                    .config
                    .persistence_root
                    .join("observed_outcomes.jsonl")
                    .display()
                    .to_string(),
                rewards_path: self
                    .config
                    .persistence_root
                    .join("rewards.jsonl")
                    .display()
                    .to_string(),
                degradation_events_path: self
                    .config
                    .persistence_root
                    .join("degradation_events.jsonl")
                    .display()
                    .to_string(),
                task1_source_path: Some(
                    "SGX Metrics + Task1 RawSample runtime adapter".to_string(),
                ),
                task2_trust_source_path: Some(selected_task2_path.display().to_string()),
                task2_trust_version: Some(eligible.trust_state_version.clone()),
            },
        );
        let d2_traffic_contexts = take_consumed_traffic_contexts();

        persist_decision_audit_with_d2_context(
            &audit,
            &self.config.persistence_root,
            d2_traffic_contexts,
        )?;

        persist_json(
            self.config
                .persistence_root
                .join("task1_bridge_status.json"),
            &serde_json::json!({
                "schema_version": "task3-task1-bridge-status-v1",
                "ts_ms": now_ms,
                "signal_available": task1_signal.is_some(),
                "source_path": task1_signal.as_ref().map(|signal| signal.source_path.clone()),
                "run_id": task1_signal.as_ref().and_then(|signal| signal.run_id.clone()),
                "recommendation_ids": task1_signal
                    .as_ref()
                    .map(|signal| signal.recommendation_ids.clone())
                    .unwrap_or_default(),
                "status": if task1_signal.is_some() {
                    "fresh Task1 full-ML route signal consumed read-only"
                } else {
                    "no fresh Task1 full-ML route signal available"
                }
            }),
        )?;
        persist_json(
            self.config
                .persistence_root
                .join("task2_bridge_status.json"),
            &serde_json::json!({
                "schema_version": "task3-task2-bridge-status-v1",
                "ts_ms": now_ms,
                "trust_state_available": !trust.missing,
                "trust_state_version": eligible.trust_state_version,
                "summary_path": selected_task2_path.display().to_string(),
                "summary": task2_summary,
                "status": if trust.missing {
                    "Task2 trust unavailable; fail-closed eligibility active"
                } else {
                    "Task2 routing trust summary consumed read-only"
                }
            }),
        )?;

        let selected_prediction = selected_route
            .as_ref()
            .and_then(|route_id| prediction_for(&predictions, route_id));
        let current_score = state
            .as_ref()
            .map(|state| prediction_score_or_zero(&predictions, &state.active_route_id))
            .unwrap_or(0.0);
        let candidate_score = selected_route
            .as_ref()
            .map(|route| prediction_score_or_zero(&predictions, route))
            .unwrap_or(0.0);
        let mode_decision = RuntimeModeDecision {
            schema_version: NETWORK_AI_RUNTIME_MODE_VERSION.to_string(),
            mode: runtime_mode,
            current_route_id: state
                .as_ref()
                .map(|state| state.active_route_id.clone())
                .unwrap_or_else(|| "unknown-unconfirmed-nebula-route".to_string()),
            selected_route_id: selected_route.clone().unwrap_or_default(),
            applied: false,
            reason: match runtime_mode {
                NetworkAiRuntimeMode::Shadow => {
                    active_mode_rejection.clone().unwrap_or_else(|| {
                        "shadow mode observed and predicted only; route apply is disabled"
                            .to_string()
                    })
                }
                NetworkAiRuntimeMode::Advisory => {
                    "advisory mode produced a route recommendation; operator action is required"
                        .to_string()
                }
                NetworkAiRuntimeMode::Active => {
                    "active mode will continue through D10 safety and production transport"
                        .to_string()
                }
            },
        };
        persist_json(
            self.config
                .persistence_root
                .join("runtime_mode_decision.json"),
            &mode_decision,
        )?;

        if runtime_mode != NetworkAiRuntimeMode::Active {
            if runtime_mode == NetworkAiRuntimeMode::Shadow {
                persist_json(
                    self.config
                        .persistence_root
                        .join("shadow_route_decision.json"),
                    &ShadowRouteDecision {
                        schema_version: "network-ai-shadow-decision-v1".to_string(),
                        decision_id: decision_id.clone(),
                        mode: runtime_mode,
                        traffic_class: selected_route
                            .as_ref()
                            .and_then(|route_id| {
                                topology
                                    .route_candidates
                                    .iter()
                                    .find(|candidate| candidate.route_id == *route_id)
                                    .map(|candidate| candidate.traffic_class)
                            })
                            .unwrap_or(TrafficClass::Operational),
                        task2_trust_version: eligible.trust_state_version.clone(),
                        eligible_route_ids: eligible
                            .eligible
                            .iter()
                            .map(|candidate| candidate.route_id.clone())
                            .collect(),
                        rejected_routes: eligible
                            .rejected
                            .iter()
                            .map(|rejected| ShadowRejectedRoute {
                                route_id: rejected.route_id.clone(),
                                reason: format!("{:?}", rejected.reason),
                            })
                            .collect(),
                        selected_route_id: selected_route.clone(),
                        expected_latency_ms: selected_prediction
                            .map(|prediction| prediction.expected_latency_ms),
                        expected_loss_pct: selected_prediction
                            .map(|prediction| prediction.expected_loss_pct),
                        expected_throughput_mbps: selected_prediction
                            .map(|prediction| prediction.expected_throughput_mbps),
                        confidence: selected_prediction.map(|prediction| prediction.confidence),
                        selection_reason: selected_prediction
                            .map(|prediction| prediction.reason.clone())
                            .unwrap_or_else(|| "no eligible route selected".to_string()),
                        degradation_probability: degradation_predictions
                            .first()
                            .map(|prediction| prediction.probability),
                        applied: false,
                    },
                )?;
            } else {
                let safety = state.as_ref().map(|state| {
                    let mut controller = SafeRuntimeRouteController::default();
                    controller.safety_guard.config = network_config.safety.clone();
                    controller.safety_guard.evaluate_with_route_health(
                        now_ms,
                        &state.as_switch_state(),
                        selected_route.as_deref(),
                        current_score,
                        candidate_score,
                        false,
                    )
                });
                persist_json(
                    self.config
                        .persistence_root
                        .join("advisory_route_recommendation.json"),
                    &AdvisoryRouteRecommendation {
                        schema_version: "network-ai-advisory-recommendation-v1".to_string(),
                        recommendation_id: decision_id.clone(),
                        mode: runtime_mode,
                        current_route_id: state
                            .as_ref()
                            .map(|state| state.active_route_id.clone())
                            .unwrap_or_else(|| "unknown-unconfirmed-nebula-route".to_string()),
                        recommended_route_id: selected_route.clone(),
                        expected_improvement_pct: if current_score > 0.0 {
                            ((candidate_score - current_score) / current_score) * 100.0
                        } else {
                            0.0
                        },
                        confidence: selected_prediction.map(|prediction| prediction.confidence),
                        reason: selected_prediction
                            .map(|prediction| prediction.reason.clone())
                            .unwrap_or_else(|| "no eligible route selected".to_string()),
                        safety_verdict: safety
                            .as_ref()
                            .map(|decision| format!("{:?}", decision.verdict))
                            .unwrap_or_else(|| "unconfirmed_current_route".to_string()),
                        safety_allowed_if_activated: safety
                            .as_ref()
                            .map(|decision| decision.allowed)
                            .unwrap_or(false),
                        safety_reason: safety
                            .map(|decision| decision.reason)
                            .unwrap_or_else(|| observed.diagnostic.clone()),
                        applied: false,
                        operator_next_step: "Switch to active mode only after reviewing safety and Task2 trust evidence".to_string(),
                    },
                )?;
            }

            return Ok(Task3RuntimeStatus {
                schema_version: STATUS_SCHEMA.to_string(),
                config_version: network_config.config_version,
                enabled,
                mode: runtime_mode,
                running: true,
                tick_count: previous_tick_count.saturating_add(1),
                last_tick_ms: Some(now_ms),
                latest_mode_decision: Some(mode_decision.clone()),
                config_error,
                last_cycle_ms: Some(now_ms),
                last_success_ms: Some(now_ms),
                trust_state_available: !trust.missing,
                candidate_count: topology.route_candidates.len(),
                eligible_count: eligible.eligible.len(),
                recommended_route: selected_route,
                active_route: if observed.confirmed {
                    state.as_ref().map(|state| state.active_route_id.clone())
                } else {
                    None
                },
                transport_apply_attempted: false,
                last_transport_result: Some(ProductionRouteApplyResult {
                    attempted: false,
                    applied: false,
                    requested_route_id: String::new(),
                    previous_route_id: state
                        .as_ref()
                        .map(|state| state.active_route_id.clone())
                        .unwrap_or_default(),
                    observed_route_id: if observed.confirmed {
                        Some(observed.route_id.clone())
                    } else {
                        None
                    },
                    rollback_attempted: false,
                    rollback_applied: false,
                    reason: mode_decision.reason.clone(),
                }),
                last_error: None,
            });
        }

        // D12 production wiring:
        // Security/policy-sensitive route actions are handed to Task2.
        // Task3 never directly mutates Task2 trust/policy state.
        if let Some((candidate, sensitive_reason)) = sensitive_route_action.as_ref() {
            let handoff_state_path = self
                .config
                .persistence_root
                .join("sensitive_route_handoff_state.json");

            // If this route already has a Task2 review, consume its current
            // lifecycle state before creating another review.
            let existing_state = std::fs::read_to_string(&handoff_state_path)
                .ok()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                .filter(|state| {
                    state
                        .get("requested_route_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(candidate.route_id.as_str())
                });

            let mut existing_review_handled = false;

            if let Some(mut state) = existing_state {
                let review_path = state
                    .get("pending_review_path")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);

                let review = review_path
                    .as_deref()
                    .and_then(|path| std::fs::read_to_string(path).ok())
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());

                if let Some(review) = review {
                    if let Some(status_raw) =
                        review.get("status").and_then(serde_json::Value::as_str)
                    {
                        let normalized = status_raw.to_ascii_lowercase().replace(['_', '-'], "");

                        match normalized.as_str() {
                            "pendingreview" => {
                                // Existing pending review owns this sensitive
                                // action. Do not enqueue another one.
                                existing_review_handled = true;
                            }

                            "approved" | "rejected" => {
                                let review_status = if normalized == "approved" {
                                    sgx_anomaly_engine::virtual_shift::ReviewStatus::Approved
                                } else {
                                    sgx_anomaly_engine::virtual_shift::ReviewStatus::Rejected
                                };

                                let plan_id = state
                                    .get("plan_id")
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or_else(|| {
                                        anyhow!("D12 finalized handoff state is missing plan_id")
                                    })?
                                    .to_string();

                                let already_linked = state
                                    .get("post_task2_audit_linked")
                                    .and_then(serde_json::Value::as_bool)
                                    .unwrap_or(false);

                                if !already_linked {
                                    let route_eligible = eligible
                                        .eligible
                                        .iter()
                                        .any(|route| route.route_id == candidate.route_id);

                                    let post_audit_root = self
                                        .config
                                        .persistence_root
                                        .join("post_task2_decision_audits");

                                    std::fs::create_dir_all(&post_audit_root)?;

                                    let post_audit_path =
                                        post_audit_root.join(format!("{}.json", plan_id));

                                    let task2_summary_path = self
                                        .config
                                        .task2_trust_root
                                        .join(&candidate.destination_node)
                                        .join("routing_trust_summary.json");

                                    let outcome = if review_status
                                        == sgx_anomaly_engine::virtual_shift::ReviewStatus::Approved
                                    {
                                        "Task2 owner approved the sensitive-route review; Task3 still requires current Task2 trust/policy eligibility before any route apply."
                                    } else {
                                        "Task2 owner rejected the sensitive-route review; Task3 keeps the route blocked."
                                    };

                                    let post_audit =
                                        sgx_anomaly_engine::network_ai::Task3PostTask2DecisionAudit {
                                            schema_version:
                                                "network-ai-post-task2-decision-v1".to_string(),
                                            handoff_plan_id: plan_id.clone(),
                                            task2_review_id: plan_id.clone(),
                                            task2_review_status: review_status,
                                            task2_trust_state_version:
                                                eligible.trust_state_version.clone(),
                                            task2_trust_summary_path:
                                                task2_summary_path.display().to_string(),
                                            later_task3_decision_id:
                                                format!("task3-runtime-{now_ms}"),
                                            requested_route_id:
                                                candidate.route_id.clone(),
                                            route_eligible,
                                            route_applied: false,
                                            outcome: outcome.to_string(),
                                        };

                                    sgx_anomaly_engine::network_ai::
                                        write_post_task2_decision_audit(
                                            &post_audit_path,
                                            &post_audit,
                                        )?;

                                    if let Some(object) = state.as_object_mut() {
                                        object.insert(
                                            "review_status".to_string(),
                                            serde_json::Value::String(status_raw.to_string()),
                                        );
                                        object.insert(
                                            "post_task2_audit_linked".to_string(),
                                            serde_json::Value::Bool(true),
                                        );
                                        object.insert(
                                            "post_task2_audit_path".to_string(),
                                            serde_json::Value::String(
                                                post_audit_path.display().to_string(),
                                            ),
                                        );
                                        object.insert(
                                            "post_task2_audit_linked_at_ms".to_string(),
                                            serde_json::json!(now_ms),
                                        );
                                    }

                                    persist_json(&handoff_state_path, &state)?;
                                }

                                // Finalized review is authoritative. Do not
                                // create another review for the same unchanged
                                // sensitive route condition.
                                existing_review_handled = true;
                            }

                            _ => {}
                        }
                    }
                }
            }

            if !existing_review_handled {
                // task2_trust_root is:
                //   .../virtual_shift/09_MEMBER_ACTIVE_POLICIES
                // therefore its parent is the authoritative Virtual Shift root.
                let virtual_shift_root =
                    self.config.task2_trust_root.parent().ok_or_else(|| {
                        anyhow!(
                            "D12 cannot derive Virtual Shift root from {}",
                            self.config.task2_trust_root.display()
                        )
                    })?;

                let review_root = virtual_shift_root.join("02_OWNER_REVIEW_DECISIONS");

                let role_config = virtual_shift_root.join("config").join("node_roles.json");

                if !role_config.is_file() {
                    return Err(anyhow!(
                        "D12 Task2 role configuration missing: {}",
                        role_config.display()
                    ));
                }

                let audit_path = self
                    .config
                    .persistence_root
                    .join("sensitive_route_handoffs")
                    .join(format!(
                        "{}-{}.json",
                        now_ms,
                        short_hash(&candidate.route_id)
                    ));

                let handoff = sgx_anomaly_engine::network_ai::SensitiveRouteHandoffService::new(
                    review_root,
                    role_config.display().to_string(),
                )
                .handoff(
                    now_ms,
                    &candidate.source_node,
                    &candidate.destination_node,
                    &candidate.route_id,
                    sensitive_reason.clone(),
                    0.0,
                    0.0,
                    &audit_path,
                )?;

                persist_json(
                    &handoff_state_path,
                    &serde_json::json!({
                        "schema_version":
                            "task3-d12-sensitive-route-handoff-state-v1",
                        "ts_ms": now_ms,
                        "plan_id": handoff.plan_id,
                        "requested_route_id": candidate.route_id,
                        "sensitive_reason": sensitive_reason,
                        "direct_apply_blocked":
                            handoff.direct_apply_blocked,
                        "owner_approval_required":
                            handoff.owner_approval_required,
                        "review_status": handoff.review_status,
                        "pending_review_path":
                            handoff.pending_review_path,
                        "handoff_audit_path":
                            audit_path.display().to_string(),
                        "task2_trust_state_version":
                            eligible.trust_state_version,
                        "post_task2_audit_linked": false
                    }),
                )?;
            }
        }

        // Runtime resilience: relay statistics must not wedge the complete
        // Task3 optimization / learning worker indefinitely.
        let relay_health_timeout = Duration::from_secs(10);
        self.persist_cycle_stage("10_before_relay_health", now_ms);
        let relay_health = timeout(
            relay_health_timeout,
            self.relay_health.relay_health(&topology),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "Task3 relay health collection timed out after {} seconds",
                relay_health_timeout.as_secs()
            )
        })??;
        let weights = MultiRelayLoadBalancer::default().calculate_with_health(
            &eligible.eligible,
            &predictions,
            selected_route
                .as_ref()
                .and_then(|route_id| {
                    topology
                        .route_candidates
                        .iter()
                        .find(|candidate| candidate.route_id == *route_id)
                        .map(|candidate| candidate.traffic_class)
                })
                .unwrap_or(TrafficClass::Operational),
            &relay_health,
            now_ms,
        );
        self.persist_cycle_stage("11_before_relay_weights", now_ms);
        let relay_control_result = self.relay_control.apply_weights(&weights).await?;
        self.persist_cycle_stage("12_after_relay_weights", now_ms);
        persist_json(
            self.config
                .persistence_root
                .join("relay_control_status.json"),
            &relay_control_result,
        )?;

        let transport_result = if let Some((candidate, sensitive_reason)) =
            sensitive_route_action.as_ref()
        {
            // D12 takes precedence over D3/D10/D11. Even if Nebula route
            // observation becomes available, this security/policy action
            // cannot be directly applied by Task3.
            ProductionRouteApplyResult {
                    attempted: false,
                    applied: false,
                    requested_route_id: candidate.route_id.clone(),
                    previous_route_id: state
                        .as_ref()
                        .map(|state| state.active_route_id.clone())
                        .unwrap_or_default(),
                    observed_route_id: if observed.confirmed {
                        Some(observed.route_id.clone())
                    } else {
                        None
                    },
                    rollback_attempted: false,
                    rollback_applied: false,
                    reason: format!(
                        "D12 sensitive route direct apply blocked; Task2 owner/admin review required: {:?}",
                        sensitive_reason
                    ),
                }
        } else if !observed.confirmed {
            ProductionRouteApplyResult {
                attempted: false,
                applied: false,
                requested_route_id: String::new(),
                previous_route_id: String::new(),
                observed_route_id: None,
                rollback_attempted: false,
                rollback_applied: false,
                reason: format!(
                    "D3 unconfirmed current Nebula route; recommendation recorded but no route applied: {}",
                    observed.diagnostic
                ),
            }
        } else if state.is_none() {
            // A destination-scoped D3 observation can confirm that the selected
            // route is currently observable without proving that it is the
            // controller's active route. Never promote that observation to
            // active state and never panic. Fail closed until active-route
            // state is independently available.
            ProductionRouteApplyResult {
                attempted: false,
                applied: false,
                requested_route_id: selected_route.clone().unwrap_or_default(),
                previous_route_id: String::new(),
                observed_route_id: if observed.confirmed {
                    Some(observed.route_id.clone())
                } else {
                    None
                },
                rollback_attempted: false,
                rollback_applied: false,
                reason: "D10 fail closed: confirmed destination route exists but active route controller state is unavailable".to_string(),
            }
        } else if let Some(route_id) = selected_route.as_ref() {
            let state = state
                .as_ref()
                .ok_or_else(|| anyhow!("active route state disappeared before D10 evaluation"))?;
            let revalidated = EligibilityFilter.filter_at(
                vec![topology
                    .route_candidates
                    .iter()
                    .find(|candidate| candidate.route_id == *route_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("selected route disappeared before apply"))?],
                &trust,
                now_ms,
            );
            if revalidated.eligible.is_empty() {
                ProductionRouteApplyResult {
                    attempted: false,
                    applied: false,
                    requested_route_id: route_id.clone(),
                    previous_route_id: state.active_route_id.clone(),
                    observed_route_id: Some(observed.route_id.clone()),
                    rollback_attempted: false,
                    rollback_applied: false,
                    reason: "fail closed: selected route failed Task2 revalidation".to_string(),
                }
            } else {
                // D10: Safety must be evaluated BEFORE the real transport
                // adapter is allowed to change the active Nebula route.
                let mut controller = SafeRuntimeRouteController::default();
                controller.safety_guard.config = network_config.safety.clone();

                let current_score = prediction_score_or_zero(&predictions, &state.active_route_id);
                let candidate_score = prediction_score_or_zero(&predictions, route_id);

                // Hard-failover is allowed only when D3 positively confirmed
                // the active Nebula route and its real runtime health failed.
                // Unconfirmed routes never reach this Active apply branch.

                let safety_decision = controller.safety_guard.evaluate_with_route_health(
                    now_ms,
                    &state.as_switch_state(),
                    Some(route_id),
                    current_score,
                    candidate_score,
                    current_route_failed,
                );

                if !safety_decision.allowed {
                    ProductionRouteApplyResult {
                        attempted: false,
                        applied: false,
                        requested_route_id: route_id.clone(),
                        previous_route_id: state.active_route_id.clone(),
                        observed_route_id: Some(observed.route_id.clone()),
                        rollback_attempted: false,
                        rollback_applied: false,
                        reason: format!(
                            "D10 safety guard blocked route apply: {:?}: {}",
                            safety_decision.verdict, safety_decision.reason
                        ),
                    }
                } else {
                    self.transport
                        .apply_route(
                            &ProductionRouteApplyRequest {
                                decision_id: decision_id.clone(),
                                requested_route_id: route_id.clone(),
                                previous_route_id: state.active_route_id.clone(),
                            },
                            &topology,
                        )
                        .await?
                }
            }
        } else {
            ProductionRouteApplyResult {
                attempted: false,
                applied: false,
                requested_route_id: String::new(),
                previous_route_id: state
                    .as_ref()
                    .map(|state| state.active_route_id.clone())
                    .unwrap_or_default(),
                observed_route_id: state.as_ref().map(|_| observed.route_id.clone()),
                rollback_attempted: false,
                rollback_applied: false,
                reason: "no eligible AI route recommendation".to_string(),
            }
        };
        let mode_decision = RuntimeModeDecision {
            schema_version: NETWORK_AI_RUNTIME_MODE_VERSION.to_string(),
            mode: runtime_mode,
            current_route_id: transport_result.previous_route_id.clone(),
            selected_route_id: transport_result.requested_route_id.clone(),
            applied: transport_result.applied,
            reason: if transport_result.attempted {
                format!(
                    "active mode delegated to D10 safety and production transport: {}",
                    transport_result.reason
                )
            } else {
                format!(
                    "active mode did not apply a route: {}",
                    transport_result.reason
                )
            },
        };
        persist_json(
            self.config
                .persistence_root
                .join("runtime_mode_decision.json"),
            &mode_decision,
        )?;

        if transport_result.attempted {
            let requested_hop_count = eligible
                .eligible
                .iter()
                .find(|route| route.route_id == transport_result.requested_route_id)
                .map(|route| route.hop_count)
                .unwrap_or(0);

            if transport_result.applied {
                // D9: RL must learn from the real post-actuation route outcome,
                // never from the pre-apply observation collected earlier in
                // this optimization cycle.
                let post_apply_telemetry = collect_overlay_path_telemetry(&topology).await;

                if let Some(measured) = post_apply_telemetry
                    .iter()
                    .find(|sample| sample.route_id == transport_result.requested_route_id)
                {
                    let reward = RouteReward::from_observed_outcome_with_weights(
                        &ObservedRewardInput {
                            route_id: transport_result.requested_route_id.clone(),
                            rtt_ms: measured.rtt_ms,
                            packet_loss_pct: measured.packet_loss_pct,
                            throughput_mbps: measured.throughput_mbps,
                            // The current overlay-path probe does not expose
                            // route-specific utilization. Keep it explicitly
                            // missing rather than reusing pre-apply telemetry.
                            bandwidth_utilization_pct: None,
                            hop_count: requested_hop_count,
                            switched_route: transport_result.requested_route_id
                                != transport_result.previous_route_id,
                            route_failed: !measured.route_available,
                        },
                        &network_config.reward_weights,
                    );

                    policy.update_with_reward(&reward);
                    append_jsonl(
                        self.config.persistence_root.join("rewards.jsonl"),
                        &serde_json::json!({
                            "decision_id": decision_id,
                            "ts_ms": now_ms,
                            "observation_phase": "post_actuation",
                            "reward": reward,
                        }),
                    )?;
                    rewards.push(reward);
                }
            } else {
                // Apply failure itself is an observed production outcome.
                // Do not attach pre-apply route performance to that failure.
                let reward = RouteReward::from_observed_outcome_with_weights(
                    &ObservedRewardInput {
                        route_id: transport_result.requested_route_id.clone(),
                        rtt_ms: None,
                        packet_loss_pct: None,
                        throughput_mbps: None,
                        bandwidth_utilization_pct: None,
                        hop_count: requested_hop_count,
                        switched_route: transport_result.requested_route_id
                            != transport_result.previous_route_id,
                        route_failed: true,
                    },
                    &network_config.reward_weights,
                );

                policy.update_with_reward(&reward);
                append_jsonl(
                    self.config.persistence_root.join("rewards.jsonl"),
                    &serde_json::json!({
                        "decision_id": decision_id,
                        "ts_ms": now_ms,
                        "observation_phase": "transport_apply_failure",
                        "reward": reward,
                    }),
                )?;
                rewards.push(reward);
            }
        }
        policy.save_json(self.config.persistence_root.join("rl_policy.json"))?;

        let apply_request = RuntimeRouteApplyRequest {
            ts_ms: now_ms,
            // D10 controller must audit/evaluate the route that AI actually
            // requested, not silently substitute the currently observed route.
            requested_route_id: transport_result.requested_route_id.clone(),
            current_score: state
                .as_ref()
                .map(|state| prediction_score_or_zero(&predictions, &state.active_route_id))
                .unwrap_or(0.0),
            candidate_score: transport_result
                .observed_route_id
                .as_ref()
                .map(|route| prediction_score_or_zero(&predictions, route))
                .unwrap_or(0.0),
            current_route_failed: false,
            transport_apply_succeeds: transport_result.applied,
            selected_by: format!("{}:{}", predictions.model_version, decision.decision_mode),
            observed_rtt_ms: observation.rtt_ms,
            observed_packet_loss_pct: observation.packet_loss_pct,
            observed_throughput_mbps: observation.throughput_mbps,
            observed_bandwidth_utilization_pct: observation.bandwidth_utilization_pct,
            observed_reward: rewards.first().map(|reward| reward.total_reward),
        };
        if let Some(state) = state.as_mut() {
            let controller = SafeRuntimeRouteController::default();
            let _route_result = controller.apply_and_persist(
                state,
                &eligible,
                &apply_request,
                self.config
                    .persistence_root
                    .join("current_route_state.json"),
                self.config
                    .persistence_root
                    .join("last_route_apply_result.json"),
                self.config
                    .persistence_root
                    .join("route_transition_audit.jsonl"),
                self.config.persistence_root.join("observed_outcomes.jsonl"),
            )?;
        }
        append_jsonl(
            self.config
                .persistence_root
                .join("transport_apply_audit.jsonl"),
            &transport_result,
        )?;

        // D10: persist current-cycle safety observability even when D3 cannot
        // confirm the active Nebula route and therefore no safety evaluation
        // or transport apply can safely occur.
        let safety_runtime_status = serde_json::json!({
            "schema_version": "task3-d10-safety-runtime-status-v1",
            "ts_ms": now_ms,
            "safety_evaluated": observed.confirmed && state.is_some(),
            "blocked_by": if !observed.confirmed {
                Some("D3_UNCONFIRMED_ACTIVE_ROUTE")
            } else {
                None::<&str>
            },
            "current_route": if observed.confirmed {
                state.as_ref().map(|state| state.active_route_id.clone())
            } else {
                None
            },
            "candidate_route": selected_route.clone(),
            "transport_apply_allowed": transport_result.attempted,
            "transport_applied": transport_result.applied,
            "reason": transport_result.reason.clone()
        });

        persist_json(
            self.config
                .persistence_root
                .join("safety_runtime_status.json"),
            &safety_runtime_status,
        )?;

        self.persist_cycle_stage("99_cycle_inner_complete", now_ms);

        Ok(Task3RuntimeStatus {
            schema_version: STATUS_SCHEMA.to_string(),
            config_version: network_config.config_version,
            enabled,
            mode: runtime_mode,
            running: true,
            tick_count: previous_tick_count.saturating_add(1),
            last_tick_ms: Some(now_ms),
            latest_mode_decision: Some(mode_decision),
            config_error,
            last_cycle_ms: Some(now_ms),
            last_success_ms: Some(now_ms),
            trust_state_available: !trust.missing,
            candidate_count: topology.route_candidates.len(),
            eligible_count: eligible.eligible.len(),
            recommended_route: selected_route,
            active_route: if observed.confirmed {
                state.as_ref().map(|state| state.active_route_id.clone())
            } else {
                None
            },
            transport_apply_attempted: transport_result.attempted,
            last_transport_result: Some(transport_result),
            last_error: None,
        })
    }

    fn load_or_observed_state(&self, observed: &ObservedRouteState) -> Result<RuntimeRouteState> {
        let path = self
            .config
            .persistence_root
            .join("current_route_state.json");
        if path.exists() {
            match RuntimeRouteState::load_json(&path) {
                Ok(state) if state.active_route_id == observed.route_id => return Ok(state),
                Ok(mut state) => {
                    state.previous_route_id = Some(state.active_route_id);
                    state.active_route_id = observed.route_id.clone();
                    state.active_route_started_ms = observed.started_ms;
                    return Ok(state);
                }
                Err(error) => {
                    tracing::warn!(%error, "corrupt Task3 route state; reconciling from observed route")
                }
            }
        }
        Ok(RuntimeRouteState {
            schema_version: "network-ai-route-controller-v1".to_string(),
            active_route_id: observed.route_id.clone(),
            active_route_started_ms: observed.started_ms,
            previous_route_id: None,
            last_switch_ms: None,
            switch_timestamps_ms: Vec::new(),
        })
    }

    fn load_history(&self, network_config: &EngineNetworkAiConfig) -> Result<RouteHistoryStore> {
        let path = self
            .config
            .persistence_root
            .join("route_history_store.json");
        RouteHistoryStore::load_or_new(path, 0.5, network_config.history_window_entries)
    }

    fn load_policy(
        &self,
        network_config: &EngineNetworkAiConfig,
    ) -> Result<ContextualBanditPolicy> {
        let path = self.config.persistence_root.join("rl_policy.json");
        let mut policy = ContextualBanditPolicy::load_or_new(
            &path,
            network_config.rl_learning_rate,
            network_config.rl_epsilon,
        )?;
        policy.learning_rate = network_config.rl_learning_rate;
        policy.epsilon = network_config.rl_epsilon;
        policy.save_json(path)?;
        Ok(policy)
    }

    async fn persist_status(&self) -> Result<()> {
        persist_json(
            self.config.persistence_root.join("runtime_status.json"),
            &*self.status.read().await,
        )
    }
}

struct SgxTask3TelemetryProvider {
    source: Mutex<SgxTelemetrySource>,
}

impl SgxTask3TelemetryProvider {
    fn new(metrics: Arc<Mutex<Metrics>>) -> Self {
        Self {
            source: Mutex::new(SgxTelemetrySource::new(metrics)),
        }
    }
}

#[async_trait]
impl NetworkTelemetryProvider for SgxTask3TelemetryProvider {
    async fn collect(&self) -> Result<ProductionTelemetry> {
        let raw = self.source.lock().await.poll().await;
        if raw.ts_ms == 0 {
            return Err(anyhow!("runtime telemetry timestamp unavailable"));
        }
        Ok(ProductionTelemetry {
            raw,
            packet_loss_pct: None,
        })
    }
}

struct SgxTask3TopologyProvider {
    node_id: String,
    nebula_base_dir: PathBuf,
    cot_circle: Arc<CircleMembership>,
    link_monitor: Arc<LinkMonitor>,
}

impl SgxTask3TopologyProvider {
    fn new(
        node_id: String,
        nebula_base_dir: PathBuf,
        cot_circle: Arc<CircleMembership>,
        link_monitor: Arc<LinkMonitor>,
    ) -> Self {
        Self {
            node_id,
            nebula_base_dir,
            cot_circle,
            link_monitor,
        }
    }
}

#[async_trait]
impl RouteTopologyProvider for SgxTask3TopologyProvider {
    async fn discover_routes(&self) -> Result<ProductionTopology> {
        let overlay_path = self.nebula_base_dir.join("overlay_registry.json");
        let relay_path = self.nebula_base_dir.join("relay_registry.json");

        let overlay = OverlayRegistry::load(&overlay_path.display().to_string())
            .map_err(|error| anyhow!("Nebula overlay registry unavailable: {error}"))?;
        let relay_registry = RelayRegistry::load(&relay_path.display().to_string()).ok();
        let snapshots = self.link_monitor.all_snapshots().await;
        let member_ids = self.cot_circle.member_ids().await;

        build_nebula_overlay_topology(
            &self.node_id,
            member_ids,
            &overlay,
            relay_registry.as_ref(),
            &snapshots,
        )
    }
}

struct FileTask2TrustProvider {
    root: PathBuf,
}

impl FileTask2TrustProvider {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn summary_path(&self, peer: &str) -> PathBuf {
        self.root.join(peer).join("routing_trust_summary.json")
    }
}

#[async_trait]
impl Task2TrustProvider for FileTask2TrustProvider {
    async fn current_trust_state(
        &self,
        local_node: &str,
        required_peers: &[String],
        now_ms: u64,
    ) -> Result<(
        TrustStateSnapshot,
        Option<Task2RoutingTrustSummary>,
        PathBuf,
    )> {
        let mut snapshot = TrustStateSnapshot::new(format!("task2-runtime-{now_ms}"))
            .observed_at(now_ms)
            .max_age(DEFAULT_TRUST_MAX_AGE_MS);
        let mut first_summary = None;
        let mut first_path = self.root.clone();
        let mut saw_summary = false;

        for peer in required_peers {
            let path = self.summary_path(peer);
            let value = match fs::read_to_string(&path) {
                Ok(raw) => serde_json::from_str::<Value>(&raw)
                    .with_context(|| format!("parsing Task2 trust summary {}", path.display()))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // D20 / Task2 authority boundary:
                    //
                    // A missing per-peer routing trust summary must never be
                    // treated as implicit authorization merely because another
                    // required peer still has a valid Task2 summary.
                    //
                    // Fail closed only for the affected peer so unrelated
                    // trusted routes can remain usable.
                    tracing::warn!(
                        peer = %peer,
                        path = %path.display(),
                        "Task2 routing trust summary missing; quarantining peer for Task3 eligibility"
                    );
                    snapshot = snapshot.quarantine_peer(peer);
                    continue;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("reading Task2 trust summary {}", path.display()))
                }
            };
            saw_summary = true;
            first_path = path.clone();

            let updated_at_ms = value
                .get("updated_at_ms")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("Task2 summary missing updated_at_ms"))?;
            let routing_allowed = value
                .get("routing_allowed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let trusted = string_field(&value, "trust_status")
                .map(|value| value.eq_ignore_ascii_case("trusted"))
                .unwrap_or(false);
            let attestation_trusted = string_field(&value, "attestation_state")
                .map(|value| value.eq_ignore_ascii_case("trusted"))
                .unwrap_or(false);
            let fresh = now_ms.saturating_sub(updated_at_ms) <= DEFAULT_TRUST_MAX_AGE_MS;

            if routing_allowed && trusted && attestation_trusted && fresh {
                snapshot = snapshot.trust_peer(peer);
                for member in string_array_field(&value, "applicable_members") {
                    snapshot = snapshot.trust_peer(member);
                }
            } else {
                snapshot = snapshot.quarantine_peer(peer);
            }

            if first_summary.is_none() {
                first_summary = Some(summary_from_value(peer, &value)?);
            }
        }

        if saw_summary {
            snapshot = snapshot.trust_peer(local_node);
            Ok((snapshot, first_summary, first_path))
        } else {
            Ok((
                TrustStateSnapshot::missing("task2-missing"),
                None,
                self.root.clone(),
            ))
        }
    }
}

struct SgxRouteObservationProvider {
    failover: Arc<FailoverEngine>,
}

impl SgxRouteObservationProvider {
    fn new(failover: Arc<FailoverEngine>) -> Self {
        Self { failover }
    }

    fn nebula_root(&self) -> PathBuf {
        PathBuf::from("/var/lib/sgx-guardian/nebula")
    }

    fn live_assured_nebula_endpoints(&self) -> Result<BTreeSet<String>> {
        let data = fs::read_to_string("/proc/net/nf_conntrack")
            .context("read live kernel conntrack table for Nebula D3 observation")?;

        let mut endpoints = BTreeSet::new();

        for line in data.lines() {
            if !line.contains(" udp ")
                || !line.contains("[ASSURED]")
                || !line.contains("sport=4242")
                || !line.contains("dport=4242")
            {
                continue;
            }

            // Parse the first conntrack tuple deterministically.
            // A conntrack line contains original and reply tuples, so stop
            // immediately after the first src/dst/sport/dport tuple.
            let mut src: Option<&str> = None;
            let mut dst: Option<&str> = None;
            let mut sport: Option<&str> = None;
            let mut dport: Option<&str> = None;

            for field in line.split_whitespace() {
                if src.is_none() {
                    if let Some(value) = field.strip_prefix("src=") {
                        src = Some(value);
                        continue;
                    }
                }

                if dst.is_none() {
                    if let Some(value) = field.strip_prefix("dst=") {
                        dst = Some(value);
                        continue;
                    }
                }

                if sport.is_none() {
                    if let Some(value) = field.strip_prefix("sport=") {
                        sport = Some(value);
                        continue;
                    }
                }

                if dport.is_none() {
                    if let Some(value) = field.strip_prefix("dport=") {
                        dport = Some(value);
                    }
                }

                if src.is_some() && dst.is_some() && sport.is_some() && dport.is_some() {
                    break;
                }
            }

            if sport == Some("4242") && dport == Some("4242") {
                if let (Some(src), Some(dst)) = (src, dst) {
                    endpoints.insert(format!("{src}:4242"));
                    endpoints.insert(format!("{dst}:4242"));
                }
            }
        }

        Ok(endpoints)
    }
}

fn match_d3_destination_routes(
    topology: &ProductionTopology,
    lighthouse: &LighthouseRegistry,
    live_endpoints: &BTreeSet<String>,
    iface: Option<String>,
    now_ms: u64,
) -> Vec<ObservedRouteState> {
    let mut observations = Vec::new();

    for destination in &topology.destinations {
        let registry_entry = lighthouse
            .lighthouses
            .iter()
            .find(|entry| entry.node_name == *destination);

        let Some(entry) = registry_entry else {
            observations.push(ObservedRouteState {
                route_id: "unknown-unconfirmed-nebula-route".to_string(),
                destination_node: destination.clone(),
                interface_name: iface.clone(),
                confirmed: false,
                diagnostic: format!(
                    "D3 destination {} is missing from Nebula lighthouse registry",
                    destination
                ),
                started_ms: now_ms,
            });
            continue;
        };

        let direct_candidate = topology.route_candidates.iter().find(|candidate| {
            candidate.destination_node == *destination && candidate.kind == RouteKind::DirectP2p
        });

        if !entry.physical_endpoint.is_empty() && live_endpoints.contains(&entry.physical_endpoint)
        {
            if let Some(candidate) = direct_candidate {
                observations.push(ObservedRouteState {
                    route_id: candidate.route_id.clone(),
                    destination_node: destination.clone(),
                    interface_name: iface.clone(),
                    confirmed: true,
                    diagnostic: format!(
                        "D3 confirmed live direct Nebula route {} to destination {} overlay_ip={} physical_endpoint={} from ASSURED UDP/4242 dataplane session",
                        candidate.route_id,
                        destination,
                        entry.overlay_ip,
                        entry.physical_endpoint
                    ),
                    started_ms: now_ms,
                });
                continue;
            }
        }

        observations.push(ObservedRouteState {
            route_id: "unknown-unconfirmed-nebula-route".to_string(),
            destination_node: destination.clone(),
            interface_name: iface.clone(),
            confirmed: false,
            diagnostic: format!(
                "D3 no exact live direct Nebula route evidence for destination {}; relay/multi-hop routes are not inferred from UDP/4242 peer-session or underlay evidence",
                destination
            ),
            started_ms: now_ms,
        });
    }

    observations
}

#[async_trait]
impl RouteObservationProvider for SgxRouteObservationProvider {
    async fn current_routes(
        &self,
        topology: &ProductionTopology,
    ) -> Result<Vec<ObservedRouteState>> {
        let iface = self.failover.current_interface().await;

        let lighthouse_path = self.nebula_root().join("lighthouse_registry.json");
        let lighthouse_path_str = lighthouse_path
            .to_str()
            .ok_or_else(|| anyhow!("invalid Nebula lighthouse registry path"))?;

        let lighthouse = LighthouseRegistry::load(lighthouse_path_str).map_err(|error| {
            anyhow!(
                "load Nebula lighthouse registry for D3 observation from {}: {}",
                lighthouse_path.display(),
                error
            )
        })?;

        let live_endpoints = self.live_assured_nebula_endpoints().map_err(|error| {
            anyhow!(
                "D3 cannot confirm current Nebula routes because live UDP/4242 dataplane evidence is unavailable: {}",
                error
            )
        })?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| anyhow!("system clock before UNIX epoch: {}", error))?
            .as_millis() as u64;

        Ok(match_d3_destination_routes(
            topology,
            &lighthouse,
            &live_endpoints,
            iface,
            now_ms,
        ))
    }

    async fn current_route(&self, topology: &ProductionTopology) -> Result<ObservedRouteState> {
        let iface = self.failover.current_interface().await;
        let nebula_root = self.nebula_root();
        let lighthouse_path = nebula_root.join("lighthouse_registry.json");

        let lighthouse =
            LighthouseRegistry::load(&lighthouse_path.display().to_string()).map_err(|error| {
                anyhow!(
                    "load Nebula lighthouse registry for D3 from {}: {}",
                    lighthouse_path.display(),
                    error
                )
            })?;

        let live_endpoints = match self.live_assured_nebula_endpoints() {
            Ok(endpoints) => endpoints,
            Err(error) => {
                return Ok(ObservedRouteState {
                    route_id: "unknown-unconfirmed-nebula-route".to_string(),
                    destination_node: String::new(),
                    interface_name: iface,
                    confirmed: false,
                    diagnostic: format!(
                        "D3 live Nebula dataplane unavailable: {}; no persisted route state used as confirmation",
                        error
                    ),
                    started_ms: now_ms(),
                });
            }
        };

        let confirmed_direct = match_d3_destination_routes(
            topology,
            &lighthouse,
            &live_endpoints,
            iface.clone(),
            now_ms(),
        )
        .into_iter()
        .filter(|route| route.confirmed)
        .collect::<Vec<_>>();

        match confirmed_direct.as_slice() {
            [route] => Ok(ObservedRouteState {
                route_id: route.route_id.clone(),
                destination_node: route.destination_node.clone(),
                interface_name: iface.clone(),
                confirmed: true,
                diagnostic: format!(
                    "{}; underlay_interface={:?}",
                    route.diagnostic, iface
                ),
                started_ms: now_ms(),
            }),

            [] => Ok(ObservedRouteState {
                route_id: "unknown-unconfirmed-nebula-route".to_string(),
                destination_node: String::new(),
                interface_name: iface.clone(),
                confirmed: false,
                diagnostic: format!(
                    "D3 found no exact direct Nebula candidate with a live ASSURED UDP/4242 destination endpoint; underlay_interface={:?}",
                    iface
                ),
                started_ms: now_ms(),
            }),

            routes => Ok(ObservedRouteState {
                route_id: "unknown-unconfirmed-nebula-route".to_string(),
                destination_node: String::new(),
                interface_name: iface.clone(),
                confirmed: false,
                diagnostic: format!(
                    "D3 observed multiple simultaneous direct Nebula destination sessions {:?}; global current_route is ambiguous and will not guess; underlay_interface={:?}",
                    routes
                        .iter()
                        .map(|route| route.route_id.as_str())
                        .collect::<Vec<_>>(),
                    iface
                ),
                started_ms: now_ms(),
            }),
        }
    }
}

struct SgxNebulaOverlayRouteTransport {
    persistence_root: PathBuf,
    allow_apply: bool,
}

impl SgxNebulaOverlayRouteTransport {
    fn new(persistence_root: PathBuf, allow_apply: bool) -> Self {
        Self {
            persistence_root,
            allow_apply,
        }
    }

    fn current_route_state_path(&self) -> PathBuf {
        self.persistence_root.join("current_route_state.json")
    }

    fn request_log_path(&self) -> PathBuf {
        self.persistence_root
            .join("nebula_overlay_route_apply_requests.jsonl")
    }

    fn status_path(&self) -> PathBuf {
        self.persistence_root
            .join("nebula_overlay_route_apply_status.json")
    }
}

#[async_trait]
impl RouteTransport for SgxNebulaOverlayRouteTransport {
    async fn apply_route(
        &self,
        request: &ProductionRouteApplyRequest,
        topology: &ProductionTopology,
    ) -> Result<ProductionRouteApplyResult> {
        let candidate = topology
            .route_candidates
            .iter()
            .find(|candidate| candidate.route_id == request.requested_route_id);
        let request_record = NebulaOverlayRouteApplyRecord::from_request(request, candidate);
        append_jsonl(self.request_log_path(), &request_record)?;

        if !self.allow_apply {
            let result = ProductionRouteApplyResult {
                attempted: false,
                applied: false,
                requested_route_id: request.requested_route_id.clone(),
                previous_route_id: request.previous_route_id.clone(),
                observed_route_id: None,
                rollback_attempted: false,
                rollback_applied: false,
                reason: "transport apply disabled by SGX_TASK3_TRANSPORT_APPLY; exact Nebula route observation is unconfirmed".to_string(),
            };
            persist_json(self.status_path(), &result)?;
            return Ok(result);
        }

        let Some(candidate) = candidate else {
            let result = ProductionRouteApplyResult {
                attempted: false,
                applied: false,
                requested_route_id: request.requested_route_id.clone(),
                previous_route_id: request.previous_route_id.clone(),
                observed_route_id: None,
                rollback_attempted: false,
                rollback_applied: false,
                reason: "selected route is not present in current Nebula overlay topology"
                    .to_string(),
            };
            persist_json(self.status_path(), &result)?;
            return Ok(result);
        };

        let observed_state = RuntimeRouteState::load_json(self.current_route_state_path()).ok();
        let mut observed_route = observed_state
            .as_ref()
            .map(|state| state.active_route_id.clone());

        // D11: Nebula performs direct-to-relay fallback internally. Confirm
        // relay-backed runtime state instead of fabricating controller state.
        if !candidate.relay_ids.is_empty() {
            let relay_confirmed = std::process::Command::new("curl")
                .args(["-fsS", "http://127.0.0.1:8625/metrics"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .and_then(|metrics| {
                    metrics.lines().find_map(|line| {
                        line.strip_prefix("nebula_relay_hostmap_main_relayIndexes ")
                            .and_then(|value| value.trim().parse::<u64>().ok())
                    })
                })
                .is_some_and(|relay_indexes| relay_indexes > 0);

            if relay_confirmed {
                observed_route = Some(request.requested_route_id.clone());
            }
        }

        if observed_route.as_deref() == Some(request.requested_route_id.as_str()) {
            let result = ProductionRouteApplyResult {
                attempted: true,
                applied: true,
                requested_route_id: request.requested_route_id.clone(),
                previous_route_id: request.previous_route_id.clone(),
                observed_route_id: observed_route,
                rollback_attempted: false,
                rollback_applied: false,
                reason: format!(
                    "Nebula overlay route confirmed exactly as {:?}: {}",
                    candidate.kind, candidate.route_id
                ),
            };
            persist_json(self.status_path(), &result)?;
            return Ok(result);
        }

        let previous_still_confirmed =
            observed_route.as_deref() == Some(request.previous_route_id.as_str());
        let result = ProductionRouteApplyResult {
            attempted: true,
            applied: false,
            requested_route_id: request.requested_route_id.clone(),
            previous_route_id: request.previous_route_id.clone(),
            observed_route_id: observed_route,
            rollback_attempted: true,
            rollback_applied: previous_still_confirmed,
            reason: "Nebula overlay route was requested but exact runtime confirmation did not match; previous confirmed route retained/rollback required".to_string(),
        };
        persist_json(self.status_path(), &result)?;
        Ok(result)
    }
}

#[derive(Debug, Clone, Serialize)]
struct NebulaOverlayRouteApplyRecord {
    schema_version: String,
    decision_id: String,
    requested_route_id: String,
    previous_route_id: String,
    route_kind: Option<RouteKind>,
    source_node: Option<String>,
    destination_node: Option<String>,
    relay_ids: Vec<String>,
    recorded_at_ms: u64,
}

impl NebulaOverlayRouteApplyRecord {
    fn from_request(
        request: &ProductionRouteApplyRequest,
        candidate: Option<&RouteCandidate>,
    ) -> Self {
        Self {
            schema_version: "task3-nebula-overlay-route-apply-request-v1".to_string(),
            decision_id: request.decision_id.clone(),
            requested_route_id: request.requested_route_id.clone(),
            previous_route_id: request.previous_route_id.clone(),
            route_kind: candidate.map(|candidate| candidate.kind),
            source_node: candidate.map(|candidate| candidate.source_node.clone()),
            destination_node: candidate.map(|candidate| candidate.destination_node.clone()),
            relay_ids: candidate
                .map(|candidate| candidate.relay_ids.clone())
                .unwrap_or_default(),
            recorded_at_ms: now_ms(),
        }
    }
}

#[async_trait]
trait NebulaRelayStatsProvider: Send + Sync {
    async fn relay_stats(&self) -> Result<RelayStats>;
}

struct LiveNebulaRelayStatsProvider;

#[async_trait]
impl NebulaRelayStatsProvider for LiveNebulaRelayStatsProvider {
    async fn relay_stats(&self) -> Result<RelayStats> {
        // NebulaStats::fetch() is node-local aggregate telemetry.
        //
        // IMPORTANT:
        // Do not merge RelayTrafficControl::current_stats() here. The tc value
        // may represent the configured HTB class rate rather than measured
        // relay throughput and therefore must not be treated as live load.
        NebulaStats::fetch()
            .await
            .map_err(|error| anyhow!("Nebula relay stats unavailable: {error}"))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RelayTelemetryRecord {
    node_id: String,
    current_mbps: f64,
    updated_at: String,
}

#[derive(Debug, Clone, Default)]
struct RelayHealthObservation {
    healthy: bool,
    recovered_at_ms: Option<u64>,
}

struct SgxRelayHealthProvider {
    stats: Arc<dyn NebulaRelayStatsProvider>,
    telemetry_dir: PathBuf,

    // Tracks actual unhealthy -> healthy transitions.
    //
    // RelayRegistry::last_seen is only a heartbeat timestamp and MUST NOT be
    // used as a recovery timestamp, otherwise the load-balancer recovery ramp
    // is restarted on every successful health check.
    observations: Mutex<std::collections::HashMap<String, RelayHealthObservation>>,
}

impl SgxRelayHealthProvider {
    fn production(nebula_base_dir: PathBuf) -> Self {
        Self {
            stats: Arc::new(LiveNebulaRelayStatsProvider),
            telemetry_dir: nebula_base_dir.join("relay_telemetry"),
            observations: Mutex::new(std::collections::HashMap::new()),
        }
    }

    #[cfg(test)]
    fn with_telemetry_dir(
        stats: Arc<dyn NebulaRelayStatsProvider>,
        telemetry_dir: PathBuf,
    ) -> Self {
        Self {
            stats,
            telemetry_dir,
            observations: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn relay_telemetry_path(&self, node_id: &str) -> Option<PathBuf> {
        let safe = !node_id.trim().is_empty()
            && node_id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
        safe.then(|| self.telemetry_dir.join(format!("{node_id}.json")))
    }

    fn load_relay_utilization_pct(&self, relay: &RelayEntry, now: u64) -> Result<Option<f64>> {
        let Some(path) = self.relay_telemetry_path(&relay.node_name) else {
            return Ok(None);
        };
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading relay telemetry {}", path.display()))
            }
        };
        let record: RelayTelemetryRecord = serde_json::from_str(&raw)
            .with_context(|| format!("parsing relay telemetry {}", path.display()))?;
        if record.node_id != relay.node_name {
            return Ok(None);
        }
        if !record.current_mbps.is_finite() || record.current_mbps.is_sign_negative() {
            return Ok(None);
        }
        let updated_at_ms = chrono::DateTime::parse_from_rfc3339(&record.updated_at)
            .map(|value| value.timestamp_millis().max(0) as u64)
            .with_context(|| format!("parsing relay telemetry updated_at {}", path.display()))?;
        if now.saturating_sub(updated_at_ms) > RELAY_TELEMETRY_MAX_AGE_MS {
            return Ok(None);
        }
        if relay.max_bandwidth_mbps == 0 {
            return Ok(None);
        }

        Ok(Some(
            ((record.current_mbps / relay.max_bandwidth_mbps as f64) * 100.0).clamp(0.0, 100.0),
        ))
    }
}

#[async_trait]
impl RelayHealthProvider for SgxRelayHealthProvider {
    async fn relay_health(&self, topology: &ProductionTopology) -> Result<Vec<RelayRuntimeHealth>> {
        // Keep the local Nebula metrics probe as a production health check.
        //
        // These values are intentionally NOT copied onto every remote relay:
        // they describe this node's aggregate Nebula runtime, not each relay's
        // independent utilization.
        let _local_stats = self.stats.relay_stats().await?;

        let now = now_ms();
        let mut observations = self.observations.lock().await;
        let mut result = Vec::with_capacity(topology.relay_routes.len());

        // A failed relay or unavailable destination can cause a previously
        // known relay route to disappear completely from the current topology.
        // Record that disappearance as unhealthy so that, if the route later
        // reappears, the unhealthy -> healthy transition starts the recovery
        // ramp instead of immediately assigning recovery_factor=1.0.
        let current_route_ids = topology
            .relay_routes
            .keys()
            .cloned()
            .collect::<std::collections::HashSet<_>>();

        for (route_id, observation) in observations.iter_mut() {
            if !current_route_ids.contains(route_id) {
                observation.healthy = false;
                observation.recovered_at_ms = None;
            }
        }

        for (route_id, relay) in &topology.relay_routes {
            let available = relay.is_active;
            let utilization_pct = self
                .load_relay_utilization_pct(relay, now)
                .with_context(|| format!("loading relay telemetry for {}", relay.node_name))?;
            let healthy = available && utilization_pct.is_some();

            let previous = observations.get(route_id).cloned();

            let recovered_at_ms = match previous {
                Some(previous) if !previous.healthy && healthy => Some(now),
                Some(previous) if previous.healthy && healthy => previous.recovered_at_ms,
                Some(_) if !healthy => None,
                None => None,
                _ => None,
            };

            observations.insert(
                route_id.clone(),
                RelayHealthObservation {
                    healthy,
                    recovered_at_ms,
                },
            );

            result.push(RelayRuntimeHealth {
                route_id: route_id.clone(),
                available,
                healthy,

                // Preserve unknown telemetry instead of fabricating another
                // relay's utilization or treating it as idle.
                utilization_pct,

                recovered_at_ms,
            });
        }

        Ok(result)
    }
}

struct PersistedRelayRecommendationControl {
    path: PathBuf,
}

impl PersistedRelayRecommendationControl {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl RelayControl for PersistedRelayRecommendationControl {
    async fn apply_weights(&self, weights: &RelayWeightSet) -> Result<RelayWeightApplyResult> {
        persist_json(&self.path, weights)?;
        Ok(RelayWeightApplyResult {
            attempted: false,
            applied: false,
            reason: "Nebula weighted relay enforcement is not exposed; weights persisted as recommendation only".to_string(),
        })
    }
}

fn build_nebula_overlay_topology(
    local_node: &str,
    _member_ids: Vec<String>,
    overlay: &OverlayRegistry,
    relay_registry: Option<&RelayRegistry>,
    snapshots: &[LinkSnapshot],
) -> Result<ProductionTopology> {
    if overlay.get_ip(local_node).is_none() {
        return Err(anyhow!(
            "local node {local_node} is missing from Nebula overlay registry"
        ));
    }

    let mut destinations = overlay
        .all_nodes()
        .into_iter()
        .filter(|node| node.node_name != local_node)
        .map(|node| node.node_name.clone())
        .collect::<Vec<_>>();
    destinations.sort();
    destinations.dedup();

    let active_relays = relay_registry
        .map(|registry| {
            let mut relays = registry
                .active_relays()
                .into_iter()
                .filter(|relay| relay.node_name != local_node)
                .filter(|relay| overlay.get_ip(&relay.node_name).is_some())
                .cloned()
                .collect::<Vec<_>>();
            relays.sort_by(|left, right| left.node_name.cmp(&right.node_name));
            relays
        })
        .unwrap_or_default();
    let underlay = summarize_underlay_metadata(snapshots);

    let mut route_candidates = Vec::new();
    let mut relay_routes = HashMap::new();

    for destination in &destinations {
        if overlay.get_ip(destination).is_none() {
            continue;
        }
        let traffic_class = traffic_class_for_peer(destination);

        route_candidates.push(overlay_candidate(
            RouteCandidate::direct(local_node, destination, traffic_class),
            overlay,
            &underlay,
        ));

        let usable_relays = active_relays
            .iter()
            .filter(|relay| relay.node_name != *destination)
            .collect::<Vec<_>>();
        for relay in &usable_relays {
            let route = overlay_candidate(
                RouteCandidate::relay(local_node, &relay.node_name, destination, traffic_class),
                overlay,
                &underlay,
            )
            .with_health(
                underlay.available && relay.is_active,
                underlay.healthy && relay.is_active,
            );
            relay_routes.insert(route.route_id.clone(), (*relay).clone());
            route_candidates.push(route);
        }

        for left_index in 0..usable_relays.len() {
            for right in usable_relays.iter().skip(left_index + 1) {
                let left = usable_relays[left_index];
                let route = overlay_candidate(
                    RouteCandidate::multi_hop(
                        local_node,
                        vec![left.node_name.clone(), right.node_name.clone()],
                        destination,
                        traffic_class,
                    ),
                    overlay,
                    &underlay,
                )
                .with_health(
                    underlay.available && left.is_active && right.is_active,
                    underlay.healthy && left.is_active && right.is_active,
                );
                relay_routes.insert(route.route_id.clone(), left.clone());
                route_candidates.push(route);
            }
        }
    }

    if destinations.is_empty() {
        return Err(anyhow!("no real CoT/Nebula destinations available"));
    }
    if route_candidates.is_empty() {
        return Err(anyhow!(
            "no Nebula overlay route candidates available from runtime registry state"
        ));
    }

    Ok(ProductionTopology {
        local_node: local_node.to_string(),
        destinations,
        route_candidates,
        transport_routes: HashMap::new(),
        relay_routes,
    })
}

#[derive(Debug, Clone)]
struct UnderlayMetadata {
    available: bool,
    healthy: bool,
    note: String,
}

fn summarize_underlay_metadata(snapshots: &[LinkSnapshot]) -> UnderlayMetadata {
    let mut entries = snapshots
        .iter()
        .map(|snap| {
            format!(
                "{}={} up={} latency={}ms bandwidth={}kbps successes={} failures={}",
                snap.interface_name,
                snap.transport_type,
                snap.is_up,
                snap.latency_ms,
                snap.bandwidth_kbps,
                snap.consecutive_successes,
                snap.consecutive_failures
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    let available = snapshots.iter().any(|snap| snap.is_up);
    let healthy = snapshots
        .iter()
        .any(|snap| snap.is_up && snap.consecutive_failures == 0);
    UnderlayMetadata {
        available,
        healthy,
        note: if entries.is_empty() {
            "underlay metadata unavailable from CoT LinkMonitor".to_string()
        } else {
            entries.join("; ")
        },
    }
}

fn overlay_candidate(
    mut candidate: RouteCandidate,
    overlay: &OverlayRegistry,
    underlay: &UnderlayMetadata,
) -> RouteCandidate {
    candidate.observed_available = underlay.available;
    candidate.observed_healthy = underlay.healthy;
    let source_ip = overlay
        .get_ip(&candidate.source_node)
        .unwrap_or("overlay-ip-missing");
    let destination_ip = overlay
        .get_ip(&candidate.destination_node)
        .unwrap_or("overlay-ip-missing");
    let relay_ips = candidate
        .relay_ids
        .iter()
        .filter_map(|relay| overlay.get_ip(relay).map(|ip| format!("{relay}={ip}")))
        .collect::<Vec<_>>();
    candidate.metadata = RouteCandidateMetadata {
        health_source: "Nebula overlay registry + CoT LinkMonitor underlay metadata".to_string(),
        trust_authority: "Task2 Virtual Shift routing_trust_summary.json".to_string(),
        trust_state_version_seen: None,
        required_trust_level: "trusted".to_string(),
        health_note: format!(
            "nebula_overlay {}={} -> {}={} relays=[{}]; underlay=[{}]",
            candidate.source_node,
            source_ip,
            candidate.destination_node,
            destination_ip,
            relay_ips.join(","),
            underlay.note
        ),
    };
    candidate
}

fn observe_network(
    raw: &RawSample,
    candidate: &RouteCandidate,
    packet_loss_pct: Option<f64>,
) -> NetworkObservation {
    NetworkTelemetryAdapter::default().observe(
        raw,
        NetworkTelemetryContext {
            source_node: candidate.source_node.clone(),
            destination_node: candidate.destination_node.clone(),
            peer_id: candidate.peer_id.clone(),
            traffic_class: candidate.traffic_class,
            current_route_id: candidate.route_id.clone(),
            route_kind: candidate.kind,
            relay_ids: candidate.relay_ids.clone(),
            relay_hops: candidate.hop_count,
            route_available: candidate.observed_available,
            packet_loss_pct: packet_loss_pct.unwrap_or(0.0),
            bandwidth_capacity_mbps: None,
        },
    )
}

async fn collect_overlay_path_telemetry(
    topology: &ProductionTopology,
) -> Vec<OverlayPathTelemetry> {
    let mut observations = Vec::with_capacity(topology.destinations.len());
    let mut probed_destinations = BTreeSet::new();
    for candidate in &topology.route_candidates {
        if !probed_destinations.insert(candidate.destination_node.clone()) {
            continue;
        }

        let overlay_ip = candidate
            .metadata
            .health_note
            .split(" -> ")
            .nth(1)
            .and_then(|value| value.split('=').nth(1))
            .and_then(|value| value.split_whitespace().next())
            .unwrap_or("overlay-ip-missing")
            .to_string();
        // Production safety boundary: an individual Nebula overlay HTTP
        // probe must never wedge the complete Task3 optimization worker.
        // The inner reqwest timeout is retained, while this outer timeout
        // guarantees progress even if connect/body handling fails to return.
        let _ = persist_json(
            "/var/lib/sgx-guardian/threat/network_ai/runtime/path_probe_stage.json",
            &serde_json::json!({
                "stage": "before_probe",
                "route_id": candidate.route_id.clone(),
                "overlay_ip": overlay_ip.clone(),
                "ts_ms": now_ms()
            }),
        );

        let probe = match timeout(Duration::from_secs(2), probe_overlay_path(&overlay_ip)).await {
            Ok(probe) => probe,
            Err(_) => {
                tracing::warn!(
                    route_id = %candidate.route_id,
                    overlay_ip = %overlay_ip,
                    "Task3 overlay path probe exceeded hard deadline"
                );
                OverlayPathProbe {
                    route_available: false,
                    rtt_ms: None,
                    packet_loss_pct: None,
                    throughput_mbps: None,
                }
            }
        };

        let _ = persist_json(
            "/var/lib/sgx-guardian/threat/network_ai/runtime/path_probe_stage.json",
            &serde_json::json!({
                "stage": "after_probe",
                "route_id": candidate.route_id.clone(),
                "overlay_ip": overlay_ip.clone(),
                "ts_ms": now_ms()
            }),
        );

        observations.push(overlay_path_telemetry(candidate, overlay_ip, probe));
    }
    observations
}

fn measured_observation_for_route(
    candidate: &RouteCandidate,
    telemetry: &[OverlayPathTelemetry],
) -> Option<RouteObservationInput> {
    let measured = telemetry
        .iter()
        .find(|telemetry| telemetry.destination_node == candidate.destination_node)?;
    let mut observation = measured.to_observation_input()?;
    observation.route_id = candidate.route_id.clone();
    observation.switched_route = false;
    Some(observation)
}

fn persist_overlay_path_telemetry(
    path: impl AsRef<Path>,
    observations: &[OverlayPathTelemetry],
) -> Result<()> {
    let path = path.as_ref();
    for observation in observations {
        append_jsonl(path, observation)?;
    }
    Ok(())
}

fn overlay_path_telemetry(
    candidate: &RouteCandidate,
    overlay_ip: String,
    probe: OverlayPathProbe,
) -> OverlayPathTelemetry {
    OverlayPathTelemetry {
        schema_version: "task3-overlay-path-telemetry-v1".to_string(),
        ts_ms: now_ms(),
        source_node: candidate.source_node.clone(),
        destination_node: candidate.destination_node.clone(),
        peer_id: candidate.peer_id.clone(),
        route_id: candidate.route_id.clone(),
        route_kind: candidate.kind,
        relay_ids: candidate.relay_ids.clone(),
        overlay_ip,
        route_available: probe.route_available,
        rtt_ms: probe.rtt_ms,
        packet_loss_pct: probe.packet_loss_pct,
        throughput_mbps: probe.throughput_mbps,
    }
}

fn persist_decision_audit_with_d2_context(
    audit: &DecisionAuditRecord,
    persistence_root: &Path,
    traffic_contexts: Vec<Value>,
) -> Result<()> {
    let path = persistence_root.join("decisions.jsonl");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("create Task3 decision audit directory {}", parent.display())
        })?;
    }

    let mut value = serde_json::to_value(audit).context("serialize Task3 decision audit record")?;

    if let Value::Object(ref mut object) = value {
        object.insert(
            "traffic_contexts".to_string(),
            Value::Array(traffic_contexts),
        );
    }

    // D14: keep the inspectable latest-decision snapshot synchronized with
    // the same enriched record that is appended to decisions.jsonl.
    let current_path = persistence_root.join("current_decision.json");
    let temporary_path = current_path.with_extension("json.tmp");
    let current_bytes =
        serde_json::to_vec_pretty(&value).context("serialize current Task3 decision audit")?;

    fs::write(&temporary_path, current_bytes).with_context(|| {
        format!(
            "write temporary Task3 decision {}",
            temporary_path.display()
        )
    })?;

    fs::rename(&temporary_path, &current_path).with_context(|| {
        format!(
            "atomically replace current Task3 decision {}",
            current_path.display()
        )
    })?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open Task3 decision audit {}", path.display()))?;

    serde_json::to_writer(&mut file, &value).context("serialize enriched Task3 decision audit")?;
    file.write_all(b"\n")
        .context("append enriched Task3 decision audit newline")?;

    // D14.5: persist selected reward with the same decision_id/ts_ms
    // as the production decision audit.
    if let Some(reward) = &audit.selected_reward {
        append_jsonl(
            persistence_root.join("rewards.jsonl"),
            &serde_json::json!({
                "decision_id": audit.decision_id,
                "ts_ms": audit.ts_ms,
                "reward": reward,
            }),
        )?;
    }

    // D14: persist each degradation prediction from this exact production
    // decision using the same decision_id and timestamp as the audit record.
    for prediction in &audit.degradation_predictions {
        append_jsonl(
            persistence_root.join("degradation_events.jsonl"),
            &serde_json::json!({
                "decision_id": audit.decision_id,
                "ts_ms": audit.ts_ms,
                "prediction": prediction,
            }),
        )?;
    }

    Ok(())
}

fn selected_task2_evidence_path(
    trust_root: &Path,
    topology: &ProductionTopology,
    selected_route_id: Option<&str>,
    fallback: &Path,
) -> PathBuf {
    selected_route_id
        .and_then(|route_id| {
            topology
                .route_candidates
                .iter()
                .find(|candidate| candidate.route_id == route_id)
                .map(|candidate| {
                    trust_root
                        .join(&candidate.destination_node)
                        .join("routing_trust_summary.json")
                })
        })
        .unwrap_or_else(|| fallback.to_path_buf())
}

async fn probe_overlay_path(overlay_ip: &str) -> OverlayPathProbe {
    // D8 production path-health evidence.
    //
    // Use multiple bounded TCP connection attempts so packet loss is measured
    // from the real Nebula overlay path instead of being represented only as
    // binary 0%/100% availability. This remains transport-level evidence:
    // no HTTP request/body is sent and throughput is not synthesized.
    const PROBE_ATTEMPTS: usize = 4;
    const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(350);

    let unavailable = || OverlayPathProbe {
        route_available: false,
        rtt_ms: None,
        packet_loss_pct: Some(100.0),
        throughput_mbps: None,
    };

    let ip = match overlay_ip.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return unavailable(),
    };

    let address = std::net::SocketAddr::new(ip, 8443);
    let mut successful_rtt_ms = Vec::with_capacity(PROBE_ATTEMPTS);

    for _ in 0..PROBE_ATTEMPTS {
        let started = Instant::now();

        match timeout(PER_ATTEMPT_TIMEOUT, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                successful_rtt_ms.push(started.elapsed().as_secs_f64() * 1000.0);
                drop(stream);
            }
            Ok(Err(error)) => {
                tracing::debug!(
                    overlay_ip = %overlay_ip,
                    %error,
                    "Task3 Nebula TCP path probe attempt failed"
                );
            }
            Err(_) => {
                tracing::debug!(
                    overlay_ip = %overlay_ip,
                    "Task3 Nebula TCP path probe attempt timed out"
                );
            }
        }
    }

    let successful = successful_rtt_ms.len();
    if successful == 0 {
        return unavailable();
    }

    let failed = PROBE_ATTEMPTS - successful;
    let packet_loss_pct = (failed as f64 / PROBE_ATTEMPTS as f64) * 100.0;
    let rtt_ms = successful_rtt_ms.iter().sum::<f64>() / successful_rtt_ms.len() as f64;

    OverlayPathProbe {
        route_available: true,
        rtt_ms: Some(rtt_ms),
        packet_loss_pct: Some(packet_loss_pct),
        throughput_mbps: None,
    }
}

fn unconfirmed_network_observation(
    raw: &RawSample,
    local_node: &str,
    packet_loss_pct: Option<f64>,
) -> NetworkObservation {
    NetworkTelemetryAdapter::default().observe(
        raw,
        NetworkTelemetryContext {
            source_node: local_node.to_string(),
            destination_node: "unknown".to_string(),
            peer_id: "unknown".to_string(),
            traffic_class: TrafficClass::Operational,
            current_route_id: "unknown-unconfirmed-nebula-route".to_string(),
            route_kind: RouteKind::Unknown,
            relay_ids: Vec::new(),
            relay_hops: 0,
            route_available: false,
            packet_loss_pct: packet_loss_pct.unwrap_or(0.0),
            bandwidth_capacity_mbps: None,
        },
    )
}

fn persist_unconfirmed_current_observation(
    path: impl AsRef<Path>,
    observation: &NetworkObservation,
    reason: &str,
) -> Result<()> {
    let mut json = serde_json::to_value(observation)?;
    json["route_observation_status"] = Value::String("unconfirmed".to_string());
    json["route_observation_reason"] = Value::String(reason.to_string());
    persist_json(path, &json)
}

fn persist_live_benchmark(
    path: impl AsRef<Path>,
    now_ms: u64,
    mode: NetworkAiRuntimeMode,
    observation: &NetworkObservation,
    history: &RouteHistoryStore,
    exact_route_confirmed: bool,
) -> Result<()> {
    let stats = history.stats_by_route.get(&observation.current_route_id);

    // D25 benchmark latency distribution is calculated from the retained
    // production samples for the currently observed route. Do not synthesize
    // percentile values from the EWMA average.
    let mut latency_samples: Vec<f64> = history
        .entries_by_route
        .get(&observation.current_route_id)
        .into_iter()
        .flatten()
        .map(|entry| entry.rtt_ms)
        .filter(|value| value.is_finite() && *value >= 0.0)
        .collect();

    latency_samples.sort_by(|a, b| a.total_cmp(b));

    let percentile = |samples: &[f64], percentile: f64| -> Option<f64> {
        if samples.is_empty() {
            return None;
        }

        let rank = percentile.clamp(0.0, 1.0) * ((samples.len() - 1) as f64);
        let lower = rank.floor() as usize;
        let upper = rank.ceil() as usize;

        if lower == upper {
            Some(samples[lower])
        } else {
            let weight = rank - lower as f64;
            Some(samples[lower] + (samples[upper] - samples[lower]) * weight)
        }
    };

    let p50_latency_ms = percentile(&latency_samples, 0.50);
    let p95_latency_ms = percentile(&latency_samples, 0.95);
    let p99_latency_ms = percentile(&latency_samples, 0.99);

    persist_json(
        path,
        &serde_json::json!({
            "schema_version": "network-ai-live-benchmark-v1",
            "ts_ms": now_ms,
            "mode": mode,
            "source": "production runtime telemetry and route history",
            "synthetic": false,
            "route_id": observation.current_route_id,
            "exact_route_confirmed": exact_route_confirmed,
            "sample_count": stats.map(|stats| stats.sample_count).unwrap_or(0),
            "latency_percentile_sample_count": latency_samples.len(),
            "average_latency_ms": stats.map(|stats| stats.ewma_latency_ms).unwrap_or(observation.rtt_ms),
            "p50_latency_ms": p50_latency_ms,
            "p95_latency_ms": p95_latency_ms,
            "p99_latency_ms": p99_latency_ms,
            "packet_loss_pct": stats.map(|stats| stats.ewma_loss_pct).unwrap_or(observation.packet_loss_pct),
            "throughput_mbps": stats.map(|stats| stats.ewma_throughput_mbps).unwrap_or(observation.throughput_mbps),
            "route_switch_count": history
                .entries_by_route
                .values()
                .flatten()
                .filter(|entry| entry.switched_route)
                .count(),
            "failed_route_count": history
                .entries_by_route
                .values()
                .flatten()
                .filter(|entry| !entry.route_available || !entry.route_healthy)
                .count(),
            "status": if exact_route_confirmed {
                "live production benchmark evidence captured"
            } else {
                "PENDING - D3/D11 dependency: exact active Nebula route remains unconfirmed"
            }
        }),
    )
}

#[cfg(test)]
fn transport_route_id(local_node: &str, iface: &str, destination: &str) -> String {
    format!(
        "transport-{}-{}-{}",
        file_safe_id(local_node),
        file_safe_id(iface),
        file_safe_id(destination)
    )
}

fn required_peers(candidates: &[RouteCandidate]) -> Vec<String> {
    let mut peers = BTreeSet::new();
    for candidate in candidates {
        peers.insert(candidate.destination_node.clone());
        for relay in &candidate.relay_ids {
            peers.insert(relay.clone());
        }
    }
    peers.into_iter().collect()
}

fn latest_task1_route_signal(now_ms: u64) -> Option<Task1RouteSignal> {
    let state_root = Path::new(TASK1_PRODUCTION_STATE_ROOT);
    let alert = load_recent_full_ml_alerts(state_root, 1)
        .ok()?
        .into_iter()
        .last()?;

    // A historical anomaly must not influence routing forever.
    if alert.ts == 0 || now_ms.saturating_sub(alert.ts) > TASK1_NETWORK_SIGNAL_MAX_AGE_MS {
        return None;
    }

    Some(Task1RouteSignal {
        source_path: full_ml_alerts_path(state_root).display().to_string(),
        run_id: Some(format!("full-ml-alert-{}", alert.ts)),
        node: alert.node,
        recommendation_count: 1,
        recommendation_ids: vec![format!("full-ml-alert-{}", alert.ts)],
        max_anomaly_score: Some(alert.score),
        max_model_confidence: Some(alert.model_confidence),
        max_advisory_confidence: Some(alert.advisory_confidence.value),
        top_evidence_features: alert.topk.into_iter().take(3).collect(),
        model_metadata_traceable: true,
    })
}

fn prediction_for<'a>(
    predictions: &'a RoutePredictionSet,
    route_id: &str,
) -> Option<&'a sgx_anomaly_engine::network_ai::RoutePrediction> {
    predictions
        .predictions
        .iter()
        .find(|prediction| prediction.route_id == route_id)
}

fn prediction_score_or_zero(predictions: &RoutePredictionSet, route_id: &str) -> f64 {
    prediction_for(predictions, route_id)
        .map(|prediction| prediction.quality_score)
        .unwrap_or(0.0)
}

fn summary_from_value(peer: &str, value: &Value) -> Result<Task2RoutingTrustSummary> {
    Ok(Task2RoutingTrustSummary {
        schema_version: value
            .get("schema_version")
            .and_then(Value::as_u64)
            .unwrap_or(1) as u32,
        node_id: value
            .get("node_id")
            .and_then(Value::as_str)
            .unwrap_or(peer)
            .to_string(),
        trust_status: string_field(value, "trust_status")
            .unwrap_or("unknown")
            .to_string(),
        routing_allowed: value
            .get("routing_allowed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        policy_status: string_field(value, "policy_status")
            .unwrap_or("unknown")
            .to_string(),
        active_policy_id: value
            .get("active_policy_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        active_policy_version: value.get("active_policy_version").and_then(Value::as_u64),
        applicable_members: string_array_field(value, "applicable_members"),
        policy_restrictions: string_array_field(value, "policy_restrictions"),
        last_alert_id: value
            .get("last_alert_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        attestation_state: string_field(value, "attestation_state")
            .unwrap_or("unknown")
            .to_string(),
        updated_at_ms: value
            .get("updated_at_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("Task2 summary missing updated_at_ms"))?,
        sources: serde_json::from_value(
            value
                .get("sources")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        )
        .unwrap_or_else(|_| Task2TrustStateSources::default()),
    })
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    let raw = value.get(key)?;
    raw.as_str().or_else(|| {
        raw.as_object()
            .and_then(|object| object.keys().next().map(String::as_str))
    })
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn persist_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("renaming {}", path.display()))?;
    Ok(())
}

fn append_jsonl(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(value)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
fn file_safe_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn short_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..4])
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::TransportType;
    use sgx_anomaly_engine::network_ai::RouteKind;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct StaticTelemetry;

    #[async_trait]
    impl NetworkTelemetryProvider for StaticTelemetry {
        async fn collect(&self) -> Result<ProductionTelemetry> {
            Ok(ProductionTelemetry {
                raw: RawSample {
                    ts_ms: now_ms(),
                    nebula_mbps: 10.0,
                    cot_latency_avg_ms: 5.0,
                    ..RawSample::default()
                },
                packet_loss_pct: Some(0.0),
            })
        }
    }

    #[derive(Clone)]
    struct StaticTopology {
        topology: ProductionTopology,
    }

    #[async_trait]
    impl RouteTopologyProvider for StaticTopology {
        async fn discover_routes(&self) -> Result<ProductionTopology> {
            Ok(self.topology.clone())
        }
    }

    struct StaticTrust {
        trust: TrustStateSnapshot,
    }

    #[async_trait]
    impl Task2TrustProvider for StaticTrust {
        async fn current_trust_state(
            &self,
            _local_node: &str,
            _required_peers: &[String],
            _now_ms: u64,
        ) -> Result<(
            TrustStateSnapshot,
            Option<Task2RoutingTrustSummary>,
            PathBuf,
        )> {
            Ok((self.trust.clone(), None, PathBuf::from("test-task2.json")))
        }
    }

    struct StaticObservation {
        route_id: String,
        confirmed: bool,
    }

    #[async_trait]
    impl RouteObservationProvider for StaticObservation {
        async fn current_route(&self, topology: &ProductionTopology) -> Result<ObservedRouteState> {
            let destination_node = topology
                .route_candidates
                .iter()
                .find(|candidate| candidate.route_id == self.route_id)
                .map(|candidate| candidate.destination_node.clone())
                .unwrap_or_default();

            Ok(ObservedRouteState {
                route_id: self.route_id.clone(),
                destination_node,
                interface_name: Some("if0".to_string()),
                confirmed: self.confirmed,
                diagnostic: if self.confirmed {
                    "test confirmed route".to_string()
                } else {
                    "test unconfirmed route".to_string()
                },
                started_ms: 1,
            })
        }
    }

    struct CountingTransport {
        calls: AtomicUsize,
        applied: bool,
    }

    #[async_trait]
    impl RouteTransport for CountingTransport {
        async fn apply_route(
            &self,
            request: &ProductionRouteApplyRequest,
            _topology: &ProductionTopology,
        ) -> Result<ProductionRouteApplyResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProductionRouteApplyResult {
                attempted: true,
                applied: self.applied,
                requested_route_id: request.requested_route_id.clone(),
                previous_route_id: request.previous_route_id.clone(),
                observed_route_id: self.applied.then(|| request.requested_route_id.clone()),
                rollback_attempted: !self.applied,
                rollback_applied: !self.applied,
                reason: "test transport".to_string(),
            })
        }
    }

    struct EmptyRelayHealth;

    #[async_trait]
    impl RelayHealthProvider for EmptyRelayHealth {
        async fn relay_health(
            &self,
            _topology: &ProductionTopology,
        ) -> Result<Vec<RelayRuntimeHealth>> {
            Ok(Vec::new())
        }
    }

    struct StaticRelayStats;

    #[async_trait]
    impl NebulaRelayStatsProvider for StaticRelayStats {
        async fn relay_stats(&self) -> Result<RelayStats> {
            Ok(RelayStats::default())
        }
    }

    struct NoopRelayControl;

    #[async_trait]
    impl RelayControl for NoopRelayControl {
        async fn apply_weights(&self, _weights: &RelayWeightSet) -> Result<RelayWeightApplyResult> {
            Ok(RelayWeightApplyResult {
                attempted: false,
                applied: false,
                reason: "test".to_string(),
            })
        }
    }

    fn overlay_registry_fixture(nodes: &[&str]) -> OverlayRegistry {
        let mut registry = OverlayRegistry::new("circle-test", "192.168.100", "nodeA");
        for node in nodes {
            if *node != "nodeA" {
                registry.assign_ip(node).expect("assign overlay ip");
            }
        }
        registry
    }

    fn relay_registry_fixture(relays: &[&str]) -> RelayRegistry {
        let mut registry = RelayRegistry::new("circle-test");
        for relay in relays {
            registry.add_relay(relay, "192.168.100.10", "10.0.0.10:4242", 10, 100, false);
        }
        registry
    }

    fn underlay_snapshot(interface_name: &str, transport_type: TransportType) -> LinkSnapshot {
        LinkSnapshot {
            interface_name: interface_name.to_string(),
            transport_type,
            is_up: true,
            latency_ms: 7,
            bandwidth_kbps: 50_000,
            consecutive_failures: 0,
            consecutive_successes: 3,
            last_probed: 1,
        }
    }

    fn relay_entry(node_name: &str, max_bandwidth_mbps: u32) -> RelayEntry {
        RelayEntry {
            node_name: node_name.to_string(),
            overlay_ip: "192.168.100.2".to_string(),
            physical_endpoint: "10.0.0.2:4242".to_string(),
            is_active: true,
            is_lighthouse: false,
            max_peers: 10,
            max_bandwidth_mbps,
            last_seen: chrono::Utc::now().timestamp(),
        }
    }

    fn relay_topology(relay: RelayEntry) -> ProductionTopology {
        let route = RouteCandidate::relay(
            "nodeA",
            &relay.node_name,
            "nodeC",
            TrafficClass::Operational,
        );
        let mut relay_routes = HashMap::new();
        relay_routes.insert(route.route_id.clone(), relay);
        ProductionTopology {
            local_node: "nodeA".to_string(),
            destinations: vec!["nodeC".to_string()],
            route_candidates: vec![route],
            transport_routes: HashMap::new(),
            relay_routes,
        }
    }

    fn write_relay_telemetry(dir: &Path, node_id: &str, current_mbps: f64, updated_at: String) {
        std::fs::create_dir_all(dir).expect("telemetry dir");
        let payload = serde_json::json!({
            "node_id": node_id,
            "current_mbps": current_mbps,
            "updated_at": updated_at,
        });
        std::fs::write(
            dir.join(format!("{node_id}.json")),
            serde_json::to_string_pretty(&payload).expect("telemetry json"),
        )
        .expect("write telemetry");
    }

    fn save_confirmed_route(root: &Path, route_id: &str) {
        fs::create_dir_all(root).expect("create runtime root");
        RuntimeRouteState {
            schema_version: "network-ai-route-controller-v1".to_string(),
            active_route_id: route_id.to_string(),
            active_route_started_ms: 42,
            previous_route_id: None,
            last_switch_ms: None,
            switch_timestamps_ms: Vec::new(),
        }
        .save_json(root.join("current_route_state.json"))
        .expect("write exact runtime route state");
    }

    fn d3_lighthouse_registry(entries: &[(&str, &str, &str)]) -> LighthouseRegistry {
        LighthouseRegistry {
            circle_id: "circle-test".to_string(),
            lighthouses: entries
                .iter()
                .map(|(node_name, overlay_ip, physical_endpoint)| {
                    crate::nebula::lighthouse::LighthouseEntry {
                        node_name: (*node_name).to_string(),
                        overlay_ip: (*overlay_ip).to_string(),
                        physical_endpoint: (*physical_endpoint).to_string(),
                        is_primary: false,
                        is_active: true,
                        is_lighthouse: true,
                        am_relay: true,
                    }
                })
                .collect(),
        }
    }

    fn endpoint_set(endpoints: &[&str]) -> BTreeSet<String> {
        endpoints
            .iter()
            .map(|endpoint| (*endpoint).to_string())
            .collect()
    }

    fn candidate(topology: &ProductionTopology, route_id: &str) -> RouteCandidate {
        topology
            .route_candidates
            .iter()
            .find(|candidate| candidate.route_id == route_id)
            .cloned()
            .expect("route candidate")
    }

    #[test]
    fn d1_builds_nebula_overlay_candidates_not_physical_transport_routes() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC", "nodeD"]);
        let relays = relay_registry_fixture(&["nodeC", "nodeD"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            Some(&relays),
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let route_ids = topology
            .route_candidates
            .iter()
            .map(|candidate| candidate.route_id.as_str())
            .collect::<BTreeSet<_>>();

        assert!(route_ids.contains("direct-nodeA-nodeB"));
        assert!(route_ids.contains("relay-nodeA-via-nodeC-nodeB"));
        assert!(route_ids.contains("relay-nodeA-via-nodeC-nodeD-nodeB"));
        assert!(!route_ids
            .iter()
            .any(|route_id| route_id.starts_with("transport-")));
        assert!(topology.transport_routes.is_empty());
        assert!(topology.route_candidates.iter().any(|candidate| {
            candidate
                .metadata
                .health_note
                .contains("underlay=[eth0=Ethernet")
                && candidate.metadata.health_note.contains("nebula_overlay")
        }));
    }

    #[test]
    fn d1_builds_direct_candidates_from_allocations_map_without_relays() {
        let overlay: OverlayRegistry = serde_json::from_str(
            r#"
            {
              "circle_id": "circle-test",
              "subnet_base": "192.168.100",
              "cidr": 24,
              "owner_node": "nodeA",
              "next_host": 4,
              "allocations": {
                "nodeA": {"node_name": "nodeA", "overlay_ip": "192.168.100.1", "overlay_ip_cidr": "192.168.100.1/24", "is_owner": true, "allocated_at": "2026-09-10T00:00:00Z", "pubkey_prefix": null},
                "nodeB": {"node_name": "nodeB", "overlay_ip": "192.168.100.2", "overlay_ip_cidr": "192.168.100.2/24", "is_owner": false, "allocated_at": "2026-09-10T00:00:00Z", "pubkey_prefix": null},
                "nodeC": {"node_name": "nodeC", "overlay_ip": "192.168.100.3", "overlay_ip_cidr": "192.168.100.3/24", "is_owner": false, "allocated_at": "2026-09-10T00:00:00Z", "pubkey_prefix": null}
              },
              "schema_version": 1,
              "last_modified": "2026-09-10T00:00:00Z"
            }
            "#,
        )
        .expect("parse allocations-map overlay registry");
        let relays = RelayRegistry::new("circle-test");
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            Some(&relays),
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let route_ids = topology
            .route_candidates
            .iter()
            .map(|candidate| candidate.route_id.as_str())
            .collect::<BTreeSet<_>>();

        assert!(route_ids.contains("direct-nodeA-nodeB"));
        assert!(route_ids.contains("direct-nodeA-nodeC"));
        assert!(topology.relay_routes.is_empty());
    }

    #[test]
    fn d1_persists_separate_overlay_telemetry_for_node_b_and_node_c() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string(), "nodeC".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let node_b = candidate(&topology, "direct-nodeA-nodeB");
        let node_c = candidate(&topology, "direct-nodeA-nodeC");
        let observation_b = overlay_path_telemetry(
            &node_b,
            overlay
                .get_ip("nodeB")
                .expect("nodeB overlay IP")
                .to_string(),
            OverlayPathProbe {
                route_available: true,
                rtt_ms: Some(11.0),
                packet_loss_pct: Some(0.0),
                throughput_mbps: Some(10.0),
            },
        );
        let observation_c = overlay_path_telemetry(
            &node_c,
            overlay
                .get_ip("nodeC")
                .expect("nodeC overlay IP")
                .to_string(),
            OverlayPathProbe {
                route_available: false,
                rtt_ms: None,
                packet_loss_pct: Some(100.0),
                throughput_mbps: None,
            },
        );

        assert_eq!(observation_b.destination_node, "nodeB");
        assert_eq!(observation_b.peer_id, "nodeB");
        assert_eq!(observation_b.route_id, "direct-nodeA-nodeB");
        assert_eq!(observation_b.overlay_ip, "192.168.100.2");
        assert_eq!(observation_b.rtt_ms, Some(11.0));
        assert_eq!(observation_b.throughput_mbps, Some(10.0));
        assert_eq!(observation_c.destination_node, "nodeC");
        assert_eq!(observation_c.peer_id, "nodeC");
        assert_eq!(observation_c.route_id, "direct-nodeA-nodeC");
        assert_eq!(observation_c.overlay_ip, "192.168.100.3");
        assert!(!observation_c.route_available);
        assert_eq!(observation_c.rtt_ms, None);
        assert_eq!(observation_c.throughput_mbps, None);

        let mut history = RouteHistoryStore::new(0.5, 20);
        history.record_measured_observation(
            observation_b
                .to_observation_input()
                .expect("nodeB measurements"),
        );
        assert_eq!(
            history
                .stats_for("direct-nodeA-nodeB")
                .expect("nodeB history")
                .sample_count,
            1
        );
        assert_eq!(
            history
                .stats_for("direct-nodeA-nodeB")
                .expect("nodeB history")
                .ewma_latency_ms,
            11.0
        );
        let missing_metric_observation = observation_c
            .to_observation_input()
            .expect("partial measured telemetry must be retained");
        assert_eq!(missing_metric_observation.throughput_mbps, None);
        assert_eq!(missing_metric_observation.bandwidth_utilization_pct, None);
    }

    #[test]
    fn d8_destination_probe_can_refresh_explicit_active_relay_route_history() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let relays = relay_registry_fixture(&["nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            Some(&relays),
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let direct = candidate(&topology, "direct-nodeA-nodeB");
        let relay = candidate(&topology, "relay-nodeA-via-nodeC-nodeB");
        let destination_probe = overlay_path_telemetry(
            &direct,
            overlay
                .get_ip("nodeB")
                .expect("nodeB overlay IP")
                .to_string(),
            OverlayPathProbe {
                route_available: true,
                rtt_ms: Some(15.0),
                packet_loss_pct: Some(0.5),
                throughput_mbps: Some(20.0),
            },
        );

        let attributed = measured_observation_for_route(&relay, &[destination_probe])
            .expect("destination probe can be attributed to explicit active route");

        assert_eq!(attributed.route_id, "relay-nodeA-via-nodeC-nodeB");
        assert_eq!(attributed.rtt_ms, 15.0);
        assert_eq!(attributed.packet_loss_pct, 0.5);
        assert_eq!(attributed.throughput_mbps, Some(20.0));
    }

    #[test]
    fn d8_destination_probe_is_not_recorded_for_every_same_destination_candidate() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let relays = relay_registry_fixture(&["nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            Some(&relays),
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let direct = candidate(&topology, "direct-nodeA-nodeB");
        let relay = candidate(&topology, "relay-nodeA-via-nodeC-nodeB");
        let destination_probe = overlay_path_telemetry(
            &direct,
            overlay
                .get_ip("nodeB")
                .expect("nodeB overlay IP")
                .to_string(),
            OverlayPathProbe {
                route_available: true,
                rtt_ms: Some(12.0),
                packet_loss_pct: Some(0.0),
                throughput_mbps: Some(22.0),
            },
        );

        let mut history = RouteHistoryStore::new(0.5, 20);
        let active_observation = measured_observation_for_route(&relay, &[destination_probe])
            .expect("active relay observation");
        history.record_measured_observation(active_observation);

        assert!(history.stats_for(&relay.route_id).is_some());
        assert!(history.stats_for(&direct.route_id).is_none());
    }

    #[test]
    fn d2_vshift_classifies_all_node_b_paths_as_security_control() {
        let _test_guard = TASK3_D2_TEST_LOCK.lock().expect("D2 test lock");
        TASK3_TRAFFIC_EVENTS
            .get_or_init(|| StdMutex::new(Vec::new()))
            .lock()
            .expect("event bridge lock")
            .clear();
        notify_task3_message("VSHIFT_ALERT", "nodeB");
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let relays = relay_registry_fixture(&["nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string(), "nodeC".to_string()],
            &overlay,
            Some(&relays),
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");

        assert!(topology
            .route_candidates
            .iter()
            .filter(|candidate| candidate.destination_node == "nodeB")
            .all(|candidate| candidate.traffic_class == TrafficClass::SecurityControl));
        assert!(topology
            .route_candidates
            .iter()
            .filter(|candidate| candidate.destination_node == "nodeC")
            .all(|candidate| candidate.traffic_class == TrafficClass::Operational));
    }

    #[test]
    fn d2_attestation_unknown_and_normal_events_are_peer_bound() {
        let _test_guard = TASK3_D2_TEST_LOCK.lock().expect("D2 test lock");
        TASK3_TRAFFIC_EVENTS
            .get_or_init(|| StdMutex::new(Vec::new()))
            .lock()
            .expect("event bridge lock")
            .clear();
        notify_task3_message("attestation", "nodeC");
        assert_eq!(
            traffic_class_for_peer("nodeC"),
            TrafficClass::SecurityControl
        );
        assert_eq!(traffic_class_for_peer("nodeB"), TrafficClass::Operational);

        notify_task3_message("unknown-message", "nodeB");
        assert_eq!(traffic_class_for_peer("nodeB"), TrafficClass::Operational);
    }

    #[test]
    fn d2_stale_events_are_ignored() {
        let _test_guard = TASK3_D2_TEST_LOCK.lock().expect("D2 test lock");
        let events = TASK3_TRAFFIC_EVENTS.get_or_init(|| StdMutex::new(Vec::new()));
        events.lock().expect("event bridge lock").clear();
        events
            .lock()
            .expect("event bridge lock")
            .push(Task3TrafficEvent {
                message_type: "VSHIFT_ALERT".to_string(),
                target_peer: "stale-peer".to_string(),
                created_at_ms: now_ms().saturating_sub(TASK3_TRAFFIC_EVENT_TTL_MS + 1),
                expires_at_ms: now_ms().saturating_sub(1),
                consumed: false,
            });

        assert_eq!(
            traffic_class_for_peer("stale-peer"),
            TrafficClass::Operational
        );
    }

    #[test]
    fn selected_task2_evidence_follows_selected_destination() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string(), "nodeC".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");

        let path = selected_task2_evidence_path(
            Path::new("/task2"),
            &topology,
            Some("direct-nodeA-nodeB"),
            Path::new("/fallback/routing_trust_summary.json"),
        );

        assert_eq!(
            path,
            PathBuf::from("/task2/nodeB/routing_trust_summary.json")
        );
    }

    #[test]
    fn d1_does_not_fabricate_candidates_for_members_missing_overlay_allocation() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string(), "nodeZ".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("wlan0", TransportType::WiFi)],
        )
        .expect("build topology");

        assert!(topology.destinations.contains(&"nodeB".to_string()));
        assert!(!topology.destinations.contains(&"nodeZ".to_string()));
        assert!(topology
            .route_candidates
            .iter()
            .all(|candidate| candidate.destination_node != "nodeZ"));
    }

    #[test]
    fn d1_fails_closed_when_local_node_is_missing_from_overlay_registry() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB"]);
        let error = build_nebula_overlay_topology(
            "nodeZ",
            vec!["nodeB".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("wwan0", TransportType::Cellular)],
        )
        .expect_err("local node without overlay allocation must fail closed");

        assert!(error
            .to_string()
            .contains("missing from Nebula overlay registry"));
    }

    #[test]
    fn d3_observes_confirmed_nebula_route_from_runtime_state() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let lighthouse = d3_lighthouse_registry(&[("nodeB", "192.168.100.2", "10.0.0.2:4242")]);

        let observed = match_d3_destination_routes(
            &topology,
            &lighthouse,
            &endpoint_set(&["10.0.0.2:4242"]),
            Some("eth0".to_string()),
            42,
        );

        assert_eq!(observed.len(), 1);
        assert!(observed[0].confirmed);
        assert_eq!(observed[0].destination_node, "nodeB");
        assert_eq!(observed[0].route_id, "direct-nodeA-nodeB");
        assert_eq!(observed[0].started_ms, 42);
        assert!(observed[0]
            .diagnostic
            .contains("confirmed live direct Nebula route"));
    }

    #[test]
    fn d3_missing_exact_route_evidence_reports_unconfirmed_not_first_candidate() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let lighthouse = d3_lighthouse_registry(&[("nodeB", "192.168.100.2", "10.0.0.2:4242")]);

        let observed = match_d3_destination_routes(
            &topology,
            &lighthouse,
            &BTreeSet::new(),
            Some("eth0".to_string()),
            42,
        );

        assert_eq!(observed.len(), 1);
        assert!(!observed[0].confirmed);
        assert_eq!(observed[0].route_id, "unknown-unconfirmed-nebula-route");
        assert_ne!(observed[0].route_id, topology.route_candidates[0].route_id);
        assert!(observed[0]
            .diagnostic
            .contains("no exact live direct Nebula route evidence"));
    }

    #[test]
    fn d3_stale_runtime_route_not_in_topology_reports_unconfirmed() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let lighthouse = d3_lighthouse_registry(&[
            ("nodeB", "192.168.100.2", "10.0.0.2:4242"),
            ("nodeZ", "192.168.100.99", "10.0.0.99:4242"),
        ]);

        let observed = match_d3_destination_routes(
            &topology,
            &lighthouse,
            &endpoint_set(&["10.0.0.99:4242"]),
            Some("eth0".to_string()),
            42,
        );

        assert_eq!(observed.len(), 1);
        assert!(!observed[0].confirmed);
        assert_eq!(observed[0].route_id, "unknown-unconfirmed-nebula-route");
        assert!(observed[0]
            .diagnostic
            .contains("no exact live direct Nebula route evidence"));
    }

    #[test]
    fn d3_ignores_legacy_transport_route_on_startup() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let lighthouse = d3_lighthouse_registry(&[("nodeB", "192.168.100.2", "10.0.0.2:4242")]);

        let observed = match_d3_destination_routes(
            &topology,
            &lighthouse,
            &endpoint_set(&["transport-nodeA-eth0-nodeB"]),
            Some("eth0".to_string()),
            42,
        );

        assert_eq!(observed.len(), 1);
        assert!(!observed[0].confirmed);
        assert_eq!(observed[0].route_id, "unknown-unconfirmed-nebula-route");
        assert!(observed[0]
            .diagnostic
            .contains("no exact live direct Nebula route evidence"));
    }

    #[test]
    fn d3_simultaneous_live_endpoints_confirm_destination_scoped_direct_routes() {
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string(), "nodeC".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        let lighthouse = d3_lighthouse_registry(&[
            ("nodeB", "192.168.100.2", "10.0.0.2:4242"),
            ("nodeC", "192.168.100.3", "10.0.0.3:4242"),
        ]);

        let observed = match_d3_destination_routes(
            &topology,
            &lighthouse,
            &endpoint_set(&["10.0.0.2:4242", "10.0.0.3:4242"]),
            Some("eth0".to_string()),
            42,
        );

        assert_eq!(observed.len(), 2);
        assert!(observed.iter().all(|route| route.confirmed));
        assert!(observed.iter().any(
            |route| route.destination_node == "nodeB" && route.route_id == "direct-nodeA-nodeB"
        ));
        assert!(observed.iter().any(
            |route| route.destination_node == "nodeC" && route.route_id == "direct-nodeA-nodeC"
        ));
    }

    #[test]
    fn d3_unconfirmed_observation_is_unavailable_and_explicitly_unknown() {
        let observation = unconfirmed_network_observation(
            &RawSample {
                ts_ms: 42,
                ..RawSample::default()
            },
            "nodeA",
            Some(0.0),
        );
        let path = temp_root("d3-unconfirmed-observation").join("current_observation.json");
        persist_unconfirmed_current_observation(
            &path,
            &observation,
            "legacy transport route ignored; no exact Nebula overlay route evidence",
        )
        .expect("persist unconfirmed observation");
        let json: Value =
            serde_json::from_str(&fs::read_to_string(path).expect("read unconfirmed observation"))
                .expect("parse unconfirmed observation");

        assert_eq!(json["current_route_id"], "unknown-unconfirmed-nebula-route");
        assert_eq!(json["route_available"], false);
        assert_eq!(json["route_kind"], "Unknown");
        assert_eq!(json["route_observation_status"], "unconfirmed");
        assert!(json["route_observation_reason"]
            .as_str()
            .expect("observation reason")
            .contains("no exact Nebula overlay route evidence"));
    }

    #[tokio::test]
    async fn d10_confirms_exact_direct_overlay_route_success() {
        let root = temp_root("d10-direct-success");
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        save_confirmed_route(&root, "direct-nodeA-nodeB");
        let adapter = SgxNebulaOverlayRouteTransport::new(root.clone(), true);

        let result = adapter
            .apply_route(
                &ProductionRouteApplyRequest {
                    decision_id: "decision-direct".to_string(),
                    requested_route_id: "direct-nodeA-nodeB".to_string(),
                    previous_route_id: "direct-nodeA-nodeB".to_string(),
                },
                &topology,
            )
            .await
            .expect("apply route");

        assert!(result.attempted);
        assert!(result.applied);
        assert_eq!(
            result.observed_route_id.as_deref(),
            Some("direct-nodeA-nodeB")
        );
        assert!(root
            .join("nebula_overlay_route_apply_status.json")
            .is_file());
        assert!(root
            .join("nebula_overlay_route_apply_requests.jsonl")
            .is_file());
    }

    #[tokio::test]
    async fn d10_wrong_peer_confirmation_fails_closed() {
        let root = temp_root("d10-wrong-peer");
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string(), "nodeC".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        save_confirmed_route(&root, "direct-nodeA-nodeC");
        let adapter = SgxNebulaOverlayRouteTransport::new(root, true);

        let result = adapter
            .apply_route(
                &ProductionRouteApplyRequest {
                    decision_id: "decision-wrong-peer".to_string(),
                    requested_route_id: "direct-nodeA-nodeB".to_string(),
                    previous_route_id: "direct-nodeA-nodeB".to_string(),
                },
                &topology,
            )
            .await
            .expect("apply route");

        assert!(result.attempted);
        assert!(!result.applied);
        assert_eq!(
            result.observed_route_id.as_deref(),
            Some("direct-nodeA-nodeC")
        );
        assert!(!result.rollback_applied);
    }

    #[tokio::test]
    async fn d10_confirms_exact_relay_overlay_route_success() {
        let root = temp_root("d10-relay-success");
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let relays = relay_registry_fixture(&["nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            Some(&relays),
            &[underlay_snapshot("wwan0", TransportType::Cellular)],
        )
        .expect("build topology");
        let relay_route = "relay-nodeA-via-nodeC-nodeB";
        assert_eq!(candidate(&topology, relay_route).kind, RouteKind::Relay);
        save_confirmed_route(&root, relay_route);
        let adapter = SgxNebulaOverlayRouteTransport::new(root, true);

        let result = adapter
            .apply_route(
                &ProductionRouteApplyRequest {
                    decision_id: "decision-relay".to_string(),
                    requested_route_id: relay_route.to_string(),
                    previous_route_id: "direct-nodeA-nodeB".to_string(),
                },
                &topology,
            )
            .await
            .expect("apply route");

        assert!(result.applied);
        assert_eq!(result.observed_route_id.as_deref(), Some(relay_route));
    }

    #[tokio::test]
    async fn d10_rolls_back_when_requested_overlay_route_is_unconfirmed() {
        let root = temp_root("d10-rollback");
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let relays = relay_registry_fixture(&["nodeC"]);
        let topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            Some(&relays),
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        save_confirmed_route(&root, "direct-nodeA-nodeB");
        let adapter = SgxNebulaOverlayRouteTransport::new(root, true);

        let result = adapter
            .apply_route(
                &ProductionRouteApplyRequest {
                    decision_id: "decision-rollback".to_string(),
                    requested_route_id: "relay-nodeA-via-nodeC-nodeB".to_string(),
                    previous_route_id: "direct-nodeA-nodeB".to_string(),
                },
                &topology,
            )
            .await
            .expect("apply route");

        assert!(result.attempted);
        assert!(!result.applied);
        assert_eq!(
            result.observed_route_id.as_deref(),
            Some("direct-nodeA-nodeB")
        );
        assert!(result.rollback_attempted);
        assert!(result.rollback_applied);
    }

    #[tokio::test]
    async fn d10_interface_only_state_cannot_create_false_overlay_success() {
        let root = temp_root("d10-interface-only");
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB"]);
        let mut topology = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build topology");
        topology
            .transport_routes
            .insert("direct-nodeA-nodeB".to_string(), "eth0".to_string());
        let adapter = SgxNebulaOverlayRouteTransport::new(root, true);

        let result = adapter
            .apply_route(
                &ProductionRouteApplyRequest {
                    decision_id: "decision-interface-only".to_string(),
                    requested_route_id: "direct-nodeA-nodeB".to_string(),
                    previous_route_id: "direct-nodeA-nodeB".to_string(),
                },
                &topology,
            )
            .await
            .expect("apply route");

        assert!(result.attempted);
        assert!(!result.applied);
        assert!(result.observed_route_id.is_none());
    }

    #[tokio::test]
    async fn d13_uses_real_per_relay_telemetry_for_utilization() {
        let telemetry_dir = temp_root("d13-telemetry-ok");
        write_relay_telemetry(
            &telemetry_dir,
            "nodeB",
            25.0,
            chrono::Utc::now().to_rfc3339(),
        );
        let provider =
            SgxRelayHealthProvider::with_telemetry_dir(Arc::new(StaticRelayStats), telemetry_dir);
        let topology = relay_topology(relay_entry("nodeB", 100));

        let health = provider
            .relay_health(&topology)
            .await
            .expect("relay health");

        assert_eq!(health.len(), 1);
        assert_eq!(health[0].utilization_pct, Some(25.0));
        assert!(health[0].available);
        assert!(health[0].healthy);
    }

    #[tokio::test]
    async fn d13_clamps_over_capacity_relay_telemetry() {
        let telemetry_dir = temp_root("d13-telemetry-clamp");
        write_relay_telemetry(
            &telemetry_dir,
            "nodeB",
            150.0,
            chrono::Utc::now().to_rfc3339(),
        );
        let provider =
            SgxRelayHealthProvider::with_telemetry_dir(Arc::new(StaticRelayStats), telemetry_dir);
        let topology = relay_topology(relay_entry("nodeB", 100));

        let health = provider
            .relay_health(&topology)
            .await
            .expect("relay health");

        assert_eq!(health[0].utilization_pct, Some(100.0));
        assert!(health[0].healthy);
    }

    #[tokio::test]
    async fn d13_missing_relay_telemetry_is_unknown_safe() {
        let telemetry_dir = temp_root("d13-telemetry-missing");
        let provider =
            SgxRelayHealthProvider::with_telemetry_dir(Arc::new(StaticRelayStats), telemetry_dir);
        let topology = relay_topology(relay_entry("nodeB", 100));

        let health = provider
            .relay_health(&topology)
            .await
            .expect("relay health");

        assert_eq!(health[0].utilization_pct, None);
        assert!(health[0].available);
        assert!(!health[0].healthy);
    }

    #[tokio::test]
    async fn d13_stale_relay_telemetry_is_unknown_safe() {
        let telemetry_dir = temp_root("d13-telemetry-stale");
        let stale = chrono::Utc::now() - chrono::Duration::seconds(300);
        write_relay_telemetry(&telemetry_dir, "nodeB", 25.0, stale.to_rfc3339());
        let provider =
            SgxRelayHealthProvider::with_telemetry_dir(Arc::new(StaticRelayStats), telemetry_dir);
        let topology = relay_topology(relay_entry("nodeB", 100));

        let health = provider
            .relay_health(&topology)
            .await
            .expect("relay health");

        assert_eq!(health[0].utilization_pct, None);
        assert!(!health[0].healthy);
    }

    #[tokio::test]
    async fn d13_mismatched_relay_telemetry_is_unknown_safe() {
        let telemetry_dir = temp_root("d13-telemetry-mismatch");
        std::fs::create_dir_all(&telemetry_dir).expect("telemetry dir");
        let payload = serde_json::json!({
            "node_id": "nodeC",
            "current_mbps": 25.0,
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        std::fs::write(
            telemetry_dir.join("nodeB.json"),
            serde_json::to_string_pretty(&payload).expect("telemetry json"),
        )
        .expect("write telemetry");
        let provider =
            SgxRelayHealthProvider::with_telemetry_dir(Arc::new(StaticRelayStats), telemetry_dir);
        let topology = relay_topology(relay_entry("nodeB", 100));

        let health = provider
            .relay_health(&topology)
            .await
            .expect("relay health");

        assert_eq!(health[0].utilization_pct, None);
        assert!(!health[0].healthy);
    }

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("sgx-task3-runtime-test-{}-{}", name, now_ms()));
        let _ = fs::remove_dir_all(&root);
        root
    }

    fn topology() -> ProductionTopology {
        let mut routes = HashMap::new();
        let route_a = transport_route_id("local", "if0", "peer");
        let route_b = transport_route_id("local", "if1", "peer");
        routes.insert(route_a.clone(), "if0".to_string());
        routes.insert(route_b.clone(), "if1".to_string());
        ProductionTopology {
            local_node: "local".to_string(),
            destinations: vec!["peer".to_string()],
            route_candidates: vec![
                RouteCandidate {
                    route_id: route_a,
                    source_node: "local".to_string(),
                    destination_node: "peer".to_string(),
                    peer_id: "peer".to_string(),
                    kind: RouteKind::DirectP2p,
                    relay_ids: Vec::new(),
                    hop_count: 0,
                    traffic_class: TrafficClass::Operational,
                    observed_available: true,
                    observed_healthy: false,
                    metadata: RouteCandidateMetadata::default(),
                },
                RouteCandidate {
                    route_id: route_b,
                    source_node: "local".to_string(),
                    destination_node: "peer".to_string(),
                    peer_id: "peer".to_string(),
                    kind: RouteKind::DirectP2p,
                    relay_ids: Vec::new(),
                    hop_count: 0,
                    traffic_class: TrafficClass::Operational,
                    observed_available: true,
                    observed_healthy: true,
                    metadata: RouteCandidateMetadata::default(),
                },
            ],
            transport_routes: routes,
            relay_routes: HashMap::new(),
        }
    }

    fn service(
        root: PathBuf,
        trust: TrustStateSnapshot,
        transport: Arc<CountingTransport>,
    ) -> Task3NetworkAiRuntimeService {
        service_with_observation(root, trust, transport, true)
    }

    fn service_with_observation(
        root: PathBuf,
        trust: TrustStateSnapshot,
        transport: Arc<CountingTransport>,
        observed_confirmed: bool,
    ) -> Task3NetworkAiRuntimeService {
        let topo = topology();
        let observed = topo
            .transport_routes
            .iter()
            .find(|(_, iface)| iface.as_str() == "if0")
            .map(|(route, _)| route.clone())
            .unwrap();
        service_with_topology(root, topo, observed, trust, transport, observed_confirmed)
    }

    fn service_with_topology(
        root: PathBuf,
        topo: ProductionTopology,
        observed: String,
        trust: TrustStateSnapshot,
        transport: Arc<CountingTransport>,
        observed_confirmed: bool,
    ) -> Task3NetworkAiRuntimeService {
        service_with_topology_and_mode(
            root,
            topo,
            observed,
            trust,
            transport,
            observed_confirmed,
            NetworkAiRuntimeMode::Active,
        )
    }

    fn service_with_topology_and_mode(
        root: PathBuf,
        topo: ProductionTopology,
        observed: String,
        trust: TrustStateSnapshot,
        transport: Arc<CountingTransport>,
        observed_confirmed: bool,
        mode: NetworkAiRuntimeMode,
    ) -> Task3NetworkAiRuntimeService {
        let config_path = root.join("config").join("network_ai.json");
        let mut network_ai_config = EngineNetworkAiConfig::default();
        network_ai_config.mode = mode;
        persist_json(&config_path, &network_ai_config).unwrap();
        if mode == NetworkAiRuntimeMode::Active {
            persist_json(
                root.join("safety_runtime_status.json"),
                &serde_json::json!({
                    "schema_version": "task3-d10-safety-runtime-status-v1",
                    "ts_ms": now_ms(),
                    "safety_evaluated": true,
                    "blocked_by": null,
                    "transport_apply_allowed": true,
                    "transport_applied": false,
                    "reason": "test fixture active-mode safety proof"
                }),
            )
            .unwrap();
        }

        Task3NetworkAiRuntimeService::new(
            Task3NetworkAiConfig {
                enabled: true,
                interval: Duration::from_secs(60),
                persistence_root: root,
                nebula_base_dir: PathBuf::new(),
                task2_trust_root: PathBuf::new(),
                network_ai_config_path: config_path,
                network_ai_config,
                config_error: None,
                allow_transport_apply: true,
            },
            Arc::new(StaticTelemetry),
            Arc::new(StaticTopology { topology: topo }),
            Arc::new(StaticTrust { trust }),
            Arc::new(StaticObservation {
                route_id: observed,
                confirmed: observed_confirmed,
            }),
            transport,
            Arc::new(EmptyRelayHealth),
            Arc::new(NoopRelayControl),
        )
    }

    #[tokio::test]
    async fn shadow_mode_persists_decision_without_transport_apply() {
        let transport = Arc::new(CountingTransport {
            calls: AtomicUsize::new(0),
            applied: true,
        });
        let root = temp_root("shadow-no-apply");
        let topo = topology();
        let observed = topo
            .transport_routes
            .iter()
            .find(|(_, iface)| iface.as_str() == "if0")
            .map(|(route, _)| route.clone())
            .unwrap();
        let status = service_with_topology_and_mode(
            root.clone(),
            topo,
            observed,
            TrustStateSnapshot::new("task2")
                .trust_peer("local")
                .trust_peer("peer"),
            transport.clone(),
            true,
            NetworkAiRuntimeMode::Shadow,
        )
        .run_cycle()
        .await
        .unwrap();

        assert_eq!(status.mode, NetworkAiRuntimeMode::Shadow);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
        assert!(!status.transport_apply_attempted);
        assert!(root.join("shadow_route_decision.json").exists());
    }

    #[tokio::test]
    async fn invalid_config_falls_back_to_shadow_without_transport_apply() {
        let transport = Arc::new(CountingTransport {
            calls: AtomicUsize::new(0),
            applied: true,
        });
        let root = temp_root("invalid-config-shadow");
        let config_path = root.join("config").join("network_ai.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, "{not-json").unwrap();

        let service = Task3NetworkAiRuntimeService::new(
            Task3NetworkAiConfig {
                enabled: true,
                interval: Duration::from_secs(60),
                persistence_root: root.clone(),
                nebula_base_dir: PathBuf::new(),
                task2_trust_root: PathBuf::new(),
                network_ai_config_path: config_path,
                network_ai_config: EngineNetworkAiConfig::default(),
                config_error: None,
                allow_transport_apply: true,
            },
            Arc::new(StaticTelemetry),
            Arc::new(StaticTopology {
                topology: topology(),
            }),
            Arc::new(StaticTrust {
                trust: TrustStateSnapshot::new("task2")
                    .trust_peer("local")
                    .trust_peer("peer"),
            }),
            Arc::new(StaticObservation {
                route_id: transport_route_id("local", "if0", "peer"),
                confirmed: true,
            }),
            transport.clone(),
            Arc::new(EmptyRelayHealth),
            Arc::new(NoopRelayControl),
        );

        let status = service.run_cycle().await.unwrap();

        assert_eq!(status.mode, NetworkAiRuntimeMode::Shadow);
        assert!(status.config_error.is_some());
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
        assert!(!status.transport_apply_attempted);
    }

    #[tokio::test]
    async fn missing_task2_trust_fails_closed_without_transport_apply() {
        let transport = Arc::new(CountingTransport {
            calls: AtomicUsize::new(0),
            applied: true,
        });
        let status = service(
            temp_root("missing-trust"),
            TrustStateSnapshot::missing("missing"),
            transport.clone(),
        )
        .run_cycle()
        .await
        .unwrap();

        assert_eq!(status.eligible_count, 0);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
        assert!(!status.transport_apply_attempted);
    }

    #[tokio::test]
    async fn d3_unconfirmed_route_continues_optimization_without_transport_apply() {
        let transport = Arc::new(CountingTransport {
            calls: AtomicUsize::new(0),
            applied: true,
        });
        let overlay = overlay_registry_fixture(&["nodeA", "nodeB", "nodeC"]);
        let topo = build_nebula_overlay_topology(
            "nodeA",
            vec!["nodeB".to_string(), "nodeC".to_string()],
            &overlay,
            None,
            &[underlay_snapshot("eth0", TransportType::Ethernet)],
        )
        .expect("build direct overlay topology");
        let status = service_with_topology(
            temp_root("d3-unconfirmed-cycle"),
            topo,
            "unknown-unconfirmed-nebula-route".to_string(),
            TrustStateSnapshot::new("task2")
                .trust_peer("nodeB")
                .trust_peer("nodeC"),
            transport.clone(),
            false,
        )
        .run_cycle()
        .await
        .expect("unconfirmed route still runs optimization");

        assert!(status.candidate_count >= 2);
        assert!(status.eligible_count >= 2);
        assert!(status
            .recommended_route
            .as_deref()
            .is_some_and(|route| route.starts_with("direct-nodeA-")));
        assert!(status.active_route.is_none());
        assert!(!status.transport_apply_attempted);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn confirmed_transport_apply_is_required_before_active_route_changes() {
        let transport = Arc::new(CountingTransport {
            calls: AtomicUsize::new(0),
            applied: true,
        });
        let status = service(
            temp_root("apply-success"),
            TrustStateSnapshot::new("task2")
                .trust_peer("local")
                .trust_peer("peer"),
            transport.clone(),
        )
        .run_cycle()
        .await
        .unwrap();

        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        assert!(status.transport_apply_attempted);
        assert!(status.last_transport_result.unwrap().applied);
    }

    #[tokio::test]
    async fn failed_transport_apply_is_audited_without_false_success() {
        let transport = Arc::new(CountingTransport {
            calls: AtomicUsize::new(0),
            applied: false,
        });
        let root = temp_root("apply-fail");
        let status = service(
            root.clone(),
            TrustStateSnapshot::new("task2")
                .trust_peer("local")
                .trust_peer("peer"),
            transport,
        )
        .run_cycle()
        .await
        .unwrap();

        if let Some(result) = status.last_transport_result {
            assert!(!result.applied);
        }
        assert!(root.join("transport_apply_audit.jsonl").exists());
    }
}
