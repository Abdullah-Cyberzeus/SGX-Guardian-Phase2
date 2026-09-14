//! Task 3 network AI integration.
//!
//! Deliverable 1 starts with a small, testable telemetry boundary:
//! shared Task 1 metrics are converted into timestamped network-route
//! observations without depending on live attestation or policy apply state.

pub mod api;
pub mod audit;
pub mod candidates;
pub mod config;
pub mod decision_audit;
pub mod degradation;
pub mod eligibility;
pub mod features;
pub mod history;
pub mod load_balancer;
pub mod predictor;
pub mod reward;
pub mod rl;
pub mod route_adapter;
pub mod runtime;
pub mod runtime_mode;
pub mod safety;
pub mod task1_bridge;
pub mod telemetry_adapter;
pub mod virtual_shift_bridge;

pub use api::{router as api_router, ModeUpdateRequest, NetworkAiApiState};
pub use audit::{
    write_post_task2_decision_audit, SensitiveRouteAuditRecord, SensitiveRouteHandoffResult,
    SensitiveRouteHandoffService, SensitiveRouteReason, Task3PostTask2DecisionAudit,
    NETWORK_AI_SENSITIVE_ROUTE_HANDOFF_VERSION,
};
pub use candidates::{RouteCandidate, RouteCandidateInventory};
pub use config::{NetworkAiConfig, NetworkAiRewardWeights, NETWORK_AI_CONFIG_VERSION};
pub use decision_audit::{
    persist_decision_audit, DecisionAuditPaths, DecisionAuditRecord, DecisionEvidenceLinks,
    RejectedCandidateAudit, NETWORK_AI_DECISION_AUDIT_VERSION,
};
pub use degradation::{
    append_degradation_prediction_jsonl, DegradationPrediction, DegradationPredictor,
    SimpleDegradationPredictor, NETWORK_AI_DEGRADATION_MODEL_VERSION,
};
pub use eligibility::{
    EligibilityDecision, EligibilityFilter, EligibilityReason, EligibleRouteSet, TrustStateSnapshot,
};
pub use features::{
    NetworkAiFeatureBuilder, NetworkAiFeatureVector, NETWORK_AI_FEATURE_SCHEMA_VERSION,
};
pub use history::{
    ObservedRouteOutcome, RouteHistoryEntry, RouteHistoryStore, RoutePerformanceStats,
};
pub use load_balancer::{
    MultiRelayLoadBalancer, RelayBalanceConfig, RelayRuntimeHealth, RelayWeight, RelayWeightSet,
    NETWORK_AI_RELAY_BALANCER_VERSION,
};
pub use predictor::{
    RoutePrediction, RoutePredictionSet, RoutePredictor, RouteQualityComponents,
    SimpleRouteQualityPredictor, NETWORK_AI_PREDICTOR_VERSION,
};
pub use reward::{RewardComponents, RouteReward, NETWORK_AI_REWARD_VERSION};
pub use rl::{
    ContextualBanditPolicy, RouteActionValue, RouteLearningDecision, NETWORK_AI_RL_VERSION,
};
pub use route_adapter::{
    RouteTransitionAuditRecord, RuntimeRouteApplyRequest, RuntimeRouteControllerResult,
    RuntimeRouteState, RuntimeRouteTransition, SafeRuntimeRouteController,
    NETWORK_AI_ROUTE_CONTROLLER_VERSION,
};
pub use runtime::{
    NetworkAiRuntime, NetworkAiRuntimeState, NetworkAiRuntimeTickInput, NetworkAiRuntimeTickResult,
    NetworkAiSourceTickInput, NETWORK_AI_RUNTIME_VERSION,
};
pub use runtime_mode::{
    NetworkAiRuntimeMode, RuntimeModeController, RuntimeModeDecision, RuntimeModeExecution,
    SensitiveRouteHandoffContext, NETWORK_AI_RUNTIME_MODE_VERSION,
};
pub use safety::{
    RouteApplyResult, RouteSafetyConfig, RouteSafetyDecision, RouteSafetyGuard, RouteSwitchState,
    SafetyVerdict,
};
pub use task1_bridge::{
    read_optional_task1_route_signal, read_task1_route_signal, OptionalTask1RouteSignal,
    Task1RouteSignal,
};
pub use telemetry_adapter::{
    append_observation_jsonl, classify_message_type, persist_current_observation,
    NetworkMessageType, NetworkObservation, NetworkTelemetryAdapter, NetworkTelemetryContext,
    PriorityClass, RouteKind, Task1MetricEvidence, TrafficClass,
    NETWORK_AI_OBSERVATION_SCHEMA_VERSION,
};
pub use virtual_shift_bridge::{
    read_optional_task2_trust_summary, read_task2_trust_summary, OptionalTask2RoutingTrust,
    Task2RoutingTrustSummary, Task2TrustStateSources,
};
