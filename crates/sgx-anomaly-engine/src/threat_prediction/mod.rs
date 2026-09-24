//! Task 4 Deliverable 1: versioned threat-prediction models and safe configuration.
//!
//! Live evidence adapters, prediction algorithms and policy integration arrive in later deliverables.
pub mod cascade;
pub mod confidence;
pub mod config;
pub mod e2e;
pub mod errors;
pub mod event;
pub mod lifecycle;
pub mod model;
pub mod predictors;
pub mod sequence;
pub mod task1_bridge;
pub mod task2_bridge;
pub mod task3_bridge;
pub mod temporal;

pub use cascade::{predict_peer_cascade, PeerRelationship};
pub use confidence::{
    assess_confidence, geo_can_support_evidence_backed_forecast, CalibrationMetadata,
    CalibrationPoint, ConfidenceAssessment, ConfidenceContext, GeoThreatSignal,
    ProbabilityCalibrationConfig,
};
pub use config::{
    EventDrivenRecalculationConfig, RecalculationTrigger, RiskThresholdProfile,
    ThreatPredictionConfig, THREAT_PREDICTION_CONFIG_VERSION,
};
pub use e2e::{
    evaluate_controlled_cases, persist_e2e_evaluation_artifact, run_e2e_cycle,
    ControlledCaseResult, ControlledEvaluationMetrics, E2eCycleInput, E2eCycleOutput,
    E2eEvaluationArtifact, E2ePrimaryPredictor, E2eResourceMetrics,
};
pub use errors::ThreatPredictionError;
pub use event::{
    EventSeverity, EvidenceSource, SecurityEvent, SecurityEventType, MAX_ATTRIBUTES,
    SECURITY_EVENT_SCHEMA_VERSION,
};
pub use lifecycle::{ForecastAuditRecord, ForecastStore};
pub(crate) use model::validate_unit_interval;
pub use model::{
    ForecastExplanation, ForecastFactor, ForecastSeverity, ForecastStatus, PredictedThreatType,
    ThreatForecast, MAX_IMMINENT_FORECAST_HORIZON_MINUTES, THREAT_FORECAST_SCHEMA_VERSION,
};
pub use predictors::{
    BruteForcePredictor, DdosPredictor, ExploitationPredictor, ProtocolAbusePredictor,
    ReconEscalationPredictor, ThreatPredictor, ThreatPredictorInput,
};
pub use sequence::{match_precursor_sequence, PrecursorSequenceDefinition, PrecursorSequenceMatch};
pub use task1_bridge::{normalize_task1_recommendations, read_task1_anomalies};
pub use task2_bridge::{
    recommend_predictive_hardening, HardeningRecommendationConfig,
    PredictiveHardeningRecommendation, PREDICTIVE_HARDENING_RECOMMENDATION_VERSION,
};
pub use task3_bridge::{
    read_task3_degradation_events_at, Task3ContextConfig, Task3NetworkContext,
    TASK3_NETWORK_CONTEXT_SCHEMA_VERSION,
};
pub use temporal::{
    TemporalFeatureConfig, TemporalFeatureEngine, TemporalFeatures, TemporalWindowFeatures,
    TimeOfDayBaseline,
};
