pub mod baseline;
pub mod remediation;
pub mod runtime;
pub mod scorer;
pub mod telemetry;
pub mod thresholds;

pub use baseline::{
    baseline_config_path, full_ml_runtime_status_path, write_runtime_status, Task1BaselineKind,
    Task1BaselineLifecycle, Task1BaselineLifecycleConfig, Task1RuntimeTracker,
    FULL_ML_ENGINE_SOURCE, FULL_ML_SCORER_SOURCE,
};
pub use remediation::{
    build_justification, build_justification_with_thresholds, generate_plan,
    generate_plan_with_thresholds, ActionType, RemediationPlan,
};
pub use runtime::{
    full_ml_alerts_path, load_recent_full_ml_alerts, spawn_full_ml_runtime,
    Task1AdvisoryConfidence, Task1FullMlAlertRecord,
};
pub use scorer::{
    anomaly_context_from_score, anomaly_context_from_score_with_thresholds, feature_from_alert,
    process_feature, process_feature_with_runtime, process_feature_with_thresholds,
    AlertAnomalyScore, AlertScorerState,
};
pub use thresholds::{
    validate as validate_threshold_settings, RecommendedThresholdRanges, Task1ThresholdDefaults,
    Task1ThresholdSettings, Task1ThresholdSettingsService, Task1ThresholdUpdate, ThresholdRange,
    DEFAULT_CRITICAL_THRESHOLD, DEFAULT_DETECTION_THRESHOLD, DEFAULT_HIGH_THRESHOLD,
};
