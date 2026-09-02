use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemediationRecommendation {
    pub rec_id: String,
    pub alert_id: String,
    pub title: String,
    pub summary: String,
    pub severity: String,
    pub confidence: f32,
    // Backward compatibility: legacy recommendation records predate these
    // explicit advisory-confidence fields.
    #[serde(default)]
    pub advisory_confidence: f32,
    #[serde(default)]
    pub advisory_basis: String,
    pub steps: Vec<RemediationStep>,
    pub context: Vec<String>,
    pub references: Vec<String>,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anomaly: Option<AnomalyDecision>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationStep {
    pub order: u8,
    pub action: String,
    pub rationale: String,
    pub automatable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnomalyContext {
    pub score: f32,
    #[serde(default)]
    pub topk: Vec<(String, f32)>,
    #[serde(default)]
    pub model_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring_runtime: Option<AnomalyScoringRuntime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AnomalySource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_signature: Option<AnomalyTopSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u64>,
    #[serde(default)]
    pub contributors: Vec<AnomalyContributor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<AnomalyDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnomalySource {
    pub ip: String,
    pub alert_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnomalyTopSignature {
    pub id: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyBaselineSelectionMode {
    Global,
    PerNode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnomalyBaselineProvenance {
    pub node_id: String,
    pub selection_mode: AnomalyBaselineSelectionMode,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub fallback_used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyScoringRuntimeModelKind {
    Heuristic,
    IsolationForest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnomalyScoringRuntime {
    pub engine_source: String,
    pub scorer_source: String,
    pub model_kind: AnomalyScoringRuntimeModelKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    pub fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<AnomalyBaselineProvenance>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyRiskLevel {
    BelowDetection,
    Detected,
    High,
    Critical,
}

impl Default for AnomalyRiskLevel {
    fn default() -> Self {
        Self::BelowDetection
    }
}

fn legacy_high_threshold() -> f32 {
    0.75
}

fn legacy_critical_threshold() -> f32 {
    0.90
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnomalyContributor {
    pub feature: String,
    pub contribution: f32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnomalyDecision {
    pub detected: bool,
    pub score: f32,
    pub threshold: f32,
    #[serde(default = "legacy_high_threshold")]
    pub high_threshold: f32,
    #[serde(default = "legacy_critical_threshold")]
    pub critical_threshold: f32,
    #[serde(default)]
    pub risk_level: AnomalyRiskLevel,
    pub normalized_score: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    pub detector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring_runtime: Option<AnomalyScoringRuntime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AnomalySource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_signature: Option<AnomalyTopSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u64>,
    #[serde(default)]
    pub contributors: Vec<AnomalyContributor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceContext {
    pub ip: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub risk_reasons: Vec<String>,
    #[serde(default)]
    pub cves: Vec<CveFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CveFinding {
    pub cve: String,
    pub cvss: Option<f32>,
}
