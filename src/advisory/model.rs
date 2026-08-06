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
    pub steps: Vec<RemediationStep>,
    pub context: Vec<String>,
    pub references: Vec<String>,
    pub source: String,
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
