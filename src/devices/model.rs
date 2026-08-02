use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceScores {
    pub security_score: Option<u8>,
    #[serde(default)]
    pub security_reasons: Vec<String>,
    pub privacy_score: Option<u8>,
    #[serde(default)]
    pub privacy_reasons: Vec<String>,
    pub privacy_basis: String,
    pub risk_level: String,
    pub computed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRecord {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub manual: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    #[serde(default = "default_monitoring_enabled")]
    pub monitoring_enabled: bool,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub rejected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl DeviceRecord {
    pub fn new_manual(
        device_id: String,
        display_name: Option<String>,
        ip: Option<String>,
        mac: Option<String>,
        manufacturer: Option<String>,
        notes: Option<String>,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            device_id,
            display_name,
            manual: true,
            ip,
            mac,
            manufacturer,
            monitoring_enabled: true,
            blocked: false,
            rejected: false,
            rejection_reason: None,
            notes,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now().to_rfc3339();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceScanRun {
    pub scan_id: String,
    pub device_id: String,
    pub step: u8,
    pub step_label: String,
    pub state: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub recommendations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_assessment: Option<FirmwareAssessment>,
    #[serde(default)]
    pub progress_history: Vec<DeviceScanProgressTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceScanProgressTransition {
    pub step: u8,
    pub step_label: String,
    pub state: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirmwareAssessment {
    pub status: FirmwareAssessmentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default)]
    pub evidence_sources: Vec<FirmwareEvidenceSource>,
    pub confidence: f32,
    pub integrity_verified: bool,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareAssessmentStatus {
    Verified,
    Observed,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirmwareEvidenceSource {
    pub source: String,
    pub value: String,
}

pub fn default_monitoring_enabled() -> bool {
    true
}
