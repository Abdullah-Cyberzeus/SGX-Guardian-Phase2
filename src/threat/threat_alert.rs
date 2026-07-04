use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    Malware,
    Exploit,
    PolicyViolation,
    Reconnaissance,
    Anomaly,
    Other,
}

impl ThreatCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ThreatCategory::Malware => "malware",
            ThreatCategory::Exploit => "exploit",
            ThreatCategory::PolicyViolation => "policy_violation",
            ThreatCategory::Reconnaissance => "reconnaissance",
            ThreatCategory::Anomaly => "anomaly",
            ThreatCategory::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatAlert {
    /// Dedup ID: SHA-256(sid || src_ip || dst_ip)[..16] hex.
    pub alert_id: String,
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub signature_id: u32,
    pub signature: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub rev: u32,
    pub gid: u32,
    pub event_type: String,
    #[serde(default)]
    pub blocked: bool,
}

impl ThreatAlert {
    pub fn compute_id(sid: u32, src: &str, dst: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sid.to_be_bytes());
        hasher.update(src.as_bytes());
        hasher.update(dst.as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }
}
