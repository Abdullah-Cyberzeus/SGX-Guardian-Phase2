use crate::did::document::Proof;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceUsage {
    pub iface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_total: u64,
    pub tx_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CategoryUsage {
    pub category: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceUsage {
    pub ip: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageSnapshot {
    pub period: String,
    pub period_start: String,
    pub interfaces: Vec<InterfaceUsage>,
    pub categories: Vec<CategoryUsage>,
    pub devices: Vec<DeviceUsage>,
    pub total_bytes: u64,
    pub quota_bytes: Option<u64>,
    pub used_pct: Option<f64>,
    pub usage_band: String,
    pub sampled_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawInterfaceCounters {
    pub iface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawCategoryCounter {
    pub category: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DusageState {
    pub period: String,
    pub period_start: String,
    pub iface_baselines: BTreeMap<String, (u64, u64)>,
    #[serde(default)]
    pub iface_last_seen: BTreeMap<String, (u64, u64)>,
    pub category_baselines: BTreeMap<String, u64>,
    #[serde(default)]
    pub category_last_seen: BTreeMap<String, u64>,
    pub sequence: u64,
    pub proof: Proof,
}

impl DusageState {
    pub fn new(period: String, period_start: String) -> Self {
        Self {
            period,
            period_start,
            iface_baselines: BTreeMap::new(),
            iface_last_seen: BTreeMap::new(),
            category_baselines: BTreeMap::new(),
            category_last_seen: BTreeMap::new(),
            sequence: 0,
            proof: Proof::default(),
        }
    }

    pub fn without_proof(&self) -> Self {
        let mut clone = self.clone();
        clone.proof = Proof::default();
        clone
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DusageQuota {
    pub quota_bytes: u64,
    pub period: String,
    pub sequence: u64,
    pub proof: Proof,
}

impl DusageQuota {
    pub fn new(quota_bytes: u64, period: String, sequence: u64) -> Self {
        Self {
            quota_bytes,
            period,
            sequence,
            proof: Proof::default(),
        }
    }

    pub fn without_proof(&self) -> Self {
        let mut clone = self.clone();
        clone.proof = Proof::default();
        clone
    }
}

pub(crate) fn local_integrity_proof(payload: &[u8]) -> Proof {
    Proof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "sha256-local-2026".to_string(),
        verification_method: "local:dusage".to_string(),
        created: Utc::now().to_rfc3339(),
        proof_purpose: "assertionMethod".to_string(),
        proof_value: hex::encode(Sha256::digest(payload)),
    }
}
