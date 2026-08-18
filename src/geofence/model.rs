use crate::did::document::Proof;
use crate::geofence::actions::ZoneAutomation;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKind {
    Coordinate,
    RfSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApObservation {
    pub bssid: String,
    pub signal_dbm: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RfSignature {
    pub aps: Vec<ApObservation>,
    #[serde(default = "default_rf_threshold")]
    pub threshold: f64,
}

pub fn default_rf_threshold() -> f64 {
    0.6
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fix {
    Coordinate {
        lat: f64,
        lng: f64,
        accuracy_m: Option<f64>,
    },
    RfSignature {
        aps: Vec<ApObservation>,
    },
}

impl Fix {
    pub fn coordinate(lat: f64, lng: f64, accuracy_m: Option<f64>) -> Self {
        Self::Coordinate {
            lat,
            lng,
            accuracy_m,
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Coordinate {
                lat,
                lng,
                accuracy_m,
            } => match accuracy_m {
                Some(accuracy) => format!("coord {:.5},{:.5} (+/-{:.0}m)", lat, lng, accuracy),
                None => format!("coord {:.5},{:.5}", lat, lng),
            },
            Self::RfSignature { aps } => format!("rf {} APs observed", aps.len()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredLocation {
    pub source: String,
    pub fix: Fix,
    pub updated_at: String,
}

impl StoredLocation {
    pub fn new(source: impl Into<String>, fix: Fix) -> Self {
        Self {
            source: source.into(),
            fix,
            updated_at: Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceSelectionStatus {
    pub selection_mode: String,
    pub active_source: Option<String>,
    pub source_reason: String,
    pub updated_at: String,
}

impl SourceSelectionStatus {
    pub fn new(
        selection_mode: impl Into<String>,
        active_source: Option<String>,
        source_reason: impl Into<String>,
    ) -> Self {
        Self {
            selection_mode: selection_mode.into(),
            active_source,
            source_reason: source_reason.into(),
            updated_at: Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeofenceZone {
    pub zone_id: String,
    pub name: String,
    /// The topology node this zone is visualized around. This is metadata only;
    /// coordinate/RF evaluation continues to use the zone's configured fix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology_node_ref: Option<String>,
    pub kind: ZoneKind,
    pub center_lat: Option<f64>,
    pub center_lng: Option<f64>,
    pub radius_m: Option<f64>,
    pub rf_signature: Option<RfSignature>,
    pub on_entry: bool,
    pub on_exit: bool,
    pub severity: String,
    #[serde(default)]
    pub automation: ZoneAutomation,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeofenceRegistry {
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub generated_at: String,
    pub sequence: u64,
    pub zones: Vec<GeofenceZone>,
    pub proof: Proof,
}

impl Default for GeofenceRegistry {
    fn default() -> Self {
        Self {
            id: "urn:sgx-guardian:geofence:registry".to_string(),
            r#type: vec!["GeofenceRegistry".to_string()],
            generated_at: Utc::now().to_rfc3339(),
            sequence: 0,
            zones: Vec::new(),
            proof: Proof::default(),
        }
    }
}

impl GeofenceRegistry {
    pub fn canonical_bytes_for_proof(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut cloned = self.clone();
        cloned.proof = Proof::default();
        let value = serde_json::to_value(&cloned)?;
        let sorted = sort_json_keys(&value);
        serde_json::to_vec(&sorted)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeofenceEvent {
    pub id: String,
    pub zone_id: String,
    pub zone_name: String,
    pub transition: String,
    pub fix_summary: String,
    pub at: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl GeofenceEvent {
    pub fn new(zone: &GeofenceZone, transition: &str, fix: &Fix) -> Self {
        let now = Utc::now();
        Self {
            id: format!("{}-{}", now.timestamp_millis(), uuid::Uuid::new_v4()),
            zone_id: zone.zone_id.clone(),
            zone_name: zone.name.clone(),
            transition: transition.to_string(),
            fix_summary: fix.summary(),
            at: now.to_rfc3339(),
            severity: zone.severity.clone(),
            origin: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneStatus {
    pub zone_id: String,
    pub zone_name: String,
    pub enabled: bool,
    pub inside: Option<bool>,
    pub distance_m: Option<f64>,
    pub rf_score: Option<f64>,
}

fn sort_json_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = std::collections::BTreeMap::new();
            for (key, value) in map {
                sorted.insert(key.clone(), sort_json_keys(value));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(sort_json_keys).collect())
        }
        _ => value.clone(),
    }
}
