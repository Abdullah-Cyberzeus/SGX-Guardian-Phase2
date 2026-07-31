use crate::geofence::errors::{GeofenceError, GeofenceResult};
use crate::geofence::model::{Fix, GeofenceZone};
use crate::geofence::persistence;
use crate::threat::ai_bridge::forward_to_ai;
use crate::threat::inventory::AlertInventory;
use crate::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

const GEOFENCE_SID_BASE: u32 = 10_000_900;

pub fn alerts_path() -> std::path::PathBuf {
    persistence::base_dir().join("alerts.jsonl")
}

pub fn list_alerts() -> GeofenceResult<Vec<ThreatAlert>> {
    Ok(AlertInventory::load_from_path(&alerts_path())
        .map_err(|error| GeofenceError::InvalidInput(error.to_string()))?
        .snapshot())
}

pub async fn emit_transition_alert(
    node_id: &str,
    zone: &GeofenceZone,
    transition: &str,
    fix: &Fix,
) -> GeofenceResult<ThreatAlert> {
    let alert = transition_alert(zone, transition, fix, Utc::now())?;
    let path = alerts_path();
    tokio::task::spawn_blocking({
        let alert = alert.clone();
        move || -> GeofenceResult<()> {
            let mut inventory = AlertInventory::load_from_path(&path)
                .map_err(|error| GeofenceError::InvalidInput(error.to_string()))?;
            inventory.ingest(alert);
            inventory
                .save_atomic(&path)
                .map_err(|error| GeofenceError::InvalidInput(error.to_string()))?;
            Ok(())
        }
    })
    .await
    .map_err(|error| GeofenceError::InvalidInput(error.to_string()))??;
    forward_to_ai(node_id, &alert);
    Ok(alert)
}

pub(crate) fn transition_alert(
    zone: &GeofenceZone,
    transition: &str,
    fix: &Fix,
    timestamp: DateTime<Utc>,
) -> GeofenceResult<ThreatAlert> {
    let sid = sid_for_transition(transition)?;
    let transition_upper = transition.to_ascii_uppercase();
    Ok(ThreatAlert {
        alert_id: geofence_alert_id(sid, &zone.zone_id, transition, timestamp),
        timestamp,
        src_ip: "geofence:local".to_string(),
        src_port: 0,
        dst_ip: zone.zone_id.clone(),
        dst_port: 0,
        protocol: "GEOFENCE".to_string(),
        signature_id: sid,
        signature: format!(
            "SGX GEOFENCE {} {} ({})",
            zone.name,
            transition_upper,
            fix.summary()
        ),
        category: ThreatCategory::PolicyViolation,
        severity: parse_severity(&zone.severity),
        rev: 1,
        gid: 1,
        event_type: "alert".to_string(),
        blocked: false,
    })
}

fn sid_for_transition(transition: &str) -> GeofenceResult<u32> {
    match transition {
        "entry" => Ok(GEOFENCE_SID_BASE),
        "exit" => Ok(GEOFENCE_SID_BASE + 1),
        other => Err(GeofenceError::InvalidInput(format!(
            "unsupported geofence transition: {}",
            other
        ))),
    }
}

fn geofence_alert_id(
    sid: u32,
    zone_id: &str,
    transition: &str,
    timestamp: DateTime<Utc>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sid.to_be_bytes());
    hasher.update(zone_id.as_bytes());
    hasher.update(transition.as_bytes());
    hasher.update(
        timestamp
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    hex::encode(&hasher.finalize()[..8])
}

pub fn parse_severity(raw: &str) -> Severity {
    match raw {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "critical" => Severity::Critical,
        _ => Severity::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geofence::actions::ZoneAutomation;
    use crate::geofence::model::ZoneKind;

    fn zone() -> GeofenceZone {
        GeofenceZone {
            zone_id: "zone-a".to_string(),
            name: "Control Room".to_string(),
            kind: ZoneKind::Coordinate,
            center_lat: Some(1.0),
            center_lng: Some(1.0),
            radius_m: Some(10.0),
            rf_signature: None,
            on_entry: true,
            on_exit: true,
            severity: "high".to_string(),
            automation: ZoneAutomation::default(),
            enabled: true,
            created_at: "now".to_string(),
            updated_at: "now".to_string(),
        }
    }

    #[test]
    fn repeated_transitions_get_distinct_ids() {
        let fix = Fix::coordinate(1.0, 2.0, None);
        let first = transition_alert(&zone(), "exit", &fix, Utc::now()).expect("first");
        let second = transition_alert(
            &zone(),
            "exit",
            &fix,
            Utc::now() + chrono::Duration::seconds(1),
        )
        .expect("second");
        assert_eq!(first.signature_id, 10_000_901);
        assert_eq!(first.category, ThreatCategory::PolicyViolation);
        assert_ne!(first.alert_id, second.alert_id);
    }
}
