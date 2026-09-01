use sgx_guardian_client::geofence::actions::ZoneAutomation;
use sgx_guardian_client::geofence::alerts::{
    alerts_path, emit_transition_alert, list_alerts, parse_severity,
};
use sgx_guardian_client::geofence::model::{Fix, GeofenceZone, ZoneKind};
use sgx_guardian_client::threat::threat_alert::Severity;

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn zone(severity: &str) -> GeofenceZone {
    GeofenceZone {
        zone_id: "zone-a".into(),
        name: "Control Room".into(),
        topology_node_ref: None,
        kind: ZoneKind::Coordinate,
        center_lat: Some(1.0),
        center_lng: Some(2.0),
        radius_m: Some(10.0),
        rf_signature: None,
        on_entry: true,
        on_exit: true,
        severity: severity.into(),
        automation: ZoneAutomation::default(),
        enabled: true,
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
    }
}

#[test]
fn parse_severity_maps_info() {
    assert_eq!(parse_severity("info"), Severity::Info);
}

#[test]
fn parse_severity_maps_low() {
    assert_eq!(parse_severity("low"), Severity::Low);
}

#[test]
fn parse_severity_maps_medium() {
    assert_eq!(parse_severity("medium"), Severity::Medium);
}

#[test]
fn parse_severity_maps_critical() {
    assert_eq!(parse_severity("critical"), Severity::Critical);
}

#[test]
fn parse_severity_defaults_high_for_high_and_unknown_values() {
    assert_eq!(parse_severity("high"), Severity::High);
    assert_eq!(parse_severity("unknown"), Severity::High);
}

#[test]
fn parse_severity_is_case_and_whitespace_sensitive() {
    assert_eq!(parse_severity("INFO"), Severity::High);
    assert_eq!(parse_severity(" info "), Severity::High);
    assert_eq!(parse_severity(""), Severity::High);
}

#[test]
fn alerts_path_defaults_under_standard_geofence_base() {
    let _env = EnvGuard::remove("SGX_GUARDIAN_GEOFENCE_BASE");
    assert!(alerts_path().ends_with("alerts.jsonl"));
}

#[test]
fn list_alerts_missing_file_returns_empty_list() {
    let dir = tempfile::tempdir().unwrap();
    let _env = EnvGuard::set(
        "SGX_GUARDIAN_GEOFENCE_BASE",
        dir.path().to_str().expect("utf8 path"),
    );
    assert!(list_alerts().unwrap().is_empty());
}

#[test]
fn list_alerts_malformed_jsonl_returns_invalid_input_error() {
    let dir = tempfile::tempdir().unwrap();
    let _env = EnvGuard::set(
        "SGX_GUARDIAN_GEOFENCE_BASE",
        dir.path().to_str().expect("utf8 path"),
    );
    std::fs::write(alerts_path(), "{bad-json\n").unwrap();
    let err = list_alerts().unwrap_err();
    assert!(err.to_string().contains("invalid geofence input"));
}

#[tokio::test]
async fn emit_transition_alert_rejects_invalid_transition_without_writing_file() {
    let dir = tempfile::tempdir().unwrap();
    let _env = EnvGuard::set(
        "SGX_GUARDIAN_GEOFENCE_BASE",
        dir.path().to_str().expect("utf8 path"),
    );
    let err = emit_transition_alert("node-a", &zone("low"), "arrive", &Fix::coordinate(1.0, 2.0, None))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unsupported geofence transition"));
    assert!(!alerts_path().exists());
}

#[tokio::test]
async fn rf_fix_summary_is_used_in_emitted_signature() {
    let dir = tempfile::tempdir().unwrap();
    let _env = EnvGuard::set(
        "SGX_GUARDIAN_GEOFENCE_BASE",
        dir.path().to_str().expect("utf8 path"),
    );
    let fix = Fix::RfSignature {
        aps: vec![
            sgx_guardian_client::geofence::model::ApObservation {
                bssid: "aa:bb".into(),
                signal_dbm: Some(-50),
            },
            sgx_guardian_client::geofence::model::ApObservation {
                bssid: "cc:dd".into(),
                signal_dbm: None,
            },
        ],
    };
    let alert = emit_transition_alert("node-a", &zone("info"), "entry", &fix)
        .await
        .unwrap();
    assert!(alert.signature.contains("rf 2 APs observed"));
    assert_eq!(alert.severity, Severity::Info);
}
