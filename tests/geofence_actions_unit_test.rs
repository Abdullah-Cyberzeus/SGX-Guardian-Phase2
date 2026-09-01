use sgx_guardian_client::geofence::actions::executor;
use sgx_guardian_client::geofence::actions::{validate, GeofenceAction, ZoneAutomation};
use sgx_guardian_client::geofence::model::{GeofenceZone, ZoneKind};

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

fn zone(automation: ZoneAutomation) -> GeofenceZone {
    GeofenceZone {
        zone_id: format!("zone-{}", uuid::Uuid::new_v4()),
        name: "Lab".into(),
        topology_node_ref: None,
        kind: ZoneKind::Coordinate,
        center_lat: Some(1.0),
        center_lng: Some(2.0),
        radius_m: Some(10.0),
        rf_signature: None,
        on_entry: true,
        on_exit: true,
        severity: "high".into(),
        automation,
        enabled: true,
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
    }
}

#[test]
fn default_automation_is_alert_on_exit_only() {
    let automation = ZoneAutomation::default();
    assert!(automation.on_entry.is_empty());
    assert_eq!(automation.on_exit.len(), 1);
    assert!(!automation.allow_destructive);
    assert_eq!(automation.min_confidence, 0.9);
}

#[test]
fn validate_accepts_boundary_confidence_values() {
    for value in [0.0, 1.0] {
        let automation = ZoneAutomation {
            min_confidence: value,
            ..Default::default()
        };
        assert!(validate(&automation).is_ok());
    }
}

#[test]
fn validate_rejects_negative_confidence() {
    let err = validate(&ZoneAutomation {
        min_confidence: -0.01,
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.contains("min_confidence"));
}

#[test]
fn validate_rejects_confidence_above_one() {
    let err = validate(&ZoneAutomation {
        min_confidence: 1.01,
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.contains("min_confidence"));
}

#[test]
fn validate_rejects_nan_confidence() {
    let err = validate(&ZoneAutomation {
        min_confidence: f64::NAN,
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.contains("min_confidence"));
}

#[test]
fn validate_rejects_infinite_confidence() {
    let err = validate(&ZoneAutomation {
        min_confidence: f64::INFINITY,
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.contains("min_confidence"));
}

#[test]
fn serde_defaults_missing_fields() {
    let automation: ZoneAutomation = serde_json::from_str("{}").unwrap();
    assert_eq!(automation, ZoneAutomation::default());
}

#[test]
fn serde_round_trips_all_action_variants() {
    let actions = vec![
        GeofenceAction::RaiseAlert { severity: Some("critical".into()) },
        GeofenceAction::Notify { severity: None },
        GeofenceAction::RunScan,
        GeofenceAction::LockNetwork,
        GeofenceAction::EmergencyKeyRotation,
    ];
    let decoded: Vec<GeofenceAction> = serde_json::from_str(&serde_json::to_string(&actions).unwrap()).unwrap();
    assert_eq!(decoded, actions);
}

#[test]
fn serde_rejects_unknown_action_variant() {
    assert!(serde_json::from_str::<GeofenceAction>(r#"{"action":"unknown"}"#).is_err());
}

#[test]
fn dry_run_enabled_defaults_true_when_env_missing() {
    let _env = EnvGuard::remove("SGX_GEOFENCE_ACTIONS_DRYRUN");
    assert!(executor::dry_run_enabled());
}

#[test]
fn dry_run_enabled_is_false_only_for_zero() {
    let _env = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
    assert!(!executor::dry_run_enabled());
}

#[test]
fn dry_run_enabled_treats_false_string_as_enabled() {
    let _env = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "false");
    assert!(executor::dry_run_enabled());
}

#[tokio::test]
async fn execute_non_destructive_actions_succeed_in_dry_run() {
    let _env = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "1");
    let zone = zone(ZoneAutomation::default());
    for action in [
        GeofenceAction::RaiseAlert { severity: None },
        GeofenceAction::Notify { severity: Some("low".into()) },
        GeofenceAction::RunScan,
    ] {
        executor::execute("node-a", &zone, "entry", 0.1, action).await.unwrap();
    }
}

#[tokio::test]
async fn destructive_action_is_downgraded_when_not_allowed() {
    let _env = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
    let zone = zone(ZoneAutomation {
        allow_destructive: false,
        ..Default::default()
    });
    executor::execute("node-a", &zone, "exit", 1.0, GeofenceAction::LockNetwork)
        .await
        .unwrap();
}

#[tokio::test]
async fn destructive_action_is_downgraded_when_confidence_low() {
    let _env = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
    let zone = zone(ZoneAutomation {
        allow_destructive: true,
        min_confidence: 0.9,
        ..Default::default()
    });
    executor::execute("node-a", &zone, "exit", 0.89, GeofenceAction::EmergencyKeyRotation)
        .await
        .unwrap();
}

#[tokio::test]
async fn live_lock_network_requires_interface() {
    let _dry = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
    let _iface = EnvGuard::remove("SGX_GEOFENCE_LOCK_INTERFACE");
    let zone = zone(ZoneAutomation {
        allow_destructive: true,
        min_confidence: 0.0,
        ..Default::default()
    });
    let err = executor::execute("node-a", &zone, "exit", 1.0, GeofenceAction::LockNetwork)
        .await
        .unwrap_err();
    assert!(err.contains("SGX_GEOFENCE_LOCK_INTERFACE"));
}

#[tokio::test]
async fn dispatch_without_state_runs_entry_and_exit_in_dry_run() {
    let _env = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "1");
    let zone = zone(ZoneAutomation {
        on_entry: vec![GeofenceAction::Notify { severity: None }],
        on_exit: vec![GeofenceAction::RaiseAlert { severity: Some("high".into()) }],
        ..Default::default()
    });
    executor::dispatch_without_state("node-a", &zone, "entry", 1.0).await;
    executor::dispatch_without_state("node-a", &zone, "exit", 1.0).await;
}
