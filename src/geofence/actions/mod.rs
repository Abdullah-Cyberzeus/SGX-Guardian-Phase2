use serde::{Deserialize, Serialize};

pub mod executor;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum GeofenceAction {
    RaiseAlert { severity: Option<String> },
    Notify { severity: Option<String> },
    RunScan,
    LockNetwork,
    EmergencyKeyRotation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneAutomation {
    #[serde(default)]
    pub on_entry: Vec<GeofenceAction>,
    #[serde(default = "default_on_exit")]
    pub on_exit: Vec<GeofenceAction>,
    #[serde(default)]
    pub allow_destructive: bool,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
}

impl Default for ZoneAutomation {
    fn default() -> Self {
        Self {
            on_entry: Vec::new(),
            on_exit: default_on_exit(),
            allow_destructive: false,
            min_confidence: default_min_confidence(),
        }
    }
}

fn default_on_exit() -> Vec<GeofenceAction> {
    vec![GeofenceAction::RaiseAlert {
        severity: Some("high".to_string()),
    }]
}

fn default_min_confidence() -> f64 {
    0.9
}

pub fn validate(automation: &ZoneAutomation) -> Result<(), String> {
    if !automation.min_confidence.is_finite() || !(0.0..=1.0).contains(&automation.min_confidence) {
        return Err("min_confidence must be between 0.0 and 1.0".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_alert_only() {
        let automation = ZoneAutomation::default();
        assert!(automation.on_entry.is_empty());
        assert_eq!(automation.on_exit.len(), 1);
        assert!(!automation.allow_destructive);
        assert_eq!(automation.min_confidence, 0.9);
    }

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

    fn zone(automation: ZoneAutomation) -> crate::geofence::model::GeofenceZone {
        crate::geofence::model::GeofenceZone {
            zone_id: format!("zone-{}", uuid::Uuid::new_v4()),
            name: "Lab".into(),
            topology_node_ref: None,
            kind: crate::geofence::model::ZoneKind::Coordinate,
            center_lat: Some(1.0),
            center_lng: Some(2.0),
            radius_m: Some(50.0),
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
    fn default_on_exit_is_high_raise_alert() {
        assert_eq!(
            default_on_exit(),
            vec![GeofenceAction::RaiseAlert {
                severity: Some("high".into())
            }]
        );
    }

    #[test]
    fn default_min_confidence_is_point_nine() {
        assert_eq!(default_min_confidence(), 0.9);
    }

    #[test]
    fn validate_accepts_min_confidence_boundaries() {
        let mut automation = ZoneAutomation::default();
        automation.min_confidence = 0.0;
        assert!(validate(&automation).is_ok());
        automation.min_confidence = 1.0;
        assert!(validate(&automation).is_ok());
    }

    #[test]
    fn validate_rejects_out_of_range_and_non_finite_confidence() {
        for value in [-0.01, 1.01, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut automation = ZoneAutomation::default();
            automation.min_confidence = value;
            let err = validate(&automation).expect_err("invalid confidence");
            assert!(err.contains("min_confidence"));
        }
    }

    #[test]
    fn serde_defaults_missing_automation_fields() {
        let automation: ZoneAutomation = serde_json::from_str("{}").expect("deserialize");
        assert_eq!(automation, ZoneAutomation::default());
    }

    #[test]
    fn serde_preserves_all_action_variants() {
        let actions = vec![
            GeofenceAction::RaiseAlert {
                severity: Some("critical".into()),
            },
            GeofenceAction::Notify { severity: None },
            GeofenceAction::RunScan,
            GeofenceAction::LockNetwork,
            GeofenceAction::EmergencyKeyRotation,
        ];
        let json = serde_json::to_string(&actions).expect("serialize");
        let decoded: Vec<GeofenceAction> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, actions);
    }

    #[test]
    fn serde_rejects_unknown_action_variant() {
        let err = serde_json::from_str::<GeofenceAction>(r#"{"action":"unknown"}"#)
            .expect_err("unknown action");
        assert!(err.to_string().contains("unknown"));
    }

    #[tokio::test]
    async fn dry_run_enabled_defaults_to_true_and_false_only_for_zero() {
        let _lock = crate::test_support::async_env_lock().await;
        let _dryrun = EnvGuard::remove("SGX_GEOFENCE_ACTIONS_DRYRUN");
        assert!(executor::dry_run_enabled());
        drop(_dryrun);

        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "1");
        assert!(executor::dry_run_enabled());
        drop(_dryrun);

        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "false");
        assert!(executor::dry_run_enabled());
        drop(_dryrun);

        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
        assert!(!executor::dry_run_enabled());
    }

    #[tokio::test]
    async fn execute_non_destructive_actions_succeed_in_dry_run() {
        let _lock = crate::test_support::async_env_lock().await;
        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "1");
        let zone = zone(ZoneAutomation::default());
        for action in [
            GeofenceAction::RaiseAlert { severity: None },
            GeofenceAction::Notify {
                severity: Some("low".into()),
            },
            GeofenceAction::RunScan,
        ] {
            executor::execute("node-a", &zone, "entry", 0.1, action)
                .await
                .expect("dry run action");
        }
    }

    #[tokio::test]
    async fn execute_destructive_action_is_downgraded_when_not_allowed() {
        let _lock = crate::test_support::async_env_lock().await;
        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
        let zone = zone(ZoneAutomation {
            allow_destructive: false,
            ..Default::default()
        });
        executor::execute("node-a", &zone, "exit", 1.0, GeofenceAction::LockNetwork)
            .await
            .expect("downgraded action");
    }

    #[tokio::test]
    async fn execute_destructive_action_is_downgraded_when_confidence_is_low() {
        let _lock = crate::test_support::async_env_lock().await;
        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
        let zone = zone(ZoneAutomation {
            allow_destructive: true,
            min_confidence: 0.9,
            ..Default::default()
        });
        executor::execute(
            "node-a",
            &zone,
            "exit",
            0.89,
            GeofenceAction::EmergencyKeyRotation,
        )
        .await
        .expect("downgraded low confidence action");
    }

    #[tokio::test]
    async fn execute_live_lock_network_requires_interface_env() {
        let _lock = crate::test_support::async_env_lock().await;
        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
        let _iface = EnvGuard::remove("SGX_GEOFENCE_LOCK_INTERFACE");
        let zone = zone(ZoneAutomation {
            allow_destructive: true,
            min_confidence: 0.5,
            ..Default::default()
        });
        let err = executor::execute("node-a", &zone, "exit", 1.0, GeofenceAction::LockNetwork)
            .await
            .expect_err("missing interface");
        assert!(err.contains("SGX_GEOFENCE_LOCK_INTERFACE"));
    }

    #[tokio::test]
    async fn execute_live_lock_network_rejects_invalid_interface() {
        let _lock = crate::test_support::async_env_lock().await;
        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
        let _iface = EnvGuard::set("SGX_GEOFENCE_LOCK_INTERFACE", "bad iface!");
        let zone = zone(ZoneAutomation {
            allow_destructive: true,
            min_confidence: 0.5,
            ..Default::default()
        });
        let err = executor::execute("node-a", &zone, "exit", 1.0, GeofenceAction::LockNetwork)
            .await
            .expect_err("invalid interface");
        assert!(err.contains("invalid"));
    }

    #[tokio::test]
    async fn execute_live_lock_network_writes_transport_lock_to_temp_dir() {
        let _lock = crate::test_support::async_env_lock().await;
        let temp = tempfile::tempdir().expect("tempdir");
        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
        let _iface = EnvGuard::set("SGX_GEOFENCE_LOCK_INTERFACE", "wg0.10:test");
        let _lock_dir = EnvGuard::set(
            "SGX_GUARDIAN_COT_LOCK_DIR",
            temp.path().to_str().expect("utf8 temp path"),
        );
        let zone = zone(ZoneAutomation {
            allow_destructive: true,
            min_confidence: 0.5,
            ..Default::default()
        });
        executor::execute("node-a", &zone, "exit", 1.0, GeofenceAction::LockNetwork)
            .await
            .expect("lock network");
        assert_eq!(
            std::fs::read_to_string(temp.path().join("transport_lock_node-a.txt"))
                .expect("lock file"),
            "wg0.10:test\n"
        );
    }

    #[tokio::test]
    async fn dispatch_without_state_runs_entry_and_exit_action_lists_in_dry_run() {
        let _lock = crate::test_support::async_env_lock().await;
        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "1");
        let zone = zone(ZoneAutomation {
            on_entry: vec![GeofenceAction::Notify { severity: None }],
            on_exit: vec![GeofenceAction::RaiseAlert {
                severity: Some("high".into()),
            }],
            ..Default::default()
        });
        executor::dispatch_without_state("node-a", &zone, "entry", 1.0).await;
        executor::dispatch_without_state("node-a", &zone, "exit", 1.0).await;
    }

    #[tokio::test]
    async fn dispatch_deduplicates_same_transition_but_resets_opposite_transition() {
        let _lock = crate::test_support::async_env_lock().await;
        let temp = tempfile::tempdir().expect("tempdir");
        let _dryrun = EnvGuard::set("SGX_GEOFENCE_ACTIONS_DRYRUN", "0");
        let _iface = EnvGuard::set("SGX_GEOFENCE_LOCK_INTERFACE", "eth0");
        let _lock_dir = EnvGuard::set(
            "SGX_GUARDIAN_COT_LOCK_DIR",
            temp.path().to_str().expect("utf8 temp path"),
        );
        let zone = zone(ZoneAutomation {
            on_entry: vec![GeofenceAction::LockNetwork],
            on_exit: vec![GeofenceAction::LockNetwork],
            allow_destructive: true,
            min_confidence: 0.0,
        });
        let lock_file = temp.path().join("transport_lock_node-a.txt");

        executor::dispatch("node-a", &zone, "entry", 1.0).await;
        assert_eq!(std::fs::read_to_string(&lock_file).unwrap(), "eth0\n");
        std::fs::remove_file(&lock_file).expect("remove lock marker");
        executor::dispatch("node-a", &zone, "entry", 1.0).await;
        assert!(!lock_file.exists(), "duplicate entry should not fire");
        executor::dispatch("node-a", &zone, "exit", 1.0).await;
        assert!(lock_file.exists(), "opposite transition should fire");
    }
}
