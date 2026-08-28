use chrono::DateTime;
use sgx_guardian_client::geofence::actions::{self, GeofenceAction, ZoneAutomation};
use sgx_guardian_client::geofence::alerts;
use sgx_guardian_client::geofence::errors::GeofenceError;
use sgx_guardian_client::geofence::model::{
    ApObservation, Fix, GeofenceEvent, GeofenceRegistry, GeofenceZone, RfSignature,
    SourceSelectionStatus, StoredLocation, ZoneKind, ZoneStatus,
};
use sgx_guardian_client::geofence::persistence;
use sgx_guardian_client::geofence::sources::manual::ManualSource;
use sgx_guardian_client::geofence::sources::reported::ReportedSource;
use sgx_guardian_client::geofence::sources::{self, LocationSource, SourceKind};
use sgx_guardian_client::geofence::zones::{self, NewZoneInput, ZonePatch};
use sgx_guardian_client::geofence::GeofenceConfig;
use sgx_guardian_client::threat::threat_alert::Severity;
use std::error::Error;
use std::fs;
use std::sync::{Mutex, MutexGuard};
use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct GeofenceEnv {
    _dir: TempDir,
    original: Vec<(&'static str, Option<String>)>,
    _lock: MutexGuard<'static, ()>,
}

impl GeofenceEnv {
    fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let keys = [
            persistence::GEOFENCE_BASE_ENV,
            "SGX_GEOFENCE_SEED_DEMO_ZONES",
            "SGX_GEOFENCE_SOURCE",
            "SGX_GEOFENCE_EVAL_SECS",
            "SGX_GEOFENCE_HYSTERESIS",
            "SGX_GEOFENCE_SOURCE_FRESHNESS_SECS",
        ];
        let original = keys
            .into_iter()
            .map(|key| (key, std::env::var(key).ok()))
            .collect();
        std::env::set_var(persistence::GEOFENCE_BASE_ENV, dir.path());
        for key in keys.into_iter().skip(1) {
            std::env::remove_var(key);
        }
        Self {
            _dir: dir,
            original,
            _lock: lock,
        }
    }

    fn set(&self, key: &'static str, value: &str) {
        std::env::set_var(key, value);
    }

    fn remove(&self, key: &'static str) {
        std::env::remove_var(key);
    }
}

impl Drop for GeofenceEnv {
    fn drop(&mut self) {
        for (key, value) in &self.original {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn observation(bssid: &str) -> ApObservation {
    ApObservation {
        bssid: bssid.into(),
        signal_dbm: Some(-50),
    }
}

fn coordinate_zone() -> GeofenceZone {
    zones::new_zone(NewZoneInput {
        name: "Office".into(),
        topology_node_ref: Some("node-office".into()),
        kind: ZoneKind::Coordinate,
        center_lat: Some(40.0),
        center_lng: Some(-74.0),
        radius_m: Some(150.0),
        rf_signature: None,
        on_entry: true,
        on_exit: true,
        severity: "high".into(),
        automation: ZoneAutomation::default(),
        enabled: true,
    })
}

fn rf_zone(threshold: f64, aps: Vec<ApObservation>) -> GeofenceZone {
    zones::new_zone(NewZoneInput {
        name: "RF Room".into(),
        topology_node_ref: None,
        kind: ZoneKind::RfSignature,
        center_lat: None,
        center_lng: None,
        radius_m: None,
        rf_signature: Some(RfSignature { aps, threshold }),
        on_entry: true,
        on_exit: false,
        severity: "medium".into(),
        automation: ZoneAutomation::default(),
        enabled: true,
    })
}

fn invalid_message(error: GeofenceError) -> String {
    match error {
        GeofenceError::InvalidInput(message) => message,
        other => panic!("expected invalid input, got {other}"),
    }
}

#[test]
fn coordinate_validation_covers_finite_ranges_and_boundaries() {
    for (lat, lng) in [(-90.0, -180.0), (0.0, 0.0), (90.0, 180.0)] {
        zones::validate_coordinate(lat, lng).unwrap();
    }
    for (lat, lng, expected) in [
        (f64::NAN, 0.0, "latitude and longitude must be finite"),
        (0.0, f64::INFINITY, "latitude and longitude must be finite"),
        (-90.01, 0.0, "latitude must be between -90 and 90"),
        (90.01, 0.0, "latitude must be between -90 and 90"),
        (0.0, -180.01, "longitude must be between -180 and 180"),
        (0.0, 180.01, "longitude must be between -180 and 180"),
    ] {
        assert_eq!(
            invalid_message(zones::validate_coordinate(lat, lng).unwrap_err()),
            expected
        );
    }

    assert_eq!(zones::haversine_m(40.0, -74.0, 40.0, -74.0), 0.0);
    let ny_to_la = zones::haversine_m(40.7128, -74.0060, 34.0522, -118.2437);
    assert!((3_935_000.0..3_950_000.0).contains(&ny_to_la));
}

#[test]
fn zone_validation_rejects_each_invalid_shape() {
    let mut zone = coordinate_zone();
    zone.name = "  ".into();
    assert_eq!(
        invalid_message(zones::validate_zone(&zone).unwrap_err()),
        "zone name must not be empty"
    );

    zone = coordinate_zone();
    zone.severity = "urgent".into();
    assert_eq!(
        invalid_message(zones::validate_zone(&zone).unwrap_err()),
        "severity must be info, low, medium, high, or critical"
    );

    zone = coordinate_zone();
    zone.automation.min_confidence = f64::NAN;
    assert_eq!(
        invalid_message(zones::validate_zone(&zone).unwrap_err()),
        "min_confidence must be between 0.0 and 1.0"
    );

    for missing in 0..3 {
        zone = coordinate_zone();
        match missing {
            0 => zone.center_lat = None,
            1 => zone.center_lng = None,
            _ => zone.radius_m = None,
        }
        assert_eq!(
            invalid_message(zones::validate_zone(&zone).unwrap_err()),
            "coordinate zones require center_lat, center_lng, and radius_m"
        );
    }
    for radius in [0.0, -1.0, f64::INFINITY] {
        zone = coordinate_zone();
        zone.radius_m = Some(radius);
        assert_eq!(
            invalid_message(zones::validate_zone(&zone).unwrap_err()),
            "radius_m must be positive"
        );
    }

    for threshold in [f64::NAN, -0.01, 1.01] {
        let zone = rf_zone(threshold, vec![observation("aa:bb:cc:dd:ee:ff")]);
        assert_eq!(
            invalid_message(zones::validate_zone(&zone).unwrap_err()),
            "rf threshold must be between 0.0 and 1.0"
        );
    }
    let zone = rf_zone(0.5, vec![observation("  ")]);
    assert_eq!(
        invalid_message(zones::validate_zone(&zone).unwrap_err()),
        "rf BSSID must not be empty"
    );
}

#[test]
fn zone_evaluation_covers_coordinate_rf_disabled_and_mismatched_fixes() {
    let zone = coordinate_zone();
    let inside = zones::evaluate_zone(&zone, &Fix::coordinate(40.0001, -74.0001, Some(5.0)));
    assert_eq!(inside.inside, Some(true));
    assert!(inside.distance_m.unwrap() < 150.0);
    assert_eq!(inside.rf_score, None);

    let outside = zones::evaluate_zone(&zone, &Fix::coordinate(41.0, -74.0, None));
    assert_eq!(outside.inside, Some(false));
    assert!(outside.distance_m.unwrap() > 100_000.0);

    let rf = rf_zone(
        0.5,
        vec![
            observation("AA:BB:CC:DD:EE:FF"),
            observation("11:22:33:44:55:66"),
        ],
    );
    let matched = zones::evaluate_zone(
        &rf,
        &Fix::RfSignature {
            aps: vec![observation("aa:bb:cc:dd:ee:ff")],
        },
    );
    assert_eq!(matched.rf_score, Some(0.5));
    assert_eq!(matched.inside, Some(true));
    let unmatched = zones::evaluate_zone(&rf, &Fix::RfSignature { aps: vec![] });
    assert_eq!(unmatched.rf_score, Some(0.0));
    assert_eq!(unmatched.inside, Some(false));

    let empty_signature = rf_zone(0.0, vec![]);
    assert_eq!(
        zones::evaluate_zone(&empty_signature, &Fix::RfSignature { aps: vec![] }).rf_score,
        Some(0.0)
    );
    let mismatch = zones::evaluate_zone(&zone, &Fix::RfSignature { aps: vec![] });
    assert_eq!(mismatch.inside, None);
    let mut disabled = zone.clone();
    disabled.enabled = false;
    assert_eq!(
        zones::evaluate_zone(&disabled, &Fix::coordinate(40.0, -74.0, None)).inside,
        None
    );
    assert_eq!(zones::status_without_fix(&zone).distance_m, None);
}

#[test]
fn new_zone_defaults_zero_rf_threshold_and_preserves_fields() {
    let zone = rf_zone(0.0, vec![observation("aa:bb:cc:dd:ee:ff")]);
    assert!(zone.zone_id.starts_with("urn:uuid:"));
    assert_eq!(zone.name, "RF Room");
    assert_eq!(zone.kind, ZoneKind::RfSignature);
    assert_eq!(zone.rf_signature.unwrap().threshold, 0.6);
    assert!(DateTime::parse_from_rfc3339(&zone.created_at).is_ok());
    assert_eq!(zone.created_at, zone.updated_at);

    let patch = ZonePatch::default();
    assert!(patch.name.is_none());
    assert!(patch.topology_node_ref.is_none());
    assert!(patch.kind.is_none());
    assert!(patch.automation.is_none());
}

#[test]
fn registry_sealing_is_stable_and_detects_missing_or_tampered_proofs() {
    let mut registry = GeofenceRegistry::default();
    registry.zones.push(coordinate_zone());
    assert!(matches!(
        zones::verify_registry(&registry),
        Err(GeofenceError::InvalidProof)
    ));
    zones::seal_registry(&mut registry).unwrap();
    assert_eq!(registry.proof.proof_type, "DataIntegrityProof");
    assert_eq!(registry.proof.cryptosuite, "sha2-256-tamper-evident");
    assert_eq!(registry.proof.proof_value.len(), 64);
    zones::verify_registry(&registry).unwrap();

    let canonical = registry.canonical_bytes_for_proof().unwrap();
    registry.proof.created = "changed proof metadata".into();
    assert_eq!(registry.canonical_bytes_for_proof().unwrap(), canonical);
    registry.sequence += 1;
    assert!(matches!(
        zones::verify_registry(&registry),
        Err(GeofenceError::InvalidProof)
    ));
}

#[test]
fn action_models_validate_defaults_boundaries_and_serde_variants() {
    let default = ZoneAutomation::default();
    assert!(actions::validate(&default).is_ok());
    assert_eq!(default.min_confidence, 0.9);
    assert!(!default.allow_destructive);

    for confidence in [0.0, 0.5, 1.0] {
        assert!(actions::validate(&ZoneAutomation {
            min_confidence: confidence,
            ..ZoneAutomation::default()
        })
        .is_ok());
    }
    for confidence in [f64::NEG_INFINITY, -0.1, 1.1, f64::NAN] {
        assert!(actions::validate(&ZoneAutomation {
            min_confidence: confidence,
            ..ZoneAutomation::default()
        })
        .is_err());
    }

    let actions = vec![
        GeofenceAction::RaiseAlert { severity: None },
        GeofenceAction::Notify {
            severity: Some("critical".into()),
        },
        GeofenceAction::RunScan,
        GeofenceAction::LockNetwork,
        GeofenceAction::EmergencyKeyRotation,
    ];
    for action in actions {
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(
            serde_json::from_str::<GeofenceAction>(&json).unwrap(),
            action
        );
    }
}

#[test]
fn geofence_errors_and_alert_severity_have_stable_public_contracts() {
    let cases = [
        (
            GeofenceError::NotFound("zone-a".into()),
            "geofence zone not found: zone-a",
        ),
        (
            GeofenceError::InvalidInput("bad".into()),
            "invalid geofence input: bad",
        ),
        (
            GeofenceError::InvalidProof,
            "geofence registry proof invalid",
        ),
        (
            GeofenceError::UnsupportedSource("x".into()),
            "unsupported geofence source: x",
        ),
        (
            GeofenceError::RfScanBusy("busy".into()),
            "rf scan busy: busy",
        ),
        (
            GeofenceError::RfUnavailable("down".into()),
            "rf source unavailable: down",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(error.source().is_none());
    }
    let io_error: GeofenceError = std::io::Error::new(std::io::ErrorKind::Other, "disk").into();
    assert_eq!(io_error.to_string(), "io: disk");
    assert!(io_error.source().is_some());
    let json_error: GeofenceError = serde_json::from_str::<serde_json::Value>("{")
        .unwrap_err()
        .into();
    assert!(json_error.to_string().starts_with("json:"));
    assert!(json_error.source().is_some());

    assert_eq!(alerts::parse_severity("info"), Severity::Info);
    assert_eq!(alerts::parse_severity("low"), Severity::Low);
    assert_eq!(alerts::parse_severity("medium"), Severity::Medium);
    assert_eq!(alerts::parse_severity("critical"), Severity::Critical);
    assert_eq!(alerts::parse_severity("high"), Severity::High);
    assert_eq!(alerts::parse_severity("unknown"), Severity::High);
}

#[test]
fn persistence_round_trips_locations_statuses_selection_events_and_errors() {
    let env = GeofenceEnv::new();
    assert_eq!(persistence::base_dir(), env._dir.path());
    assert!(persistence::load_registry().unwrap().is_none());
    assert!(persistence::load_location().unwrap().is_none());
    assert!(persistence::load_reported_location().unwrap().is_none());
    assert!(persistence::load_rf_location().unwrap().is_none());
    assert!(persistence::load_statuses().unwrap().is_none());
    assert!(persistence::load_source_selection().unwrap().is_none());
    assert!(persistence::list_events().unwrap().is_empty());
    assert!(alerts::list_alerts().unwrap().is_empty());

    let mut registry = GeofenceRegistry::default();
    registry.zones.push(coordinate_zone());
    zones::seal_registry(&mut registry).unwrap();
    persistence::save_registry(&registry).unwrap();
    assert_eq!(
        persistence::load_registry().unwrap().unwrap().zones.len(),
        1
    );

    let coordinate = StoredLocation::new("manual", Fix::coordinate(40.0, -74.0, Some(3.0)));
    persistence::save_location(&coordinate).unwrap();
    persistence::save_reported_location(&coordinate).unwrap();
    assert_eq!(
        persistence::load_location().unwrap(),
        Some(coordinate.clone())
    );
    assert_eq!(
        persistence::load_reported_location().unwrap(),
        Some(coordinate.clone())
    );
    assert_eq!(
        persistence::load_coordinate_location().unwrap(),
        Some(coordinate.clone())
    );

    let rf = StoredLocation::new(
        "rf",
        Fix::RfSignature {
            aps: vec![observation("aa:bb:cc:dd:ee:ff")],
        },
    );
    persistence::save_rf_location(&rf).unwrap();
    assert_eq!(persistence::load_rf_location().unwrap(), Some(rf));

    let statuses = vec![ZoneStatus {
        zone_id: "zone-a".into(),
        zone_name: "Office".into(),
        enabled: true,
        inside: Some(true),
        distance_m: Some(2.0),
        rf_score: None,
    }];
    persistence::save_statuses(&statuses).unwrap();
    assert_eq!(
        persistence::load_statuses().unwrap().unwrap()[0].inside,
        Some(true)
    );

    let selection = SourceSelectionStatus::new("forced", Some("manual".into()), "user selected");
    persistence::save_source_selection(&selection).unwrap();
    assert_eq!(
        persistence::load_source_selection().unwrap(),
        Some(selection)
    );

    let event = GeofenceEvent::new(&registry.zones[0], "entry", &coordinate.fix);
    persistence::append_event(&event).unwrap();
    persistence::append_event(&event).unwrap();
    let events = persistence::list_events().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], event);

    persistence::clear_location().unwrap();
    persistence::clear_location().unwrap();
    persistence::clear_statuses().unwrap();
    persistence::clear_statuses().unwrap();
    assert!(persistence::load_location().unwrap().is_none());
    assert!(persistence::load_statuses().unwrap().is_none());

    fs::write(persistence::zones_path(), b"not json").unwrap();
    assert!(matches!(
        persistence::load_registry(),
        Err(GeofenceError::Json(_))
    ));
    fs::write(persistence::events_path(), "{bad}\n").unwrap();
    assert!(matches!(
        persistence::list_events(),
        Err(GeofenceError::Json(_))
    ));
}

#[test]
fn zone_crud_updates_every_patch_field_and_handles_duplicates_and_missing_ids() {
    let _env = GeofenceEnv::new();
    let registry = zones::load_or_seed_registry().unwrap();
    assert!(registry.zones.is_empty());
    assert!(zones::list_zones().unwrap().is_empty());

    let original = coordinate_zone();
    let original_id = original.zone_id.clone();
    let created = zones::create_zone(original.clone()).unwrap();
    assert_eq!(created.zone_id, original_id);
    let duplicate = zones::create_zone(original).unwrap();
    assert_ne!(duplicate.zone_id, original_id);

    let automation = ZoneAutomation {
        on_entry: vec![GeofenceAction::RunScan],
        on_exit: vec![GeofenceAction::Notify {
            severity: Some("low".into()),
        }],
        allow_destructive: true,
        min_confidence: 0.75,
    };
    let updated = zones::update_zone(
        &original_id,
        ZonePatch {
            name: Some("Updated RF Zone".into()),
            topology_node_ref: Some(None),
            kind: Some(ZoneKind::RfSignature),
            center_lat: Some(None),
            center_lng: Some(None),
            radius_m: Some(None),
            rf_signature: Some(Some(RfSignature {
                aps: vec![observation("aa:bb:cc:dd:ee:ff")],
                threshold: 0.8,
            })),
            on_entry: Some(false),
            on_exit: Some(true),
            severity: Some("critical".into()),
            automation: Some(automation.clone()),
            enabled: Some(false),
        },
    )
    .unwrap();
    assert_eq!(updated.name, "Updated RF Zone");
    assert_eq!(updated.topology_node_ref, None);
    assert_eq!(updated.kind, ZoneKind::RfSignature);
    assert_eq!(updated.center_lat, None);
    assert_eq!(updated.rf_signature.unwrap().threshold, 0.8);
    assert!(!updated.on_entry);
    assert!(updated.on_exit);
    assert_eq!(updated.severity, "critical");
    assert_eq!(updated.automation, automation);
    assert!(!updated.enabled);

    let invalid_patch = ZonePatch {
        automation: Some(ZoneAutomation {
            min_confidence: 2.0,
            ..ZoneAutomation::default()
        }),
        ..ZonePatch::default()
    };
    assert!(matches!(
        zones::update_zone(&original_id, invalid_patch),
        Err(GeofenceError::InvalidInput(_))
    ));
    assert!(matches!(
        zones::update_zone("missing", ZonePatch::default()),
        Err(GeofenceError::NotFound(_))
    ));
    assert!(matches!(
        zones::delete_zone("missing"),
        Err(GeofenceError::NotFound(_))
    ));
    assert_eq!(
        zones::delete_zone(&original_id).unwrap().zone_id,
        original_id
    );
    assert_eq!(zones::list_zones().unwrap().len(), 1);
    zones::verify_registry(&persistence::load_registry().unwrap().unwrap()).unwrap();
}

#[tokio::test]
async fn source_kinds_config_and_manual_reported_sources_cover_storage_fallbacks() {
    let env = GeofenceEnv::new();
    let aliases = [
        ("", SourceKind::Auto, "auto"),
        ("AUTO", SourceKind::Auto, "auto"),
        ("manual", SourceKind::Manual, "manual"),
        ("reported", SourceKind::Reported, "reported"),
        ("rf", SourceKind::Rf, "rf"),
        ("rf_signature", SourceKind::Rf, "rf"),
        ("rf-signature", SourceKind::Rf, "rf"),
        ("gnss", SourceKind::Gnss, "gnss"),
        ("gps", SourceKind::Gnss, "gnss"),
    ];
    for (raw, expected, id) in aliases {
        env.set("SGX_GEOFENCE_SOURCE", raw);
        let kind = SourceKind::from_env().unwrap();
        assert_eq!(kind, expected);
        assert_eq!(kind.id(), id);
        assert_eq!(sources::from_env().unwrap().id(), id);
    }
    env.set("SGX_GEOFENCE_SOURCE", "satellite");
    assert!(matches!(
        SourceKind::from_env(),
        Err(GeofenceError::UnsupportedSource(source)) if source == "satellite"
    ));
    env.remove("SGX_GEOFENCE_SOURCE");
    assert_eq!(SourceKind::from_env().unwrap(), SourceKind::Auto);

    env.set("SGX_GEOFENCE_EVAL_SECS", "0");
    env.set("SGX_GEOFENCE_HYSTERESIS", "999");
    let config = GeofenceConfig::from_env();
    assert_eq!(config.eval_secs, 1);
    assert_eq!(config.hysteresis, 100);
    env.set("SGX_GEOFENCE_EVAL_SECS", "invalid");
    env.set("SGX_GEOFENCE_HYSTERESIS", "invalid");
    let defaults = GeofenceConfig::from_env();
    assert_eq!(defaults.eval_secs, GeofenceConfig::DEFAULT_EVAL_SECS);
    assert_eq!(defaults.hysteresis, GeofenceConfig::DEFAULT_HYSTERESIS);
    env.set("SGX_GEOFENCE_EVAL_SECS", "9999");
    assert_eq!(GeofenceConfig::from_env().eval_secs, 3600);
    env.set("SGX_GEOFENCE_SOURCE_FRESHNESS_SECS", "45");
    assert_eq!(sources::configured_freshness().as_secs(), 45);
    env.set("SGX_GEOFENCE_SOURCE_FRESHNESS_SECS", "invalid");
    assert_eq!(sources::configured_freshness().as_secs(), 120);

    let manual = ManualSource;
    assert_eq!(manual.id(), "manual");
    assert_eq!(manual.active_id(), "manual");
    assert_eq!(manual.selection_mode(), "forced");
    assert_eq!(manual.source_reason(), "forced manual");
    assert_eq!(manual.current().await, None);

    let manual_location = StoredLocation::new("manual", Fix::coordinate(1.0, 2.0, None));
    persistence::save_reported_location(&manual_location).unwrap();
    assert_eq!(manual.current().await, Some(manual_location.fix.clone()));

    fs::remove_file(persistence::reported_location_path()).unwrap();
    let reported_location = StoredLocation::new("reported", Fix::coordinate(3.0, 4.0, None));
    persistence::save_location(&reported_location).unwrap();
    let reported = ReportedSource;
    assert_eq!(reported.id(), "reported");
    assert_eq!(
        reported.current().await,
        Some(reported_location.fix.clone())
    );
    persistence::save_reported_location(&reported_location).unwrap();
    assert_eq!(reported.current().await, Some(reported_location.fix));
}
