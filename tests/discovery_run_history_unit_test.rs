use chrono::{DateTime, Utc};
use sgx_guardian_client::discovery::connected_device::DeviceStatus;
use sgx_guardian_client::discovery::inventory::{Inventory, InventoryDelta};
use sgx_guardian_client::discovery::run_history::{
    append_record, build_record, history_path, list_recent, status_counts, InventoryStatusCounts,
    ScanRunRecord, ScanRunSource,
};
use sgx_guardian_client::discovery::{ConnectedDevice, ScanIntensity, ScheduledScanKind};
use std::path::{Path, PathBuf};

fn fixed_time(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}

fn device(id: &str, status: DeviceStatus) -> ConnectedDevice {
    ConnectedDevice {
        device_id: id.into(),
        ip: format!("192.168.50.{}", id.len()),
        mac: Some(format!("AA:BB:CC:DD:EE:{:02X}", id.len())),
        vendor: None,
        hostname: None,
        os_fingerprint: None,
        os_cpe: Vec::new(),
        open_ports: Vec::new(),
        host_scripts: Vec::new(),
        status,
        first_seen: "2026-01-01T00:00:00Z".into(),
        last_seen: "2026-01-01T00:00:00Z".into(),
        vuln_triaged: false,
        last_scan_intensity: None,
    }
}

fn record(run_id: &str, intensity: ScanIntensity) -> ScanRunRecord {
    ScanRunRecord {
        run_id: run_id.into(),
        started_at: fixed_time(100),
        completed_at: fixed_time(101),
        duration_ms: 1000,
        source: ScanRunSource::Manual,
        schedule_kind: None,
        intensity,
        target: "192.168.50.0/24".into(),
        success: true,
        error: None,
        new_devices: 1,
        updated_devices: 2,
        marked_stale: 3,
        total_devices: 6,
        approved: 1,
        unauthorized: 2,
        drifted: 1,
        stale: 2,
        raw_xml_path: None,
        inventory_path: "inventory.json".into(),
    }
}

#[test]
fn history_path_appends_runs_file_name() {
    assert_eq!(
        history_path(Path::new("/tmp/state")),
        PathBuf::from("/tmp/state/runs.jsonl")
    );
}

#[test]
fn status_counts_empty_inventory_is_default() {
    assert_eq!(
        status_counts(&Inventory::default()),
        InventoryStatusCounts::default()
    );
}

#[test]
fn status_counts_counts_all_status_variants() {
    let mut inventory = Inventory::default();
    inventory
        .by_id
        .insert("a".into(), device("a", DeviceStatus::Approved));
    inventory
        .by_id
        .insert("u".into(), device("u", DeviceStatus::Unauthorized));
    inventory
        .by_id
        .insert("d".into(), device("d", DeviceStatus::Drifted));
    inventory
        .by_id
        .insert("s".into(), device("s", DeviceStatus::Stale));
    assert_eq!(
        status_counts(&inventory),
        InventoryStatusCounts {
            total_devices: 4,
            approved: 1,
            unauthorized: 1,
            drifted: 1,
            stale: 1,
        }
    );
}

#[test]
fn build_record_includes_delta_counts_and_paths() {
    let delta = InventoryDelta {
        newly_seen: vec!["n".into()],
        updated: vec!["u1".into(), "u2".into()],
        marked_stale: vec!["s".into()],
    };
    let built = build_record(
        fixed_time(100),
        fixed_time(105),
        ScanRunSource::Scheduled,
        Some(ScheduledScanKind::Hourly),
        ScanIntensity::Aggressive,
        "target".into(),
        false,
        Some("boom".into()),
        Some(&delta),
        InventoryStatusCounts {
            total_devices: 9,
            approved: 3,
            unauthorized: 2,
            drifted: 1,
            stale: 3,
        },
        Some(PathBuf::from("/tmp/raw.xml")),
        Path::new("/tmp/inventory.json"),
    );
    assert!(built.run_id.starts_with("19700101T000140Z-aggressive-"));
    assert_eq!(built.duration_ms, 5000);
    assert_eq!(built.new_devices, 1);
    assert_eq!(built.updated_devices, 2);
    assert_eq!(built.marked_stale, 1);
    assert_eq!(built.raw_xml_path.as_deref(), Some("/tmp/raw.xml"));
    assert_eq!(built.inventory_path, "/tmp/inventory.json");
}

#[test]
fn build_record_without_delta_defaults_delta_counts_to_zero() {
    let built = build_record(
        fixed_time(100),
        fixed_time(101),
        ScanRunSource::Manual,
        None,
        ScanIntensity::Stealth,
        "target".into(),
        true,
        None,
        None,
        InventoryStatusCounts::default(),
        None,
        Path::new("inventory.json"),
    );
    assert_eq!(built.new_devices, 0);
    assert_eq!(built.updated_devices, 0);
    assert_eq!(built.marked_stale, 0);
    assert!(built.error.is_none());
}

#[test]
fn build_record_clamps_negative_duration_to_zero() {
    let built = build_record(
        fixed_time(200),
        fixed_time(100),
        ScanRunSource::Manual,
        None,
        ScanIntensity::Standard,
        "target".into(),
        true,
        None,
        None,
        InventoryStatusCounts::default(),
        None,
        Path::new("inventory.json"),
    );
    assert_eq!(built.duration_ms, 0);
}

#[test]
fn build_record_run_id_contains_each_intensity_name() {
    for (intensity, name) in [
        (ScanIntensity::Stealth, "stealth"),
        (ScanIntensity::Standard, "standard"),
        (ScanIntensity::Aggressive, "aggressive"),
    ] {
        let built = build_record(
            fixed_time(300),
            fixed_time(300),
            ScanRunSource::Manual,
            None,
            intensity,
            "target".into(),
            true,
            None,
            None,
            InventoryStatusCounts::default(),
            None,
            Path::new("inventory.json"),
        );
        assert!(built.run_id.contains(name));
    }
}

#[test]
fn append_record_creates_parent_and_newline_delimits_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/runs.jsonl");
    append_record(&path, &record("one", ScanIntensity::Stealth)).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.ends_with('\n'));
    assert_eq!(text.lines().count(), 1);
}

#[test]
fn append_record_appends_without_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = history_path(dir.path());
    append_record(&path, &record("one", ScanIntensity::Stealth)).unwrap();
    append_record(&path, &record("two", ScanIntensity::Standard)).unwrap();
    assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 2);
}

#[test]
fn list_recent_missing_file_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    assert!(list_recent(&dir.path().join("missing.jsonl"), None)
        .unwrap()
        .is_empty());
}

#[test]
fn list_recent_returns_newest_first() {
    let dir = tempfile::tempdir().unwrap();
    let path = history_path(dir.path());
    append_record(&path, &record("old", ScanIntensity::Stealth)).unwrap();
    append_record(&path, &record("new", ScanIntensity::Standard)).unwrap();
    let listed = list_recent(&path, None).unwrap();
    assert_eq!(listed[0].run_id, "new");
    assert_eq!(listed[1].run_id, "old");
}

#[test]
fn list_recent_limit_zero_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = history_path(dir.path());
    append_record(&path, &record("one", ScanIntensity::Stealth)).unwrap();
    assert!(list_recent(&path, Some(0)).unwrap().is_empty());
}

#[test]
fn list_recent_limit_larger_than_history_returns_all() {
    let dir = tempfile::tempdir().unwrap();
    let path = history_path(dir.path());
    append_record(&path, &record("one", ScanIntensity::Stealth)).unwrap();
    append_record(&path, &record("two", ScanIntensity::Standard)).unwrap();
    assert_eq!(list_recent(&path, Some(99)).unwrap().len(), 2);
}

#[test]
fn list_recent_ignores_blank_and_malformed_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = history_path(dir.path());
    let valid = serde_json::to_string(&record("valid", ScanIntensity::Standard)).unwrap();
    std::fs::write(&path, format!("\nnot-json\n{}\n  \n", valid)).unwrap();
    let listed = list_recent(&path, None).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].run_id, "valid");
}

#[test]
fn scan_run_source_serializes_as_snake_case() {
    assert_eq!(
        serde_json::to_value(ScanRunSource::Manual).unwrap(),
        "manual"
    );
    assert_eq!(
        serde_json::to_value(ScanRunSource::Scheduled).unwrap(),
        "scheduled"
    );
}

#[test]
fn scan_run_record_round_trips_json() {
    let original = record("round-trip", ScanIntensity::Aggressive);
    let json = serde_json::to_string(&original).unwrap();
    let decoded: ScanRunRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}
