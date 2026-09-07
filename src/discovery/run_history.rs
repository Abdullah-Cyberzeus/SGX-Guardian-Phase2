use crate::discovery::{
    connected_device::DeviceStatus,
    error::DiscoveryResult,
    inventory::{Inventory, InventoryDelta},
    ScanIntensity, ScheduledScanKind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const RUN_HISTORY_FILE: &str = "runs.jsonl";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanRunSource {
    Manual,
    Scheduled,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryStatusCounts {
    pub total_devices: usize,
    pub approved: usize,
    pub unauthorized: usize,
    pub drifted: usize,
    pub stale: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRunRecord {
    pub run_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u128,
    pub source: ScanRunSource,
    pub schedule_kind: Option<ScheduledScanKind>,
    pub intensity: ScanIntensity,
    pub target: String,
    pub success: bool,
    pub error: Option<String>,
    pub new_devices: usize,
    pub updated_devices: usize,
    pub marked_stale: usize,
    pub total_devices: usize,
    pub approved: usize,
    pub unauthorized: usize,
    pub drifted: usize,
    pub stale: usize,
    pub raw_xml_path: Option<String>,
    pub inventory_path: String,
}

pub fn history_path(state_dir: &Path) -> PathBuf {
    state_dir.join(RUN_HISTORY_FILE)
}

pub fn status_counts(inventory: &Inventory) -> InventoryStatusCounts {
    let mut counts = InventoryStatusCounts {
        total_devices: inventory.by_id.len(),
        ..InventoryStatusCounts::default()
    };

    for device in inventory.by_id.values() {
        match device.status {
            DeviceStatus::Approved => counts.approved += 1,
            DeviceStatus::Unauthorized => counts.unauthorized += 1,
            DeviceStatus::Drifted => counts.drifted += 1,
            DeviceStatus::Stale => counts.stale += 1,
        }
    }

    counts
}

#[allow(clippy::too_many_arguments)]
pub fn build_record(
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    source: ScanRunSource,
    schedule_kind: Option<ScheduledScanKind>,
    intensity: ScanIntensity,
    target: String,
    success: bool,
    error: Option<String>,
    delta: Option<&InventoryDelta>,
    counts: InventoryStatusCounts,
    raw_xml_path: Option<PathBuf>,
    inventory_path: &Path,
) -> ScanRunRecord {
    let duration_ms = completed_at
        .signed_duration_since(started_at)
        .num_milliseconds()
        .max(0) as u128;

    ScanRunRecord {
        run_id: format!(
            "{}-{}-{}",
            started_at.format("%Y%m%dT%H%M%SZ"),
            intensity_name(intensity),
            uuid::Uuid::new_v4()
        ),
        started_at,
        completed_at,
        duration_ms,
        source,
        schedule_kind,
        intensity,
        target,
        success,
        error,
        new_devices: delta.map(|value| value.newly_seen.len()).unwrap_or(0),
        updated_devices: delta.map(|value| value.updated.len()).unwrap_or(0),
        marked_stale: delta.map(|value| value.marked_stale.len()).unwrap_or(0),
        total_devices: counts.total_devices,
        approved: counts.approved,
        unauthorized: counts.unauthorized,
        drifted: counts.drifted,
        stale: counts.stale,
        raw_xml_path: raw_xml_path.map(|path| path.display().to_string()),
        inventory_path: inventory_path.display().to_string(),
    }
}

pub fn append_record(path: &Path, record: &ScanRunRecord) -> DiscoveryResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub fn list_recent(path: &Path, limit: Option<usize>) -> DiscoveryResult<Vec<ScanRunRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let text = fs::read_to_string(path)?;
    let mut records = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<ScanRunRecord>(line).ok())
        .collect::<Vec<_>>();

    records.reverse();
    if let Some(limit) = limit {
        records.truncate(limit);
    }
    Ok(records)
}

fn intensity_name(intensity: ScanIntensity) -> &'static str {
    match intensity {
        ScanIntensity::Stealth => "stealth",
        ScanIntensity::Standard => "standard",
        ScanIntensity::Aggressive => "aggressive",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(run_id: &str, intensity: ScanIntensity) -> ScanRunRecord {
        let now = Utc::now();
        ScanRunRecord {
            run_id: run_id.to_string(),
            started_at: now,
            completed_at: now,
            duration_ms: 0,
            source: ScanRunSource::Manual,
            schedule_kind: None,
            intensity,
            target: "192.168.50.0/24".into(),
            success: true,
            error: None,
            new_devices: 1,
            updated_devices: 2,
            marked_stale: 0,
            total_devices: 3,
            approved: 1,
            unauthorized: 2,
            drifted: 0,
            stale: 0,
            raw_xml_path: Some("/var/lib/sgx-guardian/discovery/raw/1.xml".into()),
            inventory_path: "/var/lib/sgx-guardian/discovery/inventory.json".into(),
        }
    }

    #[test]
    fn append_and_list_recent_returns_newest_first_with_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = history_path(dir.path());

        append_record(&path, &record("first", ScanIntensity::Stealth)).expect("append first");
        append_record(&path, &record("second", ScanIntensity::Standard)).expect("append second");

        let runs = list_recent(&path, Some(1)).expect("list recent");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, "second");
        assert_eq!(runs[0].intensity, ScanIntensity::Standard);
    }

    fn device(id: &str, status: DeviceStatus) -> crate::discovery::ConnectedDevice {
        crate::discovery::ConnectedDevice {
            device_id: id.into(),
            ip: "192.168.50.10".into(),
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

    fn fixed_time(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).expect("fixed timestamp")
    }

    #[test]
    fn history_path_appends_runs_jsonl() {
        assert_eq!(
            history_path(Path::new("/tmp/discovery")),
            PathBuf::from("/tmp/discovery").join("runs.jsonl")
        );
    }

    #[test]
    fn status_counts_empty_inventory_is_zeroed() {
        let inventory = Inventory::default();
        assert_eq!(status_counts(&inventory), InventoryStatusCounts::default());
    }

    #[test]
    fn status_counts_counts_each_status_bucket() {
        let mut inventory = Inventory::default();
        inventory.by_id.insert(
            "approved".into(),
            device("approved", DeviceStatus::Approved),
        );
        inventory.by_id.insert(
            "unauthorized".into(),
            device("unauthorized", DeviceStatus::Unauthorized),
        );
        inventory
            .by_id
            .insert("drifted".into(), device("drifted", DeviceStatus::Drifted));
        inventory
            .by_id
            .insert("stale".into(), device("stale", DeviceStatus::Stale));

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
    fn build_record_populates_delta_counts_paths_and_duration() {
        let delta = InventoryDelta {
            newly_seen: vec!["new".into()],
            updated: vec!["updated-a".into(), "updated-b".into()],
            marked_stale: vec!["stale".into()],
        };
        let record = build_record(
            fixed_time(100),
            fixed_time(103),
            ScanRunSource::Scheduled,
            Some(ScheduledScanKind::Daily),
            ScanIntensity::Aggressive,
            "10.0.0.0/24".into(),
            false,
            Some("scan failed".into()),
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

        assert!(record.run_id.starts_with("19700101T000140Z-aggressive-"));
        assert_eq!(record.duration_ms, 3_000);
        assert_eq!(record.source, ScanRunSource::Scheduled);
        assert_eq!(record.schedule_kind, Some(ScheduledScanKind::Daily));
        assert_eq!(record.error.as_deref(), Some("scan failed"));
        assert_eq!(record.new_devices, 1);
        assert_eq!(record.updated_devices, 2);
        assert_eq!(record.marked_stale, 1);
        assert_eq!(record.raw_xml_path.as_deref(), Some("/tmp/raw.xml"));
        assert_eq!(record.inventory_path, "/tmp/inventory.json");
    }

    #[test]
    fn build_record_without_delta_or_raw_path_defaults_counts_to_zero() {
        let record = build_record(
            fixed_time(100),
            fixed_time(101),
            ScanRunSource::Manual,
            None,
            ScanIntensity::Stealth,
            "host".into(),
            true,
            None,
            None,
            InventoryStatusCounts::default(),
            None,
            Path::new("inventory.json"),
        );
        assert_eq!(record.new_devices, 0);
        assert_eq!(record.updated_devices, 0);
        assert_eq!(record.marked_stale, 0);
        assert!(record.raw_xml_path.is_none());
        assert!(record.error.is_none());
    }

    #[test]
    fn build_record_clamps_negative_duration_to_zero() {
        let record = build_record(
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
        assert_eq!(record.duration_ms, 0);
    }

    #[test]
    fn build_record_run_id_contains_each_intensity_name() {
        for (intensity, name) in [
            (ScanIntensity::Stealth, "stealth"),
            (ScanIntensity::Standard, "standard"),
            (ScanIntensity::Aggressive, "aggressive"),
        ] {
            let record = build_record(
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
            assert!(record.run_id.contains(name));
        }
    }

    #[test]
    fn append_record_creates_parent_and_writes_newline_delimited_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("runs.jsonl");
        append_record(&path, &record("one", ScanIntensity::Stealth)).expect("append");
        let text = fs::read_to_string(&path).expect("read history");
        assert!(text.ends_with('\n'));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn append_record_appends_without_overwriting_existing_runs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = history_path(dir.path());
        append_record(&path, &record("one", ScanIntensity::Stealth)).expect("append one");
        append_record(&path, &record("two", ScanIntensity::Standard)).expect("append two");
        assert_eq!(fs::read_to_string(&path).expect("read").lines().count(), 2);
    }

    #[test]
    fn list_recent_missing_file_returns_empty_vec() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(list_recent(&dir.path().join("missing.jsonl"), None)
            .expect("missing history")
            .is_empty());
    }

    #[test]
    fn list_recent_ignores_blank_and_malformed_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = history_path(dir.path());
        let valid = serde_json::to_string(&record("valid", ScanIntensity::Standard)).unwrap();
        fs::write(&path, format!("\nnot-json\n{}\n  \n", valid)).expect("write mixed history");
        let runs = list_recent(&path, None).expect("list");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, "valid");
    }

    #[test]
    fn list_recent_returns_newest_first_without_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = history_path(dir.path());
        append_record(&path, &record("old", ScanIntensity::Stealth)).expect("append old");
        append_record(&path, &record("new", ScanIntensity::Standard)).expect("append new");
        let runs = list_recent(&path, None).expect("list");
        assert_eq!(runs[0].run_id, "new");
        assert_eq!(runs[1].run_id, "old");
    }

    #[test]
    fn list_recent_limit_zero_returns_empty_vec() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = history_path(dir.path());
        append_record(&path, &record("one", ScanIntensity::Stealth)).expect("append");
        assert!(list_recent(&path, Some(0)).expect("list").is_empty());
    }

    #[test]
    fn list_recent_limit_larger_than_history_returns_all_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = history_path(dir.path());
        append_record(&path, &record("one", ScanIntensity::Stealth)).expect("append one");
        append_record(&path, &record("two", ScanIntensity::Standard)).expect("append two");
        assert_eq!(list_recent(&path, Some(99)).expect("list").len(), 2);
    }

    #[test]
    fn scan_run_source_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_value(ScanRunSource::Manual).unwrap(),
            serde_json::json!("manual")
        );
        assert_eq!(
            serde_json::to_value(ScanRunSource::Scheduled).unwrap(),
            serde_json::json!("scheduled")
        );
    }

    #[test]
    fn scan_run_record_round_trips_through_json() {
        let original = record("round-trip", ScanIntensity::Aggressive);
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: ScanRunRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, original);
    }
}
