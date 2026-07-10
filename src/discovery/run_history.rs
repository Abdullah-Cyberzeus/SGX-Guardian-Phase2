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
}
