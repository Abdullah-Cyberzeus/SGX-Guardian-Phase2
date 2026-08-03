use crate::geofence::errors::{GeofenceError, GeofenceResult};
use crate::geofence::model::{
    GeofenceEvent, GeofenceRegistry, SourceSelectionStatus, StoredLocation, ZoneStatus,
};
use std::collections::VecDeque;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const GEOFENCE_BASE: &str = "/var/lib/sgx-guardian/geofence";
pub const GEOFENCE_BASE_ENV: &str = "SGX_GUARDIAN_GEOFENCE_BASE";
pub const MAX_EVENTS: usize = 10_000;

#[cfg(test)]
pub static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn base_dir() -> PathBuf {
    env::var(GEOFENCE_BASE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(GEOFENCE_BASE))
}

pub fn zones_path() -> PathBuf {
    base_dir().join("zones.json")
}

pub fn location_path() -> PathBuf {
    base_dir().join("location.json")
}

pub fn reported_location_path() -> PathBuf {
    base_dir().join("reported_location.json")
}

pub fn rf_location_path() -> PathBuf {
    base_dir().join("rf_location.json")
}

pub fn events_path() -> PathBuf {
    base_dir().join("events.jsonl")
}

pub fn status_path() -> PathBuf {
    base_dir().join("status.json")
}

pub fn source_selection_path() -> PathBuf {
    base_dir().join("source_selection.json")
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> GeofenceResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

pub fn load_registry() -> GeofenceResult<Option<GeofenceRegistry>> {
    let path = zones_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub fn save_registry(registry: &GeofenceRegistry) -> GeofenceResult<()> {
    write_atomic(&zones_path(), &serde_json::to_vec_pretty(registry)?)
}

pub fn load_location() -> GeofenceResult<Option<StoredLocation>> {
    let path = location_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub async fn load_location_async() -> GeofenceResult<Option<StoredLocation>> {
    let path = location_path();
    if !tokio::fs::try_exists(&path).await? {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&tokio::fs::read(path).await?)?))
}

pub fn save_location(location: &StoredLocation) -> GeofenceResult<()> {
    write_atomic(&location_path(), &serde_json::to_vec_pretty(location)?)
}

pub fn clear_location() -> GeofenceResult<()> {
    match fs::remove_file(location_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn load_reported_location() -> GeofenceResult<Option<StoredLocation>> {
    let path = reported_location_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub async fn load_reported_location_async() -> GeofenceResult<Option<StoredLocation>> {
    let path = reported_location_path();
    if !tokio::fs::try_exists(&path).await? {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&tokio::fs::read(path).await?)?))
}

pub fn save_reported_location(location: &StoredLocation) -> GeofenceResult<()> {
    write_atomic(
        &reported_location_path(),
        &serde_json::to_vec_pretty(location)?,
    )
}

pub fn load_rf_location() -> GeofenceResult<Option<StoredLocation>> {
    let path = rf_location_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub fn save_rf_location(location: &StoredLocation) -> GeofenceResult<()> {
    write_atomic(&rf_location_path(), &serde_json::to_vec_pretty(location)?)
}

pub fn load_coordinate_location() -> GeofenceResult<Option<StoredLocation>> {
    if let Some(location) = load_reported_location()? {
        if matches!(location.fix, crate::geofence::model::Fix::Coordinate { .. }) {
            return Ok(Some(location));
        }
    }
    Ok(load_location()?.filter(|location| {
        matches!(location.fix, crate::geofence::model::Fix::Coordinate { .. })
            && matches!(location.source.as_str(), "reported" | "manual" | "gnss")
    }))
}

pub fn load_statuses() -> GeofenceResult<Option<Vec<ZoneStatus>>> {
    let path = status_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub fn save_statuses(statuses: &[ZoneStatus]) -> GeofenceResult<()> {
    write_atomic(&status_path(), &serde_json::to_vec_pretty(statuses)?)
}

pub fn clear_statuses() -> GeofenceResult<()> {
    match fs::remove_file(status_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn load_source_selection() -> GeofenceResult<Option<SourceSelectionStatus>> {
    let path = source_selection_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub fn save_source_selection(selection: &SourceSelectionStatus) -> GeofenceResult<()> {
    write_atomic(
        &source_selection_path(),
        &serde_json::to_vec_pretty(selection)?,
    )
}

pub fn append_event(event: &GeofenceEvent) -> GeofenceResult<()> {
    let mut events: VecDeque<GeofenceEvent> = list_events()?.into();
    events.push_back(event.clone());
    while events.len() > MAX_EVENTS {
        events.pop_front();
    }
    save_events(events.into_iter().collect())
}

pub fn list_events() -> GeofenceResult<Vec<GeofenceEvent>> {
    let path = events_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let text = fs::read_to_string(path)?;
    let mut events = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        events.push(serde_json::from_str(line)?);
    }
    Ok(events)
}

fn save_events(events: Vec<GeofenceEvent>) -> GeofenceResult<()> {
    let path = events_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("jsonl.tmp");
    {
        let mut file = File::create(&tmp)?;
        for event in events {
            serde_json::to_writer(&mut file, &event)?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    sync_parent_dir(&path)?;
    Ok(())
}

fn sync_parent_dir(path: &Path) -> Result<(), GeofenceError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}
