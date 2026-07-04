use crate::api::{error::ApiError, state::AppState};
use crate::discovery::whitelist::{Whitelist, WhitelistEntry};
use crate::discovery::{
    ConnectedDevice, DeviceStatus, NmapConfig, ScanIntensity, ScanSchedule, ScheduleProfile,
    ScheduledScans,
};
use axum::extract::{Path as AxumPath, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Ports that are considered risky when exposed on an unauthorized device.
const HIGH_RISK_PORTS: &[u16] = &[
    21, 22, 23, 25, 111, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8000, 8080, 8443,
];

pub async fn list_devices(
    State(s): State<Arc<AppState>>,
) -> Result<Json<Vec<ConnectedDevice>>, ApiError> {
    let path = inventory_path(&s);

    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| ApiError::NotFound("no scan has run yet".into()))?;

    let devices: Vec<ConnectedDevice> = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::Internal(format!("inventory parse: {}", e)))?;

    Ok(Json(devices))
}

pub async fn list_unauthorized(
    State(s): State<Arc<AppState>>,
) -> Result<Json<Vec<ConnectedDevice>>, ApiError> {
    let Json(all) = list_devices(State(s)).await?;

    let filtered = all
        .into_iter()
        .filter(|d| matches!(d.status, DeviceStatus::Unauthorized | DeviceStatus::Drifted))
        .collect();

    Ok(Json(filtered))
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub timestamp: String,
}

pub async fn scan_now(State(_s): State<Arc<AppState>>) -> Result<Json<ScanResponse>, ApiError> {
    scan_with_args(&["discovery", "scan"]).await
}

pub async fn scan_stealth(State(_s): State<Arc<AppState>>) -> Result<Json<ScanResponse>, ApiError> {
    scan_with_args(&["discovery", "scan", "--intensity", "stealth"]).await
}

pub async fn scan_standard(
    State(_s): State<Arc<AppState>>,
) -> Result<Json<ScanResponse>, ApiError> {
    scan_with_args(&["discovery", "scan", "--intensity", "standard"]).await
}

pub async fn scan_aggressive(
    State(_s): State<Arc<AppState>>,
) -> Result<Json<ScanResponse>, ApiError> {
    scan_with_args(&["discovery", "scan", "--intensity", "aggressive"]).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistDoc {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub devices: Vec<WhitelistEntry>,
}

fn default_version() -> String {
    "1.0".to_string()
}

impl Default for WhitelistDoc {
    fn default() -> Self {
        Self {
            version: default_version(),
            devices: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApproveRequest {
    pub mac: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApproveResponse {
    pub success: bool,
    pub created: bool,
    pub inventory_updated: usize,
    pub entry: WhitelistEntry,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScheduleDoc {
    pub enabled: bool,
    pub target_cidr: Option<String>,
    pub timeout_secs: u64,
    pub exclude: Vec<String>,
    pub schedules: ScheduledScans,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_schedule_mode: Option<ScanSchedule>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScheduleUpdateRequest {
    pub enabled: Option<bool>,
    #[serde(default)]
    pub target_cidr: Option<Option<String>>,
    pub timeout_secs: Option<u64>,
    pub exclude: Option<Vec<String>>,
    pub schedules: Option<SchedulePatch>,
    pub hourly_intensity: Option<ScanIntensity>,
    pub daily_intensity: Option<ScanIntensity>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SchedulePatch {
    pub hourly: Option<ScheduleProfilePatch>,
    pub daily: Option<ScheduleProfilePatch>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScheduleProfilePatch {
    pub intensity: Option<ScanIntensity>,
}

pub async fn get_whitelist(State(s): State<Arc<AppState>>) -> Result<Json<WhitelistDoc>, ApiError> {
    Ok(Json(load_whitelist_doc(&whitelist_path(&s))?))
}

pub async fn put_whitelist(
    State(s): State<Arc<AppState>>,
    Json(mut body): Json<WhitelistDoc>,
) -> Result<Json<WhitelistDoc>, ApiError> {
    if body.version.trim().is_empty() {
        body.version = default_version();
    }

    let path = whitelist_path(&s);
    let yaml = serde_yaml::to_string(&body)
        .map_err(|e| ApiError::Internal(format!("whitelist serialization error: {}", e)))?;
    atomic_write_bytes(&path, yaml.as_bytes(), "yaml.tmp")?;
    let runtime_whitelist = runtime_whitelist(&body);
    let _ = refresh_inventory_statuses(&inventory_path(&s), &runtime_whitelist)?;
    Ok(Json(body))
}

pub async fn approve_device(
    State(s): State<Arc<AppState>>,
    Json(body): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, ApiError> {
    let normalized_mac = normalize_mac(&body.mac)?;
    let whitelist_file = whitelist_path(&s);
    let mut doc = load_whitelist_doc(&whitelist_file)?;
    let mut created = false;
    let entry = match doc
        .devices
        .iter_mut()
        .find(|entry| normalize_mac_lossy(&entry.mac) == normalized_mac)
    {
        Some(existing) => {
            if let Some(label) = body.label {
                existing.label = Some(label);
            }
            existing.clone()
        }
        None => {
            let entry = WhitelistEntry {
                mac: normalized_mac,
                label: body.label,
                expected_os: None,
                expected_ports: Vec::new(),
                expected_ips: Vec::new(),
            };
            doc.devices.push(entry.clone());
            created = true;
            entry
        }
    };

    doc.devices
        .sort_by_key(|existing| normalize_mac_lossy(existing.mac.as_str()));

    let yaml = serde_yaml::to_string(&doc)
        .map_err(|e| ApiError::Internal(format!("whitelist serialization error: {}", e)))?;
    atomic_write_bytes(&whitelist_file, yaml.as_bytes(), "yaml.tmp")?;

    let inventory_updated =
        refresh_inventory_statuses(&inventory_path(&s), &runtime_whitelist(&doc))?;

    Ok(Json(ApproveResponse {
        success: true,
        created,
        inventory_updated,
        entry,
    }))
}

pub async fn get_schedule(State(s): State<Arc<AppState>>) -> Result<Json<ScheduleDoc>, ApiError> {
    let cfg = load_nmap_config(&schedule_path(&s))?;
    Ok(Json(schedule_doc_from_config(&cfg)))
}

pub async fn put_schedule(
    State(s): State<Arc<AppState>>,
    Json(body): Json<ScheduleUpdateRequest>,
) -> Result<Json<ScheduleDoc>, ApiError> {
    let path = schedule_path(&s);
    let mut cfg = load_nmap_config(&path)?;
    apply_schedule_patch(&mut cfg, body)?;
    cfg.validate()
        .map_err(|e| ApiError::BadRequest(format!("invalid discovery schedule config: {}", e)))?;

    let yaml = serde_yaml::to_string(&cfg)
        .map_err(|e| ApiError::Internal(format!("schedule serialization error: {}", e)))?;
    atomic_write_bytes(&path, yaml.as_bytes(), "yaml.tmp")?;

    let persisted = load_nmap_config(&path)?;
    Ok(Json(schedule_doc_from_config(&persisted)))
}

fn inventory_path(state: &AppState) -> PathBuf {
    PathBuf::from(&state.discovery_state_dir).join("inventory.json")
}

fn whitelist_path(state: &AppState) -> PathBuf {
    PathBuf::from(&state.discovery_config_dir).join("whitelist.yaml")
}

fn schedule_path(state: &AppState) -> PathBuf {
    PathBuf::from(&state.discovery_config_dir).join("nmap.yaml")
}

fn load_whitelist_doc(path: &Path) -> Result<WhitelistDoc, ApiError> {
    if !path.exists() {
        return Ok(WhitelistDoc::default());
    }

    let text = std::fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Ok(WhitelistDoc::default());
    }

    serde_yaml::from_str(&text)
        .map_err(|e| ApiError::Internal(format!("whitelist parse error: {}", e)))
}

fn load_nmap_config(path: &Path) -> Result<NmapConfig, ApiError> {
    NmapConfig::load(path)
        .map_err(|e| ApiError::BadRequest(format!("discovery config load error: {}", e)))
}

fn schedule_doc_from_config(cfg: &NmapConfig) -> ScheduleDoc {
    ScheduleDoc {
        enabled: cfg.enabled,
        target_cidr: cfg.target_cidr.clone(),
        timeout_secs: cfg.timeout_secs,
        exclude: cfg.exclude.clone(),
        schedules: cfg.schedules.clone(),
        legacy_schedule_mode: cfg.legacy_schedule_mode(),
    }
}

fn runtime_whitelist(doc: &WhitelistDoc) -> Whitelist {
    let entries = doc
        .devices
        .iter()
        .cloned()
        .map(|entry| (normalize_mac_lossy(&entry.mac), entry))
        .collect();
    Whitelist { entries }
}

fn refresh_inventory_statuses(path: &Path, whitelist: &Whitelist) -> Result<usize, ApiError> {
    if !path.exists() {
        return Ok(0);
    }

    let bytes = std::fs::read(path)?;
    let mut devices: Vec<ConnectedDevice> = serde_json::from_slice(&bytes)?;
    let mut updated = 0usize;

    for device in &mut devices {
        if matches!(device.status, DeviceStatus::Stale) {
            continue;
        }

        let before = device.status;
        whitelist.classify(device);
        if device.status != before {
            updated += 1;
        }
    }

    let serialized = serde_json::to_vec_pretty(&devices)
        .map_err(|e| ApiError::Internal(format!("inventory serialization error: {}", e)))?;
    atomic_write_bytes(path, &serialized, "json.tmp")?;
    Ok(updated)
}

fn apply_schedule_patch(
    cfg: &mut NmapConfig,
    patch: ScheduleUpdateRequest,
) -> Result<(), ApiError> {
    if let Some(enabled) = patch.enabled {
        cfg.enabled = enabled;
    }

    if let Some(target) = patch.target_cidr {
        cfg.target_cidr = normalize_target_override(target);
    }

    if let Some(timeout_secs) = patch.timeout_secs {
        cfg.timeout_secs = timeout_secs;
    }

    if let Some(exclude) = patch.exclude {
        cfg.exclude = normalize_excludes(exclude)?;
    }

    if let Some(schedules) = patch.schedules {
        if let Some(hourly) = schedules.hourly.and_then(|profile| profile.intensity) {
            cfg.schedules.hourly = ScheduleProfile { intensity: hourly };
        }
        if let Some(daily) = schedules.daily.and_then(|profile| profile.intensity) {
            cfg.schedules.daily = ScheduleProfile { intensity: daily };
        }
    }

    if let Some(hourly) = patch.hourly_intensity {
        cfg.schedules.hourly = ScheduleProfile { intensity: hourly };
    }

    if let Some(daily) = patch.daily_intensity {
        cfg.schedules.daily = ScheduleProfile { intensity: daily };
    }

    Ok(())
}

fn normalize_target_override(target: Option<String>) -> Option<String> {
    target.and_then(|raw| {
        let value = raw.trim();
        if value.is_empty()
            || value.eq_ignore_ascii_case("auto")
            || value.eq_ignore_ascii_case("null")
            || value.eq_ignore_ascii_case("none")
        {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn normalize_excludes(values: Vec<String>) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    let mut clear = false;

    for raw in values {
        for value in raw.split(',') {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed.eq_ignore_ascii_case("none")
                || trimmed.eq_ignore_ascii_case("null")
                || trimmed.eq_ignore_ascii_case("clear")
            {
                clear = true;
                continue;
            }

            out.push(trimmed.to_string());
        }
    }

    if clear && !out.is_empty() {
        return Err(ApiError::BadRequest(
            "exclude cannot mix clear tokens with concrete IP/CIDR values".into(),
        ));
    }

    if clear {
        return Ok(Vec::new());
    }

    Ok(out)
}

fn normalize_mac(raw: &str) -> Result<String, ApiError> {
    let compact = raw.trim().replace([':', '-'], "");
    if compact.len() != 12 || !compact.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(
            "mac must be a valid 6-byte hexadecimal address".into(),
        ));
    }

    let upper = compact.to_ascii_uppercase();
    let normalized = upper
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(":");
    Ok(normalized)
}

fn normalize_mac_lossy(raw: &str) -> String {
    normalize_mac(raw).unwrap_or_else(|_| raw.trim().to_ascii_uppercase())
}

fn atomic_write_bytes(path: &Path, content: &[u8], tmp_extension: &str) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension(tmp_extension);
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    std::fs::rename(&tmp, path)?;

    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

async fn scan_with_args(args: &[&str]) -> Result<Json<ScanResponse>, ApiError> {
    let resp = super::dkp::run_cli(args).await?;
    Ok(Json(ScanResponse {
        success: resp.success,
        stdout: resp.stdout,
        stderr: resp.stderr,
        timestamp: resp.timestamp,
    }))
}

// ── Summary endpoint ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct InventorySummary {
    pub total: usize,
    pub approved: usize,
    pub unauthorized: usize,
    pub drifted: usize,
    pub stale: usize,
    pub devices_with_open_ports: usize,
    pub total_open_ports: usize,
    pub critical_devices: usize,
    pub high_risk_devices: usize,
    pub medium_risk_devices: usize,
    pub low_risk_devices: usize,
    pub unknown_risk_devices: usize,
    /// RFC-3339 timestamp of the most recently seen device; `None` if no inventory.
    pub last_seen_at: Option<String>,
}

pub async fn get_summary(
    State(s): State<Arc<AppState>>,
) -> Result<Json<InventorySummary>, ApiError> {
    let path = inventory_path(&s);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| ApiError::NotFound("no scan has run yet".into()))?;
    let devices: Vec<ConnectedDevice> = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::Internal(format!("inventory parse: {}", e)))?;

    let mut summary = InventorySummary {
        total: devices.len(),
        approved: 0,
        unauthorized: 0,
        drifted: 0,
        stale: 0,
        devices_with_open_ports: 0,
        total_open_ports: 0,
        critical_devices: 0,
        high_risk_devices: 0,
        medium_risk_devices: 0,
        low_risk_devices: 0,
        unknown_risk_devices: 0,
        last_seen_at: None,
    };

    let mut latest_ts: Option<&str> = None;

    for d in &devices {
        match d.status {
            DeviceStatus::Approved => summary.approved += 1,
            DeviceStatus::Unauthorized => summary.unauthorized += 1,
            DeviceStatus::Drifted => summary.drifted += 1,
            DeviceStatus::Stale => summary.stale += 1,
        }

        let port_count = d.open_ports.len();
        if port_count > 0 {
            summary.devices_with_open_ports += 1;
            summary.total_open_ports += port_count;
        }

        match risk_level(d).0 {
            "critical" => summary.critical_devices += 1,
            "high" => summary.high_risk_devices += 1,
            "medium" => summary.medium_risk_devices += 1,
            "low" => summary.low_risk_devices += 1,
            _ => summary.unknown_risk_devices += 1,
        }

        if let Some(ts) = latest_ts {
            if d.last_seen.as_str() > ts {
                latest_ts = Some(d.last_seen.as_str());
            }
        } else {
            latest_ts = Some(d.last_seen.as_str());
        }
    }

    summary.last_seen_at = latest_ts.map(String::from);
    Ok(Json(summary))
}

// ── Per-device detail endpoint ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DeviceDetail {
    #[serde(flatten)]
    pub device: ConnectedDevice,
    pub risk_level: String,
    pub risk_reasons: Vec<String>,
    pub flagged_ports: Vec<u16>,
}

pub async fn get_device(
    State(s): State<Arc<AppState>>,
    AxumPath(device_id): AxumPath<String>,
) -> Result<Json<DeviceDetail>, ApiError> {
    let path = inventory_path(&s);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| ApiError::NotFound("no scan has run yet".into()))?;
    let devices: Vec<ConnectedDevice> = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::Internal(format!("inventory parse: {}", e)))?;

    let device = devices
        .into_iter()
        .find(|d| d.device_id == device_id)
        .ok_or_else(|| ApiError::NotFound(format!("device '{}' not found", device_id)))?;

    let (level, reasons, flagged) = risk_level(&device);
    Ok(Json(DeviceDetail {
        device,
        risk_level: level.to_string(),
        risk_reasons: reasons,
        flagged_ports: flagged,
    }))
}

// ── Run history endpoint ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct RunEntry {
    /// RFC-3339 UTC timestamp of when this scan completed.
    pub timestamp: String,
    pub unix_ts: u64,
    /// "raw_xml" when sourced from the forensic XML store; "inferred" otherwise.
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct RunsResponse {
    pub runs: Vec<RunEntry>,
    pub total_in_inventory: usize,
}

pub async fn get_runs(State(s): State<Arc<AppState>>) -> Result<Json<RunsResponse>, ApiError> {
    let state_dir = PathBuf::from(&s.discovery_state_dir);

    // Device count from inventory for context.
    let inv_path = inventory_path(&s);
    let total_in_inventory = tokio::fs::read(&inv_path)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<ConnectedDevice>>(&b).ok())
        .map(|d| d.len())
        .unwrap_or(0);

    // Primary source: raw XML files named `<unix_ts>.xml`.
    let raw_dir = state_dir.join("raw");
    let mut runs: Vec<RunEntry> = Vec::new();

    if let Ok(mut rd) = tokio::fs::read_dir(&raw_dir).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let p = entry.path();
            if p.extension().map(|e| e == "xml").unwrap_or(false) {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(unix_ts) = stem.parse::<u64>() {
                        let ts = unix_ts_to_rfc3339(unix_ts);
                        runs.push(RunEntry {
                            timestamp: ts,
                            unix_ts,
                            source: "raw_xml".to_string(),
                        });
                    }
                }
            }
        }
    }

    runs.sort_by(|a, b| b.unix_ts.cmp(&a.unix_ts)); // newest first
    Ok(Json(RunsResponse {
        runs,
        total_in_inventory,
    }))
}

// ── Risk computation ──────────────────────────────────────────────────────────

/// Returns (risk_level, reasons, flagged_ports).
fn risk_level(device: &ConnectedDevice) -> (&'static str, Vec<String>, Vec<u16>) {
    let mut reasons: Vec<String> = Vec::new();
    let mut flagged: Vec<u16> = Vec::new();

    let unauthorized = matches!(
        device.status,
        DeviceStatus::Unauthorized | DeviceStatus::Drifted
    );

    let has_vulns = device.open_ports.iter().any(|p| {
        p.scripts
            .iter()
            .any(|s| s.id == "vulners" && !s.output.trim().is_empty())
    }) || device
        .host_scripts
        .iter()
        .any(|s| s.id == "vulners" && !s.output.trim().is_empty());

    let risky: Vec<u16> = device
        .open_ports
        .iter()
        .filter(|p| HIGH_RISK_PORTS.contains(&p.port))
        .map(|p| p.port)
        .collect();

    if unauthorized {
        reasons.push("unauthorized device".to_string());
    }
    if has_vulns {
        reasons.push("vulnerability findings detected".to_string());
    }
    if !risky.is_empty() {
        reasons.push(format!(
            "risky ports exposed: {}",
            risky
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        flagged.extend_from_slice(&risky);
    }

    let level = if unauthorized && has_vulns {
        "critical"
    } else if unauthorized && !risky.is_empty() {
        "high"
    } else if device.open_ports.is_empty() && device.os_fingerprint.is_none() {
        "unknown"
    } else if device.open_ports.is_empty() {
        "low"
    } else if matches!(device.status, DeviceStatus::Approved) && !device.open_ports.is_empty() {
        "medium"
    } else {
        "low"
    };

    (level, reasons, flagged)
}

fn unix_ts_to_rfc3339(unix_ts: u64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(unix_ts as i64, 0)
        .single()
        .unwrap_or_else(Utc::now)
        .to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::{
        apply_schedule_patch, default_version, normalize_excludes, refresh_inventory_statuses,
        runtime_whitelist, SchedulePatch, ScheduleProfilePatch, ScheduleUpdateRequest,
        WhitelistDoc,
    };
    use crate::discovery::whitelist::WhitelistEntry;
    use crate::discovery::{ConnectedDevice, DeviceStatus, NmapConfig, OpenPort, ScanIntensity};
    use tempfile::tempdir;

    fn test_device(status: DeviceStatus) -> ConnectedDevice {
        ConnectedDevice {
            device_id: "dev-1".into(),
            ip: "192.168.50.103".into(),
            mac: Some("AA:BB:CC:11:22:33".into()),
            vendor: Some("Acme".into()),
            hostname: Some("printer".into()),
            os_fingerprint: None,
            os_cpe: Vec::new(),
            open_ports: vec![OpenPort {
                port: 22,
                protocol: "tcp".into(),
                service: Some("ssh".into()),
                product_version: None,
                cpe: Vec::new(),
                scripts: Vec::new(),
            }],
            host_scripts: Vec::new(),
            status,
            first_seen: "2026-06-12T00:00:00Z".into(),
            last_seen: "2026-06-12T00:00:00Z".into(),
            vuln_triaged: false,
            last_scan_intensity: None,
        }
    }

    #[test]
    fn schedule_patch_updates_nested_profiles_and_auto_target() {
        let mut cfg = NmapConfig::default();
        cfg.enabled = true;
        cfg.target_cidr = Some("192.168.50.0/24".into());
        cfg.timeout_secs = 600;
        cfg.exclude = vec!["192.168.50.1".into()];

        let patch = ScheduleUpdateRequest {
            enabled: Some(false),
            target_cidr: Some(None),
            timeout_secs: Some(120),
            exclude: Some(vec![]),
            schedules: Some(SchedulePatch {
                hourly: Some(ScheduleProfilePatch {
                    intensity: Some(ScanIntensity::Stealth),
                }),
                daily: Some(ScheduleProfilePatch {
                    intensity: Some(ScanIntensity::Aggressive),
                }),
            }),
            hourly_intensity: None,
            daily_intensity: None,
        };

        apply_schedule_patch(&mut cfg, patch).expect("patch should apply");

        assert!(!cfg.enabled);
        assert!(cfg.target_cidr.is_none());
        assert_eq!(cfg.timeout_secs, 120);
        assert!(cfg.exclude.is_empty());
        assert_eq!(cfg.schedules.hourly.intensity, ScanIntensity::Stealth);
        assert_eq!(cfg.schedules.daily.intensity, ScanIntensity::Aggressive);
    }

    #[test]
    fn normalize_excludes_rejects_mixed_clear_and_values() {
        let err = normalize_excludes(vec!["none".into(), "192.168.50.1".into()])
            .expect_err("mixed clear tokens should fail");
        assert!(matches!(err, crate::api::error::ApiError::BadRequest(_)));
    }

    #[test]
    fn whitelist_refresh_immediately_approves_matching_device() {
        let dir = tempdir().expect("temp dir should exist");
        let inventory_path = dir.path().join("inventory.json");
        let devices = vec![test_device(DeviceStatus::Unauthorized)];
        std::fs::write(
            &inventory_path,
            serde_json::to_vec(&devices).expect("inventory should serialize"),
        )
        .expect("inventory fixture should write");

        let doc = WhitelistDoc {
            version: default_version(),
            devices: vec![WhitelistEntry {
                mac: "AA:BB:CC:11:22:33".into(),
                label: Some("Printer".into()),
                expected_os: None,
                expected_ports: Vec::new(),
                expected_ips: Vec::new(),
            }],
        };

        let updated = refresh_inventory_statuses(&inventory_path, &runtime_whitelist(&doc))
            .expect("inventory refresh should succeed");
        assert_eq!(updated, 1);

        let stored: Vec<ConnectedDevice> = serde_json::from_slice(
            &std::fs::read(&inventory_path).expect("inventory should exist"),
        )
        .expect("inventory should parse");
        assert_eq!(stored[0].status, DeviceStatus::Approved);
    }
}
