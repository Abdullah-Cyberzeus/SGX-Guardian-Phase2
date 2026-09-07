use crate::api::{error::ApiError, state::AppState};
use crate::discovery::whitelist::{
    enrich_entries, infer_label_for_mac, Whitelist, WhitelistEntry, WhitelistEntryView,
};
use crate::discovery::{
    nmap_parser,
    run_history::{self, ScanRunRecord},
    ConnectedDevice, DeviceStatus, NmapConfig, ScanIntensity, ScanSchedule, ScheduleProfile,
    ScheduledScans,
};
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunsView {
    Raw,
    History,
}

#[derive(Debug, Deserialize, Default)]
pub struct RunsQuery {
    pub limit: Option<usize>,
    pub view: Option<RunsView>,
}

fn load_run_history(
    state: &AppState,
    limit: Option<usize>,
) -> Result<Vec<ScanRunRecord>, ApiError> {
    let path = run_history::history_path(Path::new(&state.discovery_state_dir));
    let limit = limit.unwrap_or(50).min(500);
    let runs = run_history::list_recent(&path, Some(limit))
        .map_err(|e| ApiError::Internal(format!("run history read: {}", e)))?;
    Ok(runs)
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryRunDetail {
    #[serde(flatten)]
    pub run: ScanRunRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<ConnectedDevice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices_error: Option<String>,
}

fn enrich_run_history(
    state: &AppState,
    runs: Vec<ScanRunRecord>,
) -> Result<Vec<HistoryRunDetail>, ApiError> {
    let whitelist = Whitelist::load(&whitelist_path(state)).unwrap_or_default();
    runs.into_iter()
        .map(|run| {
            let (devices, devices_error) = historical_run_devices(&run, &whitelist);
            Ok(HistoryRunDetail {
                run,
                devices,
                devices_error,
            })
        })
        .collect()
}

fn historical_run_devices(
    run: &ScanRunRecord,
    whitelist: &Whitelist,
) -> (Option<Vec<ConnectedDevice>>, Option<String>) {
    let Some(raw_xml_path) = run.raw_xml_path.as_deref() else {
        return (None, Some("raw xml not recorded for this run".into()));
    };

    let path = Path::new(raw_xml_path);
    if !path.exists() {
        return (
            None,
            Some(format!("raw xml not available at {}", raw_xml_path)),
        );
    }

    let xml = match std::fs::read_to_string(path) {
        Ok(xml) => xml,
        Err(err) => {
            return (
                None,
                Some(format!("read raw xml '{}': {}", raw_xml_path, err)),
            );
        }
    };
    let mut devices = match nmap_parser::parse(&xml) {
        Ok(devices) => devices,
        Err(err) => {
            return (
                None,
                Some(format!("parse raw xml '{}': {}", raw_xml_path, err)),
            );
        }
    };

    let observed_at = run.completed_at.to_rfc3339();
    let intensity = intensity_name(run.intensity).to_string();

    for device in &mut devices {
        device.first_seen = observed_at.clone();
        device.last_seen = observed_at.clone();
        device.last_scan_intensity = Some(intensity.clone());
        whitelist.classify(device);
    }

    devices.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then(left.device_id.cmp(&right.device_id))
    });

    (Some(devices), None)
}

pub async fn list_runs(
    State(s): State<Arc<AppState>>,
    Query(query): Query<RunsQuery>,
) -> Result<Json<Vec<HistoryRunDetail>>, ApiError> {
    let runs = load_run_history(s.as_ref(), query.limit)?;
    Ok(Json(enrich_run_history(s.as_ref(), runs)?))
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScanTargetRequest {
    pub target: Option<String>,
}

pub async fn scan_now(
    State(s): State<Arc<AppState>>,
    Query(query): Query<ScanTargetRequest>,
    body: Bytes,
) -> Result<Json<ScanResponse>, ApiError> {
    scan_with_args(
        &s,
        &["discovery", "scan"],
        resolve_scan_target(query, &body)?,
    )
    .await
}

pub async fn scan_stealth(
    State(s): State<Arc<AppState>>,
    Query(query): Query<ScanTargetRequest>,
    body: Bytes,
) -> Result<Json<ScanResponse>, ApiError> {
    scan_with_args(
        &s,
        &["discovery", "scan", "--intensity", "stealth"],
        resolve_scan_target(query, &body)?,
    )
    .await
}

pub async fn scan_standard(
    State(s): State<Arc<AppState>>,
    Query(query): Query<ScanTargetRequest>,
    body: Bytes,
) -> Result<Json<ScanResponse>, ApiError> {
    scan_with_args(
        &s,
        &["discovery", "scan", "--intensity", "standard"],
        resolve_scan_target(query, &body)?,
    )
    .await
}

pub async fn scan_aggressive(
    State(s): State<Arc<AppState>>,
    Query(query): Query<ScanTargetRequest>,
    body: Bytes,
) -> Result<Json<ScanResponse>, ApiError> {
    scan_with_args(
        &s,
        &["discovery", "scan", "--intensity", "aggressive"],
        resolve_scan_target(query, &body)?,
    )
    .await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistDoc {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub devices: Vec<WhitelistEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WhitelistViewDoc {
    pub version: String,
    pub devices: Vec<WhitelistEntryView>,
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
    pub current_devices: Vec<crate::discovery::whitelist::WhitelistInventoryDevice>,
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

pub async fn get_whitelist(
    State(s): State<Arc<AppState>>,
) -> Result<Json<WhitelistViewDoc>, ApiError> {
    let doc = load_whitelist_doc(&whitelist_path(&s))?;
    let inventory = load_inventory_devices(&inventory_path(&s))?;
    Ok(Json(enrich_whitelist_doc(doc, &inventory)))
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
    let inventory_before = load_inventory_devices(&inventory_path(&s))?;
    let requested_label = normalize_optional_label(body.label);
    let resolved_label = requested_label
        .clone()
        .or_else(|| infer_label_for_mac(&normalized_mac, &inventory_before));
    let whitelist_file = whitelist_path(&s);
    let mut doc = load_whitelist_doc(&whitelist_file)?;
    let mut created = false;
    let entry = match doc
        .devices
        .iter_mut()
        .find(|entry| normalize_mac_lossy(&entry.mac) == normalized_mac)
    {
        Some(existing) => {
            if let Some(label) = resolved_label.clone().filter(|_| {
                requested_label.is_some() || existing.label.as_deref().unwrap_or("").is_empty()
            }) {
                existing.label = Some(label);
            }
            existing.clone()
        }
        None => {
            let entry = WhitelistEntry {
                mac: normalized_mac.clone(),
                label: resolved_label,
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
    clear_device_registry_rejection(s.as_ref(), &normalized_mac).await?;

    let inventory_updated =
        refresh_inventory_statuses(&inventory_path(&s), &runtime_whitelist(&doc))?;
    let refreshed_inventory = load_inventory_devices(&inventory_path(&s))?;
    let current_devices = enrich_entries(std::slice::from_ref(&entry), &refreshed_inventory)
        .into_iter()
        .next()
        .map(|view| view.current_devices)
        .unwrap_or_default();

    Ok(Json(ApproveResponse {
        success: true,
        created,
        inventory_updated,
        entry,
        current_devices,
    }))
}

async fn clear_device_registry_rejection(state: &AppState, mac: &str) -> Result<(), ApiError> {
    let cfg = crate::devices::DevicesConfig::from_env();
    let path = cfg.registry_path();
    let mut registry = crate::devices::registry::DeviceRegistry::load(&path)
        .await
        .map_err(|err| match err {
            crate::devices::errors::DevicesError::TamperedRegistry => {
                ApiError::Internal("device registry integrity check failed".into())
            }
            other => ApiError::Internal(other.to_string()),
        })?;

    // Before mutating registry state, ensure any active nftables threat block
    // is removed. This keeps "re-approve" atomic from the API perspective:
    // if nftables enforcement fails, we don't clear `rejected/blocked`.
    let normalized_for_match = normalize_mac_for_match(mac);
    let maybe_blocked_ip = registry
        .devices
        .values()
        .find(|record| {
            record
                .mac
                .as_deref()
                .map(normalize_mac_for_match)
                .is_some_and(|record_mac| record_mac == normalized_for_match)
        })
        .and_then(|record| {
            if record.blocked {
                record.ip.as_deref()
            } else {
                None
            }
        })
        .map(|s| s.to_string());

    if let Some(ip) = maybe_blocked_ip {
        let blocker = build_threat_blocker(state).await?;
        blocker
            .unblock_ip(&ip)
            .await
            .map_err(api_error_from_threat_blocker_error)?;
    }

    if registry.clear_rejection_for_mac(mac).is_some() {
        registry
            .save_atomic(&path)
            .await
            .map_err(|err| ApiError::Internal(err.to_string()))?;
    }
    Ok(())
}

fn normalize_mac_for_match(mac: &str) -> String {
    mac.chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .flat_map(|ch| ch.to_uppercase())
        .collect()
}

async fn build_threat_blocker(
    state: &AppState,
) -> Result<crate::threat::blocker::Blocker, ApiError> {
    let cfg = crate::threat::config::SuricataConfig::load(std::path::Path::new(
        &state.threat_config_path,
    ))
    .map_err(|err| ApiError::Internal(format!("load threat config: {err}")))?;

    let cfg_shared = Arc::new(tokio::sync::Mutex::new(cfg));
    let blocker = crate::threat::blocker::Blocker::new(
        cfg_shared,
        state.node_id.clone(),
        PathBuf::from(&state.threat_state_dir),
    );

    blocker
        .restore_state()
        .await
        .map_err(|err| ApiError::Internal(format!("threat restore_state: {err}")))?;
    Ok(blocker)
}

fn api_error_from_threat_blocker_error(err: crate::threat::error::ThreatError) -> ApiError {
    match err {
        crate::threat::error::ThreatError::ProtectedIp(_) => ApiError::Forbidden(
            "refused to block protected local, gateway, or overlay address".into(),
        ),
        other => ApiError::Internal(other.to_string()),
    }
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

fn load_inventory_devices(path: &Path) -> Result<Vec<ConnectedDevice>, ApiError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let bytes = std::fs::read(path)?;
    if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(Vec::new());
    }

    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::Internal(format!("inventory parse: {}", e)))
}

fn enrich_whitelist_doc(doc: WhitelistDoc, inventory: &[ConnectedDevice]) -> WhitelistViewDoc {
    WhitelistViewDoc {
        version: doc.version,
        devices: enrich_entries(&doc.devices, inventory),
    }
}

fn load_nmap_config(path: &Path) -> Result<NmapConfig, ApiError> {
    NmapConfig::load(path)
        .map_err(|e| ApiError::BadRequest(format!("discovery config load error: {}", e)))
}

fn normalize_optional_label(label: Option<String>) -> Option<String> {
    label
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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

fn resolve_scan_target(query: ScanTargetRequest, body: &[u8]) -> Result<Option<String>, ApiError> {
    let query_target = normalize_target_override(query.target);
    if body.is_empty() {
        return Ok(query_target);
    }

    let parsed: ScanTargetRequest = serde_json::from_slice(body)
        .map_err(|e| ApiError::BadRequest(format!("invalid discovery scan request body: {}", e)))?;
    let body_target = normalize_target_override(parsed.target);
    Ok(body_target.or(query_target))
}

fn build_scan_args(args: &[&str], target: Option<String>) -> Vec<String> {
    let mut out = args
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    if let Some(target) = target {
        out.push("--target".to_string());
        out.push(target);
    }
    out
}

async fn scan_with_args(
    state: &AppState,
    args: &[&str],
    target: Option<String>,
) -> Result<Json<ScanResponse>, ApiError> {
    let args = build_scan_args(args, target);
    let refs = args.iter().map(|value| value.as_str()).collect::<Vec<_>>();
    let resp = super::dkp::run_cli(&refs).await?;
    if resp.success {
        publish_rule_events_for_latest_run(state);
    }
    Ok(Json(ScanResponse {
        success: resp.success,
        stdout: resp.stdout,
        stderr: resp.stderr,
        timestamp: resp.timestamp,
    }))
}

// The CLI subprocess (`sgx-pa-cli discovery scan ...`) updates the inventory
// directly on disk, bypassing the in-process DiscoveryScheduler that normally
// publishes DeviceDiscovered/DeviceUnauthorized rule events. Re-derive the
// device list for the run it just recorded (same approach as
// `historical_run_devices`, used for run-history enrichment) and publish from
// here so manual/frontend-triggered scans fire rule events too.
fn publish_rule_events_for_latest_run(state: &AppState) {
    let history_path = run_history::history_path(Path::new(&state.discovery_state_dir));
    let Ok(mut runs) = run_history::list_recent(&history_path, Some(1)) else {
        return;
    };
    let Some(run) = runs.pop() else {
        return;
    };
    let whitelist = Whitelist::load(&whitelist_path(state)).unwrap_or_default();
    let (devices, _) = historical_run_devices(&run, &whitelist);
    for device in devices.unwrap_or_default() {
        crate::rules::publish(crate::rules::RuleEvent::from_device_discovered(
            &state.node_id,
            &device,
        ));
        if matches!(
            device.status,
            DeviceStatus::Unauthorized | DeviceStatus::Drifted
        ) {
            crate::rules::publish(crate::rules::RuleEvent::from_device_unauthorized(
                &state.node_id,
                &device,
            ));
        }
    }
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

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RunsApiResponse {
    Raw(RunsResponse),
    History(Vec<HistoryRunDetail>),
}

pub async fn get_runs(
    State(s): State<Arc<AppState>>,
    Query(query): Query<RunsQuery>,
) -> Result<Json<RunsApiResponse>, ApiError> {
    if matches!(query.view, Some(RunsView::History)) || query.limit.is_some() {
        let runs = load_run_history(s.as_ref(), query.limit)?;
        return Ok(Json(RunsApiResponse::History(enrich_run_history(
            s.as_ref(),
            runs,
        )?)));
    }

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

    runs.sort_by_key(|run| std::cmp::Reverse(run.unix_ts)); // newest first
    Ok(Json(RunsApiResponse::Raw(RunsResponse {
        runs,
        total_in_inventory,
    })))
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

fn intensity_name(intensity: ScanIntensity) -> &'static str {
    match intensity {
        ScanIntensity::Stealth => "stealth",
        ScanIntensity::Standard => "standard",
        ScanIntensity::Aggressive => "aggressive",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_schedule_patch, build_scan_args, default_version, get_runs, list_devices,
        normalize_excludes, refresh_inventory_statuses, resolve_scan_target, risk_level,
        runtime_whitelist, ApiError, RunsApiResponse, RunsQuery, RunsView, ScanTargetRequest,
        SchedulePatch, ScheduleProfilePatch, ScheduleUpdateRequest, WhitelistDoc,
    };
    use crate::api::state::AppState;
    use crate::did::Resolver;
    use crate::discovery::run_history::{self, ScanRunRecord, ScanRunSource};
    use crate::discovery::whitelist::WhitelistEntry;
    use crate::discovery::{ConnectedDevice, DeviceStatus, NmapConfig, OpenPort, ScanIntensity};
    use crate::virtual_id_cache::VirtualIdCache;
    use axum::extract::{Query, State};
    use axum::Json;
    use chrono::{TimeZone, Utc};
    use std::sync::Arc;
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

    fn test_state(config_dir: &std::path::Path, state_dir: &std::path::Path) -> Arc<AppState> {
        let base_dir = config_dir.parent().unwrap_or(config_dir);
        let mut state =
            (*AppState::for_tests(base_dir, "test-nodeA", config_dir.display().to_string()))
                .clone();
        state.did_resolver = Resolver::new(Default::default());
        state.vid_cache = VirtualIdCache::new();
        state.discovery_config_dir = config_dir.display().to_string();
        state.discovery_state_dir = state_dir.display().to_string();
        Arc::new(state)
    }

    fn test_run_record(
        raw_xml_path: &std::path::Path,
        inventory_path: &std::path::Path,
    ) -> ScanRunRecord {
        let started_at = Utc.with_ymd_and_hms(2026, 7, 5, 5, 35, 4).unwrap();
        let completed_at = Utc.with_ymd_and_hms(2026, 7, 5, 5, 39, 8).unwrap();
        ScanRunRecord {
            run_id: "20260705T053504Z-aggressive-test".into(),
            started_at,
            completed_at,
            duration_ms: completed_at
                .signed_duration_since(started_at)
                .num_milliseconds()
                .max(0) as u128,
            source: ScanRunSource::Manual,
            schedule_kind: None,
            intensity: ScanIntensity::Aggressive,
            target: "192.168.50.0/24".into(),
            success: true,
            error: None,
            new_devices: 1,
            updated_devices: 0,
            marked_stale: 0,
            total_devices: 1,
            approved: 0,
            unauthorized: 1,
            drifted: 0,
            stale: 0,
            raw_xml_path: Some(raw_xml_path.display().to_string()),
            inventory_path: inventory_path.display().to_string(),
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
    fn resolve_scan_target_uses_query_when_body_missing() {
        let target = resolve_scan_target(
            ScanTargetRequest {
                target: Some("192.168.50.248/32".into()),
            },
            b"",
        )
        .expect("query target should parse");
        assert_eq!(target.as_deref(), Some("192.168.50.248/32"));
    }

    #[test]
    fn resolve_scan_target_prefers_body_when_present() {
        let target = resolve_scan_target(
            ScanTargetRequest {
                target: Some("192.168.50.0/24".into()),
            },
            br#"{"target":"192.168.50.248/32"}"#,
        )
        .expect("body target should parse");
        assert_eq!(target.as_deref(), Some("192.168.50.248/32"));
    }

    #[test]
    fn resolve_scan_target_ignores_auto_body_and_uses_query() {
        let target = resolve_scan_target(
            ScanTargetRequest {
                target: Some("192.168.50.248/32".into()),
            },
            br#"{"target":"auto"}"#,
        )
        .expect("body target should parse");
        assert_eq!(target.as_deref(), Some("192.168.50.248/32"));
    }

    #[test]
    fn build_scan_args_appends_target_override() {
        let args = build_scan_args(
            &["discovery", "scan", "--intensity", "standard"],
            Some("192.168.50.248/32".into()),
        );
        assert_eq!(
            args,
            vec![
                "discovery",
                "scan",
                "--intensity",
                "standard",
                "--target",
                "192.168.50.248/32",
            ]
        );
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

    #[tokio::test]
    async fn history_view_includes_historical_devices_without_touching_inventory_endpoints() {
        let dir = tempdir().expect("temp dir should exist");
        let config_dir = dir.path().join("config");
        let state_dir = dir.path().join("state");
        let raw_dir = state_dir.join("raw");
        let whitelist_path = config_dir.join("whitelist.yaml");
        let inventory_path = state_dir.join("inventory.json");
        let run_history_path = run_history::history_path(&state_dir);
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::create_dir_all(&raw_dir).expect("raw dir");
        std::fs::write(&whitelist_path, "version: \"1.0\"\ndevices: []\n")
            .expect("whitelist fixture");

        let inventory_device = ConnectedDevice {
            device_id: "inventory-dev".into(),
            ip: "192.168.50.77".into(),
            mac: Some("AA:BB:CC:11:22:33".into()),
            vendor: Some("Inventory Device".into()),
            hostname: Some("current-device".into()),
            os_fingerprint: Some("Linux".into()),
            os_cpe: Vec::new(),
            open_ports: Vec::new(),
            host_scripts: Vec::new(),
            status: DeviceStatus::Unauthorized,
            first_seen: "2026-07-05T05:16:29+00:00".into(),
            last_seen: "2026-07-05T05:39:08+00:00".into(),
            vuln_triaged: false,
            last_scan_intensity: Some("aggressive".into()),
        };
        std::fs::write(
            &inventory_path,
            serde_json::to_vec(&vec![inventory_device.clone()]).expect("inventory serialize"),
        )
        .expect("inventory write");

        let raw_xml_path = raw_dir.join("1783229948.xml");
        std::fs::write(
            &raw_xml_path,
            r#"
<nmaprun scanner="nmap" args="nmap -oX - 127.0.0.1/32">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.20.1"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="98"/>
    </os>
  </host>
</nmaprun>
"#,
        )
        .expect("raw xml write");

        run_history::append_record(
            &run_history_path,
            &test_run_record(&raw_xml_path, &inventory_path),
        )
        .expect("append run history");

        let state = test_state(&config_dir, &state_dir);

        let Json(RunsApiResponse::History(runs)) = get_runs(
            State(state.clone()),
            Query(RunsQuery {
                limit: None,
                view: Some(RunsView::History),
            }),
        )
        .await
        .expect("history response") else {
            panic!("expected history response");
        };

        assert_eq!(runs.len(), 1);
        let history_run = &runs[0];
        let devices = history_run
            .devices
            .as_ref()
            .expect("history run should include parsed devices");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip, "127.0.0.1");
        assert_eq!(devices[0].hostname.as_deref(), Some("localhost"));
        assert_eq!(
            devices[0].last_scan_intensity.as_deref(),
            Some("aggressive")
        );
        assert_eq!(
            devices[0].last_seen,
            history_run.run.completed_at.to_rfc3339()
        );

        let Json(current_devices) = list_devices(State(state))
            .await
            .expect("inventory endpoint should still read inventory.json");
        assert_eq!(current_devices, vec![inventory_device]);
    }

    #[tokio::test]
    async fn history_view_reports_missing_raw_xml_without_failing() {
        let dir = tempdir().expect("temp dir should exist");
        let config_dir = dir.path().join("config");
        let state_dir = dir.path().join("state");
        let inventory_path = state_dir.join("inventory.json");
        let run_history_path = run_history::history_path(&state_dir);
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(
            config_dir.join("whitelist.yaml"),
            "version: \"1.0\"\ndevices: []\n",
        )
        .expect("whitelist fixture");
        std::fs::write(&inventory_path, b"[]").expect("inventory write");

        let missing_raw_xml = state_dir.join("raw").join("missing.xml");
        run_history::append_record(
            &run_history_path,
            &test_run_record(&missing_raw_xml, &inventory_path),
        )
        .expect("append run history");

        let Json(RunsApiResponse::History(runs)) = get_runs(
            State(test_state(&config_dir, &state_dir)),
            Query(RunsQuery {
                limit: None,
                view: Some(RunsView::History),
            }),
        )
        .await
        .expect("history response") else {
            panic!("expected history response");
        };

        assert_eq!(runs.len(), 1);
        assert!(runs[0].devices.is_none());
        assert!(runs[0]
            .devices_error
            .as_deref()
            .expect("devices_error should be present")
            .contains("raw xml not available"));
    }

    fn scanned_device(status: DeviceStatus) -> ConnectedDevice {
        ConnectedDevice {
            device_id: "dev-risk".into(),
            ip: "10.0.0.4".into(),
            mac: Some("AA:BB:CC:DD:EE:04".into()),
            vendor: None,
            hostname: None,
            os_fingerprint: Some("Linux".into()),
            os_cpe: Vec::new(),
            open_ports: Vec::new(),
            host_scripts: Vec::new(),
            status,
            first_seen: "2026-07-24T00:00:00Z".into(),
            last_seen: "2026-07-24T00:00:00Z".into(),
            vuln_triaged: false,
            last_scan_intensity: None,
        }
    }

    fn scanned_port(port: u16, scripts: &[(&str, &str)]) -> OpenPort {
        OpenPort {
            port,
            protocol: "tcp".into(),
            service: Some("svc".into()),
            product_version: None,
            cpe: Vec::new(),
            scripts: scripts
                .iter()
                .map(|(id, output)| crate::discovery::ScriptResult {
                    id: (*id).into(),
                    output: (*output).into(),
                })
                .collect(),
        }
    }

    /// `risk_level`'s ladder, walked from the top down. Each case differs from
    /// the one above it by exactly the input that selects the next rung.
    #[test]
    fn risk_level_grades_devices_from_critical_down_to_unknown() {
        // Unauthorized + a vulnerability finding is the top of the ladder.
        let mut critical = scanned_device(DeviceStatus::Unauthorized);
        critical.open_ports = vec![scanned_port(8080, &[("vulners", "CVE-2024-0001")])];
        let (level, reasons, flagged) = risk_level(&critical);
        assert_eq!(level, "critical");
        assert!(
            reasons.iter().any(|r| r == "unauthorized device"),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| r == "vulnerability findings detected"),
            "{reasons:?}"
        );
        assert_eq!(flagged, vec![8080], "the risky port is flagged");

        // A vulners script with empty output is not a finding.
        let mut blank_vulners = scanned_device(DeviceStatus::Unauthorized);
        blank_vulners.open_ports = vec![scanned_port(8080, &[("vulners", "   ")])];
        assert_eq!(risk_level(&blank_vulners).0, "high");

        // Host-level scripts count as findings too.
        let mut host_level = scanned_device(DeviceStatus::Unauthorized);
        host_level.host_scripts = vec![crate::discovery::ScriptResult {
            id: "vulners".into(),
            output: "CVE-2024-0002".into(),
        }];
        assert_eq!(risk_level(&host_level).0, "critical");

        // Unauthorized with a risky port but no findings.
        let mut high = scanned_device(DeviceStatus::Drifted);
        high.open_ports = vec![scanned_port(22, &[])];
        assert_eq!(
            risk_level(&high).0,
            "high",
            "Drifted counts as unauthorized"
        );

        // Approved with any open port.
        let mut medium = scanned_device(DeviceStatus::Approved);
        medium.open_ports = vec![scanned_port(9999, &[])];
        let (level, reasons, flagged) = risk_level(&medium);
        assert_eq!(level, "medium");
        assert!(
            reasons.is_empty(),
            "a benign port raises nothing: {reasons:?}"
        );
        assert!(flagged.is_empty());

        // No ports at all, but the OS was fingerprinted.
        assert_eq!(risk_level(&scanned_device(DeviceStatus::Approved)).0, "low");

        // Nothing observed at all.
        let mut unknown = scanned_device(DeviceStatus::Approved);
        unknown.os_fingerprint = None;
        assert_eq!(risk_level(&unknown).0, "unknown");

        // Unauthorized with neither ports nor findings still falls through to
        // the port-based rungs.
        let mut bare_unauthorized = scanned_device(DeviceStatus::Unauthorized);
        bare_unauthorized.os_fingerprint = None;
        assert_eq!(risk_level(&bare_unauthorized).0, "unknown");
    }

    #[test]
    fn normalize_mac_accepts_common_separators_and_rejects_bad_input() {
        for raw in ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", " aabbccddeeff "] {
            assert_eq!(
                super::normalize_mac(raw).expect("valid mac"),
                "AA:BB:CC:DD:EE:FF",
                "input: {raw}"
            );
        }
        for raw in ["", "aa:bb:cc", "aa:bb:cc:dd:ee:ff:00", "zz:bb:cc:dd:ee:ff"] {
            assert!(super::normalize_mac(raw).is_err(), "input: {raw}");
        }
    }

    #[test]
    fn normalize_mac_lossy_falls_back_to_the_uppercased_input() {
        assert_eq!(
            super::normalize_mac_lossy("aa-bb-cc-dd-ee-ff"),
            "AA:BB:CC:DD:EE:FF"
        );
        // Not a MAC at all: kept as-is rather than dropped, so a malformed
        // whitelist entry still matches itself.
        assert_eq!(super::normalize_mac_lossy(" wildcard "), "WILDCARD");
    }

    #[test]
    fn normalize_mac_for_match_keeps_only_hex_digits() {
        assert_eq!(
            super::normalize_mac_for_match("aa:bb-cc.dd ee ff"),
            "AABBCCDDEEFF"
        );
        assert_eq!(
            super::normalize_mac_for_match("no-hex-here"),
            "EEE",
            "only the three `e`s are hex digits"
        );
        assert_eq!(super::normalize_mac_for_match(""), "");
    }

    #[test]
    fn normalize_target_override_treats_the_auto_tokens_as_absent() {
        for token in ["auto", "AUTO", "null", "None", "   "] {
            assert_eq!(
                super::normalize_target_override(Some(token.to_string())),
                None,
                "token: {token}"
            );
        }
        assert_eq!(super::normalize_target_override(None), None);
        assert_eq!(
            super::normalize_target_override(Some("  10.0.0.0/24  ".to_string())),
            Some("10.0.0.0/24".to_string())
        );
    }

    #[test]
    fn normalize_optional_label_drops_blank_labels() {
        assert_eq!(super::normalize_optional_label(None), None);
        assert_eq!(super::normalize_optional_label(Some("   ".into())), None);
        assert_eq!(
            super::normalize_optional_label(Some("  Kitchen  ".into())),
            Some("Kitchen".to_string())
        );
    }

    #[test]
    fn intensity_name_covers_every_scan_intensity() {
        assert_eq!(super::intensity_name(ScanIntensity::Stealth), "stealth");
        assert_eq!(super::intensity_name(ScanIntensity::Standard), "standard");
        assert_eq!(
            super::intensity_name(ScanIntensity::Aggressive),
            "aggressive"
        );
    }

    #[test]
    fn unix_ts_to_rfc3339_formats_an_epoch_second() {
        assert!(super::unix_ts_to_rfc3339(0).starts_with("1970-01-01T00:00:00"));
        assert!(super::unix_ts_to_rfc3339(1_700_000_000).starts_with("2023-11-14T"));
    }

    #[test]
    fn api_error_from_threat_blocker_error_maps_protected_ips_to_forbidden() {
        assert!(matches!(
            super::api_error_from_threat_blocker_error(
                crate::threat::error::ThreatError::ProtectedIp("10.0.0.1".into())
            ),
            ApiError::Forbidden(_)
        ));
        assert!(matches!(
            super::api_error_from_threat_blocker_error(crate::threat::error::ThreatError::Io(
                std::io::Error::other("disk")
            )),
            ApiError::Internal(message) if message.contains("disk")
        ));
    }

    #[test]
    fn atomic_write_bytes_creates_parents_and_replaces_existing_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("doc.yaml");

        super::atomic_write_bytes(&path, b"first", "tmp").expect("first write");
        assert_eq!(std::fs::read(&path).expect("read"), b"first");

        super::atomic_write_bytes(&path, b"second", "tmp").expect("second write");
        assert_eq!(std::fs::read(&path).expect("read"), b"second");

        // The temporary file is not left behind.
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn schedule_doc_from_config_projects_the_scan_config() {
        let mut cfg = NmapConfig::default();
        cfg.enabled = true;
        cfg.target_cidr = Some("10.0.0.0/24".into());
        cfg.timeout_secs = 120;
        cfg.exclude = vec!["10.0.0.1".into()];

        let doc = super::schedule_doc_from_config(&cfg);
        assert!(doc.enabled);
        assert_eq!(doc.target_cidr.as_deref(), Some("10.0.0.0/24"));
        assert_eq!(doc.timeout_secs, 120);
        assert_eq!(doc.exclude, vec!["10.0.0.1"]);
        assert_eq!(doc.legacy_schedule_mode, cfg.legacy_schedule_mode());
    }

    /// A config + state dir pair with an inventory already written, so the
    /// read-side handlers have something real to serve.
    fn state_with_inventory(devices: Vec<ConnectedDevice>) -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_dir = dir.path().join("config");
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(
            state_dir.join("inventory.json"),
            serde_json::to_vec(&devices).expect("serialize inventory"),
        )
        .expect("write inventory");
        let state = test_state(&config_dir, &state_dir);
        (dir, state)
    }

    #[tokio::test]
    async fn get_summary_counts_devices_by_status() {
        let (_dir, state) = state_with_inventory(vec![test_device(DeviceStatus::Approved), {
            let mut device = test_device(DeviceStatus::Unauthorized);
            device.device_id = "dev-2".into();
            device.mac = Some("AA:BB:CC:11:22:44".into());
            device
        }]);

        let summary = super::get_summary(State(state))
            .await
            .expect("summary succeeds");
        assert_eq!(summary.0.total, 2);
    }

    #[tokio::test]
    async fn get_summary_reports_not_found_before_any_scan_has_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_dir = dir.path().join("config");
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let state = test_state(&config_dir, &state_dir);

        let error = super::get_summary(State(state))
            .await
            .err()
            .expect("no inventory yet");
        assert!(matches!(error, ApiError::NotFound(_)), "{error:?}");
    }

    #[tokio::test]
    async fn get_device_serves_one_device_and_reports_unknown_ids() {
        let (_dir, state) = state_with_inventory(vec![test_device(DeviceStatus::Unauthorized)]);

        let detail = super::get_device(
            State(state.clone()),
            axum::extract::Path("dev-1".to_string()),
        )
        .await
        .expect("device detail");
        assert_eq!(detail.0.device.device_id, "dev-1");

        let error = super::get_device(
            State(state),
            axum::extract::Path("no-such-device".to_string()),
        )
        .await
        .err()
        .expect("unknown device");
        assert!(matches!(error, ApiError::NotFound(_)), "{error:?}");
    }

    #[tokio::test]
    async fn list_unauthorized_returns_only_unapproved_devices() {
        let (_dir, state) = state_with_inventory(vec![test_device(DeviceStatus::Approved), {
            let mut device = test_device(DeviceStatus::Unauthorized);
            device.device_id = "dev-2".into();
            device
        }]);

        let listed = super::list_unauthorized(State(state))
            .await
            .expect("list_unauthorized succeeds");
        assert!(
            listed
                .0
                .iter()
                .all(|device| device.status != DeviceStatus::Approved),
            "approved devices must not be listed"
        );
    }

    #[tokio::test]
    async fn whitelist_round_trips_through_put_and_get() {
        let (_dir, state) = state_with_inventory(vec![test_device(DeviceStatus::Unauthorized)]);

        // A blank version is replaced with the default rather than persisted.
        let saved = super::put_whitelist(
            State(state.clone()),
            Json(WhitelistDoc {
                version: "   ".to_string(),
                devices: vec![WhitelistEntry {
                    mac: "aa:bb:cc:11:22:33".into(),
                    label: Some("Printer".into()),
                    expected_os: None,
                    expected_ports: vec![22],
                    expected_ips: Vec::new(),
                }],
            }),
        )
        .await
        .expect("put_whitelist succeeds");
        assert_eq!(saved.0.version, default_version());

        let view = super::get_whitelist(State(state))
            .await
            .expect("get_whitelist succeeds");
        assert_eq!(view.0.devices.len(), 1);
        assert!(
            view.0.devices[0].inventory_match,
            "the whitelisted MAC matches the seeded inventory device"
        );
    }

    #[tokio::test]
    async fn get_whitelist_is_empty_before_one_is_written() {
        let (_dir, state) = state_with_inventory(Vec::new());
        let view = super::get_whitelist(State(state))
            .await
            .expect("get_whitelist succeeds");
        assert!(view.0.devices.is_empty());
    }

    #[tokio::test]
    async fn schedule_round_trips_through_put_and_get() {
        let (_dir, state) = state_with_inventory(Vec::new());

        let initial = super::get_schedule(State(state.clone()))
            .await
            .expect("get_schedule succeeds");
        let was_enabled = initial.0.enabled;

        let updated = super::put_schedule(
            State(state.clone()),
            Json(ScheduleUpdateRequest {
                enabled: Some(!was_enabled),
                target_cidr: Some(Some("10.10.0.0/24".to_string())),
                timeout_secs: Some(300),
                exclude: Some(vec!["10.10.0.1".to_string()]),
                schedules: None,
                hourly_intensity: None,
                daily_intensity: None,
            }),
        )
        .await
        .expect("put_schedule succeeds");
        assert_eq!(updated.0.enabled, !was_enabled);
        assert_eq!(updated.0.target_cidr.as_deref(), Some("10.10.0.0/24"));
        assert_eq!(updated.0.timeout_secs, 300);
        assert_eq!(updated.0.exclude, vec!["10.10.0.1"]);

        // The change was actually persisted, not just echoed back.
        let reloaded = super::get_schedule(State(state))
            .await
            .expect("get_schedule succeeds");
        assert_eq!(reloaded.0.target_cidr.as_deref(), Some("10.10.0.0/24"));
        assert_eq!(reloaded.0.timeout_secs, 300);
    }

    /// With no `view`/`limit` the handler serves the raw-XML listing instead of
    /// the enriched history, sorted newest first.
    #[tokio::test]
    async fn get_runs_serves_the_raw_xml_listing_newest_first() {
        let (dir, state) = state_with_inventory(vec![test_device(DeviceStatus::Approved)]);
        let raw_dir = dir.path().join("state").join("raw");
        std::fs::create_dir_all(&raw_dir).expect("raw dir");
        for name in [
            "1700000000.xml",
            "1800000000.xml",
            "not-a-timestamp.xml",
            "notes.txt",
        ] {
            std::fs::write(raw_dir.join(name), b"<nmaprun/>").expect("write raw file");
        }

        let Json(RunsApiResponse::Raw(response)) =
            super::get_runs(State(state), Query(RunsQuery::default()))
                .await
                .expect("get_runs succeeds")
        else {
            panic!("expected the raw listing when no view or limit is given");
        };

        assert_eq!(
            response.total_in_inventory, 1,
            "the raw listing carries the inventory size for context"
        );
        let timestamps: Vec<u64> = response.runs.iter().map(|run| run.unix_ts).collect();
        assert_eq!(
            timestamps,
            vec![1_800_000_000, 1_700_000_000],
            "newest first, and only well-formed .xml names are listed"
        );
        assert!(response.runs.iter().all(|run| run.source == "raw_xml"));
    }

    #[tokio::test]
    async fn get_runs_serves_an_empty_raw_listing_when_nothing_has_been_scanned() {
        let (_dir, state) = state_with_inventory(Vec::new());
        let Json(RunsApiResponse::Raw(response)) =
            super::get_runs(State(state), Query(RunsQuery::default()))
                .await
                .expect("get_runs succeeds")
        else {
            panic!("expected the raw listing");
        };
        assert!(response.runs.is_empty());
        assert_eq!(response.total_in_inventory, 0);
    }

    /// The four scan endpoints differ only in the intensity flag they pass to
    /// the CLI. `run_cli` honours `SGX_PA_CLI_PATH`, so pointing it at a stub
    /// that simply succeeds or fails exercises each handler — and
    /// `scan_with_args`' publish-on-success branch — without launching a real
    /// nmap scan.
    #[tokio::test]
    async fn every_scan_endpoint_invokes_the_cli_and_reports_its_outcome() {
        let _lock = crate::test_support::async_env_lock().await;
        let (_dir, state) = state_with_inventory(vec![test_device(DeviceStatus::Unauthorized)]);
        let previous = std::env::var_os("SGX_PA_CLI_PATH");

        // A stub that exits 0: every handler reports success and the
        // rule-event replay runs.
        std::env::set_var("SGX_PA_CLI_PATH", "/bin/true");
        for (label, response) in [
            (
                "scan_now",
                super::scan_now(
                    State(state.clone()),
                    Query(ScanTargetRequest::default()),
                    axum::body::Bytes::new(),
                )
                .await,
            ),
            (
                "scan_stealth",
                super::scan_stealth(
                    State(state.clone()),
                    Query(ScanTargetRequest::default()),
                    axum::body::Bytes::new(),
                )
                .await,
            ),
            (
                "scan_standard",
                super::scan_standard(
                    State(state.clone()),
                    Query(ScanTargetRequest::default()),
                    axum::body::Bytes::new(),
                )
                .await,
            ),
            (
                "scan_aggressive",
                super::scan_aggressive(
                    State(state.clone()),
                    Query(ScanTargetRequest::default()),
                    axum::body::Bytes::new(),
                )
                .await,
            ),
        ] {
            let response = response.unwrap_or_else(|error| panic!("{label}: {error:?}"));
            assert!(response.0.success, "{label} should report success");
        }

        // A stub that exits non-zero: the handler still answers 200, reporting
        // the failure in the body rather than as an error.
        std::env::set_var("SGX_PA_CLI_PATH", "/bin/false");
        let response = super::scan_now(
            State(state),
            Query(ScanTargetRequest::default()),
            axum::body::Bytes::new(),
        )
        .await
        .expect("scan_now still answers");
        assert!(!response.0.success, "a failing CLI is reported, not raised");

        match previous {
            Some(value) => std::env::set_var("SGX_PA_CLI_PATH", value),
            None => std::env::remove_var("SGX_PA_CLI_PATH"),
        }
    }

    /// The rules bridge replays the most recent run's devices as rule events.
    /// It is infallible by construction — every failure path just returns — so
    /// this checks it completes for both an empty history and a real run.
    #[tokio::test]
    async fn publish_rule_events_for_latest_run_handles_empty_and_populated_history() {
        let (dir, state) = state_with_inventory(vec![test_device(DeviceStatus::Unauthorized)]);

        // No history file at all: returns without publishing anything.
        super::publish_rule_events_for_latest_run(state.as_ref());

        let state_dir = dir.path().join("state");
        let raw_xml = state_dir.join("raw").join("1700000000.xml");
        std::fs::create_dir_all(raw_xml.parent().expect("raw parent")).expect("raw dir");
        std::fs::write(&raw_xml, b"<nmaprun/>").expect("write raw xml");
        let inventory = state_dir.join("inventory.json");
        let record = test_run_record(&raw_xml, &inventory);
        let history_path = run_history::history_path(&state_dir);
        run_history::append_record(&history_path, &record).expect("append run history");

        super::publish_rule_events_for_latest_run(state.as_ref());
    }

    #[tokio::test]
    async fn list_runs_is_empty_before_any_scan_has_run() {
        let (_dir, state) = state_with_inventory(Vec::new());
        let runs = super::list_runs(State(state), Query(RunsQuery::default()))
            .await
            .expect("list_runs succeeds");
        assert!(runs.0.is_empty(), "{:?}", runs.0.len());
    }

    #[test]
    fn enrich_whitelist_doc_preserves_the_version_and_entry_count() {
        let doc = WhitelistDoc {
            version: "3".to_string(),
            devices: vec![WhitelistEntry {
                mac: "AA:BB:CC:DD:EE:04".into(),
                label: Some("Sensor".into()),
                expected_os: None,
                expected_ports: Vec::new(),
                expected_ips: Vec::new(),
            }],
        };
        let inventory = vec![scanned_device(DeviceStatus::Approved)];

        let view = super::enrich_whitelist_doc(doc, &inventory);
        assert_eq!(view.version, "3");
        assert_eq!(view.devices.len(), 1);
    }
}
