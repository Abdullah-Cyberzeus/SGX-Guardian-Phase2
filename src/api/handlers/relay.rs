use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

const DEFAULT_NEBULA_DIR: &str = "/var/lib/sgx-guardian/nebula";
const NEBULA_DIR_ENV: &str = "SGX_GUARDIAN_NEBULA_DIR";
const DEFAULT_CIRCLE_ID: &str = "guardian-circle-alpha";
const DEFAULT_RELAY_MAX_PEERS: u32 = 5;
const DEFAULT_RELAY_MAX_BANDWIDTH_MBPS: u32 = 10;
const DEFAULT_RELAY_ALERT_THRESHOLD_PCT: u8 = 80;

#[derive(Serialize)]
pub struct NodeRoleListItemResponse {
    pub node: String,

    #[serde(rename = "overlayIp")]
    pub overlay_ip: String,

    pub active: bool,

    #[serde(rename = "relayEnabled")]
    pub relay_enabled: bool,

    #[serde(rename = "lighthouseEnabled")]
    pub lighthouse_enabled: bool,

    #[serde(rename = "maxPeers", skip_serializing_if = "Option::is_none")]
    pub max_peers: Option<u32>,

    #[serde(rename = "maxBandwidthMbps", skip_serializing_if = "Option::is_none")]
    pub max_bandwidth_mbps: Option<u32>,

    #[serde(rename = "currentMbps", skip_serializing_if = "Option::is_none")]
    pub current_mbps: Option<f64>,
}

#[derive(Serialize)]
pub struct RelayListResponse {
    pub relays: Vec<NodeRoleListItemResponse>,
}

#[derive(Serialize)]
pub struct LighthouseListResponse {
    pub lighthouses: Vec<NodeRoleListItemResponse>,
}

#[derive(Serialize)]
pub struct MemberListResponse {
    pub members: Vec<NodeRoleListItemResponse>,
}

#[derive(Serialize)]
pub struct RelayLighthouseListResponse {
    #[serde(rename = "relayLighthouses")]
    pub relay_lighthouses: Vec<NodeRoleListItemResponse>,
}

#[derive(Deserialize)]
pub struct RelayLimitsRequest {
    pub node: String,
    #[serde(rename = "maxPeers")]
    pub max_peers: u32,
    #[serde(rename = "maxBandwidthMbps")]
    pub max_bandwidth_mbps: u32,
}

#[derive(Serialize)]
pub struct RelayLimitsResponse {
    pub ok: bool,
    pub node: String,
    #[serde(rename = "maxPeers")]
    pub max_peers: u32,
    #[serde(rename = "maxBandwidthMbps")]
    pub max_bandwidth_mbps: u32,
    #[serde(rename = "pcrSafe")]
    pub pcr_safe: bool,
}

#[derive(Deserialize)]
pub struct RelayToggleRequest {
    pub node: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Serialize)]
pub struct RelayToggleResponse {
    pub ok: bool,
    pub node: String,
    pub enabled: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RelayEntry {
    #[serde(default)]
    node_name: String,
    #[serde(default)]
    overlay_ip: String,
    #[serde(default)]
    physical_endpoint: String,
    #[serde(default)]
    is_active: bool,
    #[serde(default)]
    is_lighthouse: bool,
    #[serde(default)]
    max_peers: u32,
    #[serde(default)]
    max_bandwidth_mbps: u32,
    #[serde(default)]
    last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RelayRegistryDoc {
    #[serde(default)]
    circle_id: String,
    #[serde(default)]
    relays: HashMap<String, RelayEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RelayStatsDoc {
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    current_mbps: f64,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RelaySyncYaml {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    relay: Option<RelayYamlSection>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RelayYamlSection {
    #[serde(default)]
    max_peers: Option<u32>,
    #[serde(default)]
    max_bandwidth_mbps: Option<u32>,
}

#[derive(Copy, Clone)]
enum RoleListKind {
    Relay,
    Lighthouse,
    Member,
    RelayLighthouse,
}

pub async fn list(State(s): State<Arc<AppState>>) -> Result<Json<RelayListResponse>, ApiError> {
    let relays = build_role_list_items(&s.config_dir, RoleListKind::Relay)?;

    Ok(Json(RelayListResponse { relays }))
}

pub async fn lighthouse_list(
    State(s): State<Arc<AppState>>,
) -> Result<Json<LighthouseListResponse>, ApiError> {
    let lighthouses = build_role_list_items(&s.config_dir, RoleListKind::Lighthouse)?;

    Ok(Json(LighthouseListResponse { lighthouses }))
}

pub async fn member_list(
    State(s): State<Arc<AppState>>,
) -> Result<Json<MemberListResponse>, ApiError> {
    let members = build_role_list_items(&s.config_dir, RoleListKind::Member)?;

    Ok(Json(MemberListResponse { members }))
}

pub async fn relay_lighthouse_list(
    State(s): State<Arc<AppState>>,
) -> Result<Json<RelayLighthouseListResponse>, ApiError> {
    let relay_lighthouses = build_role_list_items(&s.config_dir, RoleListKind::RelayLighthouse)?;

    Ok(Json(RelayLighthouseListResponse { relay_lighthouses }))
}

pub async fn limits(
    State(s): State<Arc<AppState>>,
    Json(body): Json<RelayLimitsRequest>,
) -> Result<Json<RelayLimitsResponse>, ApiError> {
    if !body
        .node
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::BadRequest(format!(
            "invalid node name: {}",
            body.node
        )));
    }

    let registry_file = registry_path();
    let mut registry = load_registry(&registry_file)?;
    let now = Utc::now().timestamp();

    let entry = registry
        .relays
        .entry(body.node.clone())
        .or_insert_with(|| RelayEntry {
            node_name: body.node.clone(),
            overlay_ip: String::new(),
            physical_endpoint: String::new(),
            is_active: false,
            is_lighthouse: false,
            max_peers: body.max_peers,
            max_bandwidth_mbps: body.max_bandwidth_mbps,
            last_seen: now,
        });

    entry.max_peers = body.max_peers;
    entry.max_bandwidth_mbps = body.max_bandwidth_mbps;
    entry.last_seen = now;
    if entry.node_name.is_empty() {
        entry.node_name = body.node.clone();
    }

    save_registry(&registry_file, &registry)?;

    log_audit(
        &s.node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Applied,
        &format!(
            "Relay runtime limits updated: node={}, max_peers={}, max_bandwidth_mbps={}",
            body.node, body.max_peers, body.max_bandwidth_mbps
        ),
    );

    Ok(Json(RelayLimitsResponse {
        ok: true,
        node: body.node,
        max_peers: body.max_peers,
        max_bandwidth_mbps: body.max_bandwidth_mbps,
        pcr_safe: true,
    }))
}

pub async fn toggle(
    State(s): State<Arc<AppState>>,
    Json(body): Json<RelayToggleRequest>,
) -> Result<Json<RelayToggleResponse>, ApiError> {
    let node = body
        .node
        .ok_or_else(|| ApiError::BadRequest("node field is required".to_string()))?;
    if !is_valid_node_name(&node) {
        return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
    }

    let enabled = body
        .enabled
        .ok_or_else(|| ApiError::BadRequest("enabled field is required".to_string()))?;

    let cfg_path = Path::new(&s.config_dir).join(format!("{}.yaml", node));
    if !cfg_path.exists() {
        return Err(ApiError::NotFound(format!(
            "config for {} not found; cannot sync relay toggle",
            node
        )));
    }

    mutate_relay_yaml(&cfg_path, enabled)?;
    sync_registry_from_yaml_toggle(&node, &cfg_path, enabled)?;

    log_audit(
        &s.node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Applied,
        &format!(
            "Relay {} via API for {}",
            if enabled { "enabled" } else { "disabled" },
            node
        ),
    );

    Ok(Json(RelayToggleResponse {
        ok: true,
        node: node.clone(),
        enabled,
        message: format!(
            "Relay {} for {}",
            if enabled { "enabled" } else { "disabled" },
            node
        ),
    }))
}

pub async fn lighthouse_toggle(
    State(s): State<Arc<AppState>>,
    Json(body): Json<RelayToggleRequest>,
) -> Result<Json<RelayToggleResponse>, ApiError> {
    let node = body
        .node
        .ok_or_else(|| ApiError::BadRequest("node field is required".to_string()))?;
    if !is_valid_node_name(&node) {
        return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
    }

    let enabled = body
        .enabled
        .ok_or_else(|| ApiError::BadRequest("enabled field is required".to_string()))?;

    let cfg_path = Path::new(&s.config_dir).join(format!("{}.yaml", node));
    if !cfg_path.exists() {
        return Err(ApiError::NotFound(format!(
            "config for {} not found; cannot sync lighthouse toggle",
            node
        )));
    }

    mutate_lighthouse_yaml(&cfg_path, enabled)?;
    sync_lighthouse_registry_from_yaml_toggle(&node, &cfg_path, enabled)?;

    log_audit(
        &s.node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Applied,
        &format!(
            "Lighthouse {} via API for {}",
            if enabled { "enabled" } else { "disabled" },
            node
        ),
    );

    Ok(Json(RelayToggleResponse {
        ok: true,
        node: node.clone(),
        enabled,
        message: format!(
            "Lighthouse {} for {}",
            if enabled { "enabled" } else { "disabled" },
            node
        ),
    }))
}

impl RoleListKind {
    fn matches(self, entry: &crate::nebula::lighthouse::LighthouseEntry) -> bool {
        match self {
            Self::Relay => entry.am_relay && !entry.is_lighthouse,
            Self::Lighthouse => !entry.am_relay && entry.is_lighthouse,
            Self::Member => !entry.am_relay && !entry.is_lighthouse,
            Self::RelayLighthouse => entry.am_relay && entry.is_lighthouse,
        }
    }

    fn includes_runtime_fields(self) -> bool {
        matches!(self, Self::Relay | Self::RelayLighthouse)
    }
}

fn build_role_list_items(
    config_dir: &str,
    kind: RoleListKind,
) -> Result<Vec<NodeRoleListItemResponse>, ApiError> {
    let lighthouse_registry = load_lighthouse_registry(&lighthouse_registry_path())?;
    let runtime_registry = if kind.includes_runtime_fields() {
        Some(load_registry(&registry_path())?)
    } else {
        None
    };
    let stats = if kind.includes_runtime_fields() {
        Some(load_stats_map(&stats_path())?)
    } else {
        None
    };

    let mut entries = lighthouse_registry
        .lighthouses
        .iter()
        .filter(|entry| kind.matches(entry))
        .collect::<Vec<_>>();

    entries.sort_by(|a, b| a.node_name.cmp(&b.node_name));

    Ok(entries
        .into_iter()
        .map(|entry| {
            let runtime_entry = runtime_registry
                .as_ref()
                .and_then(|registry| registry.relays.get(&entry.node_name));
            let (max_peers, max_bandwidth_mbps, current_mbps) = if kind.includes_runtime_fields() {
                let (max_peers, max_bandwidth_mbps) =
                    resolve_list_limits(config_dir, &entry.node_name, runtime_entry);
                let current_mbps = stats
                    .as_ref()
                    .and_then(|map| map.get(&entry.node_name))
                    .copied()
                    .unwrap_or(0.0);
                (
                    Some(max_peers),
                    Some(max_bandwidth_mbps),
                    Some(current_mbps),
                )
            } else {
                (None, None, None)
            };

            NodeRoleListItemResponse {
                node: entry.node_name.clone(),
                overlay_ip: entry.overlay_ip.clone(),
                active: entry.is_active,
                relay_enabled: entry.am_relay,
                lighthouse_enabled: entry.is_lighthouse,
                max_peers,
                max_bandwidth_mbps,
                current_mbps,
            }
        })
        .collect())
}

fn is_valid_node_name(node: &str) -> bool {
    node.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn mutate_relay_yaml(cfg_path: &Path, enabled: bool) -> Result<(), ApiError> {
    let content = fs::read_to_string(cfg_path)
        .map_err(|e| ApiError::Internal(format!("read node config failed: {}", e)))?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| ApiError::Internal(format!("parse node config yaml failed: {}", e)))?;

    if !doc.is_mapping() {
        return Err(ApiError::Internal(
            "node config root is not a mapping".to_string(),
        ));
    }

    let root = doc
        .as_mapping_mut()
        .ok_or_else(|| ApiError::Internal("node config mapping is invalid".to_string()))?;
    let relay_key = serde_yaml::Value::String("relay".to_string());
    let relay_val = root
        .entry(relay_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));

    if !relay_val.is_mapping() {
        *relay_val = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }

    let relay_map = relay_val
        .as_mapping_mut()
        .ok_or_else(|| ApiError::Internal("relay section is not a mapping".to_string()))?;

    relay_map.insert(
        serde_yaml::Value::String("enabled".to_string()),
        serde_yaml::Value::Bool(enabled),
    );
    relay_map
        .entry(serde_yaml::Value::String("max_peers".to_string()))
        .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(
            DEFAULT_RELAY_MAX_PEERS,
        )));
    relay_map
        .entry(serde_yaml::Value::String("max_bandwidth_mbps".to_string()))
        .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(
            DEFAULT_RELAY_MAX_BANDWIDTH_MBPS,
        )));
    relay_map
        .entry(serde_yaml::Value::String("alert_threshold_pct".to_string()))
        .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(
            DEFAULT_RELAY_ALERT_THRESHOLD_PCT,
        )));

    fs::write(
        cfg_path,
        serde_yaml::to_string(&doc).map_err(|e| {
            ApiError::Internal(format!("serialize updated node config yaml failed: {}", e))
        })?,
    )
    .map_err(|e| ApiError::Internal(format!("write node config failed: {}", e)))?;

    Ok(())
}

fn mutate_lighthouse_yaml(cfg_path: &Path, enabled: bool) -> Result<(), ApiError> {
    let content = fs::read_to_string(cfg_path)
        .map_err(|e| ApiError::Internal(format!("read node config failed: {}", e)))?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| ApiError::Internal(format!("parse node config yaml failed: {}", e)))?;

    if !doc.is_mapping() {
        return Err(ApiError::Internal(
            "node config root is not a mapping".to_string(),
        ));
    }

    let root = doc
        .as_mapping_mut()
        .ok_or_else(|| ApiError::Internal("node config mapping is invalid".to_string()))?;
    let lighthouse_key = serde_yaml::Value::String("lighthouse".to_string());
    let lighthouse_val = root
        .entry(lighthouse_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));

    if !lighthouse_val.is_mapping() {
        *lighthouse_val = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }

    let lighthouse_map = lighthouse_val
        .as_mapping_mut()
        .ok_or_else(|| ApiError::Internal("lighthouse section is not a mapping".to_string()))?;

    lighthouse_map.insert(
        serde_yaml::Value::String("enabled".to_string()),
        serde_yaml::Value::Bool(enabled),
    );

    fs::write(
        cfg_path,
        serde_yaml::to_string(&doc).map_err(|e| {
            ApiError::Internal(format!("serialize updated node config yaml failed: {}", e))
        })?,
    )
    .map_err(|e| ApiError::Internal(format!("write node config failed: {}", e)))?;

    Ok(())
}

fn sync_registry_from_yaml_toggle(
    node: &str,
    cfg_path: &Path,
    enable: bool,
) -> Result<(), ApiError> {
    let cfg = load_relay_yaml(cfg_path)?;
    let max_peers = cfg
        .relay
        .as_ref()
        .and_then(|r| r.max_peers)
        .unwrap_or(DEFAULT_RELAY_MAX_PEERS);
    let max_bw = cfg
        .relay
        .as_ref()
        .and_then(|r| r.max_bandwidth_mbps)
        .unwrap_or(DEFAULT_RELAY_MAX_BANDWIDTH_MBPS);

    let overlay_ip = resolve_overlay_ip(node);
    let overlay_for_new_entry = overlay_ip
        .clone()
        .unwrap_or_else(|| cfg.ip.trim().to_string());
    let endpoint_ip = if cfg.ip.trim().is_empty() {
        "0.0.0.0".to_string()
    } else {
        cfg.ip.trim().to_string()
    };
    let endpoint = format!("{}:4242", endpoint_ip);
    let now = Utc::now().timestamp();

    let registry_file = registry_path();
    let mut registry = load_registry(&registry_file)?;
    if registry.circle_id.trim().is_empty() {
        registry.circle_id = DEFAULT_CIRCLE_ID.to_string();
    }

    if enable {
        let entry = registry
            .relays
            .entry(node.to_string())
            .or_insert_with(|| RelayEntry {
                node_name: node.to_string(),
                overlay_ip: overlay_for_new_entry.clone(),
                physical_endpoint: endpoint.clone(),
                is_active: true,
                is_lighthouse: false,
                max_peers,
                max_bandwidth_mbps: max_bw,
                last_seen: now,
            });

        if entry.node_name.is_empty() {
            entry.node_name = node.to_string();
        }
        if let Some(overlay_ip) = &overlay_ip {
            entry.overlay_ip = overlay_ip.clone();
        }
        if entry.physical_endpoint.is_empty() || entry.physical_endpoint == "0.0.0.0:4242" {
            entry.physical_endpoint = endpoint.clone();
        }
        if entry.max_peers == 0 {
            entry.max_peers = max_peers;
        }
        if entry.max_bandwidth_mbps == 0 {
            entry.max_bandwidth_mbps = max_bw;
        }
        entry.is_active = true;
        entry.last_seen = now;
    } else {
        registry.relays.remove(node);
    }

    save_registry(&registry_file, &registry)?;
    sync_lighthouse_relay_role(node, enable, &overlay_for_new_entry, &endpoint)?;
    Ok(())
}

fn sync_lighthouse_registry_from_yaml_toggle(
    node: &str,
    cfg_path: &Path,
    enable: bool,
) -> Result<(), ApiError> {
    let cfg = load_relay_yaml(cfg_path)?;
    let fallback_ip = cfg.ip.trim().to_string();
    let resolved_overlay_ip = resolve_overlay_ip(node).unwrap_or_else(|| fallback_ip.clone());
    let endpoint_ip = if cfg.ip.trim().is_empty() {
        None
    } else {
        Some(cfg.ip.trim().to_string())
    };

    let path = lighthouse_registry_path();
    let mut registry = load_lighthouse_registry(&path)?;
    if registry.circle_id.trim().is_empty() {
        registry.circle_id = DEFAULT_CIRCLE_ID.to_string();
    }

    let mut changed = false;
    if enable {
        let current = registry
            .lighthouses
            .iter()
            .find(|entry| entry.node_name == node);
        let overlay_ip = if resolved_overlay_ip.is_empty() {
            current
                .map(|entry| entry.overlay_ip.clone())
                .unwrap_or_else(String::new)
        } else {
            resolved_overlay_ip.clone()
        };
        let endpoint = endpoint_ip
            .clone()
            .map(|ip| format!("{}:4242", ip))
            .or_else(|| current.map(|entry| entry.physical_endpoint.clone()))
            .unwrap_or_else(|| "0.0.0.0:4242".to_string());
        let am_relay = registry.relay_role_for(node).unwrap_or(false);

        registry.upsert_node(node, &overlay_ip, &endpoint, true, am_relay);
        changed = true;
    } else if registry.set_lighthouse_role(node, false) {
        changed = true;
    }

    if changed {
        registry
            .save(&path)
            .map_err(|e| ApiError::Internal(format!("save lighthouse registry failed: {}", e)))?;
    }

    Ok(())
}

fn load_relay_yaml(path: &Path) -> Result<RelaySyncYaml, ApiError> {
    let text = fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("read node config failed: {}", e)))?;
    serde_yaml::from_str::<RelaySyncYaml>(&text)
        .map_err(|e| ApiError::Internal(format!("parse node config failed: {}", e)))
}

fn resolve_overlay_ip(node: &str) -> Option<String> {
    let path = overlay_registry_path();
    let registry = crate::nebula::overlay_registry::OverlayRegistry::load(&path).ok()?;
    registry.get_ip(node).map(|ip| ip.to_string())
}

fn sync_lighthouse_relay_role(
    node: &str,
    enable: bool,
    overlay_ip: &str,
    endpoint: &str,
) -> Result<(), ApiError> {
    let path = lighthouse_registry_path();
    if !Path::new(&path).exists() {
        return Ok(());
    }

    let mut lh = match crate::nebula::lighthouse::LighthouseRegistry::load(&path) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let mut changed = false;
    if enable {
        if !lh.set_relay_role(node, true) {
            lh.upsert_node(node, overlay_ip, endpoint, false, true);
            changed = true;
        } else {
            changed = true;
        }
        let _ = lh.update_endpoint(node, endpoint);
        lh.mark_active(node);
    } else if lh.set_relay_role(node, false) {
        changed = true;
    }

    if changed {
        lh.save(&path)
            .map_err(|e| ApiError::Internal(format!("save lighthouse registry failed: {}", e)))?;
    }

    Ok(())
}

fn resolve_list_limits(
    config_dir: &str,
    node: &str,
    runtime_entry: Option<&RelayEntry>,
) -> (u32, u32) {
    if let Some(entry) = runtime_entry {
        return (entry.max_peers, entry.max_bandwidth_mbps);
    }

    let cfg_path = Path::new(config_dir).join(format!("{}.yaml", node));
    if let Ok(cfg) = load_relay_yaml(&cfg_path) {
        let max_peers = cfg
            .relay
            .as_ref()
            .and_then(|relay| relay.max_peers)
            .unwrap_or(DEFAULT_RELAY_MAX_PEERS);
        let max_bandwidth_mbps = cfg
            .relay
            .as_ref()
            .and_then(|relay| relay.max_bandwidth_mbps)
            .unwrap_or(DEFAULT_RELAY_MAX_BANDWIDTH_MBPS);
        return (max_peers, max_bandwidth_mbps);
    }

    (DEFAULT_RELAY_MAX_PEERS, DEFAULT_RELAY_MAX_BANDWIDTH_MBPS)
}

fn registry_path() -> String {
    format!("{}/relay_registry.json", nebula_dir())
}

fn stats_path() -> String {
    format!("{}/relay_stats.json", nebula_dir())
}

fn overlay_registry_path() -> String {
    format!("{}/overlay_registry.json", nebula_dir())
}

fn lighthouse_registry_path() -> String {
    format!("{}/lighthouse_registry.json", nebula_dir())
}

fn nebula_dir() -> String {
    std::env::var(NEBULA_DIR_ENV).unwrap_or_else(|_| DEFAULT_NEBULA_DIR.to_string())
}

fn load_registry(path: &str) -> Result<RelayRegistryDoc, ApiError> {
    if !Path::new(path).exists() {
        return Ok(RelayRegistryDoc::default());
    }
    let data = fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("read relay registry failed: {}", e)))?;
    serde_json::from_str::<RelayRegistryDoc>(&data)
        .map_err(|e| ApiError::Internal(format!("parse relay registry failed: {}", e)))
}

fn save_registry(path: &str, registry: &RelayRegistryDoc) -> Result<(), ApiError> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .map_err(|e| ApiError::Internal(format!("create relay registry dir failed: {}", e)))?;
    }
    let tmp = format!("{}.tmp", path);
    let json = serde_json::to_string_pretty(registry)
        .map_err(|e| ApiError::Internal(format!("serialize relay registry failed: {}", e)))?;
    fs::write(&tmp, json)
        .map_err(|e| ApiError::Internal(format!("write relay registry temp failed: {}", e)))?;
    fs::rename(&tmp, path)
        .map_err(|e| ApiError::Internal(format!("replace relay registry failed: {}", e)))?;
    Ok(())
}

fn load_lighthouse_registry(
    path: &str,
) -> Result<crate::nebula::lighthouse::LighthouseRegistry, ApiError> {
    if !Path::new(path).exists() {
        return Ok(crate::nebula::lighthouse::LighthouseRegistry {
            circle_id: String::new(),
            lighthouses: Vec::new(),
        });
    }

    let data = fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("read lighthouse registry failed: {}", e)))?;
    serde_json::from_str::<crate::nebula::lighthouse::LighthouseRegistry>(&data)
        .map_err(|e| ApiError::Internal(format!("parse lighthouse registry failed: {}", e)))
}

fn load_stats_map(path: &str) -> Result<HashMap<String, f64>, ApiError> {
    if !Path::new(path).exists() {
        return Ok(HashMap::new());
    }
    let data = fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("read relay stats failed: {}", e)))?;
    let value: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| ApiError::Internal(format!("parse relay stats failed: {}", e)))?;

    let mut out = HashMap::new();
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("node_id") {
                let doc = serde_json::from_value::<RelayStatsDoc>(serde_json::Value::Object(map))
                    .map_err(|e| {
                    ApiError::Internal(format!("parse relay stats doc failed: {}", e))
                })?;
                if !doc.node_id.is_empty() {
                    out.insert(doc.node_id, doc.current_mbps);
                }
            } else {
                for (node, v) in map {
                    let doc = serde_json::from_value::<RelayStatsDoc>(v).map_err(|e| {
                        ApiError::Internal(format!("parse relay stats entry failed: {}", e))
                    })?;
                    out.insert(node, doc.current_mbps);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                let doc = serde_json::from_value::<RelayStatsDoc>(item).map_err(|e| {
                    ApiError::Internal(format!("parse relay stats item failed: {}", e))
                })?;
                if !doc.node_id.is_empty() {
                    out.insert(doc.node_id, doc.current_mbps);
                }
            }
        }
        _ => {}
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use once_cell::sync::Lazy;
    use std::ffi::OsString;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct EnvGuard {
        nebula_prev: Option<OsString>,
    }

    impl EnvGuard {
        fn new(nebula_dir: &str) -> Self {
            let nebula_prev = std::env::var_os(NEBULA_DIR_ENV);
            std::env::set_var(NEBULA_DIR_ENV, nebula_dir);
            Self { nebula_prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(v) = self.nebula_prev.take() {
                std::env::set_var(NEBULA_DIR_ENV, v);
            } else {
                std::env::remove_var(NEBULA_DIR_ENV);
            }
        }
    }

    fn test_state_with_config(config_dir: &str) -> Arc<AppState> {
        Arc::new(AppState {
            node_id: "nodeA".into(),
            config_dir: config_dir.into(),
            boot_dir: "/tmp/boot".into(),
            keys_dir: "/tmp/keys".into(),
            pcr_dir: "/tmp/pcr".into(),
            pcr_baseline_dir: "/tmp".into(),
            log_dir_primary: "/tmp/logs".into(),
            log_dir_fallback: "/tmp/logs2".into(),
            did_resolver: crate::did::Resolver::new(Default::default()),
            vid_cache: crate::virtual_id_cache::VirtualIdCache::new(),
            discovery_config_dir: "/tmp/discovery-config".into(),
            discovery_state_dir: "/tmp/discovery-state".into(),
        })
    }

    fn test_state() -> Arc<AppState> {
        test_state_with_config("/tmp/config")
    }

    fn seed_role_registry_runtime_and_stats(tmp: &TempDir) {
        let nebula_dir = tmp.path().join("nebula");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");

        fs::write(
            nebula_dir.join("lighthouse_registry.json"),
            r#"{
  "circle_id": "alpha",
  "lighthouses": [
    {
      "node_name": "nodeA",
      "overlay_ip": "192.168.100.1",
      "physical_endpoint": "10.0.0.1:4242",
      "is_primary": true,
      "is_active": true,
      "is_lighthouse": true,
      "am_relay": true
    },
    {
      "node_name": "nodeB",
      "overlay_ip": "192.168.100.2",
      "physical_endpoint": "10.0.0.2:4242",
      "is_primary": false,
      "is_active": true,
      "is_lighthouse": true,
      "am_relay": false
    },
    {
      "node_name": "nodeC",
      "overlay_ip": "192.168.100.3",
      "physical_endpoint": "10.0.0.3:4242",
      "is_primary": false,
      "is_active": false,
      "is_lighthouse": false,
      "am_relay": false
    },
    {
      "node_name": "nodeD",
      "overlay_ip": "192.168.100.4",
      "physical_endpoint": "10.0.0.4:4242",
      "is_primary": false,
      "is_active": true,
      "is_lighthouse": false,
      "am_relay": true
    }
  ]
}"#,
        )
        .expect("lighthouse registry");

        fs::write(
            nebula_dir.join("relay_registry.json"),
            r#"{
  "circle_id": "alpha",
  "relays": {
    "nodeA": {
      "node_name": "nodeA",
      "overlay_ip": "192.168.100.1",
      "physical_endpoint": "10.0.0.1:4242",
      "is_active": true,
      "is_lighthouse": true,
      "max_peers": 7,
      "max_bandwidth_mbps": 11,
      "last_seen": 1711111111
    }
  }
}"#,
        )
        .expect("relay registry");

        fs::write(
            nebula_dir.join("relay_stats.json"),
            r#"{
  "nodeA": {"node_id":"nodeA","current_mbps":4.25},
  "nodeD": {"node_id":"nodeD","current_mbps":1.5}
}"#,
        )
        .expect("stats");
    }

    fn write_node_yaml(path: &Path, node: &str, ip: &str, relay_enabled: bool) {
        let yaml = format!(
            r#"---
node_id: "{node}"
hostname: "{node}-host"
ip: "{ip}"
port: 50052
public_key: "pk-{node}"

relay:
  enabled: {relay_enabled}
  max_peers: 9
  max_bandwidth_mbps: 15
  alert_threshold_pct: 80
"#
        );
        fs::write(path, yaml).expect("write node yaml");
    }

    #[tokio::test]
    async fn relay_list_route_filters_only_relay_only_nodes_and_resolves_runtime_fields() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_dir = tmp.path().join("config");
        fs::create_dir_all(&config_dir).expect("config dir");

        seed_role_registry_runtime_and_stats(&tmp);
        write_node_yaml(&config_dir.join("nodeA.yaml"), "nodeA", "10.0.0.1", true);
        write_node_yaml(&config_dir.join("nodeD.yaml"), "nodeD", "10.0.0.4", true);

        let _env = EnvGuard::new(&tmp.path().join("nebula").to_string_lossy());

        let Json(resp) = super::list(State(test_state_with_config(&config_dir.to_string_lossy())))
            .await
            .expect("relay list");

        assert_eq!(resp.relays.len(), 1);
        assert!(resp.relays.iter().all(|entry| entry.node != "nodeA"));

        assert_eq!(resp.relays[0].node, "nodeD");
        assert_eq!(resp.relays[0].overlay_ip, "192.168.100.4");
        assert!(resp.relays[0].active);
        assert!(resp.relays[0].relay_enabled);
        assert!(!resp.relays[0].lighthouse_enabled);
        assert_eq!(resp.relays[0].max_peers, Some(9));
        assert_eq!(resp.relays[0].max_bandwidth_mbps, Some(15));
        assert_eq!(resp.relays[0].current_mbps, Some(1.5));
    }

    #[tokio::test]
    async fn lighthouse_list_route_filters_only_lighthouse_only_nodes() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");

        seed_role_registry_runtime_and_stats(&tmp);

        let _env = EnvGuard::new(&tmp.path().join("nebula").to_string_lossy());

        let Json(resp) = super::lighthouse_list(State(test_state()))
            .await
            .expect("lighthouse list");

        assert_eq!(resp.lighthouses.len(), 1);
        assert!(resp.lighthouses.iter().all(|entry| entry.node != "nodeA"));

        assert_eq!(resp.lighthouses[0].node, "nodeB");
        assert!(!resp.lighthouses[0].relay_enabled);
        assert!(resp.lighthouses[0].lighthouse_enabled);
        assert_eq!(resp.lighthouses[0].max_peers, None);
        assert_eq!(resp.lighthouses[0].current_mbps, None);
    }

    #[tokio::test]
    async fn member_list_route_filters_only_members() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");

        seed_role_registry_runtime_and_stats(&tmp);

        let _env = EnvGuard::new(&tmp.path().join("nebula").to_string_lossy());

        let Json(resp) = super::member_list(State(test_state()))
            .await
            .expect("member list");

        assert_eq!(resp.members.len(), 1);
        assert_eq!(resp.members[0].node, "nodeC");
        assert!(!resp.members[0].active);
        assert!(!resp.members[0].relay_enabled);
        assert!(!resp.members[0].lighthouse_enabled);
        assert_eq!(resp.members[0].max_peers, None);
        assert_eq!(resp.members[0].current_mbps, None);
    }

    #[tokio::test]
    async fn relay_lighthouse_list_route_filters_only_dual_role_nodes() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_dir = tmp.path().join("config");
        fs::create_dir_all(&config_dir).expect("config dir");

        seed_role_registry_runtime_and_stats(&tmp);
        write_node_yaml(&config_dir.join("nodeA.yaml"), "nodeA", "10.0.0.1", true);

        let _env = EnvGuard::new(&tmp.path().join("nebula").to_string_lossy());

        let Json(resp) = super::relay_lighthouse_list(State(test_state_with_config(
            &config_dir.to_string_lossy(),
        )))
        .await
        .expect("relay lighthouse list");

        assert_eq!(resp.relay_lighthouses.len(), 1);
        assert_eq!(resp.relay_lighthouses[0].node, "nodeA");
        assert!(resp.relay_lighthouses[0].relay_enabled);
        assert!(resp.relay_lighthouses[0].lighthouse_enabled);
        assert_eq!(resp.relay_lighthouses[0].max_peers, Some(7));
        assert_eq!(resp.relay_lighthouses[0].current_mbps, Some(4.25));
    }

    #[tokio::test]
    async fn role_list_routes_return_empty_when_lighthouse_registry_is_missing() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let nebula_dir = tmp.path().join("nebula");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");
        let _env = EnvGuard::new(&nebula_dir.to_string_lossy());

        let Json(relays) = super::list(State(test_state())).await.expect("relay list");
        let Json(lighthouses) = super::lighthouse_list(State(test_state()))
            .await
            .expect("lighthouse list");
        let Json(members) = super::member_list(State(test_state()))
            .await
            .expect("member list");
        let Json(relay_lighthouses) = super::relay_lighthouse_list(State(test_state()))
            .await
            .expect("relay lighthouse list");

        assert!(relays.relays.is_empty());
        assert!(lighthouses.lighthouses.is_empty());
        assert!(members.members.is_empty());
        assert!(relay_lighthouses.relay_lighthouses.is_empty());
    }

    #[tokio::test]
    async fn relay_limits_route_updates_runtime_registry_only() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        seed_role_registry_runtime_and_stats(&tmp);
        let _env = EnvGuard::new(&tmp.path().join("nebula").to_string_lossy());

        let Json(resp) = super::limits(
            State(test_state()),
            Json(RelayLimitsRequest {
                node: "nodeA".into(),
                max_peers: 7,
                max_bandwidth_mbps: 15,
            }),
        )
        .await
        .expect("relay limits");

        assert!(resp.ok);
        assert!(resp.pcr_safe);
        assert_eq!(resp.max_peers, 7);

        let updated = fs::read_to_string(tmp.path().join("nebula").join("relay_registry.json"))
            .expect("read updated registry");
        assert!(updated.contains("\"max_peers\": 7"));
        assert!(updated.contains("\"max_bandwidth_mbps\": 15"));
    }

    #[tokio::test]
    async fn relay_toggle_route_enable_disable_enable_keeps_single_entry() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let nebula_dir = tmp.path().join("nebula");
        let config_dir = tmp.path().join("config");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");
        fs::create_dir_all(&config_dir).expect("config dir");
        let _env = EnvGuard::new(&nebula_dir.to_string_lossy());

        write_node_yaml(
            &config_dir.join("nodeB.yaml"),
            "nodeB",
            "10.20.30.40",
            false,
        );

        let mut overlay = crate::nebula::overlay_registry::OverlayRegistry::new(
            "guardian-circle-alpha",
            "192.168.100",
            "nodeA",
        );
        overlay.assign_ip("nodeB").expect("assign overlay");
        overlay
            .save(overlay_registry_path().as_str())
            .expect("save overlay registry");

        let mut lh = crate::nebula::lighthouse::LighthouseRegistry::new(
            "guardian-circle-alpha",
            "nodeA",
            "192.168.100.1",
            "10.0.0.1:4242",
        );
        lh.upsert_node("nodeB", "192.168.100.2", "10.20.30.40:4242", false, false);
        lh.save(lighthouse_registry_path().as_str())
            .expect("save lighthouse registry");

        let state = test_state_with_config(&config_dir.to_string_lossy());

        let _ = super::toggle(
            State(state.clone()),
            Json(RelayToggleRequest {
                node: Some("nodeB".to_string()),
                enabled: Some(true),
            }),
        )
        .await
        .expect("enable");

        let enabled_once: RelayRegistryDoc =
            serde_json::from_str(&fs::read_to_string(registry_path()).expect("read registry"))
                .expect("parse registry");
        assert!(enabled_once.relays.contains_key("nodeB"));
        let enabled_lighthouse = crate::nebula::lighthouse::LighthouseRegistry::load(
            lighthouse_registry_path().as_str(),
        )
        .expect("load lighthouse registry after enable");
        let enabled_lighthouse_node = enabled_lighthouse
            .lighthouses
            .iter()
            .filter(|entry| entry.node_name == "nodeB")
            .collect::<Vec<_>>();
        assert_eq!(enabled_lighthouse_node.len(), 1);
        assert!(enabled_lighthouse_node[0].am_relay);
        assert!(enabled_lighthouse_node[0].is_active);

        let _ = super::toggle(
            State(state.clone()),
            Json(RelayToggleRequest {
                node: Some("nodeB".to_string()),
                enabled: Some(false),
            }),
        )
        .await
        .expect("disable");

        let disabled: RelayRegistryDoc =
            serde_json::from_str(&fs::read_to_string(registry_path()).expect("read registry"))
                .expect("parse registry");
        assert!(!disabled.relays.contains_key("nodeB"));
        let disabled_lighthouse = crate::nebula::lighthouse::LighthouseRegistry::load(
            lighthouse_registry_path().as_str(),
        )
        .expect("load lighthouse registry after disable");
        let disabled_lighthouse_node = disabled_lighthouse
            .lighthouses
            .iter()
            .filter(|entry| entry.node_name == "nodeB")
            .collect::<Vec<_>>();
        assert_eq!(disabled_lighthouse_node.len(), 1);
        assert!(!disabled_lighthouse_node[0].am_relay);

        let Json(resp) = super::toggle(
            State(state),
            Json(RelayToggleRequest {
                node: Some("nodeB".to_string()),
                enabled: Some(true),
            }),
        )
        .await
        .expect("enable again");

        assert!(resp.ok);
        assert!(resp.enabled);
        assert_eq!(resp.message, "Relay enabled for nodeB");

        let reenabled: RelayRegistryDoc =
            serde_json::from_str(&fs::read_to_string(registry_path()).expect("read registry"))
                .expect("parse registry");
        assert_eq!(reenabled.relays.len(), 1);
        assert!(reenabled.relays.contains_key("nodeB"));
        let reenabled_lighthouse = crate::nebula::lighthouse::LighthouseRegistry::load(
            lighthouse_registry_path().as_str(),
        )
        .expect("load lighthouse registry after re-enable");
        let reenabled_lighthouse_node = reenabled_lighthouse
            .lighthouses
            .iter()
            .filter(|entry| entry.node_name == "nodeB")
            .collect::<Vec<_>>();
        assert_eq!(reenabled_lighthouse_node.len(), 1);
        assert!(reenabled_lighthouse_node[0].am_relay);
        assert_eq!(reenabled_lighthouse_node[0].overlay_ip, "192.168.100.2");
    }

    #[tokio::test]
    async fn lighthouse_toggle_route_enable_disable_preserves_single_entry_and_relay_role() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let nebula_dir = tmp.path().join("nebula");
        let config_dir = tmp.path().join("config");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");
        fs::create_dir_all(&config_dir).expect("config dir");
        let _env = EnvGuard::new(&nebula_dir.to_string_lossy());

        write_node_yaml(
            &config_dir.join("nodeB.yaml"),
            "nodeB",
            "10.20.30.40",
            false,
        );

        let mut overlay = crate::nebula::overlay_registry::OverlayRegistry::new(
            DEFAULT_CIRCLE_ID,
            "192.168.100",
            "nodeA",
        );
        overlay.assign_ip("nodeB").expect("assign overlay");
        overlay
            .save(overlay_registry_path().as_str())
            .expect("save overlay registry");

        let mut lh = crate::nebula::lighthouse::LighthouseRegistry::new(
            DEFAULT_CIRCLE_ID,
            "nodeA",
            "192.168.100.1",
            "10.0.0.1:4242",
        );
        lh.upsert_node("nodeB", "192.168.100.2", "10.20.30.39:4242", false, true);
        lh.save(lighthouse_registry_path().as_str())
            .expect("save lighthouse registry");

        let state = test_state_with_config(&config_dir.to_string_lossy());

        let Json(enabled_resp) = super::lighthouse_toggle(
            State(state.clone()),
            Json(RelayToggleRequest {
                node: Some("nodeB".to_string()),
                enabled: Some(true),
            }),
        )
        .await
        .expect("enable lighthouse");

        assert!(enabled_resp.ok);
        assert_eq!(enabled_resp.message, "Lighthouse enabled for nodeB");

        let enabled_yaml = fs::read_to_string(config_dir.join("nodeB.yaml")).expect("read yaml");
        assert!(enabled_yaml.contains("lighthouse:\n  enabled: true"));

        let enabled_registry = crate::nebula::lighthouse::LighthouseRegistry::load(
            lighthouse_registry_path().as_str(),
        )
        .expect("load lighthouse registry after enable");
        let enabled_entries = enabled_registry
            .lighthouses
            .iter()
            .filter(|entry| entry.node_name == "nodeB")
            .collect::<Vec<_>>();
        assert_eq!(enabled_entries.len(), 1);
        assert!(enabled_entries[0].is_lighthouse);
        assert!(enabled_entries[0].am_relay);
        assert_eq!(enabled_entries[0].overlay_ip, "192.168.100.2");
        assert_eq!(enabled_entries[0].physical_endpoint, "10.20.30.40:4242");

        let Json(disabled_resp) = super::lighthouse_toggle(
            State(state),
            Json(RelayToggleRequest {
                node: Some("nodeB".to_string()),
                enabled: Some(false),
            }),
        )
        .await
        .expect("disable lighthouse");

        assert!(disabled_resp.ok);
        assert_eq!(disabled_resp.message, "Lighthouse disabled for nodeB");

        let disabled_yaml = fs::read_to_string(config_dir.join("nodeB.yaml")).expect("read yaml");
        assert!(disabled_yaml.contains("lighthouse:\n  enabled: false"));

        let disabled_registry = crate::nebula::lighthouse::LighthouseRegistry::load(
            lighthouse_registry_path().as_str(),
        )
        .expect("load lighthouse registry after disable");
        let disabled_entries = disabled_registry
            .lighthouses
            .iter()
            .filter(|entry| entry.node_name == "nodeB")
            .collect::<Vec<_>>();
        assert_eq!(disabled_entries.len(), 1);
        assert!(!disabled_entries[0].is_lighthouse);
        assert!(disabled_entries[0].am_relay);
    }

    #[tokio::test]
    async fn lighthouse_toggle_route_upserts_missing_node_from_overlay_and_yaml() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let nebula_dir = tmp.path().join("nebula");
        let config_dir = tmp.path().join("config");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");
        fs::create_dir_all(&config_dir).expect("config dir");
        let _env = EnvGuard::new(&nebula_dir.to_string_lossy());

        write_node_yaml(
            &config_dir.join("nodeC.yaml"),
            "nodeC",
            "10.30.40.50",
            false,
        );

        let mut overlay = crate::nebula::overlay_registry::OverlayRegistry::new(
            DEFAULT_CIRCLE_ID,
            "192.168.100",
            "nodeA",
        );
        overlay.assign_ip("nodeC").expect("assign overlay");
        overlay
            .save(overlay_registry_path().as_str())
            .expect("save overlay registry");

        let lh = crate::nebula::lighthouse::LighthouseRegistry::new(
            DEFAULT_CIRCLE_ID,
            "nodeA",
            "192.168.100.1",
            "10.0.0.1:4242",
        );
        lh.save(lighthouse_registry_path().as_str())
            .expect("save lighthouse registry");

        let Json(resp) = super::lighthouse_toggle(
            State(test_state_with_config(&config_dir.to_string_lossy())),
            Json(RelayToggleRequest {
                node: Some("nodeC".to_string()),
                enabled: Some(true),
            }),
        )
        .await
        .expect("enable lighthouse");

        assert!(resp.ok);
        assert!(resp.enabled);

        let registry = crate::nebula::lighthouse::LighthouseRegistry::load(
            lighthouse_registry_path().as_str(),
        )
        .expect("load lighthouse registry");
        let node_c = registry
            .lighthouses
            .iter()
            .find(|entry| entry.node_name == "nodeC")
            .expect("nodeC lighthouse entry");
        assert!(node_c.is_lighthouse);
        assert!(!node_c.am_relay);
        assert_eq!(node_c.overlay_ip, "192.168.100.2");
        assert_eq!(node_c.physical_endpoint, "10.30.40.50:4242");
    }

    #[tokio::test]
    async fn relay_toggle_route_rejects_missing_enabled_field() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let nebula_dir = tmp.path().join("nebula");
        let config_dir = tmp.path().join("config");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");
        fs::create_dir_all(&config_dir).expect("config dir");
        let _env = EnvGuard::new(&nebula_dir.to_string_lossy());

        write_node_yaml(
            &config_dir.join("nodeB.yaml"),
            "nodeB",
            "10.20.30.40",
            false,
        );

        let result = super::toggle(
            State(test_state_with_config(&config_dir.to_string_lossy())),
            Json(RelayToggleRequest {
                node: Some("nodeB".to_string()),
                enabled: None,
            }),
        )
        .await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }
}
