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

#[derive(Serialize)]
pub struct RelayListItemResponse {
    pub node: String,
    #[serde(rename = "overlayIp")]
    pub overlay_ip: String,
    pub active: bool,
    #[serde(rename = "maxPeers")]
    pub max_peers: u32,
    #[serde(rename = "maxBandwidthMbps")]
    pub max_bandwidth_mbps: u32,
    #[serde(rename = "currentMbps")]
    pub current_mbps: f64,
}

#[derive(Serialize)]
pub struct RelayListResponse {
    pub relays: Vec<RelayListItemResponse>,
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

pub async fn list(_state: State<Arc<AppState>>) -> Result<Json<RelayListResponse>, ApiError> {
    let registry = load_registry(&registry_path())?;
    let stats = load_stats_map(&stats_path())?;

    let mut nodes = registry.relays.keys().cloned().collect::<Vec<_>>();
    nodes.sort();

    let relays = nodes
        .into_iter()
        .filter_map(|node| {
            registry
                .relays
                .get(&node)
                .map(|entry| RelayListItemResponse {
                    node: if entry.node_name.is_empty() {
                        node.clone()
                    } else {
                        entry.node_name.clone()
                    },
                    overlay_ip: entry.overlay_ip.clone(),
                    active: entry.is_active,
                    max_peers: entry.max_peers,
                    max_bandwidth_mbps: entry.max_bandwidth_mbps,
                    current_mbps: stats.get(&node).copied().unwrap_or(0.0),
                })
        })
        .collect();

    Ok(Json(RelayListResponse { relays }))
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

fn registry_path() -> String {
    format!("{}/relay_registry.json", nebula_dir())
}

fn stats_path() -> String {
    format!("{}/relay_stats.json", nebula_dir())
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

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            node_id: "nodeA".into(),
            config_dir: "/tmp/config".into(),
            boot_dir: "/tmp/boot".into(),
            keys_dir: "/tmp/keys".into(),
            pcr_dir: "/tmp/pcr".into(),
            pcr_baseline_dir: "/tmp".into(),
            log_dir_primary: "/tmp/logs".into(),
            log_dir_fallback: "/tmp/logs2".into(),
        })
    }

    fn seed_registry_and_stats(tmp: &TempDir) {
        let nebula_dir = tmp.path().join("nebula");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");
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
      "is_lighthouse": false,
      "max_peers": 5,
      "max_bandwidth_mbps": 10,
      "last_seen": 1710000000
    }
  }
}"#,
        )
        .expect("registry");
        fs::write(
            nebula_dir.join("relay_stats.json"),
            r#"{"node_id":"nodeA","current_mbps":4.25}"#,
        )
        .expect("stats");
    }

    #[tokio::test]
    async fn relay_list_route_reads_registry_and_stats() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        seed_registry_and_stats(&tmp);
        let _env = EnvGuard::new(&tmp.path().join("nebula").to_string_lossy());

        let Json(resp) = super::list(State(test_state())).await.expect("relay list");
        assert_eq!(resp.relays.len(), 1);
        assert_eq!(resp.relays[0].node, "nodeA");
        assert!((resp.relays[0].current_mbps - 4.25).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn relay_limits_route_updates_runtime_registry_only() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        seed_registry_and_stats(&tmp);
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
}
