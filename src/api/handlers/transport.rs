use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use axum::{
    extract::{Query, State},
    Json,
};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

const DEFAULT_SYS_NET_DIR: &str = "/sys/class/net";
const DEFAULT_LOCK_DIR: &str = "/var/lib/sgx-guardian/cot";
const SYS_NET_DIR_ENV: &str = "SGX_GUARDIAN_SYS_NET_DIR";
const LOCK_DIR_ENV: &str = "SGX_GUARDIAN_COT_LOCK_DIR";

#[derive(Deserialize)]
pub struct TransportQuery {
    pub node: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportInterface {
    pub name: String,
    pub transport: String,
    pub priority: u8,
    pub status: String,
    pub ip: Option<String>,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveTransport {
    pub name: String,
    pub transport: String,
}

#[derive(Serialize)]
pub struct TransportListResponse {
    pub node: String,
    pub interfaces: Vec<TransportInterface>,
    pub active: Option<ActiveTransport>,
    pub lock: Option<String>,
}

#[derive(Serialize)]
pub struct TransportStatusResponse {
    pub node: String,
    pub active: Option<ActiveTransport>,
    pub lock: Option<String>,
}

#[derive(Deserialize)]
pub struct TransportLockRequest {
    pub node: Option<String>,
    #[serde(rename = "interfaceName")]
    pub interface_name: Option<String>,
}

#[derive(Serialize)]
pub struct TransportLockResponse {
    pub ok: bool,
    pub node: String,
    pub lock: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct TransportUnlockRequest {
    pub node: Option<String>,
}

#[derive(Serialize)]
pub struct TransportUnlockResponse {
    pub ok: bool,
    pub node: String,
    pub lock: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportType {
    Ethernet,
    WiFi,
    Bluetooth,
    Cellular,
    Satellite,
}

impl TransportType {
    fn default_priority(self) -> u8 {
        match self {
            Self::Ethernet => 10,
            Self::WiFi => 20,
            Self::Bluetooth => 40,
            Self::Cellular => 5,
            Self::Satellite => 50,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::WiFi => "WiFi",
            Self::Bluetooth => "Bluetooth",
            Self::Cellular => "Cellular",
            Self::Satellite => "Satellite",
        }
    }
}

#[derive(Debug, Clone)]
struct TransportSnapshot {
    interfaces: Vec<TransportInterface>,
    active: Option<ActiveTransport>,
    lock: Option<String>,
}

pub async fn list(
    State(s): State<Arc<AppState>>,
    Query(q): Query<TransportQuery>,
) -> Result<Json<TransportListResponse>, ApiError> {
    let node = normalize_node(q.node, &s.node_id)?;
    let snapshot = snapshot(&node, &cot_lock_dir(), &sys_net_dir());
    Ok(Json(TransportListResponse {
        node,
        interfaces: snapshot.interfaces,
        active: snapshot.active,
        lock: snapshot.lock,
    }))
}

pub async fn status(
    State(s): State<Arc<AppState>>,
    Query(q): Query<TransportQuery>,
) -> Result<Json<TransportStatusResponse>, ApiError> {
    let node = normalize_node(q.node, &s.node_id)?;
    let snapshot = snapshot(&node, &cot_lock_dir(), &sys_net_dir());
    Ok(Json(TransportStatusResponse {
        node,
        active: snapshot.active,
        lock: snapshot.lock,
    }))
}

pub async fn lock(
    State(s): State<Arc<AppState>>,
    Json(body): Json<TransportLockRequest>,
) -> Result<Json<TransportLockResponse>, ApiError> {
    let node = normalize_required_node(body.node)?;
    let interface_name = normalize_interface_name(body.interface_name)?;

    let net_dir = sys_net_dir();
    let lock_dir = cot_lock_dir();
    let interfaces = detect_interfaces(&net_dir);
    if !interfaces.iter().any(|iface| iface.name == interface_name) {
        return Err(ApiError::NotFound(format!(
            "interface not found: {}",
            interface_name
        )));
    }

    fs::create_dir_all(&lock_dir)
        .map_err(|e| ApiError::Internal(format!("create transport lock dir failed: {}", e)))?;
    fs::write(lock_path(&lock_dir, &node), format!("{}\n", interface_name))
        .map_err(|e| ApiError::Internal(format!("write transport lock failed: {}", e)))?;

    log_audit(
        &s.node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Applied,
        &format!(
            "Transport locked via API: node={}, interface={}",
            node, interface_name
        ),
    );

    Ok(Json(TransportLockResponse {
        ok: true,
        node,
        lock: interface_name.clone(),
        message: format!("Transport locked to {}", interface_name),
    }))
}

pub async fn unlock(
    State(s): State<Arc<AppState>>,
    Json(body): Json<TransportUnlockRequest>,
) -> Result<Json<TransportUnlockResponse>, ApiError> {
    let node = normalize_required_node(body.node)?;
    let path = lock_path(&cot_lock_dir(), &node);

    let message = if Path::new(&path).exists() {
        fs::remove_file(&path)
            .map_err(|e| ApiError::Internal(format!("remove transport lock failed: {}", e)))?;
        "Transport unlocked".to_string()
    } else {
        format!("Transport already unlocked for {}", node)
    };

    log_audit(
        &s.node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Applied,
        &format!("Transport unlocked via API: node={}", node),
    );

    Ok(Json(TransportUnlockResponse {
        ok: true,
        node,
        lock: None,
        message,
    }))
}

fn normalize_node(node: Option<String>, fallback: &str) -> Result<String, ApiError> {
    let node = node.unwrap_or_else(|| fallback.to_string());
    if !node
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
    }
    Ok(node)
}

fn normalize_required_node(node: Option<String>) -> Result<String, ApiError> {
    let node = node.ok_or_else(|| ApiError::BadRequest("node field is required".to_string()))?;
    normalize_node(Some(node), "")
}

fn normalize_interface_name(interface_name: Option<String>) -> Result<String, ApiError> {
    let interface_name = interface_name
        .ok_or_else(|| ApiError::BadRequest("interfaceName field is required".to_string()))?;
    if interface_name.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "interfaceName field cannot be empty".to_string(),
        ));
    }
    if !interface_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
    {
        return Err(ApiError::BadRequest(format!(
            "invalid interfaceName: {}",
            interface_name
        )));
    }
    Ok(interface_name)
}

fn snapshot(node: &str, lock_dir: &str, net_dir: &str) -> TransportSnapshot {
    let interfaces = detect_interfaces(net_dir);
    let lock = read_lock(lock_dir, node);
    let active = determine_active(&interfaces, lock.as_deref());
    TransportSnapshot {
        interfaces,
        active,
        lock,
    }
}

fn detect_interfaces(sys_net_dir: &str) -> Vec<TransportInterface> {
    let mut out = Vec::new();
    let ip_by_interface = detect_ipv4_addrs();
    let Ok(entries) = fs::read_dir(sys_net_dir) else {
        return out;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|v| v.to_string()) else {
            continue;
        };

        if should_skip_interface(&name) {
            continue;
        }

        let Some(transport) = classify_transport(&name) else {
            continue;
        };

        let operstate_path = format!("{}/{}/operstate", sys_net_dir, name);
        let is_up = fs::read_to_string(operstate_path)
            .map(|s| s.trim() == "up")
            .unwrap_or(false);

        let ip = ip_by_interface.get(&name).cloned();
        let available = is_up && ip.is_some();

        out.push(TransportInterface {
            name,
            transport: transport.as_str().to_string(),
            priority: transport.default_priority(),
            status: if available {
                "UP".to_string()
            } else {
                "DOWN".to_string()
            },
            ip,
            available,
        });
    }

    out.sort_by_key(|iface| (iface.priority, iface.name.clone()));
    out
}

fn determine_active(
    interfaces: &[TransportInterface],
    lock: Option<&str>,
) -> Option<ActiveTransport> {
    if let Some(locked_iface) = lock {
        if let Some(locked_active) = interfaces
            .iter()
            .find(|iface| iface.name == locked_iface && iface.available)
            .map(|iface| ActiveTransport {
                name: iface.name.clone(),
                transport: iface.transport.clone(),
            })
        {
            return Some(locked_active);
        }

        return interfaces
            .iter()
            .find(|iface| iface.available)
            .map(|iface| ActiveTransport {
                name: iface.name.clone(),
                transport: iface.transport.clone(),
            });
    }

    interfaces
        .iter()
        .find(|iface| iface.available)
        .map(|iface| ActiveTransport {
            name: iface.name.clone(),
            transport: iface.transport.clone(),
        })
}

fn read_lock(lock_dir: &str, node: &str) -> Option<String> {
    let path = lock_path(lock_dir, node);
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn lock_path(lock_dir: &str, node: &str) -> String {
    format!("{}/transport_lock_{}.txt", lock_dir, node)
}

fn detect_ipv4_addrs() -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(interfaces) = NetworkInterface::show() else {
        return out;
    };

    for iface in interfaces {
        if let Some(ip) = iface.addr.iter().find_map(|addr| match addr {
            Addr::V4(v4) => Some(v4.ip.to_string()),
            Addr::V6(_) => None,
        }) {
            out.insert(iface.name, ip);
        }
    }

    out
}

fn should_skip_interface(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "lo"
        || lower.starts_with("docker")
        || lower.starts_with("veth")
        || lower.starts_with("br-")
        || lower.starts_with("virbr")
        || lower.starts_with("vnet")
        || lower.starts_with("nebula")
}

fn classify_transport(name: &str) -> Option<TransportType> {
    let lower = name.to_lowercase();
    if lower.starts_with("sat") || lower.starts_with("ppp") {
        return Some(TransportType::Satellite);
    }
    if lower.starts_with("eth")
        || lower.starts_with("en")
        || lower.starts_with("eno")
        || lower.starts_with("enp")
    {
        return Some(TransportType::Ethernet);
    }
    if lower.starts_with("wlan") || lower.starts_with("wl") || lower.starts_with("wlp") {
        return Some(TransportType::WiFi);
    }
    if lower.starts_with("bnep") || lower.starts_with("bt") || lower.starts_with("hci") {
        return Some(TransportType::Bluetooth);
    }
    if lower.starts_with("wwan") || lower.starts_with("rmnet") || lower.starts_with("usb") {
        return Some(TransportType::Cellular);
    }
    None
}

fn sys_net_dir() -> String {
    std::env::var(SYS_NET_DIR_ENV).unwrap_or_else(|_| DEFAULT_SYS_NET_DIR.to_string())
}

fn cot_lock_dir() -> String {
    std::env::var(LOCK_DIR_ENV).unwrap_or_else(|_| DEFAULT_LOCK_DIR.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use std::ffi::OsString;
    use tempfile::TempDir;

    use crate::test_utils::TEST_ENV_LOCK;

    struct EnvGuard {
        sys_net_prev: Option<OsString>,
        lock_prev: Option<OsString>,
    }

    impl EnvGuard {
        fn new(sys_net_dir: &str, lock_dir: &str) -> Self {
            let sys_net_prev = std::env::var_os(SYS_NET_DIR_ENV);
            let lock_prev = std::env::var_os(LOCK_DIR_ENV);
            std::env::set_var(SYS_NET_DIR_ENV, sys_net_dir);
            std::env::set_var(LOCK_DIR_ENV, lock_dir);
            Self {
                sys_net_prev,
                lock_prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            restore_env(SYS_NET_DIR_ENV, self.sys_net_prev.take());
            restore_env(LOCK_DIR_ENV, self.lock_prev.take());
        }
    }

    fn restore_env(key: &str, value: Option<OsString>) {
        if let Some(v) = value {
            std::env::set_var(key, v);
        } else {
            std::env::remove_var(key);
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
            did_resolver: crate::did::Resolver::new(Default::default()),
            vid_cache: crate::virtual_id_cache::VirtualIdCache::new(),
            discovery_config_dir: "/tmp/discovery-config".into(),
            discovery_state_dir: "/tmp/discovery-state".into(),
        })
    }

    fn seed_sys_net(tmp: &TempDir) {
        let eth0 = tmp.path().join("sys_net").join("eth0");
        let wlan0 = tmp.path().join("sys_net").join("wlan0");
        fs::create_dir_all(&eth0).expect("eth0 dir");
        fs::create_dir_all(&wlan0).expect("wlan0 dir");
        fs::write(eth0.join("operstate"), "down\n").expect("eth0 state");
        fs::write(wlan0.join("operstate"), "up\n").expect("wlan0 state");
    }

    #[tokio::test]
    async fn transport_list_route_returns_interfaces() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        seed_sys_net(&tmp);
        let lock_dir = tmp.path().join("cot");
        fs::create_dir_all(&lock_dir).expect("lock dir");
        let _env = EnvGuard::new(
            &tmp.path().join("sys_net").to_string_lossy(),
            &lock_dir.to_string_lossy(),
        );

        let Json(resp) = super::list(
            State(test_state()),
            Query(TransportQuery {
                node: Some("nodeA".into()),
            }),
        )
        .await
        .expect("list");

        assert!(!resp.interfaces.is_empty());
        assert_eq!(resp.node, "nodeA");
    }

    #[tokio::test]
    async fn transport_status_route_returns_lock_value() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        seed_sys_net(&tmp);
        let lock_dir = tmp.path().join("cot");
        fs::create_dir_all(&lock_dir).expect("lock dir");
        let _env = EnvGuard::new(
            &tmp.path().join("sys_net").to_string_lossy(),
            &lock_dir.to_string_lossy(),
        );
        fs::write(lock_dir.join("transport_lock_nodeA.txt"), "eth0\n").expect("write lock");

        let Json(resp) = super::status(
            State(test_state()),
            Query(TransportQuery {
                node: Some("nodeA".into()),
            }),
        )
        .await
        .expect("status");

        assert_eq!(resp.lock.as_deref(), Some("eth0"));
    }

    #[test]
    fn determine_active_prefers_locked_interface_when_available() {
        let interfaces = vec![
            TransportInterface {
                name: "eth0".to_string(),
                transport: "Ethernet".to_string(),
                priority: 10,
                status: "UP".to_string(),
                ip: Some("10.0.0.1".to_string()),
                available: true,
            },
            TransportInterface {
                name: "wlan0".to_string(),
                transport: "WiFi".to_string(),
                priority: 20,
                status: "UP".to_string(),
                ip: Some("192.168.1.2".to_string()),
                available: true,
            },
        ];

        let active = determine_active(&interfaces, Some("eth0"));
        assert_eq!(active.as_ref().map(|a| a.name.as_str()), Some("eth0"));
    }

    #[test]
    fn determine_active_falls_back_when_locked_interface_unavailable() {
        let interfaces = vec![
            TransportInterface {
                name: "eth0".to_string(),
                transport: "Ethernet".to_string(),
                priority: 10,
                status: "DOWN".to_string(),
                ip: None,
                available: false,
            },
            TransportInterface {
                name: "wlan0".to_string(),
                transport: "WiFi".to_string(),
                priority: 20,
                status: "UP".to_string(),
                ip: Some("192.168.1.2".to_string()),
                available: true,
            },
        ];

        let active = determine_active(&interfaces, Some("eth0"));
        assert_eq!(active.as_ref().map(|a| a.name.as_str()), Some("wlan0"));
    }

    #[tokio::test]
    async fn transport_lock_and_unlock_routes_update_lock_file() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        seed_sys_net(&tmp);
        let lock_dir = tmp.path().join("cot");
        fs::create_dir_all(&lock_dir).expect("lock dir");
        let _env = EnvGuard::new(
            &tmp.path().join("sys_net").to_string_lossy(),
            &lock_dir.to_string_lossy(),
        );

        let Json(lock_resp) = super::lock(
            State(test_state()),
            Json(TransportLockRequest {
                node: Some("nodeA".into()),
                interface_name: Some("eth0".into()),
            }),
        )
        .await
        .expect("lock");

        assert!(lock_resp.ok);
        assert_eq!(lock_resp.lock, "eth0");
        let lock_path = lock_dir.join("transport_lock_nodeA.txt");
        assert!(lock_path.exists());

        let Json(unlock_resp) = super::unlock(
            State(test_state()),
            Json(TransportUnlockRequest {
                node: Some("nodeA".into()),
            }),
        )
        .await
        .expect("unlock");

        assert!(unlock_resp.ok);
        assert!(unlock_resp.lock.is_none());
        assert!(!lock_path.exists());
    }
}
