// src/nebula/relay_registry.rs
// ============================================================
// Relay Registry
// Tracks dedicated relay-role nodes and their operational limits.
// ============================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RelayEntry {
    pub node_name: String,
    pub overlay_ip: String,
    pub physical_endpoint: String,
    pub is_active: bool,
    pub is_lighthouse: bool,
    pub max_peers: u32,
    pub max_bandwidth_mbps: u32, // 0 = unlimited
    pub last_seen: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RelayRegistry {
    pub circle_id: String,
    pub relays: HashMap<String, RelayEntry>,
}

impl RelayRegistry {
    pub fn new(circle_id: &str) -> Self {
        Self {
            circle_id: circle_id.to_string(),
            relays: HashMap::new(),
        }
    }

    pub fn add_relay(
        &mut self,
        node: &str,
        overlay: &str,
        endpoint: &str,
        max_peers: u32,
        max_bw: u32,
        is_lighthouse: bool,
    ) {
        let now = chrono::Utc::now().timestamp();
        self.relays.insert(
            node.to_string(),
            RelayEntry {
                node_name: node.to_string(),
                overlay_ip: overlay.to_string(),
                physical_endpoint: endpoint.to_string(),
                is_active: true,
                is_lighthouse,
                max_peers,
                max_bandwidth_mbps: max_bw,
                last_seen: now,
            },
        );
    }

    pub fn remove_relay(&mut self, node: &str) {
        self.relays.remove(node);
    }

    pub fn active_relays(&self) -> Vec<&RelayEntry> {
        self.relays.values().filter(|r| r.is_active).collect()
    }

    pub fn is_relay(&self, node: &str) -> bool {
        self.relays.contains_key(node)
    }

    pub fn mark_active(&mut self, node: &str) {
        if let Some(entry) = self.relays.get_mut(node) {
            entry.is_active = true;
            entry.last_seen = chrono::Utc::now().timestamp();
        }
    }

    pub fn mark_inactive(&mut self, node: &str) {
        if let Some(entry) = self.relays.get_mut(node) {
            entry.is_active = false;
        }
    }

    pub fn update_limits(&mut self, node: &str, max_peers: u32, max_bw: u32) -> bool {
        if let Some(entry) = self.relays.get_mut(node) {
            entry.max_peers = max_peers;
            entry.max_bandwidth_mbps = max_bw;
            return true;
        }
        false
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}", e))?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("{}", e))?;
        let tmp = format!("{}.tmp", path);
        fs::write(&tmp, json).map_err(|e| format!("{}", e))?;
        fs::rename(&tmp, path).map_err(|e| format!("{}", e))
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("{}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("{}", e))
    }

    pub fn load_or_create(path: &str, circle: &str) -> Self {
        if Path::new(path).exists() {
            match Self::load(path) {
                Ok(registry) => return registry,
                Err(e) => eprintln!("⚠️ Relay registry load failed: {}", e),
            }
        }
        Self::new(circle)
    }

    pub async fn health_check_all(&mut self, timeout_secs: u64) {
        let relay_nodes = self.relays.keys().cloned().collect::<Vec<_>>();
        for node in relay_nodes {
            let endpoint = self
                .relays
                .get(&node)
                .map(|r| r.physical_endpoint.clone())
                .unwrap_or_default();
            if endpoint.is_empty() {
                self.mark_inactive(&node);
                continue;
            }
            let tcp_ok = tokio::time::timeout(
                Duration::from_secs(timeout_secs),
                TcpStream::connect(&endpoint),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);

            // Probe overlay reachability explicitly through nebula0 to avoid
            // false positives from default-route ICMP behavior.
            let ping_ok = if !tcp_ok {
                let ip = self
                    .relays
                    .get(&node)
                    .map(|r| r.overlay_ip.clone())
                    .unwrap_or_default();

                if !ip.is_empty() {
                    std::process::Command::new("ping")
                        .args(["-c", "1", "-W", "1", "-I", "nebula0", &ip])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                false
            };

            let ok = tcp_ok || ping_ok;

            if ok {
                self.mark_active(&node);
            } else {
                self.mark_inactive(&node);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_relay() {
        let mut reg = RelayRegistry::new("alpha");
        reg.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242", 5, 10, false);
        assert!(reg.is_relay("nodeB"));
        assert_eq!(reg.active_relays().len(), 1);
    }

    #[test]
    fn test_remove_relay() {
        let mut reg = RelayRegistry::new("alpha");
        reg.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242", 5, 10, false);
        reg.remove_relay("nodeB");
        assert!(!reg.is_relay("nodeB"));
    }

    #[test]
    fn test_active_relays_filters_inactive() {
        let mut reg = RelayRegistry::new("alpha");
        reg.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242", 5, 10, false);
        reg.add_relay("nodeC", "192.168.100.3", "10.0.0.3:4242", 5, 10, false);
        reg.mark_inactive("nodeC");
        assert_eq!(reg.active_relays().len(), 1);
    }

    #[test]
    fn test_persist_and_load() {
        let mut reg = RelayRegistry::new("alpha");
        reg.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242", 5, 10, false);
        let tmp = "/tmp/test_relay_registry.json";
        reg.save(tmp).unwrap();
        let loaded = RelayRegistry::load(tmp).unwrap();
        assert!(loaded.is_relay("nodeB"));
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn test_lh_relay_dual_role() {
        let mut reg = RelayRegistry::new("alpha");
        reg.add_relay("nodeC", "192.168.100.3", "10.0.0.3:4242", 10, 0, true);
        assert!(reg.is_relay("nodeC"));
        let node = reg.relays.get("nodeC").unwrap();
        assert!(node.is_lighthouse);
        assert_eq!(node.max_bandwidth_mbps, 0);
    }
}
