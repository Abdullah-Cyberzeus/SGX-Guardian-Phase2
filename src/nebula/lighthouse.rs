// src/nebula/lighthouse.rs
// ============================================================
// Nebula Lighthouse Registry
// Tracks lighthouse nodes and their physical endpoints.
// ============================================================

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;

fn host_from_endpoint(endpoint: &str) -> Option<String> {
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .filter(|h| !h.is_empty())
}

async fn tcp_open(addr: &str, timeout_secs: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseEntry {
    pub node_name: String,
    pub overlay_ip: String,
    /// Physical routable endpoint (for example: "192.168.0.142:4242")
    pub physical_endpoint: String,
    pub is_primary: bool,
    pub is_active: bool,
    /// Explicit role flag to decouple relay and lighthouse behavior.
    #[serde(default = "default_true")]
    pub is_lighthouse: bool,
    /// Whether this node is allowed to act as a Nebula relay.
    #[serde(default = "default_true")]
    pub am_relay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseRegistry {
    pub circle_id: String,
    pub lighthouses: Vec<LighthouseEntry>,
}

impl LighthouseRegistry {
    fn reconcile_primary_lighthouse(&mut self) {
        // Keep a single primary lighthouse. If current primary is inactive or absent,
        // promote the first active lighthouse (stable lexical order).
        let current_primary_active = self
            .lighthouses
            .iter()
            .any(|l| l.is_primary && l.is_lighthouse && l.is_active);
        if current_primary_active {
            return;
        }

        for l in self.lighthouses.iter_mut() {
            l.is_primary = false;
        }

        let promote = self
            .lighthouses
            .iter()
            .filter(|l| l.is_lighthouse && l.is_active)
            .min_by(|a, b| a.node_name.cmp(&b.node_name))
            .map(|l| l.node_name.clone());

        if let Some(node) = promote {
            if let Some(entry) = self.lighthouses.iter_mut().find(|l| l.node_name == node) {
                entry.is_primary = true;
            }
        }
    }

    pub fn new(circle_id: &str, owner: &str, overlay_ip: &str, endpoint: &str) -> Self {
        Self {
            circle_id: circle_id.into(),
            lighthouses: vec![LighthouseEntry {
                node_name: owner.into(),
                overlay_ip: overlay_ip.into(),
                physical_endpoint: endpoint.into(),
                is_primary: true,
                is_active: true,
                is_lighthouse: true,
                am_relay: true,
            }],
        }
    }

    pub fn add_secondary(&mut self, name: &str, overlay_ip: &str, endpoint: &str) {
        if self
            .lighthouses
            .iter()
            .any(|l| l.node_name == name && l.is_lighthouse)
        {
            return;
        }

        if let Some(existing) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            existing.overlay_ip = overlay_ip.into();
            existing.physical_endpoint = endpoint.into();
            existing.is_lighthouse = true;
            existing.am_relay = true;
            existing.is_active = true;
            existing.is_primary = false;
            return;
        }

        self.lighthouses.push(LighthouseEntry {
            node_name: name.into(),
            overlay_ip: overlay_ip.into(),
            physical_endpoint: endpoint.into(),
            is_primary: false,
            is_active: true,
            is_lighthouse: true,
            am_relay: true,
        });
    }

    pub fn add_lighthouse(&mut self, name: &str, overlay_ip: &str, endpoint: &str) {
        self.add_secondary(name, overlay_ip, endpoint);
    }

    pub fn add_relay(&mut self, name: &str, overlay_ip: &str, endpoint: &str) {
        if let Some(existing) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            existing.overlay_ip = overlay_ip.into();
            existing.physical_endpoint = endpoint.into();
            existing.am_relay = true;
            existing.is_active = true;
            return;
        }

        self.lighthouses.push(LighthouseEntry {
            node_name: name.into(),
            overlay_ip: overlay_ip.into(),
            physical_endpoint: endpoint.into(),
            is_primary: false,
            is_active: true,
            is_lighthouse: false,
            am_relay: true,
        });
    }

    pub fn upsert_node(
        &mut self,
        name: &str,
        overlay_ip: &str,
        endpoint: &str,
        is_lighthouse: bool,
        am_relay: bool,
    ) {
        if let Some(existing) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            existing.overlay_ip = overlay_ip.into();
            existing.physical_endpoint = endpoint.into();
            existing.is_lighthouse = is_lighthouse;
            existing.am_relay = am_relay;
            existing.is_active = true;
            if !is_lighthouse {
                existing.is_primary = false;
            }
            return;
        }

        self.lighthouses.push(LighthouseEntry {
            node_name: name.into(),
            overlay_ip: overlay_ip.into(),
            physical_endpoint: endpoint.into(),
            is_primary: false,
            is_active: true,
            is_lighthouse,
            am_relay,
        });
    }

    /// Upsert endpoint metadata while preserving existing role flags.
    pub fn upsert_endpoint_only(&mut self, name: &str, overlay_ip: &str, endpoint: &str) -> bool {
        if let Some(existing) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            let changed =
                existing.overlay_ip != overlay_ip || existing.physical_endpoint != endpoint;
            existing.overlay_ip = overlay_ip.into();
            existing.physical_endpoint = endpoint.into();
            existing.is_active = true;
            return changed;
        }

        self.lighthouses.push(LighthouseEntry {
            node_name: name.into(),
            overlay_ip: overlay_ip.into(),
            physical_endpoint: endpoint.into(),
            is_primary: false,
            is_active: true,
            is_lighthouse: false,
            am_relay: false,
        });
        true
    }

    pub fn set_relay_role(&mut self, name: &str, am_relay: bool) -> bool {
        if let Some(l) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            l.am_relay = am_relay;
            return true;
        }
        false
    }

    pub fn set_lighthouse_role(&mut self, name: &str, is_lighthouse: bool) -> bool {
        if let Some(l) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            l.is_lighthouse = is_lighthouse;
            if is_lighthouse {
                l.is_active = true;
            } else {
                l.is_primary = false;
            }
            self.reconcile_primary_lighthouse();
            return true;
        }
        false
    }

    pub fn primary(&self) -> Option<&LighthouseEntry> {
        self.lighthouses
            .iter()
            .find(|l| l.is_primary && l.is_lighthouse)
    }

    /// Promote the given lighthouse node to primary.
    /// Returns true when primary assignment changed.
    pub fn set_primary_lighthouse(&mut self, name: &str) -> bool {
        let target_is_lighthouse = self
            .lighthouses
            .iter()
            .any(|l| l.node_name == name && l.is_lighthouse);
        if !target_is_lighthouse {
            return false;
        }

        let current = self
            .lighthouses
            .iter()
            .find(|l| l.is_primary && l.is_lighthouse)
            .map(|l| l.node_name.clone());
        if current.as_deref() == Some(name) {
            return false;
        }

        for entry in self.lighthouses.iter_mut().filter(|l| l.is_lighthouse) {
            entry.is_primary = entry.node_name == name;
        }
        true
    }

    pub fn active(&self) -> Vec<&LighthouseEntry> {
        self.lighthouses
            .iter()
            .filter(|l| l.is_active && l.is_lighthouse)
            .collect()
    }

    pub fn is_lighthouse(&self, name: &str) -> bool {
        self.lighthouses
            .iter()
            .any(|l| l.node_name == name && l.is_lighthouse)
    }

    pub fn is_relay(&self, name: &str) -> bool {
        self.lighthouses
            .iter()
            .any(|l| l.node_name == name && l.am_relay)
    }

    pub fn relay_role_for(&self, name: &str) -> Option<bool> {
        self.lighthouses
            .iter()
            .find(|l| l.node_name == name)
            .map(|l| l.am_relay)
    }

    pub fn active_relays(&self) -> Vec<&LighthouseEntry> {
        self.lighthouses
            .iter()
            .filter(|l| l.is_active && l.am_relay)
            .collect()
    }

    /// Overlay IPs of active lighthouses for nebula `lighthouse.hosts`.
    pub fn lighthouse_overlay_ips(&self) -> Vec<String> {
        self.active()
            .iter()
            .map(|l| l.overlay_ip.clone())
            .collect::<Vec<String>>()
    }

    /// Entries for static_host_map: (overlay_ip, physical_endpoint)
    /// Includes all active nodes we know endpoints for.
    pub fn static_host_map_entries(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();

        for entry in self.lighthouses.iter().filter(|l| l.is_active) {
            if out.iter().any(|(overlay, _)| overlay == &entry.overlay_ip) {
                continue;
            }
            out.push((entry.overlay_ip.clone(), entry.physical_endpoint.clone()));
        }

        out
    }

    pub fn primary_physical_endpoint(&self) -> Option<String> {
        self.primary().map(|p| p.physical_endpoint.clone())
    }

    pub fn update_endpoint(&mut self, name: &str, endpoint: &str) -> bool {
        if let Some(l) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            l.physical_endpoint = endpoint.into();
            return true;
        }
        false
    }

    pub fn mark_inactive(&mut self, name: &str) {
        if let Some(l) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            l.is_active = false;
        }
    }

    pub fn mark_active(&mut self, name: &str) {
        if let Some(l) = self.lighthouses.iter_mut().find(|l| l.node_name == name) {
            l.is_active = true;
        }
    }

    pub async fn health_check_all(&mut self, timeout_secs: u64, self_node_name: &str) {
        let nodes = self
            .lighthouses
            .iter()
            .filter(|l| l.is_lighthouse || l.am_relay)
            .map(|l| l.node_name.clone())
            .collect::<Vec<_>>();

        for node in nodes {
            // ✅ self always active
            if node == self_node_name {
                self.mark_active(&node);
                continue;
            }

            let (endpoint, overlay_ip) = self
                .lighthouses
                .iter()
                .find(|l| l.node_name == node)
                .map(|l| (l.physical_endpoint.clone(), l.overlay_ip.clone()))
                .unwrap_or_default();

            if endpoint.is_empty() {
                continue; // ❌ don't mark inactive
            }

            // Runtime lighthouse detection:
            // 1) overlay -> registry sync port
            // 2) LAN host (from physical_endpoint) -> registry sync port
            // 3) legacy direct endpoint probe
            let mut tcp_ok = false;
            let registry_port = crate::nebula::registry_sync::REGISTRY_SYNC_PORT;
            if !overlay_ip.is_empty() {
                let overlay_probe = format!("{}:{}", overlay_ip, registry_port);
                tcp_ok = tcp_open(&overlay_probe, timeout_secs).await;
            }
            if !tcp_ok {
                if let Some(host) = host_from_endpoint(&endpoint) {
                    let lan_probe = format!("{}:{}", host, registry_port);
                    tcp_ok = tcp_open(&lan_probe, timeout_secs).await;
                }
            }
            if !tcp_ok {
                tcp_ok = tcp_open(&endpoint, timeout_secs).await;
            }

            // Keep activity status in sync for lighthouse and relay-role nodes.
            if tcp_ok {
                self.mark_active(&node);
            } else {
                self.mark_inactive(&node);
            }
        }
        self.reconcile_primary_lighthouse();
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}", e))?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("{}", e))?;
        fs::write(path, json).map_err(|e| format!("{}", e))
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("{}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("{}", e))
    }
    pub fn mark_active_on_interaction(&mut self, node_name: &str) {
        if let Some(node) = self
            .lighthouses
            .iter_mut()
            .find(|n| n.node_name == node_name)
        {
            node.is_active = true;
        }
    }

    pub fn load_or_create(
        path: &str,
        circle_id: &str,
        owner: &str,
        overlay_ip: &str,
        endpoint: &str,
    ) -> Self {
        if Path::new(path).exists() {
            match Self::load(path) {
                Ok(registry) => {
                    println!(
                        "📡 Loaded lighthouse registry: {} entries",
                        registry.lighthouses.len()
                    );
                    return registry;
                }
                Err(e) => eprintln!("⚠️ LH registry load failed: {}", e),
            }
        }

        println!("📡 Created lighthouse registry (primary: {})", owner);
        Self::new(circle_id, owner, overlay_ip, endpoint)
    }

    pub fn summary(&self) -> String {
        let primary = self
            .primary()
            .map(|p| p.node_name.as_str())
            .unwrap_or("none");
        let active_lh = self.active();
        let active_relays = self.active_relays();
        let endpoints = active_lh
            .iter()
            .map(|l| format!("{}→{}", l.overlay_ip, l.physical_endpoint))
            .collect::<Vec<String>>()
            .join(", ");

        format!(
            "LH[{}]: primary={}, active={}/{}, relays={}/{}, endpoints=[{}]",
            self.circle_id,
            primary,
            active_lh.len(),
            self.lighthouses.iter().filter(|l| l.is_lighthouse).count(),
            active_relays.len(),
            self.lighthouses.iter().filter(|l| l.am_relay).count(),
            endpoints
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_has_primary_with_physical_endpoint() {
        let r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "192.168.0.142:4242");
        assert!(r.primary().unwrap().is_primary);
        assert_eq!(r.primary().unwrap().physical_endpoint, "192.168.0.142:4242");
    }

    #[test]
    fn test_add_secondary_no_duplicate() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        r.add_secondary("nodeD", "192.168.100.4", "10.0.0.5:4242");
        r.add_secondary("nodeD", "192.168.100.4", "different:4242");
        assert_eq!(r.lighthouses.len(), 2);
    }

    #[test]
    fn test_static_host_map_entries_have_real_ips() {
        let mut r =
            LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "192.168.0.142:4242");
        r.add_secondary("nodeD", "192.168.100.4", "10.0.0.5:4242");
        let entries = r.static_host_map_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1, "192.168.0.142:4242");
        assert!(!entries[0].1.contains("LIGHTHOUSE_PUBLIC_IP"));
    }

    #[test]
    fn test_is_lighthouse() {
        let r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        assert!(r.is_lighthouse("nodeA"));
        assert!(!r.is_lighthouse("nodeB"));
    }

    #[test]
    fn test_lighthouse_overlay_ips() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10:4242");
        r.add_secondary("nodeD", "192.168.100.4", "11:4242");
        assert_eq!(r.lighthouse_overlay_ips().len(), 2);
    }

    #[test]
    fn test_mark_inactive_then_active() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10:4242");
        r.add_secondary("nodeD", "192.168.100.4", "11:4242");
        r.mark_inactive("nodeD");
        assert_eq!(r.active().len(), 1);
        r.mark_active("nodeD");
        assert_eq!(r.active().len(), 2);
    }

    #[test]
    fn test_update_endpoint() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "old:4242");
        assert!(r.update_endpoint("nodeA", "new:4242"));
        assert_eq!(r.primary().unwrap().physical_endpoint, "new:4242");
    }

    #[test]
    fn test_save_load_roundtrip() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        r.add_secondary("nodeD", "192.168.100.4", "10.0.0.5:4242");
        let tmp = "/tmp/test_lh_registry.json";
        r.save(tmp).unwrap();
        let loaded = LighthouseRegistry::load(tmp).unwrap();
        assert_eq!(loaded.lighthouses.len(), 2);
        assert_eq!(loaded.primary().unwrap().physical_endpoint, "10.0.0.1:4242");
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn test_primary_physical_endpoint() {
        let r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "192.168.0.142:4242");
        assert_eq!(
            r.primary_physical_endpoint(),
            Some("192.168.0.142:4242".to_string())
        );
    }

    #[test]
    fn test_summary() {
        let r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "192.168.0.142:4242");
        let s = r.summary();
        assert!(s.contains("nodeA"));
        assert!(s.contains("192.168.0.142:4242"));
    }

    #[test]
    fn test_add_relay_only_node() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        assert!(r.set_relay_role("nodeA", false));
        r.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242");

        assert!(r.is_relay("nodeB"));
        assert!(!r.is_lighthouse("nodeB"));
        assert_eq!(r.active().len(), 1);
        assert_eq!(r.active_relays().len(), 1);
    }

    #[test]
    fn test_static_host_map_entries_include_relay_only_node() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        assert!(r.set_relay_role("nodeA", false));
        r.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242");

        let entries = r.static_host_map_entries();

        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|(overlay, endpoint)| overlay == "192.168.100.2" && endpoint == "10.0.0.2:4242"));
    }

    #[test]
    fn test_static_host_map_entries_include_member_nodes() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        r.upsert_node("nodeC", "192.168.100.3", "10.0.0.3:4242", false, false);
        let entries = r.static_host_map_entries();
        assert!(entries
            .iter()
            .any(|(overlay, _)| overlay == "192.168.100.3"));
    }

    #[test]
    fn test_upsert_endpoint_only_preserves_roles() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        r.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242");
        assert!(r.upsert_endpoint_only("nodeB", "192.168.100.2", "10.0.0.99:4242"));

        let node_b = r
            .lighthouses
            .iter()
            .find(|e| e.node_name == "nodeB")
            .unwrap();
        assert!(node_b.am_relay);
        assert!(!node_b.is_lighthouse);
        assert_eq!(node_b.physical_endpoint, "10.0.0.99:4242");
    }

    #[test]
    fn test_set_lighthouse_role_reconciles_primary() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        r.add_secondary("nodeB", "192.168.100.2", "10.0.0.2:4242");
        assert!(r.set_lighthouse_role("nodeA", false));
        let primary = r.primary().map(|p| p.node_name.clone());
        assert_eq!(primary.as_deref(), Some("nodeB"));
    }

    #[test]
    fn test_set_primary_lighthouse_promotes_secondary() {
        let mut r = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        r.add_secondary("nodeB", "192.168.100.2", "10.0.0.2:4242");
        assert!(r.set_primary_lighthouse("nodeB"));
        assert_eq!(r.primary().map(|p| p.node_name.as_str()), Some("nodeB"));
        assert!(!r.set_primary_lighthouse("nodeB"));
    }
}
