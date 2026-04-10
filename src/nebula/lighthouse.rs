// src/nebula/lighthouse.rs
// ============================================================
// Nebula Lighthouse Registry
// Tracks lighthouse nodes and their physical endpoints.
// ============================================================

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseEntry {
    pub node_name: String,
    pub overlay_ip: String,
    /// Physical routable endpoint (for example: "192.168.0.142:4242")
    pub physical_endpoint: String,
    pub is_primary: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseRegistry {
    pub circle_id: String,
    pub lighthouses: Vec<LighthouseEntry>,
}

impl LighthouseRegistry {
    pub fn new(circle_id: &str, owner: &str, overlay_ip: &str, endpoint: &str) -> Self {
        Self {
            circle_id: circle_id.into(),
            lighthouses: vec![LighthouseEntry {
                node_name: owner.into(),
                overlay_ip: overlay_ip.into(),
                physical_endpoint: endpoint.into(),
                is_primary: true,
                is_active: true,
            }],
        }
    }

    pub fn add_secondary(&mut self, name: &str, overlay_ip: &str, endpoint: &str) {
        if self.lighthouses.iter().any(|l| l.node_name == name) {
            return;
        }
        self.lighthouses.push(LighthouseEntry {
            node_name: name.into(),
            overlay_ip: overlay_ip.into(),
            physical_endpoint: endpoint.into(),
            is_primary: false,
            is_active: true,
        });
    }

    pub fn add_lighthouse(&mut self, name: &str, overlay_ip: &str, endpoint: &str) {
        self.add_secondary(name, overlay_ip, endpoint);
    }

    pub fn primary(&self) -> Option<&LighthouseEntry> {
        self.lighthouses.iter().find(|l| l.is_primary)
    }

    pub fn active(&self) -> Vec<&LighthouseEntry> {
        self.lighthouses.iter().filter(|l| l.is_active).collect()
    }

    pub fn is_lighthouse(&self, name: &str) -> bool {
        self.lighthouses.iter().any(|l| l.node_name == name)
    }

    /// Overlay IPs of active lighthouses for nebula `lighthouse.hosts`.
    pub fn lighthouse_overlay_ips(&self) -> Vec<String> {
        self.active()
            .iter()
            .map(|l| l.overlay_ip.clone())
            .collect::<Vec<String>>()
    }

    /// Entries for static_host_map: (overlay_ip, physical_endpoint)
    pub fn static_host_map_entries(&self) -> Vec<(String, String)> {
        self.active()
            .iter()
            .map(|l| (l.overlay_ip.clone(), l.physical_endpoint.clone()))
            .collect::<Vec<(String, String)>>()
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
        let active = self.active();
        let endpoints = active
            .iter()
            .map(|l| format!("{}→{}", l.overlay_ip, l.physical_endpoint))
            .collect::<Vec<String>>()
            .join(", ");

        format!(
            "LH[{}]: primary={}, active={}/{}, endpoints=[{}]",
            self.circle_id,
            primary,
            active.len(),
            self.lighthouses.len(),
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
}
