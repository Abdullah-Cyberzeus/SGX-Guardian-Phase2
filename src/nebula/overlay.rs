// src/nebula/overlay.rs
// ============================================================
// Nebula Overlay IP Pool Manager
//
// Manages virtual IP address allocation for the Nebula overlay
// network. Each Circle gets a /24 subnet. Circle owner is .1.
// Allocations persist to overlay_pool.json.
// ============================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Represents one Circle's overlay IP pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayPool {
    /// Circle identifier (e.g., "guardian-circle-alpha")
    pub circle_id: String,
    /// Subnet base (e.g., "192.168.100")
    pub subnet_base: String,
    /// CIDR mask (always 24 for now)
    pub cidr: u8,
    /// Next host octet to assign (starts at 2, since .1 = owner)
    pub next_host: u8,
    /// Map of node_name → assigned overlay IP string
    pub allocations: HashMap<String, String>,
    /// The node_name of the Circle owner (gets .1)
    pub owner_node: String,
}

impl OverlayPool {
    /// Create a new pool for a Circle.
    /// Owner node automatically gets .1.
    pub fn new(circle_id: &str, subnet_base: &str, owner_node: &str) -> Self {
        let mut allocations = HashMap::new();
        let owner_ip = format!("{}.1", subnet_base);
        allocations.insert(owner_node.to_string(), owner_ip);

        Self {
            circle_id: circle_id.to_string(),
            subnet_base: subnet_base.to_string(),
            cidr: 24,
            next_host: 2,
            allocations,
            owner_node: owner_node.to_string(),
        }
    }

    /// Allocate an overlay IP for a member node.
    /// Returns the allocated IP (without CIDR suffix).
    /// Returns existing allocation if node already has one — idempotent.
    pub fn allocate(&mut self, node_name: &str) -> Result<String, String> {
        if let Some(existing) = self.allocations.get(node_name) {
            return Ok(existing.clone());
        }
        if self.next_host > 254 {
            return Err(format!(
                "Overlay pool exhausted for circle {}",
                self.circle_id
            ));
        }
        let ip = format!("{}.{}", self.subnet_base, self.next_host);
        self.allocations.insert(node_name.to_string(), ip.clone());
        self.next_host += 1;
        Ok(ip)
    }

    /// Get the overlay IP for a node (if allocated).
    pub fn get_ip(&self, node_name: &str) -> Option<&String> {
        self.allocations.get(node_name)
    }

    /// Get the overlay IP with CIDR suffix (e.g., "192.168.100.1/24").
    pub fn get_ip_cidr(&self, node_name: &str) -> Option<String> {
        self.allocations
            .get(node_name)
            .map(|ip| format!("{}/{}", ip, self.cidr))
    }

    /// Deallocate a member's IP. Owner cannot be deallocated.
    pub fn deallocate(&mut self, node_name: &str) -> bool {
        if node_name == self.owner_node {
            return false;
        }
        self.allocations.remove(node_name).is_some()
    }

    /// Get subnet string (e.g., "192.168.100.0/24").
    pub fn subnet(&self) -> String {
        format!("{}.0/{}", self.subnet_base, self.cidr)
    }

    /// Total allocated IPs.
    pub fn allocated_count(&self) -> usize {
        self.allocations.len()
    }

    /// Validate an IP belongs to this pool's subnet.
    pub fn is_valid_overlay_ip(&self, ip: &str) -> bool {
        ip.starts_with(&format!("{}.", self.subnet_base))
    }

    /// Save pool state to disk (JSON).
    pub fn save(&self, path: &str) -> Result<(), String> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Dir create: {}", e))?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("Serialize: {}", e))?;
        fs::write(path, json).map_err(|e| format!("Write: {}", e))
    }

    /// Load pool state from disk.
    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("Read: {}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("Parse: {}", e))
    }

    /// Load existing pool or create new one.
    pub fn load_or_create(
        path: &str,
        circle_id: &str,
        subnet_base: &str,
        owner_node: &str,
    ) -> Self {
        if Path::new(path).exists() {
            match Self::load(path) {
                Ok(pool) => {
                    println!(
                        "📋 Loaded existing overlay pool: {} allocations",
                        pool.allocated_count()
                    );
                    return pool;
                }
                Err(e) => {
                    eprintln!("⚠️ Failed to load overlay pool ({}), creating new", e);
                }
            }
        }
        let pool = Self::new(circle_id, subnet_base, owner_node);
        println!("📋 Created new overlay pool for {}", circle_id);
        pool
    }

    /// Summary string for logging.
    pub fn summary(&self) -> String {
        format!(
            "OverlayPool[{}]: subnet={}, allocated={}, next=.{}",
            self.circle_id,
            self.subnet(),
            self.allocated_count(),
            self.next_host
        )
    }
}

// ── Unit Tests ──────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owner_gets_dot_1() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        assert_eq!(pool.get_ip("nodeA"), Some(&"192.168.100.1".to_string()));
        assert_eq!(pool.next_host, 2);
    }

    #[test]
    fn test_allocate_increments() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        assert_eq!(pool.allocate("nodeB").unwrap(), "192.168.100.2");
        assert_eq!(pool.allocate("nodeC").unwrap(), "192.168.100.3");
        assert_eq!(pool.next_host, 4);
    }

    #[test]
    fn test_allocate_idempotent() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        let ip1 = pool.allocate("nodeB").unwrap();
        let ip2 = pool.allocate("nodeB").unwrap();
        assert_eq!(ip1, ip2);
        assert_eq!(pool.next_host, 3); // Only incremented once
    }

    #[test]
    fn test_owner_cannot_be_deallocated() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        assert!(!pool.deallocate("nodeA"));
        assert!(pool.get_ip("nodeA").is_some());
    }

    #[test]
    fn test_member_can_be_deallocated() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        pool.allocate("nodeB").unwrap();
        assert!(pool.deallocate("nodeB"));
        assert!(pool.get_ip("nodeB").is_none());
    }

    #[test]
    fn test_get_ip_cidr() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        assert_eq!(
            pool.get_ip_cidr("nodeA"),
            Some("192.168.100.1/24".to_string())
        );
    }

    #[test]
    fn test_subnet_string() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        assert_eq!(pool.subnet(), "192.168.100.0/24");
    }

    #[test]
    fn test_valid_overlay_ip() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        assert!(pool.is_valid_overlay_ip("192.168.100.5"));
        assert!(!pool.is_valid_overlay_ip("10.0.0.1"));
    }

    #[test]
    fn test_pool_exhaustion() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        pool.next_host = 255;
        assert!(pool.allocate("nodeX").is_err());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        pool.allocate("nodeB").unwrap();
        pool.allocate("nodeC").unwrap();

        let tmp = "/tmp/test_overlay_pool_d1.json";
        pool.save(tmp).unwrap();
        let loaded = OverlayPool::load(tmp).unwrap();

        assert_eq!(loaded.get_ip("nodeA"), Some(&"192.168.100.1".to_string()));
        assert_eq!(loaded.get_ip("nodeB"), Some(&"192.168.100.2".to_string()));
        assert_eq!(loaded.get_ip("nodeC"), Some(&"192.168.100.3".to_string()));
        assert_eq!(loaded.next_host, 4);

        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn test_summary_contains_circle() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        let s = pool.summary();
        assert!(s.contains("alpha"));
        assert!(s.contains("192.168.100.0/24"));
    }
}
