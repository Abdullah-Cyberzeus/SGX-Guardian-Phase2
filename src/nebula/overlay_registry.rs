// src/nebula/overlay_registry.rs
// ============================================================
// Nebula Overlay IP Registry — Multi-Node, Multi-PC
//
// Problem: OverlayPool state used to be saved on only one PC.
// If nodeA ran on PC1 and later on PC2, the .1 IP
// could be assigned again, causing an IP conflict.
//
// This file maintains a JSON-based registry where:
//   - Each node name is permanently mapped to an overlay IP
//   - The circle owner (nodeA) always receives .1
//   - An atomic counter tracks the next available IP
//   - File locking keeps concurrent writes safe
//
// SYNC STRATEGY:
//   - nodeA (CA) stores its registry in /var/lib/sgx-guardian/nebula/
//   - Member nodes also register their IP during certificate requests
//   - nodeA's registry is the source of truth and performs IP assignment
//   - Member nodes cache their assigned IP locally
// ============================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const REGISTRY_SUBNET_BASE: &str = "192.168.100";
pub const REGISTRY_CIDR: u8 = 24;
pub const REGISTRY_OWNER_HOST: u8 = 1; // Circle owner always uses .1
pub const REGISTRY_START_HOST: u8 = 2; // Members start from .2
pub const REGISTRY_MAX_HOST: u8 = 254; // Maximum .254

/// Permanent IP allocation record for one node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIpRecord {
    /// Node name (e.g., "nodeA", "nodeB")
    pub node_name: String,
    /// Assigned overlay IP without CIDR (e.g., "192.168.100.1")
    pub overlay_ip: String,
    /// Overlay IP with CIDR (e.g., "192.168.100.1/24")
    pub overlay_ip_cidr: String,
    /// Is this the Circle owner/CA?
    pub is_owner: bool,
    /// When this record was created (ISO 8601)
    pub allocated_at: String,
    /// Public key fingerprint for verification (optional)
    pub pubkey_prefix: Option<String>,
}

/// The master IP registry for a Circle.
/// Saved to disk as JSON. Master copy lives on nodeA (CA).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayRegistry {
    /// Circle identifier
    pub circle_id: String,
    /// Subnet base (e.g., "192.168.100")
    pub subnet_base: String,
    /// CIDR mask
    pub cidr: u8,
    /// Name of the Circle owner node
    pub owner_node: String,
    /// Next host octet to assign (starts at 2)
    pub next_host: u8,
    /// node_name → IpRecord (permanent mapping)
    pub allocations: HashMap<String, NodeIpRecord>,
    /// Schema version for future migration
    pub schema_version: u8,
    /// Last modified timestamp
    pub last_modified: String,
}

impl OverlayRegistry {
    /// Create a new empty registry.
    /// Owner node is immediately registered with .1 IP.
    pub fn new(circle_id: &str, subnet_base: &str, owner_node: &str) -> Self {
        let mut reg = Self {
            circle_id: circle_id.to_string(),
            subnet_base: subnet_base.to_string(),
            cidr: REGISTRY_CIDR,
            owner_node: owner_node.to_string(),
            next_host: REGISTRY_START_HOST,
            allocations: HashMap::new(),
            schema_version: 1,
            last_modified: Self::now_iso(),
        };

        // Owner always gets .1 — this is immutable
        let owner_ip = format!("{}.{}", subnet_base, REGISTRY_OWNER_HOST);
        reg.allocations.insert(
            owner_node.to_string(),
            NodeIpRecord {
                node_name: owner_node.to_string(),
                overlay_ip: owner_ip.clone(),
                overlay_ip_cidr: format!("{}/{}", owner_ip, REGISTRY_CIDR),
                is_owner: true,
                allocated_at: Self::now_iso(),
                pubkey_prefix: None,
            },
        );

        reg
    }

    /// Load registry from disk, or create new one if not found.
    /// This is the main entry point — always use this.
    pub fn load_or_create(
        path: &str,
        circle_id: &str,
        subnet_base: &str,
        owner_node: &str,
    ) -> Self {
        if Path::new(path).exists() {
            match Self::load(path) {
                Ok(reg) => {
                    println!(
                        "📋 Loaded overlay registry: {} nodes allocated (circle: {})",
                        reg.allocations.len(),
                        reg.circle_id
                    );
                    return reg;
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to load overlay registry ({}), creating new", e);
                }
            }
        }

        let reg = Self::new(circle_id, subnet_base, owner_node);
        println!(
            "📋 Created new overlay registry for circle: {} (owner: {} → {}.{})",
            circle_id, owner_node, subnet_base, REGISTRY_OWNER_HOST
        );
        reg
    }

    /// Assign or retrieve an IP for a node.
    ///
    /// IDEMPOTENT: If node already has an IP, returns existing one.
    /// No duplicate assignments, no IP conflicts.
    /// Owner always gets .1 regardless of call order.
    pub fn assign_ip(&mut self, node_name: &str) -> Result<String, String> {
        // Already allocated — return existing (idempotent)
        if let Some(record) = self.allocations.get(node_name) {
            println!(
                "✅ IP for {} already allocated: {} (reusing)",
                node_name, record.overlay_ip_cidr
            );
            return Ok(record.overlay_ip_cidr.clone());
        }

        // Safety check for owner (should never happen but guard it)
        if node_name == self.owner_node {
            return Err(format!(
                "Owner {} missing from registry — this is a bug",
                node_name
            ));
        }

        // Find next available host octet
        let host = self.find_next_available_host()?;
        let ip = format!("{}.{}", self.subnet_base, host);
        let ip_cidr = format!("{}/{}", ip, self.cidr);

        self.allocations.insert(
            node_name.to_string(),
            NodeIpRecord {
                node_name: node_name.to_string(),
                overlay_ip: ip.clone(),
                overlay_ip_cidr: ip_cidr.clone(),
                is_owner: false,
                allocated_at: Self::now_iso(),
                pubkey_prefix: None,
            },
        );

        self.next_host = host + 1;
        self.last_modified = Self::now_iso();

        println!(
            "🌐 IP assigned: {} → {} (circle: {})",
            node_name, ip_cidr, self.circle_id
        );

        Ok(ip_cidr)
    }

    /// Set a specific IP/CIDR for a node (authoritative sync path).
    /// Used when CA must honor an already-assigned overlay IP from registry sync.
    pub fn set_ip(&mut self, node_name: &str, ip_cidr: &str) -> Result<(), String> {
        let (ip, cidr_s) = ip_cidr
            .split_once('/')
            .ok_or_else(|| format!("Invalid CIDR format: {}", ip_cidr))?;
        let cidr: u8 = cidr_s
            .parse::<u8>()
            .map_err(|_| format!("Invalid CIDR mask in {}", ip_cidr))?;

        if cidr != self.cidr {
            return Err(format!(
                "CIDR mismatch for {}: got /{}, expected /{}",
                node_name, cidr, self.cidr
            ));
        }

        if !ip.starts_with(&format!("{}.", self.subnet_base)) {
            return Err(format!(
                "IP {} is outside subnet base {}",
                ip, self.subnet_base
            ));
        }

        let host = ip
            .split('.')
            .next_back()
            .and_then(|s| s.parse::<u8>().ok())
            .ok_or_else(|| format!("Invalid host octet in {}", ip))?;

        if !(REGISTRY_OWNER_HOST..=REGISTRY_MAX_HOST).contains(&host) {
            return Err(format!(
                "Host octet {} out of range (.{}-.{})",
                host, REGISTRY_OWNER_HOST, REGISTRY_MAX_HOST
            ));
        }

        if node_name == self.owner_node && host != REGISTRY_OWNER_HOST {
            return Err(format!(
                "Owner {} must keep .{} (got .{})",
                node_name, REGISTRY_OWNER_HOST, host
            ));
        }

        if let Some(conflict) = self
            .allocations
            .iter()
            .find(|(name, rec)| name.as_str() != node_name && rec.overlay_ip == ip)
            .map(|(name, _)| name.clone())
        {
            return Err(format!(
                "IP conflict: {} already allocated to {}",
                ip, conflict
            ));
        }

        let existing_pubkey = self
            .allocations
            .get(node_name)
            .and_then(|r| r.pubkey_prefix.clone());

        self.allocations.insert(
            node_name.to_string(),
            NodeIpRecord {
                node_name: node_name.to_string(),
                overlay_ip: ip.to_string(),
                overlay_ip_cidr: ip_cidr.to_string(),
                is_owner: node_name == self.owner_node,
                allocated_at: Self::now_iso(),
                pubkey_prefix: existing_pubkey,
            },
        );

        if self.next_host <= host {
            self.next_host = host.saturating_add(1);
        }
        self.next_host = self.next_host.max(REGISTRY_START_HOST);
        self.last_modified = Self::now_iso();
        Ok(())
    }

    /// Total allocated nodes in registry.
    pub fn allocated_count(&self) -> usize {
        self.allocations.len()
    }

    /// Get the assigned IP (with CIDR) for a node.
    /// Returns None if not yet allocated.
    pub fn get_ip_cidr(&self, node_name: &str) -> Option<&str> {
        self.allocations
            .get(node_name)
            .map(|r| r.overlay_ip_cidr.as_str())
    }

    /// Get the assigned IP (without CIDR) for a node.
    pub fn get_ip(&self, node_name: &str) -> Option<&str> {
        self.allocations
            .get(node_name)
            .map(|r| r.overlay_ip.as_str())
    }

    /// Check if a node has been allocated an IP.
    pub fn is_allocated(&self, node_name: &str) -> bool {
        self.allocations.contains_key(node_name)
    }

    /// Update the public key prefix for a node (for verification).
    pub fn set_pubkey_prefix(&mut self, node_name: &str, prefix: &str) {
        if let Some(record) = self.allocations.get_mut(node_name) {
            record.pubkey_prefix = Some(prefix.to_string());
            self.last_modified = Self::now_iso();
        }
    }

    /// Remove a node's IP allocation (for decommissioning).
    /// Owner cannot be removed.
    pub fn remove_node(&mut self, node_name: &str) -> bool {
        if node_name == self.owner_node {
            eprintln!("⚠️  Cannot remove owner node from registry");
            return false;
        }
        let removed = self.allocations.remove(node_name).is_some();
        if removed {
            self.last_modified = Self::now_iso();
            println!("🗑️  Removed {} from overlay registry", node_name);
        }
        removed
    }

    /// Save registry to disk as JSON.
    /// This is the source of truth — call after every allocation.
    pub fn save(&self, path: &str) -> Result<(), String> {
        // Create parent directories
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Cannot create dir: {}", e))?;
        }

        // Write to temp file first, then atomic rename (prevents corruption)
        let tmp_path = format!("{}.tmp", path);
        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("Serialize error: {}", e))?;

        fs::write(&tmp_path, &json).map_err(|e| format!("Write error: {}", e))?;

        fs::rename(&tmp_path, path).map_err(|e| format!("Rename error: {}", e))?;

        Ok(())
    }

    /// Load registry from disk.
    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("Read error: {}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("Parse error: {}", e))
    }

    /// All allocated nodes as a sorted list.
    pub fn all_nodes(&self) -> Vec<&NodeIpRecord> {
        let mut nodes: Vec<&NodeIpRecord> = self.allocations.values().collect();
        // Sort: owner first, then by IP
        nodes.sort_by(|a, b| {
            if a.is_owner {
                std::cmp::Ordering::Less
            } else if b.is_owner {
                std::cmp::Ordering::Greater
            } else {
                a.overlay_ip.cmp(&b.overlay_ip)
            }
        });
        nodes
    }

    /// Summary string for logging.
    pub fn summary(&self) -> String {
        format!(
            "OverlayRegistry[{}]: {}/{} — {} nodes, next_host=.{}",
            self.circle_id,
            self.subnet_base,
            self.cidr,
            self.allocations.len(),
            self.next_host
        )
    }

    /// Print all allocations as a table.
    pub fn print_table(&self) {
        println!("─────────────────────────────────────────────────");
        println!(
            "  Circle: {}  |  Subnet: {}.0/{}",
            self.circle_id, self.subnet_base, self.cidr
        );
        println!("─────────────────────────────────────────────────");
        println!("  {:<12}  {:<20}  Role", "Node", "Overlay IP");
        println!("─────────────────────────────────────────────────");
        for record in self.all_nodes() {
            let role = if record.is_owner {
                "CA / Lighthouse"
            } else {
                "Member"
            };
            println!(
                "  {:<12}  {:<20}  {}",
                record.node_name, record.overlay_ip_cidr, role
            );
        }
        println!("─────────────────────────────────────────────────");
    }

    // ── Internal helpers ──────────────────────────────────────

    /// Find the next host octet that is not already in use.
    /// Scans existing allocations to avoid conflicts even if
    /// next_host counter drifted (e.g., after file merge).
    fn find_next_available_host(&self) -> Result<u8, String> {
        // Collect all used octets
        let used: std::collections::HashSet<u8> = self
            .allocations
            .values()
            .filter_map(|r| {
                r.overlay_ip
                    .split('.')
                    .next_back()
                    .and_then(|s| s.parse::<u8>().ok())
            })
            .collect();

        // Start from next_host counter, scan forward to find unused
        let mut candidate = self.next_host.max(REGISTRY_START_HOST);
        loop {
            if candidate > REGISTRY_MAX_HOST {
                return Err(format!(
                    "Overlay pool exhausted for circle {} (all .2–.254 allocated)",
                    self.circle_id
                ));
            }
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
            candidate += 1;
        }
    }

    fn now_iso() -> String {
        // Use chrono if available, else a simple fallback
        chrono::Utc::now().to_rfc3339()
    }
}

// ── Compat bridge: convert OverlayRegistry → OverlayPool ─────
// This bridge exists because main.rs still uses OverlayPool.
// Building a pool from the registry is straightforward.
impl From<&OverlayRegistry> for crate::nebula::overlay::OverlayPool {
    fn from(reg: &OverlayRegistry) -> Self {
        let mut pool = crate::nebula::overlay::OverlayPool::new(
            &reg.circle_id,
            &reg.subnet_base,
            &reg.owner_node,
        );
        // Sync all allocations into pool
        for record in reg.allocations.values() {
            pool.allocations
                .insert(record.node_name.clone(), record.overlay_ip.clone());
        }
        pool.next_host = reg.next_host;
        pool
    }
}

// ── Unit Tests ────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> OverlayRegistry {
        OverlayRegistry::new("alpha", "192.168.100", "nodeA")
    }

    #[test]
    fn test_owner_gets_dot1() {
        let reg = make_registry();
        assert_eq!(reg.get_ip("nodeA"), Some("192.168.100.1"));
        assert_eq!(reg.get_ip_cidr("nodeA"), Some("192.168.100.1/24"));
    }

    #[test]
    fn test_member_gets_sequential_ip() {
        let mut reg = make_registry();
        let ip_b = reg.assign_ip("nodeB").unwrap();
        let ip_c = reg.assign_ip("nodeC").unwrap();
        assert_eq!(ip_b, "192.168.100.2/24");
        assert_eq!(ip_c, "192.168.100.3/24");
    }

    #[test]
    fn test_idempotent_assignment() {
        let mut reg = make_registry();
        let ip1 = reg.assign_ip("nodeB").unwrap();
        let ip2 = reg.assign_ip("nodeB").unwrap();
        assert_eq!(ip1, ip2);
        assert_eq!(reg.allocations.len(), 2); // nodeA + nodeB only
    }

    #[test]
    fn test_authoritative_assignment_rejects_duplicate_ip_for_different_node() {
        let mut reg = make_registry();
        reg.set_ip("nodeB", "192.168.100.2/24").unwrap();
        let err = reg.set_ip("nodeC", "192.168.100.2/24").unwrap_err();
        assert!(err.contains("IP conflict"));
        assert_eq!(reg.get_ip("nodeB"), Some("192.168.100.2"));
        assert!(!reg.is_allocated("nodeC"));
    }

    #[test]
    fn test_authoritative_assignment_rejects_invalid_network_values() {
        let mut reg = make_registry();
        for invalid in [
            "192.168.101.2/24",
            "192.168.100.2/16",
            "192.168.100.0/24",
            "192.168.100.255/24",
            "not-an-ip/24",
            "192.168.100.2",
        ] {
            assert!(reg.set_ip("nodeB", invalid).is_err(), "{invalid}");
        }
        assert!(!reg.is_allocated("nodeB"));
    }

    #[test]
    fn test_owner_ip_is_immutable_on_authoritative_sync() {
        let mut reg = make_registry();
        assert!(reg.set_ip("nodeA", "192.168.100.2/24").is_err());
        assert_eq!(reg.get_ip_cidr("nodeA"), Some("192.168.100.1/24"));
    }

    #[test]
    fn test_corrupted_registry_fails_to_load_without_creating_allocations() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("broken.json");
        fs::write(&path, "not-json").unwrap();
        assert!(OverlayRegistry::load(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn test_no_ip_conflict_after_reload() {
        let mut reg = make_registry();
        reg.assign_ip("nodeB").unwrap();
        reg.assign_ip("nodeC").unwrap();

        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp = tmp_dir.path().join("registry.json");
        reg.save(tmp.to_str().unwrap()).unwrap();

        let mut reg2 = OverlayRegistry::load(tmp.to_str().unwrap()).unwrap();
        let ip_d = reg2.assign_ip("nodeD").unwrap();
        assert_eq!(ip_d, "192.168.100.4/24"); // .2 and .3 already taken
    }

    #[test]
    fn test_owner_cannot_be_removed() {
        let mut reg = make_registry();
        assert!(!reg.remove_node("nodeA"));
        assert!(reg.is_allocated("nodeA")); // still there
    }

    #[test]
    fn test_member_can_be_removed() {
        let mut reg = make_registry();
        reg.assign_ip("nodeB").unwrap();
        assert!(reg.remove_node("nodeB"));
        assert!(!reg.is_allocated("nodeB"));
    }

    #[test]
    fn test_find_next_host_skips_gaps() {
        let mut reg = make_registry();
        // Manually inject a record at .2 and .4 to create gap
        reg.allocations.insert(
            "nodeX".to_string(),
            NodeIpRecord {
                node_name: "nodeX".to_string(),
                overlay_ip: "192.168.100.2".to_string(),
                overlay_ip_cidr: "192.168.100.2/24".to_string(),
                is_owner: false,
                allocated_at: "".to_string(),
                pubkey_prefix: None,
            },
        );
        reg.allocations.insert(
            "nodeY".to_string(),
            NodeIpRecord {
                node_name: "nodeY".to_string(),
                overlay_ip: "192.168.100.4".to_string(),
                overlay_ip_cidr: "192.168.100.4/24".to_string(),
                is_owner: false,
                allocated_at: "".to_string(),
                pubkey_prefix: None,
            },
        );
        reg.next_host = 2; // Counter behind actual state

        // .2 taken, .3 free — should get .3
        let ip = reg.assign_ip("nodeNew").unwrap();
        assert_eq!(ip, "192.168.100.3/24");
    }

    #[test]
    fn test_save_load_roundtrip() {
        let mut reg = make_registry();
        reg.assign_ip("nodeB").unwrap();
        reg.assign_ip("nodeC").unwrap();

        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp = tmp_dir.path().join("registry.json");
        reg.save(tmp.to_str().unwrap()).unwrap();

        let loaded = OverlayRegistry::load(tmp.to_str().unwrap()).unwrap();
        assert_eq!(loaded.get_ip("nodeA"), Some("192.168.100.1"));
        assert_eq!(loaded.get_ip("nodeB"), Some("192.168.100.2"));
        assert_eq!(loaded.get_ip("nodeC"), Some("192.168.100.3"));
        assert_eq!(loaded.next_host, 4);
    }

    #[test]
    fn test_pool_exhaustion() {
        let mut reg = make_registry();
        reg.next_host = 255;
        // Manually fill all slots
        for i in 2..=254u8 {
            reg.allocations.insert(
                format!("node{}", i),
                NodeIpRecord {
                    node_name: format!("node{}", i),
                    overlay_ip: format!("192.168.100.{}", i),
                    overlay_ip_cidr: format!("192.168.100.{}/24", i),
                    is_owner: false,
                    allocated_at: "".to_string(),
                    pubkey_prefix: None,
                },
            );
        }
        assert!(reg.assign_ip("nodeOverflow").is_err());
    }

    // ── set_ip: conflict resolution / validation branches ────────

    #[test]
    fn test_set_ip_assigns_new_member_within_range() {
        let mut reg = make_registry();
        reg.set_ip("nodeB", "192.168.100.5/24").unwrap();
        assert_eq!(reg.get_ip_cidr("nodeB"), Some("192.168.100.5/24"));
        assert_eq!(reg.next_host, 6);
        assert!(!reg.allocations.get("nodeB").unwrap().is_owner);
    }

    #[test]
    fn test_set_ip_rejects_missing_slash() {
        let mut reg = make_registry();
        let err = reg.set_ip("nodeB", "192.168.100.5").unwrap_err();
        assert!(err.contains("Invalid CIDR format"));
    }

    #[test]
    fn test_set_ip_rejects_non_numeric_cidr_mask() {
        let mut reg = make_registry();
        let err = reg.set_ip("nodeB", "192.168.100.5/abc").unwrap_err();
        assert!(err.contains("Invalid CIDR mask"));
    }

    #[test]
    fn test_set_ip_rejects_cidr_mismatch() {
        let mut reg = make_registry();
        let err = reg.set_ip("nodeB", "192.168.100.5/16").unwrap_err();
        assert!(err.contains("CIDR mismatch"));
    }

    #[test]
    fn test_set_ip_rejects_ip_outside_subnet() {
        let mut reg = make_registry();
        let err = reg.set_ip("nodeB", "10.0.0.5/24").unwrap_err();
        assert!(err.contains("outside subnet base"));
    }

    #[test]
    fn test_set_ip_rejects_non_numeric_host_octet() {
        let mut reg = make_registry();
        let err = reg.set_ip("nodeB", "192.168.100.xyz/24").unwrap_err();
        assert!(err.contains("Invalid host octet"));
    }

    #[test]
    fn test_set_ip_rejects_host_out_of_range() {
        let mut reg = make_registry();
        let err = reg.set_ip("nodeB", "192.168.100.0/24").unwrap_err();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn test_set_ip_rejects_owner_host_change() {
        let mut reg = make_registry();
        let err = reg.set_ip("nodeA", "192.168.100.5/24").unwrap_err();
        assert!(err.contains("must keep"));
        // Owner record must be untouched.
        assert_eq!(reg.get_ip("nodeA"), Some("192.168.100.1"));
    }

    #[test]
    fn test_set_ip_rejects_conflict_with_other_node() {
        let mut reg = make_registry();
        reg.set_ip("nodeB", "192.168.100.5/24").unwrap();
        let err = reg.set_ip("nodeC", "192.168.100.5/24").unwrap_err();
        assert!(err.contains("IP conflict"));
        assert!(!reg.is_allocated("nodeC"));
    }

    #[test]
    fn test_set_ip_preserves_existing_pubkey_prefix() {
        let mut reg = make_registry();
        reg.assign_ip("nodeB").unwrap();
        reg.set_pubkey_prefix("nodeB", "prefix1234");
        // Re-set the same node to a different in-range IP.
        reg.set_ip("nodeB", "192.168.100.9/24").unwrap();
        assert_eq!(
            reg.allocations
                .get("nodeB")
                .unwrap()
                .pubkey_prefix
                .as_deref(),
            Some("prefix1234")
        );
    }

    #[test]
    fn test_set_ip_does_not_lower_next_host_counter() {
        let mut reg = make_registry();
        reg.assign_ip("nodeB").unwrap(); // .2
        reg.assign_ip("nodeC").unwrap(); // .3, next_host becomes 4
        assert_eq!(reg.next_host, 4);
        // Re-setting nodeB to a lower host must not roll next_host backward.
        reg.set_ip("nodeB", "192.168.100.2/24").unwrap();
        assert_eq!(reg.next_host, 4);
    }

    #[test]
    fn test_set_ip_raises_next_host_when_higher() {
        let mut reg = make_registry();
        reg.set_ip("nodeB", "192.168.100.10/24").unwrap();
        assert_eq!(reg.next_host, 11);
    }

    // ── Accessors and no-op branches ──────────────────────────────

    #[test]
    fn test_set_pubkey_prefix_is_noop_for_unknown_node() {
        let mut reg = make_registry();
        reg.set_pubkey_prefix("ghost", "whatever");
        assert!(!reg.allocations.contains_key("ghost"));
    }

    #[test]
    fn test_allocated_count_matches_allocations_len() {
        let mut reg = make_registry();
        assert_eq!(reg.allocated_count(), 1); // owner only
        reg.assign_ip("nodeB").unwrap();
        assert_eq!(reg.allocated_count(), 2);
    }

    #[test]
    fn test_get_ip_and_get_ip_cidr_none_for_unknown_node() {
        let reg = make_registry();
        assert_eq!(reg.get_ip("ghost"), None);
        assert_eq!(reg.get_ip_cidr("ghost"), None);
        assert!(!reg.is_allocated("ghost"));
    }

    #[test]
    fn test_all_nodes_orders_owner_first_then_by_ip() {
        let mut reg = make_registry();
        reg.assign_ip("nodeC").unwrap(); // .2
        reg.assign_ip("nodeB").unwrap(); // .3
        let nodes = reg.all_nodes();
        assert_eq!(nodes[0].node_name, "nodeA");
        assert!(nodes[0].is_owner);
        // Remaining entries sorted by overlay_ip ascending.
        assert!(nodes[1].overlay_ip <= nodes[2].overlay_ip);
    }

    #[test]
    fn test_summary_contains_key_fields() {
        let mut reg = make_registry();
        reg.assign_ip("nodeB").unwrap();
        let s = reg.summary();
        assert!(s.contains("alpha"));
        assert!(s.contains("192.168.100"));
        assert!(s.contains("24"));
        assert!(s.contains("2 nodes"));
    }

    // ── load / load_or_create: corrupted and missing state ────────

    #[test]
    fn test_load_missing_file_returns_read_error() {
        let err = OverlayRegistry::load("/nonexistent/path/does_not_exist.json").unwrap_err();
        assert!(err.contains("Read error"));
    }

    #[test]
    fn test_load_corrupted_json_returns_parse_error() {
        let tmp = "/tmp/test_overlay_corrupted_load.json";
        std::fs::write(tmp, b"{ not valid json ").unwrap();
        let err = OverlayRegistry::load(tmp).unwrap_err();
        assert!(err.contains("Parse error"));
        let _ = fs::remove_file(tmp);
    }

    #[test]
    fn test_load_or_create_builds_new_when_file_absent() {
        let tmp = "/tmp/test_overlay_load_or_create_absent.json";
        let _ = fs::remove_file(tmp);
        let reg = OverlayRegistry::load_or_create(tmp, "beta", "192.168.101", "nodeA");
        assert_eq!(reg.circle_id, "beta");
        assert_eq!(reg.get_ip("nodeA"), Some("192.168.101.1"));
        let _ = fs::remove_file(tmp);
    }

    #[test]
    fn test_load_or_create_loads_existing_state() {
        let tmp = "/tmp/test_overlay_load_or_create_existing.json";
        let mut original = make_registry();
        original.assign_ip("nodeB").unwrap();
        original.save(tmp).unwrap();

        let loaded = OverlayRegistry::load_or_create(tmp, "alpha", "192.168.100", "nodeA");
        assert_eq!(loaded.allocations.len(), 2);
        assert!(loaded.is_allocated("nodeB"));
        let _ = fs::remove_file(tmp);
    }

    #[test]
    fn test_load_or_create_falls_back_to_new_on_corrupted_file() {
        let tmp = "/tmp/test_overlay_load_or_create_corrupt.json";
        std::fs::write(tmp, b"not json at all").unwrap();

        let reg = OverlayRegistry::load_or_create(tmp, "gamma", "192.168.102", "nodeA");
        assert_eq!(reg.circle_id, "gamma");
        assert_eq!(reg.allocated_count(), 1); // fresh registry, owner only
        let _ = fs::remove_file(tmp);
    }

    // ── Compat bridge: OverlayRegistry -> OverlayPool ─────────────

    #[test]
    fn test_overlay_pool_from_overlay_registry_copies_allocations() {
        let mut reg = make_registry();
        reg.assign_ip("nodeB").unwrap();
        reg.assign_ip("nodeC").unwrap();

        let pool: crate::nebula::overlay::OverlayPool = (&reg).into();
        assert_eq!(pool.circle_id, "alpha");
        assert_eq!(pool.next_host, reg.next_host);
        assert_eq!(
            pool.allocations.get("nodeB").cloned(),
            reg.get_ip("nodeB").map(|s| s.to_string())
        );
        assert_eq!(pool.allocations.len(), reg.allocations.len());
    }
}
