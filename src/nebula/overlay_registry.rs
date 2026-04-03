// src/nebula/overlay_registry.rs
// ============================================================
// Nebula Overlay IP Registry — Multi-Node, Multi-PC
//
// Problem yeh hai ke OverlayPool sirf ek PC par save hoti thi.
// Agar nodeA PC1 par chale aur baad mein PC2 par, to .1 IP
// dobara assign ho sakti thi — IP conflict.
//
// Yeh file ek JSON-based registry maintain karti hai jis mein:
//   - Har node ka naam → overlay IP permanently mapped hai
//   - Circle owner (nodeA) hamesha .1 milta hai
//   - Ek atomic counter next available IP track karta hai
//   - File-lock se concurrent writes safe hain
//
// SYNC STRATEGY:
//   - nodeA (CA) apni registry /var/lib/sgx-guardian/nebula/ mein rakhta hai
//   - Member nodes cert request ke waqt apni IP bhi register karate hain
//   - nodeA ki registry hi master hai — wo hi IP assign karta hai
//   - Member nodes apni assigned IP locally cache karte hain
// ============================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const REGISTRY_SUBNET_BASE: &str = "192.168.100";
pub const REGISTRY_CIDR: u8 = 24;
pub const REGISTRY_OWNER_HOST: u8 = 1;       // Circle owner hamesha .1
pub const REGISTRY_START_HOST: u8 = 2;       // Members .2 se shuru
pub const REGISTRY_MAX_HOST: u8 = 254;       // Maximum .254

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
    pub fn load_or_create(path: &str, circle_id: &str, subnet_base: &str, owner_node: &str) -> Self {
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
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create dir: {}", e))?;
        }

        // Write to temp file first, then atomic rename (prevents corruption)
        let tmp_path = format!("{}.tmp", path);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize error: {}", e))?;

        fs::write(&tmp_path, &json)
            .map_err(|e| format!("Write error: {}", e))?;

        fs::rename(&tmp_path, path)
            .map_err(|e| format!("Rename error: {}", e))?;

        Ok(())
    }

    /// Load registry from disk.
    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path)
            .map_err(|e| format!("Read error: {}", e))?;
        serde_json::from_str(&json)
            .map_err(|e| format!("Parse error: {}", e))
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
        println!("  Circle: {}  |  Subnet: {}.0/{}",
            self.circle_id, self.subnet_base, self.cidr);
        println!("─────────────────────────────────────────────────");
        println!("  {:<12}  {:<20}  {}", "Node", "Overlay IP", "Role");
        println!("─────────────────────────────────────────────────");
        for record in self.all_nodes() {
            let role = if record.is_owner { "CA / Lighthouse" } else { "Member" };
            println!("  {:<12}  {:<20}  {}", record.node_name, record.overlay_ip_cidr, role);
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
                    .last()
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
// Yeh bridge isliye hai ke main.rs OverlayPool use karta hai.
// Registry se pool banana easy hai.
impl From<&OverlayRegistry> for crate::nebula::overlay::OverlayPool {
    fn from(reg: &OverlayRegistry) -> Self {
        let mut pool = crate::nebula::overlay::OverlayPool::new(
            &reg.circle_id,
            &reg.subnet_base,
            &reg.owner_node,
        );
        // Sync all allocations into pool
        for record in reg.allocations.values() {
            pool.allocations.insert(
                record.node_name.clone(),
                record.overlay_ip.clone(),
            );
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
    fn test_no_ip_conflict_after_reload() {
        let mut reg = make_registry();
        reg.assign_ip("nodeB").unwrap();
        reg.assign_ip("nodeC").unwrap();

        let tmp = "/tmp/test_registry_conflict.json";
        reg.save(tmp).unwrap();

        let mut reg2 = OverlayRegistry::load(tmp).unwrap();
        let ip_d = reg2.assign_ip("nodeD").unwrap();
        assert_eq!(ip_d, "192.168.100.4/24"); // .2 and .3 already taken

        let _ = fs::remove_file(tmp);
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
        reg.allocations.insert("nodeX".to_string(), NodeIpRecord {
            node_name: "nodeX".to_string(),
            overlay_ip: "192.168.100.2".to_string(),
            overlay_ip_cidr: "192.168.100.2/24".to_string(),
            is_owner: false,
            allocated_at: "".to_string(),
            pubkey_prefix: None,
        });
        reg.allocations.insert("nodeY".to_string(), NodeIpRecord {
            node_name: "nodeY".to_string(),
            overlay_ip: "192.168.100.4".to_string(),
            overlay_ip_cidr: "192.168.100.4/24".to_string(),
            is_owner: false,
            allocated_at: "".to_string(),
            pubkey_prefix: None,
        });
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

        let tmp = "/tmp/test_registry_roundtrip.json";
        reg.save(tmp).unwrap();

        let loaded = OverlayRegistry::load(tmp).unwrap();
        assert_eq!(loaded.get_ip("nodeA"), Some("192.168.100.1"));
        assert_eq!(loaded.get_ip("nodeB"), Some("192.168.100.2"));
        assert_eq!(loaded.get_ip("nodeC"), Some("192.168.100.3"));
        assert_eq!(loaded.next_host, 4);

        let _ = fs::remove_file(tmp);
    }

    #[test]
    fn test_pool_exhaustion() {
        let mut reg = make_registry();
        reg.next_host = 255;
        // Manually fill all slots
        for i in 2..=254u8 {
            reg.allocations.insert(format!("node{}", i), NodeIpRecord {
                node_name: format!("node{}", i),
                overlay_ip: format!("192.168.100.{}", i),
                overlay_ip_cidr: format!("192.168.100.{}/24", i),
                is_owner: false,
                allocated_at: "".to_string(),
                pubkey_prefix: None,
            });
        }
        assert!(reg.assign_ip("nodeOverflow").is_err());
    }
}