# Multi-Board CoT Fixes — Development Plan
**Based on: Latest GitHub code + Board outputs from 3 boards (28 Mar 2026)**


## All Issues Found (from board outputs + code review)

| # | Issue | Root Cause | File | Priority |
|---|-------|-----------|------|----------|
| 1 | **Cert request goes to 127.0.0.1:50061** | `ca_address` hardcoded in main.rs | `main.rs` ~line 370 | 🔴 BLOCKER |
| 2 | **Missing directories → panic** | No auto-create on fresh boards | `main.rs` (top of main) | 🔴 BLOCKER |
| 3 | **Config loaded from wrong path** | `load_config("/etc/sgx-guardian/nodeA.yaml")` but dynamic config writes to `/etc/sgx-guardian/config/nodeA.yaml` | `main.rs` ~line 431 | 🔴 BLOCKER |
| 4 | **Policy file missing → panic** | `.expect()` on policy read at line 150 | `main.rs` ~line 460 | 🔴 BLOCKER |
| 5 | **IP flip-flop** (Board 1 has 2 WiFi interfaces) | IP monitor picks wlan1 (192.168.56.1) instead of wlan0 (192.168.50.101) | `dynamic_config.rs` | 🟡 MEDIUM |
| 6 | **gRPC/attestation binds to wrong IP** | Uses detected_ip which flip-flops | `main.rs` server bind | 🟡 MEDIUM |
| 7 | **PCR stale warning on first start** | Old snapshot from previous run > 86400s ago | `pcr.rs` / `main.rs` | 🟢 LOW (cosmetic) |
| 8 | **nodeB/C SE050 falls back to software** | DKP init fails on second attempt for non-nodeA | `main.rs` DKP block | 🟡 MEDIUM |


---


## FIX 1: Certificate Request Uses Discovered IP (not 127.0.0.1)

**This is the #1 blocker. NodeB discovers nodeA at 192.168.50.101 but sends cert request to 127.0.0.1.**

### Current code (main.rs ~line 370):
```rust
let ca_address = "127.0.0.1:50061".to_string();
```

### Fix:
```rust
// Use nodeA's discovered/configured IP for cert requests
let ca_address = {
    // First try: use nodeA config IP (updated by broadcast discovery)
    let node_a_config_path = "/etc/sgx-guardian/config/nodeA.yaml";
    if let Ok(a_conf) = load_config(node_a_config_path) {
        if a_conf.ip != "0.0.0.0" && a_conf.ip != "127.0.0.1" {
            format!("{}:50061", a_conf.ip)
        } else {
            // Fallback: check if we received a broadcast from nodeA
            let fallback_path = "/etc/sgx-guardian/nodeA.yaml";
            if let Ok(a_conf2) = load_config(fallback_path) {
                if a_conf2.ip != "0.0.0.0" && a_conf2.ip != "127.0.0.1" {
                    format!("{}:50061", a_conf2.ip)
                } else {
                    "127.0.0.1:50061".to_string() // absolute last resort
                }
            } else {
                "127.0.0.1:50061".to_string()
            }
        }
    } else {
        "127.0.0.1:50061".to_string()
    }
};
println!("📡 CA address for cert request: {}", ca_address);
```

### Why this works:
Board 2 output shows `Config updated (field-level): nodeA -> ip=192.168.50.101` — the broadcast from nodeA already updates nodeA's config on nodeB. So by the time cert request runs, nodeA's real IP is available in the config file. We just need to READ it instead of hardcoding 127.0.0.1.


## FIX 2: Auto-Create Directories on Startup

### Add at the VERY START of main() in main.rs:

```rust
#[tokio::main]
async fn main() {
    let node_id = std::env::args().nth(1).unwrap_or_else(|| "nodeA".into());

    // === FIRST: Ensure all required directories exist ===
    for dir in &[
        "/etc/sgx-guardian/config",
        "/etc/sgx-guardian/schemas",
        "/etc/sgx-guardian/policies",
        "/var/lib/sgx-guardian/keys",
        "/var/lib/sgx-guardian/pcr",
        "/var/lib/sgx-guardian/boot",
        "/var/lib/sgx-guardian/sgx-agent",
        "/var/lib/sgx-guardian/nebula/ca",
        "/var/lib/sgx-guardian/nebula/nodes",
        "/var/lib/sgx-guardian/nebula/requests",
        "/var/log/sgx-guardian",
    ] {
        let _ = std::fs::create_dir_all(dir);
    }

    // Create default node configs if missing
    for (nid, port) in &[("nodeA", 50051u16), ("nodeB", 50052), ("nodeC", 50053)] {
        let path = format!("/etc/sgx-guardian/config/{}.yaml", nid);
        if !std::path::Path::new(&path).exists() {
            let letter = &nid[4..];
            let content = format!(
                "---\nnode_id: \"{}\"\nhostname: \"guardian-node-{}\"\nip: \"0.0.0.0\"\nport: {}\npublic_key: \"placeholder-key-{}\"\n\nsecure_element:\n  enabled: true\n  scp_key_path: \"/home/root/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt\"\n  interface: \"t1oi2c\"\n  auth_type: \"PlatformSCP\"\n  connection_type: \"se05x\"\n",
                nid, letter, port, letter
            );
            let _ = std::fs::write(&path, &content);
        }
        // Also create /etc/sgx-guardian/<node>.yaml symlink/copy
        let main_path = format!("/etc/sgx-guardian/{}.yaml", nid);
        if !std::path::Path::new(&main_path).exists() {
            let _ = std::fs::copy(&path, &main_path);
        }
    }

    // Create default policy schema if missing
    let schema_path = "/etc/sgx-guardian/schemas/uep_policy_v1.yaml";
    if !std::path::Path::new(schema_path).exists() {
        let schema = "---\npolicy_id: \"123e4567-e89b-12d3-a456-426614174000\"\nversion: \"1.0.0\"\ndescription: \"Default Guardian Edge Policy\"\nrules:\n  - id: \"rule-001\"\n    action: \"ALLOW\"\n    src_cidr: \"10.0.0.0/24\"\n    dst_cidr: \"0.0.0.0/0\"\n    protocol: \"TCP\"\n    port: 443\n  - id: \"rule-005\"\n    action: \"DENY\"\n    src_cidr: \"0.0.0.0/0\"\n    dst_cidr: \"10.0.0.10\"\n    protocol: \"UDP\"\n";
        let _ = std::fs::write(schema_path, schema);
    }

    // ... rest of existing main() ...
```


## FIX 3: Config Path Consistency

### Current code (main.rs ~line 431):
```rust
let node_a = load_config("/etc/sgx-guardian/nodeA.yaml").expect("Failed to load nodeA config");
let node_b = load_config("/etc/sgx-guardian/nodeB.yaml").expect("Failed to load nodeB config");
let node_c = load_config("/etc/sgx-guardian/nodeC.yaml").expect("Failed to load nodeC config");
```

### Fix — load from config/ dir with fallback, never panic:
```rust
fn load_config_safe(node: &str) -> NodeConfig {
    // Try config/ dir first (dynamic configs live here)
    let config_path = format!("/etc/sgx-guardian/config/{}.yaml", node);
    if let Ok(cfg) = load_config(&config_path) {
        return cfg;
    }
    // Fallback to root dir
    let root_path = format!("/etc/sgx-guardian/{}.yaml", node);
    if let Ok(cfg) = load_config(&root_path) {
        return cfg;
    }
    // Last resort: default config
    eprintln!("⚠️ No config found for {} — using defaults", node);
    NodeConfig {
        node_id: node.to_string(),
        hostname: format!("guardian-node-{}", &node[4..]),
        ip: "0.0.0.0".to_string(),
        port: match node { "nodeA" => 50051, "nodeB" => 50052, _ => 50053 },
        public_key: format!("placeholder-key-{}", &node[4..]),
    }
}

// Replace the 3 load_config calls with:
let node_a = load_config_safe("nodeA");
let node_b = load_config_safe("nodeB");
let node_c = load_config_safe("nodeC");
```

### Also sync configs between paths after dynamic IP update:
```rust
// After updating /etc/sgx-guardian/config/nodeX.yaml, also copy to /etc/sgx-guardian/nodeX.yaml
if !detected_ip.is_empty() {
    let config_path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);
    let main_path = format!("/etc/sgx-guardian/{}.yaml", node_id);
    let _ = dynamic_config::update_config_ip_if_changed(&config_path, &detected_ip);
    // Keep main path in sync
    let _ = std::fs::copy(&config_path, &main_path);
}
```


## FIX 4: Policy File — Graceful Fallback (no panic)

### Current code (main.rs ~line 460):
```rust
let _yaml_content = fs::read_to_string("/etc/sgx-guardian/schemas/uep_policy_v1.yaml")
    .expect("Cannot read policy file (/etc/sgx-guardian/schemas)");
```

### Fix:
```rust
let _yaml_content = fs::read_to_string("/etc/sgx-guardian/schemas/uep_policy_v1.yaml")
    .unwrap_or_else(|e| {
        eprintln!("⚠️ Policy schema not found: {} — using empty default", e);
        // Return minimal valid policy YAML
        String::from("---\npolicy_id: \"default\"\nversion: \"0.0.0\"\ndescription: \"Empty default\"\nrules: []\n")
    });
```


## FIX 5: IP Detection — Prefer Specific Interface

Board 1 has two WiFi interfaces. The IP monitor picks the wrong one.

### In dynamic_config.rs detect_local_lan_ip():
```rust
// Add preference for the interface that's on the same subnet as peers
pub fn detect_local_lan_ip() -> Result<std::net::IpAddr> {
    let interfaces = get_if_addrs::get_if_addrs()?;

    // Priority order: prefer interfaces on common subnets (192.168.50.x)
    // Skip virtual, loopback, and nebula interfaces
    let mut candidates: Vec<(String, std::net::IpAddr)> = interfaces
        .iter()
        .filter(|iface| {
            !iface.is_loopback()
                && !is_virtual_interface(&iface.name)
                && !iface.name.starts_with("nebula")
                && !iface.name.starts_with("docker")
        })
        .filter_map(|iface| match iface.addr {
            get_if_addrs::IfAddr::V4(ref addr) => {
                Some((iface.name.clone(), std::net::IpAddr::V4(addr.ip)))
            }
            _ => None,
        })
        .filter(|(_, ip)| is_routable_ip(&ip.to_string()))
        .collect();

    // Sort: prefer wlan0 over wlan1, eth0 over others
    candidates.sort_by(|(name_a, _), (name_b, _)| {
        let priority = |n: &str| -> u8 {
            if n.starts_with("eth") { 0 }
            else if n == "wlan0" { 1 }
            else if n.starts_with("wlan") { 2 }
            else if n.starts_with("wwan") { 3 }
            else { 4 }
        };
        priority(name_a).cmp(&priority(name_b))
    });

    candidates
        .first()
        .map(|(_, ip)| *ip)
        .ok_or_else(|| anyhow::anyhow!("No LAN IP found"))
}
```


## FIX 6: Server/Attestation Bind to 0.0.0.0

Currently the gRPC server and attestation listener bind to the detected IP. If the IP is wrong (due to flip-flop), connections fail.

### Fix gRPC server bind (main.rs):
```rust
// FIND:
let this_addr = format!("{}:{}", detected_ip_for_server, this_node.port);

// REPLACE WITH:
let this_addr = format!("0.0.0.0:{}", this_node.port);
// This listens on ALL interfaces — any peer can connect regardless of which IP they use
```

### Fix attestation listener (attestation_service.rs):
```rust
// FIND:
let bind_ip = node_conf.ip.clone();

// REPLACE WITH:
let bind_ip = "0.0.0.0".to_string();
// Listen on all interfaces for attestation requests
```


## FIX 7: PCR Stale Warning — Skip on First Measurement

The warning `⚠️ PCR snapshot is stale` appears because the OLD snapshot from a previous run is > 86400 seconds old. This is cosmetic — the daemon immediately measures fresh PCRs and replaces it.

### Fix in main.rs (attestation block, before PCR measurement):
```rust
// FIND the stale check line:
// "⚠️ PCR snapshot is stale (older than 86400 seconds)"

// Add a condition: only warn if this is NOT the first run
// The stale check is on the PREVIOUS snapshot. Since we're about to
// measure fresh PCRs, this warning is misleading on startup.
// Change: only print the warning at DEBUG level, or suppress on first boot.
if pcr_snapshot_exists && snapshot.is_stale() {
    // Only warn if snapshot was taken in THIS daemon session
    // On startup, old snapshots are expected to be stale
    // The fresh measurement below will replace it
    // eprintln!("⚠️ PCR snapshot is stale"); // ← comment out or make debug
}
```

**Alternatively, simpler fix:** Just move the stale check AFTER the new measurement, not before.


## FIX 8: DKP Init for nodeB/nodeC on Board

Board 2/3 show "SE050 not available" because DKP init tries to generate in SE050 first, fails (wrong key slot or connection issue), then falls back to software. This is because the DKP code on boards 2/3 tries to use SE050 but the initialization fails on the second attempt.

**This is actually acceptable for CoT testing** — the software fallback works. For production, each board should have its own SE050 properly initialized. Skip this fix for now and focus on CoT.


---


## Apply Order

```
Step 1:  main.rs — Add auto-create directories block (Fix 2)
Step 2:  main.rs — Fix policy file panic (Fix 4)
Step 3:  main.rs — Fix config path consistency (Fix 3)
Step 4:  main.rs — Fix CA address from 127.0.0.1 to discovered IP (Fix 1)
Step 5:  main.rs — Bind servers to 0.0.0.0 (Fix 6)
Step 6:  dynamic_config.rs — Fix IP detection priority (Fix 5)
Step 7:  attestation_service.rs — Bind to 0.0.0.0 (Fix 6)
Step 8:  main.rs — PCR stale warning (Fix 7, optional)
Step 9:  cargo test -- --nocapture
Step 10: cargo build
Step 11: cross build --target aarch64-unknown-linux-gnu --release
Step 12: Deploy to 3 boards, test multi-board discovery + cert
```


## Expected Result After Fixes

### NodeA (Board 1):
```
🌐 Detected LAN IP: 192.168.50.101           ← stable, no flip-flop
✅ Loaded Node A at 192.168.50.101:50051
🔐 CertService bootstrap on 0.0.0.0:50061    ← listens on all interfaces
📩 Certificate request received from nodeB    ← nodeB reaches us!
📩 Certificate request received from nodeC
```

### NodeB (Board 2):
```
Peer discovered: nodeA @ 192.168.50.101:50051 ← discovery works
📡 CA address for cert request: 192.168.50.101:50061  ← CORRECT IP!
✅ CA-signed certificate received from CA     ← cert obtained!
✅ Nebula mesh started
✅ Mutual attestation with nodeA succeeded
```

### NodeC (Board 3):
```
Peer discovered: nodeA @ 192.168.50.101:50051
📡 CA address for cert request: 192.168.50.101:50061
✅ CA-signed certificate received from CA
✅ Nebula mesh started
✅ Mutual attestation with nodeA succeeded
```
