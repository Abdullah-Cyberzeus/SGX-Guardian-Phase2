# PLAN A — Direct Integration: WiFi + Ethernet Transport Merge (v2)

## Verified Against: `AsadAli-CyberZeus/SGX` main branch (Project Knowledge — March 2026)

**Version**: 2.0  
**Date**: March 27, 2026  
**Source**: Shahzad's ZIP (WiFi + Ethernet commits)  
**Target**: Current `main` branch (verified via project knowledge from attached GitHub repo)  
**Plan Type**: Direct copy of team member implementation  

---

## CRITICAL FINDING: Shahzad's Branch is Based on OLDER Main

Shahzad's ZIP `main.rs` uses the **old `mod` declaration style**:

```rust
// SHAHZAD'S ZIP (OLD STYLE — BREAKS CURRENT MAIN)
mod audit;
mod config_loader;
mod dynamic_config;
mod attestation_service;
// ... etc
```

The **current `main` branch** uses **library-style imports**:

```rust
// CURRENT MAIN (CORRECT STYLE)
use sgx_guardian_client::attestation_service;
use sgx_guardian_client::config_loader::{load_config, CloudConfig};
use sgx_guardian_client::key_manager::KeyManager;
// ... etc
```

**You CANNOT directly copy Shahzad's `main.rs` into current `main`**. It would erase:
- SE050 Hardware Key Manager initialization
- DKP Auto-Rotation check
- Secure Boot Chain verification
- PCR Measurement block
- Library-style import architecture

Instead, the new modules must be added to `lib.rs` and changes surgically applied to the existing `main.rs`.

---

## SUMMARY

This document provides exact merge instructions adapted from Shahzad's code to work with the **current** `main` branch architecture.

**New files to create**: 4 files  
**Existing files to modify**: 4 files  
**Shahzad's `main.rs` and `lib.rs`**: DO NOT USE — they are based on an older branch  

---

## FILES INVENTORY

### New Files (Create These)

| # | File Path | Purpose | Lines |
|---|-----------|---------|-------|
| N1 | `src/node_announcement.rs` | Peer broadcast message struct | 9 |
| N2 | `src/node_broadcast.rs` | UDP broadcast sender | 66 |
| N3 | `src/node_listener.rs` | UDP broadcast receiver | 111 |
| N4 | `src/dynamic_config.rs` | IP detection, config sync, IP monitor | 394 |

### Files to Modify (Surgical Changes Only)

| # | File Path | Change Type |
|---|-----------|-------------|
| M1 | `src/lib.rs` | Add 4 module declarations |
| M2 | `src/main.rs` | Add imports + integration blocks (DO NOT REPLACE) |
| M3 | `src/config_loader.rs` | Relax IP validation |
| M4 | `src/enforcement/executor.rs` | Add broadcast/attestation/sync ports |

### Files from Shahzad's ZIP to IGNORE

| File | Reason |
|------|--------|
| `main.rs` | Based on older branch — uses `mod` declarations, missing SE050/DKP/SecureBoot |
| `lib.rs` | Missing `cloud`, `metrics_server`, `secure_element`, `policy_manager`, `policy_state` modules |
| `network..rs` | Redundant — duplicates `dynamic_config::detect_local_lan_ip()` |
| `attestation_service.rs` | Identical to current main — no changes needed |
| `client.rs` | Changes are minor and risky (TLS domain name) — apply separately if needed |
| `tls.rs` | Changes have `.unwrap()` panic risk — apply separately |
| `executor.rs` | Use surgical port additions only, not full file replacement |
| `p2p_discovery.rs` | No changes needed for WiFi/Ethernet |
| `session_manager.rs` | Already exists in `src/cot/` — Shahzad's ZIP version has different key structure |
| `interface_detector.rs` | Already exists at `src/cot/interface_detector.rs` |
| `transport_registry.rs` | Already exists at `src/cot/transport_registry.rs` |
| `wifi.rs` | Already exists at `src/cot/transports/wifi.rs` — Shahzad's version adds operstate monitoring but has constructor panic bug |
| `config_loader.rs` | Use surgical IP validation change only |

---

## STEP-BY-STEP MERGE INSTRUCTIONS

---

### STEP 1: Create `src/node_announcement.rs`

**Action**: Create new file

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeAnnouncement {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
}
```

---

### STEP 2: Create `src/node_broadcast.rs`

**Action**: Create new file  
**Full content**: Copy from Shahzad's ZIP `node_broadcast.rs` (66 lines)

The file uses `crate::node_announcement::NodeAnnouncement` — this will resolve correctly because we'll add the module to `lib.rs`.

> ⚠️ **Issue detected**: Hardcoded /24 subnet mask. **Better approach in Plan B.**

---

### STEP 3: Create `src/node_listener.rs`

**Action**: Create new file  
**Full content**: Copy from Shahzad's ZIP `node_listener.rs` (111 lines)

**CRITICAL FIX REQUIRED**: The file references `crate::dynamic_config` and `crate::node_announcement` — both resolve via `lib.rs` module declarations.

> ⚠️ **Issue detected**: No authentication on broadcasts. Port 9000 hardcoded. **Better approach in Plan B.**

---

### STEP 4: Create `src/dynamic_config.rs`

**Action**: Create new file  
**Full content**: Copy from Shahzad's ZIP `dynamic_config.rs` (394 lines)

> ⚠️ **Issue detected**: `update_peer_config()` overwrites entire YAML (destroys `metrics:` field). `is_routable_ip()` blocks valid 172.16-31.x.x IPs. **Better approach in Plan B.**

---

### STEP 5: Modify `src/lib.rs` — Add Module Declarations

**Action**: Modify existing file  
**Current `lib.rs`** (from GitHub repo):

```rust
// ===== Public exports for integration tests =====

// Core modules
pub mod attestation_service;
pub mod audit;
pub mod cert_client;
pub mod cert_service;
pub mod client;
pub mod cloud;
pub mod config_loader;
pub mod cot;
pub mod enforcement;
pub mod key_manager;
pub mod logging;
pub mod metrics;
pub mod metrics_server;
pub mod nebula;
pub mod p2p_discovery;
pub mod policy;
pub mod policy_manager;
pub mod policy_state;
pub mod secure_element;
pub mod server;
pub mod tls;
```

**Add AFTER `pub mod tls;`**:

```rust
// WiFi + Ethernet discovery modules
pub mod dynamic_config;
pub mod node_announcement;
pub mod node_broadcast;
pub mod node_listener;
```

**DO NOT** remove any existing modules. The current `lib.rs` has 21 modules — after this change it should have 25.

---

### STEP 6: Modify `src/main.rs` — Add Imports (TOP OF FILE)

**Action**: Add new imports alongside existing ones  
**Location**: After the existing `use` block at the top of `main.rs`

Find this line:

```rust
use sgx_guardian_client::server;
use sgx_guardian_client::server::start_server;
```

Add AFTER it:

```rust
// WiFi + Ethernet discovery imports
use sgx_guardian_client::dynamic_config;
use sgx_guardian_client::node_announcement::NodeAnnouncement;
use sgx_guardian_client::node_broadcast;
use sgx_guardian_client::node_listener;
```

---

### STEP 7: Modify `src/main.rs` — Add Listener Spawn

**Action**: Add code block  
**Location**: Find this line (early in `main()`, after `let node_id = args[1].clone();`):

```rust
    // Generate node-specific identity key path
    let node_key_path = format!("/var/lib/sgx-guardian/sgx-agent/device_{}.key", node_id);
```

Add **BEFORE** that line:

```rust
    // Start node announcement listener (UDP broadcast receiver)
    {
        let node_id_clone = node_id.clone();
        tokio::spawn(async move {
            node_listener::start_listener(node_id_clone).await;
        });
    }
```

---

### STEP 8: Modify `src/main.rs` — Add Dynamic IP Detection + Config Sync

**Action**: Add code block  
**Location**: Find this section (after attestation verification, before config loading):

Current code has this pattern:

```rust
    // === Load node configs ===
    println!("\n📦 Loading node configurations...");
```

Add **BEFORE** `println!("\n📦 Loading node configurations...");`:

```rust
    // === DYNAMIC IP DETECTION + CONFIG AUTO-UPDATE ===
    println!("\n🔍 Detecting local LAN IP address...");

    let detected_ip = match dynamic_config::detect_local_lan_ip() {
        Ok(ip) => {
            println!("🌐 Detected LAN IP: {}", ip);
            log_event(&node_id, &format!("Detected LAN IP: {}", ip));
            ip.to_string()
        }
        Err(e) => {
            eprintln!("❌ IP detection failed: {:?}", e);
            log_error(&node_id, &format!("IP detection failed: {:?}", e));
            String::new()
        }
    };

    // Sanitize configs before load
    for yaml_file in &[
        "/etc/sgx-guardian/config/nodeA.yaml",
        "/etc/sgx-guardian/config/nodeB.yaml",
        "/etc/sgx-guardian/config/nodeC.yaml",
    ] {
        if let Err(e) = dynamic_config::sanitize_config_ip_if_invalid(yaml_file) {
            eprintln!("⚠️ Sanitize failed for {}: {:?}", yaml_file, e);
        }
    }

    // Update ONLY current node config with detected IP
    if !detected_ip.is_empty() {
        let my_config_path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);
        let _ = dynamic_config::update_config_ip_if_changed(&my_config_path, &detected_ip);
    }
```

---

### STEP 9: Modify `src/main.rs` — Add Broadcast + IP Monitor

**Action**: Add code block  
**Location**: Find the section after config loading where `this_node` and `peers` are defined. Current code has:

```rust
    let (this_node, peers) = match node_id.as_str() {
        "nodeA" => (node_a.clone(), vec![node_b, node_c]),
        ...
    };
```

Add **AFTER** the `(this_node, peers)` match block (before the P2P Discovery section):

```rust
    // === NODE BROADCAST + CONFIG SYNC ===
    let detected_ip_for_broadcast = if detected_ip.is_empty() {
        this_node.ip.clone()
    } else {
        detected_ip.clone()
    };

    // Initial broadcast
    let announcement = NodeAnnouncement {
        node_id: this_node.node_id.clone(),
        hostname: this_node.hostname.clone(),
        ip: detected_ip_for_broadcast.clone(),
        port: this_node.port,
        public_key: this_node.public_key.clone(),
    };
    node_broadcast::broadcast_node(&announcement);

    // Start background IP monitor
    dynamic_config::start_ip_monitor(
        node_id.clone(),
        format!("/etc/sgx-guardian/config/{}.yaml", node_id),
        vec![],
        dynamic_config::NodeConfigBroadcast {
            node_id: this_node.node_id.clone(),
            hostname: this_node.hostname.clone(),
            ip: detected_ip_for_broadcast.clone(),
            port: this_node.port,
            public_key: this_node.public_key.clone(),
        },
    )
    .await;

    // Periodic broadcast (every 30 seconds)
    {
        let node_id_bc = node_id.clone();
        let hostname_bc = this_node.hostname.clone();
        let pubkey_bc = pubkey_b64.clone();
        let port_bc = this_node.port;

        tokio::spawn(async move {
            loop {
                let current_ip = match dynamic_config::detect_local_lan_ip() {
                    Ok(ip) => ip.to_string(),
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                };

                let announcement = NodeAnnouncement {
                    node_id: node_id_bc.clone(),
                    hostname: hostname_bc.clone(),
                    ip: current_ip,
                    port: port_bc,
                    public_key: pubkey_bc.clone(),
                };

                node_broadcast::broadcast_node(&announcement);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }
    println!("✅ Config auto-update system active\n");
    // === END NODE BROADCAST + CONFIG SYNC ===
```

---

### STEP 10: Modify `src/main.rs` — Update TLS SAN

**Action**: Find and replace one line  
**Current code** (from GitHub repo main):

```rust
    let san = [this_node.hostname.as_str(), "127.0.0.1"];
```

**Replace with**:

```rust
    let san_ip = if detected_ip.is_empty() { "127.0.0.1" } else { &detected_ip };
    let san = [this_node.hostname.as_str(), san_ip];
```

> ⚠️ **Issue detected**: If `detected_ip` goes out of scope or changes between detection and TLS cert generation, the SAN may be stale. **Better approach in Plan B.**

---

### STEP 11: Modify `src/config_loader.rs` — Relax IP Validation

**Action**: Find and replace  
**Current code** (from GitHub repo):

```rust
        // Validate IP address format
        if self.ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("Invalid IP address: {}", self.ip));
        }
```

**Replace with**:

```rust
        // Only check empty — dynamic IPs may be 0.0.0.0 during discovery
        if self.ip.trim().is_empty() {
            return Err("ip field cannot be empty".into());
        }
```

---

### STEP 12: Modify `src/enforcement/executor.rs` — Add Firewall Ports

**Action**: Find and add  
**Current code** (from GitHub repo) has this section:

```rust
    // Allow local gRPC / node communication (example ports)
    out.push_str("    tcp dport {50051,50052,50053} accept\n");

    // ---- END DEV SAFETY RULES ----
```

**Add BEFORE** `// ---- END DEV SAFETY RULES ----`:

```rust
    // Allow attestation ports
    out.push_str("    tcp dport {50151,50152,50153} accept\n");

    // Allow node discovery broadcast (UDP)
    out.push_str("    udp dport 9000 accept\n");
    out.push_str("    udp sport 9000 accept\n");

    // Allow config sync (TCP)
    out.push_str("    tcp dport 50070 accept\n");

    // Allow cert bootstrap
    out.push_str("    tcp dport 50061 accept\n");

    // Allow ICMP ping
    out.push_str("    ip protocol icmp accept\n");
```

---

### STEP 13: Add `network-interface` Crate to `Cargo.toml`

**Action**: Add under `[dependencies]`

```toml
network-interface = "2.0"
```

**DO NOT** add `local-ip-address` — `network.rs` is not being created (redundant).

---

## BUILD VERIFICATION

```bash
cargo clean
cargo build 2>&1
cargo test 2>&1
cargo clippy 2>&1
```

---

## RISKS SUMMARY

| Risk | Severity | Description |
|------|----------|-------------|
| No broadcast auth | HIGH | Any LAN device can inject fake peers |
| YAML overwrite | MEDIUM | `update_peer_config()` destroys extra fields |
| /24 subnet assumption | LOW | Broadcast fails on non-/24 networks |
| Port 9000 hardcoded | MEDIUM | No configuration possible |
| `is_routable_ip()` too aggressive | MEDIUM | Blocks valid 172.16-31 IPs |

---

## POST-MERGE VERIFICATION

### Three-Laptop Test

```bash
# Laptop 1: cargo run -- nodeA
# Laptop 2: cargo run -- nodeB  
# Laptop 3: cargo run -- nodeC

# Verify on each:
cat /etc/sgx-guardian/config/nodeA.yaml  # Should show real IPs
cat /etc/sgx-guardian/config/nodeB.yaml
cat /var/log/sgx-guardian/trusted_peers.json
sudo tcpdump -i any udp port 9000 -v
```

### i.MX8M Plus Board Test

```bash
cross build --target aarch64-unknown-linux-gnu --release
scp target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@<board-ip>:/usr/local/bin/

# On board:
sgx_guardian_client nodeA
# Verify: eth0 and wlan0 detected by InterfaceDetector
```

Board has Sterling-LWB5 WiFi (`wlan0`) + Qualcomm Atheros/ADIN1300 Ethernet (`eth0`). Both auto-detected.

---

*End of Plan A v2 — Verified against current `main` branch*
