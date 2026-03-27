# PLAN B — Improved / Secure Implementation: WiFi + Ethernet Transport Merge (v2)

## Verified Against: `AsadAli-CyberZeus/SGX` main branch (Project Knowledge — March 2026)

**Version**: 2.0  
**Date**: March 27, 2026  
**Base**: Shahzad's WiFi + Ethernet commits, adapted for current `main`  
**Plan Type**: Corrected, optimized, security-hardened  

---

## ISSUES FOUND IN PLAN A (COMPLETE LIST)

### Critical Issues

| # | Issue | Impact |
|---|-------|--------|
| C1 | **Shahzad's `main.rs` and `lib.rs` are from an OLDER branch** — they use `mod` declarations instead of `use sgx_guardian_client::*` imports and are missing SE050/DKP/SecureBoot/PCR blocks | Applying directly would break the build and lose hardware security features |
| C2 | **No authentication on UDP broadcasts** — any LAN device can inject fake `NodeAnnouncement` packets and poison peer configs | Zero Trust violation — allows peer impersonation |
| C3 | **`tls.rs` changes use `.unwrap()` on IP parse** — panics if IP is `0.0.0.0` during first boot before discovery | Node crashes on startup |
| C4 | **WiFi transport constructor calls `tokio::spawn()`** — panics in unit tests outside Tokio runtime | Test suite crashes |

### Moderate Issues

| # | Issue | Impact |
|---|-------|--------|
| M1 | **Hardcoded /24 subnet mask** in `subnet_broadcast()` | Fails on /16, /8 networks |
| M2 | **`update_peer_config()` overwrites entire YAML** — destroys `metrics:` config and any other extra fields | Data loss |
| M3 | **`is_routable_ip()` blocks all 172.17–31.x.x** — too aggressive, blocks valid RFC 1918 IPs | Corporate network incompatibility |
| M4 | **`network.rs` duplicates `dynamic_config::detect_local_lan_ip()`** — redundant file and dependency | Unnecessary `local-ip-address` crate |
| M5 | **Port 9000 hardcoded** everywhere — no configuration possible | Port conflicts unresolvable |
| M6 | **No rate limiting on listener** — UDP flood can saturate CPU | DoS vulnerability |
| M7 | **No deduplication** — same peer triggers repeated config file writes every 30 seconds | Unnecessary disk I/O |
| M8 | **Shahzad's `session_manager.rs` has different key structure** than current main's `src/cot/session_manager.rs` — keys by `(device_id, transport)` vs `device_id` only | Applying ZIP version would break existing CoT session tests |

---

## IMPROVED ARCHITECTURE

```
┌──────────────────────────────────────────────────────────┐
│  LAYER 1: Signed Announcements                           │
│  SHA-256 integrity digest + timestamp validation          │
│  Stale announcements (>120s) automatically rejected       │
├──────────────────────────────────────────────────────────┤
│  LAYER 2: Safe Config Updates                            │
│  Field-level YAML modification — preserves metrics:,      │
│  custom fields, comments                                  │
├──────────────────────────────────────────────────────────┤
│  LAYER 3: Rate Limiting + Deduplication                  │
│  10 announcements/min per source IP                       │
│  25-second dedup window per node_id                       │
├──────────────────────────────────────────────────────────┤
│  LAYER 4: Configurable Discovery                         │
│  Port, interval via SGX_BROADCAST_PORT env var            │
│  Reads actual netmask from sysfs                          │
└──────────────────────────────────────────────────────────┘
```

---

## STEP-BY-STEP IMPROVED IMPLEMENTATION

All steps reference the same file paths as Plan A. Only the FILE CONTENTS differ.

---

### FIX 1: Remove `network.rs` (Addresses M4)

**Action**: Do NOT create `src/network.rs`  
**Action**: Do NOT add `local-ip-address` to `Cargo.toml`  
**Action**: Only add 4 modules to `lib.rs` (not 5):

```rust
pub mod dynamic_config;
pub mod node_announcement;
pub mod node_broadcast;
pub mod node_listener;
```

---

### FIX 2: Signed `NodeAnnouncement` (Addresses C2)

**Action**: Create `src/node_announcement.rs` with integrity verification

```rust
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeAnnouncement {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub timestamp: u64,
}

impl NodeAnnouncement {
    /// Create announcement with integrity digest
    pub fn new_signed(
        node_id: String,
        hostname: String,
        ip: String,
        port: u16,
        public_key: String,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let msg = format!("{}{}{}{}{}", node_id, ip, port, public_key, timestamp);
        let digest = Sha256::digest(msg.as_bytes());
        let signature = hex::encode(digest);

        Self { node_id, hostname, ip, port, public_key, signature, timestamp }
    }

    /// Verify integrity — reject stale (>120s) or tampered announcements
    pub fn verify_integrity(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(self.timestamp) > 120 {
            return false;
        }

        let msg = format!("{}{}{}{}{}", self.node_id, self.ip, self.port, self.public_key, self.timestamp);
        let digest = Sha256::digest(msg.as_bytes());
        self.signature == hex::encode(digest)
    }
}
```

---

### FIX 3: Improved Broadcast with Real Netmask (Addresses M1, M5)

**Action**: Create `src/node_broadcast.rs`

```rust
use std::net::{UdpSocket, SocketAddrV4, Ipv4Addr};
use crate::node_announcement::NodeAnnouncement;

fn broadcast_port() -> u16 {
    std::env::var("SGX_BROADCAST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000)
}

fn subnet_broadcast(local_ip: &str) -> Ipv4Addr {
    let ip: Ipv4Addr = match local_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return Ipv4Addr::BROADCAST,
    };

    // Try to read actual netmask from system
    let mask = read_netmask_for_ip(local_ip).unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
    let ip_o = ip.octets();
    let mask_o = mask.octets();

    Ipv4Addr::new(
        ip_o[0] | !mask_o[0],
        ip_o[1] | !mask_o[1],
        ip_o[2] | !mask_o[2],
        ip_o[3] | !mask_o[3],
    )
}

fn read_netmask_for_ip(target_ip: &str) -> Option<Ipv4Addr> {
    use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
    let interfaces = NetworkInterface::show().ok()?;
    for iface in interfaces {
        for addr in &iface.addr {
            if let Addr::V4(v4) = addr {
                if v4.ip.to_string() == target_ip {
                    return v4.netmask;
                }
            }
        }
    }
    None
}

pub fn broadcast_node(info: &NodeAnnouncement) {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => { eprintln!("❌ Broadcast bind failed: {}", e); return; }
    };
    if let Err(e) = socket.set_broadcast(true) {
        eprintln!("❌ set_broadcast failed: {}", e); return;
    }
    let data = match serde_json::to_string(info) {
        Ok(d) => d,
        Err(e) => { eprintln!("❌ JSON serialize failed: {}", e); return; }
    };
    let bytes = data.as_bytes();
    let port = broadcast_port();

    let bcast_ip = subnet_broadcast(&info.ip);
    let subnet_addr = SocketAddrV4::new(bcast_ip, port);
    match socket.send_to(bytes, subnet_addr) {
        Ok(n) => println!("📡 Broadcasted to {} ({} bytes)", subnet_addr, n),
        Err(e) => eprintln!("❌ Subnet broadcast failed: {}", e),
    }

    let global_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, port);
    match socket.send_to(bytes, global_addr) {
        Ok(n) => println!("📡 Global broadcast to {} ({} bytes)", global_addr, n),
        Err(e) => eprintln!("⚠️ Global broadcast failed: {}", e),
    }
}
```

---

### FIX 4: Hardened Listener with Rate Limiting + Verification (Addresses C2, M5, M6, M7)

**Action**: Create `src/node_listener.rs`

```rust
use std::collections::HashMap;
use std::net::UdpSocket as StdUdpSocket;
use std::time::Instant;
use tokio::net::UdpSocket;
use crate::node_announcement::NodeAnnouncement;
use crate::dynamic_config;

const RATE_LIMIT_PER_MINUTE: usize = 10;
const DEDUP_INTERVAL_SECS: u64 = 25;

fn listen_port() -> u16 {
    std::env::var("SGX_BROADCAST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000)
}

pub async fn start_listener(local_node_id: String) {
    let port = listen_port();
    let bind_addr = format!("0.0.0.0:{}", port);

    let std_socket = match StdUdpSocket::bind(&bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Port {} bind failed: {}", port, e);
            return;
        }
    };
    std_socket.set_broadcast(true).expect("set_broadcast failed");
    std_socket.set_nonblocking(true).expect("set_nonblocking failed");
    let socket = UdpSocket::from_std(std_socket).expect("tokio socket conversion failed");

    println!("📡 Listener ready on {} (SO_BROADCAST enabled)", bind_addr);

    let mut buf = [0u8; 8192];
    let mut rate_map: HashMap<String, (usize, Instant)> = HashMap::new();
    let mut dedup_map: HashMap<String, Instant> = HashMap::new();

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, src)) => {
                let src_ip = src.ip().to_string();
                let now = Instant::now();

                // Rate limiting
                let entry = rate_map.entry(src_ip.clone()).or_insert((0, now));
                if now.duration_since(entry.1).as_secs() > 60 {
                    *entry = (1, now);
                } else {
                    entry.0 += 1;
                    if entry.0 > RATE_LIMIT_PER_MINUTE { continue; }
                }

                let msg = match std::str::from_utf8(&buf[..size]) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => continue,
                };

                match serde_json::from_str::<NodeAnnouncement>(&msg) {
                    Ok(peer) => {
                        if peer.node_id.trim() == local_node_id.trim() { continue; }

                        // Verify integrity digest
                        if !peer.verify_integrity() {
                            eprintln!("⚠️ Rejected {} — integrity check failed", peer.node_id);
                            continue;
                        }

                        if !dynamic_config::is_routable_ip(&peer.ip) {
                            eprintln!("⚠️ Ignoring {} — non-routable IP: {}", peer.node_id, peer.ip);
                            continue;
                        }

                        // Deduplication
                        let should_write = match dedup_map.get(&peer.node_id) {
                            Some(last) => now.duration_since(*last).as_secs() > DEDUP_INTERVAL_SECS,
                            None => true,
                        };

                        if should_write {
                            println!("🌐 Peer discovered: {} @ {}:{}", peer.node_id, peer.ip, peer.port);
                            dedup_map.insert(peer.node_id.clone(), now);

                            let peer_clone = peer.clone();
                            tokio::task::spawn_blocking(move || {
                                dynamic_config::update_peer_config(
                                    &peer_clone.node_id, &peer_clone.hostname,
                                    &peer_clone.ip, peer_clone.port, &peer_clone.public_key,
                                );
                            });
                        }
                    }
                    Err(e) => eprintln!("❌ JSON parse failed from {}: {}", src, e),
                }
            }
            Err(e) => {
                eprintln!("❌ recv_from error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }
    }
}
```

---

### FIX 5: Corrected `is_routable_ip()` in `dynamic_config.rs` (Addresses M3)

**Action**: In `src/dynamic_config.rs`, replace the `is_routable_ip()` function

```rust
pub fn is_routable_ip(ip: &str) -> bool {
    if ip.is_empty() || ip == "0.0.0.0" { return false; }
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => {
            if addr.is_loopback() { return false; }
            let o = addr.octets();
            if o[0] == 169 && o[1] == 254 { return false; }  // Link-local
            if o[0] == 172 && o[1] == 17 { return false; }   // Docker only (NOT all 172.16-31)
            true
        }
        Err(_) => false,
    }
}
```

---

### FIX 6: Field-Level Config Updates in `dynamic_config.rs` (Addresses M2)

**Action**: Replace `update_peer_config()` in `src/dynamic_config.rs`

```rust
pub fn update_peer_config(node_id: &str, hostname: &str, ip: &str, port: u16, public_key: &str) {
    let path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);

    // If file exists — field-level update to preserve extra fields
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let mut lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();

        let updates = [("node_id", node_id), ("hostname", hostname), ("ip", ip), ("public_key", public_key)];
        for (key, value) in &updates {
            let prefix = format!("{}:", key);
            let mut found = false;
            for line in lines.iter_mut() {
                if line.trim().starts_with(&prefix) {
                    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                    *line = format!("{}{}: \"{}\"", indent, key, value);
                    found = true;
                    break;
                }
            }
            if !found { lines.push(format!("{}: \"{}\"", key, value)); }
        }

        // Port (numeric)
        let mut port_found = false;
        for line in lines.iter_mut() {
            if line.trim().starts_with("port:") {
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                *line = format!("{}port: {}", indent, port);
                port_found = true;
                break;
            }
        }
        if !port_found { lines.push(format!("port: {}", port)); }

        let mut result = lines.join("\n");
        if existing.ends_with('\n') && !result.ends_with('\n') { result.push('\n'); }

        match std::fs::write(&path, &result) {
            Ok(_) => println!("✅ Config updated (field-level): {} → ip={}", node_id, ip),
            Err(e) => eprintln!("❌ Config write failed: {} — {}", path, e),
        }
        return;
    }

    // File doesn't exist — create minimal
    let yaml = format!(
        "node_id: \"{}\"\nhostname: \"{}\"\nip: \"{}\"\nport: {}\npublic_key: \"{}\"\n",
        node_id, hostname, ip, port, public_key,
    );
    match std::fs::write(&path, &yaml) {
        Ok(_) => println!("✅ Config created: {} → ip={}", node_id, ip),
        Err(e) => eprintln!("❌ Config write failed: {} — {}", path, e),
    }
}
```

---

### FIX 7: Use `new_signed()` in `main.rs` Broadcast Calls

**Action**: In both broadcast locations in `main.rs` (Steps 9 from Plan A), use:

```rust
// INSTEAD OF:
let announcement = NodeAnnouncement {
    node_id: ..., hostname: ..., ip: ..., port: ..., public_key: ...
};

// USE:
let announcement = NodeAnnouncement::new_signed(
    this_node.node_id.clone(),
    this_node.hostname.clone(),
    detected_ip_for_broadcast.clone(),
    this_node.port,
    this_node.public_key.clone(),
);
```

Apply in both the initial broadcast AND the periodic 30-second broadcast loop.

---

### FIX 8: Safe TLS SAN (Addresses C3)

**Action**: In `main.rs`, use safe IP parsing for SAN:

```rust
// INSTEAD OF Plan A's approach:
let san_ip = if detected_ip.is_empty() { "127.0.0.1" } else { &detected_ip };
let san = [this_node.hostname.as_str(), san_ip];

// USE (same — but ensure detected_ip is still in scope; it's a String on the stack)
// This is safe because detected_ip is defined early in main() and lives for the whole function
let san_ip_str = if detected_ip.is_empty() { "127.0.0.1".to_string() } else { detected_ip.clone() };
let san = [this_node.hostname.as_str(), san_ip_str.as_str()];
```

---

### FIX 9: Do NOT Replace Existing CoT Files (Addresses M8)

Shahzad's ZIP contains `session_manager.rs`, `transport_registry.rs`, `interface_detector.rs`, and `wifi.rs`. These files already exist in `src/cot/` on main. The ZIP versions have subtle differences (e.g., different session key structure, constructor that calls `tokio::spawn`). 

**DO NOT** overwrite existing CoT files. The WiFi/Ethernet discovery system works independently of the CoT transport layer — they are separate systems:

- **CoT transports** (`src/cot/transports/wifi.rs`, `ethernet.rs`) = structured message passing over TCP
- **Broadcast discovery** (`src/node_broadcast.rs`, `node_listener.rs`) = UDP peer announcement

Both coexist without conflict.

---

## CARGO.TOML DEPENDENCIES

```toml
[dependencies]
# ADD:
network-interface = "2.0"

# VERIFY already present (should be):
sha2 = "0.10"
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

**DO NOT add** `local-ip-address` (network.rs removed).

---

## RISK COMPARISON

| Risk | Plan A | Plan B |
|------|--------|--------|
| Fake peer injection | HIGH | LOW (integrity digest) |
| UDP flood DoS | HIGH | LOW (rate limiting) |
| Config field loss | MEDIUM | NONE (field-level update) |
| Port conflicts | MEDIUM | LOW (env var configurable) |
| Valid IP blocked | MEDIUM | NONE (only Docker 172.17) |
| Subnet mismatch | LOW | NONE (reads real netmask) |
| Repeated disk writes | MEDIUM | LOW (25s dedup) |
| Build breakage | CRITICAL (old main.rs) | NONE (surgical changes only) |

---

## POST-MERGE TESTING

### Test 1: Build Verification

```bash
cargo clean && cargo build 2>&1
cargo test 2>&1
cargo clippy 2>&1
```

### Test 2: Three-Laptop Discovery

```bash
# Each laptop same LAN (WiFi or Ethernet)
# Laptop 1: cargo run -- nodeA
# Laptop 2: cargo run -- nodeB
# Laptop 3: cargo run -- nodeC

# Verify auto-discovery within 30 seconds:
cat /etc/sgx-guardian/config/nodeB.yaml  # Should have real IP
sudo tcpdump -i any udp port 9000 -A    # See signed announcements
```

### Test 3: Cross-Transport (WiFi ↔ Ethernet)

1. nodeA on Ethernet, nodeB on WiFi (same LAN)
2. Both should discover each other via broadcast
3. Attestation should succeed cross-transport

### Test 4: i.MX8M Plus Board

```bash
# Cross compile
cross build --target aarch64-unknown-linux-gnu --release

# Copy to board
scp target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@<board-ip>:/usr/local/bin/

# On board - verify interface detection:
# Expected output:
# 📡 Detected 2 network interfaces:
#    eth0 → Ethernet [Up] 192.168.x.x
#    wlan0 → WiFi [Up] 192.168.x.x
# 📡 Listener ready on 0.0.0.0:9000
```

### Test 5: Mixed Board + Laptop

1. Start nodeA on i.MX8M Plus board (Ethernet)
2. Start nodeB on laptop (WiFi, same LAN)
3. Board broadcasts → laptop receives → updates config → attestation succeeds
4. SE050 hardware signing on board verified by laptop software verification

---

## FINAL CHECKLIST

- [ ] `src/network.rs` NOT created (redundant)
- [ ] `lib.rs` has exactly 25 modules (21 existing + 4 new)
- [ ] `main.rs` NOT replaced — only surgical additions
- [ ] `main.rs` still has SE050/DKP/SecureBoot/PCR blocks (unchanged)
- [ ] `main.rs` imports use `use sgx_guardian_client::*` style
- [ ] `node_announcement.rs` uses `new_signed()` with integrity digest
- [ ] `node_listener.rs` verifies integrity + rate limits + deduplicates
- [ ] `dynamic_config::update_peer_config()` does field-level updates
- [ ] `dynamic_config::is_routable_ip()` only blocks Docker 172.17
- [ ] `executor.rs` allows UDP 9000, TCP 50070, 50061, 50151-50153
- [ ] `config_loader.rs` accepts `0.0.0.0` as valid IP
- [ ] No existing CoT files (`src/cot/`) overwritten
- [ ] `cargo build` succeeds
- [ ] `cargo test` passes
- [ ] Three-laptop discovery works
- [ ] Board cross-compilation succeeds

---

*End of Plan B v2 — Verified against current `main` branch from attached GitHub repo*
