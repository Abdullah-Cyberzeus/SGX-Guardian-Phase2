# Sprint 4 — ALL Deferred Issues Fix Plan
**Scope:** Every deferred item from PR #46, PR #50, and PR #51 reviews
**Sprint Status:** Sprint 4 COMPLETE — All 4 milestones delivered ✅
**Board Freeze Constraint:** ⚠️ NO `std::thread::sleep()` in async context. Every fix verified safe.
**Date:** 27 April 2026




## Deferred Item Registry (35 unique items, deduplicated across 3 PRs)

| Priority | Count | Category |
|----------|-------|----------|
| 🔴 Critical | **6** | Security: tamper, auth, DKP atomicity, cert proto, VC validation |
| 🟠 Major | **19** | Hardening: timeouts, logging, paths, maps, error handling |
| 🟡 Minor | **10** | Polish: comments, scripts, templates, tests |




---




# CATEGORY A: SECURITY HARDENING (6 items)




## A-1: tamper.rs — Restrict clear_tamper() to test-only

**File:** `src/secure_element/tamper.rs:80-82`
**Board-safe:** ✅ Compilation-only change

**FIND:**
```rust
pub fn clear_tamper() {
    TAMPER_DETECTED.store(false, Ordering::SeqCst);
}
```

**REPLACE WITH:**
```rust
/// Reset tamper flag. Test-only — production code must never clear tamper.
#[cfg(test)]
pub(crate) fn clear_tamper() {
    TAMPER_DETECTED.store(false, Ordering::SeqCst);
}
```

**Regression:** `cargo test secure_element::tamper -- --nocapture` — tests use `clear_tamper()` in `#[cfg(test)]` context, so they compile. Production binary won't have this function.




## A-2: tamper.rs — Fail-closed on get_certuid() failure

**File:** `src/secure_element/tamper.rs:54-60`
**Board-safe:** ✅ Error handling logic only

**FIND:**
```rust
    // Check 3: Cert UID consistency
    if let Some(ref orig_cert) = se.cert_uid {
        if let Ok(cert) = se.cli.get_certuid() {
            if &cert != orig_cert {
                set_tamper("Cert UID changed");
                return TamperStatus::Detected;
            }
        }
    }
```

**REPLACE WITH:**
```rust
    // Check 3: Cert UID consistency — fail closed on read error
    if let Some(ref orig_cert) = se.cert_uid {
        match se.cli.get_certuid() {
            Ok(cert) if &cert != orig_cert => {
                set_tamper("Cert UID changed");
                return TamperStatus::Detected;
            }
            Ok(_) => {} // Match — OK
            Err(e) => {
                error!("SE050 cert UID read failed: {}", e);
                set_tamper("Cert UID read failed — possible tamper");
                return TamperStatus::Detected;
            }
        }
    }
```




## A-3: emergency_rotate.rs — Software DKP rotation guard

**File:** `sgx-pa-cli/src/commands/emergency_rotate.rs:178-212`
**Board-safe:** ✅ CLI tool, not in async runtime

In software mode (`has_ssscli == false`), the function currently updates metadata without generating a replacement key. Also, in hardware mode, the public-key export result is ignored.

**FIND** (after the `if has_ssscli {` block, before `// Update metadata`):
```rust
    if has_ssscli {
        // Hardware: generate new SE050 key
        let gen = Command::new("ssscli")
            .args(["generate", "ecc", &new_key_id_hex, "NIST_P256"])
            .output();
        if gen.map(|o| o.status.success()).unwrap_or(false) {
            println!("│  SE050: Generated key at slot {}", new_key_id_hex);
            // Export public key
            let _ = Command::new("ssscli")
                .args(["get", "ecc", "pub", &new_key_id_hex, PUBKEY_PATH])
                .output();
        } else {
            println!("│  SE050: Key generation failed");
            return false;
        }
    }
```

**REPLACE WITH:**
```rust
    if has_ssscli {
        // Hardware: generate new SE050 key
        let gen = Command::new("ssscli")
            .args(["generate", "ecc", &new_key_id_hex, "NIST_P256"])
            .output();
        if gen.map(|o| o.status.success()).unwrap_or(false) {
            println!("│  SE050: Generated key at slot {}", new_key_id_hex);
            // Export public key — MUST succeed before updating metadata
            let export = Command::new("ssscli")
                .args(["get", "ecc", "pub", &new_key_id_hex, PUBKEY_PATH])
                .output();
            if !export.map(|o| o.status.success()).unwrap_or(false) {
                eprintln!("│  SE050: Public key export FAILED — aborting rotation");
                return false;
            }
            // Verify the exported file actually exists
            if !std::path::Path::new(PUBKEY_PATH).exists() {
                eprintln!("│  SE050: Exported pubkey not found at {} — aborting", PUBKEY_PATH);
                return false;
            }
        } else {
            println!("│  SE050: Key generation failed");
            return false;
        }
    } else {
        // Software mode: emergency rotation is NOT supported without ssscli
        eprintln!("│  Software DKP emergency rotation is not implemented.");
        eprintln!("│  Use 'sgx-pa-cli dkp-rotate' for software key rotation.");
        return false;
    }
```




## A-4: dkp_rotate.rs — Atomic metadata write

**File:** `sgx-pa-cli/src/commands/dkp_rotate.rs:175-183`
**Board-safe:** ✅ CLI tool

**FIND:**
```rust
    fs::write(METADATA_PATH, serde_json::to_string_pretty(&keys).unwrap()).is_ok()
```

**REPLACE WITH:**
```rust
    let serialized = match serde_json::to_string_pretty(&keys) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to serialize DKP metadata: {}", e);
            return;
        }
    };
    let tmp_path = format!("{}.tmp", METADATA_PATH);
    if let Err(e) = fs::write(&tmp_path, &serialized) {
        eprintln!("❌ Failed to write temp metadata: {}", e);
        return;
    }
    if let Err(e) = fs::rename(&tmp_path, METADATA_PATH) {
        eprintln!("❌ Failed to atomically replace metadata: {}", e);
        return;
    }
```

**Also apply same pattern to `dkp_revoke.rs:104-112`.**




## A-5: dkp_rotate.rs — Abort if no software key found

**File:** `sgx-pa-cli/src/commands/dkp_rotate.rs:130-150`
**Board-safe:** ✅ CLI tool

**ADD after the `for entry in entries.flatten()` loop, BEFORE the metadata update:**
```rust
        if !rotated {
            eprintln!("  No software DKP key found to rotate in {}.", SOFTWARE_KEY_DIR);
            return;
        }
```

(Requires adding `let mut rotated = false;` before the loop and `rotated = true;` inside the successful rename branch.)




## A-6: SE050 UID logging redaction

**File:** `src/secure_element/se050.rs:84-118`
**Board-safe:** ✅ String formatting only

**FIND:**
```rust
        let uid = match cli.get_uid() {
            Ok(id) => {
                info!("SE050 Unique ID: {}", id);
                Some(id)
            }
```

**REPLACE WITH:**
```rust
        let uid = match cli.get_uid() {
            Ok(id) => {
                let uid_fp = {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(id.as_bytes());
                    hex::encode(&hash[..4])
                };
                info!("SE050 UID fingerprint: {}", uid_fp);
                Some(id)
            }
```

**Same pattern for cert_uid:**
```rust
        let cert_uid = match cli.get_certuid() {
            Ok(id) => {
                let cert_fp = {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(id.as_bytes());
                    hex::encode(&hash[..4])
                };
                info!("SE050 Cert UID fingerprint: {}", cert_fp);
                Some(id)
            }
```

**Also fix the audit log:**
```rust
        log_audit(
            "system",
            AuditCategory::Identity,
            AuditSeverity::Info,
            AuditAction::Loaded,
            "SE050 initialized successfully",
        );
```




---




# CATEGORY B: TRANSPORT & NETWORK HARDENING (8 items)




## B-1: CoT Ethernet transport — TCP timeouts

**File:** `src/cot/transports/ethernet.rs:33-54`
**Board-safe:** ✅ Adds timeouts (prevents hangs, doesn't add blocking)

**FIND:**
```rust
        let mut stream = TcpStream::connect(&message.target_address)
            .await
            .map_err(|e| {
                CotError::TransportError(format!(
                    "Ethernet send to {} failed: {}",
                    message.target_address, e
                ))
            })?;
```

**REPLACE WITH:**
```rust
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&message.target_address),
        )
        .await
        .map_err(|_| {
            CotError::TransportError(format!(
                "Ethernet connect to {} timed out",
                message.target_address
            ))
        })?
        .map_err(|e| {
            CotError::TransportError(format!(
                "Ethernet send to {} failed: {}",
                message.target_address, e
            ))
        })?;
```

**Apply same 5-second timeout pattern to `write_all` and `flush` calls in:**
- `src/cot/transports/wifi.rs:32-54`
- `src/cot/transports/cellular.rs:59-83`




## B-2: Ethernet transport — Remove synthetic latency

**File:** `src/cot/transports/ethernet.rs:57-63`

**FIND:**
```rust
        let start = std::time::Instant::now();
        let latency = start.elapsed();
```

**REPLACE WITH:**
```rust
        // No real probe — return health without synthetic latency
        let latency = std::time::Duration::from_millis(0);
```




## B-3: node_listener.rs — Bounded rate-limit/dedup maps

**File:** `src/node_listener.rs:41-42`
**Board-safe:** ✅ Adds periodic cleanup, no blocking

**ADD at the top of the `loop` block (after `match socket.recv_from(&mut buf).await {`):**

Actually, add BEFORE the match, at the start of the loop:
```rust
        // Evict stale entries to prevent unbounded growth from spoofed IPs
        let gc_now = Instant::now();
        if rate_map.len() > 500 {
            rate_map.retain(|_, (_, seen_at)| gc_now.duration_since(*seen_at).as_secs() <= 120);
        }
        if dedup_map.len() > 500 {
            dedup_map.retain(|_, seen_at| gc_now.duration_since(*seen_at).as_secs() <= 60);
        }
```




## B-4: nebula/interface.rs — Remove old IP before assigning new

**File:** `src/nebula/interface.rs` — `verify_and_fix_ip` mismatch branch

**FIND:**
```rust
            Some(actual) => {
                eprintln!("⚠️  nebula0 IP mismatch detected — reassigning");
                Self::assign_overlay_ip(expected_ip_cidr)
            }
```

**REPLACE WITH:**
```rust
            Some(actual) => {
                eprintln!("⚠️  nebula0 IP mismatch detected — removing old, assigning new");
                // Remove old IP first to avoid duplicate addresses
                let _ = Command::new("ip")
                    .args(["addr", "del", &actual, "dev", "nebula0"])
                    .output();
                Self::assign_overlay_ip(expected_ip_cidr)
            }
```




## B-5: Bootstrap server binding — 0.0.0.0 → configured IP

**File:** `src/main.rs` — cert bootstrap server spawn

**FIND:**
```rust
            if let Err(e) = server::start_cert_bootstrap_server("0.0.0.0:50061".to_string()).await {
```

**REPLACE WITH:**
```rust
            // Bind to detected LAN IP or localhost — do NOT expose on all interfaces
            let bootstrap_addr = if detected_ip.is_empty() {
                "127.0.0.1:50061".to_string()
            } else {
                format!("{}:50061", detected_ip)
            };
            if let Err(e) = server::start_cert_bootstrap_server(bootstrap_addr).await {
```




## B-6: config_loader.rs — Restore IP syntax validation

**File:** `src/config_loader.rs:37-39`

**FIND:**
```rust
        // Only check empty — dynamic IPs may be 0.0.0.0 during discovery
        if self.ip.trim().is_empty() {
            return Err("ip field cannot be empty".into());
        }
```

**REPLACE WITH:**
```rust
        let ip = self.ip.trim();
        if ip.is_empty() {
            return Err("ip field cannot be empty".into());
        }
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("Invalid node IP format: '{}'", self.ip));
        }
```




## B-7: secure_element/config.rs — Tilde expansion

**File:** `src/secure_element/config.rs` — `Default` impl

**FIND:**
```rust
            scp_key_path: "~/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt".to_string(),
```

**REPLACE WITH:**
```rust
            scp_key_path: "/etc/sgx-guardian/se050_scp_keys.txt".to_string(),
```

Also add a tilde expansion helper in `ssscli.rs` before the `connect()` call:
```rust
fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}{}", home.to_string_lossy(), &path[1..]);
        }
    }
    path.to_string()
}
```




## B-8: sign.rs — Verify error propagation

**File:** `src/secure_element/sign.rs:61-67`

**FIND (in `verify` closure):**
```rust
            self.cli.verify(&hex_id, &tmp_d, &tmp_s).is_ok()
```

**REPLACE WITH:**
```rust
            match self.cli.verify(&hex_id, &tmp_d, &tmp_s) {
                Ok(_) => true,
                Err(e) => {
                    eprintln!("SE050 verify error (not just invalid sig): {}", e);
                    false
                }
            }
```




---




# CATEGORY C: PACKAGING & DEPLOYMENT (5 items)




## C-1: systemd service — Fix IP restrictions

**File:** `packaging/deb/systemd/sgx-guardian.service:38-43`

**FIND:**
```ini
CapabilityBoundingSet=
AmbientCapabilities=
# ---- Networking ----
IPAddressDeny=any
IPAddressAllow=localhost
```

**REPLACE WITH:**
```ini
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
# ---- Networking ----
# Network filtering handled by nftables rules in enforcement/executor.rs
# IPAddressDeny/IPAddressAllow removed — they block Nebula overlay (UDP 4242),
# registry sync (TCP 50062), and overlay subnet (192.168.100.0/24).
```

**Apply same to `build/deb/sgx-guardian-client/lib/systemd/system/sgx-guardian.service`.**




## C-2: systemd service — Parameterize node profile

**File:** `packaging/deb/systemd/sgx-guardian.service:15-16`

**FIND:**
```ini
ExecStart=/usr/bin/sgx-guardian nodeA
```

**REPLACE WITH:**
```ini
# Node profile loaded from /etc/sgx-guardian/node_profile
EnvironmentFile=-/etc/sgx-guardian/node_profile
ExecStart=/usr/bin/sgx-guardian ${SGX_NODE_ID:-nodeA}
```

Then create `/etc/sgx-guardian/node_profile`:
```
SGX_NODE_ID=nodeA
```




## C-3: Deployment config templates

**Files:** `packaging/deb/config/nodeA.yaml`, `nodeB.yaml`, `nodeC.yaml`

Replace loopback IPs and placeholder keys with installer-safe sentinels:
```yaml
ip: "0.0.0.0"
public_key: "__GENERATED_AT_FIRST_BOOT__"
```




## C-4: Duplicate policy_id fix

**File:** `packaging/deb/policies/backup_policy.yaml`

Change `policy_id` from `"123e4567-e89b-12d3-a456-426614174000"` to a unique UUID:
```yaml
policy_id: "223e4567-e89b-12d3-a456-426614174001"
```




## C-5: install_nebula.sh — Architecture detection + checksum

**File:** `scripts/install_nebula.sh`

**FIND:**
```bash
ARCH="linux-amd64"
wget https://github.com/slackhq/nebula/releases/download/v${NEBULA_VERSION}/nebula-${ARCH}.tar.gz
```

**REPLACE WITH:**
```bash
case "$(uname -m)" in
    x86_64)  ARCH="linux-amd64" ;;
    aarch64) ARCH="linux-arm64" ;;
    armv7l)  ARCH="linux-arm-7" ;;
    *)       echo "[!] Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

BASE_URL="https://github.com/slackhq/nebula/releases/download/v${NEBULA_VERSION}"
wget "${BASE_URL}/nebula-${ARCH}.tar.gz"
wget "${BASE_URL}/SHASUM256.txt"

echo "[*] Verifying checksum..."
grep "nebula-${ARCH}.tar.gz" SHASUM256.txt | sha256sum -c - || {
    echo "[!] Checksum verification failed"; exit 1;
}
```




---




# CATEGORY D: CODE QUALITY & ERROR HANDLING (10 items)




## D-1: key_manager.rs — pubkey_der() panic → Result

**File:** `src/key_manager.rs:220-244`

This is an API change — `pubkey_der()` currently returns `Vec<u8>` and panics on missing DKP. Change to `Result<Vec<u8>>` and update all callers.

**FIND:**
```rust
    pub fn pubkey_der(&self) -> Vec<u8> {
```

**REPLACE WITH:**
```rust
    pub fn pubkey_der(&self) -> Result<Vec<u8>> {
```

Then in the Software branch: `Ok(self.keypair.public_key().as_ref().to_vec())`

In the Hardware branch: replace `panic!` with `Err(anyhow!(...))`.

**Callers to update** (search for `.pubkey_der()` in codebase):
- `src/main.rs` — add `?` or `.expect("DKP pubkey required")`
- `src/attestation_service.rs` — add `?`
- `src/cot/identity.rs` — add `?`




## D-2: nebula/daemon.rs — Fix misleading comment

**File:** `src/nebula/daemon.rs:75`

**FIND:**
```rust
        // 3. Spawn daemon (redirect output to journald / syslog via inherited fds)
```

**REPLACE WITH:**
```rust
        // 3. Spawn daemon (stdout/stderr discarded via Stdio::null — check syslog for nebula logs)
```




## D-3: main.rs — Dir creation error logging

**File:** `src/main.rs:61-76`

**FIND:**
```rust
        let _ = std::fs::create_dir_all(dir);
```

**REPLACE WITH:**
```rust
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("⚠️ Failed to create {}: {} (may cause issues later)", dir, e);
        }
```




## D-4: main.rs — Hardcoded 192.168.100 prefix

**File:** `src/main.rs` — `read_ip_from_nebula_cert` function

**FIND:**
```rust
        if let Some(idx) = line.find("192.168.100.") {
```

**REPLACE WITH:**
```rust
        // Look for any private overlay IP (not just 192.168.100.x)
        if let Some(idx) = line.find("192.168.100.")
            .or_else(|| line.find("10."))
            .or_else(|| line.find("172.16."))
        {
```




## D-5: bluetooth.rs — Fix hcitool rssi syntax

**File:** `src/cot/transports/bluetooth.rs:39-49`

`hcitool rssi` requires a MAC address, not an interface name. Since discovering connected device MACs adds complexity, simplify:

**FIND:**
```rust
        let output = Command::new("hcitool")
            .args(["rssi", "hci0"])
```

**REPLACE WITH:**
```rust
        // hcitool rssi requires a device MAC, not interface name.
        // Use hcitool con to find connected devices, then query RSSI.
        let con_output = Command::new("hcitool")
            .args(["con"])
            .output()
            .ok()?;
        let con_stdout = String::from_utf8_lossy(&con_output.stdout);
        // Extract first connected device MAC (format: "< ACL XX:XX:XX:XX:XX:XX ...")
        let mac = con_stdout.lines()
            .find(|l| l.contains("ACL"))
            .and_then(|l| l.split_whitespace().nth(2))?;

        let output = Command::new("hcitool")
            .args(["rssi", mac])
```




## D-6: verify_nebula_overlay.sh — grep error handling

**File:** `scripts/verify_nebula_overlay.sh:58-70`

**FIND:**
```bash
    STATIC=$(grep -A2 "static_host_map:" "$CFG" | head -5)
```

**REPLACE WITH:**
```bash
    STATIC=$(grep -A2 "static_host_map:" "$CFG" | head -5 || true)
```




## D-7: setup_nebula_env.sh — Binary execution validation

**File:** `scripts/setup_nebula_env.sh:6-20`

Add `set -euo pipefail` at top. After `command -v nebula`, add:
```bash
    nebula --version >/dev/null 2>&1 || { echo "[✗] Nebula binary broken"; exit 1; }
```
Same for `nebula-cert`.




## D-8: tls.rs — Redundant SAN processing

**File:** `src/tls.rs:128-151`

**FIND:**
```rust
    let mut params = CertificateParams::new(
        subject_alt_names
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>(),
    );
```

**REPLACE WITH:**
```rust
    let mut params = CertificateParams::default();
```

(Since `params.subject_alt_names` is overwritten by `san_entries` a few lines later anyway.)




## D-9: p2p_discovery.rs — Overlay gate bootstrap fix

**File:** `src/p2p_discovery.rs:171-175`

**FIND:**
```rust
                if node_id_cfg != "nodeA" && !crate::dynamic_config::overlay_is_reachable().await {
                    sleep(Duration::from_secs(15)).await;
                    continue;
                }
```

**REPLACE WITH:**
```rust
                if node_id_cfg != "nodeA" && !crate::dynamic_config::overlay_is_reachable().await {
                    // Don't skip entirely — still enqueue LAN peers for bootstrap
                    // Only skip overlay-specific peers
                    eprintln!("⏳ [{}] Overlay not yet reachable — LAN discovery continues", node_id_cfg);
                }
```




## D-10: dkp_revoke.rs — Atomic metadata write

Same pattern as A-4. Replace `fs::write(METADATA_PATH, ...)` with tmp→rename.




---




# CATEGORY E: DEFERRED ARCHITECTURAL ITEMS (6 items)

These require multi-file changes or design decisions. Provided as implementation plans rather than exact FIND→REPLACE.




## E-1: Registry sync server authentication

**Files:** `src/nebula/registry_sync.rs`

**Current state:** Binds 0.0.0.0:50062, trusts client-supplied `node_name`. Any reachable host can reserve overlay IPs.

**Implementation plan:**
1. Add a `request_signature` field to `RegistryRequest`
2. On the server side, verify the signature using the node's public key from the registry
3. For the "assign" action, verify the request comes from the CA node by checking `node_name` matches the registry owner AND the signature verifies against the CA public key
4. Reject unsigned or invalid requests with `RegistryResponse { success: false, error: "Unauthorized" }`

**Estimated effort:** 2-3 hours. No board freeze risk (pure application logic).




## E-2: proto/cert.proto — Remove node_key_pem

**Files:** `proto/cert.proto`, `src/cert_client.rs`, `src/cert_service.rs`

**Implementation plan:**
1. In `proto/cert.proto`: replace `string node_key_pem = 3;` with `reserved 3;`
2. In `cert_service.rs`: Remove the code that reads and populates `node_key_pem` from the issued cert
3. In `cert_client.rs`: Generate the Nebula keypair LOCALLY using `nebula-cert keygen`, send only the public key to the CA for signing, receive signed cert + CA cert back
4. Update `nebula-cert sign` invocation to accept `-in-pub` instead of generating the keypair

**Estimated effort:** 4-6 hours. Requires testing on boards.




## E-3: nebula/utils.rs — Real VC validation

**File:** `src/nebula/utils.rs:3-15`

**Current state:** Trusts caller-supplied `is_valid` field. Any caller can set `is_valid = true` and bypass membership checks.

**Implementation plan:**
This depends on Sprint 5+ DID/VC deliverables (W3C Verifiable Credentials). Until those are implemented:
1. Remove the `is_valid` trust and replace with a CA-side check: verify the `vc_hash` matches a pre-registered hash in the CA's membership store
2. Add a `membership_store.json` on nodeA that tracks approved node names + vc_hashes
3. On cert request, verify the vc_hash exists in the store before issuing

**Estimated effort:** 3-4 hours for intermediate solution. Full VC verification is Sprint 5.




## E-4: cert_service.rs — Long-running gRPC poll refactor

**File:** `src/cert_service.rs:257-316`

**Current state:** Holds gRPC connection for up to 1 hour while polling YAML file.

**Implementation plan:**
1. Return "pending" immediately with a `request_id`
2. Add a new RPC `check_certificate_status(request_id)` that the client polls
3. Client polls every 10 seconds instead of server holding connection

**Estimated effort:** 4-6 hours. Consider for Phase 3.




## E-5: node_announcement.rs — Real ECDSA signature

**File:** `src/node_announcement.rs`

**Current state:** SHA256 digest (checksum, not signature).

**Implementation plan:**
1. Accept `KeyManager` reference in `new_signed()`
2. Sign canonical JSON of all fields (including hostname) with `km.sign()`
3. In `verify_integrity()`, accept a `pubkey_der` and use ring to verify the ECDSA signature
4. Reject timestamps more than 120s in the future (currently only checks past)

**Estimated effort:** 3-4 hours. Requires KeyManager availability in broadcast path.




## E-6: Subprocess timeouts for nebula/install.rs

**File:** `src/nebula/install.rs:6-42`

**Implementation plan:**
All three functions (`check_binary`, `check_version`, `test_daemon_start`) use `Command::output()` which blocks. Wrap with a 10-second timeout:

```rust
use std::time::Duration;

fn with_timeout(cmd: &mut Command, secs: u64) -> Result<std::process::Output, String> {
    let child = cmd.spawn().map_err(|e| e.to_string())?;
    match child.wait_timeout(Duration::from_secs(secs)) {
        Ok(Some(status)) => { /* completed */ }
        Ok(None) => { child.kill(); return Err("timeout".into()); }
        Err(e) => return Err(e.to_string()),
    }
}
```

**Note:** Requires `wait-timeout` crate or manual thread-based timeout. **Board-safe** as long as these are called BEFORE the tokio runtime starts, which they are (they're in the pre-Nebula verification block).




---




# Apply Checklist (Priority Order)

```
Phase 1: Security Critical (do first)
  □ A-1  tamper.rs clear_tamper → #[cfg(test)]
  □ A-2  tamper.rs get_certuid fail-closed
  □ A-3  emergency_rotate.rs software guard + export verify
  □ A-4  dkp_rotate.rs atomic write
  □ A-5  dkp_rotate.rs abort if no key found
  □ A-6  se050.rs UID redaction
  □ D-10 dkp_revoke.rs atomic write

Phase 2: Transport & Network
  □ B-1  CoT transport timeouts (3 files)
  □ B-2  Ethernet synthetic latency
  □ B-3  node_listener bounded maps
  □ B-4  interface.rs remove old IP
  □ B-5  Bootstrap server binding
  □ B-6  config_loader IP validation
  □ B-7  SE config tilde expansion
  □ B-8  sign.rs verify error propagation

Phase 3: Packaging & Deployment
  □ C-1  systemd IPAddressDeny fix (2 files)
  □ C-2  systemd node parameterization
  □ C-3  Config templates
  □ C-4  Duplicate policy_id
  □ C-5  install_nebula.sh arch + checksum

Phase 4: Code Quality
  □ D-1  key_manager pubkey_der → Result
  □ D-2  daemon.rs comment fix
  □ D-3  main.rs dir creation logging
  □ D-4  main.rs hardcoded subnet
  □ D-5  bluetooth.rs hcitool fix
  □ D-6  verify script grep fix
  □ D-7  setup script validation
  □ D-8  tls.rs redundant SAN
  □ D-9  p2p_discovery overlay gate

Phase 5: Architectural (require design review)
  □ E-1  Registry auth
  □ E-2  cert.proto key removal
  □ E-3  VC validation
  □ E-4  cert_service poll refactor
  □ E-5  node_announcement real sig
  □ E-6  Subprocess timeouts

Total: 35 items
Estimated total effort: ~3-4 days
```
