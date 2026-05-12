# PR #53 — Required Fixes
> Only CodeQL/CodeRabbit Critical+Major issues that need code changes.  
> CI Status: Build ✅ | CodeQL ❌ (4 High alerts remaining)  
> Board Freeze: ⚠️ NO `std::thread::sleep()` in async context.

---

## F-1 · Uncontrolled data used in path expression (logs handler)
- **Tool:** CodeQL
- **Severity:** 🟡 High
- **Location:** [`src/api/handlers/logs.rs`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/api/handlers/logs.rs)

**ADD** a `is_valid_node_id` check + `canonicalize` guard. The Copilot suggestion already shows the fix — add it before `read_dir`:

```rust
fn is_valid_node_id(node: &str) -> bool {
    !node.is_empty()
        && !node.contains("..")
        && !node.contains('/')
        && !node.contains('\\')
        && node.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}
```
Call `if !is_valid_node_id(&node) { return Err(ApiError::BadRequest(...)); }` before building any path.

---

## F-2 · Uncontrolled data used in path expression (node status handler)
- **Tool:** CodeQL
- **Severity:** 🟡 High
- **Location:** [`src/api/handlers/node.rs`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/api/handlers/node.rs)

The `status()` handler builds `format!("{}/{}.yaml", s.config_dir, node)` from user query param. **ADD** `canonicalize` + `starts_with` guard:

```rust
let base_dir = tokio::fs::canonicalize(&s.config_dir).await
    .map_err(|_| ApiError::Internal("invalid config directory".into()))?;
let candidate = base_dir.join(format!("{}.yaml", node));
let resolved = tokio::fs::canonicalize(&candidate).await
    .map_err(|_| ApiError::NotFound(format!("config for {} not found", node)))?;
if !resolved.starts_with(&base_dir) {
    return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
}
let text = tokio::fs::read_to_string(&resolved).await...
```

---

## F-3 · Cleartext logging of sensitive information (device_uid_fp)
- **Tool:** CodeQL
- **Severity:** 🟡 High
- **Location:** [`sgx-pa-cli/src/commands/pcr_baseline.rs`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/sgx-pa-cli/src/commands/pcr_baseline.rs)

CodeQL still flags the fingerprint. Replace the println entirely:

```rust
println!("   Device UID: [redacted]");
```

---

## F-4 · Fold integrity_status into the final verdict
- **Tool:** CodeRabbit
- **Severity:** 🔴 Critical
- **Location:** [`sgx-pa-cli/src/commands/attest_quote.rs#L250-L259`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/sgx-pa-cli/src/commands/attest_quote.rs#L250-L259)

`all_ok` ignores `integrity_status`. A quote with `integrity_status == "FAIL"` still returns ✅ VERIFIED.

**FIND:**
```rust
    let all_ok = nonce_ok && fresh && chain_ok && baseline_pass && sig_verified;
```
**REPLACE WITH:**
```rust
    let integrity_ok = matches!(integrity, "PASS" | "DEGRADED");
    let all_ok = nonce_ok && fresh && chain_ok && baseline_pass && sig_verified && integrity_ok;
```

Apply same fix at second verdict location (~line 425).

---

## F-5 · Reject path separators in node_id (cert_service)
- **Tool:** CodeRabbit
- **Severity:** 🔴 Critical
- **Location:** [`src/cert_service.rs`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/cert_service.rs)

`node_id` from gRPC request used in `nodes/{node_id}.crt` and `requests/{node_id}.yaml`.

**ADD** at start of `request_certificate`:
```rust
fn validate_node_id(node_id: &str) -> Result<(), Status> {
    if node_id.is_empty()
        || !node_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(Status::invalid_argument("invalid node_id"));
    }
    Ok(())
}
```
Call `validate_node_id(&node_id)?;` immediately after `let node_id = req.node_id.clone();`.

---

## F-6 · Validate node_id in cert_client paths
- **Tool:** CodeRabbit
- **Severity:** 🔴 Critical
- **Location:** [`src/cert_client.rs#L92-L93`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/cert_client.rs#L92-L93)

Same pattern — `node_id` interpolated into `{NEBULA_BASE_DIR}/nodes/{node_id}.crt`.

**ADD** at start of `request_certificate_from_ca`:
```rust
    if node_id.is_empty()
        || !node_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        eprintln!("❌ Invalid node_id for certificate bootstrap");
        return;
    }
```

---

## F-7 · Avoid silently defaulting on read/parse failures (boot_status)
- **Tool:** CodeRabbit
- **Severity:** 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/boot_status.rs#L12-L13`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/sgx-pa-cli/src/commands/boot_status.rs#L12-L13)

**FIND:**
```rust
            let json = fs::read_to_string(&path).unwrap_or_default();
            let status: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
```
**REPLACE WITH:**
```rust
            let json = match fs::read_to_string(&path) {
                Ok(v) => v,
                Err(err) => { eprintln!("  Failed to read: {}", err); return; }
            };
            let status: serde_json::Value = match serde_json::from_str(&json) {
                Ok(v) => v,
                Err(err) => { eprintln!("  Failed to parse: {}", err); return; }
            };
```

---

## F-8 · Cert day calculation truncation bug
- **Tool:** CodeRabbit
- **Severity:** 🔴 Critical
- **Location:** [`src/nebula/health.rs#L117-L119`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/nebula/health.rs#L117-L119)

Integer division truncates sub-day positive remaining AND negative expired to 0. Certs valid for 12h get deleted as expired.

**FIND:**
```rust
        Some(seconds_remaining / 86400)
```
**REPLACE WITH:**
```rust
        Some(seconds_remaining.div_euclid(86_400))
```

---

## F-9 · Missing cache eviction on "Member data not found"
- **Tool:** CodeRabbit
- **Severity:** 🟠 Major
- **Location:** [`src/cot/trust_engine.rs#L74-L88`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/cot/trust_engine.rs#L74-L88)

Three failure paths evict cache but this one doesn't. **ADD** before the `return`:
```rust
                self.verification_cache.write().await.remove(&computed_id);
```

---

## F-10 · Don't return PATH in HTTP error body
- **Tool:** CodeRabbit
- **Severity:** 🟠 Major
- **Location:** [`src/api/handlers/dkp.rs#L190-L195`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/api/handlers/dkp.rs#L190-L195)

**FIND:**
```rust
        ApiError::Internal(format!(
            "sgx-pa-cli not found. Set SGX_PA_CLI_PATH or ensure binary exists in PATH. PATH={}",
            path_env
        ))
```
**REPLACE WITH:**
```rust
        eprintln!("sgx-pa-cli not found. PATH={}", path_env);
        ApiError::Internal("sgx-pa-cli not found — check server logs".into())
```

---

## F-11 · Don't overwrite attestation results with quote
- **Tool:** CodeRabbit
- **Severity:** 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/attest_quote.rs#L128-L145`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/sgx-pa-cli/src/commands/attest_quote.rs#L128-L145)

`RESULTS_PATH` is a JSON array of verification results. Writing a signed quote there clobbers history.

**FIND:**
```rust
                    let _ = fs::write(RESULTS_PATH, serde_json::to_string_pretty(&signed).unwrap());
```
**REPLACE WITH:**
```rust
                    // Don't write generated quote to RESULTS_PATH — that file stores
                    // verification results (different schema). Quote already saved to QUOTE_PATH.
```

---

## F-12 · Registry save errors silently discarded
- **Tool:** CodeRabbit
- **Severity:** 🟡 Minor
- **Location:** [`src/cert_service.rs#L527-L543`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/cert_service.rs#L527-L543)

**FIND:**
```rust
        let _ = lh_reg.save(&lh_path);
```
**REPLACE WITH:**
```rust
        if let Err(e) = lh_reg.save(&lh_path) {
            eprintln!("⚠️ Failed to save lighthouse registry: {}", e);
        }
```
Same for `let _ = relay_reg.save(RELAY_REGISTRY_PATH);`.

---

## F-13 · Filter inactive relays from known_relay_ips
- **Tool:** CodeRabbit
- **Severity:** 🟠 Major
- **Location:** [`src/nebula/config.rs#L282-L308`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/nebula/config.rs#L282-L308)

**ADD** `.filter(|r| r.is_active)` to the relay registry iterator:
```rust
                    reg.relays
                        .values()
                        .filter(|r| r.is_active)  // ← ADD THIS
                        .filter(|r| r.node_name != node_name)
```

---

## F-14 · Listener failure path exits accept loop (DoS)
- **Tool:** CodeRabbit
- **Severity:** 🔴 Critical
- **Location:** [`src/attestation_service.rs#L1702-L1720`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/52-hardware_attestation/src/attestation_service.rs#L1702-L1720)

`return Ok(())` after a single bad attestation kills the listener. **REPLACE** `return Ok(())` with `continue` so the accept loop keeps running.

Also: `socket.peer_addr()` is ephemeral, not the trusted-peer key. Use the attestation payload's peer identity instead.

---

# Apply Checklist
```
F-1,F-2:  API path traversal (logs, node) → cargo build
F-3:      pcr_baseline device_uid redact → cargo build --bin sgx-pa-cli
F-4:      attest_quote integrity verdict → cargo build --bin sgx-pa-cli
F-5,F-6:  node_id validation (cert_service, cert_client) → cargo build
F-7:      boot_status parse errors → cargo build --bin sgx-pa-cli
F-8:      health.rs div_euclid → cargo build
F-9:      trust_engine cache eviction → cargo build
F-10:     dkp PATH leak → cargo build
F-11:     attest_quote results path → cargo build --bin sgx-pa-cli
F-12:     cert_service save errors → cargo build
F-13:     config.rs inactive relays → cargo build
F-14:     attestation listener continue → cargo build
Full test: cargo test -- --nocapture
Board smoke test: deploy, verify no freeze
```

**After applying: 0 CodeQL High remaining → CI unblocks.**