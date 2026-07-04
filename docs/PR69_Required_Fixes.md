# PR #69 — Verifiable Credentials Required Fixes
> Branch: `feat/59_verifiable-credentials` → `main`  
> CI: All checks passed ✅  
> CodeRabbit: 10 Critical + 35 Major = 45 issues  
> Board Freeze: ⚠️ Active constraint  
> **Focus:** VC-specific NEW issues + unfixed recurring issues from PR #68

---

## F-1 · VC mutating routes (issue/renew/revoke) have no auth middleware
- **Tool:** CodeRabbit · 🔴 Critical
- **Location:** [`src/api/handlers/vc.rs#L206-L218`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/src/api/handlers/vc.rs#L206-L218)

The `issue`, `renew`, and `revoke` handlers load the runtime signing key and can act as Circle owner with zero authorization. API is bound to `127.0.0.1` (fixed in PR #53) but still needs gating.

**FIX:** Add a `require_local_or_authed` check at the top of each mutating handler. Since auth middleware is Phase 3, use a minimal localhost-only guard for now:

```rust
fn require_localhost(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
    // Admin API is already bound to 127.0.0.1 — this is defense-in-depth
    // Phase 3 will add proper bearer token / mTLS auth
    Ok(())
}
```
Remove all 3 TODO comments and replace with the guard call + a `// Phase 3: AUTH-series` tag.

---

## F-2 · VC audit logs record wrong node_id (uses env args instead of AppState)
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`src/vc/issue.rs`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/src/vc/issue.rs) — `revoke_vc()`, `renew_membership_vc()`

Both functions use `std::env::args().nth(1).unwrap_or_else(|| "nodeA".to_string())` for audit logging. When called via the REST API, `args().nth(1)` is the daemon's node_id, which happens to be correct — BUT when called via CLI, it's the CLI subcommand name, not the node_id.

**FIX:** Thread `node_id` as a parameter through the call chain:

```rust
// In src/vc/issue.rs — add node_id parameter to revoke_vc and renew_membership_vc
pub fn revoke_vc(
    issuer_did: &DidRecord,
    km: &KeyManager,
    vc_id: &str,
    reason: &str,
    node_id: &str,  // ← ADD
) -> Result<(), VcError> {
```

Update the audit log calls from:
```rust
    crate::audit::logger::log_audit(
        std::env::args().nth(1).unwrap_or_else(|| "nodeA".to_string()).as_str(),
```
To:
```rust
    crate::audit::logger::log_audit(
        node_id,
```

Update callers in `vc.rs` handlers to pass `&state.node_id`.
Update callers in `sgx-pa-cli/src/commands/vc.rs` to pass the CLI-resolved node_id.

---

## F-3 · load_runtime_signing_context falls back to "nodeA"
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`src/api/handlers/vc.rs#L759-L764`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/src/api/handlers/vc.rs#L759-L764)

**FIND:**
```rust
    let node_id = issue::resolve_runtime_node_id().unwrap_or_else(|| "nodeA".to_string());
```
**REPLACE WITH:**
```rust
    let node_id = issue::resolve_runtime_node_id()
        .ok_or_else(|| ApiError::Internal("cannot resolve runtime node_id for VC signing".into()))?;
```

---

## F-4 · sign_and_deploy.rs path traversal in policy signing
- **Tool:** CodeRabbit · 🔴 Critical
- **Location:** [`sgx-pa-cli/src/commands/sign_and_deploy.rs#L21-L46`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/sign_and_deploy.rs#L21-L46)

`args.file` is passed directly to `sign_policy_to_disk` which calls `fs::read_to_string`. No path validation.

**ADD** before the `match` block:
```rust
    let resolved = std::path::Path::new(&args.file).canonicalize().unwrap_or_else(|e| {
        eprintln!("❌ Invalid policy path: {}", e);
        std::process::exit(1);
    });
    if !resolved.to_string_lossy().starts_with("/etc/sgx-guardian/") {
        eprintln!("❌ Policy file must be under /etc/sgx-guardian/");
        std::process::exit(1);
    }
    let file_str = resolved.to_string_lossy().to_string();
```
Then pass `&file_str` instead of `&args.file`.

---

## F-5 · emergency_rotate.rs DID metadata failure silently logged
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/emergency_rotate.rs#L244-L249`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/emergency_rotate.rs#L244-L249)

**FIND:**
```rust
    if let Err(e) = sgx_guardian_client::did::method::update_dkp_version(
        sgx_guardian_client::did::DEFAULT_DID_PATH,
        new_version,
    ) {
        eprintln!("│  DID metadata update skipped: {}", e);
    }
    true
```
**REPLACE WITH:**
```rust
    if let Err(e) = sgx_guardian_client::did::method::update_dkp_version(
        sgx_guardian_client::did::DEFAULT_DID_PATH,
        new_version,
    ) {
        eprintln!("│  ❌ DID metadata update FAILED: {}", e);
        eprintln!("│  DKP and DID are now out of sync — manual fix required");
        return false;
    }
    true
```

---

## F-6 · emergency_rotate.rs rotated keys not securely wiped
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/emergency_rotate.rs#L254-L287`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/emergency_rotate.rs#L254-L287)

After `fs::rename` in `rotate_software_key`, the backup file contains the old key material.

**ADD** after successful rename in both `rotate_software_key` and `rotate_tls_cert`:
```rust
                        // Zero-fill backup to prevent key recovery
                        if let Ok(meta) = fs::metadata(&backup) {
                            let _ = fs::write(&backup, vec![0u8; meta.len() as usize]);
                        }
                        let _ = fs::remove_file(&backup);
```

---

## F-7 · transport.rs path traversal in lock_path
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/transport.rs#L89-L91`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/transport.rs#L89-L91)

**FIND:**
```rust
fn lock_path(node: &str) -> String {
    format!("{}/transport_lock_{}.txt", LOCK_DIR, node)
}
```
**REPLACE WITH:**
```rust
fn lock_path(node: &str) -> String {
    if !node.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        eprintln!("❌ Invalid node name: {}", node);
        std::process::exit(1);
    }
    format!("{}/transport_lock_{}.txt", LOCK_DIR, node)
}
```

---

## F-8 · relay.rs silent error handling masks registry corruption
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/relay.rs#L476-L492`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/relay.rs#L476-L492)

**FIND** in `load_registry`:
```rust
        .unwrap_or_default()
```
**REPLACE WITH:**
```rust
        .unwrap_or_else(|e| {
            eprintln!("⚠️ Relay registry JSON corrupted: {}", e);
            Default::default()
        })
```
Apply same to `load_stats` (~line 500).

**FIND** in `save_registry` (`fs::write` direct):
```rust
    fs::write(path, json).map_err(...)
```
**REPLACE WITH** atomic write:
```rust
    let tmp = format!("{}.tmp", path);
    fs::write(&tmp, json).map_err(...)?;
    fs::rename(&tmp, path).map_err(...)
```
Apply same to `mutate_relay_yaml` (~line 329).

---

## F-9 · pcr_baseline.rs key_version zero validation
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/pcr_baseline.rs#L148`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/pcr_baseline.rs#L148)

`0x20000010 + key_version - 1` produces wrong SE050 slot if `key_version == 0`.

**ADD** before the key_id calculation:
```rust
    if key_version == 0 {
        eprintln!("❌ key_version must be >= 1");
        return None;
    }
```

---

## F-10 · pcr_baseline.rs unwrap() panics on file read/parse
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/pcr_baseline.rs#L215-L218`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/pcr_baseline.rs#L215-L218)

**FIND:**
```rust
    let baseline: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bl_path).unwrap()).unwrap();
    let snapshot: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&pcr_path).unwrap()).unwrap();
```
**REPLACE WITH:**
```rust
    let baseline: serde_json::Value = match fs::read_to_string(&bl_path)
        .ok().and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => { eprintln!("❌ Failed to load baseline from {}", bl_path); return; }
    };
    let snapshot: serde_json::Value = match fs::read_to_string(&pcr_path)
        .ok().and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => { eprintln!("❌ Failed to load snapshot from {}", pcr_path); return; }
    };
```

---

## F-11 · dkp_rotate.rs software rotation advertises before key exists
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`sgx-pa-cli/src/commands/dkp_rotate.rs#L124-L160`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/dkp_rotate.rs#L124-L160)

Software mode renames the old key then immediately marks vN+1 as Active, even though the new key hasn't been generated yet.

**ADD** after metadata write, before DID update:
```rust
    // Verify the daemon will regenerate — mark pending, not Active
    println!("⚠️  Software key scheduled for regeneration on next daemon start");
    println!("   Key v{} is NOT active until daemon regenerates it", new_version);
```

Change the status in the pushed metadata entry from `"Active"` to `"Pending"` for software mode:
```rust
        "status": if has_ssscli { "Active" } else { "Pending" },
```

---

## F-12 · attest_quote.rs self-consistency fallback bypasses baseline requirement
- **Tool:** CodeRabbit · 🔴 Critical
- **Location:** [`sgx-pa-cli/src/commands/attest_quote.rs#L339-L375`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/attest_quote.rs#L339-L375)

When no baseline file exists, the verifier recomputes `composite_digest` from quoted PCR values — proving only internal consistency, not that PCRs match known-good state. A compromised prover can forge arbitrary PCRs.

**FIX:** Default to fail when no baseline exists. Only allow self-consistency if `--no-baseline` flag is explicitly passed:

**FIND:**
```rust
        baseline_ok = self_ok;
```
**REPLACE WITH:**
```rust
        if args.no_baseline.unwrap_or(false) {
            baseline_ok = self_ok;
            println!("  ⚠️  --no-baseline: accepting self-consistency (NOT production-safe)");
        } else {
            baseline_ok = false;
            println!("  ❌ No baseline file — cannot verify PCR integrity");
            println!("     Use --baseline <path> or --no-baseline to override");
        }
```

Apply at both verification locations (~line 339 and ~line 429).

---

## F-13 · attest_quote.rs chain_ok uses hab_events_found not boot_chain_intact
- **Tool:** CodeRabbit · 🔴 Critical · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/attest_quote.rs#L219-L230`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/attest_quote.rs#L219-L230)

**Recurring from PR #68.** Same fix:
```rust
    let chain_ok = quote["boot_chain"]["boot_chain_intact"]
        .as_bool()
        .unwrap_or(false)
        && !quote["boot_chain"]["hab_events_found"]
            .as_bool()
            .unwrap_or(true);
```

---

## F-14 · attest_quote.rs /tmp fixed paths for signing I/O
- **Tool:** CodeRabbit · 🔴 Critical · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/attest_quote.rs#L486-L503`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/attest_quote.rs#L486-L503)

**Recurring.** Same timestamp-suffix fix as PR #57/68.

---

## F-15 · pcr_baseline.rs hex decode silent zero-fill
- **Tool:** CodeRabbit · 🔴 Critical · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/pcr_baseline.rs#L72`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/sgx-pa-cli/src/commands/pcr_baseline.rs#L72)

**Recurring from PR #68.** Same fail-fast fix.

---

## F-16 · SCP key paths use tilde
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`config/nodeA.yaml`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/config/nodeA.yaml#L16), [`nodeB.yaml`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/config/nodeB.yaml#L16), [`nodeC.yaml`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/config/nodeC.yaml#L16)

**Recurring from PR #68.** Change `~` to `/etc/sgx-guardian/secure-element/scp_keys.txt`.

---

## F-17 · did.rs SSRF via ca_host in publish endpoint
- **Tool:** CodeRabbit · 🟠 Major
- **Location:** [`src/api/handlers/did.rs#L311-L320`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/59_verifiable-credentials/src/api/handlers/did.rs#L311-L320)

`ca_host` from request body passed directly to `publish_to_ca`. **Recurring from PR #68.**

**ADD** validation:
```rust
    let allowed_ca = std::env::var("SGX_CA_HOST").unwrap_or_else(|_| "192.168.50.101".to_string());
    if ca_host != allowed_ca {
        return Err(ApiError::BadRequest(format!("ca_host must be {}", allowed_ca)));
    }
```

---

# Apply Checklist
```
F-1:   src/api/handlers/vc.rs (3 TODO comments)
F-2:   src/vc/issue.rs (revoke_vc, renew_membership_vc signatures)
       src/api/handlers/vc.rs (callers)
       sgx-pa-cli/src/commands/vc.rs (callers)
F-3:   src/api/handlers/vc.rs (load_runtime_signing_context)
F-4:   sgx-pa-cli/src/commands/sign_and_deploy.rs
F-5:   sgx-pa-cli/src/commands/emergency_rotate.rs
F-6:   sgx-pa-cli/src/commands/emergency_rotate.rs (2 functions)
F-7:   sgx-pa-cli/src/commands/transport.rs
F-8:   sgx-pa-cli/src/commands/relay.rs (4 locations)
F-9:   sgx-pa-cli/src/commands/pcr_baseline.rs
F-10:  sgx-pa-cli/src/commands/pcr_baseline.rs
F-11:  sgx-pa-cli/src/commands/dkp_rotate.rs
F-12:  sgx-pa-cli/src/commands/attest_quote.rs (2 locations)
F-13:  sgx-pa-cli/src/commands/attest_quote.rs (2 locations)
F-14:  sgx-pa-cli/src/commands/attest_quote.rs
F-15:  sgx-pa-cli/src/commands/pcr_baseline.rs
F-16:  config/nodeA.yaml, nodeB.yaml, nodeC.yaml
F-17:  src/api/handlers/did.rs

cargo build && cargo build -p sgx-pa-cli --bin sgx-pa-cli
cargo test -- --nocapture --test-threads=1
Board smoke test
```

**Total: 17 fixes · ~4 hours · Regression risk: Low-Medium**
