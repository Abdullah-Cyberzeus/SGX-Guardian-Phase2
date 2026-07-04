# PR #70 — NMAP Network Discovery Required Fixes
> Branch: `feat/60_nmap` → `main`  
> CI: Build ✅ (40m) | CodeQL ❌ (failing) | CodeRabbit ✅  
> CodeRabbit: 4 Critical + 35 Major = 39 issues  
> **Focus:** NMAP-specific NEW issues + unfixed recurring from PR #68/#69

---

## F-1 · Validate node names before building config paths (relay CLI)
- **Tool:** CodeRabbit · 🔴 Critical · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/relay.rs#L217-L218`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/relay.rs#L217-L218)

`args.node` interpolated into path without validation. Apply at 3 locations (~L217, ~L267, ~L450).

**ADD** helper:
```rust
fn validate_node_name(node: &str) -> Result<()> {
    if node.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        Ok(())
    } else {
        Err(anyhow!("invalid node name '{}'", node))
    }
}
```
Call `validate_node_name(&args.node)?;` at the start of `run_set_limit`, `run_toggle`, and the third caller.

---

## F-2 · RPM systemd IPAddressAllow missing localhost
- **Tool:** CodeRabbit · 🔴 Critical
- **Location:** [`packaging/rpm/systemd/sgx-guardian.service#L43-L44`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/packaging/rpm/systemd/sgx-guardian.service#L43-L44)

API binds to `127.0.0.1`, Nebula stats on `127.0.0.1:8625`. `IPAddressDeny=any` blocks them.

**FIND:**
```ini
IPAddressAllow=192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
```
**REPLACE WITH:**
```ini
IPAddressAllow=127.0.0.1/8 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
```

---

## F-3 · pcr_baseline.rs hex decode silent zero-fill
- **Tool:** CodeRabbit · 🔴 Critical · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/pcr_baseline.rs#L72`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/pcr_baseline.rs#L72)

**Recurring from PR #68/#69.** Same fail-fast fix:
```rust
    let composite_bytes = match hex::decode(&composite) {
        Ok(v) => v,
        Err(_) => { eprintln!("❌ Invalid composite_digest"); return; }
    };
```

---

## F-4 · pcr_baseline.rs /tmp paths still predictable
- **Tool:** CodeRabbit · 🔴 Critical · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/pcr_baseline.rs#L153-L155`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/pcr_baseline.rs#L153-L155)

**Recurring.** Already timestamp-suffixed on this branch — verify it's actually using `ts` not fixed names. If still fixed, apply same suffix fix.

---

## F-5 · discovery.rs unwrap_or_default silences config corruption
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/discovery.rs#L133`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/discovery.rs#L133)

3 locations (~L133, ~L291, ~L307) silently default on broken config.

**FIND:**
```rust
    let cfg = NmapConfig::load(Path::new(CONFIG_PATH)).unwrap_or_default();
```
**REPLACE WITH:**
```rust
    let cfg = match NmapConfig::load(Path::new(CONFIG_PATH)) {
        Ok(cfg) => cfg,
        Err(e) if !Path::new(CONFIG_PATH).exists() => NmapConfig::default(),
        Err(e) => { eprintln!("❌ Failed to load {}: {}", CONFIG_PATH, e); return; }
    };
```

---

## F-6 · discovery.rs Inventory::load format mismatch with list command
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/discovery.rs#L187-L188`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/discovery.rs#L187-L188)

Write uses `Inventory::save_atomic`, read uses `serde_json::from_slice::<Vec<ConnectedDevice>>`. Schema mismatch.

**REPLACE WITH:**
```rust
    let inv = Inventory::load(&PathBuf::from(INVENTORY_PATH))?;
    let mut devices: Vec<ConnectedDevice> = inv.by_id.into_values().collect();
```

---

## F-7 · nmap.yaml intensity "standard" not in stealth/aggressive contract
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`config/discovery/nmap.yaml#L6-L9`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/config/discovery/nmap.yaml#L6-L9)

**FIND:**
```yaml
  hourly:
    intensity: standard
```
**REPLACE WITH:**
```yaml
  hourly:
    intensity: stealth
```

---

## F-8 · relay.rs silent error handling + non-atomic writes
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/relay.rs#L481-L500`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/relay.rs#L481-L500)

**Recurring from PR #69.** Same fixes: surface parse errors + atomic tmp→rename writes.

---

## F-9 · verify_audit_chain.py ignores UTF-8 decode errors
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`scripts/verify_audit_chain.py#L30`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/scripts/verify_audit_chain.py#L30)

**FIND:**
```python
    for idx, line in enumerate(path.open("r", encoding="utf-8", errors="ignore"), start=1):
```
**REPLACE WITH:**
```python
    try:
        fh = path.open("r", encoding="utf-8")
    except OSError as e:
        print(f"ERROR: cannot open log file: {e}", file=sys.stderr)
        sys.exit(2)
    for idx, line in enumerate(fh, start=1):
```

---

## F-10 · build.sh setcap on nmap in build script
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`scripts/build.sh#L227`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/scripts/build.sh#L227)

Build should NOT alter host binary capabilities. **DELETE** the line:
```bash
  as_root setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" || true
```

---

## F-11 · build.sh retry_forever can hang CI indefinitely
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`scripts/build.sh#L70-L89`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/scripts/build.sh#L70-L89)

**ADD** at top of function:
```bash
    if (( attempt >= ${RETRY_MAX_ATTEMPTS:-20} )); then
      die "${what} failed after ${attempt} attempts"
    fi
```

---

## F-12 · build.sh unlocked fallback bypasses lockfile
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`scripts/build.sh#L316-L321`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/scripts/build.sh#L316-L321)

**REPLACE** silent fallback with gated flag:
```bash
    if [[ "${ALLOW_UNLOCKED_FALLBACK:-0}" == "1" ]]; then
      warn "Retrying without --locked (ALLOW_UNLOCKED_FALLBACK=1)..."
      # existing cargo build without --locked
    else
      die "Build with --locked failed."
    fi
```

---

## F-13 · install.sh install_nmap fatal despite non-fatal intent
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`scripts/install.sh#L24`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/scripts/install.sh#L24)

**FIND:**
```bash
install_nmap
```
**REPLACE WITH:**
```bash
if ! install_nmap; then
    echo "⚠ nmap install failed. Continuing without hard-fail."
fi
```

---

## F-14 · RPM spec setcap on global nmap binary
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`packaging/rpm/SPECS/sgx-guardian-client.spec#L57-L60`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/packaging/rpm/SPECS/sgx-guardian-client.spec#L57-L60)

**REPLACE** setcap with comment:
```bash
# Keep nmap privileges scoped in systemd unit; do not set file capabilities on /usr/bin/nmap.
```

---

## F-15 · RPM service drop CAP_NET_BIND_SERVICE
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`packaging/rpm/systemd/sgx-guardian.service#L38-L39`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/packaging/rpm/systemd/sgx-guardian.service#L38-L39)

**FIND:**
```ini
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
```
**REPLACE WITH:**
```ini
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
```

---

## F-16 · DEB postinst swallows setcap failure
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`packaging/deb/DEBIAN/postinst#L37`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/packaging/deb/DEBIAN/postinst#L37)

**FIND:**
```bash
    setcap ... || true
```
**REPLACE WITH:**
```bash
    if ! setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"; then
        echo "WARNING: Failed to set nmap capabilities; discovery scans may be limited." >&2
    fi
```
Note: also drop `cap_net_bind_service` from the setcap.

---

## F-17 · pcr_baseline.rs key_version zero + unwrap panics
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/pcr_baseline.rs#L68-L69`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/pcr_baseline.rs#L68-L69), [`#L148`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/pcr_baseline.rs#L148), [`#L215-L218`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/pcr_baseline.rs#L215-L218)

**Recurring from PR #69.** Three fixes in same file:
- `key_version == 0` guard before key_id calc
- `unwrap()` → `match` with error messages on baseline/snapshot reads

---

## F-18 · attest_quote.rs chain_ok uses hab_events not boot_chain_intact
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/attest_quote.rs#L225-L230`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/attest_quote.rs#L225-L230)

**Recurring from PR #68/#69.** Same fix — `chain_ok` must use `boot_chain_intact`.

---

## F-19 · dkp_revoke.rs exit codes — error paths return 0
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/dkp_revoke.rs#L26-L119`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/dkp_revoke.rs#L26-L119)

All error branches use `return;` instead of `std::process::exit(1)`. API's `run_cli` derives success from exit code.

**REPLACE** all `return;` in error branches with `std::process::exit(1);`.

---

## F-20 · dkp_revoke.rs lossy u64→u32 cast for version lookup
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`sgx-pa-cli/src/commands/dkp_revoke.rs#L64-L67`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/sgx-pa-cli/src/commands/dkp_revoke.rs#L64-L67)

**FIND:**
```rust
        .position(|k| k["version"].as_u64().unwrap_or(0) as u32 == args.version);
```
**REPLACE WITH:**
```rust
        .position(|k| {
            k.get("version")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                == Some(args.version)
        });
```

---

## F-21 · dkp.rs run_cli timeout
- **Tool:** CodeRabbit · 🟠 Major · ⚡ Quick win
- **Location:** [`src/api/handlers/dkp.rs#L196-L203`](https://github.com/AsadAli-CyberZeus/SGX/blob/feat/60_nmap/src/api/handlers/dkp.rs#L196-L203)

**Recurring from PR #68.** Wrap `.output().await` in `tokio::time::timeout(Duration::from_secs(30), ...)`.

---

# Apply Checklist
```
F-1:   sgx-pa-cli/src/commands/relay.rs (3 locations)
F-2:   packaging/rpm/systemd/sgx-guardian.service
F-3:   sgx-pa-cli/src/commands/pcr_baseline.rs
F-4:   sgx-pa-cli/src/commands/pcr_baseline.rs (verify)
F-5:   sgx-pa-cli/src/commands/discovery.rs (3 locations)
F-6:   sgx-pa-cli/src/commands/discovery.rs
F-7:   config/discovery/nmap.yaml
F-8:   sgx-pa-cli/src/commands/relay.rs (4 locations)
F-9:   scripts/verify_audit_chain.py
F-10:  scripts/build.sh (delete line)
F-11:  scripts/build.sh
F-12:  scripts/build.sh
F-13:  scripts/install.sh
F-14:  packaging/rpm/SPECS/sgx-guardian-client.spec
F-15:  packaging/rpm/systemd/sgx-guardian.service
F-16:  packaging/deb/DEBIAN/postinst
F-17:  sgx-pa-cli/src/commands/pcr_baseline.rs
F-18:  sgx-pa-cli/src/commands/attest_quote.rs (2 locations)
F-19:  sgx-pa-cli/src/commands/dkp_revoke.rs (5 error paths)
F-20:  sgx-pa-cli/src/commands/dkp_revoke.rs
F-21:  src/api/handlers/dkp.rs

cargo build && cargo build -p sgx-pa-cli --bin sgx-pa-cli
cargo test -- --nocapture --test-threads=1
Board smoke test: verify discovery scan runs
```

**Total: 21 fixes · ~4 hours · Regression risk: Low**
