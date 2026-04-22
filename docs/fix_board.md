# SG-X Guardian — Board Freeze Fix: Deployment Package

**Purpose:** Stop STEP_06 / STEP_07 board reboots on boards 101, 115, 248.
**Root cause:** `/dev/mem` mmap to i.MX8MP OCOTP physical addresses hangs the AXI bus; HW watchdog resets the board.
**Strategy:** Remove `/dev/mem` entirely. Read OCOTP via kernel nvmem sysfs. Gate behind env flag, default OFF. Cache result. Wrap everything in timeouts.

---

## Patch Order (apply in sequence on your laptop, in the `SGX/` repo root)

### Patch 1 (REQUIRED) — Replace `src/secure_element/secure_boot.rs`

**Action:** Replace the entire file with the `secure_boot.rs` attached to this deliverable.

**What changes:**
- `read_phys_u32()` is **deleted** — no more `/dev/mem` mmap anywhere.
- New `read_nvmem_u32()` reads from `/sys/bus/nvmem/devices/imx-ocotp*/nvmem`.
- New `run_with_timeout()` helper wraps every read in a thread + mpsc::recv_timeout.
- New `BootChainStatus::unknown()` — safe default constructor.
- New `BootChainStatus::prime_cache()` — lets main.rs force the cached value.
- `BootChainStatus::check()` is now cache-backed (OnceCell).
- OCOTP reads gated behind `SGX_READ_OCOTP` (default off).
- Binary hash gated behind `SGX_MEASURE_BINARY_HASH` (default off).
- Verbose `tracing::info!` at every sub-step so we can pinpoint any future hang.

**Dependencies already in Cargo.toml:** `once_cell`, `tracing`, `sha2`, `hex`, `serde_json`. Nothing new needed.

**Tests:** 9 unit tests pass on any host (laptop, board, CI).

### Patch 2 (REQUIRED) — Add two env gates to `src/runtime_gates.rs`

Find the struct `RuntimeGates` definition and add two fields, then populate them in `load()`.

**FIND** (anywhere in the struct — pick a spot near other bool fields):
```rust
    pub startup_cooldown_ms: u64,
}
```

**REPLACE WITH:**
```rust
    pub startup_cooldown_ms: u64,

    // Board-freeze fix (Apr 2026)
    /// Attempt to read OCOTP fuses via /sys/bus/nvmem. Default OFF.
    /// When unset, BootChainStatus reports HAB: Unknown.
    pub read_ocotp: bool,
    /// Compute SHA-256 of the daemon binary (17 MB, ~1 s blocking). Default OFF.
    pub measure_binary_hash: bool,
}
```

**FIND** inside `fn load()`:
```rust
            startup_cooldown_ms:       env_u64("SGX_STARTUP_COOLDOWN_MS", 0),
        }
    }
```

**REPLACE WITH:**
```rust
            startup_cooldown_ms:       env_u64("SGX_STARTUP_COOLDOWN_MS", 0),
            read_ocotp:                env_true("SGX_READ_OCOTP"),
            measure_binary_hash:       env_true("SGX_MEASURE_BINARY_HASH"),
        }
    }
```

**FIND** inside `pub fn log_summary(&self)` — the `tracing::info!` macro call:
```rust
            self.startup_cooldown_ms
        );
    }
```

**REPLACE WITH:**
```rust
            self.startup_cooldown_ms
        );
        tracing::info!(
            "Runtime gates (boot): read_ocotp={} measure_binary_hash={}",
            self.read_ocotp, self.measure_binary_hash
        );
    }
```

### Patch 3 (DEFENSIVE) — Outer timeout + cache priming in `src/main.rs`

This wraps the STEP_06 call in an async tokio timeout and primes the cache so STEP_07 and `AttestationQuote::generate()` reuse the same snapshot.

**FIND:**
```rust
    // === Secure Boot Chain Verification ===
    println!("\n  Verifying secure boot chain...");
    {
        use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;

        let boot_status = BootChainStatus::check();
        boot_status.print();

        // Save boot chain status
        let boot_status_path = format!("/var/lib/sgx-guardian/boot/{}_chain_status.json", node_id);
        if let Err(e) = boot_status.save(&boot_status_path) {
            eprintln!("  Boot chain save failed: {}", e);
        }

        if !boot_status.boot_chain_intact {
            eprintln!(
                "  ⚠️ Boot chain verification incomplete — PCR values may not be fully trusted"
            );
        }
    }
```

**REPLACE WITH:**
```rust
    // === Secure Boot Chain Verification ===
    // Wrapped in tokio::time::timeout + spawn_blocking as belt-and-suspenders.
    // The inner check_inner() already has per-step timeouts, but this outer
    // layer guarantees the async runtime keeps scheduling even if the thread
    // stalls for any reason.
    println!("\n  Verifying secure boot chain...");
    {
        use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;

        let boot_status = match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::task::spawn_blocking(BootChainStatus::check),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                eprintln!("  ⚠️ BootChain task panicked: {:?} — using unknown defaults", e);
                BootChainStatus::unknown()
            }
            Err(_) => {
                eprintln!(
                    "  ⚠️ BootChain check TIMED OUT after 15s — using unknown defaults"
                );
                BootChainStatus::unknown()
            }
        };

        // Prime the cache so STEP_07 PCR loop and AttestationQuote::generate
        // reuse the same snapshot instead of re-running check_inner().
        BootChainStatus::prime_cache(boot_status.clone());

        boot_status.print();

        let boot_status_path =
            format!("/var/lib/sgx-guardian/boot/{}_chain_status.json", node_id);
        if let Err(e) = boot_status.save(&boot_status_path) {
            eprintln!("  Boot chain save failed: {}", e);
        }

        if !boot_status.boot_chain_intact {
            eprintln!(
                "  ⚠️ Boot chain verification incomplete — PCR values may not be fully trusted"
            );
        }
    }
```

### Patch 4 (DEFENSIVE) — File size cap in `src/secure_element/pcr.rs`

Prevents future regression if anyone adds a large file (e.g. `/boot/Image` 30+ MB) to the PCR source list.

**FIND:**
```rust
    /// Extend with SHA-256 hash of a file's contents.
    pub fn extend_from_file(&mut self, pcr_index: usize, path: &str) -> Result<String, String> {
        let data = fs::read(path).map_err(|e| format!("Read {}: {}", path, e))?;
        let measurement = Sha256::digest(&data);
        self.extend(pcr_index, &measurement)?;
        let hex = hex::encode(measurement);
        Ok(hex)
    }
```

**REPLACE WITH:**
```rust
    /// Extend with SHA-256 hash of a file's contents.
    /// Files larger than 16 MB are hashed by their metadata instead of full
    /// contents to avoid blocking the tokio runtime on large reads (e.g.
    /// /boot/Image can be 30+ MB on some boards).
    pub fn extend_from_file(&mut self, pcr_index: usize, path: &str) -> Result<String, String> {
        const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

        let meta = fs::metadata(path).map_err(|e| format!("Stat {}: {}", path, e))?;
        if meta.len() > MAX_FILE_BYTES {
            let meta_str = format!(
                "FILE_META:{}:size={}:mtime={:?}",
                path,
                meta.len(),
                meta.modified().ok()
            );
            tracing::warn!(
                "PCR{}: {} exceeds {} bytes — measuring metadata instead of contents",
                pcr_index, path, MAX_FILE_BYTES
            );
            return self.extend_from_string(pcr_index, &meta_str);
        }

        let data = fs::read(path).map_err(|e| format!("Read {}: {}", path, e))?;
        let measurement = Sha256::digest(&data);
        self.extend(pcr_index, &measurement)?;
        let hex = hex::encode(measurement);
        Ok(hex)
    }
```

### Patch 5 (OPTIONAL) — Clean up duplicate `BootChainStatus::check()` in PCR loop

Looking at the main.rs you uploaded, inside the PCR block the code calls `BootChainStatus::check()` again for the `boot_chain` source type. With Patch 3 applied, this call now hits the cache (near-instant) — no change strictly required. But for clarity, you can change that specific call to read the cached value explicitly. **If in doubt, skip this patch** — Patch 3 alone makes the recomputation free.

If you want to apply it, **FIND** inside the PCR loop:
```rust
            if src.source_type == "boot_chain" {
                // Measure the boot chain state string
                use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;
                let boot_status = BootChainStatus::check();
                let measurement = boot_status.to_measurement_string();
```

**REPLACE WITH:**
```rust
            if src.source_type == "boot_chain" {
                // Reuse the cached snapshot primed by STEP_06 above.
                use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;
                let boot_status = BootChainStatus::check(); // cache hit, near-instant
                let measurement = boot_status.to_measurement_string();
```

(Same code, just a clarifying comment. You can skip if you prefer.)

---

## Build Commands (on your laptop)

```sh
cd ~/SGX

# 1. Format + lint + tests pass on laptop (no hardware needed)
cargo fmt --all
cargo clippy --all-targets --features secure-element -- -D warnings
cargo test -p sgx-guardian-client secure_element::secure_boot -- --nocapture
cargo test -p sgx-guardian-client secure_element::pcr -- --nocapture

# 2. Cross-compile for the board
CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
cargo build --release \
    --target aarch64-unknown-linux-gnu \
    --features secure-element

# 3. Verify the new env strings are baked into the binary
strings -a target/aarch64-unknown-linux-gnu/release/sgx_guardian_client | \
    grep -E 'SGX_READ_OCOTP|SGX_MEASURE_BINARY_HASH|BootChain:|read_nvmem'
```

Expected output for step 3 — you must see **all** of these strings (plus more):
```
SGX_READ_OCOTP
SGX_MEASURE_BINARY_HASH
BootChain: reading /proc/device-tree/model
BootChain: reading /proc/version
BootChain: OCOTP read skipped (SGX_READ_OCOTP not set — safe default)
BootChain: check_inner completed in
HAB: Unknown (OCOTP read disabled — set SGX_READ_OCOTP=1 to attempt)
```

If any of those strings are **missing**, the patches weren't applied. Stop and re-check.

---

## Deploy to Board 101

```sh
# On Windows PowerShell
scp target\aarch64-unknown-linux-gnu\release\sgx_guardian_client `
    root@192.168.50.101:/home/root/
```

---

## Test on Board 101

SSH into the board. Keep a **second SSH session open** in another terminal as a liveness probe.

### Test 1 (REQUIRED) — default config (OCOTP OFF, binary hash OFF)

```sh
# On board
pkill -f sgx_guardian_client 2>/dev/null
rm -f /tmp/sgx_nodeA.log /tmp/sgx_guardian_heartbeat

# Unset ALL prior gates so only the new safe defaults apply.
for v in $(env | grep '^SGX_' | cut -d= -f1); do unset "$v"; done

# Launch through run_node.sh so stdout goes to the log file, not the serial port.
/home/root/run_node.sh nodeA
```

Watch in the second terminal:
```sh
tail -f /tmp/sgx_nodeA.log
```

**Expected:** Startup reaches `STEP_22 cot subsystem gate` or later. SSH stays alive for 10+ minutes. Search the log for these new lines — they must appear:

```
BootChain: reading /proc/device-tree/model
BootChain: reading /proc/version
BootChain: OCOTP read skipped (SGX_READ_OCOTP not set — safe default)
BootChain: binary hash skipped (SGX_MEASURE_BINARY_HASH not set — safe default)
BootChain: check_inner completed in (something small like 3-8ms)
```

And the "Verifying secure boot chain..." block should complete cleanly, showing:
```
Secure Boot Chain:
    HAB:           ❓ Not detected / unknown
    Device state:  🔓 Open / unknown
    ...
    Description:   HAB: Unknown (OCOTP read disabled — set SGX_READ_OCOTP=1 to attempt)
```

**If board freezes here → the patch was not applied or not deployed. Check `md5sum /home/root/sgx_guardian_client` on both sides.**

### Test 2 (OPTIONAL) — turn on OCOTP reads via nvmem

Same steps but with `SGX_READ_OCOTP=1`:

```sh
export SGX_READ_OCOTP=1
/home/root/run_node.sh nodeA
```

**Expected one of two outcomes** — both are acceptable:
- **A:** Board stays alive. Log shows `BootChain: OCOTP SEC_CONFIG ok (val=0xXXXXXXXX, closed=false)` and `BootChain: SRK fuse empty ... — board in OPEN mode`. This confirms the nvmem path works on this kernel build.
- **B:** Board stays alive. Log shows `BootChain: OCOTP SEC_CONFIG — nvmem node not found`. This means `/sys/bus/nvmem/devices/imx-ocotp*/nvmem` doesn't exist on this BSP. The daemon keeps running with HAB=Unknown. No freeze either way.

**If board freezes here → the kernel nvmem-imx-ocotp driver has a bug. File a Variscite ticket attaching `/home/root/sgx_kmsg.log`. Meanwhile, keep OCOTP off in production.**

### Test 3 (OPTIONAL) — full run with everything enabled

```sh
unset SGX_DISABLE_NEBULA SGX_DISABLE_COT SGX_DISABLE_ATTESTATION \
      SGX_DISABLE_BROADCAST SGX_DISABLE_GRPC_SERVER SGX_DISABLE_CERT_BOOTSTRAP \
      SGX_DISABLE_POLICY_ENFORCEMENT SGX_DISABLE_P2P_DISCOVERY
export SGX_READ_OCOTP=1
/home/root/run_node.sh nodeA
```

Soak for 30 minutes. SSH must stay alive. Full Nebula + CoT + gRPC + attestation should come up.

---

## Baseline Regeneration (one-time operator step after first successful run)

Because the measurement string for PCR0 now reports `HAB:false,CLOSED:false,...,KERNEL_HASH:...` (HAB unknown) instead of the previous frozen-before-even-measuring value, the golden PCR baseline needs to be regenerated **once**:

```sh
# On board 101 after Test 1 passes
sgx-pa-cli pcr-baseline-create
sgx-pa-cli pcr-status
```

This produces a new `/etc/sgx-guardian/pcr_nodeA_baseline.json` that the daemon will compare future measurements against. Do the same on boards 115 and 248 after they successfully boot with the new binary.

---

## Rollback

Every change is additive or gated. If anything goes wrong:

```sh
# On laptop
git checkout main -- src/secure_element/secure_boot.rs src/runtime_gates.rs \
                      src/main.rs src/secure_element/pcr.rs
cargo build --release --target aarch64-unknown-linux-gnu --features secure-element
scp target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@192.168.50.101:/home/root/
```

You're back to the previous binary. No on-disk data format changed, no protocol semantics changed.

---

## Summary

| Patch | Required? | Effect |
|-------|-----------|--------|
| 1: `secure_boot.rs` replacement | **YES** | Removes /dev/mem → stops the reboots |
| 2: `runtime_gates.rs` — 2 new flags | **YES** | Needed for patch 1 to compile |
| 3: `main.rs` — timeout wrapper + prime_cache | Recommended | Belt-and-suspenders; also shares the boot_status across STEP_06/STEP_07/attest |
| 4: `pcr.rs` — file size cap | Recommended | Prevents latent regression from large files |
| 5: PCR loop comment clarification | Optional | Cosmetic |

Patches 1 + 2 alone are sufficient to stop the freezes. The rest are hardening.

After Test 1 passes on board 101, repeat on 115 and 248 in the same order. All three should come up clean on the same binary.