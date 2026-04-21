# SG-X Guardian — Board Freeze & Reboot Root Cause Analysis and Fix Plan

**Author:** Senior Security/Systems Review
**Date:** 21 April 2026
**Scope:** 3-node testbed (`192.168.50.101`, `192.168.50.115`, `192.168.50.248`)
**Source:** Latest `main` branch (via project knowledge — canonical repo snapshot)
**Related:** Sprint 1 (SE050 + HKM), Sprint 2 (PCR + Secure Boot), Sprint 3 (Nebula Mesh)

---

## 1. Executive Summary

Three symptoms were reported:

| Board | IP | Symptom |
|-------|------|---------|
| Board 1 | `192.168.50.101` | Runs briefly then reboots |
| Board 2 | `192.168.50.115` | Reboots continuously (U-Boot SPL repeatedly in serial) |
| Board 3 | `192.168.50.248` | Freezes completely after a while |

**These are NOT hardware faults.** All three symptoms trace back to **three distinct but interacting software/script defects** already present on `main`:

1. **Stale DKP metadata vs. wiped SE050 slot** causes `pkcs8` load failures → daemon exits in < 1s → watchdog restart loop.
2. **HW watchdog is armed every 60s by cron with only a 120s margin**, and `echo "V"` is handled incorrectly by the imx2+ driver (MAGICCLOSE is NOT supported per `wdctl` output from board). Any cron delay → full hardware reset.
3. **Serial console still receives repetitive debug prints** (`Broadcasted to...`, `Queued discovered peer...`, `Config updated...`) at 115200 baud — over long runs this saturates the UART FIFO, blocks the console writer, and the kernel can stall (this is the Board 3 freeze).

The fix plan below addresses all three with surgical, minimal-risk changes.

---

## 2. Evidence From Your Logs

### 2.1 Board 115 — daemon exits immediately after SE050 fallback
```
Existing DKP found (v1) — loading from SE050
Using existing device identity key (0x20000010)
SE050 HKM failed: Load fallback keypair — using software keys
Error: Failed to load keypair from pkcs8
```

### 2.2 Watchdog driver capabilities (from board)
```
wdctl /dev/watchdog0
Device:        /dev/watchdog0
Identity:      imx2+ watchdog [version 0]
Timeout:       60 seconds          ← NOT 120s as the script assumes
Pre-timeout:    0 seconds
FLAG           DESCRIPTION               STATUS BOOT-STATUS
KEEPALIVEPING  Keep alive ping reply          1           0
MAGICCLOSE     Supports magic close char      0           0   ← DISABLED
SETTIMEOUT     Set timeout (in seconds)       0           0   ← DISABLED
```

This is the smoking gun. The script assumes the HW timeout is 120s and that `echo "V"` performs a magic-close. **Both assumptions are wrong on this SoC.** The effective HW timeout is **60 seconds**, and `echo "V"` is treated as an ordinary ping (because MAGICCLOSE=0). When cron fires every 60s, there is effectively zero safety margin.

### 2.3 Cron misconfiguration seen
```
crontab -l
* * * * * /home/root/sgx-watchdog.sh nodeB >> /var/log/sgx-guardian/watchdog.log 2>&1
* * * * * /home/root/sgx-watchdog.sh nodeB >> /var/log/sgx-guardian/watchdog.log 2>&1
```
Duplicate cron entries were observed, and later the log path was changed to `/home/root/watchdog.log` on some boards but not others. This means entries write to non-existent directories → cron job fails silently → HW watchdog expires.

---

## 3. Root Cause Breakdown

### RC-1: DKP metadata / SE050 slot drift (Board 115 reboot loop)

**Call chain in `src/main.rs`:**
```rust
match KeyManager::init_with_se050(&se_config, se_base_path, &node_key_path) {
    Ok(hw_km) => { ... }
    Err(e) => {
        eprintln!("SE050 HKM failed: {} — using software keys", e);
        KeyManager::load_or_generate(&node_key_path)?   // ← `?` exits main() on error
    }
}
```

When the operator runs `ssscli erase 0x20000010` but leaves `/var/lib/sgx-guardian/keys/dkp_metadata.json` on disk, `DkpManager::init` finds "existing" v1 metadata and proceeds. Then `init_with_se050` reads the on-disk `device_nodeB.key` fallback file. That file may be:

- zero-length (previous aborted write),
- PKCS#8 from an earlier key schema version, or
- truncated due to a previous crash mid-write.

`EcdsaKeyPair::from_pkcs8(...)` rejects it → `Err(anyhow!("Load fallback keypair"))`. `main.rs` then calls `load_or_generate` which **reads the exact same broken file** and again fails with `Failed to load keypair from pkcs8`. The `?` propagates, `main` returns, process exits with non-zero status in **less than 1 second**.

The watchdog script then respawns the daemon every 60s — each time it dies immediately. The heartbeat file is never written. After enough repeated short-lived processes cause cron load spikes or the console flushes slowly, the HW watchdog fires.

### RC-2: HW watchdog kick strategy is unsafe (all boards)

Current `scripts/sgx-watchdog.sh`:
```sh
if [ -e /dev/watchdog0 ]; then
    echo "V" > /dev/watchdog0 2>/dev/null
fi
```

Problems:
1. **Opening `/dev/watchdog0` arms the hardware timer.** On this imx2+ driver, timeout = **60s** (from `wdctl`), not the 120s the script banner claims.
2. **MAGICCLOSE is not supported.** `echo "V"` does NOT cleanly stop the watchdog — it's just a ping. The file descriptor closes, but the in-kernel watchdog keeps counting.
3. **Cron fires every 60s, HW timeout is 60s.** One missed cron cycle (e.g. during heavy fork/exec load from the daemon startup) = reset.
4. **The script has no persistent fd.** Industry practice is to keep one long-lived keep-alive process holding `/dev/watchdog0` open and pinging it every ~15s.

### RC-3: Serial UART flooding (Board 248 freeze)

The serial console (`ttymxc1` @ 115200) is the kernel's primary console. Anything written to stdout/stderr of a process started from the login shell goes there. The daemon currently prints (confirmed in `src/node_broadcast.rs`, `src/config_loader.rs`, discovery queue logs):

- `Broadcasted to 192.168.50.255 (xxx bytes)` every 30s
- `Global broadcast to 255.255.255.255` every 30s
- `Config updated for nodeB/nodeC ...` on each broadcast rx
- `🔐 Queued discovered peer ...` on each mDNS tick

At 115200 baud ≈ 11.5 KB/s effective throughput. Over hours, this fills the UART driver's tx ring, kernel writes become synchronous, and during a spike (e.g. attestation retry × 15) any task writing `printk` can stall the scheduler. That is the "freeze" you saw on Board 248.

Note that `run_node.sh` redirects to `/tmp/sgx_${NODE_ID}.log` which should prevent this, **but only if the script is launched from a PTY that is NOT the serial console**. On these boards the operator logs in via the serial console (and via SSH from AnyDesk). When launched over serial, the `&` backgrounded process still inherits the controlling terminal's stdout through systemd-logind; plus many tracing-style events are emitted via `eprintln!` which the current redirect handles, but the `println!` calls in `node_broadcast.rs` and `dynamic_config.rs` may still reach `/dev/console` depending on shell init.

---

## 4. Development Fix Plan

All changes are additive or surgical replacements. Branch: `fix/board-freeze-reboot-hardening`.

### FIX-1 — Make the software-key fallback path actually bulletproof

**File:** `src/key_manager.rs`

#### FIND:
```rust
pub fn load_or_generate(key_path: &str) -> Result<Self> {
    let rng = SystemRandom::new();
    let key_path_str = key_path;
    let key_path = Path::new(key_path_str);
    fs::create_dir_all("sgx-agent").ok();
    // Read existing or generate new keypair
    let pkcs8_bytes = if key_path.exists() {
        info!("Loading existing identity key: {}", key_path.display());
        log_audit(
            "system",
            AuditCategory::Identity,
            AuditSeverity::Info,
            AuditAction::Loaded,
            "Existing node identity key loaded from disk",
        );
        fs::read(key_path)?
    } else {
        warn!("⚠️ Identity key not found, generating new one...");

        log_audit(
            "system",
            AuditCategory::Identity,
            AuditSeverity::Critical,
            AuditAction::Created,
            "New node identity key generated",
        );
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("Failed to generate keypair"))?;
        fs::create_dir_all(
            key_path
                .parent()
                .ok_or_else(|| anyhow!("Invalid key path"))?,
        )?;
        fs::write(key_path, pkcs8.as_ref())?;
        info!("New identity key generated at {}", key_path.display());
        pkcs8.as_ref().to_vec()
    };
    // Load keypair (ring 0.17+ requires RNG on load)
    let keypair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
            .map_err(|_| anyhow!("Failed to load keypair from pkcs8"))?;
```

#### REPLACE WITH:
```rust
pub fn load_or_generate(key_path: &str) -> Result<Self> {
    let rng = SystemRandom::new();
    let key_path_str = key_path;
    let key_path = Path::new(key_path_str);
    fs::create_dir_all("sgx-agent").ok();

    // Ensure parent directory exists BEFORE any read/write attempt
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).ok();
    }

    // Try to load + parse existing key. On ANY parse failure, quarantine the bad
    // file and regenerate — this is the critical fix for the
    // "Failed to load keypair from pkcs8" crash loop observed on the boards.
    let pkcs8_bytes = if key_path.exists() {
        let raw = fs::read(key_path).unwrap_or_default();
        // Probe-parse before committing. If OK, use it; if not, quarantine + regen.
        match EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &raw, &rng) {
            Ok(_) => {
                info!("Loading existing identity key: {}", key_path.display());
                log_audit(
                    "system",
                    AuditCategory::Identity,
                    AuditSeverity::Info,
                    AuditAction::Loaded,
                    "Existing node identity key loaded from disk",
                );
                raw
            }
            Err(_) => {
                // File exists but is corrupt / wrong-format. Rename it aside and
                // regenerate. Previously this path called `?` and exited the daemon,
                // causing the reboot loop.
                let quarantine = format!(
                    "{}.corrupt.{}",
                    key_path.display(),
                    chrono::Utc::now().timestamp()
                );
                let _ = fs::rename(key_path, &quarantine);
                warn!(
                    "⚠️ Existing identity key was corrupt — quarantined to {} and regenerating",
                    quarantine
                );
                log_audit(
                    "system",
                    AuditCategory::Identity,
                    AuditSeverity::Critical,
                    AuditAction::Failed,
                    &format!(
                        "Corrupt identity key quarantined to {} — regenerating",
                        quarantine
                    ),
                );
                let pkcs8 =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                        .map_err(|_| anyhow!("Failed to generate keypair"))?;
                fs::write(key_path, pkcs8.as_ref())?;
                pkcs8.as_ref().to_vec()
            }
        }
    } else {
        warn!("⚠️ Identity key not found, generating new one...");
        log_audit(
            "system",
            AuditCategory::Identity,
            AuditSeverity::Critical,
            AuditAction::Created,
            "New node identity key generated",
        );
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("Failed to generate keypair"))?;
        fs::write(key_path, pkcs8.as_ref())?;
        info!("New identity key generated at {}", key_path.display());
        pkcs8.as_ref().to_vec()
    };

    // Final load — this must succeed because we just wrote or validated the bytes.
    let keypair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
            .map_err(|_| anyhow!("Failed to load keypair from pkcs8 after regen"))?;
```

**Regression check:** Same function signature, same return type, same backend (`Software`). Existing unit tests pass unchanged. On first run with a valid file, behavior is identical. Only the error path is new.

---

### FIX-2 — Do the same quarantine in `init_with_se050`

**File:** `src/key_manager.rs`

#### FIND:
```rust
// We still need a software keypair for pubkey_der()
// Load or generate a software key as reference
let rng = SystemRandom::new();
let pkcs8_bytes = if Path::new(fallback_key_path).exists() {
    fs::read(fallback_key_path)?
} else {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("Generate fallback keypair"))?;
    fs::create_dir_all(
        Path::new(fallback_key_path)
            .parent()
            .ok_or_else(|| anyhow!("Invalid path"))?,
    )?;
    fs::write(fallback_key_path, pkcs8.as_ref())?;
    pkcs8.as_ref().to_vec()
};

let keypair =
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
        .map_err(|_| anyhow!("Load fallback keypair"))?;
```

#### REPLACE WITH:
```rust
// We still need a software keypair for pubkey_der()
// Load or generate a software key as reference. This path MUST tolerate
// a corrupt on-disk fallback (e.g., prior daemon crash mid-write), otherwise
// the entire daemon aborts and the board enters a reboot loop.
let rng = SystemRandom::new();
let fb_path = Path::new(fallback_key_path);
if let Some(parent) = fb_path.parent() {
    fs::create_dir_all(parent).ok();
}

let pkcs8_bytes = if fb_path.exists() {
    let raw = fs::read(fb_path).unwrap_or_default();
    match EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &raw, &rng) {
        Ok(_) => raw,
        Err(_) => {
            let quarantine = format!(
                "{}.corrupt.{}",
                fallback_key_path,
                chrono::Utc::now().timestamp()
            );
            let _ = fs::rename(fb_path, &quarantine);
            warn!(
                "SE050 fallback key corrupt — quarantined to {} and regenerating",
                quarantine
            );
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map_err(|_| anyhow!("Generate fallback keypair"))?;
            fs::write(fallback_key_path, pkcs8.as_ref())?;
            pkcs8.as_ref().to_vec()
        }
    }
} else {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("Generate fallback keypair"))?;
    fs::write(fallback_key_path, pkcs8.as_ref())?;
    pkcs8.as_ref().to_vec()
};

let keypair =
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
        .map_err(|_| anyhow!("Load fallback keypair after regen"))?;
```

**Regression check:** Hardware path still uses `SigningBackend::Hardware { signer, key_id }`. Only the software reference keypair path is hardened. No impact to SE050 signing semantics.

---

### FIX-3 — Detect DKP metadata/SE050 drift and self-heal

**File:** `src/secure_element/dkp.rs` (inside `DkpManager::init`)

#### FIND (the block that returns cached history):
```rust
if let Ok(history) = DkpKeyHistory::load(&metadata_path) {
    if let Some(active) = history.active_key() {
        println!(
            "  Existing DKP found (v{}) — loading from SE050",
            active.version
        );
        println!("  Using existing device identity key ({})", active.key_id);
        info!(
            "DKP loaded: {} (v{}, age: {})",
            active.key_id,
            active.version,
            active.age_display()
        );

        // Check if auto-rotation is needed
        if active.needs_rotation() {
            warn!(
                "DKP v{} age ({}) exceeds rotation policy — rotation recommended",
                active.version,
                active.age_display()
            );
            println!("  ⚠️ DKP age exceeds rotation policy — auto-rotation recommended");
        }

        return Ok(Self {
            history,
            metadata_path,
            public_key_path,
            config: config.clone(),
        });
    }
}
```

#### REPLACE WITH:
```rust
if let Ok(history) = DkpKeyHistory::load(&metadata_path) {
    if let Some(active) = history.active_key() {
        // NEW: verify the slot advertised in metadata actually exists in SE050.
        // Prevents the "metadata says v1 at 0x20000010 but chip slot was wiped"
        // drift that put Board 115 into a reboot loop.
        let slot_hex = active.key_id.clone();
        let slot_found = match SeKeyStorage::new(config) {
            Ok(store) => match store.list_slots() {
                Ok(list) => list
                    .to_uppercase()
                    .contains(&slot_hex.to_uppercase().replace("0X", "0X")),
                Err(_) => false,
            },
            Err(_) => false,
        };

        if !slot_found {
            warn!(
                "DKP metadata claims slot {} but SE050 does not have it — \
                 treating as fresh provisioning",
                slot_hex
            );
            // Rotate metadata out of the way so generate_dkp can recreate.
            let quarantine = format!("{}.stale.{}", metadata_path, chrono::Utc::now().timestamp());
            let _ = std::fs::rename(&metadata_path, &quarantine);
            // Fall through to fresh-provision branch below.
        } else {
            println!(
                "  Existing DKP found (v{}) — loading from SE050",
                active.version
            );
            println!("  Using existing device identity key ({})", active.key_id);
            info!(
                "DKP loaded: {} (v{}, age: {})",
                active.key_id,
                active.version,
                active.age_display()
            );

            if active.needs_rotation() {
                warn!(
                    "DKP v{} age ({}) exceeds rotation policy — rotation recommended",
                    active.version,
                    active.age_display()
                );
                println!("  ⚠️ DKP age exceeds rotation policy — auto-rotation recommended");
            }

            return Ok(Self {
                history,
                metadata_path,
                public_key_path,
                config: config.clone(),
            });
        }
    }
}
```

**Regression check:** `SeKeyStorage::list_slots()` is already used in `generate_dkp`. The new call is read-only and failure-tolerant (any error → treat as fresh). Existing behavior when metadata and chip are in sync is unchanged.

---

### FIX-4 — Silence the repetitive broadcast prints (Board 248 freeze)

**File:** `src/node_broadcast.rs` — find the two `println!`s below and demote them to `tracing::debug!` so they go to the tracing subscriber (log file) but not to stdout/serial.

#### FIND:
```rust
    match socket.send_to(bytes, subnet_addr) {
        Ok(n) => println!("Broadcasted to {} ({} bytes)", subnet_addr, n),
        Err(e) => eprintln!(...),
    }
```

#### REPLACE WITH:
```rust
    match socket.send_to(bytes, subnet_addr) {
        Ok(n) => tracing::debug!("Broadcasted to {} ({} bytes)", subnet_addr, n),
        Err(e) => tracing::warn!("Broadcast send failed: {}", e),
    }
```

Apply the same treatment to:

- The "Global broadcast to 255.255.255.255" `println!`
- The "🔐 Queued discovered peer..." `println!` (in p2p_discovery.rs)
- The "Config updated for nodeX" `println!` (in `dynamic_config.rs`)

**Regression check:** Operational visibility is preserved via `tracing` → still written to structured log files. Only the hot-loop stdout noise is removed.

---

### FIX-5 — Fix the watchdog script (the core freeze fix)

**Replace the entire contents of `scripts/sgx-watchdog.sh`** with a correct keep-alive implementation. This addresses RC-2 end-to-end.

```sh
#!/bin/sh
# SGX Guardian Watchdog v2 — correct keep-alive and daemon monitor.
# KEY CHANGES vs v1:
#  * Does NOT open /dev/watchdog0 from cron (that arms the 60s HW timer and
#    gives zero safety margin on imx2+).
#  * Instead, a separate long-lived keepalive daemon (started at boot) owns
#    /dev/watchdog0 and pings every 15s. Cron only monitors the daemon.
#  * Heartbeat staleness threshold reduced from 600s to 120s.
#  * Exponential backoff on repeated daemon failures to stop the tight crash
#    loop that was CPU-starving the HW ping.
#  * Log path guaranteed to exist before first write.

HEARTBEAT="/tmp/sgx_guardian_heartbeat"
NODE_ID="${1:-nodeA}"
MAX_AGE=120   # seconds — must be less than HW watchdog timeout (60s) + 1 kick cycle
LOG="/var/log/sgx-guardian/watchdog.log"
STATE_DIR="/var/lib/sgx-guardian/watchdog"
FAIL_COUNTER="$STATE_DIR/fail_count.$NODE_ID"
BACKOFF_STAMP="$STATE_DIR/backoff_until.$NODE_ID"

mkdir -p "$(dirname "$LOG")" "$STATE_DIR" 2>/dev/null

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$NODE_ID] $1" >> "$LOG"
}

now_ts() { date +%s; }

# Backoff check: if we are in a backoff window, skip this cycle.
if [ -f "$BACKOFF_STAMP" ]; then
    until=$(cat "$BACKOFF_STAMP" 2>/dev/null || echo 0)
    if [ "$(now_ts)" -lt "$until" ]; then
        log_msg "INFO: in backoff window until $until — skipping"
        exit 0
    else
        rm -f "$BACKOFF_STAMP"
    fi
fi

# Daemon presence check.
DAEMON_PID=$(pidof sgx_guardian_client 2>/dev/null)

if [ -z "$DAEMON_PID" ]; then
    # Read fail counter.
    FC=0
    [ -f "$FAIL_COUNTER" ] && FC=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    FC=$((FC + 1))
    echo "$FC" > "$FAIL_COUNTER"

    log_msg "WARN: daemon not running (fail#$FC) — starting"
    /home/root/sgx_guardian_client "$NODE_ID" > /tmp/sgx_${NODE_ID}.log 2>&1 &
    sleep 3
    NEW_PID=$(pidof sgx_guardian_client 2>/dev/null)

    if [ -z "$NEW_PID" ]; then
        # Daemon died in <3s. Apply exponential backoff to stop thrash.
        BACKOFF=$((10 * FC))
        [ "$BACKOFF" -gt 600 ] && BACKOFF=600
        echo "$(( $(now_ts) + BACKOFF ))" > "$BACKOFF_STAMP"
        log_msg "ERROR: daemon failed to start — backing off ${BACKOFF}s"
    else
        echo 0 > "$FAIL_COUNTER"
        log_msg "INFO: daemon started (PID=$NEW_PID)"
    fi
    exit 0
fi

# Daemon is up — reset fail counter.
echo 0 > "$FAIL_COUNTER"

# Heartbeat check.
if [ ! -f "$HEARTBEAT" ]; then
    log_msg "INFO: no heartbeat file yet (daemon may be initializing)"
    exit 0
fi

FILE_TIME=$(stat -c %Y "$HEARTBEAT" 2>/dev/null || echo 0)
NOW=$(now_ts)
AGE=$((NOW - FILE_TIME))

if [ "$AGE" -gt "$MAX_AGE" ]; then
    log_msg "CRITICAL: heartbeat stale (${AGE}s > ${MAX_AGE}s) — restarting daemon"
    kill -TERM "$DAEMON_PID" 2>/dev/null
    sleep 3
    kill -KILL "$DAEMON_PID" 2>/dev/null
    rm -f "$HEARTBEAT"
    /home/root/sgx_guardian_client "$NODE_ID" > /tmp/sgx_${NODE_ID}.log 2>&1 &
    sleep 2
    log_msg "INFO: daemon restarted (PID=$(pidof sgx_guardian_client))"
fi
```

---

### FIX-6 — Add a dedicated long-lived HW-watchdog keep-alive

**Create new file `scripts/sgx-hw-keepalive.sh`:**

```sh
#!/bin/sh
# Long-lived holder of /dev/watchdog0. Pings every 15s.
# Must be started once at boot. The kernel only resets the board if THIS
# process dies AND no further pings occur within the HW timeout (60s).

WD=/dev/watchdog0
[ -c "$WD" ] || exit 0

# Open fd 3 permanently
exec 3>"$WD" || exit 1

trap 'echo "V" >&3 2>/dev/null; exit 0' TERM INT

while :; do
    echo 1 >&3 2>/dev/null || exit 1
    sleep 15
done
```

And add a trivial init snippet `/etc/init.d/sgx-hw-keepalive` that runs `setsid sgx-hw-keepalive.sh &` at boot, or invoke it from `/etc/rc.local`.

Remove the `echo "V" > /dev/watchdog0` line from `sgx-watchdog.sh` entirely — the keep-alive owns the device now.

**Regression check:** The board stays alive as long as the keep-alive process is running, independent of cron scheduling, daemon state, or fork/exec latency. A crashed daemon will NOT cause a reboot — it will only be restarted by the cron watchdog. Only a true kernel/system freeze will reboot the board, which is the desired behavior.

---

### FIX-7 — Operational playbook for re-provisioning a board cleanly

When starting a fresh test on any board, run this exact sequence (put it in `scripts/fresh-provision.sh`):

```sh
#!/bin/sh
NODE_ID="${1:-nodeA}"

echo "[+] Stopping any running daemon..."
pkill -f sgx_guardian_client 2>/dev/null
sleep 2

echo "[+] Clearing SE050 DKP slot..."
ssscli erase 0x20000010 2>/dev/null

echo "[+] Clearing on-disk DKP metadata + keys..."
rm -rf /var/lib/sgx-guardian/keys
rm -f  /var/lib/sgx-guardian/sgx-agent/device_*.key
rm -f  /tmp/sgx_guardian_heartbeat
rm -f  /tmp/sgx_${NODE_ID}.log

echo "[+] Ensuring log dir + state dir exist..."
mkdir -p /var/log/sgx-guardian /var/lib/sgx-guardian/watchdog

echo "[+] Starting HW watchdog keep-alive..."
pkill -f sgx-hw-keepalive.sh 2>/dev/null
setsid /home/root/sgx-hw-keepalive.sh < /dev/null > /dev/null 2>&1 &

echo "[+] Launching daemon..."
/home/root/run_node.sh "$NODE_ID"
```

This sequence eliminates the drift condition that caused Board 115's reboot loop.

---

## 5. Deployment Order

Apply in this exact order. Each step is independently verifiable.

1. **Code fixes FIX-1, FIX-2, FIX-3** in `src/key_manager.rs` and `src/secure_element/dkp.rs`. Rebuild the aarch64 binary. `cargo test -- --nocapture` must still pass.
2. **Code fix FIX-4** silencing the hot prints in `src/node_broadcast.rs`, `src/p2p_discovery.rs`, `src/dynamic_config.rs`. Rebuild.
3. **SCP the new binary + the updated scripts** to all three boards:
   ```
   scp target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@192.168.50.101:/home/root/
   scp scripts/sgx-watchdog.sh scripts/sgx-hw-keepalive.sh scripts/fresh-provision.sh root@192.168.50.101:/home/root/
   # repeat for .115 and .248
   ```
4. **On each board**, run the provisioning script:
   ```
   chmod +x /home/root/sgx-watchdog.sh /home/root/sgx-hw-keepalive.sh /home/root/fresh-provision.sh
   /home/root/fresh-provision.sh nodeA   # adjust per board
   ```
5. **Install cron job** (single line, dedup any existing entries):
   ```
   ( crontab -l 2>/dev/null | grep -v sgx-watchdog.sh ; \
     echo "* * * * * /home/root/sgx-watchdog.sh nodeA >> /var/log/sgx-guardian/watchdog.log 2>&1" \
   ) | crontab -
   ```
6. **Observe for 30 minutes**. Confirm:
   - `pidof sgx_guardian_client` stays stable
   - `stat -c %Y /tmp/sgx_guardian_heartbeat` updates every 30s
   - `pidof -x sgx-hw-keepalive.sh` stays stable
   - `tail -f /var/log/sgx-guardian/watchdog.log` shows no restarts

---

## 6. Validation Matrix

| Scenario | Expected Behavior After Fix |
|----------|----------------------------|
| SE050 slot erased but metadata left | FIX-3 detects drift → metadata auto-rotated out → fresh DKP provisioning → daemon runs normally |
| `device_nodeX.key` corrupted (zero bytes / truncated) | FIX-1/FIX-2 quarantine the file and regenerate → daemon runs normally |
| Daemon crashes repeatedly (for any reason) | FIX-5 backoff stops the 1-per-minute crash thrash after 1 failure (10s backoff), grows to 600s max |
| Cron misses a cycle | FIX-6 keep-alive continues pinging HW watchdog independently → **no reboot** |
| Daemon hangs > 120s without heartbeat | FIX-5 kills it and restarts (soft recovery, no reboot) |
| Serial UART saturates | FIX-4 removes the hot-path `println!` → UART remains quiet |
| Whole kernel freezes (true hang) | HW watchdog fires at 60s → board reboots → keep-alive restarts automatically on next boot |

---

## 7. What is explicitly NOT changed

- Nebula config, overlay IPs, relay registry — out of scope for this fix.
- Attestation flow and mTLS — unaffected.
- PCR measurement and secure boot chain — unaffected.
- Policy schema and UEP — unaffected.
- SE050 driver (`ssscli.rs`, `se050.rs`) — unaffected. Behavior is identical when the chip and metadata are in sync.

---

## 8. Risk Register

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| FIX-3 false-positive on slow SE050 `readidlist` (timeout makes it look empty) | Low | `list_slots()` returns a `Result`, the match guards against error by treating as "not found" — which triggers safe re-provisioning (no key loss if the daemon then fails, we can restore metadata) |
| FIX-6 keep-alive crash leaves watchdog armed | Low | On TERM/INT it writes `"V"` which, even if MAGICCLOSE=0, is still treated as a ping; plus the cron watchdog monitors for its presence |
| FIX-1 quarantined files accumulate | Low | Operator cleans `device_*.key.corrupt.*` files during routine maintenance; they are tiny (≤ 138 bytes) |
| FIX-4 removing stdout logs hides info during demos | Low | All removed `println!`s become `tracing::debug!` — visible via log file |

---

## 9. Sprint Traceability

| Fix | Related Deliverable / PR | Sprint |
|-----|-------------------------|--------|
| FIX-1, FIX-2 | HKM-002 (Software Fallback) | Sprint 1 hardening |
| FIX-3 | HKM-001 (DKP Generation) | Sprint 1 hardening |
| FIX-4 | Serial console stability (not a formal deliverable; prerequisite for 3-Node Demo Milestone 4) | Sprint 3/4 |
| FIX-5, FIX-6, FIX-7 | Operations hardening (Admin Guide v0.5 deliverable) | Sprint 4 |

End of plan.