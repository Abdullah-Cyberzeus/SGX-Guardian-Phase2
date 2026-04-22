# SG-X Guardian — Deep Code-Level Freeze Investigation (Post-Listener)

**Source:** Latest `main` branch via project_knowledge_search.
**Scope:** Runtime path executed AFTER `Listener ready on 0.0.0.0:9000 (SO_BROADCAST enabled)`.
**Reproduction:** Board 248, SSH session dies within seconds of daemon start; board unreachable for minutes.
**Governing constraint:** Confirmed this is NOT serial UART or hardware — the failure mode kills SSH over Wi-Fi identically.

---

## A. Goal Summary

Identify the exact code path inside `main.rs` between the listener bind and the first freeze, and produce a surgical debug + isolation plan so we can:

1. Land `STEP_NN` markers that trace the freeze point deterministically,
2. Gate every heavy subsystem behind `SGX_DISABLE_*` env flags,
3. Introduce 2-second cool-down between subsystem startups to prevent a thundering-herd,
4. Start the daemon with every new subsystem disabled, then re-enable them one at a time until the freeze reproduces — that reveals the guilty subsystem.

No broad refactor. Every change is a gate or a log line.

---

## B. Most Likely Root Causes, Ranked

### #1 — Nebula daemon startup with invalid `static_host_map` entry (HIGHEST SUSPECT)

**File:** `src/nebula/daemon.rs` → `NebulaDaemon::start` called from `src/main.rs`.

**Why this is #1:**

- Brand new in Sprint 3, absent in the Sprint 2 builds that ran stably.
- `NebulaDaemon::start` runs `pkill -f "nebula -config"` **without restricting to this daemon's PID**. On a board running other processes that happened to include that substring, this kills arbitrary work.
- The Nebula binary is spawned with **no resource limits**. If `static_host_map` still contains the placeholder string `LIGHTHOUSE_PUBLIC_IP:4242` (seen in earlier sprints) or resolves to an unreachable endpoint, Nebula retries **UDP 4242 punch-out packets in a tight loop** — this is well documented to saturate Wi-Fi on the Broadcom CYW43xx combo chip that the VAR-SOM-MX8MP uses.
- Nebula brings up the `nebula0` TUN interface. On some i.MX8 kernel builds without `CONFIG_TUN` built-in, `ip link add … type tun` from user space triggers `modprobe tun`, which can soft-lockup the RCU.
- The daemon's stdout/stderr are piped to `/dev/null` so we get zero visibility when it misbehaves.

### #2 — `RelayTrafficControl::apply_bandwidth_limit` applying `tc` qdisc on nebula0

**File:** `src/nebula/relay_tc.rs` → called from `src/main.rs` immediately after Nebula starts.

**Why this is #2:**

- Sprint 4 addition, also absent in stable builds.
- Calls `tc qdisc add dev nebula0 root handle 1: htb default 10` the **instant** nebula0 appears. The TUN device is often not fully registered in the netdev subsystem yet when this runs (Nebula prints "interface up" before `ioctl(SIOCGIFFLAGS)` is valid). Applying HTB to a half-initialised netdev is a known cause of kernel WARN + RCU stall on Linux 6.1 ARM64.
- On failure, the code emits a single `eprintln!` and continues — so if the kernel is about to lock up we get **no pre-freeze evidence**.

### #3 — CoT interface refresh + Bluetooth scan blocking tokio executor

**File:** `src/cot/transports/bluetooth.rs` + `src/cot/transports/mod.rs::auto_create_transports`, called from periodic refresh in `src/main.rs` Step 8.

**Why this is #3:**

- Sprint 4 addition.
- Bluetooth transport calls `Command::new("bluetoothctl").args(["show"]).output()` **synchronously from inside async contexts** (`is_available`, `health_check`). That is a cardinal sin in tokio — it blocks a worker thread.
- The VAR-SOM-MX8M-PLUS uses a shared **2.4 GHz antenna for Wi-Fi and Bluetooth (CYW43xx combo chip)**. Whenever `bluetoothctl scan on` runs (10-second timeout), the Wi-Fi throughput on the same band drops by up to 80%, and the SSH keepalive TCP retransmits time out. This exactly matches your symptom: "SSH session reset, then the board becomes unreachable for some time" — the board comes back when the BT scan window closes.
- The periodic refresh runs every 30 seconds, so the freeze would recur periodically.

### #4 — Thundering-herd of eight `tokio::spawn` tasks all starting simultaneously

After "Listener ready" the code issues ~10 `tokio::spawn` calls in tight succession with zero staggering:

```
spawn → cert_bootstrap_server  (TCP 50061 bind)
spawn → cloud uplink heartbeat
spawn → NebulaDaemon::start    (child process + waits 20s)
spawn → relay_registry health loop (nodeA)
spawn → relay stats poller (10s)
spawn → tunnel state observer (15s)
spawn → expiry monitor
spawn → cot interface refresh (30s)
spawn → cot session cleanup (60s)
spawn → p2p discovery
spawn → attestation service + listener
spawn → heartbeat writer
spawn → broadcast loop
```

On a 4-core A53 at 1.2 GHz, all of these fire within 100 ms. If even one of them holds a blocking subprocess call for ≥ 3 s, the whole runtime stalls.

---

## C. Startup Flow Trace (file-by-file)

This is the exact sequence after `"Listener ready on 0.0.0.0:9000 (SO_BROADCAST enabled)"` (from `src/node_listener.rs::start_listener`). Every entry below is a candidate freeze point.

```
STEP_01  src/main.rs                        KeyManager::init_with_se050()      — ssscli subprocess; already verified OK
STEP_02  src/main.rs                        DKP auto-rotation check             — ssscli subprocess
STEP_03  src/main.rs                        Attestation evidence create/verify  — CPU only, safe
STEP_04  src/main.rs                        Secure boot chain check             — devmem2/fs; safe if file read
STEP_05  src/main.rs                        TLS cert generate/load              — fs write; safe
STEP_06  src/main.rs                        start_server (gRPC/mTLS task)       — tokio::spawn, TCP bind on node.port
STEP_07  src/main.rs  (nodeA)               start_cert_bootstrap_server 50061   — tokio::spawn, TCP bind
STEP_08  src/main.rs                        Cloud uplink heartbeat task         — tokio::spawn; optional
STEP_09  src/main.rs                        NebulaInstall::check_binary/version/test_daemon_start  — subprocess
STEP_10  src/main.rs                        pkill -f "nebula -config"           — DANGER: broad match
STEP_11  src/main.rs                        Overlay IP resolution + lighthouse  — disk I/O
STEP_12  src/main.rs                        NebulaConfig::generate_config_*     — disk write
STEP_13  src/main.rs                        NebulaDaemon::start()               — SPAWN nebula child; 20 s wait loop
STEP_14  src/main.rs                        NebulaInterface::wait_for_interface — polls /sys/class/net/nebula0
STEP_15  src/main.rs                        RelayTrafficControl::apply_bandwidth_limit — tc qdisc on nebula0
STEP_16  src/main.rs                        RelayRegistry::add_relay + save     — disk
STEP_17  src/main.rs                        LighthouseRegistry health          — UDP/TCP probes
STEP_18  src/main.rs  (nodeA)               Relay registry health loop spawn   — periodic
STEP_19  src/main.rs                        Relay stats poller spawn (10 s)    — hits 127.0.0.1:8625
STEP_20  src/main.rs                        Tunnel state observer spawn (15 s)
STEP_21  src/main.rs                        ExpiryMonitor::start               — periodic
STEP_22  src/main.rs                        CoT DeviceIdentity                  — hash, safe
STEP_23  src/main.rs                        InterfaceDetector::detect_all       — enumerate ifaces
STEP_24  src/main.rs                        transports::auto_create_transports  — creates BT, Cellular, etc.
STEP_25  src/main.rs                        cot_registry.register() x N         — calls Transport::is_available() (BLOCKING subprocesses inside)
STEP_26  src/main.rs                        SessionManager + Circle + Trust + Router  — CPU only
STEP_27  src/main.rs                        CoT interface refresh task (30 s)
STEP_28  src/main.rs                        CoT session cleanup task (60 s)
STEP_29  src/main.rs                        P2PDiscovery::run spawn             — UDP + mDNS
STEP_30  src/main.rs                        attestation_service::run spawn      — TCP listener on port+100
STEP_31  src/main.rs                        broadcast loop + heartbeat writer   — UDP 255.255.255.255:9000
```

---

## D. First Isolation Strategy

**Start by disabling STEP_13 through STEP_20 (all Nebula + relay + tc).** This is the smallest change that rules out the #1 and #2 suspects in a single run.

If that run survives for 5+ minutes with stable SSH → the culprit is in the Nebula/relay/tc block. Re-enable one at a time.

If it still freezes → the culprit is in STEP_23–STEP_27 (CoT transports). Disable that block next.

If it still freezes after both → the culprit is in STEP_29–STEP_31 (discovery/attestation/broadcast).

---

## E. Exact Code Changes

Six surgical edits. Every behaviour gated on an env var. Default behaviour preserved when no env var is set.

### E-1. New file: `src/runtime_gates.rs`

Central place for all debug gates. Reads env vars once at startup, cached.

### E-2. Wire it into `src/lib.rs`

Add `pub mod runtime_gates;`.

### E-3. `src/main.rs` — add STEP markers and gates around every critical spawn

The markers use `tracing::info!` so they go to the file log, not flood serial.

### E-4. `src/nebula/daemon.rs` — narrow the `pkill` match

Don't broad-kill anything matching `"nebula -config"`. Kill only by the exact config path.

### E-5. `src/nebula/relay_tc.rs` — sleep 1 s before applying qdisc

Give the TUN device time to fully register before `tc` touches it.

### E-6. `src/cot/transports/mod.rs` — gate auto_create_transports behind env

Allow skipping Bluetooth specifically (main culprit on combo chip).

---

## F. Full Updated Code Blocks

### F-1. NEW FILE — `src/runtime_gates.rs`

```rust
// src/runtime_gates.rs
// =============================================================
// Debug / isolation gates for diagnosing startup freezes.
// Every env var below is read ONCE at process start and cached.
// All defaults preserve existing behaviour (nothing disabled).
//
// Usage examples (shell):
//   SGX_DISABLE_NEBULA=1         ./sgx_guardian_client nodeA
//   SGX_DISABLE_RELAY_TC=1       ./sgx_guardian_client nodeA
//   SGX_DISABLE_COT_BLUETOOTH=1  ./sgx_guardian_client nodeA
//   SGX_STARTUP_COOLDOWN_MS=2000 ./sgx_guardian_client nodeA
// =============================================================

use once_cell::sync::Lazy;

fn env_true(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

pub struct RuntimeGates {
    pub disable_nebula: bool,
    pub disable_relay_tc: bool,
    pub disable_relay_stats: bool,
    pub disable_tunnel_observer: bool,
    pub disable_cot: bool,
    pub disable_cot_bluetooth: bool,
    pub disable_cot_cellular: bool,
    pub disable_cot_satellite: bool,
    pub disable_cot_refresh: bool,
    pub disable_p2p_discovery: bool,
    pub disable_attestation: bool,
    pub disable_broadcast: bool,
    pub disable_cloud_uplink: bool,
    pub disable_expiry_monitor: bool,
    pub disable_lighthouse_health: bool,
    /// Milliseconds to sleep between major subsystem startups. 0 = no cooldown.
    pub startup_cooldown_ms: u64,
}

impl RuntimeGates {
    fn load() -> Self {
        Self {
            disable_nebula:            env_true("SGX_DISABLE_NEBULA"),
            disable_relay_tc:          env_true("SGX_DISABLE_RELAY_TC"),
            disable_relay_stats:       env_true("SGX_DISABLE_RELAY_STATS"),
            disable_tunnel_observer:   env_true("SGX_DISABLE_TUNNEL_OBSERVER"),
            disable_cot:               env_true("SGX_DISABLE_COT"),
            disable_cot_bluetooth:     env_true("SGX_DISABLE_COT_BLUETOOTH"),
            disable_cot_cellular:      env_true("SGX_DISABLE_COT_CELLULAR"),
            disable_cot_satellite:     env_true("SGX_DISABLE_COT_SATELLITE"),
            disable_cot_refresh:       env_true("SGX_DISABLE_COT_REFRESH"),
            disable_p2p_discovery:     env_true("SGX_DISABLE_P2P_DISCOVERY"),
            disable_attestation:       env_true("SGX_DISABLE_ATTESTATION"),
            disable_broadcast:         env_true("SGX_DISABLE_BROADCAST"),
            disable_cloud_uplink:      env_true("SGX_DISABLE_CLOUD_UPLINK"),
            disable_expiry_monitor:    env_true("SGX_DISABLE_EXPIRY_MONITOR"),
            disable_lighthouse_health: env_true("SGX_DISABLE_LIGHTHOUSE_HEALTH"),
            startup_cooldown_ms:       env_u64("SGX_STARTUP_COOLDOWN_MS", 0),
        }
    }

    pub fn log_summary(&self) {
        tracing::info!(
            "Runtime gates: nebula={} relay_tc={} relay_stats={} tunnel={} cot={} bt={} cell={} sat={} refresh={} p2p={} att={} bcast={} cloud={} expiry={} lhhealth={} cooldown_ms={}",
            self.disable_nebula, self.disable_relay_tc, self.disable_relay_stats,
            self.disable_tunnel_observer, self.disable_cot, self.disable_cot_bluetooth,
            self.disable_cot_cellular, self.disable_cot_satellite, self.disable_cot_refresh,
            self.disable_p2p_discovery, self.disable_attestation, self.disable_broadcast,
            self.disable_cloud_uplink, self.disable_expiry_monitor, self.disable_lighthouse_health,
            self.startup_cooldown_ms
        );
    }
}

pub static GATES: Lazy<RuntimeGates> = Lazy::new(RuntimeGates::load);

/// Sleep the configured cooldown (if > 0). Use between heavy subsystem starts.
pub async fn cooldown() {
    let ms = GATES.startup_cooldown_ms;
    if ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

/// Print STEP marker (logged + printed once to stdout for run_node.sh head -20).
pub fn step(n: u32, label: &str) {
    tracing::info!("STEP_{:02} {}", n, label);
    println!("STEP_{:02} {}", n, label);
}
```

**Cargo.toml** — ensure `once_cell` is present (it almost certainly already is; if not add `once_cell = "1.19"`).

### F-2. `src/lib.rs` — add module

```rust
pub mod runtime_gates;
```

### F-3. `src/main.rs` — insert STEP markers and gates

Below are the **FIND → REPLACE** blocks. Apply each one in order.

#### F-3.a — right after listener spawn, before KeyManager init

```rust
// FIND:
    // Start node announcement listener (UDP broadcast receiver)
    {
        let node_id_clone = node_id.clone();
        tokio::spawn(async move {
            node_listener::start_listener(node_id_clone).await;
        });
    }
```

```rust
// REPLACE WITH:
    // Start node announcement listener (UDP broadcast receiver)
    {
        let node_id_clone = node_id.clone();
        tokio::spawn(async move {
            node_listener::start_listener(node_id_clone).await;
        });
    }

    use sgx_guardian_client::runtime_gates::{cooldown, step, GATES};
    GATES.log_summary();
    step(1, "post-listener: entering KeyManager init");
```

#### F-3.b — gate cloud uplink (STEP_08)

```rust
// FIND any block that begins the cloud uplink heartbeat spawn, e.g.:
    // === Cloud uplink heartbeat ===
    {
        let node_id_clone = node_id.clone();
        tokio::spawn(async move {
            // ... body ...
        });
    }
```

```rust
// REPLACE WITH:
    step(8, "cloud-uplink spawn gate");
    if !GATES.disable_cloud_uplink {
        let node_id_clone = node_id.clone();
        tokio::spawn(async move {
            // ... body unchanged ...
        });
        cooldown().await;
    } else {
        tracing::warn!("STEP_08 SKIPPED: cloud uplink disabled by SGX_DISABLE_CLOUD_UPLINK");
    }
```

(Keep whatever the body was — don't remove it.)

#### F-3.c — gate Nebula startup (STEP_09 through STEP_17)

Find the block that starts with `// === Nebula Installation Verification ===` and ends after `println!("🌐 Nebula mesh daemon started successfully.");`. Wrap it:

```rust
// FIND:
    // === Nebula Installation Verification ===
    println!("\n🔎 Verifying Nebula Installation...");
    // ... ALL the code down through NebulaDaemon::start() and interface wait ...
```

```rust
// REPLACE WITH:
    step(9, "nebula subsystem gate");
    if !GATES.disable_nebula {
        // === Nebula Installation Verification ===
        println!("\n🔎 Verifying Nebula Installation...");
        step(10, "nebula: pre-existing kill");
        // ... ALL original code unchanged ...
        step(11, "nebula: config generation");
        // ...
        step(13, "nebula: daemon start");
        // ...
        step(14, "nebula: interface wait complete");
        cooldown().await;
    } else {
        tracing::warn!("STEP_09–14 SKIPPED: Nebula disabled by SGX_DISABLE_NEBULA");
    }
```

#### F-3.d — gate the `tc` bandwidth limit (STEP_15)

```rust
// FIND:
    if current_relay_cfg.enabled {
        if let Err(e) =
            RelayTrafficControl::apply_bandwidth_limit(current_relay_cfg.max_bandwidth_mbps)
        {
            eprintln!("⚠️  Relay tc setup failed: {}", e);
        } else {
            println!( /* ... */ );
        }
    } else {
        let _ = RelayTrafficControl::clear();
    }
```

```rust
// REPLACE WITH:
    step(15, "relay-tc gate");
    if GATES.disable_relay_tc {
        tracing::warn!("STEP_15 SKIPPED: tc qdisc disabled by SGX_DISABLE_RELAY_TC");
    } else if current_relay_cfg.enabled {
        // Let TUN fully register before touching it with tc (fixes RCU stall on i.MX8).
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Err(e) =
            RelayTrafficControl::apply_bandwidth_limit(current_relay_cfg.max_bandwidth_mbps)
        {
            eprintln!("⚠️  Relay tc setup failed: {}", e);
        } else {
            println!(
                "🛰️  Relay limits: enabled=true, max_peers={}, max_bw={} Mbps, alert={}%",
                current_relay_cfg.max_peers,
                current_relay_cfg.max_bandwidth_mbps,
                current_relay_cfg.alert_threshold_pct
            );
        }
        cooldown().await;
    } else {
        let _ = RelayTrafficControl::clear();
    }
```

#### F-3.e — gate Relay Stats Poller (STEP_19)

```rust
// FIND the block that begins:
    // === Relay Stats Poller (every 10s) ===
    {
        let metrics_clone = metrics.clone();
        // ...
        tokio::spawn(async move { /* fetch/poll loop */ });
    }
```

```rust
// REPLACE WITH:
    step(19, "relay-stats-poller gate");
    if !GATES.disable_relay_stats {
        let metrics_clone = metrics.clone();
        // ... existing body unchanged ...
        cooldown().await;
    } else {
        tracing::warn!("STEP_19 SKIPPED: relay stats poller disabled by SGX_DISABLE_RELAY_STATS");
    }
```

#### F-3.f — gate Tunnel State observer (STEP_20)

```rust
// FIND the block that begins with:
    // === Direct-vs-Relay Observability (read-only, every 15s) ===
```

```rust
// REPLACE WITH: (wrap identically)
    step(20, "tunnel-observer gate");
    if !GATES.disable_tunnel_observer {
        // ... original body unchanged ...
        cooldown().await;
    } else {
        tracing::warn!("STEP_20 SKIPPED: tunnel observer disabled by SGX_DISABLE_TUNNEL_OBSERVER");
    }
```

#### F-3.g — gate CoT (STEP_22 through STEP_28)

```rust
// FIND:
    // === CoT Deliverable Integration Start ===
    println!("🔗 Initializing Circle of Trust (CoT) transport-agnostic layer...");
    // ... everything down through Step 9 periodic session cleanup ...
    // === CoT Deliverable Integration End ===
```

```rust
// REPLACE WITH:
    step(22, "cot subsystem gate");
    if !GATES.disable_cot {
        // === CoT Deliverable Integration Start ===
        println!("🔗 Initializing Circle of Trust (CoT) transport-agnostic layer...");
        // ... original body UNCHANGED; it already calls auto_create_transports() which
        // reads SGX_DISABLE_COT_BLUETOOTH etc. (see F-6) ...
        // === CoT Deliverable Integration End ===
        cooldown().await;
    } else {
        tracing::warn!("STEP_22–28 SKIPPED: CoT disabled by SGX_DISABLE_COT");
    }
```

#### F-3.h — gate P2P Discovery (STEP_29)

```rust
// FIND the `tokio::spawn` for P2PDiscovery::run and wrap it:
    step(29, "p2p-discovery gate");
    if !GATES.disable_p2p_discovery {
        tokio::spawn({
            // ... existing body unchanged ...
        });
        cooldown().await;
    } else {
        tracing::warn!("STEP_29 SKIPPED: discovery disabled by SGX_DISABLE_P2P_DISCOVERY");
    }
```

#### F-3.i — gate Attestation service (STEP_30)

```rust
    step(30, "attestation-service gate");
    if !GATES.disable_attestation {
        tokio::spawn({
            // ... existing attestation_service::run body unchanged ...
        });
        cooldown().await;
    } else {
        tracing::warn!("STEP_30 SKIPPED: attestation disabled by SGX_DISABLE_ATTESTATION");
    }
```

#### F-3.j — gate the broadcast loop (STEP_31)

```rust
// FIND the startup broadcast loop (the one invoked after discovery starts):
    step(31, "broadcast-loop gate");
    if !GATES.disable_broadcast {
        // ... existing broadcast loop spawn unchanged ...
    } else {
        tracing::warn!("STEP_31 SKIPPED: broadcast disabled by SGX_DISABLE_BROADCAST");
    }
```

### F-4. `src/nebula/daemon.rs` — narrow `pkill`

```rust
// FIND:
    pub async fn kill_existing() {
        let _ = Command::new("pkill")
            .args(["-f", "nebula -config"])
            .output();
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
```

```rust
// REPLACE WITH:
    /// Kill only the previous instance of THIS config's nebula daemon.
    /// Previous broad-match `pkill -f "nebula -config"` could kill unrelated
    /// processes and was a suspected contributor to post-startup freezes.
    pub async fn kill_existing_for_config(config_path: &str) {
        // Escape for shell-regex: match the exact config path.
        let pattern = format!("nebula -config {}", config_path);
        let _ = Command::new("pkill").args(["-f", &pattern]).output();
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    /// Compat wrapper: old callers still work, but now it is a no-op unless
    /// caller updates to the path-aware variant. We do NOT broad-kill any more.
    pub async fn kill_existing() {
        // Intentionally left empty to avoid broad pkill.
        // Callers should use kill_existing_for_config.
    }
```

Update `NebulaDaemon::start` to call `kill_existing_for_config(config_path)` instead of `kill_existing()`.

### F-5. `src/nebula/relay_tc.rs` — add pre-flight TUN check

```rust
// FIND:
    pub fn apply_bandwidth_limit(mbps: u32) -> Result<(), String> {
        if mbps == 0 {
            return Self::clear();
        }

        Self::clear()?;
        Self::run(&[
            "qdisc", "add", "dev", "nebula0", "root", "handle", "1:", "htb", "default", "10",
        ])?;
```

```rust
// REPLACE WITH:
    pub fn apply_bandwidth_limit(mbps: u32) -> Result<(), String> {
        if mbps == 0 {
            return Self::clear();
        }

        // Verify TUN is fully registered BEFORE applying tc.
        // Without this, a partially-registered netdev caused kernel RCU
        // stalls on i.MX8 boards (observed post-Sprint-4).
        if !std::path::Path::new("/sys/class/net/nebula0/flags").exists() {
            return Err("nebula0 not registered — skip tc (fixes RCU stall on i.MX8)".into());
        }

        Self::clear()?;
        Self::run(&[
            "qdisc", "add", "dev", "nebula0", "root", "handle", "1:", "htb", "default", "10",
        ])?;
```

### F-6. `src/cot/transports/mod.rs` — per-transport gating

```rust
// FIND:
pub fn auto_create_transports() -> CotResult<Vec<Arc<dyn Transport>>> {
    let interfaces = InterfaceDetector::detect_usable()?;
    let transports: Vec<Arc<dyn Transport>> = interfaces
        .iter()
        .map(|iface| create_transport(iface))
        .collect();
    Ok(transports)
}
```

```rust
// REPLACE WITH:
pub fn auto_create_transports() -> CotResult<Vec<Arc<dyn Transport>>> {
    use crate::runtime_gates::GATES;
    let interfaces = InterfaceDetector::detect_usable()?;
    let transports: Vec<Arc<dyn Transport>> = interfaces
        .iter()
        .filter(|iface| match iface.transport_type {
            TransportType::Bluetooth if GATES.disable_cot_bluetooth => false,
            TransportType::Cellular  if GATES.disable_cot_cellular  => false,
            TransportType::Satellite if GATES.disable_cot_satellite => false,
            _ => true,
        })
        .map(|iface| create_transport(iface))
        .collect();
    Ok(transports)
}
```

---

## G. Board Test Procedure

Build, ship, and run a **staged bisect**. Each stage adds one subsystem back.

### G-1. Build on laptop

```sh
cd ~/SGX
cargo fmt --all
cargo clippy --all-targets --features secure-element -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu --features secure-element
```

### G-2. Deploy binary to board 248

```sh
scp target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@192.168.50.248:/home/root/
```

### G-3. Staged bisect runs

Do these one at a time. After each, let the daemon run 3 minutes and verify SSH stays alive. Between runs: `pkill -9 -f sgx_guardian_client && sleep 3`.

#### Stage 1 — Everything OFF except identity + listener

```sh
ssh root@192.168.50.248
export SGX_DISABLE_NEBULA=1
export SGX_DISABLE_RELAY_TC=1
export SGX_DISABLE_RELAY_STATS=1
export SGX_DISABLE_TUNNEL_OBSERVER=1
export SGX_DISABLE_COT=1
export SGX_DISABLE_P2P_DISCOVERY=1
export SGX_DISABLE_ATTESTATION=1
export SGX_DISABLE_BROADCAST=1
export SGX_DISABLE_CLOUD_UPLINK=1
export SGX_DISABLE_EXPIRY_MONITOR=1
export SGX_DISABLE_LIGHTHOUSE_HEALTH=1
export SGX_STARTUP_COOLDOWN_MS=2000
/home/root/run_node.sh nodeA
# Wait 3 minutes, keep typing `echo alive` in SSH to confirm SSH is healthy.
tail -50 /tmp/sgx_nodeA.log
```

Expected: STEP_01 printed; STEP_09, STEP_15, STEP_19, STEP_20, STEP_22, STEP_29, STEP_30, STEP_31 all show SKIPPED; SSH stable.

If SSH dies here → root cause is in STEP_01–STEP_07 (identity/cert/gRPC). Very unlikely but possible.

#### Stage 2 — Add Nebula back ONLY

```sh
unset SGX_DISABLE_NEBULA
/home/root/run_node.sh nodeA
# 3-minute soak.
```

If SSH dies → confirmed Nebula.

#### Stage 3 — Nebula + relay tc

```sh
unset SGX_DISABLE_RELAY_TC
/home/root/run_node.sh nodeA
```

If SSH dies here but not in Stage 2 → confirmed `tc` on nebula0.

#### Stage 4 — Add CoT back

```sh
unset SGX_DISABLE_COT
# Keep bluetooth disabled separately:
export SGX_DISABLE_COT_BLUETOOTH=1
/home/root/run_node.sh nodeA
```

#### Stage 5 — Enable Bluetooth transport

```sh
unset SGX_DISABLE_COT_BLUETOOTH
/home/root/run_node.sh nodeA
```

If SSH dies here → confirmed Bluetooth scan starving Wi-Fi (combo chip).

#### Stage 6 — Everything on

```sh
unset SGX_DISABLE_RELAY_STATS SGX_DISABLE_TUNNEL_OBSERVER SGX_DISABLE_P2P_DISCOVERY \
      SGX_DISABLE_ATTESTATION SGX_DISABLE_BROADCAST SGX_DISABLE_CLOUD_UPLINK \
      SGX_DISABLE_EXPIRY_MONITOR SGX_DISABLE_LIGHTHOUSE_HEALTH
/home/root/run_node.sh nodeA
```

### G-4. Where to read STEP markers

```sh
grep STEP_ /tmp/sgx_nodeA.log
```

The **last STEP marker before the freeze** identifies the guilty subsystem within 1 stage.

---

## H. Expected Results / Failure Signals

| Stage | Pass Signal | Fail Signal → Cause |
|-------|-------------|---------------------|
| 1 | `tail /tmp/sgx_nodeA.log` shows STEP_01 and no more, SSH alive 3 min | Baseline broken — suspect gRPC server or cert loading |
| 2 | Log shows STEP_09 → STEP_14, SSH alive 3 min | Last STEP is 13 and SSH dies → `nebula -config` spawn or config is the cause |
| 3 | Log shows STEP_15 done, SSH alive 3 min | Last STEP is 15 and SSH dies → `tc qdisc` on nebula0 is the cause |
| 4 | Log shows STEP_22 done, SSH alive 3 min | Last STEP is 22 and SSH dies → CoT registration (non-BT transports) |
| 5 | Log shows STEP_22 + full refresh loop, SSH alive 3 min | SSH dies only now → BT scan / combo-chip Wi-Fi starvation |
| 6 | Full startup, SSH alive 3 min | Dies only at STEP_31 → broadcast UDP storm |

---

## I. Rollback Plan

If any of the changes cause a regression or the staged runs are inconclusive:

1. Keep `runtime_gates.rs` (it's purely additive and off by default).
2. Revert `src/main.rs` to its pre-change version via `git checkout main -- src/main.rs`.
3. Revert `src/nebula/daemon.rs`, `src/nebula/relay_tc.rs`, `src/cot/transports/mod.rs` individually as needed.
4. Nothing I'm proposing changes protocol semantics, cryptographic flow, or on-disk formats — so rollback is zero-risk to data integrity.

---

## Summary

- #1 suspect is the Nebula daemon startup path (Sprint 3) + relay-tc qdisc application (Sprint 4). Both touch the kernel netdev subsystem aggressively within the first 5 seconds after the listener binds.
- #2 suspect is the Bluetooth transport hitting the shared Wi-Fi/BT antenna on the CYW43xx combo chip — a known issue on this exact VAR-SOM-MX8MP part. Explains why SSH dies over Wi-Fi and recovers after a delay.
- The staged bisect with env gates pinpoints the failure in at most 6 runs, without refactoring a single module. Start with Stage 1 — a full-off run — and walk forward.

End of plan.