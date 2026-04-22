# SG-X Guardian — Sprint 4: CoT Satellite + Transport Auto-Detection Plan
**Date:** April 10, 2026
**Target:** April 22, 2026
**Deliverable ID (per Payment Schedule):** Multi-Transport CoT — CoT Extended (Satellite), Transport Auto Detection

---

## Honest State of the CoT Layer (from latest `main`)

Pulled from `project_knowledge_search`. Here is what exists today — not a guess:

| Component | Status |
|---|---|
| `cot/types.rs` | ✅ Satellite variant in `TransportType` enum, priority = 50 |
| `cot/interface_detector.rs` | ✅ Classifies `sat*` → Satellite (pattern-match only) |
| `cot/transports/satellite.rs` | ❌ **STUB** — `is_available() → false`, `send()` returns error, `display_name()` contains `[STUB]` |
| `cot/transports/bluetooth.rs` | ✅ **REAL** — adapter_powered check, RSSI, PAN connection, scan_guardians |
| `cot/transports/ethernet.rs` | ✅ Real |
| `cot/transports/wifi.rs` | ✅ Real |
| `cot/transports/cellular.rs` | ✅ Real |
| `cot/transport_registry.rs` | ✅ `best_available()` with priority sort, `health_check_all()` |
| `cot/transports/mod.rs` | ✅ `auto_create_transports()` factory works for all 5 types |
| `main.rs` CoT init | ✅ Detects interfaces, registers transports, prints summary |
| **Failover wiring** | ❌ NOT IMPLEMENTED — registry has best_available() but nobody calls it on link loss |
| **Hot-plug detection** | ❌ Periodic re-scan exists (30s) but doesn't trigger route change |
| **Session survival across switch** | ❌ Sessions keyed on transport, not on device_id |
| **Admin observability (active transport)** | ❌ No CLI, no metric |

**Net:** The CoT skeleton is mature. Satellite is a stub. Auto-detection exists but is passive — we classify interfaces but don't react to changes. The Sprint 4 task is: replace the satellite stub + make auto-detection **active** (drive routing decisions).

---

## Honest Hardware Reality for Satellite

This is the part where other plans would pretend we can test everything. We cannot.

| Satellite Type | Interface Pattern | Can Test in Sprint 4? |
|---|---|---|
| **Starlink** (dishy via router) | `eth*` / `ens*` (appears as Ethernet) | ⚠️ Only if someone has Starlink hardware; indistinguishable from regular Ethernet at OS level |
| **Iridium Certus** (modem via USB) | `/dev/ttyACM*` → `ppp*` after PPP dial | ❌ No modem on testbed |
| **Inmarsat BGAN** (modem via USB) | `usb*` (specific Vendor/Product IDs) | ❌ No modem on testbed |
| **Globalstar / Orbcomm** (serial modems) | `/dev/ttyUSB*` | ❌ No modem on testbed |

**What we will do:**
1. Implement `SatelliteTransport` with real code paths (not a stub) that handle all 4 cases
2. Add a **mocked satellite interface** to the test harness so auto-detection + failover can be integration-tested
3. Document which code paths are unit-tested only vs integration-tested
4. Structurally correct code that works when real hardware arrives

**What we will NOT claim:**
- That we've "verified satellite works in production" (we haven't, no hardware)
- That latency / packet loss characteristics are tuned for Iridium specifically (we'll use reasonable defaults)

---

## 12 Deliverables

| # | Deliverable | Effort | Risk |
|---|---|---|---|
| 1 | Replace Satellite Stub with Real Transport | 1.5d | LOW |
| 2 | Satellite Interface Classification (all 4 vendor patterns) | 1d | LOW |
| 3 | Link Quality Monitor (per-transport metrics) | 1.5d | LOW |
| 4 | Hot-Plug Interface Event Handler | 1.5d | MEDIUM |
| 5 | Active Failover Engine (with hysteresis) | 2d | MEDIUM |
| 6 | Session Survival Across Transport Swap | 1.5d | MEDIUM |
| 7 | Transport Lock / Force Override (admin control) | 1d | LOW |
| 8 | Admin CLI: `transport-list`, `transport-stats`, `transport-lock` | 1d | LOW |
| 9 | Metrics Exposure (Prometheus) | 1d | LOW |
| 10 | Mock Satellite Test Harness | 1.5d | LOW |
| 11 | Failover Integration Test (3-transport cycle) | 1.5d | LOW |
| 12 | Admin Runbook + Transport Guide | 1d | LOW |

**Total: ~15.5 days. Parallelizable across 2 engineers. Solo will overrun by ~3 days.**

Dependencies: Relies on Sprint 3 Issue 5/6 fixes being in main (self-attestation bug fixed, approval YAML simplified).

---

# Deliverable 1 — Replace Satellite Stub with Real Transport

## What

`src/cot/transports/satellite.rs` is currently a stub. Replace with a working implementation that handles the 4 satellite modem families.

## How

```rust
// src/cot/transports/satellite.rs (new implementation)
use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq)]
pub enum SatelliteKind {
    Starlink,     // appears as eth*; detected by ASN lookup or explicit config
    Iridium,      // ppp* after chat script dial-up
    Inmarsat,     // usb* with specific VID:PID
    Generic,      // sat* / unknown — use default characteristics
}

#[derive(Debug, Clone)]
pub struct SatelliteTransport {
    interface: InterfaceInfo,
    kind: SatelliteKind,
    /// Expected baseline latency in ms (Iridium=1500, Starlink=50, Inmarsat=700)
    expected_latency_ms: u64,
    /// Bandwidth ceiling in kbps (Iridium=88, Starlink=100000, Inmarsat=492)
    expected_bandwidth_kbps: u64,
}

impl SatelliteTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        let kind = Self::detect_kind(&interface);
        let (expected_latency_ms, expected_bandwidth_kbps) = match kind {
            SatelliteKind::Starlink  => (50,   100_000),
            SatelliteKind::Iridium   => (1500, 88),
            SatelliteKind::Inmarsat  => (700,  492),
            SatelliteKind::Generic   => (500,  1_000),
        };
        Self { interface, kind, expected_latency_ms, expected_bandwidth_kbps }
    }

    fn detect_kind(iface: &InterfaceInfo) -> SatelliteKind {
        let name = iface.name.to_lowercase();
        // Env override for testing
        if let Ok(forced) = std::env::var("SGX_SAT_KIND") {
            return match forced.as_str() {
                "starlink" => SatelliteKind::Starlink,
                "iridium"  => SatelliteKind::Iridium,
                "inmarsat" => SatelliteKind::Inmarsat,
                _ => SatelliteKind::Generic,
            };
        }
        if name.starts_with("ppp") { SatelliteKind::Iridium }
        else if name.starts_with("usb") { SatelliteKind::Inmarsat }
        else if name.starts_with("sat") { SatelliteKind::Generic }
        else { SatelliteKind::Starlink }  // default for eth* flagged as satellite
    }

    /// Probe the interface by pinging its default gateway.
    /// Returns measured RTT or None if unreachable.
    async fn probe_latency(&self) -> Option<u64> {
        let gw = Self::interface_gateway(&self.interface.name)?;
        let start = std::time::Instant::now();
        // Short TCP connect to common port 53 (DNS) on gateway
        match timeout(Duration::from_secs(5), TcpStream::connect(format!("{}:53", gw))).await {
            Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
            _ => None,
        }
    }

    fn interface_gateway(iface: &str) -> Option<String> {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default", "dev", iface])
            .output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace().nth(2).map(|s| s.to_string())
    }
}

#[async_trait]
impl Transport for SatelliteTransport {
    fn transport_type(&self) -> TransportType { TransportType::Satellite }
    fn priority(&self) -> TransportPriority { self.interface.priority }

    async fn is_available(&self) -> bool {
        if !self.interface.is_usable() { return false; }
        // Probe actual reachability — don't trust link state alone
        self.probe_latency().await.is_some()
    }

    async fn send(&self, message: &TransportMessage) -> CotResult<()> {
        if !self.is_available().await {
            return Err(CotError::TransportError(format!(
                "Satellite ({:?}) unavailable: {}", self.kind, self.interface.name
            )));
        }
        // Actual send goes via the standard TCP/UDP socket path —
        // the kernel picks the route based on destination IP.
        // The `target_address` field already carries ip:port.
        let mut stream = timeout(
            Duration::from_secs(30),  // satellite can be slow
            TcpStream::connect(&message.target_address),
        ).await
         .map_err(|_| CotError::TransportError("Satellite send timeout".into()))?
         .map_err(|e| CotError::TransportError(format!("Satellite connect: {}", e)))?;
        use tokio::io::AsyncWriteExt;
        stream.write_all(&message.payload).await
            .map_err(|e| CotError::TransportError(format!("Satellite write: {}", e)))?;
        Ok(())
    }

    async fn health_check(&self) -> TransportHealth {
        match self.probe_latency().await {
            Some(ms) => TransportHealth::healthy(ms, self.expected_bandwidth_kbps),
            None => TransportHealth::unhealthy(&format!(
                "Satellite ({:?}) unreachable", self.kind
            )),
        }
    }

    fn display_name(&self) -> String {
        format!("Satellite-{:?}({})", self.kind, self.interface.name)
    }
}
```

## Verification

```bash
cargo test --lib satellite::tests
# Must cover:
#   test_satellite_type_is_satellite
#   test_priority_inherits_from_interface
#   test_kind_detection_iridium  (ppp0)
#   test_kind_detection_inmarsat (usb0)
#   test_kind_detection_generic  (sat0)
#   test_display_name_includes_kind
#   test_display_name_no_stub_marker  ← must NOT contain "[STUB]"
```

## Validation

```bash
# 1. Manual mock: create a dummy ppp0 interface
sudo ip tuntap add mode tun dev ppp0
sudo ip addr add 10.0.0.1/30 dev ppp0
sudo ip link set dev ppp0 up

# 2. Start sgx_guardian_client
cargo run -- nodeA

# 3. Expected log line:
#    "📡 Detected N network interfaces:"
#    "   ppp0 → Satellite [UP] ...: Some(10.0.0.1)"
# Transport registry summary should include "Satellite-Iridium(ppp0)"

# 4. Cleanup
sudo ip link del ppp0
```

---

# Deliverable 2 — Satellite Interface Classification (All 4 Patterns)

## What

`interface_detector.rs::classify_interface` currently only recognizes `sat*`. Add patterns for Iridium (`ppp*`), Inmarsat (`usb*` with sat VID/PID), and Starlink (via explicit config override).

## How

```rust
// src/cot/interface_detector.rs — update classify_interface
fn classify_interface(name: &str) -> Option<TransportType> {
    let lower = name.to_lowercase();

    // SATELLITE — check BEFORE cellular (usb* overlap)
    if lower.starts_with("ppp") {
        return Some(TransportType::Satellite);  // Iridium/PPP dial-up
    }
    if Self::is_satellite_usb_modem(&lower) {
        return Some(TransportType::Satellite);  // Inmarsat / specific USB sat modems
    }
    if lower.starts_with("sat") {
        return Some(TransportType::Satellite);  // explicit naming
    }

    // ETHERNET — Starlink appears here; distinguish via env override
    if lower.starts_with("eth") || lower.starts_with("en") {
        // Admin can force an Ethernet-named interface to be treated as Satellite
        if let Ok(forced) = std::env::var("SGX_SATELLITE_INTERFACES") {
            if forced.split(',').any(|n| n.trim() == name) {
                return Some(TransportType::Satellite);
            }
        }
        return Some(TransportType::Ethernet);
    }

    if lower.starts_with("wlan") || lower.starts_with("wl") || lower.starts_with("wlp") {
        return Some(TransportType::WiFi);
    }

    if lower.starts_with("bnep") || lower.starts_with("bt") || lower.starts_with("hci") {
        return Some(TransportType::Bluetooth);
    }

    if lower.starts_with("wwan") || lower.starts_with("rmnet") {
        return Some(TransportType::Cellular);
    }

    // Generic usb* — could be cellular OR satellite; default to cellular
    // (Inmarsat check above handles known sat USB modems)
    if lower.starts_with("usb") {
        return Some(TransportType::Cellular);
    }

    None
}

fn is_satellite_usb_modem(iface_name: &str) -> bool {
    // Known Inmarsat / Iridium USB VID/PIDs
    // Check /sys/class/net/<iface>/device/uevent for ID_VENDOR_ID, ID_MODEL_ID
    let path = format!("/sys/class/net/{}/device/uevent", iface_name);
    let Ok(content) = std::fs::read_to_string(&path) else { return false; };

    const SAT_VENDOR_IDS: &[&str] = &[
        "1546",  // Iridium 9602/9603 SBD modems
        "1bc7",  // Telit (some Inmarsat variants)
        "0846",  // NetGear (Inmarsat BGAN)
    ];

    for line in content.lines() {
        if let Some(vid) = line.strip_prefix("ID_VENDOR_ID=") {
            if SAT_VENDOR_IDS.contains(&vid.trim()) {
                return true;
            }
        }
    }
    false
}
```

## Verification

```bash
cargo test classify_interface
# Must cover:
#   test_classify_ppp_as_satellite
#   test_classify_sat_prefix
#   test_classify_eth_with_env_override_as_satellite
#   test_classify_eth_without_override_as_ethernet
#   test_classify_usb_default_cellular
```

## Validation

```bash
# Test 1: PPP → Satellite
sudo ip tuntap add mode tun dev ppp0
sudo ip addr add 10.0.0.1/30 dev ppp0
sudo ip link set dev ppp0 up
SGX_DEBUG_DETECT=1 cargo run --example detect_interfaces
# Expected: "ppp0 → Satellite"

# Test 2: Explicit Starlink override
sudo ip tuntap add mode tun dev starlink0
sudo ip addr add 10.0.0.1/30 dev starlink0
sudo ip link set dev starlink0 up
SGX_SATELLITE_INTERFACES=starlink0 cargo run --example detect_interfaces
# Expected: "starlink0 → Satellite"

# Cleanup
sudo ip link del ppp0; sudo ip link del starlink0
```

---

# Deliverable 3 — Link Quality Monitor (Per-Transport Metrics)

## What

Currently `health_check()` returns `is_healthy: bool + latency_ms + bandwidth_kbps` but only gets called on `health_check_all()`. We need continuous per-transport link quality tracking to drive failover decisions.

## How

Add a background monitor that polls every transport every 10 seconds and maintains rolling stats:

```rust
// src/cot/link_monitor.rs (new)
use crate::cot::transport_registry::TransportRegistry;
use crate::cot::types::TransportType;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    pub transport_type: TransportType,
    pub is_up: bool,
    pub latency_ms: u64,
    pub bandwidth_kbps: u64,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_probed: i64,
}

pub struct LinkMonitor {
    registry: Arc<TransportRegistry>,
    state: Arc<RwLock<HashMap<TransportType, LinkSnapshot>>>,
}

impl LinkMonitor {
    pub fn new(registry: Arc<TransportRegistry>) -> Arc<Self> {
        Arc::new(Self { registry, state: Arc::new(RwLock::new(HashMap::new())) })
    }

    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            let probe_interval = Duration::from_secs(10);
            loop {
                self.probe_all().await;
                tokio::time::sleep(probe_interval).await;
            }
        });
    }

    async fn probe_all(&self) {
        let transports = self.registry.all_sorted().await;
        for t in transports {
            let health = t.health_check().await;
            let tt = t.transport_type();
            let mut state = self.state.write().await;
            let entry = state.entry(tt).or_insert(LinkSnapshot {
                transport_type: tt,
                is_up: false,
                latency_ms: 0,
                bandwidth_kbps: 0,
                consecutive_failures: 0,
                consecutive_successes: 0,
                last_probed: 0,
            });
            if health.is_healthy {
                entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
                entry.consecutive_failures = 0;
                entry.latency_ms = health.latency_ms;
                entry.bandwidth_kbps = health.bandwidth_kbps;
                entry.is_up = true;
            } else {
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                entry.consecutive_successes = 0;
                entry.is_up = false;
            }
            entry.last_probed = chrono::Utc::now().timestamp();
        }
    }

    pub async fn snapshot(&self, tt: TransportType) -> Option<LinkSnapshot> {
        self.state.read().await.get(&tt).cloned()
    }

    pub async fn all_snapshots(&self) -> Vec<LinkSnapshot> {
        self.state.read().await.values().cloned().collect()
    }
}
```

Wire into `main.rs` after CoT init:

```rust
let link_monitor = LinkMonitor::new(cot_registry.clone());
link_monitor.clone().start();
```

## Verification

```bash
cargo test link_monitor::tests
# Must cover:
#   test_consecutive_failures_increments
#   test_success_resets_failure_count
#   test_snapshot_returns_none_for_untracked
```

## Validation

```bash
# Start nodeA, then:
cargo run -- nodeA 2>&1 | grep -i "link monitor"
# Expected: "📊 Link monitor: Ethernet up (latency=3ms, bw=1000000kbps)"
#           "📊 Link monitor: Cellular up (latency=45ms, bw=10000kbps)"

# Simulate failure: disconnect ethernet
sudo ip link set ens33 down
sleep 20  # wait for 2 probe cycles
# Expected log: "📊 Link monitor: Ethernet down (consecutive_failures=2)"

sudo ip link set ens33 up
sleep 20
# Expected: "📊 Link monitor: Ethernet recovered"
```

---

# Deliverable 4 — Hot-Plug Interface Event Handler

## What

Currently the code re-scans interfaces every 30 seconds but doesn't react to changes. We need to detect when an interface appears/disappears (USB modem plugged in, WiFi reconnected) and update the transport registry immediately.

## How

Option A (portable): poll `/sys/class/net` every 5 seconds, diff against known set.
Option B (Linux-only, real-time): use netlink `RTMGRP_LINK` subscription via `rtnetlink` crate.

Pick A for cross-platform safety. Option B can be a later optimization.

```rust
// src/cot/hotplug.rs (new)
use crate::cot::interface_detector::InterfaceDetector;
use crate::cot::transport_registry::TransportRegistry;
use crate::cot::transports::create_transport;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

pub struct HotplugWatcher;

impl HotplugWatcher {
    pub fn start(registry: Arc<TransportRegistry>) {
        tokio::spawn(async move {
            let mut known: HashSet<String> = HashSet::new();
            loop {
                match InterfaceDetector::detect_all() {
                    Ok(current) => {
                        let current_names: HashSet<String> =
                            current.iter().map(|i| i.name.clone()).collect();

                        // Detect newly added
                        for iface in &current {
                            if !known.contains(&iface.name) && iface.is_usable() {
                                println!("🔌 Hotplug: interface {} appeared (transport={})",
                                    iface.name, iface.transport_type);
                                let transport = create_transport(iface);
                                registry.register(transport).await;
                            }
                        }

                        // Detect removed
                        for old_name in known.difference(&current_names) {
                            println!("🔌 Hotplug: interface {} removed", old_name);
                            // Registry doesn't currently have unregister() —
                            // add it as part of this deliverable
                            registry.unregister_by_interface(old_name).await;
                        }

                        known = current_names;
                    }
                    Err(e) => eprintln!("⚠️ Hotplug scan failed: {}", e),
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }
}
```

Add `unregister_by_interface()` to `TransportRegistry`:

```rust
pub async fn unregister_by_interface(&self, iface_name: &str) {
    let mut entries = self.entries.write().await;
    entries.retain(|_tt, entry| {
        // Transport trait doesn't expose interface name directly;
        // check via display_name which includes the interface
        !entry.transport.display_name().contains(iface_name)
    });
}
```

## Verification

```bash
cargo test hotplug::tests
# test_new_interface_detected
# test_removed_interface_unregistered
# test_no_change_no_op
```

## Validation

```bash
# Start nodeA (no USB modem)
cargo run -- nodeA

# Plug in USB cellular modem
# Expected log within 5s:
#   "🔌 Hotplug: interface wwan0 appeared (transport=Cellular)"
#   "🚛 Transport Registry: [Ethernet(10), Cellular(30)]"

# Unplug modem
# Expected log within 5s:
#   "🔌 Hotplug: interface wwan0 removed"
#   "🚛 Transport Registry: [Ethernet(10)]"
```

---

# Deliverable 5 — Active Failover Engine (with Hysteresis)

## What

The registry already has `best_available()`. What's missing is the **callback** — when the currently-active transport's link fails, someone needs to:
1. Notice the failure (Deliverable 3 gives us consecutive_failures counter)
2. Pick a new transport (Deliverable 3 gives us snapshot; registry gives us best_available)
3. Apply the new transport as "active" (trigger routing update)
4. Avoid flapping via hysteresis

## How

```rust
// src/cot/failover.rs (new)
use crate::cot::link_monitor::LinkMonitor;
use crate::cot::transport_registry::TransportRegistry;
use crate::cot::types::TransportType;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::sync::RwLock;
use tokio::time::Duration;

/// Failure threshold: switch away after N consecutive probe failures
const FAILURE_THRESHOLD: u32 = 3;
/// Recovery threshold: don't switch back until N consecutive successes
const RECOVERY_THRESHOLD: u32 = 5;
/// Minimum time between failover events (prevents flap)
const MIN_SWITCH_INTERVAL_SECS: i64 = 30;

pub struct FailoverEngine {
    monitor: Arc<LinkMonitor>,
    registry: Arc<TransportRegistry>,
    active_transport: Arc<RwLock<Option<TransportType>>>,
    last_switch_at: Arc<RwLock<i64>>,
    manual_lock: Arc<RwLock<Option<TransportType>>>, // admin override
}

impl FailoverEngine {
    pub fn new(monitor: Arc<LinkMonitor>, registry: Arc<TransportRegistry>) -> Arc<Self> {
        Arc::new(Self {
            monitor,
            registry,
            active_transport: Arc::new(RwLock::new(None)),
            last_switch_at: Arc::new(RwLock::new(0)),
            manual_lock: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn lock_to(&self, tt: TransportType) {
        *self.manual_lock.write().await = Some(tt);
        println!("🔒 Transport locked to {} by admin", tt);
    }

    pub async fn unlock(&self) {
        *self.manual_lock.write().await = None;
        println!("🔓 Transport lock removed — automatic selection resumed");
    }

    pub async fn current(&self) -> Option<TransportType> {
        *self.active_transport.read().await
    }

    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                self.evaluate().await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    async fn evaluate(&self) {
        // Admin lock overrides everything
        if let Some(locked) = *self.manual_lock.read().await {
            let mut active = self.active_transport.write().await;
            if *active != Some(locked) {
                *active = Some(locked);
                println!("🔒 Active transport set to {} (admin lock)", locked);
            }
            return;
        }

        // Get current active, if any
        let current = *self.active_transport.read().await;

        // If no active yet, pick best available
        if current.is_none() {
            if let Ok(best) = self.registry.best_available().await {
                let tt = best.transport_type();
                *self.active_transport.write().await = Some(tt);
                *self.last_switch_at.write().await = chrono::Utc::now().timestamp();
                println!("✅ Initial active transport: {}", tt);
            }
            return;
        }

        let current = current.unwrap();
        let now = chrono::Utc::now().timestamp();
        let since_switch = now - *self.last_switch_at.read().await;

        // Check if current transport is failing
        let current_failed = match self.monitor.snapshot(current).await {
            Some(snap) => snap.consecutive_failures >= FAILURE_THRESHOLD,
            None => true,  // no snapshot = treat as failed
        };

        if current_failed {
            // Find the best alternative
            if let Ok(alternative) = self.registry.best_available().await {
                let new_tt = alternative.transport_type();
                if new_tt != current {
                    *self.active_transport.write().await = Some(new_tt);
                    *self.last_switch_at.write().await = now;
                    println!("🔁 Failover: {} → {} (current had {}+ consecutive failures)",
                        current, new_tt, FAILURE_THRESHOLD);
                }
            } else {
                // No alternative — stay on failed one, surface warning
                eprintln!("⚠️  All transports down — no failover target");
            }
            return;
        }

        // Current is healthy. Consider switching BACK to a higher-priority
        // transport only if it's been stably up for RECOVERY_THRESHOLD probes.
        if since_switch >= MIN_SWITCH_INTERVAL_SECS {
            if let Ok(best) = self.registry.best_available().await {
                let best_tt = best.transport_type();
                if best_tt != current && best.priority() < self.current_priority(current).await {
                    let best_stable = match self.monitor.snapshot(best_tt).await {
                        Some(s) => s.consecutive_successes >= RECOVERY_THRESHOLD,
                        None => false,
                    };
                    if best_stable {
                        *self.active_transport.write().await = Some(best_tt);
                        *self.last_switch_at.write().await = now;
                        println!("⬆️  Upgrade: {} → {} (higher priority, {}+ successes)",
                            current, best_tt, RECOVERY_THRESHOLD);
                    }
                }
            }
        }
    }

    async fn current_priority(&self, tt: TransportType) -> crate::cot::types::TransportPriority {
        self.registry.get(tt).await
            .map(|t| t.priority())
            .unwrap_or_default()
    }
}
```

Wire into `main.rs`:

```rust
let failover = FailoverEngine::new(link_monitor.clone(), cot_registry.clone());
failover.clone().start();
```

## Verification

```bash
cargo test failover::tests
# test_initial_selection_picks_best_available
# test_failover_after_threshold
# test_no_flap_within_min_interval
# test_upgrade_to_higher_priority_after_recovery
# test_manual_lock_overrides_automatic
```

## Validation

Three-transport scenario on a dev laptop with ethernet + wifi:

```bash
# Start nodeA (both ethernet and wifi up)
cargo run -- nodeA
# Expected: "✅ Initial active transport: Ethernet"

# Disconnect ethernet (unplug or ip link set ens33 down)
sudo ip link set ens33 down
# Expected within 30s (3 x 10s probes + check):
#   "🔁 Failover: Ethernet → WiFi (current had 3+ consecutive failures)"

# Reconnect ethernet
sudo ip link set ens33 up
# Expected within 60s (5 x 10s probes + hysteresis):
#   "⬆️  Upgrade: WiFi → Ethernet (higher priority, 5+ successes)"
```

---

# Deliverable 6 — Session Survival Across Transport Swap

## What

CoT sessions currently get associated with the transport they were created on. When failover happens, sessions must NOT be torn down — they must continue on the new transport. Trust is keyed on `device_id`, not on transport.

## How

Audit `cot/session_manager.rs` for any field that binds a session to a specific transport. Refactor so session state is transport-agnostic and the router looks up the current active transport on every send.

```rust
// src/cot/session_manager.rs — session struct should NOT include transport_type
pub struct Session {
    pub session_id: String,
    pub peer_device_id: String,  // identity, not transport
    pub established_at: i64,
    pub last_activity: i64,
    pub suspended: bool,
    // REMOVE if present: pub transport_type: TransportType,
}
```

```rust
// src/cot/router.rs — on send, always use the current best transport
pub async fn send_to_peer(&self, peer_device_id: &str, payload: Vec<u8>) -> CotResult<()> {
    let session = self.sessions.get_by_device(peer_device_id).await
        .ok_or_else(|| CotError::SessionInvalid("No session".into()))?;

    // Look up the current active transport AT SEND TIME
    let active = self.failover.current().await
        .ok_or(CotError::NoTransportAvailable)?;
    let transport = self.registry.get(active).await
        .ok_or(CotError::NoTransportAvailable)?;

    // Build message and send
    let msg = TransportMessage::new(
        self.identity.device_id().to_string(),
        peer_device_id.to_string(),
        session.peer_address.clone(),
        payload,
    );
    transport.send(&msg).await
}
```

And add a notification mechanism for failover events:

```rust
// In FailoverEngine:
pub fn on_switch<F>(&self, callback: F)
    where F: Fn(TransportType, TransportType) + Send + Sync + 'static
{
    // Store callback, invoke on every switch
}

// In main.rs:
failover.on_switch(|old, new| {
    log_audit(..., &format!("Transport switched: {} → {}", old, new));
});
```

## Verification

```bash
cargo test session_manager::tests::test_session_survives_transport_change
# Simulated test:
#   1. Create session with transport A
#   2. Mark transport A unavailable
#   3. Verify session still exists, last_activity unchanged
#   4. Send message — should route via transport B, session persists
```

## Validation

```bash
# Start nodeA + nodeB, establish attestation
# nodeB → nodeA via Ethernet

# Disconnect Ethernet on nodeB
sudo ip link set ens33 down

# Within 60s, failover → WiFi
# Verify session count unchanged:
sudo sgx-pa-cli session-list
# Expected: nodeA still in sessions, no session churn
```

---

# Deliverable 7 — Transport Lock / Force Override

## What

Admin needs to force a specific transport (for testing, debugging, or policy reasons). Already scaffolded in Deliverable 5's `manual_lock`. Expose via CLI and config.

## How

YAML config option in node config:

```yaml
cot:
  transport_lock: none   # or: ethernet | wifi | cellular | bluetooth | satellite
```

CLI commands in `sgx-pa-cli`:

```bash
sgx-pa-cli transport-lock cellular
# Locks active transport to Cellular, ignores failover logic

sgx-pa-cli transport-unlock
# Returns to automatic selection

sgx-pa-cli transport-show
# Shows current active + lock status
```

Wire CLI to a local IPC socket (the metrics server is already listening; reuse it with POST endpoints).

## Verification

```bash
cargo test transport_lock::tests
```

## Validation

```bash
sudo sgx-pa-cli transport-lock cellular
# Log: "🔒 Transport locked to Cellular by admin"

# Disconnect cellular modem — no failover to ethernet
sudo ip link set wwan0 down
# Log: "⚠️ Active transport Cellular unavailable; admin lock prevents failover"

sudo sgx-pa-cli transport-unlock
# Log: "🔓 Transport lock removed — automatic selection resumed"
# Within 10s: "✅ Initial active transport: Ethernet"
```

---

# Deliverable 8 — Admin CLI Commands

## What

Three new `sgx-pa-cli` subcommands: `transport-list`, `transport-stats`, `transport-lock`/`transport-unlock`.

## How

```bash
sgx-pa-cli transport-list
# Output:
# Transport    Priority  Status    Latency  Bandwidth   Interface
# Ethernet     10        UP        3 ms     1 Gbps      ens33
# Cellular     30        UP        45 ms    10 Mbps     wwan0
# WiFi         20        DOWN      -        -           (none)
# Bluetooth    40        DOWN      -        -           (none)
# Satellite    50        DOWN      -        -           (none)
#
# Active: Ethernet  (priority=10)
# Lock:   none

sgx-pa-cli transport-stats
# Output:
# Transport    Probes  Failures  Uptime %   Last Switch
# Ethernet     142     2         98.6%      (active)
# Cellular     142     0         100%       2h 14m ago (→ Ethernet)

sgx-pa-cli transport-lock <transport>
sgx-pa-cli transport-unlock
```

## Verification

```bash
cargo test --bin sgx-pa-cli test_transport_commands
```

## Validation

Exercised via Deliverable 7 & 11 validation runs.

---

# Deliverable 9 — Metrics Exposure (Prometheus)

## What

Extend `src/metrics.rs` with per-transport counters, expose via the existing Prometheus endpoint.

## How

```rust
// Metrics to expose (format: Prometheus text)
sgx_cot_transport_up{transport="ethernet"} 1
sgx_cot_transport_up{transport="wifi"} 0
sgx_cot_transport_up{transport="cellular"} 1
sgx_cot_transport_up{transport="bluetooth"} 0
sgx_cot_transport_up{transport="satellite"} 0

sgx_cot_transport_latency_ms{transport="ethernet"} 3
sgx_cot_transport_latency_ms{transport="cellular"} 45

sgx_cot_transport_bandwidth_kbps{transport="ethernet"} 1000000
sgx_cot_transport_bandwidth_kbps{transport="cellular"} 10000

sgx_cot_active_transport_info{transport="ethernet"} 1
sgx_cot_transport_switches_total 3
sgx_cot_transport_switches_total{from="ethernet",to="wifi"} 2
sgx_cot_transport_switches_total{from="wifi",to="ethernet"} 1
```

## Verification

```bash
curl http://localhost:9100/metrics | grep sgx_cot
```

## Validation

```bash
# After failover Ethernet → WiFi:
curl -s http://localhost:9100/metrics | grep sgx_cot_active
# Expected: sgx_cot_active_transport_info{transport="wifi"} 1

# Restart, repeat failover
curl -s http://localhost:9100/metrics | grep sgx_cot_transport_switches_total
# Expected: increments on every switch
```

---

# Deliverable 10 — Mock Satellite Test Harness

## What

We can't test a real sat modem. We CAN create a synthetic interface with satellite-like characteristics (high latency, limited bandwidth, periodic link loss) and use it to test Deliverables 3–6.

## How

```bash
#!/bin/bash
# tests/mock_satellite.sh — creates a TUN interface with tc-imposed sat characteristics

set -e

# Create the interface
sudo ip tuntap add mode tun dev sat0
sudo ip addr add 10.100.0.1/30 dev sat0
sudo ip link set dev sat0 up

# Apply Iridium-like characteristics:
# 1500ms latency, 3% packet loss, 88 kbps bandwidth ceiling
sudo tc qdisc add dev sat0 root handle 1: netem delay 1500ms loss 3%
sudo tc qdisc add dev sat0 parent 1:1 handle 10: tbf rate 88kbit burst 1kb latency 50ms

echo "Mock satellite interface 'sat0' ready:"
echo "  Address:    10.100.0.1/30"
echo "  Latency:    ~1500ms (Iridium-like)"
echo "  Loss:       3%"
echo "  Bandwidth:  88 kbps"
```

Companion teardown:

```bash
#!/bin/bash
# tests/mock_satellite_cleanup.sh
sudo tc qdisc del dev sat0 root 2>/dev/null || true
sudo ip link del sat0
echo "Mock satellite interface removed"
```

Optional: link-flap simulator for failover testing:

```bash
#!/bin/bash
# tests/satellite_flap.sh — toggles sat0 up/down to exercise failover
while true; do
  sleep 30
  sudo ip link set sat0 down
  echo "[flap] sat0 DOWN"
  sleep 15
  sudo ip link set sat0 up
  echo "[flap] sat0 UP"
done
```

## Verification

```bash
./tests/mock_satellite.sh
ip link show sat0 | grep UP
ping -c 3 -I sat0 10.100.0.1  # should show ~1500ms RTT
./tests/mock_satellite_cleanup.sh
```

## Validation

```bash
./tests/mock_satellite.sh
cargo run -- nodeA 2>&1 | grep -i satellite
# Expected:
#   "sat0 → Satellite [UP] ..."
#   "Transport Registry: [..., Satellite(pri=50, avail=true)]"
#   "📊 Link monitor: Satellite up (latency=1500ms, bw=88kbps)"
```

---

# Deliverable 11 — Failover Integration Test (3-Transport Cycle)

## What

End-to-end automated test that cycles through Ethernet → WiFi → Cellular → Satellite and verifies:
- Each transport gets activated in priority order as higher-priority ones fail
- Sessions survive the transitions
- Metrics increment correctly
- Recovery works (link comes back → switch to higher priority)

## How

```bash
#!/bin/bash
# tests/transport_failover_integration.sh

set -e

echo "=== Setup: Start 3-node mesh ==="
./tests/start_testbed.sh  # existing helper

sleep 30  # let attestation settle
baseline_sessions=$(sudo sgx-pa-cli session-list | grep -c "active")

echo "=== Phase 1: Verify Ethernet is active ==="
active=$(sudo sgx-pa-cli transport-show | grep "Active:" | awk '{print $2}')
test "$active" = "Ethernet" || { echo "FAIL: expected Ethernet active"; exit 1; }

echo "=== Phase 2: Disable Ethernet, expect failover to WiFi ==="
sudo ip link set ens33 down
sleep 45  # failover window (3 x 10s probe + 15s slack)
active=$(sudo sgx-pa-cli transport-show | grep "Active:" | awk '{print $2}')
test "$active" = "WiFi" || { echo "FAIL: expected WiFi active"; exit 1; }

# Session count should be unchanged
sessions_now=$(sudo sgx-pa-cli session-list | grep -c "active")
test "$sessions_now" = "$baseline_sessions" || { echo "FAIL: sessions churned"; exit 1; }

echo "=== Phase 3: Disable WiFi, expect failover to Cellular ==="
sudo ip link set wlan0 down
sleep 45
active=$(sudo sgx-pa-cli transport-show | grep "Active:" | awk '{print $2}')
test "$active" = "Cellular" || { echo "FAIL: expected Cellular"; exit 1; }

echo "=== Phase 4: Start mock satellite, disable cellular ==="
./tests/mock_satellite.sh
sudo ip link set wwan0 down
sleep 45
active=$(sudo sgx-pa-cli transport-show | grep "Active:" | awk '{print $2}')
test "$active" = "Satellite" || { echo "FAIL: expected Satellite"; exit 1; }

echo "=== Phase 5: Restore Ethernet, expect upgrade back ==="
sudo ip link set ens33 up
sleep 90  # recovery window (5 x 10s + 30s hysteresis + slack)
active=$(sudo sgx-pa-cli transport-show | grep "Active:" | awk '{print $2}')
test "$active" = "Ethernet" || { echo "FAIL: expected Ethernet (upgrade)"; exit 1; }

echo "=== Phase 6: Verify switch counter ==="
switches=$(curl -s http://localhost:9100/metrics | grep -oP 'sgx_cot_transport_switches_total \K\d+')
test "$switches" -ge "4" || { echo "FAIL: expected >=4 switches, got $switches"; exit 1; }

echo "=== Cleanup ==="
./tests/mock_satellite_cleanup.sh
sudo ip link set wlan0 up
sudo ip link set wwan0 up

echo "=== ALL PHASES PASSED ==="
```

## Verification

`shellcheck tests/transport_failover_integration.sh`

## Validation

Run on the testbed (Asad + Shahzad laptops). Expected: 6 phases pass, ≤ 10 minutes total runtime. Record output as Sprint 4 evidence.

---

# Deliverable 12 — Admin Runbook + Transport Guide

## What

Documentation covering:
1. What each transport is and when to use it
2. How auto-detection works (which interface names map to which transport)
3. Priority order and how to customize
4. How to lock a transport for testing
5. Satellite hardware families and their differences
6. Troubleshooting: transport not detected, failover not triggering, stuck on wrong transport
7. The mock-satellite test harness

`docs/cot_transport_admin_guide.md`

## Verification

Markdown lint, all internal links resolve.

## Validation

Hand to Shahzad without prior context. He runs:
1. Mock satellite setup
2. Lock transport to Cellular
3. Force failover test
Any stuck step → revise doc.

---

## Cross-Cutting Acceptance Criteria

```bash
# Full Sprint 4 validation
cd /path/to/SGX
cargo test --lib  # all unit tests pass
./tests/mock_satellite.sh && \
./tests/transport_failover_integration.sh && \
./tests/mock_satellite_cleanup.sh && \
echo "Sprint 4 CoT-Satellite: PASS"
```

Passes if:
- ✅ `satellite.rs` is not a stub (no `[STUB]` in display_name)
- ✅ All 5 transport types register on boot
- ✅ Hot-plug: USB cellular detected within 5s of plug-in
- ✅ Failover triggers within 45s of link loss
- ✅ No session churn during failover
- ✅ Admin can lock/unlock transport
- ✅ Metrics expose all 5 transports with up/down/latency/bandwidth
- ✅ Mock-satellite interface behaves like Iridium (≈1500ms latency)
- ✅ 3-transport failover cycle completes in under 10 minutes
- ✅ Runbook is self-serve

## What I'm NOT Claiming

- **Not** "production-ready satellite support" — we have no Iridium, Inmarsat, or Starlink hardware to test
- **Not** "works over real LoRa / ZigBee" — scope is the 5 transport types already in `TransportType` enum
- **Not** "CoT messages encrypted over Bluetooth" — CoT relies on Nebula's encryption; if Bluetooth can't carry IP (no BNEP), the whole stack degrades. Document this limitation
- **Not** "sub-second failover" — our probe interval is 10s, threshold is 3 failures, so failover takes 30-45s. Faster failover requires netlink subscription (future work)

## Sprint 4 Dependencies

- Sprint 3 Issue 5 fix (self-attestation bug) MUST be in main
- Sprint 3 Issue 6 fix (LH approval YAML) MUST be in main
- Sprint 4 Multi-Hop Relay: separate track, can parallelize

## Risk & Mitigation

| Risk | Mitigation |
|---|---|
| No satellite hardware available | Use mock-sat TUN interface (Deliverable 10); document limitation clearly |
| Bluetooth flaky on Linux laptops | Mark Bluetooth as "best-effort" in tests; skip BT phase if no dongle |
| Netlink hotplug not portable | Poll-based (Deliverable 4) is cross-platform; netlink is future optimization |
| Session survival bugs | Unit test in Deliverable 6 catches regressions; integration test in Deliverable 11 validates end-to-end |
| Failover flap under noisy conditions | Hysteresis (3 failures to leave, 5 successes + 30s to return) prevents flap |

---

## Effort Breakdown by Day (Single Engineer)

| Day | Work |
|---|---|
| Day 1 (half) | D1: Satellite transport — kind detection, latency probe |
| Day 1 (half) + Day 2 (half) | D1: Satellite transport — send/health_check |
| Day 2 (half) | D2: Interface classification patterns |
| Day 3 | D3: Link quality monitor + rolling stats |
| Day 4 (half) | D3: Wire into main.rs; log output |
| Day 4 (half) + Day 5 | D4: Hotplug watcher + unregister |
| Day 6 | D5: Failover engine — basic path |
| Day 7 | D5: Failover engine — hysteresis + upgrade |
| Day 8 | D6: Session survival refactor |
| Day 9 (half) | D7: Transport lock plumbing |
| Day 9 (half) | D8: CLI subcommands |
| Day 10 (half) | D9: Metrics exposure |
| Day 10 (half) | D10: Mock satellite script |
| Day 11 | D11: Integration test script |
| Day 12 | D11: Run on testbed, fix issues |
| Day 13 (half) | D12: Runbook |
| Day 13 (half) | Buffer / peer review |

13 working days. Sprint 4 window is 12. **1 engineer will overrun by ~1 day**. Two engineers in parallel (one on transports 1–4, one on failover 5–7) finish in ~8 days with slack.