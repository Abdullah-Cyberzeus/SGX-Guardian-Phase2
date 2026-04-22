# Sprint 4 — CoT Satellite + Transport Auto-Detection: Fixed Plan
**Date:** April 22, 2026
**Built against:** Latest `main` branch (verified via project_knowledge_search)
**Status:** No Sprint 4 CoT code exists in main — this plan is from scratch

---

## The Architecture Bug That Broke Everything

Before writing any Sprint 4 code, I need to explain why the previous attempt failed on your VMware testbed. This is the root cause of every issue you pasted.

### Your Log Evidence

```
📡 Detected 2 network interfaces:
   ens33 → Ethernet [UP] "192.168.0.142"
   ens37 → Ethernet [UP] "192.168.52.128"
🚛 Transport Registry: [Ethernet(pri=10, avail=true)]    ← ONLY ONE
```

Then later:
```
🔌 Hotplug: interface ens37 removed/unusable
📊 Link monitor: no registered transports to probe
⚠️  All transports down — no failover target          ← ens33 is still UP!
```

### Root Cause (from main branch code)

`src/cot/transport_registry.rs` line 18:
```rust
pub struct TransportRegistry {
    entries: Arc<RwLock<HashMap<TransportType, RegistryEntry>>>,
}
```

**`HashMap<TransportType, ...>`** — the key is `TransportType` (an enum with 5 values: Ethernet, WiFi, Bluetooth, Cellular, Satellite). This means **only ONE entry per transport type can exist**. When you have two Ethernet NICs (ens33 + ens37):

1. `register(ens33_transport)` → inserts `Ethernet → ens33` ✅
2. `register(ens37_transport)` → key `Ethernet` already exists → compares priority → same priority (10) → **skips** ❌

Result: ens37 never gets registered. But the hotplug watcher tracks interface NAMES, sees ens37, and when ens37 oscillates (your VMware NAT adapter), it calls `unregister(Ethernet)` — which **removes ens33 instead** (the only Ethernet entry). Registry goes empty → "All transports down" → system broken.

### The Fix: Interface-Based Keying

Replace `HashMap<TransportType, RegistryEntry>` with `HashMap<String, RegistryEntry>` where the key is the **interface name** (e.g., "ens33", "ens37", "wlan0"). This means:
- ens33 and ens37 coexist as separate entries
- Removing ens37 does NOT affect ens33
- `best_available()` picks the best individual interface, not the best type
- Failover can switch between two Ethernet NICs
- Link monitor tracks each NIC independently

This is a **one-line conceptual change** that cascades through 4 files. Everything else in this plan builds on top of a correct foundation.

---

## What Exists in Main (Confirmed)

| File | Status | Notes |
|---|---|---|
| `cot/types.rs` | ✅ Complete | TransportType enum, InterfaceInfo, priorities |
| `cot/transport_trait.rs` | ✅ Complete | Transport trait with `display_name()` |
| `cot/interface_detector.rs` | ✅ Complete | Classifies ens→Ethernet, wlan→WiFi, etc. |
| `cot/transport_registry.rs` | ⚠️ BROKEN | HashMap<TransportType> collapses same-type interfaces |
| `cot/transports/ethernet.rs` | ✅ Real | TCP-based, stores InterfaceInfo |
| `cot/transports/wifi.rs` | ✅ Real | TCP-based |
| `cot/transports/bluetooth.rs` | ✅ Real | BT PAN, RSSI, scan |
| `cot/transports/cellular.rs` | ✅ Real | mmcli signal, carrier check |
| `cot/transports/satellite.rs` | ❌ STUB | `is_available() → false`, `[STUB]` in name |
| `cot/transports/mod.rs` | ✅ Complete | Factory function |
| `cot/session_manager.rs` | ✅ Complete | Sessions with transport migration |
| `cot/router.rs` | ✅ Complete | Uses registry + sessions |
| `cot/link_monitor.rs` | ❌ DOES NOT EXIST | Must create from scratch |
| `cot/hotplug.rs` | ❌ DOES NOT EXIST | Must create from scratch |
| `cot/failover.rs` | ❌ DOES NOT EXIST | Must create from scratch |

---

## 12 Deliverables (Rewritten from Scratch)

| # | Deliverable | What Changes | Effort |
|---|---|---|---|
| 1 | Add `interface_name()` to Transport trait | `transport_trait.rs`, all 5 transport impls | 0.5d |
| 2 | Refactor TransportRegistry to interface-based | `transport_registry.rs` (rewrite) | 1.5d |
| 3 | Replace Satellite Stub | `transports/satellite.rs` | 1d |
| 4 | Extend Interface Classification | `interface_detector.rs` | 0.5d |
| 5 | Link Monitor (per-interface) | `link_monitor.rs` (new) | 1.5d |
| 6 | Hotplug Watcher (baseline-aware) | `hotplug.rs` (new) | 1.5d |
| 7 | Failover Engine (interface-aware) | `failover.rs` (new) | 2d |
| 8 | Session Survival Across Switch | `session_manager.rs` (minor), `router.rs` | 1d |
| 9 | Admin CLI: transport commands | `sgx-pa-cli` | 1d |
| 10 | Metrics Exposure | `metrics.rs` | 0.5d |
| 11 | Integration Wiring in main.rs | `main.rs` | 1d |
| 12 | Integration Test + Runbook | scripts + docs | 1d |

**Total: ~13 days. 2 engineers → 7 days.**

---

# Deliverable 1 — Add `interface_name()` to Transport Trait

## Why

The `Transport` trait currently has `display_name()` which returns formatted strings like `"Ethernet(ens33)"`. But the registry needs a **stable, parseable** interface identifier — not a display string. Adding `interface_name()` gives the registry a proper key.

## Changes

**File: `src/cot/transport_trait.rs`** — add one method:

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    fn transport_type(&self) -> TransportType;
    fn priority(&self) -> TransportPriority;
    fn interface_name(&self) -> &str;           // ← NEW
    async fn is_available(&self) -> bool;
    async fn send(&self, message: &TransportMessage) -> CotResult<()>;
    async fn health_check(&self) -> TransportHealth;
    fn display_name(&self) -> String;
}
```

**File: `src/cot/transports/ethernet.rs`** — add implementation:
```rust
fn interface_name(&self) -> &str {
    &self.interface.name
}
```

Same one-liner for `wifi.rs`, `bluetooth.rs`, `cellular.rs`, `satellite.rs` — all store `interface: InterfaceInfo` which has `.name`.

## Verification
```bash
cargo test --lib
# All existing tests pass (trait is backward-compatible via the addition)
```

## Validation
Compile-only. No runtime behavior change.

---

# Deliverable 2 — Refactor TransportRegistry to Interface-Based

## Why

This is THE fix. Everything else in the plan depends on this being correct.

## Full Replacement: `src/cot/transport_registry.rs`

```rust
use crate::cot::transport_trait::{Transport, TransportHealth};
use crate::cot::types::{CotError, CotResult, TransportType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

struct RegistryEntry {
    transport: Arc<dyn Transport>,
    last_health: Option<TransportHealth>,
}

/// Interface-aware transport registry.
/// Key = interface name (e.g., "ens33", "wlan0"), NOT TransportType.
/// Multiple interfaces of the same type coexist independently.
pub struct TransportRegistry {
    entries: Arc<RwLock<HashMap<String, RegistryEntry>>>,
}

impl Default for TransportRegistry {
    fn default() -> Self { Self::new() }
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self { entries: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Register a transport instance keyed by its interface name.
    /// If the same interface name is already registered, replace it.
    pub async fn register(&self, transport: Arc<dyn Transport>) {
        let key = transport.interface_name().to_string();
        let mut entries = self.entries.write().await;
        entries.insert(key, RegistryEntry { transport, last_health: None });
    }

    /// Unregister a specific interface by name.
    /// Does NOT affect other interfaces of the same transport type.
    pub async fn unregister_by_interface(&self, iface_name: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(iface_name);
    }

    /// Find the best available transport instance across ALL registered interfaces.
    /// Sorted by priority (lower = better), returns first that is_available().
    pub async fn best_available(&self) -> CotResult<Arc<dyn Transport>> {
        let entries = self.entries.read().await;
        let mut candidates: Vec<&RegistryEntry> = entries.values().collect();
        candidates.sort_by_key(|e| e.transport.priority());
        for entry in candidates {
            if entry.transport.is_available().await {
                return Ok(entry.transport.clone());
            }
        }
        Err(CotError::NoTransportAvailable)
    }

    /// Get a specific transport by interface name.
    pub async fn get_by_interface(&self, iface_name: &str) -> Option<Arc<dyn Transport>> {
        let entries = self.entries.read().await;
        entries.get(iface_name).map(|e| e.transport.clone())
    }

    /// Get any transport of a given type (first available, best priority).
    /// Backward-compatible with code that queries by TransportType.
    pub async fn get(&self, transport_type: TransportType) -> Option<Arc<dyn Transport>> {
        let entries = self.entries.read().await;
        let mut matches: Vec<&RegistryEntry> = entries
            .values()
            .filter(|e| e.transport.transport_type() == transport_type)
            .collect();
        matches.sort_by_key(|e| e.transport.priority());
        matches.first().map(|e| e.transport.clone())
    }

    /// All registered transport instances, sorted by priority.
    pub async fn all_sorted(&self) -> Vec<Arc<dyn Transport>> {
        let entries = self.entries.read().await;
        let mut transports: Vec<Arc<dyn Transport>> =
            entries.values().map(|e| e.transport.clone()).collect();
        transports.sort_by_key(|t| t.priority());
        transports
    }

    /// All registered interface names.
    pub async fn registered_interfaces(&self) -> Vec<String> {
        let entries = self.entries.read().await;
        entries.keys().cloned().collect()
    }

    pub async fn registered_types(&self) -> Vec<TransportType> {
        let entries = self.entries.read().await;
        let mut types: Vec<TransportType> = entries
            .values()
            .map(|e| e.transport.transport_type())
            .collect();
        types.sort_by_key(|t| t.default_priority());
        types.dedup();
        types
    }

    pub async fn health_check_all(&self) -> Vec<(String, TransportType, TransportHealth)> {
        let transport_list: Vec<(String, Arc<dyn Transport>)> = {
            let entries = self.entries.read().await;
            entries.iter().map(|(k, e)| (k.clone(), e.transport.clone())).collect()
        };

        let mut results = Vec::new();
        for (iface, transport) in &transport_list {
            let health = transport.health_check().await;
            results.push((iface.clone(), transport.transport_type(), health));
        }

        // Update cached health
        {
            let mut entries = self.entries.write().await;
            for (iface, _, ref health) in &results {
                if let Some(entry) = entries.get_mut(iface) {
                    entry.last_health = Some(health.clone());
                }
            }
        }
        results
    }

    pub async fn count(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Interface-aware summary for logging.
    /// Example: [ens33:Ethernet(pri=10, avail=true), ens37:Ethernet(pri=10, avail=false)]
    pub async fn summary(&self) -> String {
        let entries = self.entries.read().await;
        let mut parts: Vec<String> = Vec::new();
        for (iface, entry) in entries.iter() {
            let avail = entry.transport.is_available().await;
            parts.push(format!(
                "{}:{}(pri={}, avail={})",
                iface,
                entry.transport.transport_type(),
                entry.transport.priority().0,
                avail
            ));
        }
        parts.sort();
        format!("[{}]", parts.join(", "))
    }
}
```

## Tests (add to same file)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::transport_trait::TransportMessage;
    use crate::cot::types::TransportPriority;

    struct MockTransport {
        name: String,
        tt: TransportType,
        available: bool,
        pri: TransportPriority,
    }

    #[async_trait::async_trait]
    impl Transport for MockTransport {
        fn transport_type(&self) -> TransportType { self.tt }
        fn priority(&self) -> TransportPriority { self.pri }
        fn interface_name(&self) -> &str { &self.name }
        async fn is_available(&self) -> bool { self.available }
        async fn send(&self, _msg: &TransportMessage) -> CotResult<()> { Ok(()) }
        async fn health_check(&self) -> TransportHealth { TransportHealth::healthy(1, 1000) }
        fn display_name(&self) -> String { format!("Mock({}:{})", self.name, self.tt) }
    }

    #[tokio::test]
    async fn test_two_ethernet_interfaces_coexist() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(), tt: TransportType::Ethernet,
            available: true, pri: TransportPriority::new(10),
        })).await;
        reg.register(Arc::new(MockTransport {
            name: "ens37".into(), tt: TransportType::Ethernet,
            available: true, pri: TransportPriority::new(10),
        })).await;
        assert_eq!(reg.count().await, 2);  // BOTH present
    }

    #[tokio::test]
    async fn test_unregister_one_ethernet_keeps_other() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(), tt: TransportType::Ethernet,
            available: true, pri: TransportPriority::new(10),
        })).await;
        reg.register(Arc::new(MockTransport {
            name: "ens37".into(), tt: TransportType::Ethernet,
            available: false, pri: TransportPriority::new(10),
        })).await;

        reg.unregister_by_interface("ens37").await;
        assert_eq!(reg.count().await, 1);

        let best = reg.best_available().await.unwrap();
        assert_eq!(best.interface_name(), "ens33");  // ens33 survives
    }

    #[tokio::test]
    async fn test_best_available_picks_best_priority_across_types() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "wlan0".into(), tt: TransportType::WiFi,
            available: true, pri: TransportPriority::new(20),
        })).await;
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(), tt: TransportType::Ethernet,
            available: true, pri: TransportPriority::new(10),
        })).await;
        let best = reg.best_available().await.unwrap();
        assert_eq!(best.interface_name(), "ens33");
    }

    #[tokio::test]
    async fn test_best_available_skips_unavailable() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(), tt: TransportType::Ethernet,
            available: false, pri: TransportPriority::new(10),
        })).await;
        reg.register(Arc::new(MockTransport {
            name: "wlan0".into(), tt: TransportType::WiFi,
            available: true, pri: TransportPriority::new(20),
        })).await;
        let best = reg.best_available().await.unwrap();
        assert_eq!(best.interface_name(), "wlan0");
    }

    #[tokio::test]
    async fn test_no_transport_available() {
        let reg = TransportRegistry::new();
        assert!(reg.best_available().await.is_err());
    }

    #[tokio::test]
    async fn test_summary_shows_interface_names() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(), tt: TransportType::Ethernet,
            available: true, pri: TransportPriority::new(10),
        })).await;
        let summary = reg.summary().await;
        assert!(summary.contains("ens33"));
        assert!(summary.contains("Ethernet"));
    }
}
```

## Verification
```bash
cargo test transport_registry::tests
# All 6 tests pass, including test_two_ethernet_interfaces_coexist
```

## Validation
```bash
# On VMware with ens33 + ens37:
cargo run -- nodeA
# Expected log:
#   🚛 Transport Registry: [ens33:Ethernet(pri=10, avail=true), ens37:Ethernet(pri=10, avail=true)]
# NOT the old collapsed: [Ethernet(pri=10, avail=true)]
```

---

# Deliverable 3 — Replace Satellite Stub

## What

`src/cot/transports/satellite.rs` currently returns `is_available() → false` and has `[STUB]` in display_name. Replace with real implementation supporting 4 satellite families (Starlink, Iridium, Inmarsat, Generic).

## Key Design Points

- `SatelliteKind` enum: Starlink (appears as eth*), Iridium (ppp*), Inmarsat (usb*), Generic (sat*)
- Auto-detect kind from interface name, with env override `SGX_SAT_KIND`
- Expected latency/bandwidth per kind (Iridium=1500ms/88kbps, Starlink=50ms/100Mbps, etc.)
- Latency probe via gateway TCP connect (not ping — ICMP may be filtered on sat links)
- `interface_name()` returns the OS interface name

*(Full code as specified in the previous Sprint 4 plan, Deliverable 1 — the satellite transport implementation itself is unchanged. Only difference: add `fn interface_name(&self) -> &str { &self.interface.name }` to the impl.)*

## Verification
```bash
cargo test satellite::tests
# test_display_name_no_stub_marker ← MUST NOT contain "[STUB]"
```

---

# Deliverable 4 — Extend Interface Classification

## What

`interface_detector.rs::classify_interface` only recognizes `sat*` for satellite. Add `ppp*` (Iridium), USB vendor ID checks (Inmarsat), and `SGX_SATELLITE_INTERFACES` env override for Starlink.

*(Implementation as specified in previous plan, Deliverable 2 — unchanged.)*

---

# Deliverable 5 — Link Monitor (Per-Interface)

## Why the Previous Version Failed

The previous plan used `HashMap<TransportType, LinkSnapshot>` — same bug as the registry. When ens37 went down, it overwrote the "Ethernet" snapshot, making the monitor think ALL Ethernet was down.

## Fix: Key by Interface Name

```rust
// src/cot/link_monitor.rs (new file)
use crate::cot::transport_registry::TransportRegistry;
use crate::cot::types::TransportType;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    pub interface_name: String,          // ← keyed by this
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
    state: Arc<RwLock<HashMap<String, LinkSnapshot>>>,  // key = interface name
}

impl LinkMonitor {
    pub fn new(registry: Arc<TransportRegistry>) -> Arc<Self> {
        Arc::new(Self { registry, state: Arc::new(RwLock::new(HashMap::new())) })
    }

    pub fn start(self: Arc<Self>) {
        println!("📊 Link monitor: started (probe interval=10s)");
        tokio::spawn(async move {
            loop {
                self.probe_all().await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    }

    async fn probe_all(&self) {
        let transports = self.registry.all_sorted().await;
        if transports.is_empty() {
            return;  // Don't log "no transports" — that's the registry's concern
        }
        let mut state = self.state.write().await;

        // Remove stale entries for interfaces no longer in registry
        let active_names: std::collections::HashSet<String> =
            transports.iter().map(|t| t.interface_name().to_string()).collect();
        state.retain(|k, _| active_names.contains(k));

        for t in &transports {
            let iface = t.interface_name().to_string();
            let health = t.health_check().await;
            let tt = t.transport_type();

            let entry = state.entry(iface.clone()).or_insert(LinkSnapshot {
                interface_name: iface.clone(),
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

            // Per-interface logging
            if entry.is_up {
                println!("📊 Link monitor: {} → {} up (latency={}ms, bw={}kbps)",
                    iface, tt, entry.latency_ms, entry.bandwidth_kbps);
            } else {
                println!("📊 Link monitor: {} → {} down (consecutive_failures={})",
                    iface, tt, entry.consecutive_failures);
            }
        }
    }

    /// Get snapshot for a specific interface.
    pub async fn snapshot(&self, iface_name: &str) -> Option<LinkSnapshot> {
        self.state.read().await.get(iface_name).cloned()
    }

    pub async fn all_snapshots(&self) -> Vec<LinkSnapshot> {
        self.state.read().await.values().cloned().collect()
    }
}
```

## What This Fixes

Your log showed:
```
📊 Link monitor: Ethernet up (latency=1ms, bw=1000000kbps)    ← which one?
```

Now it shows:
```
📊 Link monitor: ens33 → Ethernet up (latency=1ms, bw=1000000kbps)
📊 Link monitor: ens37 → Ethernet down (consecutive_failures=3)
```

And when ens37 goes down, ens33's snapshot is **untouched**. The failover engine (Deliverable 7) reads per-interface snapshots and never concludes "all transports down" when one Ethernet NIC fails.

---

# Deliverable 6 — Hotplug Watcher (Baseline-Aware)

## Why the Previous Version Failed

Your log showed:
```
🔌 Hotplug: interface ens33 appeared (transport=Ethernet)     ← false! already present at startup
🔌 Hotplug: interface ens37 appeared (transport=Ethernet)     ← false! already present
...
🔌 Hotplug: interface ens37 removed/unusable                  ← then removes the ONLY Ethernet entry
🔌 Hotplug: interface ens37 appeared (transport=Ethernet)     ← oscillation
```

Two bugs: (a) first scan treats existing interfaces as "appeared", (b) removing ens37 kills ens33 via the old TransportType-keyed unregister.

## Fix: Baseline Initialization + Debounce

```rust
// src/cot/hotplug.rs (new file)
use crate::cot::interface_detector::InterfaceDetector;
use crate::cot::transport_registry::TransportRegistry;
use crate::cot::transports::create_transport;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Tracks interface state with debounce.
struct InterfaceState {
    is_present: bool,
    is_usable: bool,
    last_change: Instant,
}

pub struct HotplugWatcher;

impl HotplugWatcher {
    pub fn start(registry: Arc<TransportRegistry>) {
        tokio::spawn(async move {
            // Phase 1: Initialize baseline — do NOT emit "appeared" events
            let mut known: HashMap<String, InterfaceState> = HashMap::new();
            if let Ok(initial) = InterfaceDetector::detect_all() {
                for iface in &initial {
                    known.insert(iface.name.clone(), InterfaceState {
                        is_present: true,
                        is_usable: iface.is_usable(),
                        last_change: Instant::now(),
                    });
                    // Register WITHOUT printing "appeared"
                    if iface.is_usable() {
                        let transport = create_transport(iface);
                        registry.register(transport).await;
                    }
                }
            }

            // Phase 2: Poll for changes (real hotplug events only)
            let debounce = Duration::from_secs(3);
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;

                let current = match InterfaceDetector::detect_all() {
                    Ok(c) => c,
                    Err(e) => { eprintln!("⚠️ Hotplug scan failed: {}", e); continue; }
                };

                let current_map: HashMap<String, &crate::cot::types::InterfaceInfo> =
                    current.iter().map(|i| (i.name.clone(), i)).collect();

                // Check for newly appeared interfaces
                for iface in &current {
                    let was_known = known.get(&iface.name);
                    match was_known {
                        None => {
                            // Truly new interface — not present at baseline
                            println!("🔌 Hotplug: interface {} appeared (transport={})",
                                iface.name, iface.transport_type);
                            known.insert(iface.name.clone(), InterfaceState {
                                is_present: true,
                                is_usable: iface.is_usable(),
                                last_change: Instant::now(),
                            });
                            if iface.is_usable() {
                                let transport = create_transport(iface);
                                registry.register(transport).await;
                            }
                        }
                        Some(state) => {
                            // Known interface — check usability change
                            let now_usable = iface.is_usable();
                            if now_usable != state.is_usable
                                && state.last_change.elapsed() >= debounce
                            {
                                if now_usable {
                                    println!("🔌 Hotplug: interface {} became usable", iface.name);
                                    let transport = create_transport(iface);
                                    registry.register(transport).await;
                                } else {
                                    println!("🔌 Hotplug: interface {} became unusable", iface.name);
                                    registry.unregister_by_interface(&iface.name).await;
                                }
                                known.insert(iface.name.clone(), InterfaceState {
                                    is_present: true,
                                    is_usable: now_usable,
                                    last_change: Instant::now(),
                                });
                            }
                        }
                    }
                }

                // Check for removed interfaces
                let removed: Vec<String> = known.keys()
                    .filter(|k| !current_map.contains_key(*k))
                    .cloned()
                    .collect();
                for name in removed {
                    if let Some(state) = known.get(&name) {
                        if state.last_change.elapsed() >= debounce {
                            println!("🔌 Hotplug: interface {} removed", name);
                            registry.unregister_by_interface(&name).await;
                            known.remove(&name);
                        }
                    }
                }
            }
        });
    }
}
```

## What This Fixes

1. **No false "appeared" on startup** — baseline init is silent
2. **Debounce** — ens37 oscillation (up/down/up within 3s) doesn't cause churn
3. **Interface-specific unregister** — removing ens37 calls `unregister_by_interface("ens37")`, NOT `unregister(Ethernet)`, so ens33 is untouched

---

# Deliverable 7 — Failover Engine (Interface-Aware)

## Key Change from Previous Plan

Active transport is now a **specific interface name** (`Option<String>`), not a `TransportType`.

```rust
// src/cot/failover.rs (new file)
use crate::cot::link_monitor::LinkMonitor;
use crate::cot::transport_registry::TransportRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;

const FAILURE_THRESHOLD: u32 = 3;
const RECOVERY_THRESHOLD: u32 = 5;
const MIN_SWITCH_INTERVAL_SECS: i64 = 30;

pub struct FailoverEngine {
    monitor: Arc<LinkMonitor>,
    registry: Arc<TransportRegistry>,
    active_interface: Arc<RwLock<Option<String>>>,   // ← interface NAME, not type
    last_switch_at: Arc<RwLock<i64>>,
    manual_lock: Arc<RwLock<Option<String>>>,        // ← lock to interface name
}

impl FailoverEngine {
    pub fn new(monitor: Arc<LinkMonitor>, registry: Arc<TransportRegistry>) -> Arc<Self> {
        Arc::new(Self {
            monitor, registry,
            active_interface: Arc::new(RwLock::new(None)),
            last_switch_at: Arc::new(RwLock::new(0)),
            manual_lock: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn current_interface(&self) -> Option<String> {
        self.active_interface.read().await.clone()
    }

    pub async fn lock_to_interface(&self, iface: &str) {
        *self.manual_lock.write().await = Some(iface.to_string());
        println!("🔒 Transport locked to {} by admin", iface);
    }

    pub async fn unlock(&self) {
        *self.manual_lock.write().await = None;
        println!("🔓 Transport lock removed — automatic selection resumed");
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
        // Admin lock overrides
        if let Some(ref locked) = *self.manual_lock.read().await {
            let mut active = self.active_interface.write().await;
            if active.as_deref() != Some(locked) {
                *active = Some(locked.clone());
            }
            return;
        }

        let current = self.active_interface.read().await.clone();

        // No active yet → pick best
        if current.is_none() {
            if let Ok(best) = self.registry.best_available().await {
                let name = best.interface_name().to_string();
                *self.active_interface.write().await = Some(name.clone());
                *self.last_switch_at.write().await = chrono::Utc::now().timestamp();
                println!("✅ Initial active transport: {} ({})", name, best.transport_type());
            }
            return;
        }

        let current_iface = current.unwrap();
        let now = chrono::Utc::now().timestamp();

        // Check if current interface is failing
        let current_failed = match self.monitor.snapshot(&current_iface).await {
            Some(snap) => snap.consecutive_failures >= FAILURE_THRESHOLD,
            None => true,
        };

        if current_failed {
            if let Ok(alt) = self.registry.best_available().await {
                let new_name = alt.interface_name().to_string();
                if new_name != current_iface {
                    println!("🔁 Failover: {} → {} ({}+ failures on {})",
                        current_iface, new_name, FAILURE_THRESHOLD, current_iface);
                    *self.active_interface.write().await = Some(new_name);
                    *self.last_switch_at.write().await = now;
                }
            } else {
                eprintln!("⚠️  All transports down — no failover target");
            }
            return;
        }

        // Current healthy. Consider upgrade to better-priority interface.
        let since_switch = now - *self.last_switch_at.read().await;
        if since_switch >= MIN_SWITCH_INTERVAL_SECS {
            if let Ok(best) = self.registry.best_available().await {
                let best_name = best.interface_name().to_string();
                if best_name != current_iface {
                    // Check if the better interface is stably up
                    let stable = match self.monitor.snapshot(&best_name).await {
                        Some(s) => s.consecutive_successes >= RECOVERY_THRESHOLD,
                        None => false,
                    };
                    if stable {
                        println!("⬆️  Upgrade: {} → {} (higher priority, stable)",
                            current_iface, best_name);
                        *self.active_interface.write().await = Some(best_name);
                        *self.last_switch_at.write().await = now;
                    }
                }
            }
        }
    }
}
```

## What This Fixes

Your scenario: "ens33 is primary LAN, ens37 is NAT fallback, both Ethernet"

1. System starts → `best_available()` picks ens33 (both are pri=10, but ens33 is first/stable)
2. ens37 goes down → link monitor marks ens37's snapshot as failed, ens33 is untouched
3. Failover checks `snapshot("ens33")` → healthy → stays on ens33
4. **No "All transports down"** because the active interface (ens33) never failed

And your main use case: "Ethernet has highest speed, if Ethernet goes down switch to WiFi automatically"

1. System starts → ens33:Ethernet (pri=10) is active
2. ens33 goes down → 3 consecutive failures → failover to wlan0:WiFi (pri=20)
3. ens33 comes back → 5 consecutive successes + 30s hysteresis → upgrade back to ens33

---

# Deliverables 8–12 (Unchanged from Previous Plan)

These deliverables don't have the TransportType-keying bug because they sit above the registry:

- **D8 — Session Survival:** Sessions keyed on `peer_device_id`, router looks up `failover.current_interface()` at send time. No change needed from previous plan.
- **D9 — Admin CLI:** `transport-list` now shows interface names. `transport-lock <interface-name>` locks to a specific NIC.
- **D10 — Metrics:** Labels include interface name: `sgx_cot_transport_up{interface="ens33",transport="ethernet"} 1`
- **D11 — main.rs Wiring:** Remove old `register()` calls; HotplugWatcher does initial registration silently.
- **D12 — Integration Test + Runbook:** Updated test phases reference interface names.

---

## Main.rs Integration (D11 Detail)

The old CoT init in main.rs does:
```rust
let detected_interfaces = InterfaceDetector::detect_all()...;
for iface in &detected_interfaces {
    let transport = create_transport(iface);
    cot_registry.register(transport).await;   // ← old bug: collapses same-type
}
```

Replace with:
```rust
// Step 1: Create registry
let cot_registry = Arc::new(TransportRegistry::new());

// Step 2: Start hotplug watcher (handles BOTH initial registration AND runtime changes)
HotplugWatcher::start(cot_registry.clone());

// Step 3: Start link monitor
let link_monitor = LinkMonitor::new(cot_registry.clone());
link_monitor.clone().start();

// Step 4: Start failover engine
let failover = FailoverEngine::new(link_monitor.clone(), cot_registry.clone());
failover.clone().start();

// Give hotplug baseline scan 1s to complete before printing summary
tokio::time::sleep(Duration::from_millis(500)).await;
println!("🚛 Transport Registry: {}", cot_registry.summary().await);
```

The key difference: **HotplugWatcher does the initial registration** (without printing "appeared"), so there's no separate registration loop in main.rs that would need updating.

---

## Board vs Laptop Behavior Difference (Your Question)

You said: "on the board side it working good only on this point not whole like if different network is connected it shows individually with name different network not like on laptop any network connected wifi ethernet for both it consider it on ethernet"

**Why boards work but laptops don't:** The boards have one Ethernet NIC (eth0) and one cellular modem (wwan0) — different TransportTypes. The old `HashMap<TransportType>` can store one of each. Laptops with VMware have two Ethernet NICs (ens33 + ens37) — same TransportType — and the HashMap can only store one.

After this fix, laptops will behave like boards: each NIC tracked independently by name, regardless of how many share the same transport type.

---

## VMware-Specific Testing Procedure

```bash
# Step 1: Start nodeA on VMware (ens33=bridged, ens37=NAT)
sudo env "PATH=$PATH" "HOME=$HOME" cargo run -- nodeA

# Expected log:
#   📡 Detected 2 network interfaces:
#      ens33 → Ethernet [UP] "192.168.0.142"
#      ens37 → Ethernet [UP] "192.168.52.128"
#   🚛 Transport Registry: [ens33:Ethernet(pri=10, avail=true), ens37:Ethernet(pri=10, avail=true)]
#   ✅ Initial active transport: ens33 (Ethernet)
# NO "appeared" messages for ens33 or ens37

# Step 2: Disconnect ens37 (VMware → Network Adapter 2 → Disconnect)
# Expected within 15s:
#   📊 Link monitor: ens37 → Ethernet down (consecutive_failures=1)
#   📊 Link monitor: ens33 → Ethernet up (latency=1ms, bw=1000000kbps)
# NO "All transports down"
# Active transport stays on ens33

# Step 3: Disconnect ens33 (VMware → Network Adapter 1 → Disconnect)
# Expected within 35s:
#   📊 Link monitor: ens33 → Ethernet down (consecutive_failures=3)
#   🔁 Failover: ens33 → ens37 (3+ failures on ens33)
# IF ens37 is reconnected, failover to ens37

# Step 4: Reconnect ens33
# Expected within 80s:
#   📊 Link monitor: ens33 → Ethernet up (latency=1ms, bw=1000000kbps)
#   ⬆️  Upgrade: ens37 → ens33 (higher priority, stable)
```

---

## Acceptance Criteria Summary

| Criterion | How to Verify |
|---|---|
| ens33 + ens37 both registered | `Transport Registry: [ens33:..., ens37:...]` in log |
| No false "appeared" at startup | Grep log for "appeared" — zero hits at boot |
| ens37 down does NOT cause "all down" | Disconnect ens37, verify ens33 stays active |
| Failover between same-type NICs | Disconnect ens33, verify switch to ens37 |
| Per-interface link monitor | Log shows `ens33 → Ethernet up` not just `Ethernet up` |
| Satellite not a stub | `display_name()` does NOT contain `[STUB]` |
| Unit tests pass | `cargo test --lib` — all new + existing tests green |

---

## What I'm NOT Doing

- Not adding new transport types beyond the 5 in TransportType enum
- Not implementing netlink-based hotplug (poll-based is cross-platform)
- Not claiming sub-second failover (probe=10s, threshold=3 → 30-45s failover)
- Not claiming satellite production-tested (no hardware — mock-sat TUN only)
- Not touching Nebula config, attestation, cert bootstrap, or relay code
