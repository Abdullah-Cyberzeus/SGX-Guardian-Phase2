use crate::cot::failover::FailoverEngine;
use crate::cot::interface_detector::InterfaceDetector;
use crate::cot::link_monitor::LinkMonitor;
use crate::cot::transport_registry::TransportRegistry;
use crate::cot::transports::create_transport;
use crate::cot::types::InterfaceInfo;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) struct InterfaceState {
    is_present: bool,
    is_usable: bool,
    last_change: Instant,
}

const DEBOUNCE: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Record the interfaces present at startup and register the usable ones.
/// Deliberately emits no "appeared" events — this is the baseline, not a change.
pub(crate) async fn initialize_baseline(
    registry: &TransportRegistry,
    initial: &[InterfaceInfo],
) -> HashMap<String, InterfaceState> {
    let mut known = HashMap::new();
    for iface in initial {
        known.insert(
            iface.name.clone(),
            InterfaceState {
                is_present: true,
                is_usable: iface.is_usable(),
                last_change: Instant::now(),
            },
        );
        if iface.is_usable() {
            registry.register(create_transport(iface)).await;
        }
    }
    known
}

/// Reconcile `known` against the interfaces seen in this scan, registering and
/// unregistering transports as they appear, change usability, or disappear.
/// Returns true when the registry was modified.
pub(crate) async fn scan_step(
    registry: &TransportRegistry,
    known: &mut HashMap<String, InterfaceState>,
    current: &[InterfaceInfo],
) -> bool {
    let current_map: HashMap<&str, &InterfaceInfo> =
        current.iter().map(|i| (i.name.as_str(), i)).collect();
    let mut registry_changed = false;

    // Check for newly appeared interfaces
    for iface in current {
        match known.get(&iface.name) {
            None => {
                println!(
                    "🔌 Hotplug: interface {} appeared (transport={})",
                    iface.name, iface.transport_type
                );
                known.insert(
                    iface.name.clone(),
                    InterfaceState {
                        is_present: true,
                        is_usable: iface.is_usable(),
                        last_change: Instant::now(),
                    },
                );
                if iface.is_usable() {
                    registry.register(create_transport(iface)).await;
                    registry_changed = true;
                }
            }
            Some(state) => {
                let now_usable = iface.is_usable();
                if now_usable != state.is_usable && state.last_change.elapsed() >= DEBOUNCE {
                    if now_usable {
                        println!("🔌 Hotplug: interface {} became usable", iface.name);
                        registry.register(create_transport(iface)).await;
                    } else {
                        println!("🔌 Hotplug: interface {} became unusable", iface.name);
                        registry.unregister_by_interface(&iface.name).await;
                    }
                    registry_changed = true;
                    known.insert(
                        iface.name.clone(),
                        InterfaceState {
                            is_present: true,
                            is_usable: now_usable,
                            last_change: Instant::now(),
                        },
                    );
                }
            }
        }
    }

    // Check for removed interfaces
    let removed: Vec<String> = known
        .iter()
        .filter(|(name, state)| state.is_present && !current_map.contains_key(name.as_str()))
        .map(|(name, _)| name.clone())
        .collect();

    for name in removed {
        if let Some(state) = known.get(&name) {
            if state.last_change.elapsed() >= DEBOUNCE {
                println!("🔌 Hotplug: interface {} removed", name);
                registry.unregister_by_interface(&name).await;
                known.remove(&name);
                registry_changed = true;
            }
        }
    }

    registry_changed
}

pub struct HotplugWatcher;

impl HotplugWatcher {
    pub fn start(
        registry: Arc<TransportRegistry>,
        monitor: Arc<LinkMonitor>,
        failover: Arc<FailoverEngine>,
    ) {
        tokio::spawn(async move {
            // Phase 1: Initialize baseline — do NOT emit "appeared" events
            let initial = InterfaceDetector::detect_all().unwrap_or_default();
            let mut known = initialize_baseline(&registry, &initial).await;
            monitor.probe_once().await;
            failover.evaluate_now().await;

            // Phase 2: Poll for changes (real hotplug events only)
            loop {
                tokio::time::sleep(POLL_INTERVAL).await;

                let current = match InterfaceDetector::detect_all() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("⚠️ Hotplug scan failed: {}", e);
                        continue;
                    }
                };

                if scan_step(&registry, &mut known, &current).await {
                    monitor.probe_once().await;
                    failover.evaluate_now().await;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::{InterfaceStatus, TransportType};
    use std::net::{IpAddr, Ipv4Addr};

    fn iface(name: &str, tt: TransportType, usable: bool) -> InterfaceInfo {
        InterfaceInfo::new(
            name.to_string(),
            tt,
            usable.then(|| IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            if usable {
                InterfaceStatus::Up
            } else {
                InterfaceStatus::Down
            },
        )
    }

    /// Backdate every recorded change so debounce no longer suppresses updates.
    fn age_out(known: &mut HashMap<String, InterfaceState>) {
        for state in known.values_mut() {
            state.last_change = Instant::now() - Duration::from_secs(60);
        }
    }

    #[tokio::test]
    async fn baseline_registers_only_usable_interfaces() {
        let registry = TransportRegistry::new();
        let known = initialize_baseline(
            &registry,
            &[
                iface("eth0", TransportType::Ethernet, true),
                iface("wlan0", TransportType::WiFi, false),
            ],
        )
        .await;

        assert_eq!(known.len(), 2);
        assert_eq!(registry.registered_interfaces().await, vec!["eth0"]);
    }

    #[tokio::test]
    async fn scan_step_registers_newly_appeared_usable_interface() {
        let registry = TransportRegistry::new();
        let mut known = initialize_baseline(&registry, &[]).await;

        let changed = scan_step(
            &registry,
            &mut known,
            &[iface("wlan0", TransportType::WiFi, true)],
        )
        .await;

        assert!(changed);
        assert_eq!(registry.registered_interfaces().await, vec!["wlan0"]);
    }

    #[tokio::test]
    async fn scan_step_tracks_unusable_new_interface_without_registering() {
        let registry = TransportRegistry::new();
        let mut known = HashMap::new();

        let changed = scan_step(
            &registry,
            &mut known,
            &[iface("bnep0", TransportType::Bluetooth, false)],
        )
        .await;

        assert!(!changed);
        assert!(known.contains_key("bnep0"));
        assert_eq!(registry.count().await, 0);
    }

    #[tokio::test]
    async fn scan_step_debounces_usability_flap() {
        let registry = TransportRegistry::new();
        let mut known =
            initialize_baseline(&registry, &[iface("eth0", TransportType::Ethernet, true)]).await;

        // Within the debounce window the change is ignored.
        let changed = scan_step(
            &registry,
            &mut known,
            &[iface("eth0", TransportType::Ethernet, false)],
        )
        .await;
        assert!(!changed);
        assert_eq!(registry.count().await, 1);

        age_out(&mut known);
        let changed = scan_step(
            &registry,
            &mut known,
            &[iface("eth0", TransportType::Ethernet, false)],
        )
        .await;
        assert!(changed);
        assert_eq!(registry.count().await, 0);
    }

    #[tokio::test]
    async fn scan_step_reregisters_interface_that_becomes_usable() {
        let registry = TransportRegistry::new();
        let mut known =
            initialize_baseline(&registry, &[iface("wlan0", TransportType::WiFi, false)]).await;
        age_out(&mut known);

        let changed = scan_step(
            &registry,
            &mut known,
            &[iface("wlan0", TransportType::WiFi, true)],
        )
        .await;

        assert!(changed);
        assert_eq!(registry.registered_interfaces().await, vec!["wlan0"]);
    }

    #[tokio::test]
    async fn scan_step_unregisters_removed_interface_after_debounce() {
        let registry = TransportRegistry::new();
        let mut known =
            initialize_baseline(&registry, &[iface("eth0", TransportType::Ethernet, true)]).await;

        // Debounce still active — the interface stays known.
        assert!(!scan_step(&registry, &mut known, &[]).await);
        assert!(known.contains_key("eth0"));

        age_out(&mut known);
        assert!(scan_step(&registry, &mut known, &[]).await);
        assert!(!known.contains_key("eth0"));
        assert_eq!(registry.count().await, 0);
    }

    #[tokio::test]
    async fn scan_step_is_idempotent_when_nothing_changes() {
        let registry = TransportRegistry::new();
        let current = vec![iface("eth0", TransportType::Ethernet, true)];
        let mut known = initialize_baseline(&registry, &current).await;
        age_out(&mut known);

        assert!(!scan_step(&registry, &mut known, &current).await);
        assert_eq!(registry.count().await, 1);
    }

    #[tokio::test]
    async fn watcher_start_spawns_without_panicking() {
        let registry = Arc::new(TransportRegistry::new());
        let monitor = LinkMonitor::new(registry.clone());
        let failover = FailoverEngine::new(monitor.clone(), registry.clone());
        HotplugWatcher::start(registry, monitor, failover);
        tokio::task::yield_now().await;
    }
}
