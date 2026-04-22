use crate::cot::interface_detector::InterfaceDetector;
use crate::cot::transport_registry::TransportRegistry;
use crate::cot::transports::create_transport;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
                    known.insert(
                        iface.name.clone(),
                        InterfaceState {
                            is_present: true,
                            is_usable: iface.is_usable(),
                            last_change: Instant::now(),
                        },
                    );
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
                    Err(e) => {
                        eprintln!("⚠️ Hotplug scan failed: {}", e);
                        continue;
                    }
                };

                let current_map: HashMap<String, &crate::cot::types::InterfaceInfo> =
                    current.iter().map(|i| (i.name.clone(), i)).collect();

                // Check for newly appeared interfaces
                for iface in &current {
                    let was_known = known.get(&iface.name);
                    match was_known {
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
                                let transport = create_transport(iface);
                                registry.register(transport).await;
                            }
                        }
                        Some(state) => {
                            let now_usable = iface.is_usable();
                            if now_usable != state.is_usable
                                && state.last_change.elapsed() >= debounce
                            {
                                if now_usable {
                                    println!("🔌 Hotplug: interface {} became usable", iface.name);
                                    let transport = create_transport(iface);
                                    registry.register(transport).await;
                                } else {
                                    println!(
                                        "🔌 Hotplug: interface {} became unusable",
                                        iface.name
                                    );
                                    registry.unregister_by_interface(&iface.name).await;
                                }
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
                    .filter(|(name, state)| state.is_present && !current_map.contains_key(*name))
                    .map(|(name, _)| name.clone())
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
