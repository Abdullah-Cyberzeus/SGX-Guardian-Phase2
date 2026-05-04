use crate::cot::link_monitor::LinkMonitor;
use crate::cot::transport_registry::TransportRegistry;
use crate::network_selector::{
    best_candidate_with_live_metrics, candidate_for_interface, detect_candidates,
    set_selected_interface, LiveNetworkMetrics, SelectionPolicy,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;

const FAILURE_THRESHOLD: u32 = 3;
const RECOVERY_THRESHOLD: u32 = 3;
const MIN_SWITCH_INTERVAL_SECS: i64 = 30;

pub struct FailoverEngine {
    monitor: Arc<LinkMonitor>,
    registry: Arc<TransportRegistry>,
    active_interface: Arc<RwLock<Option<String>>>,
    last_switch_at: Arc<RwLock<i64>>,
    manual_lock: Arc<RwLock<Option<String>>>,
}

impl FailoverEngine {
    pub fn new(monitor: Arc<LinkMonitor>, registry: Arc<TransportRegistry>) -> Arc<Self> {
        Arc::new(Self {
            monitor,
            registry,
            active_interface: Arc::new(RwLock::new(None)),
            last_switch_at: Arc::new(RwLock::new(0)),
            manual_lock: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn current_interface(&self) -> Option<String> {
        self.active_interface.read().await.clone()
    }

    pub async fn lock_to_interface(&self, iface: &str) {
        let mut lock = self.manual_lock.write().await;
        if lock.as_deref() != Some(iface) {
            *lock = Some(iface.to_string());
            println!("🔒 Transport locked to {} by admin", iface);
        }
    }

    pub async fn unlock(&self) {
        let mut lock = self.manual_lock.write().await;
        if lock.is_some() {
            *lock = None;
            println!("🔓 Transport lock removed — automatic selection resumed");
        }
    }

    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                self.evaluate_now().await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    pub async fn evaluate_now(&self) {
        // Admin lock overrides
        if let Some(ref locked) = *self.manual_lock.read().await {
            let mut active = self.active_interface.write().await;
            if active.as_deref() != Some(locked) {
                *active = Some(locked.clone());
                set_selected_interface(Some(locked.clone()));
            }
            return;
        }

        let current = self.active_interface.read().await.clone();

        // No active yet → pick best by composite quality score
        if current.is_none() {
            if let Some((name, label)) = self.select_best_by_quality().await {
                *self.active_interface.write().await = Some(name.clone());
                *self.last_switch_at.write().await = chrono::Utc::now().timestamp();
                set_selected_interface(Some(name.clone()));
                if let Some(best) = candidate_for_interface(&name) {
                    println!(
                        "🌐 Best network selected: iface={} transport={} ip={} score={} metric={} latency~{}ms bw~{}kbps live={} stable={}/{}",
                        best.interface_name,
                        best.transport_type,
                        best.ip,
                        best.quality_score,
                        best.route_metric
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| "n/a".to_string()),
                        best.observed_latency_ms,
                        best.observed_bandwidth_kbps,
                        best.using_live_metrics,
                        best.consecutive_successes,
                        best.consecutive_failures
                    );
                }
                println!("✅ Initial active transport: {} ({})", name, label);
            } else if let Ok(best) = self.registry.best_available().await {
                let name = best.interface_name().to_string();
                *self.active_interface.write().await = Some(name.clone());
                *self.last_switch_at.write().await = chrono::Utc::now().timestamp();
                set_selected_interface(Some(name.clone()));
                if let Some(best) = candidate_for_interface(&name) {
                    println!(
                        "🌐 Best network selected: iface={} transport={} ip={} score={} metric={} latency~{}ms bw~{}kbps live={} stable={}/{}",
                        best.interface_name,
                        best.transport_type,
                        best.ip,
                        best.quality_score,
                        best.route_metric
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| "n/a".to_string()),
                        best.observed_latency_ms,
                        best.observed_bandwidth_kbps,
                        best.using_live_metrics,
                        best.consecutive_successes,
                        best.consecutive_failures
                    );
                }
                println!(
                    "✅ Initial active transport: {} ({})",
                    name,
                    best.transport_type()
                );
            }
            return;
        }

        let current_iface = current.unwrap_or_default();
        let now = chrono::Utc::now().timestamp();

        // Check if current interface is failing
        let current_failed = match self.monitor.snapshot(&current_iface).await {
            Some(snap) => snap.consecutive_failures >= FAILURE_THRESHOLD,
            None => true,
        };

        if current_failed {
            if let Some((new_name, _)) = self.select_best_by_quality().await {
                if new_name != current_iface {
                    println!(
                        "⚠️ Network not reachable: {}. New best network: {}",
                        current_iface, new_name
                    );
                    *self.active_interface.write().await = Some(new_name.clone());
                    set_selected_interface(Some(new_name.clone()));
                    if let Some(best) = candidate_for_interface(&new_name) {
                        println!(
                            "🌐 Best network selected: iface={} transport={} ip={} score={} metric={} latency~{}ms bw~{}kbps live={} stable={}/{}",
                            best.interface_name,
                            best.transport_type,
                            best.ip,
                            best.quality_score,
                            best.route_metric
                                .map(|m| m.to_string())
                                .unwrap_or_else(|| "n/a".to_string()),
                            best.observed_latency_ms,
                            best.observed_bandwidth_kbps,
                            best.using_live_metrics,
                            best.consecutive_successes,
                            best.consecutive_failures
                        );
                    }
                    *self.last_switch_at.write().await = now;
                }
            } else if let Ok(alt) = self.registry.best_available().await {
                let new_name = alt.interface_name().to_string();
                if new_name != current_iface {
                    println!(
                        "⚠️ Network not reachable: {}. New best network: {}",
                        current_iface, new_name
                    );
                    *self.active_interface.write().await = Some(new_name.clone());
                    set_selected_interface(Some(new_name.clone()));
                    if let Some(best) = candidate_for_interface(&new_name) {
                        println!(
                            "🌐 Best network selected: iface={} transport={} ip={} score={} metric={} latency~{}ms bw~{}kbps live={} stable={}/{}",
                            best.interface_name,
                            best.transport_type,
                            best.ip,
                            best.quality_score,
                            best.route_metric
                                .map(|m| m.to_string())
                                .unwrap_or_else(|| "n/a".to_string()),
                            best.observed_latency_ms,
                            best.observed_bandwidth_kbps,
                            best.using_live_metrics,
                            best.consecutive_successes,
                            best.consecutive_failures
                        );
                    }
                    *self.last_switch_at.write().await = now;
                }
            } else {
                eprintln!("⚠️  All transports down — no failover target");
            }
            return;
        }

        // Current healthy. Consider upgrade to better-quality interface.
        let since_switch = now - *self.last_switch_at.read().await;
        if let Some((best_name, label)) = self.select_best_by_quality().await {
            if best_name != current_iface {
                let stable = match self.monitor.snapshot(&best_name).await {
                    Some(s) => s.consecutive_successes >= RECOVERY_THRESHOLD,
                    None => false,
                };
                let immediate_upgrade = self
                    .is_higher_priority_than_current(&best_name, &current_iface)
                    .await;

                if immediate_upgrade || (since_switch >= MIN_SWITCH_INTERVAL_SECS && stable) {
                    println!(
                        "⬆️  Upgrade: {} → {} (better network quality: {})",
                        current_iface, best_name, label
                    );
                    *self.active_interface.write().await = Some(best_name.clone());
                    set_selected_interface(Some(best_name.clone()));
                    if let Some(best) = candidate_for_interface(&best_name) {
                        println!(
                            "🌐 Best network selected: iface={} transport={} ip={} score={} metric={} latency~{}ms bw~{}kbps live={} stable={}/{}",
                            best.interface_name,
                            best.transport_type,
                            best.ip,
                            best.quality_score,
                            best.route_metric
                                .map(|m| m.to_string())
                                .unwrap_or_else(|| "n/a".to_string()),
                            best.observed_latency_ms,
                            best.observed_bandwidth_kbps,
                            best.using_live_metrics,
                            best.consecutive_successes,
                            best.consecutive_failures
                        );
                    }
                    *self.last_switch_at.write().await = now;
                }
            }
        }
    }

    async fn is_higher_priority_than_current(
        &self,
        candidate_iface: &str,
        current_iface: &str,
    ) -> bool {
        let candidate = self.registry.get_by_interface(candidate_iface).await;
        let current = self.registry.get_by_interface(current_iface).await;
        match (candidate, current) {
            (Some(candidate), Some(current)) => candidate.priority() < current.priority(),
            (Some(_), None) => true,
            _ => false,
        }
    }

    async fn select_best_by_quality(&self) -> Option<(String, String)> {
        let snaps = self.monitor.all_snapshots().await;
        if snaps.is_empty() {
            return None;
        }

        let candidates = detect_candidates().ok()?;
        let live_metrics: HashMap<String, LiveNetworkMetrics> = snaps
            .iter()
            .map(|snap| {
                (
                    snap.interface_name.clone(),
                    LiveNetworkMetrics {
                        is_up: snap.is_up,
                        latency_ms: snap.latency_ms,
                        bandwidth_kbps: snap.bandwidth_kbps,
                        consecutive_failures: snap.consecutive_failures,
                        consecutive_successes: snap.consecutive_successes,
                        last_probed: snap.last_probed,
                    },
                )
            })
            .collect();
        let allowed_interfaces: HashSet<String> = snaps
            .iter()
            .map(|snap| snap.interface_name.clone())
            .collect();

        let best = best_candidate_with_live_metrics(
            &candidates,
            &live_metrics,
            &SelectionPolicy {
                allowed_interfaces: Some(allowed_interfaces),
                prefer_live_metrics: true,
                require_live_metrics: true,
                require_reachable: true,
                require_live_up: true,
                max_consecutive_failures: Some(FAILURE_THRESHOLD.saturating_sub(1)),
            },
        )?;

        let label = format!(
            "lat={}ms bw={}kbps pri={} metric={} stable={} live={}",
            best.observed_latency_ms,
            best.observed_bandwidth_kbps,
            best.default_priority,
            best.route_metric
                .map(|metric| metric.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            best.consecutive_successes,
            best.using_live_metrics
        );

        Some((best.interface_name, label))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
    use crate::cot::types::{CotResult, TransportPriority, TransportType};
    use crate::network_selector::set_selected_interface;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockTransport {
        name: String,
        tt: TransportType,
        pri: TransportPriority,
        up: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl Transport for MockTransport {
        fn transport_type(&self) -> TransportType {
            self.tt
        }
        fn priority(&self) -> TransportPriority {
            self.pri
        }
        fn interface_name(&self) -> &str {
            &self.name
        }
        async fn is_available(&self) -> bool {
            self.up.load(Ordering::SeqCst)
        }
        async fn send(&self, _message: &TransportMessage) -> CotResult<()> {
            Ok(())
        }
        async fn health_check(&self) -> TransportHealth {
            if self.up.load(Ordering::SeqCst) {
                TransportHealth::healthy(2, 1000)
            } else {
                TransportHealth::unhealthy("down")
            }
        }
        fn display_name(&self) -> String {
            format!("Mock({})", self.name)
        }
    }

    #[tokio::test]
    async fn test_initial_selection_picks_best_available() {
        set_selected_interface(None);
        let reg = Arc::new(TransportRegistry::new());
        let eth_up = Arc::new(AtomicBool::new(true));
        let wifi_up = Arc::new(AtomicBool::new(true));

        reg.register(Arc::new(MockTransport {
            name: "wlan0".into(),
            tt: TransportType::WiFi,
            pri: TransportPriority::new(20),
            up: wifi_up,
        }))
        .await;
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(),
            tt: TransportType::Ethernet,
            pri: TransportPriority::new(10),
            up: eth_up,
        }))
        .await;

        let monitor = LinkMonitor::new(reg.clone());
        monitor.probe_once_for_test().await;
        let failover = FailoverEngine::new(monitor, reg);
        failover.evaluate_now().await;
        assert_eq!(failover.current_interface().await.as_deref(), Some("ens33"));
    }
}
