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
    active_interface: Arc<RwLock<Option<String>>>,
    last_switch_at: Arc<RwLock<i64>>,
    manual_lock: Arc<RwLock<Option<String>>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
    use crate::cot::types::{CotResult, TransportPriority, TransportType};
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
        failover.evaluate().await;
        assert_eq!(failover.current_interface().await.as_deref(), Some("ens33"));
    }
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
            if let Ok(alt) = self.registry.best_available().await {
                let new_name = alt.interface_name().to_string();
                if new_name != current_iface {
                    println!(
                        "🔁 Failover: {} → {} ({}+ failures on {})",
                        current_iface, new_name, FAILURE_THRESHOLD, current_iface
                    );
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
            let Ok(best) = self.registry.best_available().await else {
                return;
            };
            let best_name = best.interface_name().to_string();
            if best_name != current_iface {
                let stable = match self.monitor.snapshot(&best_name).await {
                    Some(s) => s.consecutive_successes >= RECOVERY_THRESHOLD,
                    None => false,
                };
                if stable {
                    println!(
                        "⬆️  Upgrade: {} → {} (higher priority, stable)",
                        current_iface, best_name
                    );
                    *self.active_interface.write().await = Some(best_name);
                    *self.last_switch_at.write().await = now;
                }
            }
        }
    }
}
