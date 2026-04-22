use crate::cot::transport_registry::TransportRegistry;
use crate::cot::types::TransportType;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    pub interface_name: String,
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
    state: Arc<RwLock<HashMap<String, LinkSnapshot>>>,
}

impl LinkMonitor {
    pub fn new(registry: Arc<TransportRegistry>) -> Arc<Self> {
        Arc::new(Self {
            registry,
            state: Arc::new(RwLock::new(HashMap::new())),
        })
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
            return;
        }

        let mut state = self.state.write().await;
        let active_names: HashSet<String> = transports
            .iter()
            .map(|t| t.interface_name().to_string())
            .collect();
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

            if entry.is_up {
                println!(
                    "📊 Link monitor: {} → {} up (latency={}ms, bw={}kbps)",
                    iface, tt, entry.latency_ms, entry.bandwidth_kbps
                );
            } else {
                println!(
                    "📊 Link monitor: {} → {} down (consecutive_failures={})",
                    iface, tt, entry.consecutive_failures
                );
            }
        }
    }

    pub async fn snapshot(&self, iface_name: &str) -> Option<LinkSnapshot> {
        self.state.read().await.get(iface_name).cloned()
    }

    pub async fn all_snapshots(&self) -> Vec<LinkSnapshot> {
        self.state.read().await.values().cloned().collect()
    }

    #[cfg(test)]
    pub async fn probe_once_for_test(&self) {
        self.probe_all().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
    use crate::cot::types::{CotResult, TransportPriority, TransportType};

    struct MockTransport {
        name: String,
        tt: TransportType,
        healthy: bool,
    }

    #[async_trait::async_trait]
    impl Transport for MockTransport {
        fn transport_type(&self) -> TransportType {
            self.tt
        }
        fn priority(&self) -> TransportPriority {
            TransportPriority::new(10)
        }
        fn interface_name(&self) -> &str {
            &self.name
        }
        async fn is_available(&self) -> bool {
            self.healthy
        }
        async fn send(&self, _message: &TransportMessage) -> CotResult<()> {
            Ok(())
        }
        async fn health_check(&self) -> TransportHealth {
            if self.healthy {
                TransportHealth::healthy(3, 1000)
            } else {
                TransportHealth::unhealthy("down")
            }
        }
        fn display_name(&self) -> String {
            format!("Mock({})", self.name)
        }
    }

    #[tokio::test]
    async fn test_snapshot_returns_none_for_untracked() {
        let reg = Arc::new(TransportRegistry::new());
        let mon = LinkMonitor::new(reg);
        assert!(mon.snapshot("ens33").await.is_none());
    }

    #[tokio::test]
    async fn test_success_probe_updates_state() {
        let reg = Arc::new(TransportRegistry::new());
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(),
            tt: TransportType::Ethernet,
            healthy: true,
        }))
        .await;
        let mon = LinkMonitor::new(reg);
        mon.probe_all().await;
        let snap = mon.snapshot("ens33").await.unwrap();
        assert!(snap.is_up);
        assert_eq!(snap.consecutive_successes, 1);
        assert_eq!(snap.consecutive_failures, 0);
    }
}
