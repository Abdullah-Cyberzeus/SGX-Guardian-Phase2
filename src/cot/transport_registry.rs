// src/cot/transport_registry.rs
// ============================================================
// Transport Registry & Priority Selection
// ============================================================

use crate::cot::transport_trait::{Transport, TransportHealth};
use crate::cot::types::{CotError, CotResult, TransportType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

struct RegistryEntry {
    transport: Arc<dyn Transport>,
    last_health: Option<TransportHealth>,
}

pub struct TransportRegistry {
    entries: Arc<RwLock<HashMap<TransportType, RegistryEntry>>>,
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, transport: Arc<dyn Transport>) {
        let mut entries = self.entries.write().await;
        let tt = transport.transport_type();
        let should_insert = match entries.get(&tt) {
            Some(existing) => transport.priority() < existing.transport.priority(),
            None => true,
        };
        if should_insert {
            entries.insert(
                tt,
                RegistryEntry {
                    transport,
                    last_health: None,
                },
            );
        }
    }

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

    pub async fn get(&self, transport_type: TransportType) -> Option<Arc<dyn Transport>> {
        let entries = self.entries.read().await;
        entries.get(&transport_type).map(|e| e.transport.clone())
    }

    pub async fn registered_types(&self) -> Vec<TransportType> {
        let entries = self.entries.read().await;
        entries.keys().cloned().collect()
    }

    pub async fn all_sorted(&self) -> Vec<Arc<dyn Transport>> {
        let entries = self.entries.read().await;
        let mut transports: Vec<Arc<dyn Transport>> =
            entries.values().map(|e| e.transport.clone()).collect();
        transports.sort_by_key(|t| t.priority());
        transports
    }

    pub async fn health_check_all(&self) -> Vec<(TransportType, TransportHealth)> {
        let transport_list: Vec<(TransportType, Arc<dyn Transport>)> = {
            let entries = self.entries.read().await;
            entries
                .iter()
                .map(|(tt, e)| (*tt, e.transport.clone()))
                .collect()
        };

        let mut results = Vec::new();
        let mut health_map: Vec<(TransportType, TransportHealth)> = Vec::new();
        for (tt, transport) in &transport_list {
            let health = transport.health_check().await;
            health_map.push((*tt, health));
        }

        {
            let mut entries = self.entries.write().await;
            for (tt, health) in &health_map {
                if let Some(entry) = entries.get_mut(tt) {
                    results.push((*tt, health.clone()));
                    entry.last_health = Some(health.clone());
                }
            }
        }
        results
    }

    pub async fn unregister(&self, transport_type: TransportType) {
        let mut entries = self.entries.write().await;
        entries.remove(&transport_type);
    }

    pub async fn count(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    pub async fn summary(&self) -> String {
        let entries = self.entries.read().await;
        let mut parts: Vec<String> = Vec::new();
        for (tt, entry) in entries.iter() {
            let avail = entry.transport.is_available().await;
            parts.push(format!(
                "{}(pri={}, avail={})",
                tt,
                entry.transport.priority().0,
                avail
            ));
        }
        parts.sort();
        format!("[{}]", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::transport_trait::TransportMessage;
    use crate::cot::types::TransportPriority;

    struct MockTransport {
        tt: TransportType,
        available: bool,
        pri: TransportPriority,
    }

    #[async_trait::async_trait]
    impl Transport for MockTransport {
        fn transport_type(&self) -> TransportType {
            self.tt
        }
        fn priority(&self) -> TransportPriority {
            self.pri
        }
        async fn is_available(&self) -> bool {
            self.available
        }
        async fn send(&self, _msg: &TransportMessage) -> CotResult<()> {
            Ok(())
        }
        async fn health_check(&self) -> TransportHealth {
            TransportHealth::healthy(1, 1000)
        }
        fn display_name(&self) -> String {
            format!("Mock({})", self.tt)
        }
    }

    #[tokio::test]
    async fn test_register_and_count() {
        let reg = TransportRegistry::new();
        assert_eq!(reg.count().await, 0);
        reg.register(Arc::new(MockTransport {
            tt: TransportType::Ethernet,
            available: true,
            pri: TransportPriority::new(10),
        }))
        .await;
        assert_eq!(reg.count().await, 1);
    }

    #[tokio::test]
    async fn test_best_available_returns_highest_priority() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            tt: TransportType::WiFi,
            available: true,
            pri: TransportPriority::new(20),
        }))
        .await;
        reg.register(Arc::new(MockTransport {
            tt: TransportType::Ethernet,
            available: true,
            pri: TransportPriority::new(10),
        }))
        .await;
        let best = reg.best_available().await.unwrap();
        assert_eq!(best.transport_type(), TransportType::Ethernet);
    }

    #[tokio::test]
    async fn test_best_available_skips_unavailable() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            tt: TransportType::Ethernet,
            available: false,
            pri: TransportPriority::new(10),
        }))
        .await;
        reg.register(Arc::new(MockTransport {
            tt: TransportType::WiFi,
            available: true,
            pri: TransportPriority::new(20),
        }))
        .await;
        let best = reg.best_available().await.unwrap();
        assert_eq!(best.transport_type(), TransportType::WiFi);
    }

    #[tokio::test]
    async fn test_no_transport_available() {
        let reg = TransportRegistry::new();
        assert!(reg.best_available().await.is_err());
    }
}
