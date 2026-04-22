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
    fn default() -> Self {
        Self::new()
    }
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a transport instance keyed by its interface name.
    /// If the same interface name is already registered, replace it.
    pub async fn register(&self, transport: Arc<dyn Transport>) {
        let key = transport.interface_name().to_string();
        let mut entries = self.entries.write().await;
        entries.insert(
            key,
            RegistryEntry {
                transport,
                last_health: None,
            },
        );
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
            entries
                .iter()
                .map(|(k, e)| (k.clone(), e.transport.clone()))
                .collect()
        };

        let mut results = Vec::new();
        for (iface, transport) in &transport_list {
            let health = transport.health_check().await;
            results.push((iface.clone(), transport.transport_type(), health));
        }

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
            self.available
        }

        async fn send(&self, _msg: &TransportMessage) -> CotResult<()> {
            Ok(())
        }

        async fn health_check(&self) -> TransportHealth {
            TransportHealth::healthy(1, 1000)
        }

        fn display_name(&self) -> String {
            format!("Mock({}:{})", self.name, self.tt)
        }
    }

    #[tokio::test]
    async fn test_two_ethernet_interfaces_coexist() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(),
            tt: TransportType::Ethernet,
            available: true,
            pri: TransportPriority::new(10),
        }))
        .await;
        reg.register(Arc::new(MockTransport {
            name: "ens37".into(),
            tt: TransportType::Ethernet,
            available: true,
            pri: TransportPriority::new(10),
        }))
        .await;
        assert_eq!(reg.count().await, 2);
    }

    #[tokio::test]
    async fn test_unregister_one_ethernet_keeps_other() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(),
            tt: TransportType::Ethernet,
            available: true,
            pri: TransportPriority::new(10),
        }))
        .await;
        reg.register(Arc::new(MockTransport {
            name: "ens37".into(),
            tt: TransportType::Ethernet,
            available: false,
            pri: TransportPriority::new(10),
        }))
        .await;

        reg.unregister_by_interface("ens37").await;
        assert_eq!(reg.count().await, 1);

        let best = reg.best_available().await.unwrap();
        assert_eq!(best.interface_name(), "ens33");
    }

    #[tokio::test]
    async fn test_best_available_picks_best_priority_across_types() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "wlan0".into(),
            tt: TransportType::WiFi,
            available: true,
            pri: TransportPriority::new(20),
        }))
        .await;
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(),
            tt: TransportType::Ethernet,
            available: true,
            pri: TransportPriority::new(10),
        }))
        .await;
        let best = reg.best_available().await.unwrap();
        assert_eq!(best.interface_name(), "ens33");
    }

    #[tokio::test]
    async fn test_best_available_skips_unavailable() {
        let reg = TransportRegistry::new();
        reg.register(Arc::new(MockTransport {
            name: "ens33".into(),
            tt: TransportType::Ethernet,
            available: false,
            pri: TransportPriority::new(10),
        }))
        .await;
        reg.register(Arc::new(MockTransport {
            name: "wlan0".into(),
            tt: TransportType::WiFi,
            available: true,
            pri: TransportPriority::new(20),
        }))
        .await;
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
            name: "ens33".into(),
            tt: TransportType::Ethernet,
            available: true,
            pri: TransportPriority::new(10),
        }))
        .await;
        let summary = reg.summary().await;
        assert!(summary.contains("ens33"));
        assert!(summary.contains("Ethernet"));
    }
}
