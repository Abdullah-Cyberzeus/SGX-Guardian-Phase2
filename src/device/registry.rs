use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::device::state::Device;
use crate::storage::file_lock::SecureFileStore;
use tracing::{error, info};

#[derive(Serialize, Deserialize, Default)]
struct DevicesStore {
    devices: HashMap<String, Device>,
}

pub struct DeviceRegistry {
    /// In-memory cache of devices
    cache: RwLock<HashMap<String, Device>>,
    /// File-based persistence
    store: Arc<SecureFileStore>,
}

impl DeviceRegistry {
    pub fn new(path: &str) -> Self {
        let store = Arc::new(SecureFileStore::new(path));

        // Attempt to load existing devices
        let mut cache = HashMap::new();
        if let Ok(Some(data)) = store.read() {
            if let Ok(store_data) = serde_json::from_slice::<DevicesStore>(&data) {
                cache = store_data.devices;
                info!("Loaded {} devices from registry.", cache.len());
            } else {
                error!("Failed to parse devices.json, starting with empty registry.");
            }
        }

        Self {
            cache: RwLock::new(cache),
            store,
        }
    }

    pub async fn get_device(&self, id: &str) -> Option<Device> {
        let cache = self.cache.read().await;
        cache.get(id).cloned()
    }

    pub async fn get_all_devices(&self) -> Vec<Device> {
        let cache = self.cache.read().await;
        cache.values().cloned().collect()
    }

    pub async fn get_device_by_entity_id(&self, entity_id: &str) -> Option<Device> {
        let cache = self.cache.read().await;
        cache
            .values()
            .find(|d| d.ha_entity_id == entity_id)
            .cloned()
    }

    pub async fn upsert_device(&self, device: Device) -> Result<(), String> {
        // 1. Update memory cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(device.id.clone(), device.clone());
        }

        // 2. Persist to disk
        self.persist().await
    }

    pub async fn remove_device(&self, id: &str) -> Result<(), String> {
        // 1. Remove from cache
        {
            let mut cache = self.cache.write().await;
            if cache.remove(id).is_none() {
                return Ok(()); // Already removed
            }
        }

        // 2. Persist to disk
        self.persist().await
    }

    /// Safely writes the current in-memory cache to the JSON file
    async fn persist(&self) -> Result<(), String> {
        let cache_snapshot = self.cache.read().await.clone();
        let store_clone = self.store.clone();

        let result = tokio::task::spawn_blocking(move || {
            store_clone.write_atomic(|_old_data| {
                let to_save = DevicesStore {
                    devices: cache_snapshot,
                };
                serde_json::to_vec_pretty(&to_save)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
        })
        .await
        .map_err(|e| format!("Join error: {}", e))?;

        result.map_err(|e| format!("IO error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::state::{Device, DeviceHealth};
    use chrono::Utc;
    use tempfile::NamedTempFile;

    fn create_dummy_device(id: &str) -> Device {
        Device {
            id: id.to_string(),
            ha_entity_id: format!("light.{}", id),
            vendor: "TestVendor".to_string(),
            device_type: "light".to_string(),
            room: None,
            friendly_name: format!("Test Light {}", id),
            current_state: "off".to_string(),
            health_status: DeviceHealth::Online,
            last_seen: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_registry_upsert_and_get() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let registry = DeviceRegistry::new(&path);

        let device = create_dummy_device("dev1");
        registry.upsert_device(device.clone()).await.unwrap();

        let fetched = registry.get_device("dev1").await.unwrap();
        assert_eq!(fetched.id, "dev1");
        assert_eq!(fetched.ha_entity_id, "light.dev1");

        let fetched_by_entity = registry
            .get_device_by_entity_id("light.dev1")
            .await
            .unwrap();
        assert_eq!(fetched_by_entity.id, "dev1");
    }

    #[tokio::test]
    async fn test_registry_remove() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let registry = DeviceRegistry::new(&path);

        let device = create_dummy_device("dev2");
        registry.upsert_device(device).await.unwrap();
        assert!(registry.get_device("dev2").await.is_some());

        registry.remove_device("dev2").await.unwrap();
        assert!(registry.get_device("dev2").await.is_none());
    }

    #[tokio::test]
    async fn test_registry_persistence_reload() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();

        {
            let registry1 = DeviceRegistry::new(&path);
            let device = create_dummy_device("dev3");
            registry1.upsert_device(device).await.unwrap();
        } // registry1 drops, file should be written

        let registry2 = DeviceRegistry::new(&path);
        let fetched = registry2.get_device("dev3").await.unwrap();
        assert_eq!(fetched.id, "dev3");
    }
}
