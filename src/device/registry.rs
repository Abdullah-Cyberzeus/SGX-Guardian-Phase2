use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// In-memory cache of devices (authoritative for all reads)
    cache: RwLock<HashMap<String, Device>>,
    /// File-based persistence
    store: Arc<SecureFileStore>,
    /// Set when a deferred write is pending; drained by the background flusher.
    dirty: AtomicBool,
    /// Path, retained so a corrupt registry can be backed up rather than discarded.
    path: String,
}

impl DeviceRegistry {
    pub fn new(path: &str) -> Self {
        let store = Arc::new(SecureFileStore::new(path));

        // Attempt to load existing devices
        let mut cache = HashMap::new();
        if let Ok(Some(data)) = store.read() {
            match serde_json::from_slice::<DevicesStore>(&data) {
                Ok(store_data) => {
                    cache = store_data.devices;
                    info!("Loaded {} devices from registry.", cache.len());
                }
                Err(e) => {
                    // Do NOT silently start empty — that destroys user-assigned rooms with no
                    // recovery path. Preserve the file so it can be inspected/repaired.
                    let backup = format!("{}.corrupt.{}", path, chrono::Utc::now().timestamp());
                    match std::fs::rename(path, &backup) {
                        Ok(()) => error!(
                            "Failed to parse devices.json ({}). Backed up to {} and starting with an empty registry.",
                            e, backup
                        ),
                        Err(rename_err) => error!(
                            "Failed to parse devices.json ({}), and could not back it up ({}). Starting with an empty registry.",
                            e, rename_err
                        ),
                    }
                }
            }
        }

        Self {
            cache: RwLock::new(cache),
            store,
            dirty: AtomicBool::new(false),
            path: path.to_string(),
        }
    }

    /// Path of the backing file (used for diagnostics).
    pub fn path(&self) -> &str {
        &self.path
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

    /// Upserts many devices with a single lock acquisition and a single disk write.
    ///
    /// `persist()` rewrites the whole file, so calling `upsert_device` in a loop over N
    /// entities costs N full-file writes. Reconciliation uses this instead.
    pub async fn upsert_devices_bulk(&self, devices: Vec<Device>) -> Result<(), String> {
        if devices.is_empty() {
            return Ok(());
        }

        {
            let mut cache = self.cache.write().await;
            for device in devices {
                cache.insert(device.id.clone(), device);
            }
        }

        self.persist().await
    }

    /// Updates the cache immediately but defers the disk write to the background flusher.
    ///
    /// Home Assistant emits a `state_changed` event every time an attribute ticks (a
    /// thermostat reports `current_temperature`/`current_humidity` continuously), so writing
    /// synchronously here would fsync the entire registry several times a minute per entity.
    /// Reads are served from the cache, so they still observe the update immediately.
    pub async fn upsert_device_deferred(&self, device: Device) {
        {
            let mut cache = self.cache.write().await;
            cache.insert(device.id.clone(), device);
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Writes pending deferred changes, if any. Returns whether a write occurred.
    pub async fn flush_if_dirty(&self) -> bool {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return false;
        }
        if let Err(e) = self.persist().await {
            error!("Failed to flush device registry: {}", e);
            // Re-arm so the next tick retries rather than dropping the change.
            self.dirty.store(true, Ordering::Relaxed);
        }
        true
    }

    /// Spawns a background task that persists deferred updates every `interval`.
    pub fn start_flusher(self: &Arc<Self>, interval: std::time::Duration) {
        let registry = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                registry.flush_if_dirty().await;
            }
        });
        info!("Device registry flusher started (every {:?}).", interval);
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
            attributes: Default::default(),
        }
    }

    /// Guards the `#[serde(default)]` on `Device::attributes`: a registry file written
    /// before that field existed must still load, or `DeviceRegistry::new` discards every
    /// device (including user-assigned rooms).
    #[tokio::test]
    async fn test_loads_legacy_devices_json_without_attributes() {
        use std::io::Write;

        let mut file = NamedTempFile::new().unwrap();
        // Exactly the 9-field shape that shipped before capability support.
        let legacy = r#"{
          "devices": {
            "dev_legacy": {
              "id": "dev_legacy",
              "ha_entity_id": "climate.basement_room_2",
              "vendor": "google_nest",
              "device_type": "climate",
              "room": "Basement",
              "friendly_name": "Room 2",
              "current_state": "cool",
              "health_status": "online",
              "last_seen": "2026-08-18T09:19:41.049548190Z"
            }
          }
        }"#;
        file.write_all(legacy.as_bytes()).unwrap();
        file.flush().unwrap();

        let path = file.path().to_str().unwrap().to_string();
        let registry = DeviceRegistry::new(&path);

        let fetched = registry
            .get_device("dev_legacy")
            .await
            .expect("legacy device must load");
        assert_eq!(fetched.ha_entity_id, "climate.basement_room_2");
        assert_eq!(
            fetched.room.as_deref(),
            Some("Basement"),
            "user-assigned room must survive"
        );
        assert!(
            fetched.attributes.is_empty(),
            "missing attributes default to an empty map"
        );
    }

    #[tokio::test]
    async fn test_bulk_upsert_and_deferred_flush() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let registry = DeviceRegistry::new(&path);

        registry
            .upsert_devices_bulk(vec![
                create_dummy_device("bulk1"),
                create_dummy_device("bulk2"),
            ])
            .await
            .unwrap();
        assert!(registry.get_device("bulk1").await.is_some());
        assert!(registry.get_device("bulk2").await.is_some());

        // Deferred writes are visible in the cache immediately...
        registry
            .upsert_device_deferred(create_dummy_device("deferred"))
            .await;
        assert!(registry.get_device("deferred").await.is_some());

        // ...and reach disk on flush.
        assert!(registry.flush_if_dirty().await, "first flush should write");
        assert!(
            !registry.flush_if_dirty().await,
            "second flush is a no-op when clean"
        );

        let reloaded = DeviceRegistry::new(&path);
        assert!(reloaded.get_device("deferred").await.is_some());
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
