use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::integration::provider::{
    IntegrationMetadata, IntegrationStatus, OAuthCredentials, VendorProvider,
};
use crate::integration::store::IntegrationStore;

pub struct IntegrationManager {
    integrations: RwLock<HashMap<VendorProvider, IntegrationMetadata>>,
    store: Arc<IntegrationStore>,
}

impl IntegrationManager {
    pub fn new(filename: &str) -> Arc<Self> {
        let store = Arc::new(IntegrationStore::new(filename));
        let loaded = store.load();

        let mut map = loaded;

        // Initialize default vendor records if not present
        let default_providers = [
            (VendorProvider::GoogleNest, "Google Nest"),
            (VendorProvider::TpLinkKasa, "TP-Link Kasa Smart Home"),
        ];

        for (provider, display_name) in &default_providers {
            map.entry(*provider).or_insert_with(|| IntegrationMetadata {
                provider: *provider,
                name: display_name.to_string(),
                status: IntegrationStatus::Disconnected,
                device_count: 0,
                last_synced: None,
                error_message: None,
                credentials: None,
                kasa_credentials: None,
                nest_credentials: None,
            });
        }

        let _ = store.save(&map);

        Arc::new(Self {
            integrations: RwLock::new(map),
            store,
        })
    }

    /// List metadata for all vendor integrations
    pub async fn list_integrations(&self) -> Vec<IntegrationMetadata> {
        let guard = self.integrations.read().await;
        guard.values().cloned().collect()
    }

    /// Get metadata for a specific vendor provider
    pub async fn get_integration(&self, provider: VendorProvider) -> Option<IntegrationMetadata> {
        let guard = self.integrations.read().await;
        guard.get(&provider).cloned()
    }

    /// Connect/Authenticate an integration with OAuth credentials
    pub async fn connect_integration(
        &self,
        provider: VendorProvider,
        creds: OAuthCredentials,
    ) -> Result<(), String> {
        let mut guard = self.integrations.write().await;

        let meta = guard
            .get_mut(&provider)
            .ok_or_else(|| "Unknown provider".to_string())?;

        meta.status = IntegrationStatus::Connected;
        meta.credentials = Some(creds);
        meta.last_synced = Some(Utc::now());
        meta.error_message = None;

        info!(
            "🔌 Connected integration for provider: {}",
            provider.display_name()
        );

        self.store.save(&guard)?;
        Ok(())
    }

    /// Connect TP-Link Kasa integration with KasaCredentials, programmatic HA setup, and auto-discovery
    pub async fn connect_kasa(
        &self,
        mut creds: crate::kasa::KasaCredentials,
        flow_client: Option<&crate::kasa::KasaHaConfigFlowClient>,
        device_manager: Option<&std::sync::Arc<crate::device::manager::DeviceManager>>,
    ) -> Result<usize, String> {
        let mut guard = self.integrations.write().await;

        let meta = guard
            .get_mut(&VendorProvider::TpLinkKasa)
            .ok_or_else(|| "Unknown provider".to_string())?;

        // If HA flow client is available, run programmatic setup flow
        if let Some(client) = flow_client {
            match client.setup_kasa_config_entry(&creds).await {
                Ok(entry_id) => {
                    creds.config_entry_id = Some(entry_id);
                    meta.status = IntegrationStatus::Connected;
                    meta.error_message = None;
                }
                Err(e) => {
                    meta.status = IntegrationStatus::Error(e.clone());
                    meta.error_message = Some(e.clone());
                    meta.kasa_credentials = Some(creds);
                    let _ = self.store.save(&guard);
                    return Err(e);
                }
            }
        } else {
            meta.status = IntegrationStatus::Connected;
            meta.error_message = None;
        }

        meta.kasa_credentials = Some(creds);
        meta.last_synced = Some(Utc::now());

        info!(
            "🔌 Connected TP-Link Kasa integration (mode: {})",
            meta.kasa_credentials.as_ref().unwrap().mode
        );

        self.store.save(&guard)?;
        drop(guard);

        let mut discovered_count = 0usize;

        if let Some(dm) = device_manager {
            // Pause 2.5 seconds to allow Home Assistant's tplink driver time for UDP/TCP device discovery
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
            dm.reconcile_state().await;

            let all_devices = dm.get_registry().get_all_devices().await;
            discovered_count = all_devices
                .iter()
                .filter(|d| {
                    d.vendor == "tp_link"
                        || d.ha_entity_id.contains("kasa")
                        || d.friendly_name.to_lowercase().contains("kasa")
                        || d.ha_entity_id.contains("tplink")
                })
                .count();

            let mut write_guard = self.integrations.write().await;
            if let Some(meta_mut) = write_guard.get_mut(&VendorProvider::TpLinkKasa) {
                meta_mut.device_count = discovered_count;
                meta_mut.last_synced = Some(Utc::now());
                let _ = self.store.save(&write_guard);
            }
        }

        Ok(discovered_count)
    }

    /// Disconnect an integration, purge credentials, unbind HA entry, and remove vendor devices from registry
    pub async fn disconnect_integration(
        &self,
        provider: VendorProvider,
        flow_client: Option<&crate::kasa::KasaHaConfigFlowClient>,
        nest_flow_client: Option<&crate::nest::NestHaConfigFlowClient>,
        device_manager: Option<&Arc<crate::device::manager::DeviceManager>>,
    ) -> Result<usize, String> {
        let mut guard = self.integrations.write().await;

        let meta = guard
            .get_mut(&provider)
            .ok_or_else(|| "Unknown provider".to_string())?;

        // If disconnecting Kasa and an entry_id exists, unbind from HA programmatically
        if provider == VendorProvider::TpLinkKasa {
            if let Some(ref kasa_creds) = meta.kasa_credentials {
                if let Some(ref entry_id) = kasa_creds.config_entry_id {
                    if let Some(client) = flow_client {
                        if let Err(e) = client.remove_kasa_config_entry(entry_id).await {
                            tracing::warn!(
                                "⚠️ Could not remove HA config entry '{}': {}",
                                entry_id,
                                e
                            );
                        }
                    }
                }
            }
        } else if provider == VendorProvider::GoogleNest {
            if let Some(ref nest_creds) = meta.nest_credentials {
                if let Some(ref entry_id) = nest_creds.config_entry_id {
                    if let Some(client) = nest_flow_client {
                        if let Err(e) = client.remove_nest_config_entry(entry_id).await {
                            tracing::warn!(
                                "⚠️ Could not remove HA Nest config entry '{}': {}",
                                entry_id,
                                e
                            );
                        }
                    }
                }
            }
        }

        let mut devices_removed = 0usize;

        // Purge vendor devices from DeviceRegistry
        if let Some(dm) = device_manager {
            let target_vendor_str = match provider {
                VendorProvider::TpLinkKasa => "tp_link",
                VendorProvider::GoogleNest => "google_nest",
            };

            let all_devices = dm.get_registry().get_all_devices().await;
            for dev in all_devices {
                let is_match = dev.vendor == target_vendor_str
                    || (provider == VendorProvider::TpLinkKasa
                        && (dev.ha_entity_id.contains("kasa")
                            || dev.friendly_name.to_lowercase().contains("kasa")
                            || dev.ha_entity_id.contains("tplink")))
                    || (provider == VendorProvider::GoogleNest
                        && (dev.ha_entity_id.contains("nest")
                            || dev.friendly_name.to_lowercase().contains("nest")));

                if is_match {
                    if dm.get_registry().remove_device(&dev.id).await.is_ok() {
                        devices_removed += 1;
                    }
                }
            }
        }

        meta.status = IntegrationStatus::Disconnected;
        meta.device_count = 0;
        meta.credentials = None;
        meta.kasa_credentials = None;
        meta.nest_credentials = None;
        meta.error_message = None;

        info!(
            "🔌 Disconnected integration for provider: {} (removed {} devices)",
            provider.display_name(),
            devices_removed
        );

        self.store.save(&guard)?;
        Ok(devices_removed)
    }

    /// Connects and configures Google Nest integration
    pub async fn connect_nest(
        &self,
        mut nest_creds: crate::nest::NestCredentials,
        flow_client: Option<&crate::nest::NestHaConfigFlowClient>,
        device_manager: Option<&Arc<crate::device::manager::DeviceManager>>,
    ) -> Result<usize, String> {
        nest_creds.validate()?;

        // Programmatically set up HA config entry if flow_client is available
        if let Some(client) = flow_client {
            match client.setup_nest_config_entry(&nest_creds).await {
                Ok(entry_id) => {
                    info!(
                        "✅ Programmatically created HA Nest config entry '{}'",
                        entry_id
                    );
                    nest_creds.config_entry_id = Some(entry_id);
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ HA Nest config entry automation skipped or failed: {}",
                        e
                    );
                }
            }
        }

        {
            let mut guard = self.integrations.write().await;
            let meta = guard
                .get_mut(&VendorProvider::GoogleNest)
                .ok_or_else(|| "Google Nest provider not found".to_string())?;

            meta.nest_credentials = Some(nest_creds);
            meta.status = IntegrationStatus::Connected;
            meta.last_synced = Some(Utc::now());
            meta.error_message = None;

            self.store.save(&guard)?;
        }

        info!("✅ Google Nest integration credentials saved (AES-GCM-256 encrypted).");

        let mut discovered_count = 0usize;
        if let Some(dm) = device_manager {
            // Pause 2.5 seconds to allow HA's Nest driver time to discover SDM devices
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

            let _ = dm.reconcile_state().await;
            let all_devices = dm.get_registry().get_all_devices().await;
            discovered_count = all_devices
                .iter()
                .filter(|d| d.vendor == "google_nest" || d.ha_entity_id.contains("nest"))
                .count();

            let mut write_guard = self.integrations.write().await;
            if let Some(meta_mut) = write_guard.get_mut(&VendorProvider::GoogleNest) {
                meta_mut.device_count = discovered_count;
                meta_mut.last_synced = Some(Utc::now());
                let _ = self.store.save(&write_guard);
            }
        }

        Ok(discovered_count)
    }

    /// Updates Google Nest credentials silently (used by TokenRefreshWorker without re-triggering HA config flow)
    pub async fn update_nest_credentials(
        &self,
        nest_creds: crate::nest::NestCredentials,
    ) -> Result<(), String> {
        let mut guard = self.integrations.write().await;
        let meta = guard
            .get_mut(&VendorProvider::GoogleNest)
            .ok_or_else(|| "Google Nest provider not found".to_string())?;

        meta.nest_credentials = Some(nest_creds);
        meta.status = IntegrationStatus::Connected;
        meta.last_synced = Some(Utc::now());
        meta.error_message = None;

        self.store.save(&guard)?;
        Ok(())
    }

    /// Update integration status and optional error message
    pub async fn update_integration_status(
        &self,
        provider: VendorProvider,
        status: IntegrationStatus,
        error_msg: Option<String>,
    ) -> Result<(), String> {
        let mut guard = self.integrations.write().await;

        let meta = guard
            .get_mut(&provider)
            .ok_or_else(|| "Unknown provider".to_string())?;

        meta.status = status;
        meta.error_message = error_msg;

        self.store.save(&guard)?;
        Ok(())
    }

    /// Set or update OAuth credentials
    pub async fn set_credentials(
        &self,
        provider: VendorProvider,
        creds: OAuthCredentials,
    ) -> Result<(), String> {
        let mut guard = self.integrations.write().await;

        let meta = guard
            .get_mut(&provider)
            .ok_or_else(|| "Unknown provider".to_string())?;

        meta.credentials = Some(creds);
        meta.last_synced = Some(Utc::now());

        self.store.save(&guard)?;
        Ok(())
    }

    /// Returns JSON summary for integration status APIs
    pub async fn get_status_summary(&self) -> serde_json::Value {
        let list = self.list_integrations().await;

        let mut providers_json = serde_json::Map::new();
        for item in list {
            providers_json.insert(
                item.provider.as_str().to_string(),
                serde_json::json!({
                    "name": item.name,
                    "status": item.status.as_str(),
                    "device_count": item.device_count,
                    "last_synced": item.last_synced,
                    "error_message": item.error_message,
                    "has_credentials": item.credentials.is_some(),
                }),
            );
        }

        serde_json::json!({
            "total_integrations": providers_json.len(),
            "providers": providers_json
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_manager_connect_disconnect_flow() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();

        let manager = IntegrationManager::new(path);
        let list = manager.list_integrations().await;
        assert_eq!(list.len(), 2);

        let creds = OAuthCredentials {
            access_token: "access_token_123".to_string(),
            refresh_token: Some("refresh_token_456".to_string()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            token_type: "Bearer".to_string(),
            scope: None,
        };

        manager
            .connect_integration(VendorProvider::GoogleNest, creds)
            .await
            .unwrap();

        let nest_meta = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert_eq!(nest_meta.status, IntegrationStatus::Connected);
        assert!(nest_meta.credentials.is_some());

        manager
            .disconnect_integration(VendorProvider::GoogleNest, None, None, None)
            .await
            .unwrap();
        let nest_disconnected = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert_eq!(nest_disconnected.status, IntegrationStatus::Disconnected);
        assert!(nest_disconnected.credentials.is_none());
    }

    #[tokio::test]
    async fn test_disconnect_purges_vendor_devices() {
        use crate::device::command_tracker::CommandTracker;
        use crate::device::manager::DeviceManager;
        use crate::device::registry::DeviceRegistry;
        use crate::device::state::{Device, DeviceHealth};
        use crate::homeassistant::events::EventBus;
        use crate::homeassistant::rest::HaRestClient;
        use crate::homeassistant::HomeAssistantConfig;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let dev_file = dir.path().join("devices.json");
        let int_file = dir.path().join("integrations.json");

        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(dev_file.to_str().unwrap()));
        let command_tracker = CommandTracker::new();
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: "http://localhost:8123".to_string(),
            token: "test".to_string(),
        }));

        let dm = DeviceManager::new(registry.clone(), command_tracker, ha_rest, event_bus, None);

        // Add 2 Kasa devices and 1 Nest device to registry
        let dev1 = Device {
            id: "dev_kasa_1".to_string(),
            ha_entity_id: "switch.mock_kasa_plug".to_string(),
            vendor: "tp_link".to_string(),
            device_type: "switch".to_string(),
            room: None,
            friendly_name: "Mock Kasa Plug".to_string(),
            current_state: "on".to_string(),
            health_status: DeviceHealth::Online,
            last_seen: Utc::now(),
        };

        let dev2 = Device {
            id: "dev_nest_1".to_string(),
            ha_entity_id: "climate.hallway_thermostat".to_string(),
            vendor: "google_nest".to_string(),
            device_type: "climate".to_string(),
            room: None,
            friendly_name: "Hallway Thermostat".to_string(),
            current_state: "heat".to_string(),
            health_status: DeviceHealth::Online,
            last_seen: Utc::now(),
        };

        registry.upsert_device(dev1).await.unwrap();
        registry.upsert_device(dev2).await.unwrap();

        let manager = IntegrationManager::new(int_file.to_str().unwrap());

        // Connect Kasa
        let creds = crate::kasa::KasaCredentials::new(
            Some("cloud".to_string()),
            Some("user@example.com".to_string()),
            Some("pass".to_string()),
        );
        manager.connect_kasa(creds, None, Some(&dm)).await.unwrap();

        let initial_devices = registry.get_all_devices().await;
        assert_eq!(initial_devices.len(), 2);

        // Disconnect Kasa
        let removed_count = manager
            .disconnect_integration(VendorProvider::TpLinkKasa, None, None, Some(&dm))
            .await
            .unwrap();
        assert_eq!(removed_count, 1, "Should remove 1 Kasa device");

        let remaining_devices = registry.get_all_devices().await;
        assert_eq!(remaining_devices.len(), 1, "Should retain the Nest device");
        assert_eq!(remaining_devices[0].vendor, "google_nest");

        let kasa_status = manager
            .get_integration(VendorProvider::TpLinkKasa)
            .await
            .unwrap();
        assert_eq!(kasa_status.status, IntegrationStatus::Disconnected);
        assert!(kasa_status.kasa_credentials.is_none());
    }

    #[tokio::test]
    async fn test_connect_nest_saves_encrypted_credentials() {
        let temp_dir = tempfile::tempdir().unwrap();
        let int_file = temp_dir.path().join("integrations_nest_test.json");

        let manager = IntegrationManager::new(int_file.to_str().unwrap());

        let creds = crate::nest::NestCredentials::new(
            Some("client_id_nest".to_string()),
            Some("client_secret_nest".to_string()),
            Some("project_id_nest".to_string()),
            Some("access_token_nest".to_string()),
            Some("refresh_token_nest".to_string()),
        );

        let count = manager
            .connect_nest(creds.clone(), None, None)
            .await
            .unwrap();
        assert_eq!(count, 0);

        let status = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert_eq!(status.status, IntegrationStatus::Connected);

        // Reload store from disk to verify AES-GCM-256 decryption
        let reloaded_manager = IntegrationManager::new(int_file.to_str().unwrap());
        let reloaded_status = reloaded_manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert_eq!(reloaded_status.status, IntegrationStatus::Connected);
        assert!(reloaded_status.nest_credentials.is_some());
        let loaded_creds = reloaded_status.nest_credentials.unwrap();
        assert_eq!(loaded_creds.client_id, Some("client_id_nest".to_string()));
        assert_eq!(loaded_creds.project_id, Some("project_id_nest".to_string()));
    }

    #[tokio::test]
    async fn test_disconnect_nest_purges_devices_and_credentials() {
        let temp_dir = tempfile::tempdir().unwrap();
        let int_file = temp_dir
            .path()
            .join("integrations_nest_disconnect_test.json");
        let dev_file = temp_dir.path().join("devices_nest_disconnect_test.json");

        let event_bus = crate::homeassistant::events::EventBus::new();
        let registry = Arc::new(crate::device::registry::DeviceRegistry::new(
            dev_file.to_str().unwrap(),
        ));
        let command_tracker = crate::device::command_tracker::CommandTracker::new();
        let ha_rest = Arc::new(crate::homeassistant::rest::HaRestClient::new(
            crate::homeassistant::HomeAssistantConfig {
                url: "http://localhost:8123".to_string(),
                token: "test".to_string(),
            },
        ));

        let dm = crate::device::manager::DeviceManager::new(
            registry.clone(),
            command_tracker,
            ha_rest,
            event_bus,
            None,
        );

        let nest_dev = crate::device::state::Device {
            id: "dev_nest_thermostat_1".to_string(),
            ha_entity_id: "climate.hallway_nest_thermostat".to_string(),
            vendor: "google_nest".to_string(),
            device_type: "climate".to_string(),
            room: None,
            friendly_name: "Hallway Nest Thermostat".to_string(),
            current_state: "heat".to_string(),
            health_status: crate::device::state::DeviceHealth::Online,
            last_seen: Utc::now(),
        };

        registry.upsert_device(nest_dev).await.unwrap();

        let manager = IntegrationManager::new(int_file.to_str().unwrap());

        let creds = crate::nest::NestCredentials::new(
            Some("client_id".to_string()),
            Some("secret".to_string()),
            Some("project".to_string()),
            Some("access".to_string()),
            Some("refresh".to_string()),
        );

        manager.connect_nest(creds, None, Some(&dm)).await.unwrap();

        let status = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert_eq!(status.status, IntegrationStatus::Connected);
        assert!(status.nest_credentials.is_some());

        let removed = manager
            .disconnect_integration(VendorProvider::GoogleNest, None, None, Some(&dm))
            .await
            .unwrap();
        assert_eq!(removed, 1, "Should remove 1 Nest device");

        let status_after = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert_eq!(status_after.status, IntegrationStatus::Disconnected);
        assert!(status_after.nest_credentials.is_none());
        assert_eq!(status_after.device_count, 0);

        let devices_left = registry.get_all_devices().await;
        assert_eq!(devices_left.len(), 0);
    }
}
