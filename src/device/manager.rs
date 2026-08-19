use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::device::registry::DeviceRegistry;
use crate::device::state::{Device, DeviceHealth, is_supported_domain};
use crate::homeassistant::events::{EventBus, HaEvent};
use crate::homeassistant::rest::HaRestClient;

/// Unit used when Home Assistant's configuration has not been read yet.
const DEFAULT_TEMPERATURE_UNIT: &str = "°C";

pub struct DeviceManager {
    registry: Arc<DeviceRegistry>,
    ha_rest: Arc<HaRestClient>,
    event_bus: Arc<EventBus>,
    notification_manager: Option<Arc<crate::notification::manager::NotificationManager>>,
    /// Cached `unit_system.temperature` from HA (e.g. "°F"). Mutable because a user can
    /// switch HA between metric and US customary at any time.
    temperature_unit: RwLock<Option<String>>,
    /// Used to decide whether an unbranded `climate.*` entity belongs to Nest.
    integration_manager: RwLock<Option<Arc<crate::integration::manager::IntegrationManager>>>,
}

impl DeviceManager {
    pub fn new(
        registry: Arc<DeviceRegistry>,
        ha_rest: Arc<HaRestClient>,
        event_bus: Arc<EventBus>,
        notification_manager: Option<Arc<crate::notification::manager::NotificationManager>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry,
            ha_rest,
            event_bus,
            notification_manager,
            temperature_unit: RwLock::new(None),
            integration_manager: RwLock::new(None),
        })
    }

    pub fn get_registry(&self) -> &Arc<DeviceRegistry> {
        &self.registry
    }

    /// Wires up the integration manager after construction (they are created in either order).
    pub async fn set_integration_manager(
        &self,
        manager: Arc<crate::integration::manager::IntegrationManager>,
    ) {
        *self.integration_manager.write().await = Some(manager);
    }

    async fn is_nest_connected(&self) -> bool {
        let guard = self.integration_manager.read().await;
        let Some(manager) = guard.as_ref() else {
            // Unknown wiring — assume connected so a thermostat is not silently untagged.
            return true;
        };
        match manager
            .get_integration(crate::integration::provider::VendorProvider::GoogleNest)
            .await
        {
            Some(meta) => {
                meta.status == crate::integration::provider::IntegrationStatus::Connected
            }
            None => false,
        }
    }

    /// HA's configured temperature unit, e.g. "°F". Fetches lazily on first use.
    ///
    /// This sits on request-serving paths, so a failed lookup caches the default rather
    /// than re-attempting (and re-timing-out) on every subsequent call. `reconcile_state`
    /// calls `refresh_unit_system` directly, which always re-reads and corrects the cache.
    pub async fn temperature_unit(&self) -> String {
        if let Some(unit) = self.temperature_unit.read().await.clone() {
            return unit;
        }

        if let Err(e) = self.refresh_unit_system().await {
            warn!(
                "Could not read HA unit system, defaulting to {}: {}",
                DEFAULT_TEMPERATURE_UNIT, e
            );
            let mut guard = self.temperature_unit.write().await;
            let unit = guard
                .get_or_insert_with(|| DEFAULT_TEMPERATURE_UNIT.to_string())
                .clone();
            return unit;
        }

        self.temperature_unit
            .read()
            .await
            .clone()
            .unwrap_or_else(|| DEFAULT_TEMPERATURE_UNIT.to_string())
    }

    /// Re-reads `unit_system.temperature` from Home Assistant's configuration.
    pub async fn refresh_unit_system(&self) -> Result<(), String> {
        let config = self.ha_rest.get_config().await?;
        let unit = config
            .get("unit_system")
            .and_then(|u| u.get("temperature"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| "HA config did not include unit_system.temperature".to_string())?;

        let mut guard = self.temperature_unit.write().await;
        if guard.as_deref() != Some(unit) {
            info!("Home Assistant temperature unit: {}", unit);
        }
        *guard = Some(unit.to_string());
        Ok(())
    }

    /// Fetches all states from Home Assistant and reconciles them with the local registry.
    ///
    /// Behaviour:
    /// - Entity returned by HA with state "unavailable" / "unknown"
    ///   → **Keep** in registry, mark health = Offline.
    /// - Entity NOT returned by HA at all (entity was deleted from HA)
    ///   → **Remove** from devices.json (ghost cleanup).
    /// - Entity present and reporting a real state
    ///   → Update state + mark health = Online.
    pub async fn reconcile_state(&self) {
        println!("🔄 Starting device state reconciliation with Home Assistant...");
        info!("Starting device state reconciliation with Home Assistant...");

        // Pick up any change to HA's unit system (metric vs US customary) before deriving
        // anything from the attributes we are about to store.
        if let Err(e) = self.refresh_unit_system().await {
            warn!("Could not refresh HA unit system, keeping cached value: {}", e);
        }

        let nest_connected = self.is_nest_connected().await;

        match self.ha_rest.get_states().await {
            Ok(states) => {
                let mut updated_count = 0;
                let mut pending_upserts: Vec<crate::device::state::Device> = Vec::new();

                // Collect every supported entity_id that HA currently knows about
                let mut ha_entity_ids: std::collections::HashSet<String> =
                    std::collections::HashSet::new();

                for state_val in &states {
                    if let Some(entity_id) = state_val.get("entity_id").and_then(|v| v.as_str()) {
                        if is_supported_domain(entity_id) {
                            ha_entity_ids.insert(entity_id.to_string());
                        }
                    }
                }

                // --- Pass 1: update / create all devices HA currently reports ---
                for state_val in &states {
                    if let Some(entity_id) = state_val.get("entity_id").and_then(|v| v.as_str()) {
                        if !is_supported_domain(entity_id) {
                            continue; // Skip internal/unsupported HA entities
                        }

                        let state_str = state_val
                            .get("state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");

                        let friendly_name = state_val
                            .get("attributes")
                            .and_then(|a| a.get("friendly_name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(entity_id)
                            .to_string();

                        let is_kasa = entity_id.contains("kasa")
                            || friendly_name.to_lowercase().contains("kasa")
                            || friendly_name.to_lowercase().contains("tp-link")
                            || entity_id.contains("tplink");

                        let is_nest = is_nest_entity(entity_id, &friendly_name, nest_connected);

                        // Preserve HA's full attribute object — this is what drives capability
                        // derivation (supported_features, hvac_modes, min/max temp, ...).
                        let attributes = state_val
                            .get("attributes")
                            .and_then(|a| a.as_object())
                            .cloned()
                            .unwrap_or_default();

                        let initial_vendor = if is_kasa {
                            "tp_link".to_string()
                        } else if is_nest {
                            "google_nest".to_string()
                        } else {
                            "Unknown".to_string()
                        };

                        let mut device =
                            match self.registry.get_device_by_entity_id(entity_id).await {
                                Some(d) => d,
                                None => crate::device::state::Device {
                                    id: format!("dev_{}", uuid::Uuid::new_v4().simple()),
                                    ha_entity_id: entity_id.to_string(),
                                    vendor: initial_vendor,
                                    device_type: entity_id
                                        .split('.')
                                        .next()
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    room: None,
                                    friendly_name: friendly_name.clone(),
                                    current_state: state_str.to_string(),
                                    health_status: DeviceHealth::Online,
                                    last_seen: chrono::Utc::now(),
                                    attributes: attributes.clone(),
                                },
                            };

                        if device.vendor == "Unknown" {
                            if is_kasa {
                                device.vendor = "tp_link".to_string();
                            } else if is_nest {
                                device.vendor = "google_nest".to_string();
                            }
                        }

                        device.current_state = state_str.to_string();
                        device.friendly_name = friendly_name;
                        device.last_seen = chrono::Utc::now();
                        device.attributes = attributes;

                        // Unavailable/unknown → Offline but KEEP the entry
                        device.health_status =
                            if state_str == "unavailable" || state_str == "unknown" {
                                DeviceHealth::Offline
                            } else {
                                DeviceHealth::Online
                            };

                        pending_upserts.push(device);
                        updated_count += 1;
                    }
                }

                // Single write for the whole reconcile pass, rather than one per entity.
                if let Err(e) = self.registry.upsert_devices_bulk(pending_upserts).await {
                    error!("Failed to persist reconciled devices: {}", e);
                }

                // --- Pass 2: clean up stale Guardian entries ---
                let existing_devices = self.registry.get_all_devices().await;
                let mut purged_unsupported = 0usize;
                let mut purged_deleted = 0usize;

                for dev in existing_devices {
                    // Case A: unsupported domain (sensor.sun_*, backup_* etc.) → remove
                    if !is_supported_domain(&dev.ha_entity_id) {
                        let _ = self.registry.remove_device(&dev.id).await;
                        purged_unsupported += 1;
                        continue;
                    }

                    // Case B: supported domain but entity no longer exists in HA → deleted, remove
                    if !ha_entity_ids.contains(&dev.ha_entity_id) {
                        warn!(
                            "🗑️  Device '{}' ({}) not found in HA — removing from registry (entity deleted in HA).",
                            dev.friendly_name, dev.ha_entity_id
                        );
                        println!(
                            "🗑️  Removed deleted device: {} ({})",
                            dev.friendly_name, dev.ha_entity_id
                        );
                        let _ = self.registry.remove_device(&dev.id).await;
                        purged_deleted += 1;
                    }
                    // Case C: exists in HA but currently unavailable → already marked Offline in Pass 1, keep it
                }

                println!(
                    "✅ Reconciliation complete. Updated: {}, Purged (unsupported): {}, Purged (deleted from HA): {}",
                    updated_count, purged_unsupported, purged_deleted
                );
                info!(
                    "Reconciliation complete. Updated={} PurgedUnsupported={} PurgedDeleted={}",
                    updated_count, purged_unsupported, purged_deleted
                );
            }
            Err(e) => {
                println!("❌ Failed to fetch states for reconciliation: {}", e);
                error!("Failed to fetch states for reconciliation: {}", e);
            }
        }
    }


    /// Spawns the event loop to consume HA events and update the registry in real-time.
    pub async fn start_event_listener(self: Arc<Self>) {
        let mut rx = self.event_bus.subscribe();
        
        tokio::spawn(async move {
            info!("📡 DeviceManager Event Listener started.");
            loop {
                match rx.recv().await {
                    Ok(HaEvent::StateChanged(val)) => {
                        self.handle_state_changed(val).await;
                    }
                    Ok(_) => {} // Ignore other events for now
                    Err(RecvError::Lagged(skipped)) => {
                        warn!("DeviceManager lagged behind! Skipped {} events.", skipped);
                    }
                    Err(RecvError::Closed) => {
                        warn!("Event Bus closed. Stopping DeviceManager listener.");
                        break;
                    }
                }
            }
        });
    }

    async fn handle_state_changed(&self, val: serde_json::Value) {
        // val is the HA event payload: { "event_type": "state_changed", "data": { "entity_id": "...", "new_state": { "state": "..." } } }
        let data = match val.get("data") {
            Some(d) => d,
            None => return,
        };
        
        let entity_id = match data.get("entity_id").and_then(|e| e.as_str()) {
            Some(id) => id,
            None => return,
        };

        if !is_supported_domain(entity_id) {
            return;
        }

        let new_state = match data.get("new_state").and_then(|n| n.get("state")).and_then(|s| s.as_str()) {
            Some(s) => s,
            None => return,
        };

        let friendly_name = data.get("new_state")
            .and_then(|n| n.get("attributes"))
            .and_then(|a| a.get("friendly_name"))
            .and_then(|v| v.as_str())
            .unwrap_or(entity_id)
            .to_string();

        let is_kasa = entity_id.contains("kasa")
            || friendly_name.to_lowercase().contains("kasa")
            || friendly_name.to_lowercase().contains("tp-link")
            || entity_id.contains("tplink");

        let is_nest = is_nest_entity(entity_id, &friendly_name, self.is_nest_connected().await);

        // Keep HA's full attribute object in sync so capability derivation stays current.
        let attributes = data
            .get("new_state")
            .and_then(|n| n.get("attributes"))
            .and_then(|a| a.as_object())
            .cloned()
            .unwrap_or_default();

        let initial_vendor = if is_kasa {
            "tp_link".to_string()
        } else if is_nest {
            "google_nest".to_string()
        } else {
            "Unknown".to_string()
        };

        let mut device = match self.registry.get_device_by_entity_id(entity_id).await {
            Some(d) => d,
            None => Device {
                id: format!("dev_{}", uuid::Uuid::new_v4().simple()),
                ha_entity_id: entity_id.to_string(),
                vendor: initial_vendor,
                device_type: entity_id.split('.').next().unwrap_or("unknown").to_string(),
                room: None,
                friendly_name: friendly_name.clone(),
                current_state: new_state.to_string(),
                health_status: DeviceHealth::Online,
                last_seen: chrono::Utc::now(),
                attributes: attributes.clone(),
            },
        };

        if device.vendor == "Unknown" {
            if is_kasa {
                device.vendor = "tp_link".to_string();
            } else if is_nest {
                device.vendor = "google_nest".to_string();
            }
        }

        let old_health = device.health_status.clone();

        device.current_state = new_state.to_string();
        device.friendly_name = friendly_name;
        device.last_seen = chrono::Utc::now();
        device.attributes = attributes;
        device.health_status = if new_state == "unavailable" || new_state == "unknown" {
            DeviceHealth::Offline
        } else {
            DeviceHealth::Online
        };

        let new_health = device.health_status.clone();

        // Generate notification on health status transition
        if let Some(ref notif_mgr) = self.notification_manager {
            if old_health != DeviceHealth::Offline && new_health == DeviceHealth::Offline {
                let vendor_prefix = if device.vendor == "tp_link" || device.ha_entity_id.contains("kasa") || device.friendly_name.to_lowercase().contains("kasa") {
                    "Kasa"
                } else if device.vendor == "google_nest" || device.ha_entity_id.contains("nest") {
                    "Nest"
                } else if device.vendor == "ecobee" || device.ha_entity_id.contains("ecobee") {
                    "Ecobee"
                } else {
                    "Smart"
                };

                let title = format!("{} Device Offline", vendor_prefix);
                let message = format!("{} device '{}' went offline", vendor_prefix, device.friendly_name);
                warn!("⚠️ Device '{}' ({}) transitioned to Offline", device.friendly_name, entity_id);

                let notif_mgr_clone = notif_mgr.clone();
                tokio::spawn(async move {
                    notif_mgr_clone.create_notification(title, message, "warning").await;
                });
            } else if old_health == DeviceHealth::Offline && new_health == DeviceHealth::Online {
                let vendor_prefix = if device.vendor == "tp_link" || device.ha_entity_id.contains("kasa") || device.friendly_name.to_lowercase().contains("kasa") {
                    "Kasa"
                } else if device.vendor == "google_nest" || device.ha_entity_id.contains("nest") {
                    "Nest"
                } else if device.vendor == "ecobee" || device.ha_entity_id.contains("ecobee") {
                    "Ecobee"
                } else {
                    "Smart"
                };

                let title = format!("{} Device Online", vendor_prefix);
                let message = format!("{} device '{}' is back online", vendor_prefix, device.friendly_name);
                info!("✅ Device '{}' ({}) recovered to Online", device.friendly_name, entity_id);

                let notif_mgr_clone = notif_mgr.clone();
                tokio::spawn(async move {
                    notif_mgr_clone.create_notification(title, message, "info").await;
                });
            }
        }

        // Deferred: HA ticks attributes constantly, so this must not fsync the whole
        // registry on every event. The background flusher writes it out shortly after.
        self.registry.upsert_device_deferred(device).await;
    }

    /// Sends a command to Home Assistant.
    ///
    /// Acknowledgment is optimistic: HA's REST API only returns 2xx *after* the service
    /// handler has finished (for a cloud thermostat that includes the vendor round-trip),
    /// so a successful response is the acknowledgment. The authoritative state arrives
    /// moments later over the WebSocket and updates the registry via `handle_state_changed`.
    pub async fn send_command(
        &self,
        entity_id: &str,
        domain: &str,
        service: &str,
        service_data: Option<serde_json::Value>,
    ) -> Result<(), String> {
        // Ensure device exists in our registry first
        let device = self
            .registry
            .get_device_by_entity_id(entity_id)
            .await
            .ok_or_else(|| format!("Device with entity_id {} not found in registry", entity_id))?;

        // Defensive validation: this path is also reached by the automation engine, which
        // does not go through the HTTP handler's checks.
        let caps = self.capabilities_for(&device).await;
        crate::api::auth::command_auth::CommandAuthorizer::validate_command_schema(
            &caps,
            service,
            &service_data,
        )
        .map_err(|e| format!("invalid command: {}", e))?;

        info!("Sending command {} to {}", service, entity_id);

        self.ha_rest
            .call_service(domain, service, entity_id, service_data)
            .await
    }

    /// Derives the live capability descriptor for a device.
    pub async fn capabilities_for(
        &self,
        device: &Device,
    ) -> crate::device::capabilities::DeviceCapabilities {
        crate::device::capabilities::derive(device, &self.temperature_unit().await)
    }

    /// Re-reads one entity's attributes from HA and stores them.
    ///
    /// Used when a registry entry predates attribute capture, so capabilities can still be
    /// derived without waiting for a full reconciliation.
    pub async fn refresh_device_attributes(
        &self,
        entity_id: &str,
    ) -> Result<Option<Device>, String> {
        let Some(mut device) = self.registry.get_device_by_entity_id(entity_id).await else {
            return Ok(None);
        };

        let state_val = self.ha_rest.get_state(entity_id).await?;

        if let Some(attributes) = state_val.get("attributes").and_then(|a| a.as_object()) {
            device.attributes = attributes.clone();
        }
        if let Some(state_str) = state_val.get("state").and_then(|s| s.as_str()) {
            device.current_state = state_str.to_string();
        }
        device.last_seen = chrono::Utc::now();

        self.registry.upsert_device(device.clone()).await?;
        Ok(Some(device))
    }
}

/// Whether an entity should be attributed to the Google Nest integration.
///
/// `climate.*` only counts as Nest when the Nest integration is actually connected —
/// otherwise an ecobee or Honeywell thermostat would be mislabeled. Temperature/humidity
/// `sensor.*` entities are deliberately NOT matched on their name: that swept up Kasa
/// energy sensors and generic Zigbee probes and inflated the Nest device count.
fn is_nest_entity(entity_id: &str, friendly_name: &str, nest_connected: bool) -> bool {
    let name = friendly_name.to_lowercase();
    if entity_id.contains("nest")
        || name.contains("nest")
        || name.contains("google_nest")
        || name.contains("google nest")
    {
        return true;
    }

    nest_connected && entity_id.starts_with("climate.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::homeassistant::HomeAssistantConfig;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_device_health_transition_notification() {
        let dir = tempdir().unwrap();
        let dev_file = dir.path().join("devices.json");
        let notif_file = dir.path().join("notifications.json");

        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(dev_file.to_str().unwrap()));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: "http://localhost:8123".to_string(),
            token: "test".to_string(),
        }));
        let notif_mgr = Arc::new(crate::notification::manager::NotificationManager::load_or_create(
            notif_file,
            Some(event_bus.clone()),
        ));

        let dm = DeviceManager::new(
            registry,
            ha_rest,
            event_bus.clone(),
            Some(notif_mgr.clone()),
        );

        let entity_id = "switch.mock_kasa_plug";
        let friendly_name = "Mock Kasa Plug";

        // 1. Initial State: Online
        dm.handle_state_changed(serde_json::json!({
            "data": {
                "entity_id": entity_id,
                "new_state": {
                    "state": "on",
                    "attributes": { "friendly_name": friendly_name }
                }
            }
        })).await;

        // 2. Transition to Offline (unavailable)
        dm.handle_state_changed(serde_json::json!({
            "data": {
                "entity_id": entity_id,
                "new_state": {
                    "state": "unavailable",
                    "attributes": { "friendly_name": friendly_name }
                }
            }
        })).await;

        // Give async notification task a brief pause to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let notifs = notif_mgr.list_notifications(false, None).await;
        let has_offline_notif = notifs.iter().any(|n| n.severity == "warning" && n.message.contains("went offline"));
        assert!(has_offline_notif, "Should generate warning notification on transition to Offline");

        // 3. Transition back to Online
        dm.handle_state_changed(serde_json::json!({
            "data": {
                "entity_id": entity_id,
                "new_state": {
                    "state": "on",
                    "attributes": { "friendly_name": friendly_name }
                }
            }
        })).await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let notifs_after = notif_mgr.list_notifications(false, None).await;
        let has_online_notif = notifs_after.iter().any(|n| n.severity == "info" && n.message.contains("is back online"));
        assert!(has_online_notif, "Should generate info notification on transition back to Online");
    }

    #[tokio::test]
    async fn test_reconcile_tags_nest_devices() {
        let dir = tempfile::tempdir().unwrap();
        let dev_file = dir.path().join("devices_nest_test.json");

        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(dev_file.to_str().unwrap()));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: "http://localhost:8123".to_string(),
            token: "test".to_string(),
        }));

        let dm = DeviceManager::new(registry.clone(), ha_rest, event_bus, None);

        dm.handle_state_changed(serde_json::json!({
            "data": {
                "entity_id": "climate.living_room_nest_thermostat",
                "new_state": {
                    "state": "heat",
                    "attributes": { "friendly_name": "Living Room Nest Thermostat" }
                }
            }
        })).await;

        let dev = registry.get_device_by_entity_id("climate.living_room_nest_thermostat").await.unwrap();
        assert_eq!(dev.vendor, "google_nest");
        assert_eq!(dev.device_type, "climate");
    }
}
