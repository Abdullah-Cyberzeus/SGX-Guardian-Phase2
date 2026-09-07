use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::device::registry::DeviceRegistry;
use crate::device::state::{is_supported_domain, Device, DeviceHealth};
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
            Some(meta) => meta.status == crate::integration::provider::IntegrationStatus::Connected,
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
            warn!(
                "Could not refresh HA unit system, keeping cached value: {}",
                e
            );
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

        let new_state = match data
            .get("new_state")
            .and_then(|n| n.get("state"))
            .and_then(|s| s.as_str())
        {
            Some(s) => s,
            None => return,
        };

        let friendly_name = data
            .get("new_state")
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
                let vendor_prefix = if device.vendor == "tp_link"
                    || device.ha_entity_id.contains("kasa")
                    || device.friendly_name.to_lowercase().contains("kasa")
                {
                    "Kasa"
                } else if device.vendor == "google_nest" || device.ha_entity_id.contains("nest") {
                    "Nest"
                } else if device.vendor == "ecobee" || device.ha_entity_id.contains("ecobee") {
                    "Ecobee"
                } else {
                    "Smart"
                };

                let title = format!("{} Device Offline", vendor_prefix);
                let message = format!(
                    "{} device '{}' went offline",
                    vendor_prefix, device.friendly_name
                );
                warn!(
                    "⚠️ Device '{}' ({}) transitioned to Offline",
                    device.friendly_name, entity_id
                );

                let notif_mgr_clone = notif_mgr.clone();
                tokio::spawn(async move {
                    notif_mgr_clone
                        .create_notification(title, message, "warning")
                        .await;
                });
            } else if old_health == DeviceHealth::Offline && new_health == DeviceHealth::Online {
                let vendor_prefix = if device.vendor == "tp_link"
                    || device.ha_entity_id.contains("kasa")
                    || device.friendly_name.to_lowercase().contains("kasa")
                {
                    "Kasa"
                } else if device.vendor == "google_nest" || device.ha_entity_id.contains("nest") {
                    "Nest"
                } else if device.vendor == "ecobee" || device.ha_entity_id.contains("ecobee") {
                    "Ecobee"
                } else {
                    "Smart"
                };

                let title = format!("{} Device Online", vendor_prefix);
                let message = format!(
                    "{} device '{}' is back online",
                    vendor_prefix, device.friendly_name
                );
                info!(
                    "✅ Device '{}' ({}) recovered to Online",
                    device.friendly_name, entity_id
                );

                let notif_mgr_clone = notif_mgr.clone();
                tokio::spawn(async move {
                    notif_mgr_clone
                        .create_notification(title, message, "info")
                        .await;
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
    use crate::integration::manager::IntegrationManager;
    use crate::integration::provider::{IntegrationStatus, VendorProvider};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Minimal loopback HTTP server that serves a queue of canned responses, in order, to
    /// whichever client connects. Mirrors the pattern already used in
    /// `tests/cov_wave9_homeassistant_client_test.rs` — a real TCP accept loop bound to an
    /// ephemeral localhost port, not a mock trait. No external network is touched.
    async fn mock_http_server(responses: Vec<(u16, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = match stream.read(&mut buffer).await {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let header_end = header_end + 4;
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }
                let status_text = match status {
                    200 => "200 OK",
                    404 => "404 Not Found",
                    500 => "500 Internal Server Error",
                    other => panic!("mock_http_server: add a status text for {other}"),
                };
                let response = format!(
                    "HTTP/1.1 {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        format!("http://{addr}")
    }

    fn make_device(id: &str, entity_id: &str, state: &str) -> Device {
        Device {
            id: id.to_string(),
            ha_entity_id: entity_id.to_string(),
            vendor: "Unknown".to_string(),
            device_type: entity_id.split('.').next().unwrap_or("unknown").to_string(),
            room: None,
            friendly_name: entity_id.to_string(),
            current_state: state.to_string(),
            health_status: DeviceHealth::Online,
            last_seen: chrono::Utc::now(),
            attributes: Default::default(),
        }
    }

    /// A URL nothing listens on. Connection is refused immediately (loopback, no real
    /// network) — safe for paths that must not actually reach Home Assistant.
    const DEAD_URL: &str = "http://127.0.0.1:1";

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
        let notif_mgr = Arc::new(
            crate::notification::manager::NotificationManager::load_or_create(
                notif_file,
                Some(event_bus.clone()),
            ),
        );

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
        }))
        .await;

        // 2. Transition to Offline (unavailable)
        dm.handle_state_changed(serde_json::json!({
            "data": {
                "entity_id": entity_id,
                "new_state": {
                    "state": "unavailable",
                    "attributes": { "friendly_name": friendly_name }
                }
            }
        }))
        .await;

        // Give async notification task a brief pause to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let notifs = notif_mgr.list_notifications(false, None).await;
        let has_offline_notif = notifs
            .iter()
            .any(|n| n.severity == "warning" && n.message.contains("went offline"));
        assert!(
            has_offline_notif,
            "Should generate warning notification on transition to Offline"
        );

        // 3. Transition back to Online
        dm.handle_state_changed(serde_json::json!({
            "data": {
                "entity_id": entity_id,
                "new_state": {
                    "state": "on",
                    "attributes": { "friendly_name": friendly_name }
                }
            }
        }))
        .await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let notifs_after = notif_mgr.list_notifications(false, None).await;
        let has_online_notif = notifs_after
            .iter()
            .any(|n| n.severity == "info" && n.message.contains("is back online"));
        assert!(
            has_online_notif,
            "Should generate info notification on transition back to Online"
        );
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
        }))
        .await;

        let dev = registry
            .get_device_by_entity_id("climate.living_room_nest_thermostat")
            .await
            .unwrap();
        assert_eq!(dev.vendor, "google_nest");
        assert_eq!(dev.device_type, "climate");
    }

    // ---------------------------------------------------------------------
    // is_nest_entity: pure branch matrix
    // ---------------------------------------------------------------------

    #[test]
    fn test_is_nest_entity_matches_explicit_naming_regardless_of_connection_state() {
        assert!(is_nest_entity(
            "climate.nest_thermostat",
            "Thermostat",
            false
        ));
        assert!(is_nest_entity(
            "climate.thermostat",
            "Living Room Nest",
            true
        ));
        assert!(is_nest_entity(
            "climate.thermostat",
            "Living Room Nest",
            false
        ));
        assert!(is_nest_entity("switch.plug", "Google Nest Hub Mini", false));
        assert!(is_nest_entity("switch.plug", "google_nest_hub", false));
    }

    #[test]
    fn test_is_nest_entity_unbranded_climate_depends_on_connection_state() {
        // No explicit "nest" naming: only counted as Nest when the integration is
        // actually connected — otherwise an ecobee/Honeywell thermostat gets mislabeled.
        assert!(is_nest_entity(
            "climate.upstairs",
            "Upstairs Thermostat",
            true
        ));
        assert!(!is_nest_entity(
            "climate.upstairs",
            "Upstairs Thermostat",
            false
        ));
    }

    #[test]
    fn test_is_nest_entity_non_climate_domain_never_matches_on_connection_alone() {
        assert!(!is_nest_entity(
            "sensor.upstairs_temp",
            "Upstairs Temp",
            true
        ));
        assert!(!is_nest_entity(
            "switch.upstairs_plug",
            "Upstairs Plug",
            true
        ));
        assert!(!is_nest_entity("binary_sensor.motion", "Motion", true));
    }

    // ---------------------------------------------------------------------
    // temperature_unit / refresh_unit_system
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_refresh_unit_system_success_updates_and_is_read_back() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        let url = mock_http_server(vec![(
            200,
            r#"{"unit_system":{"temperature":"°F"}}"#.to_string(),
        )])
        .await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);

        dm.refresh_unit_system()
            .await
            .expect("refresh should succeed");
        assert_eq!(dm.temperature_unit().await, "°F");
    }

    #[tokio::test]
    async fn test_temperature_unit_falls_back_to_default_and_caches_on_ha_error() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        // Only one response is queued: the config body is missing unit_system.temperature.
        // If the second `temperature_unit()` call below issued a fresh HTTP request, the
        // mock server would have nothing left to serve and the test would hang/fail —
        // proving the cache is actually used.
        let url = mock_http_server(vec![(200, r#"{"foo":"bar"}"#.to_string())]).await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);

        assert_eq!(dm.temperature_unit().await, "°C");
        assert_eq!(dm.temperature_unit().await, "°C");
    }

    // ---------------------------------------------------------------------
    // reconcile_state
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_state_updates_purges_and_tags_vendors() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));

        // Ghost: supported domain, but HA will not report it -> removed.
        registry
            .upsert_device(make_device("dev_ghost", "light.ghost_deleted", "on"))
            .await
            .unwrap();
        // Unsupported domain: purged regardless of what HA reports.
        registry
            .upsert_device(make_device(
                "dev_unsupported",
                "automation.morning_routine",
                "on",
            ))
            .await
            .unwrap();
        // Will be updated in place (Online -> Offline, vendor tagged).
        registry
            .upsert_device(make_device("dev_kasa", "switch.mock_kasa_plug", "on"))
            .await
            .unwrap();

        let states_body = serde_json::json!([
            {"entity_id": "light.kitchen", "state": "on", "attributes": {"friendly_name": "Kitchen Light"}},
            {"entity_id": "switch.mock_kasa_plug", "state": "unavailable", "attributes": {"friendly_name": "Mock Kasa Plug"}},
            {"entity_id": "climate.living_room_nest_thermostat", "state": "heat", "attributes": {"friendly_name": "Living Room Nest Thermostat"}},
            {"entity_id": "sensor.sun_next_rising", "state": "above_horizon", "attributes": {}}
        ])
        .to_string();

        let url = mock_http_server(vec![
            (200, r#"{"unit_system":{"temperature":"°C"}}"#.to_string()),
            (200, states_body),
        ])
        .await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry.clone(), ha_rest, event_bus, None);

        dm.reconcile_state().await;

        let all = registry.get_all_devices().await;
        let entity_ids: Vec<&str> = all.iter().map(|d| d.ha_entity_id.as_str()).collect();
        assert_eq!(
            all.len(),
            3,
            "ghost and unsupported-domain devices should be purged, got: {:?}",
            entity_ids
        );

        assert!(registry
            .get_device_by_entity_id("light.ghost_deleted")
            .await
            .is_none());
        assert!(registry
            .get_device_by_entity_id("automation.morning_routine")
            .await
            .is_none());

        let kitchen = registry
            .get_device_by_entity_id("light.kitchen")
            .await
            .unwrap();
        assert_eq!(kitchen.health_status, DeviceHealth::Online);
        assert_eq!(kitchen.vendor, "Unknown");

        let kasa = registry
            .get_device_by_entity_id("switch.mock_kasa_plug")
            .await
            .unwrap();
        assert_eq!(kasa.health_status, DeviceHealth::Offline);
        assert_eq!(kasa.vendor, "tp_link");

        let nest = registry
            .get_device_by_entity_id("climate.living_room_nest_thermostat")
            .await
            .unwrap();
        assert_eq!(nest.vendor, "google_nest");

        // Internal unit-system cache picked up the config response along the way.
        assert_eq!(dm.temperature_unit().await, "°C");
    }

    #[tokio::test]
    async fn test_reconcile_state_states_fetch_failure_leaves_registry_untouched() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        registry
            .upsert_device(make_device("dev_x", "light.existing", "on"))
            .await
            .unwrap();

        let url = mock_http_server(vec![
            (200, r#"{"unit_system":{"temperature":"°C"}}"#.to_string()),
            (500, r#"{"error":"boom"}"#.to_string()),
        ])
        .await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry.clone(), ha_rest, event_bus, None);

        dm.reconcile_state().await;

        let all = registry.get_all_devices().await;
        assert_eq!(
            all.len(),
            1,
            "Pass 2 cleanup must not run when the states fetch failed"
        );
        assert_eq!(all[0].ha_entity_id, "light.existing");
    }

    #[tokio::test]
    async fn test_reconcile_state_unbranded_climate_tagged_nest_when_connected() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));

        let states_body = serde_json::json!([
            {"entity_id": "climate.upstairs", "state": "cool", "attributes": {"friendly_name": "Upstairs Thermostat"}}
        ])
        .to_string();
        let url = mock_http_server(vec![
            (200, r#"{"unit_system":{"temperature":"°C"}}"#.to_string()),
            (200, states_body),
        ])
        .await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry.clone(), ha_rest, event_bus, None);

        let integration_mgr =
            IntegrationManager::new(dir.path().join("integrations.json").to_str().unwrap());
        integration_mgr
            .update_integration_status(
                VendorProvider::GoogleNest,
                IntegrationStatus::Connected,
                None,
            )
            .await
            .unwrap();
        dm.set_integration_manager(integration_mgr).await;

        dm.reconcile_state().await;

        let dev = registry
            .get_device_by_entity_id("climate.upstairs")
            .await
            .unwrap();
        assert_eq!(
            dev.vendor, "google_nest",
            "unbranded climate entity must be tagged Nest while the integration is connected"
        );
    }

    // ---------------------------------------------------------------------
    // handle_state_changed: malformed payloads and notification labels
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_handle_state_changed_ignores_malformed_payloads() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: DEAD_URL.to_string(),
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry.clone(), ha_rest, event_bus, None);

        dm.handle_state_changed(serde_json::json!({})).await; // no "data"
        dm.handle_state_changed(serde_json::json!({"data": {}}))
            .await; // no entity_id
        dm.handle_state_changed(serde_json::json!({"data": {"entity_id": "automation.x"}}))
            .await; // unsupported domain
        dm.handle_state_changed(serde_json::json!({"data": {"entity_id": "light.no_state"}}))
            .await; // missing new_state.state

        assert!(registry.get_all_devices().await.is_empty());
    }

    #[tokio::test]
    async fn test_handle_state_changed_notification_labels_nest_ecobee_and_smart_fallback() {
        let dir = tempdir().unwrap();
        let dev_file = dir.path().join("devices.json");
        let notif_file = dir.path().join("notifications.json");
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(dev_file.to_str().unwrap()));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: DEAD_URL.to_string(),
            token: "t".into(),
        }));
        let notif_mgr = Arc::new(
            crate::notification::manager::NotificationManager::load_or_create(
                notif_file,
                Some(event_bus.clone()),
            ),
        );
        let dm = DeviceManager::new(registry, ha_rest, event_bus, Some(notif_mgr.clone()));

        // Nest label: default (no integration manager wired) treats climate.* as Nest.
        for state in ["heat", "unavailable"] {
            dm.handle_state_changed(serde_json::json!({
                "data": {
                    "entity_id": "climate.living_room",
                    "new_state": {"state": state, "attributes": {"friendly_name": "Living Room"}}
                }
            }))
            .await;
        }

        // Smart fallback label: unrelated domain, no vendor match at all.
        for state in ["locked", "unavailable"] {
            dm.handle_state_changed(serde_json::json!({
                "data": {
                    "entity_id": "lock.front_door",
                    "new_state": {"state": state, "attributes": {"friendly_name": "Front Door"}}
                }
            }))
            .await;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let notifs = notif_mgr.list_notifications(false, None).await;
        assert!(notifs.iter().any(|n| n.title == "Nest Device Offline"));
        assert!(notifs.iter().any(|n| n.title == "Smart Device Offline"));
    }

    #[tokio::test]
    async fn test_handle_state_changed_ecobee_label_when_nest_integration_disconnected() {
        let dir = tempdir().unwrap();
        let dev_file = dir.path().join("devices.json");
        let notif_file = dir.path().join("notifications.json");
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(dev_file.to_str().unwrap()));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: DEAD_URL.to_string(),
            token: "t".into(),
        }));
        let notif_mgr = Arc::new(
            crate::notification::manager::NotificationManager::load_or_create(
                notif_file,
                Some(event_bus.clone()),
            ),
        );
        let dm = DeviceManager::new(registry, ha_rest, event_bus, Some(notif_mgr.clone()));

        let integration_mgr =
            IntegrationManager::new(dir.path().join("integrations.json").to_str().unwrap());
        integration_mgr
            .update_integration_status(
                VendorProvider::GoogleNest,
                IntegrationStatus::Disconnected,
                None,
            )
            .await
            .unwrap();
        dm.set_integration_manager(integration_mgr).await;

        // "ecobee" in the entity_id, unbranded climate domain, Nest explicitly
        // disconnected: is_nest_entity is false, so vendor stays "Unknown" — but the
        // notification's vendor-label heuristic still recognizes "ecobee" in the id.
        for state in ["cool", "unavailable"] {
            dm.handle_state_changed(serde_json::json!({
                "data": {
                    "entity_id": "climate.ecobee_downstairs",
                    "new_state": {"state": state, "attributes": {"friendly_name": "Ecobee Downstairs"}}
                }
            }))
            .await;
        }

        let dev = dm
            .get_registry()
            .get_device_by_entity_id("climate.ecobee_downstairs")
            .await
            .unwrap();
        assert_eq!(dev.vendor, "Unknown");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let notifs = notif_mgr.list_notifications(false, None).await;
        assert!(notifs.iter().any(|n| n.title == "Ecobee Device Offline"));
    }

    // ---------------------------------------------------------------------
    // send_command
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_send_command_device_not_found_returns_error() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: DEAD_URL.to_string(),
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);

        let err = dm
            .send_command("switch.missing", "switch", "turn_on", None)
            .await
            .unwrap_err();
        assert!(err.contains("not found in registry"));
    }

    #[tokio::test]
    async fn test_send_command_rejects_unsupported_command_for_read_only_device() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        registry
            .upsert_device(make_device("dev_sensor", "sensor.temp", "21.0"))
            .await
            .unwrap();
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: DEAD_URL.to_string(),
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);
        // Skip the network round-trip for the unit-cache lookup — irrelevant to this path.
        *dm.temperature_unit.write().await = Some("°C".to_string());

        let err = dm
            .send_command("sensor.temp", "sensor", "turn_on", None)
            .await
            .unwrap_err();
        assert!(err.starts_with("invalid command:"), "got: {err}");
    }

    #[tokio::test]
    async fn test_send_command_success_calls_ha_service() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        registry
            .upsert_device(make_device("dev_switch", "switch.office_fan", "off"))
            .await
            .unwrap();

        let url = mock_http_server(vec![(200, "[]".to_string())]).await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);
        *dm.temperature_unit.write().await = Some("°C".to_string());

        dm.send_command("switch.office_fan", "switch", "turn_on", None)
            .await
            .expect("valid command should succeed");
    }

    #[tokio::test]
    async fn test_send_command_propagates_ha_service_failure() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        registry
            .upsert_device(make_device("dev_switch2", "switch.garage_fan", "off"))
            .await
            .unwrap();

        let url = mock_http_server(vec![(500, r#"{"error":"nope"}"#.to_string())]).await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);
        *dm.temperature_unit.write().await = Some("°C".to_string());

        let err = dm
            .send_command("switch.garage_fan", "switch", "turn_on", None)
            .await
            .unwrap_err();
        assert!(err.contains("Failed to call service"));
    }

    // ---------------------------------------------------------------------
    // capabilities_for
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_capabilities_for_derives_from_device() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: DEAD_URL.to_string(),
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);
        *dm.temperature_unit.write().await = Some("°C".to_string());

        let device = make_device("dev_light", "light.desk", "on");
        let caps = dm.capabilities_for(&device).await;
        assert_eq!(caps.domain, "light");
        assert!(caps.controllable);
    }

    // ---------------------------------------------------------------------
    // refresh_device_attributes
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_refresh_device_attributes_returns_none_when_device_missing() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: DEAD_URL.to_string(),
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);

        let result = dm.refresh_device_attributes("light.missing").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_refresh_device_attributes_updates_state_and_attributes() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        registry
            .upsert_device(make_device("dev_refresh", "light.hallway", "off"))
            .await
            .unwrap();

        let url = mock_http_server(vec![(
            200,
            r#"{"state":"on","attributes":{"brightness":200}}"#.to_string(),
        )])
        .await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry.clone(), ha_rest, event_bus, None);

        let updated = dm
            .refresh_device_attributes("light.hallway")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.current_state, "on");
        assert_eq!(updated.attributes.get("brightness").unwrap(), 200);

        let persisted = registry
            .get_device_by_entity_id("light.hallway")
            .await
            .unwrap();
        assert_eq!(persisted.current_state, "on");
    }

    #[tokio::test]
    async fn test_refresh_device_attributes_propagates_ha_error() {
        let dir = tempdir().unwrap();
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(
            dir.path().join("devices.json").to_str().unwrap(),
        ));
        registry
            .upsert_device(make_device("dev_err", "light.broken", "off"))
            .await
            .unwrap();

        let url = mock_http_server(vec![(500, "{}".to_string())]).await;
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url,
            token: "t".into(),
        }));
        let dm = DeviceManager::new(registry, ha_rest, event_bus, None);

        let err = dm
            .refresh_device_attributes("light.broken")
            .await
            .unwrap_err();
        assert!(err.contains("Failed to get state"));
    }

    #[tokio::test]
    async fn test_handle_state_changed_tags_unknown_vendor_on_update_and_labels_reconnect() {
        let dir = tempdir().unwrap();
        let dev_file = dir.path().join("devices.json");
        let notif_file = dir.path().join("notifications.json");
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(dev_file.to_str().unwrap()));
        // Seed the device directly with vendor "Unknown", as if it had been
        // discovered before vendor detection ran -- this is the "existing
        // device, still Unknown" branch inside `handle_state_changed`,
        // distinct from the "brand-new device" branch already covered by
        // `test_device_health_transition_notification`.
        registry
            .upsert_device(make_device(
                "dev_nest_retag",
                "climate.nest_thermostat",
                "heat",
            ))
            .await
            .unwrap();
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: DEAD_URL.to_string(),
            token: "t".into(),
        }));
        let notif_mgr = Arc::new(
            crate::notification::manager::NotificationManager::load_or_create(
                notif_file,
                Some(event_bus.clone()),
            ),
        );
        let dm = DeviceManager::new(
            registry.clone(),
            ha_rest,
            event_bus,
            Some(notif_mgr.clone()),
        );

        // Offline: retags the pre-existing "Unknown" vendor to "google_nest"
        // and fires the "Nest Device Offline" notification.
        dm.handle_state_changed(serde_json::json!({
            "data": {
                "entity_id": "climate.nest_thermostat",
                "new_state": {"state": "unavailable", "attributes": {"friendly_name": "Thermostat"}}
            }
        }))
        .await;
        let tagged = registry
            .get_device_by_entity_id("climate.nest_thermostat")
            .await
            .expect("device present");
        assert_eq!(tagged.vendor, "google_nest");

        // Back online: exercises the reconnect branch's vendor-prefix logic
        // (previously untested -- prior tests only went online -> offline).
        dm.handle_state_changed(serde_json::json!({
            "data": {
                "entity_id": "climate.nest_thermostat",
                "new_state": {"state": "heat", "attributes": {"friendly_name": "Thermostat"}}
            }
        }))
        .await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let notifs = notif_mgr.list_notifications(false, None).await;
        assert!(notifs.iter().any(|n| n.title == "Nest Device Offline"));
        assert!(notifs.iter().any(|n| n.title == "Nest Device Online"));
    }
}
