use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents the health status of a device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceHealth {
    Online,
    Offline,
    Unknown,
    AuthenticationError,
    IntegrationError,
    BatteryLow,
}

/// A device in the Guardian system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Guardian's internal unique device ID (e.g. "dev_a1b2c3")
    pub id: String,

    /// The Home Assistant entity ID (e.g. "light.living_room")
    pub ha_entity_id: String,

    /// Vendor of the device (e.g. "Google Nest", "TP-Link Kasa")
    pub vendor: String,

    /// Type of device (e.g. "thermostat", "light", "lock")
    pub device_type: String,

    /// Room or zone where the device is located
    pub room: Option<String>,

    /// User-friendly name
    pub friendly_name: String,

    /// Current state from Home Assistant (e.g. "on", "off", "unlocked")
    pub current_state: String,

    /// Overall health status
    pub health_status: DeviceHealth,

    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,

    /// Last-observed Home Assistant state attributes, verbatim.
    ///
    /// This is what drives capability derivation (see `device::capabilities`):
    /// `supported_features`, `hvac_modes`, `min_temp`/`max_temp`, `preset_modes`, etc.
    ///
    /// `#[serde(default)]` is mandatory — `DeviceRegistry::new` treats a parse failure as
    /// "start empty", so a registry written before this field existed must still load.
    #[serde(default)]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

/// Helper to determine if an HA entity ID belongs to a supported domain.
/// We filter out internal HA entities (like sun.sun, sensor.time, etc.)
pub fn is_supported_domain(entity_id: &str) -> bool {
    // Exclude internal Home Assistant system entities
    if entity_id.starts_with("sensor.sun_")
        || entity_id.starts_with("sensor.backup_")
        || entity_id.starts_with("sensor.date")
        || entity_id.starts_with("sensor.time")
        || entity_id.starts_with("sensor.hacs")
        || entity_id.starts_with("sun.")
    {
        return false;
    }

    let supported_domains = [
        "light.",
        "switch.",
        "climate.",
        "lock.",
        "sensor.",
        "binary_sensor.",
        "camera.",
        "media_player.",
        "cover.",
        "input_boolean.",
        "input_button.",
        "input_select.",
        "input_number.",
    ];
    supported_domains
        .iter()
        .any(|domain| entity_id.starts_with(domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_supported_domain_valid() {
        assert!(is_supported_domain("light.living_room"));
        assert!(is_supported_domain("climate.thermostat"));
        assert!(is_supported_domain("lock.front_door"));
        assert!(is_supported_domain("binary_sensor.motion"));
    }

    #[test]
    fn test_is_supported_domain_invalid() {
        assert!(!is_supported_domain("sun.sun"));
        assert!(!is_supported_domain("zone.home"));
        assert!(!is_supported_domain("automation.turn_on_lights"));
    }
}
