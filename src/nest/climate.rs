use serde_json::json;
use std::sync::Arc;
use tracing::info;

use crate::device::manager::DeviceManager;

pub struct NestClimateController;

impl NestClimateController {
    /// Sets target temperature (and optional HVAC mode) on a Nest Thermostat.
    pub async fn set_temperature(
        dm: &Arc<DeviceManager>,
        entity_id: &str,
        temperature: f64,
        hvac_mode: Option<&str>,
    ) -> Result<(), String> {
        let mut payload = json!({
            "temperature": temperature
        });

        if let Some(mode) = hvac_mode {
            payload["hvac_mode"] = json!(mode);
        }

        info!(
            "🌡️ Setting Nest Thermostat '{}' temperature to {:.1}° (hvac_mode: {:?})",
            entity_id, temperature, hvac_mode
        );

        dm.send_command(entity_id, "climate", "set_temperature", Some(payload))
            .await
    }

    /// Sets the operating HVAC mode on a Nest Thermostat (heat, cool, heat_cool, off, fan_only).
    pub async fn set_hvac_mode(
        dm: &Arc<DeviceManager>,
        entity_id: &str,
        hvac_mode: &str,
    ) -> Result<(), String> {
        let payload = json!({
            "hvac_mode": hvac_mode
        });

        info!(
            "🔥 Setting Nest Thermostat '{}' HVAC mode to '{}'",
            entity_id, hvac_mode
        );

        dm.send_command(entity_id, "climate", "set_hvac_mode", Some(payload))
            .await
    }

    /// Sets the preset mode on a Nest Thermostat (eco, none, away).
    pub async fn set_preset_mode(
        dm: &Arc<DeviceManager>,
        entity_id: &str,
        preset_mode: &str,
    ) -> Result<(), String> {
        let payload = json!({
            "preset_mode": preset_mode
        });

        info!(
            "🍃 Setting Nest Thermostat '{}' preset mode to '{}'",
            entity_id, preset_mode
        );

        dm.send_command(entity_id, "climate", "set_preset_mode", Some(payload))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nest_climate_payload_formatting() {
        let mut payload = json!({ "temperature": 21.5 });
        payload["hvac_mode"] = json!("heat");

        assert_eq!(payload["temperature"], 21.5);
        assert_eq!(payload["hvac_mode"], "heat");

        let preset_payload = json!({ "preset_mode": "eco" });
        assert_eq!(preset_payload["preset_mode"], "eco");
    }
}
