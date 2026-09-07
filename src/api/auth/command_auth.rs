use std::fmt;

use crate::device::capabilities::{CommandParamSpec, DeviceCapabilities, ParamKind};
use crate::device::state::Device;

#[derive(Debug, Clone, PartialEq)]
pub enum CommandAuthError {
    InvalidSchema(String),
    RateLimitExceeded(String),
    NoOp(String),
}

impl fmt::Display for CommandAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandAuthError::InvalidSchema(msg) => write!(f, "Invalid schema: {}", msg),
            CommandAuthError::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {}", msg),
            CommandAuthError::NoOp(msg) => write!(f, "No-op command: {}", msg),
        }
    }
}

fn invalid(msg: impl Into<String>) -> CommandAuthError {
    CommandAuthError::InvalidSchema(msg.into())
}

/// Renders a numeric range for an error message, including the unit when there is one.
fn describe_bounds(spec: &CommandParamSpec) -> String {
    match (spec.min, spec.max) {
        (Some(min), Some(max)) => match &spec.unit {
            Some(unit) => format!("{}–{} {}", min, max, unit),
            None => format!("{}–{}", min, max),
        },
        (Some(min), None) => format!("at least {}", min),
        (None, Some(max)) => format!("at most {}", max),
        (None, None) => "any numeric value".to_string(),
    }
}

pub struct CommandAuthorizer;

impl CommandAuthorizer {
    /// Validates a command against what the device actually supports.
    ///
    /// Bounds, modes and presets all come from the device's live Home Assistant attributes
    /// (see `device::capabilities`), so the errors name real limits — a thermostat on a °F
    /// scale rejects `22` and says so, instead of forwarding it for HA to refuse.
    pub fn validate_command_schema(
        caps: &DeviceCapabilities,
        command: &str,
        params: &Option<serde_json::Value>,
    ) -> Result<(), CommandAuthError> {
        if !caps.controllable {
            return Err(invalid(format!(
                "Device '{}' is read-only and accepts no commands",
                caps.ha_entity_id
            )));
        }

        let spec = caps.command(command).ok_or_else(|| {
            invalid(format!(
                "Command '{}' is not supported by {} (supported: {})",
                command,
                caps.ha_entity_id,
                caps.command_names().join(", ")
            ))
        })?;

        // Params must be an object when present.
        let provided = match params {
            Some(serde_json::Value::Object(map)) => Some(map),
            Some(serde_json::Value::Null) | None => None,
            Some(_) => {
                return Err(invalid(
                    "Command parameters must be a JSON object".to_string(),
                ));
            }
        };

        let empty = serde_json::Map::new();
        let provided = provided.unwrap_or(&empty);

        // Reject anything the command does not declare, so a stray `temperature` cannot
        // ride along on `set_hvac_mode` and be silently forwarded to HA.
        for key in provided.keys() {
            if !spec.params.iter().any(|p| &p.name == key) {
                let accepted: Vec<&str> = spec.params.iter().map(|p| p.name.as_str()).collect();
                return Err(invalid(format!(
                    "Unknown parameter '{}' for command '{}' (accepted: {})",
                    key,
                    command,
                    if accepted.is_empty() {
                        "none".to_string()
                    } else {
                        accepted.join(", ")
                    }
                )));
            }
        }

        for param in &spec.params {
            let value = provided.get(&param.name);

            let Some(value) = value else {
                if param.required {
                    return Err(invalid(format!(
                        "Command '{}' requires a '{}' parameter",
                        command, param.name
                    )));
                }
                continue;
            };

            if value.is_null() {
                if param.required {
                    return Err(invalid(format!(
                        "Parameter '{}' must not be null",
                        param.name
                    )));
                }
                continue;
            }

            Self::validate_param(command, param, value)?;
        }

        // A climate entity takes either a single setpoint or a low/high pair, never both.
        if spec.command == "set_temperature" {
            let single = provided.contains_key("temperature");
            let low = provided.contains_key("target_temp_low");
            let high = provided.contains_key("target_temp_high");

            if single && (low || high) {
                return Err(invalid(
                    "Provide either 'temperature' or the 'target_temp_low'/'target_temp_high' pair, not both"
                        .to_string(),
                ));
            }
            if low != high {
                return Err(invalid(
                    "'target_temp_low' and 'target_temp_high' must be provided together"
                        .to_string(),
                ));
            }
            if !single && !low {
                return Err(invalid(format!(
                    "Command '{}' requires a temperature setpoint",
                    command
                )));
            }
            if low && high {
                let lo = provided.get("target_temp_low").and_then(|v| v.as_f64());
                let hi = provided.get("target_temp_high").and_then(|v| v.as_f64());
                if let (Some(lo), Some(hi)) = (lo, hi) {
                    if lo > hi {
                        return Err(invalid(format!(
                            "'target_temp_low' ({}) must not exceed 'target_temp_high' ({})",
                            lo, hi
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_param(
        command: &str,
        param: &CommandParamSpec,
        value: &serde_json::Value,
    ) -> Result<(), CommandAuthError> {
        match param.kind {
            ParamKind::Number => {
                let n = value.as_f64().ok_or_else(|| {
                    invalid(format!("Parameter '{}' must be a number", param.name))
                })?;
                if !n.is_finite() {
                    return Err(invalid(format!(
                        "Parameter '{}' must be a finite number",
                        param.name
                    )));
                }
                let below = param.min.is_some_and(|min| n < min);
                let above = param.max.is_some_and(|max| n > max);
                if below || above {
                    return Err(invalid(format!(
                        "{} {} is out of range for this device ({})",
                        param.label,
                        n,
                        describe_bounds(param)
                    )));
                }
            }
            ParamKind::Enum => {
                let s = value.as_str().ok_or_else(|| {
                    invalid(format!("Parameter '{}' must be a string", param.name))
                })?;
                if !param.options.iter().any(|opt| opt == s) {
                    return Err(invalid(format!(
                        "'{}' is not a valid {} for this device (supported: {})",
                        s,
                        param.name,
                        param.options.join(", ")
                    )));
                }
            }
            ParamKind::Bool => {
                if !value.is_boolean() {
                    return Err(invalid(format!(
                        "Parameter '{}' must be true or false",
                        param.name
                    )));
                }
            }
            ParamKind::Rgb => {
                let arr = value.as_array().ok_or_else(|| {
                    invalid(format!(
                        "Parameter '{}' must be a 3-element array [r, g, b]",
                        param.name
                    ))
                })?;
                if arr.len() != 3 {
                    return Err(invalid(format!(
                        "Parameter '{}' must contain exactly 3 values [r, g, b]",
                        param.name
                    )));
                }
                for component in arr {
                    match component.as_u64() {
                        Some(v) if v <= 255 => {}
                        _ => {
                            return Err(invalid(format!(
                                "{} values must be integers between 0 and 255",
                                param.label
                            )));
                        }
                    }
                }
            }
            ParamKind::Text => {
                if !value.is_string() {
                    return Err(invalid(format!(
                        "Parameter '{}' of command '{}' must be a string",
                        param.name, command
                    )));
                }
            }
        }
        Ok(())
    }

    /// Rejects commands that would not change anything.
    ///
    /// The rules are domain-scoped: a climate entity's state is its HVAC mode
    /// (`cool`/`heat`/`off`), not `on`/`off`, so applying the generic power semantics to a
    /// thermostat used to reject perfectly valid commands.
    pub fn check_no_op(
        device: &Device,
        command: &str,
        params: &Option<serde_json::Value>,
    ) -> Result<(), CommandAuthError> {
        let domain = device
            .ha_entity_id
            .split('.')
            .next()
            .unwrap_or(&device.device_type);
        let state = device.current_state.to_lowercase();

        match domain {
            "climate" => {
                if command == "turn_off" && state == "off" {
                    return Err(CommandAuthError::NoOp(
                        "Thermostat is already off".to_string(),
                    ));
                }
                if command == "set_hvac_mode" {
                    if let Some(mode) = params
                        .as_ref()
                        .and_then(|p| p.get("hvac_mode"))
                        .and_then(|m| m.as_str())
                    {
                        if mode.eq_ignore_ascii_case(&state) {
                            return Err(CommandAuthError::NoOp(format!(
                                "Thermostat is already in '{}' mode",
                                mode
                            )));
                        }
                    }
                }
                // Deliberately not no-ops: re-asserting a setpoint (thermostats drift), and
                // `turn_on` in any state (HA restores the previous mode).
                Ok(())
            }
            "light" | "switch" | "input_boolean" | "fan" | "siren" | "humidifier" => {
                if command == "turn_on" && state == "on" {
                    // An adjustment (brightness, color, ...) makes it a real change.
                    if let Some(params_val) = params {
                        let adjusts = [
                            "brightness",
                            "color_temp",
                            "color_temp_kelvin",
                            "rgb_color",
                            "hs_color",
                            "effect",
                        ]
                        .iter()
                        .any(|key| params_val.get(key).is_some());
                        if adjusts {
                            return Ok(());
                        }
                    }
                    return Err(CommandAuthError::NoOp("Device is already on".to_string()));
                }
                if command == "turn_off" && state == "off" {
                    return Err(CommandAuthError::NoOp("Device is already off".to_string()));
                }
                Ok(())
            }
            "lock" => match command {
                "lock" if state == "locked" => Err(CommandAuthError::NoOp(
                    "Device is already locked".to_string(),
                )),
                "unlock" if state == "unlocked" => Err(CommandAuthError::NoOp(
                    "Device is already unlocked".to_string(),
                )),
                _ => Ok(()),
            },
            // Covers, media players and everything else have state vocabularies of their own
            // (`open`/`closed`, `playing`/`paused`), so the power rules must not run.
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::capabilities;
    use crate::device::state::DeviceHealth;

    fn device(entity_id: &str, state: &str, attributes: serde_json::Value) -> Device {
        Device {
            id: "dev_test".to_string(),
            ha_entity_id: entity_id.to_string(),
            vendor: "test".to_string(),
            device_type: entity_id.split('.').next().unwrap().to_string(),
            room: None,
            friendly_name: "Test".to_string(),
            current_state: state.to_string(),
            health_status: DeviceHealth::Online,
            last_seen: chrono::Utc::now(),
            attributes: attributes.as_object().cloned().unwrap_or_default(),
        }
    }

    /// Builds capabilities through the real derivation path, so these tests exercise
    /// derivation and validation together rather than a hand-written fixture.
    fn caps_for(
        entity_id: &str,
        state: &str,
        attributes: serde_json::Value,
        unit: &str,
    ) -> DeviceCapabilities {
        capabilities::derive(&device(entity_id, state, attributes), unit)
    }

    fn nest_caps() -> DeviceCapabilities {
        caps_for(
            "climate.basement_room_2",
            "cool",
            serde_json::json!({
                "hvac_modes": ["cool", "off"],
                "min_temp": 50, "max_temp": 90,
                "preset_modes": ["none", "eco"],
                "current_temperature": 71, "temperature": 74,
                "supported_features": 401
            }),
            "°F",
        )
    }

    #[test]
    fn accepts_valid_thermostat_commands() {
        let caps = nest_caps();
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_temperature",
                &Some(serde_json::json!({"temperature": 72}))
            )
            .is_ok()
        );
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_hvac_mode",
                &Some(serde_json::json!({"hvac_mode": "cool"}))
            )
            .is_ok()
        );
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_preset_mode",
                &Some(serde_json::json!({"preset_mode": "eco"}))
            )
            .is_ok()
        );
        assert!(CommandAuthorizer::validate_command_schema(&caps, "turn_off", &None).is_ok());
    }

    /// The original bug: a Celsius-looking value on a °F thermostat.
    #[test]
    fn rejects_out_of_range_temperature() {
        let caps = nest_caps();
        let err = CommandAuthorizer::validate_command_schema(
            &caps,
            "set_temperature",
            &Some(serde_json::json!({"temperature": 22})),
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("50"), "error names the real minimum: {}", msg);
        assert!(msg.contains("90"), "error names the real maximum: {}", msg);
        assert!(msg.contains("°F"), "error names the real unit: {}", msg);

        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_temperature",
                &Some(serde_json::json!({"temperature": 95}))
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_hvac_mode() {
        let caps = nest_caps();
        for mode in ["heat", "auto", "heat_cool"] {
            let err = CommandAuthorizer::validate_command_schema(
                &caps,
                "set_hvac_mode",
                &Some(serde_json::json!({ "hvac_mode": mode })),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("cool"),
                "error should list the real modes, got: {}",
                err
            );
        }
    }

    #[test]
    fn rejects_missing_required_param() {
        let caps = nest_caps();
        // Previously this forwarded a bare entity_id to HA, which 400'd.
        assert!(CommandAuthorizer::validate_command_schema(&caps, "set_hvac_mode", &None).is_err());
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_temperature",
                &Some(serde_json::json!({}))
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unsupported_command_and_unknown_params() {
        let caps = nest_caps();
        let err = CommandAuthorizer::validate_command_schema(
            &caps,
            "set_fan_mode",
            &Some(serde_json::json!({"fan_mode": "auto"})),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not supported"));

        let err = CommandAuthorizer::validate_command_schema(
            &caps,
            "set_hvac_mode",
            &Some(serde_json::json!({"hvac_mode": "cool", "temperature": 70})),
        )
        .unwrap_err();
        assert!(err.to_string().contains("Unknown parameter"));
    }

    #[test]
    fn read_only_device_accepts_nothing() {
        let caps = caps_for(
            "sensor.basement_room_2_temperature",
            "71.42",
            serde_json::json!({"unit_of_measurement": "°F"}),
            "°F",
        );
        assert!(CommandAuthorizer::validate_command_schema(&caps, "turn_on", &None).is_err());
    }

    #[test]
    fn temperature_range_xor() {
        let caps = caps_for(
            "climate.dual",
            "heat_cool",
            serde_json::json!({
                "hvac_modes": ["heat_cool", "off"],
                "min_temp": 50, "max_temp": 90,
                "supported_features": 1 | 2
            }),
            "°F",
        );

        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_temperature",
                &Some(serde_json::json!({"target_temp_low": 68, "target_temp_high": 74}))
            )
            .is_ok()
        );

        // Both forms at once.
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_temperature",
                &Some(serde_json::json!({"temperature": 70, "target_temp_low": 68}))
            )
            .is_err()
        );

        // Half a pair.
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_temperature",
                &Some(serde_json::json!({"target_temp_low": 68}))
            )
            .is_err()
        );

        // Inverted pair.
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "set_temperature",
                &Some(serde_json::json!({"target_temp_low": 78, "target_temp_high": 70}))
            )
            .is_err()
        );
    }

    #[test]
    fn validates_light_params_against_entity_bounds() {
        let caps = caps_for(
            "light.desk",
            "on",
            serde_json::json!({
                "supported_color_modes": ["color_temp", "hs"],
                "min_color_temp_kelvin": 2000,
                "max_color_temp_kelvin": 6535,
                "supported_features": 0
            }),
            "°C",
        );

        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "turn_on",
                &Some(serde_json::json!({"brightness": 200}))
            )
            .is_ok()
        );
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "turn_on",
                &Some(serde_json::json!({"brightness": 999}))
            )
            .is_err()
        );
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "turn_on",
                &Some(serde_json::json!({"rgb_color": [255, 128, 0]}))
            )
            .is_ok()
        );
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "turn_on",
                &Some(serde_json::json!({"rgb_color": [255, 300, 0]}))
            )
            .is_err()
        );
        // 1000K is outside this entity's advertised range.
        assert!(
            CommandAuthorizer::validate_command_schema(
                &caps,
                "turn_on",
                &Some(serde_json::json!({"color_temp_kelvin": 1000}))
            )
            .is_err()
        );
    }

    #[test]
    fn climate_no_op_semantics() {
        let off = device("climate.t", "off", serde_json::json!({}));
        let cooling = device("climate.t", "cool", serde_json::json!({}));

        assert!(matches!(
            CommandAuthorizer::check_no_op(&off, "turn_off", &None),
            Err(CommandAuthError::NoOp(_))
        ));
        assert!(CommandAuthorizer::check_no_op(&cooling, "turn_off", &None).is_ok());
        // `turn_on` on a thermostat reporting a mode is NOT a no-op.
        assert!(CommandAuthorizer::check_no_op(&cooling, "turn_on", &None).is_ok());
        // Re-asserting a setpoint is legitimate; thermostats drift.
        assert!(
            CommandAuthorizer::check_no_op(
                &cooling,
                "set_temperature",
                &Some(serde_json::json!({"temperature": 72}))
            )
            .is_ok()
        );

        assert!(matches!(
            CommandAuthorizer::check_no_op(
                &cooling,
                "set_hvac_mode",
                &Some(serde_json::json!({"hvac_mode": "cool"}))
            ),
            Err(CommandAuthError::NoOp(_))
        ));
        assert!(
            CommandAuthorizer::check_no_op(
                &cooling,
                "set_hvac_mode",
                &Some(serde_json::json!({"hvac_mode": "off"}))
            )
            .is_ok()
        );
    }

    #[test]
    fn switch_no_op_semantics_unchanged() {
        let on = device("light.a", "on", serde_json::json!({}));
        let off = device("light.a", "off", serde_json::json!({}));

        assert!(matches!(
            CommandAuthorizer::check_no_op(&on, "turn_on", &None),
            Err(CommandAuthError::NoOp(_))
        ));
        assert!(
            CommandAuthorizer::check_no_op(
                &on,
                "turn_on",
                &Some(serde_json::json!({"brightness": 120}))
            )
            .is_ok()
        );
        assert!(CommandAuthorizer::check_no_op(&off, "turn_on", &None).is_ok());
    }
}
