use std::fmt;

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

pub struct CommandAuthorizer;

impl CommandAuthorizer {
    /// Validates command name and parameter bounds per device domain/type.
    pub fn validate_command_schema(
        device_type: &str,
        command: &str,
        params: &Option<serde_json::Value>,
    ) -> Result<(), CommandAuthError> {
        let domain = device_type.split('.').next().unwrap_or(device_type);

        match domain {
            "light" | "switch" | "input_boolean" => {
                match command {
                    "turn_on" | "turn_off" | "toggle" => {}
                    _ => {
                        return Err(CommandAuthError::InvalidSchema(format!(
                            "Command '{}' is not supported for domain '{}'",
                            command, domain
                        )))
                    }
                }

                if let Some(params_val) = params {
                    if let Some(brightness) = params_val.get("brightness") {
                        if let Some(b) = brightness.as_u64() {
                            if b > 255 {
                                return Err(CommandAuthError::InvalidSchema(format!(
                                    "Invalid brightness {}: must be between 0 and 255",
                                    b
                                )));
                            }
                        } else {
                            return Err(CommandAuthError::InvalidSchema(
                                "Brightness must be an integer between 0 and 255".to_string(),
                            ));
                        }
                    }

                    if let Some(color_temp) = params_val
                        .get("color_temp")
                        .or_else(|| params_val.get("color_temp_kelvin"))
                    {
                        if let Some(ct) = color_temp.as_u64() {
                            if !(1500..=6500).contains(&ct) {
                                return Err(CommandAuthError::InvalidSchema(format!(
                                    "Invalid color_temp {}: must be between 1500K and 6500K",
                                    ct
                                )));
                            }
                        } else {
                            return Err(CommandAuthError::InvalidSchema(
                                "Color temperature must be an integer between 1500 and 6500"
                                    .to_string(),
                            ));
                        }
                    }

                    if let Some(rgb_color) = params_val.get("rgb_color") {
                        if let Some(arr) = rgb_color.as_array() {
                            if arr.len() != 3 {
                                return Err(CommandAuthError::InvalidSchema(
                                    "rgb_color must be an array of 3 RGB values [r, g, b]"
                                        .to_string(),
                                ));
                            }
                            for val in arr {
                                if let Some(v) = val.as_u64() {
                                    if v > 255 {
                                        return Err(CommandAuthError::InvalidSchema(format!(
                                            "RGB color values must be between 0 and 255, got {}",
                                            v
                                        )));
                                    }
                                } else {
                                    return Err(CommandAuthError::InvalidSchema(
                                        "RGB color values must be integers between 0 and 255"
                                            .to_string(),
                                    ));
                                }
                            }
                        } else {
                            return Err(CommandAuthError::InvalidSchema(
                                "rgb_color must be a 3-element array [r, g, b]".to_string(),
                            ));
                        }
                    }

                    if let Some(hs_color) = params_val.get("hs_color") {
                        if let Some(arr) = hs_color.as_array() {
                            if arr.len() != 2 {
                                return Err(CommandAuthError::InvalidSchema(
                                    "hs_color must be an array of 2 values [hue, saturation]"
                                        .to_string(),
                                ));
                            }
                        } else {
                            return Err(CommandAuthError::InvalidSchema(
                                "hs_color must be a 2-element array [hue, saturation]".to_string(),
                            ));
                        }
                    }
                }
            }
            "climate" => match command {
                "set_temperature" => {
                    if let Some(params_val) = params {
                        if let Some(temp) = params_val.get("temperature") {
                            if let Some(t) = temp.as_f64() {
                                if !(10.0..=95.0).contains(&t) {
                                    return Err(CommandAuthError::InvalidSchema(format!(
                                        "Target temperature {:.1} out of bounds (10.0 to 95.0)",
                                        t
                                    )));
                                }
                            } else {
                                return Err(CommandAuthError::InvalidSchema(
                                    "Temperature parameter must be a numeric value".to_string(),
                                ));
                            }
                        } else {
                            return Err(CommandAuthError::InvalidSchema(
                                "Command 'set_temperature' requires a 'temperature' parameter"
                                    .to_string(),
                            ));
                        }
                    } else {
                        return Err(CommandAuthError::InvalidSchema(
                            "Command 'set_temperature' requires a 'params' payload".to_string(),
                        ));
                    }
                }
                "set_hvac_mode" | "set_preset_mode" | "set_fan_mode" | "turn_on" | "turn_off" => {}
                _ => {
                    return Err(CommandAuthError::InvalidSchema(format!(
                        "Command '{}' is not supported for domain 'climate'",
                        command
                    )))
                }
            },
            "lock" => match command {
                "lock" | "unlock" => {}
                _ => {
                    return Err(CommandAuthError::InvalidSchema(format!(
                        "Command '{}' is not supported for domain 'lock'",
                        command
                    )))
                }
            },
            _ => {
                // Generic fallback validation for other domains (e.g. input_button, fan, cover)
                match command {
                    "turn_on" | "turn_off" | "toggle" | "press" | "open_cover" | "close_cover" => {}
                    _ => {
                        return Err(CommandAuthError::InvalidSchema(format!(
                            "Command '{}' is not supported for domain '{}'",
                            command, domain
                        )))
                    }
                }
            }
        }

        Ok(())
    }

    /// Rejects redundant no-op commands (e.g. turning on an already on device without parameter adjustments).
    pub fn check_no_op(
        current_state: &str,
        command: &str,
        params: &Option<serde_json::Value>,
    ) -> Result<(), CommandAuthError> {
        let normalized_state = current_state.to_lowercase();

        // If turn_on includes light adjustment parameters (brightness, color_temp, color_temp_kelvin, rgb_color, etc.), allow it
        if command == "turn_on" && normalized_state == "on" {
            if let Some(params_val) = params {
                if params_val.get("brightness").is_some()
                    || params_val.get("color_temp").is_some()
                    || params_val.get("color_temp_kelvin").is_some()
                    || params_val.get("rgb_color").is_some()
                    || params_val.get("hs_color").is_some()
                    || params_val.get("effect").is_some()
                {
                    return Ok(());
                }
            }
            return Err(CommandAuthError::NoOp("Device is already on".to_string()));
        }

        match command {
            "turn_off" if normalized_state == "off" => {
                Err(CommandAuthError::NoOp("Device is already off".to_string()))
            }
            "lock" if normalized_state == "locked" => Err(CommandAuthError::NoOp(
                "Device is already locked".to_string(),
            )),
            "unlock" if normalized_state == "unlocked" => Err(CommandAuthError::NoOp(
                "Device is already unlocked".to_string(),
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_light_turn_on() {
        let res = CommandAuthorizer::validate_command_schema(
            "light",
            "turn_on",
            &Some(serde_json::json!({"brightness": 200})),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_invalid_brightness_bounds() {
        let res = CommandAuthorizer::validate_command_schema(
            "light",
            "turn_on",
            &Some(serde_json::json!({"brightness": 999})),
        );
        assert!(matches!(res, Err(CommandAuthError::InvalidSchema(_))));
    }

    #[test]
    fn test_climate_temperature_bounds() {
        let valid = CommandAuthorizer::validate_command_schema(
            "climate",
            "set_temperature",
            &Some(serde_json::json!({"temperature": 22.5})),
        );
        assert!(valid.is_ok());

        let invalid = CommandAuthorizer::validate_command_schema(
            "climate",
            "set_temperature",
            &Some(serde_json::json!({"temperature": 2.0})),
        );
        assert!(matches!(invalid, Err(CommandAuthError::InvalidSchema(_))));
    }

    #[test]
    fn test_color_temp_and_rgb_validation() {
        let valid_ct = CommandAuthorizer::validate_command_schema(
            "light",
            "turn_on",
            &Some(serde_json::json!({"color_temp": 4000})),
        );
        assert!(valid_ct.is_ok());

        let invalid_ct = CommandAuthorizer::validate_command_schema(
            "light",
            "turn_on",
            &Some(serde_json::json!({"color_temp": 1000})),
        );
        assert!(matches!(
            invalid_ct,
            Err(CommandAuthError::InvalidSchema(_))
        ));

        let valid_rgb = CommandAuthorizer::validate_command_schema(
            "light",
            "turn_on",
            &Some(serde_json::json!({"rgb_color": [255, 128, 0]})),
        );
        assert!(valid_rgb.is_ok());

        let invalid_rgb = CommandAuthorizer::validate_command_schema(
            "light",
            "turn_on",
            &Some(serde_json::json!({"rgb_color": [255, 300, 0]})),
        );
        assert!(matches!(
            invalid_rgb,
            Err(CommandAuthError::InvalidSchema(_))
        ));
    }

    #[test]
    fn test_no_op_rejection() {
        let res = CommandAuthorizer::check_no_op("on", "turn_on", &None);
        assert!(matches!(res, Err(CommandAuthError::NoOp(_))));

        let valid_with_param = CommandAuthorizer::check_no_op(
            "on",
            "turn_on",
            &Some(serde_json::json!({"brightness": 120})),
        );
        assert!(valid_with_param.is_ok());

        let valid = CommandAuthorizer::check_no_op("off", "turn_on", &None);
        assert!(valid.is_ok());
    }
}
