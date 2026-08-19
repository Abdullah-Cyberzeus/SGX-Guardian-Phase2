//! Derives what a device can actually do from the Home Assistant attributes we captured.
//!
//! Everything downstream — the command validator and the control UI — reads this instead of
//! guessing. Before it existed, the UI offered a hardcoded HVAC list and a "°C" label to a
//! thermostat that only supports `cool`/`off` on a °F scale, so most commands were rejected
//! by HA. Deriving from `supported_features` and the entity's own attribute lists means an
//! option is offered if and only if the device really has it.
//!
//! Adding a domain is one `derive_*` function plus one match arm in [`derive`].

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::device::state::Device;

/// `ClimateEntityFeature` — <https://developers.home-assistant.io/docs/core/entity/climate>
///
/// Worked example: the Nest thermostat reports `supported_features = 401`, which is
/// `TARGET_TEMPERATURE(1) | PRESET_MODE(16) | TURN_OFF(128) | TURN_ON(256)`. It therefore
/// gets a setpoint, presets and power, but no fan, swing, humidity or temperature *range*.
pub mod climate_features {
    pub const TARGET_TEMPERATURE: u64 = 1;
    pub const TARGET_TEMPERATURE_RANGE: u64 = 2;
    pub const TARGET_HUMIDITY: u64 = 4;
    pub const FAN_MODE: u64 = 8;
    pub const PRESET_MODE: u64 = 16;
    pub const SWING_MODE: u64 = 32;
    pub const TURN_OFF: u64 = 128;
    pub const TURN_ON: u64 = 256;
    pub const SWING_HORIZONTAL_MODE: u64 = 512;
}

/// `LightEntityFeature`
pub mod light_features {
    pub const EFFECT: u64 = 4;
    pub const FLASH: u64 = 8;
    pub const TRANSITION: u64 = 32;
}

/// `CoverEntityFeature`
pub mod cover_features {
    pub const OPEN: u64 = 1;
    pub const CLOSE: u64 = 2;
    pub const SET_POSITION: u64 = 4;
    pub const STOP: u64 = 8;
    pub const SET_TILT_POSITION: u64 = 128;
}

/// `LockEntityFeature`
pub mod lock_features {
    pub const OPEN: u64 = 1;
}

/// `MediaPlayerEntityFeature`
pub mod media_features {
    pub const PAUSE: u64 = 1;
    pub const VOLUME_SET: u64 = 4;
    pub const VOLUME_MUTE: u64 = 8;
    pub const PREVIOUS_TRACK: u64 = 16;
    pub const NEXT_TRACK: u64 = 32;
    pub const TURN_ON: u64 = 128;
    pub const TURN_OFF: u64 = 256;
    pub const PLAY: u64 = 16384;
}

/// How a command parameter should be entered and validated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamKind {
    Number,
    Enum,
    Bool,
    Rgb,
    Text,
}

/// One parameter of one command, carrying the real bounds/options for *this* device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandParamSpec {
    pub name: String,
    pub label: String,
    pub kind: ParamKind,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
}

impl CommandParamSpec {
    fn new(name: &str, label: &str, kind: ParamKind, required: bool) -> Self {
        Self {
            name: name.to_string(),
            label: label.to_string(),
            kind,
            required,
            min: None,
            max: None,
            step: None,
            unit: None,
            options: Vec::new(),
            default: None,
        }
    }

    fn number(name: &str, label: &str, required: bool) -> Self {
        Self::new(name, label, ParamKind::Number, required)
    }

    fn enumerated(name: &str, label: &str, options: Vec<String>, required: bool) -> Self {
        let mut spec = Self::new(name, label, ParamKind::Enum, required);
        spec.options = options;
        spec
    }

    fn bounds(mut self, min: Option<f64>, max: Option<f64>, step: Option<f64>) -> Self {
        self.min = min;
        self.max = max;
        self.step = step;
        self
    }

    fn unit(mut self, unit: &str) -> Self {
        self.unit = Some(unit.to_string());
        self
    }

    fn default_value(mut self, value: Option<Value>) -> Self {
        self.default = value;
        self
    }
}

/// A command this device accepts, with its parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub command: String,
    pub label: String,
    pub domain: String,
    pub params: Vec<CommandParamSpec>,
}

impl CommandSpec {
    fn new(domain: &str, command: &str, label: &str, params: Vec<CommandParamSpec>) -> Self {
        Self {
            command: command.to_string(),
            label: label.to_string(),
            domain: domain.to_string(),
            params,
        }
    }
}

/// A read-only value worth showing next to the controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reading {
    pub key: String,
    pub label: String,
    pub value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

impl Reading {
    fn new(key: &str, label: &str, value: Value, unit: Option<String>) -> Self {
        Self {
            key: key.to_string(),
            label: label.to_string(),
            value,
            unit,
        }
    }
}

/// Climate-specific detail, surfaced so the UI can render a thermostat properly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClimateCapabilities {
    pub hvac_modes: Vec<String>,
    pub preset_modes: Vec<String>,
    pub fan_modes: Vec<String>,
    pub swing_modes: Vec<String>,
    pub min_temp: Option<f64>,
    pub max_temp: Option<f64>,
    pub target_temp_step: Option<f64>,
    pub supports_target_temperature: bool,
    pub supports_temperature_range: bool,
    pub supports_target_humidity: bool,
    pub min_humidity: Option<f64>,
    pub max_humidity: Option<f64>,
    pub current_temperature: Option<f64>,
    pub target_temperature: Option<f64>,
    pub target_temp_low: Option<f64>,
    pub target_temp_high: Option<f64>,
    pub current_humidity: Option<f64>,
    pub hvac_action: Option<String>,
    pub preset_mode: Option<String>,
    pub fan_mode: Option<String>,
}

/// Light-specific detail.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LightCapabilities {
    pub supported_color_modes: Vec<String>,
    pub effect_list: Vec<String>,
    pub min_color_temp_kelvin: Option<u64>,
    pub max_color_temp_kelvin: Option<u64>,
    pub brightness: Option<u64>,
    pub supports_brightness: bool,
    pub supports_color: bool,
    pub supports_color_temp: bool,
}

/// What a device can do, derived from its live HA attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub device_id: String,
    pub ha_entity_id: String,
    pub domain: String,
    pub temperature_unit: String,
    pub supported_features: u64,
    /// `false` means the UI must render no command controls at all (sensors, cameras, ...).
    pub controllable: bool,
    pub supported_commands: Vec<CommandSpec>,
    pub readings: Vec<Reading>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub climate: Option<ClimateCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub light: Option<LightCapabilities>,
}

impl DeviceCapabilities {
    /// Looks up a command by name.
    pub fn command(&self, name: &str) -> Option<&CommandSpec> {
        self.supported_commands.iter().find(|c| c.command == name)
    }

    /// Command names, for error messages.
    pub fn command_names(&self) -> Vec<&str> {
        self.supported_commands
            .iter()
            .map(|c| c.command.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Attribute helpers
// ---------------------------------------------------------------------------

fn attr_f64(attrs: &Map<String, Value>, key: &str) -> Option<f64> {
    attrs.get(key).and_then(|v| v.as_f64())
}

fn attr_u64(attrs: &Map<String, Value>, key: &str) -> Option<u64> {
    attrs.get(key).and_then(|v| v.as_u64())
}

fn attr_str(attrs: &Map<String, Value>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

fn attr_str_list(attrs: &Map<String, Value>, key: &str) -> Vec<String> {
    attrs
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn supported_features(attrs: &Map<String, Value>) -> u64 {
    attr_u64(attrs, "supported_features").unwrap_or(0)
}

fn is_fahrenheit(unit: &str) -> bool {
    unit.contains('F')
}

/// Sensible setpoint bounds when the entity did not report `min_temp`/`max_temp`
/// (a legacy registry entry, or an entity that is currently unavailable).
fn fallback_temp_bounds(unit: &str) -> (f64, f64, f64) {
    if is_fahrenheit(unit) {
        (45.0, 95.0, 1.0)
    } else {
        (7.0, 35.0, 0.5)
    }
}

fn titleize(value: &str) -> String {
    value
        .split(['_', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Derives capabilities for a device. Pure and synchronous, so it is cheap to call per
/// request and trivial to test.
pub fn derive(device: &Device, temperature_unit: &str) -> DeviceCapabilities {
    let domain = device
        .ha_entity_id
        .split('.')
        .next()
        .unwrap_or("unknown")
        .to_string();

    let attrs = &device.attributes;
    let state = device.current_state.as_str();
    let sf = supported_features(attrs);

    let mut caps = DeviceCapabilities {
        device_id: device.id.clone(),
        ha_entity_id: device.ha_entity_id.clone(),
        domain: domain.clone(),
        temperature_unit: temperature_unit.to_string(),
        supported_features: sf,
        controllable: true,
        supported_commands: Vec::new(),
        readings: Vec::new(),
        climate: None,
        light: None,
    };

    match domain.as_str() {
        "climate" => {
            let (commands, readings, climate) = derive_climate(attrs, state, temperature_unit);
            caps.supported_commands = commands;
            caps.readings = readings;
            caps.climate = Some(climate);
        }
        "light" => {
            let (commands, readings, light) = derive_light(attrs, sf);
            caps.supported_commands = commands;
            caps.readings = readings;
            caps.light = Some(light);
        }
        "switch" | "input_boolean" | "fan" | "siren" | "humidifier" => {
            caps.supported_commands = derive_switch_like(&domain);
        }
        "lock" => caps.supported_commands = derive_lock(sf),
        "cover" => caps.supported_commands = derive_cover(sf),
        "media_player" => caps.supported_commands = derive_media_player(attrs, sf),
        "input_button" => {
            caps.supported_commands =
                vec![CommandSpec::new("input_button", "press", "Press", vec![])];
        }
        "input_select" => {
            let options = attr_str_list(attrs, "options");
            if options.is_empty() {
                caps.controllable = false;
            } else {
                caps.supported_commands = vec![CommandSpec::new(
                    "input_select",
                    "select_option",
                    "Select Option",
                    vec![CommandParamSpec::enumerated(
                        "option",
                        "Option",
                        options,
                        true,
                    )
                    .default_value(Some(Value::String(state.to_string())))],
                )];
            }
        }
        "input_number" => {
            let step = attr_f64(attrs, "step");
            caps.supported_commands = vec![CommandSpec::new(
                "input_number",
                "set_value",
                "Set Value",
                vec![CommandParamSpec::number("value", "Value", true)
                    .bounds(attr_f64(attrs, "min"), attr_f64(attrs, "max"), step)
                    .default_value(state.parse::<f64>().ok().map(Value::from))],
            )];
        }
        // Read-only domains: rendering an On/Off control here was pure fiction.
        "sensor" | "binary_sensor" | "camera" | "weather" | "device_tracker" | "person" => {
            caps.controllable = false;
            caps.readings = derive_readonly_readings(attrs, state);
        }
        _ => {
            // Unknown domain: expose nothing rather than guessing at On/Off.
            caps.controllable = false;
        }
    }

    if caps.supported_commands.is_empty() {
        caps.controllable = false;
    }

    caps
}

// ---------------------------------------------------------------------------
// Per-domain derivation
// ---------------------------------------------------------------------------

fn derive_climate(
    attrs: &Map<String, Value>,
    state: &str,
    unit: &str,
) -> (Vec<CommandSpec>, Vec<Reading>, ClimateCapabilities) {
    let sf = supported_features(attrs);

    let hvac_modes = attr_str_list(attrs, "hvac_modes");
    let preset_modes = attr_str_list(attrs, "preset_modes");
    let fan_modes = attr_str_list(attrs, "fan_modes");
    let swing_modes = attr_str_list(attrs, "swing_modes");

    let (fb_min, fb_max, fb_step) = fallback_temp_bounds(unit);
    let min_temp = attr_f64(attrs, "min_temp").or(Some(fb_min));
    let max_temp = attr_f64(attrs, "max_temp").or(Some(fb_max));
    let step = attr_f64(attrs, "target_temp_step").or(Some(fb_step));

    let supports_target_temperature = sf & climate_features::TARGET_TEMPERATURE != 0;
    let supports_temperature_range = sf & climate_features::TARGET_TEMPERATURE_RANGE != 0;
    let supports_target_humidity = sf & climate_features::TARGET_HUMIDITY != 0;

    let climate = ClimateCapabilities {
        hvac_modes: hvac_modes.clone(),
        preset_modes: preset_modes.clone(),
        fan_modes: fan_modes.clone(),
        swing_modes: swing_modes.clone(),
        min_temp,
        max_temp,
        target_temp_step: step,
        supports_target_temperature,
        supports_temperature_range,
        supports_target_humidity,
        min_humidity: attr_f64(attrs, "min_humidity"),
        max_humidity: attr_f64(attrs, "max_humidity"),
        current_temperature: attr_f64(attrs, "current_temperature"),
        target_temperature: attr_f64(attrs, "temperature"),
        target_temp_low: attr_f64(attrs, "target_temp_low"),
        target_temp_high: attr_f64(attrs, "target_temp_high"),
        current_humidity: attr_f64(attrs, "current_humidity"),
        hvac_action: attr_str(attrs, "hvac_action"),
        preset_mode: attr_str(attrs, "preset_mode"),
        fan_mode: attr_str(attrs, "fan_mode"),
    };

    let mut commands = Vec::new();

    // A climate entity's *state* is its HVAC mode, so it doubles as the current selection.
    if !hvac_modes.is_empty() {
        commands.push(CommandSpec::new(
            "climate",
            "set_hvac_mode",
            "Set HVAC Mode",
            vec![CommandParamSpec::enumerated(
                "hvac_mode",
                "HVAC mode",
                hvac_modes.clone(),
                true,
            )
            .default_value(Some(Value::String(state.to_string())))],
        ));
    }

    if supports_target_temperature || supports_temperature_range {
        let mut params = Vec::new();

        // When an entity supports both, each individual field becomes optional and the
        // validator enforces "single setpoint XOR low/high pair".
        let both = supports_target_temperature && supports_temperature_range;

        if supports_target_temperature {
            params.push(
                CommandParamSpec::number("temperature", "Temperature", !both)
                    .bounds(min_temp, max_temp, step)
                    .unit(unit)
                    .default_value(climate.target_temperature.map(Value::from)),
            );
        }
        if supports_temperature_range {
            params.push(
                CommandParamSpec::number("target_temp_low", "Low temperature", !both)
                    .bounds(min_temp, max_temp, step)
                    .unit(unit)
                    .default_value(climate.target_temp_low.map(Value::from)),
            );
            params.push(
                CommandParamSpec::number("target_temp_high", "High temperature", !both)
                    .bounds(min_temp, max_temp, step)
                    .unit(unit)
                    .default_value(climate.target_temp_high.map(Value::from)),
            );
        }

        // HA accepts an optional hvac_mode alongside a setpoint.
        if !hvac_modes.is_empty() {
            params.push(CommandParamSpec::enumerated(
                "hvac_mode",
                "HVAC mode (optional)",
                hvac_modes.clone(),
                false,
            ));
        }

        commands.push(CommandSpec::new(
            "climate",
            "set_temperature",
            "Set Temperature",
            params,
        ));
    }

    if sf & climate_features::PRESET_MODE != 0 && !preset_modes.is_empty() {
        commands.push(CommandSpec::new(
            "climate",
            "set_preset_mode",
            "Set Preset Mode",
            vec![CommandParamSpec::enumerated(
                "preset_mode",
                "Preset",
                preset_modes,
                true,
            )
            .default_value(climate.preset_mode.clone().map(Value::String))],
        ));
    }

    if sf & climate_features::FAN_MODE != 0 && !fan_modes.is_empty() {
        commands.push(CommandSpec::new(
            "climate",
            "set_fan_mode",
            "Set Fan Mode",
            vec![
                CommandParamSpec::enumerated("fan_mode", "Fan mode", fan_modes, true)
                    .default_value(climate.fan_mode.clone().map(Value::String)),
            ],
        ));
    }

    if sf & climate_features::SWING_MODE != 0 && !swing_modes.is_empty() {
        commands.push(CommandSpec::new(
            "climate",
            "set_swing_mode",
            "Set Swing Mode",
            vec![CommandParamSpec::enumerated(
                "swing_mode",
                "Swing mode",
                swing_modes,
                true,
            )],
        ));
    }

    if supports_target_humidity {
        commands.push(CommandSpec::new(
            "climate",
            "set_humidity",
            "Set Humidity",
            vec![CommandParamSpec::number("humidity", "Humidity", true)
                .bounds(
                    climate.min_humidity.or(Some(30.0)),
                    climate.max_humidity.or(Some(99.0)),
                    Some(1.0),
                )
                .unit("%")],
        ));
    }

    if sf & climate_features::TURN_ON != 0 {
        commands.push(CommandSpec::new("climate", "turn_on", "Turn On", vec![]));
    }
    if sf & climate_features::TURN_OFF != 0 {
        commands.push(CommandSpec::new("climate", "turn_off", "Turn Off", vec![]));
    }

    let mut readings = Vec::new();
    if let Some(current) = climate.current_temperature {
        readings.push(Reading::new(
            "current_temperature",
            "Current temperature",
            Value::from(current),
            Some(unit.to_string()),
        ));
    }
    if let Some(humidity) = climate.current_humidity {
        readings.push(Reading::new(
            "current_humidity",
            "Humidity",
            Value::from(humidity),
            Some("%".to_string()),
        ));
    }
    if let Some(action) = &climate.hvac_action {
        readings.push(Reading::new(
            "hvac_action",
            "HVAC action",
            Value::String(action.clone()),
            None,
        ));
    }
    if let Some(preset) = &climate.preset_mode {
        readings.push(Reading::new(
            "preset_mode",
            "Preset",
            Value::String(preset.clone()),
            None,
        ));
    }

    (commands, readings, climate)
}

fn derive_light(
    attrs: &Map<String, Value>,
    sf: u64,
) -> (Vec<CommandSpec>, Vec<Reading>, LightCapabilities) {
    let color_modes = attr_str_list(attrs, "supported_color_modes");
    let effect_list = attr_str_list(attrs, "effect_list");

    let supports_brightness = color_modes.iter().any(|m| {
        matches!(
            m.as_str(),
            "brightness" | "color_temp" | "hs" | "rgb" | "rgbw" | "rgbww" | "xy" | "white"
        )
    });
    let supports_color = color_modes
        .iter()
        .any(|m| matches!(m.as_str(), "hs" | "rgb" | "rgbw" | "rgbww" | "xy"));
    let supports_color_temp = color_modes.iter().any(|m| m == "color_temp");

    let light = LightCapabilities {
        supported_color_modes: color_modes,
        effect_list: effect_list.clone(),
        min_color_temp_kelvin: attr_u64(attrs, "min_color_temp_kelvin"),
        max_color_temp_kelvin: attr_u64(attrs, "max_color_temp_kelvin"),
        brightness: attr_u64(attrs, "brightness"),
        supports_brightness,
        supports_color,
        supports_color_temp,
    };

    let mut on_params = Vec::new();
    if supports_brightness {
        on_params.push(
            CommandParamSpec::number("brightness", "Brightness", false)
                .bounds(Some(0.0), Some(255.0), Some(1.0))
                .default_value(light.brightness.map(Value::from)),
        );
    }
    if supports_color_temp {
        on_params.push(
            CommandParamSpec::number("color_temp_kelvin", "Color temperature", false)
                .bounds(
                    light.min_color_temp_kelvin.map(|v| v as f64).or(Some(2000.0)),
                    light.max_color_temp_kelvin.map(|v| v as f64).or(Some(6535.0)),
                    Some(50.0),
                )
                .unit("K"),
        );
    }
    if supports_color {
        on_params.push(CommandParamSpec::new(
            "rgb_color",
            "RGB color",
            ParamKind::Rgb,
            false,
        ));
    }
    if sf & light_features::EFFECT != 0 && !effect_list.is_empty() {
        on_params.push(CommandParamSpec::enumerated(
            "effect",
            "Effect",
            effect_list,
            false,
        ));
    }

    let commands = vec![
        CommandSpec::new("light", "turn_on", "Turn On", on_params),
        CommandSpec::new("light", "turn_off", "Turn Off", vec![]),
        CommandSpec::new("light", "toggle", "Toggle", vec![]),
    ];

    (commands, Vec::new(), light)
}

fn derive_switch_like(domain: &str) -> Vec<CommandSpec> {
    vec![
        CommandSpec::new(domain, "turn_on", "Turn On", vec![]),
        CommandSpec::new(domain, "turn_off", "Turn Off", vec![]),
        CommandSpec::new(domain, "toggle", "Toggle", vec![]),
    ]
}

fn derive_lock(sf: u64) -> Vec<CommandSpec> {
    let mut commands = vec![
        CommandSpec::new("lock", "lock", "Lock", vec![]),
        CommandSpec::new("lock", "unlock", "Unlock", vec![]),
    ];
    if sf & lock_features::OPEN != 0 {
        commands.push(CommandSpec::new("lock", "open", "Open", vec![]));
    }
    commands
}

fn derive_cover(sf: u64) -> Vec<CommandSpec> {
    let mut commands = Vec::new();
    if sf & cover_features::OPEN != 0 {
        commands.push(CommandSpec::new("cover", "open_cover", "Open", vec![]));
    }
    if sf & cover_features::CLOSE != 0 {
        commands.push(CommandSpec::new("cover", "close_cover", "Close", vec![]));
    }
    if sf & cover_features::STOP != 0 {
        commands.push(CommandSpec::new("cover", "stop_cover", "Stop", vec![]));
    }
    if sf & cover_features::SET_POSITION != 0 {
        commands.push(CommandSpec::new(
            "cover",
            "set_cover_position",
            "Set Position",
            vec![
                CommandParamSpec::number("position", "Position", true)
                    .bounds(Some(0.0), Some(100.0), Some(1.0))
                    .unit("%"),
            ],
        ));
    }
    if sf & cover_features::SET_TILT_POSITION != 0 {
        commands.push(CommandSpec::new(
            "cover",
            "set_cover_tilt_position",
            "Set Tilt",
            vec![
                CommandParamSpec::number("tilt_position", "Tilt position", true)
                    .bounds(Some(0.0), Some(100.0), Some(1.0))
                    .unit("%"),
            ],
        ));
    }
    commands
}

fn derive_media_player(attrs: &Map<String, Value>, sf: u64) -> Vec<CommandSpec> {
    let mut commands = Vec::new();
    if sf & media_features::TURN_ON != 0 {
        commands.push(CommandSpec::new("media_player", "turn_on", "Turn On", vec![]));
    }
    if sf & media_features::TURN_OFF != 0 {
        commands.push(CommandSpec::new(
            "media_player",
            "turn_off",
            "Turn Off",
            vec![],
        ));
    }
    if sf & media_features::PLAY != 0 {
        commands.push(CommandSpec::new(
            "media_player",
            "media_play",
            "Play",
            vec![],
        ));
    }
    if sf & media_features::PAUSE != 0 {
        commands.push(CommandSpec::new(
            "media_player",
            "media_pause",
            "Pause",
            vec![],
        ));
    }
    if sf & media_features::NEXT_TRACK != 0 {
        commands.push(CommandSpec::new(
            "media_player",
            "media_next_track",
            "Next Track",
            vec![],
        ));
    }
    if sf & media_features::PREVIOUS_TRACK != 0 {
        commands.push(CommandSpec::new(
            "media_player",
            "media_previous_track",
            "Previous Track",
            vec![],
        ));
    }
    if sf & media_features::VOLUME_SET != 0 {
        commands.push(CommandSpec::new(
            "media_player",
            "volume_set",
            "Set Volume",
            vec![CommandParamSpec::number("volume_level", "Volume", true)
                .bounds(Some(0.0), Some(1.0), Some(0.01))
                .default_value(attr_f64(attrs, "volume_level").map(Value::from))],
        ));
    }
    if sf & media_features::VOLUME_MUTE != 0 {
        commands.push(CommandSpec::new(
            "media_player",
            "volume_mute",
            "Mute",
            vec![CommandParamSpec::new(
                "is_volume_muted",
                "Muted",
                ParamKind::Bool,
                true,
            )],
        ));
    }
    commands
}

fn derive_readonly_readings(attrs: &Map<String, Value>, state: &str) -> Vec<Reading> {
    let unit = attr_str(attrs, "unit_of_measurement");
    let label = attr_str(attrs, "device_class")
        .map(|c| titleize(&c))
        .unwrap_or_else(|| "State".to_string());

    let value = state
        .parse::<f64>()
        .map(Value::from)
        .unwrap_or_else(|_| Value::String(state.to_string()));

    vec![Reading::new("state", &label, value, unit)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::state::DeviceHealth;

    fn device_with(entity_id: &str, state: &str, attributes: Value) -> Device {
        Device {
            id: "dev_test".to_string(),
            ha_entity_id: entity_id.to_string(),
            vendor: "google_nest".to_string(),
            device_type: entity_id.split('.').next().unwrap().to_string(),
            room: None,
            friendly_name: "Test Device".to_string(),
            current_state: state.to_string(),
            health_status: DeviceHealth::Online,
            last_seen: chrono::Utc::now(),
            attributes: attributes.as_object().cloned().unwrap_or_default(),
        }
    }

    /// The exact attribute payload the live Nest thermostat reports.
    fn nest_thermostat() -> Device {
        device_with(
            "climate.basement_room_2",
            "cool",
            serde_json::json!({
                "hvac_modes": ["cool", "off"],
                "min_temp": 50,
                "max_temp": 90,
                "preset_modes": ["none", "eco"],
                "current_temperature": 71,
                "temperature": 74,
                "current_humidity": 63.0,
                "hvac_action": "idle",
                "preset_mode": "none",
                "friendly_name": "Room 2",
                "supported_features": 401
            }),
        )
    }

    #[test]
    fn derives_nest_thermostat() {
        let caps = derive(&nest_thermostat(), "°F");

        assert!(caps.controllable);
        assert_eq!(caps.supported_features, 401);
        assert_eq!(caps.temperature_unit, "°F");

        let mut names = caps.command_names();
        names.sort();
        assert_eq!(
            names,
            vec![
                "set_hvac_mode",
                "set_preset_mode",
                "set_temperature",
                "turn_off",
                "turn_on"
            ],
            "401 grants exactly these; no fan/swing/humidity"
        );

        // The setpoint must carry the device's real bounds and HA's real unit.
        let temp = caps
            .command("set_temperature")
            .unwrap()
            .params
            .iter()
            .find(|p| p.name == "temperature")
            .unwrap();
        assert_eq!(temp.min, Some(50.0));
        assert_eq!(temp.max, Some(90.0));
        assert_eq!(temp.unit.as_deref(), Some("°F"));
        assert_eq!(temp.default, Some(Value::from(74.0)));
        assert!(temp.required, "single-setpoint device requires `temperature`");

        // Only the modes the device actually has.
        let hvac = &caps.command("set_hvac_mode").unwrap().params[0];
        assert_eq!(hvac.options, vec!["cool", "off"]);
        assert_eq!(hvac.default, Some(Value::String("cool".into())));

        let preset = &caps.command("set_preset_mode").unwrap().params[0];
        assert_eq!(preset.options, vec!["none", "eco"]);

        let climate = caps.climate.unwrap();
        assert!(climate.supports_target_temperature);
        assert!(!climate.supports_temperature_range);
        assert_eq!(climate.current_temperature, Some(71.0));
    }

    #[test]
    fn bitmask_gating() {
        let cases: Vec<(u64, Vec<&str>, Vec<&str>)> = vec![
            // (supported_features, must contain, must NOT contain)
            (0, vec![], vec!["set_temperature", "turn_on", "turn_off"]),
            (
                climate_features::TARGET_TEMPERATURE,
                vec!["set_temperature"],
                vec!["turn_on", "set_preset_mode"],
            ),
            (
                climate_features::TARGET_TEMPERATURE_RANGE,
                vec!["set_temperature"],
                vec!["turn_on"],
            ),
            (
                climate_features::FAN_MODE,
                vec!["set_fan_mode"],
                vec!["set_temperature"],
            ),
            (
                climate_features::PRESET_MODE,
                vec!["set_preset_mode"],
                vec!["set_fan_mode"],
            ),
            (
                climate_features::TURN_ON | climate_features::TURN_OFF,
                vec!["turn_on", "turn_off"],
                vec!["set_temperature"],
            ),
        ];

        for (sf, expect, reject) in cases {
            let device = device_with(
                "climate.test",
                "cool",
                serde_json::json!({
                    "hvac_modes": ["cool", "off"],
                    "fan_modes": ["auto", "on"],
                    "preset_modes": ["none", "eco"],
                    "supported_features": sf
                }),
            );
            let caps = derive(&device, "°F");
            let names = caps.command_names();
            for cmd in expect {
                assert!(names.contains(&cmd), "sf={} should expose {}", sf, cmd);
            }
            for cmd in reject {
                assert!(!names.contains(&cmd), "sf={} must not expose {}", sf, cmd);
            }
        }
    }

    #[test]
    fn temperature_range_params_are_optional_when_both_bits_set() {
        let device = device_with(
            "climate.dual",
            "heat_cool",
            serde_json::json!({
                "hvac_modes": ["heat_cool", "off"],
                "min_temp": 50, "max_temp": 90,
                "supported_features":
                    climate_features::TARGET_TEMPERATURE | climate_features::TARGET_TEMPERATURE_RANGE
            }),
        );
        let caps = derive(&device, "°F");
        let params = &caps.command("set_temperature").unwrap().params;

        for name in ["temperature", "target_temp_low", "target_temp_high"] {
            let p = params.iter().find(|p| p.name == name).unwrap();
            assert!(!p.required, "{} is optional when both bits are set", name);
        }
        assert!(caps.climate.unwrap().supports_temperature_range);
    }

    #[test]
    fn unit_aware_defaults_when_bounds_missing() {
        let attrs = serde_json::json!({
            "hvac_modes": ["heat", "off"],
            "supported_features": climate_features::TARGET_TEMPERATURE
        });

        let f = derive(&device_with("climate.f", "heat", attrs.clone()), "°F");
        let fp = &f.command("set_temperature").unwrap().params[0];
        assert_eq!((fp.min, fp.max, fp.step), (Some(45.0), Some(95.0), Some(1.0)));

        let c = derive(&device_with("climate.c", "heat", attrs), "°C");
        let cp = &c.command("set_temperature").unwrap().params[0];
        assert_eq!((cp.min, cp.max, cp.step), (Some(7.0), Some(35.0), Some(0.5)));
    }

    /// Permanent guard: sensors used to be handed a nonfunctional On/Off control.
    #[test]
    fn sensor_is_not_controllable() {
        let device = device_with(
            "sensor.basement_room_2_temperature",
            "71.42",
            serde_json::json!({
                "unit_of_measurement": "°F",
                "device_class": "temperature",
                "friendly_name": "Room 2 Temperature"
            }),
        );
        let caps = derive(&device, "°F");

        assert!(!caps.controllable);
        assert!(caps.supported_commands.is_empty());
        assert_eq!(caps.readings.len(), 1);
        assert_eq!(caps.readings[0].unit.as_deref(), Some("°F"));
    }

    #[test]
    fn unknown_domain_is_not_controllable() {
        let caps = derive(
            &device_with("weather.home", "sunny", serde_json::json!({})),
            "°F",
        );
        assert!(!caps.controllable);
        assert!(caps.supported_commands.is_empty());
    }

    #[test]
    fn light_controls_follow_color_modes() {
        let device = device_with(
            "light.desk",
            "on",
            serde_json::json!({
                "supported_color_modes": ["color_temp", "hs"],
                "min_color_temp_kelvin": 2000,
                "max_color_temp_kelvin": 6535,
                "brightness": 180,
                "supported_features": 0
            }),
        );
        let caps = derive(&device, "°F");
        let params = &caps.command("turn_on").unwrap().params;
        let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();

        assert!(names.contains(&"brightness"));
        assert!(names.contains(&"color_temp_kelvin"));
        assert!(names.contains(&"rgb_color"));
        assert!(!names.contains(&"effect"), "EFFECT bit is not set");

        let ct = params
            .iter()
            .find(|p| p.name == "color_temp_kelvin")
            .unwrap();
        assert_eq!(ct.min, Some(2000.0), "kelvin bounds come from the entity");
        assert_eq!(ct.max, Some(6535.0));
    }

    #[test]
    fn light_without_color_support_gets_no_color_params() {
        let device = device_with(
            "light.plain",
            "on",
            serde_json::json!({ "supported_color_modes": ["onoff"], "supported_features": 0 }),
        );
        let caps = derive(&device, "°C");
        assert!(caps.command("turn_on").unwrap().params.is_empty());
    }
}
