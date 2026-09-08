use chrono::Utc;
use serde_json::{json, Value};
use sgx_guardian_client::api::auth::command_auth::{CommandAuthError, CommandAuthorizer};
use sgx_guardian_client::device::capabilities::{
    self, climate_features, cover_features, light_features, lock_features, media_features,
    CommandParamSpec, CommandSpec, DeviceCapabilities, ParamKind,
};
use sgx_guardian_client::device::state::{Device, DeviceHealth};

fn device(entity_id: &str, state: &str, attributes: Value) -> Device {
    Device {
        id: format!("dev-{}", entity_id.replace('.', "-")),
        ha_entity_id: entity_id.into(),
        vendor: "test".into(),
        device_type: entity_id.split('.').next().unwrap_or("unknown").into(),
        room: Some("Lab".into()),
        friendly_name: "Test Device".into(),
        current_state: state.into(),
        health_status: DeviceHealth::Online,
        last_seen: Utc::now(),
        attributes: attributes.as_object().cloned().unwrap_or_default(),
    }
}

fn caps(entity_id: &str, state: &str, attributes: Value) -> DeviceCapabilities {
    capabilities::derive(&device(entity_id, state, attributes), "°C")
}

#[allow(clippy::too_many_arguments)]
fn param(
    name: &str,
    label: &str,
    kind: ParamKind,
    required: bool,
    min: Option<f64>,
    max: Option<f64>,
    unit: Option<&str>,
    options: &[&str],
) -> CommandParamSpec {
    CommandParamSpec {
        name: name.into(),
        label: label.into(),
        kind,
        required,
        min,
        max,
        step: None,
        unit: unit.map(str::to_string),
        options: options.iter().map(|value| (*value).to_string()).collect(),
        default: None,
    }
}

fn custom_caps(command: &str, params: Vec<CommandParamSpec>) -> DeviceCapabilities {
    DeviceCapabilities {
        device_id: "dev-custom".into(),
        ha_entity_id: "custom.entity".into(),
        domain: "custom".into(),
        temperature_unit: "°C".into(),
        supported_features: 0,
        controllable: true,
        supported_commands: vec![CommandSpec {
            command: command.into(),
            label: "Custom command".into(),
            domain: "custom".into(),
            params,
        }],
        readings: vec![],
        climate: None,
        light: None,
    }
}

fn schema_error(caps: &DeviceCapabilities, command: &str, params: Option<Value>) -> String {
    match CommandAuthorizer::validate_command_schema(caps, command, &params).unwrap_err() {
        CommandAuthError::InvalidSchema(message) => message,
        other => panic!("expected invalid schema, got {other:?}"),
    }
}

#[test]
fn readonly_unknown_and_input_domains_derive_values_labels_and_controls() {
    let numeric = caps(
        "sensor.temperature",
        "21.5",
        json!({"device_class":"air_temperature", "unit_of_measurement":"°C"}),
    );
    assert!(!numeric.controllable);
    assert_eq!(numeric.readings[0].label, "Air Temperature");
    assert_eq!(numeric.readings[0].value, json!(21.5));
    assert_eq!(numeric.readings[0].unit.as_deref(), Some("°C"));

    for domain in [
        "binary_sensor",
        "camera",
        "weather",
        "device_tracker",
        "person",
    ] {
        let derived = caps(&format!("{domain}.sample"), "active", json!({}));
        assert!(!derived.controllable);
        assert_eq!(derived.readings[0].label, "State");
        assert_eq!(derived.readings[0].value, "active");
    }
    let unknown = caps("automation.rule", "on", json!({}));
    assert!(!unknown.controllable);
    assert!(unknown.supported_commands.is_empty());

    let button = caps("input_button.run", "unknown", json!({}));
    assert_eq!(button.command_names(), vec!["press"]);
    let select = caps(
        "input_select.mode",
        "eco",
        json!({"options":["eco", 7, "comfort"]}),
    );
    let option = &select.command("select_option").unwrap().params[0];
    assert_eq!(option.options, vec!["eco", "comfort"]);
    assert_eq!(option.default, Some(json!("eco")));
    assert!(!caps("input_select.empty", "none", json!({"options":[]})).controllable);

    let number = caps(
        "input_number.target",
        "12.5",
        json!({"min":1.0,"max":20.0,"step":0.5}),
    );
    let value = &number.command("set_value").unwrap().params[0];
    assert_eq!(
        (value.min, value.max, value.step),
        (Some(1.0), Some(20.0), Some(0.5))
    );
    assert_eq!(value.default, Some(json!(12.5)));
}

#[test]
fn switch_lock_and_cover_domains_derive_exact_feature_commands() {
    for domain in ["switch", "input_boolean", "fan", "siren", "humidifier"] {
        let derived = caps(&format!("{domain}.sample"), "off", json!({}));
        assert_eq!(
            derived.command_names(),
            vec!["turn_on", "turn_off", "toggle"]
        );
    }

    let lock = caps(
        "lock.front",
        "locked",
        json!({"supported_features": lock_features::OPEN}),
    );
    assert_eq!(lock.command_names(), vec!["lock", "unlock", "open"]);
    assert_eq!(
        caps("lock.basic", "unlocked", json!({"supported_features":0})).command_names(),
        vec!["lock", "unlock"]
    );

    let all_cover = cover_features::OPEN
        | cover_features::CLOSE
        | cover_features::STOP
        | cover_features::SET_POSITION
        | cover_features::SET_TILT_POSITION;
    let cover = caps(
        "cover.blind",
        "open",
        json!({"supported_features":all_cover}),
    );
    assert_eq!(
        cover.command_names(),
        vec![
            "open_cover",
            "close_cover",
            "stop_cover",
            "set_cover_position",
            "set_cover_tilt_position"
        ]
    );
    for command in ["set_cover_position", "set_cover_tilt_position"] {
        let spec = &cover.command(command).unwrap().params[0];
        assert_eq!(
            (spec.min, spec.max, spec.unit.as_deref()),
            (Some(0.0), Some(100.0), Some("%"))
        );
    }
    assert!(!caps("cover.none", "closed", json!({"supported_features":0})).controllable);
}

#[test]
fn media_player_derives_all_feature_commands_and_parameter_types() {
    let all = media_features::PAUSE
        | media_features::VOLUME_SET
        | media_features::VOLUME_MUTE
        | media_features::PREVIOUS_TRACK
        | media_features::NEXT_TRACK
        | media_features::TURN_ON
        | media_features::TURN_OFF
        | media_features::PLAY;
    let media = caps(
        "media_player.speaker",
        "playing",
        json!({"supported_features":all,"volume_level":0.4}),
    );
    for command in [
        "turn_on",
        "turn_off",
        "media_play",
        "media_pause",
        "media_next_track",
        "media_previous_track",
        "volume_set",
        "volume_mute",
    ] {
        assert!(media.command(command).is_some(), "missing {command}");
    }
    let volume = &media.command("volume_set").unwrap().params[0];
    assert_eq!(volume.kind, ParamKind::Number);
    assert_eq!(
        (volume.min, volume.max, volume.step),
        (Some(0.0), Some(1.0), Some(0.01))
    );
    assert_eq!(volume.default, Some(json!(0.4)));
    assert_eq!(
        media.command("volume_mute").unwrap().params[0].kind,
        ParamKind::Bool
    );

    CommandAuthorizer::validate_command_schema(
        &media,
        "volume_set",
        &Some(json!({"volume_level":1.0})),
    )
    .unwrap();
    assert!(schema_error(&media, "volume_set", Some(json!({"volume_level":1.1}))).contains("0–1"));
    CommandAuthorizer::validate_command_schema(
        &media,
        "volume_mute",
        &Some(json!({"is_volume_muted":true})),
    )
    .unwrap();
    assert!(
        schema_error(&media, "volume_mute", Some(json!({"is_volume_muted":1})))
            .contains("true or false")
    );
}

#[test]
fn climate_derives_full_features_fallback_bounds_readings_and_commands() {
    let all = climate_features::TARGET_TEMPERATURE
        | climate_features::TARGET_TEMPERATURE_RANGE
        | climate_features::TARGET_HUMIDITY
        | climate_features::FAN_MODE
        | climate_features::PRESET_MODE
        | climate_features::SWING_MODE
        | climate_features::TURN_OFF
        | climate_features::TURN_ON;
    let climate = capabilities::derive(
        &device(
            "climate.lab",
            "heat",
            json!({
                "supported_features":all,
                "hvac_modes":["off", "heat", 5],
                "preset_modes":["none", "eco"],
                "fan_modes":["auto", "high"],
                "swing_modes":["off", "vertical"],
                "current_temperature":21.0,
                "temperature":22.0,
                "target_temp_low":18.0,
                "target_temp_high":24.0,
                "current_humidity":48.0,
                "hvac_action":"heating",
                "preset_mode":"eco",
                "fan_mode":"auto"
            }),
        ),
        "°F",
    );
    for command in [
        "set_hvac_mode",
        "set_temperature",
        "set_preset_mode",
        "set_fan_mode",
        "set_swing_mode",
        "set_humidity",
        "turn_on",
        "turn_off",
    ] {
        assert!(climate.command(command).is_some(), "missing {command}");
    }
    let details = climate.climate.as_ref().unwrap();
    assert_eq!(
        (details.min_temp, details.max_temp, details.target_temp_step),
        (Some(45.0), Some(95.0), Some(1.0))
    );
    assert!(details.supports_target_temperature);
    assert!(details.supports_temperature_range);
    assert!(details.supports_target_humidity);
    assert_eq!(climate.readings.len(), 4);
    let temp_params = &climate.command("set_temperature").unwrap().params;
    assert!(temp_params
        .iter()
        .filter(|spec| spec.name.starts_with("target_temp"))
        .all(|spec| !spec.required));
    let humidity = &climate.command("set_humidity").unwrap().params[0];
    assert_eq!(
        (humidity.min, humidity.max, humidity.unit.as_deref()),
        (Some(30.0), Some(99.0), Some("%"))
    );

    let celsius = caps(
        "climate.simple",
        "cool",
        json!({"supported_features":climate_features::TARGET_TEMPERATURE}),
    );
    let details = celsius.climate.unwrap();
    assert_eq!(
        (details.min_temp, details.max_temp, details.target_temp_step),
        (Some(7.0), Some(35.0), Some(0.5))
    );
}

#[test]
fn light_derives_brightness_color_temperature_rgb_effect_and_defaults() {
    let light = caps(
        "light.office",
        "on",
        json!({
            "supported_features":light_features::EFFECT,
            "supported_color_modes":["brightness", "color_temp", "rgb", 4],
            "effect_list":["rainbow", "pulse"],
            "min_color_temp_kelvin":2200,
            "max_color_temp_kelvin":6500,
            "brightness":128
        }),
    );
    let details = light.light.as_ref().unwrap();
    assert!(details.supports_brightness);
    assert!(details.supports_color);
    assert!(details.supports_color_temp);
    assert_eq!(details.brightness, Some(128));
    let params = &light.command("turn_on").unwrap().params;
    assert_eq!(
        params
            .iter()
            .map(|spec| spec.name.as_str())
            .collect::<Vec<_>>(),
        vec!["brightness", "color_temp_kelvin", "rgb_color", "effect"]
    );
    let color_temp = params
        .iter()
        .find(|spec| spec.name == "color_temp_kelvin")
        .unwrap();
    assert_eq!(
        (color_temp.min, color_temp.max, color_temp.unit.as_deref()),
        (Some(2200.0), Some(6500.0), Some("K"))
    );
    assert_eq!(
        params
            .iter()
            .find(|spec| spec.name == "rgb_color")
            .unwrap()
            .kind,
        ParamKind::Rgb
    );
    assert_eq!(
        params
            .iter()
            .find(|spec| spec.name == "effect")
            .unwrap()
            .options,
        vec!["rainbow", "pulse"]
    );

    let fallback = caps(
        "light.fallback",
        "off",
        json!({"supported_color_modes":["color_temp"]}),
    );
    let spec = fallback
        .command("turn_on")
        .unwrap()
        .params
        .iter()
        .find(|spec| spec.name == "color_temp_kelvin")
        .unwrap();
    assert_eq!((spec.min, spec.max), (Some(2000.0), Some(6535.0)));
}

#[test]
fn schema_validation_rejects_readonly_unknown_nonobject_unknown_and_required_values() {
    let readonly = caps("sensor.temp", "20", json!({}));
    assert!(schema_error(&readonly, "turn_on", None).contains("read-only"));

    let switch = caps("switch.pump", "off", json!({}));
    assert!(schema_error(&switch, "explode", None).contains("not supported"));
    assert!(schema_error(&switch, "turn_on", Some(json!(7))).contains("JSON object"));
    assert!(
        schema_error(&switch, "turn_on", Some(json!({"extra":true}))).contains("accepted: none")
    );
    CommandAuthorizer::validate_command_schema(&switch, "turn_on", &None).unwrap();
    CommandAuthorizer::validate_command_schema(&switch, "turn_on", &Some(Value::Null)).unwrap();

    let required = custom_caps(
        "submit",
        vec![param(
            "name",
            "Name",
            ParamKind::Text,
            true,
            None,
            None,
            None,
            &[],
        )],
    );
    assert!(schema_error(&required, "submit", None).contains("requires a 'name'"));
    assert!(
        schema_error(&required, "submit", Some(json!({"name":null}))).contains("must not be null")
    );
    CommandAuthorizer::validate_command_schema(&required, "submit", &Some(json!({"name":"value"})))
        .unwrap();
    assert!(
        schema_error(&required, "submit", Some(json!({"name":false}))).contains("must be a string")
    );
}

#[test]
fn numeric_enum_boolean_rgb_and_optional_parameter_validation_cover_bound_shapes() {
    let numeric = custom_caps(
        "numbers",
        vec![
            param(
                "both",
                "Both",
                ParamKind::Number,
                true,
                Some(1.0),
                Some(3.0),
                Some("V"),
                &[],
            ),
            param(
                "minimum",
                "Minimum",
                ParamKind::Number,
                true,
                Some(5.0),
                None,
                None,
                &[],
            ),
            param(
                "maximum",
                "Maximum",
                ParamKind::Number,
                true,
                None,
                Some(9.0),
                None,
                &[],
            ),
            param(
                "free",
                "Free",
                ParamKind::Number,
                true,
                None,
                None,
                None,
                &[],
            ),
        ],
    );
    let valid = Some(json!({"both":2.0,"minimum":5.0,"maximum":9.0,"free":-100.0}));
    CommandAuthorizer::validate_command_schema(&numeric, "numbers", &valid).unwrap();
    assert!(schema_error(
        &numeric,
        "numbers",
        Some(json!({"both":0,"minimum":5,"maximum":9,"free":1}))
    )
    .contains("1–3 V"));
    assert!(schema_error(
        &numeric,
        "numbers",
        Some(json!({"both":2,"minimum":4,"maximum":9,"free":1}))
    )
    .contains("at least 5"));
    assert!(schema_error(
        &numeric,
        "numbers",
        Some(json!({"both":2,"minimum":5,"maximum":10,"free":1}))
    )
    .contains("at most 9"));
    assert!(schema_error(
        &numeric,
        "numbers",
        Some(json!({"both":"2","minimum":5,"maximum":9,"free":1}))
    )
    .contains("must be a number"));

    let kinds = custom_caps(
        "kinds",
        vec![
            param(
                "mode",
                "Mode",
                ParamKind::Enum,
                true,
                None,
                None,
                None,
                &["auto", "eco"],
            ),
            param(
                "enabled",
                "Enabled",
                ParamKind::Bool,
                true,
                None,
                None,
                None,
                &[],
            ),
            param(
                "color",
                "Color",
                ParamKind::Rgb,
                true,
                None,
                None,
                None,
                &[],
            ),
            param(
                "note",
                "Note",
                ParamKind::Text,
                false,
                None,
                None,
                None,
                &[],
            ),
        ],
    );
    CommandAuthorizer::validate_command_schema(
        &kinds,
        "kinds",
        &Some(json!({"mode":"eco","enabled":true,"color":[0,128,255],"note":null})),
    )
    .unwrap();
    assert!(schema_error(
        &kinds,
        "kinds",
        Some(json!({"mode":1,"enabled":true,"color":[0,0,0]}))
    )
    .contains("must be a string"));
    assert!(schema_error(
        &kinds,
        "kinds",
        Some(json!({"mode":"bad","enabled":true,"color":[0,0,0]}))
    )
    .contains("supported: auto, eco"));
    assert!(schema_error(
        &kinds,
        "kinds",
        Some(json!({"mode":"eco","enabled":"yes","color":[0,0,0]}))
    )
    .contains("true or false"));
    assert!(schema_error(
        &kinds,
        "kinds",
        Some(json!({"mode":"eco","enabled":true,"color":"red"}))
    )
    .contains("3-element array"));
    assert!(schema_error(
        &kinds,
        "kinds",
        Some(json!({"mode":"eco","enabled":true,"color":[0,1]}))
    )
    .contains("exactly 3"));
    for invalid in [
        json!([-1, 0, 0]),
        json!([256, 0, 0]),
        json!([1.5, 0, 0]),
        json!(["1", 0, 0]),
    ] {
        assert!(schema_error(
            &kinds,
            "kinds",
            Some(json!({"mode":"eco","enabled":true,"color":invalid}))
        )
        .contains("integers between 0 and 255"));
    }
}

#[test]
fn temperature_schema_enforces_single_or_pair_pair_order_and_optional_mode() {
    let all = climate_features::TARGET_TEMPERATURE | climate_features::TARGET_TEMPERATURE_RANGE;
    let climate = caps(
        "climate.range",
        "heat",
        json!({
            "supported_features":all,
            "hvac_modes":["heat","cool"],
            "min_temp":5.0,
            "max_temp":35.0
        }),
    );
    for valid in [
        json!({"temperature":20.0}),
        json!({"temperature":20.0,"hvac_mode":"cool"}),
        json!({"target_temp_low":18.0,"target_temp_high":23.0}),
    ] {
        CommandAuthorizer::validate_command_schema(&climate, "set_temperature", &Some(valid))
            .unwrap();
    }
    assert!(schema_error(&climate, "set_temperature", Some(json!({})))
        .contains("requires a temperature setpoint"));
    assert!(schema_error(
        &climate,
        "set_temperature",
        Some(json!({"temperature":20,"target_temp_low":18,"target_temp_high":23}))
    )
    .contains("either 'temperature'"));
    assert!(schema_error(
        &climate,
        "set_temperature",
        Some(json!({"target_temp_low":18}))
    )
    .contains("provided together"));
    assert!(schema_error(
        &climate,
        "set_temperature",
        Some(json!({"target_temp_low":25,"target_temp_high":20}))
    )
    .contains("must not exceed"));
}

#[test]
fn no_op_detection_is_domain_specific_and_allows_real_adjustments() {
    let climate = device("climate.office", "OFF", json!({}));
    assert!(matches!(
        CommandAuthorizer::check_no_op(&climate, "turn_off", &None),
        Err(CommandAuthError::NoOp(message)) if message == "Thermostat is already off"
    ));
    let climate = device("climate.office", "Cool", json!({}));
    assert!(matches!(
        CommandAuthorizer::check_no_op(
            &climate,
            "set_hvac_mode",
            &Some(json!({"hvac_mode":"COOL"}))
        ),
        Err(CommandAuthError::NoOp(message)) if message.contains("COOL")
    ));
    assert!(CommandAuthorizer::check_no_op(&climate, "set_temperature", &None).is_ok());
    assert!(CommandAuthorizer::check_no_op(&climate, "turn_on", &None).is_ok());

    for domain in [
        "light",
        "switch",
        "input_boolean",
        "fan",
        "siren",
        "humidifier",
    ] {
        let on = device(&format!("{domain}.sample"), "ON", json!({}));
        assert!(matches!(
            CommandAuthorizer::check_no_op(&on, "turn_on", &None),
            Err(CommandAuthError::NoOp(message)) if message == "Device is already on"
        ));
        assert!(
            CommandAuthorizer::check_no_op(&on, "turn_on", &Some(json!({"brightness":100})))
                .is_ok()
        );
        let off = device(&format!("{domain}.sample"), "off", json!({}));
        assert!(CommandAuthorizer::check_no_op(&off, "turn_off", &None).is_err());
    }

    let locked = device("lock.front", "locked", json!({}));
    assert!(CommandAuthorizer::check_no_op(&locked, "lock", &None).is_err());
    assert!(CommandAuthorizer::check_no_op(&locked, "unlock", &None).is_ok());
    let unlocked = device("lock.front", "unlocked", json!({}));
    assert!(CommandAuthorizer::check_no_op(&unlocked, "unlock", &None).is_err());
    assert!(CommandAuthorizer::check_no_op(&unlocked, "lock", &None).is_ok());

    for (entity, state, command) in [
        ("cover.blind", "open", "turn_on"),
        ("media_player.tv", "off", "turn_off"),
        ("custom.device", "on", "turn_on"),
    ] {
        assert!(
            CommandAuthorizer::check_no_op(&device(entity, state, json!({})), command, &None)
                .is_ok()
        );
    }
}

#[test]
fn capability_models_serialize_deserialize_and_lookup_missing_commands() {
    let derived = caps("light.simple", "off", json!({}));
    assert!(derived.command("missing").is_none());
    let encoded = serde_json::to_string(&derived).unwrap();
    let decoded: DeviceCapabilities = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.device_id, derived.device_id);
    assert_eq!(decoded.command_names(), derived.command_names());
    assert!(!decoded.light.unwrap().supports_brightness);

    for kind in [
        ParamKind::Number,
        ParamKind::Enum,
        ParamKind::Bool,
        ParamKind::Rgb,
        ParamKind::Text,
    ] {
        let encoded = serde_json::to_string(&kind).unwrap();
        assert_eq!(serde_json::from_str::<ParamKind>(&encoded).unwrap(), kind);
    }
    for health in [
        DeviceHealth::Online,
        DeviceHealth::Offline,
        DeviceHealth::Unknown,
        DeviceHealth::AuthenticationError,
        DeviceHealth::IntegrationError,
        DeviceHealth::BatteryLow,
    ] {
        let encoded = serde_json::to_string(&health).unwrap();
        assert_eq!(
            serde_json::from_str::<DeviceHealth>(&encoded).unwrap(),
            health
        );
    }
}
