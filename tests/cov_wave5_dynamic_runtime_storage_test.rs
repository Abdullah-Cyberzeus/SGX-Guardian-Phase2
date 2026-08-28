//! Unit coverage for dynamic YAML configuration, runtime configuration/state,
//! encrypted password persistence, and atomic file storage.

use std::sync::{Arc, Mutex, OnceLock};

use sgx_guardian_client::dynamic_config::{
    broadcast_own_config_to_peers, extract_ip_from_yaml, is_routable_ip,
    sanitize_config_ip_if_invalid, update_config_ip_if_changed, NodeConfigBroadcast,
};
use sgx_guardian_client::runtime::config_store::ConfigStore;
use sgx_guardian_client::runtime::crypto::{
    decrypt_password, encrypt_password, validate_hotspot_password,
};
use sgx_guardian_client::runtime::errors::RuntimeError;
use sgx_guardian_client::runtime::event_bus::{EventBus, RuntimeEvent};
use sgx_guardian_client::runtime::models::{
    GuardianConfig, HotspotConfig, RuntimeFlags, RuntimeMode, SavedWifi, UplinkConfig,
};
use sgx_guardian_client::runtime::state::{StateMetadata, StateTransition, SystemState};
use sgx_guardian_client::runtime::state_machine::StateMachine;
use sgx_guardian_client::storage::file_lock::SecureFileStore;
use tempfile::TempDir;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct EnvRestore {
    values: Vec<(&'static str, Option<String>)>,
}

impl EnvRestore {
    fn set(values: &[(&'static str, String)]) -> Self {
        let previous = values
            .iter()
            .map(|(key, _)| (*key, std::env::var(key).ok()))
            .collect();
        for (key, value) in values {
            std::env::set_var(key, value);
        }
        Self { values: previous }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in &self.values {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn runtime_config() -> GuardianConfig {
    GuardianConfig {
        mode: RuntimeMode::DualWifi,
        flags: RuntimeFlags {
            restore_on_boot: true,
        },
        hotspot: HotspotConfig {
            interface: "wlan0".into(),
            ssid: "Guardian Lab".into(),
            password: "Strong!Pass123".into(),
            channel: 6,
            band: Some("2.4GHz".into()),
            client_isolation: true,
        },
        uplink: UplinkConfig {
            interface: "wlan1".into(),
            networks: vec![
                SavedWifi {
                    ssid: "Home".into(),
                    bssid: Some("00:11:22:33:44:55".into()),
                    password: Some("Uplink!Pass123".into()),
                },
                SavedWifi {
                    ssid: "Open".into(),
                    bssid: None,
                    password: None,
                },
                SavedWifi {
                    ssid: "Empty password".into(),
                    bssid: None,
                    password: Some(String::new()),
                },
            ],
        },
    }
}

#[test]
fn dynamic_yaml_extracts_quoted_indented_and_missing_ips() {
    assert_eq!(
        extract_ip_from_yaml("ip: 192.168.1.2\n"),
        Some("192.168.1.2".into())
    );
    assert_eq!(
        extract_ip_from_yaml("  ip: \"10.0.0.7\"\n"),
        Some("10.0.0.7".into())
    );
    assert_eq!(
        extract_ip_from_yaml("ip: '172.18.0.8'\n"),
        Some("172.18.0.8".into())
    );
    assert_eq!(extract_ip_from_yaml("node_id: a\nip:    \n"), None);
    assert_eq!(extract_ip_from_yaml("node_id: a\n"), None);
    assert_eq!(extract_ip_from_yaml("topic: value\n"), None);
}

#[test]
fn dynamic_yaml_update_preserves_shape_newline_and_reports_missing_field() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("node.yaml");
    std::fs::write(
        &path,
        "node_id: node-a\nnetwork:\n  ip: '192.168.1.2'\n  ip: second-is-untouched\nport: 5000\n",
    )
    .unwrap();

    let (old, new, changed) =
        update_config_ip_if_changed(path.to_str().unwrap(), "10.0.0.9").unwrap();
    assert_eq!(old, "192.168.1.2");
    assert_eq!(new, "10.0.0.9");
    assert!(changed);
    let updated = std::fs::read_to_string(&path).unwrap();
    assert!(updated.contains("  ip: \"10.0.0.9\""));
    assert!(updated.contains("  ip: second-is-untouched"));
    assert!(updated.ends_with('\n'));

    let (_, _, changed) = update_config_ip_if_changed(path.to_str().unwrap(), "10.0.0.9").unwrap();
    assert!(!changed);

    let no_newline = temp.path().join("no-newline.yaml");
    std::fs::write(&no_newline, "ip: 1.1.1.1").unwrap();
    update_config_ip_if_changed(no_newline.to_str().unwrap(), "8.8.8.8").unwrap();
    assert_eq!(
        std::fs::read_to_string(no_newline).unwrap(),
        "ip: \"8.8.8.8\""
    );

    let missing = temp.path().join("missing-ip.yaml");
    std::fs::write(&missing, "node_id: node-a\n").unwrap();
    let error = update_config_ip_if_changed(missing.to_str().unwrap(), "10.0.0.1")
        .unwrap_err()
        .to_string();
    assert!(error.contains("'ip:' field not found"));
    assert!(update_config_ip_if_changed("/definitely/missing/config.yaml", "10.0.0.1").is_err());
}

#[test]
fn dynamic_yaml_sanitizer_resets_invalid_and_preserves_valid_values() {
    let temp = TempDir::new().unwrap();
    let invalid = temp.path().join("invalid.yaml");
    std::fs::write(&invalid, "node_id: n\nip: not-an-ip\n").unwrap();
    sanitize_config_ip_if_invalid(invalid.to_str().unwrap()).unwrap();
    assert_eq!(
        extract_ip_from_yaml(&std::fs::read_to_string(&invalid).unwrap()).as_deref(),
        Some("0.0.0.0")
    );

    let valid = temp.path().join("valid.yaml");
    let original = "node_id: n\nip: 192.168.1.9\n";
    std::fs::write(&valid, original).unwrap();
    sanitize_config_ip_if_invalid(valid.to_str().unwrap()).unwrap();
    assert_eq!(std::fs::read_to_string(valid).unwrap(), original);

    let absent = temp.path().join("absent-ip.yaml");
    std::fs::write(&absent, "node_id: n\n").unwrap();
    sanitize_config_ip_if_invalid(absent.to_str().unwrap()).unwrap();
    assert_eq!(std::fs::read_to_string(absent).unwrap(), "node_id: n\n");
    assert!(sanitize_config_ip_if_invalid("/definitely/missing/node.yaml").is_err());
}

#[test]
fn routable_ip_filter_and_broadcast_payload_serde_cover_edge_cases() {
    for valid in [
        "10.0.0.1",
        "172.16.0.1",
        "172.18.0.1",
        "192.168.1.1",
        "224.0.0.1",
    ] {
        assert!(
            is_routable_ip(valid),
            "expected current implementation to accept {valid}"
        );
    }
    for invalid in [
        "",
        "0.0.0.0",
        "127.0.0.1",
        "127.255.255.255",
        "169.254.3.4",
        "172.17.0.2",
        "::1",
        "hostname",
    ] {
        assert!(!is_routable_ip(invalid), "expected rejection for {invalid}");
    }

    let payload = NodeConfigBroadcast {
        node_id: "node-a".into(),
        hostname: "guardian-a".into(),
        ip: "192.168.1.10".into(),
        port: 50070,
        public_key: "pubkey".into(),
    };
    let json = serde_json::to_string(&payload).unwrap();
    let decoded: NodeConfigBroadcast = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.node_id, payload.node_id);
    assert_eq!(decoded.port, payload.port);
}

#[tokio::test]
async fn broadcast_returns_immediately_when_every_peer_is_filtered() {
    let payload = NodeConfigBroadcast {
        node_id: "node-a".into(),
        hostname: "guardian-a".into(),
        ip: "192.168.1.10".into(),
        port: 50070,
        public_key: "pubkey".into(),
    };
    broadcast_own_config_to_peers(
        &payload,
        &[
            "".into(),
            "0.0.0.0".into(),
            "127.0.0.1".into(),
            "invalid".into(),
        ],
    )
    .await;
}

#[test]
fn runtime_password_crypto_round_trips_randomizes_and_validates_inputs() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let temp = TempDir::new().unwrap();
    let key_path = temp.path().join("keys/runtime.key");
    let _restore =
        EnvRestore::set(&[("GUARDIAN_KEY_FILE", key_path.to_string_lossy().into_owned())]);

    assert_eq!(
        encrypt_password("").unwrap_err(),
        "Cannot encrypt empty password"
    );
    assert_eq!(
        decrypt_password("").unwrap_err(),
        "Cannot decrypt empty input"
    );
    assert_eq!(decrypt_password("not base64").unwrap_err(), "Base64 error");
    assert_eq!(decrypt_password("AQID").unwrap_err(), "Too short");

    let first = encrypt_password("Correct!Horse123").unwrap();
    let second = encrypt_password("Correct!Horse123").unwrap();
    assert_ne!(first, second);
    assert_eq!(decrypt_password(&first).unwrap(), "Correct!Horse123");
    assert_eq!(std::fs::read(&key_path).unwrap().len(), 32);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let mut tampered =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &first).unwrap();
    *tampered.last_mut().unwrap() ^= 0xff;
    let tampered = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, tampered);
    assert_eq!(decrypt_password(&tampered).unwrap_err(), "Decryption error");

    assert!(validate_hotspot_password("short!").is_err());
    assert!(validate_hotspot_password("abcdefgh").is_err());
    assert!(validate_hotspot_password("Unique!Pass123").is_ok());
}

#[test]
fn runtime_config_store_defaults_encrypts_and_round_trips_all_password_forms() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("config/wifi.json");
    let key_path = temp.path().join("keys/wifi.key");
    let _restore = EnvRestore::set(&[
        (
            "GUARDIAN_CONFIG_FILE",
            config_path.to_string_lossy().into_owned(),
        ),
        ("GUARDIAN_KEY_FILE", key_path.to_string_lossy().into_owned()),
    ]);

    let default = ConfigStore::load().unwrap();
    assert_eq!(default.mode, RuntimeMode::Off);
    assert!(default.hotspot.password.is_empty());
    assert!(default.uplink.networks.is_empty());

    let expected = runtime_config();
    ConfigStore::save(&expected).unwrap();
    let raw = std::fs::read_to_string(&config_path).unwrap();
    assert!(!raw.contains("Strong!Pass123"));
    assert!(!raw.contains("Uplink!Pass123"));
    assert!(raw.contains("Empty password"));

    let loaded = ConfigStore::load().unwrap();
    assert_eq!(loaded.mode, RuntimeMode::DualWifi);
    assert_eq!(loaded.hotspot.password, expected.hotspot.password);
    assert_eq!(
        loaded.uplink.networks[0].password,
        expected.uplink.networks[0].password
    );
    assert_eq!(loaded.uplink.networks[1].password, None);
    assert_eq!(loaded.uplink.networks[2].password.as_deref(), Some(""));

    std::fs::write(&config_path, "{not json}").unwrap();
    assert!(matches!(
        ConfigStore::load(),
        Err(RuntimeError::InvalidConfig(_))
    ));
}

#[test]
fn runtime_config_store_rejects_ciphertext_after_key_replacement() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("wifi.json");
    let key_path = temp.path().join("wifi.key");
    let _restore = EnvRestore::set(&[
        (
            "GUARDIAN_CONFIG_FILE",
            config_path.to_string_lossy().into_owned(),
        ),
        ("GUARDIAN_KEY_FILE", key_path.to_string_lossy().into_owned()),
    ]);

    ConfigStore::save(&runtime_config()).unwrap();
    std::fs::write(&key_path, [7u8; 31]).unwrap();
    let error = ConfigStore::load().unwrap_err().to_string();
    assert!(error.contains("Failed to decrypt hotspot password"));
}

#[tokio::test]
async fn runtime_state_machine_publishes_transitions_errors_and_reset() {
    let bus = Arc::new(EventBus::new());
    let mut receiver = bus.subscribe();
    let machine = StateMachine::new(bus);
    let initial = machine.get_status().await;
    assert_eq!(initial.state, SystemState::Idle);
    assert!(initial.metadata.message.is_none());

    for state in [
        SystemState::ApplyingChange,
        SystemState::HotspotStarting,
        SystemState::HotspotActive,
        SystemState::ClientConnecting,
        SystemState::ClientConnected,
        SystemState::DualStarting,
        SystemState::DualActive,
    ] {
        machine.transition_to(state).await;
        assert_eq!(machine.get_status().await.state, state);
        match receiver.recv().await.unwrap() {
            RuntimeEvent::StateChanged(received) => assert_eq!(received, state),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    machine
        .set_error_state("uplink failed".into(), Some("UPLINK".into()))
        .await;
    let status = machine.get_status().await;
    assert_eq!(status.state, SystemState::Error);
    assert_eq!(status.metadata.message.as_deref(), Some("uplink failed"));
    assert_eq!(status.metadata.error_code.as_deref(), Some("UPLINK"));
    assert!(
        matches!(receiver.recv().await.unwrap(), RuntimeEvent::Error(message) if message == "uplink failed")
    );

    machine.reset_to_idle().await;
    assert_eq!(machine.get_status().await.state, SystemState::Idle);
    assert!(matches!(
        receiver.recv().await.unwrap(),
        RuntimeEvent::StateChanged(SystemState::Idle)
    ));
}

#[test]
fn runtime_models_events_errors_and_defaults_serialize_all_variants() {
    let config = GuardianConfig::default();
    assert_eq!(config.mode, RuntimeMode::Off);
    assert!(!config.flags.restore_on_boot);
    assert!(!config.hotspot.client_isolation);

    for mode in [
        RuntimeMode::Off,
        RuntimeMode::HotspotOnly,
        RuntimeMode::ClientOnly,
        RuntimeMode::DualWifi,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(serde_json::from_str::<RuntimeMode>(&json).unwrap(), mode);
    }
    for state in [
        SystemState::Idle,
        SystemState::ApplyingChange,
        SystemState::HotspotStarting,
        SystemState::HotspotActive,
        SystemState::ClientConnecting,
        SystemState::ClientConnected,
        SystemState::DualStarting,
        SystemState::DualActive,
        SystemState::Error,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<SystemState>(&json).unwrap(), state);
    }

    let transition = StateTransition {
        from: SystemState::Idle,
        to: SystemState::ApplyingChange,
    };
    let decoded: StateTransition =
        serde_json::from_str(&serde_json::to_string(&transition).unwrap()).unwrap();
    assert_eq!(decoded.from, SystemState::Idle);
    assert_eq!(decoded.to, SystemState::ApplyingChange);
    let metadata = StateMetadata {
        message: Some("message".into()),
        error_code: Some("CODE".into()),
    };
    assert!(serde_json::to_string(&metadata).unwrap().contains("CODE"));

    assert_eq!(
        RuntimeError::InvalidConfig("bad".into()).to_string(),
        "Invalid configuration: bad"
    );
    assert_eq!(
        RuntimeError::StateMachineError("bad".into()).to_string(),
        "State machine error: bad"
    );
    assert_eq!(
        RuntimeError::Internal("bad".into()).to_string(),
        "Internal error: bad"
    );

    let events = [
        RuntimeEvent::StateChanged(SystemState::Idle),
        RuntimeEvent::UplinkDisconnected,
        RuntimeEvent::HotspotStarted,
        RuntimeEvent::Error("bad".into()),
    ];
    for event in events {
        let json = serde_json::to_string(&event).unwrap();
        let _: RuntimeEvent = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn secure_file_store_reads_missing_updates_existing_and_preserves_on_modifier_error() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("state.json");
    let store = SecureFileStore::new(&path);
    assert_eq!(store.read().unwrap(), None);

    store
        .write_atomic(|old| {
            assert!(old.is_none());
            Ok::<_, std::io::Error>(b"first".to_vec())
        })
        .unwrap();
    assert_eq!(store.read().unwrap().as_deref(), Some(b"first".as_slice()));
    assert!(path.with_extension("lock").exists());
    assert!(!path.with_extension("tmp").exists());

    store
        .write_atomic(|old| {
            assert_eq!(old.as_deref(), Some(b"first".as_slice()));
            Ok::<_, std::io::Error>(b"second".to_vec())
        })
        .unwrap();
    assert_eq!(store.read().unwrap().as_deref(), Some(b"second".as_slice()));

    let result =
        store.write_atomic(|_| Err::<Vec<u8>, _>(std::io::Error::other("modifier rejected")));
    assert!(result.is_err());
    assert_eq!(store.read().unwrap().as_deref(), Some(b"second".as_slice()));
}
