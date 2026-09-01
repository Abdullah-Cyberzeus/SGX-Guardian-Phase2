use sgx_guardian_client::device::manager::DeviceManager;
use sgx_guardian_client::device::registry::DeviceRegistry;
use sgx_guardian_client::device::state::{is_supported_domain, Device, DeviceHealth};
use sgx_guardian_client::homeassistant::events::EventBus;
use sgx_guardian_client::homeassistant::rest::HaRestClient;
use sgx_guardian_client::homeassistant::HomeAssistantConfig;
use std::sync::Arc;

fn registry() -> Arc<DeviceRegistry> {
    let file = tempfile::NamedTempFile::new().unwrap();
    Arc::new(DeviceRegistry::new(file.path().to_str().unwrap()))
}

fn manager() -> Arc<DeviceManager> {
    DeviceManager::new(
        registry(),
        Arc::new(HaRestClient::new(HomeAssistantConfig { url: "http://127.0.0.1:9".into(), token: "token".into() })),
        EventBus::new(),
        None,
    )
}

fn device(id: &str, entity: &str) -> Device {
    Device {
        id: id.into(),
        ha_entity_id: entity.into(),
        vendor: "Vendor".into(),
        device_type: "light".into(),
        room: None,
        friendly_name: "Light".into(),
        current_state: "off".into(),
        health_status: DeviceHealth::Online,
        last_seen: chrono::Utc::now(),
        attributes: serde_json::Map::new(),
    }
}

#[test]
fn manager_new_returns_shared_arc() {
    assert_eq!(Arc::strong_count(&manager()), 1);
}

#[tokio::test]
async fn get_registry_returns_same_registry() {
    let reg = registry();
    let manager = DeviceManager::new(
        reg.clone(),
        Arc::new(HaRestClient::new(HomeAssistantConfig { url: "http://127.0.0.1:9".into(), token: "token".into() })),
        EventBus::new(),
        None,
    );
    assert!(Arc::ptr_eq(manager.get_registry(), &reg));
}

#[tokio::test]
async fn send_command_missing_device_errors_before_rest_call() {
    let err = manager().send_command("light.missing", "light", "turn_on", None).await.unwrap_err();
    assert!(err.contains("not found"));
}

#[tokio::test]
async fn refresh_device_attributes_missing_device_returns_none() {
    assert!(manager().refresh_device_attributes("light.missing").await.unwrap().is_none());
}

#[tokio::test]
async fn registry_visible_through_manager_after_insert() {
    let manager = manager();
    manager.get_registry().upsert_device(device("id", "light.a")).await.unwrap();
    assert!(manager.get_registry().get_device_by_entity_id("light.a").await.is_some());
}

#[tokio::test]
async fn set_integration_manager_accepts_manager() {
    let dir = tempfile::tempdir().unwrap();
    let old = std::env::var_os("SGX_DATA_DIR");
    std::env::set_var("SGX_DATA_DIR", dir.path());
    let integration = sgx_guardian_client::integration::manager::IntegrationManager::new("i.json");
    manager().set_integration_manager(integration).await;
    if let Some(value) = old {
        std::env::set_var("SGX_DATA_DIR", value);
    } else {
        std::env::remove_var("SGX_DATA_DIR");
    }
}

#[tokio::test]
async fn registry_path_is_temp_file() {
    let manager = manager();
    assert!(manager.get_registry().path().contains("/tmp"));
}

macro_rules! supported_domain_tests {
    ($($name:ident => $entity:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            assert_eq!(is_supported_domain($entity), $expected);
        }
    )+};
}

supported_domain_tests! {
    supports_light => "light.kitchen", true,
    supports_switch => "switch.outlet", true,
    supports_climate => "climate.hall", true,
    supports_lock => "lock.front", true,
    supports_sensor => "sensor.temperature", true,
    supports_binary_sensor => "binary_sensor.motion", true,
    supports_camera => "camera.door", true,
    supports_media_player => "media_player.tv", true,
    supports_cover => "cover.garage", true,
    supports_input_boolean => "input_boolean.flag", true,
    supports_input_button => "input_button.push", true,
    supports_input_select => "input_select.mode", true,
    supports_input_number => "input_number.level", true,
    rejects_sun => "sun.sun", false,
    rejects_sensor_time => "sensor.time", false,
    rejects_sensor_date => "sensor.date", false,
    rejects_sensor_hacs => "sensor.hacs", false,
    rejects_zone => "zone.home", false,
    rejects_automation => "automation.rule", false,
    rejects_empty => "", false,
}
