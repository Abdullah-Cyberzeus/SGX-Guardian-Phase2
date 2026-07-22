use sgx_guardian_client::netbridge::types::WifiClientSettings;
use sgx_guardian_client::netbridge::wifi_client::WifiClientOrchestrator;

#[test]
fn test_wifi_client_orchestrator_creation() {
    let settings = WifiClientSettings {
        interface: "wlan1".to_string(),
        ..Default::default()
    };
    let orch = WifiClientOrchestrator::new(settings);
    assert_eq!(orch.settings.interface, "wlan1");
    assert!(orch.runner.is_none());
}

#[test]
fn test_is_connected_initially_false() {
    let settings = WifiClientSettings {
        interface: "wlan_non_existent".to_string(),
        ..Default::default()
    };
    let orch = WifiClientOrchestrator::new(settings);

    // This will attempt to run wpa_cli on a non-existent interface, which will fail or return not COMPLETED.
    assert!(!orch.is_connected());
}

#[tokio::test]
async fn test_disconnect_when_not_connected() {
    let settings = WifiClientSettings::default();
    let mut orch = WifiClientOrchestrator::new(settings);

    // Should not crash
    let res = orch.disconnect().await;
    assert!(res.is_ok());
}
