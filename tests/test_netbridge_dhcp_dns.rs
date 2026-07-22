use sgx_guardian_client::netbridge::dhcp_dns::DnsmasqOrchestrator;
use sgx_guardian_client::netbridge::types::DnsmasqSettings;

#[test]
fn test_dnsmasq_orchestrator_creation() {
    let settings = DnsmasqSettings {
        interface: "uap1".to_string(),
        ..Default::default()
    };
    let orch = DnsmasqOrchestrator::new(settings);
    assert_eq!(orch.settings.interface, "uap1");
    assert!(orch.runner.is_none());
}

#[tokio::test]
async fn test_dnsmasq_stop_when_not_running() {
    let settings = DnsmasqSettings::default();
    let mut orch = DnsmasqOrchestrator::new(settings);

    let res = orch.stop().await;
    assert!(res.is_ok());
}
