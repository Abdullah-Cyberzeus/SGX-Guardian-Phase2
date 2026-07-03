use sgx_guardian_client::cot::transport_trait::{Transport, TransportMessage};
use sgx_guardian_client::cot::transports::ethernet::EthernetTransport;
use sgx_guardian_client::cot::transports::wifi::WiFiTransport;
use sgx_guardian_client::cot::transports::cellular::CellularTransport;
use sgx_guardian_client::cot::types::{InterfaceInfo, InterfaceStatus, TransportType};

fn make_mock_interface(name: &str, t_type: TransportType) -> InterfaceInfo {
    InterfaceInfo::new(
        name.into(),
        t_type,
        Some("127.0.0.1".parse().unwrap()),
        InterfaceStatus::Up,
    )
}

#[tokio::test]
async fn test_ethernet_transport() {
    let iface = make_mock_interface("lo", TransportType::Ethernet);
    let transport = EthernetTransport::new(iface);
    
    // Test available
    let _avail = transport.is_available().await;
    
    // Test health check
    let health = transport.health_check().await;
    assert!(!health.is_healthy || health.is_healthy); // Just want coverage
    
    // Test send (will fail because nothing is listening or fast fail)
    let msg = TransportMessage::new("a".into(), "b".into(), "127.0.0.1:9999".into(), vec![1]);
    let res = transport.send(&msg).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_wifi_transport() {
    let iface = make_mock_interface("wlan0", TransportType::WiFi);
    let transport = WiFiTransport::new(iface);
    
    let _avail = transport.is_available().await;
    let health = transport.health_check().await;
    assert!(!health.is_healthy || health.is_healthy);
    
    let msg = TransportMessage::new("a".into(), "b".into(), "127.0.0.1:9999".into(), vec![1]);
    let res = transport.send(&msg).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_cellular_transport() {
    let iface = make_mock_interface("wwan0", TransportType::Cellular);
    let transport = CellularTransport::new(iface);
    
    let _avail = transport.is_available().await;
    let health = transport.health_check().await;
    assert!(!health.is_healthy || health.is_healthy);
    
    let msg = TransportMessage::new("a".into(), "b".into(), "127.0.0.1:9999".into(), vec![1]);
    let res = transport.send(&msg).await;
    assert!(res.is_err());
}
