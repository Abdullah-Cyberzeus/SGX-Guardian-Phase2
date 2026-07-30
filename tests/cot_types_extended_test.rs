// tests/cot_types_extended_test.rs
// Integration tests covering uncovered branches in src/cot/types.rs

use sgx_guardian_client::cot::types::{
    CotError, InterfaceInfo, InterfaceStatus, PeerEndpoint, TransportPriority, TransportType,
};

// ── TransportType ────────────────────────────────────────────────────────────

#[test]
fn test_transport_type_display_all() {
    assert_eq!(format!("{}", TransportType::Ethernet), "Ethernet");
    assert_eq!(format!("{}", TransportType::WiFi), "WiFi");
    assert_eq!(format!("{}", TransportType::Bluetooth), "Bluetooth");
    assert_eq!(format!("{}", TransportType::Cellular), "Cellular");
    assert_eq!(format!("{}", TransportType::Satellite), "Satellite");
}

#[test]
fn test_transport_priority_ordering() {
    // Cellular is highest priority (lowest number)
    assert!(
        TransportType::Cellular.default_priority() < TransportType::Ethernet.default_priority()
    );
    assert!(TransportType::Ethernet.default_priority() < TransportType::WiFi.default_priority());
    assert!(TransportType::WiFi.default_priority() < TransportType::Bluetooth.default_priority());
    assert!(
        TransportType::Bluetooth.default_priority() < TransportType::Satellite.default_priority()
    );
}

// ── TransportPriority ────────────────────────────────────────────────────────

#[test]
fn test_transport_priority_default_is_lowest() {
    let default = TransportPriority::default();
    let high = TransportPriority::new(0);
    assert!(high < default);
}

#[test]
fn test_transport_priority_new_and_ordering() {
    let p10 = TransportPriority::new(10);
    let p20 = TransportPriority::new(20);
    assert!(p10 < p20);
    assert_eq!(p10, TransportPriority::new(10));
}

// ── InterfaceStatus ──────────────────────────────────────────────────────────

#[test]
fn test_interface_status_display_all() {
    assert_eq!(format!("{}", InterfaceStatus::Up), "UP");
    assert_eq!(format!("{}", InterfaceStatus::Down), "DOWN");
    assert_eq!(format!("{}", InterfaceStatus::Unknown), "UNKNOWN");
}

// ── InterfaceInfo::is_usable ─────────────────────────────────────────────────

#[test]
fn test_interface_info_up_with_ip_is_usable() {
    let iface = InterfaceInfo::new(
        "eth0".into(),
        TransportType::Ethernet,
        Some("10.0.0.1".parse().unwrap()),
        InterfaceStatus::Up,
    );
    assert!(iface.is_usable());
}

#[test]
fn test_interface_info_down_not_usable() {
    let iface = InterfaceInfo::new(
        "eth0".into(),
        TransportType::Ethernet,
        Some("10.0.0.1".parse().unwrap()),
        InterfaceStatus::Down,
    );
    assert!(!iface.is_usable());
}

#[test]
fn test_interface_info_up_no_ip_not_usable() {
    let iface = InterfaceInfo::new(
        "eth0".into(),
        TransportType::Ethernet,
        None,
        InterfaceStatus::Up,
    );
    assert!(!iface.is_usable());
}

#[test]
fn test_interface_info_unknown_status_not_usable() {
    let iface = InterfaceInfo::new(
        "eth0".into(),
        TransportType::Ethernet,
        Some("10.0.0.1".parse().unwrap()),
        InterfaceStatus::Unknown,
    );
    assert!(!iface.is_usable());
}

// ── PeerEndpoint ─────────────────────────────────────────────────────────────

#[test]
fn test_peer_endpoint_new_fields() {
    let ep = PeerEndpoint::new(
        "device-abc".into(),
        TransportType::Bluetooth,
        "AA:BB:CC:DD:EE:FF".into(),
    );
    assert_eq!(ep.device_id, "device-abc");
    assert_eq!(ep.transport_type, TransportType::Bluetooth);
    assert_eq!(ep.address, "AA:BB:CC:DD:EE:FF");
    assert!(!ep.reachable);
    assert!(ep.last_seen.is_none());
}

// ── CotError Display ──────────────────────────────────────────────────────────

#[test]
fn test_cot_error_display_all_variants() {
    let cases: &[(CotError, &str)] = &[
        (CotError::NoTransportAvailable, "no usable transport"),
        (
            CotError::TransportNotRegistered(TransportType::WiFi),
            "WiFi not registered",
        ),
        (CotError::PeerNotFound("abc".into()), "peer not found"),
        (
            CotError::SessionInvalid("expired".into()),
            "session invalid",
        ),
        (
            CotError::TrustVerificationFailed("sig fail".into()),
            "trust verification failed",
        ),
        (
            CotError::MembershipDenied("already member".into()),
            "membership denied",
        ),
        (
            CotError::InterfaceDetectionFailed("no iface".into()),
            "interface detection failed",
        ),
        (CotError::TransportError("io err".into()), "transport error"),
        (CotError::ConfigError("bad conf".into()), "config error"),
        (CotError::IdentityError("bad key".into()), "identity error"),
    ];

    for (err, expected_substr) in cases {
        let displayed = format!("{}", err);
        assert!(
            displayed.contains(expected_substr),
            "Expected '{}' in '{}' for {:?}",
            expected_substr,
            displayed,
            err
        );
    }
}

#[test]
fn test_cot_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CotError::NoTransportAvailable);
    assert!(!err.to_string().is_empty());
}
