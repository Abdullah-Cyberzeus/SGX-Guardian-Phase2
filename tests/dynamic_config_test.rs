use sgx_guardian_client::dynamic_config::*;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_config_ip_operations() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "node_id: \"test-node\"").unwrap();
    writeln!(file, "ip: \"127.0.0.1\"").unwrap();
    writeln!(file, "port: 5000").unwrap();

    let path = file.path().to_str().unwrap().to_string();

    // Test update_config_ip_if_changed
    let (old_ip, new_ip, changed) = update_config_ip_if_changed(&path, "192.168.1.100").unwrap();
    assert_eq!(old_ip, "127.0.0.1");
    assert_eq!(new_ip, "192.168.1.100");
    assert!(changed);

    // Unchanged test
    let (_, _, changed2) = update_config_ip_if_changed(&path, "192.168.1.100").unwrap();
    assert!(!changed2);

    // Test sanitize (valid IP should not change)
    sanitize_config_ip_if_invalid(&path).unwrap();

    // Make invalid
    let _ = update_config_ip_if_changed(&path, "invalid_ip");
    sanitize_config_ip_if_invalid(&path).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("ip: \"0.0.0.0\""));
}

#[test]
fn test_update_peer_config_invalid() {
    // Invalid node ID should be rejected
    update_peer_config("invalid/id", "host", "1.1.1.1", 80, "pubkey");
}

#[test]
fn test_broadcast_no_routable() {
    let config = NodeConfigBroadcast {
        node_id: "test".to_string(),
        hostname: "host".to_string(),
        ip: "1.1.1.1".to_string(),
        port: 80,
        public_key: "pubkey".to_string(),
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Should skip because IPs are not routable
        broadcast_own_config_to_peers(&config, &[String::from("127.0.0.1")]).await;
    });
}
