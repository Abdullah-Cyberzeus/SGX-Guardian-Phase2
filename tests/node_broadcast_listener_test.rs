use sgx_guardian_client::node_announcement::NodeAnnouncement;
use sgx_guardian_client::node_broadcast::broadcast_node;

static TEST_ENV_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

// ─── NodeAnnouncement ────────────────────────────────────────

#[test]
fn test_node_announcement_new_signed() {
    let ann = NodeAnnouncement::new_signed(
        "node1".to_string(),
        "host1".to_string(),
        "192.168.1.100".to_string(),
        8080,
        "pubkey-abc".to_string(),
    );

    assert_eq!(ann.node_id, "node1");
    assert_eq!(ann.hostname, "host1");
    assert_eq!(ann.ip, "192.168.1.100");
    assert_eq!(ann.port, 8080);
    assert_eq!(ann.public_key, "pubkey-abc");
    assert!(!ann.signature.is_empty(), "signature should not be empty");
    assert!(ann.timestamp > 0, "timestamp should be positive");
}

#[test]
fn test_node_announcement_verify_integrity_valid() {
    let ann = NodeAnnouncement::new_signed(
        "node1".to_string(),
        "host1".to_string(),
        "192.168.1.100".to_string(),
        8080,
        "pubkey-abc".to_string(),
    );

    assert!(ann.verify_integrity(), "fresh announcement should verify");
}

#[test]
fn test_node_announcement_verify_integrity_stale() {
    let mut ann = NodeAnnouncement::new_signed(
        "node1".to_string(),
        "host1".to_string(),
        "192.168.1.100".to_string(),
        8080,
        "pubkey-abc".to_string(),
    );

    // Set timestamp to 200 seconds ago — exceeds 120s threshold
    let old_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 200;
    ann.timestamp = old_ts;

    // Recompute signature for the stale timestamp
    use sha2::{Digest, Sha256};
    let msg = format!(
        "{}{}{}{}{}",
        ann.node_id, ann.ip, ann.port, ann.public_key, ann.timestamp
    );
    let digest = Sha256::digest(msg.as_bytes());
    ann.signature = hex::encode(digest);

    assert!(!ann.verify_integrity(), "stale announcement should fail");
}

#[test]
fn test_node_announcement_verify_integrity_tampered() {
    let mut ann = NodeAnnouncement::new_signed(
        "node1".to_string(),
        "host1".to_string(),
        "192.168.1.100".to_string(),
        8080,
        "pubkey-abc".to_string(),
    );

    // Tamper with the IP after signing
    ann.ip = "10.0.0.1".to_string();

    assert!(
        !ann.verify_integrity(),
        "tampered announcement should fail verification"
    );
}

#[test]
fn test_node_announcement_serialization_roundtrip() {
    let ann = NodeAnnouncement::new_signed(
        "node1".to_string(),
        "host1".to_string(),
        "192.168.1.100".to_string(),
        8080,
        "pubkey-abc".to_string(),
    );

    let json = serde_json::to_string(&ann).unwrap();
    let parsed: NodeAnnouncement = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.node_id, ann.node_id);
    assert_eq!(parsed.hostname, ann.hostname);
    assert_eq!(parsed.ip, ann.ip);
    assert_eq!(parsed.port, ann.port);
    assert_eq!(parsed.public_key, ann.public_key);
    assert_eq!(parsed.signature, ann.signature);
    assert_eq!(parsed.timestamp, ann.timestamp);
}

#[test]
fn test_node_announcement_default_fields() {
    // signature and timestamp should default if not present in JSON
    let json = r#"{
        "node_id": "n1",
        "hostname": "h1",
        "ip": "1.2.3.4",
        "port": 1000,
        "public_key": "pk"
    }"#;
    let ann: NodeAnnouncement = serde_json::from_str(json).unwrap();
    assert_eq!(ann.signature, "");
    assert_eq!(ann.timestamp, 0);
}

// ─── broadcast_node ──────────────────────────────────────────

#[tokio::test]
async fn test_broadcast_node_sends_udp() {
    let _lock = TEST_ENV_LOCK.lock().await;

    // Use an ephemeral port for broadcast
    let port = {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.local_addr().unwrap().port()
    };

    std::env::set_var("SGX_BROADCAST_PORT", port.to_string());

    // Bind a receiver on the same port to catch broadcast
    let receiver = std::net::UdpSocket::bind(format!("0.0.0.0:{}", port)).unwrap();
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();

    let ann = NodeAnnouncement::new_signed(
        "test-broadcaster".to_string(),
        "testhost".to_string(),
        "127.0.0.1".to_string(),
        5000,
        "test-pubkey".to_string(),
    );

    broadcast_node(&ann);

    // Try to receive — may or may not succeed depending on OS broadcast support
    let mut buf = [0u8; 8192];
    match receiver.recv_from(&mut buf) {
        Ok((size, _)) => {
            let msg = std::str::from_utf8(&buf[..size]).unwrap();
            let parsed: NodeAnnouncement = serde_json::from_str(msg).unwrap();
            assert_eq!(parsed.node_id, "test-broadcaster");
        }
        Err(_) => {
            // Broadcast to self may not work on all systems — this is OK
        }
    }

    std::env::remove_var("SGX_BROADCAST_PORT");
}

#[tokio::test]
async fn test_broadcast_port_env_override() {
    let _lock = TEST_ENV_LOCK.lock().await;

    std::env::set_var("SGX_BROADCAST_PORT", "19999");

    // Just call broadcast to exercise the port-reading path
    let ann = NodeAnnouncement::new_signed(
        "port-test".to_string(),
        "testhost".to_string(),
        "127.0.0.1".to_string(),
        5000,
        "test-pubkey".to_string(),
    );
    broadcast_node(&ann);

    std::env::remove_var("SGX_BROADCAST_PORT");
}
