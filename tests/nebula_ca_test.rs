use sgx_guardian_client::nebula::ca::NebulaCA;
use sgx_guardian_client::nebula::models::CircleMembership;
use sgx_guardian_client::nebula::utils::validate_circle_membership;

// ─── generate_ca ─────────────────────────────────────────────

#[test]
fn test_generate_ca_creates_keypair() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    let result = NebulaCA::generate_ca(base);
    assert!(result.is_ok(), "generate_ca failed: {:?}", result.err());

    let ca_key = tmp.path().join("ca/ca.key");
    let ca_crt = tmp.path().join("ca/ca.crt");
    assert!(ca_key.exists(), "ca.key not created");
    assert!(ca_crt.exists(), "ca.crt not created");

    // Files should be non-empty
    assert!(std::fs::metadata(&ca_key).unwrap().len() > 0);
    assert!(std::fs::metadata(&ca_crt).unwrap().len() > 0);
}

#[test]
fn test_generate_ca_idempotent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    // First call creates
    assert!(NebulaCA::generate_ca(base).is_ok());

    let ca_crt = tmp.path().join("ca/ca.crt");
    let first_content = std::fs::read_to_string(&ca_crt).unwrap();

    // Second call is idempotent — should not overwrite
    assert!(NebulaCA::generate_ca(base).is_ok());

    let second_content = std::fs::read_to_string(&ca_crt).unwrap();
    assert_eq!(
        first_content, second_content,
        "idempotent call overwrote CA"
    );
}

#[test]
fn test_generate_ca_partial_state_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    // Create only ca.key (no ca.crt) → partial state
    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    std::fs::write(ca_dir.join("ca.key"), "partial-key").unwrap();

    let result = NebulaCA::generate_ca(base);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Partial CA state"),
        "unexpected error: {}",
        err_msg
    );
}

// ─── save_ca_cert ────────────────────────────────────────────

#[test]
fn test_save_ca_cert_new() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    let pem = "-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----";
    let result = NebulaCA::save_ca_cert(base, pem);
    assert!(result.is_ok(), "save_ca_cert failed: {:?}", result.err());

    let ca_crt = tmp.path().join("ca/ca.crt");
    assert!(ca_crt.exists());
    assert_eq!(std::fs::read_to_string(ca_crt).unwrap(), pem.trim());
}

#[test]
fn test_save_ca_cert_idempotent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    let pem = "-----BEGIN CERTIFICATE-----\nSAME_CERT\n-----END CERTIFICATE-----";
    assert!(NebulaCA::save_ca_cert(base, pem).is_ok());
    // Second call with identical PEM → idempotent
    assert!(NebulaCA::save_ca_cert(base, pem).is_ok());
}

#[test]
fn test_save_ca_cert_mismatch_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    let pem1 = "-----BEGIN CERTIFICATE-----\nCERT_A\n-----END CERTIFICATE-----";
    let pem2 = "-----BEGIN CERTIFICATE-----\nCERT_B\n-----END CERTIFICATE-----";

    assert!(NebulaCA::save_ca_cert(base, pem1).is_ok());

    // Different PEM → refuses overwrite
    let result = NebulaCA::save_ca_cert(base, pem2);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("mismatch") || err_msg.contains("Refusing"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_save_ca_cert_empty_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    let result = NebulaCA::save_ca_cert(base, "   ");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("empty"), "unexpected error: {}", err_msg);
}

// ─── ca_cert_exists ──────────────────────────────────────────

#[test]
fn test_ca_cert_exists_true_when_present() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    assert!(
        !NebulaCA::ca_cert_exists(base),
        "should be false when absent"
    );

    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    std::fs::write(ca_dir.join("ca.crt"), "CERT_DATA").unwrap();

    assert!(
        NebulaCA::ca_cert_exists(base),
        "should be true when present and non-empty"
    );
}

#[test]
fn test_ca_cert_exists_false_when_empty() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    std::fs::write(ca_dir.join("ca.crt"), "").unwrap();

    assert!(
        !NebulaCA::ca_cert_exists(base),
        "should be false when empty"
    );
}

// ─── ca_fingerprint ──────────────────────────────────────────

#[test]
fn test_ca_fingerprint_fallback_sha256() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    // No cert → None
    assert!(NebulaCA::ca_fingerprint(base).is_none());

    // Create a mock cert file (not valid nebula format, so nebula-cert print will fail)
    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    std::fs::write(ca_dir.join("ca.crt"), "MOCK_CERT_FOR_FINGERPRINT").unwrap();

    // Should fall back to SHA-256 hash of raw bytes
    let fp = NebulaCA::ca_fingerprint(base);
    assert!(fp.is_some(), "fingerprint should use SHA-256 fallback");
    let fp_str = fp.unwrap();
    assert_eq!(
        fp_str.len(),
        16,
        "fingerprint should be 8-byte hex = 16 chars, got: {}",
        fp_str
    );
}

#[test]
fn test_ca_fingerprint_with_real_ca() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    // Generate a real CA to get a valid cert
    if NebulaCA::generate_ca(base).is_ok() {
        let fp = NebulaCA::ca_fingerprint(base);
        assert!(fp.is_some(), "fingerprint should work with real CA");
        // With a real cert, nebula-cert print might work, giving a longer fingerprint
        let fp_str = fp.unwrap();
        assert!(!fp_str.is_empty());
    }
}

// ─── issue_node_cert ─────────────────────────────────────────

#[test]
fn test_issue_node_cert_happy_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    // First generate CA
    assert!(NebulaCA::generate_ca(base).is_ok(), "CA gen failed");

    let membership = CircleMembership {
        node_name: "test-node".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "abc123".to_string(),
        is_valid: true,
    };

    let result = NebulaCA::issue_node_cert(base, &membership, "192.168.100.2/24");
    assert!(result.is_ok(), "issue_node_cert failed: {:?}", result.err());

    let cert = tmp.path().join("nodes/test-node.crt");
    let key = tmp.path().join("nodes/test-node.key");
    assert!(cert.exists(), "node cert not created");
    assert!(key.exists(), "node key not created");
    assert!(std::fs::metadata(&cert).unwrap().len() > 0);
    assert!(std::fs::metadata(&key).unwrap().len() > 0);
}

#[test]
fn test_issue_node_cert_idempotent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    assert!(NebulaCA::generate_ca(base).is_ok());

    let membership = CircleMembership {
        node_name: "idempotent-node".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "abc123".to_string(),
        is_valid: true,
    };

    assert!(NebulaCA::issue_node_cert(base, &membership, "192.168.100.3/24").is_ok());

    let cert = tmp.path().join("nodes/idempotent-node.crt");
    let first_content = std::fs::read_to_string(&cert).unwrap();

    // Second call → idempotent
    assert!(NebulaCA::issue_node_cert(base, &membership, "192.168.100.3/24").is_ok());

    let second_content = std::fs::read_to_string(&cert).unwrap();
    assert_eq!(
        first_content, second_content,
        "idempotent call overwrote cert"
    );
}

#[test]
fn test_issue_node_cert_partial_state_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    assert!(NebulaCA::generate_ca(base).is_ok());

    // Create only the .crt (no .key) → partial state
    let nodes_dir = tmp.path().join("nodes");
    std::fs::create_dir_all(&nodes_dir).unwrap();
    std::fs::write(nodes_dir.join("partial-node.crt"), "partial").unwrap();

    let membership = CircleMembership {
        node_name: "partial-node".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "abc123".to_string(),
        is_valid: true,
    };

    let result = NebulaCA::issue_node_cert(base, &membership, "192.168.100.4/24");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Partial") || err_msg.contains("partial"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_issue_node_cert_missing_ca() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    // Don't generate CA → should fail
    let membership = CircleMembership {
        node_name: "no-ca-node".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "abc123".to_string(),
        is_valid: true,
    };

    let result = NebulaCA::issue_node_cert(base, &membership, "192.168.100.5/24");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not found") || err_msg.contains("CA"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_issue_node_cert_invalid_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    assert!(NebulaCA::generate_ca(base).is_ok());

    let membership = CircleMembership {
        node_name: "bad node!@#".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "abc123".to_string(),
        is_valid: true,
    };

    let result = NebulaCA::issue_node_cert(base, &membership, "192.168.100.6/24");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Invalid node name"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_issue_node_cert_empty_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    assert!(NebulaCA::generate_ca(base).is_ok());

    let membership = CircleMembership {
        node_name: "".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "abc123".to_string(),
        is_valid: true,
    };

    let result = NebulaCA::issue_node_cert(base, &membership, "192.168.100.7/24");
    assert!(result.is_err());
}

#[test]
fn test_issue_node_cert_invalid_membership() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_str().unwrap();

    assert!(NebulaCA::generate_ca(base).is_ok());

    let membership = CircleMembership {
        node_name: "bad-membership".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "".to_string(), // empty vc_hash → invalid
        is_valid: true,
    };

    let result = NebulaCA::issue_node_cert(base, &membership, "192.168.100.8/24");
    assert!(result.is_err());
}

// ─── validate_circle_membership ──────────────────────────────

#[test]
fn test_validate_circle_membership_valid() {
    let m = CircleMembership {
        node_name: "test".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "hash123".to_string(),
        is_valid: true,
    };
    assert!(validate_circle_membership(&m));
}

#[test]
fn test_validate_circle_membership_invalid_flag() {
    let m = CircleMembership {
        node_name: "test".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "hash123".to_string(),
        is_valid: false,
    };
    assert!(!validate_circle_membership(&m));
}

#[test]
fn test_validate_circle_membership_empty_hash() {
    let m = CircleMembership {
        node_name: "test".to_string(),
        circle_id: "alpha".to_string(),
        vc_hash: "".to_string(),
        is_valid: true,
    };
    assert!(!validate_circle_membership(&m));
}
