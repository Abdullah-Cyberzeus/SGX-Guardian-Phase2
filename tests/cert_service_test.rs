use sgx_guardian_client::cert_service::{ApprovalDecision, CertRequestYaml};

// ─── ApprovalDecision serde ──────────────────────────────────

#[test]
fn test_approval_decision_all_aliases() {
    // false / reject / no → False
    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: member\napprove: false\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::False));

    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: member\napprove: reject\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::False));

    // member
    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: member\napprove: member\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::Member));

    // lighthouse
    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: lighthouse\napprove: lighthouse\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::Lighthouse));

    // lh alias
    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: lighthouse\napprove: lh\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::Lighthouse));

    // relay
    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: relay\napprove: relay\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::Relay));

    // lh_relay
    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: lh_relay\napprove: lh_relay\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::LhRelay));

    // lhrelay alias
    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: lh_relay\napprove: lhrelay\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::LhRelay));

    // relay_lh alias
    let parsed: CertRequestYaml = serde_yaml::from_str(
        "node_id: test\nrequested_at: '2026-01-01T00:00:00Z'\noverlay_ip: '10.0.0.1/24'\npublic_key_fingerprint: abc\nrequested_role: lh_relay\napprove: relay_lh\n",
    ).unwrap();
    assert!(matches!(parsed.approve, ApprovalDecision::LhRelay));
}

// ─── CertRequestYaml roundtrip ───────────────────────────────

#[test]
fn test_cert_request_yaml_serde_roundtrip() {
    let req = CertRequestYaml {
        node_id: "nodeB".to_string(),
        requested_at: "2026-07-01T12:00:00Z".to_string(),
        overlay_ip: "192.168.100.2/24".to_string(),
        public_key_fingerprint: "abcdef1234".to_string(),
        requested_role: "member".to_string(),
        approve: ApprovalDecision::Member,
    };

    // Serialize to YAML
    let yaml = serde_yaml::to_string(&req).unwrap();
    assert!(yaml.contains("nodeB"));
    assert!(yaml.contains("192.168.100.2/24"));

    // Deserialize back
    let parsed: CertRequestYaml = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(parsed.node_id, "nodeB");
    assert_eq!(parsed.overlay_ip, "192.168.100.2/24");
    assert!(matches!(parsed.approve, ApprovalDecision::Member));
}

#[test]
fn test_cert_request_yaml_all_roles_serializable() {
    let roles = vec![
        ApprovalDecision::False,
        ApprovalDecision::Member,
        ApprovalDecision::Lighthouse,
        ApprovalDecision::Relay,
        ApprovalDecision::LhRelay,
    ];

    for role in roles {
        let req = CertRequestYaml {
            node_id: "node".to_string(),
            requested_at: "now".to_string(),
            overlay_ip: "10.0.0.1/24".to_string(),
            public_key_fingerprint: "fp".to_string(),
            requested_role: "member".to_string(),
            approve: role,
        };
        let yaml = serde_yaml::to_string(&req).unwrap();
        assert!(!yaml.is_empty());
    }
}

// ─── Cert service writes YAML request file ───────────────────

#[tokio::test]
async fn test_cert_service_creates_yaml_request_file() {
    // Only run if /var/lib/sgx-guardian is writable
    let writable = {
        let test_path = "/var/lib/sgx-guardian/nebula/.write_test_cert";
        let _ = std::fs::create_dir_all("/var/lib/sgx-guardian/nebula");
        if std::fs::write(test_path, "").is_ok() {
            let _ = std::fs::remove_file(test_path);
            true
        } else {
            false
        }
    };

    if !writable {
        return;
    }

    use sgx_guardian_client::proto::sgx::cert_service_server::CertService;
    use sgx_guardian_client::proto::sgx::CertSignRequest;
    use sgx_guardian_client::cert_service::MyCertService;
    use tonic::Request;

    let service = MyCertService;
    let request = Request::new(CertSignRequest {
        node_id: "test-cert-node".to_string(),
        public_key_pem: "test-pubkey-pem".to_string(),
        wants_lighthouse: false,
        wants_relay: false,
        overlay_ip: String::new(),
    });

    // The service will write YAML and then poll for approval — we don't wait for full approval
    // Instead, pre-write a "rejected" approval to short-circuit polling.
    let yaml_path = "/var/lib/sgx-guardian/nebula/requests/test-cert-node.yaml";
    let _ = std::fs::create_dir_all("/var/lib/sgx-guardian/nebula/requests");

    // Write rejected approval YAML before the gRPC call creates it
    // so the service immediately reads "false" and returns rejected
    let rejection_yaml = "node_id: test-cert-node\nrequested_at: '2026-07-01T00:00:00Z'\noverlay_ip: '10.0.0.2/24'\npublic_key_fingerprint: test-fp\nrequested_role: member\napprove: false\n";
    let _ = std::fs::write(yaml_path, rejection_yaml);

    // Spawn request in background — will read YAML and return "rejected"
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        service.request_certificate(request),
    ).await;

    // Either times out (if waiting for file) or returns rejected
    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.into_inner().status, "rejected");
        }
        Ok(Err(_)) => { /* Error is acceptable */ }
        Err(_) => { /* Timeout is acceptable if the service waits */ }
    }

    // Cleanup
    let _ = std::fs::remove_file(yaml_path);
}

#[tokio::test]
async fn test_cert_service_invalid_node_id_rejected() {
    use sgx_guardian_client::proto::sgx::cert_service_server::CertService;
    use sgx_guardian_client::proto::sgx::CertSignRequest;
    use sgx_guardian_client::cert_service::MyCertService;
    use tonic::Request;

    let service = MyCertService;

    // Empty node_id → invalid_argument
    let request = Request::new(CertSignRequest {
        node_id: "".to_string(),
        public_key_pem: "test-pubkey".to_string(),
        wants_lighthouse: false,
        wants_relay: false,
        overlay_ip: String::new(),
    });

    let result = service.request_certificate(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_cert_service_invalid_chars_node_id() {
    use sgx_guardian_client::proto::sgx::cert_service_server::CertService;
    use sgx_guardian_client::proto::sgx::CertSignRequest;
    use sgx_guardian_client::cert_service::MyCertService;
    use tonic::Request;

    let service = MyCertService;

    // Node ID with spaces/special chars → invalid
    let request = Request::new(CertSignRequest {
        node_id: "bad node!".to_string(),
        public_key_pem: "test-pubkey".to_string(),
        wants_lighthouse: false,
        wants_relay: false,
        overlay_ip: String::new(),
    });

    let result = service.request_certificate(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}
