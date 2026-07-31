use sgx_guardian_client::cert_client::*;
use sgx_guardian_client::proto::sgx::cert_service_server::{CertService, CertServiceServer};
use sgx_guardian_client::proto::sgx::{CertSignRequest, CertSignResponse};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

static TEST_ENV_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

struct MockCertService {
    response: Arc<Mutex<CertSignResponse>>,
}

#[tonic::async_trait]
impl CertService for MockCertService {
    async fn request_certificate(
        &self,
        request: Request<CertSignRequest>,
    ) -> Result<Response<CertSignResponse>, Status> {
        let req = request.into_inner();
        assert_eq!(req.node_id, "test-node");
        assert_eq!(req.overlay_ip, "192.168.100.2/24");
        assert_eq!(req.public_key_pem, "test-pubkey");

        let resp = self.response.lock().await.clone();
        Ok(Response::new(resp))
    }
}

#[tokio::test]
async fn test_request_cert_rejected() {
    let _lock = TEST_ENV_LOCK.lock().await;

    let tmp_vc = tempfile::tempdir().expect("tempdir");
    std::env::set_var("SGX_GUARDIAN_VC_BASE", tmp_vc.path());
    std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.2");

    // Get an ephemeral port on 127.0.0.2 loopback IP (which is considered a valid LAN IP)
    let addr = {
        let listener = tokio::net::TcpListener::bind("127.0.0.2:0")
            .await
            .expect("bind listener");
        listener.local_addr().expect("local addr")
    };

    let mock_resp = CertSignResponse {
        status: "rejected".into(),
        signed_cert_pem: "".into(),
        node_key_pem: "".into(),
        ca_cert_pem: "".into(),
        message: "rejected message".into(),
        assigned_lighthouse: false,
        lighthouse_registry_json: "".into(),
        overlay_registry_json: "".into(),
        signed_policy_bytes: vec![],
        assigned_relay: false,
        relay_registry_json: "".into(),
        signing_pubkey_der: vec![],
        member_vc_json: "".into(),
    };
    let mock_service = MockCertService {
        response: Arc::new(Mutex::new(mock_resp)),
    };

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(CertServiceServer::new(mock_service))
            .serve_with_shutdown(addr, async {
                rx.await.ok();
            })
            .await
            .unwrap();
    });

    // Give the server a small moment to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    request_certificate_from_ca(
        "test-node".to_string(),
        addr.to_string(),
        "192.168.100.2/24".to_string(),
        "test-pubkey".to_string(),
        false,
        false,
        None,
    )
    .await;

    tx.send(()).ok();
    handle.await.ok();

    std::env::remove_var("SGX_GUARDIAN_VC_BASE");
    std::env::remove_var("SGX_LIGHTHOUSE_IP");
}

#[tokio::test]
async fn test_request_cert_connection_failure() {
    let _lock = TEST_ENV_LOCK.lock().await;

    let tmp_vc = tempfile::tempdir().expect("tempdir");
    std::env::set_var("SGX_GUARDIAN_VC_BASE", tmp_vc.path());
    std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.2");

    // Spawn client against a non-existent port on 127.0.0.2
    let client_handle = tokio::spawn(async move {
        request_certificate_from_ca(
            "test-node".to_string(),
            "127.0.0.2:1".to_string(),
            "192.168.100.2/24".to_string(),
            "test-pubkey".to_string(),
            false,
            false,
            None,
        )
        .await;
    });

    // Let it run for a short duration and then abort to prevent infinite loop
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    client_handle.abort();

    std::env::remove_var("SGX_GUARDIAN_VC_BASE");
    std::env::remove_var("SGX_LIGHTHOUSE_IP");
}

#[tokio::test]
async fn test_request_cert_already_present() {
    let _lock = TEST_ENV_LOCK.lock().await;

    let tmp_vc = tempfile::tempdir().expect("tempdir");
    std::env::set_var("SGX_GUARDIAN_VC_BASE", tmp_vc.path());
    std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.2");

    let cert_path = "/var/lib/sgx-guardian/nebula/nodes/test-node-existing.crt";
    let key_path = "/var/lib/sgx-guardian/nebula/nodes/test-node-existing.key";
    let ca_path = "/var/lib/sgx-guardian/nebula/ca/ca.crt";

    // Write VC & status list to our temp directory so persistence helpers find it
    let own_dir = tmp_vc.path().join("own");
    std::fs::create_dir_all(&own_dir).unwrap();
    let vc_json = r#"{
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "id": "did:test",
      "type": ["VerifiableCredential"],
      "issuer": "did:issuer",
      "issuanceDate": "2026-06-30T10:00:00Z",
      "expirationDate": "2027-06-30T10:00:00Z",
      "credentialSubject": {
        "id": "did:test",
        "role": "member",
        "permissions": ["read"],
        "joinDate": "2026-06-30T10:00:00Z",
        "circleId": "alpha",
        "membershipStatus": "active"
      },
      "credentialStatus": {
        "id": "https://example.com/status/1",
        "type": "StatusList2021Status",
        "statusPurpose": "revocation",
        "statusListIndex": "1",
        "statusListCredential": "https://example.com/status/1"
      },
      "proof": {
        "type": "JsonWebSignature2020",
        "cryptosuite": "Ed25519Signature2020",
        "created": "2026-06-30T10:00:00Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:issuer#key-1",
        "proofValue": "dummy"
      }
    }"#;
    std::fs::write(own_dir.join("test_vc.json"), vc_json).unwrap();
    std::fs::write(tmp_vc.path().join("status_list.json"), "{}").unwrap();

    let writable = {
        let test_file = "/var/lib/sgx-guardian/nebula/ca/dummy_test_write.txt";
        let _ = std::fs::create_dir_all("/var/lib/sgx-guardian/nebula/ca");
        if std::fs::write(test_file, "").is_ok() {
            let _ = std::fs::remove_file(test_file);
            true
        } else {
            false
        }
    };

    if writable {
        // Create mock cert & key
        std::fs::write(cert_path, "MOCK CERT").unwrap();
        std::fs::write(key_path, "MOCK KEY").unwrap();
        std::fs::write(ca_path, "MOCK CA").unwrap();

        // Call the client pointing to an invalid address.
        // Because files exist and VC exists, it must return immediately without connecting!
        request_certificate_from_ca(
            "test-node-existing".to_string(),
            "127.0.0.2:1".to_string(),
            "192.168.100.2/24".to_string(),
            "test-pubkey".to_string(),
            false,
            false,
            None,
        )
        .await;

        // Clean up mock files
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(ca_path);
    }

    std::env::remove_var("SGX_GUARDIAN_VC_BASE");
    std::env::remove_var("SGX_LIGHTHOUSE_IP");
}

#[tokio::test]
async fn test_request_cert_approved_flow() {
    let _lock = TEST_ENV_LOCK.lock().await;

    let tmp_vc = tempfile::tempdir().expect("tempdir");
    std::env::set_var("SGX_GUARDIAN_VC_BASE", tmp_vc.path());
    std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.2");

    let writable = {
        let test_file = "/var/lib/sgx-guardian/nebula/ca/dummy_test_write.txt";
        let _ = std::fs::create_dir_all("/var/lib/sgx-guardian/nebula/ca");
        if std::fs::write(test_file, "").is_ok() {
            let _ = std::fs::remove_file(test_file);
            true
        } else {
            false
        }
    };

    if writable {
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.2:0")
                .await
                .expect("bind listener");
            listener.local_addr().expect("local addr")
        };

        let vc_json = r#"{
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          "id": "did:test",
          "type": ["VerifiableCredential"],
          "issuer": "did:issuer",
          "issuanceDate": "2026-06-30T10:00:00Z",
          "expirationDate": "2027-06-30T10:00:00Z",
          "credentialSubject": {
            "id": "did:test",
            "role": "member",
            "permissions": ["read"],
            "joinDate": "2026-06-30T10:00:00Z",
            "circleId": "alpha",
            "membershipStatus": "active"
          },
          "credentialStatus": {
            "id": "https://example.com/status/1",
            "type": "StatusList2021Status",
            "statusPurpose": "revocation",
            "statusListIndex": "1",
            "statusListCredential": "https://example.com/status/1"
          },
          "proof": {
            "type": "JsonWebSignature2020",
            "cryptosuite": "Ed25519Signature2020",
            "created": "2026-06-30T10:00:00Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:issuer#key-1",
            "proofValue": "dummy"
          }
        }"#;

        // Seed mock node YAML configuration to allow editing max_peers/etc.
        let cfg_path = "/etc/sgx-guardian/config/test-node-approved.yaml";
        let _ = std::fs::create_dir_all("/etc/sgx-guardian/config");
        std::fs::write(cfg_path, "relay: {}\n").ok();

        let mock_resp = CertSignResponse {
            status: "approved".into(),
            signed_cert_pem: "APPROVED CERT".into(),
            node_key_pem: "APPROVED KEY".into(),
            ca_cert_pem: "APPROVED CA".into(),
            message: "approved message".into(),
            assigned_lighthouse: true,
            lighthouse_registry_json: r#"{"circle_id":"alpha","lighthouses":[]}"#.into(),
            overlay_registry_json: r#"{"circle_id":"alpha","subnet_base":"192.168.100","cidr":24,"owner_node":"test-node-approved","next_host":2,"allocations":{"test-node-approved":"192.168.100.2"},"schema_version":1,"last_modified":"2026-07-02T12:00:00Z"}"#.into(),
            signed_policy_bytes: vec![1, 2, 3],
            assigned_relay: true,
            relay_registry_json: r#"{"circle_id":"alpha","relays":[]}"#.into(),
            signing_pubkey_der: vec![4, 5, 6],
            member_vc_json: vc_json.into(),
        };

        let mock_service = MockCertService {
            response: Arc::new(Mutex::new(mock_resp)),
        };

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(CertServiceServer::new(mock_service))
                .serve_with_shutdown(addr, async {
                    rx.await.ok();
                })
                .await
                .unwrap();
        });

        // Give the server a small moment to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Run full client request cert approved flow
        request_certificate_from_ca(
            "test-node-approved".to_string(),
            addr.to_string(),
            "192.168.100.2/24".to_string(),
            "test-pubkey".to_string(),
            true,
            true,
            None,
        )
        .await;

        tx.send(()).ok();
        handle.await.ok();

        // Verify written files
        assert_eq!(
            std::fs::read_to_string("/var/lib/sgx-guardian/nebula/nodes/test-node-approved.crt")
                .unwrap(),
            "APPROVED CERT"
        );
        assert_eq!(
            std::fs::read_to_string("/var/lib/sgx-guardian/nebula/nodes/test-node-approved.key")
                .unwrap(),
            "APPROVED KEY"
        );
        assert_eq!(
            std::fs::read_to_string("/var/lib/sgx-guardian/nebula/ca/ca.crt").unwrap(),
            "APPROVED CA"
        );

        // Clean up files
        let _ = std::fs::remove_file("/var/lib/sgx-guardian/nebula/nodes/test-node-approved.crt");
        let _ = std::fs::remove_file("/var/lib/sgx-guardian/nebula/nodes/test-node-approved.key");
        let _ = std::fs::remove_file("/var/lib/sgx-guardian/nebula/ca/ca.crt");
        let _ = std::fs::remove_file("/var/lib/sgx-guardian/nebula/overlay_registry.json");
        let _ = std::fs::remove_file("/var/lib/sgx-guardian/nebula/lighthouse_registry.json");
        let _ = std::fs::remove_file("/var/lib/sgx-guardian/nebula/relay_registry.json");
        let _ = std::fs::remove_file("/var/lib/sgx-guardian/nebula/am_lighthouse");
        let _ = std::fs::remove_file("/var/lib/sgx-guardian/nebula/am_relay");
        let _ = std::fs::remove_file("/etc/sgx-guardian/policies/policy.sig");
        let _ = std::fs::remove_file("/etc/sgx-guardian/policies/pa_admin_pub.der");
        let _ = std::fs::remove_file(cfg_path);
    }

    std::env::remove_var("SGX_GUARDIAN_VC_BASE");
    std::env::remove_var("SGX_LIGHTHOUSE_IP");
}
