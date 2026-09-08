use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sgx_broker::create_app;
use sgx_broker::models::{EnrollmentRequest, EnrollmentResponse, HealthResponse};
use sgx_broker::state::AppState;
use tokio::sync::mpsc;
use tower::ServiceExt;

fn approved_response() -> EnrollmentResponse {
    EnrollmentResponse {
        status: "APPROVED".to_string(),
        overlay_ip: "192.168.100.3/24".to_string(),
        cert: "cert".to_string(),
        key: "key".to_string(),
        ca_cert: "ca".to_string(),
        config: "config".to_string(),
        member_vc_json: "vc".to_string(),
        status_list_json: "status".to_string(),
        did_doc_aggregate_json: "[]".to_string(),
        signing_pubkey_der_b64: "pubkey".to_string(),
        signed_policy_b64: "policy".to_string(),
        message: "approved".to_string(),
    }
}

#[tokio::test]
async fn test_health_endpoint() {
    let state = AppState::new();
    let app = create_app(state);

    let req = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let health: HealthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(health.status, "ok");
    assert!(!health.ca_connected);
}

#[tokio::test]
async fn test_enrollment_ca_offline_rejection() {
    let state = AppState::new();
    let app = create_app(state);

    let payload = serde_json::json!({
        "circle_id": "guardian-circle-alpha",
        "node_id": "test-node",
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        "did_doc_json": "{}"
    });

    let req = Request::builder()
        .uri("/api/v1/enroll")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let enroll: EnrollmentResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(enroll.status, "ERROR");
    assert!(enroll.message.contains("Home CA node is not connected"));
}

#[tokio::test]
async fn test_enrollment_validation_empty_fields() {
    let state = AppState::new();
    let app = create_app(state);

    let payload = serde_json::json!({
        "circle_id": "",
        "node_id": "test-node",
        "public_key_pem": "test"
    });

    let req = Request::builder()
        .uri("/api/v1/enroll")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn enrollment_rejects_invalid_node_identifiers_without_contacting_ca() {
    let state = AppState::new();
    let (ca_tx, mut ca_rx) = mpsc::channel(1);
    state.register_ca("guardian-circle-alpha", ca_tx);

    for node_id in ["", "node C", "node/C", "node.C", "node\nC"] {
        let app = create_app(state.clone());
        let payload = serde_json::json!({
            "circle_id": "guardian-circle-alpha",
            "node_id": node_id,
            "public_key_pem": "test-public-key",
            "did_doc_json": "{}"
        });
        let request = Request::builder()
            .uri("/api/v1/enroll")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(other_ca_rx_empty(&mut ca_rx));
}

fn other_ca_rx_empty(receiver: &mut mpsc::Receiver<String>) -> bool {
    receiver.try_recv().is_err()
}

#[tokio::test]
async fn enrollment_rejects_missing_identity_fields_without_contacting_ca() {
    let state = AppState::new();
    let (ca_tx, mut ca_rx) = mpsc::channel(1);
    state.register_ca("guardian-circle-alpha", ca_tx);

    for (public_key_pem, did_doc_json) in [("", "{}"), ("key", "")] {
        let app = create_app(state.clone());
        let payload = serde_json::json!({
            "circle_id": "guardian-circle-alpha",
            "node_id": "nodeC",
            "public_key_pem": public_key_pem,
            "did_doc_json": did_doc_json
        });
        let request = Request::builder()
            .uri("/api/v1/enroll")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(other_ca_rx_empty(&mut ca_rx));
}

#[tokio::test]
async fn enrollment_returns_error_when_ca_channel_has_already_closed() {
    let state = AppState::new();
    let (ca_tx, ca_rx) = mpsc::channel(1);
    drop(ca_rx);
    state.register_ca("guardian-circle-alpha", ca_tx);
    let app = create_app(state);
    let payload = serde_json::json!({
        "circle_id": "guardian-circle-alpha",
        "node_id": "nodeC",
        "public_key_pem": "key",
        "did_doc_json": "{}"
    });
    let request = Request::builder()
        .uri("/api/v1/enroll")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let enrollment: EnrollmentResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(enrollment.status, "ERROR");
    assert!(enrollment.message.contains("Failed to forward"));
}

#[tokio::test]
async fn enrollment_is_forwarded_to_the_matching_circle_ca_and_returns_its_response() {
    let state = AppState::new();
    let (ca_tx, mut ca_rx) = mpsc::channel(1);
    state.register_ca("guardian-circle-alpha", ca_tx);
    let app = create_app(state.clone());

    let payload = serde_json::json!({
        "circle_id": "guardian-circle-alpha",
        "node_id": "nodeC",
        "public_key_pem": "test-public-key",
        "did_doc_json": "{\"id\":\"did:guardian:test\"}"
    });
    let request = Request::builder()
        .uri("/api/v1/enroll")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let enrollment = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    let forwarded = ca_rx.recv().await.expect("broker forwards request to CA");
    let envelope: serde_json::Value = serde_json::from_str(&forwarded).unwrap();
    assert_eq!(envelope["event"], "ENROLLMENT_REQUEST");
    assert_eq!(envelope["payload"]["node_id"], "nodeC");
    assert_eq!(envelope["payload"]["circle_id"], "guardian-circle-alpha");

    let request_id = envelope["request_id"].as_str().unwrap();
    assert!(state.resolve_pending(request_id, approved_response()));

    let response = enrollment.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let enrollment: EnrollmentResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(enrollment.status, "APPROVED");
    assert_eq!(enrollment.overlay_ip, "192.168.100.3/24");
}

#[tokio::test]
async fn enrollment_for_a_circle_without_its_ca_is_not_sent_to_another_circle() {
    let state = AppState::new();
    let (other_ca_tx, mut other_ca_rx) = mpsc::channel(1);
    state.register_ca("other-circle", other_ca_tx);
    let app = create_app(state);
    let payload = serde_json::json!({
        "circle_id": "guardian-circle-alpha",
        "node_id": "nodeC",
        "public_key_pem": "test-public-key",
        "did_doc_json": "{}"
    });
    let request = Request::builder()
        .uri("/api/v1/enroll")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let enrollment: EnrollmentResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(enrollment.status, "ERROR");
    assert!(enrollment.message.contains("not connected"));
    assert!(other_ca_rx.try_recv().is_err());
}

#[tokio::test]
async fn test_models_roundtrip() {
    let req = EnrollmentRequest {
        circle_id: "circle-1".to_string(),
        node_id: "nodeC".to_string(),
        public_key_pem: "key-pem-data".to_string(),
        did_doc_json: "{\"id\":\"did:guardian:test\"}".to_string(),
    };

    let serialized = serde_json::to_string(&req).unwrap();
    let deserialized: EnrollmentRequest = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.node_id, "nodeC");
    assert_eq!(deserialized.circle_id, "circle-1");

    let resp = EnrollmentResponse {
        status: "APPROVED".to_string(),
        overlay_ip: "192.168.100.3/24".to_string(),
        cert: "cert-data".to_string(),
        key: "key-data".to_string(),
        ca_cert: "ca-data".to_string(),
        config: "config-yaml".to_string(),
        member_vc_json: "member-vc".to_string(),
        status_list_json: "status-list".to_string(),
        did_doc_aggregate_json: "[]".to_string(),
        signing_pubkey_der_b64: "pa-key".to_string(),
        signed_policy_b64: "policy".to_string(),
        message: "signed".to_string(),
    };

    let resp_str = serde_json::to_string(&resp).unwrap();
    let resp_de: EnrollmentResponse = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp_de.status, "APPROVED");
    assert_eq!(resp_de.key, "key-data");
}

#[test]
fn test_lighthouse_manager_config_generation() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let path = tmp_dir.path().to_str().unwrap();

    assert!(!sgx_broker::lighthouse_manager::certificates_exist(path));

    // Create dummy cert files
    std::fs::write(format!("{}/ca.crt", path), "dummy-ca").unwrap();
    std::fs::write(format!("{}/vps-lighthouse.crt", path), "dummy-cert").unwrap();
    std::fs::write(format!("{}/vps-lighthouse.key", path), "dummy-key").unwrap();

    assert!(sgx_broker::lighthouse_manager::certificates_exist(path));

    // Ensure config is created
    assert!(sgx_broker::lighthouse_manager::ensure_nebula_config(path).is_ok());
    let cfg_content = std::fs::read_to_string(format!("{}/config.yaml", path)).unwrap();
    assert!(cfg_content.contains("am_lighthouse: true"));
    assert!(cfg_content.contains("am_relay: true"));
    assert!(cfg_content.contains("port: 4242"));
}
