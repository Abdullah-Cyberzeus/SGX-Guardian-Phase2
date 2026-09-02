use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sgx_broker::create_app;
use sgx_broker::models::{EnrollmentRequest, EnrollmentResponse, HealthResponse};
use sgx_broker::state::AppState;
use tower::ServiceExt;

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
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
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
async fn test_models_roundtrip() {
    let req = EnrollmentRequest {
        circle_id: "circle-1".to_string(),
        node_id: "nodeC".to_string(),
        public_key_pem: "key-pem-data".to_string(),
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
        message: "signed".to_string(),
    };

    let resp_str = serde_json::to_string(&resp).unwrap();
    let resp_de: EnrollmentResponse = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp_de.status, "APPROVED");
    assert_eq!(resp_de.key, "key-data");
}
