use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use sgx_guardian_client::runtime::event_bus::EventBus;
use sgx_guardian_client::runtime::models::{GuardianConfig, RuntimeMode};
use sgx_guardian_client::runtime::runtime_manager::RuntimeManager;
use sgx_guardian_client::runtime::server::build_wifi_router;
use sgx_guardian_client::runtime::state_machine::StateMachine;
use std::sync::Arc;
use tower::ServiceExt;

fn router() -> axum::Router {
    let bus = Arc::new(EventBus::new());
    let manager = Arc::new(RuntimeManager::new(Arc::new(StateMachine::new(bus.clone()))));
    build_wifi_router(manager, bus)
}

async fn request(method: Method, path: &str, body: Option<GuardianConfig>) -> axum::response::Response {
    let dir = tempfile::tempdir().unwrap();
    let previous_config = std::env::var_os("GUARDIAN_CONFIG_FILE");
    let previous_key = std::env::var_os("GUARDIAN_KEY_FILE");
    std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("wifi.json"));
    std::env::set_var("GUARDIAN_KEY_FILE", dir.path().join("wifi.key"));

    let mut builder = Request::builder().method(method).uri(path);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = body
        .map(|cfg| Body::from(serde_json::to_vec(&cfg).unwrap()))
        .unwrap_or_else(Body::empty);
    let response = router().oneshot(builder.body(body).unwrap()).await.unwrap();

    match previous_config {
        Some(value) => std::env::set_var("GUARDIAN_CONFIG_FILE", value),
        None => std::env::remove_var("GUARDIAN_CONFIG_FILE"),
    }
    match previous_key {
        Some(value) => std::env::set_var("GUARDIAN_KEY_FILE", value),
        None => std::env::remove_var("GUARDIAN_KEY_FILE"),
    }

    response
}

fn cfg(mode: RuntimeMode) -> GuardianConfig {
    let mut cfg = GuardianConfig::default();
    cfg.mode = mode;
    cfg.hotspot.password = "StrongPass!1".into();
    cfg
}

#[tokio::test]
async fn get_mode_returns_ok() {
    assert_eq!(request(Method::GET, "/mode", None).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_scan_returns_ok() {
    assert_eq!(request(Method::GET, "/scan", None).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_clients_returns_ok() {
    assert_eq!(request(Method::GET, "/clients", None).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_route_returns_not_found() {
    assert_eq!(request(Method::GET, "/missing", None).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn post_mode_off_returns_ok() {
    assert_eq!(request(Method::POST, "/mode", Some(cfg(RuntimeMode::Off))).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn post_mode_hotspot_rejects_short_password() {
    let mut payload = cfg(RuntimeMode::HotspotOnly);
    payload.hotspot.password = "short!".into();
    assert_eq!(request(Method::POST, "/mode", Some(payload)).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_mode_dual_rejects_password_without_symbol() {
    let mut payload = cfg(RuntimeMode::DualWifi);
    payload.hotspot.password = "Password123".into();
    assert_eq!(request(Method::POST, "/mode", Some(payload)).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_mode_hotspot_rejects_eight_chars_without_symbol() {
    let mut payload = cfg(RuntimeMode::HotspotOnly);
    payload.hotspot.password = "Password".into();
    assert_eq!(request(Method::POST, "/mode", Some(payload)).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_mode_invalid_json_returns_bad_request() {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/mode")
        .header("content-type", "application/json")
        .body(Body::from("{"))
        .unwrap();
    assert_eq!(router().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
}

macro_rules! method_not_allowed_tests {
    ($($name:ident => $method:expr, $path:expr),+ $(,)?) => {$(
        #[tokio::test]
        async fn $name() {
            assert_eq!(request($method, $path, None).await.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
    )+};
}

method_not_allowed_tests! {
    put_mode_not_allowed => Method::PUT, "/mode",
    delete_mode_not_allowed => Method::DELETE, "/mode",
    post_scan_not_allowed => Method::POST, "/scan",
    post_clients_not_allowed => Method::POST, "/clients",
    put_scan_not_allowed => Method::PUT, "/scan",
    delete_clients_not_allowed => Method::DELETE, "/clients",
}

macro_rules! mode_post_tests {
    ($($name:ident => $mode:expr),+ $(,)?) => {$(
        #[tokio::test]
        async fn $name() {
            assert_eq!(request(Method::POST, "/mode", Some(cfg($mode))).await.status(), StatusCode::OK);
        }
    )+};
}

mode_post_tests! {
    post_off_mode_ok => RuntimeMode::Off,
}

#[tokio::test]
async fn get_mode_body_contains_mode_field() {
    let bytes = axum::body::to_bytes(request(Method::GET, "/mode", None).await.into_body(), usize::MAX).await.unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap().get("mode").is_some());
}

#[tokio::test]
async fn get_mode_body_contains_status_field() {
    let bytes = axum::body::to_bytes(request(Method::GET, "/mode", None).await.into_body(), usize::MAX).await.unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap().get("status").is_some());
}

#[tokio::test]
async fn get_mode_body_contains_security_field() {
    let bytes = axum::body::to_bytes(request(Method::GET, "/mode", None).await.into_body(), usize::MAX).await.unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap().get("security").is_some());
}

#[tokio::test]
async fn scan_body_contains_networks_array() {
    let bytes = axum::body::to_bytes(request(Method::GET, "/scan", None).await.into_body(), usize::MAX).await.unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["networks"].is_array());
}

#[tokio::test]
async fn clients_body_contains_clients_array() {
    let bytes = axum::body::to_bytes(request(Method::GET, "/clients", None).await.into_body(), usize::MAX).await.unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["clients"].is_array());
}

#[tokio::test]
async fn post_mode_response_reports_applying() {
    let bytes = axum::body::to_bytes(request(Method::POST, "/mode", Some(cfg(RuntimeMode::Off))).await.into_body(), usize::MAX).await.unwrap();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["status"], "applying");
}

#[tokio::test]
async fn post_mode_response_has_downtime_estimate() {
    let bytes = axum::body::to_bytes(request(Method::POST, "/mode", Some(cfg(RuntimeMode::Off))).await.into_body(), usize::MAX).await.unwrap();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["estimated_downtime_seconds"], 3);
}

#[tokio::test]
async fn bad_password_response_contains_error_status() {
    let mut payload = cfg(RuntimeMode::HotspotOnly);
    payload.hotspot.password = "short".into();
    let bytes = axum::body::to_bytes(request(Method::POST, "/mode", Some(payload)).await.into_body(), usize::MAX).await.unwrap();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["status"], "error");
}

#[tokio::test]
async fn bad_password_response_contains_message() {
    let mut payload = cfg(RuntimeMode::HotspotOnly);
    payload.hotspot.password = "short".into();
    let bytes = axum::body::to_bytes(request(Method::POST, "/mode", Some(payload)).await.into_body(), usize::MAX).await.unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["message"].as_str().unwrap().contains("Password"));
}
