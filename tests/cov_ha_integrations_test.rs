//! Integration tests for `src/api/handlers/ha_integrations.rs`.
//!
//! Every handler except `get_nest_oauth_url`/`nest_oauth_callback` starts by
//! calling `state.get_integration_manager().await`, which is `None` by
//! default (`AppState::for_tests` leaves it uninitialized) — so this file
//! first seeds a real `IntegrationManager` directly onto `AppState`'s public
//! `integration_manager: Arc<RwLock<Option<Arc<IntegrationManager>>>>` field,
//! backed by a tempdir via the `SGX_DATA_DIR` override that
//! `storage::resolve_data_file` reads. No HA server or device manager is
//! configured, so `connect_kasa`/`connect_nest`/`disconnect_integration`
//! exercise their "no HA flow client" / "no device manager" branches, which
//! is real, deterministic production behavior for a Guardian with no
//! Home Assistant configured yet — not a mock.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sgx_guardian_client::integration::manager::IntegrationManager;
use tower::ServiceExt;

struct HaEnv {
    _env: support::Env,
    _data_dir: tempfile::TempDir,
    router: axum::Router,
    token: String,
}

impl HaEnv {
    async fn new_uninitialized() -> Self {
        let env = support::Env::new();
        let token = env.owner_token().await;
        let router = env.router();
        let data_dir = tempfile::tempdir().expect("data dir");
        Self {
            _env: env,
            _data_dir: data_dir,
            router,
            token,
        }
    }

    async fn new() -> Self {
        let env = Self::new_uninitialized().await;
        std::env::set_var("SGX_DATA_DIR", env._data_dir.path());
        let manager = IntegrationManager::new("cov-ha-integrations.json");
        *env._env.state.integration_manager.write().await = Some(manager);
        env
    }
}

async fn json_request(
    env: &HaEnv,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {}", env.token));
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let request = builder.body(body).expect("build request");
    let response = env.router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let parsed = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, parsed)
}

#[tokio::test]
async fn every_handler_reports_service_unavailable_before_manager_init() {
    let env = HaEnv::new_uninitialized().await;

    let (list_status, _) = json_request(&env, "GET", "/api/v1/ha/integrations", None).await;
    assert_eq!(list_status, StatusCode::SERVICE_UNAVAILABLE);

    let (status_status, _) = json_request(
        &env,
        "GET",
        "/api/v1/ha/integrations/tp_link_kasa/status",
        None,
    )
    .await;
    assert_eq!(status_status, StatusCode::SERVICE_UNAVAILABLE);

    let (connect_status, _) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/tp_link_kasa/connect",
        Some(serde_json::json!({ "mode": "local" })),
    )
    .await;
    assert_eq!(connect_status, StatusCode::SERVICE_UNAVAILABLE);

    let (disconnect_status, _) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/tp_link_kasa/disconnect",
        None,
    )
    .await;
    assert_eq!(disconnect_status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn list_integrations_reports_the_seeded_default_providers() {
    let env = HaEnv::new().await;
    let (status, body) = json_request(&env, "GET", "/api/v1/ha/integrations", None).await;
    assert_eq!(status, StatusCode::OK, "list response: {body}");
    assert_eq!(body["total_integrations"], 2);
    assert!(body["providers"]["google_nest"].is_object());
    assert!(body["providers"]["tp_link_kasa"].is_object());
}

#[tokio::test]
async fn get_integration_status_rejects_an_unknown_provider_and_returns_a_known_one() {
    let env = HaEnv::new().await;
    let (bad_status, bad_body) = json_request(
        &env,
        "GET",
        "/api/v1/ha/integrations/not-a-provider/status",
        None,
    )
    .await;
    assert_eq!(bad_status, StatusCode::BAD_REQUEST);
    assert!(bad_body.to_string().contains("Unknown vendor provider"));

    let (ok_status, ok_body) = json_request(
        &env,
        "GET",
        "/api/v1/ha/integrations/tp_link_kasa/status",
        None,
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "status response: {ok_body}");
    assert_eq!(ok_body["provider"], "tp_link_kasa");
    assert_eq!(ok_body["status"], "disconnected");
}

#[tokio::test]
async fn connect_integration_rejects_an_unknown_provider() {
    let env = HaEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/not-a-provider/connect",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("Unknown vendor provider"));
}

#[tokio::test]
async fn connect_kasa_succeeds_in_local_mode_without_credentials() {
    let env = HaEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/tp_link_kasa/connect",
        Some(serde_json::json!({ "mode": "local" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "connect response: {body}");
    assert_eq!(body["status"], "connected");
    assert_eq!(body["mode"], "local");
}

#[tokio::test]
async fn connect_kasa_rejects_cloud_mode_missing_username_or_password() {
    let env = HaEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/kasa/connect",
        Some(serde_json::json!({ "mode": "cloud", "username": "user@example.com" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "connect response: {body}");
}

#[tokio::test]
async fn connect_kasa_rejects_a_malformed_payload() {
    let env = HaEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/kasa/connect",
        Some(serde_json::json!({ "mode": 123 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("Invalid Kasa connect payload"));
}

#[tokio::test]
async fn connect_nest_succeeds_with_a_bare_access_token() {
    let env = HaEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/google_nest/connect",
        Some(serde_json::json!({ "access_token": "test-access-token" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "connect response: {body}");
    assert_eq!(body["status"], "connected");
    assert_eq!(body["ha_restarting"], false);
}

#[tokio::test]
async fn connect_nest_rejects_a_malformed_payload() {
    let env = HaEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/nest/connect",
        Some(serde_json::json!({ "access_token": 42 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("Invalid Nest connect payload"));
}

#[tokio::test]
async fn disconnect_integration_rejects_an_unknown_provider_and_succeeds_for_a_known_one() {
    let env = HaEnv::new().await;
    let (bad_status, _) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/not-a-provider/disconnect",
        None,
    )
    .await;
    assert_eq!(bad_status, StatusCode::BAD_REQUEST);

    let (ok_status, ok_body) = json_request(
        &env,
        "POST",
        "/api/v1/ha/integrations/tp_link_kasa/disconnect",
        None,
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "disconnect response: {ok_body}");
    assert_eq!(ok_body["status"], "disconnected");
}

#[tokio::test]
async fn get_nest_oauth_url_reports_unconfigured_without_client_credentials() {
    let env = HaEnv::new_uninitialized().await;
    let previous_client = std::env::var_os("SGX_NEST_CLIENT_ID");
    let previous_project = std::env::var_os("SGX_NEST_PROJECT_ID");
    std::env::remove_var("SGX_NEST_CLIENT_ID");
    std::env::remove_var("SGX_NEST_PROJECT_ID");

    let (status, body) = json_request(
        &env,
        "GET",
        "/api/v1/ha/integrations/google_nest/oauth/auth_url",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "oauth url response: {body}");
    assert_eq!(body["configured"], false);
    assert!(body["auth_url"]
        .as_str()
        .unwrap()
        .contains("nestservices.google.com"));

    if let Some(previous) = previous_client {
        std::env::set_var("SGX_NEST_CLIENT_ID", previous);
    }
    if let Some(previous) = previous_project {
        std::env::set_var("SGX_NEST_PROJECT_ID", previous);
    }
}

#[tokio::test]
async fn get_nest_oauth_url_reports_configured_with_client_credentials() {
    let env = HaEnv::new_uninitialized().await;
    let previous_client = std::env::var_os("SGX_NEST_CLIENT_ID");
    let previous_project = std::env::var_os("SGX_NEST_PROJECT_ID");
    std::env::set_var("SGX_NEST_CLIENT_ID", "test-client-id");
    std::env::set_var("SGX_NEST_PROJECT_ID", "test-project-id");

    let (status, body) = json_request(
        &env,
        "GET",
        "/api/v1/ha/integrations/google_nest/oauth/auth_url",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "oauth url response: {body}");
    assert_eq!(body["configured"], true);
    assert!(body["auth_url"]
        .as_str()
        .unwrap()
        .contains("test-client-id"));

    match previous_client {
        Some(previous) => std::env::set_var("SGX_NEST_CLIENT_ID", previous),
        None => std::env::remove_var("SGX_NEST_CLIENT_ID"),
    }
    match previous_project {
        Some(previous) => std::env::set_var("SGX_NEST_PROJECT_ID", previous),
        None => std::env::remove_var("SGX_NEST_PROJECT_ID"),
    }
}

#[tokio::test]
async fn nest_oauth_callback_reports_the_access_denied_error_from_google() {
    let env = HaEnv::new_uninitialized().await;
    let (status, body) = json_request(
        &env,
        "GET",
        "/api/v1/ha/integrations/google_nest/oauth/callback?error=access_denied",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("access denied"));
}

#[tokio::test]
async fn nest_oauth_callback_requires_a_code_parameter() {
    let env = HaEnv::new_uninitialized().await;
    let (status, body) = json_request(
        &env,
        "GET",
        "/api/v1/ha/integrations/google_nest/oauth/callback",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("Missing required 'code'"));
}
