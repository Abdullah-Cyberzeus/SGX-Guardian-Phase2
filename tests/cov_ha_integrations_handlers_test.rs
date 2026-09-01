// Integration tests for the Home Assistant vendor-integration handlers
// (src/api/handlers/ha_integrations.rs). `AppState::for_tests` never
// initializes an `IntegrationManager` (it's `None` by default), so every
// handler's "not initialized" 503 branch is real and reachable without any
// setup; reaching past it just requires writing a real `IntegrationManager`
// into `state.integration_manager` directly (a `pub` field), which is
// simpler than standing up a fake HTTP HA server.

#[path = "wave_b_support/mod.rs"]
mod support;

use serde_json::json;

async fn install_integration_manager(env: &support::Env) {
    let path = env
        .state
        .keys_dir
        .clone()
        .replace("keys", "integrations.json");
    let manager = sgx_guardian_client::integration::manager::IntegrationManager::new(&path);
    *env.state.integration_manager.write().await = Some(manager);
}

#[tokio::test]
async fn list_integrations_returns_503_when_manager_not_initialized() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/ha/integrations",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

#[tokio::test]
async fn list_integrations_returns_200_with_default_providers_once_initialized() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    install_integration_manager(&env).await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/ha/integrations",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
}

#[tokio::test]
async fn get_integration_status_rejects_unknown_provider_and_finds_known_ones() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    install_integration_manager(&env).await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/ha/integrations/not-a-real-vendor/status",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/ha/integrations/google_nest/status",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["provider"], "google_nest");
}

#[tokio::test]
async fn connect_integration_returns_503_when_manager_not_initialized() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/ha/integrations/google_nest/connect",
        Some(&owner_token),
        Some(json!({"access_token": "irrelevant"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn connect_integration_rejects_unknown_provider_and_bad_payloads() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    install_integration_manager(&env).await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/ha/integrations/not-a-real-vendor/connect",
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    // Kasa credentials require a mode (local/cloud); an empty payload fails
    // `KasaCredentials::validate()`.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/ha/integrations/tplink/connect",
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");

    // Unlike Kasa, `NestCredentials::validate()` doesn't require any field
    // to be present up front (client id/secret arrive via the OAuth flow
    // later) -- an empty payload is accepted and connects successfully.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/ha/integrations/google_nest/connect",
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "connected");
}

#[tokio::test]
async fn disconnect_integration_returns_503_when_manager_not_initialized_and_400_for_unknown_provider(
) {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/ha/integrations/google_nest/disconnect",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);

    install_integration_manager(&env).await;
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/ha/integrations/not-a-real-vendor/disconnect",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn disconnect_integration_succeeds_for_an_already_disconnected_provider() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    install_integration_manager(&env).await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/ha/integrations/tplink/disconnect",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "disconnected");
}

#[tokio::test]
async fn nest_oauth_auth_url_is_public_and_always_succeeds_with_demo_fallback_credentials() {
    // On the public-route allowlist (no bearer token needed). With no
    // `SGX_NEST_*` env vars configured in this sandbox, it still succeeds --
    // it falls back to hardcoded demo client/project IDs and just reports
    // `configured: false`, rather than ever failing.
    let env = support::Env::new();
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/ha/integrations/google_nest/oauth/auth_url",
        None,
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["configured"], false);
}

#[tokio::test]
async fn nest_oauth_callback_rejects_missing_code_and_surfaces_denied_error() {
    // Also public. Both branches below run before any real network call.
    let env = support::Env::new();
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/ha/integrations/google_nest/oauth/callback",
        None,
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/ha/integrations/google_nest/oauth/callback?error=access_denied",
        None,
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("access_denied"));
}
