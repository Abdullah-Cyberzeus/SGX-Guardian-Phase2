// Integration tests for the browser auth API handlers
// (src/api/handlers/auth.rs): signup, login, session lifecycle and profile
// self-service. Uses the shared wave_b_support fixture purely for its
// router/AppState wiring here -- these handlers don't need the Circle-owner
// VC bootstrap, but `Env::new()` sets it up regardless (harmless).

#[path = "wave_b_support/mod.rs"]
mod support;

use serde_json::json;

const PASSWORD: &str = "Correct Horse Battery Staple 42!";

#[tokio::test]
async fn signup_creates_the_initial_owner_and_a_session() {
    // Must run on a completely fresh Env: `signup` uses `create_initial_owner`,
    // which only succeeds while no user exists yet.
    let env = support::Env::new();
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/signup",
        None,
        Some(json!({
            "name": "First Owner",
            "email": "owner@example.com",
            "password": PASSWORD,
            "role": "admin",
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_eq!(body["role"], "admin");
}

#[tokio::test]
async fn signup_rejects_missing_fields_and_member_role() {
    let env = support::Env::new();
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/signup",
        None,
        Some(json!({"name": "", "email": "", "password": PASSWORD})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/signup",
        None,
        Some(json!({
            "name": "Someone",
            "email": "someone@example.com",
            "password": PASSWORD,
            "role": "member",
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn signup_returns_403_after_the_first_owner_exists() {
    let env = support::Env::new();
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/signup",
        None,
        Some(json!({
            "name": "First Owner",
            "email": "owner@example.com",
            "password": PASSWORD,
            "role": "admin",
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/signup",
        None,
        Some(json!({
            "name": "Second Owner",
            "email": "owner2@example.com",
            "password": PASSWORD,
            "role": "admin",
        })),
    )
    .await;
    // Once any user exists, `create_initial_owner` always fails with
    // "signup is only allowed before the first user is created", which the
    // handler maps to FORBIDDEN -- the CONFLICT branch is reserved for a
    // duplicate-email error against an *empty* user store, which can't
    // actually happen (an empty store has no email to collide with).
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn login_succeeds_with_correct_credentials_and_fails_with_wrong_password() {
    let env = support::Env::new();
    support::call(
        env.router(),
        "POST",
        "/api/v1/auth/signup",
        None,
        Some(json!({
            "name": "First Owner",
            "email": "owner@example.com",
            "password": PASSWORD,
            "role": "admin",
        })),
    )
    .await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({"email": "owner@example.com", "password": PASSWORD})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["user"]["email"], "owner@example.com");

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({"email": "owner@example.com", "password": "wrong-password"})),
    )
    .await;
    assert!(status.is_client_error(), "wrong password must be rejected");
}

#[tokio::test]
async fn session_returns_the_caller_and_401_without_a_token() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/auth/session",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true);

    let (status, _) = support::call(env.router(), "GET", "/api/v1/auth/session", None, None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_the_current_session() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/logout",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "logged_out");

    // The same (now-revoked) token can no longer authenticate.
    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/auth/session",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_all_sessions_reports_a_count() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/sessions/revoke-all",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["revokedSessions"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn refresh_session_issues_a_new_token_and_revokes_the_old_one() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/auth/session/refresh",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let new_token = body["token"].as_str().unwrap().to_string();
    assert_ne!(new_token, owner_token);

    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/auth/session",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "the pre-refresh token must be revoked"
    );

    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/auth/session",
        Some(&new_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn update_profile_changes_name_and_privacy_toggles() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, body) = support::call(
        env.router(),
        "PATCH",
        "/api/v1/auth/profile",
        Some(&owner_token),
        Some(json!({"name": "Renamed Owner", "hide_typing": true})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["name"], "Renamed Owner");
    assert_eq!(body["hide_typing"], true);
}
