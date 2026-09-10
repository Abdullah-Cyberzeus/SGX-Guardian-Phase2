// Integration tests for the browser auth API handlers
// (src/api/handlers/auth.rs): signup, login, session lifecycle and profile
// self-service. Uses the shared wave_b_support fixture purely for its
// router/AppState wiring here -- these handlers don't need the Circle-owner
// VC bootstrap, but `Env::new()` sets it up regardless (harmless).

#[path = "wave_b_support/mod.rs"]
mod support;

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
