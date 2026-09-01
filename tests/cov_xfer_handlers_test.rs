// Integration tests for the file-transfer API handlers
// (src/api/handlers/xfer.rs). Every handler resolves the caller's allowed
// Circle contacts via `local_active_circle_ids`, which needs the same
// bootstrapped Circle-owner identity call.rs/circle.rs's tests depend on --
// hence `wave_b_support::Env` here too, even for the owner-only tests below.

#[path = "wave_b_support/mod.rs"]
mod support;

use serde_json::json;

const CIRCLE: &str = "xfer-circle";

#[tokio::test]
async fn send_rejects_empty_peer_did() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/xfer/send",
        Some(&owner_token),
        Some(json!({"peer_did": "  "})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn send_rejects_neither_or_both_of_path_and_vault_id() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/xfer/send",
        Some(&owner_token),
        Some(json!({"peer_did": "did:guardian:someone"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/xfer/send",
        Some(&owner_token),
        Some(json!({
            "peer_did": "did:guardian:someone",
            "path": "/tmp/whatever",
            "vault_id": "urn:uuid:00000000-0000-0000-0000-000000000000",
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn send_rejects_missing_local_file_path() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/xfer/send",
        Some(&owner_token),
        Some(json!({
            "peer_did": "did:guardian:someone",
            "path": "/definitely/does/not/exist.bin",
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn send_forbids_member_targeting_a_peer_outside_their_circles() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "circle-a").await;
    env.create_circle(&owner_token, "circle-b").await;
    let (caller_token, _caller_did) = env.member_token("circle-a").await;
    let (_target_token, target_did) = env.member_token("circle-b").await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/xfer/send",
        Some(&caller_token),
        Some(json!({
            "peer_did": target_did,
            "path": "/tmp/whatever",
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_detail_and_cancel_handle_empty_and_unknown_transfers() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/xfer/transfers",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["count"], 0);

    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/xfer/transfers/does-not-exist",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/xfer/transfers/does-not-exist/cancel",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn inbox_is_empty_for_the_device_owner_with_nothing_queued() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/xfer/inbox",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["count"], 0);
}
