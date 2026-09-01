// Integration tests for the group-call API handlers
// (src/api/handlers/group_call.rs).
//
// Unlike call.rs's 1:1 local-browser-call path, `group_call::create` always
// calls `get_local_nebula_ip()` for the *host* participant unconditionally
// (even when every invitee is a local browser member), and `join`/`decline`/
// `leave`/`heartbeat`/`media_ready` all resolve the local Nebula IP before
// touching the group-session store at all. With no real Nebula overlay in
// this sandbox, that call deterministically fails -> every one of those
// handlers' *success* paths is unreachable here; what's real and tested
// below is every validation/conflict/not-found branch that runs before (or
// entirely without) that Nebula lookup.

#[path = "wave_b_support/mod.rs"]
mod support;

use serde_json::json;

const CIRCLE: &str = "group-call-circle";

#[tokio::test]
async fn active_returns_200_with_empty_groups_initially() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/group-calls/active",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["total"], 0);
}

#[tokio::test]
async fn create_returns_400_for_empty_media() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-calls",
        Some(&owner_token),
        Some(json!({"title": "Standup", "call_all": true, "media": []})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn create_returns_400_when_no_trusted_members_selected() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    // No trusted_peers.json seeded and no browser members registered:
    // `call_all` resolves to zero candidates before any Nebula lookup runs.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-calls",
        Some(&owner_token),
        Some(json!({"title": "Standup", "call_all": true, "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Select at least one trusted member"));
}

#[tokio::test]
async fn create_returns_503_when_nebula_unavailable_for_a_valid_local_target() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    // A real local browser member exists as a valid call_all target, so the
    // handler proceeds all the way to resolving the host's own Nebula IP --
    // which deterministically fails here.
    let (_member_token, _member_did) = env.member_token(CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-calls",
        Some(&owner_token),
        Some(json!({"title": "Standup", "call_all": true, "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

#[tokio::test]
async fn create_returns_409_when_a_one_to_one_call_is_already_active() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (initiator_token, _initiator_did) = env.member_token(CIRCLE).await;
    let (_receiver_token, receiver_did) = env.member_token(CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/calls/initiate",
        Some(&initiator_token),
        Some(json!({"target_peer_id": receiver_did, "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-calls",
        Some(&owner_token),
        Some(json!({"title": "Standup", "call_all": true, "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn join_decline_leave_and_heartbeat_return_503_without_a_nebula_overlay() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    for action in ["join", "decline", "leave", "heartbeat"] {
        let (status, body) = support::call(
            env.router(),
            "POST",
            &format!("/api/v1/group-call/does-not-exist/{action}"),
            Some(&owner_token),
            None,
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{action}: {body}"
        );
    }
}

#[tokio::test]
async fn media_ready_returns_503_without_a_nebula_overlay() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-call/does-not-exist/media-ready",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

#[tokio::test]
async fn moderate_returns_403_for_unknown_group() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-call/does-not-exist/moderate",
        Some(&owner_token),
        Some(json!({"action": "kick", "device_id": "did:guardian:someone"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn end_returns_404_for_unknown_group() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-call/does-not-exist/end",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn submit_signal_returns_400_for_unsupported_kind_and_404_for_unknown_group() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-call/does-not-exist/signal",
        Some(&owner_token),
        Some(json!({
            "target_device_id": "did:guardian:someone",
            "type": "hangup",
            "payload": {},
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-call/does-not-exist/signal",
        Some(&owner_token),
        Some(json!({
            "target_device_id": "did:guardian:someone",
            "type": "sdp_offer",
            "payload": {},
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signals_returns_404_for_unknown_group() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/group-call/does-not-exist/signals",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}
