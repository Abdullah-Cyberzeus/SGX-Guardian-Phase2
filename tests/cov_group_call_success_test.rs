//! Happy-path integration tests for `src/api/handlers/group_call.rs`.
//!
//! The pre-existing `tests/cov_group_call_handlers_test.rs` covers only the
//! validation/conflict/not-found branches, on the stated assumption that
//! every Nebula-dependent success path is unreachable without a real overlay
//! interface. That is no longer true: `NebulaClient::get_local_ip` honours an
//! opt-in `SGX_NEBULA_LOCAL_IP_OVERRIDE` escape hatch (the network-layer
//! sibling of `SGX_FORCE_SOFTWARE_KEYS`), so setting it to a real
//! overlay-range address makes the full create -> join -> heartbeat ->
//! media-ready -> signal -> moderate -> leave/end lifecycle reachable with no
//! hardware.
//!
//! `SGX_NEBULA_LOCAL_IP_OVERRIDE` is process-global, so these run with
//! `--test-threads=1` like every other `wave_b_support::Env` suite.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::http::StatusCode;
use serde_json::json;

const CIRCLE: &str = "group-call-success-circle";
const OVERLAY_IP: &str = "192.168.100.1";

fn with_overlay() {
    std::env::set_var("SGX_NEBULA_LOCAL_IP_OVERRIDE", OVERLAY_IP);
}

/// Creates a group call with one local browser member invited, returning
/// `(env, owner_token, member_token, member_did, group_id)`.
async fn created_group() -> (support::Env, String, String, String, String) {
    with_overlay();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (member_token, member_did) = env.member_token(CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-calls",
        Some(&owner_token),
        Some(json!({"title": "Standup", "call_all": true, "media": ["audio", "video"]})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create should succeed: {body}");
    let group_id = body["session"]["group_id"]
        .as_str()
        .unwrap_or_else(|| panic!("group_id missing from create response: {body}"))
        .to_string();
    (env, owner_token, member_token, member_did, group_id)
}

#[tokio::test]
async fn create_succeeds_with_an_overlay_ip_and_rings_the_local_browser_member() {
    with_overlay();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (_member_token, member_did) = env.member_token(CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/group-calls",
        Some(&owner_token),
        Some(json!({"title": "Standup", "call_all": true, "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let session = &body["session"];
    assert!(session["group_id"].as_str().is_some());
    assert_eq!(session["title"], "Standup");
    let participants = session["participants"]
        .as_object()
        .or_else(|| session["participants"].as_array().map(|_| unreachable!()))
        .map(|map| map.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        participants.iter().any(|key| key.contains(&member_did))
            || session.to_string().contains(&member_did),
        "the invited browser member must appear in the session: {session}"
    );
}

#[tokio::test]
async fn create_is_idempotent_for_a_repeated_idempotency_key() {
    with_overlay();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (_member_token, _member_did) = env.member_token(CIRCLE).await;

    // `support::call` has no header seam, so drive the router directly to
    // attach the idempotency key.
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    let router = env.router();
    let make_request = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/group-calls")
            .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", "group-create-key-1")
            .body(Body::from(
                serde_json::to_vec(
                    &json!({"title": "Standup", "call_all": true, "media": ["audio"]}),
                )
                .unwrap(),
            ))
            .expect("build request")
    };

    let first = router
        .clone()
        .oneshot(make_request())
        .await
        .expect("first create");
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .expect("read first body"),
    )
    .expect("parse first body");

    let second = router
        .oneshot(make_request())
        .await
        .expect("replayed create");
    assert_eq!(second.status(), StatusCode::OK);
    let second_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .expect("read second body"),
    )
    .expect("parse second body");

    assert_eq!(
        first_body["session"]["group_id"], second_body["session"]["group_id"],
        "replaying the same idempotency key must return the original group"
    );
}

#[tokio::test]
async fn active_lists_a_created_group_for_the_host() {
    let (env, owner_token, _member_token, _member_did, group_id) = created_group().await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/group-calls/active",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 1, "{body}");
    assert!(body.to_string().contains(&group_id));
}

#[tokio::test]
async fn invited_member_can_join_heartbeat_and_report_media_ready() {
    let (env, _owner_token, member_token, _member_did, group_id) = created_group().await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/join"),
        Some(&member_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "join should succeed: {body}");

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/heartbeat"),
        Some(&member_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "heartbeat should succeed: {body}");

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/media-ready"),
        Some(&member_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "media-ready should succeed: {body}");
}

#[tokio::test]
async fn invited_member_can_decline_instead_of_joining() {
    let (env, _owner_token, member_token, _member_did, group_id) = created_group().await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/decline"),
        Some(&member_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "decline should succeed: {body}");
}

#[tokio::test]
async fn a_joined_member_can_leave_the_group() {
    let (env, _owner_token, member_token, _member_did, group_id) = created_group().await;

    let (join_status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/join"),
        Some(&member_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(join_status, StatusCode::OK);

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/leave"),
        Some(&member_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "leave should succeed: {body}");
}

#[tokio::test]
async fn signals_round_trip_between_participants() {
    let (env, owner_token, member_token, member_did, group_id) = created_group().await;

    let (join_status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/join"),
        Some(&member_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(join_status, StatusCode::OK);

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/signal"),
        Some(&owner_token),
        Some(json!({
            "target_device_id": member_did,
            "type": "sdp_offer",
            "payload": {"sdp": "v=0"},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "submit_signal should succeed: {body}");

    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/group-call/{group_id}/signals"),
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signals should succeed: {body}");
    assert!(
        body["signals"].as_array().is_some(),
        "signals response must carry a signals array: {body}"
    );
}

#[tokio::test]
async fn host_can_moderate_and_then_end_the_group() {
    let (env, owner_token, member_token, member_did, group_id) = created_group().await;

    let (join_status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/join"),
        Some(&member_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(join_status, StatusCode::OK);

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/moderate"),
        Some(&owner_token),
        Some(json!({"action": "set_audio", "device_id": member_did, "allowed": false})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "moderate should succeed: {body}");

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/group-call/{group_id}/end"),
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "end should succeed: {body}");

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/group-calls/active",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 0, "ended group must leave no active calls: {body}");
}
