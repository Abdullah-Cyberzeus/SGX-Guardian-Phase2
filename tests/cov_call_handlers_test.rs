// Integration tests for the call API handlers (src/api/handlers/call.rs).
// Uses tower::ServiceExt::oneshot against the real router + AppState, no
// mocked HTTP layer. Local (same-node) browser-member calls are used for the
// success paths because they never touch the real Nebula overlay, which is
// unavailable in this sandbox; the legacy `/api/v1/call/*` endpoints are
// exercised for their Nebula-unavailable and not-found/forbidden branches,
// which are deterministic without a real overlay. Every `/api/v1/call*`
// route requires a bearer token (none of them are in the auth middleware's
// public-route allowlist), so every request below carries one.

#[path = "wave_b_support/mod.rs"]
mod support;

use serde_json::json;

const CIRCLE: &str = "call-test-circle";

#[tokio::test]
async fn full_local_browser_call_lifecycle_reaches_connected_and_ends() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (initiator_token, _initiator_did) = env.member_token(CIRCLE).await;
    let (receiver_token, receiver_did) = env.member_token(CIRCLE).await;

    // Initiate: A calls B, both are local browser members -> local call path.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/calls/initiate",
        Some(&initiator_token),
        Some(json!({"target_peer_id": receiver_did, "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "offer_received");
    let session_id = body["session_id"].as_str().expect("session_id").to_string();

    // A second concurrent initiate from the same actor is rejected.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/calls/initiate",
        Some(&initiator_token),
        Some(json!({"target_peer_id": receiver_did, "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");

    // Status is visible before acceptance.
    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/call/{session_id}/status"),
        Some(&initiator_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");

    // Wrong actor cannot accept.
    let (status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/accept"),
        Some(&initiator_token),
        Some(json!({"accepted_media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

    // Receiver accepts.
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/accept"),
        Some(&receiver_token),
        Some(json!({"accepted_media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "accepted");

    // Non-participant cannot list signals.
    let (outsider_token, _outsider_did) = env.member_token(CIRCLE).await;
    let (status, _) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/call/{session_id}/signals"),
        Some(&outsider_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

    // Unsupported signal kind is rejected.
    let (status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/signal"),
        Some(&initiator_token),
        Some(json!({"type": "hangup", "payload": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    // Initiator sends an SDP offer -> Accepted moves to MediaNegotiation.
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/signal"),
        Some(&initiator_token),
        Some(json!({"type": "sdp_offer", "payload": {"sdp": "v=0"}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "sent");

    // Replaying the same idempotent operation_id short-circuits to "already_sent".
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/signal"),
        Some(&initiator_token),
        Some(json!({"type": "sdp_offer", "payload": {"sdp": "v=0"}, "operation_id": "dup-1"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/signal"),
        Some(&initiator_token),
        Some(json!({"type": "sdp_offer", "payload": {"sdp": "v=0"}, "operation_id": "dup-1"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "already_sent");

    // Receiver can list the queued signal.
    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/call/{session_id}/signals"),
        Some(&receiver_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(!body["signals"]
        .as_array()
        .expect("signals array")
        .is_empty());

    // Quality reports are refused before the call is connected.
    let (status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/quality"),
        Some(&owner_token),
        Some(json!({"rtt_ms": 20})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);

    // Initiator reports media ready first -> still waiting for peer.
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/media-ready"),
        Some(&initiator_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "waiting_for_peer");

    // Receiver reports media ready -> both sides ready, call connects.
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/media-ready"),
        Some(&receiver_token),
        Some(json!({"dtls_fingerprint": "AA:BB:CC"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "connected");

    // Now a quality report is accepted.
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/quality"),
        Some(&owner_token),
        Some(json!({"rtt_ms": 42, "jitter_ms": 3, "packet_loss_percent": 0.5, "codec": "opus"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "recorded");

    // The connected session shows up as active.
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/calls/active",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["calls"]
        .as_array()
        .expect("calls array")
        .iter()
        .any(|call| call["session_id"] == session_id));

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/calls",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["total"].as_u64().unwrap() >= 1);

    // A non-participant cannot end the call.
    let (status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/end"),
        Some(&outsider_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

    // The initiator ends the call.
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/end"),
        Some(&initiator_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ended");

    // `CallHistoryStore` writes to the hardcoded, non-overridable
    // `/var/log/sgx-guardian/call_history.json` (no env var or `AppState`
    // field points elsewhere), which this sandbox cannot create -> the
    // record never actually persists here. This still exercises the member
    // history-filtering branch end-to-end (role check, own-DID resolution,
    // `member_account_created_at` lookup), just against an empty history.
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/calls/history",
        Some(&initiator_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["calls"].as_array().is_some());

    // The session is now gone from the active list.
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/calls/active",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(!body["calls"]
        .as_array()
        .expect("calls array")
        .iter()
        .any(|call| call["session_id"] == session_id));
}

#[tokio::test]
async fn browser_call_rejects_empty_target_and_empty_media() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (token, _did) = env.member_token(CIRCLE).await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/calls/initiate",
        Some(&token),
        Some(json!({"target_peer_id": "", "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/calls/initiate",
        Some(&token),
        Some(json!({"target_peer_id": "did:guardian:someone", "media": []})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn browser_call_forbidden_when_target_is_not_a_trusted_mesh_peer() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (caller_token, _caller_did) = env.member_token(CIRCLE).await;

    // `target_did` is neither this node nor a registered browser member, so
    // `initiate_browser_call` falls through to the trusted-mesh-peer lookup;
    // with no `trusted_peers.json` seeded, that lookup deterministically
    // fails and the request is rejected before any session is created.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/calls/initiate",
        Some(&caller_token),
        Some(json!({"target_peer_id": "did:guardian:unregistered-peer", "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("not in the trusted registry"));
}

#[tokio::test]
async fn reject_browser_call_ends_the_local_session() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (initiator_token, _initiator_did) = env.member_token(CIRCLE).await;
    let (receiver_token, receiver_did) = env.member_token(CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/calls/initiate",
        Some(&initiator_token),
        Some(json!({"target_peer_id": receiver_did, "media": ["audio"]})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let session_id = body["session_id"].as_str().unwrap().to_string();

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/call/{session_id}/reject"),
        Some(&receiver_token),
        Some(json!({"reason": "busy"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "rejected");

    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/call/{session_id}/status"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["state"], "ended");
    assert_eq!(body["terminal"], true);
}

#[tokio::test]
async fn call_status_returns_404_for_unknown_session() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/call/does-not-exist/status",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn legacy_initiate_call_rejects_empty_device_ids() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/call/initiate",
        Some(&owner_token),
        Some(json!({
            "initiator_device_id": "",
            "initiator_virtual_id": "v1",
            "receiver_device_id": "device-2",
            "receiver_virtual_id": "v2",
            "receiver_nebula_ip": "192.168.100.2",
            "requested_media": ["audio"],
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn legacy_initiate_call_fails_when_nebula_overlay_unavailable() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    // Valid device ids, but there is no real Nebula overlay in this sandbox,
    // so `get_local_nebula_ip` deterministically fails.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/call/initiate",
        Some(&owner_token),
        Some(json!({
            "initiator_device_id": "device-1",
            "initiator_virtual_id": "v1",
            "receiver_device_id": "device-2",
            "receiver_virtual_id": "v2",
            "receiver_nebula_ip": "192.168.100.2",
            "requested_media": ["audio"],
        })),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{body}"
    );
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Nebula overlay unavailable"));
}

#[tokio::test]
async fn legacy_accept_reject_end_return_404_for_unknown_session() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/call/accept",
        Some(&owner_token),
        Some(json!({
            "session_id": "missing",
            "device_id": "device-2",
            "virtual_id": "v2",
            "accepted_media": ["audio"],
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/call/reject",
        Some(&owner_token),
        Some(json!({
            "session_id": "missing",
            "device_id": "device-2",
            "reason": "busy",
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/call/end",
        Some(&owner_token),
        Some(json!({"session_id": "missing"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn legacy_accept_call_conflicts_without_nebula_endpoint_for_local_session() {
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
    let session_id = body["session_id"].as_str().unwrap().to_string();

    // The legacy endpoint requires the caller's `device_id` to equal the
    // stored receiver device id (`receiver_did` here), and a locally created
    // browser session never populates `initiator_nebula_ip` -> CONFLICT.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/call/accept",
        Some(&owner_token),
        Some(json!({
            "session_id": session_id,
            "device_id": receiver_did,
            "virtual_id": receiver_did,
            "accepted_media": ["audio"],
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Nebula address is unavailable"));
}

#[tokio::test]
async fn legacy_end_call_ends_a_local_session_without_peer_notification() {
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
    let session_id = body["session_id"].as_str().unwrap().to_string();

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/call/end",
        Some(&owner_token),
        Some(json!({"session_id": session_id})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ended");
    assert_eq!(body["peer_notified"], false);
}
