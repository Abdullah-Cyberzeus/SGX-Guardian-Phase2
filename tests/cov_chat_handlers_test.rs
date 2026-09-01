// Integration tests for the chat API handlers (src/api/handlers/chat.rs).
//
// `chat::storage`'s base directory is a `once_cell::Lazy<String>` read from
// `CHAT_STORAGE_DIR` exactly once per process (see
// `tests/chat_host_integration.rs`'s file-level doc comment for the same
// constraint) -- so this file sets it a single time, before any test touches
// chat storage, to one shared temp directory for the whole binary. Every
// test below therefore uses distinct DIDs/circles so they never collide in
// that shared directory. Must run with `--test-threads=1` (this crate's
// convention for exactly this reason).

#[path = "wave_b_support/mod.rs"]
mod support;

use serde_json::json;
use std::sync::OnceLock;

const CIRCLE: &str = "chat-circle";

static CHAT_STORAGE: OnceLock<tempfile::TempDir> = OnceLock::new();

fn ensure_chat_storage() {
    CHAT_STORAGE.get_or_init(|| {
        let dir = tempfile::tempdir().expect("chat storage tempdir");
        std::env::set_var("CHAT_STORAGE_DIR", dir.path());
        dir
    });
}

#[tokio::test]
async fn send_message_rejects_neither_content_nor_attachment() {
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/chat/send",
        Some(&owner_token),
        Some(json!({
            "recipient_did": "did:guardian:someone",
            "is_group": false,
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn typing_succeeds_for_device_owner_caller() {
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/chat/typing",
        Some(&owner_token),
        Some(json!({
            "recipient_did": "did:guardian:someone",
            "is_group": false,
            "is_typing": true,
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ok");
}

// The next two tests exercise the route-scope gate in
// `authorization::member_required_scope` (neither `/typing` nor `/sync` is
// in its `/api/v1/chat/*` match arms, so member sessions are denied there
// unconditionally) rather than `ensure_member_contact_access`/
// `ensure_local_guardian_circle_access` -- see the comment on
// `get_history_allows_a_member_reading_a_fellow_circle_browser_members_p2p_history`
// below for where those are actually exercised.
#[tokio::test]
async fn typing_forbids_a_member_messaging_a_non_contact_directly() {
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (member_token, _did) = env.member_token(CIRCLE).await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/chat/typing",
        Some(&member_token),
        Some(json!({
            "recipient_did": "did:guardian:unrelated-guardian",
            "is_group": false,
            "is_typing": true,
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_history_allows_a_member_reading_a_fellow_circle_browser_members_p2p_history() {
    // `/api/v1/chat/typing` and `/api/v1/chat/sync` aren't in
    // `authorization::member_required_scope`'s `/api/v1/chat/*` match arms at
    // all, so a member session is denied at the route-scope gate before
    // `ensure_member_contact_access`/`ensure_local_guardian_circle_access`
    // ever run -- no member call to either route can succeed. `/chat/history`
    // (GET) *is* scoped to `MESSAGES_READ` for members, so it's used here
    // instead to exercise the actual contact-access success path.
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (reader_token, _reader_did) = env.member_token(CIRCLE).await;
    let (_peer_token, peer_did) = env.member_token(CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/chat/history?peer_did={peer_did}"),
        Some(&reader_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["messages"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn typing_forbids_group_message_to_a_circle_the_guardian_does_not_host() {
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (member_token, _did) = env.member_token(CIRCLE).await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/chat/typing",
        Some(&member_token),
        Some(json!({
            "recipient_did": "some-other-circle-not-hosted-here",
            "is_group": true,
            "is_typing": true,
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_history_requires_peer_did_or_group_id() {
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/chat/history",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_history_returns_empty_p2p_history_for_owner() {
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/chat/history?peer_did=did:guardian:nobody-yet",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["messages"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_history_forbids_a_member_reading_a_circle_they_are_not_scoped_to() {
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "circle-history-a").await;
    env.create_circle(&owner_token, "circle-history-b").await;
    let (member_token, _did) = env.member_token("circle-history-a").await;

    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/chat/history?group_id=circle-history-b",
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mark_as_read_returns_400_when_conversation_history_is_missing() {
    ensure_chat_storage();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/chat/read",
        Some(&owner_token),
        Some(json!({
            "message_id": "does-not-exist",
            "original_sender_did": "did:guardian:nobody-yet",
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
}
