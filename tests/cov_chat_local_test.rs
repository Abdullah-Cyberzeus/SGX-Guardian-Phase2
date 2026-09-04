//! Same-Guardian chat delivery for `src/api/handlers/chat.rs`.
//!
//! The pre-existing `tests/cov_chat_handlers_test.rs` covers the validation and
//! authorization rejections on `/send`, `/typing`, `/read` and `/history`, and
//! `tests/chat_host_integration.rs` exercises the transport layer. Neither
//! drives a message that is actually *accepted*, because both sides of a normal
//! conversation live on different Guardians.
//!
//! There are two exceptions that need no peer at all, and `send_message` names
//! them itself (chat.rs:281-283): a browser member addressing this Guardian's
//! own DID, and this Guardian addressing one of its own browser members. Both
//! are `is_local_direct`, so the whole accept → persist → mark-read → history
//! path runs in-process. The shared `wave_b_support::Env` plus the PWA
//! enrollment flow produces exactly that pair of identities.
//!
//! `Env` sets process-global env vars; run with `--test-threads=1`.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

const PASSWORD: &str = "Sup3rSecret!Passphrase";

/// `chat::storage`'s root is a process-wide `Lazy`, so it can only be pointed
/// somewhere writable once, before the first message is stored. Its default
/// (`/var/lib/sgx-guardian/chat`) is not writable here. The directory is
/// therefore shared by every test in this binary, which is why each fixture
/// takes its own Circle id — group conversations are keyed by that id.
fn chat_storage_root() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    static mut KEEP_ALIVE: Option<tempfile::TempDir> = None;
    ONCE.call_once(|| {
        let dir = tempfile::tempdir().expect("chat storage tempdir");
        std::env::set_var("CHAT_STORAGE_DIR", dir.path());
        // Kept for the lifetime of the process so the directory is not removed
        // while the storage layer still points at it.
        unsafe { KEEP_ALIVE = Some(dir) };
    });
}

struct Chat {
    env: support::Env,
    circle: String,
    owner_token: String,
    guardian_did: String,
    member_token: String,
    member_did: String,
}

/// Bootstraps an owner, a Circle, and one approved browser member — the two
/// identities that can exchange local direct messages.
async fn chat_fixture(circle: &str) -> Chat {
    chat_storage_root();
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, circle).await;

    let (status, onboarding) =
        support::call(env.router(), "GET", "/api/v1/pwa/onboarding", None, None).await;
    assert_eq!(status, StatusCode::OK, "{onboarding}");
    let fingerprint = onboarding["fingerprint"].as_str().expect("fingerprint");
    let guardian_did = onboarding["guardianDid"]
        .as_str()
        .expect("guardianDid")
        .to_string();

    let (status, minted) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{circle}/member-invites"),
        Some(&owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint should succeed: {minted}");
    let claim = minted["link"]
        .as_str()
        .and_then(|link| link.split_once("?member_invite="))
        .map(|(_, claim)| claim.to_string())
        .expect("claim in link");
    let approval_id = minted["enrollment"]["approvalId"]
        .as_str()
        .expect("approvalId")
        .to_string();

    let (status, joined) = support::call(
        env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(json!({
            "name": "Chat Member",
            "email": "chat@example.test",
            "password": PASSWORD,
            "inviteToken": claim,
            "acceptedFingerprint": fingerprint,
            "fingerprintConfirmed": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "join should succeed: {joined}");
    let member_token = joined["token"].as_str().expect("token").to_string();
    let member_did = joined["browserMemberDid"]
        .as_str()
        .expect("browserMemberDid")
        .to_string();

    let (status, approved) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{circle}/member-enrollments/{approval_id}/approve"),
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve should succeed: {approved}");

    Chat {
        env,
        circle: circle.to_string(),
        owner_token,
        guardian_did,
        member_token,
        member_did,
    }
}

async fn send(chat: &Chat, token: &str, body: Value) -> (StatusCode, Value) {
    support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/send",
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn a_browser_member_can_send_a_direct_message_to_this_guardian() {
    let chat = chat_fixture("chat-direct-inbound").await;

    let (status, body) = send(
        &chat,
        &chat.member_token,
        json!({
            "recipient_did": chat.guardian_did,
            "content": "hello from the browser",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "send should be accepted: {body}");
    assert!(
        body["message_id"].as_str().is_some_and(|id| !id.is_empty()),
        "{body}"
    );
    // The local-direct return (chat.rs:628-638) deliberately answers with an
    // empty signature — there is no outbound envelope to sign — and reuses the
    // `DeliveredToRemoteGuardian` status string to mean "handed over", since
    // the recipient is this Guardian itself.
    assert_eq!(body["signature_base64"], "", "{body}");
    assert_eq!(body["status"], "delivered_to_remote_guardian", "{body}");
}

#[tokio::test]
async fn this_guardian_can_send_a_direct_message_to_its_own_browser_member() {
    let chat = chat_fixture("chat-direct-outbound").await;

    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": chat.member_did,
            "content": "hello from the Guardian",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "send should be accepted: {body}");
    assert!(body["message_id"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn a_local_conversation_round_trips_through_history_for_both_participants() {
    let chat = chat_fixture("chat-roundtrip").await;

    let (status, sent) = send(
        &chat,
        &chat.member_token,
        json!({
            "recipient_did": chat.guardian_did,
            "content": "first",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let message_id = sent["message_id"].as_str().expect("message_id").to_string();

    // The sender sees it in their own conversation with the Guardian.
    let (status, body) = support::call(
        chat.env.router(),
        "GET",
        &format!("/api/v1/chat/history?peer_did={}", chat.guardian_did),
        Some(&chat.member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history should succeed: {body}");
    let messages = body["messages"].as_array().expect("messages");
    assert!(
        messages
            .iter()
            .any(|message| message["message_id"] == message_id.as_str()),
        "the sent message must appear in history: {body}"
    );

    // ...and so does the Guardian, reading the same pair conversation.
    let (status, body) = support::call(
        chat.env.router(),
        "GET",
        &format!("/api/v1/chat/history?peer_did={}", chat.member_did),
        Some(&chat.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history should succeed: {body}");
    assert!(
        body["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .any(|message| message["message_id"] == message_id.as_str()),
        "both participants read the same conversation: {body}"
    );
}

#[tokio::test]
async fn history_paginates_with_after_seq_and_limit() {
    let chat = chat_fixture("chat-pagination").await;

    for index in 0..3 {
        let (status, body) = send(
            &chat,
            &chat.member_token,
            json!({
                "recipient_did": chat.guardian_did,
                "content": format!("message {index}"),
                "is_group": false,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let (status, body) = support::call(
        chat.env.router(),
        "GET",
        &format!("/api/v1/chat/history?peer_did={}&limit=2", chat.guardian_did),
        Some(&chat.member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page = body["messages"].as_array().expect("messages");
    assert!(page.len() <= 2, "limit must be honoured: {body}");

    // Reading past the end returns nothing rather than failing.
    let (status, body) = support::call(
        chat.env.router(),
        "GET",
        &format!(
            "/api/v1/chat/history?peer_did={}&after_seq=100000",
            chat.guardian_did
        ),
        Some(&chat.member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["messages"].as_array().expect("messages").is_empty(),
        "{body}"
    );
}

#[tokio::test]
async fn a_replayed_message_id_returns_the_original_message_instead_of_a_duplicate() {
    let chat = chat_fixture("chat-replay").await;

    let body = json!({
        "recipient_did": chat.guardian_did,
        "content": "retry me",
        "is_group": false,
        "message_id": "client-generated-id-1",
    });

    let (first_status, first) = send(&chat, &chat.member_token, body.clone()).await;
    assert_eq!(first_status, StatusCode::OK, "{first}");
    let (second_status, second) = send(&chat, &chat.member_token, body).await;
    assert_eq!(second_status, StatusCode::OK, "{second}");
    assert_eq!(
        first["message_id"], second["message_id"],
        "a replayed send must not create a second message"
    );

    let (status, history) = support::call(
        chat.env.router(),
        "GET",
        &format!("/api/v1/chat/history?peer_did={}", chat.guardian_did),
        Some(&chat.member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    let matching = history["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .filter(|message| message["message_id"] == "client-generated-id-1")
        .count();
    assert_eq!(matching, 1, "exactly one stored copy: {history}");
}

#[tokio::test]
async fn a_group_message_to_the_circle_is_accepted_and_readable() {
    let chat = chat_fixture("chat-group").await;

    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": chat.circle,
            "content": "hello everyone",
            "is_group": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group send should be accepted: {body}");
    let message_id = body["message_id"].as_str().expect("message_id").to_string();

    let (status, body) = support::call(
        chat.env.router(),
        "GET",
        &format!("/api/v1/chat/history?group_id={}", chat.circle),
        Some(&chat.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group history should succeed: {body}");
    assert!(
        body["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .any(|message| message["message_id"] == message_id.as_str()),
        "{body}"
    );
}

#[tokio::test]
async fn a_locally_delivered_message_can_be_marked_as_read() {
    let chat = chat_fixture("chat-read").await;

    let (status, sent) = send(
        &chat,
        &chat.member_token,
        json!({
            "recipient_did": chat.guardian_did,
            "content": "please read me",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let message_id = sent["message_id"].as_str().expect("message_id").to_string();

    let (status, body) = support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/read",
        Some(&chat.owner_token),
        Some(json!({
            "message_id": message_id,
            "original_sender_did": chat.member_did,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mark-as-read should succeed: {body}");
    assert_eq!(body["message_id"], message_id, "{body}");
}

#[tokio::test]
async fn typing_notifications_are_accepted_for_a_local_peer_and_for_the_circle() {
    let chat = chat_fixture("chat-typing").await;

    for (label, body) in [
        (
            "direct",
            json!({
                "recipient_did": chat.guardian_did,
                "is_group": false,
                "is_typing": true,
            }),
        ),
        (
            "direct stop",
            json!({
                "recipient_did": chat.guardian_did,
                "is_group": false,
                "is_typing": false,
            }),
        ),
        (
            "group",
            json!({
                "recipient_did": chat.circle,
                "is_group": true,
                "is_typing": true,
            }),
        ),
    ] {
        let (status, response) = support::call(
            chat.env.router(),
            "POST",
            "/api/v1/chat/typing",
            Some(&chat.owner_token),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}: {response}");
    }

    // A browser member's session does not carry the scope this route requires,
    // so the same call is refused for them.
    let (status, response) = support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/typing",
        Some(&chat.member_token),
        Some(json!({
            "recipient_did": chat.guardian_did,
            "is_group": false,
            "is_typing": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
}

/// Uploads a real chat attachment through `/api/v1/chat/upload` and returns its
/// id. `axum::extract::Multipart` cannot be constructed synthetically, so the
/// body is hand-built — same technique as `tests/cov_chat_attachments_test.rs`.
async fn upload_attachment(chat: &Chat, token: &str, filename: &str) -> String {
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    let boundary = "cov-chat-local-boundary";
    let content = b"attachment payload";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/chat/upload")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("build upload request");
    let response = chat
        .env
        .router()
        .oneshot(request)
        .await
        .expect("upload response");
    assert_eq!(response.status(), StatusCode::OK, "upload should succeed");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read upload body");
    let parsed: Value = serde_json::from_slice(&bytes).expect("parse upload response");
    parsed["attachment_id"]
        .as_str()
        .expect("attachment_id")
        .to_string()
}

/// An attachment is uploaded before its destination is known, so `send_message`
/// has to bind it afterwards: a direct message records the recipient DID on the
/// Vault record, a group message moves the record into that Circle's namespace.
/// Both paths run entirely locally.
#[tokio::test]
async fn an_uploaded_attachment_is_bound_to_its_conversation_on_send() {
    let chat = chat_fixture("chat-attach-bind").await;
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", vault_dir.path());

    // Direct: the record stays in the Personal namespace and gains a recipient.
    let direct_id = upload_attachment(&chat, &chat.owner_token, "direct.txt").await;
    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": chat.member_did,
            "attachment_id": direct_id,
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "direct attachment send: {body}");

    // Group: the record is moved into the Circle's namespace so Circle
    // membership authorizes access to it.
    let group_id = upload_attachment(&chat, &chat.owner_token, "group.txt").await;
    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": chat.circle,
            "attachment_id": group_id,
            "is_group": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group attachment send: {body}");
}

#[tokio::test]
async fn an_attachment_uploaded_by_someone_else_cannot_be_attached() {
    let chat = chat_fixture("chat-attach-foreign").await;
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", vault_dir.path());

    // Uploaded by the Guardian, then attached by the browser member.
    let attachment_id = upload_attachment(&chat, &chat.owner_token, "not-yours.txt").await;
    let (status, body) = send(
        &chat,
        &chat.member_token,
        json!({
            "recipient_did": chat.guardian_did,
            "attachment_id": attachment_id,
            "is_group": false,
        }),
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "a member must not be able to attach the Guardian's file: {status} {body}"
    );
}

/// Writes a trusted-peer registry for this Guardian. The entries are real
/// registry shapes; none of the addresses is listening, so every outbound leg
/// fails deterministically — which is the point: the handler's peer-selection
/// and dispatch logic runs without a second Guardian.
fn write_peer_registry(chat: &Chat, peers: Value) {
    let path = std::path::Path::new(&chat.env.state.log_dir_primary).join("trusted_peers.json");
    std::fs::create_dir_all(path.parent().expect("registry parent")).expect("create log dir");
    std::fs::write(&path, serde_json::to_vec(&peers).expect("serialize registry"))
        .expect("write trusted peer registry");
}

/// Every filtering branch of `trigger_sync`'s peer loop in one registry: an
/// untrusted peer, one with neither DID nor peer id, one with no address, one
/// with an unparseable address, one identified only by `peer_id` (so its DID is
/// derived), and one fully-specified peer.
#[tokio::test]
async fn trigger_sync_selects_only_trusted_peers_with_a_usable_address() {
    let chat = chat_fixture("chat-sync-peers").await;

    write_peer_registry(
        &chat,
        json!([
            {"peer_id": "untrusted", "status": "unknown", "ip": "127.0.0.1", "did": "did:guardian:untrusted"},
            {"status": "verified", "ip": "127.0.0.1"},
            {"peer_id": "no-address", "status": "verified", "did": "did:guardian:no-address"},
            {"peer_id": "bad-address", "status": "verified", "ip": "not-an-ip", "did": "did:guardian:bad-address"},
            {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1"},
            {"peer_id": "nodeC", "status": "trusted", "ip": "127.0.0.2", "did": "did:guardian:nodec"}
        ]),
    );

    let (status, body) = support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/sync",
        Some(&chat.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sync should succeed: {body}");
    assert_eq!(
        body["peers_synced"].as_u64(),
        Some(2),
        "only the two usable trusted peers are synced: {body}"
    );
}

/// The non-local dispatch path: a recipient that resolves to a trusted peer is
/// accepted and queued for the background gRPC push (which then fails against
/// the dead address, leaving the message pending — the real offline behaviour).
#[tokio::test]
async fn a_message_to_a_trusted_remote_peer_is_accepted_and_left_pending() {
    let chat = chat_fixture("chat-remote").await;
    write_peer_registry(
        &chat,
        json!([
            {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:remote-peer"}
        ]),
    );

    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": "did:guardian:remote-peer",
            "content": "over the overlay",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "remote send should be accepted: {body}");
    // The peer resolved and the message was queued for the background gRPC
    // push. Nothing is listening at that address, so the push fails and the
    // message stays where the handler left it — accepted by this Guardian but
    // not yet delivered. That is the real offline-peer behaviour.
    assert_eq!(body["status"], "accepted_by_guardian", "{body}");
    assert!(body["message_id"].as_str().is_some(), "{body}");
}

/// A peer can also be addressed by its bare `peer_id` label rather than a DID.
#[tokio::test]
async fn a_message_addressed_by_peer_id_resolves_to_the_same_trusted_peer() {
    let chat = chat_fixture("chat-remote-by-id").await;
    write_peer_registry(
        &chat,
        json!([{"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1"}]),
    );

    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": "nodeB",
            "content": "addressed by label",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_message_to_an_untrusted_or_addressless_peer_is_refused() {
    let chat = chat_fixture("chat-remote-untrusted").await;
    write_peer_registry(
        &chat,
        json!([
            {"peer_id": "nodeB", "status": "unknown", "ip": "127.0.0.1", "did": "did:guardian:untrusted-peer"},
            {"peer_id": "nodeC", "status": "verified", "did": "did:guardian:addressless-peer"}
        ]),
    );

    // Present in the registry, but has not passed mutual attestation.
    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": "did:guardian:untrusted-peer",
            "content": "hello?",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Trusted, but the registry entry carries no address to send to.
    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": "did:guardian:addressless-peer",
            "content": "hello?",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
}

/// `send_message` merges the per-node registry into the global one, adding any
/// peer whose DID the global file does not already carry.
#[tokio::test]
async fn the_per_node_peer_registry_is_merged_into_the_global_one() {
    let chat = chat_fixture("chat-registry-merge").await;
    write_peer_registry(
        &chat,
        json!([{"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:already-global"}]),
    );

    // One entry duplicating the global list (skipped) and one new (merged in),
    // plus one with no DID at all (skipped).
    let per_node = std::path::Path::new(&chat.env.state.log_dir_primary)
        .join(format!("trusted_peers_{}.json", chat.env.state.node_id));
    std::fs::write(
        &per_node,
        serde_json::to_vec(&json!([
            {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:already-global"},
            {"peer_id": "nodeD", "status": "verified", "ip": "127.0.0.3", "did": "did:guardian:per-node-only"},
            {"peer_id": "nameless", "status": "verified", "ip": "127.0.0.4"}
        ]))
        .expect("serialize per-node registry"),
    )
    .expect("write per-node registry");

    // The per-node-only peer is reachable as a recipient purely because of the
    // merge — it is absent from the global file.
    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": "did:guardian:per-node-only",
            "content": "merged in",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the merged per-node peer must be addressable: {body}"
    );
}

/// A group send with trusted peers present walks the Circle-member fan-out
/// loop; none of the peers is a Circle member here, so nothing is dispatched,
/// but the selection logic runs.
#[tokio::test]
async fn a_group_send_walks_the_peer_fan_out_selection() {
    let chat = chat_fixture("chat-group-fanout").await;
    write_peer_registry(
        &chat,
        json!([
            {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:not-a-member"},
            {"peer_id": "nodeC", "status": "unknown", "ip": "127.0.0.2", "did": "did:guardian:untrusted"},
            {"peer_id": "nodeD", "status": "verified", "did": "did:guardian:no-address"}
        ]),
    );

    let (status, body) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": chat.circle,
            "content": "to the circle",
            "is_group": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group send should be accepted: {body}");
}

/// Reading a message from a remote peer also pushes a read receipt back to
/// that peer. The peer address is dead, so the background push fails — but the
/// receipt-target selection and dispatch run.
#[tokio::test]
async fn reading_a_remote_peers_message_dispatches_a_receipt_back_to_them() {
    let chat = chat_fixture("chat-receipt").await;
    write_peer_registry(
        &chat,
        json!([
            {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:receipt-peer"}
        ]),
    );

    let (status, sent) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": "did:guardian:receipt-peer",
            "content": "conversation starter",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let message_id = sent["message_id"].as_str().expect("message_id").to_string();

    // The Guardian reads it: `local_pair_conversation_id` resolves to the peer
    // DID for a device-owned session, which is the same conversation the send
    // above wrote to.
    let (status, body) = support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/read",
        Some(&chat.owner_token),
        Some(json!({
            "message_id": message_id,
            "original_sender_did": "did:guardian:receipt-peer",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mark-as-read should succeed: {body}");
}

#[tokio::test]
async fn a_group_message_can_be_marked_as_read() {
    let chat = chat_fixture("chat-group-read").await;

    let (status, sent) = send(
        &chat,
        &chat.owner_token,
        json!({
            "recipient_did": chat.circle,
            "content": "read this",
            "is_group": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let message_id = sent["message_id"].as_str().expect("message_id").to_string();

    let (status, body) = support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/read",
        Some(&chat.owner_token),
        Some(json!({
            "message_id": message_id,
            "original_sender_did": chat.guardian_did,
            "group_id": chat.circle,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group mark-as-read: {body}");
}

#[tokio::test]
async fn marking_a_message_read_in_a_conversation_that_does_not_exist_is_refused() {
    let chat = chat_fixture("chat-read-missing").await;

    // A group whose history was never written.
    let (status, body) = support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/read",
        Some(&chat.owner_token),
        Some(json!({
            "message_id": "no-such-message",
            "original_sender_did": chat.guardian_did,
            "group_id": chat.circle,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown group: {body}");

    // A direct conversation that was never written either.
    let (status, body) = support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/read",
        Some(&chat.owner_token),
        Some(json!({
            "message_id": "no-such-message",
            "original_sender_did": "did:guardian:never-spoke-to-us",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown conversation: {body}");
}

#[tokio::test]
async fn trigger_sync_reports_zero_peers_when_the_registry_is_empty() {
    let chat = chat_fixture("chat-sync").await;

    let (status, body) = support::call(
        chat.env.router(),
        "POST",
        "/api/v1/chat/sync",
        Some(&chat.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sync should succeed: {body}");
}

#[tokio::test]
async fn sending_to_an_unknown_recipient_is_refused() {
    let chat = chat_fixture("chat-unknown").await;

    let (status, body) = send(
        &chat,
        &chat.member_token,
        json!({
            "recipient_did": "did:guardian:nobody-at-all",
            "content": "hello?",
            "is_group": false,
        }),
    )
    .await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "an unreachable recipient must not report success: {status} {body}"
    );
}

#[tokio::test]
async fn sending_an_attachment_the_sender_does_not_own_is_refused() {
    let chat = chat_fixture("chat-attachment").await;

    let (status, body) = send(
        &chat,
        &chat.member_token,
        json!({
            "recipient_did": chat.guardian_did,
            "attachment_id": "00000000-0000-0000-0000-000000000000",
            "is_group": false,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an attachment with no metadata is not found: {body}"
    );
}
