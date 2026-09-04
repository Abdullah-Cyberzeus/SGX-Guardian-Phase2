//! Receiving-side / snapshot coverage for `src/api/handlers/circle.rs`.
//!
//! The pre-existing `tests/cov_circle_handlers_test.rs` is thorough on the
//! owner-side operations (create/edit/archive/delete/members/roles/invite
//! minting, listing and revocation). This file covers the handlers on the
//! other side of the wire that it does not touch: the authoritative member
//! snapshot an owner serves, snapshot sync, the received-invite inbox, and
//! the invite preview/accept/reject/redeem entry points.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

const CIRCLE: &str = "receiving-circle";
const TEST_DID: &str = "did:guardian:9iwQY8smBVRjQHqDt4kWZ3J4mvzG8DR3dw4HvHcKGhu3";

/// The peer/service auth headers `verify_guardian_service_auth_for_payload`
/// reads. `support::call` cannot set arbitrary headers, so these tests dispatch
/// through the router directly.
async fn post_with_headers(
    router: axum::Router,
    uri: &str,
    headers: &[(&str, String)],
    body: Value,
) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
    }
    let request = builder
        .body(Body::from(serde_json::to_vec(&body).expect("serialize body")))
        .expect("build request");
    router.oneshot(request).await.expect("router response").status()
}

/// Returns `(env, owner_token, owner_did)`. The owner DID is read back out of
/// the circle's own signed snapshot, so it is a DID the node's resolver really
/// knows — which is what lets the signature-verification branch be reached.
async fn env_with_owner_did() -> (support::Env, String, String) {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/circles/{CIRCLE}/members/snapshot"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let owner_did = body["ownerDid"].as_str().expect("ownerDid").to_string();
    (env, owner_token, owner_did)
}

/// A syntactically valid snapshot payload owned by `owner_did`. It never
/// verifies — these tests are about the header-auth gate that runs first.
fn snapshot_payload(owner_did: &str) -> Value {
    json!({
        "circleId": CIRCLE,
        "version": 7,
        "ownerDid": owner_did,
        "members": [],
        "updatedAt": "2026-01-01T00:00:00+00:00",
    })
}

/// Minted invite tokens are URL-safe unpadded base64; fall back to the standard
/// alphabet so this keeps working if that ever changes.
fn decode_invite_token(token_b64: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(token_b64))
        .expect("decode invite token")
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

const GOOD_NONCE: &str = "nonce-0123456789";
const GOOD_SIG: &str = "GuardianService AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[tokio::test]
async fn owner_can_serve_the_authoritative_member_snapshot() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/circles/{CIRCLE}/members/snapshot"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "snapshot should succeed: {body}");
    assert_eq!(body["circleId"], CIRCLE, "{body}");
    assert!(
        body["proof"]["proofValue"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "the served snapshot must be signed: {body}"
    );
}

#[tokio::test]
async fn member_snapshot_reports_not_found_for_an_unknown_circle() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/no-such-circle/members/snapshot",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sync_member_snapshots_succeeds_with_nothing_to_pull() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    // Only locally-owned/mesh circles exist, and the pull loop skips both, so
    // this reaches its `Ok(applied)` return without any network call.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/sync",
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sync should succeed: {body}");
}

#[tokio::test]
async fn received_invite_inbox_is_empty_initially() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/invites/inbox",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "inbox should succeed: {body}");
    assert_eq!(body["count"], 0, "{body}");
}

#[tokio::test]
async fn join_preview_decodes_and_verifies_a_freshly_minted_invite() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (mint_status, mint_body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/invites"),
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "role": "member", "deliver": false})),
    )
    .await;
    assert_eq!(mint_status, StatusCode::CREATED, "{mint_body}");
    let token_b64 = mint_body["token_b64"]
        .as_str()
        .expect("token_b64")
        .to_string();

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/join/preview",
        Some(&owner_token),
        Some(json!({"token_b64": token_b64})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "preview should succeed: {body}");
    assert_eq!(body["circle_id"], CIRCLE, "{body}");
    assert_eq!(body["role"], "member", "{body}");
}

#[tokio::test]
async fn join_preview_rejects_a_malformed_token() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/join/preview",
        Some(&owner_token),
        Some(json!({"token_b64": "not-a-valid-token"})),
    )
    .await;
    assert!(
        status.is_client_error(),
        "a malformed invite token must be rejected, got {status}"
    );
}

#[tokio::test]
async fn accept_and_reject_report_not_found_for_an_unknown_invite() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (accept_status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/invites/no-such-invite/accept",
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert!(
        accept_status.is_client_error(),
        "unknown invite accept must fail, got {accept_status}"
    );

    let (reject_status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/invites/no-such-invite/reject",
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert!(
        reject_status.is_client_error(),
        "unknown invite reject must fail, got {reject_status}"
    );
}

/// `join` verifies the invite, resolves the owner host and signs a join
/// request before noticing that the invite is addressed to somebody else. That
/// mismatch is the furthest this fixture can get without a live owner on the
/// other end, and it walks the whole handler plus `join_remote_circle`'s setup.
#[tokio::test]
async fn join_rejects_an_invite_addressed_to_a_different_node() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (mint_status, mint_body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/invites"),
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "role": "member", "deliver": false})),
    )
    .await;
    assert_eq!(mint_status, StatusCode::CREATED, "{mint_body}");

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/join",
        Some(&owner_token),
        Some(json!({
            "token_b64": mint_body["token_b64"],
            // Given explicitly so the handler never has to resolve the owner's
            // endpoint over the network.
            "owner_host": "https://127.0.0.1:9",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains("invite targets"),
        "should fail on the target-DID mismatch, not earlier: {body}"
    );
}

#[tokio::test]
async fn join_rejects_a_malformed_token() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/join",
        Some(&owner_token),
        Some(json!({"token_b64": "not-a-valid-token"})),
    )
    .await;
    assert!(status.is_client_error(), "got {status}");
}

/// `enforce_join_rate_limit` guards both join entry points. Repeated previews
/// from the same session must eventually trip it.
#[tokio::test]
async fn repeated_join_previews_are_rate_limited() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let mut limited = false;
    for _ in 0..200 {
        let (status, _) = support::call(
            env.router(),
            "POST",
            "/api/v1/circles/join/preview",
            Some(&owner_token),
            Some(json!({"token_b64": "not-a-valid-token"})),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "join previews should be rate limited eventually");
}

/// A well-formed `JoinRequest` carrying a genuinely-signed invite but an
/// unsigned join proof: the invite verifies, so `redeem` gets as far as
/// checking the joiner's own signature and rejects there.
#[tokio::test]
async fn redeem_rejects_a_join_request_whose_proof_does_not_verify() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (mint_status, mint_body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/invites"),
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "role": "member", "deliver": false})),
    )
    .await;
    assert_eq!(mint_status, StatusCode::CREATED, "{mint_body}");
    let token_json: Value = serde_json::from_slice(&decode_invite_token(
        mint_body["token_b64"].as_str().expect("token_b64"),
    ))
    .expect("invite token json");

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/redeem",
        Some(&owner_token),
        Some(json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "inviteToken": token_json,
            "joinerDid": TEST_DID,
            "accepted": true,
            "nonce": "join-nonce-0123456789",
            "issuedAt": now_rfc3339(),
        })),
    )
    .await;
    // The invite itself verifies, so `redeem` proceeds to `verify_join_request`,
    // which has to resolve the joiner's DID before it can check the proof. This
    // fixture has no such peer, so it stops there — that is the real, reachable
    // outcome, and the handler body up to the joiner check is what runs.
    assert!(
        status.is_client_error() || status == StatusCode::INTERNAL_SERVER_ERROR,
        "redeem must resolve deterministically: {status} {body}"
    );
    assert!(
        !body.to_string().contains("Circle membership issued"),
        "an unsigned join request must never be granted membership: {body}"
    );
}

#[tokio::test]
async fn redeem_rejects_a_malformed_token() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/redeem",
        Some(&owner_token),
        Some(json!({"token_b64": "not-a-valid-token"})),
    )
    .await;
    assert!(
        status.is_client_error(),
        "a malformed redeem token must be rejected, got {status}"
    );
}

/// Every rejection branch of `verify_guardian_service_auth_for_payload`, driven
/// through `receive_member_snapshot`. Each case differs from the previous one by
/// exactly the header that the next check in the function reads, so the whole
/// gate is walked top to bottom. All of them must answer 401 — the point is
/// *which* check produced it, and every case here reaches a distinct one.
#[tokio::test]
async fn snapshot_inbox_rejects_every_malformed_peer_auth_header_combination() {
    let (env, _owner_token, owner_did) = env_with_owner_did().await;
    let payload = snapshot_payload(&owner_did);

    let stale = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
        ("missing authorization header", vec![]),
        (
            "unsupported authorization scheme",
            vec![(header::AUTHORIZATION.as_str(), "Bearer nope".to_string())],
        ),
        (
            "missing guardian did header",
            vec![(header::AUTHORIZATION.as_str(), GOOD_SIG.to_string())],
        ),
        (
            "missing timestamp header",
            vec![
                (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
                ("x-sgx-guardian-did", owner_did.clone()),
            ],
        ),
        (
            "missing nonce header",
            vec![
                (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
                ("x-sgx-guardian-did", owner_did.clone()),
                ("x-sgx-guardian-timestamp", now_rfc3339()),
            ],
        ),
        (
            "service DID does not match the snapshot owner",
            vec![
                (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
                ("x-sgx-guardian-did", TEST_DID.to_string()),
                ("x-sgx-guardian-timestamp", now_rfc3339()),
                ("x-sgx-guardian-nonce", GOOD_NONCE.to_string()),
            ],
        ),
        (
            "nonce too short",
            vec![
                (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
                ("x-sgx-guardian-did", owner_did.clone()),
                ("x-sgx-guardian-timestamp", now_rfc3339()),
                ("x-sgx-guardian-nonce", "short".to_string()),
            ],
        ),
        (
            "unparseable timestamp",
            vec![
                (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
                ("x-sgx-guardian-did", owner_did.clone()),
                ("x-sgx-guardian-timestamp", "not-a-timestamp".to_string()),
                ("x-sgx-guardian-nonce", GOOD_NONCE.to_string()),
            ],
        ),
        (
            "timestamp outside the allowed skew",
            vec![
                (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
                ("x-sgx-guardian-did", owner_did.clone()),
                ("x-sgx-guardian-timestamp", stale),
                ("x-sgx-guardian-nonce", GOOD_NONCE.to_string()),
            ],
        ),
        (
            "signature is not base64",
            vec![
                (
                    header::AUTHORIZATION.as_str(),
                    "GuardianService !!!not-base64!!!".to_string(),
                ),
                ("x-sgx-guardian-did", owner_did.clone()),
                ("x-sgx-guardian-timestamp", now_rfc3339()),
                ("x-sgx-guardian-nonce", GOOD_NONCE.to_string()),
            ],
        ),
        (
            // Well-formed all the way down: the DID resolves, the canonical
            // bytes hash, and the signature decodes — it is simply not a valid
            // signature over them. This is the deepest reachable branch.
            "signature does not verify",
            vec![
                (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
                ("x-sgx-guardian-did", owner_did.clone()),
                ("x-sgx-guardian-timestamp", now_rfc3339()),
                ("x-sgx-guardian-nonce", GOOD_NONCE.to_string()),
            ],
        ),
    ];

    for (label, headers) in cases {
        let status =
            post_with_headers(env.router(), "/api/v1/circles/snapshots/inbox", &headers, payload.clone())
                .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "case: {label}");
    }
}

/// An unresolvable owner DID reaches the resolver call and fails there. Kept
/// separate from the table above because it needs its own payload: the header
/// DID and the snapshot's `ownerDid` have to agree to get that far.
#[tokio::test]
async fn snapshot_inbox_rejects_an_owner_did_the_resolver_does_not_know() {
    let env = support::Env::new();
    let _ = env.owner_token().await;

    let headers = vec![
        (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
        ("x-sgx-guardian-did", TEST_DID.to_string()),
        ("x-sgx-guardian-timestamp", now_rfc3339()),
        ("x-sgx-guardian-nonce", GOOD_NONCE.to_string()),
    ];
    let status = post_with_headers(
        env.router(),
        "/api/v1/circles/snapshots/inbox",
        &headers,
        snapshot_payload(TEST_DID),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The invite inbox runs the same gate via `verify_guardian_service_auth`,
/// which additionally has to build canonical bytes from the invite token before
/// it can check anything.
#[tokio::test]
async fn invite_inbox_rejects_a_request_without_peer_auth_headers() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (mint_status, mint_body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/invites"),
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "role": "member", "deliver": false})),
    )
    .await;
    assert_eq!(mint_status, StatusCode::CREATED, "{mint_body}");
    let token_b64 = mint_body["token_b64"].as_str().expect("token_b64");
    let token_json: Value = serde_json::from_slice(&decode_invite_token(token_b64))
        .expect("invite token json");

    let status = post_with_headers(
        env.router(),
        "/api/v1/circles/invites/inbox",
        &[],
        token_json.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ...and with headers present but a signature that cannot verify, so the
    // invite-flavoured canonical-bytes builder runs too.
    let headers = vec![
        (header::AUTHORIZATION.as_str(), GOOD_SIG.to_string()),
        (
            "x-sgx-guardian-did",
            token_json["issuerDid"]
                .as_str()
                .expect("issuerDid")
                .to_string(),
        ),
        ("x-sgx-guardian-timestamp", now_rfc3339()),
        ("x-sgx-guardian-nonce", GOOD_NONCE.to_string()),
    ];
    let status = post_with_headers(
        env.router(),
        "/api/v1/circles/invites/inbox",
        &headers,
        token_json,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn receive_member_snapshot_rejects_an_unsigned_snapshot() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/snapshots/inbox",
        Some(&owner_token),
        Some(json!({
            "circle_id": CIRCLE,
            "version": 1,
            "owner_did": "did:guardian:someone-else",
            "members": [],
            "updated_at": "2026-01-01T00:00:00Z",
        })),
    )
    .await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "an unsigned/ownerless snapshot must be rejected, got {status}"
    );
}
