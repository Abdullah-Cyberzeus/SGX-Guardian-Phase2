// Integration tests for the PWA onboarding/enrollment handlers
// (src/api/handlers/pwa.rs), built on the shared wave_b_support fixture.
//
// Request/response payloads for these handlers are camelCase on the wire
// (`#[serde(rename_all = "camelCase")]`), unlike call.rs/circle.rs's mostly
// snake_case types -- every field access below uses the camelCase form.

#[path = "wave_b_support/mod.rs"]
mod support;

use serde_json::json;

const CIRCLE: &str = "family";

/// Fetches the Guardian's own fingerprint via the public onboarding
/// endpoint, so tests don't need to reimplement `guardian_fingerprint`.
async fn current_fingerprint(env: &support::Env) -> String {
    let (status, body) =
        support::call(env.router(), "GET", "/api/v1/pwa/onboarding", None, None).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    body["fingerprint"].as_str().unwrap().to_string()
}

fn join_member_body(invite_token: &str, email: &str, fingerprint: &str) -> serde_json::Value {
    json!({
        "name": "New Member",
        "email": email,
        "password": "Correct Horse Battery Staple 42!",
        "inviteToken": invite_token,
        "acceptedFingerprint": fingerprint,
        "fingerprintConfirmed": true,
    })
}

#[tokio::test]
async fn onboarding_returns_200_with_active_circle_summaries() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (status, body) =
        support::call(env.router(), "GET", "/api/v1/pwa/onboarding", None, None).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["circles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|circle| circle["id"] == CIRCLE));
    assert_eq!(body["internetRequired"], false);
}

#[tokio::test]
async fn preview_member_invite_returns_400_for_malformed_token() {
    let env = support::Env::new();
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/pwa/onboarding/invite-preview",
        None,
        Some(json!({"inviteToken": "not-a-real-token"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

/// Mints an owner-only member enrollment for `circle_id` and returns its
/// full JSON body (contains `link`, `expiresAt`, and the nested
/// `enrollment` view with `approvalId`/the dotted claim embedded in `link`).
async fn mint_enrollment(
    env: &support::Env,
    owner_token: &str,
    circle_id: &str,
) -> serde_json::Value {
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{circle_id}/member-invites"),
        Some(owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    body
}

fn claim_from_link(link: &str) -> String {
    link.split("member_invite=").nth(1).unwrap().to_string()
}

#[tokio::test]
async fn mint_member_enrollment_returns_200_with_link_for_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let body = mint_enrollment(&env, &owner_token, CIRCLE).await;
    assert!(body["link"].as_str().unwrap().contains("member_invite="));
    assert_eq!(body["enrollment"]["circleId"], CIRCLE);
    assert_eq!(body["enrollment"]["state"], "issued");
}

#[tokio::test]
async fn mint_member_enrollment_returns_403_if_not_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (member_token, _did) = env.member_token(CIRCLE).await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-invites"),
        Some(&member_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mint_member_enrollment_returns_409_if_circle_archived() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/archive"),
        Some(&owner_token),
        None,
    )
    .await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-invites"),
        Some(&owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn list_member_enrollments_returns_200_for_owner_and_403_for_non_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    mint_enrollment(&env, &owner_token, CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["enrollments"].as_array().unwrap().len(), 1);

    let (member_token, _did) = env.member_token(CIRCLE).await;
    let (status, _) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments"),
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn preview_member_invite_returns_200_with_approval_required_for_enrollment_claim() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let mint_body = mint_enrollment(&env, &owner_token, CIRCLE).await;
    let claim = claim_from_link(mint_body["link"].as_str().unwrap());

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/pwa/onboarding/invite-preview",
        None,
        Some(json!({"inviteToken": claim})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true);
    assert_eq!(body["approvalRequired"], true);
    assert_eq!(body["circleId"], CIRCLE);
}

#[tokio::test]
async fn member_approval_status_returns_200_then_404_for_wrong_id() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let mint_body = mint_enrollment(&env, &owner_token, CIRCLE).await;
    let claim = claim_from_link(mint_body["link"].as_str().unwrap());
    let approval_id = mint_body["enrollment"]["approvalId"].as_str().unwrap();

    let (status, body) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/pwa/onboarding/approval/{approval_id}?claim={claim}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["state"], "issued");

    let (status, _) = support::call(
        env.router(),
        "GET",
        &format!("/api/v1/pwa/onboarding/approval/wrong-id?claim={claim}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

/// Full enrollment-claim registration: mints an owner enrollment, registers
/// a brand-new member account against it (landing "pending"), and returns
/// `(session_token, approval_id, member_join_response_body)`.
async fn register_pending_member(
    env: &support::Env,
    owner_token: &str,
    circle_id: &str,
    email: &str,
) -> (String, String, serde_json::Value) {
    let fingerprint = current_fingerprint(env).await;
    let mint_body = mint_enrollment(env, owner_token, circle_id).await;
    let claim = claim_from_link(mint_body["link"].as_str().unwrap());

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(join_member_body(&claim, email, &fingerprint)),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "pending");
    let token = body["token"].as_str().unwrap().to_string();
    let approval_id = body["approvalId"].as_str().unwrap().to_string();
    (token, approval_id, body)
}

#[tokio::test]
async fn join_member_rejects_unconfirmed_or_mismatched_fingerprint() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let mint_body = mint_enrollment(&env, &owner_token, CIRCLE).await;
    let claim = claim_from_link(mint_body["link"].as_str().unwrap());

    let mut body = join_member_body(&claim, "a@example.com", "irrelevant");
    body["fingerprintConfirmed"] = json!(false);
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(body),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    let mismatched = join_member_body(&claim, "a@example.com", "0000-0000-0000-0000");
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(mismatched),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn join_member_via_regular_invite_conflicts_on_reserved_target_did() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let fingerprint = current_fingerprint(&env).await;
    // A regular (non-enrollment) circle invite is minted for a fixed target
    // DID; `join_member`'s non-enrollment path always derives a *fresh*
    // random DID for the new registration, which can never equal that fixed
    // target -> a deterministic, real CONFLICT from `assert_redeemable`.
    let (status, mint_body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/invites"),
        Some(&owner_token),
        Some(json!({
            "target_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
            "role": "member",
            "deliver": false,
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{mint_body}");
    let token_b64 = mint_body["token_b64"].as_str().unwrap();

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(join_member_body(token_b64, "b@example.com", &fingerprint)),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn join_member_via_enrollment_claim_is_pending_then_approved() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (_token, approval_id, _body) =
        register_pending_member(&env, &owner_token, CIRCLE, "pending@example.com").await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/approve"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["state"], "approved");

    // Approving twice is a conflict: the enrollment is no longer pending.
    let (status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/approve"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn join_member_via_enrollment_claim_can_be_rejected() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (_token, approval_id, _body) =
        register_pending_member(&env, &owner_token, CIRCLE, "rejected@example.com").await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/reject"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["state"], "rejected");
}

#[tokio::test]
async fn approve_and_reject_member_enrollment_return_404_for_unknown_approval() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/does-not-exist/approve"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn join_additional_circle_rebinds_enrollment_to_existing_member_then_can_be_approved() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "home").await;
    env.create_circle(&owner_token, "work").await;

    let (member_token, _approval_id, join_body) =
        register_pending_member(&env, &owner_token, "home", "multi@example.com").await;
    let home_approval_id = join_body["approvalId"].as_str().unwrap();
    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/home/member-enrollments/{home_approval_id}/approve"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");

    // The member is active in "home"; mint a throwaway enrollment for "work"
    // and have the already-authenticated member claim+rebind it to
    // themselves instead of registering a brand-new account.
    let work_mint = mint_enrollment(&env, &owner_token, "work").await;
    let work_claim = claim_from_link(work_mint["link"].as_str().unwrap());

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&member_token),
        Some(json!({"inviteToken": work_claim})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["enrollment"]["state"], "pending");
    let work_approval_id = body["enrollment"]["approvalId"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/work/member-enrollments/{work_approval_id}/approve"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["state"], "approved");
}

#[tokio::test]
async fn remove_registration_revokes_sessions() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;
    let (member_token, approval_id, _body) =
        register_pending_member(&env, &owner_token, CIRCLE, "leaver@example.com").await;
    support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/approve"),
        Some(&owner_token),
        None,
    )
    .await;

    let (status, body) = support::call(
        env.router(),
        "DELETE",
        "/api/v1/pwa/registration",
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "registration_removed");
    assert!(body["revokedSessions"].as_u64().unwrap() >= 1);
}
