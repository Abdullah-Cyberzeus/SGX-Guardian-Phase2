//! The PWA browser-member enrollment lifecycle in `src/api/handlers/pwa.rs`.
//!
//! The pre-existing `tests/api_pwa_handlers_test.rs` and
//! `tests/cov_pwa_handlers_test.rs` cover contacts/presence/identity/health and
//! the unauthenticated rejections. What they do not touch is the enrollment
//! chain, which is the largest block in the file — and, crucially, it is
//! entirely local: `mint_member_enrollment` requires only that the Circle's
//! `owner_did` equals `state.device_did`, which is exactly what the shared
//! `wave_b_support::Env` fixture bootstraps. So mint → preview → join →
//! approve/reject runs end to end with no peer Guardian and no network at all.
//!
//! `Env` sets process-global env vars; run with `--test-threads=1`.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

const CIRCLE: &str = "pwa-enrollment-circle";
const PASSWORD: &str = "Sup3rSecret!Passphrase";

/// A bootstrapped owner plus one Circle they own, and the Guardian fingerprint
/// the join flow demands the browser echo back.
struct Fixture {
    env: support::Env,
    owner_token: String,
    fingerprint: String,
}

async fn fixture() -> Fixture {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/pwa/onboarding",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "onboarding should succeed: {body}");
    let fingerprint = body["fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();
    assert!(
        body["circles"]
            .as_array()
            .is_some_and(|circles| circles.iter().any(|circle| circle["id"] == CIRCLE)),
        "the new Circle should be offered for onboarding: {body}"
    );

    Fixture {
        env,
        owner_token,
        fingerprint,
    }
}

/// Mints a member invitation and returns `(approval_id, claim)`. The claim is
/// only ever handed out inside the join link, so it is parsed back out of it
/// the same way a browser would.
async fn mint(fixture: &Fixture) -> (String, String) {
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-invites"),
        Some(&fixture.owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint should succeed: {body}");

    let link = body["link"].as_str().expect("link").to_string();
    let claim = link
        .split_once("?member_invite=")
        .map(|(_, claim)| claim.to_string())
        .unwrap_or_else(|| panic!("join link must carry the claim: {link}"));
    let approval_id = body["enrollment"]["approvalId"]
        .as_str()
        .expect("approvalId")
        .to_string();
    assert_eq!(body["enrollment"]["state"], "issued", "{body}");
    (approval_id, claim)
}

fn join_body(claim: &str, fingerprint: &str, email: &str) -> Value {
    json!({
        "name": "Member One",
        "email": email,
        "password": PASSWORD,
        "inviteToken": claim,
        "acceptedFingerprint": fingerprint,
        "fingerprintConfirmed": true,
    })
}

#[tokio::test]
async fn owner_mints_a_member_invitation_and_can_list_it() {
    let fixture = fixture().await;
    let (approval_id, _claim) = mint(&fixture).await;

    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments"),
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "listing should succeed: {body}");
    let enrollments = body["enrollments"].as_array().expect("enrollments");
    assert_eq!(enrollments.len(), 1, "{body}");
    assert_eq!(enrollments[0]["approvalId"], approval_id, "{body}");
}

#[tokio::test]
async fn minting_reports_bad_request_for_an_unknown_circle() {
    let fixture = fixture().await;

    let (status, _) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/circles/no-such-circle/member-invites",
        Some(&fixture.owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = support::call(
        fixture.env.router(),
        "GET",
        "/api/v1/circles/no-such-circle/member-enrollments",
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn minting_is_refused_once_the_circle_is_archived() {
    let fixture = fixture().await;

    let (archive_status, archive_body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/archive"),
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert!(
        archive_status.is_success(),
        "archive should succeed: {archive_status} {archive_body}"
    );

    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-invites"),
        Some(&fixture.owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn invite_preview_resolves_a_minted_claim_and_reports_approval_is_required() {
    let fixture = fixture().await;
    let (_approval_id, claim) = mint(&fixture).await;

    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/invite-preview",
        None,
        Some(json!({"inviteToken": claim})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "preview should succeed: {body}");
    assert_eq!(body["valid"], true, "{body}");
    assert_eq!(body["circleId"], CIRCLE, "{body}");
    assert_eq!(body["role"], "member", "{body}");
    assert_eq!(body["approvalRequired"], true, "{body}");
}

#[tokio::test]
async fn invite_preview_rejects_malformed_and_unknown_claims() {
    let fixture = fixture().await;

    // Every shape `parse_enrollment_claim` rejects: no separator, empty
    // approval id, wrong secret length, and a non-hex secret.
    for malformed in [
        "no-separator",
        &format!(".{}", "a".repeat(64)),
        "approval.tooshort",
        &format!("approval.{}", "z".repeat(64)),
    ] {
        let (status, _) = support::call(
            fixture.env.router(),
            "POST",
            "/api/v1/pwa/onboarding/invite-preview",
            None,
            Some(json!({"inviteToken": malformed})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "claim: {malformed}");
    }

    // Well-formed, but no such enrollment was ever recorded here.
    let (status, _) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/invite-preview",
        None,
        Some(json!({"inviteToken": format!("unknown-approval.{}", "a".repeat(64))})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn member_approval_status_reports_the_issued_state_and_hides_mismatched_ids() {
    let fixture = fixture().await;
    let (approval_id, claim) = mint(&fixture).await;

    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        &format!("/api/v1/pwa/onboarding/approval/{approval_id}?claim={claim}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "status should succeed: {body}");
    assert_eq!(body["approvalId"], approval_id, "{body}");
    assert_eq!(body["state"], "issued", "{body}");

    // A valid claim presented against a different approval id must not resolve.
    let (status, _) = support::call(
        fixture.env.router(),
        "GET",
        &format!("/api/v1/pwa/onboarding/approval/some-other-id?claim={claim}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn join_requires_an_explicitly_confirmed_matching_fingerprint() {
    let fixture = fixture().await;
    let (_approval_id, claim) = mint(&fixture).await;

    let mut unconfirmed = join_body(&claim, &fixture.fingerprint, "one@example.test");
    unconfirmed["fingerprintConfirmed"] = json!(false);
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(unconfirmed),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let mismatched = join_body(&claim, "0000-0000-0000-0000", "one@example.test");
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(mismatched),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a fingerprint mismatch must be a hard stop: {body}"
    );
}

#[tokio::test]
async fn join_validates_the_name_email_and_password_before_anything_else() {
    let fixture = fixture().await;
    let (_approval_id, claim) = mint(&fixture).await;

    let mut short_name = join_body(&claim, &fixture.fingerprint, "one@example.test");
    short_name["name"] = json!("A");
    let (status, _) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(short_name),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut bad_email = join_body(&claim, &fixture.fingerprint, "not-an-email");
    bad_email["name"] = json!("Member One");
    let (status, _) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(bad_email),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Fails the password policy (no digit, no symbol, too short).
    let mut weak = join_body(&claim, &fixture.fingerprint, "one@example.test");
    weak["password"] = json!("short");
    let (status, _) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(weak),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn full_enrollment_lifecycle_from_mint_through_owner_approval() {
    let fixture = fixture().await;
    let (approval_id, claim) = mint(&fixture).await;

    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(join_body(&claim, &fixture.fingerprint, "one@example.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "join should succeed: {body}");
    assert_eq!(body["status"], "pending", "approval is still required: {body}");
    assert_eq!(body["approvalId"], approval_id, "{body}");
    assert_eq!(body["role"], "member", "{body}");
    assert!(
        body["token"].as_str().is_some_and(|token| !token.is_empty()),
        "a session is issued even while pending: {body}"
    );
    assert_eq!(body["guardianFingerprint"], fixture.fingerprint, "{body}");

    // The owner now sees it awaiting a decision.
    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments"),
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enrollments"][0]["state"], "pending", "{body}");

    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/approve"),
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve should succeed: {body}");
    assert_eq!(body["state"], "approved", "{body}");

    // Deciding twice is a conflict, not a second approval.
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/approve"),
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn owner_can_reject_a_pending_enrollment() {
    let fixture = fixture().await;
    let (approval_id, claim) = mint(&fixture).await;

    let (join_status, join_body_value) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(join_body(&claim, &fixture.fingerprint, "two@example.test")),
    )
    .await;
    assert_eq!(join_status, StatusCode::OK, "{join_body_value}");

    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/reject"),
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reject should succeed: {body}");
    assert_eq!(body["state"], "rejected", "{body}");
}

#[tokio::test]
async fn deciding_an_unknown_or_still_issued_enrollment_is_refused() {
    let fixture = fixture().await;
    let (approval_id, _claim) = mint(&fixture).await;

    let (status, _) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/no-such-approval/approve"),
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Minted but never claimed by a browser: still "issued", so there is no
    // account to approve yet.
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/approve"),
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn a_claim_cannot_be_redeemed_twice() {
    let fixture = fixture().await;
    let (_approval_id, claim) = mint(&fixture).await;

    let (first, first_body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(join_body(&claim, &fixture.fingerprint, "three@example.test")),
    )
    .await;
    assert_eq!(first, StatusCode::OK, "{first_body}");

    // The enrollment has moved to "pending", so the claim is spent.
    let (second, second_body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(join_body(&claim, &fixture.fingerprint, "four@example.test")),
    )
    .await;
    assert_eq!(second, StatusCode::CONFLICT, "{second_body}");

    // ...and previewing it now reports the same conflict rather than success.
    let (preview, preview_body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/invite-preview",
        None,
        Some(json!({"inviteToken": claim})),
    )
    .await;
    assert_eq!(preview, StatusCode::CONFLICT, "{preview_body}");
}

#[tokio::test]
async fn join_member_replays_a_cached_response_for_a_repeated_idempotency_key() {
    let fixture = fixture().await;
    let (_approval_id, claim) = mint(&fixture).await;

    // `support::call` cannot set an Idempotency-Key, so this drives the router
    // directly. A retried registration must replay the original account and
    // session rather than redeeming the invite a second time.
    let body = join_body(&claim, &fixture.fingerprint, "five@example.test");
    let first = post_with_idempotency_key(fixture.env.router(), &body, "join-key-1").await;
    let second = post_with_idempotency_key(fixture.env.router(), &body, "join-key-1").await;

    assert_eq!(first.0, StatusCode::OK, "{:?}", first.1);
    assert_eq!(second.0, StatusCode::OK, "{:?}", second.1);
    assert_eq!(
        first.1["userId"], second.1["userId"],
        "the same key must replay the original registration"
    );
    assert_eq!(first.1["token"], second.1["token"], "and its session token");
}

/// Runs the full mint → join → approve chain and returns the resulting active
/// member's session token, so the additional-Circle handlers have a real
/// browser member to act as.
async fn approved_member_token(fixture: &Fixture, email: &str) -> String {
    approved_member(fixture, email).await.0
}

/// As above, but also returns the browser member's stable DID.
async fn approved_member(fixture: &Fixture, email: &str) -> (String, String) {
    let (approval_id, claim) = mint(fixture).await;

    let (join_status, join_response) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(join_body(&claim, &fixture.fingerprint, email)),
    )
    .await;
    assert_eq!(join_status, StatusCode::OK, "{join_response}");

    let (approve_status, approve_body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/approve"),
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(approve_status, StatusCode::OK, "{approve_body}");

    (
        join_response["token"].as_str().expect("token").to_string(),
        join_response["browserMemberDid"]
            .as_str()
            .expect("browserMemberDid")
            .to_string(),
    )
}

/// Mints an enrollment claim for a second Circle owned by the same Guardian.
async fn mint_for(fixture: &Fixture, circle_id: &str) -> (String, String) {
    fixture.env.create_circle(&fixture.owner_token, circle_id).await;
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/{circle_id}/member-invites"),
        Some(&fixture.owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint should succeed: {body}");
    let link = body["link"].as_str().expect("link").to_string();
    let claim = link
        .split_once("?member_invite=")
        .map(|(_, claim)| claim.to_string())
        .expect("claim in link");
    let approval_id = body["enrollment"]["approvalId"]
        .as_str()
        .expect("approvalId")
        .to_string();
    (approval_id, claim)
}

#[tokio::test]
async fn an_active_member_can_request_an_additional_circle_and_the_owner_approves_it() {
    let fixture = fixture().await;
    let member_token = approved_member_token(&fixture, "extra@example.test").await;
    let (second_approval_id, second_claim) = mint_for(&fixture, "pwa-second-circle").await;

    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&member_token),
        Some(json!({"inviteToken": second_claim})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "additional join should succeed: {body}");
    assert_eq!(body["enrollment"]["state"], "pending", "{body}");
    assert_eq!(body["enrollment"]["circleId"], "pwa-second-circle", "{body}");

    // Re-submitting the same claim replays the pending request rather than
    // creating a second one.
    let (replay_status, replay_body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&member_token),
        Some(json!({"inviteToken": second_claim})),
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK, "{replay_body}");
    assert_eq!(replay_body["enrollment"]["state"], "pending", "{replay_body}");

    let (approve_status, approve_body) = support::call(
        fixture.env.router(),
        "POST",
        &format!(
            "/api/v1/circles/pwa-second-circle/member-enrollments/{second_approval_id}/approve"
        ),
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(approve_status, StatusCode::OK, "{approve_body}");
    assert_eq!(approve_body["state"], "approved", "{approve_body}");
}

#[tokio::test]
async fn additional_circle_join_is_refused_for_a_circle_the_member_already_belongs_to() {
    let fixture = fixture().await;
    let member_token = approved_member_token(&fixture, "dupe@example.test").await;

    // A brand-new claim for the Circle this member was just approved into.
    let (_approval_id, claim) = mint(&fixture).await;
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&member_token),
        Some(json!({"inviteToken": claim})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn additional_circle_join_is_refused_for_a_non_member_session() {
    let fixture = fixture().await;
    let (_approval_id, claim) = mint_for(&fixture, "pwa-owner-only-circle").await;

    // The Circle owner's own session is not a PWA member session.
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&fixture.owner_token),
        Some(json!({"inviteToken": claim})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn a_member_can_remove_their_own_browser_registration() {
    let fixture = fixture().await;
    let member_token = approved_member_token(&fixture, "gone@example.test").await;

    let (status, body) = support::call(
        fixture.env.router(),
        "DELETE",
        "/api/v1/pwa/registration",
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "removal should succeed: {body}");
    assert_eq!(body["status"], "registration_removed", "{body}");

    // The session it was issued under is revoked along with the registration.
    let (after, _) = support::call(
        fixture.env.router(),
        "DELETE",
        "/api/v1/pwa/registration",
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(
        after,
        StatusCode::UNAUTHORIZED,
        "the revoked session must no longer authenticate"
    );
}

/// `contacts` only reaches its interesting body once the Guardian actually has
/// a Circle registry and at least one approved browser member — the
/// pre-existing suite only covers its no-registry error path. With the shared
/// `Env` fixture both preconditions hold, so this walks the self row, the
/// browser-member projection loop, and `contact_metadata` underneath it.
#[tokio::test]
async fn contacts_lists_this_guardian_and_its_approved_browser_members() {
    let fixture = fixture().await;
    let member_token = approved_member_token(&fixture, "contact@example.test").await;

    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        "/api/v1/pwa/contacts",
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "contacts should succeed: {body}");

    let contacts = body["contacts"].as_array().expect("contacts");
    assert_eq!(
        body["total"].as_u64(),
        Some(contacts.len() as u64),
        "total must match the list: {body}"
    );
    assert!(
        body["presenceHeartbeatSeconds"].as_u64().is_some(),
        "presence cadence is advertised to the browser: {body}"
    );

    // The Guardian always lists itself first-class.
    let this_guardian = contacts
        .iter()
        .find(|contact| contact["fullName"] == "This Guardian")
        .unwrap_or_else(|| panic!("the Guardian's own row must be present: {body}"));
    assert_eq!(this_guardian["memberType"], "guardian", "{this_guardian}");
    assert_eq!(this_guardian["status"], "verified", "{this_guardian}");
    assert_eq!(this_guardian["callAvailable"], true, "{this_guardian}");

    // ...and the approved browser member appears as a browser contact.
    let browser = contacts
        .iter()
        .find(|contact| contact["memberType"] == "browser")
        .unwrap_or_else(|| panic!("the approved browser member must be listed: {body}"));
    assert_eq!(browser["role"], "member", "{browser}");
    assert!(browser["did"].as_str().is_some(), "{browser}");

    // Sorted by display name.
    let names: Vec<&str> = contacts
        .iter()
        .filter_map(|contact| contact["displayName"].as_str())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "contacts must be sorted by display name");

    // The member's own session sees the list too, and never sees itself in it.
    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        "/api/v1/pwa/contacts",
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let member_view = body["contacts"].as_array().expect("contacts");
    assert!(
        member_view
            .iter()
            .any(|contact| contact["fullName"] == "This Guardian"),
        "a member still sees the Guardian: {body}"
    );
    assert!(
        !member_view.iter().any(|contact| contact["memberType"] == "browser"),
        "a member must not be listed as their own contact: {body}"
    );
}

/// The peer-projection half of `contacts` only runs when `peers::list` returns
/// a verified peer whose DID is already a Circle member. Seeding the trusted
/// peer registry with the approved browser member's own DID satisfies both
/// conditions without inventing any new identity.
#[tokio::test]
async fn contacts_projects_verified_peers_from_the_trusted_peer_registry() {
    let fixture = fixture().await;
    let (_token, member_did) = approved_member(&fixture, "peer@example.test").await;

    let registry = std::path::Path::new(&fixture.env.state.log_dir_primary)
        .join("trusted_peers.json");
    std::fs::create_dir_all(registry.parent().expect("registry parent"))
        .expect("create log dir");
    std::fs::write(
        &registry,
        serde_json::to_vec(&json!([{
            "peer_id": "nodeB",
            "virtual_id": "vid-nodeb",
            "status": "verified",
            "ip": "127.0.0.1",
            "did": member_did,
        }]))
        .expect("serialize registry"),
    )
    .expect("write trusted peer registry");

    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        "/api/v1/pwa/contacts",
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "contacts should succeed: {body}");

    let peer = body["contacts"]
        .as_array()
        .expect("contacts")
        .iter()
        .find(|contact| contact["peerId"] == "nodeB")
        .unwrap_or_else(|| panic!("the verified peer must be projected: {body}"));
    assert_eq!(peer["did"].as_str(), Some(member_did.as_str()), "{peer}");
    assert_eq!(peer["status"], "verified", "{peer}");
    assert!(
        peer["presenceStatus"].as_str().is_some(),
        "presence is computed for peers too: {peer}"
    );
}

#[tokio::test]
async fn minting_replays_a_cached_response_for_a_repeated_idempotency_key() {
    let fixture = fixture().await;

    let body = json!({"baseUrl": "https://guardian.local"});
    let uri = format!("/api/v1/circles/{CIRCLE}/member-invites");
    let first = post_json_with_key(&fixture, &uri, &body, "mint-key-1").await;
    let second = post_json_with_key(&fixture, &uri, &body, "mint-key-1").await;

    assert_eq!(first.0, StatusCode::OK, "{:?}", first.1);
    assert_eq!(second.0, StatusCode::OK, "{:?}", second.1);
    assert_eq!(
        first.1["enrollment"]["approvalId"], second.1["enrollment"]["approvalId"],
        "the same key must replay the original invitation rather than minting a second one"
    );
    assert_eq!(first.1["link"], second.1["link"], "including its claim link");
}

#[tokio::test]
async fn repeated_invite_previews_are_rate_limited() {
    let fixture = fixture().await;

    let mut limited = false;
    for _ in 0..200 {
        let (status, _) = support::call(
            fixture.env.router(),
            "POST",
            "/api/v1/pwa/onboarding/invite-preview",
            None,
            Some(json!({"inviteToken": "no-separator"})),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "invite previews should be rate limited eventually");
}

#[tokio::test]
async fn additional_circle_join_refuses_spent_archived_and_duplicated_requests() {
    let fixture = fixture().await;
    let member_token = approved_member_token(&fixture, "extras@example.test").await;

    // A claim that a different browser already consumed is no longer "issued".
    let (_spent_approval, spent_claim) = mint_for(&fixture, "pwa-spent-circle").await;
    let (join_status, join_response) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/onboarding/join",
        None,
        Some(join_body(&spent_claim, &fixture.fingerprint, "spender@example.test")),
    )
    .await;
    assert_eq!(join_status, StatusCode::OK, "{join_response}");
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&member_token),
        Some(json!({"inviteToken": spent_claim})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "a spent claim: {body}");

    // Two outstanding claims for the same Circle: the second is a duplicate
    // request, not a second membership.
    let (_first_approval, first_claim) = mint_for(&fixture, "pwa-dup-circle").await;
    let (second_status, second_body) = support::call(
        fixture.env.router(),
        "POST",
        &format!("/api/v1/circles/pwa-dup-circle/member-invites"),
        Some(&fixture.owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(second_status, StatusCode::OK, "{second_body}");
    let second_claim = second_body["link"]
        .as_str()
        .and_then(|link| link.split_once("?member_invite="))
        .map(|(_, claim)| claim.to_string())
        .expect("second claim");

    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&member_token),
        Some(json!({"inviteToken": first_claim})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&member_token),
        Some(json!({"inviteToken": second_claim})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "a duplicate request: {body}");

    // An archived Circle cannot be joined at all.
    let (_archived_approval, archived_claim) =
        mint_for(&fixture, "pwa-archived-circle").await;
    let (archive_status, archive_body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/circles/pwa-archived-circle/archive",
        Some(&fixture.owner_token),
        Some(json!({})),
    )
    .await;
    assert!(
        archive_status.is_success(),
        "{archive_status} {archive_body}"
    );
    let (status, body) = support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/pwa/circles/join",
        Some(&member_token),
        Some(json!({"inviteToken": archived_claim})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "an archived Circle: {body}");
}

async fn post_json_with_key(
    fixture: &Fixture,
    uri: &str,
    body: &Value,
    key: &str,
) -> (StatusCode, Value) {
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", fixture.owner_token),
        )
        .header("idempotency-key", key)
        .body(Body::from(serde_json::to_vec(body).expect("serialize body")))
        .expect("build request");
    let response = fixture
        .env
        .router()
        .oneshot(request)
        .await
        .expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

#[tokio::test]
async fn contacts_requires_a_session() {
    let fixture = fixture().await;

    let (status, _) = support::call(
        fixture.env.router(),
        "GET",
        "/api/v1/pwa/contacts",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn post_with_idempotency_key(
    router: axum::Router,
    body: &Value,
    key: &str,
) -> (StatusCode, Value) {
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/pwa/onboarding/join")
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(serde_json::to_vec(body).expect("serialize body")))
        .expect("build request");
    let response = router.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}
