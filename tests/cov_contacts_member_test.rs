//! Contact-book coverage for `src/api/handlers/contacts.rs` that needs a real
//! Circle membership to reach.
//!
//! `COVERAGE_90_PLAN.md` records this file as blocked: `create()` gates every
//! save through `ensure_saveable_contact_did`, which only accepts a DID that is
//! either an active browser member of a shared Circle or a VC-attested peer, so
//! the earlier pass could exercise nothing but the member-saves-its-own-Guardian
//! special case and the fail-closed rejection.
//!
//! That blocker is gone: the PWA enrollment flow (mint → join → approve, all
//! local — see `tests/cov_pwa_enrollment_test.rs`) produces a genuinely active
//! browser member of a Circle this Guardian owns. Saving *that* DID walks
//! `is_active_browser_member_contact` and the whole authorized create path.
//!
//! `Env` sets process-global env vars; run with `--test-threads=1`.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

const CIRCLE: &str = "contacts-circle";
const PASSWORD: &str = "Sup3rSecret!Passphrase";

struct Fixture {
    env: support::Env,
    owner_token: String,
    guardian_did: String,
    member_token: String,
    member_did: String,
}

/// An owner, a Circle, and one approved browser member of it.
async fn fixture() -> Fixture {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, CIRCLE).await;

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
        &format!("/api/v1/circles/{CIRCLE}/member-invites"),
        Some(&owner_token),
        Some(json!({"baseUrl": "https://guardian.local"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let claim = minted["link"]
        .as_str()
        .and_then(|link| link.split_once("?member_invite="))
        .map(|(_, claim)| claim.to_string())
        .expect("claim");
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
            "name": "Contact Member",
            "email": "contact@example.test",
            "password": PASSWORD,
            "inviteToken": claim,
            "acceptedFingerprint": fingerprint,
            "fingerprintConfirmed": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{joined}");
    let member_token = joined["token"].as_str().expect("token").to_string();
    let member_did = joined["browserMemberDid"]
        .as_str()
        .expect("browserMemberDid")
        .to_string();

    let (status, approved) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/{CIRCLE}/member-enrollments/{approval_id}/approve"),
        Some(&owner_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");

    Fixture {
        env,
        owner_token,
        guardian_did,
        member_token,
        member_did,
    }
}

async fn create_contact(fixture: &Fixture, token: &str, body: Value) -> (StatusCode, Value) {
    support::call(
        fixture.env.router(),
        "POST",
        "/api/v1/contacts",
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn the_owner_can_save_an_approved_browser_member_as_a_contact() {
    let fixture = fixture().await;

    let (status, body) = create_contact(
        &fixture,
        &fixture.owner_token,
        json!({
            "did": fixture.member_did,
            "name": "Contact Member",
            "alias": "CM",
            "notes": "joined via the PWA",
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an active browser member is a saveable contact: {body}"
    );
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["contact"]["did"], fixture.member_did, "{body}");
}

#[tokio::test]
async fn a_saved_contact_round_trips_through_list_get_update_and_delete() {
    let fixture = fixture().await;

    let (status, _) = create_contact(
        &fixture,
        &fixture.owner_token,
        json!({"did": fixture.member_did, "name": "Original"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        "/api/v1/contacts",
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 1, "{body}");
    assert!(body["timestamp"].as_str().is_some(), "{body}");

    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        &format!("/api/v1/contacts/{}", fixture.member_did),
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "Original", "{body}");

    let (status, body) = support::call(
        fixture.env.router(),
        "PATCH",
        &format!("/api/v1/contacts/{}", fixture.member_did),
        Some(&fixture.owner_token),
        Some(json!({"alias": "Renamed", "notes": "updated"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["contact"]["alias"], "Renamed", "{body}");

    let (status, body) = support::call(
        fixture.env.router(),
        "DELETE",
        &format!("/api/v1/contacts/{}", fixture.member_did),
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], true, "{body}");

    // Gone from both the listing and the direct lookup.
    let (status, body) = support::call(
        fixture.env.router(),
        "GET",
        "/api/v1/contacts",
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 0, "{body}");

    let (status, _) = support::call(
        fixture.env.router(),
        "GET",
        &format!("/api/v1/contacts/{}", fixture.member_did),
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_member_can_save_their_own_guardian_but_not_an_unrelated_did() {
    let fixture = fixture().await;

    // The documented special case: a member always shares a Circle with the
    // Guardian hosting them, so the Guardian's own DID is always saveable.
    let (status, body) = create_contact(
        &fixture,
        &fixture.member_token,
        json!({"did": fixture.guardian_did, "name": "My Guardian"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = create_contact(
        &fixture,
        &fixture.member_token,
        json!({"did": "did:guardian:9iwQY8smBVRjQHqDt4kWZ3J4mvzG8DR3dw4HvHcKGhu3"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a stranger's DID must be refused: {body}"
    );
    assert!(
        body.to_string().contains("not an active peer"),
        "the refusal names the reason: {body}"
    );
}

#[tokio::test]
async fn admin_and_member_address_books_are_separate() {
    let fixture = fixture().await;

    // The owner saves the member; the member saves the Guardian.
    let (status, _) = create_contact(
        &fixture,
        &fixture.owner_token,
        json!({"did": fixture.member_did, "name": "Member"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = create_contact(
        &fixture,
        &fixture.member_token,
        json!({"did": fixture.guardian_did, "name": "Guardian"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Each side sees exactly one contact — its own.
    for (label, token, expected_did) in [
        ("owner", &fixture.owner_token, &fixture.member_did),
        ("member", &fixture.member_token, &fixture.guardian_did),
    ] {
        let (status, body) = support::call(
            fixture.env.router(),
            "GET",
            "/api/v1/contacts",
            Some(token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}: {body}");
        assert_eq!(body["total"], 1, "{label} sees only its own book: {body}");
        assert_eq!(
            body["contacts"][0]["did"],
            expected_did.as_str(),
            "{label}: {body}"
        );
    }
}

#[tokio::test]
async fn contact_dids_are_validated_before_any_membership_check() {
    let fixture = fixture().await;

    for malformed in ["", "   ", "not-a-did", "did:other:abc"] {
        let (status, body) =
            create_contact(&fixture, &fixture.owner_token, json!({"did": malformed})).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "did {malformed:?} must be rejected: {body}"
        );
    }
}

#[tokio::test]
async fn updating_or_deleting_an_unknown_contact_reports_not_found() {
    let fixture = fixture().await;
    let unknown = "did:guardian:9iwQY8smBVRjQHqDt4kWZ3J4mvzG8DR3dw4HvHcKGhu3";

    let (status, _) = support::call(
        fixture.env.router(),
        "PATCH",
        &format!("/api/v1/contacts/{unknown}"),
        Some(&fixture.owner_token),
        Some(json!({"alias": "nope"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = support::call(
        fixture.env.router(),
        "DELETE",
        &format!("/api/v1/contacts/{unknown}"),
        Some(&fixture.owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// `known_trusted_peer_dids` reads the trusted-peer registries. A Circle peer
/// that is *not* a browser member has to appear there as well before it can be
/// saved — the second gate in `ensure_saveable_contact_did`.
#[tokio::test]
async fn a_circle_peer_absent_from_the_trusted_registry_is_refused() {
    let fixture = fixture().await;

    let registry =
        std::path::Path::new(&fixture.env.state.log_dir_primary).join("trusted_peers.json");
    std::fs::create_dir_all(registry.parent().expect("parent")).expect("log dir");
    std::fs::write(
        &registry,
        serde_json::to_vec(&json!([{
            "peer_id": "nodeB",
            "status": "verified",
            "ip": "127.0.0.1",
            "did": "did:guardian:9iwQY8smBVRjQHqDt4kWZ3J4mvzG8DR3dw4HvHcKGhu3",
        }]))
        .expect("serialize"),
    )
    .expect("write registry");

    // Present in the trusted registry, but not a member of any Circle here, so
    // the first gate still refuses it.
    let (status, body) = create_contact(
        &fixture,
        &fixture.owner_token,
        json!({"did": "did:guardian:9iwQY8smBVRjQHqDt4kWZ3J4mvzG8DR3dw4HvHcKGhu3"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
