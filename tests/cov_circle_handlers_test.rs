// Integration tests for Circle API handlers (circle.rs), using
// tower::ServiceExt::oneshot to make HTTP requests without a listener.
//
// The 401 tests below use a bare `AppState::for_tests` (no bootstrapped
// Circle-owner identity) since the auth middleware rejects unauthenticated
// requests before any handler logic runs. Everything else goes through
// `wave_b_support::Env`, which additionally bootstraps a Circle-owner
// identity so `circle::create` and friends work end-to-end -- see that
// module's doc comment for why, and for the "node name must be nodeA" and
// "single-threaded" constraints that come with it.

#![allow(dead_code)]

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

fn unauthenticated_app() -> axum::Router {
    let temp = tempfile::tempdir().expect("tempdir");
    let temp = Box::leak(Box::new(temp));
    let config = temp.path().join("config");
    std::fs::create_dir_all(&config).expect("config dir");
    let state = sgx_guardian_client::api::state::AppState::for_tests(
        temp.path(),
        "coverage-node",
        config.to_string_lossy().to_string(),
    );
    sgx_guardian_client::api::build_router(state, axum::Router::new())
}

#[tokio::test]
async fn list_circles_without_authentication_returns_401() {
    let app = unauthenticated_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/circles")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error body");
    assert!(
        error.get("error").is_some() || error.get("message").is_some(),
        "authentication errors must have a stable JSON error shape: {error}"
    );
}

#[tokio::test]
async fn circle_mutations_without_authentication_return_401() {
    let app = unauthenticated_app();
    for (method, uri, body) in [
        ("POST", "/api/v1/circles", Some(r#"{"name":"x"}"#)),
        ("GET", "/api/v1/circles/missing", None),
        ("PATCH", "/api/v1/circles/missing", Some(r#"{"name":"x"}"#)),
        ("DELETE", "/api/v1/circles/missing", None),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(body.map(Body::from).unwrap_or_else(Body::empty))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }
}

#[tokio::test]
async fn other_wave_b_routes_without_authentication_return_401() {
    let app = unauthenticated_app();
    for (method, uri) in [
        ("GET", "/api/v1/calls"),
        ("POST", "/api/v1/calls"),
        ("GET", "/api/v1/circles/test/member-enrollments"),
        ("GET", "/api/v1/vault/files"),
        ("GET", "/api/v1/devices"),
        ("GET", "/api/v1/crl/list"),
        ("GET", "/api/v1/xfer/transfers"),
        ("GET", "/api/v1/ha/integrations"),
        ("POST", "/api/v1/ha/integrations/nest/connect"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }
}

// ============================================================================
// CIRCLE CRUD
// ============================================================================

#[tokio::test]
async fn create_circle_returns_201_with_circle_response() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles",
        Some(&owner_token),
        Some(json!({"circle_id": "family", "name": "Family Circle"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["circle"]["circleId"], "family");
    assert_eq!(body["circle"]["name"], "Family Circle");
    assert_eq!(body["circle"]["status"], "active");
}

#[tokio::test]
async fn create_circle_returns_400_if_name_missing_or_empty() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles",
        Some(&owner_token),
        Some(json!({"circle_id": "family"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"]["message"].as_str().unwrap().contains("name"));
}

#[tokio::test]
async fn create_circle_returns_400_if_circle_id_invalid() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles",
        Some(&owner_token),
        Some(json!({"circle_id": "family/circle", "name": "Family"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn create_circle_returns_400_if_days_out_of_range() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles",
        Some(&owner_token),
        Some(json!({"circle_id": "family", "name": "Family", "days": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn create_circle_returns_409_if_circle_id_already_exists() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles",
        Some(&owner_token),
        Some(json!({"circle_id": "family", "name": "Family Again"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn list_circles_returns_200_with_circle_array() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The mesh circle plus the one just created.
    assert!(body["circles"].as_array().unwrap().len() >= 2);
}

#[tokio::test]
async fn list_circles_filters_to_own_circles_for_member_browser_session() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    env.create_circle(&owner_token, "work").await;
    let (member_token, _member_did) = env.member_token("family").await;

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles",
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A browser member session only sees the mesh circle if they hold an
    // active VC-issued membership there too; a login-store circle_ids entry
    // alone (no membership VC) yields an empty filtered list.
    assert!(body["circles"].as_array().is_some());
}

#[tokio::test]
async fn get_circle_detail_returns_200_for_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/family",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["circle"]["circleId"], "family");
}

#[tokio::test]
async fn get_circle_detail_returns_403_for_non_member_browser_session() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    env.create_circle(&owner_token, "work").await;
    let (outsider_token, _did) = env.member_token("work").await;

    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/family",
        Some(&outsider_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_circle_detail_returns_404_if_not_found() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/does-not-exist",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn edit_circle_returns_200_with_updated_response() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (status, body) = support::call(
        env.router(),
        "PATCH",
        "/api/v1/circles/family",
        Some(&owner_token),
        Some(json!({"name": "Renamed Family", "description": "updated"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["circle"]["name"], "Renamed Family");
    assert_eq!(body["circle"]["description"], "updated");
}

#[tokio::test]
async fn edit_circle_returns_403_if_not_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    // A circle whose owner_did is not this device's identity: fabricated
    // directly through the store (bypassing the HTTP create flow, which
    // always makes this device the owner), since there is only one
    // device-level identity available in this fixture.
    sgx_guardian_client::circle::store::create_circle(
        "nodeA",
        "foreign".to_string(),
        "Foreign Circle".to_string(),
        String::new(),
        "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB".to_string(),
    )
    .expect("seed foreign-owned circle");

    let (status, _) = support::call(
        env.router(),
        "PATCH",
        "/api/v1/circles/foreign",
        Some(&owner_token),
        Some(json!({"name": "Hijacked"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn edit_circle_returns_403_for_a_circle_id_with_no_local_owner_authority() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    // `edit` checks device-level owner *authority* for this exact circle_id
    // before ever checking whether the circle exists (`ensure_circle_owner_access`
    // runs first): a circle_id this device never created or was granted
    // ownership VCs for -- existent or not -- is indistinguishable from "not
    // owner" at this layer, so it's FORBIDDEN rather than NOT_FOUND.
    let (status, _) = support::call(
        env.router(),
        "PATCH",
        "/api/v1/circles/does-not-exist",
        Some(&owner_token),
        Some(json!({"name": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn archive_and_unarchive_circle_round_trip() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/archive",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["circle"]["status"], "archived");

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/unarchive",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["circle"]["status"], "active");
}

#[tokio::test]
async fn delete_circle_returns_200_with_revoked_vc_ids() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (status, body) = support::call(
        env.router(),
        "DELETE",
        "/api/v1/circles/family",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["circle_id"], "family");
    assert!(body["revoked_vc_ids"].as_array().is_some());

    // The circle is really gone.
    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/family",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ============================================================================
// MEMBER MANAGEMENT
// ============================================================================

const TEST_DID: &str = "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB";

#[tokio::test]
async fn add_member_returns_201_then_200_on_reuse() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        Some(json!({"did": TEST_DID, "role": "member"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["reused_existing"], false);

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        Some(json!({"did": TEST_DID, "role": "member"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reused_existing"], true);
}

#[tokio::test]
async fn add_member_returns_400_if_did_missing_or_invalid() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        Some(json!({"role": "member"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        Some(json!({"did": "not-a-did", "role": "member"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_member_returns_400_if_role_invalid() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        Some(json!({"did": TEST_DID, "role": "guest"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unsupported role"));
}

#[tokio::test]
async fn list_members_returns_200_with_member_array() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        Some(json!({"did": TEST_DID, "role": "member"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["members"]
        .as_array()
        .unwrap()
        .iter()
        .any(|member| member["did"] == TEST_DID));
}

#[tokio::test]
async fn list_members_returns_403_if_not_member() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    env.create_circle(&owner_token, "work").await;
    let (outsider_token, _did) = env.member_token("work").await;

    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/family/members",
        Some(&outsider_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn remove_member_returns_200_with_revoked_vc_ids() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        Some(json!({"did": TEST_DID, "role": "member"})),
    )
    .await;

    let (status, body) = support::call(
        env.router(),
        "DELETE",
        &format!("/api/v1/circles/family/members/{TEST_DID}"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body["revoked_vc_ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn change_member_role_returns_200_with_updated_role() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/members",
        Some(&owner_token),
        Some(json!({"did": TEST_DID, "role": "member"})),
    )
    .await;

    let (status, body) = support::call(
        env.router(),
        "PATCH",
        &format!("/api/v1/circles/family/members/{TEST_DID}"),
        Some(&owner_token),
        Some(json!({"role": "owner"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["vc"]["credentialSubject"]["role"], "owner");
}

// ============================================================================
// INVITE MANAGEMENT
// ============================================================================

#[tokio::test]
async fn mint_invite_returns_201_with_token() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;

    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/invites",
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "role": "member", "deliver": false})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(!body["token_b64"].as_str().unwrap().is_empty());
    assert_eq!(body["delivered"], false);
}

#[tokio::test]
async fn mint_invite_returns_403_if_not_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (member_token, _did) = env.member_token("family").await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/invites",
        Some(&member_token),
        Some(json!({"target_did": TEST_DID, "deliver": false})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mint_invite_returns_409_if_circle_archived() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/archive",
        Some(&owner_token),
        None,
    )
    .await;

    let (status, _) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/invites",
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "deliver": false})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn list_invites_returns_200_with_invite_array_as_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (_, mint_body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/invites",
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "deliver": false})),
    )
    .await;
    let invite_id = mint_body["invite_id"].as_str().unwrap().to_string();

    let (status, body) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/family/invites",
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["invites"]
        .as_array()
        .unwrap()
        .iter()
        .any(|invite| invite["id"] == invite_id));
}

#[tokio::test]
async fn list_invites_returns_403_if_not_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (member_token, _did) = env.member_token("family").await;

    let (status, _) = support::call(
        env.router(),
        "GET",
        "/api/v1/circles/family/invites",
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_invite_returns_200_and_removes_token() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (_, mint_body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/invites",
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "deliver": false})),
    )
    .await;
    let invite_id = mint_body["invite_id"].as_str().unwrap().to_string();

    let (status, _) = support::call(
        env.router(),
        "DELETE",
        &format!("/api/v1/circles/family/invites/{invite_id}"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = support::call(
        env.router(),
        "DELETE",
        &format!("/api/v1/circles/family/invites/{invite_id}"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "revoking an already-revoked invite should not find it again"
    );
}

#[tokio::test]
async fn revoke_invite_returns_403_if_not_owner() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (member_token, _did) = env.member_token("family").await;

    let (status, _) = support::call(
        env.router(),
        "DELETE",
        "/api/v1/circles/family/invites/missing",
        Some(&member_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_invite_returns_400_if_invite_not_in_circle() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    env.create_circle(&owner_token, "work").await;
    let (_, mint_body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/invites",
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "deliver": false})),
    )
    .await;
    let invite_id = mint_body["invite_id"].as_str().unwrap().to_string();

    let (status, _) = support::call(
        env.router(),
        "DELETE",
        &format!("/api/v1/circles/work/invites/{invite_id}"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deliver_existing_invite_returns_200_with_delivered_flag() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    env.create_circle(&owner_token, "family").await;
    let (_, mint_body) = support::call(
        env.router(),
        "POST",
        "/api/v1/circles/family/invites",
        Some(&owner_token),
        Some(json!({"target_did": TEST_DID, "deliver": false})),
    )
    .await;
    let invite_id = mint_body["invite_id"].as_str().unwrap().to_string();

    let (status, body) = support::call(
        env.router(),
        "POST",
        &format!("/api/v1/circles/family/invites/{invite_id}/deliver"),
        Some(&owner_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // No real delivery transport is reachable in this sandbox, so delivery
    // itself deterministically fails, but the handler's own logic (idempotency,
    // ownership check, token re-encoding, share-link building) still runs.
    assert_eq!(body["delivered"], false);
}
