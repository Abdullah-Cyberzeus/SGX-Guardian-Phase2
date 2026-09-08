//! Integration tests for `src/api/handlers/vc.rs`, the largest completely
//! untested Wave H handler (baseline 21/564 lines, 3.72% — the plan doc's
//! prior "422/564" claim did not survive re-verification with a real
//! `cargo tarpaulin` run and is treated as stale per this plan's own
//! data-integrity rule).
//!
//! Uses the shared `wave_b_support::Env` fixture, which bootstraps a real
//! Circle-owner identity via `SGX_GUARDIAN_DID_PATH`/`SGX_GUARDIAN_DEVICE_KEY_DIR`
//! + `SGX_FORCE_SOFTWARE_KEYS` — exactly the env vars `load_issuer_record()`/
//! `load_runtime_signing_context()` read — so `issue`/`renew`/`revoke`/`verify`
//! can be exercised as real, successful end-to-end flows, not just error paths.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

struct VcEnv {
    _env: support::Env,
    router: axum::Router,
    token: String,
}

impl VcEnv {
    async fn new() -> Self {
        let env = support::Env::new();
        let token = env.owner_token().await;
        let router = env.router();
        Self {
            _env: env,
            router,
            token,
        }
    }
}

async fn json_request(
    env: &VcEnv,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {}", env.token));
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let request = builder.body(body).expect("build request");
    let response = env.router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let parsed = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, parsed)
}

fn new_subject_did(seed: &str) -> String {
    sgx_guardian_client::api::handlers::browser_member::did_for_registration(seed)
}

#[tokio::test]
async fn issue_creates_a_new_member_vc_and_reuses_it_on_replay() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-issue-subject-1");

    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "issue response: {body}");
    assert_eq!(body["reused"], false);
    let vc_id = body["vc_id"].as_str().expect("vc_id").to_string();

    // Reissuing to the same subject/role must reuse the existing active VC.
    let (replay_status, replay_body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(replay_body["reused"], true);
    assert_eq!(replay_body["vc_id"], vc_id);
}

#[tokio::test]
async fn issue_rejects_missing_subject_invalid_role_and_invalid_days() {
    let env = VcEnv::new().await;

    let (missing_status, missing_body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(missing_status, StatusCode::BAD_REQUEST);
    assert!(missing_body.to_string().contains("to is required"));

    let subject = new_subject_did("vc-issue-bad-role");
    let (role_status, role_body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "superuser" })),
    )
    .await;
    assert_eq!(role_status, StatusCode::BAD_REQUEST);
    assert!(role_body.to_string().contains("unsupported role"));

    let (days_status, days_body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "days": 0 })),
    )
    .await;
    assert_eq!(days_status, StatusCode::BAD_REQUEST);
    assert!(days_body.to_string().contains("days must be between"));
}

#[tokio::test]
async fn renew_extends_an_existing_vc_and_reports_not_found_for_an_unknown_one() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-renew-subject");
    let (_, issued) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 5 })),
    )
    .await;
    let vc_id = issued["vc_id"].as_str().expect("vc_id").to_string();

    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/renew",
        Some(serde_json::json!({ "id": vc_id, "days": 90 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "renew response: {body}");
    assert_eq!(body["vc_id"], vc_id);

    let (not_found_status, _) = json_request(
        &env,
        "POST",
        "/api/v1/vc/renew",
        Some(serde_json::json!({ "id": "urn:uuid:00000000-0000-0000-0000-000000000000", "days": 30 })),
    )
    .await;
    assert_eq!(not_found_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn renew_rejects_a_missing_id_and_missing_days() {
    let env = VcEnv::new().await;
    let (id_status, id_body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/renew",
        Some(serde_json::json!({ "days": 30 })),
    )
    .await;
    assert_eq!(id_status, StatusCode::BAD_REQUEST);
    assert!(id_body.to_string().contains("id is required"));

    let (days_status, days_body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/renew",
        Some(serde_json::json!({ "id": "urn:uuid:00000000-0000-0000-0000-000000000000" })),
    )
    .await;
    assert_eq!(days_status, StatusCode::BAD_REQUEST);
    assert!(days_body.to_string().contains("days is required"));
}

#[tokio::test]
async fn revoke_marks_a_vc_revoked_and_reports_not_found_for_an_unknown_one() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-revoke-subject");
    let (_, issued) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;
    let vc_id = issued["vc_id"].as_str().expect("vc_id").to_string();

    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/revoke",
        Some(serde_json::json!({ "id": vc_id, "reason": "compromised" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke response: {body}");
    assert_eq!(body["revoked"], true);

    let (status_status, status_body) =
        json_request(&env, "GET", &format!("/api/v1/vc/status/{vc_id}"), None).await;
    assert_eq!(status_status, StatusCode::OK);
    assert_eq!(status_body["revoked"], true);
    assert_eq!(status_body["active"], false);

    let (not_found_status, _) = json_request(
        &env,
        "POST",
        "/api/v1/vc/revoke",
        Some(serde_json::json!({ "id": "urn:uuid:00000000-0000-0000-0000-000000000000" })),
    )
    .await;
    assert_eq!(not_found_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_rejects_an_overlong_reason() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-revoke-reason-subject");
    let (_, issued) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;
    let vc_id = issued["vc_id"].as_str().expect("vc_id").to_string();

    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/revoke",
        Some(serde_json::json!({ "id": vc_id, "reason": "x".repeat(300) })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("256 characters or fewer"));

    let (blank_status, blank_body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/revoke",
        Some(serde_json::json!({ "id": vc_id, "reason": "   " })),
    )
    .await;
    assert_eq!(blank_status, StatusCode::BAD_REQUEST);
    assert!(blank_body.to_string().contains("reason must not be empty"));
}

#[tokio::test]
async fn status_reports_active_for_a_freshly_issued_vc_and_bad_request_for_a_malformed_id() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-status-subject");
    let (_, issued) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;
    let vc_id = issued["vc_id"].as_str().expect("vc_id").to_string();

    let (status, body) =
        json_request(&env, "GET", &format!("/api/v1/vc/status?id={vc_id}"), None).await;
    assert_eq!(status, StatusCode::OK, "status response: {body}");
    assert_eq!(body["active"], true);
    assert_eq!(body["revoked"], false);

    let (bad_status, bad_body) =
        json_request(&env, "GET", "/api/v1/vc/status?id=not-a-urn", None).await;
    assert_eq!(bad_status, StatusCode::BAD_REQUEST);
    assert!(bad_body.to_string().contains("urn:uuid:"));
}

#[tokio::test]
async fn verify_reports_valid_for_a_freshly_issued_vc_and_not_found_for_an_unknown_one() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-verify-subject");
    let (_, issued) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;
    let vc_id = issued["vc_id"].as_str().expect("vc_id").to_string();

    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/verify",
        Some(serde_json::json!({ "id": vc_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "verify response: {body}");
    assert_eq!(body["vc_id"], vc_id);
    assert_eq!(body["valid"], true);

    let (not_found_status, _) = json_request(
        &env,
        "POST",
        "/api/v1/vc/verify",
        Some(serde_json::json!({ "id": "urn:uuid:00000000-0000-0000-0000-000000000000" })),
    )
    .await;
    assert_eq!(not_found_status, StatusCode::NOT_FOUND);

    // Verifying a revoked VC must succeed at the HTTP level (200) while
    // reporting `valid: false` with a reason — exercising the "verify
    // failed" branch rather than an HTTP error.
    json_request(
        &env,
        "POST",
        "/api/v1/vc/revoke",
        Some(serde_json::json!({ "id": vc_id, "reason": "test revoke before verify" })),
    )
    .await;
    let (revoked_verify_status, revoked_verify_body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/verify",
        Some(serde_json::json!({ "id": vc_id })),
    )
    .await;
    assert_eq!(revoked_verify_status, StatusCode::OK);
    assert_eq!(revoked_verify_body["valid"], false, "{revoked_verify_body}");
    assert!(revoked_verify_body["reason"].is_string());
}

#[tokio::test]
async fn list_and_own_files_reflect_a_freshly_issued_vc() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-list-subject");
    json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;

    // `list`/`files_own` read the *issuer's own* VC store, which after
    // `bootstrap_owner_identity` already holds at least the owner's own
    // mesh-membership VC, regardless of what was just issued to `subject`
    // (issued VCs land in the issuer's "issued" store, not "own").
    let (list_status, list_body) = json_request(&env, "GET", "/api/v1/vc/list", None).await;
    assert_eq!(list_status, StatusCode::OK);
    assert!(list_body["count"].as_u64().unwrap() >= 1);

    let (files_own_status, files_own_body) =
        json_request(&env, "GET", "/api/v1/vc/files/own", None).await;
    assert_eq!(files_own_status, StatusCode::OK);
    assert!(files_own_body["count"].as_u64().unwrap() >= 1);

    let (issued_status, issued_body) =
        json_request(&env, "GET", "/api/v1/vc/files/issued", None).await;
    assert_eq!(issued_status, StatusCode::OK);
    assert!(
        issued_body["count"].as_u64().unwrap() >= 1,
        "issued list: {issued_body}"
    );

    let (peers_status, peers_body) = json_request(&env, "GET", "/api/v1/vc/peers", None).await;
    assert_eq!(peers_status, StatusCode::OK, "peers response: {peers_body}");
    assert!(peers_body["count"].is_u64());
}

#[tokio::test]
async fn show_filters_by_scope_role_and_status() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-show-subject");
    json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;

    let (all_status, all_body) = json_request(&env, "GET", "/api/v1/vc/show?scope=all", None).await;
    assert_eq!(all_status, StatusCode::OK);
    assert!(all_body["count"].as_u64().unwrap() >= 1);

    let (issued_status, issued_body) = json_request(
        &env,
        "GET",
        "/api/v1/vc/show?scope=issued&role=member",
        None,
    )
    .await;
    assert_eq!(issued_status, StatusCode::OK);
    assert!(
        issued_body["count"].as_u64().unwrap() >= 1,
        "issued+member: {issued_body}"
    );

    let (bad_scope_status, bad_scope_body) =
        json_request(&env, "GET", "/api/v1/vc/show?scope=bogus", None).await;
    assert_eq!(bad_scope_status, StatusCode::BAD_REQUEST);
    assert!(bad_scope_body.to_string().contains("unsupported scope"));

    let (bad_status_status, bad_status_body) =
        json_request(&env, "GET", "/api/v1/vc/show?status=bogus", None).await;
    assert_eq!(bad_status_status, StatusCode::BAD_REQUEST);
    assert!(bad_status_body.to_string().contains("unsupported status"));

    let (active_status, active_body) =
        json_request(&env, "GET", "/api/v1/vc/show?status=active", None).await;
    assert_eq!(active_status, StatusCode::OK);
    assert!(active_body["count"].as_u64().unwrap() >= 1);

    // No issued VC has been revoked yet: the "revoked" filter must exclude
    // everything without erroring.
    let (revoked_status, revoked_body) =
        json_request(&env, "GET", "/api/v1/vc/show?status=revoked", None).await;
    assert_eq!(revoked_status, StatusCode::OK);
    assert_eq!(revoked_body["count"], 0);

    let (expired_status, expired_body) =
        json_request(&env, "GET", "/api/v1/vc/show?status=expired", None).await;
    assert_eq!(expired_status, StatusCode::OK);
    assert_eq!(expired_body["count"], 0);

    let (bad_role_status, bad_role_body) =
        json_request(&env, "GET", "/api/v1/vc/show?role=superuser", None).await;
    assert_eq!(bad_role_status, StatusCode::BAD_REQUEST);
    assert!(bad_role_body.to_string().contains("unsupported role"));
}

#[tokio::test]
async fn file_issued_own_and_peer_return_the_underlying_json_or_not_found() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-file-subject");
    let (_, issued) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;
    let vc_id = issued["vc_id"].as_str().expect("vc_id").to_string();

    let (found_status, found_body) = json_request(
        &env,
        "GET",
        &format!("/api/v1/vc/files/issued/{vc_id}"),
        None,
    )
    .await;
    assert_eq!(
        found_status,
        StatusCode::OK,
        "file_issued response: {found_body}"
    );
    assert_eq!(found_body["id"], vc_id);

    let (not_found_status, _) = json_request(
        &env,
        "GET",
        "/api/v1/vc/files/issued/urn:uuid:00000000-0000-0000-0000-000000000000",
        None,
    )
    .await;
    assert_eq!(not_found_status, StatusCode::NOT_FOUND);

    let (peer_not_found_status, _) = json_request(
        &env,
        "GET",
        &format!(
            "/api/v1/vc/files/peer/{}",
            new_subject_did("vc-no-such-peer")
        ),
        None,
    )
    .await;
    assert_eq!(peer_not_found_status, StatusCode::NOT_FOUND);

    // `bootstrap_owner_identity` seeds the owner's own mesh-membership VC,
    // which `list`/`files_own` already confirm is present — look it up and
    // fetch it by id to exercise `file_own`'s success path.
    let (_, own_list) = json_request(&env, "GET", "/api/v1/vc/list", None).await;
    let own_vc_id = own_list["vcs"][0]["id"]
        .as_str()
        .expect("own vc id")
        .to_string();
    let (own_status, own_body) = json_request(
        &env,
        "GET",
        &format!("/api/v1/vc/files/own/{own_vc_id}"),
        None,
    )
    .await;
    assert_eq!(own_status, StatusCode::OK, "file_own response: {own_body}");
    assert_eq!(own_body["id"], own_vc_id);

    let (files_peers_status, files_peers_body) =
        json_request(&env, "GET", "/api/v1/vc/files/peers", None).await;
    assert_eq!(
        files_peers_status,
        StatusCode::OK,
        "files_peers: {files_peers_body}"
    );
    assert!(files_peers_body["count"].is_u64());

    let (bad_id_status, _) =
        json_request(&env, "GET", "/api/v1/vc/files/own/not-a-urn", None).await;
    assert_eq!(bad_id_status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn status_list_and_index_are_readable_after_bootstrap() {
    let env = VcEnv::new().await;

    let (list_status, _) = json_request(&env, "GET", "/api/v1/vc/status-list", None).await;
    assert_eq!(list_status, StatusCode::OK);

    let (index_status, index_body) =
        json_request(&env, "GET", "/api/v1/vc/status-list-index", None).await;
    assert_eq!(
        index_status,
        StatusCode::OK,
        "status-list-index: {index_body}"
    );
}

#[tokio::test]
async fn summary_reports_aggregate_counts_after_issuing_and_revoking() {
    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-summary-subject");
    let (_, issued) = json_request(
        &env,
        "POST",
        "/api/v1/vc/issue",
        Some(serde_json::json!({ "to": subject, "role": "member", "days": 30 })),
    )
    .await;
    let vc_id = issued["vc_id"].as_str().expect("vc_id").to_string();
    json_request(
        &env,
        "POST",
        "/api/v1/vc/revoke",
        Some(serde_json::json!({ "id": vc_id, "reason": "test" })),
    )
    .await;

    let (status, body) = json_request(&env, "GET", "/api/v1/vc/summary", None).await;
    assert_eq!(status, StatusCode::OK, "summary response: {body}");
    assert!(body["issued_total"].as_u64().unwrap() >= 1);
    assert!(body["revoked_total"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn audit_filters_by_action_and_respects_limit() {
    let env = VcEnv::new().await;

    // The real process-wide `AUDIT_LOGGER` is only initialized by `main.rs`
    // at real startup, so `log_audit()` calls made through the handlers
    // silently no-op in tests. `resolve_audit_log_path()` honors
    // `SGX_GUARDIAN_AUDIT_LOG_PATH` though, so write the exact on-disk
    // record shape (`AuditWriter::build_record`) by hand instead.
    let log_dir = tempfile::tempdir().expect("audit log tempdir");
    let log_path = log_dir.path().join("audit.jsonl");
    let lines = [
        serde_json::json!({
            "previous_hash": "0",
            "hash": "1",
            "event": {
                "timestamp": 1_700_000_000u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Info",
                "action": "Succeeded",
                "message": "VC_VERIFY_SUCCESS: urn:uuid:00000000-0000-0000-0000-000000000000",
            }
        }),
        serde_json::json!({
            "previous_hash": "1",
            "hash": "2",
            "event": {
                "timestamp": 1_700_000_001u64,
                "node_id": "nodeA",
                "category": "Network",
                "severity": "Info",
                "action": "Succeeded",
                "message": "unrelated non-VC event",
            }
        }),
        serde_json::json!({
            "previous_hash": "2",
            "hash": "3",
            "event": {
                "timestamp": 1_700_000_002u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Info",
                "action": "Loaded",
                "message": "VC_REUSED_NO_CHANGE: urn:uuid:1 for did:guardian:x",
            }
        }),
        serde_json::json!({
            "previous_hash": "3",
            "hash": "4",
            "event": {
                "timestamp": 1_700_000_003u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Warning",
                "action": "Failed",
                "message": "VC_VERIFY_FAILED: urn:uuid:2 (expired)",
            }
        }),
        serde_json::json!({
            "previous_hash": "4",
            "hash": "5",
            "event": {
                "timestamp": 1_700_000_004u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Info",
                "action": "Succeeded",
                "message": "Issued VC urn:uuid:3 to did:guardian:y",
            }
        }),
        serde_json::json!({
            "previous_hash": "5",
            "hash": "6",
            "event": {
                "timestamp": 1_700_000_005u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Info",
                "action": "Succeeded",
                "message": "VC renewed by Circle owner: urn:uuid:4",
            }
        }),
        serde_json::json!({
            "previous_hash": "6",
            "hash": "7",
            "event": {
                "timestamp": 1_700_000_006u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Warning",
                "action": "Succeeded",
                "message": "Revoked VC urn:uuid:5 reason=compromised",
            }
        }),
        serde_json::json!({
            "previous_hash": "7",
            "hash": "8",
            "event": {
                "timestamp": 1_700_000_007u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Info",
                "action": "Succeeded",
                "message": "some message not matching any known VC audit action",
            }
        }),
        serde_json::json!({
            "previous_hash": "8",
            "hash": "9",
            "event": {
                "timestamp": 1_700_000_008u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Info",
                "action": "Loaded",
                "message": "VC_FILE_READ: own/urn:uuid:6",
            }
        }),
        serde_json::json!({
            "previous_hash": "9",
            "hash": "10",
            "event": {
                "timestamp": 1_700_000_009u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Info",
                "action": "Loaded",
                "message": "VC_SUMMARY_READ: summary requested",
            }
        }),
        serde_json::json!({
            "previous_hash": "10",
            "hash": "11",
            "event": {
                "timestamp": 1_700_000_010u64,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": "Info",
                "action": "Loaded",
                "message": "VC_STATUS_LIST_PULLED: issuer=did:guardian:ca next_index=1",
            }
        }),
    ];
    // A line that isn't valid JSON, and a line whose JSON has no "event"
    // key, must both be skipped without aborting the whole read.
    let malformed_line = "not json at all".to_string();
    let no_event_line = serde_json::json!({ "previous_hash": "11", "hash": "12" }).to_string();
    let body = lines
        .iter()
        .map(|line| line.to_string())
        .chain(std::iter::once(malformed_line))
        .chain(std::iter::once(no_event_line))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&log_path, body).expect("write audit log");
    std::env::set_var("SGX_GUARDIAN_AUDIT_LOG_PATH", &log_path);

    let (status, body) = json_request(&env, "GET", "/api/v1/vc/audit", None).await;
    assert_eq!(status, StatusCode::OK, "audit response: {body}");
    // 11 well-formed lines plus a malformed line and a no-"event" line: 1
    // non-"Vc" category, 1 "Vc" line whose message matches no known action
    // pattern, the malformed line, and the no-"event" line are all skipped
    // by `read_vc_audit_items`, leaving 9 of the 11 well-formed lines.
    assert_eq!(body["count"], 9, "audit response: {body}");
    let actions: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"VC_VERIFY_SUCCESS"));
    assert!(actions.contains(&"VC_REUSED_NO_CHANGE"));
    assert!(actions.contains(&"VC_VERIFY_FAILED"));
    assert!(actions.contains(&"VC_ISSUED"));
    assert!(actions.contains(&"VC_RENEWED"));
    assert!(actions.contains(&"VC_REVOKED"));
    assert!(actions.contains(&"VC_FILE_READ"));
    assert!(actions.contains(&"VC_SUMMARY_READ"));
    assert!(actions.contains(&"VC_STATUS_LIST_PULLED"));

    let (filtered_status, filtered_body) =
        json_request(&env, "GET", "/api/v1/vc/audit?action=NoSuchAction", None).await;
    assert_eq!(filtered_status, StatusCode::OK);
    assert_eq!(filtered_body["count"], 0);

    let (limited_status, limited_body) =
        json_request(&env, "GET", "/api/v1/vc/audit?limit=0", None).await;
    assert_eq!(limited_status, StatusCode::OK);
    assert_eq!(limited_body["count"], 0);

    std::env::remove_var("SGX_GUARDIAN_AUDIT_LOG_PATH");
}

#[tokio::test]
async fn pull_status_rejects_an_unroutable_ca_host_explicitly() {
    let env = VcEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/vc/status-list/pull",
        Some(serde_json::json!({ "ca_host": "127.0.0.1" })),
    )
    .await;
    // No real CA is listening in this sandbox, so the real (unmocked) pull
    // attempt fails deterministically with a connection error mapped to a
    // non-success status — this exercises the network-attempt branch rather
    // than the "CA host is not configured" validation branch, since this
    // repo's checked-in `config/nodeA.yaml` provides a fallback CA host
    // (127.0.0.1) that `resolve_ca_host()` would otherwise pick up anyway.
    assert!(!status.is_success(), "pull_status response: {body}");
}

#[tokio::test]
async fn pull_status_falls_back_to_resolve_ca_host_when_no_host_is_given() {
    let env = VcEnv::new().await;
    // No `ca_host`/`owner_addr` in the body at all, and no `SGX_CA_HOST` env
    // var set: `resolve_ca_host()` falls through to its checked-in-file
    // fallbacks, including the relative `config/nodeA.yaml` (present in
    // this repo, ip "127.0.0.1") — exercising that fallback chain rather
    // than short-circuiting on an explicit request field.
    let previous = std::env::var_os("SGX_CA_HOST");
    std::env::remove_var("SGX_CA_HOST");

    let (status, body) = json_request(&env, "POST", "/api/v1/vc/status-list/pull", None).await;
    assert!(!status.is_success(), "pull_status response: {body}");

    if let Some(previous) = previous {
        std::env::set_var("SGX_CA_HOST", previous);
    }
}

#[tokio::test]
async fn status_and_summary_report_a_vc_with_a_past_expiration_date_as_expired() {
    use sgx_guardian_client::did::document::Proof;
    use sgx_guardian_client::vc::credential::{
        CredentialRole, CredentialStatus, CredentialSubject, MembershipStatus,
        VerifiableCredential, TYPE_CIRCLE_MEMBERSHIP, TYPE_VC, VC_CONTEXT_CORE,
    };

    let env = VcEnv::new().await;
    let subject = new_subject_did("vc-expired-subject");
    let vc_id = "urn:uuid:11111111-1111-1111-1111-111111111111".to_string();
    let vc = VerifiableCredential {
        context: vec![VC_CONTEXT_CORE.to_string()],
        id: vc_id.clone(),
        vc_type: vec![TYPE_VC.to_string(), TYPE_CIRCLE_MEMBERSHIP.to_string()],
        issuer: env._env.state.device_did.clone(),
        issuance_date: "2020-01-01T00:00:00Z".to_string(),
        expiration_date: "2020-02-01T00:00:00Z".to_string(),
        credential_subject: CredentialSubject::new(
            subject,
            CredentialRole::Member,
            vec!["READ".to_string()],
            "2020-01-01T00:00:00Z".to_string(),
            "guardian-circle-alpha".to_string(),
            None,
            MembershipStatus::Active,
        ),
        credential_status: CredentialStatus {
            id: format!("{}/status-list#1", env._env.state.device_did),
            status_type: "StatusList2021Entry".to_string(),
            status_purpose: "revocation".to_string(),
            status_list_index: "1".to_string(),
            status_list_credential: format!("{}/status-list", env._env.state.device_did),
        },
        proof: Proof::default(),
    };
    sgx_guardian_client::vc::persistence::save_issued(&vc).expect("seed expired vc");

    let (status_code, status_body) =
        json_request(&env, "GET", &format!("/api/v1/vc/status/{vc_id}"), None).await;
    assert_eq!(
        status_code,
        StatusCode::OK,
        "status response: {status_body}"
    );
    assert_eq!(status_body["expired"], true);
    assert_eq!(status_body["active"], false);
    assert_eq!(status_body["reason"], "VC expired");

    let (summary_status, summary_body) =
        json_request(&env, "GET", "/api/v1/vc/summary", None).await;
    assert_eq!(
        summary_status,
        StatusCode::OK,
        "summary response: {summary_body}"
    );
    assert!(summary_body["expired_total"].as_u64().unwrap() >= 1);
}
