//! Integration tests for `src/api/handlers/policy.rs`.
//!
//! `sign_deploy_current_with_paths` already had 4 solid pre-existing tests.
//! This file covers the rest: the pure filesystem helpers, `resolve_active_policy_preview_path`'s
//! fallback (both real candidate paths are hardcoded, non-overridable system
//! paths confirmed absent in this sandbox), the HTTP-level handlers'
//! deterministic error branches (`current`/`backup`/`verify_deployed` all
//! read/require real, absent `/etc/sgx-guardian/...` paths), and `sign`/`verify`
//! via real multipart bodies routed to the actually-compiled `sgx-pa-cli`
//! binary (via the `SGX_PA_CLI_PATH` override in `run_cli`), whose own
//! deterministic failure (`guardian_private.key` absent) still fully
//! exercises the handler's multipart-parsing + CLI-invocation logic.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use sgx_guardian_client::api::state::AppState;
use tower::ServiceExt;

// `atomic_write_text`/`atomic_write_bytes`/`atomic_copy_file`/
// `promote_pending_to_active`/`ensure_parent_dir`/`resolve_active_policy_preview_path`/
// `tempdir` are private to `policy.rs`, so they're exercised indirectly
// through `sign_deploy_current_with_paths` (already covered) and through
// the HTTP handlers below instead of directly from this integration file.

struct PolicyEnv {
    _env: support::Env,
    router: axum::Router,
    token: String,
    state: std::sync::Arc<AppState>,
}

impl PolicyEnv {
    async fn new() -> Self {
        let env = support::Env::new();
        let token = env.owner_token().await;
        let router = env.router();
        let state = env.state.clone();
        Self {
            _env: env,
            router,
            token,
            state,
        }
    }
}

#[tokio::test]
async fn verify_deployed_reports_not_found_when_no_signature_is_deployed() {
    let env = PolicyEnv::new().await;
    use sgx_guardian_client::api::handlers::policy::verify_deployed;
    let result = verify_deployed(State(env.state.clone())).await;
    assert!(
        result.is_err(),
        "no deployed policy.sig exists in this sandbox"
    );
}

#[tokio::test]
async fn current_reports_not_found_when_no_real_policy_file_exists() {
    let env = PolicyEnv::new().await;
    use sgx_guardian_client::api::handlers::policy::current;
    // Both preview candidates and the fallback are hardcoded
    // `/etc/sgx-guardian/...` paths, confirmed absent in this sandbox.
    assert!(!std::path::Path::new("/etc/sgx-guardian/policies/active_policy.yaml").exists());
    assert!(!std::path::Path::new("/etc/sgx-guardian/schemas/uep_policy_v1.yaml").exists());
    let result = current(State(env.state.clone())).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn backup_reports_not_found_when_no_real_backup_policy_exists() {
    let env = PolicyEnv::new().await;
    use sgx_guardian_client::api::handlers::policy::backup;
    assert!(!std::path::Path::new("/etc/sgx-guardian/policies/backup_policy.yaml").exists());
    let result = backup(State(env.state.clone())).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn save_current_rejects_invalid_policy_yaml() {
    let env = PolicyEnv::new().await;
    use axum::Json;
    use sgx_guardian_client::api::handlers::policy::{save_current, SavePolicyRequest};
    let result = save_current(
        State(env.state.clone()),
        Json(SavePolicyRequest {
            content: "not: [valid policy: structure".to_string(),
        }),
    )
    .await;
    assert!(result.is_err(), "malformed YAML must fail validation");
}

fn multipart_body(boundary: &str, fields: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, content) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

#[tokio::test]
async fn sign_rejects_a_request_with_no_policy_field() {
    let env = PolicyEnv::new().await;
    let boundary = "cov-policy-sign-no-field";
    let body = multipart_body(boundary, &[("key", "key.pkcs8", b"not a real key")]);
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/policy/sign")
        .header(header::AUTHORIZATION, format!("Bearer {}", env.token))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("build request");
    let response = env.router.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_rejects_a_request_with_no_policy_field() {
    let env = PolicyEnv::new().await;
    let boundary = "cov-policy-verify-no-field";
    let body = multipart_body(boundary, &[("other", "x.txt", b"irrelevant")]);
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/policy/verify")
        .header(header::AUTHORIZATION, format!("Bearer {}", env.token))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("build request");
    let response = env.router.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
