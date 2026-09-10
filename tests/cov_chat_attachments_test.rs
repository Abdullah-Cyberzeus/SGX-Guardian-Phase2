//! Integration tests for `src/api/handlers/chat_attachments.rs`.
//!
//! `upload_attachment` takes a real `axum::extract::Multipart`, which can only be
//! constructed via real HTTP request parsing (no synthetic literal exists for it), so this
//! goes through the real router with a hand-built `multipart/form-data` body rather than
//! calling the handler function directly.
//!
//! Uses the shared `wave_b_support::Env` fixture (bootstrapped owner identity), plus
//! `SGX_GUARDIAN_VAULT_BASE` pointed at this env's own tempdir so vault storage doesn't touch
//! `/var/lib/sgx-guardian`. Per that fixture's own documented convention, run with
//! `--test-threads=1` (shared process-global env vars).

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

fn empty_multipart_body(boundary: &str) -> Vec<u8> {
    format!("--{boundary}--\r\n").into_bytes()
}

#[tokio::test]
async fn upload_rejects_a_request_with_no_file_field() {
    let env = support::Env::new();
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", vault_dir.path());

    let token = env.owner_token().await;
    let router = env.router();

    let boundary = "cov-chat-attach-empty";
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/chat/upload")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(empty_multipart_body(boundary)))
        .expect("build request");

    let response = router.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    std::env::remove_var("SGX_GUARDIAN_VAULT_BASE");
}

#[tokio::test]
async fn download_reports_not_found_for_an_unknown_attachment_id() {
    let env = support::Env::new();
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", vault_dir.path());

    let token = env.owner_token().await;
    let router = env.router();

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/chat/download/does-not-exist")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request");
    let response = router.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    std::env::remove_var("SGX_GUARDIAN_VAULT_BASE");
}
