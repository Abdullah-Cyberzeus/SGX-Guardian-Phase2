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

fn multipart_body(boundary: &str, filename: &str, content_type: &str, content: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

fn empty_multipart_body(boundary: &str) -> Vec<u8> {
    format!("--{boundary}--\r\n").into_bytes()
}

#[tokio::test]
async fn upload_and_download_a_chat_attachment_round_trip() {
    let env = support::Env::new();
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", vault_dir.path());

    let token = env.owner_token().await;
    let router = env.router();

    let boundary = "cov-chat-attach-boundary";
    let body = multipart_body(boundary, "note.txt", "text/plain", b"hello attachment");
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

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("upload response");
    assert_eq!(response.status(), StatusCode::OK, "upload should succeed");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read upload response body");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("parse upload response");
    let attachment_id = parsed["attachment_id"]
        .as_str()
        .expect("attachment_id present")
        .to_string();
    assert_eq!(parsed["status"], "uploaded");

    let download_uri = format!("/api/v1/chat/download/{attachment_id}");
    let download_request = Request::builder()
        .method("GET")
        .uri(&download_uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build download request");
    let download_response = router
        .oneshot(download_request)
        .await
        .expect("download response");
    assert_eq!(
        download_response.status(),
        StatusCode::OK,
        "download should succeed"
    );
    let downloaded = axum::body::to_bytes(download_response.into_body(), usize::MAX)
        .await
        .expect("read downloaded bytes");
    assert_eq!(downloaded.as_ref(), b"hello attachment");

    std::env::remove_var("SGX_GUARDIAN_VAULT_BASE");
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
async fn upload_with_idempotency_key_replay_returns_the_same_attachment_without_reingesting() {
    let env = support::Env::new();
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", vault_dir.path());

    let token = env.owner_token().await;
    let router = env.router();
    let idempotency_key = "cov-chat-attach-idem-key-1";

    let boundary = "cov-chat-attach-idem-boundary";
    let body = multipart_body(boundary, "note.txt", "text/plain", b"idempotent content");
    let first_request = Request::builder()
        .method("POST")
        .uri("/api/v1/chat/upload")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("idempotency-key", idempotency_key)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("build first request");
    let first_response = router
        .clone()
        .oneshot(first_request)
        .await
        .expect("first upload response");
    assert_eq!(first_response.status(), StatusCode::OK);
    let first_bytes = axum::body::to_bytes(first_response.into_body(), usize::MAX)
        .await
        .expect("read first response body");
    let first_parsed: serde_json::Value =
        serde_json::from_slice(&first_bytes).expect("parse first response");
    let first_attachment_id = first_parsed["attachment_id"]
        .as_str()
        .expect("attachment_id present")
        .to_string();

    let replay_body = multipart_body(boundary, "note.txt", "text/plain", b"idempotent content");
    let replay_request = Request::builder()
        .method("POST")
        .uri("/api/v1/chat/upload")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("idempotency-key", idempotency_key)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(replay_body))
        .expect("build replay request");
    let replay_response = router
        .oneshot(replay_request)
        .await
        .expect("replay upload response");
    assert_eq!(replay_response.status(), StatusCode::OK);
    let replay_bytes = axum::body::to_bytes(replay_response.into_body(), usize::MAX)
        .await
        .expect("read replay response body");
    let replay_parsed: serde_json::Value =
        serde_json::from_slice(&replay_bytes).expect("parse replay response");
    assert_eq!(replay_parsed["attachment_id"], first_attachment_id);

    std::env::remove_var("SGX_GUARDIAN_VAULT_BASE");
}

#[tokio::test]
async fn upload_rejects_a_file_over_the_50_mib_limit() {
    let env = support::Env::new();
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", vault_dir.path());

    let token = env.owner_token().await;
    let router = env.router();

    let boundary = "cov-chat-attach-oversize";
    let oversized = vec![0u8; 50 * 1024 * 1024 + 1];
    let body = multipart_body(boundary, "huge.bin", "application/octet-stream", &oversized);
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/chat/upload")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("build request");
    let response = router.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

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
