//! Integration tests for `src/api/handlers/backup.rs`.
//!
//! `BackupConfig::from_env()` reads the unconditional `SGX_GUARDIAN_BACKUP_BASE`
//! env var (see `src/backup/mod.rs`), so a real backup store can be pointed at a
//! tempdir with no mocking. Uses the shared `wave_b_support::Env` fixture for the
//! router. Run with `--test-threads=1` (shared process-global env var).

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

fn multipart_body(boundary: &str, passphrase: Option<&str>, file: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(passphrase) = passphrase {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"passphrase\"\r\n\r\n");
        body.extend_from_slice(passphrase.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    if let Some((filename, content)) = file {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

struct BackupEnv {
    _env: support::Env,
    _base: tempfile::TempDir,
    router: axum::Router,
    token: String,
}

impl BackupEnv {
    async fn new() -> Self {
        let env = support::Env::new();
        let base = tempfile::tempdir().expect("backup tempdir");
        std::env::set_var("SGX_GUARDIAN_BACKUP_BASE", base.path());
        let token = env.owner_token().await;
        let router = env.router();
        Self {
            _env: env,
            _base: base,
            router,
            token,
        }
    }
}

async fn json_request(
    env: &BackupEnv,
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

#[tokio::test]
async fn create_rejects_empty_passphrase() {
    let env = BackupEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/backup/create",
        Some(serde_json::json!({ "passphrase": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("passphrase must not be empty"));
}

#[tokio::test]
async fn create_and_history_round_trip() {
    let env = BackupEnv::new().await;

    let (empty_status, empty_history) =
        json_request(&env, "GET", "/api/v1/backup/history", None).await;
    assert_eq!(empty_status, StatusCode::OK);
    assert_eq!(empty_history["records"].as_array().unwrap().len(), 0);

    let (create_status, created) = json_request(
        &env,
        "POST",
        "/api/v1/backup/create",
        Some(serde_json::json!({ "passphrase": "correct horse battery staple", "portable": true })),
    )
    .await;
    assert_eq!(create_status, StatusCode::OK);
    let backup_id = created["id"].as_str().expect("backup id").to_string();

    let (history_status, history) =
        json_request(&env, "GET", "/api/v1/backup/history", None).await;
    assert_eq!(history_status, StatusCode::OK);
    let backups = history["records"].as_array().expect("backups array");
    assert_eq!(backups.len(), 1);
    assert_eq!(backups[0]["id"], backup_id);
}

#[tokio::test]
async fn download_reports_not_found_and_rejects_empty_id() {
    let env = BackupEnv::new().await;

    let (empty_status, _) = json_request(&env, "GET", "/api/v1/backup/download/", None).await;
    assert_eq!(empty_status, StatusCode::NOT_FOUND);

    let (not_found_status, _) =
        json_request(&env, "GET", "/api/v1/backup/download/does-not-exist", None).await;
    assert_eq!(not_found_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn download_and_delete_reject_an_id_that_sanitizes_to_empty() {
    let env = BackupEnv::new().await;

    let (download_status, download_body) =
        json_request(&env, "GET", "/api/v1/backup/download/!!!", None).await;
    assert_eq!(download_status, StatusCode::BAD_REQUEST);
    assert!(download_body
        .to_string()
        .contains("backup id must not be empty"));

    let (delete_status, delete_body) = json_request(&env, "DELETE", "/api/v1/backup/!!!", None).await;
    assert_eq!(delete_status, StatusCode::BAD_REQUEST);
    assert!(delete_body
        .to_string()
        .contains("backup id must not be empty"));
}

#[tokio::test]
async fn download_rejects_a_bundle_over_the_configured_max_bundle_size() {
    let env = BackupEnv::new().await;

    let (_, created) = json_request(
        &env,
        "POST",
        "/api/v1/backup/create",
        Some(serde_json::json!({ "passphrase": "correct horse battery staple" })),
    )
    .await;
    let backup_id = created["id"].as_str().expect("backup id").to_string();

    std::env::set_var("SGX_BACKUP_MAX_BUNDLE_BYTES", "1");
    let (status, body) = json_request(
        &env,
        "GET",
        &format!("/api/v1/backup/download/{backup_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body.to_string().contains("too large to download"));
    std::env::remove_var("SGX_BACKUP_MAX_BUNDLE_BYTES");
}

#[tokio::test]
async fn import_rejects_a_file_over_the_configured_max_bundle_size() {
    let env = BackupEnv::new().await;
    std::env::set_var("SGX_BACKUP_MAX_BUNDLE_BYTES", "10");

    let boundary = "cov-backup-import-configured-oversize";
    let body = multipart_body(
        boundary,
        Some("some-passphrase"),
        Some(("bundle.sgxbak", b"this payload is longer than ten bytes")),
    );
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(parsed.to_string().contains("bundle too large"));

    std::env::remove_var("SGX_BACKUP_MAX_BUNDLE_BYTES");
}

#[tokio::test]
async fn create_download_and_delete_round_trip() {
    let env = BackupEnv::new().await;

    let (_, created) = json_request(
        &env,
        "POST",
        "/api/v1/backup/create",
        Some(serde_json::json!({ "passphrase": "correct horse battery staple" })),
    )
    .await;
    let backup_id = created["id"].as_str().expect("backup id").to_string();

    let download_request = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/backup/download/{backup_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {}", env.token))
        .body(Body::empty())
        .expect("build download request");
    let download_response = env
        .router
        .clone()
        .oneshot(download_request)
        .await
        .expect("download response");
    assert_eq!(download_response.status(), StatusCode::OK);
    assert_eq!(
        download_response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type"),
        "application/octet-stream"
    );
    let bytes = axum::body::to_bytes(download_response.into_body(), usize::MAX)
        .await
        .expect("read download body");
    assert!(!bytes.is_empty());

    let (delete_status, delete_body) = json_request(
        &env,
        "DELETE",
        &format!("/api/v1/backup/{backup_id}"),
        None,
    )
    .await;
    assert_eq!(delete_status, StatusCode::OK);
    assert_eq!(delete_body["status"], "deleted");

    let (redownload_status, _) = json_request(
        &env,
        "GET",
        &format!("/api/v1/backup/download/{backup_id}"),
        None,
    )
    .await;
    assert_eq!(redownload_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_rejects_empty_id() {
    let env = BackupEnv::new().await;
    let (status, _) = json_request(&env, "DELETE", "/api/v1/backup/", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn validate_rejects_empty_passphrase_and_reports_not_found_for_a_real_one() {
    let env = BackupEnv::new().await;

    let (empty_status, _) = json_request(
        &env,
        "POST",
        "/api/v1/backup/validate",
        Some(serde_json::json!({ "id": "whatever", "passphrase": "" })),
    )
    .await;
    assert_eq!(empty_status, StatusCode::BAD_REQUEST);

    let (not_found_status, _) = json_request(
        &env,
        "POST",
        "/api/v1/backup/validate",
        Some(serde_json::json!({ "id": "does-not-exist", "passphrase": "some-passphrase" })),
    )
    .await;
    assert_eq!(not_found_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn restore_is_unconditionally_unavailable() {
    let env = BackupEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/backup/restore",
        Some(serde_json::json!({ "id": "any", "passphrase": "any" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.to_string().contains("legacy /backup/restore is not used"));
}

async fn multipart_request(
    env: &BackupEnv,
    boundary: &str,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/backup/import")
        .header(header::AUTHORIZATION, format!("Bearer {}", env.token))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("build request");
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

#[tokio::test]
async fn import_requires_a_passphrase_field() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-no-passphrase";
    let body = multipart_body(boundary, None, Some(("bundle.sgxbak", b"not a real bundle")));
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed.to_string().contains("passphrase field is required"));
}

#[tokio::test]
async fn import_rejects_empty_passphrase() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-empty-passphrase";
    let body = multipart_body(boundary, Some(""), Some(("bundle.sgxbak", b"not a real bundle")));
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed.to_string().contains("passphrase must not be empty"));
}

#[tokio::test]
async fn import_requires_a_file_field() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-no-file";
    let body = multipart_body(boundary, Some("some-passphrase"), None);
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed.to_string().contains("file field is required"));
}

#[tokio::test]
async fn import_rejects_a_filename_without_the_sgxbak_extension() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-bad-ext";
    let body = multipart_body(boundary, Some("some-passphrase"), Some(("bundle.zip", b"data")));
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed.to_string().contains("must be a .sgxbak bundle"));
}

#[tokio::test]
async fn import_rejects_a_path_traversal_filename() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-traversal";
    let body = multipart_body(
        boundary,
        Some("some-passphrase"),
        Some(("../evil.sgxbak", b"data")),
    );
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed.to_string().contains("unsafe backup filename"));
}

#[tokio::test]
async fn import_rejects_duplicate_passphrase_field() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-dup-passphrase";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"passphrase\"\r\n\r\nfirst\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"passphrase\"\r\n\r\nsecond\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed.to_string().contains("duplicate passphrase field"));
}

#[tokio::test]
async fn import_rejects_duplicate_file_field() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-dup-file";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"a.sgxbak\"\r\n\r\ndata1\r\n",
    );
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"b.sgxbak\"\r\n\r\ndata2\r\n",
    );
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed.to_string().contains("duplicate file field"));
}

#[tokio::test]
async fn import_rejects_an_unexpected_field_name() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-bad-field";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"unexpected\"\r\n\r\nvalue\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed.to_string().contains("unexpected multipart field"));
}

#[tokio::test]
async fn import_rejects_a_field_with_no_name() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-no-name";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data\r\n\r\nvalue\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(parsed
        .to_string()
        .contains("multipart fields must be named file or passphrase"));
}

#[tokio::test]
async fn import_of_a_bogus_bundle_fails_after_staging_and_cleans_up() {
    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-bogus-bundle";
    let body = multipart_body(
        boundary,
        Some("some-passphrase"),
        Some(("bundle.sgxbak", b"not a real encrypted bundle")),
    );
    let (status, _) = multipart_request(&env, boundary, body).await;
    assert!(status.is_client_error() || status.is_server_error());
}

#[tokio::test]
async fn import_round_trips_a_real_backup_created_elsewhere() {
    let source_base = tempfile::tempdir().expect("source backup tempdir");
    let source_config = sgx_guardian_client::backup::BackupConfig {
        base_dir: source_base.path().to_path_buf(),
        max_bundle_bytes: 1024 * 1024 * 1024,
    };
    let state_dir = tempfile::tempdir().expect("state tempdir");
    let config_dir = tempfile::tempdir().expect("config tempdir");
    let source_state = sgx_guardian_client::api::state::AppState::for_tests(
        state_dir.path(),
        "nodeA",
        config_dir.path().to_string_lossy().to_string(),
    );
    let record = sgx_guardian_client::backup::create::create_backup(
        source_state,
        source_config.clone(),
        "correct horse battery staple".to_string(),
        true,
    )
    .await
    .expect("create source backup");
    let bundle_bytes =
        tokio::fs::read(source_config.bundle_path(&record.id)).await.expect("read bundle");

    let env = BackupEnv::new().await;
    let boundary = "cov-backup-import-real";
    let body = multipart_body(
        boundary,
        Some("correct horse battery staple"),
        Some(("real.sgxbak", &bundle_bytes)),
    );
    let (status, parsed) = multipart_request(&env, boundary, body).await;
    assert_eq!(status, StatusCode::OK, "import response: {parsed}");
}
