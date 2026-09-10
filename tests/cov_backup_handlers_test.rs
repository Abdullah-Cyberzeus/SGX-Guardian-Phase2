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

fn multipart_body(
    boundary: &str,
    passphrase: Option<&str>,
    file: Option<(&str, &[u8])>,
) -> Vec<u8> {
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
            format!(
                "Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\r\n"
            )
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
    let bundle_bytes = tokio::fs::read(source_config.bundle_path(&record.id))
        .await
        .expect("read bundle");

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
