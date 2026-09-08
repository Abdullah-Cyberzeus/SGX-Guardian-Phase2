//! Additional integration tests for `src/api/handlers/xfer.rs`, alongside
//! the pre-existing `tests/cov_xfer_handlers_test.rs` (which already covers
//! empty peer_did, neither/both path+vault_id, missing file path, a member
//! forbidden from targeting a peer outside their circles, and empty
//! list/detail/cancel/inbox responses). This file adds the remaining
//! validation branches and a full local self-transfer success round trip.

#[path = "wave_b_support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

struct XferEnv {
    _env: support::Env,
    _xfer_base: tempfile::TempDir,
    router: axum::Router,
    token: String,
}

impl XferEnv {
    async fn new() -> Self {
        let env = support::Env::new();
        let xfer_base = tempfile::tempdir().expect("xfer base tempdir");
        std::env::set_var("SGX_GUARDIAN_XFER_BASE", xfer_base.path());
        let token = env.owner_token().await;
        let router = env.router();
        Self {
            _env: env,
            _xfer_base: xfer_base,
            router,
            token,
        }
    }
}

async fn json_request(
    env: &XferEnv,
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
async fn send_rejects_an_empty_path() {
    let env = XferEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/xfer/send",
        Some(serde_json::json!({ "peer_did": "did:guardian:peer", "path": "   " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("path must not be empty"));
}

#[tokio::test]
async fn send_rejects_a_path_that_is_a_directory_not_a_regular_file() {
    let env = XferEnv::new().await;
    let dir = tempfile::tempdir().expect("dir");
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/xfer/send",
        Some(serde_json::json!({
            "peer_did": "did:guardian:peer",
            "path": dir.path().to_str().unwrap(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("regular file"));
}

#[tokio::test]
async fn send_rejects_a_file_over_the_configured_max_size() {
    let env = XferEnv::new().await;
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(file.path(), b"0123456789").expect("write");
    std::env::set_var("SGX_XFER_MAX_FILE_BYTES", "5");

    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/xfer/send",
        Some(serde_json::json!({
            "peer_did": "did:guardian:peer",
            "path": file.path().to_str().unwrap(),
        })),
    )
    .await;
    std::env::remove_var("SGX_XFER_MAX_FILE_BYTES");
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "send response: {body}"
    );
    assert!(body.to_string().contains("file too large"));
}

#[tokio::test]
async fn send_rejects_an_invalid_vault_id_format() {
    let env = XferEnv::new().await;
    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/xfer/send",
        Some(serde_json::json!({ "peer_did": "did:guardian:peer", "vault_id": "../escape" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "send response: {body}");
}

#[tokio::test]
async fn detail_rejects_an_empty_id() {
    let env = XferEnv::new().await;
    let (status, _) = json_request(&env, "GET", "/api/v1/xfer/transfers/%20", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cancel_rejects_an_empty_id() {
    let env = XferEnv::new().await;
    let (status, _) = json_request(&env, "POST", "/api/v1/xfer/transfers/%20/cancel", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn send_a_vault_record_to_self_completes_locally_without_any_network_transfer() {
    let env = XferEnv::new().await;
    let vault_base = tempfile::tempdir().expect("vault base");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", vault_base.path());

    // An owner-role session's caller_did resolves via `resolve_sender_did` to
    // the mesh subject DID for this node, which `bootstrap_owner_identity`
    // pins to `state.device_did` — so sending to `state.device_did` as the
    // peer takes the local-recipient short-circuit (`clone_for_local_recipient`),
    // never touching the network.
    let caller_did = env._env.state.device_did.clone();
    let staging = tempfile::NamedTempFile::new().expect("staging file");
    std::fs::write(staging.path(), b"self-transfer payload").expect("write staging file");
    let record = sgx_guardian_client::vault::ingest::ingest_upload_file(
        sgx_guardian_client::vault::namespace::VaultNamespace::Personal,
        &caller_did,
        staging.path(),
        sgx_guardian_client::vault::ingest::IngestMeta {
            filename: "self.txt".to_string(),
            mime: "text/plain".to_string(),
            sha256_plain: {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(b"self-transfer payload"))
            },
            size_plain: "self-transfer payload".len() as u64,
            chunk_bytes: sgx_guardian_client::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
        },
        String::new(),
        String::new(),
    )
    .await
    .expect("seed vault record");

    let (status, body) = json_request(
        &env,
        "POST",
        "/api/v1/xfer/send",
        Some(serde_json::json!({ "peer_did": caller_did, "vault_id": record.vault_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "send response: {body}");
    assert_eq!(body["status"], "accepted");
    let transfer_id = body["transfer_id"]
        .as_str()
        .expect("transfer_id")
        .to_string();
    assert!(transfer_id.starts_with("local-"));

    let (list_status, list_body) = json_request(&env, "GET", "/api/v1/xfer/transfers", None).await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list_body["count"], 1, "{list_body}");

    let (detail_status, detail_body) = json_request(
        &env,
        "GET",
        &format!("/api/v1/xfer/transfers/{transfer_id}"),
        None,
    )
    .await;
    assert_eq!(detail_status, StatusCode::OK, "{detail_body}");
    assert_eq!(detail_body["status"], "completed");

    let (inbox_status, inbox_body) = json_request(&env, "GET", "/api/v1/xfer/inbox", None).await;
    assert_eq!(inbox_status, StatusCode::OK);
    assert_eq!(inbox_body["count"], 1, "{inbox_body}");
}
