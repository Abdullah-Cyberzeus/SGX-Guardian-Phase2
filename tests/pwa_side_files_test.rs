use axum::body::{to_bytes, Body};
use axum::extract::{Path, Query, State};
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde_json::Value;
use sgx_guardian_client::api::auth::authorization::default_scopes;
use sgx_guardian_client::api::auth::middleware::AuthenticatedSession;
use sgx_guardian_client::api::auth::session::Claims;
use sgx_guardian_client::api::error::ApiError;
use sgx_guardian_client::api::handlers::browser_member::did_for_registration;
use sgx_guardian_client::api::handlers::vault;
use sgx_guardian_client::api::state::AppState;
use sgx_guardian_client::vault::folders;
use sgx_guardian_client::vault::ingest::{self, IngestMeta};
use sgx_guardian_client::vault::{persistence, VaultConfig, VaultNamespace, VAULT_BASE_ENV};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

struct TestEnv {
    previous: Vec<(&'static str, Option<String>)>,
}

impl TestEnv {
    fn set(temp: &TempDir) -> Self {
        let settings = [
            (VAULT_BASE_ENV, temp.path().join("vault")),
            ("SGX_FORCE_SOFTWARE_KEYS", std::path::PathBuf::from("1")),
            ("SGX_GUARDIAN_DID_PATH", temp.path().join("did.json")),
            (
                "SGX_GUARDIAN_DEVICE_KEY_DIR",
                temp.path().join("device-keys"),
            ),
            (
                "SGX_GUARDIAN_DID_DOC_PATH",
                temp.path().join("did_doc.json"),
            ),
            ("SGX_GUARDIAN_DID_PEERS_DIR", temp.path().join("did-peers")),
            (
                "SGX_GUARDIAN_DID_CA_AGGREGATE_PATH",
                temp.path().join("ca-aggregate.json"),
            ),
            (
                "SGX_GUARDIAN_DID_SELF_VERSION_COUNTER_PATH",
                temp.path().join("did-version-counter"),
            ),
            ("SGX_GUARDIAN_VID_STATE_DIR", temp.path().join("virtual-id")),
        ];
        let previous = settings
            .iter()
            .map(|(key, _)| (*key, std::env::var(key).ok()))
            .collect::<Vec<_>>();
        for (key, value) in settings {
            std::env::set_var(key, value);
        }
        Self { previous }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        for (key, previous) in self.previous.iter().rev() {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn member_session(
    circle_ids: Vec<String>,
    registration_id: &str,
) -> Option<Extension<AuthenticatedSession>> {
    Some(Extension(AuthenticatedSession {
        claims: Claims {
            sub: format!("user-{registration_id}"),
            role: "member".to_string(),
            scopes: default_scopes("member"),
            circle_ids,
            browser_registration_id: Some(registration_id.to_string()),
            guardian_fingerprint: None,
            iss: "did:guardian:test-device".to_string(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 300,
            jti: uuid::Uuid::new_v4().to_string(),
        },
        token: String::new(),
    }))
}

#[allow(clippy::too_many_arguments)]
async fn ingest_member_file(
    temp: &TempDir,
    namespace: VaultNamespace,
    owner_did: &str,
    folder_id: &str,
    filename: &str,
    mime: &str,
    description: &str,
    payload: &[u8],
) -> sgx_guardian_client::vault::VaultRecord {
    let source = temp.path().join(format!("source-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&source, payload)
        .await
        .expect("write source payload");

    ingest::ingest_upload_file(
        namespace,
        owner_did,
        &source,
        IngestMeta {
            filename: filename.to_string(),
            mime: mime.to_string(),
            sha256_plain: hex::encode(Sha256::digest(payload)),
            size_plain: payload.len() as u64,
            chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
        },
        folder_id.to_string(),
        description.to_string(),
    )
    .await
    .expect("ingest PWA files test record")
}

fn multipart_body(
    boundary: &str,
    description: Option<&str>,
    file: Option<(&str, &str, &[u8])>,
) -> String {
    let mut body = String::new();
    if let Some(description) = description {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\n{description}\r\n"
        ));
    }
    if let Some((filename, mime, payload)) = file {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: {mime}\r\n\r\n{}\r\n",
            String::from_utf8_lossy(payload)
        ));
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    body
}

fn upload_router(
    state: std::sync::Arc<AppState>,
    session: &Option<Extension<AuthenticatedSession>>,
) -> Router {
    let Extension(auth) = session.clone().expect("member session");
    Router::new()
        .route("/api/v1/vault/upload", post(vault::upload))
        .with_state(state)
        .layer(Extension(auth))
}

#[tokio::test]
async fn pwa_side_files_test_covers_member_files_feature() {
    let temp = TempDir::new().expect("create PWA files temp dir");
    let _env = TestEnv::set(&temp);
    let config = VaultConfig::from_env();
    let state = AppState::for_tests(
        temp.path(),
        "nodeA",
        temp.path().join("config").to_string_lossy().to_string(),
    );

    let alice_reg = "pwa-files-alice-registration";
    let bob_reg = "pwa-files-bob-registration";
    let alice_did = did_for_registration(alice_reg);
    let bob_did = did_for_registration(bob_reg);
    let alice_auth = member_session(vec!["circle-files".to_string()], alice_reg);
    let bob_auth = member_session(vec!["circle-other".to_string()], bob_reg);

    let shared_folder = folders::create_folder(
        &config,
        &VaultNamespace::Circle("circle-files".to_string()),
        "nodeA",
        "",
        "Team Files",
    )
    .await
    .expect("create shared folder");
    let personal_folder = folders::create_folder(
        &config,
        &VaultNamespace::Personal,
        "nodeA",
        "",
        "Private Notes",
    )
    .await
    .expect("create personal folder");

    let alice_personal = ingest_member_file(
        &temp,
        VaultNamespace::Personal,
        &alice_did,
        "",
        "alice-notes.txt",
        "text/plain",
        "private member notes",
        b"alice private file",
    )
    .await;
    let bob_personal = ingest_member_file(
        &temp,
        VaultNamespace::Personal,
        &bob_did,
        "",
        "bob-notes.txt",
        "text/plain",
        "bob private notes",
        b"bob private file",
    )
    .await;
    let circle_file = ingest_member_file(
        &temp,
        VaultNamespace::Circle("circle-files".to_string()),
        &alice_did,
        "",
        "shared-plan.txt",
        "text/plain",
        "shared with circle",
        b"shared circle file",
    )
    .await;
    let outside_circle_file = ingest_member_file(
        &temp,
        VaultNamespace::Circle("circle-other".to_string()),
        &bob_did,
        "",
        "outside-plan.txt",
        "text/plain",
        "other circle file",
        b"outside circle file",
    )
    .await;

    let Json(alice_personal_list) = vault::list(
        State(state.clone()),
        alice_auth.clone(),
        Query(vault::VaultListQuery {
            circle_id: None,
            namespace: Some(VaultNamespace::PERSONAL_STORAGE_KEY.to_string()),
            folder_id: None,
            starred: None,
        }),
    )
    .await
    .expect("Alice lists her personal files");
    assert_eq!(alice_personal_list.count, 1);
    assert_eq!(
        alice_personal_list.files[0].vault_id,
        alice_personal.vault_id
    );
    assert_eq!(alice_personal_list.files[0].owner_did, alice_did);

    let Json(bob_personal_list) = vault::list(
        State(state.clone()),
        bob_auth.clone(),
        Query(vault::VaultListQuery {
            circle_id: None,
            namespace: Some(VaultNamespace::PERSONAL_STORAGE_KEY.to_string()),
            folder_id: None,
            starred: None,
        }),
    )
    .await
    .expect("Bob lists only his personal files");
    assert_eq!(bob_personal_list.count, 1);
    assert_eq!(bob_personal_list.files[0].vault_id, bob_personal.vault_id);

    let Json(alice_circle_list) = vault::list(
        State(state.clone()),
        alice_auth.clone(),
        Query(vault::VaultListQuery {
            circle_id: Some("circle-files".to_string()),
            namespace: None,
            folder_id: None,
            starred: None,
        }),
    )
    .await
    .expect("Alice lists files in her Circle");
    assert_eq!(alice_circle_list.count, 1);
    assert_eq!(alice_circle_list.files[0].vault_id, circle_file.vault_id);

    let Json(bob_blocked_circle_list) = vault::list(
        State(state.clone()),
        bob_auth.clone(),
        Query(vault::VaultListQuery {
            circle_id: Some("circle-files".to_string()),
            namespace: None,
            folder_id: None,
            starred: None,
        }),
    )
    .await
    .expect("Bob gets no files for a Circle he cannot access");
    assert_eq!(bob_blocked_circle_list.count, 0);

    let Json(detail) = vault::detail(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
    )
    .await
    .expect("Alice can open her file detail");
    assert_eq!(detail.filename, "alice-notes.txt");
    assert_eq!(detail.description, "private member notes");
    assert!(matches!(
        vault::detail(
            State(state.clone()),
            bob_auth.clone(),
            Path(alice_personal.vault_id.clone()),
        )
        .await,
        Err(ApiError::Forbidden(message)) if message.contains("owner")
    ));
    assert!(matches!(
        vault::detail(
            State(state.clone()),
            bob_auth.clone(),
            Path(circle_file.vault_id.clone()),
        )
        .await,
        Err(ApiError::Forbidden(message)) if message.contains("Circle")
    ));
    assert!(matches!(
        vault::detail(
            State(state.clone()),
            alice_auth.clone(),
            Path("../bad".to_string()),
        )
        .await,
        Err(ApiError::BadRequest(_))
    ));

    let Json(created_star) = vault::toggle_star(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
        None,
    )
    .await
    .expect("Alice toggles star on");
    assert!(created_star.starred);
    let Json(unstarred) = vault::toggle_star(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
        Some(Json(vault::ToggleStarRequest {
            starred: Some(false),
        })),
    )
    .await
    .expect("Alice explicitly toggles star off");
    assert!(!unstarred.starred);
    assert!(matches!(
        vault::toggle_star(
            State(state.clone()),
            bob_auth.clone(),
            Path(alice_personal.vault_id.clone()),
            None,
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));

    assert!(matches!(
        vault::rename_or_move_file(
            State(state.clone()),
            alice_auth.clone(),
            Path(alice_personal.vault_id.clone()),
            Json(vault::UpdateFileRequest {
                filename: None,
                folder_id: None,
            }),
        )
        .await,
        Err(ApiError::BadRequest(message)) if message.contains("at least one")
    ));
    let Json(renamed_personal) = vault::rename_or_move_file(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
        Json(vault::UpdateFileRequest {
            filename: Some("../Alice Final.txt".to_string()),
            folder_id: Some(personal_folder.folder_id.clone()),
        }),
    )
    .await
    .expect("Alice renames and moves her personal file");
    assert_eq!(renamed_personal.filename, "Alice Final.txt");
    assert_eq!(renamed_personal.folder_id, personal_folder.folder_id);

    let Json(moved_circle_file) = vault::rename_or_move_file(
        State(state.clone()),
        alice_auth.clone(),
        Path(circle_file.vault_id.clone()),
        Json(vault::UpdateFileRequest {
            filename: Some("Shared Final.txt".to_string()),
            folder_id: Some(shared_folder.folder_id.clone()),
        }),
    )
    .await
    .expect("Circle member renames and moves Circle file");
    assert_eq!(moved_circle_file.filename, "Shared Final.txt");
    assert_eq!(moved_circle_file.folder_id, shared_folder.folder_id);
    assert!(matches!(
        vault::rename_or_move_file(
            State(state.clone()),
            bob_auth.clone(),
            Path(circle_file.vault_id.clone()),
            Json(vault::UpdateFileRequest {
                filename: Some("blocked.txt".to_string()),
                folder_id: None,
            }),
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));

    let Json(tree) = vault::tree(
        State(state.clone()),
        alice_auth.clone(),
        Query(vault::VaultTreeQuery {
            ns: Some("circle-files".to_string()),
            folder: Some(shared_folder.folder_id.clone()),
        }),
    )
    .await
    .expect("Alice opens Circle folder tree");
    assert_eq!(tree.namespace, "circle-files");
    assert_eq!(tree.folder_id, shared_folder.folder_id);
    assert_eq!(tree.breadcrumbs[0].name, "Team Files");
    assert_eq!(tree.file_count, 1);
    assert_eq!(tree.files[0].vault_id, circle_file.vault_id);

    let Json(personal_tree) = vault::tree(
        State(state.clone()),
        alice_auth.clone(),
        Query(vault::VaultTreeQuery {
            ns: Some(VaultNamespace::PERSONAL_STORAGE_KEY.to_string()),
            folder: Some(String::new()),
        }),
    )
    .await
    .expect("PWA member opens personal root tree");
    assert_eq!(personal_tree.folder_count, 0);
    assert!(matches!(
        vault::tree(
            State(state.clone()),
            alice_auth.clone(),
            Query(vault::VaultTreeQuery {
                ns: Some("circle-files".to_string()),
                folder: Some("urn:uuid:00000000-0000-0000-0000-000000000000".to_string()),
            }),
        )
        .await,
        Err(ApiError::NotFound(message)) if message.contains("folder")
    ));

    let Json(folders) = vault::list_folders(
        State(state.clone()),
        alice_auth.clone(),
        Query(vault::VaultFolderListQuery {
            namespace: None,
            circle_id: None,
            parent_id: Some(String::new()),
        }),
    )
    .await
    .expect("PWA member lists only accessible Circle folders");
    assert_eq!(folders.count, 1);
    assert_eq!(folders.folders[0].namespace, "circle-files");
    assert_eq!(folders.folders[0].name, "Team Files");
    assert!(matches!(
        vault::list_folders(
            State(state.clone()),
            alice_auth.clone(),
            Query(vault::VaultFolderListQuery {
                namespace: Some("circle-files".to_string()),
                circle_id: None,
                parent_id: Some("urn:uuid:00000000-0000-0000-0000-000000000000".to_string()),
            }),
        )
        .await,
        Err(ApiError::NotFound(message)) if message.contains("folder")
    ));

    let Json(search) = vault::search(
        State(state.clone()),
        alice_auth.clone(),
        Query(vault::VaultSearchQuery {
            q: "final".to_string(),
            limit: Some(10),
        }),
    )
    .await
    .expect("Alice searches visible files");
    let search_ids = search
        .results
        .iter()
        .map(|result| result.file.vault_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(search.count, 2);
    assert!(search_ids.contains(&alice_personal.vault_id.as_str()));
    assert!(search_ids.contains(&circle_file.vault_id.as_str()));
    assert!(!search_ids.contains(&bob_personal.vault_id.as_str()));
    assert!(!search_ids.contains(&outside_circle_file.vault_id.as_str()));
    assert!(matches!(
        vault::search(
            State(state.clone()),
            alice_auth.clone(),
            Query(vault::VaultSearchQuery {
                q: "   ".to_string(),
                limit: None,
            }),
        )
        .await,
        Err(ApiError::BadRequest(message)) if message.contains("search")
    ));

    let Json(overview) = vault::overview(State(state.clone()), alice_auth.clone())
        .await
        .expect("Alice opens files overview");
    assert_eq!(overview.file_count, 2);
    assert!(overview.namespaces.iter().any(|item| item.namespace
        == VaultNamespace::PERSONAL_STORAGE_KEY
        && item.file_count == 1));
    assert!(overview
        .namespaces
        .iter()
        .any(|item| item.namespace == "circle-files" && item.file_count == 1));
    assert!(!overview
        .namespaces
        .iter()
        .any(|item| item.namespace == "circle-other"));

    let Json(personal_quota) = vault::quota_status(
        State(state.clone()),
        alice_auth.clone(),
        Query(vault::VaultQuotaQuery {
            ns: Some(VaultNamespace::PERSONAL_STORAGE_KEY.to_string()),
            circle_id: None,
        }),
    )
    .await
    .expect("Alice checks personal quota");
    assert!(personal_quota.used_bytes > 0);
    assert!(personal_quota.quota_bytes >= personal_quota.used_bytes);

    let preview = vault::preview(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
    )
    .await
    .expect("Alice previews text file");
    assert_eq!(preview.status(), axum::http::StatusCode::OK);

    let download = vault::download(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
    )
    .await
    .expect("Alice downloads her file");
    assert_eq!(download.status(), axum::http::StatusCode::OK);

    let Json(history) = vault::history(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
    )
    .await
    .expect("Alice opens download history");
    assert_eq!(history.vault_id, alice_personal.vault_id);
    assert_eq!(history.count, 2);
    assert!(history
        .downloads
        .iter()
        .all(|entry| entry.downloader_did == alice_did));
    assert!(matches!(
        vault::history(
            State(state.clone()),
            bob_auth.clone(),
            Path(alice_personal.vault_id.clone()),
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));

    assert!(matches!(
        vault::set_expiry(
            State(state.clone()),
            alice_auth.clone(),
            Path(alice_personal.vault_id.clone()),
            Json(vault::SetExpiryRequest {
                expires_at: Some("not-a-date".to_string()),
            }),
        )
        .await,
        Err(ApiError::BadRequest(message)) if message.contains("RFC3339")
    ));
    assert!(matches!(
        vault::set_expiry(
            State(state.clone()),
            alice_auth.clone(),
            Path(alice_personal.vault_id.clone()),
            Json(vault::SetExpiryRequest {
                expires_at: Some((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339()),
            }),
        )
        .await,
        Err(ApiError::BadRequest(message)) if message.contains("future")
    ));
    let future_expiry = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let Json(expiring) = vault::set_expiry(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
        Json(vault::SetExpiryRequest {
            expires_at: Some(future_expiry.clone()),
        }),
    )
    .await
    .expect("Alice sets future expiry");
    assert_eq!(expiring.expires_at.as_deref(), Some(future_expiry.as_str()));
    let Json(cleared_expiry) = vault::set_expiry(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
        Json(vault::SetExpiryRequest { expires_at: None }),
    )
    .await
    .expect("Alice clears expiry");
    assert_eq!(cleared_expiry.expires_at, None);
    assert!(matches!(
        vault::set_expiry(
            State(state.clone()),
            bob_auth.clone(),
            Path(alice_personal.vault_id.clone()),
            Json(vault::SetExpiryRequest { expires_at: None }),
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));

    let Json(revoked) = vault::revoke(
        State(state.clone()),
        alice_auth.clone(),
        Path(alice_personal.vault_id.clone()),
    )
    .await
    .expect("Alice revokes her file");
    assert!(revoked.revoked);
    assert!(revoked.revoked_at.is_some());
    assert!(matches!(
        vault::download(
            State(state.clone()),
            alice_auth.clone(),
            Path(alice_personal.vault_id.clone()),
        )
        .await,
        Err(ApiError::Forbidden(message)) if message.contains("revoked")
    ));

    let Json(delete_circle) = vault::delete_file(
        State(state.clone()),
        alice_auth.clone(),
        Path(circle_file.vault_id.clone()),
    )
    .await
    .expect("Alice deletes accessible Circle file");
    assert!(delete_circle.success);
    assert!(delete_circle.message.contains(&circle_file.vault_id));
    assert!(matches!(
        vault::delete_file(
            State(state.clone()),
            alice_auth.clone(),
            Path(circle_file.vault_id.clone()),
        )
        .await,
        Err(ApiError::NotFound(_))
    ));

    let boundary = "pwa-files-boundary";
    let upload_body = multipart_body(
        boundary,
        Some("uploaded from PWA files tab"),
        Some(("pwa-upload.txt", "text/plain", b"uploaded via multipart")),
    );
    let upload_response = upload_router(state.clone(), &alice_auth)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/vault/upload?ns=personal")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .header("idempotency-key", "pwa-files-upload-key")
                .body(Body::from(upload_body))
                .expect("build upload request"),
        )
        .await
        .expect("send upload request");
    assert_eq!(upload_response.status(), StatusCode::OK);
    let upload_json: Value = serde_json::from_slice(
        &to_bytes(upload_response.into_body(), usize::MAX)
            .await
            .expect("read upload body"),
    )
    .expect("parse upload response");
    let uploaded_id = upload_json["record"]["vault_id"]
        .as_str()
        .expect("uploaded id");
    assert_eq!(upload_json["record"]["filename"], "pwa-upload.txt");
    assert_eq!(upload_json["record"]["owner_did"], alice_did);
    assert_eq!(
        upload_json["download_path"],
        format!("/api/v1/vault/files/{uploaded_id}/download")
    );

    let retry_body = multipart_body(
        boundary,
        Some("ignored retry description"),
        Some((
            "retry.txt",
            "text/plain",
            b"retry should not create another file",
        )),
    );
    let retry_response = upload_router(state.clone(), &alice_auth)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/vault/upload?ns=personal")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .header("idempotency-key", "pwa-files-upload-key")
                .body(Body::from(retry_body))
                .expect("build upload retry request"),
        )
        .await
        .expect("send upload retry");
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry_json: Value = serde_json::from_slice(
        &to_bytes(retry_response.into_body(), usize::MAX)
            .await
            .expect("read upload retry body"),
    )
    .expect("parse retry response");
    assert_eq!(retry_json["record"]["vault_id"], uploaded_id);

    let missing_file_response = upload_router(state.clone(), &alice_auth)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/vault/upload?ns=personal")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart_body(
                    boundary,
                    Some("description only"),
                    None,
                )))
                .expect("build missing file request"),
        )
        .await
        .expect("send missing file request");
    assert_eq!(missing_file_response.status(), StatusCode::BAD_REQUEST);

    let forbidden_circle_upload = upload_router(state.clone(), &bob_auth)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/vault/upload?ns=circle-files")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart_body(
                    boundary,
                    None,
                    Some(("blocked.txt", "text/plain", b"blocked")),
                )))
                .expect("build forbidden Circle upload request"),
        )
        .await
        .expect("send forbidden Circle upload");
    assert_eq!(forbidden_circle_upload.status(), StatusCode::FORBIDDEN);

    let saved_after_revoke = persistence::find_record(&config, &alice_personal.vault_id)
        .await
        .expect("lookup revoked file")
        .expect("revoked file metadata remains");
    assert!(saved_after_revoke.revoked);
}
