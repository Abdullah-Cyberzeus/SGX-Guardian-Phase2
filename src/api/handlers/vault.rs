use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::vault::downloads::{self, DownloadRecord};
use crate::vault::errors::VaultError;
use crate::vault::folders::{self, FolderIndex, FolderNode};
use crate::vault::namespace::{VaultNamespace, validate_folder_id, validate_vault_id};
use crate::vault::{
    VaultConfig, VaultRecord, VaultSource, download_path, ingest, persistence,
    quota as vault_quota, upload,
};
use axum::body::{Body, Bytes};
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

const PREVIEW_MAX_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct VaultListQuery {
    pub circle_id: Option<String>,
    pub namespace: Option<String>,
    pub folder_id: Option<String>,
    pub starred: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct VaultTreeQuery {
    pub ns: Option<String>,
    pub folder: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultSearchQuery {
    pub q: String,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct VaultUploadQuery {
    pub ns: Option<String>,
    pub folder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultQuotaQuery {
    pub ns: Option<String>,
    pub circle_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultNamespaceQuery {
    pub ns: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultFolderListQuery {
    pub namespace: Option<String>,
    pub circle_id: Option<String>,
    pub parent_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultDeleteFolderQuery {
    pub ns: Option<String>,
    pub recursive: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateFolderRequest {
    pub namespace: Option<String>,
    pub parent_id: Option<String>,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFolderRequest {
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub parent_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFileRequest {
    pub filename: Option<String>,
    pub folder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ToggleStarRequest {
    pub starred: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct VaultListResponse {
    pub count: usize,
    pub files: Vec<VaultRecord>,
}

#[derive(Debug, Serialize)]
pub struct VaultBreadcrumb {
    pub folder_id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct VaultTreeResponse {
    pub namespace: String,
    pub folder_id: String,
    pub breadcrumbs: Vec<VaultBreadcrumb>,
    pub folders: Vec<FolderNode>,
    pub files: Vec<VaultRecord>,
    pub file_count: usize,
    pub folder_count: usize,
}

#[derive(Debug, Serialize)]
pub struct VaultNamespaceOverview {
    pub namespace: String,
    pub file_count: usize,
    pub folder_count: usize,
    pub used_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct VaultOverviewResponse {
    pub file_count: usize,
    pub folder_count: usize,
    pub used_bytes: u64,
    pub capacity_bytes: u64,
    pub namespaces: Vec<VaultNamespaceOverview>,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct VaultSearchResult {
    pub namespace: String,
    pub breadcrumbs: Vec<VaultBreadcrumb>,
    pub file: VaultRecord,
}

#[derive(Debug, Serialize)]
pub struct VaultSearchResponse {
    pub query: String,
    pub count: usize,
    pub results: Vec<VaultSearchResult>,
}

#[derive(Debug, Serialize)]
pub struct VaultUploadResponse {
    pub record: VaultRecord,
    pub download_path: String,
}

#[derive(Debug, Serialize)]
pub struct VaultActionResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct VaultFolderEntry {
    pub folder_id: String,
    pub parent_id: String,
    pub name: String,
    pub namespace: String,
    pub circle_id: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct VaultFolderListResponse {
    pub count: usize,
    pub folders: Vec<VaultFolderEntry>,
}

#[derive(Debug, Serialize)]
pub struct VaultPreviewMetadata {
    pub previewable: bool,
    pub reason: String,
    pub mime: String,
    pub size_plain: u64,
}

#[derive(Debug, Serialize)]
pub struct VaultQuotaResponse {
    pub used_bytes: u64,
    pub quota_bytes: u64,
    pub remaining_bytes: u64,
    pub usage_percent: f64,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<VaultListQuery>,
) -> Result<Json<VaultListResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let namespace = optional_namespace(query.namespace.as_deref(), query.circle_id.as_deref())?;
    let namespace_key = namespace.as_ref().map(VaultNamespace::storage_key);
    let mut records = persistence::list_records(&config, namespace_key.as_deref())
        .await
        .map_err(map_vault_error)?;
    records.retain(|record| authorize_record_access(&session, &caller_did, record).is_ok());

    if let Some(folder_id) = query.folder_id.as_deref() {
        let folder_id = normalize_folder_id(Some(folder_id))?;
        records.retain(|record| record.folder_id == folder_id);
    }
    if let Some(starred) = query.starred {
        records.retain(|record| record.starred == starred);
    }

    Ok(Json(VaultListResponse {
        count: records.len(),
        files: records,
    }))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<VaultRecord>, ApiError> {
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let record = load_authorized_record(&config, &session, &caller_did, &id).await?;
    Ok(Json(record))
}

pub async fn overview(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<VaultOverviewResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let mut records = persistence::list_records(&config, None)
        .await
        .map_err(map_vault_error)?;
    records.retain(|record| authorize_record_access(&session, &caller_did, record).is_ok());
    let visible_used_bytes = records.iter().map(|record| record.size_cipher).sum();

    let mut usage_by_namespace = BTreeMap::<String, (usize, u64)>::new();
    for record in &records {
        let entry = usage_by_namespace
            .entry(record.namespace_key())
            .or_insert((0, 0));
        entry.0 += 1;
        entry.1 += record.size_cipher;
    }

    let mut namespaces = BTreeSet::new();
    namespaces.insert(VaultNamespace::PERSONAL_STORAGE_KEY.to_string());
    namespaces.extend(usage_by_namespace.keys().cloned());
    let member_circle_ids = session.as_ref().and_then(|Extension(auth)| {
        (auth.claims.role == "member").then_some(&auth.claims.circle_ids)
    });
    if member_circle_ids.is_none() {
        for namespace in folders::list_namespaces(&config)
            .await
            .map_err(map_vault_error)?
        {
            namespaces.insert(namespace.storage_key());
        }
    } else if let Some(circle_ids) = member_circle_ids {
        namespaces.extend(circle_ids.iter().cloned());
    }

    let mut items = Vec::new();
    let mut folder_count = 0_usize;
    for namespace_key in namespaces {
        let namespace = VaultNamespace::parse(&namespace_key).map_err(map_vault_error)?;
        let index = folders::load_index(&config, &namespace, &state.node_id)
            .await
            .map_err(map_vault_error)?;
        let (file_count, used_bytes) = usage_by_namespace
            .get(&namespace_key)
            .copied()
            .unwrap_or((0, 0));
        let visible_folder_count = if member_circle_ids.is_some() && namespace.is_personal() {
            0
        } else {
            index.folders.len()
        };
        folder_count += visible_folder_count;
        items.push(VaultNamespaceOverview {
            namespace: namespace_key,
            file_count,
            folder_count: visible_folder_count,
            used_bytes,
        });
    }

    items.sort_by(|left, right| {
        namespace_sort_key(&left.namespace).cmp(&namespace_sort_key(&right.namespace))
    });

    Ok(Json(VaultOverviewResponse {
        file_count: records.len(),
        folder_count,
        used_bytes: visible_used_bytes,
        capacity_bytes: vault_quota::capacity_bytes(),
        namespaces: items,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn quota_status(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<VaultQuotaQuery>,
) -> Result<Json<VaultQuotaResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let namespace = optional_namespace(query.ns.as_deref(), query.circle_id.as_deref())?
        .unwrap_or(VaultNamespace::Personal);
    let (used_bytes, quota_bytes) = if namespace.is_personal() {
        let caller_did = resolve_caller_did(&state, &session);
        let used = persistence::list_records(&config, Some(&namespace.storage_key()))
            .await
            .map_err(map_vault_error)?
            .into_iter()
            .filter(|record| authorize_record_access(&session, &caller_did, record).is_ok())
            .map(|record| record.size_cipher)
            .sum();
        let limit = vault_quota::configured_quota_bytes(&config, &namespace)
            .await
            .map_err(map_vault_error)?;
        (used, limit)
    } else {
        let quota = vault_quota::compute_namespace(&config, &namespace)
            .await
            .map_err(map_vault_error)?;
        (quota.used_bytes, quota.quota_bytes)
    };

    Ok(Json(VaultQuotaResponse {
        used_bytes,
        quota_bytes,
        remaining_bytes: quota_bytes.saturating_sub(used_bytes),
        usage_percent: if quota_bytes == 0 {
            0.0
        } else {
            (used_bytes as f64 / quota_bytes as f64) * 100.0
        },
    }))
}

pub async fn tree(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<VaultTreeQuery>,
) -> Result<Json<VaultTreeResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let namespace = required_namespace(query.ns.as_deref())?;
    let folder_id = normalize_folder_id(query.folder.as_deref())?;
    let namespace_key = namespace.storage_key();
    let index = folders::load_index(&config, &namespace, &state.node_id)
        .await
        .map_err(map_vault_error)?;
    if !folder_id.is_empty() && !index.contains_folder(&folder_id) {
        return Err(ApiError::NotFound(format!(
            "folder not found: {}",
            folder_id
        )));
    }

    let mut files = persistence::list_records(&config, Some(&namespace_key))
        .await
        .map_err(map_vault_error)?
        .into_iter()
        .filter(|record| record.folder_id == folder_id)
        .filter(|record| authorize_record_access(&session, &caller_did, record).is_ok())
        .collect::<Vec<_>>();
    files.sort_by(|left, right| {
        left.filename
            .to_lowercase()
            .cmp(&right.filename.to_lowercase())
    });

    let breadcrumbs = index
        .breadcrumbs(&folder_id)
        .map_err(map_vault_error)?
        .into_iter()
        .map(|folder| VaultBreadcrumb {
            folder_id: folder.folder_id,
            name: folder.name,
        })
        .collect::<Vec<_>>();
    let folders = if session
        .as_ref()
        .is_some_and(|Extension(auth)| auth.claims.role == "member" && namespace.is_personal())
    {
        Vec::new()
    } else {
        index.children_of(&folder_id)
    };

    Ok(Json(VaultTreeResponse {
        namespace: namespace_key,
        folder_id,
        file_count: files.len(),
        folder_count: folders.len(),
        breadcrumbs,
        folders,
        files,
    }))
}

pub async fn search(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<VaultSearchQuery>,
) -> Result<Json<VaultSearchResponse>, ApiError> {
    let needle = query.q.trim().to_lowercase();
    if needle.is_empty() {
        return Err(ApiError::BadRequest(
            "search query must not be empty".to_string(),
        ));
    }
    let limit = query.limit.unwrap_or(50).min(100);
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let records = persistence::list_records(&config, None)
        .await
        .map_err(map_vault_error)?;
    let mut indices = BTreeMap::<String, FolderIndex>::new();
    let mut results = Vec::new();

    for record in records
        .into_iter()
        .filter(|record| record.filename.to_lowercase().contains(&needle))
        .filter(|record| authorize_record_access(&session, &caller_did, record).is_ok())
        .take(limit)
    {
        let namespace_key = record.namespace_key();
        if !indices.contains_key(&namespace_key) {
            let namespace = VaultNamespace::parse(&namespace_key).map_err(map_vault_error)?;
            let index = folders::load_index(&config, &namespace, &state.node_id)
                .await
                .map_err(map_vault_error)?;
            indices.insert(namespace_key.clone(), index);
        }
        let breadcrumbs = indices
            .get(&namespace_key)
            .expect("folder index cached")
            .breadcrumbs(&record.folder_id)
            .map_err(map_vault_error)?
            .into_iter()
            .map(|folder| VaultBreadcrumb {
                folder_id: folder.folder_id,
                name: folder.name,
            })
            .collect::<Vec<_>>();
        results.push(VaultSearchResult {
            namespace: namespace_key,
            breadcrumbs,
            file: record,
        });
    }

    Ok(Json(VaultSearchResponse {
        query: query.q,
        count: results.len(),
        results,
    }))
}

pub async fn upload(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<VaultUploadQuery>,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<VaultUploadResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let namespace = required_namespace(query.ns.as_deref())?;
    if let VaultNamespace::Circle(circle_id) = &namespace {
        if !is_admin_caller(&session) {
            let Some(Extension(authed)) = session.as_ref() else {
                return Err(ApiError::Forbidden(
                    "not a member of this Circle".to_string(),
                ));
            };
            if !authed.claims.circle_ids.contains(circle_id) {
                return Err(ApiError::Forbidden(
                    "not a member of this Circle".to_string(),
                ));
            }
        }
    }
    let folder_id = normalize_folder_id(query.folder_id.as_deref())?;
    ensure_folder_exists(&config, &namespace, &state.node_id, &folder_id).await?;

    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(vault_id) = idempotency_lookup(&namespace.storage_key(), key) {
            if let Some(record) = persistence::find_record(&config, &vault_id)
                .await
                .map_err(map_vault_error)?
            {
                return Ok(Json(VaultUploadResponse {
                    download_path: download_path(&record.vault_id),
                    record,
                }));
            }
        }
    }

    let chunk_bytes = VaultConfig::DEFAULT_CHUNK_BYTES;
    let namespace_quota_bytes = vault_quota::configured_quota_bytes(&config, &namespace)
        .await
        .map_err(map_vault_error)?;

    let mut description = String::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::BadRequest(error.to_string()))?
    {
        if field.name() == Some("description") {
            description = field.text().await.unwrap_or_default();
            continue;
        }
        let is_file_field = field.file_name().is_some() || field.name() == Some("file");
        if !is_file_field {
            continue;
        }

        let filename = field
            .file_name()
            .map(crate::xfer::manifest::safe_manifest_name)
            .unwrap_or_else(|| "upload.bin".to_string());
        let mime = field
            .content_type()
            .map(ToString::to_string)
            .unwrap_or_else(|| ingest::infer_mime(&filename));
        let staging_path =
            persistence::staging_dir(&config).join(format!("upload-{}.part", Uuid::new_v4()));

        if let Some(parent) = staging_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut file = tokio::fs::File::create(&staging_path).await?;
        let mut field = field;
        let mut size_plain = 0_u64;
        let mut hasher = Sha256::new();

        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|error| ApiError::BadRequest(error.to_string()))?
        {
            size_plain = size_plain.saturating_add(chunk.len() as u64);
            if vault_quota::estimate_cipher_size(size_plain, chunk_bytes) > namespace_quota_bytes {
                drop(file);
                let _ = tokio::fs::remove_file(&staging_path).await;
                return Err(ApiError::PayloadTooLarge(
                    "vault quota exceeded".to_string(),
                ));
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        file.sync_data().await?;

        let record = upload::ingest_staged_upload(
            &config,
            upload::StagedUpload {
                namespace,
                folder_id,
                filename,
                mime,
                sender_did: caller_did.clone(),
                staging_path,
                size_plain,
                sha256_plain: hex::encode(hasher.finalize()),
                chunk_bytes,
                description,
            },
        )
        .await
        .map_err(map_vault_error)?;

        if let Some(key) = idempotency_key.as_deref() {
            idempotency_store(&record.namespace_key(), key, &record.vault_id);
        }

        log_audit(
            &state.node_id,
            AuditCategory::Vault,
            AuditSeverity::Info,
            AuditAction::Created,
            &format!(
                "vault upload stored id={} namespace={} file={} bytes={}",
                record.vault_id,
                record.namespace_key(),
                record.filename,
                record.size_plain
            ),
        );

        return Ok(Json(VaultUploadResponse {
            download_path: download_path(&record.vault_id),
            record,
        }));
    }

    Err(ApiError::BadRequest("missing file field".to_string()))
}

pub async fn create_folder(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateFolderRequest>,
) -> Result<Json<FolderNode>, ApiError> {
    let config = VaultConfig::from_env();
    let namespace = required_namespace(body.namespace.as_deref())?;
    let folder = folders::create_folder(
        &config,
        &namespace,
        &state.node_id,
        body.parent_id.as_deref().unwrap_or_default(),
        &body.name,
    )
    .await
    .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Info,
        AuditAction::Created,
        &format!(
            "vault folder created id={} namespace={} name={}",
            folder.folder_id,
            namespace.storage_key(),
            folder.name
        ),
    );

    Ok(Json(folder))
}

pub async fn list_folders(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<VaultFolderListQuery>,
) -> Result<Json<VaultFolderListResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let namespace_filter =
        optional_namespace(query.namespace.as_deref(), query.circle_id.as_deref())?;
    let parent_filter = query
        .parent_id
        .as_deref()
        .map(validate_folder_id)
        .transpose()
        .map_err(map_vault_error)?;

    let namespaces = if let Some(namespace) = namespace_filter.clone() {
        vec![namespace]
    } else {
        folders::list_namespaces(&config)
            .await
            .map_err(map_vault_error)?
    };

    let mut found_parent = parent_filter
        .as_ref()
        .map(|parent_id| parent_id.is_empty())
        .unwrap_or(false);
    let mut entries = Vec::new();

    for namespace in namespaces {
        if let Some(Extension(auth)) = session.as_ref() {
            if auth.claims.role == "member"
                && (namespace.is_personal()
                    || matches!(&namespace, VaultNamespace::Circle(circle_id) if !auth.claims.circle_ids.contains(circle_id)))
            {
                continue;
            }
        }
        let namespace_key = namespace.storage_key();
        let index = folders::load_index(&config, &namespace, &state.node_id)
            .await
            .map_err(map_vault_error)?;
        if let Some(parent_id) = parent_filter.as_deref() {
            if !parent_id.is_empty() && index.contains_folder(parent_id) {
                found_parent = true;
            }
        }
        for folder in index.folders {
            if parent_filter
                .as_ref()
                .is_some_and(|parent_id| folder.parent_id != *parent_id)
            {
                continue;
            }
            entries.push(VaultFolderEntry {
                folder_id: folder.folder_id,
                parent_id: folder.parent_id,
                name: folder.name,
                namespace: namespace_key.clone(),
                circle_id: if namespace.is_personal() {
                    String::new()
                } else {
                    namespace_key.clone()
                },
                created_at: folder.created_at,
            });
        }
    }

    if let Some(parent_id) = parent_filter {
        if !parent_id.is_empty() && !found_parent {
            return Err(ApiError::NotFound(format!(
                "folder not found: {}",
                parent_id
            )));
        }
    }

    entries.sort_by(|left, right| {
        namespace_sort_key(&left.namespace)
            .cmp(&namespace_sort_key(&right.namespace))
            .then_with(|| left.parent_id.cmp(&right.parent_id))
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.folder_id.cmp(&right.folder_id))
    });

    Ok(Json(VaultFolderListResponse {
        count: entries.len(),
        folders: entries,
    }))
}

pub async fn rename_or_move_folder(
    State(state): State<Arc<AppState>>,
    Path(folder_id): Path<String>,
    Json(body): Json<UpdateFolderRequest>,
) -> Result<Json<FolderNode>, ApiError> {
    let config = VaultConfig::from_env();
    let namespace = required_namespace(body.namespace.as_deref())?;
    let folder_id = validate_folder_id(&folder_id).map_err(map_vault_error)?;
    let folder = folders::update_folder(
        &config,
        &namespace,
        &state.node_id,
        &folder_id,
        body.name.as_deref(),
        body.parent_id.as_deref(),
    )
    .await
    .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!(
            "vault folder updated id={} namespace={} name={}",
            folder.folder_id,
            namespace.storage_key(),
            folder.name
        ),
    );

    Ok(Json(folder))
}

pub async fn delete_folder(
    State(state): State<Arc<AppState>>,
    Path(folder_id): Path<String>,
    Query(query): Query<VaultDeleteFolderQuery>,
) -> Result<Json<VaultActionResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let namespace = required_namespace(query.ns.as_deref())?;
    let recursive = query.recursive.unwrap_or(false);
    let folder_id = validate_folder_id(&folder_id).map_err(map_vault_error)?;
    let namespace_key = namespace.storage_key();
    let index = folders::load_index(&config, &namespace, &state.node_id)
        .await
        .map_err(map_vault_error)?;
    let subtree = index.subtree_ids(&folder_id).map_err(map_vault_error)?;
    let subtree_ids = subtree.iter().cloned().collect::<BTreeSet<_>>();
    let records = persistence::list_records(&config, Some(&namespace_key))
        .await
        .map_err(map_vault_error)?;
    let records_to_delete = records
        .into_iter()
        .filter(|record| subtree_ids.contains(&record.folder_id))
        .collect::<Vec<_>>();

    if !recursive && !records_to_delete.is_empty() {
        return Err(ApiError::Conflict(format!(
            "folder {} is not empty",
            folder_id
        )));
    }

    for record in &records_to_delete {
        persistence::delete_record(&config, record)
            .await
            .map_err(map_vault_error)?;
    }
    let removed =
        folders::delete_folder(&config, &namespace, &state.node_id, &folder_id, recursive)
            .await
            .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Info,
        AuditAction::Revoked,
        &format!(
            "vault folder deleted id={} namespace={} recursive={} files_removed={}",
            folder_id,
            namespace_key,
            recursive,
            records_to_delete.len()
        ),
    );

    Ok(Json(VaultActionResponse {
        success: true,
        message: format!("deleted {} folder(s)", removed.len()),
    }))
}

pub async fn rename_or_move_file(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
    Json(body): Json<UpdateFileRequest>,
) -> Result<Json<VaultRecord>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let caller_did = resolve_caller_did(&state, &session);
    let mut record = load_authorized_record(&config, &session, &caller_did, &id).await?;
    let mut changed = false;

    if let Some(filename) = body.filename.as_deref() {
        record.filename = normalize_filename(filename)?;
        if record.mime == "application/octet-stream" {
            record.mime = ingest::infer_mime(&record.filename);
        }
        changed = true;
    }
    if let Some(folder_id) = body.folder_id.as_deref() {
        let folder_id = normalize_folder_id(Some(folder_id))?;
        ensure_folder_exists(&config, &record.namespace_ref(), &state.node_id, &folder_id).await?;
        record.folder_id = folder_id;
        changed = true;
    }
    if !changed {
        return Err(ApiError::BadRequest(
            "at least one file field must be updated".to_string(),
        ));
    }

    persistence::save_record(&config, &record)
        .await
        .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!(
            "vault file updated id={} namespace={} file={}",
            record.vault_id,
            record.namespace_key(),
            record.filename
        ),
    );

    Ok(Json(record))
}

pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<VaultActionResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let caller_did = resolve_caller_did(&state, &session);
    let record = load_authorized_record(&config, &session, &caller_did, &id).await?;
    persistence::delete_record(&config, &record)
        .await
        .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Info,
        AuditAction::Revoked,
        &format!(
            "vault file deleted id={} namespace={} file={}",
            record.vault_id,
            record.namespace_key(),
            record.filename
        ),
    );

    Ok(Json(VaultActionResponse {
        success: true,
        message: format!("deleted {}", record.vault_id),
    }))
}

pub async fn toggle_star(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
    body: Option<Json<ToggleStarRequest>>,
) -> Result<Json<VaultRecord>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let caller_did = resolve_caller_did(&state, &session);
    let mut record = load_authorized_record(&config, &session, &caller_did, &id).await?;
    let next = body
        .map(|payload| payload.starred.unwrap_or(!record.starred))
        .unwrap_or(!record.starred);
    record.starred = next;
    persistence::save_record(&config, &record)
        .await
        .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!(
            "vault file star toggled id={} starred={}",
            record.vault_id, record.starred
        ),
    );

    Ok(Json(record))
}

pub async fn download(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let record = load_authorized_record(&config, &session, &caller_did, &id).await?;
    ensure_downloadable(&record)?;
    let response = stream_record(record.clone(), "attachment")
        .await
        .map_err(map_vault_error)?;
    record_download_audit(&config, &record.vault_id, &caller_did, "direct").await;
    Ok(response)
}

pub async fn preview(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let record = load_authorized_record(&config, &session, &caller_did, &id).await?;
    ensure_downloadable(&record)?;
    if !is_previewable(&record) {
        return Ok(Json(VaultPreviewMetadata {
            previewable: false,
            reason: if record.size_plain > PREVIEW_MAX_BYTES {
                "preview disabled for large file".to_string()
            } else {
                "preview not available for this content type".to_string()
            },
            mime: record.mime.clone(),
            size_plain: record.size_plain,
        })
        .into_response());
    }

    let response = stream_record(record.clone(), "inline")
        .await
        .map_err(map_vault_error)?;
    record_download_audit(&config, &record.vault_id, &caller_did, "preview").await;
    Ok(response)
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<VaultRecord>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let caller_did = resolve_caller_did(&state, &session);
    let mut record = load_record_by_id(&config, &id).await?;
    authorize_owner_only(&session, &caller_did, &record)?;
    record.revoked = true;
    record.revoked_at = Some(chrono::Utc::now().to_rfc3339());
    persistence::save_record(&config, &record)
        .await
        .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Warning,
        AuditAction::Revoked,
        &format!(
            "vault file access revoked id={} namespace={} by={}",
            record.vault_id,
            record.namespace_key(),
            caller_did
        ),
    );

    Ok(Json(record))
}

pub async fn restore(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<VaultRecord>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let caller_did = resolve_caller_did(&state, &session);
    let mut record = load_record_by_id(&config, &id).await?;
    authorize_owner_only(&session, &caller_did, &record)?;
    record.revoked = false;
    record.revoked_at = None;
    persistence::save_record(&config, &record)
        .await
        .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Warning,
        AuditAction::Updated,
        &format!(
            "vault file access restored id={} namespace={} by={}",
            record.vault_id,
            record.namespace_key(),
            caller_did
        ),
    );

    Ok(Json(record))
}

#[derive(Debug, Deserialize)]
pub struct SetExpiryRequest {
    pub expires_at: Option<String>,
}

pub async fn set_expiry(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
    Json(body): Json<SetExpiryRequest>,
) -> Result<Json<VaultRecord>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let caller_did = resolve_caller_did(&state, &session);
    let mut record = load_record_by_id(&config, &id).await?;
    authorize_owner_only(&session, &caller_did, &record)?;

    record.expires_at = match body.expires_at {
        Some(raw) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(&raw).map_err(|_| {
                ApiError::BadRequest("expires_at must be an RFC3339 timestamp".to_string())
            })?;
            if parsed <= chrono::Utc::now() {
                return Err(ApiError::BadRequest(
                    "expires_at must be in the future".to_string(),
                ));
            }
            Some(raw)
        }
        None => None,
    };
    persistence::save_record(&config, &record)
        .await
        .map_err(map_vault_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!(
            "vault file expiry updated id={} namespace={} expires_at={:?}",
            record.vault_id,
            record.namespace_key(),
            record.expires_at
        ),
    );

    Ok(Json(record))
}

#[derive(Debug, Serialize)]
pub struct VaultHistoryResponse {
    pub vault_id: String,
    pub count: usize,
    pub downloads: Vec<DownloadRecord>,
}

pub async fn history(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<VaultHistoryResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let caller_did = resolve_caller_did(&state, &session);
    let record = load_record_by_id(&config, &id).await?;
    authorize_owner_only(&session, &caller_did, &record)?;

    let entries = downloads::list_downloads_for(&config, &record.vault_id)
        .await
        .map_err(map_vault_error)?;

    Ok(Json(VaultHistoryResponse {
        vault_id: record.vault_id,
        count: entries.len(),
        downloads: entries,
    }))
}

pub(crate) fn ensure_downloadable(record: &VaultRecord) -> Result<(), ApiError> {
    if record.revoked {
        return Err(ApiError::Forbidden(
            "access to this file has been revoked by its owner".to_string(),
        ));
    }
    if record.is_expired() {
        return Err(ApiError::Gone("this file has expired".to_string()));
    }
    Ok(())
}

pub(crate) async fn record_download_audit(
    config: &VaultConfig,
    vault_id: &str,
    caller_did: &str,
    source: &str,
) {
    if let Err(error) = downloads::record_download(config, vault_id, caller_did, source).await {
        tracing::warn!(%vault_id, %error, "failed to record vault download audit entry");
    }
}

/// Client-supplied `Idempotency-Key` -> vault_id, scoped per namespace. A
/// retried upload with the same key returns the record already created
/// instead of ingesting a duplicate. No TTL: keys are one-shot client UUIDs.
static IDEMPOTENCY_CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<(String, String), String>>> =
    std::sync::OnceLock::new();

fn idempotency_cache() -> &'static std::sync::Mutex<HashMap<(String, String), String>> {
    IDEMPOTENCY_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

pub(crate) fn idempotency_lookup(namespace_key: &str, key: &str) -> Option<String> {
    idempotency_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&(namespace_key.to_string(), key.to_string()))
        .cloned()
}

pub(crate) fn idempotency_store(namespace_key: &str, key: &str, vault_id: &str) {
    idempotency_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(
            (namespace_key.to_string(), key.to_string()),
            vault_id.to_string(),
        );
}

/// The Guardian device itself (admin/owner session, or no session when login
/// is disabled) is unrestricted. Only browser member sessions are scoped.
fn is_admin_caller(session: &Option<Extension<AuthenticatedSession>>) -> bool {
    session
        .as_ref()
        .map(|Extension(session)| session.claims.role != "member")
        .unwrap_or(true)
}

pub(crate) fn resolve_caller_did(
    state: &AppState,
    session: &Option<Extension<AuthenticatedSession>>,
) -> String {
    crate::api::handlers::browser_member::did_from_session(session)
        .unwrap_or_else(|| resolve_sender_did(state))
}

/// A caller may access a Circle-namespace file when their Guardian/member
/// session belongs to that Circle. Personal records never inherit the admin
/// device-wide bypass: they belong only to their owner (or the other party of
/// a direct-message attachment). This keeps Guardian-admin and browser-member
/// Personal Vaults separate on the same hardware.
pub(crate) fn authorize_record_access(
    session: &Option<Extension<AuthenticatedSession>>,
    caller_did: &str,
    record: &VaultRecord,
) -> Result<(), ApiError> {
    match record.namespace_ref() {
        VaultNamespace::Circle(circle_id) => {
            if is_admin_caller(session) {
                return Ok(());
            }
            let Some(Extension(authed)) = session.as_ref() else {
                return Err(ApiError::Forbidden(
                    "Circle session is required".to_string(),
                ));
            };
            if authed.claims.circle_ids.contains(&circle_id) {
                Ok(())
            } else {
                Err(ApiError::Forbidden(
                    "not a member of this Circle".to_string(),
                ))
            }
        }
        VaultNamespace::Personal => {
            if record.source == VaultSource::ChatAttachment {
                if let Some(recipient) = record.conversation_recipient_did.as_deref() {
                    if caller_did == record.owner_did || caller_did == recipient {
                        return Ok(());
                    }
                    return Err(ApiError::Forbidden(
                        "not a participant in this conversation".to_string(),
                    ));
                }
            }
            if caller_did == record.owner_did {
                Ok(())
            } else {
                Err(ApiError::Forbidden(
                    "not the owner of this file".to_string(),
                ))
            }
        }
    }
}

fn authorize_owner_only(
    session: &Option<Extension<AuthenticatedSession>>,
    caller_did: &str,
    record: &VaultRecord,
) -> Result<(), ApiError> {
    let circle_admin =
        is_admin_caller(session) && matches!(record.namespace_ref(), VaultNamespace::Circle(_));
    if circle_admin || caller_did == record.owner_did {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "only the file owner can perform this action".to_string(),
        ))
    }
}

pub(crate) async fn load_authorized_record(
    config: &VaultConfig,
    session: &Option<Extension<AuthenticatedSession>>,
    caller_did: &str,
    id: &str,
) -> Result<VaultRecord, ApiError> {
    let record = load_record_by_id(config, id).await?;
    authorize_record_access(session, caller_did, &record)?;
    Ok(record)
}

pub(crate) fn map_vault_error(error: VaultError) -> ApiError {
    match error {
        VaultError::NotFound(message) => ApiError::NotFound(message),
        VaultError::InvalidStructure(message) => ApiError::BadRequest(message),
        VaultError::Conflict(message) => ApiError::Conflict(message),
        VaultError::QuotaExceeded { .. } => ApiError::PayloadTooLarge(error.to_string()),
        VaultError::Integrity { .. } => ApiError::Conflict(error.to_string()),
        VaultError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(io.to_string())
        }
        other => ApiError::Internal(other.to_string()),
    }
}

fn normalize_folder_id(folder_id: Option<&str>) -> Result<String, ApiError> {
    folder_id
        .map(validate_folder_id)
        .transpose()
        .map_err(map_vault_error)
        .map(|folder_id| folder_id.unwrap_or_default())
}

fn normalize_filename(filename: &str) -> Result<String, ApiError> {
    if filename.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "filename must not be empty".to_string(),
        ));
    }
    Ok(crate::xfer::manifest::safe_manifest_name(filename))
}

fn optional_namespace(
    namespace: Option<&str>,
    circle_id: Option<&str>,
) -> Result<Option<VaultNamespace>, ApiError> {
    if let Some(namespace) = namespace.filter(|value| !value.trim().is_empty()) {
        return VaultNamespace::parse(namespace)
            .map(Some)
            .map_err(map_vault_error);
    }
    if let Some(circle_id) = circle_id.filter(|value| !value.trim().is_empty()) {
        return VaultNamespace::parse(circle_id)
            .map(Some)
            .map_err(map_vault_error);
    }
    Ok(None)
}

fn required_namespace(namespace: Option<&str>) -> Result<VaultNamespace, ApiError> {
    VaultNamespace::parse(namespace.unwrap_or(VaultNamespace::PERSONAL_STORAGE_KEY))
        .map_err(map_vault_error)
}

fn resolve_sender_did(state: &AppState) -> String {
    crate::vc::issue::subject_did_for_node(&state.node_id).unwrap_or_else(|_| state.node_id.clone())
}

async fn ensure_folder_exists(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    node_id: &str,
    folder_id: &str,
) -> Result<(), ApiError> {
    if folder_id.is_empty() {
        return Ok(());
    }
    let index = folders::load_index(config, namespace, node_id)
        .await
        .map_err(map_vault_error)?;
    if !index.contains_folder(folder_id) {
        return Err(ApiError::NotFound(format!(
            "folder not found: {}",
            folder_id
        )));
    }
    Ok(())
}

pub(crate) async fn load_record_by_id(
    config: &VaultConfig,
    id: &str,
) -> Result<VaultRecord, ApiError> {
    let id = validate_vault_id(id).map_err(map_vault_error)?;
    persistence::find_record(config, &id)
        .await
        .map_err(map_vault_error)?
        .ok_or_else(|| ApiError::NotFound(format!("vault file not found: {}", id)))
}

pub(crate) async fn stream_record(
    record: VaultRecord,
    disposition_kind: &str,
) -> Result<Response, VaultError> {
    let temp_path = ingest::decrypt_record_to_temp(&record).await?;
    let file = tokio::fs::File::open(&temp_path).await?;
    let stream = TempFileStream::new(file, temp_path);
    let body = Body::from_stream(stream);

    let content_type = HeaderValue::from_str(&record.mime)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let disposition = HeaderValue::from_str(&format!(
        "{}; filename=\"{}\"",
        disposition_kind,
        sanitize_filename(&record.filename)
    ))
    .map_err(|error| VaultError::InvalidStructure(format!("content-disposition: {}", error)))?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, record.size_plain.to_string())
        .header(header::CONTENT_DISPOSITION, disposition)
        .header("x-sgx-vault-id", record.vault_id.clone())
        .header("x-sgx-vault-download", download_path(&record.vault_id))
        .body(body)
        .map_err(|error| VaultError::InvalidStructure(format!("build response: {}", error)))
}

fn sanitize_filename(filename: &str) -> String {
    crate::xfer::manifest::safe_manifest_name(filename).replace('"', "_")
}

fn is_previewable(record: &VaultRecord) -> bool {
    if record.size_plain > PREVIEW_MAX_BYTES {
        return false;
    }
    record.mime.starts_with("image/")
        || record.mime.starts_with("text/")
        || matches!(
            record.mime.as_str(),
            "application/pdf" | "application/json" | "application/xml" | "text/csv"
        )
}

fn namespace_sort_key(namespace: &str) -> (u8, String) {
    let rank = if namespace.eq_ignore_ascii_case(VaultNamespace::PERSONAL_STORAGE_KEY) {
        0
    } else {
        1
    };
    (rank, namespace.to_lowercase())
}

struct TempFileStream {
    file: tokio::fs::File,
    path: std::path::PathBuf,
    done: bool,
    chunk_bytes: usize,
}

impl TempFileStream {
    fn new(file: tokio::fs::File, path: std::path::PathBuf) -> Self {
        Self {
            file,
            path,
            done: false,
            chunk_bytes: 64 * 1024,
        }
    }
}

impl Stream for TempFileStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }

        let mut buffer = vec![0_u8; self.chunk_bytes];
        let mut read_buf = ReadBuf::new(&mut buffer);
        match Pin::new(&mut self.file).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled().len();
                if filled == 0 {
                    self.done = true;
                    Poll::Ready(None)
                } else {
                    buffer.truncate(filled);
                    Poll::Ready(Some(Ok(Bytes::from(buffer))))
                }
            }
            Poll::Ready(Err(error)) => {
                self.done = true;
                Poll::Ready(Some(Err(error)))
            }
        }
    }
}

impl Drop for TempFileStream {
    fn drop(&mut self) {
        let path = self.path.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(path).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::session::Claims;
    use crate::api::handlers::browser_member::did_for_registration;
    use crate::vault::ingest::IngestMeta;
    use tempfile::TempDir;

    /// Points `VaultConfig::from_env()` at a temp directory for the
    /// duration of one test, restoring the previous value on drop.
    struct TestVaultBase {
        previous: Option<String>,
    }

    impl TestVaultBase {
        fn set(path: &std::path::Path) -> Self {
            let previous = std::env::var(crate::vault::VAULT_BASE_ENV).ok();
            std::env::set_var(crate::vault::VAULT_BASE_ENV, path);
            Self { previous }
        }
    }

    impl Drop for TestVaultBase {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(crate::vault::VAULT_BASE_ENV, value),
                None => std::env::remove_var(crate::vault::VAULT_BASE_ENV),
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
                scopes: crate::api::auth::authorization::default_scopes("member"),
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

    fn member_did(registration_id: &str) -> String {
        did_for_registration(registration_id)
    }

    async fn ingest_test_file(
        temp: &TempDir,
        namespace: VaultNamespace,
        owner_did: &str,
        filename: &str,
    ) -> VaultRecord {
        let payload = b"vault authorization test payload".to_vec();
        let source = temp.path().join(format!("{}-source", uuid::Uuid::new_v4()));
        tokio::fs::write(&source, &payload)
            .await
            .expect("write source");
        ingest::ingest_upload_file(
            namespace,
            owner_did,
            &source,
            IngestMeta {
                filename: filename.to_string(),
                mime: "text/plain".to_string(),
                sha256_plain: hex::encode(Sha256::digest(&payload)),
                size_plain: payload.len() as u64,
                chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
            },
            String::new(),
            String::new(),
        )
        .await
        .expect("ingest test file")
    }

    #[tokio::test]
    async fn duplicate_filename_gets_deterministic_suffix() {
        let _env_lock = crate::vault::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = TestVaultBase::set(temp.path());
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Docker,
        );

        let first = ingest_test_file(
            &temp,
            VaultNamespace::Personal,
            "did:guardian:owner",
            "notes.txt",
        )
        .await;
        let second = ingest_test_file(
            &temp,
            VaultNamespace::Personal,
            "did:guardian:owner",
            "notes.txt",
        )
        .await;
        let third = ingest_test_file(
            &temp,
            VaultNamespace::Personal,
            "did:guardian:owner",
            "notes.txt",
        )
        .await;

        assert_eq!(first.filename, "notes.txt");
        assert_eq!(second.filename, "notes (1).txt");
        assert_eq!(third.filename, "notes (2).txt");
    }

    #[tokio::test]
    async fn disallowed_mime_type_is_rejected() {
        let _env_lock = crate::vault::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = TestVaultBase::set(temp.path());
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Docker,
        );
        let source = temp.path().join("payload.bin");
        tokio::fs::write(&source, b"binary")
            .await
            .expect("write source");

        let error = ingest::ingest_upload_file(
            VaultNamespace::Personal,
            "did:guardian:owner",
            &source,
            IngestMeta {
                filename: "malware.exe".to_string(),
                mime: "application/x-msdownload".to_string(),
                sha256_plain: hex::encode(Sha256::digest(b"binary")),
                size_plain: 6,
                chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
            },
            String::new(),
            String::new(),
        )
        .await
        .expect_err("disallowed mime must be rejected");
        assert!(matches!(error, VaultError::InvalidStructure(_)));
    }

    #[tokio::test]
    async fn revoked_file_blocks_download_but_metadata_stays_visible() {
        let _env_lock = crate::vault::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = TestVaultBase::set(temp.path());
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Docker,
        );
        let state = crate::api::state::AppState::for_tests(
            temp.path(),
            "nodeA",
            temp.path().join("config").to_string_lossy().to_string(),
        );
        let owner_did = resolve_caller_did(&state, &None);
        let record =
            ingest_test_file(&temp, VaultNamespace::Personal, &owner_did, "secret.txt").await;

        // Owner (Guardian device / admin session) revokes it.
        let revoked = revoke(State(state.clone()), None, Path(record.vault_id.clone()))
            .await
            .expect("revoke succeeds");
        assert!(revoked.revoked);

        let download_error = download(State(state.clone()), None, Path(record.vault_id.clone()))
            .await
            .expect_err("revoked file must not download");
        assert!(matches!(download_error, ApiError::Forbidden(_)));

        // Metadata is still visible — only future access is blocked.
        let detail_result = detail(State(state), None, Path(record.vault_id.clone())).await;
        assert!(detail_result.is_ok());
    }

    #[tokio::test]
    async fn expired_file_download_returns_gone() {
        let _env_lock = crate::vault::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = TestVaultBase::set(temp.path());
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Docker,
        );
        let state = crate::api::state::AppState::for_tests(
            temp.path(),
            "nodeA",
            temp.path().join("config").to_string_lossy().to_string(),
        );
        let owner_did = resolve_caller_did(&state, &None);
        let mut record =
            ingest_test_file(&temp, VaultNamespace::Personal, &owner_did, "expiring.txt").await;
        let config = VaultConfig::from_env();
        record.expires_at = Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
        persistence::save_record(&config, &record)
            .await
            .expect("save expired record");
        let error = download(State(state), None, Path(record.vault_id.clone()))
            .await
            .expect_err("expired file must not download");
        assert!(matches!(error, ApiError::Gone(_)));
    }

    #[tokio::test]
    async fn personal_namespace_is_private_per_member() {
        let _env_lock = crate::vault::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = TestVaultBase::set(temp.path());
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Docker,
        );
        let member_a_reg = "member-a-registration";
        let member_b_reg = "member-b-registration";
        let member_a_did = member_did(member_a_reg);
        let record =
            ingest_test_file(&temp, VaultNamespace::Personal, &member_a_did, "diary.txt").await;
        let state = crate::api::state::AppState::for_tests(
            temp.path(),
            "nodeA",
            temp.path().join("config").to_string_lossy().to_string(),
        );

        let owner_session = member_session(vec![], member_a_reg);
        let other_session = member_session(vec![], member_b_reg);

        let owner_result = detail(
            State(state.clone()),
            owner_session,
            Path(record.vault_id.clone()),
        )
        .await;
        assert!(
            owner_result.is_ok(),
            "owning member must see their own file"
        );

        let other_result = detail(
            State(state.clone()),
            other_session,
            Path(record.vault_id.clone()),
        )
        .await;
        assert!(
            matches!(other_result, Err(ApiError::Forbidden(_))),
            "a different member must not see another member's personal file"
        );

        // The Guardian admin has its own Personal Vault and must not inherit
        // a browser member's private records.
        let admin_result = detail(State(state), None, Path(record.vault_id.clone())).await;
        assert!(matches!(admin_result, Err(ApiError::Forbidden(_))));
    }

    #[tokio::test]
    async fn circle_namespace_requires_membership() {
        let _env_lock = crate::vault::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = TestVaultBase::set(temp.path());
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Docker,
        );
        let record = ingest_test_file(
            &temp,
            VaultNamespace::Circle("circle-x".to_string()),
            "did:guardian:uploader",
            "shared.txt",
        )
        .await;
        let state = crate::api::state::AppState::for_tests(
            temp.path(),
            "nodeA",
            temp.path().join("config").to_string_lossy().to_string(),
        );

        let member_in_circle = member_session(vec!["circle-x".to_string()], "in-circle-member");
        let member_outside_circle =
            member_session(vec!["circle-y".to_string()], "outside-circle-member");

        let in_result = detail(
            State(state.clone()),
            member_in_circle,
            Path(record.vault_id.clone()),
        )
        .await;
        assert!(
            in_result.is_ok(),
            "a Circle member must see the Circle's files"
        );

        let out_result = detail(
            State(state),
            member_outside_circle,
            Path(record.vault_id.clone()),
        )
        .await;
        assert!(
            matches!(out_result, Err(ApiError::Forbidden(_))),
            "a non-member must not see the Circle's files"
        );
    }

    #[tokio::test]
    async fn history_is_owner_only_and_records_downloads() {
        let _env_lock = crate::vault::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = TestVaultBase::set(temp.path());
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Docker,
        );
        let owner_reg = "history-owner-registration";
        let owner_did = member_did(owner_reg);
        let record =
            ingest_test_file(&temp, VaultNamespace::Personal, &owner_did, "report.txt").await;
        let state = crate::api::state::AppState::for_tests(
            temp.path(),
            "nodeA",
            temp.path().join("config").to_string_lossy().to_string(),
        );

        let owner_session = member_session(vec![], owner_reg);
        let _ = download(
            State(state.clone()),
            owner_session.clone(),
            Path(record.vault_id.clone()),
        )
        .await
        .expect("owner can download their own file");

        let history_result = history(
            State(state.clone()),
            owner_session,
            Path(record.vault_id.clone()),
        )
        .await
        .expect("owner can view download history");
        assert_eq!(history_result.0.count, 1);
        assert_eq!(history_result.0.downloads[0].downloader_did, owner_did);

        let other_session = member_session(vec![], "someone-else-registration");
        let denied = history(State(state), other_session, Path(record.vault_id.clone())).await;
        assert!(matches!(denied, Err(ApiError::Forbidden(_))));
    }
}
