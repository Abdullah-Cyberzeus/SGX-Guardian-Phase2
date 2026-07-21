use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::vault::errors::VaultError;
use crate::vault::folders::{self, FolderIndex, FolderNode};
use crate::vault::namespace::{validate_folder_id, validate_vault_id, VaultNamespace};
use crate::vault::{
    download_path, ingest, persistence, quota as vault_quota, upload, VaultConfig, VaultRecord,
};
use axum::body::{Body, Bytes};
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
    State(_state): State<Arc<AppState>>,
    Query(query): Query<VaultListQuery>,
) -> Result<Json<VaultListResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let namespace = optional_namespace(query.namespace.as_deref(), query.circle_id.as_deref())?;
    let namespace_key = namespace.as_ref().map(VaultNamespace::storage_key);
    let mut records = persistence::list_records(&config, namespace_key.as_deref())
        .await
        .map_err(map_vault_error)?;

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
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<VaultRecord>, ApiError> {
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let config = VaultConfig::from_env();
    let record = persistence::find_record(&config, &id)
        .await
        .map_err(map_vault_error)?
        .ok_or_else(|| ApiError::NotFound(format!("vault file not found: {}", id)))?;
    Ok(Json(record))
}

pub async fn overview(
    State(state): State<Arc<AppState>>,
) -> Result<Json<VaultOverviewResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let records = persistence::list_records(&config, None)
        .await
        .map_err(map_vault_error)?;
    let quota = vault_quota::compute(&config)
        .await
        .map_err(map_vault_error)?;

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
    for namespace in folders::list_namespaces(&config)
        .await
        .map_err(map_vault_error)?
    {
        namespaces.insert(namespace.storage_key());
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
        folder_count += index.folders.len();
        items.push(VaultNamespaceOverview {
            namespace: namespace_key,
            file_count,
            folder_count: index.folders.len(),
            used_bytes,
        });
    }

    items.sort_by(|left, right| {
        namespace_sort_key(&left.namespace).cmp(&namespace_sort_key(&right.namespace))
    });

    Ok(Json(VaultOverviewResponse {
        file_count: records.len(),
        folder_count,
        used_bytes: quota.used_bytes,
        capacity_bytes: quota.capacity_bytes,
        namespaces: items,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn quota_status(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<VaultQuotaQuery>,
) -> Result<Json<VaultQuotaResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let namespace = optional_namespace(query.ns.as_deref(), query.circle_id.as_deref())?
        .unwrap_or(VaultNamespace::Personal);
    let quota = vault_quota::compute_namespace(&config, &namespace)
        .await
        .map_err(map_vault_error)?;

    Ok(Json(VaultQuotaResponse {
        used_bytes: quota.used_bytes,
        quota_bytes: quota.quota_bytes,
        remaining_bytes: quota.remaining_bytes(),
        usage_percent: quota.usage_percent(),
    }))
}

pub async fn tree(
    State(state): State<Arc<AppState>>,
    Query(query): Query<VaultTreeQuery>,
) -> Result<Json<VaultTreeResponse>, ApiError> {
    let config = VaultConfig::from_env();
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
    let folders = index.children_of(&folder_id);

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
    let records = persistence::list_records(&config, None)
        .await
        .map_err(map_vault_error)?;
    let mut indices = BTreeMap::<String, FolderIndex>::new();
    let mut results = Vec::new();

    for record in records
        .into_iter()
        .filter(|record| record.filename.to_lowercase().contains(&needle))
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
    Query(query): Query<VaultUploadQuery>,
    mut multipart: Multipart,
) -> Result<Json<VaultUploadResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let namespace = required_namespace(query.ns.as_deref())?;
    let folder_id = normalize_folder_id(query.folder_id.as_deref())?;
    ensure_folder_exists(&config, &namespace, &state.node_id, &folder_id).await?;

    let chunk_bytes = VaultConfig::DEFAULT_CHUNK_BYTES;
    let namespace_quota_bytes = vault_quota::configured_quota_bytes(&config, &namespace)
        .await
        .map_err(map_vault_error)?;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::BadRequest(error.to_string()))?
    {
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
                sender_did: resolve_sender_did(&state),
                staging_path,
                size_plain,
                sha256_plain: hex::encode(hasher.finalize()),
                chunk_bytes,
            },
        )
        .await
        .map_err(map_vault_error)?;

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
    Path(id): Path<String>,
    Json(body): Json<UpdateFileRequest>,
) -> Result<Json<VaultRecord>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let mut record = persistence::find_record(&config, &id)
        .await
        .map_err(map_vault_error)?
        .ok_or_else(|| ApiError::NotFound(format!("vault file not found: {}", id)))?;
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
    Path(id): Path<String>,
) -> Result<Json<VaultActionResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let record = persistence::find_record(&config, &id)
        .await
        .map_err(map_vault_error)?
        .ok_or_else(|| ApiError::NotFound(format!("vault file not found: {}", id)))?;
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
    Path(id): Path<String>,
    body: Option<Json<ToggleStarRequest>>,
) -> Result<Json<VaultRecord>, ApiError> {
    let config = VaultConfig::from_env();
    let id = validate_vault_id(&id).map_err(map_vault_error)?;
    let mut record = persistence::find_record(&config, &id)
        .await
        .map_err(map_vault_error)?
        .ok_or_else(|| ApiError::NotFound(format!("vault file not found: {}", id)))?;
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
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let config = VaultConfig::from_env();
    let record = load_record_by_id(&config, &id).await?;
    stream_record(record, "attachment")
        .await
        .map_err(map_vault_error)
}

pub async fn preview(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let config = VaultConfig::from_env();
    let record = load_record_by_id(&config, &id).await?;
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

    stream_record(record, "inline")
        .await
        .map_err(map_vault_error)
}

fn map_vault_error(error: VaultError) -> ApiError {
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

async fn load_record_by_id(config: &VaultConfig, id: &str) -> Result<VaultRecord, ApiError> {
    let id = validate_vault_id(id).map_err(map_vault_error)?;
    persistence::find_record(config, &id)
        .await
        .map_err(map_vault_error)?
        .ok_or_else(|| ApiError::NotFound(format!("vault file not found: {}", id)))
}

async fn stream_record(
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
