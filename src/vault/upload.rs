use crate::vault::errors::VaultError;
use crate::vault::ingest::{self, IngestMeta};
use crate::vault::namespace::{validate_folder_id, VaultNamespace};
use crate::vault::{VaultConfig, VaultRecord};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct StagedUpload {
    pub namespace: VaultNamespace,
    pub folder_id: String,
    pub filename: String,
    pub mime: String,
    pub sender_did: String,
    pub staging_path: PathBuf,
    pub size_plain: u64,
    pub sha256_plain: String,
    pub chunk_bytes: u32,
}

impl StagedUpload {
    pub fn normalized_folder_id(&self) -> Result<String, VaultError> {
        validate_folder_id(&self.folder_id)
    }
}

pub async fn ingest_staged_upload(
    _config: &VaultConfig,
    upload: StagedUpload,
) -> Result<VaultRecord, VaultError> {
    let folder_id = upload.normalized_folder_id()?;

    let result = ingest::ingest_upload_file(
        upload.namespace,
        &upload.sender_did,
        &upload.staging_path,
        IngestMeta {
            filename: upload.filename,
            mime: upload.mime,
            sha256_plain: upload.sha256_plain,
            size_plain: upload.size_plain,
            chunk_bytes: upload.chunk_bytes,
        },
        folder_id,
    )
    .await;

    if result.is_err() {
        let _ = ingest::cleanup_plaintext(&upload.staging_path).await;
    }

    result
}
