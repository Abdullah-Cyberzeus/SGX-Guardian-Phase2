use crate::api::state::AppState;
use crate::backup::crypto;
use crate::backup::errors::BackupError;
use crate::backup::model::{
    Manifest, ValidateReport, BACKUP_SCHEMA_VERSION, COMPONENT_SCHEMA_VERSION,
};
use crate::backup::BackupConfig;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DecodedBackup {
    pub manifest: Manifest,
    pub files: Vec<DecodedFile>,
}

#[derive(Debug, Clone)]
pub struct DecodedFile {
    pub archive_path: String,
    pub bytes: Vec<u8>,
}

pub async fn validate_backup(
    state: Arc<AppState>,
    config: BackupConfig,
    id: &str,
    passphrase: String,
) -> Result<ValidateReport, BackupError> {
    let decoded = decode_backup_by_id(&config, id, &passphrase).await?;
    validate_manifest(&decoded)?;
    let same_device_identity = decoded.manifest.source_did == state.device_did;
    let mut warnings = Vec::new();
    if !same_device_identity {
        warnings.push(
            "target DID differs from the backup DID; identity_meta is metadata-only and new hardware must re-enrol"
                .to_string(),
        );
    }
    Ok(ValidateReport {
        status: "ok".to_string(),
        backup_id: decoded.manifest.backup_id,
        source_node_id: decoded.manifest.source_node_id,
        source_did: decoded.manifest.source_did,
        target_did: state.device_did.clone(),
        same_device_identity,
        portable: decoded.manifest.portable,
        components: decoded.manifest.components,
        warnings,
    })
}

pub async fn decode_backup_by_id(
    config: &BackupConfig,
    id: &str,
    passphrase: &str,
) -> Result<DecodedBackup, BackupError> {
    let path = config.bundle_path(id);
    if !tokio::fs::try_exists(&path).await? {
        return Err(BackupError::NotFound(id.to_string()));
    }
    decode_backup_file(&path, passphrase, config.max_bundle_bytes).await
}

pub async fn decode_backup_file(
    path: &Path,
    passphrase: &str,
    max_bytes: u64,
) -> Result<DecodedBackup, BackupError> {
    let path = path.to_path_buf();
    let passphrase = passphrase.to_string();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(path)?;
        let plaintext = crypto::decrypt_from_reader(file, &passphrase, max_bytes)?;
        decode_plaintext(&plaintext)
    })
    .await
    .map_err(|error| BackupError::Crypto(format!("backup validation task failed: {}", error)))?
}

pub fn validate_manifest(decoded: &DecodedBackup) -> Result<(), BackupError> {
    if decoded.manifest.schema_version != BACKUP_SCHEMA_VERSION {
        return Err(BackupError::UnsupportedSchema(format!(
            "manifest version {}",
            decoded.manifest.schema_version
        )));
    }
    if decoded.manifest.backup_id.trim().is_empty() {
        return Err(BackupError::Integrity(
            "manifest backup_id must not be empty".to_string(),
        ));
    }
    if decoded.manifest.source_did.trim().is_empty() {
        return Err(BackupError::Integrity(
            "manifest source_did must not be empty".to_string(),
        ));
    }
    for component in &decoded.manifest.components {
        if component.schema_version != COMPONENT_SCHEMA_VERSION {
            return Err(BackupError::UnsupportedSchema(format!(
                "component {:?} version {}",
                component.component, component.schema_version
            )));
        }
    }
    let mut encoded_files = Vec::new();
    for file in &decoded.files {
        let path = file.archive_path.as_bytes();
        let path_len = u32::try_from(path.len())
            .map_err(|_| BackupError::Integrity("archive path too long".to_string()))?;
        let data_len = u64::try_from(file.bytes.len())
            .map_err(|_| BackupError::Integrity("archive data too long".to_string()))?;
        use std::io::Write;
        encoded_files.write_all(&path_len.to_be_bytes())?;
        encoded_files.write_all(path)?;
        encoded_files.write_all(&data_len.to_be_bytes())?;
        encoded_files.write_all(&file.bytes)?;
    }
    let got = hex::encode(Sha256::digest(&encoded_files));
    if got != decoded.manifest.plaintext_sha256 {
        return Err(BackupError::Integrity(format!(
            "plaintext hash mismatch: expected {}, got {}",
            decoded.manifest.plaintext_sha256, got
        )));
    }
    let manifest_paths = decoded
        .manifest
        .components
        .iter()
        .flat_map(|component| component.paths.iter())
        .collect::<std::collections::BTreeSet<_>>();
    let file_paths = decoded
        .files
        .iter()
        .map(|file| &file.archive_path)
        .collect::<std::collections::BTreeSet<_>>();
    if manifest_paths != file_paths {
        return Err(BackupError::Integrity(
            "manifest paths do not match bundle contents".to_string(),
        ));
    }
    Ok(())
}

fn decode_plaintext(plaintext: &[u8]) -> Result<DecodedBackup, BackupError> {
    if plaintext.len() < 4 {
        return Err(BackupError::Integrity(
            "missing manifest header".to_string(),
        ));
    }
    let manifest_len =
        u32::from_be_bytes(plaintext[..4].try_into().expect("slice length checked")) as usize;
    let manifest_start = 4_usize;
    let manifest_end = manifest_start
        .checked_add(manifest_len)
        .ok_or_else(|| BackupError::Integrity("invalid manifest length".to_string()))?;
    if manifest_end > plaintext.len() {
        return Err(BackupError::Integrity("truncated manifest".to_string()));
    }
    let manifest = serde_json::from_slice(&plaintext[manifest_start..manifest_end])?;
    let mut cursor = std::io::Cursor::new(&plaintext[manifest_end..]);
    let mut files = Vec::new();
    loop {
        let mut path_len = [0_u8; 4];
        match cursor.read_exact(&mut path_len) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        }
        let path_len = u32::from_be_bytes(path_len) as usize;
        let mut path = vec![0_u8; path_len];
        cursor.read_exact(&mut path)?;
        let mut data_len = [0_u8; 8];
        cursor.read_exact(&mut data_len)?;
        let data_len = u64::from_be_bytes(data_len) as usize;
        let mut bytes = vec![0_u8; data_len];
        cursor.read_exact(&mut bytes)?;
        let archive_path = String::from_utf8(path)
            .map_err(|_| BackupError::Integrity("archive path is not UTF-8".to_string()))?;
        if archive_path.starts_with('/') || archive_path.contains("..") {
            return Err(BackupError::Integrity(format!(
                "unsafe archive path: {}",
                archive_path
            )));
        }
        files.push(DecodedFile {
            archive_path,
            bytes,
        });
    }
    Ok(DecodedBackup { manifest, files })
}
