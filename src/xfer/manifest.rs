use crate::did::document::Proof;
use crate::key_manager::KeyManager;
use crate::xfer::errors::XferError;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub transfer_id: String,
    pub circle_id: String,
    pub sender_did: String,
    pub filename: String,
    pub size: u64,
    pub chunk_bytes: u32,
    pub chunk_count: u32,
    pub chunk_digests: Vec<String>,
    pub file_sha256: String,
    pub created_at: String,
    pub proof: Proof,
}

#[derive(Debug, Clone)]
pub struct FileMaterial {
    pub filename: String,
    pub size: u64,
    pub chunk_digests: Vec<String>,
    pub file_sha256: String,
}

impl FileManifest {
    pub fn build_signed(
        circle_id: &str,
        sender_did: &str,
        material: FileMaterial,
        chunk_bytes: u32,
        km: &KeyManager,
        vm_ref: &str,
    ) -> Result<Self, XferError> {
        let transfer_id = derive_transfer_id(
            sender_did,
            circle_id,
            &material.filename,
            material.size,
            &material.file_sha256,
            chunk_bytes,
        );
        let mut manifest = Self {
            transfer_id,
            circle_id: circle_id.to_string(),
            sender_did: sender_did.to_string(),
            filename: safe_manifest_name(&material.filename),
            size: material.size,
            chunk_bytes,
            chunk_count: material.chunk_digests.len() as u32,
            chunk_digests: material.chunk_digests,
            file_sha256: material.file_sha256,
            created_at: Utc::now().to_rfc3339(),
            proof: Proof::default(),
        };
        let canonical = manifest.canonical_bytes_for_sign()?;
        crate::did::doc_sign::sign_in_place_generic(&mut manifest.proof, &canonical, km, vm_ref)?;
        Ok(manifest)
    }

    pub fn without_proof(&self) -> Self {
        let mut clone = self.clone();
        clone.proof = Proof::default();
        clone
    }

    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, XferError> {
        let value = serde_json::to_value(self.without_proof())?;
        let sorted = sort_value(&value);
        Ok(serde_json::to_vec(&sorted)?)
    }

    pub fn validate_shape(&self) -> Result<(), XferError> {
        if self.transfer_id.trim().is_empty() {
            return Err(XferError::InvalidStructure(
                "transfer_id must not be empty".to_string(),
            ));
        }
        if self.circle_id.trim().is_empty() {
            return Err(XferError::InvalidStructure(
                "circle_id must not be empty".to_string(),
            ));
        }
        if self.sender_did.trim().is_empty() {
            return Err(XferError::InvalidStructure(
                "sender_did must not be empty".to_string(),
            ));
        }
        if self.filename.trim().is_empty() {
            return Err(XferError::InvalidStructure(
                "filename must not be empty".to_string(),
            ));
        }
        if self.chunk_bytes == 0 {
            return Err(XferError::InvalidStructure(
                "chunk_bytes must be non-zero".to_string(),
            ));
        }
        if self.chunk_count as usize != self.chunk_digests.len() {
            return Err(XferError::InvalidStructure(format!(
                "chunk_count {} != digests {}",
                self.chunk_count,
                self.chunk_digests.len()
            )));
        }
        Ok(())
    }

    pub fn chunk_len(&self, index: u32) -> Result<usize, XferError> {
        if index >= self.chunk_count {
            return Err(XferError::InvalidStructure(format!(
                "chunk index {} out of range {}",
                index, self.chunk_count
            )));
        }
        let standard = self.chunk_bytes as u64;
        let remainder = self.size % standard;
        let is_last = index + 1 == self.chunk_count;
        let len = if is_last && remainder != 0 {
            remainder
        } else if self.size == 0 && self.chunk_count == 0 {
            0
        } else {
            standard
        };
        Ok(len as usize)
    }
}

pub fn derive_transfer_id(
    sender_did: &str,
    circle_id: &str,
    filename: &str,
    size: u64,
    file_sha256: &str,
    chunk_bytes: u32,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sender_did.as_bytes());
    hasher.update([0]);
    hasher.update(circle_id.as_bytes());
    hasher.update([0]);
    hasher.update(filename.as_bytes());
    hasher.update([0]);
    hasher.update(size.to_be_bytes());
    hasher.update([0]);
    hasher.update(file_sha256.as_bytes());
    hasher.update([0]);
    hasher.update(chunk_bytes.to_be_bytes());
    format!("xfer-{}", hex::encode(hasher.finalize()))
}

pub fn inspect_file_blocking(
    path: PathBuf,
    chunk_bytes: u32,
    max_file_bytes: u64,
) -> Result<FileMaterial, XferError> {
    let file = std::fs::File::open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(XferError::InvalidStructure(format!(
            "path is not a regular file: {}",
            path.display()
        )));
    }
    let size = metadata.len();
    if size > max_file_bytes {
        return Err(XferError::FileTooLarge {
            size,
            max: max_file_bytes,
        });
    }

    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(safe_manifest_name)
        .unwrap_or_else(|| "file.bin".to_string());

    let mut reader = std::io::BufReader::new(file);
    let mut file_hasher = Sha256::new();
    let mut chunk_digests = Vec::new();
    let mut buffer = vec![0_u8; chunk_bytes as usize];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let slice = &buffer[..read];
        file_hasher.update(slice);
        chunk_digests.push(hex::encode(Sha256::digest(slice)));
    }

    Ok(FileMaterial {
        filename,
        size,
        chunk_digests,
        file_sha256: hex::encode(file_hasher.finalize()),
    })
}

pub fn safe_manifest_name(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file.bin");
    let cleaned = base
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '\0' => '_',
            _ => ch,
        })
        .collect::<String>();
    if cleaned.trim().is_empty() {
        "file.bin".to_string()
    } else {
        cleaned
    }
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), sort_value(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(sort_value).collect()),
        _ => value.clone(),
    }
}
