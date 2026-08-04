use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("backup not found: {0}")]
    NotFound(String),
    #[error("invalid backup request: {0}")]
    InvalidRequest(String),
    #[error("duplicate backup: {0}")]
    Duplicate(String),
    #[error("backup integrity check failed: {0}")]
    Integrity(String),
    #[error("unsupported backup schema: {0}")]
    UnsupportedSchema(String),
    #[error("restore is not available: {0}")]
    RestoreUnavailable(String),
    #[error("backup bundle is too large: {size} > {max}")]
    BundleTooLarge { size: u64, max: u64 },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("crypto: {0}")]
    Crypto(String),
}
