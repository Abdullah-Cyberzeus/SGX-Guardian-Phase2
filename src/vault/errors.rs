use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault not found: {0}")]
    NotFound(String),
    #[error("invalid vault structure: {0}")]
    InvalidStructure(String),
    #[error("vault conflict: {0}")]
    Conflict(String),
    #[error(
        "vault quota exceeded: capacity={capacity_bytes} used={used_bytes} required={required_bytes}"
    )]
    QuotaExceeded {
        capacity_bytes: u64,
        used_bytes: u64,
        required_bytes: u64,
    },
    #[error("integrity mismatch: expected {expected}, got {got}")]
    Integrity { expected: String, got: String },
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
}
