use thiserror::Error;

#[derive(Debug, Error)]
pub enum XferError {
    #[error("invalid transfer structure: {0}")]
    InvalidStructure(String),
    #[error("invalid transfer proof for {0}")]
    InvalidProof(String),
    #[error("circle mismatch: expected {expected}, got {got}")]
    CircleMismatch { expected: String, got: String },
    #[error("peer is revoked: {0}")]
    RevokedPeer(String),
    #[error("peer not found in local directory: {0}")]
    PeerNotFound(String),
    #[error("source not found: {0}")]
    SourceNotFound(String),
    #[error("transfer not found: {0}")]
    TransferNotFound(String),
    #[error("hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },
    #[error("file too large: {size} > {max}")]
    FileTooLarge { size: u64, max: u64 },
    #[error("transfer cancelled: {0}")]
    Cancelled(String),
    #[error("transfer conflict: {0}")]
    Conflict(String),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("did: {0}")]
    Did(#[from] crate::did::errors::DidError),
}
