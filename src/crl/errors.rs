use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrlError {
    #[error("invalid CRL entry: {0}")]
    InvalidStructure(String),
    #[error("invalid signature on CRL entry {0}")]
    InvalidProof(String),
    #[error("issuer DID not resolvable: {0}")]
    IssuerNotResolvable(String),
    #[error("member-issued entries must be Critical or High severity (got {0:?})")]
    MemberSeverityTooLow(crate::crl::entry::Severity),
    #[error("member-issued entries must be a security-critical reason (got {0})")]
    MemberReasonNotCritical(String),
    #[error("only the Circle owner can issue administrative_removal or voluntary_departure")]
    NotOwner,
    #[error("circle mismatch: expected {expected}, got {got}")]
    CircleMismatch { expected: String, got: String },
    #[error("revoker may not revoke themselves")]
    SelfRevocation,
    #[error("DID is already revoked (entry {0})")]
    AlreadyRevoked(String),
    #[error("only the Circle owner can unrevoke a DID")]
    UnrevokeRequiresOwner,
    #[error("DID is not currently revoked: {0}")]
    NotRevoked(String),
    #[error("CRL self-verification failed: Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("did: {0}")]
    Did(#[from] crate::did::errors::DidError),
}
