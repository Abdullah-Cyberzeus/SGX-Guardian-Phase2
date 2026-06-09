use crate::did::errors::DidError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VcError {
    #[error("VC structure invalid: {0}")]
    InvalidStructure(String),
    #[error("VC issuer DID not resolvable: {0}")]
    IssuerNotResolvable(String),
    #[error("VC proof signature invalid")]
    InvalidProof,
    #[error("VC expired (expirationDate={0})")]
    Expired(String),
    #[error("VC subject mismatch: expected {expected}, got {got}")]
    SubjectMismatch { expected: String, got: String },
    #[error("VC revoked at status list index {0}")]
    Revoked(u64),
    #[error("status list unavailable: {0}")]
    StatusListUnavailable(String),
    #[error("status list signature invalid")]
    StatusListProofInvalid,
    #[error("status list index out of range: {index} (size={size})")]
    IndexOutOfRange { index: u64, size: u64 },
    #[error("circle mismatch: expected {expected}, got {got}")]
    CircleMismatch { expected: String, got: String },
    #[error("issuer mismatch: expected {expected}, got {got}")]
    IssuerMismatch { expected: String, got: String },
    #[error("not the CA: only the Circle owner may issue VCs")]
    NotCircleOwnerForIssue,
    #[error("not the CA: only the Circle owner may revoke VCs")]
    NotCircleOwnerForRevoke,
    #[error("not the CA: only the Circle owner may renew VCs")]
    NotCircleOwnerForRenew,
    #[error("VC not found: {0}")]
    NotFound(String),
    #[error("Cannot renew revoked VC")]
    CannotRenewRevokedVc,
    #[error("Cannot renew expired VC without --allow-expired (expirationDate={0})")]
    CannotRenewExpiredVc(String),
    #[error("membershipStatus must be active, got {0}")]
    InvalidMembershipStatus(String),
    #[error("permission not in allowed set: {0}")]
    UnknownPermission(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("did: {0}")]
    Did(#[from] DidError),
}
