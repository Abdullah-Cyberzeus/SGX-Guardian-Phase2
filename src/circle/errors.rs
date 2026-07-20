use thiserror::Error;

pub type CircleResult<T> = Result<T, CircleError>;

#[derive(Debug, Error)]
pub enum CircleError {
    #[error("invalid circle data: {0}")]
    Invalid(String),
    #[error("circle not found: {0}")]
    NotFound(String),
    #[error("circle conflict: {0}")]
    Conflict(String),
    #[error("invalid circle proof: {0}")]
    InvalidProof(String),
    #[error("invite expired at {0}")]
    InviteExpired(String),
    #[error("invite replay rejected: {0}")]
    InviteReplay(String),
    #[error("QR payload exceeds budget ({size} > {max})")]
    QrPayloadTooLarge { size: usize, max: usize },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("vc: {0}")]
    Vc(#[from] crate::vc::errors::VcError),
    #[error("did: {0}")]
    Did(#[from] crate::did::errors::DidError),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
}
