use thiserror::Error;

pub type NotifyResult<T> = Result<T, NotifyError>;

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("did: {0}")]
    Did(#[from] crate::did::DidError),
    #[error("invalid prefs proof: {0}")]
    InvalidProof(String),
    #[error("missing local did document")]
    MissingSelfDocument,
    #[error("task join: {0}")]
    TaskJoin(String),
}
