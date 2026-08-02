use thiserror::Error;

#[derive(Debug, Error)]
pub enum DevicesError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("device not found")]
    NotFound,
    #[error("registry integrity check failed")]
    TamperedRegistry,
    #[error("invalid device request: {0}")]
    Invalid(String),
}

pub type DevicesResult<T> = Result<T, DevicesError>;
