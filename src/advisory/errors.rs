use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdvisoryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid advisory rules: {0}")]
    InvalidRules(String),
}

pub type AdvisoryResult<T> = Result<T, AdvisoryError>;
