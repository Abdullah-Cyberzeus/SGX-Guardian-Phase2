use thiserror::Error;

pub type DusageResult<T> = Result<T, DusageError>;

#[derive(Debug, Error)]
pub enum DusageError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid data-usage period: {0}")]
    InvalidPeriod(String),
    #[error("nft counter command failed: {0}")]
    Nft(String),
}
