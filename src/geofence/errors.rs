use thiserror::Error;

#[derive(Debug, Error)]
pub enum GeofenceError {
    #[error("geofence zone not found: {0}")]
    NotFound(String),
    #[error("invalid geofence input: {0}")]
    InvalidInput(String),
    #[error("geofence registry proof invalid")]
    InvalidProof,
    #[error("unsupported geofence source: {0}")]
    UnsupportedSource(String),
    #[error("rf scan busy: {0}")]
    RfScanBusy(String),
    #[error("rf source unavailable: {0}")]
    RfUnavailable(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type GeofenceResult<T> = Result<T, GeofenceError>;
