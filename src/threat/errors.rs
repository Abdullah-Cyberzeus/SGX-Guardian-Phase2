/// Threat Detection Errors
use std::fmt;

/// Threat detection result type
pub type ThreatResult<T> = Result<T, ThreatError>;

/// Threat detection error types
#[derive(Debug, Clone)]
pub enum ThreatError {
    /// Rule evaluation failed
    RuleEvaluationFailed(String),
    /// Anomaly detection failed
    AnomalyDetectionFailed(String),
    /// Peer not found
    PeerNotFound(String),
    /// Incident not found
    IncidentNotFound(String),
    /// Invalid threat parameters
    InvalidParameters(String),
    /// Thread/concurrency error
    SyncError(String),
    /// Generic threat error
    Other(String),
}

impl fmt::Display for ThreatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatError::RuleEvaluationFailed(msg) => {
                write!(f, "Rule evaluation failed: {}", msg)
            }
            ThreatError::AnomalyDetectionFailed(msg) => {
                write!(f, "Anomaly detection failed: {}", msg)
            }
            ThreatError::PeerNotFound(id) => write!(f, "Peer not found: {}", id),
            ThreatError::IncidentNotFound(id) => write!(f, "Incident not found: {}", id),
            ThreatError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            ThreatError::SyncError(msg) => write!(f, "Synchronization error: {}", msg),
            ThreatError::Other(msg) => write!(f, "Threat error: {}", msg),
        }
    }
}

impl std::error::Error for ThreatError {}
