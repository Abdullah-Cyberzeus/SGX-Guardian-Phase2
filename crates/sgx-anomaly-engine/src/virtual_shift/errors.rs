use std::fmt;

/// Errors at the Task 1 -> Virtual Shift trust boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VirtualShiftError {
    EmptyAnomalyId,
    EmptyNodeId,
    InvalidScore,
    InvalidConfidence,
    InvalidTimestamp,
    TooManyAffectedPeers { maximum: usize },
    EmptyAffectedPeer,
    DuplicateAffectedPeer(String),
    TooManyEvidenceItems { maximum: usize },
    EmptyEvidenceFeature,
    UnknownEvidenceFeature(String),
    InvalidTriggerScoreThreshold,
    InvalidTriggerConfidenceThreshold,
    InvalidTriggerCooldown,
}

impl fmt::Display for VirtualShiftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAnomalyId => write!(formatter, "anomaly_id must not be empty"),
            Self::EmptyNodeId => write!(formatter, "source node must not be empty"),
            Self::InvalidScore => write!(
                formatter,
                "anomaly score must be finite and between 0 and 1"
            ),
            Self::InvalidConfidence => {
                write!(
                    formatter,
                    "anomaly confidence must be finite and between 0 and 1"
                )
            }
            Self::InvalidTimestamp => {
                write!(formatter, "observed timestamp must be greater than zero")
            }
            Self::TooManyAffectedPeers { maximum } => {
                write!(formatter, "affected peer list exceeds maximum of {maximum}")
            }
            Self::EmptyAffectedPeer => {
                write!(formatter, "affected peer identifier must not be empty")
            }
            Self::DuplicateAffectedPeer(peer) => {
                write!(formatter, "affected peer '{peer}' appears more than once")
            }
            Self::TooManyEvidenceItems { maximum } => {
                write!(formatter, "evidence list exceeds maximum of {maximum}")
            }
            Self::EmptyEvidenceFeature => write!(formatter, "evidence feature must not be empty"),
            Self::UnknownEvidenceFeature(feature) => {
                write!(
                    formatter,
                    "evidence feature '{feature}' is not in the locked schema"
                )
            }
            Self::InvalidTriggerScoreThreshold => write!(
                formatter,
                "Virtual Shift score threshold must be finite and between 0 and 1"
            ),
            Self::InvalidTriggerConfidenceThreshold => write!(
                formatter,
                "Virtual Shift confidence threshold must be finite and between 0 and 1"
            ),
            Self::InvalidTriggerCooldown => {
                write!(
                    formatter,
                    "Virtual Shift cooldown must be greater than zero"
                )
            }
        }
    }
}

impl std::error::Error for VirtualShiftError {}
