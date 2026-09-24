use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Safe, caller-visible validation failures for the Task 4 AI boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatPredictionError {
    InvalidConfig(String),
    InvalidProbability(String),
    InvalidConfidence(String),
    InvalidHorizon(String),
    InvalidForecast(String),
    MalformedEvent(String),
    InvalidTimestamp(String),
    AttributeLimitExceeded(String),
    Io(String),
    Serialization(String),
}

impl Display for ThreatPredictionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid Task4 configuration: {message}")
            }
            Self::InvalidProbability(message) => {
                write!(formatter, "invalid Task4 probability: {message}")
            }
            Self::InvalidConfidence(message) => {
                write!(formatter, "invalid Task4 confidence: {message}")
            }
            Self::InvalidHorizon(message) => {
                write!(formatter, "invalid Task4 forecast horizon: {message}")
            }
            Self::InvalidForecast(message) => {
                write!(formatter, "invalid Task4 forecast: {message}")
            }
            Self::MalformedEvent(message) => write!(formatter, "malformed Task4 event: {message}"),
            Self::InvalidTimestamp(message) => {
                write!(formatter, "invalid Task4 timestamp: {message}")
            }
            Self::AttributeLimitExceeded(message) => {
                write!(formatter, "Task4 event attribute limit exceeded: {message}")
            }
            Self::Io(message) => write!(formatter, "Task4 configuration I/O failure: {message}"),
            Self::Serialization(message) => write!(
                formatter,
                "Task4 configuration serialization failure: {message}"
            ),
        }
    }
}

impl Error for ThreatPredictionError {}
