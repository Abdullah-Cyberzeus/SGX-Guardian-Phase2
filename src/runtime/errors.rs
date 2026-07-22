use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("State machine error: {0}")]
    StateMachineError(String),
    #[error("Internal error: {0}")]
    Internal(String),
}
