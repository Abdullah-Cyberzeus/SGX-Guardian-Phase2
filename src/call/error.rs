//! Call-specific errors for the secure calling subsystem.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CallError {
    #[error("Invalid call state: cannot transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Session not found: {session_id}")]
    SessionNotFound { session_id: String },

    #[error("Offer invalid: {reason}")]
    InvalidOffer { reason: String },

    #[error("Nonce already used: {nonce}")]
    NonceReused { nonce: String },

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Device not authorized for call: {reason}")]
    UnauthorizedDevice { reason: String },

    #[error("Nebula send failed: {reason}")]
    NebulaError { reason: String },

    #[error("Session timeout after {seconds} seconds")]
    SessionTimeout { seconds: u64 },

    #[error("Call rejected: {reason}")]
    CallRejected { reason: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key manager error: {0}")]
    KeyManagerError(String),

    #[error("Audit error: {0}")]
    AuditError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type CallResult<T> = Result<T, CallError>;
