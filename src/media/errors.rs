//! Media module error types

use std::fmt;

/// Media operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    /// WebRTC peer connection error
    PeerConnectionError(String),
    /// ICE candidate gathering failed
    IceCandidateFailed(String),
    /// DTLS handshake failed
    DtlsHandshakeFailed(String),
    /// SRTP session setup failed
    SrtpSetupFailed(String),
    /// Codec not supported
    UnsupportedCodec(String),
    /// Invalid state for operation
    InvalidState(String),
    /// Media path verification failed
    MediaPathDenied(String),
    /// Encryption/decryption error
    EncryptionError(String),
}

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaError::PeerConnectionError(e) => write!(f, "Peer connection error: {}", e),
            MediaError::IceCandidateFailed(e) => write!(f, "ICE candidate failed: {}", e),
            MediaError::DtlsHandshakeFailed(e) => write!(f, "DTLS handshake failed: {}", e),
            MediaError::SrtpSetupFailed(e) => write!(f, "SRTP setup failed: {}", e),
            MediaError::UnsupportedCodec(e) => write!(f, "Unsupported codec: {}", e),
            MediaError::InvalidState(e) => write!(f, "Invalid state: {}", e),
            MediaError::MediaPathDenied(e) => write!(f, "Media path denied: {}", e),
            MediaError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
        }
    }
}

impl std::error::Error for MediaError {}

pub type MediaResult<T> = Result<T, MediaError>;
