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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_media_error_has_actionable_display_text() {
        let cases = [
            (
                MediaError::PeerConnectionError("peer".into()),
                "Peer connection error: peer",
            ),
            (
                MediaError::IceCandidateFailed("ice".into()),
                "ICE candidate failed: ice",
            ),
            (
                MediaError::DtlsHandshakeFailed("dtls".into()),
                "DTLS handshake failed: dtls",
            ),
            (
                MediaError::SrtpSetupFailed("srtp".into()),
                "SRTP setup failed: srtp",
            ),
            (
                MediaError::UnsupportedCodec("codec".into()),
                "Unsupported codec: codec",
            ),
            (
                MediaError::InvalidState("state".into()),
                "Invalid state: state",
            ),
            (
                MediaError::MediaPathDenied("policy".into()),
                "Media path denied: policy",
            ),
            (
                MediaError::EncryptionError("crypto".into()),
                "Encryption error: crypto",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
            let trait_object: &dyn std::error::Error = &error;
            assert_eq!(trait_object.to_string(), expected);
        }
    }
}
