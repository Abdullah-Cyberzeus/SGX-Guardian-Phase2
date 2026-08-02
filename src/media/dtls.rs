//! DTLS (Datagram TLS) - Encryption for Media Transport
//!
//! Handles DTLS handshake and key derivation for secure media transport.
//! Integrates with existing TLS infrastructure.

use crate::media::errors::{MediaError, MediaResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// DTLS handshake state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DtlsHandshakeState {
    /// New, not started
    New,
    /// ClientHello sent
    ClientHelloSent,
    /// ServerHello received
    ServerHelloReceived,
    /// Certificate exchange in progress
    CertificateExchange,
    /// Handshake complete, keys derived
    HandshakeComplete,
    /// Handshake failed
    Failed,
    /// Connection closed
    Closed,
}

impl DtlsHandshakeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DtlsHandshakeState::New => "new",
            DtlsHandshakeState::ClientHelloSent => "client_hello_sent",
            DtlsHandshakeState::ServerHelloReceived => "server_hello_received",
            DtlsHandshakeState::CertificateExchange => "certificate_exchange",
            DtlsHandshakeState::HandshakeComplete => "handshake_complete",
            DtlsHandshakeState::Failed => "failed",
            DtlsHandshakeState::Closed => "closed",
        }
    }
}

/// DTLS context for media encryption
pub struct DtlsContext {
    peer_id: String,
    state: DtlsHandshakeState,
    local_fingerprint: String,
    remote_fingerprint: Option<String>,
    master_key: Option<Vec<u8>>,
    master_salt: Option<Vec<u8>>,
}

impl DtlsContext {
    /// Create a new DTLS context
    pub fn new(peer_id: impl Into<String>) -> Self {
        let peer_id = peer_id.into();
        let fingerprint = Self::generate_fingerprint(&peer_id);

        DtlsContext {
            peer_id,
            state: DtlsHandshakeState::New,
            local_fingerprint: fingerprint,
            remote_fingerprint: None,
            master_key: None,
            master_salt: None,
        }
    }

    /// Get peer ID
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Get handshake state
    pub fn state(&self) -> DtlsHandshakeState {
        self.state
    }

    /// Get local fingerprint (certificate fingerprint for verification)
    pub fn local_fingerprint(&self) -> &str {
        &self.local_fingerprint
    }

    /// Set remote fingerprint (peer's certificate fingerprint)
    pub fn set_remote_fingerprint(&mut self, fingerprint: impl Into<String>) -> MediaResult<()> {
        if self.state != DtlsHandshakeState::New {
            return Err(MediaError::InvalidState(
                "Cannot set fingerprint after handshake started".to_string(),
            ));
        }
        self.remote_fingerprint = Some(fingerprint.into());
        Ok(())
    }

    /// Get remote fingerprint
    pub fn remote_fingerprint(&self) -> Option<&str> {
        self.remote_fingerprint.as_deref()
    }

    /// Start DTLS handshake (client side)
    pub fn start_handshake(&mut self) -> MediaResult<()> {
        if self.state != DtlsHandshakeState::New {
            return Err(MediaError::InvalidState(
                "Handshake already in progress".to_string(),
            ));
        }

        if self.remote_fingerprint.is_none() {
            return Err(MediaError::InvalidState(
                "Remote fingerprint must be set before handshake".to_string(),
            ));
        }

        self.state = DtlsHandshakeState::ClientHelloSent;
        Ok(())
    }

    /// Simulate receiving ServerHello
    pub fn process_server_hello(&mut self) -> MediaResult<()> {
        if self.state != DtlsHandshakeState::ClientHelloSent {
            return Err(MediaError::DtlsHandshakeFailed(
                "Invalid handshake state".to_string(),
            ));
        }
        self.state = DtlsHandshakeState::ServerHelloReceived;
        Ok(())
    }

    /// Complete handshake and derive keys
    pub fn complete_handshake(&mut self) -> MediaResult<()> {
        if self.state != DtlsHandshakeState::ServerHelloReceived {
            return Err(MediaError::DtlsHandshakeFailed(
                "Cannot complete from this state".to_string(),
            ));
        }

        // Derive master key and salt from handshake material
        self.derive_keys()?;
        self.state = DtlsHandshakeState::HandshakeComplete;
        Ok(())
    }

    /// Derive encryption keys from DTLS handshake
    fn derive_keys(&mut self) -> MediaResult<()> {
        // Simulate PRF (Pseudo-Random Function) with SHA256
        let mut hasher = Sha256::new();
        hasher.update(self.peer_id.as_bytes());
        hasher.update(self.local_fingerprint.as_bytes());

        if let Some(ref remote) = self.remote_fingerprint {
            hasher.update(remote.as_bytes());
        }

        let hash = hasher.finalize();
        let hash_vec = hash.to_vec();

        // Split hash into master key and salt
        self.master_key = Some(hash_vec[0..16].to_vec());
        self.master_salt = Some(hash_vec[16..28].to_vec());

        Ok(())
    }

    /// Get master key for SRTP
    pub fn master_key(&self) -> Option<&[u8]> {
        self.master_key.as_deref()
    }

    /// Get master salt for SRTP
    pub fn master_salt(&self) -> Option<&[u8]> {
        self.master_salt.as_deref()
    }

    /// Close DTLS context
    pub fn close(&mut self) -> MediaResult<()> {
        self.state = DtlsHandshakeState::Closed;
        self.master_key = None;
        self.master_salt = None;
        Ok(())
    }

    /// Generate a fingerprint (simulated certificate fingerprint)
    fn generate_fingerprint(peer_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(peer_id.as_bytes());
        let hash = hasher.finalize();
        format!("sha-256 {}", hex::encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtls_context_creation() {
        let ctx = DtlsContext::new("test-peer");
        assert_eq!(ctx.peer_id(), "test-peer");
        assert_eq!(ctx.state(), DtlsHandshakeState::New);
        assert!(!ctx.local_fingerprint().is_empty());
    }

    #[test]
    fn test_dtls_set_remote_fingerprint() {
        let mut ctx = DtlsContext::new("test-peer");
        let result = ctx.set_remote_fingerprint("sha-256 abcd1234...");
        assert!(result.is_ok());
        assert_eq!(ctx.remote_fingerprint(), Some("sha-256 abcd1234..."));
    }

    #[test]
    fn test_dtls_handshake_flow() {
        let mut ctx = DtlsContext::new("test-peer");
        ctx.set_remote_fingerprint("sha-256 remote...").unwrap();

        assert!(ctx.start_handshake().is_ok());
        assert_eq!(ctx.state(), DtlsHandshakeState::ClientHelloSent);

        assert!(ctx.process_server_hello().is_ok());
        assert_eq!(ctx.state(), DtlsHandshakeState::ServerHelloReceived);

        assert!(ctx.complete_handshake().is_ok());
        assert_eq!(ctx.state(), DtlsHandshakeState::HandshakeComplete);
    }

    #[test]
    fn test_dtls_key_derivation() {
        let mut ctx = DtlsContext::new("test-peer");
        ctx.set_remote_fingerprint("sha-256 remote...").unwrap();
        ctx.start_handshake().unwrap();
        ctx.process_server_hello().unwrap();
        ctx.complete_handshake().unwrap();

        assert!(ctx.master_key().is_some());
        assert!(ctx.master_salt().is_some());
        assert_eq!(ctx.master_key().unwrap().len(), 16);
        assert_eq!(ctx.master_salt().unwrap().len(), 12);
    }

    #[test]
    fn test_dtls_invalid_fingerprint_after_handshake() {
        let mut ctx = DtlsContext::new("test-peer");
        ctx.set_remote_fingerprint("sha-256 remote...").unwrap();
        ctx.start_handshake().unwrap();

        let result = ctx.set_remote_fingerprint("sha-256 other...");
        assert!(result.is_err());
    }

    #[test]
    fn test_dtls_close() {
        let mut ctx = DtlsContext::new("test-peer");
        ctx.set_remote_fingerprint("sha-256 remote...").unwrap();
        ctx.start_handshake().unwrap();
        ctx.process_server_hello().unwrap();
        ctx.complete_handshake().unwrap();

        assert!(ctx.close().is_ok());
        assert_eq!(ctx.state(), DtlsHandshakeState::Closed);
        assert!(ctx.master_key().is_none());
    }
}
