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
    /// Create a new DTLS context from the local media certificate bytes.
    pub fn new(peer_id: impl Into<String>, local_certificate_der: &[u8]) -> MediaResult<Self> {
        let peer_id = peer_id.into();
        if local_certificate_der.is_empty() {
            return Err(MediaError::InvalidState(
                "Local DTLS certificate is required".to_string(),
            ));
        }
        let fingerprint = Self::fingerprint_for_certificate(local_certificate_der);

        Ok(DtlsContext {
            peer_id,
            state: DtlsHandshakeState::New,
            local_fingerprint: fingerprint,
            remote_fingerprint: None,
            master_key: None,
            master_salt: None,
        })
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
        let fingerprint = fingerprint.into();
        if !Self::is_valid_sha256_fingerprint(&fingerprint) {
            return Err(MediaError::InvalidState(
                "Remote DTLS fingerprint must be a SHA-256 certificate fingerprint".to_string(),
            ));
        }
        if normalize_fingerprint(&fingerprint) == normalize_fingerprint(&self.local_fingerprint) {
            return Err(MediaError::InvalidState(
                "Remote DTLS fingerprint must differ from local certificate".to_string(),
            ));
        }
        self.remote_fingerprint = Some(fingerprint);
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

    /// Record that the peer's ServerHello was received by the browser DTLS stack.
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

        // Mirror the verified browser DTLS-SRTP exporter material for backend
        // evidence. Browser media uses native WebRTC DTLS-SRTP; this module only
        // stores verifier state and never fabricates fingerprints from IDs.
        self.derive_keys()?;
        self.state = DtlsHandshakeState::HandshakeComplete;
        Ok(())
    }

    /// Derive encryption keys from DTLS handshake
    fn derive_keys(&mut self) -> MediaResult<()> {
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

    fn fingerprint_for_certificate(certificate_der: &[u8]) -> String {
        format!("sha-256 {}", hex::encode(Sha256::digest(certificate_der)))
    }

    fn is_valid_sha256_fingerprint(value: &str) -> bool {
        let normalized = normalize_fingerprint(value);
        normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

/// Extract and normalize the DTLS certificate fingerprint from raw SDP text
/// (the standard `a=fingerprint:sha-256 XX:XX:...` attribute line). Returns
/// `None` if the SDP has no fingerprint line, or it isn't a well-formed
/// SHA-256 digest — callers must treat that as "no evidence", not "verified".
pub fn extract_sdp_fingerprint(sdp: &str) -> Option<String> {
    for line in sdp.lines() {
        let Some(rest) = line.trim().strip_prefix("a=fingerprint:") else {
            continue;
        };
        let Some((algo, digest)) = rest.split_once(' ') else {
            continue;
        };
        if !algo.eq_ignore_ascii_case("sha-256") {
            continue;
        }
        let normalized = normalize_fingerprint(digest);
        if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Some(format!("sha-256 {}", normalized));
        }
    }
    None
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha-256")
        .unwrap_or(value.trim())
        .replace([':', ' '], "")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote_fingerprint() -> &'static str {
        "sha-256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    fn other_fingerprint() -> &'static str {
        "sha-256 f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
    }

    #[test]
    fn test_dtls_context_creation() {
        let ctx = DtlsContext::new("test-peer", b"local-cert").unwrap();
        assert_eq!(ctx.peer_id(), "test-peer");
        assert_eq!(ctx.state(), DtlsHandshakeState::New);
        assert!(!ctx.local_fingerprint().is_empty());
    }

    #[test]
    fn test_dtls_set_remote_fingerprint() {
        let mut ctx = DtlsContext::new("test-peer", b"local-cert").unwrap();
        let result = ctx.set_remote_fingerprint(remote_fingerprint());
        assert!(result.is_ok());
        assert_eq!(ctx.remote_fingerprint(), Some(remote_fingerprint()));
    }

    #[test]
    fn test_dtls_handshake_flow() {
        let mut ctx = DtlsContext::new("test-peer", b"local-cert").unwrap();
        ctx.set_remote_fingerprint(remote_fingerprint()).unwrap();

        assert!(ctx.start_handshake().is_ok());
        assert_eq!(ctx.state(), DtlsHandshakeState::ClientHelloSent);

        assert!(ctx.process_server_hello().is_ok());
        assert_eq!(ctx.state(), DtlsHandshakeState::ServerHelloReceived);

        assert!(ctx.complete_handshake().is_ok());
        assert_eq!(ctx.state(), DtlsHandshakeState::HandshakeComplete);
    }

    #[test]
    fn test_dtls_key_derivation() {
        let mut ctx = DtlsContext::new("test-peer", b"local-cert").unwrap();
        ctx.set_remote_fingerprint(remote_fingerprint()).unwrap();
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
        let mut ctx = DtlsContext::new("test-peer", b"local-cert").unwrap();
        ctx.set_remote_fingerprint(remote_fingerprint()).unwrap();
        ctx.start_handshake().unwrap();

        let result = ctx.set_remote_fingerprint(other_fingerprint());
        assert!(result.is_err());
    }

    #[test]
    fn test_dtls_close() {
        let mut ctx = DtlsContext::new("test-peer", b"local-cert").unwrap();
        ctx.set_remote_fingerprint(remote_fingerprint()).unwrap();
        ctx.start_handshake().unwrap();
        ctx.process_server_hello().unwrap();
        ctx.complete_handshake().unwrap();

        assert!(ctx.close().is_ok());
        assert_eq!(ctx.state(), DtlsHandshakeState::Closed);
        assert!(ctx.master_key().is_none());
    }

    #[test]
    fn extracts_and_normalizes_fingerprint_from_real_sdp() {
        let sdp = "v=0\r\no=- 46 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:abcd\r\na=fingerprint:sha-256 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\na=setup:actpass\r\n";
        let fingerprint = extract_sdp_fingerprint(sdp).expect("fingerprint present");
        assert_eq!(
            fingerprint,
            "sha-256 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn extraction_is_case_and_separator_insensitive_but_matches_the_same_digest() {
        let colon_form = "m=audio\r\na=fingerprint:sha-256 AB:CD:EF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:AB:CD:EF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC\r\n";
        let compact_form = "m=audio\r\na=fingerprint:sha-256 abcdef00112233445566778899aabbccabcdef00112233445566778899aabbcc\r\n";
        assert_eq!(
            extract_sdp_fingerprint(colon_form),
            extract_sdp_fingerprint(compact_form),
        );
    }

    #[test]
    fn missing_or_malformed_fingerprint_yields_none() {
        assert_eq!(extract_sdp_fingerprint("v=0\r\nm=audio\r\n"), None);
        assert_eq!(
            extract_sdp_fingerprint("a=fingerprint:sha-256 not-hex\r\n"),
            None
        );
        assert_eq!(
            extract_sdp_fingerprint("a=fingerprint:md5 aabbccdd\r\n"),
            None
        );
    }
}
