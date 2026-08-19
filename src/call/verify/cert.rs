//! Stage 1: Certificate validity — checks expiry, issuer signature, encoding.
//!
//! Verifies the peer certificate bundled inside the call offer.
//! Fails immediately if: expired, not-yet-valid, bad issuer signature, or malformed.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::errors::{VerifyError, VerifyResult};

/// Minimal certificate fields extracted from a DER/PEM blob for verification.
/// In production, replace this with a proper x509 parser (e.g., `x509-parser` crate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCertificate {
    /// PEM-encoded certificate data
    pub pem: String,
    /// Device identifier (CN or Subject Alt Name)
    pub device_id: String,
    /// Validity window start (RFC 3339)
    pub not_before: String,
    /// Validity window end (RFC 3339)
    pub not_after: String,
    /// Issuer distinguished name
    pub issuer: String,
    /// Hex-encoded serial number
    pub serial: String,
    /// Base64-encoded issuer signature over the TBS certificate
    pub issuer_signature: String,
    /// Hex-encoded SHA-256 fingerprint of the cert DER
    pub fingerprint: String,
}

impl PeerCertificate {
    /// Return the parsed not-before timestamp, or error if malformed.
    fn parsed_not_before(&self) -> VerifyResult<chrono::DateTime<Utc>> {
        chrono::DateTime::parse_from_rfc3339(&self.not_before)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| VerifyError::CertMalformed {
                device_id: self.device_id.clone(),
                reason: format!("invalid not_before: {}", self.not_before),
            })
    }

    /// Return the parsed not-after timestamp, or error if malformed.
    fn parsed_not_after(&self) -> VerifyResult<chrono::DateTime<Utc>> {
        chrono::DateTime::parse_from_rfc3339(&self.not_after)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| VerifyError::CertMalformed {
                device_id: self.device_id.clone(),
                reason: format!("invalid not_after: {}", self.not_after),
            })
    }
}

/// Trusted Certificate Authority configuration used to validate peer certs.
#[derive(Debug, Clone)]
pub struct TrustedCA {
    /// Canonical issuer distinguished name this CA presents
    pub issuer_dn: String,
    /// PEM-encoded CA public key (ECDSA P-256)
    pub public_key_pem: String,
}

/// Result of a successful certificate verification.
#[derive(Debug, Clone)]
pub struct CertVerifyOk {
    pub device_id: String,
    pub serial: String,
    pub fingerprint: String,
    pub issuer: String,
    pub not_after: String,
}

/// Stage 1 verifier: certificate validity.
pub struct CertVerifier {
    trusted_ca: TrustedCA,
}

impl CertVerifier {
    pub fn new(trusted_ca: TrustedCA) -> Self {
        CertVerifier { trusted_ca }
    }

    /// Verify the peer certificate.
    ///
    /// Checks (in order):
    /// 1. PEM is non-empty / fields are present
    /// 2. Validity window — not_before ≤ now ≤ not_after
    /// 3. Issuer matches the trusted CA
    /// 4. Issuer signature over the canonical certificate record
    pub fn verify(&self, cert: &PeerCertificate) -> VerifyResult<CertVerifyOk> {
        // ── 1. Presence check ────────────────────────────────────────────────
        if cert.pem.is_empty() || cert.device_id.is_empty() || cert.fingerprint.is_empty() {
            return Err(VerifyError::CertMissing {
                device_id: cert.device_id.clone(),
            });
        }

        let now = Utc::now();

        // ── 2. Validity window ───────────────────────────────────────────────
        let not_before = cert.parsed_not_before()?;
        let not_after = cert.parsed_not_after()?;

        if now < not_before {
            return Err(VerifyError::CertNotYetValid {
                device_id: cert.device_id.clone(),
            });
        }
        if now > not_after {
            return Err(VerifyError::CertExpired {
                device_id: cert.device_id.clone(),
            });
        }

        // ── 3. Issuer check ──────────────────────────────────────────────────
        if cert.issuer != self.trusted_ca.issuer_dn {
            return Err(VerifyError::CertBadSignature {
                device_id: cert.device_id.clone(),
            });
        }

        // ── 4. Fingerprint + signature verification ──────────────────────────
        let cert_bytes = certificate_bytes(cert)?;
        let actual_fingerprint = format!("sha-256 {}", hex::encode(Sha256::digest(&cert_bytes)));
        if !fingerprints_equal(&cert.fingerprint, &actual_fingerprint) {
            return Err(VerifyError::CertBadSignature {
                device_id: cert.device_id.clone(),
            });
        }
        let signature =
            decode_signature(&cert.issuer_signature).map_err(|_| VerifyError::CertBadSignature {
                device_id: cert.device_id.clone(),
            })?;
        let public_key =
            decode_public_key(&self.trusted_ca.public_key_pem).map_err(|_| VerifyError::CertBadSignature {
                device_id: cert.device_id.clone(),
            })?;
        crate::key_manager::KeyManager::verify_signature(
            &canonical_certificate_bytes(cert),
            &signature,
            &public_key,
        )
        .map_err(|_| VerifyError::CertBadSignature {
            device_id: cert.device_id.clone(),
        })?;

        Ok(CertVerifyOk {
            device_id: cert.device_id.clone(),
            serial: cert.serial.clone(),
            fingerprint: cert.fingerprint.clone(),
            issuer: cert.issuer.clone(),
            not_after: cert.not_after.clone(),
        })
    }
}

fn certificate_bytes(cert: &PeerCertificate) -> VerifyResult<Vec<u8>> {
    if cert.pem.contains("-----BEGIN") {
        pem::parse(&cert.pem)
            .map(|block| block.contents().to_vec())
            .map_err(|_| VerifyError::CertMalformed {
                device_id: cert.device_id.clone(),
                reason: "invalid PEM certificate".into(),
            })
    } else {
        Ok(cert.pem.as_bytes().to_vec())
    }
}

fn canonical_certificate_bytes(cert: &PeerCertificate) -> Vec<u8> {
    let fields = [
        cert.pem.as_str(),
        cert.device_id.as_str(),
        cert.not_before.as_str(),
        cert.not_after.as_str(),
        cert.issuer.as_str(),
        cert.serial.as_str(),
        cert.fingerprint.as_str(),
    ];
    let mut output = Vec::new();
    for field in fields {
        output.extend_from_slice(&(field.len() as u64).to_be_bytes());
        output.extend_from_slice(field.as_bytes());
    }
    output
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha-256")
        .unwrap_or(value.trim())
        .replace([':', ' '], "")
        .to_ascii_lowercase()
}

fn fingerprints_equal(left: &str, right: &str) -> bool {
    normalize_fingerprint(left) == normalize_fingerprint(right)
}

fn decode_signature(value: &str) -> Result<Vec<u8>, ()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(());
    }
    if let Ok(bytes) = hex::decode(trimmed) {
        return Ok(bytes);
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|_| ())
}

fn decode_public_key(value: &str) -> Result<Vec<u8>, ()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(());
    }
    if trimmed.contains("-----BEGIN") {
        return pem::parse(trimmed)
            .map(|block| block.contents().to_vec())
            .map_err(|_| ());
    }
    if let Ok(bytes) = hex::decode(trimmed) {
        return Ok(bytes);
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_key_manager(device_id: &str) -> crate::key_manager::KeyManager {
        let temp = tempfile::tempdir().expect("temp key dir");
        let key_path = temp.path().join(format!("{device_id}.pk8"));
        crate::key_manager::KeyManager::load_or_generate(key_path.to_str().unwrap())
            .expect("key manager")
    }

    fn make_ca(key_manager: &crate::key_manager::KeyManager) -> TrustedCA {
        TrustedCA {
            issuer_dn: "CN=SGX-Guardian-CA".to_string(),
            public_key_pem: hex::encode(key_manager.pubkey_der().expect("public key")),
        }
    }

    fn valid_cert(device_id: &str, key_manager: &crate::key_manager::KeyManager) -> PeerCertificate {
        let now = Utc::now();
        let mut cert = PeerCertificate {
            pem: "fake-cert-der".to_string(),
            device_id: device_id.to_string(),
            not_before: (now - Duration::hours(1)).to_rfc3339(),
            not_after: (now + Duration::hours(23)).to_rfc3339(),
            issuer: "CN=SGX-Guardian-CA".to_string(),
            serial: "0102030405".to_string(),
            issuer_signature: String::new(),
            fingerprint: "sha-256 c861ba8441753651c1d9c05cd27f0e94919bcd0a63abf60471c36fe14da05f76".to_string(),
        };
        cert.issuer_signature = hex::encode(
            key_manager
                .sign(&canonical_certificate_bytes(&cert))
                .expect("sign certificate"),
        );
        cert
    }

    #[test]
    fn test_valid_cert() {
        let key_manager = make_key_manager("device-1");
        let verifier = CertVerifier::new(make_ca(&key_manager));
        let cert = valid_cert("device-1", &key_manager);
        assert!(verifier.verify(&cert).is_ok());
    }

    #[test]
    fn test_expired_cert() {
        let key_manager = make_key_manager("device-exp");
        let verifier = CertVerifier::new(make_ca(&key_manager));
        let now = Utc::now();
        let cert = PeerCertificate {
            not_after: (now - Duration::seconds(1)).to_rfc3339(),
            not_before: (now - Duration::hours(2)).to_rfc3339(),
            ..valid_cert("device-exp", &key_manager)
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertExpired { .. }));
    }

    #[test]
    fn test_not_yet_valid_cert() {
        let key_manager = make_key_manager("device-future");
        let verifier = CertVerifier::new(make_ca(&key_manager));
        let now = Utc::now();
        let cert = PeerCertificate {
            not_before: (now + Duration::hours(1)).to_rfc3339(),
            not_after: (now + Duration::hours(25)).to_rfc3339(),
            ..valid_cert("device-future", &key_manager)
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertNotYetValid { .. }));
    }

    #[test]
    fn test_wrong_issuer() {
        let key_manager = make_key_manager("device-rogue");
        let verifier = CertVerifier::new(make_ca(&key_manager));
        let cert = PeerCertificate {
            issuer: "CN=ROGUE-CA".to_string(),
            ..valid_cert("device-rogue", &key_manager)
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertBadSignature { .. }));
    }

    #[test]
    fn test_missing_cert() {
        let key_manager = make_key_manager("device-missing");
        let verifier = CertVerifier::new(make_ca(&key_manager));
        let cert = PeerCertificate {
            pem: String::new(),
            ..valid_cert("device-missing", &key_manager)
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertMissing { .. }));
    }

    #[test]
    fn test_no_signature() {
        let key_manager = make_key_manager("device-nosig");
        let verifier = CertVerifier::new(make_ca(&key_manager));
        let cert = PeerCertificate {
            issuer_signature: String::new(),
            ..valid_cert("device-nosig", &key_manager)
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertBadSignature { .. }));
    }
}
