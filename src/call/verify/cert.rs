//! Stage 1: Certificate validity — checks expiry, issuer signature, encoding.
//!
//! Verifies the peer certificate bundled inside the call offer.
//! Fails immediately if: expired, not-yet-valid, bad issuer signature, or malformed.

use chrono::Utc;
use serde::{Deserialize, Serialize};

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
    /// 4. Issuer signature over certificate body (stubbed — replace with ring verify)
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

        // ── 4. Signature verification ────────────────────────────────────────
        // TODO: integrate ring::signature::UnparsedPublicKey to verify
        // issuer_signature bytes over the DER TBS certificate.
        // For now we check the signature field is non-empty (checked at presence).
        if cert.issuer_signature.is_empty() {
            return Err(VerifyError::CertBadSignature {
                device_id: cert.device_id.clone(),
            });
        }

        Ok(CertVerifyOk {
            device_id: cert.device_id.clone(),
            serial: cert.serial.clone(),
            fingerprint: cert.fingerprint.clone(),
            issuer: cert.issuer.clone(),
            not_after: cert.not_after.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_ca() -> TrustedCA {
        TrustedCA {
            issuer_dn: "CN=SGX-Guardian-CA".to_string(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nMIIB...".to_string(),
        }
    }

    fn valid_cert(device_id: &str) -> PeerCertificate {
        let now = Utc::now();
        PeerCertificate {
            pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".to_string(),
            device_id: device_id.to_string(),
            not_before: (now - Duration::hours(1)).to_rfc3339(),
            not_after: (now + Duration::hours(23)).to_rfc3339(),
            issuer: "CN=SGX-Guardian-CA".to_string(),
            serial: "0102030405".to_string(),
            issuer_signature: "deadbeef".to_string(),
            fingerprint: "aabbccdd".to_string(),
        }
    }

    #[test]
    fn test_valid_cert() {
        let verifier = CertVerifier::new(make_ca());
        let cert = valid_cert("device-1");
        assert!(verifier.verify(&cert).is_ok());
    }

    #[test]
    fn test_expired_cert() {
        let verifier = CertVerifier::new(make_ca());
        let now = Utc::now();
        let cert = PeerCertificate {
            not_after: (now - Duration::seconds(1)).to_rfc3339(),
            not_before: (now - Duration::hours(2)).to_rfc3339(),
            ..valid_cert("device-exp")
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertExpired { .. }));
    }

    #[test]
    fn test_not_yet_valid_cert() {
        let verifier = CertVerifier::new(make_ca());
        let now = Utc::now();
        let cert = PeerCertificate {
            not_before: (now + Duration::hours(1)).to_rfc3339(),
            not_after: (now + Duration::hours(25)).to_rfc3339(),
            ..valid_cert("device-future")
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertNotYetValid { .. }));
    }

    #[test]
    fn test_wrong_issuer() {
        let verifier = CertVerifier::new(make_ca());
        let cert = PeerCertificate {
            issuer: "CN=ROGUE-CA".to_string(),
            ..valid_cert("device-rogue")
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertBadSignature { .. }));
    }

    #[test]
    fn test_missing_cert() {
        let verifier = CertVerifier::new(make_ca());
        let cert = PeerCertificate {
            pem: String::new(),
            ..valid_cert("device-missing")
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertMissing { .. }));
    }

    #[test]
    fn test_no_signature() {
        let verifier = CertVerifier::new(make_ca());
        let cert = PeerCertificate {
            issuer_signature: String::new(),
            ..valid_cert("device-nosig")
        };
        let err = verifier.verify(&cert).unwrap_err();
        assert!(matches!(err, VerifyError::CertBadSignature { .. }));
    }
}
