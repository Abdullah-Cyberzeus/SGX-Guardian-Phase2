//! Trusted call-peer identity and signing-key resolution.

use crate::call::error::{CallError, CallResult};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPeerIdentity {
    pub device_id: String,
    pub did: String,
    pub public_key_point: Vec<u8>,
}

#[async_trait]
pub trait PeerIdentityResolver: Send + Sync {
    /// `device_id` is the sender's self-declared identifier from the signaling
    /// envelope; `peer_ip` is the Nebula overlay IP the message actually
    /// arrived from. Implementations must anchor trust to `peer_ip`, since
    /// the trusted-peer registry is keyed by the observed attestation
    /// address, not by the peer's self-asserted device_id.
    async fn resolve(&self, device_id: &str, peer_ip: &str) -> CallResult<TrustedPeerIdentity>;
}

pub struct RejectUnknownPeerResolver;

#[async_trait]
impl PeerIdentityResolver for RejectUnknownPeerResolver {
    async fn resolve(&self, device_id: &str, _peer_ip: &str) -> CallResult<TrustedPeerIdentity> {
        Err(CallError::UnauthorizedDevice {
            reason: format!("No trusted identity resolver configured for {}", device_id),
        })
    }
}

#[derive(Clone)]
pub struct DidPeerIdentityResolver {
    did_resolver: crate::did::Resolver,
    trusted_peer_files: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct TrustedPeerRecord {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    did: Option<String>,
}

const P256_SPKI_DER_PREFIX: &[u8] =
    b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";

fn uncompressed_p256_point(encoded: &[u8]) -> Option<Vec<u8>> {
    if encoded.len() == 65 && encoded.first() == Some(&0x04) {
        return Some(encoded.to_vec());
    }
    encoded
        .strip_prefix(P256_SPKI_DER_PREFIX)
        .filter(|point| point.len() == 65 && point.first() == Some(&0x04))
        .map(|point| point.to_vec())
}

impl DidPeerIdentityResolver {
    pub fn new(
        did_resolver: crate::did::Resolver,
        primary_log_dir: impl AsRef<Path>,
        fallback_log_dir: impl AsRef<Path>,
    ) -> Self {
        Self {
            did_resolver: did_resolver.with_reject_deactivated(true),
            trusted_peer_files: vec![
                primary_log_dir.as_ref().join("trusted_peers.json"),
                fallback_log_dir.as_ref().join("trusted_peers.json"),
            ],
        }
    }

    async fn trusted_did(&self, peer_ip: &str) -> CallResult<String> {
        for path in &self.trusted_peer_files {
            let Ok(bytes) = tokio::fs::read(path).await else {
                continue;
            };
            let records: Vec<TrustedPeerRecord> =
                serde_json::from_slice(&bytes).map_err(|_| CallError::UnauthorizedDevice {
                    reason: "Trusted peer registry is malformed".into(),
                })?;
            if let Some(record) = records.into_iter().find(|peer| peer.ip == peer_ip) {
                if !matches!(record.status.as_str(), "verified" | "trusted" | "success") {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Peer is not currently trusted".into(),
                    });
                }
                return record
                    .did
                    .filter(|did| !did.trim().is_empty())
                    .ok_or_else(|| CallError::UnauthorizedDevice {
                        reason: "Trusted peer has no bound DID".into(),
                    });
            }
        }
        Err(CallError::UnauthorizedDevice {
            reason: "Peer is absent from the trusted attestation registry".into(),
        })
    }
}

#[async_trait]
impl PeerIdentityResolver for DidPeerIdentityResolver {
    async fn resolve(&self, device_id: &str, peer_ip: &str) -> CallResult<TrustedPeerIdentity> {
        let did = self.trusted_did(peer_ip).await?;
        let resolved =
            self.did_resolver
                .resolve(&did)
                .await
                .map_err(|_| CallError::UnauthorizedDevice {
                    reason: "Peer DID could not be resolved and verified".into(),
                })?;
        if resolved.status != "active" {
            return Err(CallError::UnauthorizedDevice {
                reason: "Peer DID is not active".into(),
            });
        }
        let encoded_key = general_purpose::STANDARD
            .decode(resolved.public_key_der_b64)
            .map_err(|_| CallError::UnauthorizedDevice {
                reason: "Peer DID contains an invalid public key".into(),
            })?;
        let point =
            uncompressed_p256_point(&encoded_key).ok_or_else(|| CallError::UnauthorizedDevice {
                reason: "Peer DID key is not an uncompressed P-256 point".into(),
            })?;
        Ok(TrustedPeerIdentity {
            device_id: device_id.to_string(),
            did,
            public_key_point: point,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{uncompressed_p256_point, DidPeerIdentityResolver, P256_SPKI_DER_PREFIX};
    use crate::did::{Resolver, ResolverConfig};
    use tempfile::tempdir;

    fn resolver(
        primary: impl AsRef<std::path::Path>,
        fallback: impl AsRef<std::path::Path>,
    ) -> DidPeerIdentityResolver {
        DidPeerIdentityResolver::new(Resolver::new(ResolverConfig::default()), primary, fallback)
    }

    #[test]
    fn accepts_raw_and_spki_wrapped_p256_points() {
        let mut point = vec![0x04];
        point.extend([0x5a; 64]);

        assert_eq!(uncompressed_p256_point(&point), Some(point.clone()));

        let mut spki = P256_SPKI_DER_PREFIX.to_vec();
        spki.extend_from_slice(&point);
        assert_eq!(uncompressed_p256_point(&spki), Some(point));
    }

    #[test]
    fn rejects_invalid_p256_key_encodings() {
        assert_eq!(uncompressed_p256_point(&[0x04; 64]), None);
        assert_eq!(uncompressed_p256_point(&[0x02; 65]), None);
    }

    #[tokio::test]
    async fn trusted_registry_uses_fallback_and_requires_verified_did_binding() {
        let dir = tempdir().unwrap();
        let primary = dir.path().join("primary");
        let fallback = dir.path().join("fallback");
        std::fs::create_dir_all(&fallback).unwrap();
        std::fs::write(
            fallback.join("trusted_peers.json"),
            serde_json::to_vec(&serde_json::json!([
                {
                    "ip": "192.168.100.9",
                    "status": "verified",
                    "did": "did:guardian:trusted-peer"
                }
            ]))
            .unwrap(),
        )
        .unwrap();

        let resolver = resolver(&primary, &fallback);
        assert_eq!(
            resolver.trusted_did("192.168.100.9").await.unwrap(),
            "did:guardian:trusted-peer"
        );
        assert!(resolver.trusted_did("192.168.100.99").await.is_err());

        std::fs::create_dir_all(&primary).unwrap();
        std::fs::write(
            primary.join("trusted_peers.json"),
            br#"[{"ip":"192.168.100.10","status":"pending","did":"did:guardian:pending"}]"#,
        )
        .unwrap();
        assert!(resolver.trusted_did("192.168.100.10").await.is_err());

        std::fs::write(
            primary.join("trusted_peers.json"),
            br#"[{"ip":"192.168.100.10","status":"trusted","did":""}]"#,
        )
        .unwrap();
        assert!(resolver.trusted_did("192.168.100.10").await.is_err());
    }

    #[tokio::test]
    async fn malformed_trusted_registry_fails_closed() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("trusted_peers.json"), b"not-json").unwrap();
        let resolver = resolver(dir.path(), dir.path().join("missing"));
        assert!(resolver.trusted_did("192.168.100.8").await.is_err());
    }
}
