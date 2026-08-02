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
    async fn resolve(&self, device_id: &str) -> CallResult<TrustedPeerIdentity>;
}

pub struct RejectUnknownPeerResolver;

#[async_trait]
impl PeerIdentityResolver for RejectUnknownPeerResolver {
    async fn resolve(&self, device_id: &str) -> CallResult<TrustedPeerIdentity> {
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
    peer_id: String,
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

    async fn trusted_did(&self, device_id: &str) -> CallResult<String> {
        for path in &self.trusted_peer_files {
            let Ok(bytes) = tokio::fs::read(path).await else {
                continue;
            };
            let records: Vec<TrustedPeerRecord> =
                serde_json::from_slice(&bytes).map_err(|_| CallError::UnauthorizedDevice {
                    reason: "Trusted peer registry is malformed".into(),
                })?;
            if let Some(record) = records.into_iter().find(|peer| peer.peer_id == device_id) {
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
    async fn resolve(&self, device_id: &str) -> CallResult<TrustedPeerIdentity> {
        let did = self.trusted_did(device_id).await?;
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
    use super::{uncompressed_p256_point, P256_SPKI_DER_PREFIX};

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
}
