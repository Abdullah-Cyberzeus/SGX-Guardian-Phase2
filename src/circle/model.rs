use crate::circle::errors::CircleError;
use crate::did::doc_sign;
use crate::did::document::{Jwk, Proof, VerificationMethod};
use crate::did::Resolver;
use crate::key_manager::KeyManager;
use crate::vc::credential::sort_json_keys;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CircleKind {
    Mesh,
    Comms,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CircleStatus {
    Active,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Circle {
    pub circle_id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub owner_did: String,
    pub kind: CircleKind,
    pub status: CircleStatus,
    pub created_at: String,
    pub updated_at: String,
}

impl Circle {
    pub fn is_mesh(&self) -> bool {
        matches!(self.kind, CircleKind::Mesh)
    }

    pub fn is_archived(&self) -> bool {
        matches!(self.status, CircleStatus::Archived)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CircleRegistry {
    pub circles: Vec<Circle>,
    pub sequence: u64,
    #[serde(default)]
    pub proof: Proof,
}

impl CircleRegistry {
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let value = serde_json::to_value(&copy)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }

    pub fn sign(&mut self, km: &KeyManager, vm_ref: &str) -> Result<(), CircleError> {
        let canonical = self.canonical_bytes_for_sign()?;
        crate::did::doc_sign::sign_in_place_generic(&mut self.proof, &canonical, km, vm_ref)?;
        Ok(())
    }

    pub async fn verify_with_resolver(
        &self,
        resolver: &Resolver,
        signer_did: &str,
    ) -> Result<(), CircleError> {
        let resolved = resolver.resolve(signer_did).await?;
        let public_key = general_purpose::STANDARD.decode(resolved.public_key_der_b64)?;
        self.verify_with_public_key(&public_key)
    }

    pub fn verify_with_public_key(&self, public_key: &[u8]) -> Result<(), CircleError> {
        let canonical = self.canonical_bytes_for_sign()?;
        verify_signed_proof(&self.proof, &canonical, public_key)
    }
}

pub(crate) fn verify_signed_proof(
    proof: &Proof,
    canonical: &[u8],
    public_key_der_or_raw: &[u8],
) -> Result<(), CircleError> {
    if proof.verification_method.trim().is_empty() || proof.proof_value.trim().is_empty() {
        return Err(CircleError::InvalidProof("missing proof fields".into()));
    }
    let signature = general_purpose::STANDARD.decode(&proof.proof_value)?;
    let digest = Sha256::digest(canonical);
    doc_sign::ecdsa_p256_verify_der_or_raw(public_key_der_or_raw, &digest, &signature)?;
    Ok(())
}

pub(crate) fn public_key_from_vm(vm: &VerificationMethod) -> Result<Vec<u8>, CircleError> {
    jwk_to_raw_point(&vm.public_key_jwk)
}

fn jwk_to_raw_point(jwk: &Jwk) -> Result<Vec<u8>, CircleError> {
    let x = general_purpose::URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|err| CircleError::InvalidProof(format!("jwk.x decode: {}", err)))?;
    let y = general_purpose::URL_SAFE_NO_PAD
        .decode(&jwk.y)
        .map_err(|err| CircleError::InvalidProof(format!("jwk.y decode: {}", err)))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(CircleError::InvalidProof(format!(
            "unexpected coordinate lengths x={} y={}",
            x.len(),
            y.len()
        )));
    }
    let mut raw = Vec::with_capacity(65);
    raw.push(0x04);
    raw.extend_from_slice(&x);
    raw.extend_from_slice(&y);
    Ok(raw)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::did::document::VerificationMethod;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use sha2::{Digest, Sha256};

    fn sample_circle(status: CircleStatus, kind: CircleKind) -> Circle {
        Circle {
            circle_id: "circle-1".to_string(),
            name: "Test Circle".to_string(),
            description: "desc".to_string(),
            owner_did: "did:guardian:owner".to_string(),
            kind,
            status,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn circle_is_mesh_reflects_kind() {
        let mesh = sample_circle(CircleStatus::Active, CircleKind::Mesh);
        let comms = sample_circle(CircleStatus::Active, CircleKind::Comms);
        assert!(mesh.is_mesh());
        assert!(!comms.is_mesh());
    }

    #[test]
    fn circle_is_archived_reflects_status() {
        let active = sample_circle(CircleStatus::Active, CircleKind::Comms);
        let archived = sample_circle(CircleStatus::Archived, CircleKind::Comms);
        assert!(!active.is_archived());
        assert!(archived.is_archived());
    }

    #[test]
    fn registry_canonical_bytes_ignore_proof_but_detect_field_changes() {
        let mut registry = CircleRegistry {
            circles: vec![sample_circle(CircleStatus::Active, CircleKind::Mesh)],
            sequence: 1,
            proof: Proof::default(),
        };
        let baseline = registry.canonical_bytes_for_sign().expect("canonical");

        // Mutating only the proof must not change the canonical bytes.
        registry.proof = Proof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "ecdsa-2019".to_string(),
            verification_method: "did:guardian:owner#dkp-v1".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "deadbeef".to_string(),
        };
        let same = registry.canonical_bytes_for_sign().expect("canonical");
        assert_eq!(baseline, same);

        // Mutating a real field must change the canonical bytes.
        registry.sequence = 2;
        let changed = registry.canonical_bytes_for_sign().expect("canonical");
        assert_ne!(baseline, changed);
    }

    #[test]
    fn verify_signed_proof_rejects_missing_fields() {
        let proof = Proof::default();
        let err = verify_signed_proof(&proof, b"payload", &[0u8; 65]).unwrap_err();
        assert!(matches!(err, CircleError::InvalidProof(_)));
    }

    #[test]
    fn verify_signed_proof_rejects_invalid_base64() {
        let proof = Proof {
            verification_method: "did:guardian:owner#dkp-v1".to_string(),
            proof_value: "not-valid-base64!!!".to_string(),
            ..Proof::default()
        };
        assert!(verify_signed_proof(&proof, b"payload", &[0u8; 65]).is_err());
    }

    /// Full sign/verify round trip using an in-memory ECDSA keypair (no
    /// KeyManager, no disk I/O) to exercise the real crypto path.
    #[test]
    fn verify_signed_proof_accepts_genuine_signature_and_rejects_tampered_payload() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate keypair");
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("load keypair");
        let public_key = keypair.public_key().as_ref().to_vec();

        let canonical = b"canonical-bytes-for-signing";
        let digest = Sha256::digest(canonical);
        let signature = keypair.sign(&rng, &digest).expect("sign");

        let proof = Proof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "ecdsa-2019".to_string(),
            verification_method: "did:guardian:owner#dkp-v1".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: general_purpose::STANDARD.encode(signature.as_ref()),
        };

        verify_signed_proof(&proof, canonical, &public_key).expect("valid signature verifies");
        assert!(verify_signed_proof(&proof, b"tampered-bytes", &public_key).is_err());
    }

    #[test]
    fn jwk_to_raw_point_rejects_wrong_coordinate_lengths() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: general_purpose::URL_SAFE_NO_PAD.encode([1u8; 16]),
            y: general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]),
            kid: "dkp-v1".to_string(),
        };
        let err = jwk_to_raw_point(&jwk).unwrap_err();
        assert!(matches!(err, CircleError::InvalidProof(_)));
    }

    #[test]
    fn jwk_to_raw_point_accepts_valid_32_byte_coordinates() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
            y: general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]),
            kid: "dkp-v1".to_string(),
        };
        let raw = jwk_to_raw_point(&jwk).expect("valid point");
        assert_eq!(raw.len(), 65);
        assert_eq!(raw[0], 0x04);
    }

    #[test]
    fn public_key_from_vm_delegates_to_jwk_conversion() {
        let vm = VerificationMethod {
            id: "did:guardian:owner#dkp-v1".to_string(),
            vm_type: "JsonWebKey2020".to_string(),
            controller: "did:guardian:owner".to_string(),
            public_key_jwk: Jwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]),
                y: general_purpose::URL_SAFE_NO_PAD.encode([4u8; 32]),
                kid: "dkp-v1".to_string(),
            },
        };
        let raw = public_key_from_vm(&vm).expect("valid vm");
        assert_eq!(raw.len(), 65);
    }
}
