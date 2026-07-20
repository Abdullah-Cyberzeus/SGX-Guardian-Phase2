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
