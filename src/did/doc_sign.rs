use crate::did::document::{DidDocument, Proof};
use crate::did::errors::DidError;
use crate::key_manager::KeyManager;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use ring::signature::{self, UnparsedPublicKey};
use sha2::{Digest, Sha256};

const DOMAIN_SEPARATOR: &[u8] = b"sgx-guardian:did:guardian:doc:v1:";

pub fn sign_in_place(doc: &mut DidDocument, km: &KeyManager, vm_ref: &str) -> Result<(), DidError> {
    let canonical = doc.canonical_bytes_for_sign()?;
    let mut to_sign = Vec::with_capacity(DOMAIN_SEPARATOR.len() + canonical.len());
    to_sign.extend_from_slice(DOMAIN_SEPARATOR);
    to_sign.extend_from_slice(&canonical);
    let digest = Sha256::digest(&to_sign);
    sign_proof_from_digest(
        doc.proof.get_or_insert_with(Proof::default),
        &digest,
        km,
        vm_ref,
    )
}

pub fn sign_in_place_generic(
    proof: &mut Proof,
    canonical_bytes: &[u8],
    km: &KeyManager,
    vm_ref: &str,
) -> Result<(), DidError> {
    let digest = Sha256::digest(canonical_bytes);
    sign_proof_from_digest(proof, &digest, km, vm_ref)
}

fn sign_proof_from_digest(
    proof: &mut Proof,
    digest: &[u8],
    km: &KeyManager,
    vm_ref: &str,
) -> Result<(), DidError> {
    let sig = km
        .sign(digest)
        .map_err(|e| DidError::Signing(format!("DKP sign: {}", e)))?;
    *proof = Proof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: "ecdsa-2019".into(),
        verification_method: vm_ref.to_string(),
        created: Utc::now().to_rfc3339(),
        proof_purpose: "assertionMethod".into(),
        proof_value: general_purpose::STANDARD.encode(sig),
    };
    Ok(())
}

pub fn verify(doc: &DidDocument) -> Result<(), DidError> {
    let proof = doc
        .proof
        .as_ref()
        .ok_or_else(|| DidError::InvalidFormat("Document has no proof".into()))?;

    let vm = doc
        .verification_method
        .iter()
        .find(|v| v.id == proof.verification_method)
        .ok_or_else(|| {
            DidError::InvalidFormat(format!(
                "proof.verificationMethod {} not found in verificationMethod[]",
                proof.verification_method
            ))
        })?;
    if vm.vm_type != "JsonWebKey2020" {
        return Err(DidError::InvalidFormat(format!(
            "Unsupported verificationMethod.type {}",
            vm.vm_type
        )));
    }
    if vm.public_key_jwk.kty != "EC" {
        return Err(DidError::InvalidFormat(format!(
            "Invalid JWK kty {}",
            vm.public_key_jwk.kty
        )));
    }
    if vm.public_key_jwk.crv != "P-256" {
        return Err(DidError::InvalidFormat(format!(
            "Invalid JWK crv {}",
            vm.public_key_jwk.crv
        )));
    }

    let x = general_purpose::URL_SAFE_NO_PAD
        .decode(&vm.public_key_jwk.x)
        .map_err(|e| DidError::InvalidFormat(format!("jwk.x decode: {}", e)))?;
    let y = general_purpose::URL_SAFE_NO_PAD
        .decode(&vm.public_key_jwk.y)
        .map_err(|e| DidError::InvalidFormat(format!("jwk.y decode: {}", e)))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(DidError::InvalidFormat(format!(
            "Invalid JWK coord length x={}, y={}",
            x.len(),
            y.len()
        )));
    }
    let mut raw = Vec::with_capacity(65);
    raw.push(0x04);
    raw.extend_from_slice(&x);
    raw.extend_from_slice(&y);

    let canonical = doc.canonical_bytes_for_sign()?;
    let mut to_verify = Vec::with_capacity(DOMAIN_SEPARATOR.len() + canonical.len());
    to_verify.extend_from_slice(DOMAIN_SEPARATOR);
    to_verify.extend_from_slice(&canonical);
    let digest = Sha256::digest(&to_verify);

    let sig = general_purpose::STANDARD
        .decode(&proof.proof_value)
        .map_err(|e| DidError::InvalidFormat(format!("proofValue decode: {}", e)))?;

    ecdsa_p256_verify_der_or_raw(&raw, &digest, &sig)
}

pub fn verify_with_replay_protection(
    doc: &DidDocument,
    floor_version: u32,
) -> Result<(), DidError> {
    verify(doc)?;
    if doc.sgx_version_id < floor_version {
        return Err(DidError::ReplayedOldVersion {
            incoming: doc.sgx_version_id,
            known: floor_version,
        });
    }
    Ok(())
}

pub fn ecdsa_p256_verify_der_or_raw(
    public_key_der: &[u8],
    digest: &[u8],
    sig: &[u8],
) -> Result<(), DidError> {
    let raw = normalize_p256_pubkey(public_key_der).ok_or_else(|| {
        DidError::InvalidFormat(format!(
            "Unsupported public key length {} for P-256 verification",
            public_key_der.len()
        ))
    })?;

    let algo: &dyn signature::VerificationAlgorithm = match sig.len() {
        64 => &signature::ECDSA_P256_SHA256_FIXED,
        _ if sig.first() == Some(&0x30) => &signature::ECDSA_P256_SHA256_ASN1,
        _ => {
            return Err(DidError::InvalidFormat(format!(
                "Unknown ECDSA signature format (len={})",
                sig.len()
            )))
        }
    };
    let key = UnparsedPublicKey::new(algo, raw);
    key.verify(digest, sig)
        .map_err(|_| DidError::DerivSignatureInvalid)
}

fn normalize_p256_pubkey(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() == 65 && bytes.first() == Some(&0x04) {
        return Some(bytes.to_vec());
    }
    if bytes.len() == 91 {
        return Some(bytes[26..].to_vec());
    }
    if bytes.len() > 65 && bytes[bytes.len() - 65] == 0x04 {
        return Some(bytes[bytes.len() - 65..].to_vec());
    }
    None
}
