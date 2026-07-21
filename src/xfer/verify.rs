use crate::did::Resolver;
use crate::xfer::errors::XferError;
use crate::xfer::manifest::FileManifest;
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};

pub async fn verify_manifest(
    manifest: &FileManifest,
    resolver: &Resolver,
    expected_sender_did: &str,
    expected_circle_id: &str,
) -> Result<(), XferError> {
    manifest.validate_shape()?;
    if manifest.circle_id != expected_circle_id {
        return Err(XferError::CircleMismatch {
            expected: expected_circle_id.to_string(),
            got: manifest.circle_id.clone(),
        });
    }
    if manifest.sender_did != expected_sender_did {
        return Err(XferError::InvalidStructure(format!(
            "manifest sender mismatch: expected {}, got {}",
            expected_sender_did, manifest.sender_did
        )));
    }
    if !manifest
        .proof
        .verification_method
        .starts_with(&format!("{}#dkp-v", manifest.sender_did))
    {
        return Err(XferError::InvalidProof(manifest.transfer_id.clone()));
    }

    let resolved = resolver
        .resolve(&manifest.sender_did)
        .await
        .map_err(|error| {
            XferError::InvalidStructure(format!(
                "resolve sender {}: {}",
                manifest.sender_did, error
            ))
        })?;
    let public_key_der = general_purpose::STANDARD
        .decode(&resolved.public_key_der_b64)
        .map_err(|_| XferError::InvalidProof(manifest.transfer_id.clone()))?;
    let signature = general_purpose::STANDARD
        .decode(&manifest.proof.proof_value)
        .map_err(|_| XferError::InvalidProof(manifest.transfer_id.clone()))?;
    let canonical = manifest.canonical_bytes_for_sign()?;
    let digest = Sha256::digest(&canonical);
    crate::did::doc_sign::ecdsa_p256_verify_der_or_raw(&public_key_der, &digest, &signature)
        .map_err(|_| XferError::InvalidProof(manifest.transfer_id.clone()))?;
    Ok(())
}
