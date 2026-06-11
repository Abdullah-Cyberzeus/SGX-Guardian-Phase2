use crate::did::Resolver;
use crate::vc::credential::{
    VerifiableCredential, TYPE_CIRCLE_MEMBERSHIP, TYPE_VC, VC_CONTEXT_CORE,
};
use crate::vc::errors::VcError;
use crate::vc::status_list::StatusListView;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use ring::signature;
use sha2::{Digest, Sha256};

pub struct VerifyOptions<'a> {
    pub expected_subject_did: Option<&'a str>,
    pub expected_circle_id: Option<&'a str>,
    pub expected_issuer_did: Option<&'a str>,
    pub check_status_list: bool,
    pub status_list: Option<&'a StatusListView>,
}

pub async fn verify_vc(
    vc: &VerifiableCredential,
    resolver: &Resolver,
    opts: VerifyOptions<'_>,
) -> Result<(), VcError> {
    if !vc.vc_type.iter().any(|ty| ty == TYPE_VC)
        || !vc.vc_type.iter().any(|ty| ty == TYPE_CIRCLE_MEMBERSHIP)
    {
        return Err(VcError::InvalidStructure(
            "missing required VC type".to_string(),
        ));
    }
    if !vc.context.iter().any(|ctx| ctx == VC_CONTEXT_CORE) {
        return Err(VcError::InvalidStructure(
            "missing VC core context".to_string(),
        ));
    }
    if vc.credential_status.status_type != "StatusList2021Entry" {
        return Err(VcError::InvalidStructure(
            "credentialStatus.type must be StatusList2021Entry".to_string(),
        ));
    }
    if vc.credential_status.status_purpose != "revocation" {
        return Err(VcError::InvalidStructure(
            "credentialStatus.statusPurpose must be revocation".to_string(),
        ));
    }

    if let Some(expected) = opts.expected_subject_did {
        if vc.subject_did() != expected {
            return Err(VcError::SubjectMismatch {
                expected: expected.to_string(),
                got: vc.subject_did().to_string(),
            });
        }
    }
    if let Some(expected) = opts.expected_circle_id {
        if vc.credential_subject.circle_id != expected {
            return Err(VcError::CircleMismatch {
                expected: expected.to_string(),
                got: vc.credential_subject.circle_id.clone(),
            });
        }
    }
    if let Some(expected) = opts.expected_issuer_did {
        if vc.issuer != expected {
            return Err(VcError::IssuerMismatch {
                expected: expected.to_string(),
                got: vc.issuer.clone(),
            });
        }
    }
    if !vc.has_active_membership_status() {
        return Err(VcError::InvalidMembershipStatus(
            vc.credential_subject.membership_status.to_string(),
        ));
    }
    if vc.is_expired(Utc::now()) {
        return Err(VcError::Expired(vc.expiration_date.clone()));
    }

    let issuer = resolver
        .resolve(vc.issuer_did())
        .await
        .map_err(|e| VcError::IssuerNotResolvable(format!("{}: {}", vc.issuer_did(), e)))?;
    let canonical = vc.canonical_bytes_for_sign()?;
    verify_proof_material(
        &issuer.public_key_der_b64,
        &vc.proof.proof_value,
        &canonical,
    )?;

    if opts.check_status_list {
        let status_list = opts.status_list.ok_or_else(|| {
            VcError::StatusListUnavailable("verify caller did not supply a status list".to_string())
        })?;
        if status_list.id() != vc.credential_status.status_list_credential {
            return Err(VcError::InvalidStructure(format!(
                "status list mismatch: expected {}, got {}",
                vc.credential_status.status_list_credential,
                status_list.id()
            )));
        }
        if status_list.issuer_did() != vc.issuer {
            return Err(VcError::IssuerMismatch {
                expected: vc.issuer.clone(),
                got: status_list.issuer_did().to_string(),
            });
        }
        let index = vc
            .credential_status
            .status_list_index
            .parse::<u64>()
            .map_err(|e| VcError::InvalidStructure(format!("idx: {}", e)))?;
        if status_list.is_revoked(index)? {
            return Err(VcError::Revoked(index));
        }
    }

    Ok(())
}

fn verify_proof_material(
    issuer_public_key_der_b64: &str,
    proof_value_b64: &str,
    canonical_bytes: &[u8],
) -> Result<(), VcError> {
    let public_key = general_purpose::STANDARD
        .decode(issuer_public_key_der_b64)
        .map_err(|_| VcError::InvalidProof)?;
    let public_key = normalize_p256_pubkey(&public_key).ok_or(VcError::InvalidProof)?;
    let signature = general_purpose::STANDARD
        .decode(proof_value_b64)
        .map_err(|_| VcError::InvalidProof)?;
    let digest = Sha256::digest(canonical_bytes);
    let algorithm: &dyn signature::VerificationAlgorithm = match signature.len() {
        64 => &signature::ECDSA_P256_SHA256_FIXED,
        _ if signature.first() == Some(&0x30) => &signature::ECDSA_P256_SHA256_ASN1,
        _ => return Err(VcError::InvalidProof),
    };
    let key = signature::UnparsedPublicKey::new(algorithm, public_key);
    key.verify(&digest, &signature)
        .map_err(|_| VcError::InvalidProof)
}

fn normalize_p256_pubkey(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() == 65 {
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
