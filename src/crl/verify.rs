use crate::crl::entry::{CrlEntry, RevokerRole, Severity};
use crate::crl::errors::CrlError;
use crate::crl::list::CertificateRevocationList;
use crate::did::Resolver;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

pub async fn verify_entry(
    entry: &CrlEntry,
    resolver: &Resolver,
    expected_circle_id: &str,
) -> Result<(), CrlError> {
    if entry.circle_id != expected_circle_id {
        return Err(CrlError::CircleMismatch {
            expected: expected_circle_id.to_string(),
            got: entry.circle_id.clone(),
        });
    }

    if matches!(entry.revoker_role, RevokerRole::Member) {
        if !entry.reason.is_security_critical() {
            return Err(CrlError::MemberReasonNotCritical(
                entry.reason.as_str().to_string(),
            ));
        }
        if !matches!(entry.severity, Severity::Critical | Severity::High) {
            return Err(CrlError::MemberSeverityTooLow(entry.severity));
        }
    }

    if entry.revoker_did == entry.revoked_did {
        return Err(CrlError::SelfRevocation);
    }

    let timestamp = DateTime::parse_from_rfc3339(&entry.timestamp)
        .map_err(|error| CrlError::InvalidStructure(format!("timestamp: {}", error)))?;
    let now = Utc::now();
    let skew_minutes = (now - timestamp.with_timezone(&Utc)).num_minutes().abs();
    if skew_minutes > 60 * 24 * 365 {
        return Err(CrlError::InvalidStructure(
            "timestamp too far from local clock".into(),
        ));
    }

    let resolved = resolver
        .resolve(&entry.revoker_did)
        .await
        .map_err(|error| {
            CrlError::IssuerNotResolvable(format!("{}: {}", entry.revoker_did, error))
        })?;

    let canonical = entry.canonical_bytes_for_sign()?;
    let public_key_der = general_purpose::STANDARD
        .decode(&resolved.public_key_der_b64)
        .map_err(|_| CrlError::InvalidProof(entry.id.clone()))?;
    let signature = general_purpose::STANDARD
        .decode(&entry.proof.proof_value)
        .map_err(|_| CrlError::InvalidProof(entry.id.clone()))?;
    let digest = Sha256::digest(&canonical);

    crate::did::doc_sign::ecdsa_p256_verify_der_or_raw(&public_key_der, &digest, &signature)
        .map_err(|_| CrlError::InvalidProof(entry.id.clone()))?;

    Ok(())
}

pub async fn verify_list(
    crl: &CertificateRevocationList,
    resolver: &Resolver,
    expected_circle_id: &str,
) -> Result<(), CrlError> {
    if crl.circle_id != expected_circle_id {
        return Err(CrlError::CircleMismatch {
            expected: expected_circle_id.to_string(),
            got: crl.circle_id.clone(),
        });
    }

    for entry in &crl.entries {
        verify_entry(entry, resolver, expected_circle_id).await?;
    }

    let mut clone = crl.clone();
    clone.recompute_root();
    if clone.merkle_root != crl.merkle_root {
        return Err(CrlError::MerkleRootMismatch);
    }

    Ok(())
}
