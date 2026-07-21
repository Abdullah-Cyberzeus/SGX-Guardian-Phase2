use crate::crl::entry::{CrlEntry, RevokerRole, Severity, UnrevokeTombstone};
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

    // Re-derive the revoker's actual role from their verified membership VC —
    // NEVER trust the wire-supplied entry.revoker_role. A Member could set
    // revoker_role: Owner on a self-signed entry to bypass the Member-only
    // reason/severity guards below and revoke anyone, including the Owner.
    if crate::crl::is_revoked(&entry.revoker_did) {
        return Err(CrlError::InvalidStructure(format!(
            "revoker {} is themselves revoked",
            entry.revoker_did
        )));
    }

    let actual_role = match crate::vc::issue::known_ca_did() {
        Ok(ca_did) if ca_did == entry.revoker_did => RevokerRole::Owner,
        _ => {
            let revoker_vc =
                crate::vc::persistence::load_peer(&entry.revoker_did).map_err(|e| {
                    CrlError::IssuerNotResolvable(format!(
                        "no valid membership VC for revoker {}: {}",
                        entry.revoker_did, e
                    ))
                })?;
            let is_active_member = revoker_vc.credential_subject.circle_id == expected_circle_id
                && revoker_vc.credential_subject.role
                    == crate::vc::credential::CredentialRole::Member
                && revoker_vc.has_active_membership_status();
            if !is_active_member {
                return Err(CrlError::IssuerNotResolvable(format!(
                    "no valid active Member VC for revoker {} in circle {}",
                    entry.revoker_did, expected_circle_id
                )));
            }
            RevokerRole::Member
        }
    };

    // Reject wire role mismatch (e.g. Member claiming Owner)
    if entry.revoker_role != actual_role {
        return Err(CrlError::InvalidStructure(format!(
            "wire revoker_role {:?} != verified role {:?} for {}",
            entry.revoker_role, actual_role, entry.revoker_did
        )));
    }

    // SECURITY: Members can NEVER revoke the Circle Owner. The Owner is the
    // CA/issuer, so an Owner revocation collapses the entire trust chain
    // circle-wide and is unrecoverable — a Member with a valid VC and a
    // Compromised/Critical-severity entry would otherwise pass every other
    // check here. Only another Owner (future multi-owner) may revoke an
    // Owner.
    if matches!(actual_role, RevokerRole::Member) {
        let target_is_owner = crate::vc::issue::known_ca_did()
            .map(|ca_did| ca_did == entry.revoked_did)
            .unwrap_or(false);
        if target_is_owner {
            return Err(CrlError::InvalidStructure(format!(
                "Member {} cannot revoke Owner {} — Owner revocation requires Owner authority",
                entry.revoker_did, entry.revoked_did
            )));
        }
    }

    if matches!(actual_role, RevokerRole::Member) {
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

    verify_timestamp("CRL entry", &entry.timestamp)?;

    let resolved = resolver
        .resolve(&entry.revoker_did)
        .await
        .map_err(|error| {
            CrlError::IssuerNotResolvable(format!("{}: {}", entry.revoker_did, error))
        })?;

    let canonical = entry.canonical_bytes_for_sign()?;
    verify_canonical_signature(
        &entry.id,
        &entry.proof.proof_value,
        &canonical,
        &resolved.public_key_der_b64,
    )?;

    Ok(())
}

pub async fn verify_tombstone(
    tombstone: &UnrevokeTombstone,
    resolver: &Resolver,
) -> Result<(), CrlError> {
    if tombstone.revoked_did.trim().is_empty() {
        return Err(CrlError::InvalidStructure(
            "tombstone revoked_did must not be empty".into(),
        ));
    }
    if tombstone.original_entry_id.trim().is_empty() {
        return Err(CrlError::InvalidStructure(
            "tombstone original_entry_id must not be empty".into(),
        ));
    }
    if tombstone.owner_did.trim().is_empty() {
        return Err(CrlError::InvalidStructure(
            "tombstone owner_did must not be empty".into(),
        ));
    }
    if tombstone.sequence == 0 {
        return Err(CrlError::InvalidStructure(
            "tombstone sequence must be greater than zero".into(),
        ));
    }

    let expected_owner = crate::vc::issue::known_ca_did().map_err(|error| {
        CrlError::IssuerNotResolvable(format!("circle owner DID not known: {}", error))
    })?;
    if tombstone.owner_did != expected_owner {
        return Err(CrlError::InvalidStructure(format!(
            "tombstone owner_did {} != circle owner {}",
            tombstone.owner_did, expected_owner
        )));
    }

    verify_timestamp("CRL tombstone", &tombstone.timestamp)?;

    let resolved = resolver
        .resolve(&tombstone.owner_did)
        .await
        .map_err(|error| {
            CrlError::IssuerNotResolvable(format!("{}: {}", tombstone.owner_did, error))
        })?;
    let canonical = tombstone.canonical_bytes_for_sign()?;
    verify_canonical_signature(
        &tombstone.id,
        &tombstone.proof.proof_value,
        &canonical,
        &resolved.public_key_der_b64,
    )?;

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
    for tombstone in &crl.tombstones {
        verify_tombstone(tombstone, resolver).await?;
    }
    for tombstone in &crl.tombstones {
        if crl
            .entries
            .iter()
            .any(|entry| entry.revoked_did == tombstone.revoked_did)
        {
            return Err(CrlError::InvalidStructure(format!(
                "CRL contains both active revoke and tombstone for {}",
                tombstone.revoked_did
            )));
        }
    }

    let mut clone = crl.clone();
    clone.recompute_root();
    if clone.merkle_root != crl.merkle_root {
        return Err(CrlError::MerkleRootMismatch);
    }

    Ok(())
}

fn verify_timestamp(label: &str, timestamp: &str) -> Result<(), CrlError> {
    let timestamp = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|error| CrlError::InvalidStructure(format!("timestamp: {}", error)))?;
    let now = Utc::now();
    let skew = now.signed_duration_since(timestamp.with_timezone(&Utc));

    const MAX_FUTURE_SKEW_MINUTES: i64 = 15;
    if skew < chrono::Duration::minutes(-MAX_FUTURE_SKEW_MINUTES) {
        return Err(CrlError::InvalidStructure(format!(
            "{} timestamp too far in the future",
            label
        )));
    }

    const CRL_ENTRY_MAX_AGE_DAYS: i64 = 365;
    if skew.num_days() > CRL_ENTRY_MAX_AGE_DAYS {
        return Err(CrlError::InvalidStructure(format!("{} expired", label)));
    }

    Ok(())
}

fn verify_canonical_signature(
    record_id: &str,
    proof_value_b64: &str,
    canonical: &[u8],
    public_key_der_b64: &str,
) -> Result<(), CrlError> {
    let public_key_der = general_purpose::STANDARD
        .decode(public_key_der_b64)
        .map_err(|_| CrlError::InvalidProof(record_id.to_string()))?;
    let signature = general_purpose::STANDARD
        .decode(proof_value_b64)
        .map_err(|_| CrlError::InvalidProof(record_id.to_string()))?;
    let digest = Sha256::digest(canonical);

    crate::did::doc_sign::ecdsa_p256_verify_der_or_raw(&public_key_der, &digest, &signature)
        .map_err(|_| CrlError::InvalidProof(record_id.to_string()))
}
