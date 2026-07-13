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

    let timestamp = DateTime::parse_from_rfc3339(&entry.timestamp)
        .map_err(|error| CrlError::InvalidStructure(format!("timestamp: {}", error)))?;
    let now = Utc::now();
    let skew = now.signed_duration_since(timestamp.with_timezone(&Utc));

    // Future-dated entries beyond normal clock drift are rejected outright —
    // a legitimate entry's timestamp should never be meaningfully ahead of
    // "now" on any honest node.
    const MAX_FUTURE_SKEW_MINUTES: i64 = 15;
    if skew < chrono::Duration::minutes(-MAX_FUTURE_SKEW_MINUTES) {
        return Err(CrlError::InvalidStructure(
            "timestamp too far in the future".into(),
        ));
    }

    // Entries older than CRL_ENTRY_MAX_AGE_DAYS are expired. This bounds how
    // far an attacker-backdated timestamp can reach and pairs with the
    // latest-wins gossip merge rule (store::incoming_wins) so a stale,
    // backdated entry can't be kept alive indefinitely.
    const CRL_ENTRY_MAX_AGE_DAYS: i64 = 365;
    if skew.num_days() > CRL_ENTRY_MAX_AGE_DAYS {
        return Err(CrlError::InvalidStructure("CRL entry expired".into()));
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
