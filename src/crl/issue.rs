//! CRL issuance helpers.

use crate::crl::entry::{
    CrlEntry, RevocationEvidence, RevocationReason, RevokerRole, Severity, UnrevokeTombstone,
    CRL_CONTEXT_CORE, CRL_CONTEXT_SGX, CRL_UNREVOKE_TOMBSTONE_TYPE,
};
use crate::crl::errors::CrlError;
use crate::crl::list::CertificateRevocationList;
use crate::crl::persistence;
use crate::did::doc_sign;
use crate::did::{DidRecord, DEFAULT_DID_PATH};
use crate::key_manager::KeyManager;
use chrono::Utc;
use std::env;
use uuid::Uuid;

pub const DEFAULT_CIRCLE_ID: &str = "guardian-circle-alpha";

pub struct IssueRequest<'a> {
    pub revoked_did: &'a str,
    pub reason: RevocationReason,
    pub severity: Severity,
    pub circle_id: &'a str,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    pub evidence: Option<RevocationEvidence>,
}

pub fn load_runtime_signing_context() -> Result<(DidRecord, std::sync::Arc<KeyManager>), CrlError> {
    let revoker = DidRecord::load(&did_path())?;
    let node_id =
        crate::vc::issue::resolve_runtime_node_id().unwrap_or_else(|| "nodeA".to_string());
    let km = crate::vc::issue::load_runtime_key_manager(&node_id)
        .map_err(|e| CrlError::InvalidStructure(format!("load key manager: {}", e)))?;
    Ok((revoker, km))
}

pub fn current_circle_id() -> Result<String, CrlError> {
    let revoker = DidRecord::load(&did_path())?;
    let membership = crate::vc::persistence::load_own_any()
        .map_err(|e| CrlError::InvalidStructure(format!("local membership vc: {}", e)))?
        .ok_or_else(|| CrlError::InvalidStructure("local membership VC not found".into()))?;
    if membership.subject_did() != revoker.did {
        return Err(CrlError::InvalidStructure(format!(
            "local membership VC subject mismatch: expected {}, got {}",
            revoker.did,
            membership.subject_did()
        )));
    }
    Ok(membership.credential_subject.circle_id.clone())
}

/// Issue a revocation for `revoked_did`. The caller passes their own
/// DidRecord and KeyManager — those determine `revoker_did` and (via
/// role inspection) `revoker_role`.
pub fn issue_revocation(
    revoker: &DidRecord,
    revoker_role: RevokerRole,
    km: &KeyManager,
    req: IssueRequest<'_>,
) -> Result<CrlEntry, CrlError> {
    if matches!(revoker_role, RevokerRole::Member) {
        if local_circle_owner_did()
            .is_some_and(|owner_did| owner_did == req.revoked_did)
        {
            return Err(CrlError::OwnerRevocationRequiresOwner);
        }
        if !req.reason.is_security_critical() {
            return Err(CrlError::MemberReasonNotCritical(
                req.reason.as_str().to_string(),
            ));
        }
        if !matches!(req.severity, Severity::Critical | Severity::High) {
            return Err(CrlError::MemberSeverityTooLow(req.severity));
        }
    }

    if req.revoked_did == revoker.did {
        return Err(CrlError::SelfRevocation);
    }

    if crate::crl::is_revoked(req.revoked_did) {
        return Err(CrlError::AlreadyRevoked(req.revoked_did.to_string()));
    }

    let now = Utc::now();
    let mut entry = CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: req.revoked_did.to_string(),
        device_id: req.device_id,
        user_id: req.user_id,
        circle_id: req.circle_id.to_string(),
        reason: req.reason,
        severity: req.severity,
        timestamp: now.to_rfc3339(),
        revoker_did: revoker.did.clone(),
        revoker_role,
        evidence: req.evidence,
        proof: crate::did::document::Proof::default(),
        peers_notified: Vec::new(),
        propagated: false,
    };

    let canonical = entry.canonical_bytes_for_sign()?;
    let vm_ref = format!(
        "{}#dkp-v{}",
        revoker.did,
        revoker.current_dkp_version.max(1)
    );
    doc_sign::sign_in_place_generic(&mut entry.proof, &canonical, km, &vm_ref)?;

    persistence::save_entry(&entry)?;

    let mut crl = persistence::load_crl()?
        .unwrap_or_else(|| CertificateRevocationList::new(&revoker.did, req.circle_id));
    crl.upsert(entry.clone())?;
    crl.sequence += 1;
    crl.generated_at = now.to_rfc3339();
    crl.recompute_root();

    let crl_canonical = crl.canonical_bytes_for_sign()?;
    doc_sign::sign_in_place_generic(&mut crl.proof, &crl_canonical, km, &vm_ref)?;
    persistence::save_crl(&crl)?;

    if matches!(revoker_role, RevokerRole::Owner) {
        cross_revoke_owned_vcs(revoker, req.revoked_did, km, &vm_ref)?;
    }

    let node_id =
        crate::vc::issue::resolve_runtime_node_id().unwrap_or_else(|| "unknown".to_string());
    crate::audit::logger::log_audit(
        &node_id,
        crate::audit::event::AuditCategory::Crl,
        match entry.severity {
            Severity::Critical => crate::audit::event::AuditSeverity::Critical,
            Severity::High => crate::audit::event::AuditSeverity::Warning,
            Severity::Medium | Severity::Low => crate::audit::event::AuditSeverity::Info,
        },
        crate::audit::event::AuditAction::Succeeded,
        &format!(
            "Issued CRL entry {} revoked_did={} reason={} severity={} revoker_role={:?}",
            entry.id,
            entry.revoked_did,
            entry.reason.as_str(),
            entry.severity.as_str(),
            entry.revoker_role
        ),
    );

    Ok(entry)
}

fn local_circle_owner_did() -> Option<String> {
    crate::vc::issue::known_ca_did().ok().or_else(|| {
        crate::vc::persistence::load_own_any()
            .ok()
            .flatten()
            .map(|membership| membership.issuer.clone())
    })
}

pub fn local_revocation_context(revoker: &DidRecord) -> Result<(String, RevokerRole), CrlError> {
    let membership = crate::vc::persistence::load_own_any()
        .map_err(|e| CrlError::InvalidStructure(format!("local membership vc: {}", e)))?
        .ok_or_else(|| CrlError::InvalidStructure("local membership VC not found".into()))?;

    if membership.subject_did() != revoker.did {
        return Err(CrlError::InvalidStructure(format!(
            "local membership VC subject mismatch: expected {}, got {}",
            revoker.did,
            membership.subject_did()
        )));
    }

    let role = match membership.credential_subject.role {
        crate::vc::credential::CredentialRole::Owner => RevokerRole::Owner,
        crate::vc::credential::CredentialRole::Member => RevokerRole::Member,
    };

    Ok((membership.credential_subject.circle_id.clone(), role))
}

fn cross_revoke_owned_vcs(
    revoker: &DidRecord,
    revoked_did: &str,
    km: &KeyManager,
    vm_ref: &str,
) -> Result<(), CrlError> {
    set_owned_vcs_revoked(revoker, revoked_did, km, vm_ref, true)
}

/// Reverse a revocation (admin-only, see `unrevoke_revocation`). Only the
/// Circle Owner may unrevoke — this is a security-sensitive override, not a
/// member-level action. Restores any VC status-list bits that were flipped
/// by the original owner-initiated revoke.
pub fn unrevoke_revocation(
    revoker: &DidRecord,
    revoker_role: RevokerRole,
    km: &KeyManager,
    revoked_did: &str,
) -> Result<UnrevokeTombstone, CrlError> {
    if !matches!(revoker_role, RevokerRole::Owner) {
        return Err(CrlError::UnrevokeRequiresOwner);
    }

    let mut crl =
        persistence::load_crl()?.ok_or_else(|| CrlError::NotRevoked(revoked_did.to_string()))?;
    let removed = crl.remove(revoked_did)?;

    let now = Utc::now();
    let next_sequence = crl.sequence + 1;
    let mut tombstone = UnrevokeTombstone {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        r#type: vec![
            "VerifiableCredential".into(),
            CRL_UNREVOKE_TOMBSTONE_TYPE.into(),
        ],
        revoked_did: revoked_did.to_string(),
        original_entry_id: removed.id.clone(),
        owner_did: revoker.did.clone(),
        sequence: next_sequence,
        timestamp: now.to_rfc3339(),
        proof: crate::did::document::Proof::default(),
        peers_notified: Vec::new(),
        propagated: false,
    };
    crl.generated_at = now.to_rfc3339();

    let vm_ref = format!(
        "{}#dkp-v{}",
        revoker.did,
        revoker.current_dkp_version.max(1)
    );
    let tombstone_canonical = tombstone.canonical_bytes_for_sign()?;
    doc_sign::sign_in_place_generic(&mut tombstone.proof, &tombstone_canonical, km, &vm_ref)?;
    persistence::save_tombstone(&tombstone)?;

    crl.upsert_tombstone(tombstone.clone());
    crl.sequence = next_sequence;
    crl.recompute_root();

    let crl_canonical = crl.canonical_bytes_for_sign()?;
    doc_sign::sign_in_place_generic(&mut crl.proof, &crl_canonical, km, &vm_ref)?;
    persistence::save_crl(&crl)?;

    set_owned_vcs_revoked(revoker, revoked_did, km, &vm_ref, false)?;

    let node_id =
        crate::vc::issue::resolve_runtime_node_id().unwrap_or_else(|| "unknown".to_string());
    crate::audit::logger::log_audit(
        &node_id,
        crate::audit::event::AuditCategory::Crl,
        crate::audit::event::AuditSeverity::Critical,
        crate::audit::event::AuditAction::Succeeded,
        &format!(
            "Unrevoked CRL entry {} revoked_did={} tombstone_id={} by owner_did={}",
            removed.id, revoked_did, tombstone.id, revoker.did
        ),
    );

    Ok(tombstone)
}

fn set_owned_vcs_revoked(
    revoker: &DidRecord,
    revoked_did: &str,
    km: &KeyManager,
    vm_ref: &str,
    revoked: bool,
) -> Result<(), CrlError> {
    let issued = crate::vc::persistence::list_issued_for_subject(revoked_did)
        .map_err(|e| CrlError::InvalidStructure(format!("vc list: {}", e)))?;
    if issued.is_empty() {
        return Ok(());
    }

    let mut status_list = crate::vc::status_list::StatusListManager::load_or_create(revoker, km)
        .map_err(|e| CrlError::InvalidStructure(format!("status list load: {}", e)))?;

    for vc in &issued {
        let index = vc
            .credential_status
            .status_list_index
            .parse::<u64>()
            .map_err(|e| CrlError::InvalidStructure(format!("vc {} bad index: {}", vc.id, e)))?;
        status_list
            .set_revoked(index, revoked)
            .map_err(|e| CrlError::InvalidStructure(format!("set_revoked: {}", e)))?;
    }

    status_list
        .commit(km, vm_ref)
        .map_err(|e| CrlError::InvalidStructure(format!("commit status list: {}", e)))?;
    Ok(())
}

fn did_path() -> String {
    env::var("SGX_GUARDIAN_DID_PATH").unwrap_or_else(|_| DEFAULT_DID_PATH.to_string())
}
