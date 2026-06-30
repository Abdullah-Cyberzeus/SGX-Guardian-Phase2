//! CRL issuance helpers.

use crate::crl::entry::{
    CrlEntry, RevocationEvidence, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE,
    CRL_CONTEXT_SGX,
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

pub fn load_runtime_signing_context() -> Result<(DidRecord, KeyManager), CrlError> {
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
            .set_revoked(index, true)
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
