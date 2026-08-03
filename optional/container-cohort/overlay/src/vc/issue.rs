use crate::did::doc_persistence;
use crate::did::DidRecord;
use crate::key_manager::KeyManager;
use crate::vc::credential::{
    CredentialRole, CredentialStatus, CredentialSubject, MembershipStatus, VerifiableCredential,
    TYPE_CIRCLE_MEMBERSHIP, TYPE_VC, VC_CONTEXT_CORE, VC_CONTEXT_JWS_2020, VC_CONTEXT_SGX_CIRCLE,
    VC_CONTEXT_STATUS_LIST_2021,
};
use crate::vc::errors::VcError;
use crate::vc::persistence;
use crate::vc::status_list::StatusListManager;
use chrono::{Duration, Utc};
use once_cell::sync::Lazy;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use uuid::Uuid;

pub const DEFAULT_VC_DURATION_DAYS: i64 = 365;
pub const DEFAULT_CIRCLE_ID: &str = "guardian-circle-alpha";
pub const DEVICE_KEY_DIR_ENV: &str = "SGX_GUARDIAN_DEVICE_KEY_DIR";
pub const OWNER_DEFAULT_PERMISSIONS: &[&str] = &[
    "mesh:join",
    "cert:issue",
    "cert:approve",
    "cert:renew",
    "vc:issue",
    "vc:revoke",
    "vc:status:update",
    "attest:peer",
    "did:resolve",
    "status:read",
    "status:write",
    "circle:manage",
];
pub const MEMBER_DEFAULT_PERMISSIONS: &[&str] = &[
    "mesh:join",
    "cert:request",
    "cert:renew",
    "attest:peer",
    "did:resolve",
    "status:read",
];
pub const ALLOWED_PERMISSIONS: &[&str] = &[
    "mesh:join",
    "cert:request",
    "cert:issue",
    "cert:approve",
    "cert:renew",
    "vc:issue",
    "vc:revoke",
    "vc:status:update",
    "attest:peer",
    "did:resolve",
    "status:read",
    "status:write",
    "circle:manage",
];

pub struct IssueRequest<'a> {
    pub subject_did: &'a str,
    pub role: CredentialRole,
    pub permissions: Vec<String>,
    pub circle_id: &'a str,
    pub node_hint: Option<String>,
    pub duration_days: Option<i64>,
}

pub enum IssueMembershipOutcome {
    IssuedNew {
        vc: VerifiableCredential,
        replaced_expired: bool,
    },
    ReusedExisting {
        vc: VerifiableCredential,
    },
}

impl IssueMembershipOutcome {
    pub fn into_vc(self) -> VerifiableCredential {
        match self {
            Self::IssuedNew { vc, .. } | Self::ReusedExisting { vc } => vc,
        }
    }
}

pub struct RenewRequest<'a> {
    pub vc_id: Option<&'a str>,
    pub subject_did: Option<&'a str>,
    pub circle_id: &'a str,
    pub duration_days: i64,
    pub allow_expired: bool,
}

#[derive(Clone, Copy)]
pub enum VcAdminAction {
    Issue,
    Revoke,
    Renew,
}

impl VcAdminAction {
    fn not_authorized_error(self) -> VcError {
        match self {
            Self::Issue => VcError::NotCircleOwnerForIssue,
            Self::Revoke => VcError::NotCircleOwnerForRevoke,
            Self::Renew => VcError::NotCircleOwnerForRenew,
        }
    }

    fn required_permissions(self) -> &'static [&'static str] {
        match self {
            Self::Issue | Self::Renew => &["vc:issue"],
            Self::Revoke => &["vc:revoke"],
        }
    }
}

pub fn issue_membership_vc(
    issuer_did: &DidRecord,
    km: &KeyManager,
    req: IssueRequest<'_>,
) -> Result<VerifiableCredential, VcError> {
    issue_membership_vc_with_outcome(issuer_did, km, req).map(IssueMembershipOutcome::into_vc)
}

pub fn issue_membership_vc_with_outcome(
    issuer_did: &DidRecord,
    km: &KeyManager,
    req: IssueRequest<'_>,
) -> Result<IssueMembershipOutcome, VcError> {
    validate_permissions_for_role(&req.role, &req.permissions)?;
    ensure_circle_owner(
        issuer_did,
        req.circle_id,
        VcAdminAction::Issue,
        can_bootstrap_issue(issuer_did, req.circle_id)?,
    )?;

    let mut status_list = StatusListManager::load_or_create(issuer_did, km)?;
    let now = Utc::now();
    let mut replaced_expired = false;
    if let Some(existing) =
        persistence::find_issued_for_subject_and_role(req.subject_did, req.circle_id, &req.role)?
    {
        match classify_vc_state(&existing, &status_list, now)? {
            VcLifecycleState::Active => {
                if permission_sets_match(&existing.credential_subject.permissions, &req.permissions)
                {
                    return Ok(IssueMembershipOutcome::ReusedExisting { vc: existing });
                }
                revoke_status_entry(&mut status_list, &existing)?;
            }
            VcLifecycleState::Expired => {
                replaced_expired = true;
            }
            VcLifecycleState::Revoked => {}
        }
    }

    let expires = now + Duration::days(req.duration_days.unwrap_or(DEFAULT_VC_DURATION_DAYS));
    let status_index = status_list.allocate_index()?;
    let status_list_credential = format!("{}/status-list", issuer_did.did);
    let vm_ref = format!(
        "{}#dkp-v{}",
        issuer_did.did,
        issuer_did.current_dkp_version.max(1)
    );

    let mut vc = VerifiableCredential {
        context: vec![
            VC_CONTEXT_CORE.into(),
            VC_CONTEXT_JWS_2020.into(),
            VC_CONTEXT_STATUS_LIST_2021.into(),
            VC_CONTEXT_SGX_CIRCLE.into(),
        ],
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        vc_type: vec![TYPE_VC.into(), TYPE_CIRCLE_MEMBERSHIP.into()],
        issuer: issuer_did.did.clone(),
        issuance_date: now.to_rfc3339(),
        expiration_date: expires.to_rfc3339(),
        credential_subject: CredentialSubject::new(
            req.subject_did.to_string(),
            req.role,
            req.permissions,
            now.to_rfc3339(),
            req.circle_id.to_string(),
            req.node_hint,
            MembershipStatus::Active,
        ),
        credential_status: CredentialStatus {
            id: format!("{}#{}", status_list_credential, status_index),
            status_type: "StatusList2021Entry".into(),
            status_purpose: "revocation".into(),
            status_list_index: status_index.to_string(),
            status_list_credential,
        },
        proof: crate::did::document::Proof::default(),
    };

    let canonical = vc.canonical_bytes_for_sign()?;
    crate::did::doc_sign::sign_in_place_generic(&mut vc.proof, &canonical, km, &vm_ref)?;
    persistence::save_issued(&vc)?;
    if vc.subject_did() == issuer_did.did {
        persistence::save_own(&vc)?;
    } else {
        persistence::save_peer(vc.subject_did(), &vc)?;
    }
    status_list.commit(km, &vm_ref)?;

    crate::audit::logger::log_audit(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "nodeA".to_string())
            .as_str(),
        crate::audit::event::AuditCategory::Vc,
        crate::audit::event::AuditSeverity::Info,
        crate::audit::event::AuditAction::Succeeded,
        &format!(
            "Issued VC {} to {} (role={:?}, idx={})",
            vc.id,
            vc.subject_did(),
            vc.credential_subject.role,
            status_index
        ),
    );

    Ok(IssueMembershipOutcome::IssuedNew {
        vc,
        replaced_expired,
    })
}

pub fn renew_membership_vc(
    issuer_did: &DidRecord,
    km: &KeyManager,
    req: RenewRequest<'_>,
    node_id: &str,
) -> Result<VerifiableCredential, VcError> {
    if req.duration_days <= 0 {
        return Err(VcError::InvalidStructure(
            "renewal days must be greater than zero".to_string(),
        ));
    }

    let target = match (req.vc_id, req.subject_did) {
        (Some(vc_id), None) => persistence::find_vc_by_id(vc_id)?
            .ok_or_else(|| VcError::NotFound(vc_id.to_string()))?,
        (None, Some(subject_did)) => {
            persistence::find_issued_for_subject(subject_did, req.circle_id)?
                .ok_or_else(|| VcError::NotFound(subject_did.to_string()))?
        }
        (Some(_), Some(_)) => {
            return Err(VcError::InvalidStructure(
                "renew requires either vc_id or subject_did, not both".to_string(),
            ))
        }
        (None, None) => {
            return Err(VcError::InvalidStructure(
                "renew requires vc_id or subject_did".to_string(),
            ))
        }
    };

    ensure_circle_owner(
        issuer_did,
        &target.credential_subject.circle_id,
        VcAdminAction::Renew,
        false,
    )?;
    if !target.has_active_membership_status() {
        return Err(VcError::InvalidMembershipStatus(
            target.credential_subject.membership_status.to_string(),
        ));
    }

    let status_list = StatusListManager::load_or_create(issuer_did, km)?;
    let now = Utc::now();
    match classify_vc_state(&target, &status_list, now)? {
        VcLifecycleState::Active => {}
        VcLifecycleState::Expired if req.allow_expired => {}
        VcLifecycleState::Expired => {
            return Err(VcError::CannotRenewExpiredVc(
                target.expiration_date.clone(),
            ))
        }
        VcLifecycleState::Revoked => return Err(VcError::CannotRenewRevokedVc),
    }

    let mut renewed = target.clone();
    renewed.expiration_date = (now + Duration::days(req.duration_days)).to_rfc3339();
    let vm_ref = format!(
        "{}#dkp-v{}",
        issuer_did.did,
        issuer_did.current_dkp_version.max(1)
    );
    let canonical = renewed.canonical_bytes_for_sign()?;
    crate::did::doc_sign::sign_in_place_generic(&mut renewed.proof, &canonical, km, &vm_ref)?;
    persist_renewed_copies(&renewed)?;

    crate::audit::logger::log_audit(
        node_id,
        crate::audit::event::AuditCategory::Vc,
        crate::audit::event::AuditSeverity::Info,
        crate::audit::event::AuditAction::Succeeded,
        &format!(
            "VC renewed by Circle owner: {} for {} (idx={})",
            renewed.id,
            renewed.subject_did(),
            renewed.credential_status.status_list_index
        ),
    );

    Ok(renewed)
}

pub fn revoke_vc(
    issuer_did: &DidRecord,
    km: &KeyManager,
    vc_id: &str,
    reason: &str,
    node_id: &str,
) -> Result<(), VcError> {
    let vc = persistence::load_issued(vc_id)?;
    ensure_circle_owner(
        issuer_did,
        &vc.credential_subject.circle_id,
        VcAdminAction::Revoke,
        false,
    )?;
    let index = vc
        .credential_status
        .status_list_index
        .parse::<u64>()
        .map_err(|e| VcError::InvalidStructure(format!("index: {}", e)))?;
    let mut status_list = StatusListManager::load_or_create(issuer_did, km)?;
    status_list.set_revoked(index, true)?;
    let vm_ref = format!(
        "{}#dkp-v{}",
        issuer_did.did,
        issuer_did.current_dkp_version.max(1)
    );
    status_list.commit(km, &vm_ref)?;
    crate::audit::logger::log_audit(
        node_id,
        crate::audit::event::AuditCategory::Vc,
        crate::audit::event::AuditSeverity::Warning,
        crate::audit::event::AuditAction::Revoked,
        &format!("Revoked VC {} (idx={}) reason={}", vc_id, index, reason),
    );
    Ok(())
}

pub fn ensure_owner_vc(
    issuer_did: &DidRecord,
    km: &KeyManager,
) -> Result<VerifiableCredential, VcError> {
    let vc = issue_membership_vc(
        issuer_did,
        km,
        IssueRequest {
            subject_did: &issuer_did.did,
            role: CredentialRole::Owner,
            permissions: default_permissions_for_role(CredentialRole::Owner),
            circle_id: DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeA".to_string()),
            duration_days: None,
        },
    )?;
    persistence::save_own(&vc)?;
    Ok(vc)
}

pub fn default_permissions_for_role(role: CredentialRole) -> Vec<String> {
    match role {
        CredentialRole::Owner => OWNER_DEFAULT_PERMISSIONS,
        CredentialRole::Member => MEMBER_DEFAULT_PERMISSIONS,
    }
    .iter()
    .map(|permission| (*permission).to_string())
    .collect()
}

pub fn subject_did_for_node(node_name: &str) -> Result<String, VcError> {
    if let Ok(Some(doc)) = doc_persistence::load_self() {
        if doc.sgx_node_name.as_deref() == Some(node_name) {
            return Ok(doc.id);
        }
    }
    for doc in doc_persistence::list_peer_docs()? {
        if doc.sgx_node_name.as_deref() == Some(node_name) {
            return Ok(doc.id);
        }
    }
    for doc in doc_persistence::load_ca_aggregate()? {
        if doc.sgx_node_name.as_deref() == Some(node_name) {
            return Ok(doc.id);
        }
    }
    Err(VcError::InvalidStructure(format!(
        "subject DID not found for node {}",
        node_name
    )))
}

pub fn known_ca_did() -> Result<String, VcError> {
    if let Ok(configured_did) = configured_ca_did() {
        return Ok(configured_did);
    }

    let local_did = DidRecord::load(crate::did::DEFAULT_DID_PATH)?;
    find_local_self_authorizing_vc(&local_did.did, DEFAULT_CIRCLE_ID, VcAdminAction::Issue)?
        .map(|vc| vc.issuer)
        .ok_or_else(|| {
            VcError::InvalidStructure(
                "circle owner DID could not be determined from local VC or config".to_string(),
            )
        })
}

pub fn is_self_ca() -> bool {
    let Ok(local_did) = DidRecord::load(crate::did::DEFAULT_DID_PATH) else {
        return false;
    };
    find_local_self_authorizing_vc(&local_did.did, DEFAULT_CIRCLE_ID, VcAdminAction::Issue)
        .map(|vc| vc.is_some())
        .unwrap_or(false)
}

pub fn resolve_runtime_node_id() -> Option<String> {
    if let Ok(Some(doc)) = doc_persistence::load_self() {
        if let Some(node_name) = doc.sgx_node_name {
            if !node_name.trim().is_empty() {
                return Some(node_name);
            }
        }
    }

    if let Ok(node_id) = std::env::var("SGX_NODE_ID") {
        if !node_id.trim().is_empty() {
            return Some(node_id);
        }
    }

    let mut matches = fs::read_dir("/var/lib/sgx-guardian/sgx-agent")
        .or_else(|_| fs::read_dir(runtime_device_key_dir()))
        .ok()?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            name.strip_prefix("device_")
                .and_then(|suffix| suffix.strip_suffix(".key"))
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    matches.sort();
    (matches.len() == 1).then(|| matches.remove(0))
}

/// Process-wide cache of runtime KeyManagers, keyed by the resolved key path.
///
/// load_runtime_key_manager() used to reconstruct a fresh KeyManager on
/// EVERY call — CRL gossip (every 60s round), CRL issuance, cert-service VC
/// issuance, and the VC REST API each independently re-ran DkpManager::init(),
/// re-probing the SE050 slot every time ("Existing DKP found ... loading
/// from SE050" printing far more often than at startup). Beyond the noisy
/// logs, this meant far more SE050 traffic than necessary, increasing the
/// odds of colliding with a concurrent SE050 operation. The underlying DKP
/// key never changes at runtime, so it's safe to build it once and share it.
///
/// Keyed by the full resolved key path rather than node_id: tests reuse the
/// same node_id (e.g. "nodeA") across isolated temp directories via
/// SGX_GUARDIAN_DEVICE_KEY_DIR, and caching by node_id alone would leak a
/// KeyManager built for one test's directory into another's. The key path
/// already encodes that directory, so it's the correct identity to cache on
/// and happens to make tests safe for free.
static KEY_MANAGER_CACHE: Lazy<StdMutex<HashMap<String, Arc<KeyManager>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

pub fn load_runtime_key_manager(node_id: &str) -> anyhow::Result<Arc<KeyManager>> {
    let key_path = runtime_device_key_dir().join(format!("device_{}.key", node_id));
    let key_path = key_path.to_string_lossy().to_string();
    if let Some(km) = KEY_MANAGER_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key_path)
    {
        return Ok(km.clone());
    }

    let km = if let Some(ctx) = crate::platform::PlatformContext::global() {
        ctx.initialize_key_manager(node_id, &key_path)?
    } else if software_keys_forced() {
        KeyManager::load_or_generate(&key_path)?
    } else {
        #[cfg(feature = "secure-element")]
        {
            KeyManager::init_with_se050(
                &crate::secure_element::config::SeConfig::default(),
                "/var/lib/sgx-guardian",
                &key_path,
            )?
        }
        #[cfg(not(feature = "secure-element"))]
        {
            KeyManager::load_or_generate(&key_path)?
        }
    };

    let km = Arc::new(km);
    KEY_MANAGER_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key_path, km.clone());
    Ok(km)
}

fn runtime_device_key_dir() -> PathBuf {
    std::env::var(DEVICE_KEY_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/sgx-agent"))
}

fn software_keys_forced() -> bool {
    fn env_true(key: &str) -> bool {
        matches!(
            std::env::var(key).ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
        )
    }

    env_true("SGX_FORCE_SOFTWARE_KEYS") || env_true("SGX_DISABLE_SE050_DKP")
}

pub fn ensure_circle_owner(
    issuer_did: &DidRecord,
    circle_id: &str,
    action: VcAdminAction,
    allow_bootstrap: bool,
) -> Result<(), VcError> {
    if find_local_self_authorizing_vc(&issuer_did.did, circle_id, action)?.is_some() {
        return Ok(());
    }

    if allow_bootstrap {
        if let Ok(configured_owner_did) = configured_ca_did() {
            if configured_owner_did == issuer_did.did {
                return Ok(());
            }
        }
    }

    Err(action.not_authorized_error())
}

fn configured_ca_did() -> Result<String, VcError> {
    subject_did_for_node("nodeA")
}

fn find_local_self_authorizing_vc(
    local_did: &str,
    circle_id: &str,
    action: VcAdminAction,
) -> Result<Option<VerifiableCredential>, VcError> {
    let mut matches = persistence::list_own()?
        .into_iter()
        .chain(persistence::list_issued()?)
        .filter(|vc| {
            vc.subject_did() == local_did
                && vc.issuer_did() == local_did
                && vc.credential_subject.circle_id == circle_id
                && vc.has_active_membership_status()
                && !vc.is_expired(Utc::now())
                && vc.has_all_permissions(action.required_permissions())
        })
        .collect::<Vec<_>>();
    matches.sort_by(|a, b| a.issuance_date.cmp(&b.issuance_date));
    Ok(matches.pop())
}

fn can_bootstrap_issue(issuer_did: &DidRecord, circle_id: &str) -> Result<bool, VcError> {
    if find_local_self_authorizing_vc(&issuer_did.did, circle_id, VcAdminAction::Issue)?.is_some() {
        return Ok(false);
    }

    match configured_ca_did() {
        Ok(configured_owner_did) if configured_owner_did == issuer_did.did => Ok(true),
        _ => Ok(false),
    }
}

pub fn validate_permissions_for_role(
    role: &CredentialRole,
    permissions: &[String],
) -> Result<(), VcError> {
    for permission in permissions {
        if !ALLOWED_PERMISSIONS.contains(&permission.as_str()) {
            return Err(VcError::UnknownPermission(permission.clone()));
        }
    }

    match role {
        CredentialRole::Owner => {
            for required in OWNER_DEFAULT_PERMISSIONS {
                if !permissions.iter().any(|granted| granted == required) {
                    return Err(VcError::InvalidStructure(format!(
                        "owner VC missing required permission {}",
                        required
                    )));
                }
            }
            Ok(())
        }
        CredentialRole::Member => {
            let granted = permissions
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let expected = MEMBER_DEFAULT_PERMISSIONS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();

            if granted == expected {
                return Ok(());
            }

            if let Some(permission) = permissions
                .iter()
                .find(|permission| !expected.contains(permission.as_str()))
            {
                return Err(VcError::InvalidStructure(format!(
                    "member VC permission not allowed: {}",
                    permission
                )));
            }

            if let Some(permission) = MEMBER_DEFAULT_PERMISSIONS
                .iter()
                .find(|permission| !granted.contains(*permission))
            {
                return Err(VcError::InvalidStructure(format!(
                    "member VC missing required permission {}",
                    permission
                )));
            }

            Ok(())
        }
    }
}

fn permission_sets_match(left: &[String], right: &[String]) -> bool {
    left.iter().map(String::as_str).collect::<BTreeSet<_>>()
        == right.iter().map(String::as_str).collect::<BTreeSet<_>>()
}

fn revoke_status_entry(
    status_list: &mut StatusListManager,
    vc: &VerifiableCredential,
) -> Result<(), VcError> {
    status_list.set_revoked(vc_status_index(vc)?, true)?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VcLifecycleState {
    Active,
    Expired,
    Revoked,
}

pub fn classify_vc_state(
    vc: &VerifiableCredential,
    status_list: &StatusListManager,
    now: chrono::DateTime<Utc>,
) -> Result<VcLifecycleState, VcError> {
    let index = vc_status_index(vc)?;
    if status_list.is_revoked(index)? {
        return Ok(VcLifecycleState::Revoked);
    }
    if vc.is_expired(now) {
        return Ok(VcLifecycleState::Expired);
    }
    Ok(VcLifecycleState::Active)
}

fn vc_status_index(vc: &VerifiableCredential) -> Result<u64, VcError> {
    vc.credential_status
        .status_list_index
        .parse::<u64>()
        .map_err(|e| VcError::InvalidStructure(format!("index: {}", e)))
}

fn persist_renewed_copies(vc: &VerifiableCredential) -> Result<(), VcError> {
    persistence::save_issued(vc)?;

    if persistence::own_path_for_id(&vc.id).exists() {
        persistence::save_own(vc)?;
    }
    if persistence::peer_path_for_subject(vc.subject_did()).exists() {
        persistence::save_peer(vc.subject_did(), vc)?;
    }

    Ok(())
}
