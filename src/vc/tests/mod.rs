use crate::did::doc_persistence::{
    CA_AGGREGATE_PATH_ENV, PEERS_DOC_DIR_ENV, SELF_DOC_PATH_ENV, VERSION_COUNTER_PATH_ENV,
};
use crate::did::doc_sign;
use crate::did::document::{DidDocument, DocBuildInput};
use crate::did::persistence::{DerivationProof, DidRecord};
use crate::did::{derive, Resolver};
use crate::key_manager::KeyManager;
use crate::vc::credential::{CredentialRole, MembershipStatus};
use crate::vc::issue::{self, IssueMembershipOutcome, IssueRequest, RenewRequest};
use crate::vc::{persistence, status_list, verify, VcError};
use chrono::Utc;
use once_cell::sync::Lazy;
use std::ffi::OsString;
use std::sync::Mutex;
use tempfile::TempDir;

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

struct EnvGuard {
    self_doc_prev: Option<OsString>,
    peers_dir_prev: Option<OsString>,
    aggregate_prev: Option<OsString>,
    counter_prev: Option<OsString>,
    vc_base_prev: Option<OsString>,
    self_is_ca_prev: Option<OsString>,
    _td: TempDir,
}

impl EnvGuard {
    fn new() -> Self {
        let td = TempDir::new().expect("tempdir");
        let self_doc = td.path().join("did_doc.json");
        let peers_dir = td.path().join("peers");
        let aggregate = td.path().join("aggregate.json");
        let counter = td.path().join("version_counter");
        let vc_base = td.path().join("vc");
        let self_doc_prev = std::env::var_os(SELF_DOC_PATH_ENV);
        let peers_dir_prev = std::env::var_os(PEERS_DOC_DIR_ENV);
        let aggregate_prev = std::env::var_os(CA_AGGREGATE_PATH_ENV);
        let counter_prev = std::env::var_os(VERSION_COUNTER_PATH_ENV);
        let vc_base_prev = std::env::var_os(crate::vc::persistence::VC_BASE_ENV);
        let self_is_ca_prev = std::env::var_os("SGX_SELF_IS_CA");
        std::env::set_var(SELF_DOC_PATH_ENV, &self_doc);
        std::env::set_var(PEERS_DOC_DIR_ENV, &peers_dir);
        std::env::set_var(CA_AGGREGATE_PATH_ENV, &aggregate);
        std::env::set_var(VERSION_COUNTER_PATH_ENV, &counter);
        std::env::set_var(crate::vc::persistence::VC_BASE_ENV, &vc_base);
        std::env::set_var("SGX_SELF_IS_CA", "1");
        Self {
            self_doc_prev,
            peers_dir_prev,
            aggregate_prev,
            counter_prev,
            vc_base_prev,
            self_is_ca_prev,
            _td: td,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        restore_env(SELF_DOC_PATH_ENV, self.self_doc_prev.take());
        restore_env(PEERS_DOC_DIR_ENV, self.peers_dir_prev.take());
        restore_env(CA_AGGREGATE_PATH_ENV, self.aggregate_prev.take());
        restore_env(VERSION_COUNTER_PATH_ENV, self.counter_prev.take());
        restore_env(
            crate::vc::persistence::VC_BASE_ENV,
            self.vc_base_prev.take(),
        );
        restore_env("SGX_SELF_IS_CA", self.self_is_ca_prev.take());
    }
}

fn restore_env(key: &str, value: Option<OsString>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

fn make_ca_material() -> (TempDir, KeyManager, DidRecord, DidDocument, String) {
    let (td, km, record, doc) = make_material("nodeA", 1, "192.168.100.1/24");
    (td, km, record, doc, "did:guardian:member-test".to_string())
}

fn make_member_material() -> (TempDir, KeyManager, DidRecord, DidDocument) {
    make_material("nodeB", 2, "192.168.100.2/24")
}

fn make_material(
    node_name: &str,
    seed: u8,
    overlay_ip_cidr: &str,
) -> (TempDir, KeyManager, DidRecord, DidDocument) {
    let td = TempDir::new().expect("km tempdir");
    let key_path = td.path().join(format!("device_{}.key", node_name));
    let km = KeyManager::load_or_generate(key_path.to_str().unwrap()).expect("key");
    let pubkey = km.pubkey_der().expect("pubkey");
    let did = derive(&[seed; 16], &pubkey);
    let did_str = did.as_str().to_string();
    let now = Utc::now().to_rfc3339();
    let record = DidRecord {
        did: did_str.clone(),
        method: "guardian".into(),
        method_version: "1.0".into(),
        did_id_b58: did.msi().to_string(),
        did_id_hex: hex::encode(did.id_bytes()),
        created_at: now.clone(),
        deactivated_at: None,
        derivation: DerivationProof {
            se050_uid: "01".into(),
            se050_uid_source: "test".into(),
            dkp_v1_pubkey_sha256_b16: "01".into(),
            dkp_v1_pubkey_path: "test".into(),
            dkp_v1_pubkey_der_b64: None,
            dik_pubkey_sha256_b16: "01".into(),
            dik_pubkey_der_b64: None,
        },
        current_dkp_version: 1,
        deriv_signature_b64: String::new(),
    };
    let mut doc = crate::did::document::DidDocument::build(DocBuildInput {
        did: &did_str,
        node_name: Some(node_name),
        current_dkp_version: 1,
        current_dkp_pubkey_der: &pubkey,
        overlay_ip_cidr: Some(overlay_ip_cidr),
        attestation_bind: None,
        cert_bootstrap_bind: Some((
            overlay_ip_cidr.split('/').next().unwrap_or("127.0.0.1"),
            50061,
        )),
        revoked: vec![],
        previous_version_id: 0,
        created_at: Some(now),
        status: Some("active".into()),
    })
    .expect("doc build");
    let vm_ref = doc.verification_method.first().expect("vm").id.clone();
    doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign doc");
    (td, km, record, doc)
}

fn build_resolver() -> Resolver {
    Resolver::new(Default::default())
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

fn save_owner_context(doc: &DidDocument) {
    crate::did::doc_persistence::save_self(doc).expect("save self doc");
    crate::did::doc_persistence::save_peer(doc).expect("save peer doc");
    crate::did::doc_persistence::save_ca_aggregate(std::slice::from_ref(doc))
        .expect("save aggregate");
}

fn clear_owner_context() {
    let _ = std::fs::remove_file(crate::did::doc_persistence::configured_self_doc_path());
    let _ = std::fs::remove_file(crate::did::doc_persistence::configured_ca_aggregate_path());
    let _ = std::fs::remove_dir_all(crate::did::doc_persistence::configured_peers_doc_dir());
}

fn read_file(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).expect("read file")
}

fn verify_with_status_list(
    rt: &tokio::runtime::Runtime,
    vc: &crate::vc::credential::VerifiableCredential,
    resolver: &Resolver,
    subject_did: &str,
    issuer_did: &str,
) -> Result<(), VcError> {
    let status_credential = persistence::load_status_list_credential().expect("status list");
    let status_view = rt
        .block_on(async {
            status_list::verify_status_list_credential(
                &status_credential,
                resolver,
                Some(issuer_did),
            )
            .await
        })
        .expect("verify status list");
    rt.block_on(async {
        verify::verify_vc(
            vc,
            resolver,
            verify::VerifyOptions {
                expected_subject_did: Some(subject_did),
                expected_circle_id: Some(issue::DEFAULT_CIRCLE_ID),
                expected_issuer_did: Some(issuer_did),
                check_status_list: true,
                status_list: Some(&status_view),
            },
        )
        .await
    })
}

#[test]
fn vc_roundtrip_issue_and_verify() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);

    let vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue vc");

    let json = serde_json::to_value(&vc).expect("serialize vc");
    assert_eq!(
        json["credentialSubject"]["membershipStatus"].as_str(),
        Some("active")
    );

    let resolver = build_resolver();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    verify_with_status_list(&rt, &vc, &resolver, &subject_did, &issuer.did).expect("verify vc");
}

#[test]
fn vc_revocation_is_enforced() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);
    let _owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("owner vc");

    let vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: None,
            duration_days: Some(30),
        },
    )
    .expect("issue vc");
    issue::revoke_vc(&issuer, &km, &vc.id, "test", "nodeA").expect("revoke vc");

    let resolver = build_resolver();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let err = verify_with_status_list(&rt, &vc, &resolver, &subject_did, &issuer.did)
        .expect_err("revoked vc must fail");
    assert!(matches!(err, VcError::Revoked(_)));
}

#[test]
fn vc_subject_and_circle_mismatches_are_rejected() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);
    let mut vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: None,
            duration_days: Some(30),
        },
    )
    .expect("issue vc");
    let resolver = build_resolver();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let err = rt
        .block_on(async {
            verify::verify_vc(
                &vc,
                &resolver,
                verify::VerifyOptions {
                    expected_subject_did: Some("did:guardian:other"),
                    expected_circle_id: Some(issue::DEFAULT_CIRCLE_ID),
                    expected_issuer_did: Some(&issuer.did),
                    check_status_list: false,
                    status_list: None,
                },
            )
            .await
        })
        .expect_err("subject mismatch");
    assert!(matches!(err, VcError::SubjectMismatch { .. }));

    vc.credential_subject.circle_id = "other-circle".into();
    let err = rt
        .block_on(async {
            verify::verify_vc(
                &vc,
                &resolver,
                verify::VerifyOptions {
                    expected_subject_did: Some(&subject_did),
                    expected_circle_id: Some(issue::DEFAULT_CIRCLE_ID),
                    expected_issuer_did: Some(&issuer.did),
                    check_status_list: false,
                    status_list: None,
                },
            )
            .await
        })
        .expect_err("circle mismatch");
    assert!(matches!(err, VcError::CircleMismatch { .. }));
}

#[test]
fn status_list_tamper_is_rejected() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);
    let _ = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: None,
            duration_days: Some(30),
        },
    )
    .expect("issue vc");

    let resolver = build_resolver();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut status_credential = persistence::load_status_list_credential().expect("status list");
    status_credential.credential_subject.encoded_list.push('A');
    let err = rt
        .block_on(async {
            status_list::verify_status_list_credential(
                &status_credential,
                &resolver,
                Some(&issuer.did),
            )
            .await
        })
        .expect_err("tampered status list");
    assert!(matches!(
        err,
        VcError::StatusListProofInvalid | VcError::InvalidStructure(_)
    ));
}

#[test]
fn owner_vc_allows_issue_without_placeholder_gate() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);
    let _owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("owner vc");
    clear_owner_context();

    let vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("owner should issue via local owner vc");

    assert_eq!(vc.subject_did(), subject_did);
    assert_eq!(vc.issuer_did(), issuer.did);
}

#[test]
fn owner_authorization_ignores_newer_self_member_vc() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);

    let owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("owner vc");
    assert!(matches!(
        owner_vc.credential_subject.role,
        CredentialRole::Owner
    ));

    let self_member_vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &issuer.did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeA".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue newer self-member vc");
    assert!(matches!(
        self_member_vc.credential_subject.role,
        CredentialRole::Member
    ));

    let target_vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("owner should still issue vc");
    assert_eq!(target_vc.subject_did(), subject_did);

    issue::revoke_vc(&issuer, &km, &target_vc.id, "owner regression", "nodeA")
        .expect("owner should still revoke vc");
}

#[test]
fn owner_and_member_permission_bundles_are_distinct() {
    assert_eq!(
        issue::default_permissions_for_role(CredentialRole::Owner),
        vec![
            "mesh:join".to_string(),
            "cert:issue".to_string(),
            "cert:approve".to_string(),
            "cert:renew".to_string(),
            "vc:issue".to_string(),
            "vc:revoke".to_string(),
            "vc:status:update".to_string(),
            "attest:peer".to_string(),
            "did:resolve".to_string(),
            "status:read".to_string(),
            "status:write".to_string(),
            "circle:manage".to_string(),
        ]
    );
    assert_eq!(
        issue::default_permissions_for_role(CredentialRole::Member),
        vec![
            "mesh:join".to_string(),
            "cert:request".to_string(),
            "cert:renew".to_string(),
            "attest:peer".to_string(),
            "did:resolve".to_string(),
            "status:read".to_string(),
        ]
    );
    assert_ne!(
        issue::default_permissions_for_role(CredentialRole::Owner),
        issue::default_permissions_for_role(CredentialRole::Member)
    );
}

#[test]
fn owner_vc_can_approve_and_sign_cert_requests() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, _) = make_ca_material();
    save_owner_context(&doc);

    let owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("owner vc");

    assert!(owner_vc.has_permission("cert:approve"));
    assert!(owner_vc.has_permission("cert:issue"));
    assert!(owner_vc.has_permission("vc:issue"));
    assert!(owner_vc.has_permission("vc:revoke"));
}

#[test]
fn member_vc_can_request_cert_but_cannot_approve_or_sign() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_owner_dir, owner_km, owner, owner_doc, _) = make_ca_material();
    let (_member_dir, _member_km, member, _member_doc) = make_member_material();
    save_owner_context(&owner_doc);

    let member_vc = issue::issue_membership_vc(
        &owner,
        &owner_km,
        IssueRequest {
            subject_did: &member.did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue member vc");

    assert!(member_vc.has_permission("cert:request"));
    assert!(!member_vc.has_permission("cert:approve"));
    assert!(!member_vc.has_permission("cert:issue"));
    assert!(!member_vc.has_permission("vc:issue"));
    assert!(!member_vc.has_permission("vc:revoke"));
}

#[test]
fn member_cannot_issue_vc() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_owner_dir, owner_km, owner, owner_doc, _) = make_ca_material();
    let (_member_dir, member_km, member, member_doc) = make_member_material();
    crate::did::doc_persistence::save_self(&member_doc).expect("save member self doc");
    crate::did::doc_persistence::save_peer(&owner_doc).expect("save owner peer doc");
    crate::did::doc_persistence::save_ca_aggregate(std::slice::from_ref(&owner_doc))
        .expect("save owner aggregate");

    let member_vc = issue::issue_membership_vc(
        &owner,
        &owner_km,
        IssueRequest {
            subject_did: &member.did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue member vc");
    persistence::save_own(&member_vc).expect("save member own vc");

    let err = issue::issue_membership_vc(
        &member,
        &member_km,
        IssueRequest {
            subject_did: "did:guardian:new-member",
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeC".into()),
            duration_days: Some(30),
        },
    )
    .expect_err("member must not issue vc");
    assert!(matches!(err, VcError::NotCircleOwnerForIssue));
}

#[test]
fn member_cannot_revoke_vc() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_owner_dir, owner_km, owner, owner_doc, _) = make_ca_material();
    let (_member_dir, member_km, member, member_doc) = make_member_material();
    crate::did::doc_persistence::save_self(&member_doc).expect("save member self doc");
    crate::did::doc_persistence::save_peer(&owner_doc).expect("save owner peer doc");
    crate::did::doc_persistence::save_ca_aggregate(std::slice::from_ref(&owner_doc))
        .expect("save owner aggregate");

    let member_vc = issue::issue_membership_vc(
        &owner,
        &owner_km,
        IssueRequest {
            subject_did: &member.did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue member vc");
    persistence::save_own(&member_vc).expect("save member own vc");

    let target_vc = issue::issue_membership_vc(
        &owner,
        &owner_km,
        IssueRequest {
            subject_did: "did:guardian:target-member",
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeC".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue target vc");

    let err = issue::revoke_vc(&member, &member_km, &target_vc.id, "not owner", "nodeA")
        .expect_err("member must not revoke vc");
    assert!(matches!(err, VcError::NotCircleOwnerForRevoke));
}

#[test]
fn reissue_replaces_active_member_vc_when_permissions_change() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);

    let mut legacy_vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue legacy vc");
    legacy_vc.credential_subject.permissions =
        issue::default_permissions_for_role(CredentialRole::Owner);
    legacy_vc.proof = crate::did::document::Proof::default();
    let canonical = legacy_vc
        .canonical_bytes_for_sign()
        .expect("canonical bytes");
    let vm_ref = format!("{}#dkp-v{}", issuer.did, issuer.current_dkp_version.max(1));
    crate::did::doc_sign::sign_in_place_generic(&mut legacy_vc.proof, &canonical, &km, &vm_ref)
        .expect("re-sign legacy vc");
    persistence::save_issued(&legacy_vc).expect("overwrite issued legacy vc");

    let outcome = issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("reissue corrected member vc");

    let corrected = match outcome {
        IssueMembershipOutcome::IssuedNew { vc, .. } => vc,
        IssueMembershipOutcome::ReusedExisting { .. } => {
            panic!("permission drift must force new member VC")
        }
    };

    assert_ne!(legacy_vc.id, corrected.id);
    assert_eq!(
        corrected.credential_subject.permissions,
        issue::default_permissions_for_role(CredentialRole::Member)
    );
    assert_ne!(
        legacy_vc.credential_status.status_list_index,
        corrected.credential_status.status_list_index
    );

    let resolver = build_resolver();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let err = verify_with_status_list(&rt, &legacy_vc, &resolver, &subject_did, &issuer.did)
        .expect_err("legacy over-privileged member vc must be revoked");
    assert!(matches!(err, VcError::Revoked(_)));
}

#[test]
fn suspended_or_revoked_membership_status_is_rejected() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);
    let vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue vc");

    let resolver = build_resolver();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    for status in [MembershipStatus::Suspended, MembershipStatus::Revoked] {
        let mut altered = vc.clone();
        altered.credential_subject.membership_status = status.clone();
        let err = verify_with_status_list(&rt, &altered, &resolver, &subject_did, &issuer.did)
            .expect_err("inactive membership status must fail");
        assert!(matches!(err, VcError::InvalidMembershipStatus(_)));
    }
}

#[test]
fn legacy_active_vc_without_membership_status_still_verifies() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);

    let mut vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue vc");
    vc.credential_subject.membership_status = MembershipStatus::Active;
    vc.credential_subject.membership_status_explicit = false;
    vc.proof = crate::did::document::Proof::default();
    let canonical = vc.canonical_bytes_for_sign().expect("canonical bytes");
    let vm_ref = format!("{}#dkp-v{}", issuer.did, issuer.current_dkp_version.max(1));
    crate::did::doc_sign::sign_in_place_generic(&mut vc.proof, &canonical, &km, &vm_ref)
        .expect("sign legacy vc");

    let json = serde_json::to_value(&vc).expect("serialize legacy vc");
    assert!(json["credentialSubject"]["membershipStatus"].is_null());

    let resolver = build_resolver();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    verify_with_status_list(&rt, &vc, &resolver, &subject_did, &issuer.did)
        .expect("legacy vc should verify");
}

#[test]
fn repeated_issue_reuses_active_vc_without_mutating_files() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);

    let first = issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue vc");
    let vc = match first {
        IssueMembershipOutcome::IssuedNew { vc, .. } => vc,
        IssueMembershipOutcome::ReusedExisting { .. } => panic!("first issue must create vc"),
    };

    let issued_path = persistence::issued_path_for_id(&vc.id);
    let issued_before = read_file(&issued_path);
    let status_before = read_file(&persistence::status_list_path());
    let next_index_before = read_file(&persistence::status_list_index_path());

    let second = issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(90),
        },
    )
    .expect("reissue vc");
    let reused = match second {
        IssueMembershipOutcome::ReusedExisting { vc } => vc,
        IssueMembershipOutcome::IssuedNew { .. } => panic!("second issue must reuse vc"),
    };

    assert_eq!(vc.id, reused.id);
    assert_eq!(vc.issuance_date, reused.issuance_date);
    assert_eq!(vc.expiration_date, reused.expiration_date);
    assert_eq!(vc.proof.created, reused.proof.created);
    assert_eq!(vc.proof.proof_value, reused.proof.proof_value);
    assert_eq!(
        vc.credential_status.status_list_index,
        reused.credential_status.status_list_index
    );
    assert_eq!(issued_before, read_file(&issued_path));
    assert_eq!(status_before, read_file(&persistence::status_list_path()));
    assert_eq!(
        next_index_before,
        read_file(&persistence::status_list_index_path())
    );
}

#[test]
fn expired_issue_creates_new_vc_with_expired_replacement_outcome() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);

    let original = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(-1),
        },
    )
    .expect("issue expired vc");

    let outcome = issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("reissue after expiry");

    match outcome {
        IssueMembershipOutcome::IssuedNew {
            vc,
            replaced_expired,
        } => {
            assert!(replaced_expired);
            assert_ne!(original.id, vc.id);
            assert_ne!(
                original.credential_status.status_list_index,
                vc.credential_status.status_list_index
            );
        }
        IssueMembershipOutcome::ReusedExisting { .. } => {
            panic!("expired vc must not be reused");
        }
    }
}

#[test]
fn cert_approval_issue_flow_reuses_existing_active_vc() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);

    let initial = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: None,
        },
    )
    .expect("issue vc");

    let outcome = issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: None,
        },
    )
    .expect("reissue vc");

    match outcome {
        IssueMembershipOutcome::ReusedExisting { vc } => assert_eq!(initial.id, vc.id),
        IssueMembershipOutcome::IssuedNew { .. } => {
            panic!("cert approval flow should reuse active vc")
        }
    }
}

#[test]
fn vc_renew_by_id_updates_expiration_and_proof_but_preserves_identity_fields() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);
    let _owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("owner vc");

    let vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue vc");
    persistence::save_own(&vc).expect("save own copy");
    persistence::save_peer(&subject_did, &vc).expect("save peer copy");
    let next_index_before = read_file(&persistence::status_list_index_path());

    std::thread::sleep(std::time::Duration::from_millis(10));
    let renewed = issue::renew_membership_vc(
        &issuer,
        &km,
        RenewRequest {
            vc_id: Some(&vc.id),
            subject_did: None,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            duration_days: 90,
            allow_expired: false,
        },
        "nodeA",
    )
    .expect("renew vc");

    assert_eq!(vc.id, renewed.id);
    assert_eq!(vc.issuance_date, renewed.issuance_date);
    assert_eq!(
        vc.credential_status.status_list_index,
        renewed.credential_status.status_list_index
    );
    assert_eq!(vc.subject_did(), renewed.subject_did());
    assert_eq!(vc.credential_subject.role, renewed.credential_subject.role);
    assert_ne!(vc.expiration_date, renewed.expiration_date);
    assert_ne!(vc.proof.created, renewed.proof.created);
    assert_ne!(vc.proof.proof_value, renewed.proof.proof_value);

    let issued_copy = persistence::load_issued(&vc.id).expect("load issued copy");
    assert_eq!(issued_copy, renewed);
    let own_copy: crate::vc::credential::VerifiableCredential =
        serde_json::from_slice(&read_file(&persistence::own_path_for_id(&vc.id)))
            .expect("load own copy");
    assert_eq!(own_copy, renewed);
    let peer_copy: crate::vc::credential::VerifiableCredential = serde_json::from_slice(
        &read_file(&persistence::peer_path_for_subject(&subject_did)),
    )
    .expect("load peer copy");
    assert_eq!(peer_copy, renewed);
    assert_eq!(
        next_index_before,
        read_file(&persistence::status_list_index_path())
    );
}

#[test]
fn revoked_vc_cannot_be_renewed() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);
    let _owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("owner vc");

    let vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(30),
        },
    )
    .expect("issue vc");
    issue::revoke_vc(&issuer, &km, &vc.id, "test revoke", "nodeA").expect("revoke vc");

    let err = issue::renew_membership_vc(
        &issuer,
        &km,
        RenewRequest {
            vc_id: Some(&vc.id),
            subject_did: None,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            duration_days: 30,
            allow_expired: false,
        },
        "nodeA",
    )
    .expect_err("revoked vc must not renew");
    assert!(matches!(err, VcError::CannotRenewRevokedVc));
}

#[test]
fn expired_vc_renewal_requires_allow_expired() {
    let _guard = env_lock();
    let _env = EnvGuard::new();
    let (_km_dir, km, issuer, doc, subject_did) = make_ca_material();
    save_owner_context(&doc);
    let _owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("owner vc");

    let expired = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject_did,
            role: CredentialRole::Member,
            permissions: issue::default_permissions_for_role(CredentialRole::Member),
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: Some("nodeB".into()),
            duration_days: Some(-1),
        },
    )
    .expect("issue expired vc");

    let err = issue::renew_membership_vc(
        &issuer,
        &km,
        RenewRequest {
            vc_id: Some(&expired.id),
            subject_did: None,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            duration_days: 30,
            allow_expired: false,
        },
        "nodeA",
    )
    .expect_err("expired renewal without override must fail");
    assert!(matches!(err, VcError::CannotRenewExpiredVc(_)));

    let renewed = issue::renew_membership_vc(
        &issuer,
        &km,
        RenewRequest {
            vc_id: Some(&expired.id),
            subject_did: None,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            duration_days: 30,
            allow_expired: true,
        },
        "nodeA",
    )
    .expect("expired renewal with override should succeed");
    assert_eq!(expired.id, renewed.id);
    assert_eq!(expired.issuance_date, renewed.issuance_date);
    assert_eq!(
        expired.credential_status.status_list_index,
        renewed.credential_status.status_list_index
    );
    assert_ne!(expired.expiration_date, renewed.expiration_date);
}
