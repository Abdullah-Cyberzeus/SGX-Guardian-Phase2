use crate::crl::entry::{
    CrlEntry, RevocationEvidence, RevocationReason, RevokerRole, Severity, UnrevokeTombstone,
    CRL_CONTEXT_CORE, CRL_CONTEXT_SGX, CRL_UNREVOKE_TOMBSTONE_TYPE,
};
use crate::crl::issue::{self, IssueRequest};
use crate::crl::list::CertificateRevocationList;
use crate::did::doc_persistence;
use crate::did::doc_sign;
use crate::did::document::{DidDocument, DocBuildInput, Proof};
use crate::did::persistence::{DerivationProof, DidRecord};
use crate::key_manager::KeyManager;
use crate::vc::credential::{
    CredentialRole, CredentialStatus, CredentialSubject, MembershipStatus, VerifiableCredential,
    TYPE_CIRCLE_MEMBERSHIP, TYPE_VC, VC_CONTEXT_CORE, VC_CONTEXT_JWS_2020, VC_CONTEXT_SGX_CIRCLE,
    VC_CONTEXT_STATUS_LIST_2021,
};
use crate::vc::status_list::StatusListManager;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub use crate::crl::CrlError;

#[path = "entry_tests.rs"]
mod entry_tests;
#[path = "issue_tests.rs"]
mod issue_tests;
#[path = "list_tests.rs"]
mod list_tests;
#[path = "verify_tests.rs"]
mod verify_tests;

struct TestEnv {
    _crl_base: TempDir,
    _vc_base: TempDir,
    _did_base: TempDir,
    _peer_docs: TempDir,
    _key_dir: TempDir,
    // Held for the whole lifetime of the redirect. `TestEnv` repoints
    // `VC_BASE_ENV` and the DID document paths, which are process-global, and
    // its `Drop` then *removes* them — which used to yank the VC store out
    // from under concurrent tests in `api` and `vc`.
    _env_lock: crate::test_support::EnvLockGuard,
}

struct NodeCrlBase {
    _base: TempDir,
}

impl NodeCrlBase {
    fn new() -> Self {
        Self {
            _base: TempDir::new().expect("node crl tempdir"),
        }
    }

    fn activate(&self) {
        env::set_var(crate::crl::persistence::CRL_BASE_ENV, self._base.path());
    }
}

impl TestEnv {
    fn new() -> Self {
        let _env_lock = crate::test_support::env_lock();
        let crl_base = TempDir::new().expect("crl tempdir");
        let vc_base = TempDir::new().expect("vc tempdir");
        let did_base = TempDir::new().expect("did tempdir");
        let peer_docs = TempDir::new().expect("peer docs tempdir");
        let key_dir = TempDir::new().expect("key tempdir");

        env::set_var(crate::crl::persistence::CRL_BASE_ENV, crl_base.path());
        env::set_var(crate::vc::persistence::VC_BASE_ENV, vc_base.path());
        env::set_var(
            doc_persistence::SELF_DOC_PATH_ENV,
            did_base.path().join("did_doc.json"),
        );
        env::set_var(doc_persistence::PEERS_DOC_DIR_ENV, peer_docs.path());
        env::set_var(
            doc_persistence::CA_AGGREGATE_PATH_ENV,
            did_base.path().join("circle_did_docs.json"),
        );

        Self {
            _crl_base: crl_base,
            _vc_base: vc_base,
            _did_base: did_base,
            _peer_docs: peer_docs,
            _key_dir: key_dir,
            _env_lock,
        }
    }

    fn key_path(&self, node_id: &str) -> PathBuf {
        self._key_dir.path().join(format!("device_{}.key", node_id))
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        env::remove_var(crate::crl::persistence::CRL_BASE_ENV);
        env::remove_var(crate::vc::persistence::VC_BASE_ENV);
        env::remove_var(doc_persistence::SELF_DOC_PATH_ENV);
        env::remove_var(doc_persistence::PEERS_DOC_DIR_ENV);
        env::remove_var(doc_persistence::CA_AGGREGATE_PATH_ENV);
    }
}

fn test_lock() -> crate::test_support::EnvLockGuard {
    doc_persistence::lock_test_env()
}

fn make_did_record(did: &str, current_dkp_version: u32) -> DidRecord {
    DidRecord {
        did: did.to_string(),
        method: "guardian".to_string(),
        method_version: "1.0".to_string(),
        did_id_b58: format!("b58-{}", did.replace(':', "_")),
        did_id_hex: hex::encode(did.as_bytes()),
        created_at: Utc::now().to_rfc3339(),
        deactivated_at: None,
        derivation: DerivationProof {
            se050_uid: "se050-test-uid".to_string(),
            se050_uid_source: "test".to_string(),
            dkp_v1_pubkey_sha256_b16: "00".repeat(32),
            dkp_v1_pubkey_path: "device.key".to_string(),
            dkp_v1_pubkey_der_b64: None,
            dik_pubkey_sha256_b16: "11".repeat(32),
            dik_pubkey_der_b64: None,
        },
        current_dkp_version,
        deriv_signature_b64: "signature".to_string(),
    }
}

fn test_did(label: &str) -> String {
    let digest = Sha256::digest(label.as_bytes());
    format!("did:guardian:{}", bs58::encode(digest).into_string())
}

fn make_key_manager(key_path: &Path) -> KeyManager {
    KeyManager::load_or_generate(key_path.to_str().expect("utf8 key path")).expect("key manager")
}

fn make_membership_vc(
    subject_did: &str,
    role: CredentialRole,
    circle_id: &str,
    issuer_did: &str,
    status_index: u64,
) -> VerifiableCredential {
    VerifiableCredential {
        context: vec![
            VC_CONTEXT_CORE.into(),
            VC_CONTEXT_JWS_2020.into(),
            VC_CONTEXT_STATUS_LIST_2021.into(),
            VC_CONTEXT_SGX_CIRCLE.into(),
        ],
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        vc_type: vec![TYPE_VC.into(), TYPE_CIRCLE_MEMBERSHIP.into()],
        issuer: issuer_did.to_string(),
        issuance_date: Utc::now().to_rfc3339(),
        expiration_date: (Utc::now() + chrono::Duration::days(30)).to_rfc3339(),
        credential_subject: CredentialSubject::new(
            subject_did.to_string(),
            role,
            vec!["mesh:join".to_string(), "did:resolve".to_string()],
            Utc::now().to_rfc3339(),
            circle_id.to_string(),
            Some("node-test".to_string()),
            MembershipStatus::Active,
        ),
        credential_status: CredentialStatus {
            id: format!("{}/status-list#{}", issuer_did, status_index),
            status_type: "StatusList2021Entry".to_string(),
            status_purpose: "revocation".to_string(),
            status_list_index: status_index.to_string(),
            status_list_credential: format!("{}/status-list", issuer_did),
        },
        proof: Proof::default(),
    }
}

fn save_own_membership_vc(vc: &VerifiableCredential) {
    crate::vc::persistence::save_own(vc).expect("save own vc");
}

fn save_issued_vc(vc: &VerifiableCredential) {
    crate::vc::persistence::save_issued(vc).expect("save issued vc");
}

fn seed_peer_document(revoker: &DidRecord, km: &KeyManager, node_name: &str) {
    let public_key_der = km.pubkey_der().expect("pubkey der");
    let mut doc = DidDocument::build(DocBuildInput {
        did: &revoker.did,
        node_name: Some(node_name),
        current_dkp_version: revoker.current_dkp_version,
        current_dkp_pubkey_der: &public_key_der,
        overlay_ip_cidr: None,
        attestation_bind: None,
        cert_bootstrap_bind: None,
        revoked: vec![],
        previous_version_id: 0,
        created_at: None,
        status: Some("active".to_string()),
    })
    .expect("build did document");
    let vm_ref = format!(
        "{}#dkp-v{}",
        revoker.did,
        revoker.current_dkp_version.max(1)
    );
    doc_sign::sign_in_place(&mut doc, km, &vm_ref).expect("sign did document");
    doc_persistence::save_peer(&doc).expect("save peer doc");
}

fn build_entry(
    revoked_did: &str,
    revoker_did: &str,
    circle_id: &str,
    reason: RevocationReason,
    severity: Severity,
    revoker_role: RevokerRole,
) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: revoked_did.to_string(),
        device_id: Some("device-001".to_string()),
        user_id: Some("user-001".to_string()),
        circle_id: circle_id.to_string(),
        reason,
        severity,
        timestamp: Utc::now().to_rfc3339(),
        revoker_did: revoker_did.to_string(),
        revoker_role,
        evidence: Some(RevocationEvidence {
            note: Some("test".to_string()),
            audit_ref: None,
            attestation_ref: None,
            evidence_digest: None,
        }),
        proof: Proof::default(),
        peers_notified: vec![test_did("peerA")],
        propagated: true,
    }
}

fn sign_entry_with_key(
    entry: &mut CrlEntry,
    km: &KeyManager,
    vm_ref: &str,
) -> Result<(), crate::did::errors::DidError> {
    let canonical = entry.canonical_bytes_for_sign()?;
    doc_sign::sign_in_place_generic(&mut entry.proof, &canonical, km, vm_ref)
}

fn build_tombstone(
    revoked_did: &str,
    original_entry_id: &str,
    owner_did: &str,
    sequence: u64,
) -> UnrevokeTombstone {
    UnrevokeTombstone {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        r#type: vec![
            "VerifiableCredential".into(),
            CRL_UNREVOKE_TOMBSTONE_TYPE.into(),
        ],
        revoked_did: revoked_did.to_string(),
        original_entry_id: original_entry_id.to_string(),
        owner_did: owner_did.to_string(),
        sequence,
        timestamp: Utc::now().to_rfc3339(),
        proof: Proof::default(),
        peers_notified: vec![test_did("peerA")],
        propagated: true,
    }
}

fn sign_tombstone_with_key(
    tombstone: &mut UnrevokeTombstone,
    km: &KeyManager,
    vm_ref: &str,
) -> Result<(), crate::did::errors::DidError> {
    let canonical = tombstone.canonical_bytes_for_sign()?;
    doc_sign::sign_in_place_generic(&mut tombstone.proof, &canonical, km, vm_ref)
}
