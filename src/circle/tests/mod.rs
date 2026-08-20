use crate::circle::invite::{self, InviteToken};
use crate::circle::members;
use crate::circle::persistence::CIRCLE_BASE_ENV;
use crate::circle::store;
use crate::did::doc_persistence::{
    lock_test_env, save_ca_aggregate, save_peer, save_self, CA_AGGREGATE_PATH_ENV,
    PEERS_DOC_DIR_ENV, SELF_DOC_PATH_ENV, VERSION_COUNTER_PATH_ENV,
};
use crate::did::doc_sign;
use crate::did::document::{DidDocument, DocBuildInput};
use crate::did::persistence::{DerivationProof, DidRecord};
use crate::did::{derive, Resolver};
use crate::key_manager::KeyManager;
use crate::vc::credential::CredentialRole;
use crate::vc::issue::{self, IssueRequest};
use base64::Engine as _;
use chrono::{Duration, Utc};
use std::ffi::OsString;
use tempfile::TempDir;

const DID_PATH_ENV: &str = "SGX_GUARDIAN_DID_PATH";

struct EnvGuard {
    self_doc_prev: Option<OsString>,
    peers_dir_prev: Option<OsString>,
    aggregate_prev: Option<OsString>,
    counter_prev: Option<OsString>,
    vc_base_prev: Option<OsString>,
    circle_base_prev: Option<OsString>,
    did_path_prev: Option<OsString>,
    device_key_dir_prev: Option<OsString>,
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
        let circle_base = td.path().join("circles");
        let did_path = td.path().join("did.json");
        let key_dir = td.path().join("keys");

        let self_doc_prev = std::env::var_os(SELF_DOC_PATH_ENV);
        let peers_dir_prev = std::env::var_os(PEERS_DOC_DIR_ENV);
        let aggregate_prev = std::env::var_os(CA_AGGREGATE_PATH_ENV);
        let counter_prev = std::env::var_os(VERSION_COUNTER_PATH_ENV);
        let vc_base_prev = std::env::var_os(crate::vc::persistence::VC_BASE_ENV);
        let circle_base_prev = std::env::var_os(CIRCLE_BASE_ENV);
        let did_path_prev = std::env::var_os(DID_PATH_ENV);
        let device_key_dir_prev = std::env::var_os(issue::DEVICE_KEY_DIR_ENV);

        std::env::set_var(SELF_DOC_PATH_ENV, &self_doc);
        std::env::set_var(PEERS_DOC_DIR_ENV, &peers_dir);
        std::env::set_var(CA_AGGREGATE_PATH_ENV, &aggregate);
        std::env::set_var(VERSION_COUNTER_PATH_ENV, &counter);
        std::env::set_var(crate::vc::persistence::VC_BASE_ENV, &vc_base);
        std::env::set_var(CIRCLE_BASE_ENV, &circle_base);
        std::env::set_var(DID_PATH_ENV, &did_path);
        std::env::set_var(issue::DEVICE_KEY_DIR_ENV, &key_dir);

        Self {
            self_doc_prev,
            peers_dir_prev,
            aggregate_prev,
            counter_prev,
            vc_base_prev,
            circle_base_prev,
            did_path_prev,
            device_key_dir_prev,
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
        restore_env(CIRCLE_BASE_ENV, self.circle_base_prev.take());
        restore_env(DID_PATH_ENV, self.did_path_prev.take());
        restore_env(issue::DEVICE_KEY_DIR_ENV, self.device_key_dir_prev.take());
    }
}

fn restore_env(key: &str, value: Option<OsString>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

fn make_material(
    node_name: &str,
    seed: u8,
    overlay_ip_cidr: &str,
) -> (KeyManager, DidRecord, DidDocument) {
    let key_dir = std::env::var(issue::DEVICE_KEY_DIR_ENV).expect("device key dir");
    std::fs::create_dir_all(&key_dir).expect("create key dir");
    let key_path = std::path::Path::new(&key_dir).join(format!("device_{}.key", node_name));
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
    let mut doc = DidDocument::build(DocBuildInput {
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
    (km, record, doc)
}

/// Like `make_material`, but pinned to an explicit `did_str` instead of
/// deriving one from a seed — for tests that need the Circle-owner identity
/// to equal an already-fixed DID (e.g. `AppState::for_tests`'s own
/// deterministic `device_did`), since `local_active_circle_ids` and similar
/// authorization checks key off `AppState::device_did` specifically, not
/// off whichever DID happens to own a Circle.
fn make_material_for_did(
    node_name: &str,
    did_str: &str,
    overlay_ip_cidr: &str,
) -> (KeyManager, DidRecord, DidDocument) {
    let key_dir = std::env::var(issue::DEVICE_KEY_DIR_ENV).expect("device key dir");
    std::fs::create_dir_all(&key_dir).expect("create key dir");
    let key_path = std::path::Path::new(&key_dir).join(format!("device_{}.key", node_name));
    let km = KeyManager::load_or_generate(key_path.to_str().unwrap()).expect("key");
    let pubkey = km.pubkey_der().expect("pubkey");
    let did = crate::did::Did::parse(did_str).expect("parse pinned did");
    let now = Utc::now().to_rfc3339();
    let record = DidRecord {
        did: did_str.to_string(),
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
    let mut doc = DidDocument::build(DocBuildInput {
        did: did_str,
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
    (km, record, doc)
}

fn save_local_owner(record: &DidRecord, doc: &DidDocument) {
    record
        .save(&std::env::var(DID_PATH_ENV).expect("did path"))
        .expect("save did");
    save_self(doc).expect("save self doc");
    save_peer(doc).expect("save peer doc");
    save_ca_aggregate(std::slice::from_ref(doc)).expect("save aggregate");
}

fn save_peer_context(doc: &DidDocument) {
    save_peer(doc).expect("save peer doc");
    let mut docs = crate::did::doc_persistence::load_ca_aggregate().expect("load aggregate");
    docs.push(doc.clone());
    save_ca_aggregate(&docs).expect("save aggregate");
}

fn resolver() -> Resolver {
    Resolver::new(Default::default())
}

fn sign_invite_token(token: &mut InviteToken, record: &DidRecord, km: &KeyManager) {
    let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
    let canonical = token.canonical_bytes_for_sign().expect("canonical invite");
    crate::did::doc_sign::sign_in_place_generic(&mut token.proof, &canonical, km, &vm_ref)
        .expect("sign invite");
}

#[test]
fn registry_roundtrip_and_tamper_detection() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    let (km, owner, owner_doc) = make_material("nodeA", 1, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let seeded = store::load_or_seed("nodeA").expect("seed registry");
    assert_eq!(seeded.circles.len(), 1);
    assert_eq!(
        seeded.circles[0].circle_id,
        issue::DEFAULT_CIRCLE_ID.to_string()
    );

    let created = store::create_circle(
        "nodeA",
        "circle-ops".to_string(),
        "Ops".to_string(),
        "Operators".to_string(),
        owner.did.clone(),
    )
    .expect("create circle");
    assert_eq!(created.owner_did, owner.did);

    let edited = store::edit_circle(
        "nodeA",
        "circle-ops",
        Some("Ops Renamed".to_string()),
        Some("Updated description".to_string()),
    )
    .expect("edit circle");
    assert_eq!(edited.name, "Ops Renamed");

    let archived = store::archive_circle("nodeA", "circle-ops").expect("archive circle");
    assert!(matches!(
        archived.status,
        crate::circle::CircleStatus::Archived
    ));

    let registry = store::load_or_seed("nodeA").expect("reload registry");
    let circle = registry
        .circles
        .iter()
        .find(|circle| circle.circle_id == "circle-ops")
        .expect("circle in registry");
    assert!(circle.is_archived());

    let mesh_unarchive_err = store::unarchive_circle("nodeA", issue::DEFAULT_CIRCLE_ID)
        .expect_err("mesh is not archived");
    assert!(matches!(
        mesh_unarchive_err,
        crate::circle::CircleError::Conflict(_)
    ));

    let unarchived = store::unarchive_circle("nodeA", "circle-ops").expect("unarchive circle");
    assert!(matches!(
        unarchived.status,
        crate::circle::CircleStatus::Active
    ));

    let registry = store::load_or_seed("nodeA").expect("reload registry after unarchive");
    let circle = registry
        .circles
        .iter()
        .find(|circle| circle.circle_id == "circle-ops")
        .expect("circle in registry");
    assert!(!circle.is_archived());

    let member_vc =
        members::add_member("nodeA", "circle-ops", &owner.did, CredentialRole::Owner, 30)
            .expect("add member before delete")
            .vc;

    let mesh_delete_err = members::delete_circle("nodeA", issue::DEFAULT_CIRCLE_ID, "test")
        .expect_err("mesh cannot be deleted");
    assert!(matches!(
        mesh_delete_err,
        crate::circle::CircleError::Conflict(_)
    ));

    let revoked_ids =
        members::delete_circle("nodeA", "circle-ops", "test cleanup").expect("delete circle");
    assert!(revoked_ids.contains(&member_vc.id));

    let registry = store::load_or_seed("nodeA").expect("reload registry after delete");
    assert!(!registry
        .circles
        .iter()
        .any(|circle| circle.circle_id == "circle-ops"));

    let path = crate::circle::persistence::registry_path();
    let mut tampered: crate::circle::CircleRegistry =
        serde_json::from_slice(&std::fs::read(&path).expect("registry bytes"))
            .expect("registry json");
    tampered.sequence += 1;
    crate::circle::persistence::write_atomic(&path, &serde_json::to_vec_pretty(&tampered).unwrap())
        .expect("write tampered registry");
    let err = store::load_or_seed("nodeA").expect_err("tampered registry must fail");
    assert!(matches!(
        err,
        crate::circle::CircleError::Did(_) | crate::circle::CircleError::InvalidProof(_)
    ));
}

#[test]
fn load_own_any_prefers_mesh_circle_membership() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    let (km, owner, owner_doc) = make_material("nodeA", 1, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let secondary = issue::issue_membership_vc(
        &owner,
        &km,
        IssueRequest {
            subject_did: &owner.did,
            role: CredentialRole::Owner,
            permissions: issue::default_permissions_for_role(CredentialRole::Owner),
            circle_id: "circle-secondary",
            node_hint: Some("nodeA".into()),
            duration_days: Some(30),
        },
    )
    .expect("secondary owner vc");
    assert_eq!(secondary.credential_subject.circle_id, "circle-secondary");

    let preferred = crate::vc::persistence::load_own_any()
        .expect("load own")
        .expect("own vc");
    assert_eq!(
        preferred.credential_subject.circle_id,
        issue::DEFAULT_CIRCLE_ID
    );
}

#[test]
fn invite_roundtrip_verifies_and_fits_qr_budget() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    let (km, owner, owner_doc) = make_material("nodeA", 1, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let circle = store::create_circle(
        "nodeA",
        "circle-ops".to_string(),
        "Ops".to_string(),
        String::new(),
        owner.did.clone(),
    )
    .expect("create circle");
    let (_member_km, member, member_doc) = make_material("nodeB", 2, "192.168.100.2/24");
    save_peer_context(&member_doc);
    let token = invite::mint_invite(
        &circle,
        &owner,
        &km,
        &member.did,
        CredentialRole::Member,
        Some(60),
        Some(1),
    )
    .expect("mint invite");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async { invite::verify_invite(&token, &resolver()).await })
        .expect("verify invite");

    let compact = invite::encode_compact(&token).expect("compact");
    let decoded = invite::decode_compact(&compact).expect("decode");
    assert_eq!(decoded, token);

    let link = invite::build_share_link(&compact, "http://owner.example:8443").expect("link");
    assert!(link.len() <= invite::MAX_QR_PAYLOAD_SIZE);
}

#[test]
fn targeted_invite_acceptance_issues_vc_and_persists_circle_state() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    let (owner_km, owner, owner_doc) = make_material("nodeA", 1, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &owner_km).expect("owner vc");
    let (member_km, member, member_doc) = make_material("nodeB", 2, "192.168.100.2/24");
    save_peer_context(&member_doc);

    let circle = store::create_circle(
        "nodeA",
        "circle-ops".to_string(),
        "Ops".to_string(),
        String::new(),
        owner.did.clone(),
    )
    .expect("create circle");
    let token = invite::mint_invite(
        &circle,
        &owner,
        &owner_km,
        &member.did,
        CredentialRole::Member,
        Some(60),
        Some(1),
    )
    .expect("mint invite");

    let members_before = members::list_members("nodeA", "circle-ops").expect("members");
    assert!(members_before.iter().any(|entry| {
        entry.did == member.did
            && matches!(
                entry.lifecycle_state,
                crate::circle::members::MemberLifecycleState::Invited
            )
    }));

    invite::save_received_invite(token.clone()).expect("nodeB stores invite");
    let join_request =
        invite::sign_join_request(&member, &member_km, token.clone()).expect("signed acceptance");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        invite::verify_invite(&token, &resolver()).await?;
        invite::verify_join_request(&join_request, &resolver()).await
    })
    .expect("verified acceptance");
    invite::assert_redeemable(&circle, &token, &join_request.joiner_did).expect("redeemable");

    let outcome = issue::issue_membership_vc_with_outcome(
        &owner,
        &owner_km,
        IssueRequest {
            subject_did: &join_request.joiner_did,
            role: token.role.clone(),
            permissions: issue::default_permissions_for_role(token.role.clone()),
            circle_id: &circle.circle_id,
            node_hint: None,
            duration_days: Some(issue::DEFAULT_VC_DURATION_DAYS),
        },
    )
    .expect("issue vc");
    invite::record_redemption(&token.id, &join_request.joiner_did).expect("record redemption");
    let vc = outcome.into_vc();
    crate::vc::persistence::save_own(&vc).expect("nodeB stores own vc");
    invite::save_joined_circle("nodeB", &token).expect("nodeB saves circle");
    invite::set_received_invite_state(&token.id, invite::ReceivedInviteState::Accepted)
        .expect("accepted state");

    let members_after = members::list_members("nodeA", "circle-ops").expect("nodeA members");
    assert!(members_after.iter().any(|entry| {
        entry.did == member.did
            && matches!(
                entry.lifecycle_state,
                crate::circle::members::MemberLifecycleState::Active
            )
    }));
    let node_b_circle = store::get_circle("nodeB", "circle-ops").expect("nodeB circle reload");
    assert_eq!(node_b_circle.owner_did, owner.did);
    let node_b_members = members::list_members("nodeB", "circle-ops").expect("nodeB members");
    assert!(node_b_members.iter().any(|entry| entry.did == owner.did));
    assert!(node_b_members.iter().any(|entry| entry.did == member.did));

    let replay = invite::assert_redeemable(&circle, &token, &join_request.joiner_did)
        .expect_err("replay rejected after restart/reload");
    assert!(matches!(
        replay,
        crate::circle::CircleError::InviteReplay(_)
    ));
}

#[test]
fn decode_compact_rejects_invalid_base64_as_invalid_input() {
    let err = invite::decode_compact("not-a-valid-token***").expect_err("invalid base64");
    assert!(matches!(err, crate::circle::CircleError::Invalid(_)));
}

#[test]
fn decode_compact_rejects_non_json_payload_as_invalid_input() {
    let compact = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("not-json");
    let err = invite::decode_compact(&compact).expect_err("invalid json payload");
    assert!(matches!(err, crate::circle::CircleError::Invalid(_)));
}

#[test]
fn expired_invite_is_rejected() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    let (km, owner, owner_doc) = make_material("nodeA", 1, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let circle = store::create_circle(
        "nodeA",
        "circle-ops".to_string(),
        "Ops".to_string(),
        String::new(),
        owner.did.clone(),
    )
    .expect("create circle");
    let mut token = invite::mint_invite(
        &circle,
        &owner,
        &km,
        &owner.did,
        CredentialRole::Member,
        Some(60),
        Some(1),
    )
    .expect("mint invite");
    token.expires_at = (Utc::now() - Duration::minutes(1)).to_rfc3339();
    sign_invite_token(&mut token, &owner, &km);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let err = rt
        .block_on(async { invite::verify_invite(&token, &resolver()).await })
        .expect_err("expired invite should fail");
    assert!(matches!(err, crate::circle::CircleError::InviteExpired(_)));
}

#[test]
fn tampered_invite_is_rejected() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    let (km, owner, owner_doc) = make_material("nodeA", 1, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let circle = store::create_circle(
        "nodeA",
        "circle-ops".to_string(),
        "Ops".to_string(),
        String::new(),
        owner.did.clone(),
    )
    .expect("create circle");
    let mut token = invite::mint_invite(
        &circle,
        &owner,
        &km,
        &owner.did,
        CredentialRole::Member,
        Some(60),
        Some(1),
    )
    .expect("mint invite");
    token.circle_name = "Tampered".to_string();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let err = rt
        .block_on(async { invite::verify_invite(&token, &resolver()).await })
        .expect_err("tampered invite should fail");
    assert!(matches!(
        err,
        crate::circle::CircleError::Did(_) | crate::circle::CircleError::InvalidProof(_)
    ));
}

#[test]
fn invite_replay_and_non_owner_invites_are_rejected() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    let (owner_km, owner, owner_doc) = make_material("nodeA", 1, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &owner_km).expect("owner vc");

    let (member_km, member, member_doc) = make_material("nodeB", 2, "192.168.100.2/24");
    save_peer_context(&member_doc);
    let (_joiner_km, joiner, joiner_doc) = make_material("nodeC", 3, "192.168.100.3/24");
    save_peer_context(&joiner_doc);

    let circle = store::create_circle(
        "nodeA",
        "circle-ops".to_string(),
        "Ops".to_string(),
        String::new(),
        owner.did.clone(),
    )
    .expect("create circle");

    let token = invite::mint_invite(
        &circle,
        &owner,
        &owner_km,
        &joiner.did,
        CredentialRole::Member,
        Some(60),
        Some(1),
    )
    .expect("mint invite");
    invite::assert_redeemable(&circle, &token, &joiner.did).expect("first redeem allowed");
    invite::record_redemption(&token.id, &joiner.did).expect("record redemption");
    let replay = invite::assert_redeemable(&circle, &token, &joiner.did)
        .expect_err("second redemption must fail");
    assert!(matches!(
        replay,
        crate::circle::CircleError::InviteReplay(_)
    ));

    let forged = invite::mint_invite(
        &circle,
        &member,
        &member_km,
        &joiner.did,
        CredentialRole::Member,
        Some(60),
        Some(1),
    )
    .expect("forged invite");
    let err = invite::assert_redeemable(&circle, &forged, &joiner.did)
        .expect_err("non-owner invite must fail");
    assert!(matches!(err, crate::circle::CircleError::Invalid(_)));
}

/// Phase 12 backend test gap: idempotent mutations, exercised at the HTTP
/// layer through the real router. A retried `POST /api/v1/circles` carrying
/// the same `Idempotency-Key` must return the exact same circle instead of
/// creating a second one — before `src/api/idempotency.rs` existed this was
/// silently broken, since `circle_id` is auto-generated per call when
/// omitted from the request body.
#[tokio::test]
async fn http_circle_create_is_idempotent_on_retry() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    let (km, owner, owner_doc) = make_material("nodeA", 1, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let app_dir = tempfile::TempDir::new().expect("app state tempdir");
    let config_dir = app_dir.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    let state = crate::api::state::AppState::for_tests(
        app_dir.path(),
        "nodeA",
        config_dir.to_string_lossy().to_string(),
    );
    let app = crate::api::build_router(state.clone(), axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    let base_url = format!("http://{}", addr);
    let client = crate::api::state::AppState::authed_client_for_tests(&state).await;

    let body = serde_json::json!({"name": "Idempotency Test Circle"});
    let idempotency_key = uuid::Uuid::new_v4().to_string();

    let first = client
        .post(format!("{}/api/v1/circles", base_url))
        .header("Idempotency-Key", &idempotency_key)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), reqwest::StatusCode::CREATED);
    let first_body: serde_json::Value = first.json().await.unwrap();
    let first_circle_id = first_body["circle"]["circleId"].as_str().unwrap().to_string();

    let second = client
        .post(format!("{}/api/v1/circles", base_url))
        .header("Idempotency-Key", &idempotency_key)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::CREATED);
    let second_body: serde_json::Value = second.json().await.unwrap();
    assert_eq!(
        second_body["circle"]["circleId"].as_str().unwrap(),
        first_circle_id,
        "retried create must replay the original circle, not mint a new circle_id"
    );

    let listing: serde_json::Value = client
        .get(format!("{}/api/v1/circles", base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // `circle::create` seeds the device's own mesh circle as a side effect
    // of its collision-check lookup, so two identical idempotent creates
    // leave exactly two circles: the auto-seeded mesh circle plus the one
    // "Idempotency Test Circle" (not created twice).
    let circles_after_retry = listing["count"].as_u64().unwrap();
    assert_eq!(
        circles_after_retry, 2,
        "mesh circle + exactly one Idempotency Test Circle after two identical idempotent creates"
    );

    // Control case: the SAME request repeated WITHOUT an Idempotency-Key is
    // a genuinely distinct request and must create a second circle — proving
    // the case above isn't passing by coincidence (e.g. name collisions).
    let no_key = client
        .post(format!("{}/api/v1/circles", base_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(no_key.status(), reqwest::StatusCode::CREATED);
    let listing_after: serde_json::Value = client
        .get(format!("{}/api/v1/circles", base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listing_after["count"].as_u64().unwrap(),
        circles_after_retry + 1
    );
}

/// A retried `POST /api/v1/group-calls` with the same `Idempotency-Key` must
/// replay the original session instead of hitting the "Another call is
/// already active" conflict a second, non-idempotent attempt would trigger.
#[tokio::test]
async fn http_group_call_create_is_idempotent_on_retry() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();
    // No real `nebula0` overlay interface exists in this sandbox/CI run —
    // see `NebulaClient::get_local_ip`'s test-only override.
    std::env::set_var("SGX_NEBULA_LOCAL_IP_OVERRIDE", "192.168.100.1");

    let app_dir = tempfile::TempDir::new().expect("app state tempdir");
    let config_dir = app_dir.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    let state = crate::api::state::AppState::for_tests(
        app_dir.path(),
        "nodeA",
        config_dir.to_string_lossy().to_string(),
    );

    // `local_active_circle_ids` (used by group-call's browser-member roster
    // lookup) checks membership by `AppState::device_did` specifically, not
    // just any Circle-owner DID — so the bootstrap owner identity must be
    // pinned to the app state's own device DID, unlike the plain circle-CRUD
    // idempotency test above (which never touches that roster lookup).
    let (km, owner, owner_doc) =
        make_material_for_did("nodeA", &state.device_did, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let app = crate::api::build_router(state.clone(), axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    let base_url = format!("http://{}", addr);
    let admin = crate::api::state::AppState::authed_client_for_tests(&state).await;

    let circle: serde_json::Value = admin
        .post(format!("{}/api/v1/circles", base_url))
        .json(&serde_json::json!({"name": "Group Call Idempotency Circle"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let circle_id = circle["circle"]["circleId"].as_str().unwrap().to_string();

    // Seed one active browser member so `call_all` has a real target — an
    // admin/device caller with no circle members can't create a group call
    // at all (correctly: "Select at least one trusted member").
    let _member = crate::api::state::AppState::member_client_for_tests(&state, &circle_id).await;

    let idempotency_key = uuid::Uuid::new_v4().to_string();
    let body =
        serde_json::json!({"title": "Idempotency Test Call", "call_all": true, "media": ["audio"]});

    let first = admin
        .post(format!("{}/api/v1/group-calls", base_url))
        .header("Idempotency-Key", &idempotency_key)
        .json(&body)
        .send()
        .await
        .unwrap();
    let first_status = first.status();
    let first_text = first.text().await.unwrap();
    assert_eq!(
        first_status,
        reqwest::StatusCode::CREATED,
        "first group-call create failed: {}",
        first_text
    );
    let first_body: serde_json::Value = serde_json::from_str(&first_text).unwrap();
    let group_id = first_body["session"]["group_id"]
        .as_str()
        .expect("first create returns a session with a group_id")
        .to_string();

    let second = admin
        .post(format!("{}/api/v1/group-calls", base_url))
        .header("Idempotency-Key", &idempotency_key)
        .json(&body)
        .send()
        .await
        .unwrap();
    // The pre-existing group-call idempotency cache (`group_call.rs`'s
    // `CREATED_OPERATIONS`) intentionally replies 200 OK on a cache hit
    // (vs. 201 Created for a genuine first-time create) — the point under
    // test is that it's a successful replay, not the 409 conflict a second,
    // non-idempotent create would hit ("Another call is already active").
    assert_eq!(
        second.status(),
        reqwest::StatusCode::OK,
        "a retried create with the same Idempotency-Key must replay successfully, not 409 conflict"
    );
    let second_body: serde_json::Value = second.json().await.unwrap();
    assert_eq!(
        second_body["session"]["group_id"].as_str().unwrap(),
        group_id,
        "retried create must replay the original session, not attempt a second call"
    );
}

/// Phase 12 backend test gap: roster privacy and Circle-restricted chat
/// authorization. A browser member of Circle A must not be able to read
/// Circle B's member roster or chat history, or send into Circle B, even
/// though both Circles are hosted by the same Guardian — and a member of
/// the target Circle must be able to do all three.
#[tokio::test]
async fn member_cannot_access_a_circle_they_do_not_belong_to() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();

    let app_dir = tempfile::TempDir::new().expect("app state tempdir");
    // `chat::storage` caches this path in a process-global `Lazy` on first
    // access, so it must be set before any request touches chat send/history.
    std::env::set_var(
        "CHAT_STORAGE_DIR",
        app_dir.path().join("chat").to_string_lossy().to_string(),
    );
    let config_dir = app_dir.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    let state = crate::api::state::AppState::for_tests(
        app_dir.path(),
        "nodeA",
        config_dir.to_string_lossy().to_string(),
    );

    // Roster/authorization checks key off `AppState::device_did` for "is
    // this Circle active on this Guardian" — see the group-call idempotency
    // test above for why the bootstrap owner identity must match it.
    let (km, owner, owner_doc) =
        make_material_for_did("nodeA", &state.device_did, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let app = crate::api::build_router(state.clone(), axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    let base_url = format!("http://{}", addr);
    let admin = crate::api::state::AppState::authed_client_for_tests(&state).await;

    let circle_a: serde_json::Value = admin
        .post(format!("{}/api/v1/circles", base_url))
        .json(&serde_json::json!({"name": "Circle A"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let circle_a_id = circle_a["circle"]["circleId"].as_str().unwrap().to_string();

    let circle_b: serde_json::Value = admin
        .post(format!("{}/api/v1/circles", base_url))
        .json(&serde_json::json!({"name": "Circle B"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let circle_b_id = circle_b["circle"]["circleId"].as_str().unwrap().to_string();

    let member_a =
        crate::api::state::AppState::member_client_for_tests(&state, &circle_a_id).await;
    let member_b =
        crate::api::state::AppState::member_client_for_tests(&state, &circle_b_id).await;

    // Positive control: a member of Circle A can read Circle A's roster,
    // read its chat history, and send into it.
    let roster_ok = member_a
        .get(format!("{}/api/v1/circles/{}/members", base_url, circle_a_id))
        .send()
        .await
        .unwrap();
    assert_eq!(roster_ok.status(), reqwest::StatusCode::OK);

    let history_ok = member_a
        .get(format!(
            "{}/api/v1/chat/history?group_id={}",
            base_url, circle_a_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(history_ok.status(), reqwest::StatusCode::OK);

    let send_ok = member_a
        .post(format!("{}/api/v1/chat/send", base_url))
        .json(&serde_json::json!({
            "recipient_did": circle_a_id,
            "content": "hello circle A",
            "is_group": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(send_ok.status(), reqwest::StatusCode::OK);

    // Negative cases: a member of Circle B must be rejected on all three
    // for Circle A, which they do not belong to.
    let roster_denied = member_b
        .get(format!("{}/api/v1/circles/{}/members", base_url, circle_a_id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        roster_denied.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a member of Circle B must not see Circle A's roster"
    );

    let history_denied = member_b
        .get(format!(
            "{}/api/v1/chat/history?group_id={}",
            base_url, circle_a_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        history_denied.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a member of Circle B must not read Circle A's chat history"
    );

    let send_denied = member_b
        .post(format!("{}/api/v1/chat/send", base_url))
        .json(&serde_json::json!({
            "recipient_did": circle_a_id,
            "content": "should be rejected",
            "is_group": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        send_denied.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a member of Circle B must not be able to send into Circle A"
    );
}

/// Phase 12 backend test gap: file authorization. A file uploaded to a
/// Circle's Vault namespace must be downloadable by a member of that
/// Circle, but rejected for a member of a different Circle.
#[tokio::test]
async fn vault_file_download_is_restricted_to_circle_members() {
    let _guard = lock_test_env();
    let _env = EnvGuard::new();

    let app_dir = tempfile::TempDir::new().expect("app state tempdir");
    std::env::set_var(
        "SGX_GUARDIAN_VAULT_BASE",
        app_dir.path().join("vault").to_string_lossy().to_string(),
    );
    // Vault content wrapping defaults to real SE050 hardware crypto, same
    // class of gap as the DID/VC signing key — this dev-mode flag is the
    // vault subsystem's own equivalent of `SGX_FORCE_SOFTWARE_KEYS`.
    std::env::set_var("SGX_GUARDIAN_VAULT_DEV_MODE", "1");
    let config_dir = app_dir.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    let state = crate::api::state::AppState::for_tests(
        app_dir.path(),
        "nodeA",
        config_dir.to_string_lossy().to_string(),
    );

    let (km, owner, owner_doc) =
        make_material_for_did("nodeA", &state.device_did, "192.168.100.1/24");
    save_local_owner(&owner, &owner_doc);
    issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    let app = crate::api::build_router(state.clone(), axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    let base_url = format!("http://{}", addr);
    let admin = crate::api::state::AppState::authed_client_for_tests(&state).await;

    let circle_a: serde_json::Value = admin
        .post(format!("{}/api/v1/circles", base_url))
        .json(&serde_json::json!({"name": "Vault Circle A"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let circle_a_id = circle_a["circle"]["circleId"].as_str().unwrap().to_string();

    let circle_b: serde_json::Value = admin
        .post(format!("{}/api/v1/circles", base_url))
        .json(&serde_json::json!({"name": "Vault Circle B"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let circle_b_id = circle_b["circle"]["circleId"].as_str().unwrap().to_string();

    let member_a =
        crate::api::state::AppState::member_client_for_tests(&state, &circle_a_id).await;
    let member_b =
        crate::api::state::AppState::member_client_for_tests(&state, &circle_b_id).await;

    let boundary = "vaultboundary";
    let body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\nCircle A only content\r\n--{b}--\r\n",
        b = boundary
    );
    let upload = member_a
        .post(format!("{}/api/v1/vault/upload?ns={}", base_url, circle_a_id))
        .header("Content-Type", format!("multipart/form-data; boundary={}", boundary))
        .body(body)
        .send()
        .await
        .unwrap();
    let upload_status = upload.status();
    let upload_text = upload.text().await.unwrap();
    assert_eq!(
        upload_status,
        reqwest::StatusCode::OK,
        "vault upload failed: {}",
        upload_text
    );
    let upload_body: serde_json::Value = serde_json::from_str(&upload_text).unwrap();
    let vault_id = upload_body["record"]["vault_id"].as_str().unwrap().to_string();

    // Positive control: a member of Circle A can download it.
    let owner_download = member_a
        .get(format!("{}/api/v1/vault/files/{}/download", base_url, vault_id))
        .send()
        .await
        .unwrap();
    assert_eq!(owner_download.status(), reqwest::StatusCode::OK);

    // A member of a different Circle must be rejected.
    let outsider_download = member_b
        .get(format!("{}/api/v1/vault/files/{}/download", base_url, vault_id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        outsider_download.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a member of a different Circle must not download this file"
    );
}
