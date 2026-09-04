//! Tests for `circle::snapshot`, reusing the identity/env fixtures already
//! defined in the parent `circle::tests` module (`EnvGuard`, `make_material`,
//! `save_local_owner`, `save_peer_context`, `resolver`).

use super::{make_material, resolver, save_local_owner, save_peer_context, EnvGuard};
use crate::circle::members::{CircleMember, MemberLifecycleState};
use crate::circle::snapshot::{self, CircleMemberSnapshot};
use crate::did::document::Proof;
use crate::vc::credential::{CredentialRole, MembershipStatus};
use chrono::Utc;

fn member(did: &str, status: MembershipStatus, lifecycle: MemberLifecycleState) -> CircleMember {
    CircleMember {
        did: did.to_string(),
        vc_id: format!("vc-{did}"),
        issuer_did: "did:guardian:issuer".to_string(),
        role: CredentialRole::Member,
        permissions: vec![],
        join_date: Utc::now().to_rfc3339(),
        expiration_date: Utc::now().to_rfc3339(),
        membership_status: status,
        lifecycle_state: lifecycle,
        node_hint: None,
        name: None,
        email: None,
        member_type: None,
        browser_registration_id: None,
        online: None,
        presence_status: None,
    }
}

fn blank_snapshot(circle_id: &str, owner_did: &str, members: Vec<CircleMember>) -> CircleMemberSnapshot {
    CircleMemberSnapshot {
        circle_id: circle_id.to_string(),
        version: 1,
        owner_did: owner_did.to_string(),
        members,
        updated_at: Utc::now().to_rfc3339(),
        proof: Proof::default(),
    }
}

#[test]
fn load_returns_none_when_nothing_is_persisted() {
    let _env = EnvGuard::new();
    assert!(snapshot::load("no-such-circle").expect("load").is_none());
}

#[test]
fn save_load_cache_and_clear_round_trip() {
    let _env = EnvGuard::new();
    let owner = member(
        "did:guardian:owner",
        MembershipStatus::Active,
        MemberLifecycleState::Active,
    );
    let snap = blank_snapshot("circle-round-trip", "did:guardian:owner", vec![owner]);

    snapshot::save(&snap).expect("save");
    let loaded = snapshot::load("circle-round-trip")
        .expect("load")
        .expect("present");
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.owner_did, "did:guardian:owner");

    snapshot::clear("circle-round-trip").expect("clear");
    assert!(snapshot::load("circle-round-trip").expect("load").is_none());
}

#[test]
fn load_reads_through_to_disk_and_repopulates_cache_after_clear() {
    let _env = EnvGuard::new();
    let owner = member(
        "did:guardian:owner2",
        MembershipStatus::Active,
        MemberLifecycleState::Active,
    );
    let snap = blank_snapshot("circle-disk", "did:guardian:owner2", vec![owner]);
    snapshot::save(&snap).expect("save");

    // Clearing removes the cache entry AND the file; loading again is None.
    snapshot::clear("circle-disk").expect("clear");
    assert!(snapshot::load("circle-disk").expect("load").is_none());

    // Re-saving and loading again exercises the cache-hit path (a second
    // `load()` call hits cache without touching disk).
    snapshot::save(&snap).expect("save");
    let first = snapshot::load("circle-disk").expect("load").expect("present");
    let second = snapshot::load("circle-disk").expect("load").expect("present");
    assert_eq!(first.version, second.version);
}

#[test]
fn load_reads_from_disk_when_the_cache_has_never_been_populated() {
    let _env = EnvGuard::new();
    // Write the snapshot file directly (bypassing `save()`, which also
    // populates the in-memory cache) so this exercises the disk-read branch
    // of `load()` rather than a cache hit.
    let owner = member(
        "did:guardian:owner-disk-only",
        MembershipStatus::Active,
        MemberLifecycleState::Active,
    );
    let snap = blank_snapshot("circle-disk-only", "did:guardian:owner-disk-only", vec![owner]);
    let path = crate::circle::persistence::snapshot_path("circle-disk-only");
    std::fs::create_dir_all(path.parent().expect("parent dir")).expect("mkdir");
    std::fs::write(&path, serde_json::to_vec_pretty(&snap).expect("serialize")).expect("write");

    let loaded = snapshot::load("circle-disk-only")
        .expect("load")
        .expect("present");
    assert_eq!(loaded.circle_id, "circle-disk-only");
}

#[test]
fn canonical_bytes_for_sign_ignores_the_proof_field() {
    let mut snap = blank_snapshot("circle-canon", "did:guardian:owner3", vec![]);
    let empty_proof_bytes = snap.canonical_bytes_for_sign().expect("canonical");
    snap.proof = Proof {
        proof_type: "test".to_string(),
        ..Proof::default()
    };
    let populated_proof_bytes = snap.canonical_bytes_for_sign().expect("canonical");
    assert_eq!(empty_proof_bytes, populated_proof_bytes);
}

#[tokio::test]
async fn accept_from_owner_rejects_blank_circle_id() {
    let _env = EnvGuard::new();
    let snap = blank_snapshot("", "did:guardian:owner", vec![]);
    let err = snapshot::accept_from_owner(snap, &resolver())
        .await
        .expect_err("blank circle_id must be rejected");
    assert!(matches!(err, crate::circle::CircleError::Invalid(_)));
}

#[tokio::test]
async fn accept_from_owner_rejects_blank_owner_did() {
    let _env = EnvGuard::new();
    let snap = blank_snapshot("circle-x", "", vec![]);
    let err = snapshot::accept_from_owner(snap, &resolver())
        .await
        .expect_err("blank owner_did must be rejected");
    assert!(matches!(err, crate::circle::CircleError::Invalid(_)));
}

#[tokio::test]
async fn accept_from_owner_requires_an_active_owner_membership_entry() {
    let _env = EnvGuard::new();
    // No members at all -> no active-owner entry.
    let snap = blank_snapshot("circle-no-owner", "did:guardian:owner", vec![]);
    let err = snapshot::accept_from_owner(snap, &resolver())
        .await
        .expect_err("missing active owner membership must be rejected");
    assert!(matches!(err, crate::circle::CircleError::Invalid(_)));
}

#[tokio::test]
async fn accept_from_owner_rejects_a_non_active_member_entry() {
    let _env = EnvGuard::new();
    let owner = member(
        "did:guardian:owner",
        MembershipStatus::Active,
        MemberLifecycleState::Active,
    );
    let stale_member = member(
        "did:guardian:stale",
        MembershipStatus::Active,
        MemberLifecycleState::Expired,
    );
    let snap = blank_snapshot("circle-stale-member", "did:guardian:owner", vec![owner, stale_member]);
    let err = snapshot::accept_from_owner(snap, &resolver())
        .await
        .expect_err("a non-active member entry must be rejected");
    assert!(matches!(err, crate::circle::CircleError::Invalid(_)));
}

#[tokio::test]
async fn accept_from_owner_accepts_a_correctly_signed_snapshot_and_rejects_a_stale_replay() {
    let _env = EnvGuard::new();
    let (km, record, doc) = make_material("nodeA", 7, "192.168.77.1/24");
    save_local_owner(&record, &doc);
    save_peer_context(&doc);

    let owner_member = member(
        &record.did,
        MembershipStatus::Active,
        MemberLifecycleState::Active,
    );
    let mut snap = blank_snapshot("circle-signed", &record.did, vec![owner_member]);
    let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
    snap.sign(&km, &vm_ref).expect("sign snapshot");

    let accepted = snapshot::accept_from_owner(snap.clone(), &resolver())
        .await
        .expect("well-formed signed snapshot should be accepted");
    assert_eq!(accepted.version, 1);

    // Replaying the same (or an older) version once a newer one is stored
    // must be rejected as a stale/conflicting update.
    let err = snapshot::accept_from_owner(snap, &resolver())
        .await
        .expect_err("replaying a stale version must be rejected");
    assert!(matches!(err, crate::circle::CircleError::Conflict(_)));
}

#[tokio::test]
async fn accept_from_owner_for_node_prunes_local_state_when_local_did_is_no_longer_a_member() {
    let _env = EnvGuard::new();
    let (km, record, doc) = make_material("nodeA", 8, "192.168.78.1/24");
    save_local_owner(&record, &doc);
    save_peer_context(&doc);

    let owner_member = member(
        &record.did,
        MembershipStatus::Active,
        MemberLifecycleState::Active,
    );
    let mut snap = blank_snapshot("circle-pruned", &record.did, vec![owner_member]);
    let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
    snap.sign(&km, &vm_ref).expect("sign snapshot");

    // `local_did` is neither the owner nor present in the member list, so
    // this should prune any local circle/snapshot state and return the
    // snapshot unmodified rather than persisting it.
    let result = snapshot::accept_from_owner_for_node(
        snap,
        &resolver(),
        Some("did:guardian:not-a-member"),
        Some("nodeA"),
    )
    .await
    .expect("pruning path should not error");
    assert_eq!(result.circle_id, "circle-pruned");
    assert!(snapshot::load("circle-pruned").expect("load").is_none());
}

#[test]
fn build_authoritative_filters_inactive_members_sorts_and_signs() {
    let _env = EnvGuard::new();
    let (km, record, _doc) = make_material("nodeA", 9, "192.168.79.1/24");

    let active_b = member(
        "did:guardian:bbb",
        MembershipStatus::Active,
        MemberLifecycleState::Active,
    );
    let active_a = member(
        "did:guardian:aaa",
        MembershipStatus::Active,
        MemberLifecycleState::Active,
    );
    let revoked = member(
        "did:guardian:revoked",
        MembershipStatus::Revoked,
        MemberLifecycleState::Revoked,
    );

    let snap = snapshot::build_authoritative(
        "circle-authoritative",
        &record,
        &std::sync::Arc::new(km),
        vec![active_b, active_a, revoked],
    )
    .expect("build authoritative snapshot");

    assert_eq!(snap.members.len(), 2, "revoked member must be filtered out");
    assert_eq!(snap.members[0].did, "did:guardian:aaa", "members must be sorted by DID");
    assert_eq!(snap.members[1].did, "did:guardian:bbb");
    assert_eq!(snap.version, 1);
    assert!(!snap.proof.proof_value.is_empty(), "snapshot must be signed");

    // A second call for the same circle bumps the version.
    let key_dir = std::env::var(crate::vc::issue::DEVICE_KEY_DIR_ENV).expect("device key dir");
    let key_path = format!("{key_dir}/device_nodeA.key");
    let km2 = crate::key_manager::KeyManager::load_or_generate(&key_path).expect("reload key");
    let snap2 = snapshot::build_authoritative(
        "circle-authoritative",
        &record,
        &std::sync::Arc::new(km2),
        vec![snap.members[0].clone(), snap.members[1].clone()],
    )
    .expect("build authoritative snapshot v2");
    assert_eq!(snap2.version, 2);
}

#[tokio::test]
async fn pull_latest_for_joined_circles_returns_zero_when_nothing_needs_pulling() {
    let _env = EnvGuard::new();
    let (km, owner, owner_doc) = make_material("nodeA", 10, "192.168.80.1/24");
    save_local_owner(&owner, &owner_doc);
    crate::vc::issue::ensure_owner_vc(&owner, &km).expect("owner vc");

    // `load_or_seed` seeds exactly one (mesh) circle owned by this node, and
    // the loop skips both mesh circles and circles this node owns itself, so
    // the loop body (which would otherwise make a real network call) never
    // executes — this covers the function's setup/return path only.
    let applied = snapshot::pull_latest_for_joined_circles("nodeA", &resolver())
        .await
        .expect("pull with nothing to do should not error");
    assert_eq!(applied, 0);
}
