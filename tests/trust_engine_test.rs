// tests/trust_engine_test.rs
// Integration tests for src/cot/trust_engine.rs

use sgx_guardian_client::cot::identity::DeviceIdentity;
use sgx_guardian_client::cot::membership::{CircleMembership, TrustLevel};
use sgx_guardian_client::cot::trust_engine::TrustEngine;
use sgx_guardian_client::cot::types::TransportType;
use std::sync::Arc;

fn make_key(seed: u8) -> Vec<u8> {
    let mut key = vec![0x04];
    key.extend_from_slice(&[seed; 32]);
    key.extend_from_slice(&[seed + 1; 32]);
    key
}

async fn setup(seed: u8) -> (TrustEngine, Arc<CircleMembership>, String) {
    let owner_key = make_key(seed);
    let owner_id = DeviceIdentity::compute_id(&owner_key);
    let local_identity = DeviceIdentity::from_public_key(&owner_key).unwrap();
    let circle = Arc::new(CircleMembership::new(
        "test-circle".into(),
        owner_id.clone(),
        owner_key.clone(),
    ));
    // Set owner as verified
    circle
        .set_trust_level(&owner_id, TrustLevel::Verified)
        .await
        .unwrap();
    let engine = TrustEngine::new(local_identity, circle.clone());
    (engine, circle, owner_id)
}

#[tokio::test]
async fn test_verify_known_verified_member() {
    let (engine, _, _) = setup(0xAA).await;
    let owner_key = make_key(0xAA);
    let result = engine
        .verify_peer(&owner_key, TransportType::Ethernet)
        .await;
    assert!(result.is_trusted);
    assert_eq!(result.trust_level, TrustLevel::Verified);
    assert!(result.reason.is_none());
}

#[tokio::test]
async fn test_verify_unknown_peer_rejected() {
    let (engine, _, _) = setup(0xAA).await;
    // Use a different key so device_id doesn't match any member
    let unknown_key = make_key(0x11);
    let result = engine.verify_peer(&unknown_key, TransportType::WiFi).await;
    assert!(!result.is_trusted);
    assert_eq!(result.trust_level, TrustLevel::Unverified);
    assert!(result.reason.is_some());
}

#[tokio::test]
async fn test_verify_revoked_member_rejected() {
    let (engine, circle, owner_id) = setup(0xAA).await;
    circle
        .set_trust_level(&owner_id, TrustLevel::Revoked)
        .await
        .unwrap();
    let owner_key = make_key(0xAA);
    let result = engine
        .verify_peer(&owner_key, TransportType::Cellular)
        .await;
    assert!(!result.is_trusted);
    assert_eq!(result.trust_level, TrustLevel::Revoked);
}

#[tokio::test]
async fn test_verify_key_mismatch_rejected() {
    let (engine, circle, _owner_id) = setup(0xAA).await;
    // Add a member with key 0xBB
    let member_key = make_key(0xBB);
    let member_id = DeviceIdentity::compute_id(&member_key);
    circle
        .add_member(member_id.clone(), member_key.clone())
        .await
        .unwrap();
    circle
        .set_trust_level(&member_id, TrustLevel::Verified)
        .await
        .unwrap();

    // Present a different key but claim to be the same device ID
    // TrustEngine will compute device_id from presented_public_key and look it up —
    // the member's stored key won't match the computed ID from a different raw key
    let wrong_key = make_key(0xCC);
    let result = engine
        .verify_peer(&wrong_key, TransportType::Ethernet)
        .await;
    // wrong_key generates a device_id that isn't in the circle → rejected as not a member
    assert!(!result.is_trusted);
}

#[tokio::test]
async fn test_is_authorized_verified_member() {
    let (engine, circle, owner_id) = setup(0xAA).await;
    // Owner is already Verified in setup
    assert!(circle.is_trusted_member(&owner_id).await);
    let authorized = engine.is_authorized(&owner_id, "send").await;
    assert!(authorized);
}

#[tokio::test]
async fn test_is_authorized_unverified_member() {
    let (engine, circle, _) = setup(0xAA).await;
    let member_key = make_key(0xBB);
    let member_id = DeviceIdentity::compute_id(&member_key);
    circle
        .add_member(member_id.clone(), member_key)
        .await
        .unwrap();
    // Default trust is Unverified
    let authorized = engine.is_authorized(&member_id, "send").await;
    assert!(!authorized);
}

#[tokio::test]
async fn test_cached_verification_populated_after_success() {
    let (engine, _, _) = setup(0xAA).await;
    let owner_key = make_key(0xAA);

    // Not in cache before verification
    let cached_before = engine
        .cached_verification(&DeviceIdentity::compute_id(&owner_key))
        .await;
    assert!(cached_before.is_none());

    // Verify
    let result = engine
        .verify_peer(&owner_key, TransportType::Ethernet)
        .await;
    assert!(result.is_trusted);

    // Should now be in cache
    let cached_after = engine
        .cached_verification(&DeviceIdentity::compute_id(&owner_key))
        .await;
    assert!(cached_after.is_some());
    assert!(cached_after.unwrap().is_trusted);
}

#[tokio::test]
async fn test_cached_verification_cleared_on_failure() {
    let (engine, circle, _) = setup(0xAA).await;
    let owner_key = make_key(0xAA);
    let owner_id = DeviceIdentity::compute_id(&owner_key);

    // First verify successfully to populate cache
    engine
        .verify_peer(&owner_key, TransportType::Ethernet)
        .await;

    // Revoke member
    circle
        .set_trust_level(&owner_id, TrustLevel::Revoked)
        .await
        .unwrap();

    // Verify again — should fail and clear cache
    engine
        .verify_peer(&owner_key, TransportType::Ethernet)
        .await;

    let cached = engine.cached_verification(&owner_id).await;
    assert!(cached.is_none());
}

#[tokio::test]
async fn test_decision_log_grows() {
    let (engine, _, owner_id) = setup(0xAA).await;
    engine.is_authorized(&owner_id, "action1").await;
    engine.is_authorized(&owner_id, "action2").await;
    engine.is_authorized(&owner_id, "action3").await;

    let log = engine.decision_log().await;
    assert!(log.len() >= 3);
}

#[tokio::test]
async fn test_local_identity_accessible() {
    let (engine, _, _) = setup(0xAA).await;
    let identity = engine.local_identity();
    assert!(!identity.device_id().is_empty());
}

#[tokio::test]
async fn test_verify_sets_transport_type_in_result() {
    let (engine, _, _) = setup(0xAA).await;
    let owner_key = make_key(0xAA);

    let result = engine
        .verify_peer(&owner_key, TransportType::Satellite)
        .await;
    assert_eq!(result.transport_used, TransportType::Satellite);
}
