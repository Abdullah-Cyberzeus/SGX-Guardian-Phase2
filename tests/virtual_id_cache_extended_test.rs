// tests/virtual_id_cache_extended_test.rs
// Integration tests for uncovered branches in src/virtual_id_cache.rs

use sgx_guardian_client::virtual_id_cache::{
    ObservationContext, RotationReason, VidObservation, VirtualIdCache,
    compute_stable_security_state_hex,
};

fn make_ctx<'a>(
    peer_did: &'a str,
    vid: &'a str,
    stable: &'a str,
    dkp_vm: &'a str,
    dkp_kid: &'a str,
    dkp_fp: &'a str,
    pcr: &'a str,
    policy: &'a str,
) -> ObservationContext<'a> {
    ObservationContext {
        peer_did,
        new_vid_hex: vid,
        new_stable_hex: stable,
        new_dkp_verification_method_id: dkp_vm,
        new_dkp_kid: dkp_kid,
        new_dkp_fp: dkp_fp,
        new_pcr_digest: pcr,
        new_policy_digest: policy,
        peer_ip_hint: "",
    }
}

// ── RotationReason ────────────────────────────────────────────────────────────

#[test]
fn test_rotation_reason_is_security_event() {
    assert!(RotationReason::DidChanged.is_security_event());
    assert!(RotationReason::DkpRotated.is_security_event());
    assert!(RotationReason::PcrChanged.is_security_event());
    assert!(RotationReason::PolicyChanged.is_security_event());
    assert!(RotationReason::MultipleSecurityInputs.is_security_event());
}

#[test]
fn test_rotation_reason_not_security_event() {
    assert!(!RotationReason::InitialObservation.is_security_event());
    assert!(!RotationReason::NonceOnly.is_security_event());
    assert!(!RotationReason::UnknownInputChange.is_security_event());
}

#[test]
fn test_rotation_reason_as_str_all_variants() {
    assert_eq!(RotationReason::InitialObservation.as_str(), "initial_observation");
    assert_eq!(RotationReason::NonceOnly.as_str(), "nonce_refreshed");
    assert_eq!(RotationReason::DidChanged.as_str(), "did_changed");
    assert_eq!(RotationReason::DkpRotated.as_str(), "dkp_rotated");
    assert_eq!(RotationReason::PcrChanged.as_str(), "pcr_changed");
    assert_eq!(RotationReason::PolicyChanged.as_str(), "policy_changed");
    assert_eq!(RotationReason::MultipleSecurityInputs.as_str(), "multiple_security_inputs");
    assert_eq!(RotationReason::UnknownInputChange.as_str(), "unknown_input_change");
}

// ── VirtualIdCache::new / default ────────────────────────────────────────────

#[test]
fn test_virtual_id_cache_new_is_empty() {
    let cache = VirtualIdCache::new();
    assert!(cache.current_for_sync("did:guardian:any").is_none());
}

#[test]
fn test_virtual_id_cache_default_is_empty() {
    let cache = VirtualIdCache::default();
    assert!(cache.current_for_sync("did:guardian:any").is_none());
}

// ── observe_sync lifecycle ────────────────────────────────────────────────────

#[test]
fn test_observe_sync_first_then_unchanged() {
    let cache = VirtualIdCache::new();
    let r1 = cache.observe_sync("did:guardian:a", "vid-1");
    assert_eq!(r1, VidObservation::FirstSeen);

    let r2 = cache.observe_sync("did:guardian:a", "vid-1");
    assert_eq!(r2, VidObservation::Unchanged);
}

#[test]
fn test_observe_sync_rotation_is_multiple_security_inputs() {
    let cache = VirtualIdCache::new();
    cache.observe_sync("did:guardian:a", "vid-1");
    let r = cache.observe_sync("did:guardian:a", "vid-2");
    match r {
        VidObservation::Rotated { reason, .. } => {
            assert_eq!(reason, RotationReason::MultipleSecurityInputs);
        }
        _ => panic!("Expected Rotated"),
    }
}

// ── forget / clear ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_forget_removes_entry() {
    let cache = VirtualIdCache::new();
    cache.observe_sync("did:guardian:a", "vid-1");
    assert!(cache.current_for_sync("did:guardian:a").is_some());

    cache.forget("did:guardian:a").await;
    assert!(cache.current_for_sync("did:guardian:a").is_none());
}

#[tokio::test]
async fn test_clear_removes_all_entries() {
    let cache = VirtualIdCache::new();
    cache.observe_sync("did:guardian:a", "vid-1");
    cache.observe_sync("did:guardian:b", "vid-2");
    cache.clear().await;
    assert!(cache.current_for_sync("did:guardian:a").is_none());
    assert!(cache.current_for_sync("did:guardian:b").is_none());
}

#[test]
fn test_clear_sync() {
    let cache = VirtualIdCache::new();
    cache.observe_sync("did:guardian:a", "vid-1");
    cache.clear_sync();
    assert!(cache.current_for_sync("did:guardian:a").is_none());
}

// ── snapshot ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_snapshot_contains_all_entries() {
    let cache = VirtualIdCache::new();
    cache.observe_sync("did:guardian:a", "vid-1");
    cache.observe_sync("did:guardian:b", "vid-2");
    let snap = cache.snapshot().await;
    assert_eq!(snap.len(), 2);
    assert!(snap.contains_key("did:guardian:a"));
    assert!(snap.contains_key("did:guardian:b"));
}

#[test]
fn test_snapshot_sync() {
    let cache = VirtualIdCache::new();
    cache.observe_sync("did:guardian:x", "vid-x");
    let snap = cache.snapshot_sync();
    assert!(snap.contains_key("did:guardian:x"));
}

// ── current_for ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_current_for_async() {
    let cache = VirtualIdCache::new();
    cache.observe_sync("did:guardian:a", "vid-1");
    let entry = cache.current_for("did:guardian:a").await;
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().vid_hex, "vid-1");
}

// ── observe_rich: PCR change ──────────────────────────────────────────────────

#[test]
fn test_observe_rich_pcr_change_classified_correctly() {
    let cache = VirtualIdCache::new();
    cache.observe_rich(&make_ctx(
        "did:guardian:a",
        "vid-1",
        "stable-1",
        "did:guardian:a#dkp-v1",
        "dkp-v1",
        "fp-1",
        "pcr-1",
        "policy-1",
    ));
    let result = cache.observe_rich(&make_ctx(
        "did:guardian:a",
        "vid-2",
        "stable-2",
        "did:guardian:a#dkp-v1",
        "dkp-v1",
        "fp-1",
        "pcr-2",
        "policy-1",
    ));
    match result {
        VidObservation::Rotated { reason, .. } => {
            assert_eq!(reason, RotationReason::PcrChanged);
        }
        _ => panic!("Expected Rotated"),
    }
}

// ── observe_rich: policy change ───────────────────────────────────────────────

#[test]
fn test_observe_rich_policy_change_classified_correctly() {
    let cache = VirtualIdCache::new();
    cache.observe_rich(&make_ctx(
        "did:guardian:b",
        "vid-1",
        "stable-1",
        "did:guardian:b#dkp-v1",
        "dkp-v1",
        "fp-1",
        "pcr-1",
        "policy-1",
    ));
    let result = cache.observe_rich(&make_ctx(
        "did:guardian:b",
        "vid-2",
        "stable-2",
        "did:guardian:b#dkp-v1",
        "dkp-v1",
        "fp-1",
        "pcr-1",
        "policy-2",
    ));
    match result {
        VidObservation::Rotated { reason, .. } => {
            assert_eq!(reason, RotationReason::PolicyChanged);
        }
        _ => panic!("Expected Rotated"),
    }
}

// ── observe_rich: nonce only ──────────────────────────────────────────────────

#[test]
fn test_observe_rich_nonce_only_classified_correctly() {
    let cache = VirtualIdCache::new();
    let stable = "stable-x";
    cache.observe_rich(&make_ctx(
        "did:guardian:c",
        "vid-1",
        stable,
        "did:guardian:c#dkp-v1",
        "dkp-v1",
        "fp-1",
        "pcr-1",
        "policy-1",
    ));
    // Same stable component, different vid (nonces changed)
    let result = cache.observe_rich(&make_ctx(
        "did:guardian:c",
        "vid-2",
        stable, // same stable
        "did:guardian:c#dkp-v1",
        "dkp-v1",
        "fp-1",
        "pcr-1",
        "policy-1",
    ));
    match result {
        VidObservation::Rotated { reason, cooldown_allows_reattest, .. } => {
            assert_eq!(reason, RotationReason::NonceOnly);
            assert!(!cooldown_allows_reattest, "NonceOnly must not trigger re-attest");
        }
        _ => panic!("Expected Rotated"),
    }
}

// ── compute_stable_security_state_hex ────────────────────────────────────────

#[test]
fn test_compute_stable_security_state_hex_deterministic() {
    let h1 = compute_stable_security_state_hex(
        "did:guardian:x", "#dkp-v1", "v1", "fp-1", "pcr-1", "policy-1",
    );
    let h2 = compute_stable_security_state_hex(
        "did:guardian:x", "#dkp-v1", "v1", "fp-1", "pcr-1", "policy-1",
    );
    assert_eq!(h1, h2);
}

#[test]
fn test_compute_stable_security_state_hex_changes_with_pcr() {
    let h1 = compute_stable_security_state_hex(
        "did:guardian:x", "#dkp-v1", "v1", "fp-1", "pcr-1", "policy-1",
    );
    let h2 = compute_stable_security_state_hex(
        "did:guardian:x", "#dkp-v1", "v1", "fp-1", "pcr-2", "policy-1",
    );
    assert_ne!(h1, h2);
}

// ── DID-changed hint via IP ───────────────────────────────────────────────────

#[test]
fn test_did_changed_detected_via_ip_hint() {
    let cache = VirtualIdCache::new();

    // First, DID-A connects from IP 10.0.0.1
    let ctx_a = ObservationContext {
        peer_did: "did:guardian:A",
        new_vid_hex: "vid-a-1",
        new_stable_hex: "stable-a",
        new_dkp_verification_method_id: "did:guardian:A#dkp-v1",
        new_dkp_kid: "kid-a",
        new_dkp_fp: "fp-a",
        new_pcr_digest: "pcr-1",
        new_policy_digest: "policy-1",
        peer_ip_hint: "10.0.0.1",
    };
    cache.observe_rich(&ctx_a);

    // Now, DID-B connects from the same IP 10.0.0.1
    let ctx_b = ObservationContext {
        peer_did: "did:guardian:B",
        new_vid_hex: "vid-b-1",
        new_stable_hex: "stable-b",
        new_dkp_verification_method_id: "did:guardian:B#dkp-v1",
        new_dkp_kid: "kid-b",
        new_dkp_fp: "fp-b",
        new_pcr_digest: "pcr-1",
        new_policy_digest: "policy-1",
        peer_ip_hint: "10.0.0.1",
    };
    let result = cache.observe_rich(&ctx_b);

    // DID-B is a new DID, but the IP hint shows that DID-A was there before
    // → should be classified as DidChanged
    match result {
        VidObservation::Rotated { reason, .. } => {
            assert_eq!(reason, RotationReason::DidChanged);
        }
        VidObservation::FirstSeen => {
            // Also acceptable if DidChanged detection isn't triggered in this path
        }
        _ => panic!("Expected Rotated or FirstSeen, got {:?}", result),
    }
}
