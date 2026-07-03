// tests/virtual_id_extended_test.rs
// Integration tests for uncovered branches in src/virtual_id.rs

use sgx_guardian_client::virtual_id::VirtualIdInputs;

fn sample_inputs<'a>() -> VirtualIdInputs<'a> {
    VirtualIdInputs {
        did: "did:guardian:node-abc",
        dkp_pubkey_der: &[0xAA; 65],
        pcr_values: &[0x01; 32],
        policy_digest: &[0x02; 32],
        nonce_i: &[0x03; 32],
        nonce_r: &[0x04; 32],
    }
}

// ── stable_component ──────────────────────────────────────────────────────────

#[test]
fn test_stable_component_deterministic() {
    let inp = sample_inputs();
    assert_eq!(inp.stable_component(), inp.stable_component());
}

#[test]
fn test_stable_component_differs_from_full_vid() {
    let inp = sample_inputs();
    let vid = inp.compute();
    let stable = inp.stable_component();
    assert_ne!(vid, stable, "stable_component should differ from full VID");
}

#[test]
fn test_stable_component_changes_with_pcr() {
    let inp = sample_inputs();
    let different_pcr_inp = VirtualIdInputs {
        pcr_values: &[0xFF; 32],
        ..inp.clone()
    };
    assert_ne!(inp.stable_component(), different_pcr_inp.stable_component());
}

#[test]
fn test_stable_component_changes_with_policy() {
    let inp = sample_inputs();
    let different_policy_inp = VirtualIdInputs {
        policy_digest: &[0xFF; 32],
        ..inp.clone()
    };
    assert_ne!(
        inp.stable_component(),
        different_policy_inp.stable_component()
    );
}

#[test]
fn test_stable_component_changes_with_dkp_key() {
    let inp = sample_inputs();
    let different_dkp_inp = VirtualIdInputs {
        dkp_pubkey_der: &[0xBB; 65],
        ..inp.clone()
    };
    assert_ne!(inp.stable_component(), different_dkp_inp.stable_component());
}

#[test]
fn test_stable_component_changes_with_did() {
    let inp = sample_inputs();
    let different_did_inp = VirtualIdInputs {
        did: "did:guardian:other-node",
        ..inp.clone()
    };
    assert_ne!(inp.stable_component(), different_did_inp.stable_component());
}

/// Key property: stable_component does NOT change when only nonces change.
#[test]
fn test_stable_component_unchanged_when_nonces_change() {
    let inp = sample_inputs();
    let different_nonce_inp = VirtualIdInputs {
        nonce_i: &[0xEE; 32],
        nonce_r: &[0xFF; 32],
        ..inp.clone()
    };
    assert_eq!(
        inp.stable_component(),
        different_nonce_inp.stable_component(),
        "stable_component must not change when only nonces change"
    );
}

/// Full VID DOES change when nonces change.
#[test]
fn test_full_vid_changes_when_nonces_change() {
    let inp = sample_inputs();
    let different_nonce_inp = VirtualIdInputs {
        nonce_i: &[0xEE; 32],
        nonce_r: &[0xFF; 32],
        ..inp.clone()
    };
    assert_ne!(
        inp.compute(),
        different_nonce_inp.compute(),
        "full VID must change when nonces change"
    );
}

// ── canonical_bytes structure ──────────────────────────────────────────────────

#[test]
fn test_canonical_bytes_length_is_deterministic() {
    let inp = sample_inputs();
    let b1 = inp.canonical_bytes();
    let b2 = inp.canonical_bytes();
    assert_eq!(b1.len(), b2.len());
    assert_eq!(b1, b2);
}

/// Verify length-prefix encoding in stable_component prevents collisions:
/// two inputs whose raw bytes are the same when concatenated but differ in how
/// they split produce different stable_component outputs.
#[test]
fn test_stable_component_collision_resistance() {
    // "AB" | "CD"  vs  "A" | "BCD"
    let a = VirtualIdInputs {
        did: "AB",
        dkp_pubkey_der: b"CD",
        pcr_values: &[0u8; 32],
        policy_digest: &[0u8; 32],
        nonce_i: &[0u8; 32],
        nonce_r: &[0u8; 32],
    };
    let b = VirtualIdInputs {
        did: "A",
        dkp_pubkey_der: b"BCD",
        ..a.clone()
    };
    // stable_component should differ because length-prefixes are embedded
    assert_ne!(a.stable_component(), b.stable_component());
}

#[test]
fn test_canonical_bytes_changes_with_longer_did() {
    let short_did_inp = sample_inputs();
    let long_did_inp = VirtualIdInputs {
        did: "did:guardian:much-longer-did-value-that-changes-length",
        ..short_did_inp.clone()
    };
    assert_ne!(short_did_inp.canonical_bytes(), long_did_inp.canonical_bytes());
}

#[test]
#[allow(deprecated)]
fn test_compute_virtual_id_legacy_deterministic() {
    use sgx_guardian_client::virtual_id::compute_virtual_id_legacy;
    let result1 =
        compute_virtual_id_legacy(&[0xAA; 65], &[0x01; 32], &[0x02; 32], &[0x03; 16], &[0x04; 16]);
    let result2 =
        compute_virtual_id_legacy(&[0xAA; 65], &[0x01; 32], &[0x02; 32], &[0x03; 16], &[0x04; 16]);
    assert_eq!(result1, result2);
}

#[test]
#[allow(deprecated)]
fn test_compute_virtual_id_legacy_changes_with_different_input() {
    use sgx_guardian_client::virtual_id::compute_virtual_id_legacy;
    let result1 =
        compute_virtual_id_legacy(&[0xAA; 65], &[0x01; 32], &[0x02; 32], &[0x03; 16], &[0x04; 16]);
    let result2 =
        compute_virtual_id_legacy(&[0xBB; 65], &[0x01; 32], &[0x02; 32], &[0x03; 16], &[0x04; 16]);
    assert_ne!(result1, result2);
}
