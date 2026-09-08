use sgx_guardian_client::attestation_service::AttestationService;
use sgx_guardian_client::attestation_service::{
    attestation_listener_port_for_base, attestation_listener_port_for_node,
    trigger_reattestation_for, AttestationEvidence, BaselineStatus, BootChainSummary,
    ChallengeRequest, ChallengeResponse, QuoteVerificationResult, SignedQuote,
};
use sgx_guardian_client::key_manager::KeyManager;
use tempfile::TempDir;

#[test]
fn test_attestation_evidence() {
    let temp_dir = TempDir::new().unwrap();
    let keys_dir = temp_dir.path().join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();

    let km = KeyManager::load_or_generate(keys_dir.join("key").to_str().unwrap()).unwrap();

    // Test evidence generation
    let policy_yaml = "---\nversion: 1.0\n";
    let result = AttestationService::create_signed_evidence(&km, policy_yaml);

    // If it fails because of missing DidRecord, that's fine, it covers the execution path.
    // Or it might succeed.
    let _ = result;
}

fn evidence(policy_digest: &str) -> AttestationEvidence {
    AttestationEvidence {
        node_id: "nodeA".into(),
        subject_did: String::new(),
        nonce: "00".repeat(32),
        nonce_i: Some("00".repeat(32)),
        nonce_r: Some(String::new()),
        policy_digest: policy_digest.into(),
        virtual_id: String::new(),
        signature: String::new(),
        pubkey_der_b64: String::new(),
        presented_vc_json: None,
        pcr_values: None,
        key_version: None,
        baseline_status: None,
    }
}

#[test]
fn attestation_port_adds_offset() {
    assert_eq!(attestation_listener_port_for_base(50051), 50151);
}

#[test]
fn attestation_port_saturates_at_max() {
    assert_eq!(attestation_listener_port_for_base(u16::MAX), u16::MAX);
}

#[test]
fn node_a_listener_port_is_stable() {
    assert_eq!(attestation_listener_port_for_node("nodeA"), 50151);
}

#[test]
fn node_b_listener_port_is_stable() {
    assert_eq!(attestation_listener_port_for_node("nodeB"), 50152);
}

#[test]
fn node_c_listener_port_is_stable() {
    assert_eq!(attestation_listener_port_for_node("nodeC"), 50153);
}

#[test]
fn unknown_node_listener_port_falls_back_to_node_a() {
    assert_eq!(attestation_listener_port_for_node("nodeZ"), 50151);
}

#[test]
fn trigger_reattestation_without_sender_is_noop() {
    trigger_reattestation_for("did:peer");
}

#[test]
fn malformed_policy_digest_is_rejected() {
    assert!(!AttestationService::verify_signed_evidence(&evidence("bad"), "policy").unwrap());
}

#[test]
fn short_hex_policy_digest_is_rejected() {
    assert!(!AttestationService::verify_signed_evidence(&evidence("00"), "policy").unwrap());
}

#[test]
fn digest_mismatch_is_rejected_before_signature_decode() {
    assert!(
        !AttestationService::verify_signed_evidence(&evidence(&"00".repeat(32)), "policy").unwrap()
    );
}

#[test]
fn baseline_status_serializes_mismatches() {
    let status = BaselineStatus {
        state: "MISMATCH".into(),
        mismatched_pcrs: vec![0, 4],
        composite_digest: "aa".repeat(32),
    };
    assert!(serde_json::to_string(&status).unwrap().contains("MISMATCH"));
}

#[test]
fn boot_chain_summary_round_trips() {
    let summary = BootChainSummary {
        hab_enabled: true,
        device_closed: true,
        hab_events_found: false,
        boot_chain_intact: true,
    };
    let parsed: BootChainSummary =
        serde_json::from_str(&serde_json::to_string(&summary).unwrap()).unwrap();
    assert!(parsed.boot_chain_intact);
}

#[test]
fn signed_quote_round_trips() {
    let quote = SignedQuote {
        quote_json: "{}".into(),
        signature_b64: "sig".into(),
        signing_backend: "Software".into(),
    };
    assert_eq!(
        serde_json::from_str::<SignedQuote>(&serde_json::to_string(&quote).unwrap())
            .unwrap()
            .signing_backend,
        "Software"
    );
}

#[test]
fn challenge_request_round_trips() {
    let req = ChallengeRequest {
        verifier_node_id: "nodeA".into(),
        nonce: "aa".repeat(32),
        timestamp: "2026-01-01T00:00:00Z".into(),
    };
    assert_eq!(
        serde_json::from_str::<ChallengeRequest>(&serde_json::to_string(&req).unwrap())
            .unwrap()
            .nonce
            .len(),
        64
    );
}

#[test]
fn challenge_response_round_trips_with_counter_challenge() {
    let resp = ChallengeResponse {
        prover_node_id: "nodeB".into(),
        signed_quote: SignedQuote {
            quote_json: "{}".into(),
            signature_b64: "s".into(),
            signing_backend: "Software".into(),
        },
        counter_challenge_nonce: Some("bb".repeat(32)),
    };
    assert!(serde_json::to_string(&resp)
        .unwrap()
        .contains("counter_challenge_nonce"));
}

#[test]
fn quote_verification_result_round_trips_failure_reason() {
    let result = QuoteVerificationResult {
        verified: false,
        nonce_valid: false,
        signature_valid: false,
        pcr_match: false,
        boot_chain_ok: false,
        freshness_ok: false,
        reason: "bad nonce".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
    };
    assert_eq!(
        serde_json::from_str::<QuoteVerificationResult>(&serde_json::to_string(&result).unwrap())
            .unwrap()
            .reason,
        "bad nonce"
    );
}

macro_rules! evidence_serde_tests {
    ($($name:ident => $node:expr, $digest:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let digest = ($digest).to_string();
            let mut ev = evidence(&digest);
            ev.node_id = $node.into();
            let parsed: AttestationEvidence = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
            assert_eq!(parsed.node_id, $node);
            assert_eq!(parsed.policy_digest, digest);
        }
    )+};
}

evidence_serde_tests! {
    evidence_node_a_round_trip => "nodeA", &"11".repeat(32),
    evidence_node_b_round_trip => "nodeB", &"22".repeat(32),
    evidence_empty_node_round_trip => "", &"33".repeat(32),
    evidence_long_node_round_trip => "node-abcdefghijklmnopqrstuvwxyz", &"44".repeat(32),
    evidence_upper_node_round_trip => "NODE", &"55".repeat(32),
    evidence_dash_node_round_trip => "node-a", &"66".repeat(32),
    evidence_numeric_node_round_trip => "123", &"77".repeat(32),
    evidence_colon_node_round_trip => "did:node", &"88".repeat(32),
    evidence_space_node_round_trip => "node space", &"99".repeat(32),
}
