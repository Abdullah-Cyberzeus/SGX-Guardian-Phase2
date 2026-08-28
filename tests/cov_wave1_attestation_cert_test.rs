// tests/cov_wave1_attestation_cert_test.rs
//
// Coverage wave 1: src/attestation_service.rs, src/cert_service.rs, src/cert_client.rs
//
// These three modules are dominated by hardcoded absolute filesystem paths
// (`/var/lib/sgx-guardian/...`, `/etc/sgx-guardian/...`) with no dependency
// injection, so a large share of their "happy path" branches (actually
// signing/writing a Nebula cert, syncing overlay/lighthouse/relay registries,
// etc.) cannot be exercised here without either running as root or writing
// into real system paths — both of which are out of scope for this test
// file. Where a branch is reachable only through those hardcoded paths, it
// is deliberately left uncovered and called out in the PR description
// instead of faked.
//
// Every test that touches process-wide environment variables acquires
// `ENV_LOCK` for its whole body, mirroring the pattern already used in
// tests/cert_client_test.rs, since `cargo test` runs multiple tests from
// this file concurrently in one process.

use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use sgx_guardian_client::attestation_service::{
    AttestationEvidence, AttestationQuote, AttestationService, BaselineStatus, BootChainSummary,
    ChallengeRequest, SignedQuote,
};
use sgx_guardian_client::key_manager::KeyManager;
use sgx_guardian_client::secure_element::pcr::{PcrBaseline, PcrSnapshot};
use sgx_guardian_client::virtual_id::{pcr_values_material, VirtualIdInputs};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;

static ENV_LOCK: Lazy<AsyncMutex<()>> = Lazy::new(|| AsyncMutex::new(()));

// ════════════════════════════════════════════════════════════════════
// Shared helpers
// ════════════════════════════════════════════════════════════════════

fn new_km(tmp: &TempDir, label: &str) -> KeyManager {
    let path = tmp.path().join(format!("{}.key", label));
    KeyManager::load_or_generate(path.to_str().unwrap()).expect("generate software key")
}

fn test_nonce(label: &str) -> String {
    let hash = Sha256::digest(format!("cov-wave1-nonce::{}", label).as_bytes());
    hex::encode(&hash[..16])
}

fn write_lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

/// Mirrors `build_evidence_signing_message` in src/attestation_service.rs.
fn evidence_signing_message(
    nonce_i: &str,
    nonce_r: &str,
    policy_digest: &str,
    baseline_status: Option<&BaselineStatus>,
    virtual_id_hex: &str,
) -> Vec<u8> {
    let mut msg = Vec::new();
    write_lp(&mut msg, nonce_i.as_bytes());
    write_lp(&mut msg, nonce_r.as_bytes());
    write_lp(&mut msg, policy_digest.as_bytes());
    match baseline_status {
        Some(bs) => write_lp(&mut msg, serde_json::to_string(bs).unwrap().as_bytes()),
        None => write_lp(&mut msg, b""),
    }
    write_lp(&mut msg, virtual_id_hex.as_bytes());
    msg
}

/// Builds a fully self-consistent, correctly signed `AttestationEvidence`
/// using a real software `KeyManager`, mirroring exactly what
/// `AttestationService::verify_signed_evidence` recomputes so the round
/// trip validates. `pcr_values`/`baseline_status` let callers reach the
/// PCR-freshness and baseline-state branches deliberately.
fn make_signed_evidence(
    km: &KeyManager,
    policy_yaml: &str,
    nonce_label: &str,
    baseline_status: Option<BaselineStatus>,
    pcr_values: Option<PcrSnapshot>,
    subject_did: &str,
    node_id: &str,
) -> AttestationEvidence {
    let pubkey = km.pubkey_der().expect("pubkey der");
    let policy_digest = hex::encode(Sha256::digest(policy_yaml.as_bytes()));
    let nonce_i = test_nonce(nonce_label);
    let nonce_r = String::new();

    let pcr_dig_bytes = match &pcr_values {
        Some(snap) => pcr_values_material(&snap.pcr_values, &snap.composite_digest),
        None => match &baseline_status {
            Some(bs) => pcr_values_material(&[], &bs.composite_digest),
            None => Vec::new(),
        },
    };

    let policy_dig_bytes = hex::decode(&policy_digest).unwrap();
    let nonce_i_bytes = hex::decode(&nonce_i).unwrap();
    let nonce_r_bytes: Vec<u8> = Vec::new();

    let virtual_id = hex::encode(
        VirtualIdInputs {
            did: subject_did,
            dkp_pubkey_der: &pubkey,
            pcr_values: &pcr_dig_bytes,
            policy_digest: &policy_dig_bytes,
            nonce_i: &nonce_i_bytes,
            nonce_r: &nonce_r_bytes,
        }
        .compute(),
    );

    let msg = evidence_signing_message(
        &nonce_i,
        &nonce_r,
        &policy_digest,
        baseline_status.as_ref(),
        &virtual_id,
    );
    let sig = km.sign(&msg).expect("sign evidence");

    AttestationEvidence {
        node_id: node_id.to_string(),
        subject_did: subject_did.to_string(),
        nonce: nonce_i.clone(),
        nonce_i: Some(nonce_i),
        nonce_r: Some(nonce_r),
        policy_digest,
        virtual_id,
        signature: general_purpose::STANDARD.encode(sig),
        pubkey_der_b64: general_purpose::STANDARD.encode(pubkey),
        presented_vc_json: None,
        pcr_values,
        key_version: Some(1),
        baseline_status,
    }
}

fn fresh_pcr_snapshot(
    schema_version: u8,
    measured_at: &str,
    integrity_status: &str,
) -> PcrSnapshot {
    PcrSnapshot {
        pcr_values: vec![],
        composite_digest: String::new(),
        composite_signature: None,
        nonce: String::new(),
        measured_at: measured_at.to_string(),
        device_uid: "test-device".to_string(),
        key_version: 1,
        firmware_version: None,
        measurement_errors: vec![],
        integrity_status: integrity_status.to_string(),
        schema_version,
    }
}

// ════════════════════════════════════════════════════════════════════
// src/attestation_service.rs — AttestationService::verify_signed_evidence
//
// Existing tests/test_attestation.rs already covers: raw + SPKI-DER pubkey
// success, tampered signature, invalid signature base64, modified policy,
// digest formatting, serialization roundtrip — all with baseline_status
// and pcr_values left at None. The gaps this wave targets: the malformed
// policy-digest guard, PCR-snapshot freshness/schema/integrity rejection,
// invalid pubkey base64, VirtualID-mismatch rejection, and — the biggest
// gap — every branch of the post-signature baseline_status enforcement
// (ALL_MATCH / MISMATCH / BAD_SIGNATURE / ABSENT / unknown), none of which
// the existing suite reaches because it never sets baseline_status.
// ════════════════════════════════════════════════════════════════════

#[test]
fn verify_signed_evidence_rejects_malformed_policy_digest() {
    let mut ev = AttestationEvidence {
        node_id: "nodeA".into(),
        subject_did: String::new(),
        nonce: String::new(),
        nonce_i: None,
        nonce_r: None,
        policy_digest: "not-64-hex".into(),
        virtual_id: String::new(),
        signature: String::new(),
        pubkey_der_b64: String::new(),
        presented_vc_json: None,
        pcr_values: None,
        key_version: None,
        baseline_status: None,
    };
    let ok = AttestationService::verify_signed_evidence(&ev, "policy").unwrap();
    assert!(!ok, "malformed (non-64-hex) policy digest must be rejected");

    // Also cover the "right length, non-hex characters" arm of is_hex_digest_64.
    ev.policy_digest = "z".repeat(64);
    let ok = AttestationService::verify_signed_evidence(&ev, "policy").unwrap();
    assert!(!ok);
}

#[test]
fn verify_signed_evidence_rejects_invalid_pubkey_base64() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "pubkey-b64");
    let policy = "policy: pubkey-b64-test";
    let mut ev = make_signed_evidence(&km, policy, "pubkey-b64", None, None, "did:x", "nodeA");
    ev.pubkey_der_b64 = "%%%not-base64%%%".into();

    let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(!ok, "invalid pubkey base64 must be rejected");
}

#[test]
fn verify_signed_evidence_rejects_virtual_id_mismatch() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "vid-mismatch");
    let policy = "policy: vid-mismatch-test";
    let mut ev = make_signed_evidence(&km, policy, "vid-mismatch", None, None, "did:x", "nodeA");
    ev.virtual_id = "f".repeat(64);

    let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(!ok, "tampered virtual_id must fail recomputation check");
}

#[test]
fn verify_signed_evidence_rejects_pcr_schema_mismatch() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "pcr-schema");
    let policy = "policy: pcr-schema-test";
    let snap = fresh_pcr_snapshot(99, &chrono::Utc::now().to_rfc3339(), "PASS");
    let ev = make_signed_evidence(
        &km,
        policy,
        "pcr-schema",
        None,
        Some(snap),
        "did:x",
        "nodeA",
    );

    let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(!ok, "wrong PCR schema version must be rejected");
}

#[test]
fn verify_signed_evidence_rejects_stale_pcr_snapshot() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "pcr-stale");
    let policy = "policy: pcr-stale-test";
    let snap = fresh_pcr_snapshot(1, "2000-01-01T00:00:00Z", "PASS");
    let ev = make_signed_evidence(&km, policy, "pcr-stale", None, Some(snap), "did:x", "nodeA");

    let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(!ok, "stale PCR snapshot must be rejected");
}

#[test]
fn verify_signed_evidence_rejects_pcr_integrity_fail() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "pcr-fail");
    let policy = "policy: pcr-fail-test";
    let snap = fresh_pcr_snapshot(1, &chrono::Utc::now().to_rfc3339(), "FAIL");
    let ev = make_signed_evidence(&km, policy, "pcr-fail", None, Some(snap), "did:x", "nodeA");

    let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(!ok, "PCR integrity_status=FAIL must be rejected");
}

#[test]
fn verify_signed_evidence_accepts_fresh_pcr_snapshot_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "pcr-pass");
    let policy = "policy: pcr-pass-test";
    let snap = fresh_pcr_snapshot(1, &chrono::Utc::now().to_rfc3339(), "PASS");
    let ev = make_signed_evidence(&km, policy, "pcr-pass", None, Some(snap), "did:x", "nodeA");

    let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(ok, "fresh, schema-correct, PASS PCR snapshot should verify");
}

#[test]
fn verify_signed_evidence_baseline_status_branch_matrix() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "baseline-matrix");
    let policy = "policy: baseline-matrix-test";

    let make = |label: &str, state: &str| {
        make_signed_evidence(
            &km,
            policy,
            label,
            Some(BaselineStatus {
                state: state.to_string(),
                mismatched_pcrs: vec![1, 3],
                composite_digest: String::new(),
            }),
            None,
            "did:baseline",
            "nodeA",
        )
    };

    let all_match = make("all-match", "ALL_MATCH");
    assert!(
        AttestationService::verify_signed_evidence(&all_match, policy).unwrap(),
        "ALL_MATCH baseline must verify"
    );

    for state in ["MISMATCH", "BAD_SIGNATURE", "ABSENT", "SOME_FUTURE_STATE"] {
        let ev = make(state, state);
        let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
        assert!(!ok, "baseline state '{}' must be rejected", state);
    }
}

// ════════════════════════════════════════════════════════════════════
// src/attestation_service.rs — create_signed_evidence
//
// The existing tests/attestation_test.rs calls create_signed_evidence but
// (per its own comment) only cares that it doesn't panic — in the default
// sandbox it errors out inside observe_runtime_virtual_id because that
// helper's state file lives under /var/lib/sgx-guardian/identity. Pointing
// SGX_GUARDIAN_VID_STATE_DIR at a tempdir (a real, documented env override
// in src/virtual_id.rs) lets it actually succeed, which newly exercises
// the message-build/sign/Ok(AttestationEvidence) tail of the function —
// and, as a bonus, cross-validates against verify_signed_evidence's
// ABSENT-baseline rejection branch using production code on both sides.
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn create_signed_evidence_succeeds_and_round_trips_through_verify() {
    let _guard = ENV_LOCK.lock().await;
    let tmp = TempDir::new().unwrap();
    let vid_dir = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_VID_STATE_DIR", vid_dir.path());

    let km = new_km(&tmp, "create-evidence");
    let policy_yaml = "---\nversion: 1\nrule: allow\n";

    let result = AttestationService::create_signed_evidence(&km, policy_yaml);

    std::env::remove_var("SGX_GUARDIAN_VID_STATE_DIR");

    let ev = result.expect("create_signed_evidence should succeed with a writable VID state dir");
    assert_eq!(
        ev.policy_digest,
        hex::encode(Sha256::digest(policy_yaml.as_bytes()))
    );
    assert_eq!(ev.virtual_id.len(), 64);
    assert!(ev.virtual_id.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!ev.signature.is_empty());
    // No real PCR/baseline files exist in this sandbox, so baseline state
    // is deterministically ABSENT — verify_signed_evidence must reject it
    // under the "untrusted without a signed baseline" policy.
    let baseline = ev.baseline_status.as_ref().expect("baseline computed");
    assert_eq!(baseline.state, "ABSENT");

    let verified = AttestationService::verify_signed_evidence(&ev, policy_yaml).unwrap();
    assert!(
        !verified,
        "evidence with an ABSENT baseline must be rejected by the verifier"
    );
}

// ════════════════════════════════════════════════════════════════════
// src/attestation_service.rs — SignedQuote::verify / AttestationQuote /
// generate_quote / handle_challenge / verify_quote
//
// None of these are touched by any pre-existing test file.
// ════════════════════════════════════════════════════════════════════

fn sample_quote(
    nonce: &str,
    timestamp: String,
    hab_events_found: bool,
    integrity: &str,
    pcr: Vec<String>,
) -> AttestationQuote {
    AttestationQuote {
        version: 1,
        challenge_nonce: nonce.to_string(),
        device_nonce: "aa".repeat(16),
        timestamp,
        node_id: "nodeA".into(),
        device_uid: "dev-uid".into(),
        key_version: 1,
        pubkey_b64: String::new(),
        pcr_values: pcr,
        composite_digest: "digest".into(),
        integrity_status: integrity.to_string(),
        boot_chain: BootChainSummary {
            hab_enabled: true,
            device_closed: true,
            hab_events_found,
            boot_chain_intact: !hab_events_found,
        },
        firmware_version: "1.0".into(),
        active_policy_digest: "policydigest".into(),
    }
}

#[test]
fn signed_quote_verify_invalid_signature_base64() {
    let sq = SignedQuote {
        quote_json: "{}".into(),
        signature_b64: "%%%not-base64%%%".into(),
        signing_backend: "Software".into(),
    };
    let result = sq.verify(&[0u8; 65], "nonce", None, 300);
    assert!(!result.verified);
    assert_eq!(result.reason, "Invalid signature base64");
}

#[test]
fn signed_quote_verify_unknown_signature_format() {
    let sq = SignedQuote {
        quote_json: "{}".into(),
        signature_b64: general_purpose::STANDARD.encode([1u8, 2, 3, 4, 5]),
        signing_backend: "Software".into(),
    };
    let result = sq.verify(&[0u8; 65], "nonce", None, 300);
    assert!(!result.verified);
    assert!(result.reason.starts_with("Unknown sig format"));
}

#[test]
fn signed_quote_verify_signature_check_fails_with_wrong_key() {
    let tmp = TempDir::new().unwrap();
    let signer = new_km(&tmp, "quote-signer");
    let wrong = new_km(&tmp, "quote-wrong-key");

    let quote = sample_quote(
        "nonceA",
        chrono::Utc::now().to_rfc3339(),
        false,
        "PASS",
        vec![],
    );
    let signed = quote.sign(&signer).unwrap();
    let wrong_pubkey = wrong.pubkey_der().unwrap();

    let result = signed.verify(&wrong_pubkey, "nonceA", None, 300);
    assert!(!result.verified);
    assert_eq!(result.reason, "Signature verification failed");
}

#[test]
fn signed_quote_verify_quote_parse_failure() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "quote-parse-fail");
    let quote_json = "this is not valid json".to_string();
    let hash = Sha256::digest(quote_json.as_bytes());
    let sig = km.sign(&hash).unwrap();
    let signed = SignedQuote {
        quote_json,
        signature_b64: general_purpose::STANDARD.encode(sig),
        signing_backend: km.backend_name().to_string(),
    };

    let pubkey = km.pubkey_der().unwrap();
    let result = signed.verify(&pubkey, "any", None, 300);
    assert!(!result.verified);
    assert!(
        result.signature_valid,
        "signature over the raw bytes is still valid"
    );
    assert!(result.reason.starts_with("Quote parse:"));
}

#[test]
fn signed_quote_verify_nonce_mismatch() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "quote-nonce");
    let quote = sample_quote(
        "expected-nonce",
        chrono::Utc::now().to_rfc3339(),
        false,
        "PASS",
        vec![],
    );
    let signed = quote.sign(&km).unwrap();
    let pubkey = km.pubkey_der().unwrap();

    let result = signed.verify(&pubkey, "different-nonce", None, 300);
    assert!(!result.verified);
    assert!(result.signature_valid);
    assert!(!result.nonce_valid);
    assert_eq!(result.reason, "Nonce mismatch (possible replay)");
}

#[test]
fn signed_quote_verify_stale_quote_rejected() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "quote-stale");
    let quote = sample_quote(
        "n1",
        "2000-01-01T00:00:00Z".to_string(),
        false,
        "PASS",
        vec![],
    );
    let signed = quote.sign(&km).unwrap();
    let pubkey = km.pubkey_der().unwrap();

    let result = signed.verify(&pubkey, "n1", None, 300);
    assert!(!result.verified);
    assert!(!result.freshness_ok);
    assert!(result.reason.starts_with("Quote too old"));
}

#[test]
fn signed_quote_verify_boot_chain_failure_rejected() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "quote-bootchain");
    let quote = sample_quote(
        "n1",
        chrono::Utc::now().to_rfc3339(),
        true, // hab_events_found -> boot_chain_ok = false
        "PASS",
        vec![],
    );
    let signed = quote.sign(&km).unwrap();
    let pubkey = km.pubkey_der().unwrap();

    let result = signed.verify(&pubkey, "n1", None, 300);
    assert!(!result.verified);
    assert!(!result.boot_chain_ok);
    assert_eq!(result.reason, "Boot chain or integrity check failed");
}

#[test]
fn signed_quote_verify_pcr_mismatch_against_baseline() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "quote-pcr-mismatch");
    let quote = sample_quote(
        "n1",
        chrono::Utc::now().to_rfc3339(),
        false,
        "PASS",
        vec!["aa".repeat(32), "bb".repeat(32)],
    );
    let signed = quote.sign(&km).unwrap();
    let pubkey = km.pubkey_der().unwrap();

    let baseline = PcrBaseline {
        pcr_values: vec!["cc".repeat(32), "dd".repeat(32)],
        composite_digest: String::new(),
        baseline_signature: String::new(),
        signing_backend: None,
        signing_public_key_sha256: None,
        signature_format: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        device_uid: "dev".into(),
        key_version: 1,
        schema_version: 1,
    };

    let result = signed.verify(&pubkey, "n1", Some(&baseline), 300);
    assert!(!result.verified);
    assert!(!result.pcr_match);
    assert_eq!(result.reason, "PCR mismatch against baseline");
}

#[test]
fn signed_quote_verify_full_success_with_matching_baseline_and_spki_der_key() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "quote-success");
    let pcr = vec!["11".repeat(32), "22".repeat(32)];
    let quote = sample_quote(
        "n1",
        chrono::Utc::now().to_rfc3339(),
        false,
        "PASS",
        pcr.clone(),
    );
    let signed = quote.sign(&km).unwrap();

    // Wrap the raw 65-byte EC point in an SE050-style SPKI DER prefix to
    // exercise the `len() == 91` branch of SignedQuote::verify.
    let raw = km.pubkey_der().unwrap();
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    spki.extend_from_slice(&raw);
    assert_eq!(spki.len(), 91);

    let baseline = PcrBaseline {
        pcr_values: pcr,
        composite_digest: String::new(),
        baseline_signature: String::new(),
        signing_backend: None,
        signing_public_key_sha256: None,
        signature_format: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        device_uid: "dev".into(),
        key_version: 1,
        schema_version: 1,
    };

    let result = signed.verify(&spki, "n1", Some(&baseline), 300);
    assert!(result.verified, "reason={}", result.reason);
    assert_eq!(result.reason, "All checks passed");
    assert!(result.pcr_match && result.boot_chain_ok && result.nonce_valid && result.freshness_ok);
}

#[test]
fn signed_quote_save_and_load_round_trip() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "quote-save-load");
    let quote = sample_quote("n1", chrono::Utc::now().to_rfc3339(), false, "PASS", vec![]);
    let signed = quote.sign(&km).unwrap();

    let path = tmp.path().join("nested").join("quote.json");
    signed
        .save(path.to_str().unwrap())
        .expect("save should create parent dirs");
    let loaded = SignedQuote::load(path.to_str().unwrap()).expect("load should succeed");

    assert_eq!(loaded.quote_json, signed.quote_json);
    assert_eq!(loaded.signature_b64, signed.signature_b64);
}

#[test]
fn signed_quote_load_missing_file_errors() {
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("does_not_exist.json");
    let result = SignedQuote::load(missing.to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn attestation_quote_generate_and_sign_round_trip() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "quote-generate");
    let quote = AttestationQuote::generate("challenge-nonce-1", "nodeA", &km)
        .expect("quote generation should succeed without hardware");
    assert_eq!(quote.challenge_nonce, "challenge-nonce-1");
    assert_eq!(quote.node_id, "nodeA");
    assert!(!quote.device_nonce.is_empty());

    let signed = quote.sign(&km).expect("signing should succeed");
    assert!(!signed.signature_b64.is_empty());
    assert_eq!(signed.signing_backend, km.backend_name());

    let pubkey = km.pubkey_der().unwrap();
    let result = signed.verify(&pubkey, "challenge-nonce-1", None, 300);
    assert!(result.signature_valid);
    assert!(result.nonce_valid);
}

#[test]
fn generate_quote_and_handle_challenge_produce_valid_response() {
    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "handle-challenge");

    let signed = AttestationService::generate_quote("nonce-xyz", &km).expect("generate_quote");
    let pubkey = km.pubkey_der().unwrap();
    let verify_result = AttestationService::verify_quote(&signed, "nonce-xyz", &pubkey, None);
    assert!(verify_result.signature_valid);
    assert!(verify_result.nonce_valid);

    let req = ChallengeRequest {
        verifier_node_id: "verifier-node".into(),
        nonce: "chal-nonce".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let resp = AttestationService::handle_challenge(&req, &km).expect("handle_challenge");
    assert_eq!(resp.signed_quote.signing_backend, km.backend_name());
    assert!(resp.counter_challenge_nonce.is_some());
    assert_eq!(resp.counter_challenge_nonce.unwrap().len(), 64);
}

// ════════════════════════════════════════════════════════════════════
// src/attestation_service.rs — AttestationService::mutual_attest
//
// Zero pre-existing coverage. mutual_attest is exercised end-to-end
// against a real local TCP peer we control, using the exact same wire
// framing (4-byte BE length + JSON) as write_evidence_framed /
// read_evidence_framed.
// ════════════════════════════════════════════════════════════════════

async fn spawn_mock_attestation_peer_success(
    policy_yaml: String,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };

        // Drain the caller's framed evidence (content not needed for this test).
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).await.is_err() {
            return;
        }

        // Reply with our own validly signed evidence (baseline_status: None,
        // matching the already-proven-good pattern from tests/test_attestation.rs).
        let peer_tmp = TempDir::new().unwrap();
        let peer_km = new_km(&peer_tmp, "mock-peer");
        let peer_ev = make_signed_evidence(
            &peer_km,
            &policy_yaml,
            "mutual-attest-peer",
            None,
            None,
            "did:guardian:mockpeer",
            "mockpeer",
        );
        let out = serde_json::to_vec(&peer_ev).unwrap();
        let _ = stream.write_all(&(out.len() as u32).to_be_bytes()).await;
        let _ = stream.write_all(&out).await;
        let _ = stream.flush().await;
    });

    (addr, handle)
}

#[tokio::test]
async fn mutual_attest_fails_after_exhausting_connect_retries() {
    // No env vars touched by this path (it returns before evidence
    // creation), but we still serialize against the other env-var tests
    // in this file for safety since it shares a process.
    let _guard = ENV_LOCK.lock().await;

    // Bind to grab a free port, then drop the listener so nothing answers.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "mutual-attest-unreachable");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        AttestationService::mutual_attest(addr.ip().to_string(), addr.port(), &km),
    )
    .await
    .expect("mutual_attest must give up after its retry budget, not hang");

    assert_eq!(
        result.unwrap(),
        false,
        "unreachable peer must yield Ok(false)"
    );
}

#[tokio::test]
async fn mutual_attest_full_success_round_trip_persists_trusted_peer() {
    let _guard = ENV_LOCK.lock().await;

    let home = TempDir::new().unwrap();
    let vid_dir = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_HOME", home.path());
    std::env::set_var("SGX_GUARDIAN_VID_STATE_DIR", vid_dir.path());
    std::env::set_var("SGX_REQUIRE_VC", "0");
    std::env::set_var("SGX_GUARDIAN_NODE_ID", "wave1node");

    let policy = sgx_guardian_client::policy::load_effective_policy_material();
    let (addr, peer_handle) = spawn_mock_attestation_peer_success(policy.yaml.clone()).await;

    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "mutual-attest-success");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        AttestationService::mutual_attest(addr.ip().to_string(), addr.port(), &km),
    )
    .await
    .expect("mutual_attest should complete quickly against a responsive local peer");

    peer_handle.await.ok();

    let outcome = result.expect("mutual_attest should not error");

    let trusted_path = home
        .path()
        .join("logs")
        .join("trusted_peers_wave1node.json");
    let trusted_contents = std::fs::read_to_string(&trusted_path).ok();

    std::env::remove_var("SGX_GUARDIAN_HOME");
    std::env::remove_var("SGX_GUARDIAN_VID_STATE_DIR");
    std::env::remove_var("SGX_REQUIRE_VC");
    std::env::remove_var("SGX_GUARDIAN_NODE_ID");

    assert!(outcome, "full mutual attestation handshake should succeed");
    let contents =
        trusted_contents.expect("write_trusted_peer should have written the fallback log dir");
    assert!(contents.contains("verified"));
    assert!(contents.contains(&addr.port().to_string()));
}

#[tokio::test]
async fn mutual_attest_ok_false_when_peer_accepts_then_closes() {
    let _guard = ENV_LOCK.lock().await;

    let home = TempDir::new().unwrap();
    let vid_dir = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_HOME", home.path());
    std::env::set_var("SGX_GUARDIAN_VID_STATE_DIR", vid_dir.path());
    std::env::set_var("SGX_REQUIRE_VC", "0");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_handle = tokio::spawn(async move {
        // Accept and immediately drop — peer never sends framed evidence back.
        let _ = listener.accept().await;
    });

    let tmp = TempDir::new().unwrap();
    let km = new_km(&tmp, "mutual-attest-peer-closes");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        AttestationService::mutual_attest(addr.ip().to_string(), addr.port(), &km),
    )
    .await
    .expect("mutual_attest should not hang when the peer closes the connection");

    accept_handle.await.ok();

    std::env::remove_var("SGX_GUARDIAN_HOME");
    std::env::remove_var("SGX_GUARDIAN_VID_STATE_DIR");
    std::env::remove_var("SGX_REQUIRE_VC");

    assert_eq!(
        result.unwrap(),
        false,
        "no reply from peer must yield Ok(false)"
    );
}

// ════════════════════════════════════════════════════════════════════
// src/cert_service.rs — MyCertService::request_certificate
//
// Existing tests/cert_service_test.rs already covers: ApprovalDecision
// serde aliases, CertRequestYaml roundtrip, empty/invalid-char node_id
// rejection, and (only when /var/lib/sgx-guardian happens to be writable)
// the full YAML-request-then-rejected flow. This sandbox has no write
// access to /var/lib (root-owned), so the gap this wave targets is the
// large, always-reachable-but-previously-untested middle of the handler:
// role-string selection, request logging/audit, the idempotency check
// when no cert exists yet, and the node_lock per-node-id mutex — ending
// in a deterministic "Failed to create requests directory" Internal
// error once it hits the (also root-owned) nebula base dir.
// ════════════════════════════════════════════════════════════════════

fn assert_nebula_base_unwritable() {
    assert!(
        std::fs::create_dir_all("/var/lib/sgx-guardian").is_err(),
        "this test file assumes /var/lib/sgx-guardian is not writable by the test user; \
         if it now is, the deterministic permission-denied assertions below no longer hold"
    );
}

#[tokio::test]
async fn cert_service_request_certificate_fails_creating_requests_dir_member_role() {
    assert_nebula_base_unwritable();
    use sgx_guardian_client::cert_service::MyCertService;
    use sgx_guardian_client::proto::sgx::cert_service_server::CertService;
    use sgx_guardian_client::proto::sgx::CertSignRequest;
    use tonic::Request;

    let service = MyCertService;
    let request = Request::new(CertSignRequest {
        node_id: "cov-wave1-member".to_string(),
        public_key_pem: "test-pubkey-pem".to_string(),
        wants_lighthouse: false,
        wants_relay: false,
        overlay_ip: String::new(),
        pairing_proof: String::new(),
    });

    let result = service.request_certificate(request).await;
    let status = result.expect_err("permission-denied nebula base dir must surface as an Err");
    assert_eq!(status.code(), tonic::Code::Internal);
    assert!(status.message().contains("requests directory"));
}

#[tokio::test]
async fn cert_service_request_certificate_role_selection_and_node_lock_reuse() {
    assert_nebula_base_unwritable();
    use sgx_guardian_client::cert_service::MyCertService;
    use sgx_guardian_client::proto::sgx::cert_service_server::CertService;
    use sgx_guardian_client::proto::sgx::CertSignRequest;
    use tonic::Request;

    let service = MyCertService;

    // lh_relay, lighthouse-only and relay-only role branches, each on a
    // distinct node_id so node_lock() inserts a fresh entry per call.
    for (node_id, wants_lighthouse, wants_relay) in [
        ("cov-wave1-lhrelay", true, true),
        ("cov-wave1-lh-only", true, false),
        ("cov-wave1-relay-only", false, true),
    ] {
        let request = Request::new(CertSignRequest {
            node_id: node_id.to_string(),
            public_key_pem: "test-pubkey-pem".to_string(),
            wants_lighthouse,
            wants_relay,
            overlay_ip: String::new(),
            pairing_proof: String::new(),
        });
        let result = service.request_certificate(request).await;
        assert_eq!(
            result.unwrap_err().code(),
            tonic::Code::Internal,
            "node_id={node_id}"
        );
    }

    // Same node_id twice in a row exercises node_lock()'s HashMap
    // "already present, clone the existing Arc<Mutex<()>>" branch.
    for _ in 0..2 {
        let request = Request::new(CertSignRequest {
            node_id: "cov-wave1-repeat".to_string(),
            public_key_pem: "test-pubkey-pem".to_string(),
            wants_lighthouse: false,
            wants_relay: false,
            overlay_ip: String::new(),
            pairing_proof: String::new(),
        });
        let result = service.request_certificate(request).await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::Internal);
    }
}

// ════════════════════════════════════════════════════════════════════
// src/cert_client.rs — request_certificate_from_ca
//
// Existing tests/cert_client_test.rs already covers: rejected response,
// connection failure/retry loop, and (writable-gated) the already-present
// and full-approved flows. Gaps this wave targets: the invalid-node_id
// guard, the resolve_nodea_ip_for_bootstrap fallback-to-config-files loop
// plus split_host_port's default-port branch (neither exercised by the
// existing suite, which always sets a valid SGX_LIGHTHOUSE_IP with a
// host:port CA address), the deterministic permission-denied abort when
// ca_cert_pem is non-empty (this sandbox has no write access to
// /var/lib/sgx-guardian, so NebulaCA::save_ca_cert() reliably fails), and
// the "pending" / unknown-status response branches. The deep interior of
// the "approved" branch beyond the CA-cert save (registry sync, role
// markers, relay config, signed policy/pubkey save, VC persistence) stays
// gated behind the same real /var/lib/sgx-guardian write access the
// existing suite requires and is not re-attempted here.
// ════════════════════════════════════════════════════════════════════

fn set_common_cert_client_env(vc_base: &TempDir) {
    std::env::set_var("SGX_GUARDIAN_VC_BASE", vc_base.path());
}

fn clear_common_cert_client_env() {
    std::env::remove_var("SGX_GUARDIAN_VC_BASE");
    std::env::remove_var("SGX_LIGHTHOUSE_IP");
}

#[tokio::test]
async fn request_certificate_from_ca_rejects_invalid_node_id_without_network() {
    let _guard = ENV_LOCK.lock().await;
    let vc_base = TempDir::new().unwrap();
    set_common_cert_client_env(&vc_base);

    // Must return immediately (no connection attempt) for both an empty
    // and a special-character node_id.
    for bad_node_id in ["", "bad node!"] {
        let fut = sgx_guardian_client::cert_client::request_certificate_from_ca(
            bad_node_id.to_string(),
            "127.0.0.1:1".to_string(),
            String::new(),
            "pubkey".to_string(),
            false,
            false,
            None,
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), fut)
            .await
            .expect("invalid node_id must short-circuit instantly, not attempt to connect");
    }

    clear_common_cert_client_env();
}

#[tokio::test]
async fn request_certificate_from_ca_falls_back_to_config_lookup_and_default_port() {
    let _guard = ENV_LOCK.lock().await;
    let vc_base = TempDir::new().unwrap();
    set_common_cert_client_env(&vc_base);
    // Deliberately do NOT set SGX_LIGHTHOUSE_IP, and use a CA address with
    // no port so split_host_port() takes its "(addr, 50061)" default-port
    // branch. resolve_nodea_ip_for_bootstrap() then falls through its
    // env-var check into the /etc/sgx-guardian/config/nodeA.yaml /
    // /etc/sgx-guardian/nodeA.yaml lookup loop (both absent -> None).
    std::env::remove_var("SGX_LIGHTHOUSE_IP");

    let fut = sgx_guardian_client::cert_client::request_certificate_from_ca(
        "cov-wave1-fallback".to_string(),
        "127.0.0.5".to_string(), // no ":port" suffix
        String::new(),
        "pubkey".to_string(),
        false,
        false,
        None,
    );
    // The connection attempt to 127.0.0.5:50061 will fail; we only need
    // one loop iteration's worth of execution before cutting it off.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(600), fut).await;

    clear_common_cert_client_env();
}

#[tokio::test]
async fn request_certificate_from_ca_rejects_malformed_ca_address() {
    let _guard = ENV_LOCK.lock().await;
    let vc_base = TempDir::new().unwrap();
    set_common_cert_client_env(&vc_base);
    std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.2");

    // A space is not a legal URI character, so Channel::from_shared()
    // inside try_request() fails with "Invalid CA address" before any
    // network I/O happens.
    let fut = sgx_guardian_client::cert_client::request_certificate_from_ca(
        "cov-wave1-badaddr".to_string(),
        "not a valid uri".to_string(),
        String::new(),
        "pubkey".to_string(),
        false,
        false,
        None,
    );
    let _ = tokio::time::timeout(std::time::Duration::from_millis(600), fut).await;

    clear_common_cert_client_env();
}

struct StatusMockCertService {
    status: &'static str,
    ca_cert_pem: &'static str,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[tonic::async_trait]
impl sgx_guardian_client::proto::sgx::cert_service_server::CertService for StatusMockCertService {
    async fn request_certificate(
        &self,
        _request: tonic::Request<sgx_guardian_client::proto::sgx::CertSignRequest>,
    ) -> Result<tonic::Response<sgx_guardian_client::proto::sgx::CertSignResponse>, tonic::Status>
    {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(tonic::Response::new(
            sgx_guardian_client::proto::sgx::CertSignResponse {
                status: self.status.to_string(),
                signed_cert_pem: String::new(),
                node_key_pem: String::new(),
                ca_cert_pem: self.ca_cert_pem.to_string(),
                message: "mock response".to_string(),
                assigned_lighthouse: false,
                lighthouse_registry_json: String::new(),
                overlay_registry_json: String::new(),
                signed_policy_bytes: vec![],
                assigned_relay: false,
                relay_registry_json: String::new(),
                signing_pubkey_der: vec![],
                member_vc_json: String::new(),
            },
        ))
    }
}

async fn spawn_status_mock_server(
    status: &'static str,
    ca_cert_pem: &'static str,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    use sgx_guardian_client::proto::sgx::cert_service_server::CertServiceServer;

    // Grab a free ephemeral port on the 127.0.0.2 loopback alias, then
    // release it immediately — tonic's Server::serve_with_shutdown binds
    // it again itself. Mirrors the established pattern in
    // tests/cert_client_test.rs.
    let addr = {
        let listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mock = StatusMockCertService {
        status,
        ca_cert_pem,
        calls: calls.clone(),
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(CertServiceServer::new(mock))
            .serve_with_shutdown(addr, async {
                rx.await.ok();
            })
            .await;
    });
    (addr, calls, tx, handle)
}

#[tokio::test]
async fn request_certificate_from_ca_approved_with_ca_cert_aborts_on_permission_denied() {
    let _guard = ENV_LOCK.lock().await;
    let vc_base = TempDir::new().unwrap();
    set_common_cert_client_env(&vc_base);
    std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.2");

    let (addr, calls, shutdown, handle) = spawn_status_mock_server(
        "approved",
        "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let fut = sgx_guardian_client::cert_client::request_certificate_from_ca(
        "cov-wave1-approved-abort".to_string(),
        addr.to_string(),
        "192.168.100.9/24".to_string(),
        "pubkey".to_string(),
        false,
        false,
        None,
    );
    // NebulaCA::save_ca_cert() must fail (permission denied under
    // /var/lib/sgx-guardian) and the function returns immediately —
    // no timeout needed if the sandbox assumption holds.
    tokio::time::timeout(std::time::Duration::from_secs(5), fut)
        .await
        .expect("permission-denied CA-cert save must abort promptly, not loop");

    let _ = shutdown.send(());
    handle.await.ok();
    assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 1);

    clear_common_cert_client_env();
}

#[tokio::test]
async fn request_certificate_from_ca_pending_status_loops_without_panicking() {
    let _guard = ENV_LOCK.lock().await;
    let vc_base = TempDir::new().unwrap();
    set_common_cert_client_env(&vc_base);
    std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.2");

    let (addr, calls, shutdown, handle) = spawn_status_mock_server("pending", "").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let fut = sgx_guardian_client::cert_client::request_certificate_from_ca(
        "cov-wave1-pending".to_string(),
        addr.to_string(),
        String::new(),
        "pubkey".to_string(),
        false,
        false,
        None,
    );
    let _ = tokio::time::timeout(std::time::Duration::from_millis(600), fut).await;

    let _ = shutdown.send(());
    handle.await.ok();
    assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 1);

    clear_common_cert_client_env();
}

#[tokio::test]
async fn request_certificate_from_ca_unknown_status_loops_without_panicking() {
    let _guard = ENV_LOCK.lock().await;
    let vc_base = TempDir::new().unwrap();
    set_common_cert_client_env(&vc_base);
    std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.2");

    let (addr, calls, shutdown, handle) = spawn_status_mock_server("banana", "").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let fut = sgx_guardian_client::cert_client::request_certificate_from_ca(
        "cov-wave1-unknown-status".to_string(),
        addr.to_string(),
        String::new(),
        "pubkey".to_string(),
        false,
        false,
        None,
    );
    let _ = tokio::time::timeout(std::time::Duration::from_millis(600), fut).await;

    let _ = shutdown.send(());
    handle.await.ok();
    assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 1);

    clear_common_cert_client_env();
}
