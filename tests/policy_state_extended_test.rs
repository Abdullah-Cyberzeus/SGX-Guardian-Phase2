// tests/policy_state_extended_test.rs
// Integration tests for uncovered branches in src/policy_state.rs
//
// NOTE: Tests that exercise activate_policy() / rollback_policy() use the
// public internal function `activate_policy_with_paths` indirectly via
// the src/policy_state module's private test helpers. Since the environment
// variable approach races under parallel test execution, we test the logic
// via the private path-based function exposed in the existing in-module tests,
// and add our own integration tests for the public API using a global mutex
// to serialize them.

use sha2::{Digest, Sha256};
use sgx_guardian_client::policy_state::{ensure_policy_dir, ActivationOutcome};
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

// Global mutex to prevent concurrent tests from stomping on each other via
// the SGX_GUARDIAN_POLICY_DIR env var (environment is process-wide).
static POLICY_ENV_LOCK: Mutex<()> = Mutex::new(());

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ── ensure_policy_dir ─────────────────────────────────────────────────────────

#[test]
fn test_ensure_policy_dir_creates_dir_if_missing() {
    let _lock = POLICY_ENV_LOCK.lock().unwrap();
    let td = TempDir::new().unwrap();
    let sub = td.path().join("policies-create-test");
    std::env::set_var("SGX_GUARDIAN_POLICY_DIR", sub.to_str().unwrap());

    assert!(!sub.exists());
    ensure_policy_dir().unwrap();
    assert!(sub.exists());

    std::env::remove_var("SGX_GUARDIAN_POLICY_DIR");
}

#[test]
fn test_ensure_policy_dir_idempotent_if_exists() {
    let _lock = POLICY_ENV_LOCK.lock().unwrap();
    let td = TempDir::new().unwrap();
    let dir = td.path().join("policies-exist");
    fs::create_dir_all(&dir).unwrap();
    std::env::set_var("SGX_GUARDIAN_POLICY_DIR", dir.to_str().unwrap());

    // Should not fail when directory already exists
    ensure_policy_dir().unwrap();
    assert!(dir.exists());

    std::env::remove_var("SGX_GUARDIAN_POLICY_DIR");
}

// ── current_active_policy_digest: None when no active file ───────────────────

#[test]
fn test_current_active_policy_digest_none_when_no_file() {
    let _lock = POLICY_ENV_LOCK.lock().unwrap();
    let td = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_POLICY_DIR", td.path().to_str().unwrap());

    // No active policy written → should return Ok(None)
    let result = sgx_guardian_client::policy_state::current_active_policy_digest().unwrap();
    assert!(result.is_none());

    std::env::remove_var("SGX_GUARDIAN_POLICY_DIR");
}

// ── activate + digest roundtrip ───────────────────────────────────────────────

#[test]
fn test_activate_policy_first_time_no_backup_roundtrip() {
    let _lock = POLICY_ENV_LOCK.lock().unwrap();
    let td = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_POLICY_DIR", td.path().to_str().unwrap());

    let yaml = "policy_id: first\nversion: \"1\"\nrules: []\n";
    let digest = sha256_hex(yaml);

    let outcome = sgx_guardian_client::policy_state::activate_policy(yaml, &digest).unwrap();

    match outcome {
        ActivationOutcome::Activated { backup_rotated } => {
            assert!(!backup_rotated, "No backup on first activation");
        }
        ActivationOutcome::Unchanged => panic!("Expected Activated, got Unchanged"),
    }

    // Verify digest is now current
    let current = sgx_guardian_client::policy_state::current_active_policy_digest()
        .unwrap()
        .unwrap();
    assert_eq!(current, digest);

    std::env::remove_var("SGX_GUARDIAN_POLICY_DIR");
}

#[test]
fn test_activate_policy_same_digest_is_unchanged() {
    let _lock = POLICY_ENV_LOCK.lock().unwrap();
    let td = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_POLICY_DIR", td.path().to_str().unwrap());

    let yaml = "policy_id: stable\nversion: \"1\"\nrules: []\n";
    let digest = sha256_hex(yaml);

    // First activation
    sgx_guardian_client::policy_state::activate_policy(yaml, &digest).unwrap();

    // Second activation with identical content → Unchanged
    let outcome = sgx_guardian_client::policy_state::activate_policy(yaml, &digest).unwrap();
    assert_eq!(outcome, ActivationOutcome::Unchanged);

    std::env::remove_var("SGX_GUARDIAN_POLICY_DIR");
}

#[test]
fn test_activate_policy_new_digest_rotates_backup() {
    let _lock = POLICY_ENV_LOCK.lock().unwrap();
    let td = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_POLICY_DIR", td.path().to_str().unwrap());

    let yaml_v1 = "policy_id: v1\nversion: \"1\"\nrules: []\n";
    let digest_v1 = sha256_hex(yaml_v1);

    // Activate v1 first
    sgx_guardian_client::policy_state::activate_policy(yaml_v1, &digest_v1).unwrap();

    // Now activate v2 with different content
    let yaml_v2 = "policy_id: v2\nversion: \"2\"\nrules: []\n";
    let digest_v2 = sha256_hex(yaml_v2);
    let outcome =
        sgx_guardian_client::policy_state::activate_policy(yaml_v2, &digest_v2).unwrap();

    match outcome {
        ActivationOutcome::Activated { backup_rotated } => {
            assert!(backup_rotated, "Backup should be rotated");
        }
        ActivationOutcome::Unchanged => panic!("Expected Activated, got Unchanged"),
    }

    std::env::remove_var("SGX_GUARDIAN_POLICY_DIR");
}

// ── rollback_policy ───────────────────────────────────────────────────────────

#[test]
fn test_rollback_policy_is_noop_when_no_backup() {
    let _lock = POLICY_ENV_LOCK.lock().unwrap();
    let td = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_POLICY_DIR", td.path().to_str().unwrap());

    // No backup — rollback should succeed silently
    sgx_guardian_client::policy_state::rollback_policy().unwrap();

    std::env::remove_var("SGX_GUARDIAN_POLICY_DIR");
}

#[test]
fn test_rollback_policy_restores_previous_active() {
    let _lock = POLICY_ENV_LOCK.lock().unwrap();
    let td = TempDir::new().unwrap();
    std::env::set_var("SGX_GUARDIAN_POLICY_DIR", td.path().to_str().unwrap());

    let yaml_v1 = "policy_id: old\nversion: \"1\"\nrules: []\n";
    let digest_v1 = sha256_hex(yaml_v1);
    sgx_guardian_client::policy_state::activate_policy(yaml_v1, &digest_v1).unwrap();

    let yaml_v2 = "policy_id: new\nversion: \"2\"\nrules: []\n";
    let digest_v2 = sha256_hex(yaml_v2);
    sgx_guardian_client::policy_state::activate_policy(yaml_v2, &digest_v2).unwrap();

    // Rollback → active reverts to v1 content
    sgx_guardian_client::policy_state::rollback_policy().unwrap();

    let current = sgx_guardian_client::policy_state::current_active_policy_digest()
        .unwrap()
        .unwrap();
    assert_eq!(current, digest_v1);

    std::env::remove_var("SGX_GUARDIAN_POLICY_DIR");
}
