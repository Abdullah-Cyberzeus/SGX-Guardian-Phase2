//! Subprocess-based tests for small `std::process::exit` branches across several
//! `sgx-pa-cli` commands, gathered into one file rather than one file per command since each
//! only needs one or two quick invocations.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn logs_reports_no_log_file_for_an_unknown_node() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["logs", "--node", "node-truly-nonexistent-xyz"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("No log file found"));
}

#[test]
fn status_rejects_an_invalid_node_name() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["status", "--node", "bad name!"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Invalid node name"));
}

#[test]
fn dkp_revoke_reports_missing_metadata() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["dkp-revoke", "--version", "1"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("No DKP metadata found"));
}

#[test]
fn policy_sign_and_deploy_rejects_a_nonexistent_path() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["policy-sign-and-deploy", "/nonexistent/path/policy.yaml"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Invalid policy path"));
}

#[test]
fn policy_sign_and_deploy_rejects_a_path_outside_etc_sgx_guardian() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("policy.yaml");
    std::fs::write(&path, "rules: []").unwrap();
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["policy-sign-and-deploy", path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("must be under /etc/sgx-guardian/"));
}

#[test]
fn pairing_proof_reports_missing_node_id() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env_remove("SGX_NODE_ID")
        .env_remove("SGX_GUARDIAN_DID_DOC_PATH")
        .args(["pairing", "proof", "--pairing-code", "code123"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("node-id is required"));
}

#[test]
fn status_loads_the_real_checked_in_nodea_config() {
    // The compiled binary's exe_dir/../../config/nodeA.yaml resolves to the real,
    // already-checked-in `config/nodeA.yaml` at the workspace root — read-only, exercises
    // the full success path including the `relay` block.
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["status", "--node", "nodeA"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Node Status"))
        .stdout(predicate::str::contains("Relay: enabled=false"));
}
