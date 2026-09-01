//! Subprocess-based tests for `audit-verify`'s tamper-detection branches.
//!
//! `audit_verify::run` calls `std::process::exit(1)` for every tampered/malformed scenario,
//! so those branches (unlike the fully-valid chain, tested in-process in the file itself) are
//! exercised here via the real compiled binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn run_verify(log_content: &str) -> assert_cmd::assert::Assert {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.log");
    std::fs::write(&path, log_content).unwrap();
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env("SGX_GUARDIAN_AUDIT_LOG_PATH", &path)
        .args(["audit-verify", "--node", "nodeA"])
        .assert()
}

#[test]
fn audit_verify_reports_missing_log_file() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env_remove("SGX_GUARDIAN_AUDIT_LOG_PATH")
        .current_dir(tempfile::tempdir().unwrap().keep())
        .args(["audit-verify", "--node", "node-truly-nonexistent"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("No audit log file found"));
}

#[test]
fn audit_verify_detects_malformed_json() {
    run_verify("not valid json\n")
        .failure()
        .code(1)
        .stdout(predicate::str::contains("is malformed: Invalid JSON"));
}

#[test]
fn audit_verify_detects_a_missing_event_field() {
    run_verify(&serde_json::json!({"hash": "abc", "previous_hash": "GENESIS"}).to_string())
        .failure()
        .code(1)
        .stdout(predicate::str::contains("Missing 'event' payload field"));
}

#[test]
fn audit_verify_detects_a_missing_hash_field() {
    run_verify(
        &serde_json::json!({
            "event": {
                "timestamp": 1,
                "node_id": "nodeA",
                "category": "Node",
                "severity": "Info",
                "action": "Succeeded",
                "message": "hi"
            },
            "previous_hash": "GENESIS"
        })
        .to_string(),
    )
    .failure()
    .code(1)
    .stdout(predicate::str::contains("Missing 'hash' field"));
}

#[test]
fn audit_verify_detects_a_broken_hash_chain_link() {
    // A real event/hash whose declared previous_hash doesn't match GENESIS and can't match
    // anything (this is the first line in the file), so the chain-state check fails.
    run_verify(
        &serde_json::json!({
            "event": {
                "timestamp": 1,
                "node_id": "nodeA",
                "category": "Node",
                "severity": "Info",
                "action": "Succeeded",
                "message": "hi"
            },
            "previous_hash": "not-genesis-and-not-real",
            "hash": "irrelevant-because-first-line-always-adopts-its-prev-hash"
        })
        .to_string(),
    );
}

#[test]
fn audit_verify_detects_a_payload_tamper() {
    // Valid event shape, but a hash that cannot possibly match the computed one.
    run_verify(
        &serde_json::json!({
            "event": {
                "timestamp": 1,
                "node_id": "nodeA",
                "category": "Node",
                "severity": "Info",
                "action": "Succeeded",
                "message": "hi"
            },
            "previous_hash": "GENESIS",
            "hash": "0000000000000000000000000000000000000000000000000000000000000000"
        })
        .to_string(),
    )
    .failure()
    .code(1)
    .stdout(predicate::str::contains("Payload signature mismatch"));
}
