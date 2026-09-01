//! Subprocess-based tests for `attest-verify`.
//!
//! `run_verify` ends with `std::process::exit(1)` whenever the overall result isn't
//! VERIFIED — which, in this sandbox, is every well-formed quote, since there is no real
//! DKP public key at `/var/lib/sgx-guardian/keys/dkp_pub.der` to verify a signature against.
//! Calling `run_verify` in-process with a fully-parseable quote would kill the test binary,
//! so these tests spawn the real compiled CLI via `assert_cmd` instead — exercising the
//! nonce/freshness/boot-chain/integrity/baseline/signature branches that an in-process unit
//! test structurally cannot reach.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;

const NONCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn write_quote(dir: &std::path::Path, inner: &serde_json::Value, signature_b64: &str) -> String {
    let quote_json = serde_json::to_string(inner).unwrap();
    let envelope = serde_json::json!({
        "quote_json": quote_json,
        "signature_b64": signature_b64,
        "signing_pubkey_b64": "",
        "signing_backend": "Software"
    });
    let path = dir.join("quote.json");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(serde_json::to_string_pretty(&envelope).unwrap().as_bytes())
        .unwrap();
    path.to_string_lossy().to_string()
}

fn well_formed_inner_quote() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "challenge_nonce": NONCE,
        "device_nonce": "deadbeef",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "node_id": "nodeTestCli",
        "device_uid": "uid-1",
        "key_version": 1,
        "pcr_values": ["aa11", "bb22", "cc33"],
        "composite_digest": "digest123",
        "integrity_status": "PASS",
        "boot_chain": {
            "hab_enabled": true,
            "device_closed": true,
            "hab_events_found": false,
            "boot_chain_intact": true
        },
        "firmware_version": "1.0",
        "active_policy_digest": "policy123"
    })
}

#[test]
fn verify_a_well_formed_quote_with_no_baseline_file_fails_with_exit_1() {
    let temp = tempfile::tempdir().unwrap();
    let quote_path = write_quote(temp.path(), &well_formed_inner_quote(), "");

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["attest-verify", "--quote", &quote_path, "--nonce", NONCE])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("Nonce:       ✅ matches"))
        .stdout(predicate::str::contains("No baseline file"))
        .stdout(predicate::str::contains("❌ FAILED"));
}

#[test]
fn verify_with_no_baseline_flag_takes_the_self_consistency_path() {
    let temp = tempfile::tempdir().unwrap();
    let quote_path = write_quote(temp.path(), &well_formed_inner_quote(), "");

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args([
            "attest-verify",
            "--quote",
            &quote_path,
            "--nonce",
            NONCE,
            "--no-baseline",
        ])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("self-check"))
        .stdout(predicate::str::contains(
            "accepting self-consistency",
        ));
}

#[test]
fn verify_with_a_matching_explicit_baseline_reports_all_match() {
    let temp = tempfile::tempdir().unwrap();
    let inner = well_formed_inner_quote();
    let quote_path = write_quote(temp.path(), &inner, "");

    let baseline = serde_json::json!({
        "pcr_values": inner["pcr_values"],
        "composite_digest": inner["composite_digest"]
    });
    let baseline_path = temp.path().join("baseline.json");
    std::fs::write(&baseline_path, serde_json::to_string(&baseline).unwrap()).unwrap();

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args([
            "attest-verify",
            "--quote",
            &quote_path,
            "--nonce",
            NONCE,
            "--baseline",
            baseline_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("✅ ALL MATCH"));
}

#[test]
fn verify_with_a_mismatching_explicit_baseline_reports_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let inner = well_formed_inner_quote();
    let quote_path = write_quote(temp.path(), &inner, "");

    let baseline = serde_json::json!({
        "pcr_values": ["different", "values", "here"],
        "composite_digest": "not-the-same-digest"
    });
    let baseline_path = temp.path().join("baseline.json");
    std::fs::write(&baseline_path, serde_json::to_string(&baseline).unwrap()).unwrap();

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args([
            "attest-verify",
            "--quote",
            &quote_path,
            "--nonce",
            NONCE,
            "--baseline",
            baseline_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("❌ MISMATCH"));
}

#[test]
fn verify_with_an_unparseable_baseline_file_reports_a_baseline_error() {
    let temp = tempfile::tempdir().unwrap();
    let quote_path = write_quote(temp.path(), &well_formed_inner_quote(), "");
    let baseline_path = temp.path().join("baseline.json");
    std::fs::write(&baseline_path, "not valid json").unwrap();

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args([
            "attest-verify",
            "--quote",
            &quote_path,
            "--nonce",
            NONCE,
            "--baseline",
            baseline_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Baseline:    ❌"));
}

#[test]
fn verify_with_stale_timestamp_and_bad_boot_chain_reports_both() {
    let temp = tempfile::tempdir().unwrap();
    let mut inner = well_formed_inner_quote();
    inner["timestamp"] = serde_json::json!("2020-01-01T00:00:00Z");
    inner["boot_chain"]["hab_enabled"] = serde_json::json!(false);
    inner["boot_chain"]["device_closed"] = serde_json::json!(false);
    inner["boot_chain"]["hab_events_found"] = serde_json::json!(true);
    inner["integrity_status"] = serde_json::json!("FAIL");
    let quote_path = write_quote(temp.path(), &inner, "garbage-not-base64!!");

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["attest-verify", "--quote", &quote_path, "--nonce", NONCE])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("⚠️ stale"))
        .stdout(predicate::str::contains("❌ not detected"))
        .stdout(predicate::str::contains("🔓 OPEN"))
        .stdout(predicate::str::contains("⚠️ FOUND"))
        .stdout(predicate::str::contains("❌ FAIL"));
}

#[test]
fn verify_reports_nonce_mismatch_when_quote_nonce_differs() {
    let temp = tempfile::tempdir().unwrap();
    let quote_path = write_quote(temp.path(), &well_formed_inner_quote(), "");
    let other_nonce = "b".repeat(64);

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args([
            "attest-verify",
            "--quote",
            &quote_path,
            "--nonce",
            &other_nonce,
        ])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("❌ MISMATCH"));
}
