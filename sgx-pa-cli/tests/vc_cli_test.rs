//! Subprocess-based tests for `vc <subcommand>`.
//!
//! Every `cmd_*` function in `sgx-pa-cli/src/commands/vc.rs` terminates via
//! `std::process::exit(1)` on any failure rather than returning a `Result`, so none of them
//! can be safely called in-process from a unit test (`std::process::exit` would kill the test
//! binary itself). These tests spawn the real compiled CLI via `assert_cmd` instead.
//!
//! `SGX_GUARDIAN_VC_BASE` is a real override the main crate's `vc::persistence` module already
//! supports, so `vc show`/`vc status` can be redirected to a tempdir without touching the
//! hardcoded `/var/lib/sgx-guardian` paths. `vc issue`/`vc revoke`/`vc renew` additionally load
//! the node's DID record from a hardcoded, non-overridable path that doesn't exist in this
//! sandbox, so only their pre-DID-load validation branches are reachable here.

use assert_cmd::Command;
use predicates::prelude::*;

fn sample_vc_json(id: &str, status_list_index: &str) -> serde_json::Value {
    serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": id,
        "type": ["VerifiableCredential"],
        "issuer": "did:guardian:issuer",
        "issuanceDate": "2026-01-01T00:00:00Z",
        "expirationDate": "2030-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:guardian:subject",
            "role": "member",
            "permissions": ["read"],
            "joinDate": "2026-01-01T00:00:00Z",
            "circleId": "circle-1",
            "nodeHint": null
        },
        "credentialStatus": {
            "id": "status-1",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": status_list_index,
            "statusListCredential": "https://example/status-list.json"
        },
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-2022",
            "verificationMethod": "did:guardian:issuer#key-1",
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "assertionMethod",
            "proofValue": "z-fake-signature"
        }
    })
}

// ── vc show (SGX_GUARDIAN_VC_BASE override, no DID/key material needed) ────

#[test]
fn vc_show_reports_no_local_vcs_on_an_empty_store() {
    let temp = tempfile::tempdir().unwrap();
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env("SGX_GUARDIAN_VC_BASE", temp.path())
        .args(["vc", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No local VCs found."));
}

#[test]
fn vc_show_lists_a_seeded_local_vc() {
    let temp = tempfile::tempdir().unwrap();
    let own_dir = temp.path().join("own");
    std::fs::create_dir_all(&own_dir).unwrap();
    let vc = sample_vc_json("vc-show-1", "1");
    std::fs::write(
        own_dir.join("vc-show-1.json"),
        serde_json::to_string_pretty(&vc).unwrap(),
    )
    .unwrap();

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env("SGX_GUARDIAN_VC_BASE", temp.path())
        .args(["vc", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("vc-show-1"))
        .stdout(predicate::str::contains("did:guardian:subject"));
}

// ── vc status ────────────────────────────────────────────────────────────

#[test]
fn vc_status_reports_not_found_for_an_unknown_id() {
    let temp = tempfile::tempdir().unwrap();
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env("SGX_GUARDIAN_VC_BASE", temp.path())
        .args(["vc", "status", "--id", "does-not-exist"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("VC not found"));
}

#[test]
fn vc_status_prints_a_table_for_a_seeded_vc_with_no_status_list() {
    let temp = tempfile::tempdir().unwrap();
    let own_dir = temp.path().join("own");
    std::fs::create_dir_all(&own_dir).unwrap();
    let vc = sample_vc_json("vc-status-1", "2");
    std::fs::write(
        own_dir.join("vc-status-1.json"),
        serde_json::to_string_pretty(&vc).unwrap(),
    )
    .unwrap();

    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env("SGX_GUARDIAN_VC_BASE", temp.path())
        .args(["vc", "status", "--id", "vc-status-1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("vc-status-1"))
        .stdout(predicate::str::contains("false")); // no status list -> not revoked
}

// ── vc verify ────────────────────────────────────────────────────────────

#[test]
fn vc_verify_reports_error_for_a_missing_file() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("does-not-exist.json");
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["vc", "verify", "--path", missing.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Could not load VC"));
}

#[test]
fn vc_verify_reports_error_for_invalid_json() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bad.json");
    std::fs::write(&path, "not valid json").unwrap();
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["vc", "verify", "--path", path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Could not load VC"));
}

#[test]
fn vc_verify_fails_closed_when_the_status_list_is_unavailable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vc.json");
    let vc = sample_vc_json("vc-verify-1", "3");
    std::fs::write(&path, serde_json::to_string_pretty(&vc).unwrap()).unwrap();

    // A separate, empty VC_BASE means `load_status_list_credential` finds nothing, so the
    // command fails closed rather than skipping revocation-status verification.
    let vc_base = tempfile::tempdir().unwrap();
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env("SGX_GUARDIAN_VC_BASE", vc_base.path())
        .args(["vc", "verify", "--path", path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("status list is unavailable"));
}

// ── vc issue / revoke / renew: validation before the (hardcoded, absent) DID load ──

#[test]
fn vc_issue_rejects_an_unknown_role_before_touching_any_files() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["vc", "issue", "--to", "did:guardian:x", "--role", "bogus"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unsupported role"));
}

#[test]
fn vc_issue_with_a_valid_role_fails_on_the_missing_node_identity() {
    // /var/lib/sgx-guardian/identity/did.json genuinely doesn't exist in this sandbox.
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["vc", "issue", "--to", "did:guardian:x", "--role", "member"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Load issuer DID failed"));
}

#[test]
fn vc_revoke_fails_on_the_missing_node_identity() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["vc", "revoke", "--id", "some-vc-id"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Load issuer DID failed"));
}

#[test]
fn vc_renew_rejects_non_positive_days() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["vc", "renew", "--to", "did:guardian:x", "--days", "0"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("greater than zero"));
}

#[test]
fn vc_renew_rejects_both_id_and_to_specified() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args([
            "vc", "renew", "--id", "vc-1", "--to", "did:guardian:x", "--days", "30",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("exactly one of"));
}

#[test]
fn vc_renew_rejects_neither_id_nor_to_specified() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["vc", "renew", "--days", "30"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("exactly one of"));
}

// ── vc pull-status-list ─────────────────────────────────────────────────

#[test]
fn vc_pull_status_list_reports_unconfigured_ca_host() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env_remove("SGX_CA_HOST")
        .current_dir(tempfile::tempdir().unwrap().keep())
        .args(["vc", "pull-status-list"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("CA host is not configured"));
}
