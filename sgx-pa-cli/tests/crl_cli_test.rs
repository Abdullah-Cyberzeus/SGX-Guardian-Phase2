//! Subprocess-based tests for `crl <subcommand>`.
//!
//! `crl.rs`'s underlying CRL storage (`sgx_guardian_client::crl::persistence`) only honors
//! `SGX_GUARDIAN_CRL_BASE` when the *main crate* is compiled with `cfg(test)` — a build-time
//! gate that never applies when it's linked into the real `sgx-pa-cli` binary as a normal
//! dependency. So unlike `vc.rs`'s `SGX_GUARDIAN_VC_BASE`, this override cannot redirect I/O
//! here; every read genuinely goes to `/var/lib/sgx-guardian/identity/crl`, which doesn't
//! exist in this sandbox. That absence is itself a real, deterministic "no CRL" branch for
//! every read-only subcommand. `crl revoke`/`crl unrevoke` end in `std::process::exit(1)` on
//! any failure, so (as with `vc.rs`) they're exercised via a spawned subprocess rather than
//! in-process.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn crl_list_reports_no_entries_when_the_crl_is_absent() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No CRL entries found."));
}

#[test]
fn crl_show_reports_not_found_when_the_crl_is_absent() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "show", "--id", "some-entry-id"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("CRL entry not found"));
}

#[test]
fn crl_check_reports_not_revoked_when_the_crl_is_absent() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "check", "--did", "did:guardian:someone"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"revoked\": false"))
        .stdout(predicate::str::contains("\"entry\": null"));
}

#[test]
fn crl_root_reports_zero_sequence_when_the_crl_is_absent() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "root"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sequence\": 0"))
        .stdout(predicate::str::contains("\"merkle_root\": \"\""));
}

#[test]
fn crl_verify_reports_crl_not_found_when_absent() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "verify"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("CRL not found"));
}

#[test]
fn crl_revoke_rejects_an_empty_did() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "revoke", "--did", "   "])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("did must not be empty"));
}

#[test]
fn crl_revoke_rejects_an_unknown_reason() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args([
            "crl",
            "revoke",
            "--did",
            "did:guardian:x",
            "--reason",
            "bogus-reason",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unsupported revocation reason"));
}

#[test]
fn crl_revoke_rejects_an_unknown_severity() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args([
            "crl",
            "revoke",
            "--did",
            "did:guardian:x",
            "--severity",
            "bogus-severity",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unsupported severity"));
}

#[test]
fn crl_revoke_with_valid_args_fails_on_missing_node_identity() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "revoke", "--did", "did:guardian:x"])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn crl_unrevoke_rejects_an_empty_did() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "unrevoke", "--did", ""])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("did must not be empty"));
}

#[test]
fn crl_unrevoke_with_valid_did_fails_on_missing_node_identity() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["crl", "unrevoke", "--did", "did:guardian:x"])
        .assert()
        .failure()
        .code(1);
}
