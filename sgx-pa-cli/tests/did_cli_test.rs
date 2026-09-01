//! Subprocess-based tests for `did <subcommand>`.
//!
//! Every `cmd_*` function reads from hardcoded, non-overridable system paths
//! (`did::DEFAULT_DID_PATH`, `did::registry::default_peers_dir()`) and most end in
//! `std::process::exit` on failure, so they're exercised here via the real compiled binary
//! rather than in-process. All of the paths below genuinely don't exist in this sandbox,
//! which gives deterministic "absent" branches for free — the same technique used for
//! `crl.rs`.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn did_show_reports_missing_did_file() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["did", "show"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Could not load DID"));
}

#[test]
fn did_create_delegates_to_show_and_reports_missing_did_file() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["did", "create"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("performed by the daemon"))
        .stderr(predicate::str::contains("Could not load DID"));
}

#[test]
fn did_resolve_self_reports_failure_without_a_local_did() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["did", "resolve"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Resolve failed"));
}

#[test]
fn did_resolve_a_remote_did_fails_without_a_configured_ca_host() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .env_remove("SGX_CA_HOST")
        .args(["did", "resolve", "did:guardian:someone-else"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("❌"));
}

#[test]
fn did_peers_reports_no_cached_peers() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["did", "peers"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no cached peer DIDs"));
}

#[test]
fn did_deactivate_requires_explicit_confirmation() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["did", "deactivate"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Re-run with --yes"));
}

#[test]
fn did_deactivate_with_yes_fails_on_missing_did_file() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["did", "deactivate", "--yes"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Deactivate failed"));
}

#[test]
fn did_remint_requires_explicit_confirmation() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["did", "remint"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Re-run with --yes"));
}

#[test]
fn did_remint_with_yes_reports_no_did_file_and_succeeds() {
    // No did.json exists at the hardcoded path in this sandbox, so remint's "nothing to do"
    // branch is a real, deterministic success path.
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["did", "remint", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No did.json found"));
}
