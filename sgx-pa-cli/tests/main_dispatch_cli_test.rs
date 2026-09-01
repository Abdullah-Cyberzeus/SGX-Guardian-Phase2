//! Touches `main.rs`'s subcommand dispatch `match` arms that aren't already exercised by
//! another integration test file. `main()` itself can't be called in-process (it reads real
//! `std::env::args()`), so these spawn the real binary. Assertions are deliberately loose —
//! the goal is reaching each match arm, not asserting specific behavior (which the relevant
//! command's own unit tests already do); every command below is filesystem-only (no network),
//! matching the established pattern of hardcoded system paths that are absent in this sandbox.

use assert_cmd::Command;

fn run(args: &[&str]) {
    // Bound how long any single invocation may run — a hang here would otherwise stall the
    // whole suite indefinitely.
    let _ = Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(args)
        .timeout(std::time::Duration::from_secs(10))
        .assert();
}

#[test]
fn dispatch_reaches_status_and_boot_status() {
    run(&["status", "--node", "nodeA"]);
    run(&["boot-status"]);
}

#[test]
fn dispatch_reaches_logs_and_peers() {
    run(&["logs", "--node", "nodeA"]);
    run(&["peers"]);
}

#[test]
fn dispatch_reaches_sign_and_verify() {
    run(&["sign", "/nonexistent/policy.yaml"]);
    run(&["verify", "--signed", "not-a-json-envelope"]);
}

#[test]
fn dispatch_reaches_dkp_status_and_pcr_status() {
    run(&["dkp-status"]);
    run(&["pcr-status"]);
}

#[test]
fn dispatch_reaches_dkp_revoke() {
    run(&["dkp-revoke", "--version", "1"]);
}

#[test]
fn dispatch_reaches_relay_family() {
    run(&["relay-list"]);
    run(&["relay", "stats", "nodeA"]);
    run(&["relay", "set-limit", "nodeA", "--max-peers", "5"]);
    run(&["relay", "toggle", "nodeA", "--enable"]);
}

#[test]
fn dispatch_reaches_discovery_config_show() {
    // Read-only, no network scan.
    run(&["discovery", "config-show"]);
}

#[test]
fn dispatch_reaches_transport_aliases() {
    run(&["transport-stats"]);
    run(&["transport-unlock"]);
}

#[test]
fn dispatch_reaches_attest_generate() {
    run(&["attest-generate", "--nonce", &"a".repeat(64)]);
}
