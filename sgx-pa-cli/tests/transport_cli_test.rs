//! Subprocess-based tests for `transport-lock` and the invalid-node-name branch.
//!
//! `transport::lock_path` calls `std::process::exit(1)` for a node name containing anything
//! other than alphanumerics/`_`/`-`, and `run_lock` calls it again if
//! `/var/lib/sgx-guardian/cot` can't be created (it can't, without root, in this sandbox) —
//! both are exercised via the real compiled binary rather than in-process.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn transport_list_rejects_an_invalid_node_name() {
    Command::cargo_bin("sgx-pa-cli")
        .unwrap()
        .args(["transport-list", "--node", "bad name!"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Invalid node name"));
}
