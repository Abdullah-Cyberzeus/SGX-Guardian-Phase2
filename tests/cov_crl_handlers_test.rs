//! Integration tests for `src/api/handlers/crl.rs`'s CLI-backed handlers
//! (`revoke`/`unrevoke`/`list`/`entry`/`check`/`verify`/`root`), which all
//! shell out to `sgx-pa-cli` via `run_cli`/`run_cli_with_env`. The existing
//! in-file tests only cover the "CLI binary not found" branch. This file
//! points `SGX_PA_CLI_PATH` at the real binary built for this workspace
//! (`target/debug/sgx-pa-cli`) and exercises its real, deterministic
//! behavior against the hardcoded `/var/lib/sgx-guardian/identity/...`
//! paths that are genuinely absent in this sandbox (confirmed by hand:
//! `crl list`/`crl root`/`crl check` succeed gracefully against an absent
//! CRL/DID; `crl verify`/`crl show` fail with real "not found" messages;
//! `crl revoke`/`crl unrevoke` fail with a real "DID file I/O error" since
//! there's no local DID document).
//!
//! `crl::persistence::crl_base()`'s `SGX_GUARDIAN_CRL_BASE` override is only
//! active under `#[cfg(test)]`, which is true for this test binary's own
//! in-process calls but NOT for the separately-compiled `sgx-pa-cli`
//! subprocess — so this deliberately does NOT set that override, letting
//! both sides agree on the same (absent) real path instead of diverging.

use axum::extract::{Query, State};
use axum::Json;
use sgx_guardian_client::api::error::ApiError;
use sgx_guardian_client::api::handlers::crl::{
    check, entry, list, revoke, root, unrevoke, verify, CheckQuery, EntryQuery, RevokeCrlRequest,
    UnrevokeCrlRequest,
};
use sgx_guardian_client::api::state::AppState;
use std::sync::Arc;

fn pa_cli_path() -> String {
    let mut path = std::env::current_exe().expect("current exe");
    path.pop(); // deps/
    path.pop(); // debug/
    path.push("sgx-pa-cli");
    assert!(path.is_file(), "expected sgx-pa-cli built at {:?}", path);
    path.to_string_lossy().to_string()
}

struct PaCliGuard(Option<std::ffi::OsString>);

impl PaCliGuard {
    fn set() -> Self {
        let previous = std::env::var_os("SGX_PA_CLI_PATH");
        std::env::set_var("SGX_PA_CLI_PATH", pa_cli_path());
        Self(previous)
    }
}

impl Drop for PaCliGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => std::env::set_var("SGX_PA_CLI_PATH", value),
            None => std::env::remove_var("SGX_PA_CLI_PATH"),
        }
    }
}

fn test_state(temp: &tempfile::TempDir) -> Arc<AppState> {
    AppState::for_tests(
        temp.path(),
        "nodeA",
        temp.path().join("config").to_string_lossy().to_string(),
    )
}

#[tokio::test]
async fn list_succeeds_via_the_real_cli_against_an_absent_crl() {
    let _guard = PaCliGuard::set();
    let temp = tempfile::TempDir::new().expect("tempdir");
    let response = list(State(test_state(&temp)))
        .await
        .expect("list should succeed against an absent CRL");
    assert_eq!(response.0.count, 0);
    assert!(response.0.entries.is_empty());
}

#[tokio::test]
async fn root_succeeds_via_the_real_cli_with_default_values() {
    let _guard = PaCliGuard::set();
    let temp = tempfile::TempDir::new().expect("tempdir");
    let response = root(State(test_state(&temp)))
        .await
        .expect("root should succeed against an absent CRL");
    assert_eq!(response.0.sequence, 0);
    assert_eq!(response.0.merkle_root, "");
}

#[tokio::test]
async fn check_succeeds_via_the_real_cli_and_reports_not_revoked() {
    let _guard = PaCliGuard::set();
    let temp = tempfile::TempDir::new().expect("tempdir");
    let response = check(
        State(test_state(&temp)),
        Query(CheckQuery {
            did: "did:guardian:someone".into(),
        }),
    )
    .await
    .expect("check should succeed against an absent CRL");
    assert!(!response.0.revoked);
    assert!(response.0.entry.is_none());
}

#[tokio::test]
async fn verify_reports_a_non_success_body_when_the_real_cli_finds_no_crl() {
    let _guard = PaCliGuard::set();
    let temp = tempfile::TempDir::new().expect("tempdir");
    let response = verify(State(test_state(&temp)))
        .await
        .expect("verify itself must not error even when the CLI reports failure");
    assert!(!response.0.ok);
    assert!(!response.0.errors.is_empty());
}

#[tokio::test]
async fn entry_reports_not_found_via_the_real_cli_for_an_unknown_id() {
    let _guard = PaCliGuard::set();
    let temp = tempfile::TempDir::new().expect("tempdir");
    let error = entry(
        State(test_state(&temp)),
        Query(EntryQuery { id: "abc".into() }),
    )
    .await
    .expect_err("unknown entry id must fail");
    assert!(matches!(error, ApiError::NotFound(_)), "{error:?}");
}

#[tokio::test]
async fn revoke_surfaces_a_real_cli_failure_as_bad_request() {
    let _guard = PaCliGuard::set();
    let temp = tempfile::TempDir::new().expect("tempdir");
    let error = revoke(
        State(test_state(&temp)),
        Json(RevokeCrlRequest {
            did: "did:guardian:someone".into(),
            reason: "compromised".into(),
            severity: "low".into(),
            device_id: None,
            user_id: None,
            note: None,
            audit_ref: None,
            attestation_ref: None,
            evidence_digest: None,
        }),
    )
    .await
    .expect_err("revoke without a real local DID document must fail");
    // The real CLI's error message doesn't match any of `map_cli_failure`'s
    // specific patterns ("already revoked", "self", "not found"), so it
    // falls through to the default BadRequest mapping.
    assert!(matches!(error, ApiError::BadRequest(_)), "{error:?}");
}

#[tokio::test]
async fn unrevoke_surfaces_a_real_cli_failure_as_bad_request() {
    let _guard = PaCliGuard::set();
    let temp = tempfile::TempDir::new().expect("tempdir");
    let error = unrevoke(
        State(test_state(&temp)),
        Json(UnrevokeCrlRequest {
            did: "did:guardian:someone".into(),
        }),
    )
    .await
    .expect_err("unrevoke without a real local DID document must fail");
    assert!(matches!(error, ApiError::BadRequest(_)), "{error:?}");
}
