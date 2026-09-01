//! Shared locks for process-global state (env vars) that more than one command module's
//! tests need to mutate — `audit_logs.rs` and `audit_verify.rs` both read
//! `SGX_GUARDIAN_AUDIT_LOG_PATH`, for instance. A single shared lock per variable prevents
//! two files' tests from racing on the same env var under the default parallel test runner.
//!
//! Included separately (via `#[cfg(test)] mod test_support;`) from both `main.rs` and
//! `lib.rs`, since `commands` is itself compiled twice — once per crate root — and each
//! needs its own accessible copy.

use std::sync::Mutex;

pub(crate) static AUDIT_LOG_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Guards every test mutation of `SGX_GUARDIAN_DID_PATH`, `SGX_GUARDIAN_DID_DOC_PATH`, and
/// `SGX_GUARDIAN_DID_PEERS_DIR` — shared between `diddoc.rs` (which sets the doc-path/peers-dir
/// pair) and `pairing.rs` (which touches both `SGX_GUARDIAN_DID_PATH` and, indirectly via
/// `resolve_runtime_node_id`, `SGX_GUARDIAN_DID_DOC_PATH`) so their tests can't race on the
/// same process-global variables.
pub(crate) static DID_ENV_LOCK: Mutex<()> = Mutex::new(());
