//! Ephemeral, hardware-independent Guardian API server for local E2E test
//! runs (Playwright, manual QA). Boots the real router against a throwaway
//! tempdir-backed `AppState` — the same harness already used by the Rust
//! integration tests (see `tests/api_guardian_keys_test.rs`'s `test_state`)
//! — but stays alive on a fixed port until killed, instead of tearing down
//! after a single test. No Nebula/discovery/attestation/hardware keys are
//! involved: `AppState::for_tests` generates a software signing key, and
//! `bootstrap_owner_identity` (see `src/testkit.rs`) gives the device a
//! working Circle-owner identity so `POST /api/v1/circles`, invites, group
//! calls, etc. all work end-to-end — everything under the given state
//! directory.
//!
//! Configuration resolution and path isolation live in
//! `sgx_guardian_client::testkit::test_server` so they are unit-tested; this
//! binary is only the wiring. Environment variables:
//!   TEST_GUARDIAN_PORT           - port to bind on 127.0.0.1 (default 8443)
//!   TEST_GUARDIAN_STATE_DIR      - directory for all test state (default: a
//!                                  fresh PID-scoped dir under the OS temp dir)
//!   TEST_GUARDIAN_NODE_ID        - node id for the test Guardian (default
//!                                  "nodeA")
//!   TEST_GUARDIAN_ADMIN_EMAIL    - seeded Owner account email
//!   TEST_GUARDIAN_ADMIN_PASSWORD - seeded Owner account password

use sgx_guardian_client::api::auth::password;
use sgx_guardian_client::api::auth::store::{NewUser, UserRole};
use sgx_guardian_client::api::{build_router, state::AppState};
use sgx_guardian_client::testkit::bootstrap_owner_identity;
use sgx_guardian_client::testkit::test_server::{
    isolate_identity_paths, prepare_state_dirs, TestServerConfig, DEFAULT_OVERLAY_CIDR,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let config = TestServerConfig::from_env();
    prepare_state_dirs(&config).expect("create test guardian state dirs");
    isolate_identity_paths(&config.state_dir);

    let state = AppState::for_tests(
        &config.state_dir,
        &config.node_id,
        config.config_dir().to_string_lossy().to_string(),
    );

    bootstrap_owner_identity(
        &config.node_id,
        &state.device_did,
        &config.device_key_dir(),
        DEFAULT_OVERLAY_CIDR,
    )
    .expect("bootstrap test guardian owner identity");

    let admin_pw_hash = password::hash_password(config.admin_password.clone())
        .await
        .expect("hash test guardian admin password");
    state
        .admin
        .users
        .create_initial_owner(NewUser {
            name: "Test Guardian Admin".to_string(),
            email: config.admin_email.clone(),
            pw_hash: admin_pw_hash,
            role: UserRole::Owner,
            oidc_sub: None,
        })
        .await
        .expect("seed test guardian admin account");
    eprintln!(
        "test_guardian_server admin account: {} / {}",
        config.admin_email, config.admin_password
    );

    let app = build_router(state, axum::Router::new());

    let port = config.port;
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|error| panic!("bind test guardian server to 127.0.0.1:{port}: {error}"));

    eprintln!(
        "test_guardian_server listening on http://127.0.0.1:{port} (state dir: {})",
        config.state_dir.display()
    );

    axum::serve(listener, app.into_make_service())
        .await
        .expect("test guardian server crashed");
}
