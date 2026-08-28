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
//! Configuration is via environment variables so CI and Playwright can
//! point it at a fresh directory per run without touching the real
//! `/var/lib/sgx-guardian` paths used in production:
//!   TEST_GUARDIAN_PORT       - port to bind on 127.0.0.1 (default 8443)
//!   TEST_GUARDIAN_STATE_DIR  - directory for all test state (default: a
//!                              fresh dir under the OS temp dir, PID-scoped)
//!   TEST_GUARDIAN_NODE_ID    - node id for the test Guardian (default
//!                              "nodeA" — `vc::issue::configured_ca_did()`
//!                              hardcodes the Circle-owner bootstrap check
//!                              to node name "nodeA", so a different value
//!                              here needs a Circle owner seeded some other
//!                              way; the default just matches that constant)
//!   TEST_GUARDIAN_ADMIN_EMAIL    - seeded Owner account email (default
//!                                  "admin@sgx-guardian.local")
//!   TEST_GUARDIAN_ADMIN_PASSWORD - seeded Owner account password (default
//!                                  "AdminTest123!", chosen only to satisfy
//!                                  the real password policy — never used
//!                                  outside this ephemeral test server)

use sgx_guardian_client::api::auth::password;
use sgx_guardian_client::api::auth::store::{NewUser, UserRole};
use sgx_guardian_client::api::{build_router, state::AppState};
use sgx_guardian_client::did::doc_persistence;
use sgx_guardian_client::testkit::bootstrap_owner_identity;
use std::path::PathBuf;
use tokio::net::TcpListener;

/// Points every Circle/VC/DID-document storage path this Guardian reads at
/// `state_dir`-scoped subdirectories, and forces software key signing —
/// this test server has no hardware SE050/Nebula overlay to fall back on.
fn isolate_identity_paths(state_dir: &std::path::Path) {
    std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");
    std::env::set_var(
        "SGX_GUARDIAN_CIRCLE_BASE",
        state_dir.join("circle-base").to_string_lossy().to_string(),
    );
    std::env::set_var(
        "SGX_GUARDIAN_VC_BASE",
        state_dir.join("vc-base").to_string_lossy().to_string(),
    );
    std::env::set_var(
        "SGX_GUARDIAN_DID_PATH",
        state_dir.join("did.json").to_string_lossy().to_string(),
    );
    std::env::set_var(
        "SGX_GUARDIAN_DEVICE_KEY_DIR",
        state_dir.join("device-keys").to_string_lossy().to_string(),
    );
    std::env::set_var(
        sgx_guardian_client::virtual_id::RUNTIME_VID_STATE_DIR_ENV,
        state_dir.join("virtual-id").to_string_lossy().to_string(),
    );
    std::env::set_var(
        doc_persistence::SELF_DOC_PATH_ENV,
        state_dir.join("did_doc.json").to_string_lossy().to_string(),
    );
    std::env::set_var(
        doc_persistence::PEERS_DOC_DIR_ENV,
        state_dir.join("did-peers").to_string_lossy().to_string(),
    );
    std::env::set_var(
        doc_persistence::CA_AGGREGATE_PATH_ENV,
        state_dir
            .join("ca-aggregate.json")
            .to_string_lossy()
            .to_string(),
    );
    std::env::set_var(
        doc_persistence::VERSION_COUNTER_PATH_ENV,
        state_dir
            .join("did-version-counter")
            .to_string_lossy()
            .to_string(),
    );
    // No real `nebula0` TUN interface exists in this environment either —
    // group calls and similar need a plausible overlay IP to resolve.
    if std::env::var("SGX_NEBULA_LOCAL_IP_OVERRIDE").is_err() {
        std::env::set_var("SGX_NEBULA_LOCAL_IP_OVERRIDE", "192.168.100.1");
    }
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("TEST_GUARDIAN_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8443);

    let state_dir = std::env::var("TEST_GUARDIAN_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("sgx-test-guardian-{}", std::process::id()))
        });
    std::fs::create_dir_all(&state_dir).expect("create test guardian state dir");
    isolate_identity_paths(&state_dir);

    let config_dir = state_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("create test guardian config dir");

    let node_id = std::env::var("TEST_GUARDIAN_NODE_ID").unwrap_or_else(|_| "nodeA".to_string());

    let state = AppState::for_tests(
        &state_dir,
        &node_id,
        config_dir.to_string_lossy().to_string(),
    );

    bootstrap_owner_identity(
        &node_id,
        &state.device_did,
        &state_dir.join("device-keys"),
        "192.168.100.1/24",
    )
    .expect("bootstrap test guardian owner identity");

    let admin_email = std::env::var("TEST_GUARDIAN_ADMIN_EMAIL")
        .unwrap_or_else(|_| "admin@sgx-guardian.local".to_string());
    let admin_password = std::env::var("TEST_GUARDIAN_ADMIN_PASSWORD")
        .unwrap_or_else(|_| "AdminTest123!".to_string());
    let admin_pw_hash = password::hash_password(admin_password.clone())
        .await
        .expect("hash test guardian admin password");
    state
        .admin
        .users
        .create_initial_owner(NewUser {
            name: "Test Guardian Admin".to_string(),
            email: admin_email.clone(),
            pw_hash: admin_pw_hash,
            role: UserRole::Owner,
            oidc_sub: None,
        })
        .await
        .expect("seed test guardian admin account");
    eprintln!(
        "test_guardian_server admin account: {} / {}",
        admin_email, admin_password
    );

    let app = build_router(state, axum::Router::new());

    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|error| panic!("bind test guardian server to 127.0.0.1:{port}: {error}"));

    eprintln!(
        "test_guardian_server listening on http://127.0.0.1:{port} (state dir: {})",
        state_dir.display()
    );

    axum::serve(listener, app.into_make_service())
        .await
        .expect("test guardian server crashed");
}
