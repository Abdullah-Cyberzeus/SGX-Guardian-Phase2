// Shared fixture for Wave B API handler integration tests (call, circle, pwa,
// vault, ...). Not a test file itself -- included per-file via
// `#[path = "wave_b_support/mod.rs"] mod support;`.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use serde_json::Value;
use sgx_guardian_client::api::auth::session;
use sgx_guardian_client::api::auth::store::{NewMemberRegistration, NewUser, UserRole};
use sgx_guardian_client::api::handlers::browser_member::did_for_registration;
use sgx_guardian_client::api::handlers::pwa::guardian_fingerprint;
use sgx_guardian_client::api::state::AppState;
use std::sync::Arc;
use tower::ServiceExt;

// `vc::issue::configured_ca_did()` hardcodes the bootstrap-eligible CA/mesh
// owner node name to "nodeA" (it looks up the DID document whose
// `sgx_node_name == "nodeA"`), so this must match exactly for
// `bootstrap_owner_identity`'s `ensure_owner_vc` call to succeed.
const NODE_ID: &str = "nodeA";

/// A full router + backing `AppState`, isolated to a temp directory for the
/// lifetime of the test, with a bootstrapped Circle-owner identity (DID
/// record/document + mesh owner VC) so `circle::create` and anything that
/// transitively calls `mesh_circle_id()`/`load_runtime_signing_context()`
/// (i.e. most of `circle.rs`, and any call/chat/vault path that resolves
/// Circle membership) works end-to-end without real hardware.
///
/// The Circle/VC/DID subsystems read their storage locations from *process*
/// env vars rather than from `AppState`, so `Env::new()` repoints those vars
/// at this instance's temp dir before constructing anything. Because that
/// state is process-wide, tests using `Env` must run with
/// `--test-threads=1` (this crate's convention for such tests) so two
/// `Env`s are never live/racing in the same process at once.
pub struct Env {
    pub state: Arc<AppState>,
    _temp: tempfile::TempDir,
}

impl Env {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = temp.path().join("config");
        std::fs::create_dir_all(&config).expect("config dir");

        std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");
        std::env::set_var("SGX_GUARDIAN_CIRCLE_BASE", temp.path().join("circle-base"));
        std::env::set_var("SGX_GUARDIAN_VC_BASE", temp.path().join("vc-base"));
        std::env::set_var("SGX_GUARDIAN_DID_PATH", temp.path().join("did.json"));
        std::env::set_var(
            "SGX_GUARDIAN_DEVICE_KEY_DIR",
            temp.path().join("device-keys"),
        );
        std::env::set_var(
            sgx_guardian_client::virtual_id::RUNTIME_VID_STATE_DIR_ENV,
            temp.path().join("virtual-id"),
        );
        std::env::set_var(
            sgx_guardian_client::did::doc_persistence::SELF_DOC_PATH_ENV,
            temp.path().join("did_doc.json"),
        );
        std::env::set_var(
            sgx_guardian_client::did::doc_persistence::PEERS_DOC_DIR_ENV,
            temp.path().join("did-peers"),
        );
        std::env::set_var(
            sgx_guardian_client::did::doc_persistence::CA_AGGREGATE_PATH_ENV,
            temp.path().join("ca-aggregate.json"),
        );
        std::env::set_var(
            sgx_guardian_client::did::doc_persistence::VERSION_COUNTER_PATH_ENV,
            temp.path().join("did-version-counter"),
        );

        let state = AppState::for_tests(
            temp.path(),
            NODE_ID,
            config.to_string_lossy().to_string(),
        );

        sgx_guardian_client::testkit::bootstrap_owner_identity(
            NODE_ID,
            &state.device_did,
            &temp.path().join("device-keys"),
            "192.168.100.1/24",
        )
        .expect("bootstrap Circle-owner identity");

        Self { state, _temp: temp }
    }

    pub fn router(&self) -> Router {
        sgx_guardian_client::api::build_router(self.state.clone(), Router::new())
    }

    /// Seeds an Owner admin user (device-level / full-access caller) and
    /// returns a bearer token for it.
    pub async fn owner_token(&self) -> String {
        let user = self
            .state
            .admin
            .users
            .create(NewUser {
                name: "Wave B Owner".into(),
                email: format!("wave-b-owner-{}@example.com", uuid::Uuid::new_v4()),
                pw_hash: "test-hash".into(),
                role: UserRole::Owner,
                oidc_sub: None,
            })
            .await
            .expect("seed owner user");
        self.issue_token(&user).await
    }

    /// Seeds an active browser Member of `circle_id` and returns
    /// `(bearer_token, member_did)`. Each call creates a distinct member with
    /// a distinct, deterministically-derivable DID.
    pub async fn member_token(&self, circle_id: &str) -> (String, String) {
        let registration_id = uuid::Uuid::new_v4().to_string();
        let did = did_for_registration(&registration_id);
        let fingerprint = guardian_fingerprint(&self.state.device_pubkey_point);
        let user = self
            .state
            .admin
            .users
            .create_or_reactivate_member(NewMemberRegistration {
                name: "Wave B Member".into(),
                email: format!("wave-b-member-{}@example.com", uuid::Uuid::new_v4()),
                pw_hash: "test-hash".into(),
                circle_id: circle_id.to_string(),
                browser_registration_id: registration_id,
                guardian_fingerprint: fingerprint,
                registration_expires_at: chrono::Utc::now().timestamp() + 3600,
                invite_id: uuid::Uuid::new_v4().to_string(),
                pending_approval: false,
            })
            .await
            .expect("seed member user");
        let token = self.issue_token(&user).await;
        (token, did)
    }

    /// Creates a real Circle via `POST /circles` (bootstrapping the mesh
    /// owner VC and the circle registry the first time it's called), as the
    /// device-level owner. Panics on failure since callers need this to
    /// succeed to set up any circle-scoped fixture state.
    pub async fn create_circle(&self, owner_token: &str, circle_id: &str) {
        let (status, body) = call(
            self.router(),
            "POST",
            "/api/v1/circles",
            Some(owner_token),
            Some(serde_json::json!({"circle_id": circle_id, "name": circle_id})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "circle creation fixture failed: {body}"
        );
    }

    async fn issue_token(&self, user: &sgx_guardian_client::api::auth::store::User) -> String {
        let (token, _, session_rec) = session::issue(
            self.state.signer.clone(),
            &self.state.device_did,
            user,
            std::time::Duration::from_secs(300),
        )
        .await
        .expect("issue token");
        self.state
            .admin
            .sessions
            .put(session_rec)
            .await
            .expect("store session");
        token
    }
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}

/// Dispatches one HTTP request against `router` via `tower::ServiceExt::oneshot`
/// (no real socket) and returns `(status, json_body)`. `body` is serialized as
/// the JSON request payload when present.
pub async fn call(
    router: Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = if let Some(body) = body {
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize body")))
            .expect("build request")
    } else {
        builder.body(Body::empty()).expect("build request")
    };
    let response = router.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}
