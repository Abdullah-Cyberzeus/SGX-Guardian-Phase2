//! REST API module for the SG-X Guardian admin console.
//! Runs as a tokio task alongside the existing gRPC server.
//! Port: 8443 (separate listener from the :50051 mTLS gRPC endpoint).

use axum::{
    routing::{get, post},
    Json, Router,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use hyper_util::service::TowerToHyperService;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

pub mod auth;
pub mod error;
pub mod handlers;
pub mod routes;
pub mod state;
pub mod tls;

use state::AppState;
pub use tls::AdminTls;

/// Build the full axum router with all v1 routes.
pub fn build_router(state: Arc<AppState>, wifi_router: Router) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any);

    Router::new()
        // Phase 1 - read endpoints
        .route("/api/v1/node/status", get(handlers::node::status))
        .route("/api/v1/node/boot-status", get(handlers::node::boot_status))
        .route("/api/v1/node/restart", post(handlers::node::restart))
        .route("/api/v1/peers", get(handlers::peers::list))
        .route("/api/v1/attestation", get(handlers::attestation::last))
        .route("/api/v1/logs", get(handlers::logs::tail))
        .route("/api/v1/dkp/status", get(handlers::dkp::status))
        .route("/api/v1/pcr/status", get(handlers::pcr::status))
        .route("/api/v1/did/status", get(handlers::did::status))
        .route("/api/v1/did/resolve", get(handlers::did::resolve))
        .route("/api/v1/did/document", get(handlers::did::document))
        .route("/api/v1/did/document/raw", get(handlers::did::document_raw))
        .route(
            "/api/v1/did/document/verify",
            post(handlers::did::document_verify),
        )
        .route(
            "/api/v1/did/document/publish",
            post(handlers::did::document_publish),
        )
        .route(
            "/api/v1/did/document/peers",
            get(handlers::did::document_peers),
        )
        .route(
            "/api/v1/did/document/peer",
            get(handlers::did::document_peer),
        )
        .route("/api/v1/transport/list", get(handlers::transport::list))
        .route("/api/v1/transport/status", get(handlers::transport::status))
        .route("/api/v1/transport/lock", post(handlers::transport::lock))
        .route(
            "/api/v1/transport/unlock",
            post(handlers::transport::unlock),
        )
        .route("/api/v1/relay/list", get(handlers::relay::list))
        .route(
            "/api/v1/lighthouse/list",
            get(handlers::relay::lighthouse_list),
        )
        .route("/api/v1/member/list", get(handlers::relay::member_list))
        .route(
            "/api/v1/relay-lighthouse/list",
            get(handlers::relay::relay_lighthouse_list),
        )
        .route("/api/v1/relay/toggle", post(handlers::relay::toggle))
        .route(
            "/api/v1/lighthouse/toggle",
            post(handlers::relay::lighthouse_toggle),
        )
        .route(
            "/api/v1/discovery/summary",
            get(handlers::discovery::get_summary),
        )
        .route("/api/v1/discovery/runs", get(handlers::discovery::get_runs))
        .route(
            "/api/v1/discovery/devices",
            get(handlers::discovery::list_devices),
        )
        .route(
            "/api/v1/discovery/devices/{device_id}",
            get(handlers::discovery::get_device),
        )
        .route(
            "/api/v1/discovery/list",
            get(handlers::discovery::list_devices),
        )
        .route(
            "/api/v1/discovery/inventory/list",
            get(handlers::discovery::list_devices),
        )
        .route(
            "/api/v1/discovery/devices/unauthorized",
            get(handlers::discovery::list_unauthorized),
        )
        .route(
            "/api/v1/discovery/unauthorized",
            get(handlers::discovery::list_unauthorized),
        )
        .route(
            "/api/v1/discovery/scan",
            post(handlers::discovery::scan_now),
        )
        .route(
            "/api/v1/discovery/scan/stealth",
            post(handlers::discovery::scan_stealth),
        )
        .route(
            "/api/v1/discovery/scan/standard",
            post(handlers::discovery::scan_standard),
        )
        .route(
            "/api/v1/discovery/scan/aggressive",
            post(handlers::discovery::scan_aggressive),
        )
        .route(
            "/api/v1/discovery/approve",
            post(handlers::discovery::approve_device),
        )
        .route(
            "/api/v1/discovery/whitelist",
            get(handlers::discovery::get_whitelist),
        )
        .route(
            "/api/v1/discovery/whitelist",
            axum::routing::put(handlers::discovery::put_whitelist),
        )
        .route(
            "/api/v1/discovery/schedule",
            get(handlers::discovery::get_schedule),
        )
        .route(
            "/api/v1/discovery/schedule",
            axum::routing::put(handlers::discovery::put_schedule),
        )
        // Phase 2 - action endpoints
        .route("/api/v1/dkp/rotate", post(handlers::dkp::rotate))
        .route("/api/v1/dkp/revoke", post(handlers::dkp::revoke))
        .route(
            "/api/v1/dkp/emergency-rotate",
            post(handlers::dkp::emergency_rotate),
        )
        .route(
            "/api/v1/pcr/baseline/create",
            post(handlers::pcr::baseline_create),
        )
        // alias expected by frontend service
        .route(
            "/api/v1/pcr/baseline/update",
            post(handlers::pcr::baseline_create),
        )
        .route(
            "/api/v1/pcr/baseline/verify",
            post(handlers::pcr::baseline_verify),
        )
        // alias expected by frontend service
        .route("/api/v1/pcr/verify", post(handlers::pcr::baseline_verify))
        .route("/api/v1/policy/sign", post(handlers::policy::sign))
        .route("/api/v1/policy/verify", post(handlers::policy::verify))
        .route(
            "/api/v1/policy/verify-deployed",
            post(handlers::policy::verify_deployed),
        )
        .route("/api/v1/policy/current", get(handlers::policy::current))
        .route("/api/v1/policy/backup", get(handlers::policy::backup))
        .route(
            "/api/v1/policy/current",
            axum::routing::put(handlers::policy::save_current),
        )
        .route(
            "/api/v1/guardian/key/status",
            get(handlers::guardian_keys::status),
        )
        .route(
            "/api/v1/guardian/key/generate",
            post(handlers::guardian_keys::generate),
        )
        .route(
            "/api/v1/policy/sign-deploy-current",
            post(handlers::policy::sign_deploy_current),
        )
        .route("/api/v1/did/deactivate", post(handlers::did::deactivate))
        .route("/api/v1/relay/limits", post(handlers::relay::limits))
        .route("/api/v1/vc/issue", post(handlers::vc::issue))
        .route("/api/v1/vc/renew", post(handlers::vc::renew))
        .route("/api/v1/vc/verify", post(handlers::vc::verify))
        .route("/api/v1/vc/show", get(handlers::vc::show))
        .route("/api/v1/vc/status/{vc_id}", get(handlers::vc::status_by_id))
        .route(
            "/api/v1/vc/status-list/pull",
            post(handlers::vc::pull_status),
        )
        .route("/api/v1/vc/files/issued", get(handlers::vc::files_issued))
        .route("/api/v1/vc/files/own", get(handlers::vc::files_own))
        .route("/api/v1/vc/files/peers", get(handlers::vc::files_peers))
        .route("/api/v1/vid/show", get(handlers::vid::show))
        .route("/api/v1/vid/peers", get(handlers::vid::peers))
        .route(
            "/api/v1/vc/files/issued/{vc_id}",
            get(handlers::vc::file_issued),
        )
        .route("/api/v1/vc/files/own/{vc_id}", get(handlers::vc::file_own))
        .route("/api/v1/vc/files/peer/{did}", get(handlers::vc::file_peer))
        .route("/api/v1/vc/status-list", get(handlers::vc::status_list_get))
        .route(
            "/api/v1/vc/status-list-index",
            get(handlers::vc::status_list_index_get),
        )
        .route("/api/v1/vc/summary", get(handlers::vc::summary))
        .route("/api/v1/vc/audit", get(handlers::vc::audit))
        .route("/api/v1/vc/list", get(handlers::vc::list))
        .route("/api/v1/vc/peers", get(handlers::vc::peers))
        .route("/api/v1/vc/revoke", post(handlers::vc::revoke))
        .route("/api/v1/vc/status", get(handlers::vc::status))
        .route("/api/v1/vc/pull-status", post(handlers::vc::pull_status))
        .route("/api/v1/threat/status", get(handlers::threat::status))
        .route("/api/v1/threat/alerts", get(handlers::threat::list_alerts))
        .route(
            "/api/v1/threat/modbus",
            get(handlers::threat::modbus_alerts),
        )
        .route("/api/v1/threat/blocks", get(handlers::threat::list_blocks))
        .route("/api/v1/threat/blocks", post(handlers::threat::block_ip))
        .route(
            "/api/v1/threat/blocks/unblock",
            post(handlers::threat::unblock),
        )
        .route(
            "/api/v1/threat/rules/update",
            post(handlers::threat::update_rules),
        )
        .route(
            "/api/v1/threat/validate",
            post(handlers::threat::validate_config),
        )
        .route("/api/v1/threat/config", get(handlers::threat::get_config))
        .route("/api/v1/threat/config", post(handlers::threat::set_config))
        .route("/api/v1/threat/start", post(handlers::threat::start))
        .merge(routes::crl_router())
        .route("/api/v1/auth/signup", post(handlers::auth::signup))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        .route("/api/v1/auth/session", get(handlers::auth::session))
        .route("/api/v1/devices", get(handlers::devices::list))
        .route("/api/v1/devices/pair", post(handlers::devices::pair))
        .route(
            "/api/v1/devices/pairing-code",
            get(handlers::devices::pairing_code),
        )
        .route(
            "/api/v1/devices/pairing-status",
            get(handlers::devices::pairing_status),
        )
        .route(
            "/api/v1/devices/{device_id}",
            get(handlers::devices::detail),
        )
        .route(
            "/api/v1/devices/{id}/unpair",
            post(handlers::devices::unpair),
        )
        .merge(routes::vault_router())
        .merge(routes::xfer_router())
        .merge(routes::circle_router())
        .merge(routes::notify_router())
        // Health
        .route(
            "/api/v1/health",
            get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::middleware::require_auth,
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
        // SGX Guardian Wi-Fi Runtime Sub-Router (must be applied after .with_state returns Router<()>)
        .nest("/api/v1/wifi", wifi_router)
}

/// Entry point. Spawned from main.rs as a tokio task.
pub async fn serve(
    state: Arc<AppState>,
    bind: SocketAddr,
    tls: Option<AdminTls>,
    wifi_router: Router,
) -> anyhow::Result<()> {
    let app = build_router(state, wifi_router);

    match tls {
        Some(tls) => {
            let config = crate::api::tls::build_admin_server_config(&tls.cert_path, &tls.key_path)?;
            let listener = tokio::net::TcpListener::bind(bind).await?;
            tracing::info!("Admin REST API listening on https://{} (TLS)", bind);
            serve_tls_listener(listener, app, config).await?;
        }
        None => {
            tracing::warn!(
                "Admin REST API on http://{} (TLS DISABLED - dev only)",
                bind
            );
            let listener = tokio::net::TcpListener::bind(bind).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

async fn serve_tls_listener(
    listener: tokio::net::TcpListener,
    app: Router,
    config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(config);

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(connection) => connection,
            Err(err) => {
                tracing::warn!("Admin TLS accept error: {}", err);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::warn!(
                        "Rejected non-TLS or invalid TLS admin connection from {}: {}",
                        remote_addr,
                        err
                    );
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service = TowerToHyperService::new(app);
            let builder = HyperBuilder::new(TokioExecutor::new());
            if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                tracing::warn!("Admin TLS connection error from {}: {}", remote_addr, err);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::password;
    use crate::api::auth::store::{NewUser, UserRole};
    use crate::api::state::{AuthLockoutConfig, AuthRateLimitConfig};
    use crate::did::doc_persistence::{
        self, CA_AGGREGATE_PATH_ENV, PEERS_DOC_DIR_ENV, SELF_DOC_PATH_ENV, VERSION_COUNTER_PATH_ENV,
    };
    use crate::did::doc_sign;
    use crate::did::document::{DidDocument, DocBuildInput, RevokedVm};
    use crate::did::persistence::{DerivationProof, DidRecord};
    use crate::did::Did;
    use crate::key_manager::KeyManager;
    use crate::nebula::registry_sync::{RegistryRequest, RegistryResponse, REGISTRY_SYNC_PORT};
    use crate::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};
    use crate::vc::{issue, persistence};
    use chrono::Utc;
    use reqwest::StatusCode;
    use serde_json::Value;
    use sha2::Digest;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    const DEPLOYED_SIG_PATH: &str = "/etc/sgx-guardian/policies/policy.sig";

    struct EnvGuard {
        self_doc_prev: Option<OsString>,
        peers_dir_prev: Option<OsString>,
        aggregate_prev: Option<OsString>,
        counter_prev: Option<OsString>,
    }

    impl EnvGuard {
        fn new(self_doc_path: &Path, peers_dir: &Path, aggregate_path: &Path) -> Self {
            let counter_path = self_doc_path.with_file_name("self_version_counter");
            let self_doc_prev = std::env::var_os(SELF_DOC_PATH_ENV);
            let peers_dir_prev = std::env::var_os(PEERS_DOC_DIR_ENV);
            let aggregate_prev = std::env::var_os(CA_AGGREGATE_PATH_ENV);
            let counter_prev = std::env::var_os(VERSION_COUNTER_PATH_ENV);
            std::env::set_var(SELF_DOC_PATH_ENV, self_doc_path);
            std::env::set_var(PEERS_DOC_DIR_ENV, peers_dir);
            std::env::set_var(CA_AGGREGATE_PATH_ENV, aggregate_path);
            std::env::set_var(VERSION_COUNTER_PATH_ENV, counter_path);
            Self {
                self_doc_prev,
                peers_dir_prev,
                aggregate_prev,
                counter_prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            restore_env(SELF_DOC_PATH_ENV, self.self_doc_prev.take());
            restore_env(PEERS_DOC_DIR_ENV, self.peers_dir_prev.take());
            restore_env(CA_AGGREGATE_PATH_ENV, self.aggregate_prev.take());
            restore_env(VERSION_COUNTER_PATH_ENV, self.counter_prev.take());
        }
    }

    fn restore_env(key: &str, value: Option<OsString>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    struct ScopedEnvVar {
        key: &'static str,
        prev: Option<OsString>,
    }

    impl ScopedEnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            restore_env(self.key, self.prev.take());
        }
    }

    #[derive(Default)]
    struct ApiSe050State {
        available: bool,
        keys: HashMap<String, u8>,
    }

    struct ApiSe050Backend {
        state: Arc<std::sync::Mutex<ApiSe050State>>,
        utf8_marshaled_unwrap: bool,
    }

    impl ApiSe050Backend {
        fn available_with_utf8_marshaled_unwrap(utf8_marshaled_unwrap: bool) -> Arc<Self> {
            Arc::new(Self {
                state: Arc::new(std::sync::Mutex::new(ApiSe050State {
                    available: true,
                    ..Default::default()
                })),
                utf8_marshaled_unwrap,
            })
        }

        fn key_mask(key_id: &str) -> u8 {
            sha2::Sha256::digest(key_id.as_bytes())[0]
        }
    }

    impl crate::vault::wrapper::Se050WrapBackend for ApiSe050Backend {
        fn slot_exists(&self, key_id: &str) -> Result<bool, crate::vault::VaultError> {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            Ok(state.keys.contains_key(key_id))
        }

        fn provision_key(&self, key_id: &str) -> Result<(), crate::vault::VaultError> {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            state
                .keys
                .entry(key_id.to_string())
                .or_insert_with(|| Self::key_mask(key_id));
            Ok(())
        }

        fn wrap(&self, key_id: &str, plain: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
            let mask = {
                let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if !state.available {
                    return Err(crate::vault::VaultError::Crypto(
                        "mock SE050 unavailable".to_string(),
                    ));
                }
                *state.keys.get(key_id).ok_or_else(|| {
                    crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
                })?
            };
            Ok(plain.iter().map(|byte| byte ^ mask).collect())
        }

        fn unwrap(
            &self,
            key_id: &str,
            wrapped: &[u8],
        ) -> Result<Vec<u8>, crate::vault::VaultError> {
            let mask = {
                let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if !state.available {
                    return Err(crate::vault::VaultError::Crypto(
                        "mock SE050 unavailable".to_string(),
                    ));
                }
                *state.keys.get(key_id).ok_or_else(|| {
                    crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
                })?
            };
            let plain: Vec<u8> = wrapped.iter().map(|byte| byte ^ mask).collect();
            if self.utf8_marshaled_unwrap {
                Ok(crate::vault::wrapper::test_encode_ssscli_utf8_marshaled_bytes(&plain))
            } else {
                Ok(plain)
            }
        }
    }

    struct VcEnvGuard {
        doc_env: EnvGuard,
        did_path_prev: Option<OsString>,
        vc_base_prev: Option<OsString>,
        key_dir_prev: Option<OsString>,
        node_id_prev: Option<OsString>,
        audit_path_prev: Option<OsString>,
        did_path: PathBuf,
        key_dir: PathBuf,
        audit_log_path: PathBuf,
        _td: TempDir,
    }

    impl VcEnvGuard {
        fn new() -> Self {
            let td = TempDir::new().expect("vc tempdir");
            let self_doc_path = td.path().join("identity").join("did_doc.json");
            let peers_dir = td.path().join("identity").join("peers");
            let aggregate_path = td.path().join("identity").join("circle_did_docs.json");
            let did_path = td.path().join("identity").join("did.json");
            let vc_base = td.path().join("identity").join("vc");
            let key_dir = td.path().join("sgx-agent");
            let log_dir = td.path().join("logs");
            let audit_log_path = log_dir.join("audit-vc-test.log");
            let doc_env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate_path);
            let did_path_prev = std::env::var_os("SGX_GUARDIAN_DID_PATH");
            let vc_base_prev = std::env::var_os(crate::vc::persistence::VC_BASE_ENV);
            let key_dir_prev = std::env::var_os(crate::vc::issue::DEVICE_KEY_DIR_ENV);
            let node_id_prev = std::env::var_os("SGX_NODE_ID");
            let audit_path_prev = std::env::var_os("SGX_GUARDIAN_AUDIT_LOG_PATH");
            std::env::set_var("SGX_GUARDIAN_DID_PATH", &did_path);
            std::env::set_var(crate::vc::persistence::VC_BASE_ENV, &vc_base);
            std::env::set_var(crate::vc::issue::DEVICE_KEY_DIR_ENV, &key_dir);
            std::env::set_var("SGX_NODE_ID", "nodeA");
            std::env::set_var("SGX_GUARDIAN_AUDIT_LOG_PATH", &audit_log_path);
            std::fs::create_dir_all(&key_dir).expect("create key dir");
            std::fs::create_dir_all(&log_dir).expect("create log dir");
            Self {
                doc_env,
                did_path_prev,
                vc_base_prev,
                key_dir_prev,
                node_id_prev,
                audit_path_prev,
                did_path,
                key_dir,
                audit_log_path,
                _td: td,
            }
        }

        fn state(&self) -> Arc<AppState> {
            AppState::for_tests(
                self._td.path(),
                "nodeA",
                self._td.path().join("config").to_string_lossy().to_string(),
            )
        }
    }

    impl Drop for VcEnvGuard {
        fn drop(&mut self) {
            restore_env("SGX_GUARDIAN_DID_PATH", self.did_path_prev.take());
            restore_env(
                crate::vc::persistence::VC_BASE_ENV,
                self.vc_base_prev.take(),
            );
            restore_env(
                crate::vc::issue::DEVICE_KEY_DIR_ENV,
                self.key_dir_prev.take(),
            );
            restore_env("SGX_NODE_ID", self.node_id_prev.take());
            restore_env("SGX_GUARDIAN_AUDIT_LOG_PATH", self.audit_path_prev.take());
            let _ = &self.doc_env;
        }
    }

    fn test_state() -> Arc<AppState> {
        let base = std::env::temp_dir().join(format!("sgx-guardian-api-{}", uuid::Uuid::new_v4()));
        AppState::for_tests(
            &base,
            "test-nodeA",
            base.join("config").to_string_lossy().to_string(),
        )
    }

    async fn spawn_api_with_state(state: Arc<AppState>) -> (String, tokio::task::JoinHandle<()>) {
        let app = build_router(state, Router::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });
        (format!("http://{}", addr), handle)
    }

    async fn authed_client_for_state(state: &Arc<AppState>) -> reqwest::Client {
        let user = state
            .admin
            .users
            .create(NewUser {
                name: "API Test Admin".into(),
                email: format!("api-test-{}@example.com", uuid::Uuid::new_v4()),
                pw_hash: "test-hash".into(),
                role: UserRole::Owner,
            })
            .await
            .expect("seed API test user");
        let (token, _, session_rec) = crate::api::auth::session::issue(
            state.signer.clone(),
            &state.device_did,
            &user,
            Duration::from_secs(300),
        )
        .await
        .expect("issue API test token");
        state
            .admin
            .sessions
            .put(session_rec)
            .await
            .expect("store API test session");

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                .expect("authorization header"),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("authorized API test client")
    }

    async fn spawn_authed_api() -> (String, reqwest::Client, tokio::task::JoinHandle<()>) {
        spawn_authed_api_with_state(test_state()).await
    }

    async fn spawn_authed_api_with_state(
        state: Arc<AppState>,
    ) -> (String, reqwest::Client, tokio::task::JoinHandle<()>) {
        let client = authed_client_for_state(&state).await;
        let (base_url, handle) = spawn_api_with_state(state).await;
        (base_url, client, handle)
    }

    async fn spawn_secured_api_with_state(
        state: Arc<AppState>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = build_router(state.clone(), Router::new()).layer(
            axum::middleware::from_fn_with_state(state, auth::middleware::require_auth),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind secured test listener");
        let addr = listener.local_addr().expect("secured listener addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });
        (format!("http://{}", addr), handle)
    }

    fn write_test_tls_materials(dir: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
        let cert_path = dir.join("device_nodeA_cert.der");
        let key_path = dir.join("device_nodeA.key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "nodeA");
        params.subject_alt_names.push(rcgen::SanType::IpAddress(
            "127.0.0.1".parse().expect("loopback"),
        ));
        let cert = rcgen::Certificate::from_params(params).expect("build test cert");
        let cert_der = cert.serialize_der().expect("serialize cert");
        std::fs::write(&cert_path, &cert_der).expect("write cert");
        std::fs::write(&key_path, cert.serialize_private_key_der()).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key");
        }
        (cert_path, key_path, cert_der)
    }

    async fn spawn_https_secured_api_with_state(
        state: Arc<AppState>,
    ) -> (String, Vec<u8>, tokio::task::JoinHandle<()>) {
        let tls_dir = TempDir::new().expect("tls tempdir");
        let (cert_path, key_path, cert_der) = write_test_tls_materials(tls_dir.path());
        let config = crate::api::tls::build_admin_server_config(
            cert_path.to_str().expect("cert path"),
            key_path.to_str().expect("key path"),
        )
        .expect("build admin tls config");
        let app = build_router(state.clone(), Router::new()).layer(
            axum::middleware::from_fn_with_state(state, auth::middleware::require_auth),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind https test listener");
        let addr = listener.local_addr().expect("https listener addr");
        let handle = tokio::spawn(async move {
            let _tls_dir = tls_dir;
            let _ = serve_tls_listener(listener, app, config).await;
        });
        (format!("https://{}", addr), cert_der, handle)
    }

    fn auth_test_state(auth_lockout: AuthLockoutConfig) -> Arc<AppState> {
        auth_test_state_with_limits(auth_lockout, AuthRateLimitConfig::default())
    }

    fn auth_test_state_with_limits(
        auth_lockout: AuthLockoutConfig,
        auth_rate_limit: AuthRateLimitConfig,
    ) -> Arc<AppState> {
        let base = std::env::temp_dir().join(format!("sgx-guardian-auth-{}", uuid::Uuid::new_v4()));
        let mut state = (*AppState::for_tests(
            &base,
            "auth-nodeA",
            base.join("config").to_string_lossy().to_string(),
        ))
        .clone();
        state.auth_lockout = auth_lockout;
        state.auth_rate_limit = auth_rate_limit;
        Arc::new(state)
    }

    async fn seed_auth_user(state: &Arc<AppState>, email: &str, password: &str) {
        let pw_hash = password::hash_password(password.to_string())
            .await
            .expect("hash auth password");
        state
            .admin
            .users
            .create_initial_owner(NewUser {
                name: "Admin".into(),
                email: email.into(),
                pw_hash,
                role: UserRole::Owner,
            })
            .await
            .expect("seed auth user");
    }

    async fn auth_user(state: &Arc<AppState>, email: &str) -> crate::api::auth::store::User {
        state
            .admin
            .users
            .find_by_email(email)
            .await
            .expect("lookup auth user")
            .expect("auth user exists")
    }

    async fn login_request(
        client: &reqwest::Client,
        base_url: &str,
        email: &str,
        password: &str,
    ) -> reqwest::Response {
        client
            .post(format!("{}/api/v1/auth/login", base_url))
            .json(&serde_json::json!({
                "email": email,
                "password": password,
            }))
            .send()
            .await
            .expect("login request")
    }

    async fn signup_request(
        client: &reqwest::Client,
        base_url: &str,
        name: &str,
        email: &str,
        password: &str,
    ) -> reqwest::Response {
        client
            .post(format!("{}/api/v1/auth/signup", base_url))
            .json(&serde_json::json!({
                "name": name,
                "email": email,
                "password": password,
            }))
            .send()
            .await
            .expect("signup request")
    }

    struct PairDeviceSpec<'a> {
        serial: &'a str,
        node_id: &'a str,
        device_did: &'a str,
        seed: u8,
    }

    async fn pair_device_via_api(
        state: &Arc<AppState>,
        client: &reqwest::Client,
        base_url: &str,
        token: &str,
        device: PairDeviceSpec<'_>,
    ) -> (String, String) {
        let challenge_response: Value = client
            .get(format!("{}/api/v1/devices/pairing-code", base_url))
            .query(&[("serial", device.serial), ("ttl_secs", "300")])
            .bearer_auth(token)
            .send()
            .await
            .expect("pairing code request")
            .json()
            .await
            .expect("pairing code body");

        let key_dir = std::env::temp_dir().join(format!(
            "sgx-guardian-device-{}-{}",
            device.node_id,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&key_dir).expect("create device key dir");
        let key_path = key_dir.join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("device key path"))
                .expect("load device key"),
        );
        let proof = crate::api::auth::pairing::build_pairing_proof(
            challenge_response["pairingCode"]
                .as_str()
                .expect("pairing code"),
            device.node_id,
            device.device_did,
            &signer.pubkey_der().expect("device pubkey"),
            signer.clone(),
        )
        .await
        .expect("build pairing proof");

        let pair_response = client
            .post(format!("{}/api/v1/devices/pair", base_url))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "serial": device.serial,
                "proof": proof,
            }))
            .send()
            .await
            .expect("pair device request");
        assert_eq!(pair_response.status(), StatusCode::OK);
        let pair_body: Value = pair_response.json().await.expect("pair device body");
        let device_id = pair_body["deviceId"]
            .as_str()
            .expect("paired device id")
            .to_string();

        let challenge = crate::api::auth::pairing::decode_challenge(
            challenge_response["pairingCode"]
                .as_str()
                .expect("pairing code"),
        )
        .expect("decode pairing challenge");
        let authorized = crate::api::auth::pairing::authorize_pairing_proof(
            state.admin.as_ref(),
            &proof,
            crate::api::auth::pairing::PairingUsage::Bootstrap,
        )
        .await
        .expect("authorize bootstrap proof");
        state
            .admin
            .finalize_bootstrap(&authorized)
            .await
            .expect("finalize bootstrap");

        let peer_doc = signed_doc(
            device.device_did,
            device.node_id,
            device.seed as u32,
            1,
            "active",
            vec![],
            true,
        );
        doc_persistence::save_peer(&peer_doc).expect("save peer did doc");

        assert_eq!(challenge.serial, device.serial);
        (device_id, proof)
    }

    fn write_test_node_config(state: &Arc<AppState>) {
        let config_dir = Path::new(&state.config_dir);
        std::fs::create_dir_all(config_dir).expect("create node config dir");
        std::fs::write(
            config_dir.join(format!("{}.yaml", state.node_id)),
            format!(
                "node_id: {}\nhostname: localhost\nip: 127.0.0.1\nport: 8443\npublic_key: test-public-key\n",
                state.node_id
            ),
        )
        .expect("write node config");
    }

    fn tamper_jwt_signature(token: &str) -> String {
        let mut parts = token.split('.');
        let header = parts.next().expect("jwt header");
        let claims = parts.next().expect("jwt claims");
        let mut signature = parts.next().expect("jwt signature").to_string();
        assert!(parts.next().is_none(), "jwt should have exactly 3 parts");
        let last = signature.pop().expect("jwt signature character");
        signature.push(if last == 'A' { 'B' } else { 'A' });
        format!("{}.{}.{}", header, claims, signature)
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn vault_download_and_preview_routes_stream_original_bytes_with_se050_after_restart() {
        let _vault_lock = crate::vault::lock_test_env().await;
        let _xfer_lock = crate::xfer::lock_test_env().await;
        let td = TempDir::new().expect("tempdir");
        let vault_base = td.path().join("vault");
        let vault_base_value = vault_base.to_string_lossy().to_string();
        let _vault_base = ScopedEnvVar::set(crate::vault::VAULT_BASE_ENV, &vault_base_value);
        let _node_id = ScopedEnvVar::set("SGX_NODE_ID", "nodeA");
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Production,
        );
        let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(
            ApiSe050Backend::available_with_utf8_marshaled_unwrap(true),
        );

        let payload = b"\x89PNG\r\n\x1a\nse050-api-regression".to_vec();
        let input_path = td.path().join("se050-preview.png");
        tokio::fs::write(&input_path, &payload)
            .await
            .expect("write preview fixture");

        let record = crate::vault::ingest::ingest_file(
            "guardian-circle-alpha",
            "did:guardian:sender",
            &input_path,
            crate::vault::ingest::IngestMeta {
                filename: "se050-preview.png".into(),
                mime: "image/png".into(),
                sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
                size_plain: payload.len() as u64,
                chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
            },
        )
        .await
        .expect("ingest hardware-backed vault record");

        let download = crate::api::handlers::vault::download(
            axum::extract::State(test_state()),
            axum::extract::Path(record.vault_id.clone()),
        )
        .await
        .expect("download response");
        assert_eq!(download.status(), StatusCode::OK);
        let downloaded = axum::body::to_bytes(download.into_body(), usize::MAX)
            .await
            .expect("downloaded bytes");
        assert_eq!(downloaded.as_ref(), payload.as_slice());
        assert_eq!(
            hex::encode(sha2::Sha256::digest(downloaded.as_ref())),
            record.sha256_plain
        );

        let preview = crate::api::handlers::vault::preview(
            axum::extract::State(test_state()),
            axum::extract::Path(record.vault_id.clone()),
        )
        .await
        .expect("preview response");
        assert_eq!(preview.status(), StatusCode::OK);
        let previewed = axum::body::to_bytes(preview.into_body(), usize::MAX)
            .await
            .expect("preview bytes");
        assert_eq!(previewed.as_ref(), payload.as_slice());

        let restart_download = crate::api::handlers::vault::download(
            axum::extract::State(test_state()),
            axum::extract::Path(record.vault_id.clone()),
        )
        .await
        .expect("download after restart response");
        assert_eq!(restart_download.status(), StatusCode::OK);
        let restarted_bytes = axum::body::to_bytes(restart_download.into_body(), usize::MAX)
            .await
            .expect("download bytes after restart");
        assert_eq!(restarted_bytes.as_ref(), payload.as_slice());
        assert_eq!(
            hex::encode(sha2::Sha256::digest(restarted_bytes.as_ref())),
            record.sha256_plain
        );
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn vault_quota_endpoint_reports_namespace_usage() {
        let _vault_lock = crate::vault::lock_test_env().await;
        let td = TempDir::new().expect("tempdir");
        let vault_base = td.path().join("vault");
        let vault_base_value = vault_base.to_string_lossy().to_string();
        let _vault_base = ScopedEnvVar::set(crate::vault::VAULT_BASE_ENV, &vault_base_value);
        let config = crate::vault::VaultConfig::from_env();
        crate::vault::quota::save_settings(
            &config,
            &crate::vault::quota::VaultQuotaSettings {
                personal_quota_bytes: 500,
                circle_quota_bytes: 700,
            },
        )
        .await
        .expect("save quota settings");
        crate::vault::persistence::save_record(
            &config,
            &crate::vault::VaultRecord {
                vault_id: "urn:uuid:quota-personal".into(),
                namespace: crate::vault::VaultNamespace::PERSONAL_STORAGE_KEY.to_string(),
                circle_id: String::new(),
                filename: "quota.txt".into(),
                mime: "text/plain".into(),
                size_plain: 32,
                size_cipher: 200,
                sha256_plain: "aa".repeat(32),
                sender_did: "did:guardian:sender".into(),
                received_at: "2026-07-18T00:00:00Z".into(),
                source: crate::vault::VaultSource::Upload,
                folder_id: String::new(),
                starred: false,
                enc: crate::vault::EncMeta {
                    algo: "AES-256-GCM/STREAM-BE32".into(),
                    chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
                    base_nonce_b64: "bm9uY2VwcmU=".into(),
                    wrapped_dek_b64: "d3JhcHBlZA==".into(),
                    wrap_scheme: "software-hkdf".into(),
                    wrap_key_id: "software-master-v1".into(),
                },
            },
        )
        .await
        .expect("save quota record");

        let response = crate::api::handlers::vault::quota_status(
            axum::extract::State(test_state()),
            axum::extract::Query(crate::api::handlers::vault::VaultQuotaQuery {
                ns: Some("personal".into()),
                circle_id: None,
            }),
        )
        .await
        .expect("quota handler response");
        let body = response.0;

        assert_eq!(body.used_bytes, 200);
        assert_eq!(body.quota_bytes, 500);
        assert_eq!(body.remaining_bytes, 300);
        assert_eq!(body.usage_percent, 40.0);
    }

    fn make_vc_material(
        node_name: &str,
        seed: u8,
        overlay_ip_cidr: &str,
    ) -> (TempDir, KeyManager, DidRecord, DidDocument) {
        let td = TempDir::new().expect("vc key tempdir");
        let key_path = td.path().join(format!("device_{}.key", node_name));
        let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
        let pubkey = km.pubkey_der().expect("pubkey");
        let did = Did::from_id_bytes(&[seed; 32]);
        let did_str = did.to_string();
        let now = Utc::now().to_rfc3339();
        let record = DidRecord {
            did: did_str.clone(),
            method: "guardian".into(),
            method_version: "1.0".into(),
            did_id_b58: did.msi().to_string(),
            did_id_hex: hex::encode(did.id_bytes()),
            created_at: now.clone(),
            deactivated_at: None,
            derivation: DerivationProof {
                se050_uid: "01".into(),
                se050_uid_source: "test".into(),
                dkp_v1_pubkey_sha256_b16: "01".into(),
                dkp_v1_pubkey_path: "test".into(),
                dkp_v1_pubkey_der_b64: None,
                dik_pubkey_sha256_b16: "01".into(),
                dik_pubkey_der_b64: None,
            },
            current_dkp_version: 1,
            deriv_signature_b64: String::new(),
        };
        let mut doc = DidDocument::build(DocBuildInput {
            did: &did_str,
            node_name: Some(node_name),
            current_dkp_version: 1,
            current_dkp_pubkey_der: &pubkey,
            overlay_ip_cidr: Some(overlay_ip_cidr),
            attestation_bind: None,
            cert_bootstrap_bind: Some((
                overlay_ip_cidr.split('/').next().unwrap_or("127.0.0.1"),
                50061,
            )),
            revoked: vec![],
            previous_version_id: 0,
            created_at: Some(now),
            status: Some("active".into()),
        })
        .expect("build vc did doc");
        let vm_ref = doc.verification_method.first().expect("vm").id.clone();
        doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign vc did doc");
        (td, km, record, doc)
    }

    fn install_vc_runtime_material(
        env: &VcEnvGuard,
        km_dir: &TempDir,
        record: &DidRecord,
        doc: &DidDocument,
    ) {
        record
            .save(env.did_path.to_str().expect("did path"))
            .expect("save did record");
        doc_persistence::save_self(doc).expect("save self doc");
        doc_persistence::save_peer(doc).expect("save self peer doc");
        doc_persistence::save_ca_aggregate(std::slice::from_ref(doc)).expect("save aggregate");
        std::fs::copy(
            km_dir.path().join("device_nodeA.key"),
            env.key_dir.join("device_nodeA.key"),
        )
        .expect("copy runtime key");
    }

    fn write_audit_record(
        path: &Path,
        timestamp: u64,
        severity: &str,
        action: &str,
        message: &str,
    ) {
        let record = serde_json::json!({
            "previous_hash": "prev",
            "hash": "hash",
            "event": {
                "timestamp": timestamp,
                "node_id": "nodeA",
                "category": "Vc",
                "severity": severity,
                "action": action,
                "message": message
            }
        });
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open audit log");
        use std::io::Write;
        writeln!(file, "{}", record).expect("write audit record");
    }

    fn signed_doc(
        did: &str,
        node_name: &str,
        version: u32,
        current_dkp_version: u32,
        status: &str,
        revoked: Vec<RevokedVm>,
        include_cert_bootstrap: bool,
    ) -> DidDocument {
        let td = TempDir::new().expect("tempdir");
        let key_path = td.path().join("dkp.key");
        let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
        let der = km.pubkey_der().expect("pubkey der");
        let mut doc = DidDocument::build(DocBuildInput {
            did,
            node_name: Some(node_name),
            current_dkp_version,
            current_dkp_pubkey_der: &der,
            overlay_ip_cidr: Some("192.168.100.10/24"),
            attestation_bind: Some(("192.168.100.10", 50051)),
            cert_bootstrap_bind: include_cert_bootstrap.then_some(("192.168.100.10", 50061)),
            revoked,
            previous_version_id: version.saturating_sub(1),
            created_at: Some("2026-05-21T10:00:00Z".to_string()),
            status: Some(status.to_string()),
        })
        .expect("build did doc");
        let vm_ref = doc.verification_method[0].id.clone();
        doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign did doc");
        doc
    }

    async fn spawn_mock_ca_publish_server(
        expected_node_name: &'static str,
    ) -> tokio::task::JoinHandle<()> {
        let listener = TcpListener::bind(("127.0.0.1", REGISTRY_SYNC_PORT))
            .await
            .expect("bind mock ca");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept publish");
            let (reader, mut writer) = stream.into_split();
            let mut buffered = BufReader::new(reader);
            let mut line = String::new();
            buffered.read_line(&mut line).await.expect("read publish");
            let request: RegistryRequest =
                serde_json::from_str(line.trim()).expect("publish request json");
            assert_eq!(request.action, "publish_did_doc");
            assert_eq!(request.node_name, expected_node_name);
            let payload = request.did_doc_json.expect("did doc payload");
            let doc: DidDocument = serde_json::from_str(&payload).expect("publish doc json");
            assert!(doc.proof.is_some());

            let mut response = serde_json::to_string(&RegistryResponse {
                success: true,
                ..RegistryResponse::default()
            })
            .expect("publish response");
            response.push('\n');
            writer
                .write_all(response.as_bytes())
                .await
                .expect("write publish response");
        })
    }

    fn write_threat_alerts(path: &Path, alerts: &[ThreatAlert]) {
        let parent = path.parent().expect("alerts parent");
        std::fs::create_dir_all(parent).expect("create alerts dir");
        let payload = alerts
            .iter()
            .map(|alert| serde_json::to_string(alert).expect("serialize alert"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, format!("{}\n", payload)).expect("write alerts");
    }

    fn sample_threat_alert(signature_id: u32, signature: &str) -> ThreatAlert {
        ThreatAlert {
            alert_id: ThreatAlert::compute_id(signature_id, "192.168.50.115", "192.168.50.248"),
            timestamp: Utc::now(),
            src_ip: "192.168.50.115".into(),
            src_port: 43000,
            dst_ip: "192.168.50.248".into(),
            dst_port: 502,
            protocol: "TCP".into(),
            signature_id,
            signature: signature.into(),
            category: ThreatCategory::PolicyViolation,
            severity: Severity::High,
            rev: 1,
            gid: 1,
            event_type: "alert".into(),
            blocked: false,
        }
    }

    #[tokio::test]
    async fn verify_deployed_does_not_require_multipart_upload() {
        let (base_url, client, handle) = spawn_authed_api().await;
        let url = format!("{}/api/v1/policy/verify-deployed", base_url);
        let response = client
            .post(url)
            .send()
            .await
            .expect("request verify-deployed");
        handle.abort();
        assert_ne!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn verify_deployed_missing_signature_returns_not_found() {
        if std::path::Path::new(DEPLOYED_SIG_PATH).is_file() {
            // This assertion specifically validates the missing-file behavior.
            // Skip in environments where the deployed policy signature already exists.
            return;
        }

        let (base_url, client, handle) = spawn_authed_api().await;
        let url = format!("{}/api/v1/policy/verify-deployed", base_url);
        let response = client
            .post(url)
            .send()
            .await
            .expect("request verify-deployed");
        let status = response.status();
        let body: Value = response.json().await.expect("json error body");
        handle.abort();

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
        assert_eq!(
            body["error"]["message"],
            format!(
                "deployed policy signature not found at {}",
                DEPLOYED_SIG_PATH
            )
        );
    }

    #[tokio::test]
    async fn verify_upload_endpoint_still_requires_multipart_body() {
        let (base_url, client, handle) = spawn_authed_api().await;
        let url = format!("{}/api/v1/policy/verify", base_url);
        let response = client.post(url).send().await.expect("request verify");
        handle.abort();
        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::UNSUPPORTED_MEDIA_TYPE
            ),
            "expected multipart validation failure, got {}",
            response.status()
        );
    }

    // Held across .await deliberately: these tests mutate process-wide env
    // vars (SELF_DOC_PATH_ENV etc. via VcEnvGuard/EnvGuard) that the async
    // API calls read, so the lock must serialize the WHOLE test, not just
    // setup, against other tests running in parallel threads. #[tokio::test]
    // here defaults to a current-thread runtime, so there's no cross-thread
    // guard hand-off for this to deadlock.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn signup_creates_initial_owner_and_returns_session() {
        let state = auth_test_state(AuthLockoutConfig::default());
        let (base_url, handle) = spawn_secured_api_with_state(state.clone()).await;
        let client = reqwest::Client::new();

        let response = signup_request(
            &client,
            &base_url,
            "Admin",
            "admin@example.com",
            "GuardianPass123!",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.expect("signup body");
        let token = body["token"].as_str().expect("signup token");
        assert_eq!(body["email"], "admin@example.com");
        assert_eq!(body["role"], "owner");
        assert!(body["userId"].as_str().is_some());
        assert!(body["expiresAt"].as_i64().is_some());

        let session = client
            .get(format!("{}/api/v1/auth/session", base_url))
            .bearer_auth(token)
            .send()
            .await
            .expect("session after signup");
        assert_eq!(session.status(), StatusCode::OK);

        let stored = auth_user(&state, "admin@example.com").await;
        assert_eq!(stored.role, UserRole::Owner);
        assert_eq!(stored.status, "active");
        assert_ne!(stored.pw_hash, "GuardianPass123!");
        assert!(stored.pw_hash.starts_with("$argon2"));

        handle.abort();
    }

    #[tokio::test]
    async fn signup_rejects_weak_password() {
        let state = auth_test_state(AuthLockoutConfig::default());
        let (base_url, handle) = spawn_api_with_state(state).await;
        let client = reqwest::Client::new();

        let response =
            signup_request(&client, &base_url, "Admin", "admin@example.com", "weak").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = response.json().await.expect("weak signup body");
        assert_eq!(body["error"]["code"], "BAD_REQUEST");

        handle.abort();
    }

    #[tokio::test]
    async fn login_wrong_password_increments_failed_attempts() {
        let state = auth_test_state(AuthLockoutConfig {
            max_failed_attempts: 5,
            attempt_window_secs: 300,
            lockout_secs: 60,
        });
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        let (base_url, handle) = spawn_api_with_state(state.clone()).await;
        let client = reqwest::Client::new();

        let response =
            login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let user = auth_user(&state, "admin@example.com").await;
        assert_eq!(user.failed_attempts, 1);
        assert_eq!(user.locked_until, None);
        assert!(user.last_failed_at.is_some());

        handle.abort();
    }

    #[tokio::test]
    async fn login_threshold_sets_locked_until() {
        let state = auth_test_state(AuthLockoutConfig {
            max_failed_attempts: 5,
            attempt_window_secs: 300,
            lockout_secs: 60,
        });
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        let (base_url, handle) = spawn_api_with_state(state.clone()).await;
        let client = reqwest::Client::new();

        for attempt in 1..=5 {
            let response =
                login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
            if attempt < 5 {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(response.status(), StatusCode::LOCKED);
                let body: Value = response.json().await.expect("locked response body");
                assert_eq!(body["error"]["code"], "LOCKED");
            }
        }

        let user = auth_user(&state, "admin@example.com").await;
        assert_eq!(user.failed_attempts, 5);
        assert!(user.locked_until.is_some());
        assert!(user.locked_until.expect("locked until") > Utc::now().timestamp());

        handle.abort();
    }

    #[tokio::test]
    async fn login_rejects_correct_password_during_lockout() {
        let state = auth_test_state(AuthLockoutConfig {
            max_failed_attempts: 5,
            attempt_window_secs: 300,
            lockout_secs: 60,
        });
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        let (base_url, handle) = spawn_api_with_state(state).await;
        let client = reqwest::Client::new();

        for _ in 0..5 {
            let _ = login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
        }

        let response =
            login_request(&client, &base_url, "admin@example.com", "GuardianPass123!").await;
        assert_eq!(response.status(), StatusCode::LOCKED);
        let body: Value = response.json().await.expect("lockout body");
        assert_eq!(body["error"]["code"], "LOCKED");

        handle.abort();
    }

    #[tokio::test]
    async fn login_allows_success_after_lockout_expires() {
        let state = auth_test_state(AuthLockoutConfig {
            max_failed_attempts: 5,
            attempt_window_secs: 300,
            lockout_secs: 1,
        });
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        let (base_url, handle) = spawn_api_with_state(state.clone()).await;
        let client = reqwest::Client::new();

        for _ in 0..5 {
            let _ = login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
        }

        let locked =
            login_request(&client, &base_url, "admin@example.com", "GuardianPass123!").await;
        assert_eq!(locked.status(), StatusCode::LOCKED);

        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let success =
            login_request(&client, &base_url, "admin@example.com", "GuardianPass123!").await;
        assert_eq!(success.status(), StatusCode::OK);
        let body: Value = success.json().await.expect("success login body");
        assert!(body["token"].as_str().is_some());

        let user = auth_user(&state, "admin@example.com").await;
        assert_eq!(user.failed_attempts, 0);
        assert_eq!(user.locked_until, None);
        assert_eq!(user.last_failed_at, None);

        handle.abort();
    }

    #[tokio::test]
    async fn login_success_resets_failed_attempts() {
        let state = auth_test_state(AuthLockoutConfig {
            max_failed_attempts: 5,
            attempt_window_secs: 300,
            lockout_secs: 60,
        });
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        let (base_url, handle) = spawn_api_with_state(state.clone()).await;
        let client = reqwest::Client::new();

        for _ in 0..4 {
            let response =
                login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let success =
            login_request(&client, &base_url, "admin@example.com", "GuardianPass123!").await;
        assert_eq!(success.status(), StatusCode::OK);

        let user = auth_user(&state, "admin@example.com").await;
        assert_eq!(user.failed_attempts, 0);
        assert_eq!(user.locked_until, None);
        assert_eq!(user.last_failed_at, None);

        for _ in 0..4 {
            let response =
                login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let locked = login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
        assert_eq!(locked.status(), StatusCode::LOCKED);

        handle.abort();
    }

    #[tokio::test]
    async fn login_rate_limit_returns_too_many_requests() {
        let state = auth_test_state_with_limits(
            AuthLockoutConfig {
                max_failed_attempts: 5,
                attempt_window_secs: 300,
                lockout_secs: 60,
            },
            AuthRateLimitConfig {
                max_attempts: 2,
                window_secs: 60,
            },
        );
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        let (base_url, handle) = spawn_api_with_state(state).await;
        let client = reqwest::Client::new();

        for _ in 0..2 {
            let response =
                login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let limited = login_request(&client, &base_url, "admin@example.com", "WrongPass123!").await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let body: Value = limited.json().await.expect("rate limit body");
        assert_eq!(body["error"]["code"], "TOO_MANY_REQUESTS");

        handle.abort();
    }

    #[tokio::test]
    async fn fresh_login_token_works_on_session_and_node_status() {
        let state = auth_test_state(AuthLockoutConfig::default());
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        write_test_node_config(&state);
        let (base_url, handle) = spawn_secured_api_with_state(state).await;
        let client = reqwest::Client::new();

        let login =
            login_request(&client, &base_url, "admin@example.com", "GuardianPass123!").await;
        assert_eq!(login.status(), StatusCode::OK);
        let login_body: Value = login.json().await.expect("login body");
        let token = login_body["token"]
            .as_str()
            .expect("login token")
            .to_string();

        let session = client
            .get(format!("{}/api/v1/auth/session", base_url))
            .bearer_auth(&token)
            .send()
            .await
            .expect("session request");
        assert_eq!(session.status(), StatusCode::OK);
        let session_body: Value = session.json().await.expect("session body");
        assert_eq!(session_body["valid"], true);
        assert_eq!(session_body["userId"], login_body["user"]["id"]);
        assert_eq!(session_body["email"], login_body["user"]["email"]);
        assert_eq!(session_body["role"], login_body["user"]["role"]);
        assert_eq!(session_body["expiresAt"], login_body["expiresAt"]);

        let node_status = client
            .get(format!("{}/api/v1/node/status", base_url))
            .bearer_auth(&token)
            .send()
            .await
            .expect("node status request");
        assert_eq!(node_status.status(), StatusCode::OK);
        let node_body: Value = node_status.json().await.expect("node status body");
        assert_eq!(node_body["nodeId"], "auth-nodeA");
        assert_eq!(node_body["hostname"], "localhost");

        handle.abort();
    }

    #[tokio::test]
    async fn logout_revokes_active_session() {
        let state = auth_test_state(AuthLockoutConfig::default());
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        let (base_url, handle) = spawn_secured_api_with_state(state).await;
        let client = reqwest::Client::new();

        let login =
            login_request(&client, &base_url, "admin@example.com", "GuardianPass123!").await;
        assert_eq!(login.status(), StatusCode::OK);
        let login_body: Value = login.json().await.expect("login body");
        let token = login_body["token"].as_str().expect("login token");

        let logout = client
            .post(format!("{}/api/v1/auth/logout", base_url))
            .bearer_auth(token)
            .send()
            .await
            .expect("logout request");
        assert_eq!(logout.status(), StatusCode::OK);
        let logout_body: Value = logout.json().await.expect("logout body");
        assert_eq!(logout_body["status"], "logged_out");

        let session = client
            .get(format!("{}/api/v1/auth/session", base_url))
            .bearer_auth(token)
            .send()
            .await
            .expect("session after logout");
        assert_eq!(session.status(), StatusCode::UNAUTHORIZED);

        handle.abort();
    }

    #[tokio::test]
    async fn tampered_login_token_returns_unauthorized() {
        let state = auth_test_state(AuthLockoutConfig::default());
        seed_auth_user(&state, "admin@example.com", "GuardianPass123!").await;
        write_test_node_config(&state);
        let (base_url, handle) = spawn_secured_api_with_state(state).await;
        let client = reqwest::Client::new();

        let login =
            login_request(&client, &base_url, "admin@example.com", "GuardianPass123!").await;
        assert_eq!(login.status(), StatusCode::OK);
        let login_body: Value = login.json().await.expect("login body");
        let token = tamper_jwt_signature(login_body["token"].as_str().expect("login token"));

        for path in ["/api/v1/auth/session", "/api/v1/node/status"] {
            let response = client
                .get(format!("{}{}", base_url, path))
                .bearer_auth(&token)
                .send()
                .await
                .expect("tampered token request");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        handle.abort();
    }

    #[tokio::test]
    async fn pairing_and_device_dashboard_flow_work_for_node_b_and_node_c() {
        let _lock = crate::test_support::async_env_lock().await;
        let env = VcEnvGuard::new();
        let state = auth_test_state(AuthLockoutConfig::default());
        write_test_node_config(&state);
        let (base_url, handle) = spawn_secured_api_with_state(state.clone()).await;
        let client = reqwest::Client::new();

        let signup = signup_request(
            &client,
            &base_url,
            "Admin",
            "admin@example.com",
            "GuardianPass123!",
        )
        .await;
        assert_eq!(signup.status(), StatusCode::OK);
        let signup_body: Value = signup.json().await.expect("signup body");
        let token = signup_body["token"]
            .as_str()
            .expect("signup token")
            .to_string();
        let user_id = signup_body["userId"]
            .as_str()
            .expect("signup user id")
            .to_string();

        let node_b_did = Did::from_id_bytes(&[41u8; 32]).to_string();
        let (node_b_device_id, node_b_proof) = pair_device_via_api(
            &state,
            &client,
            &base_url,
            &token,
            PairDeviceSpec {
                serial: "GX-2024-TX-042-B9F3",
                node_id: "nodeB",
                device_did: &node_b_did,
                seed: 41,
            },
        )
        .await;

        let node_c_did = Did::from_id_bytes(&[42u8; 32]).to_string();
        let (node_c_device_id, _node_c_proof) = pair_device_via_api(
            &state,
            &client,
            &base_url,
            &token,
            PairDeviceSpec {
                serial: "GX-2024-TX-042-C9F3",
                node_id: "nodeC",
                device_did: &node_c_did,
                seed: 42,
            },
        )
        .await;

        let node_b_status = client
            .get(format!("{}/api/v1/devices/pairing-status", base_url))
            .query(&[("serial", "GX-2024-TX-042-B9F3")])
            .bearer_auth(&token)
            .send()
            .await
            .expect("node b pairing status");
        assert_eq!(node_b_status.status(), StatusCode::OK);
        let node_b_status_body: Value = node_b_status.json().await.expect("node b pairing body");
        assert_eq!(node_b_status_body["status"], "completed");
        assert_eq!(node_b_status_body["apiConsumed"], true);
        assert_eq!(node_b_status_body["bootstrapConsumed"], true);
        assert_eq!(node_b_status_body["deviceId"], node_b_device_id);
        assert_eq!(node_b_status_body["nodeId"], "nodeB");
        assert_eq!(node_b_status_body["did"], node_b_did);

        let node_c_status = client
            .get(format!("{}/api/v1/devices/pairing-status", base_url))
            .query(&[("serial", "GX-2024-TX-042-C9F3")])
            .bearer_auth(&token)
            .send()
            .await
            .expect("node c pairing status");
        assert_eq!(node_c_status.status(), StatusCode::OK);
        let node_c_status_body: Value = node_c_status.json().await.expect("node c pairing body");
        assert_eq!(node_c_status_body["status"], "completed");
        assert_eq!(node_c_status_body["apiConsumed"], true);
        assert_eq!(node_c_status_body["bootstrapConsumed"], true);
        assert_eq!(node_c_status_body["deviceId"], node_c_device_id);
        assert_eq!(node_c_status_body["nodeId"], "nodeC");
        assert_eq!(node_c_status_body["did"], node_c_did);

        let detail = client
            .get(format!("{}/api/v1/devices/{}", base_url, node_b_device_id))
            .bearer_auth(&token)
            .send()
            .await
            .expect("device detail");
        assert_eq!(detail.status(), StatusCode::OK);
        let detail_body: Value = detail.json().await.expect("device detail body");
        assert_eq!(detail_body["bootstrapStatus"], "completed");
        assert_eq!(detail_body["overlayIp"], "192.168.100.10");
        assert_eq!(
            detail_body["attestationEndpoint"],
            "tcp://192.168.100.10:50051"
        );

        let devices = client
            .get(format!("{}/api/v1/devices", base_url))
            .bearer_auth(&token)
            .send()
            .await
            .expect("devices list");
        assert_eq!(devices.status(), StatusCode::OK);
        let mut devices_body: Vec<Value> = devices.json().await.expect("devices body");
        devices_body.sort_by(|left, right| {
            left["serial"]
                .as_str()
                .unwrap_or_default()
                .cmp(right["serial"].as_str().unwrap_or_default())
        });
        assert_eq!(devices_body.len(), 2);
        assert_eq!(devices_body[0]["serial"], "GX-2024-TX-042-B9F3");
        assert_eq!(devices_body[0]["status"], "active");
        assert_eq!(devices_body[0]["nodeId"], "nodeB");
        assert_eq!(devices_body[1]["serial"], "GX-2024-TX-042-C9F3");
        assert_eq!(devices_body[1]["status"], "active");
        assert_eq!(devices_body[1]["nodeId"], "nodeC");

        let replay = client
            .post(format!("{}/api/v1/devices/pair", base_url))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "serial": "GX-2024-TX-042-B9F3",
                "proof": node_b_proof,
            }))
            .send()
            .await
            .expect("replay pair proof");
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

        let tampered = client
            .get(format!("{}/api/v1/devices", base_url))
            .send()
            .await
            .expect("missing bearer devices");
        assert_eq!(tampered.status(), StatusCode::UNAUTHORIZED);

        assert_eq!(
            state
                .admin
                .devices
                .list(&user_id)
                .await
                .expect("admin device store list")
                .len(),
            2
        );

        let pairings = state.admin.pairings.list().await.expect("pairing records");
        assert_eq!(pairings.len(), 2);
        assert!(pairings.iter().all(|pairing| pairing.api_consumed));
        assert!(pairings.iter().all(|pairing| pairing.bootstrap_consumed));

        let expired_challenge = crate::api::auth::pairing::PairingChallenge {
            serial: "GX-2024-TX-042-EXPIRED".into(),
            challenge: "expired".into(),
            nonce: "deadbeefdeadbeef".into(),
            exp: Utc::now().timestamp() - 10,
            issued_at: Utc::now().timestamp() - 20,
        };
        state
            .admin
            .pairings
            .put(crate::api::auth::pairing::record_from_challenge(
                &expired_challenge,
                &user_id,
            ))
            .await
            .expect("store expired challenge");
        let expired_key_dir = std::env::temp_dir().join(format!(
            "sgx-guardian-expired-device-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&expired_key_dir).expect("expired key dir");
        let expired_signer = Arc::new(
            KeyManager::load_or_generate(
                expired_key_dir
                    .join("device.key")
                    .to_str()
                    .expect("expired device key path"),
            )
            .expect("expired device key"),
        );
        let expired_code = crate::api::auth::pairing::encode_challenge(&expired_challenge)
            .expect("encode expired challenge");
        let expired_proof = crate::api::auth::pairing::build_pairing_proof(
            &expired_code,
            "nodeExpired",
            &Did::from_id_bytes(&[43u8; 32]).to_string(),
            &expired_signer.pubkey_der().expect("expired pubkey"),
            expired_signer,
        )
        .await
        .expect("expired proof");
        let expired_pair = client
            .post(format!("{}/api/v1/devices/pair", base_url))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "serial": "GX-2024-TX-042-EXPIRED",
                "proof": expired_proof,
            }))
            .send()
            .await
            .expect("expired pair request");
        assert_eq!(expired_pair.status(), StatusCode::BAD_REQUEST);

        let unpair = client
            .post(format!(
                "{}/api/v1/devices/{}/unpair",
                base_url, node_c_device_id
            ))
            .bearer_auth(&token)
            .send()
            .await
            .expect("unpair request");
        assert_eq!(unpair.status(), StatusCode::OK);
        let unpair_body: Value = unpair.json().await.expect("unpair body");
        assert_eq!(unpair_body["deviceId"], node_c_device_id);
        assert_eq!(unpair_body["status"], "unpaired");

        let devices_after_unpair = client
            .get(format!("{}/api/v1/devices", base_url))
            .bearer_auth(&token)
            .send()
            .await
            .expect("devices after unpair");
        let devices_after_unpair_body: Vec<Value> = devices_after_unpair
            .json()
            .await
            .expect("devices after unpair body");
        assert_eq!(devices_after_unpair_body.len(), 1);
        assert_eq!(devices_after_unpair_body[0]["deviceId"], node_b_device_id);

        let _ = env;
        handle.abort();
    }

    #[tokio::test]
    async fn vc_issue_reuse_status_and_safe_file_reads_work() {
        let _lock = crate::test_support::async_env_lock().await;
        let env = VcEnvGuard::new();
        let (km_dir, _km, issuer, doc) = make_vc_material("nodeA", 7, "192.168.100.1/24");
        install_vc_runtime_material(&env, &km_dir, &issuer, &doc);

        let (base_url, client, handle) = spawn_authed_api_with_state(env.state()).await;
        let subject = Did::from_id_bytes(&[8u8; 32]).to_string();

        let first = client
            .post(format!("{}/api/v1/vc/issue", base_url))
            .json(&serde_json::json!({
                "to": subject,
                "role": "member",
                "days": 30
            }))
            .send()
            .await
            .expect("first vc issue");
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body: Value = first.json().await.expect("first vc issue body");
        let vc_id = first_body["vc_id"].as_str().expect("vc id").to_string();
        assert_eq!(first_body["reused"], false);

        let issued_path = persistence::issued_path_for_id(&vc_id);
        let modified_before = std::fs::metadata(&issued_path)
            .expect("issued metadata")
            .modified()
            .expect("issued mtime");
        let next_index_before =
            std::fs::read_to_string(persistence::status_list_index_path()).expect("next index");

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let second = client
            .post(format!("{}/api/v1/vc/issue", base_url))
            .json(&serde_json::json!({
                "to": first_body["subject"].as_str().expect("subject"),
                "role": "member",
                "days": 365
            }))
            .send()
            .await
            .expect("second vc issue");
        assert_eq!(second.status(), StatusCode::OK);
        let second_body: Value = second.json().await.expect("second vc issue body");
        assert_eq!(second_body["reused"], true);
        assert_eq!(
            second_body["message"],
            "Existing active VC found — no changes made"
        );
        assert_eq!(second_body["vc_id"], vc_id);

        let modified_after = std::fs::metadata(&issued_path)
            .expect("issued metadata after")
            .modified()
            .expect("issued mtime after");
        let next_index_after =
            std::fs::read_to_string(persistence::status_list_index_path()).expect("next index");
        assert_eq!(modified_before, modified_after);
        assert_eq!(next_index_before, next_index_after);

        let show: Value = client
            .get(format!("{}/api/v1/vc/show", base_url))
            .query(&[("scope", "issued"), ("status", "active")])
            .send()
            .await
            .expect("vc show request")
            .json()
            .await
            .expect("vc show body");
        assert_eq!(show["status"], "success");
        assert_eq!(show["count"], 1);
        assert_eq!(show["items"][0]["vc_id"], vc_id);
        assert_eq!(show["items"][0]["source_scope"], "issued");

        let status: Value = client
            .get(format!("{}/api/v1/vc/status/{}", base_url, vc_id))
            .send()
            .await
            .expect("vc status request")
            .json()
            .await
            .expect("vc status body");
        assert_eq!(status["active"], true);
        assert_eq!(status["revoked"], false);
        assert_eq!(status["expired"], false);

        let full_vc: Value = client
            .get(format!("{}/api/v1/vc/files/issued/{}", base_url, vc_id))
            .send()
            .await
            .expect("vc file request")
            .json()
            .await
            .expect("vc file body");
        assert_eq!(full_vc["id"], vc_id);

        handle.abort();
    }

    #[allow(clippy::await_holding_lock)] // see vc_issue_reuse_status_and_safe_file_reads_work
    #[tokio::test]
    async fn vc_renew_verify_revoke_summary_and_audit_routes_work() {
        let _lock = crate::test_support::async_env_lock().await;
        let env = VcEnvGuard::new();
        let (km_dir, km, issuer, doc) = make_vc_material("nodeA", 9, "192.168.100.1/24");
        install_vc_runtime_material(&env, &km_dir, &issuer, &doc);
        let _owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("ensure owner vc");

        let (base_url, client, handle) = spawn_authed_api_with_state(env.state()).await;
        let subject = Did::from_id_bytes(&[10u8; 32]).to_string();

        let issued: Value = client
            .post(format!("{}/api/v1/vc/issue", base_url))
            .json(&serde_json::json!({
                "to": subject,
                "role": "member",
                "days": 30
            }))
            .send()
            .await
            .expect("issue member vc")
            .json()
            .await
            .expect("issue member vc body");
        let vc_id = issued["vc_id"].as_str().expect("issued vc id").to_string();
        let old_expiration = issued["vc"]["expirationDate"]
            .as_str()
            .expect("old expiration")
            .to_string();
        let old_proof_created = issued["vc"]["proof"]["created"]
            .as_str()
            .expect("old proof created")
            .to_string();
        let old_proof_value = issued["vc"]["proof"]["proofValue"]
            .as_str()
            .expect("old proof value")
            .to_string();
        let issued_vc: crate::vc::credential::VerifiableCredential =
            serde_json::from_value(issued["vc"].clone()).expect("issued vc");
        persistence::save_peer(&subject, &issued_vc).expect("seed peer cached vc");
        let next_index_before =
            std::fs::read_to_string(persistence::status_list_index_path()).expect("next index");

        tokio::time::sleep(Duration::from_millis(20)).await;

        let renewed: Value = client
            .post(format!("{}/api/v1/vc/renew", base_url))
            .json(&serde_json::json!({
                "id": vc_id,
                "days": 90
            }))
            .send()
            .await
            .expect("renew vc")
            .json()
            .await
            .expect("renew vc body");
        assert_eq!(renewed["status"], "success");
        assert_eq!(renewed["vc_id"], issued["vc_id"]);
        assert_eq!(renewed["old_expiration"], old_expiration);
        assert_ne!(renewed["new_expiration"], old_expiration);
        assert_ne!(renewed["vc"]["proof"]["created"], old_proof_created);
        assert_ne!(renewed["vc"]["proof"]["proofValue"], old_proof_value);
        assert_eq!(renewed["vc"]["issuanceDate"], issued["vc"]["issuanceDate"]);
        assert_eq!(
            renewed["vc"]["credentialStatus"]["statusListIndex"],
            issued["vc"]["credentialStatus"]["statusListIndex"]
        );
        let renewed_issued_file: Value = client
            .get(format!("{}/api/v1/vc/files/issued/{}", base_url, vc_id))
            .send()
            .await
            .expect("issued vc file")
            .json()
            .await
            .expect("issued vc file body");
        let renewed_peer_file: Value = client
            .get(format!("{}/api/v1/vc/files/peer/{}", base_url, subject))
            .send()
            .await
            .expect("peer vc file")
            .json()
            .await
            .expect("peer vc file body");
        assert_eq!(
            renewed_issued_file["expirationDate"],
            renewed_peer_file["expirationDate"]
        );
        assert_eq!(
            renewed_issued_file["proof"]["created"],
            renewed_peer_file["proof"]["created"]
        );
        assert_eq!(
            renewed_issued_file["proof"]["proofValue"],
            renewed_peer_file["proof"]["proofValue"]
        );
        assert_eq!(
            renewed_issued_file["issuanceDate"],
            issued["vc"]["issuanceDate"]
        );
        assert_eq!(
            renewed_issued_file["credentialStatus"]["statusListIndex"],
            issued["vc"]["credentialStatus"]["statusListIndex"]
        );
        assert_eq!(
            next_index_before,
            std::fs::read_to_string(persistence::status_list_index_path()).expect("next index")
        );

        let verify_ok: Value = client
            .post(format!("{}/api/v1/vc/verify", base_url))
            .json(&serde_json::json!({ "id": issued["vc_id"] }))
            .send()
            .await
            .expect("verify vc")
            .json()
            .await
            .expect("verify vc body");
        assert_eq!(verify_ok["valid"], true);

        let revoke: Value = client
            .post(format!("{}/api/v1/vc/revoke", base_url))
            .json(&serde_json::json!({
                "id": issued["vc_id"],
                "reason": "member removed from circle"
            }))
            .send()
            .await
            .expect("revoke vc")
            .json()
            .await
            .expect("revoke vc body");
        assert_eq!(revoke["revoked"], true);

        let verify_revoked: Value = client
            .post(format!("{}/api/v1/vc/verify", base_url))
            .json(&serde_json::json!({ "id": issued["vc_id"] }))
            .send()
            .await
            .expect("verify revoked vc")
            .json()
            .await
            .expect("verify revoked vc body");
        assert_eq!(verify_revoked["valid"], false);
        assert!(verify_revoked["reason"]
            .as_str()
            .expect("revoked reason")
            .contains("revoked"));

        let status: Value = client
            .get(format!("{}/api/v1/vc/status/{}", base_url, vc_id))
            .send()
            .await
            .expect("status after revoke")
            .json()
            .await
            .expect("status after revoke body");
        assert_eq!(status["revoked"], true);
        assert_eq!(status["active"], false);

        let own_files: Value = client
            .get(format!("{}/api/v1/vc/files/own", base_url))
            .send()
            .await
            .expect("own files")
            .json()
            .await
            .expect("own files body");
        assert_eq!(own_files["count"], 1);

        let peer_files: Value = client
            .get(format!("{}/api/v1/vc/files/peers", base_url))
            .send()
            .await
            .expect("peer files")
            .json()
            .await
            .expect("peer files body");
        assert_eq!(peer_files["count"], 1);

        let summary: Value = client
            .get(format!("{}/api/v1/vc/summary", base_url))
            .send()
            .await
            .expect("vc summary")
            .json()
            .await
            .expect("vc summary body");
        assert_eq!(summary["issued_total"], 2);
        assert_eq!(summary["own_total"], 1);
        assert_eq!(summary["peer_total"], 1);
        assert_eq!(summary["active_total"], 1);
        assert_eq!(summary["revoked_total"], 1);
        assert_eq!(summary["expired_total"], 0);
        assert_eq!(summary["next_index"], 2);

        write_audit_record(
            &env.audit_log_path,
            1,
            "Info",
            "Loaded",
            "VC_FILE_READ: issued/test",
        );
        write_audit_record(
            &env.audit_log_path,
            2,
            "Info",
            "Loaded",
            "VC_SUMMARY_READ: summary requested",
        );
        write_audit_record(
            &env.audit_log_path,
            3,
            "Info",
            "Succeeded",
            "Issued VC urn:uuid:test to did:guardian:test (role=Member, idx=1)",
        );

        let audit_filtered: Value = client
            .get(format!("{}/api/v1/vc/audit", base_url))
            .query(&[("action", "VC_FILE_READ"), ("limit", "10")])
            .send()
            .await
            .expect("vc audit")
            .json()
            .await
            .expect("vc audit body");
        assert_eq!(audit_filtered["count"], 1);
        assert_eq!(audit_filtered["items"][0]["action"], "VC_FILE_READ");

        let audit_all: Value = client
            .get(format!("{}/api/v1/vc/audit", base_url))
            .query(&[("limit", "10")])
            .send()
            .await
            .expect("vc audit all")
            .json()
            .await
            .expect("vc audit all body");
        assert_eq!(audit_all["count"], 3);

        let status_list: Value = client
            .get(format!("{}/api/v1/vc/status-list", base_url))
            .send()
            .await
            .expect("status list")
            .json()
            .await
            .expect("status list body");
        assert_eq!(
            status_list["issuer"].as_str().expect("status list issuer"),
            issuer.did
        );

        let index_file: Value = client
            .get(format!("{}/api/v1/vc/status-list-index", base_url))
            .send()
            .await
            .expect("status list index")
            .json()
            .await
            .expect("status list index body");
        assert_eq!(index_file["next_index"], 2);

        handle.abort();
    }

    #[allow(clippy::await_holding_lock)] // see vc_issue_reuse_status_and_safe_file_reads_work
    #[tokio::test]
    async fn vc_verify_uses_same_resolver_cache_as_did_resolve_api() {
        let _lock = crate::test_support::async_env_lock().await;
        let env = VcEnvGuard::new();
        let (km_dir, _km, issuer, doc) = make_vc_material("nodeA", 31, "192.168.100.1/24");
        install_vc_runtime_material(&env, &km_dir, &issuer, &doc);
        let state = env.state();

        let (base_url, client, handle) = spawn_authed_api_with_state(state.clone()).await;
        let subject = Did::from_id_bytes(&[32u8; 32]).to_string();

        let issued: Value = client
            .post(format!("{}/api/v1/vc/issue", base_url))
            .json(&serde_json::json!({
                "to": subject,
                "role": "member",
                "days": 30
            }))
            .send()
            .await
            .expect("issue vc")
            .json()
            .await
            .expect("issue vc body");
        let vc_id = issued["vc_id"].as_str().expect("vc id").to_string();

        let warm_resolve: Value = client
            .get(format!("{}/api/v1/did/resolve", base_url))
            .query(&[("did", issuer.did.as_str())])
            .send()
            .await
            .expect("warm did resolve")
            .json()
            .await
            .expect("warm did resolve body");
        assert_eq!(warm_resolve["did"], issuer.did);
        assert!(matches!(
            warm_resolve["source"].as_str(),
            Some("local_peer_doc" | "local_aggregate" | "mem_cache")
        ));

        let issuer_did = Did::parse(&issuer.did).expect("issuer did");
        let peer_path = doc_persistence::configured_peers_doc_dir()
            .join(format!("did_doc_{}.json", issuer_did.msi()));
        std::fs::remove_file(peer_path).expect("remove issuer peer doc");
        std::fs::write(doc_persistence::configured_ca_aggregate_path(), "[]")
            .expect("clear issuer aggregate doc");

        let cached_resolve: Value = client
            .get(format!("{}/api/v1/did/resolve", base_url))
            .query(&[("did", issuer.did.as_str())])
            .send()
            .await
            .expect("cached did resolve")
            .json()
            .await
            .expect("cached did resolve body");
        assert_eq!(cached_resolve["did"], issuer.did);
        assert_eq!(cached_resolve["source"], "mem_cache");

        let verify_ok: Value = client
            .post(format!("{}/api/v1/vc/verify", base_url))
            .json(&serde_json::json!({ "id": vc_id }))
            .send()
            .await
            .expect("verify vc with cached resolver")
            .json()
            .await
            .expect("verify vc with cached resolver body");
        assert_eq!(verify_ok["valid"], true);

        state.did_resolver.invalidate_all().await;
        let verify_unresolved: Value = client
            .post(format!("{}/api/v1/vc/verify", base_url))
            .json(&serde_json::json!({ "id": issued["vc_id"] }))
            .send()
            .await
            .expect("verify vc without issuer doc")
            .json()
            .await
            .expect("verify vc without issuer doc body");
        assert_eq!(verify_unresolved["valid"], false);
        assert!(verify_unresolved["reason"]
            .as_str()
            .expect("unresolved reason")
            .contains("VC issuer DID not resolvable"));

        handle.abort();
    }

    #[tokio::test]
    async fn did_deactivate_route_rejects_unconfirmed_requests() {
        let (base_url, client, handle) = spawn_authed_api().await;
        let url = format!("{}/api/v1/did/deactivate", base_url);
        let response = client
            .post(url)
            .json(&serde_json::json!({
                "reason": "manual-admin",
                "confirm": false
            }))
            .send()
            .await
            .expect("request did deactivate");
        let status = response.status();
        let body: Value = response.json().await.expect("json error body");
        handle.abort();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "BAD_REQUEST");
    }

    #[allow(clippy::await_holding_lock)] // see vc_issue_reuse_status_and_safe_file_reads_work
    #[tokio::test]
    async fn did_document_routes_work_end_to_end() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let self_doc_path = td.path().join("identity").join("did_doc.json");
        let peers_dir = td.path().join("identity").join("peers");
        let aggregate_path = td.path().join("identity").join("circle_did_docs.json");
        let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate_path);
        let _ca_host = ScopedEnvVar::set("SGX_CA_HOST", "127.0.0.1");

        let self_did = Did::from_id_bytes(&[7u8; 32]).to_string();
        let peer_did = Did::from_id_bytes(&[8u8; 32]).to_string();
        let self_doc = signed_doc(
            &self_did,
            "nodeA",
            5,
            3,
            "active",
            vec![
                RevokedVm {
                    id: format!("{}#dkp-v1", self_did),
                    revoked_at: "2026-05-20T08:00:00Z".to_string(),
                    reason: "rotation".to_string(),
                },
                RevokedVm {
                    id: format!("{}#dkp-v2", self_did),
                    revoked_at: "2026-05-20T09:00:00Z".to_string(),
                    reason: "rotation".to_string(),
                },
            ],
            true,
        );
        let peer_doc = signed_doc(&peer_did, "nodeB", 4, 4, "active", vec![], false);
        doc_persistence::save_self(&self_doc).expect("save self doc");
        doc_persistence::write_self_floor_version(self_doc.sgx_version_id)
            .expect("write self floor version");
        doc_persistence::save_peer(&peer_doc).expect("save peer doc");

        let publish_handle = spawn_mock_ca_publish_server("nodeB").await;
        let (base_url, client, handle) = spawn_authed_api().await;

        let summary: Value = client
            .get(format!("{}/api/v1/did/document", base_url))
            .send()
            .await
            .expect("summary request")
            .json()
            .await
            .expect("summary json");
        assert_eq!(summary["did"], self_did);
        assert_eq!(summary["controller"], self_doc.controller);
        assert_eq!(summary["node_name"], "nodeA");
        assert_eq!(summary["version"], 5);
        assert_eq!(summary["status"], "active");
        assert_eq!(summary["active_vms"], 1);
        assert_eq!(summary["revoked_vms"], 2);
        assert_eq!(summary["services"], 3);
        assert_eq!(summary["proof_vm"], format!("{}#dkp-v3", self_did));

        let raw: Value = client
            .get(format!("{}/api/v1/did/document/raw", base_url))
            .send()
            .await
            .expect("raw request")
            .json()
            .await
            .expect("raw json");
        assert_eq!(raw["id"], self_did);
        assert_eq!(raw["sgx:nodeName"], "nodeA");
        assert_eq!(raw["sgx:versionId"], 5);
        assert_eq!(
            raw["proof"]["verificationMethod"],
            format!("{}#dkp-v3", self_did)
        );

        let verify: Value = client
            .post(format!("{}/api/v1/did/document/verify", base_url))
            .send()
            .await
            .expect("verify request")
            .json()
            .await
            .expect("verify json");
        assert_eq!(verify["valid"], true);
        assert_eq!(verify["version"], 5);
        assert_eq!(verify["message"], "DID Document proof valid");

        let publish: Value = client
            .post(format!("{}/api/v1/did/document/publish", base_url))
            .json(&serde_json::json!({
                "ca_host": "127.0.0.1",
                "node_name": "nodeB"
            }))
            .send()
            .await
            .expect("publish request")
            .json()
            .await
            .expect("publish json");
        assert_eq!(publish["success"], true);
        assert_eq!(publish["did"], self_did);
        assert_eq!(publish["version"], 5);
        assert_eq!(publish["ca_host"], "127.0.0.1");
        assert_eq!(publish["node_name"], "nodeB");

        let peers: Value = client
            .get(format!("{}/api/v1/did/document/peers", base_url))
            .send()
            .await
            .expect("peers request")
            .json()
            .await
            .expect("peers json");
        assert_eq!(peers["count"], 1);
        assert_eq!(peers["peers"][0]["did"], peer_did);
        assert_eq!(peers["peers"][0]["node_name"], "nodeB");
        assert_eq!(peers["peers"][0]["version"], 4);
        assert_eq!(peers["peers"][0]["status"], "active");
        assert_eq!(peers["peers"][0]["services"], 2);

        let peer: Value = client
            .get(format!("{}/api/v1/did/document/peer", base_url))
            .query(&[("did", peer_did.as_str())])
            .send()
            .await
            .expect("peer request")
            .json()
            .await
            .expect("peer json");
        assert_eq!(peer["id"], peer_did);
        assert_eq!(peer["sgx:nodeName"], "nodeB");
        assert_eq!(peer["sgx:versionId"], 4);

        handle.abort();
        publish_handle.await.expect("mock ca task");
    }

    #[allow(clippy::await_holding_lock)] // see vc_issue_reuse_status_and_safe_file_reads_work
    #[tokio::test]
    async fn did_resolve_query_returns_peer_resolution_result() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let self_doc_path = td.path().join("identity").join("did_doc.json");
        let peers_dir = td.path().join("identity").join("peers");
        let aggregate_path = td.path().join("identity").join("circle_did_docs.json");
        let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate_path);

        let peer_did = Did::from_id_bytes(&[21u8; 32]).to_string();
        let peer_doc = signed_doc(&peer_did, "nodeB", 7, 4, "active", vec![], false);
        doc_persistence::save_peer(&peer_doc).expect("save peer doc");

        let (base_url, client, handle) = spawn_authed_api().await;
        let response: Value = client
            .get(format!("{}/api/v1/did/resolve", base_url))
            .query(&[("did", peer_did.as_str())])
            .send()
            .await
            .expect("resolve request")
            .json()
            .await
            .expect("resolve json");
        handle.abort();

        assert_eq!(response["did"], peer_did);
        assert_eq!(response["source"], "local_peer_doc");
        assert_eq!(response["status"], "active");
        assert_eq!(response["version_id"], 7);
        assert_eq!(response["dkp_version"], 4);
        assert_eq!(response["services"].as_array().map(Vec::len), Some(2));
    }

    #[tokio::test]
    async fn threat_modbus_endpoint_groups_alerts_into_five_rules() {
        let td = TempDir::new().expect("tempdir");
        let alerts_path = td.path().join("alerts.jsonl");
        write_threat_alerts(
            &alerts_path,
            &[
                sample_threat_alert(10000201, "SGX OT Modbus Unauthorized Write Single Coil FC5"),
                sample_threat_alert(
                    10000202,
                    "SGX OT Modbus Unauthorized Write Multiple Coils FC15",
                ),
                sample_threat_alert(10000203, "SGX OT Modbus Write Safety Critical Register FC6"),
                sample_threat_alert(10000209, "SGX OT Modbus Exception Response Detected"),
                sample_threat_alert(10000210, "SGX OT Modbus Write Command Time Audit"),
            ],
        );

        let mut state = (*test_state()).clone();
        state.threat_state_dir = td.path().to_string_lossy().to_string();
        let (base_url, client, handle) = spawn_authed_api_with_state(Arc::new(state)).await;

        let response: Value = client
            .get(format!("{}/api/v1/threat/modbus", base_url))
            .send()
            .await
            .expect("modbus request")
            .json()
            .await
            .expect("modbus json");
        handle.abort();

        assert_eq!(response["total_matches"], 5);
        let rules = response["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 5);

        assert_eq!(rules[0]["rule_id"], 1);
        assert_eq!(rules[0]["matched"], true);
        assert_eq!(rules[0]["match_count"], 2);

        assert_eq!(rules[1]["rule_id"], 2);
        assert_eq!(rules[1]["matched"], true);
        assert_eq!(rules[1]["match_count"], 1);

        assert_eq!(rules[2]["rule_id"], 3);
        assert_eq!(rules[2]["matched"], false);
        assert_eq!(rules[2]["match_count"], 0);

        assert_eq!(rules[3]["rule_id"], 4);
        assert_eq!(rules[3]["matched"], true);
        assert_eq!(rules[3]["match_count"], 1);

        assert_eq!(rules[4]["rule_id"], 5);
        assert_eq!(rules[4]["matched"], true);
        assert_eq!(rules[4]["match_count"], 1);
    }

    #[allow(clippy::await_holding_lock)] // see vc_issue_reuse_status_and_safe_file_reads_work
    #[tokio::test]
    async fn did_document_verify_rejects_replayed_lower_version() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let self_doc_path = td.path().join("identity").join("did_doc.json");
        let peers_dir = td.path().join("identity").join("peers");
        let aggregate_path = td.path().join("identity").join("circle_did_docs.json");
        let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate_path);

        let did = Did::from_id_bytes(&[9u8; 32]).to_string();
        let current_doc = signed_doc(&did, "nodeA", 5, 3, "active", vec![], false);
        let older_doc = signed_doc(&did, "nodeA", 4, 2, "active", vec![], false);
        doc_persistence::save_self(&current_doc).expect("save self doc");
        doc_persistence::write_self_floor_version(current_doc.sgx_version_id)
            .expect("write self floor version");
        // Must live under the configured self-doc directory — document_verify's
        // path parameter is now restricted to the configured DID doc directories.
        let older_path = td.path().join("identity").join("older_did_doc.json");
        std::fs::write(
            &older_path,
            serde_json::to_vec_pretty(&older_doc).expect("older doc json"),
        )
        .expect("write older doc");

        let (base_url, client, handle) = spawn_authed_api().await;
        let response = client
            .post(format!("{}/api/v1/did/document/verify", base_url))
            .json(&serde_json::json!({
                "path": older_path
            }))
            .send()
            .await
            .expect("verify request");
        let status = response.status();
        let body: Value = response.json().await.expect("verify error body");
        handle.abort();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "BAD_REQUEST");
        assert!(body["error"]["message"]
            .as_str()
            .expect("verify error message")
            .contains("older than locally known v5"));
    }

    #[allow(clippy::await_holding_lock)] // see vc_issue_reuse_status_and_safe_file_reads_work
    #[tokio::test]
    async fn did_document_verify_rejects_path_outside_configured_directories() {
        let _lock = doc_persistence::lock_test_env();
        let td = TempDir::new().expect("tempdir");
        let self_doc_path = td.path().join("identity").join("did_doc.json");
        let peers_dir = td.path().join("identity").join("peers");
        let aggregate_path = td.path().join("identity").join("circle_did_docs.json");
        let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate_path);

        // A file that exists but sits OUTSIDE the configured DID directories —
        // must be rejected before it ever reaches fs::read_to_string.
        let outside_path = td.path().join("outside_did_doc.json");
        std::fs::write(&outside_path, b"{}").expect("write outside file");

        let (base_url, client, handle) = spawn_authed_api().await;
        let response = client
            .post(format!("{}/api/v1/did/document/verify", base_url))
            .json(&serde_json::json!({
                "path": outside_path
            }))
            .send()
            .await
            .expect("verify request");
        let status = response.status();
        let body: Value = response.json().await.expect("verify error body");
        handle.abort();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]["message"]
            .as_str()
            .expect("verify error message")
            .contains("configured DID document directories"));
    }

    #[tokio::test]
    async fn did_document_routes_validate_inputs() {
        let (base_url, client, handle) = spawn_authed_api().await;

        let publish_response = client
            .post(format!("{}/api/v1/did/document/publish", base_url))
            .json(&serde_json::json!({
                "ca_host": "127.0.0.1",
                "node_name": ""
            }))
            .send()
            .await
            .expect("publish validation request");
        let publish_status = publish_response.status();
        let publish_body: Value = publish_response
            .json()
            .await
            .expect("publish validation body");

        let peer_response = client
            .get(format!("{}/api/v1/did/document/peer", base_url))
            .query(&[("did", "not-a-did")])
            .send()
            .await
            .expect("peer validation request");
        let peer_status = peer_response.status();
        let peer_body: Value = peer_response.json().await.expect("peer validation body");

        handle.abort();

        assert_eq!(publish_status, StatusCode::BAD_REQUEST);
        assert_eq!(publish_body["error"]["code"], "BAD_REQUEST");
        assert_eq!(publish_body["error"]["message"], "node_name is required");

        assert_eq!(peer_status, StatusCode::BAD_REQUEST);
        assert_eq!(peer_body["error"]["code"], "BAD_REQUEST");
    }

    #[tokio::test]
    async fn https_health_succeeds_with_node_cert() {
        let (base_url, cert_der, handle) = spawn_https_secured_api_with_state(test_state()).await;
        let client = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_der(&cert_der).expect("reqwest test cert"),
            )
            .build()
            .expect("https client");

        let response = client
            .get(format!("{}/api/v1/health", base_url))
            .send()
            .await
            .expect("https health request");

        handle.abort();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn plaintext_http_is_rejected_on_tls_port() {
        let (base_url, _cert_der, handle) = spawn_https_secured_api_with_state(test_state()).await;
        let response = reqwest::Client::new()
            .get(base_url.replacen("https://", "http://", 1) + "/api/v1/health")
            .send()
            .await;

        handle.abort();
        assert!(response.is_err(), "plaintext HTTP unexpectedly succeeded");
    }
}
