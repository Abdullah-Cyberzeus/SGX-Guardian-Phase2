//! REST API module for the SG-X Guardian admin console.
//! Runs as a tokio task alongside the existing gRPC server.
//! Port: 8443 (separate listener from the :50051 mTLS gRPC endpoint).

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub mod error;
pub mod handlers;
pub mod state;

use state::AppState;

/// Build the full axum router with all v1 routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

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
            "/api/v1/discovery/devices",
            get(handlers::discovery::list_devices),
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
        .route("/api/v1/vc/status/:vc_id", get(handlers::vc::status_by_id))
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
            "/api/v1/vc/files/issued/:vc_id",
            get(handlers::vc::file_issued),
        )
        .route("/api/v1/vc/files/own/:vc_id", get(handlers::vc::file_own))
        .route("/api/v1/vc/files/peer/:did", get(handlers::vc::file_peer))
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
        // Health
        .route("/api/v1/health", get(|| async { "ok" }))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Entry point. Spawned from main.rs as a tokio task.
pub async fn serve(state: Arc<AppState>, bind: SocketAddr) -> anyhow::Result<()> {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("Admin REST API listening on http://{}", bind);
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::doc_persistence::{
        self, CA_AGGREGATE_PATH_ENV, PEERS_DOC_DIR_ENV, SELF_DOC_PATH_ENV, VERSION_COUNTER_PATH_ENV,
    };
    use crate::did::doc_sign;
    use crate::did::document::{DidDocument, DocBuildInput, RevokedVm};
    use crate::did::persistence::{DerivationProof, DidRecord};
    use crate::did::Did;
    use crate::key_manager::KeyManager;
    use crate::nebula::registry_sync::{RegistryRequest, RegistryResponse, REGISTRY_SYNC_PORT};
    use crate::vc::{issue, persistence};
    use chrono::Utc;
    use once_cell::sync::Lazy;
    use reqwest::StatusCode;
    use serde_json::Value;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const DEPLOYED_SIG_PATH: &str = "/etc/sgx-guardian/policies/policy.sig";
    static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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

    struct VcEnvGuard {
        doc_env: EnvGuard,
        did_path_prev: Option<OsString>,
        vc_base_prev: Option<OsString>,
        key_dir_prev: Option<OsString>,
        node_id_prev: Option<OsString>,
        audit_path_prev: Option<OsString>,
        did_path: PathBuf,
        key_dir: PathBuf,
        log_dir: PathBuf,
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
                log_dir,
                audit_log_path,
                _td: td,
            }
        }

        fn state(&self) -> Arc<AppState> {
            Arc::new(AppState {
                node_id: "nodeA".into(),
                config_dir: "/tmp/config".into(),
                boot_dir: "/tmp/boot".into(),
                keys_dir: self.key_dir.to_string_lossy().to_string(),
                pcr_dir: "/tmp/pcr".into(),
                pcr_baseline_dir: "/tmp".into(),
                log_dir_primary: self.log_dir.to_string_lossy().to_string(),
                log_dir_fallback: self.log_dir.to_string_lossy().to_string(),
                did_resolver: crate::did::Resolver::new(Default::default()),
                vid_cache: crate::virtual_id_cache::VirtualIdCache::new(),
                discovery_config_dir: "/tmp/discovery-config".into(),
                discovery_state_dir: "/tmp/discovery-state".into(),
            })
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
        Arc::new(AppState {
            node_id: "test-nodeA".into(),
            config_dir: "/tmp/config".into(),
            boot_dir: "/tmp/boot".into(),
            keys_dir: "/tmp/keys".into(),
            pcr_dir: "/tmp/pcr".into(),
            pcr_baseline_dir: "/tmp".into(),
            log_dir_primary: "/tmp/logs".into(),
            log_dir_fallback: "/tmp/logs-fallback".into(),
            did_resolver: crate::did::Resolver::new(Default::default()),
            vid_cache: crate::virtual_id_cache::VirtualIdCache::new(),
            discovery_config_dir: "/tmp/discovery-config".into(),
            discovery_state_dir: "/tmp/discovery-state".into(),
        })
    }

    async fn spawn_api() -> (String, tokio::task::JoinHandle<()>) {
        spawn_api_with_state(test_state()).await
    }

    async fn spawn_api_with_state(state: Arc<AppState>) -> (String, tokio::task::JoinHandle<()>) {
        let app = build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });
        (format!("http://{}", addr), handle)
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

    #[tokio::test]
    async fn verify_deployed_does_not_require_multipart_upload() {
        let (base_url, handle) = spawn_api().await;
        let url = format!("{}/api/v1/policy/verify-deployed", base_url);
        let response = reqwest::Client::new()
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

        let (base_url, handle) = spawn_api().await;
        let url = format!("{}/api/v1/policy/verify-deployed", base_url);
        let response = reqwest::Client::new()
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
        let (base_url, handle) = spawn_api().await;
        let url = format!("{}/api/v1/policy/verify", base_url);
        let response = reqwest::Client::new()
            .post(url)
            .send()
            .await
            .expect("request verify");
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

    #[tokio::test]
    async fn vc_issue_reuse_status_and_safe_file_reads_work() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let env = VcEnvGuard::new();
        let (km_dir, _km, issuer, doc) = make_vc_material("nodeA", 7, "192.168.100.1/24");
        install_vc_runtime_material(&env, &km_dir, &issuer, &doc);

        let (base_url, handle) = spawn_api_with_state(env.state()).await;
        let client = reqwest::Client::new();
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

    #[tokio::test]
    async fn vc_renew_verify_revoke_summary_and_audit_routes_work() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let env = VcEnvGuard::new();
        let (km_dir, km, issuer, doc) = make_vc_material("nodeA", 9, "192.168.100.1/24");
        install_vc_runtime_material(&env, &km_dir, &issuer, &doc);
        let _owner_vc = issue::ensure_owner_vc(&issuer, &km).expect("ensure owner vc");

        let (base_url, handle) = spawn_api_with_state(env.state()).await;
        let client = reqwest::Client::new();
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

    #[tokio::test]
    async fn vc_verify_uses_same_resolver_cache_as_did_resolve_api() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let env = VcEnvGuard::new();
        let (km_dir, _km, issuer, doc) = make_vc_material("nodeA", 31, "192.168.100.1/24");
        install_vc_runtime_material(&env, &km_dir, &issuer, &doc);
        let state = env.state();

        let (base_url, handle) = spawn_api_with_state(state.clone()).await;
        let client = reqwest::Client::new();
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
        let (base_url, handle) = spawn_api().await;
        let url = format!("{}/api/v1/did/deactivate", base_url);
        let response = reqwest::Client::new()
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

    #[tokio::test]
    async fn did_document_routes_work_end_to_end() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let td = TempDir::new().expect("tempdir");
        let self_doc_path = td.path().join("identity").join("did_doc.json");
        let peers_dir = td.path().join("identity").join("peers");
        let aggregate_path = td.path().join("identity").join("circle_did_docs.json");
        let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate_path);

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
        let (base_url, handle) = spawn_api().await;
        let client = reqwest::Client::new();

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

    #[tokio::test]
    async fn did_resolve_query_returns_peer_resolution_result() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let td = TempDir::new().expect("tempdir");
        let self_doc_path = td.path().join("identity").join("did_doc.json");
        let peers_dir = td.path().join("identity").join("peers");
        let aggregate_path = td.path().join("identity").join("circle_did_docs.json");
        let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate_path);

        let peer_did = Did::from_id_bytes(&[21u8; 32]).to_string();
        let peer_doc = signed_doc(&peer_did, "nodeB", 7, 4, "active", vec![], false);
        doc_persistence::save_peer(&peer_doc).expect("save peer doc");

        let (base_url, handle) = spawn_api().await;
        let response: Value = reqwest::Client::new()
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
    async fn did_document_verify_rejects_replayed_lower_version() {
        let _lock = TEST_ENV_LOCK.lock().await;
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
        let older_path = td.path().join("older_did_doc.json");
        std::fs::write(
            &older_path,
            serde_json::to_vec_pretty(&older_doc).expect("older doc json"),
        )
        .expect("write older doc");

        let (base_url, handle) = spawn_api().await;
        let response = reqwest::Client::new()
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

    #[tokio::test]
    async fn did_document_routes_validate_inputs() {
        let (base_url, handle) = spawn_api().await;
        let client = reqwest::Client::new();

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
}
