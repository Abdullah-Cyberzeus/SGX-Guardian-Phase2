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
        .route("/api/v1/relay/toggle", post(handlers::relay::toggle))
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
        .route("/api/v1/threat/status", get(handlers::threat::status))
        .route("/api/v1/threat/alerts", get(handlers::threat::list_alerts))
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
        self, CA_AGGREGATE_PATH_ENV, PEERS_DOC_DIR_ENV, SELF_DOC_PATH_ENV,
    };
    use crate::did::doc_sign;
    use crate::did::document::{DidDocument, DocBuildInput, RevokedVm};
    use crate::did::Did;
    use crate::key_manager::KeyManager;
    use crate::nebula::registry_sync::{RegistryRequest, RegistryResponse, REGISTRY_SYNC_PORT};
    use once_cell::sync::Lazy;
    use reqwest::StatusCode;
    use serde_json::Value;
    use std::ffi::OsString;
    use std::path::Path;
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
    }

    impl EnvGuard {
        fn new(self_doc_path: &Path, peers_dir: &Path, aggregate_path: &Path) -> Self {
            let self_doc_prev = std::env::var_os(SELF_DOC_PATH_ENV);
            let peers_dir_prev = std::env::var_os(PEERS_DOC_DIR_ENV);
            let aggregate_prev = std::env::var_os(CA_AGGREGATE_PATH_ENV);
            std::env::set_var(SELF_DOC_PATH_ENV, self_doc_path);
            std::env::set_var(PEERS_DOC_DIR_ENV, peers_dir);
            std::env::set_var(CA_AGGREGATE_PATH_ENV, aggregate_path);
            Self {
                self_doc_prev,
                peers_dir_prev,
                aggregate_prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            restore_env(SELF_DOC_PATH_ENV, self.self_doc_prev.take());
            restore_env(PEERS_DOC_DIR_ENV, self.peers_dir_prev.take());
            restore_env(CA_AGGREGATE_PATH_ENV, self.aggregate_prev.take());
        }
    }

    fn restore_env(key: &str, value: Option<OsString>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
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
            threat_config_path: "/tmp/threat-config.yaml".into(),
            threat_state_dir: "/tmp/threat-state".into(),
        })
    }

    async fn spawn_api() -> (String, tokio::task::JoinHandle<()>) {
        let app = build_router(test_state());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });
        (format!("http://{}", addr), handle)
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
