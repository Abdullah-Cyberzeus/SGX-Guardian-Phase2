use sgx_guardian_client::api::{build_router, state::AppState};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use std::ffi::OsString;
use sgx_guardian_client::did::persistence::{DidRecord, DerivationProof};
use sgx_guardian_client::did::document::{DidDocument, VerificationMethod, Jwk};
use base64::engine::general_purpose;
use base64::Engine as _;

struct EnvGuard {
    vars: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    fn new(mappings: &[(&'static str, &str)]) -> Self {
        let mut vars = Vec::new();
        for (k, v) in mappings {
            vars.push((*k, std::env::var_os(*k)));
            std::env::set_var(k, v);
        }
        Self { vars }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in &self.vars {
            if let Some(val) = v {
                std::env::set_var(k, val);
            } else {
                std::env::remove_var(k);
            }
        }
    }
}

fn seed_did(did_path: &str, dkp_pubkey_path: &str, doc_path: &str) {
    let did = sgx_guardian_client::did::Did::from_id_bytes(&[1u8; 32]);
    let rec = DidRecord {
        did: did.as_str().to_string(),
        method: "guardian".into(),
        method_version: "1.0".into(),
        did_id_b58: did.msi().to_string(),
        did_id_hex: "01".repeat(32),
        created_at: "2026-04-26T10:00:00Z".into(),
        deactivated_at: None,
        derivation: DerivationProof {
            se050_uid: "fixture-uid".into(),
            se050_uid_source: "fallback".into(),
            dkp_v1_pubkey_sha256_b16: "ab".repeat(32),
            dkp_v1_pubkey_path: dkp_pubkey_path.to_string(),
            dkp_v1_pubkey_der_b64: None,
            dik_pubkey_sha256_b16: "cd".repeat(32),
            dik_pubkey_der_b64: Some(general_purpose::STANDARD.encode([1u8; 64])),
        },
        current_dkp_version: 3,
        deriv_signature_b64: "Zm9v".into(),
    };
    rec.save(did_path).expect("save did");

    let mut pubkey = vec![0x04];
    pubkey.extend_from_slice(&[1u8; 64]);
    std::fs::write(dkp_pubkey_path, pubkey).unwrap();

    let vm = VerificationMethod {
        id: format!("{}#dkp-v3", did.as_str()),
        vm_type: "JsonWebKey2020".into(),
        controller: did.as_str().to_string(),
        public_key_jwk: Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: general_purpose::URL_SAFE_NO_PAD.encode(&[1u8; 32]),
            y: general_purpose::URL_SAFE_NO_PAD.encode(&[1u8; 32]),
            kid: "dkp-v3".into(),
        },
    };

    let doc = DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".into()],
        id: did.as_str().to_string(),
        controller: did.as_str().to_string(),
        verification_method: vec![vm.clone()],
        authentication: vec![vm.id.clone()],
        assertion_method: vec![vm.id.clone()],
        service: vec![],
        sgx_node_name: Some("nodeA".into()),
        sgx_created: "2026-04-26T10:00:00Z".into(),
        sgx_updated: "2026-04-26T10:00:00Z".into(),
        sgx_version_id: 1,
        sgx_method_spec_version: "1.0".into(),
        sgx_status: Some("active".into()),
        sgx_revoked_vm: vec![],
        proof: None,
    };
    let json = serde_json::to_string(&doc).unwrap();
    std::fs::write(doc_path, json).unwrap();
}

async fn spawn_api(temp_dir: &std::path::Path) -> (String, tokio::task::JoinHandle<()>, Arc<AppState>, EnvGuard) {
    let pcr_dir = temp_dir.join("pcr");
    let logs_dir = temp_dir.join("logs");
    let keys_dir = temp_dir.join("keys");
    let config_dir = temp_dir.join("config");
    let boot_dir = temp_dir.join("boot");
    let identity_dir = temp_dir.join("identity");
    let peers_dir = temp_dir.join("peers");
    let did_dir = temp_dir.join("did");
    
    std::fs::create_dir_all(&pcr_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&boot_dir).unwrap();
    std::fs::create_dir_all(&identity_dir).unwrap();
    std::fs::create_dir_all(&peers_dir).unwrap();
    std::fs::create_dir_all(&did_dir).unwrap();

    let did_path = identity_dir.join("did.json");
    let doc_path = identity_dir.join("did_doc.json");
    let dkp_path = keys_dir.join("dkp_pub.der");
    let aggregate_path = identity_dir.join("circle_did_docs.json");
    let counter_path = did_dir.join("self_version_counter");

    seed_did(did_path.to_str().unwrap(), dkp_path.to_str().unwrap(), doc_path.to_str().unwrap());

    let env_guard = EnvGuard::new(&[
        ("SGX_GUARDIAN_DID_PATH", did_path.to_str().unwrap()),
        ("SGX_GUARDIAN_DKP_PUBKEY_PATH", dkp_path.to_str().unwrap()),
        ("SGX_GUARDIAN_DID_DOC_PATH", doc_path.to_str().unwrap()),
        ("SGX_GUARDIAN_DID_PEERS_DIR", peers_dir.to_str().unwrap()),
        ("SGX_GUARDIAN_DID_CA_AGGREGATE_PATH", aggregate_path.to_str().unwrap()),
        ("SGX_GUARDIAN_DID_SELF_VERSION_COUNTER_PATH", counter_path.to_str().unwrap()),
    ]);

    let state = Arc::new(AppState {
        node_id: "test-nodeA".into(),
        config_dir: config_dir.to_string_lossy().to_string(),
        boot_dir: boot_dir.to_string_lossy().to_string(),
        keys_dir: keys_dir.to_string_lossy().to_string(),
        pcr_dir: pcr_dir.to_string_lossy().to_string(),
        pcr_baseline_dir: temp_dir.join("baseline").to_string_lossy().to_string(),
        log_dir_primary: logs_dir.to_string_lossy().to_string(),
        log_dir_fallback: temp_dir.join("logs-fallback").to_string_lossy().to_string(),
        did_resolver: sgx_guardian_client::did::Resolver::new(Default::default()),
        vid_cache: sgx_guardian_client::virtual_id_cache::VirtualIdCache::new(),
        discovery_config_dir: temp_dir.join("discovery-config").to_string_lossy().to_string(),
        discovery_state_dir: temp_dir.join("discovery-state").to_string_lossy().to_string(),
    });

    let app = build_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    (format!("http://{}", addr), handle, state, env_guard)
}

#[tokio::test]
async fn test_did_endpoints() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, _state, _guard) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();
    
    // 1. GET /api/v1/did/status
    let res = client.get(&format!("{}/api/v1/did/status", base_url)).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "active");

    // 2. GET /api/v1/did/resolve (Local)
    let res = client.get(&format!("{}/api/v1/did/resolve", base_url)).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ACTIVE");

    // 3. GET /api/v1/did/document
    let res = client.get(&format!("{}/api/v1/did/document", base_url)).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["node_name"], "nodeA");

    // 4. GET /api/v1/did/document/raw
    let res = client.get(&format!("{}/api/v1/did/document/raw", base_url)).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["id"].is_string());

    // 5. POST /api/v1/did/deactivate (without confirm)
    let res = client.post(&format!("{}/api/v1/did/deactivate", base_url))
        .json(&serde_json::json!({"reason": "test", "confirm": false}))
        .send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);

    // 6. POST /api/v1/did/deactivate (with confirm)
    let res = client.post(&format!("{}/api/v1/did/deactivate", base_url))
        .json(&serde_json::json!({"reason": "test", "confirm": true}))
        .send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    
    // 7. GET /api/v1/did/peers
    let res = client.get(&format!("{}/api/v1/did/document/peers", base_url)).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}
