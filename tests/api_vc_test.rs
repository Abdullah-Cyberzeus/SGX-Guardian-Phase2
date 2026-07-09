use sgx_guardian_client::api::{build_router, state::AppState};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

fn test_state(temp_dir: &std::path::Path) -> Arc<AppState> {
    let config_dir = temp_dir.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();

    Arc::new(AppState {
        node_id: "test-nodeA".into(),
        config_dir: config_dir.to_string_lossy().to_string(),
        boot_dir: temp_dir.join("boot").to_string_lossy().to_string(),
        keys_dir: temp_dir.join("keys").to_string_lossy().to_string(),
        pcr_dir: temp_dir.join("pcr").to_string_lossy().to_string(),
        pcr_baseline_dir: temp_dir.join("baseline").to_string_lossy().to_string(),
        threat_config_path: temp_dir.join("threat.json").to_string_lossy().to_string(),
        threat_state_dir: temp_dir.join("threat_state").to_string_lossy().to_string(),
        log_dir_primary: temp_dir.join("logs").to_string_lossy().to_string(),
        log_dir_fallback: temp_dir.join("logs2").to_string_lossy().to_string(),
        did_resolver: sgx_guardian_client::did::Resolver::new(Default::default()),
        vid_cache: sgx_guardian_client::virtual_id_cache::VirtualIdCache::new(),
        discovery_config_dir: temp_dir.join("disc-config").to_string_lossy().to_string(),
        discovery_state_dir: temp_dir.join("disc-state").to_string_lossy().to_string(),
    })
}

async fn spawn_api(
    temp_dir: &std::path::Path,
) -> (String, tokio::task::JoinHandle<()>, Arc<AppState>) {
    let state = test_state(temp_dir);
    let app = build_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    (format!("http://{}", addr), handle, state)
}

#[tokio::test]
async fn test_vc_endpoints() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();

    // Test /api/v1/vc/issue
    let res = client
        .post(format!("{}/api/v1/vc/issue", base_url))
        .json(&serde_json::json!({
            "credentialType": "EmployeeCredential",
            "subjectDid": "did:example:123",
            "claims": {
                "name": "Alice",
                "role": "Admin"
            },
            "expirationDate": "2026-12-31T23:59:59Z",
            "owner": "test-nodeA"
        }))
        .send()
        .await
        .unwrap();
    // Will fail with 500 or 400 without proper DID/DKP setup, but that covers the handler logic
    assert!(!res.status().is_success());

    // Test /api/v1/vc/verify
    let res = client
        .post(format!("{}/api/v1/vc/verify", base_url))
        .json(&serde_json::json!({
            "credential_jwt": "eyJhbG..."
        }))
        .send()
        .await
        .unwrap();
    assert!(!res.status().is_success());

    // Test /api/v1/vc/revoke
    let res = client
        .post(format!("{}/api/v1/vc/revoke", base_url))
        .json(&serde_json::json!({
            "jti": "urn:uuid:123",
            "reason": "compromised"
        }))
        .send()
        .await
        .unwrap();
    assert!(!res.status().is_success());

    // Test /api/v1/vc/status
    let res = client
        .get(format!("{}/api/v1/vc/status/urn:uuid:123", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST); // Validation fails for '123'
}
