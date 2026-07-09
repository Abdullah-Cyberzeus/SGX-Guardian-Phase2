use sgx_guardian_client::api::{build_router, state::AppState};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

fn test_state(temp_dir: &std::path::Path) -> Arc<AppState> {
    let config_dir = temp_dir.join("config");
    let discovery_config_dir = temp_dir.join("discovery_config");
    let discovery_state_dir = temp_dir.join("discovery_state");

    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&discovery_config_dir).unwrap();
    std::fs::create_dir_all(&discovery_state_dir).unwrap();

    // Create a mock inventory.json
    let inventory_path = discovery_state_dir.join("inventory.json");
    std::fs::write(
        &inventory_path,
        r#"[
        {
            "device_id": "dev-1",
            "ip": "192.168.1.5",
            "mac": "AA:BB:CC:11:22:33",
            "vendor": "TestVendor",
            "hostname": "host-1",
            "os_fingerprint": null,
            "os_cpe": [],
            "open_ports": [],
            "host_scripts": [],
            "status": "unauthorized",
            "first_seen": "2026-06-24T10:00:00Z",
            "last_seen": "2026-06-24T10:00:00Z",
            "vuln_triaged": false
        }
    ]"#,
    )
    .unwrap();

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
        discovery_config_dir: discovery_config_dir.to_string_lossy().to_string(),
        discovery_state_dir: discovery_state_dir.to_string_lossy().to_string(),
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
async fn test_discovery_endpoints() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();

    // 1. GET /api/v1/discovery/devices
    let res = client
        .get(format!("{}/api/v1/discovery/devices", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let devices: serde_json::Value = res.json().await.unwrap();
    assert!(devices.as_array().unwrap().len() == 1);

    // 2. GET /api/v1/discovery/unauthorized
    let res = client
        .get(format!("{}/api/v1/discovery/unauthorized", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let unauth: serde_json::Value = res.json().await.unwrap();
    assert!(unauth.as_array().unwrap().len() == 1);

    // 3. POST /api/v1/discovery/scan/now
    let res = client
        .post(format!("{}/api/v1/discovery/scan/now", base_url))
        .send()
        .await
        .unwrap();
    let _ = res.status();

    // 4. POST /api/v1/discovery/scan/stealth
    let res = client
        .post(format!("{}/api/v1/discovery/scan/stealth", base_url))
        .send()
        .await
        .unwrap();
    let _ = res.status();

    // 5. GET /api/v1/discovery/whitelist
    let res = client
        .get(format!("{}/api/v1/discovery/whitelist", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // 6. PUT /api/v1/discovery/whitelist
    let res = client
        .put(format!("{}/api/v1/discovery/whitelist", base_url))
        .json(&serde_json::json!({
            "version": "1.0",
            "devices": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // 7. POST /api/v1/discovery/approve
    let res = client
        .post(format!("{}/api/v1/discovery/approve", base_url))
        .json(&serde_json::json!({
            "mac": "AA:BB:CC:11:22:33",
            "label": "Approved Device"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // 8. GET /api/v1/discovery/schedule
    let res = client
        .get(format!("{}/api/v1/discovery/schedule", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // 9. PUT /api/v1/discovery/schedule
    let res = client
        .put(format!("{}/api/v1/discovery/schedule", base_url))
        .json(&serde_json::json!({
            "enabled": true,
            "timeout_secs": 600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}
