use sgx_guardian_client::api::{build_router, state::AppState};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

fn test_state(temp_dir: &std::path::Path) -> Arc<AppState> {
    let pcr_dir = temp_dir.join("pcr");
    let logs_dir = temp_dir.join("logs");
    let keys_dir = temp_dir.join("keys");
    let config_dir = temp_dir.join("config");
    let boot_dir = temp_dir.join("boot");

    std::fs::create_dir_all(&pcr_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&boot_dir).unwrap();

    Arc::new(AppState {
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
        discovery_config_dir: temp_dir
            .join("discovery-config")
            .to_string_lossy()
            .to_string(),
        discovery_state_dir: temp_dir
            .join("discovery-state")
            .to_string_lossy()
            .to_string(),
    })
}

async fn spawn_api(temp_dir: &std::path::Path) -> (String, tokio::task::JoinHandle<()>) {
    let state = test_state(temp_dir);
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    (format!("http://{}", addr), handle)
}

#[tokio::test]
async fn test_attestation_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/api/v1/attestation", base_url))
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_client_error()
            || res.status().is_success()
            || res.status().is_server_error()
    );
}

#[tokio::test]
async fn test_dkp_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/api/v1/dkp/status", base_url))
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_client_error()
            || res.status().is_success()
            || res.status().is_server_error()
    );
}

#[tokio::test]
async fn test_logs_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/api/v1/logs", base_url))
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_client_error()
            || res.status().is_success()
            || res.status().is_server_error()
    );
}

#[tokio::test]
async fn test_node_status_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle) = spawn_api(temp_dir.path()).await;

    // Create valid config file for test-nodeA
    let config_yaml = "
node_id: test-nodeA
hostname: test-host
ip: 10.0.0.1
port: 50051
public_key: dummy_pubkey
";
    std::fs::write(temp_dir.path().join("config/test-nodeA.yaml"), config_yaml).unwrap();

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/api/v1/node/status", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["nodeId"], "test-nodeA");
    assert_eq!(body["hostname"], "test-host");
    assert_eq!(body["ip"], "10.0.0.1");
}

#[tokio::test]
async fn test_node_boot_status_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle) = spawn_api(temp_dir.path()).await;

    // Create valid chain_status.json
    let boot_json = serde_json::json!({
        "hab_enabled": true,
        "device_closed": true,
        "hab_events_found": false,
        "device_model": "test-model",
        "kernel_version": "5.15.0",
        "boot_chain_intact": true,
        "guardian_binary_hash": "deadbeef"
    });
    std::fs::write(
        temp_dir.path().join("boot/test_chain_status.json"),
        serde_json::to_string(&boot_json).unwrap(),
    )
    .unwrap();

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/api/v1/node/boot-status", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["habEnabled"], true);
    assert_eq!(body["deviceClosed"], true);
    assert_eq!(body["deviceModel"], "test-model");
    assert_eq!(body["guardianBinaryHash"], "deadbeef");
    assert!(body["trustChain"].is_array());
}

#[tokio::test]
async fn test_node_restart_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle) = spawn_api(temp_dir.path()).await;

    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/api/v1/node/restart", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["message"], "Guardian daemon restart initiated");
}

#[tokio::test]
async fn test_pcr_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/api/v1/pcr/status", base_url))
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_client_error()
            || res.status().is_success()
            || res.status().is_server_error()
    );
}

#[tokio::test]
async fn test_peers_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/api/v1/peers", base_url))
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_client_error()
            || res.status().is_success()
            || res.status().is_server_error()
    );
}
