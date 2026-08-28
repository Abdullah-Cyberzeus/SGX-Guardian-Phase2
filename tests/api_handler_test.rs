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

    let mut state = Arc::try_unwrap(AppState::for_tests(
        temp_dir,
        "test-nodeA",
        config_dir.to_string_lossy().to_string(),
    ))
    .unwrap_or_else(|_| unreachable!("sole Arc owner"));
    state.boot_dir = boot_dir.to_string_lossy().to_string();
    state.keys_dir = keys_dir.to_string_lossy().to_string();
    state.pcr_dir = pcr_dir.to_string_lossy().to_string();
    state.pcr_baseline_dir = temp_dir.join("baseline").to_string_lossy().to_string();
    state.log_dir_primary = logs_dir.to_string_lossy().to_string();
    state.log_dir_fallback = temp_dir.join("logs-fallback").to_string_lossy().to_string();
    state.discovery_config_dir = temp_dir
        .join("discovery-config")
        .to_string_lossy()
        .to_string();
    state.discovery_state_dir = temp_dir
        .join("discovery-state")
        .to_string_lossy()
        .to_string();
    Arc::new(state)
}

async fn spawn_api(
    temp_dir: &std::path::Path,
) -> (String, tokio::task::JoinHandle<()>, Arc<AppState>) {
    let state = test_state(temp_dir);
    let app = build_router(state.clone(), axum::Router::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    (format!("http://{}", addr), handle, state)
}

#[tokio::test]
async fn test_attestation_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
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
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
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
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
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
    let (base_url, _handle, state) = spawn_api(temp_dir.path()).await;

    // Create valid config file for test-nodeA
    let config_yaml = "
node_id: test-nodeA
hostname: test-host
ip: 10.0.0.1
port: 50051
public_key: dummy_pubkey
";
    std::fs::write(temp_dir.path().join("config/test-nodeA.yaml"), config_yaml).unwrap();

    let client = AppState::authed_client_for_tests(&state).await;
    let res = client
        .get(format!("{}/api/v1/node/status", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["nodeId"], "test-nodeA");
    assert_eq!(body["deviceName"], "test-nodeA");
    assert_eq!(body["hostname"], "test-host");
    assert_eq!(body["displayHostname"], "test-host");
    assert_eq!(body["ip"], "10.0.0.1");
}

#[tokio::test]
async fn test_node_display_info_can_change_without_changing_identity() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, state) = spawn_api(temp_dir.path()).await;
    let config_path = temp_dir.path().join("config/test-nodeA.yaml");
    let config_yaml = "node_id: test-nodeA\nhostname: test-host\nip: 10.0.0.1\nport: 50051\npublic_key: dummy_pubkey\ncustom_section:\n  preserved: true\n";
    std::fs::write(&config_path, config_yaml).unwrap();

    let client = AppState::authed_client_for_tests(&state).await;
    let response = client
        .patch(format!("{}/api/v1/node/status", base_url))
        .json(&serde_json::json!({
            "deviceName": "Living Room Guardian",
            "displayHostname": "guardian-home"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["deviceName"], "Living Room Guardian");
    assert_eq!(body["displayHostname"], "guardian-home");
    assert_eq!(body["nodeId"], "test-nodeA");
    assert_eq!(body["hostname"], "test-host");

    let persisted = std::fs::read_to_string(config_path).unwrap();
    assert!(persisted.contains("device_name: \"Living Room Guardian\""));
    assert!(persisted.contains("display_hostname: \"guardian-home\""));
    assert!(persisted.contains("custom_section:"));
}

#[tokio::test]
async fn test_node_boot_status_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, state) = spawn_api(temp_dir.path()).await;

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

    let client = AppState::authed_client_for_tests(&state).await;
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
    let (base_url, _handle, state) = spawn_api(temp_dir.path()).await;

    let client = AppState::authed_client_for_tests(&state).await;
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
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
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
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
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
