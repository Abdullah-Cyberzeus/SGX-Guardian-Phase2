use sgx_guardian_client::api::{build_router, state::AppState};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

fn test_state(temp_dir: &std::path::Path) -> Arc<AppState> {
    let config_dir = temp_dir.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();

    let mut state = Arc::try_unwrap(AppState::for_tests(
        temp_dir,
        "test-nodeA",
        config_dir.to_string_lossy().to_string(),
    ))
    .unwrap_or_else(|_| unreachable!("sole Arc owner"));
    state.boot_dir = temp_dir.join("boot").to_string_lossy().to_string();
    state.keys_dir = temp_dir.join("keys").to_string_lossy().to_string();
    state.pcr_dir = temp_dir.join("pcr").to_string_lossy().to_string();
    state.pcr_baseline_dir = temp_dir.join("baseline").to_string_lossy().to_string();
    state.log_dir_primary = temp_dir.join("logs").to_string_lossy().to_string();
    state.log_dir_fallback = temp_dir.join("logs2").to_string_lossy().to_string();
    state.discovery_config_dir = temp_dir.join("disc-config").to_string_lossy().to_string();
    state.discovery_state_dir = temp_dir.join("disc-state").to_string_lossy().to_string();
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
async fn test_relay_endpoints() {
    let temp_dir = TempDir::new().unwrap();
    let nebula_dir = temp_dir.path().join("nebula");
    std::fs::create_dir_all(&nebula_dir).unwrap();
    std::env::set_var("SGX_GUARDIAN_NEBULA_DIR", nebula_dir.to_str().unwrap());

    let (base_url, _handle, state) = spawn_api(temp_dir.path()).await;
    let client = AppState::authed_client_for_tests(&state).await;

    // GET /api/v1/relay/list
    let res = client
        .get(format!("{}/api/v1/relay/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // GET /api/v1/lighthouse/list
    let res = client
        .get(format!("{}/api/v1/lighthouse/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // GET /api/v1/member/list
    let res = client
        .get(format!("{}/api/v1/member/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // GET /api/v1/relay-lighthouse/list
    let res = client
        .get(format!("{}/api/v1/relay-lighthouse/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // POST /api/v1/relay/limits
    let res = client
        .post(format!("{}/api/v1/relay/limits", base_url))
        .json(&serde_json::json!({
            "node": "node-alpha",
            "maxPeers": 10,
            "maxBandwidthMbps": 50
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // POST /api/v1/relay/toggle
    let res = client
        .post(format!("{}/api/v1/relay/toggle", base_url))
        .json(&serde_json::json!({
            "node": "node-alpha",
            "enabled": true
        }))
        .send()
        .await
        .unwrap();
    // Fails because config file node-alpha.yaml doesn't exist
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);

    // POST /api/v1/relay/lighthouse-toggle
    let res = client
        .post(format!("{}/api/v1/relay/lighthouse-toggle", base_url))
        .json(&serde_json::json!({
            "node": "node-alpha",
            "enabled": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
}
