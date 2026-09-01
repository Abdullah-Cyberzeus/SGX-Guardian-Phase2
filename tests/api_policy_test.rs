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
async fn test_policy_multipart_endpoints_missing_fields() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, state) = spawn_api(temp_dir.path()).await;
    let client = AppState::authed_client_for_tests(&state).await;

    // POST /api/v1/policy/sign missing 'policy'
    let body1 = "--boundary\r\n\
Content-Disposition: form-data; name=\"key\"\r\n\
\r\n\
dummy-key\r\n\
--boundary--\r\n";

    let res = client
        .post(format!("{}/api/v1/policy/sign", base_url))
        .header("Content-Type", "multipart/form-data; boundary=boundary")
        .body(body1)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);

    // POST /api/v1/policy/verify missing 'policy'
    let body2 = "--boundary\r\n\
Content-Disposition: form-data; name=\"wrong_field\"\r\n\
\r\n\
dummy\r\n\
--boundary--\r\n";

    let res = client
        .post(format!("{}/api/v1/policy/verify", base_url))
        .header("Content-Type", "multipart/form-data; boundary=boundary")
        .body(body2)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
}
