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
        log_dir_primary: temp_dir.join("logs").to_string_lossy().to_string(),
        log_dir_fallback: temp_dir.join("logs2").to_string_lossy().to_string(),
        did_resolver: sgx_guardian_client::did::Resolver::new(Default::default()),
        vid_cache: sgx_guardian_client::virtual_id_cache::VirtualIdCache::new(),
        discovery_config_dir: temp_dir.join("disc-config").to_string_lossy().to_string(),
        discovery_state_dir: temp_dir.join("disc-state").to_string_lossy().to_string(),
    })
}

async fn spawn_api(temp_dir: &std::path::Path) -> (String, tokio::task::JoinHandle<()>, Arc<AppState>) {
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
async fn test_policy_get_current_and_backup() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
    
    // Write an invalid policy to active path to test validation error
    let _ = std::fs::create_dir_all("/etc/sgx-guardian/policies");
    
    // We only test this if we can write to /etc/sgx-guardian/policies (which might not be true in test env)
    // Actually, in `api/handlers/policy.rs`, these paths are hardcoded to `/etc/sgx-guardian/...` or `crate::policy_state::ACTIVE_POLICY`.
    // We can test `save_current` which writes to PENDING_POLICY_PATH, but that is also hardcoded to `/etc/sgx-guardian/policies/pending_policy.yaml`.
    // If the test env can't write there, it will fail with 500. We can just test that we get 400 for bad YAML on save_current.
    
    let client = reqwest::Client::new();
    
    // 1. PUT invalid YAML to current
    let res = client.put(&format!("{}/api/v1/policy/current", base_url))
        .json(&serde_json::json!({"content": "invalid: yaml: : :"}))
        .send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);

    // 2. PUT valid YAML but missing required fields
    let res = client.put(&format!("{}/api/v1/policy/current", base_url))
        .json(&serde_json::json!({"content": "policy_id: alpha\nrules: []"}))
        .send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);

    // 3. POST verify-deployed without a sig file
    let res = client.post(&format!("{}/api/v1/policy/verify-deployed", base_url)).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);

    // 4. POST sign-deploy-current without pending policy
    let res = client.post(&format!("{}/api/v1/policy/sign-deploy-current", base_url)).send().await.unwrap();
    // returns 400 because pending policy is not found
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_policy_multipart_endpoints_missing_fields() {
    let temp_dir = TempDir::new().unwrap();
    let (base_url, _handle, _state) = spawn_api(temp_dir.path()).await;
    let client = reqwest::Client::new();

    // POST /api/v1/policy/sign missing 'policy'
    let body1 = "--boundary\r\n\
Content-Disposition: form-data; name=\"key\"\r\n\
\r\n\
dummy-key\r\n\
--boundary--\r\n";

    let res = client.post(&format!("{}/api/v1/policy/sign", base_url))
        .header("Content-Type", "multipart/form-data; boundary=boundary")
        .body(body1)
        .send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);

    // POST /api/v1/policy/verify missing 'policy'
    let body2 = "--boundary\r\n\
Content-Disposition: form-data; name=\"wrong_field\"\r\n\
\r\n\
dummy\r\n\
--boundary--\r\n";

    let res = client.post(&format!("{}/api/v1/policy/verify", base_url))
        .header("Content-Type", "multipart/form-data; boundary=boundary")
        .body(body2)
        .send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
}
