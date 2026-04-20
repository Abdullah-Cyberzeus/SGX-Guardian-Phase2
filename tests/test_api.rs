use std::sync::Arc;

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().to_path_buf();

    let state = Arc::new(sgx_guardian_client::api::state::AppState {
        node_id: "nodeA".to_string(),
        config_dir: root.join("config").to_string_lossy().to_string(),
        boot_dir: root.join("boot").to_string_lossy().to_string(),
        keys_dir: root.join("keys").to_string_lossy().to_string(),
        pcr_dir: root.join("pcr").to_string_lossy().to_string(),
        pcr_baseline_dir: root.to_string_lossy().to_string(),
        log_dir_primary: root.join("logs").to_string_lossy().to_string(),
        log_dir_fallback: root.join("logs_fb").to_string_lossy().to_string(),
    });

    let app = sgx_guardian_client::api::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    let url = format!("http://{}/api/v1/health", addr);
    let body = reqwest::get(url).await.unwrap().text().await.unwrap();
    assert_eq!(body, "ok");

    server.abort();
}
