use serde_json::json;
use sgx_guardian_client::api::build_router;
use sgx_guardian_client::api::state::AppState;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_cert_requests_and_approve_api() {
    let tmp = TempDir::new().expect("tempdir");
    let nebula_dir = tmp.path().to_str().unwrap().to_string();
    std::env::set_var("SGX_NEBULA_DIR", &nebula_dir);

    // Create requests directory
    let requests_dir = tmp.path().join("requests");
    fs::create_dir_all(&requests_dir).expect("create dir");

    // Write a mock yaml request file for nodeB
    let request_file_path = requests_dir.join("nodeB.yaml");
    let yaml_content = r#"node_id: nodeB
requested_at: "2026-07-02T12:00:00Z"
overlay_ip: "192.168.100.2/24"
public_key_fingerprint: "abc123xyz"
requested_role: member
approve: false
"#;
    fs::write(&request_file_path, yaml_content).expect("write mock yaml");

    let state = Arc::new(AppState {
        node_id: "nodeA".into(),
        config_dir: "/tmp/config".into(),
        boot_dir: "/tmp/boot".into(),
        keys_dir: "/tmp/keys".into(),
        pcr_dir: "/tmp/pcr".into(),
        pcr_baseline_dir: "/tmp/pcr_baseline".into(),
        threat_config_path: "/tmp/test_threat_config.json".into(),
        threat_state_dir: "/tmp/test_threat_state".into(),
        log_dir_primary: "/tmp/logs".into(),
        log_dir_fallback: "logs".into(),
        did_resolver: sgx_guardian_client::did::Resolver::new(Default::default()),
        vid_cache: sgx_guardian_client::virtual_id_cache::VirtualIdCache::new(),
        discovery_config_dir: "/tmp/discovery_config".into(),
        discovery_state_dir: "/tmp/discovery_state".into(),
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    let client = reqwest::Client::new();
    let base_url = format!("http://{}", addr);

    // 1. Fetch pending requests
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/cert/requests", base_url))
        .send()
        .await
        .expect("send GET request")
        .json()
        .await
        .expect("parse GET json");

    assert_eq!(resp.as_array().unwrap().len(), 1);
    assert_eq!(resp[0]["node_id"], "nodeB");
    assert_eq!(resp[0]["approve"], "false");
    assert_eq!(resp[0]["requested_role"], "member");

    // 2. Approve request
    let approve_payload = json!({
        "node_id": "nodeB",
        "decision": "member"
    });

    let post_resp: serde_json::Value = client
        .post(format!("{}/api/v1/cert/approve", base_url))
        .json(&approve_payload)
        .send()
        .await
        .expect("send POST request")
        .json()
        .await
        .expect("parse POST json");

    assert_eq!(post_resp["status"], "success");

    // 3. Re-fetch pending requests to confirm decision has been written
    let resp_updated: serde_json::Value = client
        .get(format!("{}/api/v1/cert/requests", base_url))
        .send()
        .await
        .expect("send GET request")
        .json()
        .await
        .expect("parse GET json");

    assert_eq!(resp_updated.as_array().unwrap().len(), 1);
    assert_eq!(resp_updated[0]["node_id"], "nodeB");
    assert_eq!(resp_updated[0]["approve"], "member");

    // Clean up env
    std::env::remove_var("SGX_NEBULA_DIR");
}
