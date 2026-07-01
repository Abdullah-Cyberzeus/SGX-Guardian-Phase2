use serde_json::json;
use sgx_guardian_client::api::build_router;
use sgx_guardian_client::api::state::AppState;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_audit_logs_api() {
    // 1. Create a TempDir for logs
    let temp_dir = TempDir::new().expect("create temp dir");
    let log_dir_primary = temp_dir.path().to_string_lossy().to_string();

    // 2. Write mock audit log entries for nodeA
    let audit_log_path = temp_dir.path().join("audit-nodeA.log");
    let mut file = File::create(&audit_log_path).expect("create audit log file");

    let entries = vec![
        json!({
            "event": {
                "timestamp": 1782881390,
                "node_id": "nodeA",
                "category": "Node",
                "severity": "Info",
                "action": "Started",
                "message": "Node started successfully"
            },
            "hash": "hash1",
            "previous_hash": "GENESIS"
        }),
        json!({
            "event": {
                "timestamp": 1782881392,
                "node_id": "nodeA",
                "category": "Network",
                "severity": "Warning",
                "action": "Failed",
                "message": "TLS connection failed to 127.0.0.1:50052: transport error"
            },
            "hash": "hash2",
            "previous_hash": "hash1"
        }),
        json!({
            "event": {
                "timestamp": 1782881395,
                "node_id": "nodeA",
                "category": "Identity",
                "severity": "Critical",
                "action": "Rejected",
                "message": "DKP key rotation failed due to SE050 error"
            },
            "hash": "hash3",
            "previous_hash": "hash2"
        }),
    ];

    for entry in entries {
        writeln!(file, "{}", entry).expect("write log line");
    }
    drop(file);

    // 3. Setup state
    // Set SGX_GUARDIAN_AUDIT_LOG_PATH to our explicit mock file so it resolves correctly
    std::env::set_var("SGX_GUARDIAN_AUDIT_LOG_PATH", &audit_log_path);

    let state = Arc::new(AppState {
        node_id: "nodeA".into(),
        config_dir: "/tmp/config".into(),
        boot_dir: "/tmp/boot".into(),
        keys_dir: "/tmp/keys".into(),
        pcr_dir: "/tmp/pcr".into(),
        pcr_baseline_dir: "/tmp/pcr_baseline".into(),
        log_dir_primary,
        log_dir_fallback: "logs".into(),
        did_resolver: sgx_guardian_client::did::Resolver::new(Default::default()),
        vid_cache: sgx_guardian_client::virtual_id_cache::VirtualIdCache::new(),
        discovery_config_dir: "/tmp/discovery_config".into(),
        discovery_state_dir: "/tmp/discovery_state".into(),
    });

    // 4. Spawn test server
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

    // 5. Test basic query (returns all in reverse chronological order)
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/audit/logs", base_url))
        .send()
        .await
        .expect("send request")
        .json()
        .await
        .expect("parse json");

    assert_eq!(resp["status"], "success");
    assert_eq!(resp["count"], 3);
    assert_eq!(resp["items"][0]["event"]["category"], "Identity"); // Newest first
    assert_eq!(resp["items"][2]["event"]["category"], "Node"); // Oldest last

    // 6. Test category filtering
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/audit/logs?category=network", base_url))
        .send()
        .await
        .expect("send request")
        .json()
        .await
        .expect("parse json");
    assert_eq!(resp["count"], 1);
    assert_eq!(resp["items"][0]["event"]["category"], "Network");

    // 7. Test severity filtering
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/audit/logs?severity=warn", base_url))
        .send()
        .await
        .expect("send request")
        .json()
        .await
        .expect("parse json");
    assert_eq!(resp["count"], 1);
    assert_eq!(resp["items"][0]["event"]["severity"], "Warning");

    // 8. Test search filtering
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/audit/logs?search=dkp", base_url))
        .send()
        .await
        .expect("send request")
        .json()
        .await
        .expect("parse json");
    assert_eq!(resp["count"], 1);
    assert!(resp["items"][0]["event"]["message"]
        .as_str()
        .unwrap()
        .contains("DKP"));

    // 9. Test tail filtering
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/audit/logs?tail=2", base_url))
        .send()
        .await
        .expect("send request")
        .json()
        .await
        .expect("parse json");
    assert_eq!(resp["count"], 2);
    assert_eq!(resp["items"][0]["event"]["category"], "Identity");
    assert_eq!(resp["items"][1]["event"]["category"], "Network");

    // Clean up
    std::env::remove_var("SGX_GUARDIAN_AUDIT_LOG_PATH");
}
