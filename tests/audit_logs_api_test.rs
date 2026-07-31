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

    let mut state = Arc::try_unwrap(AppState::for_tests(temp_dir.path(), "nodeA", "/tmp/config"))
        .unwrap_or_else(|_| unreachable!("sole Arc owner"));
    state.log_dir_primary = log_dir_primary;
    state.log_dir_fallback = "logs".into();
    let state = Arc::new(state);

    // 4. Spawn test server
    let app = build_router(state.clone(), axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    let client = AppState::authed_client_for_tests(&state).await;
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

#[tokio::test]
async fn test_raw_logs_api() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let log_dir_primary = temp_dir.path().to_string_lossy().to_string();

    // Setup state
    let mut state = Arc::try_unwrap(AppState::for_tests(temp_dir.path(), "nodeA", "/tmp/config"))
        .unwrap_or_else(|_| unreachable!("sole Arc owner"));
    state.log_dir_primary = log_dir_primary.clone();
    state.log_dir_fallback = "logs-fallback".into();
    let state = Arc::new(state);

    let app = build_router(state.clone(), axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    let client = AppState::authed_client_for_tests(&state).await;
    let base_url = format!("http://{}", addr);

    // 1. Test empty log dir (should return 404)
    let res = client
        .get(format!("{}/api/v1/logs", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // 2. Write mock raw logs
    let raw_log_path = temp_dir.path().join("nodeA-2026-07-03.log");
    let mut file = File::create(&raw_log_path).unwrap();
    writeln!(
        file,
        r#"{{"timestamp":"2026-07-03T10:00:00Z","level":"info","message":"started"}}"#
    )
    .unwrap();
    writeln!(
        file,
        r#"{{"timestamp":"2026-07-03T10:01:00Z","level":"warn","message":"low memory"}}"#
    )
    .unwrap();
    writeln!(
        file,
        r#"{{"timestamp":"2026-07-03T10:02:00Z","level":"error","message":"crash"}}"#
    )
    .unwrap();
    writeln!(file, "plain text log line without json").unwrap();
    drop(file);

    // 3. Test raw logs query (tail, level, search)
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/logs?tail=2", base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["total"], 2);
    assert_eq!(resp["entries"][0]["level"], "error"); // 3rd line
    assert_eq!(resp["entries"][1]["level"], "info"); // 4th line parsed as info

    let resp_warn: serde_json::Value = client
        .get(format!("{}/api/v1/logs?level=warn", base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp_warn["total"], 1);
    assert_eq!(resp_warn["entries"][0]["message"], "low memory");

    let resp_search: serde_json::Value = client
        .get(format!("{}/api/v1/logs?search=crash", base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp_search["total"], 1);
    assert_eq!(resp_search["entries"][0]["message"], "crash");
}
