use serde_json::json;
use sgx_guardian_client::api::build_router;
use sgx_guardian_client::api::state::AppState;
use std::fs::File;
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_attestation_history_api() {
    let tmp = TempDir::new().expect("tempdir");
    let log_dir_primary = tmp.path().to_str().unwrap().to_string();

    let attestation_path = tmp.path().join("last_attestation.json");
    let mut file = File::create(&attestation_path).expect("create file");

    let entries = json!([
        {
            "peer_id": "192.168.100.2:50051",
            "policy_digest": "digest_a",
            "result": "success",
            "timestamp": "2026-07-01T15:30:46Z",
            "peer_did": "did:guardian:nodeB",
            "count": 5
        },
        {
            "peer_id": "192.168.100.2:50051",
            "policy_digest": "digest_a",
            "result": "failed",
            "timestamp": "2026-07-01T15:32:10Z",
            "peer_did": "did:guardian:nodeB",
            "count": 2
        },
        {
            "peer_id": "192.168.100.3:50051",
            "policy_digest": "digest_b",
            "result": "success",
            "timestamp": "2026-07-01T15:35:00Z",
            "peer_did": "did:guardian:nodeC",
            "count": 1
        }
    ]);

    serde_json::to_writer_pretty(&mut file, &entries).expect("write entries");
    drop(file);

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

    // 1. Fetch all
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/attestation", base_url))
        .send()
        .await
        .expect("send request")
        .json()
        .await
        .expect("parse json");

    assert_eq!(resp.as_array().unwrap().len(), 3);
    assert_eq!(resp[0]["peerDid"], "did:guardian:nodeB");
    assert_eq!(resp[0]["count"], 5);

    // 2. Filter by result=failed
    let resp: serde_json::Value = client
        .get(format!("{}/api/v1/attestation?result=failed", base_url))
        .send()
        .await
        .expect("send request")
        .json()
        .await
        .expect("parse json");

    assert_eq!(resp.as_array().unwrap().len(), 1);
    assert_eq!(resp[0]["peerDid"], "did:guardian:nodeB");
    assert_eq!(resp[0]["result"], "failed");
    assert_eq!(resp[0]["count"], 2);

    // 3. Filter by peer_did=did:guardian:nodeC
    let resp: serde_json::Value = client
        .get(format!(
            "{}/api/v1/attestation?peer_did=did:guardian:nodeC",
            base_url
        ))
        .send()
        .await
        .expect("send request")
        .json()
        .await
        .expect("parse json");

    assert_eq!(resp.as_array().unwrap().len(), 1);
    assert_eq!(resp[0]["peerDid"], "did:guardian:nodeC");
    assert_eq!(resp[0]["count"], 1);
}
