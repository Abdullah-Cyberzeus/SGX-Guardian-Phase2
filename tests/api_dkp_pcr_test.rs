use axum::extract::State;
use axum::Json;
use sgx_guardian_client::api::handlers::{dkp, pcr};
use sgx_guardian_client::api::state::AppState;
use sgx_guardian_client::did::Resolver;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tempfile::TempDir;

fn create_mock_app_state(node_id: &str) -> (Arc<AppState>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let resolver = Resolver::new(Default::default());
    let mut state = AppState::from_env(node_id.to_string(), resolver);
    
    // Override directories to point to our temp dir
    let arc_state = Arc::get_mut(&mut state).unwrap();
    arc_state.pcr_dir = temp_dir.path().to_str().unwrap().to_string();
    arc_state.keys_dir = temp_dir.path().to_str().unwrap().to_string();

    (state, temp_dir)
}

#[tokio::test]
async fn test_pcr_status_success() {
    let node_id = "test-node-123";
    let (state, temp_dir) = create_mock_app_state(node_id);

    let pcr_json = r#"{
        "composite_digest": "abcdef123456",
        "integrity_status": "PASS",
        "device_uid": "0123456789",
        "key_version": 2,
        "measured_at": "2023-10-27T10:00:00Z",
        "schema_version": 1,
        "pcr_values": ["val0", "val1", "val2", "val3", "val4"]
    }"#;

    let pcr_file_path = temp_dir.path().join(format!("{}_current.json", node_id));
    fs::write(&pcr_file_path, pcr_json).unwrap();

    let response = pcr::status(State(state)).await;
    assert!(response.is_ok());

    let status = response.unwrap().0;
    assert_eq!(status.node, node_id);
    assert_eq!(status.composite_digest, "abcdef123456");
    assert_eq!(status.integrity_status, "PASS");
    assert_eq!(status.device_uid, "0123456789");
    assert_eq!(status.key_version, 2);
    assert_eq!(status.measured_at, "2023-10-27T10:00:00Z");
    assert_eq!(status.schema_version, 1);
    assert_eq!(status.registers.len(), 5);
    assert_eq!(status.registers[0].value, "val0");
    assert_eq!(status.registers[4].value, "val4");
}

#[tokio::test]
async fn test_pcr_status_missing_file_fails() {
    let (state, _temp_dir) = create_mock_app_state("test-node-456");
    let response = pcr::status(State(state)).await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_dkp_status_success() {
    let (state, temp_dir) = create_mock_app_state("test-node");

    let dkp_meta_json = r#"[
        {
            "version": 1,
            "key_id": "key-1",
            "algorithm": "ECDSA-P256",
            "status": "Revoked",
            "created_at": "2023-01-01T00:00:00Z"
        },
        {
            "version": 2,
            "key_id": "key-2",
            "algorithm": "ECDSA-P256",
            "status": "Active",
            "created_at": "2023-06-01T00:00:00Z",
            "rotated_from": "key-1"
        }
    ]"#;

    let dkp_meta_path = temp_dir.path().join("dkp_metadata.json");
    fs::write(&dkp_meta_path, dkp_meta_json).unwrap();

    let dkp_pub_path = temp_dir.path().join("dkp_pub.der");
    fs::write(&dkp_pub_path, b"mock_pub_key_bytes").unwrap();

    let response = dkp::status(State(state)).await;
    assert!(response.is_ok());

    let status = response.unwrap().0;
    assert_eq!(status.total_versions, 2);
    assert_eq!(status.active_version, Some(2));
    assert_eq!(status.active_pub_size, Some(18));
    assert!(status.active_pub_path.is_some());
    assert_eq!(status.keys.len(), 2);

    assert_eq!(status.keys[0].version, 1);
    assert_eq!(status.keys[0].status, "Revoked");

    assert_eq!(status.keys[1].version, 2);
    assert_eq!(status.keys[1].status, "Active");
    assert_eq!(status.keys[1].rotated_from, Some("key-1".to_string()));
}

#[tokio::test]
async fn test_dkp_status_missing_file_fails() {
    let (state, _temp_dir) = create_mock_app_state("test-node");
    let response = dkp::status(State(state)).await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_run_cli_handlers() {
    let (state, temp_dir) = create_mock_app_state("test-node");
    
    // Create a mock sgx-pa-cli executable
    let mock_cli_path = temp_dir.path().join("sgx-pa-cli");
    let mock_cli_script = r#"#!/bin/sh
echo "Mock CLI output"
"#;
    fs::write(&mock_cli_path, mock_cli_script).unwrap();
    
    let mut perms = fs::metadata(&mock_cli_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&mock_cli_path, perms).unwrap();

    // Set environment variable to force run_cli to use our mock
    std::env::set_var("SGX_PA_CLI_PATH", mock_cli_path.to_str().unwrap());

    // Test pcr::baseline_create
    let response = pcr::baseline_create(State(state.clone())).await;
    assert!(response.is_ok());
    let action_response = response.unwrap().0;
    assert!(action_response.success);
    assert!(action_response.stdout.contains("Mock CLI output"));

    // Test dkp::rotate
    let response = dkp::rotate(State(state.clone())).await;
    assert!(response.is_ok());
    let action_response = response.unwrap().0;
    assert!(action_response.success);

    // Test dkp::revoke
    let revoke_body = Json(dkp::RevokeBody {
        version: 1,
        reason: Some("Compromised".to_string()),
    });
    let response = dkp::revoke(State(state.clone()), revoke_body).await;
    assert!(response.is_ok());
    let action_response = response.unwrap().0;
    assert!(action_response.success);

    // Test dkp::emergency_rotate
    let emergency_body = Json(dkp::EmergencyBody {
        reason: Some("Emergency".to_string()),
    });
    let response = dkp::emergency_rotate(State(state.clone()), emergency_body).await;
    assert!(response.is_ok());
    let action_response = response.unwrap().0;
    assert!(action_response.success);

    std::env::remove_var("SGX_PA_CLI_PATH");
}
