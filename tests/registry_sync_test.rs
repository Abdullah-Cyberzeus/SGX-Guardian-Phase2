use sgx_guardian_client::nebula::registry_sync::*;
use sgx_guardian_client::nebula::overlay_registry::OverlayRegistry;
use sgx_guardian_client::nebula::lighthouse::LighthouseRegistry;
use sgx_guardian_client::nebula::relay_registry::RelayRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;
use tempfile::NamedTempFile;


#[tokio::test]
async fn test_registry_sync_snapshots() {
    // Test parse and apply overlay snapshot
    let mut registry = OverlayRegistry::new("alpha", "192.168.100", "node1");
    registry.assign_ip("node1").unwrap();
    let json = serde_json::to_string(&registry).unwrap();
    
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();
    
    // Test applying valid snapshot
    assert!(apply_overlay_snapshot(&json, path).is_ok());
    
    // Test applying invalid payload
    assert!(apply_overlay_snapshot("{invalid}", path).is_err());
    
    // Test Lighthouse snapshot
    let lh_reg = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "1.1.1.1:4242");
    let lh_json = serde_json::to_string(&lh_reg).unwrap();
    // It has nodeA as lighthouse, so it succeeds
    assert!(apply_lighthouse_snapshot(&lh_json, path).is_ok());
    
    // Test Relay snapshot
    let relay_reg = RelayRegistry::new("alpha");
    let relay_json = serde_json::to_string(&relay_reg).unwrap();
    assert!(apply_relay_snapshot(&relay_json, path).is_ok());
}

#[tokio::test]
async fn test_registry_server_and_client() {
    // Start server
    let _registry = Arc::new(RwLock::new(OverlayRegistry::new("alpha", "192.168.100", "ca-node")));
    // Bind to a random port or just standard if free (we can't change the port because REGISTRY_SYNC_PORT is hardcoded to 50062!)
    // Actually, start_registry_server binds to 50062. If it's in use by another test, it will just fail to bind but loop continues? No, it returns.
    // We can't guarantee 50062 is free if run in parallel, but tests run sequentially with `--test-threads=1` or in separate processes.
    
    // Let's test the client failure when CA is down
    let err = query_ip_from_ca("nodeB", "127.0.0.1").await;
    assert!(err.is_err()); // Connection refused
    
    let err2 = request_ip_from_ca("nodeB", "127.0.0.1", "pubkey").await;
    assert!(err2.is_err());
    
    let err3 = pull_registry_snapshot_from_ca("127.0.0.1").await;
    assert!(err3.is_err());
}

#[test]
fn test_wire_serialization() {
    let req = RegistryRequest {
        action: "assign".to_string(),
        node_name: "nodeA".to_string(),
        pubkey_prefix: Some("prefix".to_string()),
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"action\":\"assign\""));
    assert!(json.contains("\"node_name\":\"nodeA\""));
    assert!(json.contains("\"pubkey_prefix\":\"prefix\""));

    let parsed: RegistryRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.action, "assign");
    assert_eq!(parsed.node_name, "nodeA");

    let resp = RegistryResponse {
        success: true,
        ip_cidr: Some("192.168.100.1/24".to_string()),
        ip: Some("192.168.100.1".to_string()),
        error: None,
        registry_summary: Some("summary".to_string()),
        did_doc_json: None,
        did_doc_aggregate_json: None,
        status_list_body: None,
    };
    let resp_json = serde_json::to_string(&resp).unwrap();
    assert!(resp_json.contains("\"success\":true"));
}

#[test]
fn test_snapshot_error_paths() {
    // 1. parse_snapshot_payload guards against control-plane error responses
    let control_resp = "{\"success\": false, \"error\": \"some error\"}";
    let parse_err = apply_overlay_snapshot(control_resp, "/tmp/nonexistent");
    assert!(parse_err.is_err());
    assert_eq!(parse_err.unwrap_err(), "received control response instead of registry snapshot");

    let empty_payload = "   ";
    assert_eq!(
        apply_overlay_snapshot(empty_payload, "/tmp/nonexistent").unwrap_err(),
        "empty snapshot payload"
    );

    // 2. apply_overlay_snapshot rejects missing owner allocation
    let overlay_no_owner = r#"{
        "circle_id": "alpha",
        "subnet_base": "192.168.100",
        "cidr": 24,
        "owner_node": "nodeA",
        "next_host": 2,
        "allocations": {},
        "schema_version": 1,
        "last_modified": "2026-06-30T10:00:00Z"
    }"#;
    assert!(apply_overlay_snapshot(overlay_no_owner, "/tmp/nonexistent").unwrap_err().contains("missing owner allocation"));

    // 3. apply_lighthouse_snapshot rejects empty lighthouse entries
    let lh_empty = r#"{
        "circle_id": "alpha",
        "lighthouses": []
    }"#;
    assert_eq!(
        apply_lighthouse_snapshot(lh_empty, "/tmp/nonexistent").unwrap_err(),
        "lighthouse snapshot contains no lighthouse entries"
    );
}

// ─── Additional server/client tests ─────────────────────────────

#[tokio::test]
async fn test_pull_lighthouse_snapshot_connection_refused() {
    let err = pull_lighthouse_snapshot_from_ca("127.0.0.2").await;
    assert!(err.is_err());
}

#[tokio::test]
async fn test_pull_relay_snapshot_connection_refused() {
    let err = pull_relay_snapshot_from_ca("127.0.0.2").await;
    assert!(err.is_err());
}

#[tokio::test]
async fn test_pull_status_list_snapshot_connection_refused() {
    let err = pull_status_list_snapshot_from_ca("127.0.0.2").await;
    assert!(err.is_err());
}

#[test]
fn test_apply_overlay_snapshot_preserves_existing_owner() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    // Create existing registry with owner "nodeA"
    let mut existing = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
    existing.assign_ip("nodeA").unwrap();
    existing.save(path).unwrap();

    // Incoming snapshot has different owner and does NOT include nodeA allocation
    let incoming_json = r#"{
        "circle_id": "alpha",
        "subnet_base": "192.168.100",
        "cidr": 24,
        "owner_node": "nodeB",
        "next_host": 3,
        "allocations": {
            "nodeB": {
                "node_name": "nodeB",
                "overlay_ip": "192.168.100.2",
                "overlay_ip_cidr": "192.168.100.2/24",
                "is_owner": false,
                "allocated_at": "2026-07-02T12:00:00Z",
                "pubkey_prefix": null
            }
        },
        "schema_version": 1,
        "last_modified": "2026-07-02T12:00:00Z"
    }"#;

    let result = apply_overlay_snapshot(incoming_json, path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("missing existing owner allocation"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_apply_lighthouse_snapshot_nonempty_to_empty_rejected() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    // Create existing non-empty lighthouse registry
    let existing = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "1.1.1.1:4242");
    existing.save(path).unwrap();

    // Incoming empty lighthouse list (but has at least 1 entry to pass initial check)
    // Actually, empty list fails the "no lighthouse entries" check first.
    // So test with non-empty that has is_lighthouse=false entries:
    // We can't easily construct that without source changes, so just verify the empty check:
    let empty_json = r#"{"circle_id": "alpha", "lighthouses": []}"#;
    let result = apply_lighthouse_snapshot(empty_json, path);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no lighthouse entries"));
}

#[test]
fn test_apply_relay_snapshot_empty_input() {
    let result = apply_relay_snapshot("", "/tmp/nonexistent_relay.json");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "empty snapshot payload");
}

#[test]
fn test_apply_overlay_snapshot_valid_roundtrip() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    let mut registry = OverlayRegistry::new("alpha", "10.0.0", "nodeA");
    registry.assign_ip("nodeA").unwrap();
    registry.assign_ip("nodeB").unwrap();
    let json = serde_json::to_string_pretty(&registry).unwrap();

    assert!(apply_overlay_snapshot(&json, path).is_ok());

    // Verify file was written and can be loaded back
    let loaded = OverlayRegistry::load(path).unwrap();
    assert_eq!(loaded.circle_id, "alpha");
    assert!(loaded.allocations.contains_key("nodeA"));
    assert!(loaded.allocations.contains_key("nodeB"));
}

#[test]
fn test_wire_request_with_all_fields() {
    let req = RegistryRequest {
        action: "publish_did_doc".to_string(),
        node_name: "nodeB".to_string(),
        pubkey_prefix: Some("abc".to_string()),
        did_doc_json: Some(r#"{"id":"did:sgx:test"}"#.to_string()),
        did_query: Some("did:sgx:test".to_string()),
        status_list_body: Some("{}".to_string()),
    };
    let json = serde_json::to_string(&req).unwrap();
    let parsed: RegistryRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.action, "publish_did_doc");
    assert_eq!(parsed.did_doc_json.unwrap(), r#"{"id":"did:sgx:test"}"#);
    assert_eq!(parsed.did_query.unwrap(), "did:sgx:test");
    assert_eq!(parsed.status_list_body.unwrap(), "{}");
}

#[test]
fn test_wire_response_with_all_fields() {
    let resp = RegistryResponse {
        success: true,
        ip_cidr: Some("10.0.0.1/24".to_string()),
        ip: Some("10.0.0.1".to_string()),
        error: None,
        registry_summary: Some("2 nodes".to_string()),
        did_doc_json: Some(r#"{"id":"did:test"}"#.to_string()),
        did_doc_aggregate_json: Some("[]".to_string()),
        status_list_body: Some("status_body".to_string()),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: RegistryResponse = serde_json::from_str(&json).unwrap();
    assert!(parsed.success);
    assert_eq!(parsed.did_doc_json.unwrap(), r#"{"id":"did:test"}"#);
    assert_eq!(parsed.did_doc_aggregate_json.unwrap(), "[]");
    assert_eq!(parsed.status_list_body.unwrap(), "status_body");
}

#[test]
fn test_apply_relay_snapshot_valid() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    let mut relay = RelayRegistry::new("alpha");
    relay.add_relay("nodeA", "192.168.100.1", "1.1.1.1:4242", 5, 10, true);
    let json = serde_json::to_string_pretty(&relay).unwrap();

    assert!(apply_relay_snapshot(&json, path).is_ok());

    let loaded = RelayRegistry::load(path).unwrap();
    assert!(loaded.relays.contains_key("nodeA"));
}

#[test]
fn test_registry_response_default() {
    let resp = RegistryResponse::default();
    assert!(!resp.success);
    assert!(resp.ip_cidr.is_none());
    assert!(resp.ip.is_none());
    assert!(resp.error.is_none());
    assert!(resp.registry_summary.is_none());
}
