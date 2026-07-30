// tests/nebula_relay_registry_extended_test.rs
// Integration tests for uncovered branches in src/nebula/relay_registry.rs

use sgx_guardian_client::nebula::relay_registry::RelayRegistry;
use tempfile::NamedTempFile;

fn make_registry() -> RelayRegistry {
    let mut reg = RelayRegistry::new("test-circle");
    reg.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242", 10, 50, false);
    reg.add_relay("nodeC", "192.168.100.3", "10.0.0.3:4242", 5, 0, true);
    reg
}

// ── update_limits ─────────────────────────────────────────────────────────────

#[test]
fn test_update_limits_returns_true_for_existing_node() {
    let mut reg = make_registry();
    let updated = reg.update_limits("nodeB", 20, 100);
    assert!(updated);
    let entry = reg.relays.get("nodeB").unwrap();
    assert_eq!(entry.max_peers, 20);
    assert_eq!(entry.max_bandwidth_mbps, 100);
}

#[test]
fn test_update_limits_returns_false_for_missing_node() {
    let mut reg = make_registry();
    let updated = reg.update_limits("nonexistent", 20, 100);
    assert!(!updated);
}

// ── mark_active / mark_inactive ───────────────────────────────────────────────

#[test]
fn test_mark_inactive_then_mark_active_toggles_state() {
    let mut reg = make_registry();
    reg.mark_inactive("nodeB");
    assert!(!reg.relays.get("nodeB").unwrap().is_active);

    reg.mark_active("nodeB");
    assert!(reg.relays.get("nodeB").unwrap().is_active);
}

#[test]
fn test_mark_active_updates_last_seen() {
    let mut reg = make_registry();
    let before = reg.relays.get("nodeB").unwrap().last_seen;
    std::thread::sleep(std::time::Duration::from_millis(10));
    reg.mark_active("nodeB");
    let after = reg.relays.get("nodeB").unwrap().last_seen;
    assert!(after >= before);
}

#[test]
fn test_mark_active_on_nonexistent_is_noop() {
    let mut reg = make_registry();
    // Should not panic
    reg.mark_active("nobody");
    reg.mark_inactive("nobody");
}

// ── load_or_create ────────────────────────────────────────────────────────────

#[test]
fn test_load_or_create_missing_file_returns_new_registry() {
    let reg = RelayRegistry::load_or_create("/tmp/sgx-test-nonexistent-relay.json", "beta");
    assert_eq!(reg.circle_id, "beta");
    assert!(reg.relays.is_empty());
}

#[test]
fn test_load_or_create_valid_file_returns_loaded_registry() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    let mut reg = RelayRegistry::new("gamma");
    reg.add_relay("nodeX", "192.168.200.1", "10.1.0.1:4242", 8, 20, false);
    reg.save(&path).unwrap();

    let loaded = RelayRegistry::load_or_create(&path, "gamma");
    assert_eq!(loaded.circle_id, "gamma");
    assert!(loaded.is_relay("nodeX"));
}

#[test]
fn test_load_or_create_invalid_file_falls_back_to_new() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    // Write invalid JSON
    std::fs::write(&path, b"not-valid-json!!!").unwrap();

    let reg = RelayRegistry::load_or_create(&path, "delta");
    // Should fall back to a fresh registry
    assert_eq!(reg.circle_id, "delta");
    assert!(reg.relays.is_empty());
}

// ── active_relays filtering ───────────────────────────────────────────────────

#[test]
fn test_active_relays_returns_only_active() {
    let mut reg = make_registry();
    // nodeB and nodeC both active initially
    assert_eq!(reg.active_relays().len(), 2);

    reg.mark_inactive("nodeC");
    let active = reg.active_relays();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].node_name, "nodeB");
}

// ── save and load roundtrip ───────────────────────────────────────────────────

#[test]
fn test_save_load_roundtrip_with_multiple_relays() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    let mut reg = make_registry();
    reg.mark_inactive("nodeC");
    reg.save(&path).unwrap();

    let loaded = RelayRegistry::load(&path).unwrap();
    assert_eq!(loaded.circle_id, "test-circle");
    assert!(loaded.is_relay("nodeB"));
    assert!(loaded.is_relay("nodeC"));
    assert!(!loaded.relays.get("nodeC").unwrap().is_active);
}

// ── is_lighthouse attribute ───────────────────────────────────────────────────

#[test]
fn test_relay_with_lighthouse_role() {
    let reg = make_registry();
    let node_c = reg.relays.get("nodeC").unwrap();
    assert!(node_c.is_lighthouse);
    assert_eq!(node_c.max_bandwidth_mbps, 0); // unlimited
}

#[test]
fn test_relay_without_lighthouse_role() {
    let reg = make_registry();
    let node_b = reg.relays.get("nodeB").unwrap();
    assert!(!node_b.is_lighthouse);
    assert_eq!(node_b.max_peers, 10);
}
