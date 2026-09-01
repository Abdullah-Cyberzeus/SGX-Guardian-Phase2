use chrono::Utc;
use sgx_guardian_client::threat::inventory::{AlertInventory, IngestOutcome};
use sgx_guardian_client::threat::service::ThreatService;
use sgx_guardian_client::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};
use std::sync::Arc;
use tokio::sync::Mutex;

fn service(node: &str) -> ThreatService {
    let dir = tempfile::tempdir().unwrap();
    ThreatService {
        node_id: node.into(),
        config_path: dir.path().join("suricata.yaml"),
        state_dir: dir.path().join("state"),
        inventory: Arc::new(Mutex::new(AlertInventory::default())),
    }
}

fn alert(id: &str) -> ThreatAlert {
    ThreatAlert {
        alert_id: id.into(),
        timestamp: Utc::now(),
        src_ip: "203.0.113.10".into(),
        src_port: 1,
        dst_ip: "198.51.100.1".into(),
        dst_port: 2,
        protocol: "TCP".into(),
        signature_id: 1,
        signature: "sig".into(),
        category: ThreatCategory::Other,
        severity: Severity::Low,
        rev: 1,
        gid: 1,
        event_type: "alert".into(),
        blocked: false,
    }
}

#[test]
fn service_preserves_node_id() {
    assert_eq!(service("node-a").node_id, "node-a");
}

#[test]
fn service_allows_empty_node_id() {
    assert!(service("").node_id.is_empty());
}

#[test]
fn service_config_path_has_file_name() {
    assert_eq!(service("n").config_path.file_name().unwrap(), "suricata.yaml");
}

#[test]
fn service_state_dir_has_expected_name() {
    assert_eq!(service("n").state_dir.file_name().unwrap(), "state");
}

#[tokio::test]
async fn service_inventory_starts_empty() {
    assert!(service("n").inventory.lock().await.snapshot().is_empty());
}

#[tokio::test]
async fn service_inventory_is_shared_arc() {
    let svc = service("n");
    let cloned = svc.inventory.clone();
    svc.inventory.lock().await.ingest(alert("a"));
    assert_eq!(cloned.lock().await.snapshot().len(), 1);
}

macro_rules! inventory_insert_tests {
    ($($name:ident => $id:expr),+ $(,)?) => {$(
        #[tokio::test]
        async fn $name() {
            let svc = service("n");
            assert_eq!(svc.inventory.lock().await.ingest(alert($id)), IngestOutcome::Inserted);
        }
    )+};
}

inventory_insert_tests! {
    inventory_insert_a => "a",
    inventory_insert_b => "b",
    inventory_insert_empty_id => "",
    inventory_insert_long_id => "abcdefghijklmnopqrstuvwxyz0123456789",
}

#[tokio::test]
async fn duplicate_alert_is_detected() {
    let svc = service("n");
    let mut inv = svc.inventory.lock().await;
    let alert = alert("a");
    assert_eq!(inv.ingest(alert.clone()), IngestOutcome::Inserted);
    assert_eq!(inv.ingest(alert), IngestOutcome::Duplicate);
}

#[tokio::test]
async fn blocked_duplicate_updates_alert() {
    let svc = service("n");
    let mut inv = svc.inventory.lock().await;
    assert_eq!(inv.ingest(alert("a")), IngestOutcome::Inserted);
    let mut blocked = alert("a");
    blocked.blocked = true;
    assert_eq!(inv.ingest(blocked), IngestOutcome::Updated);
}

#[tokio::test]
async fn higher_severity_duplicate_updates_alert() {
    let svc = service("n");
    let mut inv = svc.inventory.lock().await;
    assert_eq!(inv.ingest(alert("a")), IngestOutcome::Inserted);
    let mut high = alert("a");
    high.severity = Severity::High;
    assert_eq!(inv.ingest(high), IngestOutcome::Updated);
}

#[tokio::test]
async fn snapshot_returns_clone() {
    let svc = service("n");
    svc.inventory.lock().await.ingest(alert("a"));
    let mut snapshot = svc.inventory.lock().await.snapshot();
    snapshot.clear();
    assert_eq!(svc.inventory.lock().await.snapshot().len(), 1);
}

macro_rules! node_id_tests {
    ($($name:ident => $node:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            assert_eq!(service($node).node_id, $node);
        }
    )+};
}

node_id_tests! {
    node_id_simple => "node1",
    node_id_dash => "node-a",
    node_id_upper => "NODE",
    node_id_numeric => "123",
    node_id_colon => "did:guardian:node",
    node_id_space => "node space",
    node_id_unicode_safe => "node-check",
    node_id_long => "node-abcdefghijklmnopqrstuvwxyz",
}

#[tokio::test]
async fn inventory_preserves_insert_order() {
    let svc = service("n");
    let mut inv = svc.inventory.lock().await;
    inv.ingest(alert("a"));
    inv.ingest(alert("b"));
    let ids: Vec<_> = inv.snapshot().into_iter().map(|a| a.alert_id).collect();
    assert_eq!(ids, vec!["a", "b"]);
}

#[tokio::test]
async fn service_can_hold_multiple_alerts() {
    let svc = service("n");
    for id in ["a", "b", "c"] {
        svc.inventory.lock().await.ingest(alert(id));
    }
    assert_eq!(svc.inventory.lock().await.snapshot().len(), 3);
}

#[tokio::test]
async fn service_inventory_mutex_allows_sequential_locks() {
    let svc = service("n");
    drop(svc.inventory.lock().await);
    drop(svc.inventory.lock().await);
}

#[test]
fn service_paths_are_isolated_per_tempdir() {
    let a = service("a");
    let b = service("b");
    assert_ne!(a.state_dir, b.state_dir);
}
