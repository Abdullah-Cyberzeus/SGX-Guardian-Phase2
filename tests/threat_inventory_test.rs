use chrono::Utc;
use sgx_guardian_client::threat::{
    inventory::{AlertInventory, IngestOutcome, MAX_ALERTS},
    threat_alert::{Severity, ThreatAlert, ThreatCategory},
};
use tempfile::tempdir;

fn sample_alert(id_suffix: usize) -> ThreatAlert {
    ThreatAlert {
        alert_id: format!("alert-{id_suffix}"),
        timestamp: Utc::now(),
        src_ip: format!("192.0.2.{}", id_suffix % 250 + 1),
        src_port: 4000,
        dst_ip: "198.51.100.20".into(),
        dst_port: 80,
        protocol: "TCP".into(),
        signature_id: id_suffix as u32,
        signature: format!("sig-{id_suffix}"),
        category: ThreatCategory::Other,
        severity: Severity::Low,
        rev: 1,
        gid: 1,
        event_type: "alert".into(),
        blocked: false,
    }
}

#[test]
fn inventory_dedups_recent_alerts() {
    let mut inventory = AlertInventory::default();
    let alert = sample_alert(1);
    assert_eq!(inventory.ingest(alert.clone()), IngestOutcome::Inserted);
    assert_eq!(inventory.ingest(alert), IngestOutcome::Duplicate);
    assert_eq!(inventory.snapshot().len(), 1);
}

#[test]
fn inventory_evicts_when_ring_is_full() {
    let mut inventory = AlertInventory::default();
    for idx in 0..(MAX_ALERTS + 5) {
        assert_eq!(inventory.ingest(sample_alert(idx)), IngestOutcome::Inserted);
    }
    let snapshot = inventory.snapshot();
    assert_eq!(snapshot.len(), MAX_ALERTS);
    assert_eq!(snapshot.first().expect("first").alert_id, "alert-5");
}

#[test]
fn inventory_save_atomic_round_trip() {
    let mut inventory = AlertInventory::default();
    assert_eq!(inventory.ingest(sample_alert(10)), IngestOutcome::Inserted);
    assert_eq!(inventory.ingest(sample_alert(11)), IngestOutcome::Inserted);

    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("alerts.jsonl");
    inventory.save_atomic(&path).expect("save");

    let loaded = AlertInventory::load_from_path(&path).expect("load");
    let snapshot = loaded.snapshot();
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0].alert_id, "alert-10");
    assert_eq!(snapshot[1].alert_id, "alert-11");
}

#[test]
fn inventory_updates_recent_alert_when_block_state_changes() {
    let mut inventory = AlertInventory::default();
    let mut alert = sample_alert(7);
    assert_eq!(inventory.ingest(alert.clone()), IngestOutcome::Inserted);

    alert.blocked = true;
    alert.severity = Severity::Critical;
    alert.category = ThreatCategory::Malware;

    assert_eq!(inventory.ingest(alert), IngestOutcome::Updated);

    let snapshot = inventory.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].blocked);
    assert_eq!(snapshot[0].severity, Severity::Critical);
    assert_eq!(snapshot[0].category, ThreatCategory::Malware);
}
