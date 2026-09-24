use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use sgx_anomaly_engine::threat_prediction::{
    EventSeverity, EvidenceSource, SecurityEvent, SecurityEventType, SECURITY_EVENT_SCHEMA_VERSION,
};

use sgx_guardian_client::task4_threat_prediction::{
    config::Task4ThreatPredictionRuntimeConfig, runtime::spawn_production_runtime,
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn event(
    id: &str,
    ts: u64,
    event_type: SecurityEventType,
    source: EvidenceSource,
) -> SecurityEvent {
    SecurityEvent {
        schema_version: SECURITY_EVENT_SCHEMA_VERSION,
        event_id: id.to_string(),
        observed_at_ms: ts,
        source,
        node_id: "nodeA".to_string(),
        peer_id: None,

        // All explicit targets are deliberately identical so D5 target
        // correlation is tested, not bypassed.
        source_ip: Some("192.168.1.154".to_string()),
        destination_ip: Some("192.168.1.195".to_string()),

        source_port: None,
        destination_port: None,
        event_type,
        severity: EventSeverity::High,
        confidence: 0.90,
        attributes: BTreeMap::new(),
    }
}

#[tokio::test]
async fn d5_runtime_precursor_sequence_reaches_six_of_six() {
    // Production runtime supports this scheduler override.
    // It only shortens the wait for this integration validation.
    std::env::set_var("SGX_TASK4_PREDICTION_INTERVAL_SECS", "1");

    let root = PathBuf::from("/tmp/sgx-task4-d5-runtime");
    let state_dir = root.join("state");
    let threat_dir = root.join("threat");
    let config_path = root.join("config.json");

    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let mut config = Task4ThreatPredictionRuntimeConfig::for_tests(
        "nodeA",
        config_path,
        state_dir.clone(),
        threat_dir,
    );

    assert!(
        config.config_error.is_none(),
        "Task4 config error: {:?}",
        config.config_error
    );

    config.prediction.enabled = true;

    let handle = spawn_production_runtime(config).expect("spawn Task4 production runtime");

    // Allow the initial startup prediction cycle to complete.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Keep the complete ordered precursor chain in the past.
    // The matcher deliberately rejects evidence newer than evaluated_at_ms.
    let base = now_ms().saturating_sub(60_000);

    let events = [
        event(
            "d5-recon-001",
            base,
            SecurityEventType::Reconnaissance,
            EvidenceSource::Suricata,
        ),
        event(
            "d5-port-002",
            base + 1_000,
            SecurityEventType::PortDiscovery,
            EvidenceSource::NmapDiscovery,
        ),
        event(
            "d5-exposure-003",
            base + 2_000,
            SecurityEventType::ExposureDiscovery,
            EvidenceSource::Suricata,
        ),
        event(
            "d5-auth-004",
            base + 3_000,
            SecurityEventType::AuthenticationFailure,
            EvidenceSource::GuardianThreat,
        ),
        event(
            "d5-protocol-005",
            base + 4_000,
            SecurityEventType::ProtocolViolation,
            EvidenceSource::Suricata,
        ),
        event(
            "d5-anomaly-006",
            base + 5_000,
            SecurityEventType::TrafficAnomaly,
            EvidenceSource::Task1Anomaly,
        ),
    ];

    for event in events {
        handle
            .try_publish(event)
            .expect("publish D5 canonical SecurityEvent");
    }

    // In cfg(test), for_tests() debounce drives the production scheduler
    // at a short interval. Give collector + prediction cycle enough time.
    // Startup cycle occurs before the six events are collected.
    // Wait for the next real production scheduler cycle.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let status = handle.status().await;

    println!("===== D5 RUNTIME STATUS =====");
    println!("{}", serde_json::to_string_pretty(&status).unwrap());

    assert_eq!(
        status.events_ingested, 6,
        "all six canonical precursor events must enter production runtime"
    );
    assert_eq!(
        status.events_dropped, 0,
        "D5 validation must not drop canonical events"
    );
    assert!(
        status.last_successful_cycle_at_ms.is_some(),
        "prediction cycle must execute successfully"
    );

    let sequence_path = state_dir.join("precursor_sequence.json");
    let raw = fs::read_to_string(&sequence_path).expect("read production precursor_sequence.json");

    println!("===== D5 PRECURSOR SEQUENCE =====");
    println!("{raw}");

    let sequence: serde_json::Value = serde_json::from_str(&raw).expect("parse precursor sequence");

    assert_eq!(sequence["matched_steps"].as_u64(), Some(6));
    assert_eq!(sequence["total_steps"].as_u64(), Some(6));
    assert_eq!(sequence["fresh"].as_bool(), Some(true));

    let ids = sequence["matched_event_ids"]
        .as_array()
        .expect("matched_event_ids array");

    assert_eq!(ids.len(), 6);

    println!("D5_RUNTIME_VALIDATION=PASS");
}
