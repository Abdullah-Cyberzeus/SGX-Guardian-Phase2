//! Unit coverage for notification storage/bus, integration crypto/models,
//! and deterministic device risk scoring.

use chrono::Utc;
use sgx_guardian_client::devices::model::{default_monitoring_enabled, DeviceRecord};
use sgx_guardian_client::devices::scoring::privacy::privacy_score;
use sgx_guardian_client::devices::scoring::security::{bucket_to_risk_level, security_score};
use sgx_guardian_client::devices::scoring::{risk_band, score_device, RiskBand};
use sgx_guardian_client::discovery::{ConnectedDevice, DeviceStatus, OpenPort, ScriptResult};
use sgx_guardian_client::integration::crypto::{decrypt_tokens, encrypt_tokens};
use sgx_guardian_client::integration::provider::{
    IntegrationMetadata, IntegrationStatus, OAuthCredentials, VendorProvider,
};
use sgx_guardian_client::notify::bus;
use sgx_guardian_client::notify::model::{
    NotificationCategory, NotificationEvent, NotificationKind,
};
use sgx_guardian_client::notify::store::{next_event_id, prime_store, NotificationStore};
use tempfile::TempDir;

fn notification(id: &str, kind: NotificationKind, read: bool) -> NotificationEvent {
    NotificationEvent {
        id: id.into(),
        kind,
        title: "Test notification".into(),
        body: "Coverage event".into(),
        severity: "medium".into(),
        ref_id: Some("ref-1".into()),
        created_at: Utc::now().to_rfc3339(),
        read,
        actor_did: Some("did:guardian:actor".into()),
    }
}

fn port(number: u16, service: Option<&str>, scripts: Vec<ScriptResult>) -> OpenPort {
    OpenPort {
        port: number,
        protocol: "tcp".into(),
        service: service.map(str::to_string),
        product_version: None,
        cpe: vec![],
        scripts,
    }
}

fn device(status: DeviceStatus) -> ConnectedDevice {
    ConnectedDevice {
        device_id: "device-1".into(),
        ip: "192.0.2.10".into(),
        mac: Some("AA:BB:CC:DD:EE:FF".into()),
        vendor: Some("Example Vendor".into()),
        hostname: Some("example-device".into()),
        os_fingerprint: Some("Linux".into()),
        os_cpe: vec![],
        open_ports: vec![],
        host_scripts: vec![],
        status,
        first_seen: "2026-01-01T00:00:00Z".into(),
        last_seen: "2026-01-01T00:00:00Z".into(),
        vuln_triaged: false,
        last_scan_intensity: None,
    }
}

#[test]
fn notification_store_crud_truncation_replay_and_atomic_round_trip() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("nested/notifications.jsonl");
    let mut store = NotificationStore::default();

    assert!(store.history(10).is_empty());
    assert!(store.replay_after("0").is_empty());
    assert_eq!(store.unread_count(), 0);
    assert!(!store.mark_read("missing"));
    assert_eq!(store.mark_all_read(), 0);

    store.append(notification("10", NotificationKind::AlertHigh, false), 3);
    store.append(
        notification("", NotificationKind::DeviceDiscovered, false),
        3,
    );
    store.append(
        notification("non-numeric", NotificationKind::CircleNewMessage, true),
        3,
    );
    assert_eq!(store.history(20).len(), 3);
    assert_eq!(store.history(2).len(), 2);
    assert_eq!(store.unread_count(), 2);
    let generated_id = store.history(3)[1].id.clone();
    assert!(generated_id.parse::<u64>().is_ok());
    assert!(store.mark_read(&generated_id));
    assert!(!store.mark_read(&generated_id));
    assert_eq!(store.unread_count(), 1);
    assert_eq!(store.mark_all_read(), 1);
    assert_eq!(store.mark_all_read(), 0);

    let numeric_replay = store.replay_after("10");
    assert!(numeric_replay
        .iter()
        .all(|event| event.id.parse::<u64>().unwrap_or(0) > 10));
    assert_eq!(store.replay_after("bad cursor").len(), 3);

    store.save_atomic(&path).unwrap();
    let loaded = NotificationStore::load_from_path(&path, 2).unwrap();
    assert_eq!(loaded.history(10).len(), 2);
    assert_eq!(loaded.history(10)[0].id, "non-numeric");

    let mut one = NotificationStore::default();
    one.append(notification("1", NotificationKind::AlertLow, false), 0);
    one.append(notification("2", NotificationKind::AlertMedium, false), 0);
    assert_eq!(one.history(10).len(), 1, "zero cap retains one newest item");
    assert_eq!(one.history(1)[0].id, "2");
}

#[test]
fn notification_store_handles_missing_blank_malformed_and_prime_paths() {
    let temp = TempDir::new().unwrap();
    let missing = temp.path().join("missing.jsonl");
    assert!(NotificationStore::load_from_path(&missing, 10)
        .unwrap()
        .history(1)
        .is_empty());

    prime_store(&missing, 10).unwrap();
    assert!(missing.exists());
    prime_store(&missing, 10).unwrap();

    std::fs::write(&missing, "\n  \n").unwrap();
    assert!(NotificationStore::load_from_path(&missing, 10)
        .unwrap()
        .history(1)
        .is_empty());
    std::fs::write(&missing, "{not-json}\n").unwrap();
    assert!(NotificationStore::load_from_path(&missing, 10).is_err());

    let first = next_event_id().parse::<u64>().unwrap();
    let second = next_event_id().parse::<u64>().unwrap();
    assert!(second > first);
}

#[tokio::test]
async fn notification_bus_delivers_cloned_events_and_kind_categories_are_complete() {
    let mut receiver = bus::subscribe();
    let event = notification("bus-1", NotificationKind::CircleIncomingCall, false);
    bus::publish(event.clone());
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.id, event.id);
    assert_eq!(received.actor_did, event.actor_did);

    for kind in [
        NotificationKind::AlertHigh,
        NotificationKind::AlertMedium,
        NotificationKind::AlertLow,
    ] {
        assert_eq!(kind.category(), NotificationCategory::Alerts);
    }
    for kind in [
        NotificationKind::DeviceDiscovered,
        NotificationKind::DevicePendingApproval,
        NotificationKind::GuardianOffline,
        NotificationKind::CircleMemberPendingApproval,
    ] {
        assert_eq!(kind.category(), NotificationCategory::Devices);
    }
    for kind in [
        NotificationKind::CircleNewMessage,
        NotificationKind::CircleIncomingCall,
        NotificationKind::CircleMemberJoined,
        NotificationKind::CircleFileShared,
    ] {
        assert_eq!(kind.category(), NotificationCategory::Circles);
    }

    let json = serde_json::to_string(&event).unwrap();
    let decoded: NotificationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, event);
}

#[test]
fn integration_crypto_round_trips_randomizes_and_rejects_corruption() {
    for plaintext in [b"".as_slice(), b"a", b"oauth access and refresh tokens"] {
        let encrypted = encrypt_tokens(plaintext).unwrap();
        assert!(encrypted.len() >= plaintext.len() + 28);
        assert_eq!(decrypt_tokens(&encrypted).unwrap(), plaintext);
    }

    let first = encrypt_tokens(b"same plaintext").unwrap();
    let second = encrypt_tokens(b"same plaintext").unwrap();
    assert_ne!(first, second, "fresh nonces must randomize ciphertext");

    for short_len in 0..=12 {
        assert!(decrypt_tokens(&vec![0; short_len]).is_err());
    }
    let mut bad_nonce = first.clone();
    bad_nonce[0] ^= 0xff;
    assert!(decrypt_tokens(&bad_nonce).is_err());
    let mut bad_tag = first;
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 0xff;
    assert!(decrypt_tokens(&bad_tag).is_err());
}

#[test]
fn integration_provider_aliases_statuses_defaults_and_serde_round_trip() {
    assert_eq!(VendorProvider::default(), VendorProvider::GoogleNest);
    for alias in ["google_nest", "GOOGLE_NEST", "nest", "NeSt"] {
        assert_eq!(
            VendorProvider::from_str(alias),
            Some(VendorProvider::GoogleNest)
        );
    }
    for alias in ["tp_link_kasa", "KASA", "tplink"] {
        assert_eq!(
            VendorProvider::from_str(alias),
            Some(VendorProvider::TpLinkKasa)
        );
    }
    assert_eq!(VendorProvider::from_str("unknown"), None);
    assert_eq!(VendorProvider::GoogleNest.as_str(), "google_nest");
    assert_eq!(VendorProvider::GoogleNest.display_name(), "Google Nest");
    assert_eq!(VendorProvider::TpLinkKasa.as_str(), "tp_link_kasa");
    assert_eq!(
        VendorProvider::TpLinkKasa.display_name(),
        "TP-Link Kasa Smart Home"
    );

    let statuses = [
        (IntegrationStatus::Disconnected, "disconnected"),
        (IntegrationStatus::Connected, "connected"),
        (IntegrationStatus::Expired, "expired"),
        (IntegrationStatus::Error("invalid grant".into()), "error"),
    ];
    for (status, expected) in statuses {
        assert_eq!(status.as_str(), expected);
    }
    assert_eq!(
        IntegrationStatus::default(),
        IntegrationStatus::Disconnected
    );

    let metadata = IntegrationMetadata {
        provider: VendorProvider::GoogleNest,
        name: "Nest".into(),
        status: IntegrationStatus::Connected,
        device_count: 3,
        last_synced: Some(Utc::now()),
        error_message: None,
        credentials: Some(OAuthCredentials {
            access_token: "access".into(),
            refresh_token: Some("refresh".into()),
            expires_at: Some(Utc::now()),
            token_type: "Bearer".into(),
            scope: Some("devices.read".into()),
        }),
        kasa_credentials: None,
        nest_credentials: None,
    };
    let json = serde_json::to_string(&metadata).unwrap();
    assert!(json.contains("google_nest"));
    let decoded: IntegrationMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.provider, VendorProvider::GoogleNest);
    assert_eq!(decoded.status, IntegrationStatus::Connected);
    assert_eq!(
        decoded.credentials.unwrap().refresh_token.as_deref(),
        Some("refresh")
    );
}

#[test]
fn risk_band_covers_unknown_low_medium_high_and_critical() {
    let mut unknown = device(DeviceStatus::Approved);
    unknown.os_fingerprint = None;
    assert_eq!(risk_band(&unknown).level, "unknown");

    let low = device(DeviceStatus::Approved);
    assert_eq!(risk_band(&low).level, "low");

    let mut medium = device(DeviceStatus::Approved);
    medium.open_ports.push(port(1234, Some("custom"), vec![]));
    assert_eq!(risk_band(&medium).level, "medium");

    let mut high = device(DeviceStatus::Unauthorized);
    high.open_ports.push(port(22, Some("ssh"), vec![]));
    let high_band = risk_band(&high);
    assert_eq!(high_band.level, "high");
    assert_eq!(high_band.flagged_ports, vec![22]);
    assert!(high_band
        .reasons
        .iter()
        .any(|reason| reason.contains("unauthorized")));

    let mut critical = high;
    critical.open_ports[0].scripts.push(ScriptResult {
        id: "vulners".into(),
        output: "CVE-TEST 9.8".into(),
    });
    let critical_band = risk_band(&critical);
    assert_eq!(critical_band.level, "critical");
    assert!(critical_band
        .reasons
        .iter()
        .any(|reason| reason.contains("vulnerability")));

    let mut drifted = device(DeviceStatus::Drifted);
    drifted.host_scripts.push(ScriptResult {
        id: "vulners".into(),
        output: "host finding".into(),
    });
    assert_eq!(risk_band(&drifted).level, "critical");
}

#[test]
fn security_scoring_covers_status_port_cvss_cpe_and_bucket_boundaries() {
    let bands = [
        RiskBand {
            level: "low",
            reasons: vec![],
            flagged_ports: vec![],
        },
        RiskBand {
            level: "medium",
            reasons: vec![],
            flagged_ports: vec![],
        },
        RiskBand {
            level: "high",
            reasons: vec![],
            flagged_ports: vec![],
        },
        RiskBand {
            level: "critical",
            reasons: vec![],
            flagged_ports: vec![],
        },
    ];
    assert_eq!(bucket_to_risk_level(99, bands[3].level), 20);
    assert_eq!(bucket_to_risk_level(1, bands[2].level), 21);
    assert_eq!(bucket_to_risk_level(99, bands[2].level), 50);
    assert_eq!(bucket_to_risk_level(1, bands[1].level), 51);
    assert_eq!(bucket_to_risk_level(99, bands[1].level), 75);
    assert_eq!(bucket_to_risk_level(1, bands[0].level), 76);
    assert_eq!(bucket_to_risk_level(120, bands[0].level), 100);
    assert_eq!(bucket_to_risk_level(42, "unknown"), 42);

    for (status, expected_reason) in [
        (DeviceStatus::Unauthorized, "unauthorized device"),
        (DeviceStatus::Drifted, "drifted"),
        (DeviceStatus::Stale, "stale"),
        (DeviceStatus::Approved, "open port"),
    ] {
        let mut candidate = device(status);
        candidate
            .open_ports
            .push(port(1234, Some("custom"), vec![]));
        let score = security_score(
            &candidate,
            &RiskBand {
                level: "low",
                reasons: vec![],
                flagged_ports: vec![],
            },
        );
        assert!(score.score.is_some());
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains(expected_reason)));
    }

    for (cvss, deduction) in [(9.8, "-45"), (7.5, "-30"), (4.2, "-15"), (2.1, "-5")] {
        let mut candidate = device(DeviceStatus::Approved);
        candidate.os_cpe.push("cpe:/o:test".into());
        candidate.open_ports.push(port(
            22,
            Some("ssh"),
            vec![ScriptResult {
                id: "vulners".into(),
                output: format!("CVE-X {cvss} garbage 99.0 -1.0"),
            }],
        ));
        let score = security_score(
            &candidate,
            &RiskBand {
                level: "critical",
                reasons: vec![],
                flagged_ports: vec![22],
            },
        );
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains(deduction)));
        assert!(score.reasons.iter().any(|reason| reason.contains("OS CPE")));
    }
}

#[test]
fn privacy_and_combined_scoring_cover_all_observable_penalties() {
    let mut no_data = device(DeviceStatus::Approved);
    no_data.open_ports.clear();
    no_data.os_fingerprint = None;
    no_data.vendor = None;
    no_data.hostname = None;
    assert_eq!(privacy_score(&no_data).score, None);

    let mut candidate = device(DeviceStatus::Approved);
    candidate.vendor = None;
    candidate.hostname = Some("living-room camera nvr".into());
    candidate.open_ports = vec![
        port(21, Some("ftp"), vec![]),
        port(1900, Some("ssdp"), vec![]),
        port(8080, Some("mdns"), vec![]),
        port(1234, Some("custom"), vec![]),
    ];
    let privacy = privacy_score(&candidate);
    assert!(privacy.score.unwrap() < 50);
    for expected in [
        "cleartext",
        "broadcast",
        "remote administration",
        "chatty",
        "sensitive",
        "unknown vendor",
    ] {
        assert!(privacy
            .reasons
            .iter()
            .any(|reason| reason.contains(expected)));
    }

    let scores = score_device(&candidate);
    assert_eq!(scores.privacy_basis, "network-observable");
    assert_eq!(scores.risk_level, "medium");
    assert!(scores.security_score.is_some());
    assert!(chrono::DateTime::parse_from_rfc3339(&scores.computed_at).is_ok());
}

#[test]
fn manual_device_record_defaults_and_serialization_are_stable() {
    assert!(default_monitoring_enabled());
    let mut record = DeviceRecord::new_manual(
        "manual-1".into(),
        Some("Camera".into()),
        Some("192.0.2.20".into()),
        Some("00:11:22:33:44:55".into()),
        Some("Example".into()),
        Some("lab".into()),
    );
    assert!(record.manual);
    assert!(record.monitoring_enabled);
    assert!(!record.blocked);
    assert!(!record.rejected);
    assert_eq!(record.rejection_reason, None);
    assert_eq!(record.created_at, record.updated_at);
    record.touch();
    assert!(chrono::DateTime::parse_from_rfc3339(&record.updated_at).is_ok());

    let json = serde_json::to_string(&record).unwrap();
    let decoded: DeviceRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, record);

    let legacy: DeviceRecord = serde_json::from_value(serde_json::json!({
        "device_id":"legacy",
        "created_at":"2026-01-01T00:00:00Z",
        "updated_at":"2026-01-01T00:00:00Z"
    }))
    .unwrap();
    assert!(legacy.monitoring_enabled);
    assert!(!legacy.manual);
}
