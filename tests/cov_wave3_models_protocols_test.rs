//! Unit coverage for pure models, validation, caches, errors, and framed protocols.

use std::time::{Duration, SystemTime};

use sgx_guardian_client::crl::gossip::protocol as gossip_protocol;
use sgx_guardian_client::did::document::DidDocument;
use sgx_guardian_client::did::resolver::ResolutionSource;
use sgx_guardian_client::did::resolver_cache::{CacheEntry, ResolverCache};
use sgx_guardian_client::did::Did;
use sgx_guardian_client::geofence::actions::{self, GeofenceAction, ZoneAutomation};
use sgx_guardian_client::geofence::model::{
    default_rf_threshold, ApObservation, Fix, GeofenceEvent, GeofenceRegistry, GeofenceZone,
    RfSignature, SourceSelectionStatus, StoredLocation, ZoneKind,
};
use sgx_guardian_client::geofence::sources::{gnss::GnssSource, LocationSource};
use sgx_guardian_client::threat::errors::ThreatError;
use sgx_guardian_client::tpm::{self, quote, TpmConfig, TpmError};
use sgx_guardian_client::vault::namespace::{
    validate_folder_id, validate_folder_name, validate_vault_id, VaultNamespace,
};
use sgx_guardian_client::xfer::protocol as xfer_protocol;
use tokio::io::{AsyncWriteExt, BufReader};

fn document_for(did: &Did) -> DidDocument {
    DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".into()],
        id: did.to_string(),
        controller: did.to_string(),
        verification_method: vec![],
        authentication: vec![],
        assertion_method: vec![],
        service: vec![],
        sgx_node_name: Some("cache-test".into()),
        sgx_created: "2026-01-01T00:00:00Z".into(),
        sgx_updated: "2026-01-01T00:00:00Z".into(),
        sgx_version_id: 1,
        sgx_method_spec_version: "1.0".into(),
        sgx_status: Some("active".into()),
        sgx_revoked_vm: vec![],
        proof: None,
    }
}

fn coordinate_zone() -> GeofenceZone {
    GeofenceZone {
        zone_id: "zone-home".into(),
        name: "Home".into(),
        topology_node_ref: Some("node-a".into()),
        kind: ZoneKind::Coordinate,
        center_lat: Some(40.0),
        center_lng: Some(-74.0),
        radius_m: Some(100.0),
        rf_signature: None,
        on_entry: true,
        on_exit: true,
        severity: "high".into(),
        automation: ZoneAutomation::default(),
        enabled: true,
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
    }
}

#[test]
fn vault_namespace_and_identifier_validation_cover_all_rejections() {
    for raw in ["", "  ", "personal", "PERSONAL"] {
        let namespace = VaultNamespace::parse(raw).unwrap();
        assert!(namespace.is_personal());
        assert_eq!(namespace.storage_key(), "personal");
        assert_eq!(namespace.dir_name(), "personal");
    }

    let circle = VaultNamespace::parse(" circle-alpha ").unwrap();
    assert_eq!(circle, VaultNamespace::Circle("circle-alpha".into()));
    assert_eq!(circle.storage_key(), "circle-alpha");
    assert!(!circle.is_personal());
    let encoded = serde_json::to_string(&circle).unwrap();
    assert_eq!(encoded, r#"{"circle":"circle-alpha"}"#);
    assert_eq!(
        serde_json::from_str::<VaultNamespace>(&encoded).unwrap(),
        circle
    );

    for invalid in [".", "..", "a/b", r"a\b", "bad\0id", "line\nbreak"] {
        assert!(
            VaultNamespace::parse(invalid).is_err(),
            "accepted {invalid:?}"
        );
        assert!(validate_folder_name(invalid).is_err());
        assert!(validate_vault_id(invalid).is_err());
        if !invalid.trim().is_empty() {
            assert!(validate_folder_id(invalid).is_err());
        }
    }
    assert!(validate_folder_name("  ").is_err());
    assert!(validate_vault_id("  ").is_err());
    assert_eq!(validate_folder_id("  ").unwrap(), "");
    assert_eq!(validate_folder_name(" Photos ").unwrap(), "Photos");
    assert_eq!(validate_folder_id(" folder-a ").unwrap(), "folder-a");
    assert_eq!(validate_vault_id(" vault-a ").unwrap(), "vault-a");
}

#[test]
fn threat_errors_format_each_variant_and_implement_error() {
    let cases = [
        (
            ThreatError::RuleEvaluationFailed("bad rule".into()),
            "Rule evaluation failed: bad rule",
        ),
        (
            ThreatError::AnomalyDetectionFailed("bad model".into()),
            "Anomaly detection failed: bad model",
        ),
        (
            ThreatError::PeerNotFound("peer-1".into()),
            "Peer not found: peer-1",
        ),
        (
            ThreatError::IncidentNotFound("incident-1".into()),
            "Incident not found: incident-1",
        ),
        (
            ThreatError::InvalidParameters("threshold".into()),
            "Invalid parameters: threshold",
        ),
        (
            ThreatError::SyncError("poisoned".into()),
            "Synchronization error: poisoned",
        ),
        (
            ThreatError::Other("unknown".into()),
            "Threat error: unknown",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        let as_error: &dyn std::error::Error = &error;
        assert!(as_error.source().is_none());
        assert!(format!("{error:?}").contains(expected.rsplit_once(": ").unwrap().1));
    }
}

#[test]
fn geofence_models_summarize_serialize_validate_and_canonicalize() {
    assert_eq!(default_rf_threshold(), 0.6);
    let precise = Fix::coordinate(40.123456, -74.987654, Some(12.4));
    let imprecise = Fix::coordinate(1.0, 2.0, None);
    let rf = Fix::RfSignature {
        aps: vec![
            ApObservation {
                bssid: "aa:bb:cc:dd:ee:ff".into(),
                signal_dbm: Some(-42),
            },
            ApObservation {
                bssid: "11:22:33:44:55:66".into(),
                signal_dbm: None,
            },
        ],
    };
    assert_eq!(precise.summary(), "coord 40.12346,-74.98765 (+/-12m)");
    assert_eq!(imprecise.summary(), "coord 1.00000,2.00000");
    assert_eq!(rf.summary(), "rf 2 APs observed");

    let stored = StoredLocation::new("manual", precise.clone());
    assert_eq!(stored.source, "manual");
    assert!(chrono::DateTime::parse_from_rfc3339(&stored.updated_at).is_ok());
    let status = SourceSelectionStatus::new("automatic", Some("gnss".into()), "best accuracy");
    assert_eq!(status.active_source.as_deref(), Some("gnss"));

    let defaults = ZoneAutomation::default();
    assert!(actions::validate(&defaults).is_ok());
    assert_eq!(defaults.min_confidence, 0.9);
    assert_eq!(
        defaults.on_exit,
        vec![GeofenceAction::RaiseAlert {
            severity: Some("high".into())
        }]
    );
    for invalid in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
        let automation = ZoneAutomation {
            min_confidence: invalid,
            ..ZoneAutomation::default()
        };
        assert!(actions::validate(&automation).is_err());
    }

    let zone = coordinate_zone();
    let event = GeofenceEvent::new(&zone, "entry", &precise);
    assert_eq!(event.zone_id, zone.zone_id);
    assert_eq!(event.zone_name, zone.name);
    assert_eq!(event.transition, "entry");
    assert_eq!(event.severity, "high");

    let mut registry = GeofenceRegistry::default();
    registry.zones.push(zone);
    registry.proof.proof_value = "excluded-from-signing".into();
    let first = registry.canonical_bytes_for_proof().unwrap();
    registry.proof.proof_value = "different-proof".into();
    let second = registry.canonical_bytes_for_proof().unwrap();
    assert_eq!(first, second);
    assert!(!String::from_utf8(first)
        .unwrap()
        .contains("different-proof"));

    let signature = RfSignature {
        aps: vec![],
        threshold: default_rf_threshold(),
    };
    assert_eq!(signature.threshold, 0.6);
}

#[tokio::test]
async fn gnss_source_has_stable_identity_and_no_stub_fix() {
    let source = GnssSource;
    assert_eq!(source.id(), "gnss");
    assert_eq!(source.current().await, None);
}

#[test]
fn resolver_cache_handles_hits_expiry_future_timestamps_invalidation_and_clear() {
    let did_a = Did::from_id_bytes(&[1; 32]);
    let did_b = Did::from_id_bytes(&[2; 32]);
    let mut cache = ResolverCache::default();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
    assert!(cache.get_fresh(&did_a, Duration::from_secs(60)).is_none());

    cache.put(
        did_a.clone(),
        CacheEntry {
            doc: document_for(&did_a),
            fetched_at: SystemTime::now(),
            source: ResolutionSource::CaNetwork,
        },
    );
    let hit = cache
        .get_fresh(&did_a, Duration::from_secs(60))
        .expect("fresh cache entry");
    assert_eq!(hit.doc.id, did_a.to_string());
    assert_eq!(hit.source.as_str(), "ca_network");
    assert_eq!(cache.len(), 1);

    cache.put(
        did_b.clone(),
        CacheEntry {
            doc: document_for(&did_b),
            fetched_at: SystemTime::UNIX_EPOCH,
            source: ResolutionSource::LocalPeerDoc,
        },
    );
    assert!(cache.get_fresh(&did_b, Duration::from_secs(60)).is_none());

    cache.put(
        did_b.clone(),
        CacheEntry {
            doc: document_for(&did_b),
            fetched_at: SystemTime::now() + Duration::from_secs(60),
            source: ResolutionSource::LocalAggregate,
        },
    );
    assert!(cache.get_fresh(&did_b, Duration::from_secs(60)).is_none());
    cache.invalidate(&did_b);
    assert_eq!(cache.len(), 1);
    cache.invalidate(&did_b);
    cache.clear();
    assert!(cache.is_empty());

    assert_eq!(ResolutionSource::MemCache.as_str(), "mem_cache");
    assert_eq!(ResolutionSource::LocalPeerDoc.as_str(), "local_peer_doc");
    assert_eq!(ResolutionSource::LocalAggregate.as_str(), "local_aggregate");
}

#[test]
fn tpm_public_helpers_cover_stub_attempt_logic_and_error_messages() {
    let mut cfg = TpmConfig {
        device: "/definitely/not/a/tpm-device".into(),
        tcti: "device:/definitely/not/a/tpm-device".into(),
        explicit_backend: false,
        dik_handle: 0x8100_0100,
        dkp_handle_base: 0x8100_0010,
        ek_handle: 0x8101_0001,
        pcr_selection: "sha256:0,2,4,7".into(),
        owner_auth: None,
        key_auth: None,
    };
    assert!(!tpm::should_attempt(&cfg));
    cfg.explicit_backend = true;
    assert!(tpm::should_attempt(&cfg));
    assert!(quote::generate_quote_stub(&cfg, "nonce").is_ok());

    let messages = [
        TpmError::Tool("tpm2_sign".into(), "failed".into()).to_string(),
        TpmError::NotAvailable("missing".into()).to_string(),
        TpmError::Key("bad key".into()).to_string(),
        TpmError::Parse("bad bytes".into()).to_string(),
        TpmError::from(std::io::Error::other("disk")).to_string(),
    ];
    assert_eq!(messages[0], "tpm2 tool `tpm2_sign` failed: failed");
    assert_eq!(messages[1], "tpm not available: missing");
    assert_eq!(messages[2], "tpm key error: bad key");
    assert_eq!(messages[3], "invalid TPM output: bad bytes");
    assert_eq!(messages[4], "io: disk");
}

#[tokio::test]
async fn xfer_protocol_handles_success_close_timeout_and_size_limits_in_memory() {
    let (mut client, server) = tokio::io::duplex(2 * 1024 * 1024);
    let message = serde_json::json!({"kind":"test","value":7});
    xfer_protocol::write_json_line(&mut client, &message)
        .await
        .unwrap();
    let mut reader = BufReader::new(server);
    let line = xfer_protocol::read_json_line_with_timeout(&mut reader, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap(),
        message
    );

    let (closed_writer, closed_reader) = tokio::io::duplex(16);
    drop(closed_writer);
    let error = xfer_protocol::read_json_line_with_timeout(
        &mut BufReader::new(closed_reader),
        Duration::from_millis(50),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("closed connection"));

    let (_idle_writer, idle_reader) = tokio::io::duplex(16);
    let error = xfer_protocol::read_json_line_with_timeout(
        &mut BufReader::new(idle_reader),
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("read timeout"));

    let (mut oversized_writer, oversized_reader) = tokio::io::duplex(2 * 1024 * 1024);
    let oversized_line = vec![b'x'; xfer_protocol::MAX_LINE_BYTES + 1];
    let writer_task = tokio::spawn(async move {
        oversized_writer.write_all(&oversized_line).await.unwrap();
        oversized_writer.write_all(b"\n").await.unwrap();
    });
    let error = xfer_protocol::read_json_line_with_timeout(
        &mut BufReader::new(oversized_reader),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("exceeds MAX_LINE_BYTES"));
    writer_task.await.unwrap();

    let (mut sink, _reader) = tokio::io::duplex(2 * 1024 * 1024);
    let oversized_json = "x".repeat(xfer_protocol::MAX_LINE_BYTES + 1);
    let error = xfer_protocol::write_json_line(&mut sink, &oversized_json)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds MAX_LINE_BYTES"));
}

#[tokio::test]
async fn gossip_protocol_handles_success_close_and_size_limits_in_memory() {
    let (mut client, server) = tokio::io::duplex(2 * 1024 * 1024);
    let message = serde_json::json!({"kind":gossip_protocol::KIND_ACK,"merged":2});
    gossip_protocol::write_json_line(&mut client, &message)
        .await
        .unwrap();
    let line = gossip_protocol::read_json_line(&mut BufReader::new(server))
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap(),
        message
    );

    let (closed_writer, closed_reader) = tokio::io::duplex(16);
    drop(closed_writer);
    let error = gossip_protocol::read_json_line(&mut BufReader::new(closed_reader))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("closed connection"));

    let (mut oversized_writer, oversized_reader) = tokio::io::duplex(2 * 1024 * 1024);
    let oversized_line = vec![b'x'; gossip_protocol::MAX_LINE_BYTES + 1];
    let writer_task = tokio::spawn(async move {
        oversized_writer.write_all(&oversized_line).await.unwrap();
        oversized_writer.write_all(b"\n").await.unwrap();
    });
    let error = gossip_protocol::read_json_line(&mut BufReader::new(oversized_reader))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds MAX_LINE_BYTES"));
    writer_task.await.unwrap();

    let (mut sink, _reader) = tokio::io::duplex(2 * 1024 * 1024);
    let oversized_json = "x".repeat(gossip_protocol::MAX_LINE_BYTES + 1);
    let error = gossip_protocol::write_json_line(&mut sink, &oversized_json)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds MAX_LINE_BYTES"));
}
