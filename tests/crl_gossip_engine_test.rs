use sgx_guardian_client::crl::gossip::engine::{
    did_record_path, entries_merged_total, last_round, parse_nebula_endpoint, rounds_initiated,
    rounds_served, threshold_count, GossipPeer, LastRound, RoundReport,
};
use sgx_guardian_client::crl::entry::{
    CrlEntry, RevocationEvidence, RevocationReason, RevokerRole, Severity, UnrevokeTombstone,
    CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
use sgx_guardian_client::crl::gossip::emergency::{
    last_notice as emergency_last_notice, notices_merged, notices_received, notices_rebroadcast,
    notices_sent, sessions_terminated_total, LastNotice, RevocationNotice, KIND_NOTICE,
    MAX_DATAGRAM_BYTES,
};
use sgx_guardian_client::crl::gossip::notifications::{
    recent as recent_notifications, record as record_notification, EmergencyNotification,
    MAX_FEED_RETURN,
};
use sgx_guardian_client::crl::gossip::protocol::{
    read_json_line, write_json_line, SyncAck, SyncPush, SyncRequest, SyncResponse, KIND_ACK,
    KIND_PUSH, KIND_REQUEST, KIND_RESPONSE, MAX_ENTRIES_PER_MESSAGE, MAX_LINE_BYTES,
};
use sgx_guardian_client::did::document::Proof;
use std::io::Write as _;
use tempfile::tempdir;
use tokio::io::{AsyncWriteExt as _, BufReader};

#[test]
fn did_record_path_uses_env_override() {
    let prev = std::env::var_os("SGX_GUARDIAN_DID_PATH");
    std::env::set_var("SGX_GUARDIAN_DID_PATH", "/tmp/test-did.json");
    assert_eq!(did_record_path(), "/tmp/test-did.json");
    if let Some(value) = prev {
        std::env::set_var("SGX_GUARDIAN_DID_PATH", value);
    } else {
        std::env::remove_var("SGX_GUARDIAN_DID_PATH");
    }
}

#[test]
fn parse_nebula_endpoint_accepts_cidr() {
    assert_eq!(parse_nebula_endpoint("nebula://192.168.100.7/24"), Some("192.168.100.7".into()));
}

#[test]
fn parse_nebula_endpoint_accepts_no_cidr() {
    assert_eq!(parse_nebula_endpoint("nebula://192.168.100.8"), Some("192.168.100.8".into()));
}

#[test]
fn parse_nebula_endpoint_accepts_ipv6_like_text() {
    assert_eq!(parse_nebula_endpoint("nebula://fd00::1/64"), Some("fd00::1".into()));
}

#[test]
fn parse_nebula_endpoint_rejects_wrong_scheme() {
    assert_eq!(parse_nebula_endpoint("http://192.168.100.7/24"), None);
}

#[test]
fn parse_nebula_endpoint_rejects_empty_after_scheme() {
    assert_eq!(parse_nebula_endpoint("nebula://"), None);
}

#[test]
fn parse_nebula_endpoint_keeps_host_port_as_ip_text() {
    assert_eq!(parse_nebula_endpoint("nebula://192.168.100.7:4242/24"), Some("192.168.100.7:4242".into()));
}

macro_rules! threshold_tests {
    ($($name:ident => $members:expr, $pct:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            assert_eq!(threshold_count($members, $pct), $expected);
        }
    )+};
}

threshold_tests! {
    threshold_zero_members_floor_one => 0, 0, 1,
    threshold_one_member_zero_pct_floor_one => 1, 0, 1,
    threshold_one_member_full_pct => 1, 100, 1,
    threshold_two_members_eighty_pct => 2, 80, 2,
    threshold_three_members_fifty_pct_rounds_up => 3, 50, 2,
    threshold_ten_members_ten_pct => 10, 10, 1,
    threshold_ten_members_ninety_pct => 10, 90, 9,
    threshold_hundred_members_thirty_three_pct => 100, 33, 33,
}

#[test]
fn metrics_are_readable_without_rounds() {
    let _ = rounds_initiated();
    let _ = rounds_served();
    let _ = entries_merged_total();
}

#[test]
fn last_round_is_readable_without_panic() {
    let _ = last_round();
}

#[test]
fn last_round_serializes_all_fields() {
    let round = LastRound {
        direction: "outbound".into(),
        peer_did: "did:peer".into(),
        peer_node: "nodeB".into(),
        merged: 1,
        sent: 2,
        merkle_root: "abc".into(),
        at: "2026-01-01T00:00:00Z".into(),
    };
    let json = serde_json::to_string(&round).unwrap();
    assert!(json.contains("outbound"));
    assert!(json.contains("nodeB"));
}

#[test]
fn gossip_peer_clone_preserves_fields() {
    let peer = GossipPeer { did: "did:a".into(), node_name: "nodeA".into(), overlay_ip: "192.168.100.2".into() };
    let cloned = peer.clone();
    assert_eq!(cloned.did, "did:a");
    assert_eq!(cloned.overlay_ip, "192.168.100.2");
}

#[test]
fn gossip_peer_debug_mentions_node() {
    let peer = GossipPeer { did: "did:a".into(), node_name: "nodeA".into(), overlay_ip: "192.168.100.2".into() };
    assert!(format!("{peer:?}").contains("nodeA"));
}

#[test]
fn round_report_serializes_newly_propagated() {
    let report = RoundReport {
        peer_did: "did:peer".into(),
        peer_node: "nodeB".into(),
        merged: 1,
        replaced: 2,
        pushed: 3,
        peer_merged: 4,
        merkle_root: "root".into(),
        sequence: 9,
        newly_propagated: vec!["entry".into()],
    };
    assert!(serde_json::to_string(&report).unwrap().contains("entry"));
}

macro_rules! endpoint_rejection_tests {
    ($($name:ident => $endpoint:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            assert_eq!(parse_nebula_endpoint($endpoint), None);
        }
    )+};
}

endpoint_rejection_tests! {
    reject_empty => "",
    reject_plain_ip => "192.168.100.1/24",
    reject_uppercase_scheme => "NEBULA://192.168.100.1/24",
    reject_missing_host_with_slash => "nebula:///24",
    reject_leading_space => " nebula://192.168.100.1/24",
    reject_trailing_scheme_text => "xnebula://192.168.100.1/24"
}

fn proof() -> Proof {
    Proof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: "ecdsa-rdfc-2019".into(),
        verification_method: "did:guardian:issuer#dkp-v1".into(),
        created: "2026-01-01T00:00:00Z".into(),
        proof_purpose: "assertionMethod".into(),
        proof_value: "sig".into(),
    }
}

fn crl_entry(id: &str, revoked: &str, reason: RevocationReason, severity: Severity) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: id.into(),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: revoked.into(),
        device_id: Some("device-1".into()),
        user_id: None,
        circle_id: "circle-1".into(),
        reason,
        severity,
        timestamp: "2026-01-01T00:00:00Z".into(),
        revoker_did: "did:guardian:issuer".into(),
        revoker_role: RevokerRole::Owner,
        evidence: Some(RevocationEvidence {
            note: Some("note".into()),
            audit_ref: Some("audit".into()),
            attestation_ref: None,
            evidence_digest: Some("00".repeat(32)),
        }),
        proof: proof(),
        peers_notified: vec!["did:peer".into()],
        propagated: true,
    }
}

fn tombstone(id: &str, revoked: &str) -> UnrevokeTombstone {
    UnrevokeTombstone {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: id.into(),
        r#type: vec!["VerifiableCredential".into(), "UnrevokeTombstone".into()],
        revoked_did: revoked.into(),
        original_entry_id: "entry-1".into(),
        owner_did: "did:guardian:owner".into(),
        sequence: 7,
        timestamp: "2026-01-02T00:00:00Z".into(),
        proof: proof(),
        peers_notified: vec!["did:peer".into()],
        propagated: true,
    }
}

#[test]
fn protocol_constants_match_expected_caps_and_kinds() {
    assert_eq!(MAX_ENTRIES_PER_MESSAGE, 1000);
    assert_eq!(MAX_LINE_BYTES, 1_048_576);
    assert_eq!(KIND_REQUEST, "crl_sync_request");
    assert_eq!(KIND_RESPONSE, "crl_sync_response");
    assert_eq!(KIND_PUSH, "crl_sync_push");
    assert_eq!(KIND_ACK, "crl_sync_ack");
}

#[tokio::test]
async fn write_json_line_writes_newline_delimited_request() {
    let request = SyncRequest {
        kind: KIND_REQUEST.into(),
        circle_id: "circle".into(),
        sender_did: "did:sender".into(),
        sequence: 3,
        merkle_root: "root".into(),
        fingerprints: vec!["a".into(), "b".into()],
    };
    let mut out = Vec::new();
    write_json_line(&mut out, &request).await.unwrap();
    assert!(out.ends_with(b"\n"));
    assert!(String::from_utf8(out).unwrap().contains("crl_sync_request"));
}

#[tokio::test]
async fn write_json_line_rejects_oversized_message() {
    let request = SyncRequest {
        kind: KIND_REQUEST.into(),
        circle_id: "circle".into(),
        sender_did: "did:sender".into(),
        sequence: 1,
        merkle_root: "x".repeat(MAX_LINE_BYTES),
        fingerprints: vec![],
    };
    let mut out = Vec::new();
    assert!(write_json_line(&mut out, &request).await.is_err());
    assert!(out.is_empty());
}

#[tokio::test]
async fn read_json_line_reads_one_line() {
    let mut reader = BufReader::new("one\ntwo\n".as_bytes());
    assert_eq!(read_json_line(&mut reader).await.unwrap(), "one\n");
}

#[tokio::test]
async fn read_json_line_rejects_closed_peer() {
    let mut reader = BufReader::new("".as_bytes());
    assert!(read_json_line(&mut reader).await.is_err());
}

#[tokio::test]
async fn read_json_line_rejects_line_over_cap() {
    let input = format!("{}\n", "x".repeat(MAX_LINE_BYTES + 1));
    let mut reader = BufReader::new(input.as_bytes());
    assert!(read_json_line(&mut reader).await.is_err());
}

#[tokio::test]
async fn protocol_round_trip_request_through_memory_pipe() {
    let (mut client, server) = tokio::io::duplex(4096);
    let request = SyncRequest {
        kind: KIND_REQUEST.into(),
        circle_id: "circle".into(),
        sender_did: "did:sender".into(),
        sequence: 1,
        merkle_root: "root".into(),
        fingerprints: vec!["fp".into()],
    };
    write_json_line(&mut client, &request).await.unwrap();
    client.shutdown().await.unwrap();
    let mut reader = BufReader::new(server);
    let line = read_json_line(&mut reader).await.unwrap();
    let decoded: SyncRequest = serde_json::from_str(&line).unwrap();
    assert_eq!(decoded.fingerprints, vec!["fp"]);
}

#[test]
fn sync_response_serializes_entries_tombstones_want_and_error() {
    let response = SyncResponse {
        kind: KIND_RESPONSE.into(),
        circle_id: "circle".into(),
        sender_did: "did:sender".into(),
        sequence: 9,
        merkle_root: "root".into(),
        entries: vec![crl_entry("entry-1", "did:revoked", RevocationReason::Lost, Severity::High)],
        tombstones: vec![tombstone("tomb-1", "did:revoked")],
        want: vec!["missing".into()],
        error: Some("bad".into()),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("crl_sync_response"));
    assert!(json.contains("missing"));
    assert!(json.contains("bad"));
}

#[test]
fn sync_response_omits_empty_tombstones_and_error() {
    let response = SyncResponse {
        kind: KIND_RESPONSE.into(),
        circle_id: "circle".into(),
        sender_did: "did:sender".into(),
        sequence: 9,
        merkle_root: "root".into(),
        entries: vec![],
        tombstones: vec![],
        want: vec![],
        error: None,
    };
    let value = serde_json::to_value(response).unwrap();
    assert!(value.get("tombstones").is_none());
    assert!(value.get("error").is_none());
}

#[test]
fn sync_push_omits_empty_tombstones_but_keeps_entries() {
    let push = SyncPush {
        kind: KIND_PUSH.into(),
        entries: vec![crl_entry(
            "entry-1",
            "did:revoked",
            RevocationReason::Compromised,
            Severity::Critical,
        )],
        tombstones: vec![],
    };
    let value = serde_json::to_value(push).unwrap();
    assert_eq!(value["kind"], KIND_PUSH);
    assert!(value.get("tombstones").is_none());
    assert_eq!(value["entries"].as_array().unwrap().len(), 1);
}

#[test]
fn sync_ack_omits_error_when_none_and_keeps_error_when_present() {
    let ok = SyncAck {
        kind: KIND_ACK.into(),
        merged: 2,
        merkle_root: "root".into(),
        error: None,
    };
    assert!(serde_json::to_value(ok).unwrap().get("error").is_none());
    let bad = SyncAck {
        kind: KIND_ACK.into(),
        merged: 0,
        merkle_root: "root".into(),
        error: Some("verify failed".into()),
    };
    assert_eq!(serde_json::to_value(bad).unwrap()["error"], "verify failed");
}

#[test]
fn emergency_counters_and_last_notice_are_readable() {
    let _ = notices_sent();
    let _ = notices_received();
    let _ = notices_merged();
    let _ = notices_rebroadcast();
    let _ = sessions_terminated_total();
    let _ = emergency_last_notice();
}

#[test]
fn emergency_last_notice_serializes_observable_fields() {
    let last = LastNotice {
        direction: "sent".into(),
        revoked_did: "did:revoked".into(),
        origin_did: "did:origin".into(),
        peers: 2,
        merged: true,
        at: "2026-01-01T00:00:00Z".into(),
    };
    let json = serde_json::to_string(&last).unwrap();
    assert!(json.contains("did:revoked"));
    assert!(json.contains("\"merged\":true"));
}

#[test]
fn revocation_notice_serializes_kind_ttl_and_entry() {
    let notice = RevocationNotice {
        kind: KIND_NOTICE.into(),
        circle_id: "circle".into(),
        origin_did: "did:origin".into(),
        notice_id: "notice-1".into(),
        ttl: 2,
        sent_at: "2026-01-01T00:00:00Z".into(),
        entry: crl_entry("entry-1", "did:revoked", RevocationReason::PolicyViolation, Severity::Critical),
    };
    let bytes = serde_json::to_vec(&notice).unwrap();
    assert!(bytes.len() < MAX_DATAGRAM_BYTES);
    let decoded: RevocationNotice = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.kind, KIND_NOTICE);
    assert_eq!(decoded.ttl, 2);
}

#[test]
fn notification_record_persists_and_recent_returns_most_recent_first() {
    let dir = tempdir().unwrap();
    let previous = std::env::var_os("SGX_GUARDIAN_CRL_DIR");
    std::env::set_var("SGX_GUARDIAN_CRL_DIR", dir.path());
    let first = crl_entry("entry-1", "did:first", RevocationReason::Lost, Severity::Critical);
    let second = crl_entry("entry-2", "did:second", RevocationReason::Stolen, Severity::Critical);
    record_notification("node", &first, "did:origin", 1);
    record_notification("node", &second, "did:origin", 2);
    let notes = recent_notifications(10);
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0].revoked_did, "did:second");
    assert_eq!(notes[1].revoked_did, "did:first");
    assert_eq!(notes[0].sessions_terminated, 2);
    if let Some(value) = previous {
        std::env::set_var("SGX_GUARDIAN_CRL_DIR", value);
    } else {
        std::env::remove_var("SGX_GUARDIAN_CRL_DIR");
    }
}

#[test]
fn notification_recent_returns_empty_for_missing_feed() {
    let dir = tempdir().unwrap();
    let previous = std::env::var_os("SGX_GUARDIAN_CRL_DIR");
    std::env::set_var("SGX_GUARDIAN_CRL_DIR", dir.path());
    assert!(recent_notifications(5).is_empty());
    if let Some(value) = previous {
        std::env::set_var("SGX_GUARDIAN_CRL_DIR", value);
    } else {
        std::env::remove_var("SGX_GUARDIAN_CRL_DIR");
    }
}

#[test]
fn notification_recent_ignores_malformed_lines_and_caps_limit() {
    let dir = tempdir().unwrap();
    let previous = std::env::var_os("SGX_GUARDIAN_CRL_DIR");
    std::env::set_var("SGX_GUARDIAN_CRL_DIR", dir.path());
    let path = dir.path().join("emergency_notifications.jsonl");
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "not json").unwrap();
    for i in 0..(MAX_FEED_RETURN + 5) {
        let note = EmergencyNotification {
            notified_at: format!("2026-01-01T00:00:{:02}Z", i % 60),
            revoked_did: format!("did:{i}"),
            reason: "lost".into(),
            severity: "critical".into(),
            revoker_did: "did:revoker".into(),
            origin_did: "did:origin".into(),
            sessions_terminated: i,
            headline: "headline".into(),
        };
        writeln!(file, "{}", serde_json::to_string(&note).unwrap()).unwrap();
    }
    let notes = recent_notifications(MAX_FEED_RETURN + 99);
    assert_eq!(notes.len(), MAX_FEED_RETURN);
    assert_eq!(notes[0].revoked_did, format!("did:{}", MAX_FEED_RETURN + 4));
    if let Some(value) = previous {
        std::env::set_var("SGX_GUARDIAN_CRL_DIR", value);
    } else {
        std::env::remove_var("SGX_GUARDIAN_CRL_DIR");
    }
}

#[test]
fn emergency_notification_serializes_all_fields() {
    let note = EmergencyNotification {
        notified_at: "2026-01-01T00:00:00Z".into(),
        revoked_did: "did:revoked".into(),
        reason: "compromised".into(),
        severity: "critical".into(),
        revoker_did: "did:revoker".into(),
        origin_did: "did:origin".into(),
        sessions_terminated: 3,
        headline: "alert".into(),
    };
    let value = serde_json::to_value(note).unwrap();
    assert_eq!(value["sessions_terminated"], 3);
    assert_eq!(value["headline"], "alert");
}
