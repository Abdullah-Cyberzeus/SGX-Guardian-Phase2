//! Disk-free unit tests for the gossip layer. Board integration is covered
//! by CRL-011..CRL-021 in CRL_Gossip_Verification_Log.md.

use super::engine::{parse_nebula_endpoint, threshold_count};
use super::store::{incoming_record_wins, incoming_wins, normalized, normalized_tombstone};
use super::{parse_enabled, parse_interval, parse_port, parse_threshold};
use crate::crl::entry::{
    CrlEntry, RevocationReason, RevokerRole, Severity, UnrevokeTombstone, CRL_CONTEXT_CORE,
    CRL_CONTEXT_SGX, CRL_UNREVOKE_TOMBSTONE_TYPE,
};
use crate::did::document::Proof;

fn sample_entry(revoked: &str, timestamp: &str, entry_id: &str) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: entry_id.to_string(),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: revoked.to_string(),
        device_id: None,
        user_id: None,
        circle_id: "guardian-circle-alpha".to_string(),
        reason: RevocationReason::Compromised,
        severity: Severity::Critical,
        timestamp: timestamp.to_string(),
        revoker_did: "did:guardian:issuer".to_string(),
        revoker_role: RevokerRole::Owner,
        evidence: None,
        proof: Proof::default(),
        peers_notified: vec!["did:guardian:peerX".to_string()],
        propagated: true,
    }
}

fn sample_tombstone(revoked: &str, timestamp: &str, tombstone_id: &str) -> UnrevokeTombstone {
    UnrevokeTombstone {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: tombstone_id.to_string(),
        r#type: vec![
            "VerifiableCredential".into(),
            CRL_UNREVOKE_TOMBSTONE_TYPE.into(),
        ],
        revoked_did: revoked.to_string(),
        original_entry_id: "urn:uuid:original".to_string(),
        owner_did: "did:guardian:owner".to_string(),
        sequence: 4,
        timestamp: timestamp.to_string(),
        proof: Proof::default(),
        peers_notified: vec!["did:guardian:peerX".to_string()],
        propagated: true,
    }
}

#[test]
fn threshold_math_matches_spec() {
    assert_eq!(threshold_count(2, 80), 2);
    assert_eq!(threshold_count(4, 80), 4);
    assert_eq!(threshold_count(1, 80), 1);
    assert_eq!(threshold_count(0, 80), 1);
    assert_eq!(threshold_count(10, 100), 10);
    assert_eq!(threshold_count(10, 1), 1);
}

#[test]
fn nebula_endpoint_parsing() {
    assert_eq!(
        parse_nebula_endpoint("nebula://192.168.100.7/24"),
        Some("192.168.100.7".to_string())
    );
    assert_eq!(
        parse_nebula_endpoint("nebula://192.168.100.7"),
        Some("192.168.100.7".to_string())
    );
    assert_eq!(parse_nebula_endpoint("tcp://192.168.100.7:50061"), None);
    assert_eq!(parse_nebula_endpoint("nebula://"), None);
}

#[test]
fn conflict_rule_is_deterministic_and_symmetric() {
    let older = sample_entry("did:guardian:target", "2026-07-01T00:00:00Z", "urn:uuid:a");
    let newer = sample_entry("did:guardian:target", "2026-07-02T00:00:00Z", "urn:uuid:b");
    // Later timestamp wins: an older incoming entry must not displace a newer existing one.
    assert!(!incoming_wins(&newer, &older));
    // ...but a newer incoming entry must displace an older existing one.
    assert!(incoming_wins(&older, &newer));
    let twin_a = sample_entry("did:guardian:t2", "2026-07-01T00:00:00Z", "urn:uuid:c");
    let twin_b = sample_entry("did:guardian:t2", "2026-07-01T00:00:00Z", "urn:uuid:d");
    assert_ne!(
        incoming_wins(&twin_a, &twin_b),
        incoming_wins(&twin_b, &twin_a)
    );
}

#[test]
fn normalized_resets_remote_gossip_bookkeeping() {
    let entry = sample_entry("did:guardian:target", "2026-07-01T00:00:00Z", "urn:uuid:e");
    let cleaned = normalized(&entry);
    assert!(cleaned.peers_notified.is_empty());
    assert!(!cleaned.propagated);
    assert_eq!(cleaned.fingerprint(), entry.fingerprint());

    let tombstone = sample_tombstone("did:guardian:target", "2026-07-02T00:00:00Z", "urn:uuid:t");
    let cleaned_tombstone = normalized_tombstone(&tombstone);
    assert!(cleaned_tombstone.peers_notified.is_empty());
    assert!(!cleaned_tombstone.propagated);
    assert_eq!(cleaned_tombstone.fingerprint(), tombstone.fingerprint());
}

#[test]
fn newer_tombstone_beats_older_revoke() {
    let revoke = sample_entry("did:guardian:target", "2026-07-01T00:00:00Z", "urn:uuid:r");
    let tombstone = sample_tombstone("did:guardian:target", "2026-07-02T00:00:00Z", "urn:uuid:t");
    assert!(incoming_record_wins(
        &revoke.timestamp,
        &revoke.fingerprint(),
        &tombstone.timestamp,
        &tombstone.fingerprint(),
    ));
    assert!(!incoming_record_wins(
        &tombstone.timestamp,
        &tombstone.fingerprint(),
        &revoke.timestamp,
        &revoke.fingerprint(),
    ));
}

#[test]
fn env_parsers_apply_defaults_and_clamps() {
    assert!(parse_enabled(None));
    assert!(!parse_enabled(Some("0".into())));
    assert!(!parse_enabled(Some("false".into())));
    assert!(parse_enabled(Some("1".into())));
    assert_eq!(parse_port(None), 50063);
    assert_eq!(parse_port(Some("50099".into())), 50099);
    assert_eq!(parse_port(Some("junk".into())), 50063);
    assert_eq!(parse_interval(None), 60);
    assert_eq!(parse_interval(Some("3".into())), 10);
    assert_eq!(parse_interval(Some("900".into())), 300);
    assert_eq!(parse_threshold(None), 80);
    assert_eq!(parse_threshold(Some("0".into())), 1);
}

#[test]
fn protocol_messages_round_trip() {
    let request = super::protocol::SyncRequest {
        kind: super::protocol::KIND_REQUEST.to_string(),
        circle_id: "guardian-circle-alpha".into(),
        sender_did: "did:guardian:nodeA".into(),
        sequence: 7,
        merkle_root: "abc123".into(),
        fingerprints: vec!["fp1".into(), "fp2".into()],
    };
    let json = serde_json::to_string(&request).expect("serialize request");
    let parsed: super::protocol::SyncRequest = serde_json::from_str(&json).expect("parse request");
    assert_eq!(parsed.fingerprints.len(), 2);
    assert_eq!(parsed.merkle_root, "abc123");

    let ack = super::protocol::SyncAck {
        kind: super::protocol::KIND_ACK.to_string(),
        merged: 3,
        merkle_root: "def456".into(),
        error: None,
    };
    let json = serde_json::to_string(&ack).expect("serialize ack");
    assert!(!json.contains("error"));
    let parsed: super::protocol::SyncAck = serde_json::from_str(&json).expect("parse ack");
    assert_eq!(parsed.merged, 3);

    let push = super::protocol::SyncPush {
        kind: super::protocol::KIND_PUSH.to_string(),
        entries: vec![sample_entry(
            "did:guardian:target",
            "2026-07-01T00:00:00Z",
            "urn:uuid:push-revoke",
        )],
        tombstones: vec![sample_tombstone(
            "did:guardian:target",
            "2026-07-02T00:00:00Z",
            "urn:uuid:push-tombstone",
        )],
    };
    let json = serde_json::to_string(&push).expect("serialize push");
    let parsed: super::protocol::SyncPush = serde_json::from_str(&json).expect("parse push");
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.tombstones.len(), 1);
}
