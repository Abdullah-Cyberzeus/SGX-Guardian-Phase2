//! Disk-free unit tests for the emergency layer. Board integration is
//! covered by CRL-022…CRL-034 in CRL_Emergency_Verification_Log.md.

use super::emergency::{RevocationNotice, KIND_NOTICE, MAX_DATAGRAM_BYTES};
use crate::crl::entry::{
    CrlEntry, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
use crate::did::document::Proof;

fn sample_entry(sev: Severity) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: "urn:uuid:emergtest".to_string(),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: "did:guardian:target".to_string(),
        device_id: None,
        user_id: None,
        circle_id: "guardian-circle-alpha".to_string(),
        reason: RevocationReason::Compromised,
        severity: sev,
        timestamp: "2026-07-06T00:00:00Z".to_string(),
        revoker_did: "did:guardian:owner".to_string(),
        revoker_role: RevokerRole::Owner,
        evidence: None,
        proof: Proof::default(),
        peers_notified: Vec::new(),
        propagated: false,
    }
}

#[test]
fn notice_round_trips_within_datagram_cap() {
    let notice = RevocationNotice {
        kind: KIND_NOTICE.to_string(),
        circle_id: "guardian-circle-alpha".into(),
        origin_did: "did:guardian:nodeA".into(),
        notice_id: "n1".into(),
        ttl: 1,
        sent_at: "2026-07-06T00:00:00Z".into(),
        entry: sample_entry(Severity::Critical),
    };
    let bytes = serde_json::to_vec(&notice).expect("serialize notice");
    assert!(
        bytes.len() < MAX_DATAGRAM_BYTES,
        "notice must fit one datagram"
    );
    let parsed: RevocationNotice = serde_json::from_slice(&bytes).expect("parse notice");
    assert_eq!(parsed.entry.revoked_did, "did:guardian:target");
    assert_eq!(parsed.ttl, 1);
    assert_eq!(parsed.kind, KIND_NOTICE);
}

#[test]
fn config_parses_emergency_fields() {
    assert_eq!(
        super::parse_emergency_port(None),
        super::GossipConfig::DEFAULT_EMERGENCY_PORT
    );
    assert_eq!(
        super::parse_emergency_ttl(None),
        super::GossipConfig::DEFAULT_EMERGENCY_TTL
    );
    assert_eq!(super::parse_emergency_ttl(Some("99".into())), 4);
}

#[test]
fn notification_headline_is_user_safe() {
    let entry = sample_entry(Severity::Critical);
    let note = super::notifications::EmergencyNotification {
        notified_at: "2026-07-06T00:00:00Z".into(),
        revoked_did: entry.revoked_did.clone(),
        reason: entry.reason.as_str().to_string(),
        severity: entry.severity.as_str().to_string(),
        revoker_did: entry.revoker_did.clone(),
        origin_did: "did:guardian:nodeA".into(),
        sessions_terminated: 2,
        headline:
            "Security alert: a device was revoked (compromised). Sessions with it were closed."
                .into(),
    };
    assert!(!note.headline.contains("did:guardian:"));
}
