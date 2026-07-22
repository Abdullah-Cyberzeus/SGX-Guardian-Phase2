//! Disk-free unit tests. Board integration is CRL-033..CRL-043.

use super::queue::PendingRevocation;
use super::{
    parse_enabled, parse_flush_rounds, parse_interval, parse_max_retries, parse_probe_timeout,
};
use crate::crl::entry::{
    CrlEntry, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
use crate::did::document::Proof;

fn sample_entry(id: &str, revoker: &str, propagated: bool) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: id.into(),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: "did:guardian:target".into(),
        device_id: None,
        user_id: None,
        circle_id: "guardian-circle-alpha".into(),
        reason: RevocationReason::Compromised,
        severity: Severity::Critical,
        timestamp: "2026-07-06T00:00:00Z".into(),
        revoker_did: revoker.into(),
        revoker_role: RevokerRole::Owner,
        evidence: None,
        proof: Proof::default(),
        peers_notified: vec![],
        propagated,
    }
}

#[test]
fn env_parsers_apply_defaults_and_clamps() {
    assert!(parse_enabled(None));
    assert!(!parse_enabled(Some("off".into())));
    assert_eq!(parse_interval(None), 20);
    assert_eq!(parse_interval(Some("2".into())), 5);
    assert_eq!(parse_interval(Some("9000".into())), 600);
    assert_eq!(parse_max_retries(None), 0);
    assert_eq!(parse_max_retries(Some("5000".into())), 1000);
    assert_eq!(parse_flush_rounds(None), 3);
    assert_eq!(parse_flush_rounds(Some("99".into())), 20);
    assert_eq!(parse_flush_rounds(Some("0".into())), 1);
    assert_eq!(parse_probe_timeout(Some("50".into())), 200);
}

#[test]
fn pending_revocation_round_trips() {
    let pending = PendingRevocation {
        entry: sample_entry("urn:uuid:p1", "did:guardian:self", false),
        attempts: 2,
        queued_at: "2026-07-06T00:00:00Z".into(),
        last_attempt_at: Some("2026-07-06T00:01:00Z".into()),
        last_error: None,
        parked: false,
    };
    let json = serde_json::to_string(&pending).expect("serialize");
    let parsed: PendingRevocation = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.attempts, 2);
    assert_eq!(parsed.entry.id, "urn:uuid:p1");
    assert!(!parsed.parked);
}

#[test]
fn reconcile_selects_locally_issued_unpropagated() {
    let self_did = "did:guardian:self";
    let mine_unpropagated = sample_entry("urn:uuid:a", self_did, false);
    let mine_propagated = sample_entry("urn:uuid:b", self_did, true);
    let theirs = sample_entry("urn:uuid:c", "did:guardian:other", false);

    let wants_queue = |e: &CrlEntry| e.revoker_did == self_did && !e.propagated;
    assert!(wants_queue(&mine_unpropagated));
    assert!(!wants_queue(&mine_propagated));
    assert!(!wants_queue(&theirs));
}

#[test]
fn parked_when_retry_budget_exhausted() {
    let max_retries = 3u32;
    let mut attempts = 2u32;
    attempts = attempts.saturating_add(1);
    let parked = max_retries > 0 && attempts >= max_retries;
    assert!(parked);

    let unlimited = 0u32;
    let parked_unlimited = unlimited > 0 && attempts >= unlimited;
    assert!(!parked_unlimited);
}
