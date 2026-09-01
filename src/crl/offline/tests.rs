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

#[test]
fn parse_enabled_accepts_truthy_and_unknown_values() {
    assert!(parse_enabled(Some("1".into())));
    assert!(parse_enabled(Some("true".into())));
    assert!(parse_enabled(Some("on".into())));
    assert!(parse_enabled(Some("yes".into())));
    assert!(parse_enabled(Some("unexpected".into())));
}

#[test]
fn parse_enabled_rejects_falsey_values_case_and_space_insensitive() {
    assert!(!parse_enabled(Some(" 0 ".into())));
    assert!(!parse_enabled(Some(" FALSE ".into())));
    assert!(!parse_enabled(Some("Off".into())));
}

#[test]
fn parse_interval_accepts_midrange_and_defaults_bad_values() {
    assert_eq!(parse_interval(Some("5".into())), 5);
    assert_eq!(parse_interval(Some("300".into())), 300);
    assert_eq!(parse_interval(Some("bad".into())), 20);
}

#[test]
fn parse_max_retries_accepts_zero_midrange_and_defaults_bad_values() {
    assert_eq!(parse_max_retries(Some("0".into())), 0);
    assert_eq!(parse_max_retries(Some("7".into())), 7);
    assert_eq!(parse_max_retries(Some("bad".into())), 0);
}

#[test]
fn parse_flush_rounds_accepts_bounds_and_defaults_bad_values() {
    assert_eq!(parse_flush_rounds(Some("1".into())), 1);
    assert_eq!(parse_flush_rounds(Some("20".into())), 20);
    assert_eq!(parse_flush_rounds(Some("bad".into())), 3);
}

#[test]
fn parse_probe_timeout_accepts_bounds_and_defaults_bad_values() {
    assert_eq!(parse_probe_timeout(None), 1500);
    assert_eq!(parse_probe_timeout(Some("200".into())), 200);
    assert_eq!(parse_probe_timeout(Some("10000".into())), 10_000);
    assert_eq!(parse_probe_timeout(Some("bad".into())), 1500);
}

#[test]
fn pending_revocation_default_parked_field_deserializes_false() {
    let json = serde_json::json!({
        "entry": sample_entry("urn:uuid:p2", "did:guardian:self", false),
        "attempts": 0,
        "queued_at": "2026-07-06T00:00:00Z",
        "last_attempt_at": null,
        "last_error": null
    });
    let parsed: PendingRevocation = serde_json::from_value(json).unwrap();
    assert!(!parsed.parked);
}

#[test]
fn pending_revocation_preserves_last_error_and_attempt_time() {
    let pending = PendingRevocation {
        entry: sample_entry("urn:uuid:p3", "did:guardian:self", false),
        attempts: 9,
        queued_at: "2026-07-06T00:00:00Z".into(),
        last_attempt_at: Some("2026-07-06T00:02:00Z".into()),
        last_error: Some("offline".into()),
        parked: true,
    };
    let parsed: PendingRevocation =
        serde_json::from_str(&serde_json::to_string(&pending).unwrap()).unwrap();
    assert_eq!(parsed.last_error.as_deref(), Some("offline"));
    assert_eq!(parsed.last_attempt_at.as_deref(), Some("2026-07-06T00:02:00Z"));
    assert!(parsed.parked);
}
