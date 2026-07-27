use sgx_guardian_client::discovery::{ConnectedDevice, DeviceStatus, OpenPort};
use sgx_guardian_client::rules::model::RuleTrigger;
use sgx_guardian_client::rules::persistence::RulesPaths;
use sgx_guardian_client::rules::{
    Condition, Rule, RuleAction, RuleDraft, RuleEvent, RulePatch, RuleRegistry,
};
use std::path::PathBuf;

fn device(id: &str, status: DeviceStatus, ports: &[u16]) -> ConnectedDevice {
    ConnectedDevice {
        device_id: id.to_string(),
        ip: "192.168.1.77".to_string(),
        mac: None,
        vendor: None,
        hostname: None,
        os_fingerprint: None,
        os_cpe: Vec::new(),
        open_ports: ports
            .iter()
            .map(|p| OpenPort {
                port: *p,
                protocol: "tcp".to_string(),
                service: None,
                product_version: None,
                cpe: Vec::new(),
                scripts: Vec::new(),
            })
            .collect(),
        host_scripts: Vec::new(),
        status,
        first_seen: "2026-01-01T00:00:00Z".to_string(),
        last_seen: "2026-01-01T00:00:00Z".to_string(),
        vuln_triaged: false,
        last_scan_intensity: None,
    }
}

#[test]
fn device_discovered_carries_id_ip_status_and_ports() {
    let dev = device("dev-9", DeviceStatus::Approved, &[22, 443]);
    let event = RuleEvent::from_device_discovered("nodeA", &dev);

    assert_eq!(event.trigger(), RuleTrigger::DeviceDiscovered);
    assert_eq!(event.target_key(), "dev-9");
    assert_eq!(event.src_ip(), Some("192.168.1.77"));
    assert_eq!(event.ports(), vec![22, 443]);
    assert_eq!(event.device_status(), Some("approved"));
}

#[test]
fn device_unauthorized_uses_ip_as_target_when_device_id_blank() {
    let dev = device("", DeviceStatus::Unauthorized, &[]);
    let event = RuleEvent::from_device_unauthorized("nodeA", &dev);

    assert_eq!(event.trigger(), RuleTrigger::DeviceUnauthorized);
    assert_eq!(event.target_key(), "192.168.1.77");
    assert_eq!(event.device_status(), Some("unauthorized"));
}

#[test]
fn attestation_failed_targets_did_when_present_else_falls_back_to_peer() {
    let with_did = RuleEvent::AttestationFailed {
        node_id: "nodeA".to_string(),
        peer: "192.168.100.2".to_string(),
        did: Some("did:guardian:abc".to_string()),
        reason: "pcr_or_signature_failure".to_string(),
        severity: "critical".to_string(),
    };
    assert_eq!(with_did.target_key(), "did:guardian:abc");
    assert_eq!(with_did.target_did(), Some("did:guardian:abc"));
    assert_eq!(with_did.severity_name(), Some("critical"));

    let without_did = RuleEvent::AttestationFailed {
        node_id: "nodeA".to_string(),
        peer: "192.168.100.2".to_string(),
        did: None,
        reason: "pcr_or_signature_failure".to_string(),
        severity: "critical".to_string(),
    };
    assert_eq!(without_did.target_key(), "192.168.100.2");
    assert_eq!(without_did.target_did(), None);
}

#[test]
fn crl_revocation_targets_revoked_did_and_reports_reason_as_category() {
    let event = RuleEvent::CrlRevocation {
        node_id: "nodeA".to_string(),
        revoked_did: "did:guardian:revoked".to_string(),
        reason: "key_compromise".to_string(),
        severity: "high".to_string(),
    };

    assert_eq!(event.trigger(), RuleTrigger::CrlRevocation);
    assert_eq!(event.target_key(), "did:guardian:revoked");
    assert_eq!(event.target_did(), Some("did:guardian:revoked"));
    assert_eq!(event.category_name(), Some("key_compromise"));
    assert_eq!(event.severity_name(), Some("high"));
    assert!(event.summary().contains("did:guardian:revoked"));
}

#[test]
fn rule_action_label_formats_every_variant() {
    assert_eq!(
        RuleAction::RaiseAlert {
            severity: "high".to_string()
        }
        .label(),
        "RaiseAlert(high)"
    );
    assert_eq!(
        RuleAction::Notify {
            severity: "info".to_string()
        }
        .label(),
        "Notify(info)"
    );
    assert_eq!(
        RuleAction::BlockIp { ttl_secs: Some(60) }.label(),
        "BlockIp(ttl=60s)"
    );
    assert_eq!(RuleAction::BlockIp { ttl_secs: None }.label(), "BlockIp");
    assert_eq!(
        RuleAction::RunScan {
            intensity: "stealth".to_string()
        }
        .label(),
        "RunScan(stealth)"
    );
    assert_eq!(RuleAction::RevokeDid.label(), "RevokeDid");
    assert_eq!(RuleAction::LockTransport.label(), "LockTransport");
    assert_eq!(
        RuleAction::EmergencyKeyRotation.label(),
        "EmergencyKeyRotation"
    );
}

#[test]
fn rule_action_destructive_flags_only_high_risk_actions() {
    assert!(RuleAction::RevokeDid.destructive());
    assert!(RuleAction::LockTransport.destructive());
    assert!(RuleAction::EmergencyKeyRotation.destructive());

    assert!(!RuleAction::RaiseAlert {
        severity: "high".to_string()
    }
    .destructive());
    assert!(!RuleAction::Notify {
        severity: "high".to_string()
    }
    .destructive());
    assert!(!RuleAction::BlockIp { ttl_secs: None }.destructive());
    assert!(!RuleAction::RunScan {
        intensity: "stealth".to_string()
    }
    .destructive());
}

#[test]
fn rule_from_draft_applies_documented_defaults() {
    let rule = Rule::from_draft(RuleDraft::default());

    assert_eq!(rule.name, "Untitled rule");
    assert!(rule.enabled);
    assert_eq!(rule.trigger, RuleTrigger::ThreatAlert);
    assert_eq!(rule.condition, Condition::All(Vec::new()));
    assert_eq!(
        rule.actions,
        vec![RuleAction::RaiseAlert {
            severity: "high".to_string()
        }]
    );
    assert!(!rule.notify);
    assert!(!rule.allow_destructive);
    assert_eq!(rule.cooldown_secs, 300);
    assert_eq!(rule.max_actions_per_hour, 20);
}

#[test]
fn rule_from_draft_honors_explicit_rule_id() {
    let rule = Rule::from_draft(RuleDraft {
        rule_id: Some("urn:uuid:fixed-id".to_string()),
        ..RuleDraft::default()
    });
    assert_eq!(rule.rule_id, "urn:uuid:fixed-id");
}

#[test]
fn rule_from_draft_empty_actions_list_falls_back_to_default() {
    let rule = Rule::from_draft(RuleDraft {
        actions: Some(Vec::new()),
        ..RuleDraft::default()
    });
    assert_eq!(
        rule.actions,
        vec![RuleAction::RaiseAlert {
            severity: "high".to_string()
        }]
    );
}

#[test]
fn apply_patch_only_touches_fields_that_are_some() {
    let mut rule = Rule::from_draft(RuleDraft {
        name: Some("Original".to_string()),
        cooldown_secs: Some(120),
        ..RuleDraft::default()
    });

    rule.apply_patch(RulePatch {
        name: Some("Renamed".to_string()),
        enabled: Some(false),
        ..RulePatch::default()
    });

    assert_eq!(rule.name, "Renamed");
    assert!(!rule.enabled);
    // Untouched fields keep their prior values.
    assert_eq!(rule.cooldown_secs, 120);
    assert_eq!(rule.trigger, RuleTrigger::ThreatAlert);
}

#[test]
fn apply_patch_empty_actions_falls_back_to_default_actions() {
    let mut rule = Rule::from_draft(RuleDraft {
        actions: Some(vec![RuleAction::RevokeDid]),
        ..RuleDraft::default()
    });

    rule.apply_patch(RulePatch {
        actions: Some(Vec::new()),
        ..RulePatch::default()
    });

    assert_eq!(
        rule.actions,
        vec![RuleAction::RaiseAlert {
            severity: "high".to_string()
        }]
    );
}

#[test]
fn effective_actions_injects_notify_when_missing() {
    let rule = Rule::from_draft(RuleDraft {
        actions: Some(vec![RuleAction::RevokeDid]),
        notify: Some(true),
        ..RuleDraft::default()
    });

    let actions = rule.effective_actions();
    assert_eq!(actions.len(), 2);
    assert!(actions
        .iter()
        .any(|a| matches!(a, RuleAction::Notify { .. })));
}

#[test]
fn effective_actions_does_not_duplicate_existing_notify() {
    let rule = Rule::from_draft(RuleDraft {
        actions: Some(vec![RuleAction::Notify {
            severity: "critical".to_string(),
        }]),
        notify: Some(true),
        ..RuleDraft::default()
    });

    let actions = rule.effective_actions();
    assert_eq!(actions.len(), 1);
    assert_eq!(
        actions[0],
        RuleAction::Notify {
            severity: "critical".to_string()
        }
    );
}

#[test]
fn effective_actions_leaves_actions_unchanged_when_notify_is_false() {
    let rule = Rule::from_draft(RuleDraft {
        actions: Some(vec![RuleAction::RevokeDid]),
        notify: Some(false),
        ..RuleDraft::default()
    });

    assert_eq!(rule.effective_actions(), vec![RuleAction::RevokeDid]);
}

#[test]
fn canonical_bytes_for_sign_is_deterministic_across_key_ordering() {
    let registry = RuleRegistry {
        rules: vec![Rule::from_draft(RuleDraft {
            rule_id: Some("urn:uuid:fixed".to_string()),
            ..RuleDraft::default()
        })],
        sequence: 3,
        ..RuleRegistry::default()
    };

    let a = registry.canonical_bytes_for_sign().expect("canonical a");
    let b = registry.canonical_bytes_for_sign().expect("canonical b");
    assert_eq!(
        a, b,
        "same content must canonicalize identically every time"
    );
}

#[test]
fn canonical_bytes_for_sign_ignores_existing_proof_but_reflects_content_changes() {
    let mut registry = RuleRegistry {
        sequence: 1,
        ..RuleRegistry::default()
    };
    let baseline = registry.canonical_bytes_for_sign().expect("baseline");

    // Mutating only the proof must not change the signed payload.
    registry.proof.proof_value = "some-signature-bytes".to_string();
    let with_proof = registry.canonical_bytes_for_sign().expect("with proof");
    assert_eq!(baseline, with_proof);

    // Mutating real content must change the signed payload.
    registry.sequence = 2;
    let changed = registry.canonical_bytes_for_sign().expect("changed");
    assert_ne!(baseline, changed);
}

#[test]
fn rules_paths_from_base_joins_expected_filenames() {
    let paths = RulesPaths::from_base(PathBuf::from("/var/lib/sgx-guardian/rules"));
    assert_eq!(
        paths.rules_file,
        PathBuf::from("/var/lib/sgx-guardian/rules/rules.json")
    );
    assert_eq!(
        paths.executions_file,
        PathBuf::from("/var/lib/sgx-guardian/rules/executions.jsonl")
    );
    assert_eq!(
        paths.state_file,
        PathBuf::from("/var/lib/sgx-guardian/rules/state.json")
    );
    assert_eq!(paths.base, PathBuf::from("/var/lib/sgx-guardian/rules"));
}

#[test]
fn threat_alert_accessors_are_none_for_non_threat_events() {
    let event = RuleEvent::GeofenceEntry {
        node_id: "nodeA".to_string(),
        device_id: "dev-1".to_string(),
        zone: "warehouse".to_string(),
    };

    assert_eq!(event.src_ip(), None);
    assert_eq!(event.ports(), Vec::<u16>::new());
    assert_eq!(event.severity_name(), None);
    assert_eq!(event.category_name(), None);
    assert_eq!(event.signature_id(), None);
    assert_eq!(event.device_status(), None);
    assert_eq!(event.target_did(), None);
    assert_eq!(event.zone(), Some("warehouse"));
}

#[test]
fn geofence_exit_target_key_combines_device_and_zone() {
    let event = RuleEvent::GeofenceExit {
        node_id: "nodeA".to_string(),
        device_id: "dev-7".to_string(),
        zone: "office".to_string(),
    };

    assert_eq!(event.trigger(), RuleTrigger::GeofenceExit);
    assert_eq!(event.target_key(), "dev-7:office");
    assert!(event.summary().contains("dev-7"));
    assert!(event.summary().contains("office"));
}

#[test]
fn device_discovered_zone_and_signature_id_are_none() {
    let dev = device("dev-1", DeviceStatus::Approved, &[]);
    let event = RuleEvent::from_device_discovered("nodeA", &dev);

    assert_eq!(event.zone(), None);
    assert_eq!(event.signature_id(), None);
    assert_eq!(event.target_did(), None);
    assert_eq!(event.category_name(), None);
}
