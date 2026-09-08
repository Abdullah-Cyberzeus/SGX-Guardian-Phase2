use chrono::Utc;
use sgx_guardian_client::threat::{
    blocker::Blocker,
    config::{BlockMode, SuricataConfig},
    threat_alert::{Severity, ThreatAlert, ThreatCategory},
};

fn alert(src_ip: &str, severity: Severity) -> ThreatAlert {
    ThreatAlert {
        alert_id: format!("alert-{src_ip}"),
        timestamp: Utc::now(),
        src_ip: src_ip.into(),
        src_port: 4444,
        dst_ip: "198.51.100.20".into(),
        dst_port: 80,
        protocol: "TCP".into(),
        signature_id: 1234,
        signature: "Test signature".into(),
        category: ThreatCategory::Other,
        severity,
        rev: 1,
        gid: 1,
        event_type: "alert".into(),
        blocked: false,
    }
}

#[test]
fn blocker_should_block_matrix() {
    let inline_cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..SuricataConfig::default()
    };
    let disabled_inline_cfg = SuricataConfig {
        enabled: false,
        block_mode: BlockMode::InlineBlock,
        ..SuricataConfig::default()
    };
    let alert_only_cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::AlertOnly,
        ..SuricataConfig::default()
    };

    assert!(Blocker::should_block(
        &inline_cfg,
        &alert("203.0.113.10", Severity::High)
    ));
    assert!(Blocker::should_block(
        &inline_cfg,
        &alert("203.0.113.11", Severity::Critical)
    ));
    assert!(!Blocker::should_block(
        &inline_cfg,
        &alert("203.0.113.12", Severity::Medium)
    ));
    assert!(!Blocker::should_block(
        &alert_only_cfg,
        &alert("203.0.113.13", Severity::High)
    ));
    assert!(!Blocker::should_block(
        &disabled_inline_cfg,
        &alert("203.0.113.14", Severity::Critical)
    ));
    assert!(!Blocker::should_block(
        &inline_cfg,
        &alert("192.168.100.77", Severity::Critical)
    ));
}

#[test]
fn should_block_rejects_info_severity() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("203.0.113.1", Severity::Info)
    ));
}

#[test]
fn should_block_rejects_low_severity() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("203.0.113.1", Severity::Low)
    ));
}

#[test]
fn should_block_rejects_medium_severity() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("203.0.113.1", Severity::Medium)
    ));
}

#[test]
fn should_block_accepts_high_severity() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(Blocker::should_block(
        &cfg,
        &alert("203.0.113.1", Severity::High)
    ));
}

#[test]
fn should_block_accepts_critical_severity() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(Blocker::should_block(
        &cfg,
        &alert("203.0.113.1", Severity::Critical)
    ));
}

#[test]
fn should_block_rejects_alert_only_mode() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::AlertOnly,
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("203.0.113.1", Severity::Critical)
    ));
}

#[test]
fn should_block_rejects_when_disabled() {
    let cfg = SuricataConfig {
        enabled: false,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("203.0.113.1", Severity::Critical)
    ));
}

#[test]
fn should_block_rejects_exact_ip_exempt() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        block_exempt: vec!["203.0.113.1".into()],
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("203.0.113.1", Severity::Critical)
    ));
}

#[test]
fn should_block_rejects_cidr_exempt() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        block_exempt: vec!["203.0.113.0/24".into()],
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("203.0.113.99", Severity::Critical)
    ));
}

#[test]
fn should_block_ignores_invalid_exempt_entry() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        block_exempt: vec!["not cidr".into()],
        ..Default::default()
    };
    assert!(Blocker::should_block(
        &cfg,
        &alert("203.0.113.99", Severity::Critical)
    ));
}

#[test]
fn should_block_accepts_invalid_source_ip_when_not_exempt() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(Blocker::should_block(
        &cfg,
        &alert("bad-ip", Severity::Critical)
    ));
}

#[test]
fn block_record_round_trips_json() {
    let record = sgx_guardian_client::threat::blocker::BlockRecord {
        ip: "203.0.113.1".into(),
        expires_at: 123,
    };
    assert_eq!(
        serde_json::from_value::<sgx_guardian_client::threat::blocker::BlockRecord>(
            serde_json::to_value(&record).unwrap()
        )
        .unwrap(),
        record
    );
}

#[test]
fn block_attempt_equality_works() {
    let a = sgx_guardian_client::threat::blocker::BlockAttempt {
        blocked: true,
        reason: Some("r".into()),
    };
    assert_eq!(a, a.clone());
}

#[test]
fn block_attempt_debug_mentions_blocked() {
    let a = sgx_guardian_client::threat::blocker::BlockAttempt {
        blocked: false,
        reason: None,
    };
    assert!(format!("{a:?}").contains("blocked"));
}

#[test]
fn load_block_records_missing_file_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    assert!(sgx_guardian_client::threat::blocker::load_block_records(
        &dir.path().join("missing.json")
    )
    .unwrap()
    .is_empty());
}

#[test]
fn load_block_records_empty_file_returns_empty() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(
        sgx_guardian_client::threat::blocker::load_block_records(file.path())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn load_block_records_malformed_json_errors() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"{").unwrap();
    assert!(sgx_guardian_client::threat::blocker::load_block_records(file.path()).is_err());
}

#[test]
fn load_block_records_valid_json_loads() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), br#"[{"ip":"203.0.113.1","expires_at":123}]"#).unwrap();
    assert_eq!(
        sgx_guardian_client::threat::blocker::load_block_records(file.path())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn should_block_ipv6_high_severity() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(Blocker::should_block(
        &cfg,
        &alert("2001:db8::1", Severity::High)
    ));
}

#[test]
fn should_block_ipv6_cidr_exempt() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        block_exempt: vec!["2001:db8::/32".into()],
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("2001:db8::1", Severity::High)
    ));
}

#[test]
fn should_block_ipv4_boundary_first_address() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(Blocker::should_block(
        &cfg,
        &alert("0.0.0.0", Severity::Critical)
    ));
}

#[test]
fn should_block_ipv4_boundary_last_address() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        ..Default::default()
    };
    assert!(Blocker::should_block(
        &cfg,
        &alert("255.255.255.255", Severity::Critical)
    ));
}

#[test]
fn should_block_exact_exempt_takes_precedence_over_high_severity() {
    let cfg = SuricataConfig {
        enabled: true,
        block_mode: BlockMode::InlineBlock,
        block_exempt: vec!["198.51.100.8".into()],
        ..Default::default()
    };
    assert!(!Blocker::should_block(
        &cfg,
        &alert("198.51.100.8", Severity::High)
    ));
}

#[test]
fn load_block_records_preserves_multiple_records() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        br#"[{"ip":"203.0.113.1","expires_at":1},{"ip":"203.0.113.2","expires_at":2}]"#,
    )
    .unwrap();
    assert_eq!(
        sgx_guardian_client::threat::blocker::load_block_records(file.path())
            .unwrap()
            .len(),
        2
    );
}
