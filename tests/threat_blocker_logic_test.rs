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
