// tests/nebula_health_extended_test.rs
// Integration tests for uncovered branches in src/nebula/health.rs

use sgx_guardian_client::nebula::health::{
    LighthouseHealthReport, NebulaHealth, OverlayHealthReport,
};
use sgx_guardian_client::nebula::lighthouse::LighthouseRegistry;
use sgx_guardian_client::nebula::overlay::OverlayPool;

// ── NebulaHealth::check with non-existent directory ───────────────────────────

#[test]
fn test_nebula_health_check_missing_dir() {
    let report = NebulaHealth::check("/tmp/sgx-test-nonexistent-dir-xyz123", "nodeA");
    // All cert/key files should be absent
    assert!(!report.ca_cert_present);
    assert!(!report.ca_key_present);
    assert!(!report.node_cert_present);
    assert!(!report.node_key_present);
    // cert_days_remaining should be None because node cert is absent
    assert!(report.cert_days_remaining.is_none());
    // daemon_running is whatever pgrep says — just verify it returns
    let _ = report.daemon_running;
}

#[test]
fn test_nebula_health_report_summary_format() {
    let report = NebulaHealth::check("/tmp/nonexistent-abc", "nodeA");
    let summary = report.summary();
    assert!(summary.contains("CA Cert:"));
    assert!(summary.contains("CA Key:"));
    assert!(summary.contains("Node Cert:"));
    assert!(summary.contains("Node Key:"));
    assert!(summary.contains("Daemon Running:"));
    assert!(summary.contains("Cert Days Remaining:"));
}

// ── LighthouseHealthReport ────────────────────────────────────────────────────

#[test]
fn test_lighthouse_health_is_healthy_when_primary_active_as_lh() {
    let report = LighthouseHealthReport {
        is_lighthouse: true,
        udp_listening: true,
        active_count: 1,
        primary_active: true,
    };
    assert!(report.is_healthy());
}

#[test]
fn test_lighthouse_health_not_healthy_when_lh_udp_closed() {
    let report = LighthouseHealthReport {
        is_lighthouse: true,
        udp_listening: false,
        active_count: 1,
        primary_active: true,
    };
    assert!(!report.is_healthy());
}

#[test]
fn test_lighthouse_health_member_healthy_with_active_primary() {
    let report = LighthouseHealthReport {
        is_lighthouse: false,
        udp_listening: false, // members don't listen
        active_count: 1,
        primary_active: true,
    };
    assert!(report.is_healthy());
}

#[test]
fn test_lighthouse_health_member_not_healthy_when_no_primary() {
    let report = LighthouseHealthReport {
        is_lighthouse: false,
        udp_listening: false,
        active_count: 0,
        primary_active: false,
    };
    assert!(!report.is_healthy());
}

#[test]
fn test_lighthouse_health_summary_contains_key_fields() {
    let report = LighthouseHealthReport {
        is_lighthouse: true,
        udp_listening: true,
        active_count: 3,
        primary_active: true,
    };
    let summary = report.summary();
    assert!(summary.contains("LH:"));
    assert!(summary.contains("is_lh=true"));
    assert!(summary.contains("active=3"));
    assert!(summary.contains("OPEN"));
    assert!(summary.contains("✅"));
}

#[test]
fn test_lighthouse_health_summary_degraded() {
    let report = LighthouseHealthReport {
        is_lighthouse: true,
        udp_listening: false,
        active_count: 0,
        primary_active: false,
    };
    let summary = report.summary();
    assert!(summary.contains("CLOSED"));
    assert!(summary.contains("⚠️"));
}

// ── OverlayHealthReport ───────────────────────────────────────────────────────

#[test]
fn test_overlay_health_is_healthy_all_ok() {
    let report = OverlayHealthReport {
        interface_up: true,
        expected_ip: "192.168.100.1/24".into(),
        actual_ip: "192.168.100.1/24".into(),
        ip_correct: true,
        pool_valid: true,
        pool_summary: "Pool OK".into(),
    };
    assert!(report.is_healthy());
}

#[test]
fn test_overlay_health_not_healthy_when_interface_down() {
    let report = OverlayHealthReport {
        interface_up: false,
        expected_ip: "192.168.100.1/24".into(),
        actual_ip: "192.168.100.1/24".into(),
        ip_correct: true,
        pool_valid: true,
        pool_summary: "Pool OK".into(),
    };
    assert!(!report.is_healthy());
}

#[test]
fn test_overlay_health_not_healthy_when_ip_wrong() {
    let report = OverlayHealthReport {
        interface_up: true,
        expected_ip: "192.168.100.1/24".into(),
        actual_ip: "192.168.100.2/24".into(),
        ip_correct: false,
        pool_valid: true,
        pool_summary: "Pool OK".into(),
    };
    assert!(!report.is_healthy());
}

#[test]
fn test_overlay_health_summary_contains_key_fields() {
    let report = OverlayHealthReport {
        interface_up: true,
        expected_ip: "192.168.100.1/24".into(),
        actual_ip: "192.168.100.1/24".into(),
        ip_correct: true,
        pool_valid: true,
        pool_summary: "Pool OK".into(),
    };
    let summary = report.summary();
    assert!(summary.contains("Overlay:"));
    assert!(summary.contains("up=true"));
    assert!(summary.contains("ip_match=true"));
    assert!(summary.contains("pool_ok=true"));
    assert!(summary.contains("✅ HEALTHY"));
}

#[test]
fn test_overlay_health_summary_degraded() {
    let report = OverlayHealthReport {
        interface_up: false,
        expected_ip: "192.168.100.1/24".into(),
        actual_ip: "none".into(),
        ip_correct: false,
        pool_valid: false,
        pool_summary: "Empty".into(),
    };
    let summary = report.summary();
    assert!(summary.contains("❌ DEGRADED"));
}

// ── NebulaHealth::check_lighthouse ───────────────────────────────────────────

#[test]
fn test_check_lighthouse_node_a_is_lighthouse() {
    let reg = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
    let report = NebulaHealth::check_lighthouse(&reg, "nodeA");
    assert!(report.is_lighthouse);
    assert_eq!(report.active_count, 1);
}

#[test]
fn test_check_lighthouse_node_b_is_not_lighthouse() {
    let reg = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
    let report = NebulaHealth::check_lighthouse(&reg, "nodeB");
    assert!(!report.is_lighthouse);
}

// ── NebulaHealth::check_overlay ──────────────────────────────────────────────

#[test]
fn test_check_overlay_empty_pool() {
    let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
    let report = NebulaHealth::check_overlay(&pool, "nodeA");
    // Without assigning an IP to nodeA in the pool, expected_ip may be "none"
    // The test just ensures no panic and returns valid report
    let _ = report.is_healthy();
    let _ = report.summary();
}

#[test]
fn test_check_overlay_summary_format_fields() {
    let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
    let report = NebulaHealth::check_overlay(&pool, "nodeA");
    let s = report.summary();
    assert!(s.contains("Overlay:"));
    assert!(s.contains("up="));
    assert!(s.contains("ip_match="));
    assert!(s.contains("pool_ok="));
}
