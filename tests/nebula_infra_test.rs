use sgx_guardian_client::nebula::daemon::NebulaDaemon;
use sgx_guardian_client::nebula::install::NebulaInstall;
use sgx_guardian_client::nebula::interface::NebulaInterface;
use sgx_guardian_client::nebula::stats::NebulaStats;

// ─── NebulaInstall ───────────────────────────────────────────

#[test]
fn test_nebula_check_binary() {
    // nebula is installed at /usr/local/bin/nebula
    let result = NebulaInstall::check_binary();
    assert!(
        result.is_ok(),
        "nebula binary check failed: {:?}",
        result.err()
    );
}

#[test]
fn test_nebula_check_version() {
    let result = NebulaInstall::check_version();
    assert!(
        result.is_ok(),
        "nebula version check failed: {:?}",
        result.err()
    );
    let version = result.unwrap();
    assert!(!version.is_empty(), "version string should not be empty");
}

#[test]
fn test_nebula_test_daemon_start() {
    let result = NebulaInstall::test_daemon_start();
    assert!(result.is_ok(), "nebula --help failed: {:?}", result.err());
}

// ─── NebulaInterface ─────────────────────────────────────────

#[test]
fn test_interface_is_up_returns_bool() {
    // On dev machine without nebula0, this should return false
    let up = NebulaInterface::is_up();
    // We can't assert true or false — just that it doesn't panic
    let _ = up;
}

#[test]
fn test_interface_get_overlay_ip_no_nebula0() {
    // Without nebula0 interface, should return None
    // (If nebula0 exists on the machine, it returns Some)
    let ip = NebulaInterface::get_overlay_ip();
    // Just verify it doesn't panic
    let _ = ip;
}

#[test]
fn test_interface_verify_ip_without_interface() {
    // Without nebula0, verify_ip should return false
    let verified = NebulaInterface::verify_ip("192.168.100.99/24");
    // If nebula0 doesn't exist, this is false
    // If it does exist with a different IP, also false
    let _ = verified;
}

#[test]
fn test_interface_status_report_format() {
    let report = NebulaInterface::status_report();
    assert!(
        report.contains("Guardian Mesh interface:"),
        "report should mention the Guardian Mesh label: got {}",
        report
    );
    assert!(report.contains("up="), "report should contain up= field");
    assert!(report.contains("ip="), "report should contain ip= field");
}

#[tokio::test]
async fn test_interface_wait_for_interface_timeout() {
    // With a 1-second timeout, this should return quickly
    // (nebula0 unlikely to appear in 1s if not already present)
    let result = NebulaInterface::wait_for_interface(1).await;
    // Just verify it completes without hanging
    let _ = result;
}

// ─── NebulaDaemon ────────────────────────────────────────────

#[test]
fn test_daemon_is_running_returns_bool() {
    let running = NebulaDaemon::is_running();
    // Just ensure it doesn't panic
    let _ = running;
}

#[tokio::test]
async fn test_daemon_kill_existing_noop() {
    // kill_existing is intentionally left empty (no-op)
    NebulaDaemon::kill_existing().await;
    // Should complete without error
}

#[tokio::test]
async fn test_daemon_kill_existing_for_config() {
    // Calling with a non-existent config path should be harmless
    NebulaDaemon::kill_existing_for_config("/tmp/nonexistent_config.yaml").await;
}

#[test]
fn test_daemon_test_config_invalid_path() {
    // Test config validation with a non-existent file
    let result = NebulaDaemon::test_config("/tmp/nonexistent_nebula_config_12345.yaml");
    // nebula -config <bad_path> -test should fail
    assert!(result.is_err(), "expected error for non-existent config");
}

// ─── NebulaStats (parse_prometheus) ──────────────────────────

#[test]
fn test_parse_prometheus_empty_input() {
    let result = NebulaStats::parse_prometheus("");
    assert!(result.is_ok());
    let stats = result.unwrap();
    assert_eq!(stats.active_peers, 0);
    assert_eq!(stats.total_bytes_relayed, 0);
    assert_eq!(stats.direct_tunnels, 0);
    assert_eq!(stats.relay_tunnels, 0);
}

#[test]
fn test_parse_prometheus_comments_only() {
    let input = "# HELP some_metric\n# TYPE some_metric gauge\n";
    let result = NebulaStats::parse_prometheus(input);
    assert!(result.is_ok());
    let stats = result.unwrap();
    assert_eq!(stats.active_peers, 0);
}

#[test]
fn test_parse_prometheus_full_metrics() {
    let input = r#"
# HELP nebula_relay_active_peers active
nebula_relay_active_peers 5
nebula_relay_tx_bytes_total 1000000
nebula_relay_rx_bytes_total 500000
nebula_tunnels_direct 3
nebula_tunnels_relay 2
"#;
    let result = NebulaStats::parse_prometheus(input).unwrap();
    assert_eq!(result.active_peers, 5);
    assert_eq!(result.total_bytes_relayed, 1_500_000);
    assert_eq!(result.direct_tunnels, 3);
    assert_eq!(result.relay_tunnels, 2);
}

#[test]
fn test_parse_prometheus_negative_float() {
    let input = "nebula_relay_tx_bytes_total -1.5\n";
    let result = NebulaStats::parse_prometheus(input).unwrap();
    // Negative float should clamp to 0
    assert_eq!(result.total_bytes_relayed, 0);
}

#[test]
fn test_parse_prometheus_with_labels() {
    let input = r#"nebula_tunnels_active{type="relay"} 7
"#;
    let result = NebulaStats::parse_prometheus(input).unwrap();
    // nebula_tunnels_active is an active_peers candidate
    assert_eq!(result.active_peers, 7);
}

#[test]
fn test_parse_prometheus_malformed_value() {
    let input = "nebula_relay_active_peers not_a_number\n";
    let result = NebulaStats::parse_prometheus(input).unwrap();
    // Unparseable value → skipped, so 0
    assert_eq!(result.active_peers, 0);
}

#[test]
fn test_parse_prometheus_float_rounding() {
    let input = "nebula_connections_active 3.7\n";
    let result = NebulaStats::parse_prometheus(input).unwrap();
    assert_eq!(result.active_peers, 4); // 3.7 rounds to 4
}

#[test]
fn test_parse_prometheus_multiple_lines_same_metric() {
    // Multiple entries for same metric should saturating_add
    let input = r#"nebula_relay_tx_bytes_total{dir="in"} 100
nebula_relay_tx_bytes_total{dir="out"} 200
"#;
    let result = NebulaStats::parse_prometheus(input).unwrap();
    assert_eq!(result.total_bytes_relayed, 300);
}
