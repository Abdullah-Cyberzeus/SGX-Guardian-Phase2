// tests/nebula_relay_tc_extended_test.rs
// Integration tests for uncovered branches in src/nebula/relay_tc.rs

use sgx_guardian_client::nebula::relay_tc::RelayTrafficControl;

// ── parse_stats edge cases ────────────────────────────────────────────────────

#[test]
fn test_parse_stats_with_kbit_rate() {
    let sample = r#"
class htb 1:1 root rate 500Kbit ceil 500Kbit burst 1600b cburst 1600b
 Sent 987654 bytes 1111 pkt (dropped 0, overlimits 0 requeues 0)
"#;
    let parsed = RelayTrafficControl::parse_stats(sample).unwrap();
    assert_eq!(parsed.bytes_sent, 987_654);
    assert_eq!(parsed.packets_sent, 1111);
    // 500 Kbit = 0.5 Mbit
    assert!(
        (parsed.current_mbps - 0.5).abs() < 0.001,
        "Expected 0.5 Mbps but got {}",
        parsed.current_mbps
    );
}

#[test]
fn test_parse_stats_with_gbit_rate() {
    let sample = r#"
class htb 1:1 root rate 1Gbit ceil 1Gbit burst 1600b cburst 1600b
 Sent 1000000 bytes 500 pkt (dropped 0, overlimits 0 requeues 0)
"#;
    let parsed = RelayTrafficControl::parse_stats(sample).unwrap();
    assert_eq!(parsed.bytes_sent, 1_000_000);
    assert_eq!(parsed.packets_sent, 500);
    // 1 Gbit = 1000 Mbit
    assert!(
        (parsed.current_mbps - 1000.0).abs() < 0.001,
        "Expected 1000 Mbps but got {}",
        parsed.current_mbps
    );
}

#[test]
fn test_parse_stats_with_mbit_rate() {
    let sample = r#"
class htb 1:1 root rate 10Mbit ceil 10Mbit burst 1600b cburst 1600b
 Sent 2000000 bytes 3000 pkt (dropped 0, overlimits 0 requeues 0)
"#;
    let parsed = RelayTrafficControl::parse_stats(sample).unwrap();
    assert!(
        (parsed.current_mbps - 10.0).abs() < 0.001,
        "Expected 10 Mbps but got {}",
        parsed.current_mbps
    );
    assert_eq!(parsed.bytes_sent, 2_000_000);
    assert_eq!(parsed.packets_sent, 3000);
}

#[test]
fn test_parse_stats_empty_input_returns_none() {
    let parsed = RelayTrafficControl::parse_stats("");
    assert!(parsed.is_none());
}

#[test]
fn test_parse_stats_no_matching_lines_returns_none() {
    let sample = r#"
# This is a comment
Some unrelated text here
Another unrelated line
"#;
    let parsed = RelayTrafficControl::parse_stats(sample);
    assert!(parsed.is_none());
}

#[test]
fn test_parse_stats_with_only_sent_line() {
    // Has bytes/packets but no rate — bytes_sent and packets_sent are set, current_mbps = 0
    // Since bytes_sent > 0, it should return Some
    let sample = r#"
 Sent 500000 bytes 750 pkt (dropped 0, overlimits 0 requeues 0)
"#;
    let parsed = RelayTrafficControl::parse_stats(sample).unwrap();
    assert_eq!(parsed.bytes_sent, 500_000);
    assert_eq!(parsed.packets_sent, 750);
}

#[test]
fn test_parse_stats_with_only_rate_line() {
    // Has rate but no Sent line — current_mbps is set, bytes_sent = 0
    let sample = r#"
class htb 1:1 root rate 5Mbit ceil 5Mbit burst 1599b cburst 1599b
"#;
    let parsed = RelayTrafficControl::parse_stats(sample);
    // bytes_sent=0, packets_sent=0, current_mbps=5.0 — 5.0 != 0.0 so returns Some
    let parsed = parsed.unwrap();
    assert!((parsed.current_mbps - 5.0).abs() < 0.001);
    assert_eq!(parsed.bytes_sent, 0);
}

// ── clear — should not panic even when nebula0 doesn't exist ─────────────────

#[test]
fn test_clear_does_not_panic_without_nebula0() {
    // This calls tc qdisc del dev nebula0 root; tc may fail but we ignore it
    let result = RelayTrafficControl::clear();
    // clear always returns Ok(())
    assert!(result.is_ok());
}

// ── apply_bandwidth_limit: zero triggers clear (no nebula0 so returns Err) ──

#[test]
fn test_apply_bandwidth_limit_zero_calls_clear() {
    // apply_bandwidth_limit(0) calls clear() which always succeeds
    let result = RelayTrafficControl::apply_bandwidth_limit(0);
    assert!(result.is_ok());
}

#[test]
fn test_apply_bandwidth_limit_nonzero_fails_without_nebula0() {
    // nebula0 doesn't exist in test environment; should return Err about not registered
    let result = RelayTrafficControl::apply_bandwidth_limit(10);
    // Either fails because nebula0 not registered, or tc command fails
    // We just check it doesn't panic
    let _ = result;
}

#[test]
fn test_parse_stats_sent_line_with_zero_values_returns_none() {
    let parsed =
        RelayTrafficControl::parse_stats("Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)");
    assert!(parsed.is_none());
}

#[test]
fn test_parse_stats_sent_line_with_invalid_bytes_defaults_bytes_to_zero() {
    let parsed = RelayTrafficControl::parse_stats(
        "Sent nope bytes 42 pkt (dropped 0, overlimits 0 requeues 0)",
    )
    .unwrap();
    assert_eq!(parsed.bytes_sent, 0);
    assert_eq!(parsed.packets_sent, 42);
}

#[test]
fn test_parse_stats_sent_line_with_invalid_packets_defaults_packets_to_zero() {
    let parsed = RelayTrafficControl::parse_stats(
        "Sent 42 bytes nope pkt (dropped 0, overlimits 0 requeues 0)",
    )
    .unwrap();
    assert_eq!(parsed.bytes_sent, 42);
    assert_eq!(parsed.packets_sent, 0);
}

#[test]
fn test_parse_stats_sent_line_requires_enough_tokens() {
    assert!(RelayTrafficControl::parse_stats("Sent 42 bytes").is_none());
}

#[test]
fn test_parse_stats_sent_prefix_is_case_sensitive() {
    assert!(RelayTrafficControl::parse_stats("sent 42 bytes 7 pkt").is_none());
}

#[test]
fn test_parse_stats_rate_prefix_is_case_sensitive() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb 1:1 root RATE 5Mbit ceil 5Mbit\nSent 1 bytes 1 pkt",
    )
    .unwrap();
    assert_eq!(parsed.current_mbps, 0.0);
}

#[test]
fn test_parse_stats_rate_token_must_follow_rate_word() {
    let parsed =
        RelayTrafficControl::parse_stats("class htb 1:1 root rate ceil 5Mbit\nSent 1 bytes 1 pkt")
            .unwrap();
    assert_eq!(parsed.current_mbps, 0.0);
}

#[test]
fn test_parse_stats_unknown_rate_unit_defaults_to_zero() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb 1:1 root rate 10bit ceil 10bit\nSent 1 bytes 1 pkt",
    )
    .unwrap();
    assert_eq!(parsed.current_mbps, 0.0);
}

#[test]
fn test_parse_stats_invalid_rate_number_defaults_to_zero() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb 1:1 root rate fastMbit ceil fastMbit\nSent 1 bytes 1 pkt",
    )
    .unwrap();
    assert_eq!(parsed.current_mbps, 0.0);
}

#[test]
fn test_parse_stats_decimal_mbit_rate() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb 1:1 root rate 1.25Mbit ceil 1.25Mbit\nSent 1 bytes 1 pkt",
    )
    .unwrap();
    assert!((parsed.current_mbps - 1.25).abs() < 0.001);
}

#[test]
fn test_parse_stats_decimal_kbit_rate() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb 1:1 root rate 1250Kbit ceil 1250Kbit\nSent 1 bytes 1 pkt",
    )
    .unwrap();
    assert!((parsed.current_mbps - 1.25).abs() < 0.001);
}

#[test]
fn test_parse_stats_decimal_gbit_rate() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb 1:1 root rate 0.5Gbit ceil 0.5Gbit\nSent 1 bytes 1 pkt",
    )
    .unwrap();
    assert!((parsed.current_mbps - 500.0).abs() < 0.001);
}

#[test]
fn test_parse_stats_lowercase_rate_units() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb 1:1 root rate 2mbit ceil 2mbit\nSent 1 bytes 1 pkt",
    )
    .unwrap();
    assert!((parsed.current_mbps - 2.0).abs() < 0.001);
}

#[test]
fn test_parse_stats_last_sent_line_wins() {
    let parsed =
        RelayTrafficControl::parse_stats("Sent 10 bytes 1 pkt\nSent 20 bytes 2 pkt").unwrap();
    assert_eq!(parsed.bytes_sent, 20);
    assert_eq!(parsed.packets_sent, 2);
}

#[test]
fn test_parse_stats_last_rate_line_wins() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb rate 1Mbit\nclass htb rate 2Mbit\nSent 1 bytes 1 pkt",
    )
    .unwrap();
    assert!((parsed.current_mbps - 2.0).abs() < 0.001);
}

#[test]
fn test_parse_stats_large_u64_values() {
    let parsed =
        RelayTrafficControl::parse_stats(&format!("Sent {} bytes {} pkt", u64::MAX, u64::MAX - 1))
            .unwrap();
    assert_eq!(parsed.bytes_sent, u64::MAX);
    assert_eq!(parsed.packets_sent, u64::MAX - 1);
}

#[test]
fn test_parse_stats_partial_fields_are_preserved() {
    let parsed = RelayTrafficControl::parse_stats(
        "class htb 1:1 root rate 3Mbit ceil 3Mbit\nSent nope bytes 0 pkt",
    )
    .unwrap();
    assert_eq!(parsed.bytes_sent, 0);
    assert_eq!(parsed.packets_sent, 0);
    assert!((parsed.current_mbps - 3.0).abs() < 0.001);
}
