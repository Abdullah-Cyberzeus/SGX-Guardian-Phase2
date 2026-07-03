// tests/nebula_tunnel_state_extended_test.rs
// Integration tests for uncovered branches in src/nebula/tunnel_state.rs

use sgx_guardian_client::nebula::tunnel_state::TunnelState;

// ── parse_handshake_metrics edge cases ────────────────────────────────────────

#[test]
fn test_parse_empty_string_returns_empty() {
    let peers = TunnelState::parse_handshake_metrics("");
    assert!(peers.is_empty());
}

#[test]
fn test_parse_only_comments_and_blank_lines() {
    let txt = r#"
# This is a Prometheus comment
# HELP nebula_handshake_direct_total Direct handshakes

"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert!(peers.is_empty());
}

#[test]
fn test_parse_zeros_returns_empty() {
    let txt = r#"
nebula_handshake_direct_total 0
nebula_handshake_via_relay_total 0
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert!(peers.is_empty());
}

#[test]
fn test_parse_direct_only_no_relay() {
    let txt = r#"
nebula_handshake_direct_total 5
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert_eq!(peers.len(), 1);
    assert!(peers[0].via_direct);
    assert!(peers[0].via_relay.is_none());
}

#[test]
fn test_parse_relay_only_no_direct() {
    let txt = r#"
nebula_handshake_via_relay_total 3
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert_eq!(peers.len(), 1);
    assert!(!peers[0].via_direct);
    assert!(peers[0].via_relay.is_some());
}

#[test]
fn test_parse_nebula_tunnels_direct_variant() {
    let txt = r#"
nebula_tunnels_direct 7
nebula_tunnels_relay 0
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert_eq!(peers.len(), 1);
    assert!(peers[0].via_direct);
    assert!(peers[0].via_relay.is_none());
}

#[test]
fn test_parse_nebula_tunnels_relay_variant() {
    let txt = r#"
nebula_tunnels_direct 0
nebula_tunnels_relay 4
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert_eq!(peers.len(), 1);
    assert!(!peers[0].via_direct); // relay count > direct count → !via_direct
    assert!(peers[0].via_relay.is_some());
}

#[test]
fn test_parse_mixed_variant_names() {
    // Use one "handshake" prefix and one "tunnels" prefix
    let txt = r#"
nebula_handshake_direct_total 2
nebula_tunnels_relay 1
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert_eq!(peers.len(), 1);
    // direct=2, relay=1 → direct >= relay → via_direct = true
    assert!(peers[0].via_direct);
    assert!(peers[0].via_relay.is_some()); // relay > 0
}

#[test]
fn test_parse_equal_direct_and_relay_prefers_direct() {
    let txt = r#"
nebula_handshake_direct_total 3
nebula_handshake_via_relay_total 3
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert_eq!(peers.len(), 1);
    // direct >= relay → via_direct = true
    assert!(peers[0].via_direct);
    assert!(peers[0].via_relay.is_some()); // relay > 0
}

#[test]
fn test_parse_result_has_aggregate_device_id() {
    let txt = r#"
nebula_handshake_direct_total 1
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert_eq!(peers[0].peer_overlay_ip, "aggregate");
}

#[test]
fn test_parse_unrelated_metric_lines_ignored() {
    let txt = r#"
go_goroutines 42
process_cpu_seconds_total 1.23
nebula_handshake_direct_total 2
"#;
    let peers = TunnelState::parse_handshake_metrics(txt);
    assert_eq!(peers.len(), 1);
    assert!(peers[0].via_direct);
}
