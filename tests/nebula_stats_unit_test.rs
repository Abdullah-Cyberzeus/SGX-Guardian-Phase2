use sgx_guardian_client::nebula::stats::{NebulaStats, RelayStats};

#[test]
fn relay_stats_default_is_zeroed() {
    let stats = RelayStats::default();
    assert_eq!(stats.active_peers, 0);
    assert_eq!(stats.total_bytes_relayed, 0);
    assert_eq!(stats.current_mbps, 0.0);
    assert_eq!(stats.direct_tunnels, 0);
    assert_eq!(stats.relay_tunnels, 0);
}

#[test]
fn parses_primary_metric_names() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
nebula_relay_active_peers 2
nebula_relay_bytes_total 100
nebula_tunnels_direct 3
nebula_tunnels_relay 4
"#,
    )
    .unwrap();
    assert_eq!(parsed.active_peers, 2);
    assert_eq!(parsed.total_bytes_relayed, 100);
    assert_eq!(parsed.direct_tunnels, 3);
    assert_eq!(parsed.relay_tunnels, 4);
}

#[test]
fn parses_fallback_active_peer_metric_names() {
    let tunnels = NebulaStats::parse_prometheus("nebula_tunnels_active 7").unwrap();
    assert_eq!(tunnels.active_peers, 7);
    let connections = NebulaStats::parse_prometheus("nebula_connections_active 8").unwrap();
    assert_eq!(connections.active_peers, 8);
}

#[test]
fn first_active_candidate_wins_even_when_zero() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
nebula_relay_active_peers 0
nebula_tunnels_active 9
"#,
    )
    .unwrap();
    assert_eq!(parsed.active_peers, 0);
}

#[test]
fn relay_byte_candidates_are_summed() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
nebula_relay_bytes_total 1
nebula_relay_tx_bytes_total 2
nebula_relay_rx_bytes_total 3
nebula_relay_messages_total 4
"#,
    )
    .unwrap();
    assert_eq!(parsed.total_bytes_relayed, 10);
}

#[test]
fn duplicate_metric_lines_are_summed_before_selection() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
nebula_relay_tx_bytes_total 10
nebula_relay_tx_bytes_total 15
nebula_tunnels_direct 1
nebula_tunnels_direct 2
"#,
    )
    .unwrap();
    assert_eq!(parsed.total_bytes_relayed, 25);
    assert_eq!(parsed.direct_tunnels, 3);
}

#[test]
fn metrics_with_labels_are_grouped_by_base_metric_name() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
nebula_relay_tx_bytes_total{relay="a"} 10
nebula_relay_tx_bytes_total{relay="b"} 20
nebula_tunnels_relay{node="a"} 1
nebula_tunnels_relay{node="b"} 2
"#,
    )
    .unwrap();
    assert_eq!(parsed.total_bytes_relayed, 30);
    assert_eq!(parsed.relay_tunnels, 3);
}

#[test]
fn comments_blank_lines_and_extra_columns_are_ignored_or_tolerated() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
# HELP ignored

nebula_relay_active_peers 5 extra-column
not_enough_columns
"#,
    )
    .unwrap();
    assert_eq!(parsed.active_peers, 5);
}

#[test]
fn floating_point_values_are_rounded() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
nebula_relay_active_peers 1.4
nebula_tunnels_direct 1.5
nebula_tunnels_relay 2.6
"#,
    )
    .unwrap();
    assert_eq!(parsed.active_peers, 1);
    assert_eq!(parsed.direct_tunnels, 2);
    assert_eq!(parsed.relay_tunnels, 3);
}

#[test]
fn negative_floats_are_clamped_to_zero() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
nebula_relay_active_peers -5.0
nebula_relay_bytes_total -1.2
"#,
    )
    .unwrap();
    assert_eq!(parsed.active_peers, 0);
    assert_eq!(parsed.total_bytes_relayed, 0);
}

#[test]
fn invalid_numeric_values_are_ignored() {
    let parsed = NebulaStats::parse_prometheus(
        r#"
nebula_relay_active_peers nope
nebula_tunnels_active 6
nebula_relay_bytes_total NaN
"#,
    )
    .unwrap();
    assert_eq!(parsed.active_peers, 6);
    assert_eq!(parsed.total_bytes_relayed, 0);
}

#[test]
fn u32_fields_saturate_at_u32_max() {
    let huge = (u32::MAX as u64) + 100;
    let parsed = NebulaStats::parse_prometheus(&format!(
        "nebula_relay_active_peers {huge}\nnebula_tunnels_direct {huge}\nnebula_tunnels_relay {huge}"
    ))
    .unwrap();
    assert_eq!(parsed.active_peers, u32::MAX);
    assert_eq!(parsed.direct_tunnels, u32::MAX);
    assert_eq!(parsed.relay_tunnels, u32::MAX);
}

#[test]
fn relay_bytes_saturate_when_summed() {
    let parsed = NebulaStats::parse_prometheus(&format!(
        "nebula_relay_bytes_total {}\nnebula_relay_tx_bytes_total 99",
        u64::MAX
    ))
    .unwrap();
    assert_eq!(parsed.total_bytes_relayed, u64::MAX);
}

#[test]
fn unknown_metrics_do_not_affect_stats() {
    let parsed = NebulaStats::parse_prometheus("custom_metric 99").unwrap();
    assert_eq!(parsed.active_peers, 0);
    assert_eq!(parsed.total_bytes_relayed, 0);
    assert_eq!(parsed.direct_tunnels, 0);
    assert_eq!(parsed.relay_tunnels, 0);
}

#[test]
fn empty_input_returns_default_stats() {
    let parsed = NebulaStats::parse_prometheus("").unwrap();
    assert_eq!(parsed.active_peers, 0);
    assert_eq!(parsed.total_bytes_relayed, 0);
}

#[test]
fn current_mbps_is_not_computed_by_parse_only() {
    let parsed = NebulaStats::parse_prometheus("nebula_relay_bytes_total 1000").unwrap();
    assert_eq!(parsed.current_mbps, 0.0);
}
