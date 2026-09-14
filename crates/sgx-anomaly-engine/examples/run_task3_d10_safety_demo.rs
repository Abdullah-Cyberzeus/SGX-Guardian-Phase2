use sgx_anomaly_engine::network_ai::{
    EligibilityFilter, RouteCandidateInventory, RouteSafetyGuard, RouteSwitchState,
    RuntimeRouteApplyRequest, RuntimeRouteState, SafeRuntimeRouteController, TrafficClass,
    TrustStateSnapshot,
};

fn print_case(name: &str, decision: &sgx_anomaly_engine::network_ai::RouteSafetyDecision) {
    println!(
        "{:<28} verdict={:?} allowed={} hard_failover={} improvement={:.2}% recent_switches={}",
        name,
        decision.verdict,
        decision.allowed,
        decision.hard_failover,
        decision.improvement_pct,
        decision.recent_switches_in_window
    );
}

fn main() {
    let guard = RouteSafetyGuard::default();

    println!("=== D10 SAFETY GUARD VERIFICATION ===");

    let base = RouteSwitchState {
        current_route_id: "direct-nodeA-nodeB".to_string(),
        current_route_started_ms: 0,
        last_switch_ms: Some(10_000),
        switch_timestamps_ms: vec![10_000],
    };

    let same = guard.evaluate(60_000, &base, Some("direct-nodeA-nodeB"), 40.0, 50.0);
    print_case("same-route", &same);

    let small = guard.evaluate(
        60_000,
        &base,
        Some("relay-nodeA-via-nodeC-nodeB"),
        48.0,
        50.0,
    );
    print_case("small-improvement", &small);

    let hold_state = RouteSwitchState {
        current_route_started_ms: 50_000,
        last_switch_ms: None,
        switch_timestamps_ms: vec![],
        ..base.clone()
    };
    let hold = guard.evaluate(
        60_000,
        &hold_state,
        Some("relay-nodeA-via-nodeC-nodeB"),
        40.0,
        50.0,
    );
    print_case("hold-time-active", &hold);

    let cooldown_state = RouteSwitchState {
        current_route_started_ms: 0,
        last_switch_ms: Some(50_000),
        switch_timestamps_ms: vec![50_000],
        ..base.clone()
    };
    let cooldown = guard.evaluate(
        60_000,
        &cooldown_state,
        Some("relay-nodeA-via-nodeC-nodeB"),
        40.0,
        50.0,
    );
    print_case("cooldown-active", &cooldown);

    let flap_state = RouteSwitchState {
        current_route_started_ms: 0,
        last_switch_ms: Some(10_000),
        switch_timestamps_ms: vec![1_000, 2_000, 3_000, 4_000, 5_000, 6_000],
        ..base.clone()
    };
    let flap = guard.evaluate(
        60_000,
        &flap_state,
        Some("relay-nodeA-via-nodeC-nodeB"),
        40.0,
        50.0,
    );
    print_case("too-many-switches", &flap);

    let allowed = guard.evaluate(
        60_000,
        &base,
        Some("relay-nodeA-via-nodeC-nodeB"),
        40.0,
        50.0,
    );
    print_case("normal-safe-switch", &allowed);

    let failover = guard.evaluate_with_route_health(
        60_000,
        &cooldown_state,
        Some("relay-nodeA-via-nodeC-nodeB"),
        40.0,
        35.0,
        true,
    );
    print_case("hard-failover", &failover);

    println!();
    println!("=== D10 RUNTIME CONTROLLER VERIFICATION ===");

    let inventory = RouteCandidateInventory::from_relays(
        "nodeA",
        "nodeB",
        TrafficClass::SecurityControl,
        ["nodeC"],
    );

    let trust = TrustStateSnapshot::new("d10-trust")
        .trust_peer("nodeB")
        .trust_peer("nodeC");

    let eligible = EligibilityFilter.filter(inventory.candidates, &trust);

    let mut state = RuntimeRouteState::from_switch_state(&RouteSwitchState {
        current_route_id: "direct-nodeA-nodeB".to_string(),
        current_route_started_ms: 0,
        last_switch_ms: Some(10_000),
        switch_timestamps_ms: vec![10_000],
    });

    let request = RuntimeRouteApplyRequest {
        ts_ms: 60_000,
        requested_route_id: "relay-nodeA-via-nodeC-nodeB".to_string(),
        current_score: 40.0,
        candidate_score: 50.0,
        current_route_failed: false,
        transport_apply_succeeds: true,
        selected_by: "d10-test".to_string(),
        observed_rtt_ms: 15.0,
        observed_packet_loss_pct: 0.5,
        observed_throughput_mbps: 50.0,
        observed_bandwidth_utilization_pct: 40.0,
        observed_reward: Some(20.0),
    };

    let ok = SafeRuntimeRouteController::default().apply(&mut state, &eligible, &request);

    println!(
        "successful-apply applied={} active={} previous={:?} rollback={:?}",
        ok.audit.apply_result.applied,
        ok.state.active_route_id,
        ok.state.previous_route_id,
        ok.audit.apply_result.rollback_route_id
    );

    let mut failed_state = RuntimeRouteState::from_switch_state(&RouteSwitchState {
        current_route_id: "direct-nodeA-nodeB".to_string(),
        current_route_started_ms: 0,
        last_switch_ms: Some(10_000),
        switch_timestamps_ms: vec![10_000],
    });

    let mut failed_request = request.clone();
    failed_request.transport_apply_succeeds = false;

    let failed_apply =
        SafeRuntimeRouteController::default().apply(&mut failed_state, &eligible, &failed_request);

    println!(
        "transport-failure applied={} active={} rollback={:?} reason={}",
        failed_apply.audit.apply_result.applied,
        failed_apply.state.active_route_id,
        failed_apply.audit.apply_result.rollback_route_id,
        failed_apply.audit.apply_result.reason
    );

    let mut blocked_state = RuntimeRouteState::from_switch_state(&RouteSwitchState {
        current_route_id: "direct-nodeA-nodeB".to_string(),
        current_route_started_ms: 0,
        last_switch_ms: Some(10_000),
        switch_timestamps_ms: vec![10_000],
    });

    let mut blocked_request = request.clone();
    blocked_request.requested_route_id = "relay-nodeA-via-nodeZ-nodeB".to_string();

    let blocked = SafeRuntimeRouteController::default().apply(
        &mut blocked_state,
        &eligible,
        &blocked_request,
    );

    println!(
        "untrusted-route applied={} verdict={:?} active={}",
        blocked.audit.apply_result.applied,
        blocked.audit.safety_decision.verdict,
        blocked.state.active_route_id
    );
}
