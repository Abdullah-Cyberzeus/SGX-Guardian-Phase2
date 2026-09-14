//! Bounded D17 runtime proof: two fresh Task2-filtered inputs are supplied to
//! the Guardian-facing Task3 runtime. It exits after the requested tick count.

use anyhow::Result;
use sgx_anomaly_engine::network_ai::{
    EligibilityFilter, NetworkAiConfig, NetworkAiRuntime, RouteCandidateInventory,
    RouteSwitchState, RuntimeRouteApplyRequest, RuntimeRouteState, TrafficClass,
    TrustStateSnapshot,
};
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let config_path = args
        .windows(2)
        .find(|pair| pair[0] == "--config")
        .map(|pair| PathBuf::from(&pair[1]));
    let config = match config_path {
        Some(path) => NetworkAiConfig::load_json(path)?,
        None => NetworkAiConfig::default(),
    };
    let route_state = RuntimeRouteState::from_switch_state(&RouteSwitchState {
        current_route_id: "direct-nodeA-nodeB".into(),
        current_route_started_ms: 0,
        last_switch_ms: None,
        switch_timestamps_ms: vec![],
    });
    let mut runtime = NetworkAiRuntime::new(config.clone(), route_state);
    runtime.start();
    let inputs = [100_000_u64, 101_000]
        .into_iter()
        .map(|ts_ms| {
            let candidates = RouteCandidateInventory::from_relays(
                "nodeA",
                "nodeB",
                TrafficClass::Operational,
                ["nodeC"],
            )
            .candidates;
            let fresh_eligible_routes = EligibilityFilter.filter_at(
                candidates,
                &TrustStateSnapshot::new(format!("task2-trust-{ts_ms}"))
                    .trust_peer("nodeB")
                    .trust_peer("nodeC"),
                ts_ms,
            );
            sgx_anomaly_engine::network_ai::NetworkAiRuntimeTickInput {
                fresh_eligible_routes,
                apply_request: RuntimeRouteApplyRequest {
                    ts_ms,
                    requested_route_id: "relay-nodeA-via-nodeC-nodeB".into(),
                    current_score: 10.0,
                    candidate_score: 30.0,
                    current_route_failed: false,
                    transport_apply_succeeds: true,
                    selected_by: "d17-runtime-demo".into(),
                    observed_rtt_ms: 10.0,
                    observed_packet_loss_pct: 0.1,
                    observed_throughput_mbps: 50.0,
                    observed_bandwidth_utilization_pct: 20.0,
                    observed_reward: None,
                },
            }
        })
        .collect();
    let results = tokio::runtime::Runtime::new()?.block_on(runtime.run_for_ticks(inputs));
    let evidence = PathBuf::from("data/network_ai/d17_runtime_demo/runtime.json");
    runtime.save_state_json(&evidence)?;
    runtime.stop();
    println!("TASK 3 D17 BOUNDED RUNTIME");
    println!("Config version : {}", config.config_version);
    println!("Mode           : {:?}", config.mode);
    println!("Ticks run      : {}", results.len());
    println!(
        "Applied        : {}",
        results.iter().any(|result| result.applied)
    );
    println!("Latest Task2   : fresh trust snapshot supplied per tick");
    println!("Runtime state  : {}", evidence.display());
    Ok(())
}
