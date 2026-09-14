use anyhow::Result;
use sgx_anomaly_engine::{
    network_ai::{
        NetworkAiConfig, NetworkAiRuntime, NetworkAiSourceTickInput, RouteSwitchState,
        RuntimeRouteState, TrafficClass,
    },
    RawSample,
};

fn main() -> Result<()> {
    let mut runtime = NetworkAiRuntime::new(
        NetworkAiConfig::default(),
        RuntimeRouteState::from_switch_state(&RouteSwitchState {
            current_route_id: "direct-nodeA-nodeB".into(),
            current_route_started_ms: 0,
            last_switch_ms: None,
            switch_timestamps_ms: vec![],
        }),
    );
    runtime.start();
    let result = runtime.tick_from_sources(NetworkAiSourceTickInput {
        raw: RawSample {
            ts_ms: 1789000000000,
            nebula_mbps: 40.0,
            relay_ratio: 0.2,
            cot_latency_avg_ms: 12.0,
            ..Default::default()
        },
        source_node: "nodeA".into(),
        destination_node: "nodeB".into(),
        relay_nodes: vec!["nodeC".into(), "nodeD".into()],
        traffic_class: TrafficClass::Operational,
        task1_recommendation_path: None,
        task2_trust_summary_path: Some(
            "data/virtual_shift/15_ROUTING_TRUST_STATE/nodeB/routing_trust_summary.json".into(),
        ),
        evidence_root: "data/network_ai/d17_source_runtime_demo".into(),
        requested_route_id: None,
        sensitive_handoff: None,
    })?;
    println!(
        "D17 source runtime tick: applied={}, decision={}",
        result.applied,
        result.runtime_state.latest_mode_decision.unwrap().reason
    );
    Ok(())
}
