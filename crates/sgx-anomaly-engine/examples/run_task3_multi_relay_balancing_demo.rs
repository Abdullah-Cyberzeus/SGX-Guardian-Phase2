use anyhow::{Context, Result};
use sgx_anomaly_engine::network_ai::{
    EligibilityFilter, MultiRelayLoadBalancer, RelayRuntimeHealth, RouteCandidateInventory,
    RouteHistoryEntry, RouteHistoryStore, RoutePredictor, SimpleRouteQualityPredictor,
    TrafficClass, TrustStateSnapshot,
};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let out_dir = PathBuf::from("data/network_ai/task3_deliverable_13_demo");
    fs::create_dir_all(&out_dir).context("creating D13 demo output directory")?;

    let inventory = RouteCandidateInventory::from_relays(
        "nodeA",
        "nodeB",
        TrafficClass::SecurityControl,
        ["nodeC", "nodeD", "nodeE"],
    );
    let eligible = EligibilityFilter.filter(
        inventory.candidates.clone(),
        &TrustStateSnapshot::new("task2-trust-demo-v1")
            .trust_peer("nodeB")
            .trust_peer("nodeC")
            .trust_peer("nodeD")
            .trust_peer("nodeE"),
    );
    let mut history = RouteHistoryStore::new(1.0, 10);
    for (route_id, rtt, loss, throughput) in [
        ("relay-nodeA-via-nodeC-nodeB", 12.0, 0.2, 75.0),
        ("relay-nodeA-via-nodeD-nodeB", 16.0, 0.6, 60.0),
        ("relay-nodeA-via-nodeE-nodeB", 20.0, 1.0, 48.0),
    ] {
        history.record(RouteHistoryEntry {
            ts_ms: 1_000,
            route_id: route_id.to_string(),
            rtt_ms: rtt,
            packet_loss_pct: loss,
            throughput_mbps: throughput,
            bandwidth_utilization_pct: 30.0,
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
    }
    let predictions = SimpleRouteQualityPredictor::default().predict(&eligible.eligible, &history);
    let health = vec![
        RelayRuntimeHealth {
            route_id: "relay-nodeA-via-nodeC-nodeB".into(),
            available: true,
            healthy: true,
            utilization_pct: 35.0,
            recovered_at_ms: None,
        },
        RelayRuntimeHealth {
            route_id: "relay-nodeA-via-nodeD-nodeB".into(),
            available: true,
            healthy: true,
            utilization_pct: 97.0,
            recovered_at_ms: None,
        },
        RelayRuntimeHealth {
            route_id: "relay-nodeA-via-nodeE-nodeB".into(),
            available: true,
            healthy: true,
            utilization_pct: 25.0,
            recovered_at_ms: Some(59_000),
        },
    ];
    let weights = MultiRelayLoadBalancer::default().calculate_with_health(
        &eligible.eligible,
        &predictions,
        TrafficClass::SecurityControl,
        &health,
        60_000,
    );
    fs::write(
        out_dir.join("relay_weights.json"),
        serde_json::to_string_pretty(&weights)?,
    )?;

    println!("==========================================================================");
    println!("TASK 3 - MULTI-RELAY LOAD BALANCING (DELIVERABLE 13)");
    println!("==========================================================================");
    println!("Task2 trust filtering happened before this calculation.");
    println!(
        "{:<44} {:<5} {:<8} {:<8} {:<8} Reason",
        "Route", "Rank", "Weight", "Overload", "Recovery"
    );
    println!("{}", "-".repeat(135));
    for weight in &weights.weights {
        println!(
            "{:<44} {:<5} {:<8.4} {:<8.2} {:<8.2} {}",
            weight.route_id,
            weight.rank,
            weight.weight,
            weight.overload_factor,
            weight.recovery_factor,
            weight.reason
        );
    }
    println!("Total stable weight: {:.4}", weights.total_weight);
    println!("Overloaded relay nodeD is down-weighted; newly recovered nodeE ramps gradually.");
    println!("Saved: {}", out_dir.join("relay_weights.json").display());
    Ok(())
}
