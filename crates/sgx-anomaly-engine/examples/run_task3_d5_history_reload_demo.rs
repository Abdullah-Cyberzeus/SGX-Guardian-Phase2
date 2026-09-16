use sgx_anomaly_engine::network_ai::{RouteHistoryEntry, RouteHistoryStore};

fn main() -> anyhow::Result<()> {
    let path = "/var/lib/sgx-guardian/data/network_ai/d5_manual_history.json";

    let mut store = RouteHistoryStore::new(0.5, 20);

    store.record(RouteHistoryEntry {
        ts_ms: 1000,
        route_id: "direct-nodeA-nodeB".to_string(),
        rtt_ms: 20.0,
        packet_loss_pct: 1.0,
        throughput_mbps: Some(40.0),
        bandwidth_utilization_pct: Some(30.0),
        route_available: true,
        route_healthy: true,
        switched_route: false,
    });

    store.record(RouteHistoryEntry {
        ts_ms: 2000,
        route_id: "direct-nodeA-nodeB".to_string(),
        rtt_ms: 30.0,
        packet_loss_pct: 3.0,
        throughput_mbps: Some(20.0),
        bandwidth_utilization_pct: Some(50.0),
        route_available: true,
        route_healthy: true,
        switched_route: true,
    });

    store.save_json(path)?;

    println!("PHASE 1: SAVED");
    println!("path={path}");

    drop(store);

    let loaded = RouteHistoryStore::load_json(path)?;
    let stats = loaded
        .stats_for("direct-nodeA-nodeB")
        .expect("route stats missing after reload");

    println!("PHASE 2: RELOADED");
    println!("sample_count={}", stats.sample_count);
    println!("success_count={}", stats.success_count);
    println!("failure_count={}", stats.failure_count);
    println!("switch_count={}", stats.switch_count);
    println!("ewma_latency_ms={}", stats.ewma_latency_ms);
    println!("ewma_loss_pct={}", stats.ewma_loss_pct);
    println!("ewma_throughput_mbps={}", stats.ewma_throughput_mbps);
    println!("success_rate={}", stats.success_rate);

    Ok(())
}
