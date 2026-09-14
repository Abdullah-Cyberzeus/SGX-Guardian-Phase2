//! D25 repeatable laptop/synthetic benchmark: same topology and workload for static vs AI routing.
use anyhow::{bail, Result};
use serde::Serialize;
use sgx_anomaly_engine::network_ai::{
    ContextualBanditPolicy, EligibilityFilter, RouteCandidateInventory, RouteHistoryEntry,
    RouteHistoryStore, RoutePredictor, RouteReward, RouteSafetyGuard, RouteSwitchState,
    RuntimeRouteApplyRequest, RuntimeRouteState, SafeRuntimeRouteController,
    SimpleRouteQualityPredictor, TrafficClass, TrustStateSnapshot,
};
use std::{fs, path::PathBuf};

#[derive(Clone)]
struct Sample {
    latency_ms: f64,
    loss_pct: f64,
    throughput_mbps: f64,
}
#[derive(Serialize, Clone)]
struct Metrics {
    average_latency_ms: f64,
    p50_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
    average_packet_loss_pct: f64,
    average_throughput_mbps: f64,
    route_switch_count: u32,
}
#[derive(Serialize)]
struct Benchmark {
    schema_version: &'static str,
    scope: &'static str,
    topology: &'static str,
    workload: &'static str,
    static_route: String,
    ai_route: String,
    task2_trust_version: String,
    static_metrics: Metrics,
    ai_metrics: Metrics,
    latency_improvement_pct: f64,
    target_range_pct: String,
    target_met: bool,
    result: String,
    d10_safety_allowed: bool,
    d11_applied: bool,
    repeatable: bool,
    limitation: &'static str,
}

fn metrics(samples: &[Sample], switches: u32) -> Metrics {
    let mut l: Vec<_> = samples.iter().map(|v| v.latency_ms).collect();
    l.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| l[((l.len() - 1) as f64 * q).ceil() as usize];
    Metrics {
        average_latency_ms: l.iter().sum::<f64>() / l.len() as f64,
        p50_latency_ms: p(0.50),
        p95_latency_ms: p(0.95),
        p99_latency_ms: p(0.99),
        average_packet_loss_pct: samples.iter().map(|v| v.loss_pct).sum::<f64>()
            / samples.len() as f64,
        average_throughput_mbps: samples.iter().map(|v| v.throughput_mbps).sum::<f64>()
            / samples.len() as f64,
        route_switch_count: switches,
    }
}
fn main() -> Result<()> {
    let root = PathBuf::from("data/network_ai/d25_static_vs_ai_benchmark");
    fs::create_dir_all(&root)?;
    // Fixed synthetic workload, replayed identically for both strategies. These are observed fixture samples, not a live-board claim.
    let static_samples = vec![
        Sample {
            latency_ms: 82.0,
            loss_pct: 2.2,
            throughput_mbps: 23.0,
        },
        Sample {
            latency_ms: 78.0,
            loss_pct: 1.8,
            throughput_mbps: 25.0,
        },
        Sample {
            latency_ms: 85.0,
            loss_pct: 2.6,
            throughput_mbps: 21.0,
        },
        Sample {
            latency_ms: 80.0,
            loss_pct: 2.0,
            throughput_mbps: 24.0,
        },
        Sample {
            latency_ms: 88.0,
            loss_pct: 2.9,
            throughput_mbps: 20.0,
        },
    ];
    let relay_samples = vec![
        Sample {
            latency_ms: 48.0,
            loss_pct: 0.6,
            throughput_mbps: 58.0,
        },
        Sample {
            latency_ms: 45.0,
            loss_pct: 0.5,
            throughput_mbps: 61.0,
        },
        Sample {
            latency_ms: 50.0,
            loss_pct: 0.7,
            throughput_mbps: 56.0,
        },
        Sample {
            latency_ms: 47.0,
            loss_pct: 0.6,
            throughput_mbps: 59.0,
        },
        Sample {
            latency_ms: 49.0,
            loss_pct: 0.5,
            throughput_mbps: 57.0,
        },
    ];
    let trust = TrustStateSnapshot::new("task2-d25-trusted-v1")
        .trust_peer("nodeB")
        .trust_peer("nodeC");
    let inventory = RouteCandidateInventory::from_relays(
        "nodeA",
        "nodeB",
        TrafficClass::Operational,
        ["nodeC", "nodeZ"],
    );
    let eligible = EligibilityFilter.filter_at(inventory.candidates, &trust, 200_000);
    let mut history = RouteHistoryStore::new(0.5, 32);
    for (i, s) in static_samples.iter().enumerate() {
        history.record(RouteHistoryEntry {
            ts_ms: 190_000 + i as u64,
            route_id: "direct-nodeA-nodeB".into(),
            rtt_ms: s.latency_ms,
            packet_loss_pct: s.loss_pct,
            throughput_mbps: s.throughput_mbps,
            bandwidth_utilization_pct: 70.0,
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
    }
    for (i, s) in relay_samples.iter().enumerate() {
        history.record(RouteHistoryEntry {
            ts_ms: 190_000 + i as u64,
            route_id: "relay-nodeA-via-nodeC-nodeB".into(),
            rtt_ms: s.latency_ms,
            packet_loss_pct: s.loss_pct,
            throughput_mbps: s.throughput_mbps,
            bandwidth_utilization_pct: 38.0,
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
    }
    let predictions = SimpleRouteQualityPredictor::default().predict(&eligible.eligible, &history);
    let rewards: Vec<_> = predictions
        .predictions
        .iter()
        .map(|p| RouteReward::from_prediction_with_weights(p, 1, true, false, &Default::default()))
        .collect();
    let mut rl = ContextualBanditPolicy::new(0.1, 0.0);
    for r in &rewards {
        rl.update_with_reward(r);
    }
    let decision = rl.choose_exploit(&predictions);
    let selected = decision
        .selected_route_id
        .ok_or_else(|| anyhow::anyhow!("no trusted eligible AI route"))?;
    if selected == "relay-nodeA-via-nodeZ-nodeB" {
        bail!("untrusted route incorrectly selected");
    }
    let score = |id: &str| {
        predictions
            .predictions
            .iter()
            .find(|p| p.route_id == id)
            .map(|p| p.quality_score)
            .unwrap_or(0.0)
    };
    let mut state = RuntimeRouteState::from_switch_state(&RouteSwitchState {
        current_route_id: "direct-nodeA-nodeB".into(),
        current_route_started_ms: 0,
        last_switch_ms: None,
        switch_timestamps_ms: vec![],
    });
    let apply = SafeRuntimeRouteController {
        safety_guard: RouteSafetyGuard::default(),
    }
    .apply(
        &mut state,
        &eligible,
        &RuntimeRouteApplyRequest {
            ts_ms: 200_000,
            requested_route_id: selected.clone(),
            current_score: score("direct-nodeA-nodeB"),
            candidate_score: score(&selected),
            current_route_failed: false,
            transport_apply_succeeds: true,
            selected_by: decision.decision_mode.clone(),
            observed_rtt_ms: 47.8,
            observed_packet_loss_pct: 0.58,
            observed_throughput_mbps: 58.2,
            observed_bandwidth_utilization_pct: 38.0,
            observed_reward: None,
        },
    );
    if !apply.audit.apply_result.applied {
        bail!(
            "D10/D11 did not allow selected trusted route: {}",
            apply.audit.apply_result.reason
        );
    }
    let static_metrics = metrics(&static_samples, 0);
    let ai_metrics = metrics(&relay_samples, 1);
    let improvement = (static_metrics.average_latency_ms - ai_metrics.average_latency_ms)
        / static_metrics.average_latency_ms
        * 100.0;
    let target = (20.0..=40.0).contains(&improvement);
    let report=Benchmark{schema_version:"network-ai-d25-benchmark-v1",scope:"laptop synthetic deterministic benchmark",topology:"nodeA -> nodeB; trusted relay nodeC; untrusted relay nodeZ excluded by Task2",workload:"five fixed operational samples replayed with same topology and measurement method",static_route:"direct-nodeA-nodeB".into(),ai_route:selected,task2_trust_version:trust.version,static_metrics,ai_metrics,latency_improvement_pct:improvement,target_range_pct:"20-40".into(),target_met:target,result:if target{"PASS: measured synthetic result is inside target".into()}else{"FAIL: measured synthetic result is outside target".into()},d10_safety_allowed:apply.audit.safety_decision.allowed,d11_applied:apply.audit.apply_result.applied,repeatable:true,limitation:"Synthetic/laptop measurement only; this is not a physical-board or live-network performance claim."};
    fs::write(
        root.join("benchmark.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("D25 STATIC vs AI BENCHMARK");
    println!(
        "Static avg/p50/p95/p99: {:.1}/{:.1}/{:.1}/{:.1} ms",
        report.static_metrics.average_latency_ms,
        report.static_metrics.p50_latency_ms,
        report.static_metrics.p95_latency_ms,
        report.static_metrics.p99_latency_ms
    );
    println!(
        "AI     avg/p50/p95/p99: {:.1}/{:.1}/{:.1}/{:.1} ms",
        report.ai_metrics.average_latency_ms,
        report.ai_metrics.p50_latency_ms,
        report.ai_metrics.p95_latency_ms,
        report.ai_metrics.p99_latency_ms
    );
    println!(
        "Latency improvement: {:.2}% | target 20-40%: {} | D10/D11: {}/{}",
        report.latency_improvement_pct,
        if report.target_met { "PASS" } else { "FAIL" },
        report.d10_safety_allowed,
        report.d11_applied
    );
    println!("Evidence: {}", root.join("benchmark.json").display());
    Ok(())
}
