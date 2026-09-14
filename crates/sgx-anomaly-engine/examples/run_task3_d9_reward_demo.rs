use sgx_anomaly_engine::network_ai::{
    ContextualBanditPolicy, NetworkAiFeatureVector, RoutePrediction, RouteQualityComponents,
    RouteReward, NETWORK_AI_PREDICTOR_VERSION,
};

fn prediction(route_id: &str, latency: f64, loss: f64, throughput: f64) -> RoutePrediction {
    RoutePrediction {
        route_id: route_id.to_string(),
        model_version: NETWORK_AI_PREDICTOR_VERSION.to_string(),
        expected_latency_ms: latency,
        expected_loss_pct: loss,
        expected_throughput_mbps: throughput,
        confidence: 0.9,
        quality_score: 0.0,
        features: NetworkAiFeatureVector {
            schema_version: "network-ai-v1".to_string(),
            route_id: route_id.to_string(),
            normalized_latency: 0.0,
            normalized_loss: 0.0,
            normalized_throughput: 0.0,
            normalized_utilization: 0.0,
            normalized_hops: 0.0,
            normalized_success_rate: 1.0,
            normalized_failure_rate: 0.0,
            normalized_route_age: 0.0,
            priority: 1.0,
            task1_anomaly_score: 0.0,
            missing_history: false,
            explainability: vec![],
        },
        components: RouteQualityComponents {
            latency_component: 0.0,
            throughput_component: 0.0,
            loss_penalty: 0.0,
            hop_penalty: 0.0,
            failure_penalty: 0.0,
            availability_penalty: 0.0,
            task1_anomaly_component: 0.0,
            total_score: 0.0,
        },
        reason: "D9 manual verification".to_string(),
    }
}

fn main() {
    let good =
        RouteReward::from_prediction(&prediction("good-route", 12.0, 0.2, 80.0), 0, false, false);

    let congested = RouteReward::from_prediction(
        &prediction("congested-route", 85.0, 12.0, 5.0),
        2,
        true,
        false,
    );

    let failed =
        RouteReward::from_prediction(&prediction("failed-route", 85.0, 20.0, 1.0), 2, true, true);

    println!("=== D9 REWARD BEHAVIOR ===");

    for reward in [&good, &congested, &failed] {
        println!();
        println!("route={}", reward.route_id);
        println!("total_reward={}", reward.total_reward);
        println!("latency_reward={}", reward.components.latency_reward);
        println!("throughput_reward={}", reward.components.throughput_reward);
        println!(
            "packet_loss_penalty={}",
            reward.components.packet_loss_penalty
        );
        println!(
            "congestion_penalty={}",
            reward.components.congestion_penalty
        );
        println!("hop_penalty={}", reward.components.hop_penalty);
        println!(
            "route_switch_penalty={}",
            reward.components.route_switch_penalty
        );
        println!("failure_penalty={}", reward.components.failure_penalty);
    }

    let mut policy = ContextualBanditPolicy::default();

    println!();
    println!("=== Q VALUE UPDATES ===");

    for reward in [&good, &congested, &failed] {
        let q = policy.update_with_reward(reward);
        println!(
            "route={} q_value={} update_count={}",
            q.route_id, q.q_value, q.update_count
        );
    }
}
