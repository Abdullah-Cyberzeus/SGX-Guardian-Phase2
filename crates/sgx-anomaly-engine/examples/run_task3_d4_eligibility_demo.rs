use sgx_anomaly_engine::network_ai::{
    EligibilityFilter, RouteCandidateInventory, TrafficClass, TrustStateSnapshot,
};

fn main() {
    let inventory = RouteCandidateInventory::from_relays(
        "nodeA",
        "nodeB",
        TrafficClass::SecurityControl,
        ["nodeC", "nodeD"],
    );

    let trust = TrustStateSnapshot::new("d4-test")
        .trust_peer("nodeB")
        .trust_peer("nodeC")
        .trust_peer("nodeD")
        .quarantine_peer("nodeD")
        .prohibit_route("relay-nodeA-via-nodeC-nodeB");

    let result = EligibilityFilter.filter(inventory.candidates, &trust);

    println!("TASK3 D4 - ELIGIBILITY VERIFICATION");
    println!("Eligible:");
    for route in &result.eligible {
        println!("  PASS   {}", route.route_id);
    }

    println!("Rejected:");
    for decision in &result.rejected {
        println!("  REJECT {} -> {:?}", decision.route_id, decision.reason);
    }
}
