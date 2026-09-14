use sgx_anomaly_engine::network_ai::classify_message_type;

fn main() {
    let cases = [
        "VSHIFT_ALERT",
        "virtual_shift_alert",
        "attestation",
        "attestation_challenge",
        "attestation_response",
        "policy-verification",
        "crl",
        "telemetry",
        "heartbeat",
        "runtime_metrics",
        "health",
        "unknown-message-type",
    ];

    println!("TASK3 D2 - TRAFFIC CLASSIFICATION VERIFICATION");
    println!("{:<28} {:<24} {:<18}", "Input", "TrafficClass", "Priority");
    println!("{}", "-".repeat(74));

    for input in cases {
        let (msg_type, traffic, priority) = classify_message_type(input);

        println!(
            "{:<28} {:<24?} {:<18?} ({:?})",
            input, traffic, priority, msg_type
        );
    }
}
