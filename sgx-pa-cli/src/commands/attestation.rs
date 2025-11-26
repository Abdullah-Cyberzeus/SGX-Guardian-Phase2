use anyhow::Result;
use serde::Deserialize;
use std::fs;

/// Represents the most recent attestation record written by an SG-X node,
/// including peer identity, policy digest, result status, and timestamp.
#[derive(Deserialize)]
struct LastAttestation {
    peer_id: String,
    policy_digest: String,
    result: String,
    timestamp: String,
}

/// Reads the last attestation result from the logs directory and prints it
/// in a human-readable format. Handles missing or malformed data gracefully.
pub fn run() -> Result<()> {
    let data = fs::read_to_string("../logs/last_attestation.json")
        .or_else(|_| fs::read_to_string("logs/last_attestation.json"))
        .unwrap_or_else(|_| "{}".to_string());

    if data.trim().is_empty() {
        println!("No attestation results recorded yet.");
        return Ok(());
    }

    let record: LastAttestation = serde_json::from_str(&data).unwrap_or_else(|_| LastAttestation {
        peer_id: "unknown".to_string(),
        policy_digest: "-".to_string(),
        result: "N/A".to_string(),
        timestamp: "-".to_string(),
    });

    println!("Attestation Result:");
    println!("Peer ID: {}", record.peer_id);
    println!("Policy Digest: {}", record.policy_digest);
    println!("Result: {}", record.result);
    println!("Timestamp: {}", record.timestamp);

    Ok(())
}
