//! Demo-only re-attestation connector. Replace it with a board adapter later.

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    MockAttestationConnector, MockAttestationOutcome, ReAttestationService, ReAttestationStatus,
    VShiftAlert,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let alert_path = args.first().ok_or_else(|| anyhow::anyhow!("usage: cargo run --example run_virtual_shift_mock_attestation_demo -- <vshift_alert.json> <member-node> <pass|fail>"))?;
    let member = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("member node is required"))?;
    let outcome = match args.get(2).map(String::as_str) {
        Some("pass") => MockAttestationOutcome::Pass,
        Some("fail") => MockAttestationOutcome::Fail,
        _ => anyhow::bail!("mock outcome must be pass or fail"),
    };
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(alert_path)?)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let result = ReAttestationService::new("data/virtual_shift/VS18_MEMBER_IDENTITY_STATE")
        .complete_after_rotation(
            member,
            &alert,
            "mock_attestation_connector",
            &MockAttestationConnector::new(outcome),
            now,
        )?;
    println!("==========================================================================");
    println!("TASK 2 - VS18 MOCK RE-ATTESTATION CONNECTOR");
    println!("==========================================================================");
    println!("Member                  : {}", result.member_id);
    println!(
        "VirtualID               : {}",
        result.virtual_id.as_deref().unwrap_or("not used")
    );
    println!("Result                  : {:?}", result.status);
    println!("Connector               : {}", result.connector);
    println!("Reason                  : {}", result.reason);
    println!("Identity state JSON     : {}", result.identity_state_path);
    println!("Attestation JSON        : data/virtual_shift/VS18_MEMBER_IDENTITY_STATE/{}/{}/attestation_result.json", result.member_id, result.alert_id);
    match result.status {
        ReAttestationStatus::Trusted => {
            println!("RESULT: mock proof accepted; member is trusted again.")
        }
        ReAttestationStatus::Failed => {
            println!("RESULT: mock proof failed; member remains untrusted/restricted.")
        }
        ReAttestationStatus::Rejected => {
            println!("STOP: VS18 rotation/re-attestation-required state was not valid.")
        }
    }
    Ok(())
}
