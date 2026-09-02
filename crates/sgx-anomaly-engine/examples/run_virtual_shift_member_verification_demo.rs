//! VS16 demonstration: one Circle member receives and verifies one saved
//! VSHIFT_ALERT. It writes durable member verification evidence and never
//! applies a policy (VS17 remains the enforcement boundary).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{MemberAlertVerifier, VShiftAlert, VerificationStatus};

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let alert_path = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_member_verification_demo -- <vshift_alert.json> <nodeB|nodeC>"
    ))?;
    let member = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("receiving member ID is required"))?;
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(alert_path)?)?;
    let verifier = MemberAlertVerifier::from_config(
        "config/circle_guardian_authorization.json",
        "data/virtual_shift/VS16_MEMBER_VERIFICATION",
    )?;
    let result = verifier.verify_and_record(member, &alert, now_ms()?)?;

    println!("==========================================================================");
    println!("TASK 2 - VS16 RECEIVING MEMBER VERIFICATION");
    println!("==========================================================================");
    println!("Receiving member       : {}", result.member_id);
    println!("Alert ID               : {}", result.alert_id);
    println!("Circle                 : {}", result.circle_id);
    println!("Guardian signer        : {}", result.signer_id);
    println!("Policy version          : {}", result.policy_version);
    println!("Result                 : {:?}", result.status);
    println!("Reason                 : {}", result.reason);
    println!(
        "Verification JSON      : data/virtual_shift/VS16_MEMBER_VERIFICATION/{}/{}/verification.json",
        result.member_id, result.alert_id
    );
    match result.status {
        VerificationStatus::VerifiedNotApplied => {
            println!("STOP: alert is verified, but VS17 policy application has NOT run.");
        }
        VerificationStatus::AlreadyVerified => {
            println!("STOP: replay ignored; the original accepted VS16 proof remains available for VS17.");
        }
        VerificationStatus::Rejected => {
            println!("STOP: rejected before enforcement; no policy state was changed.");
        }
    }
    Ok(())
}
