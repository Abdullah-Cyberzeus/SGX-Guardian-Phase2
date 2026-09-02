//! VS18 demonstration: rotate a member VirtualID after successful VS17 apply.

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    IdentityRotationStatus, MemberIdentityRotator, VShiftAlert,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let alert_path = args.first().ok_or_else(|| anyhow::anyhow!("usage: cargo run --example run_virtual_shift_identity_rotation_demo -- <vshift_alert.json> <member-node>"))?;
    let member = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("member node is required"))?;
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(alert_path)?)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let rotator = MemberIdentityRotator::new(
        "data/virtual_shift/VS17_MEMBER_POLICY_STATE",
        "data/virtual_shift/VS18_MEMBER_IDENTITY_STATE",
    );
    let result = rotator.rotate_after_applied_policy(member, &alert, now)?;
    println!("==========================================================================");
    println!("TASK 2 - VS18 VIRTUALID ROTATION + RE-ATTESTATION");
    println!("==========================================================================");
    println!("Member                  : {}", result.member_id);
    println!("Alert ID                : {}", result.alert_id);
    println!("Policy version          : {}", result.policy_version);
    println!("Result                  : {:?}", result.status);
    println!(
        "Old VirtualID           : {}",
        result.old_virtual_id.as_deref().unwrap_or("not changed")
    );
    println!(
        "New VirtualID           : {}",
        result.new_virtual_id.as_deref().unwrap_or("not issued")
    );
    println!("Attestation state       : {:?}", result.attestation_state);
    println!("Reason                  : {}", result.reason);
    println!("Identity state JSON     : {}", result.identity_state_path);
    println!("Rotation evidence JSON  : data/virtual_shift/VS18_MEMBER_IDENTITY_STATE/{}/{}/rotation_result.json", result.member_id, result.alert_id);
    match result.status {
        IdentityRotationStatus::RotatedReAttestationRequired => println!(
            "NEXT: member must complete fresh attestation before the new identity is trusted."
        ),
        IdentityRotationStatus::Rejected => println!("STOP: identity was not changed."),
    }
    Ok(())
}
