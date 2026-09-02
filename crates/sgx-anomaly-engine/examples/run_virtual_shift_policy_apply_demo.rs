//! VS17 demonstration: activate one already VS16-verified alert locally.

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{MemberPolicyApplier, PolicyApplyStatus, VShiftAlert};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let alert_path = args.first().ok_or_else(|| anyhow::anyhow!("usage: cargo run --example run_virtual_shift_policy_apply_demo -- <vshift_alert.json> <nodeB|nodeC>"))?;
    let member = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("receiving member ID is required"))?;
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(alert_path)?)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let applier = MemberPolicyApplier::new(
        "config/active_virtual_shift_policy.json",
        "data/virtual_shift/VS16_MEMBER_VERIFICATION",
        "data/virtual_shift/VS17_MEMBER_POLICY_STATE",
    );
    let result = applier.apply_verified_alert(member, &alert, now)?;
    println!("==========================================================================");
    println!("TASK 2 - VS17 SAFE MEMBER POLICY APPLY");
    println!("==========================================================================");
    println!("Receiving member       : {}", result.member_id);
    println!("Alert ID               : {}", result.alert_id);
    println!("Policy version          : {}", result.policy_version);
    println!("Result                 : {:?}", result.status);
    println!("Reason                 : {}", result.reason);
    println!(
        "Backup                 : {}",
        result.backup_path.as_deref().unwrap_or("not created")
    );
    println!("Member active policy   : {}", result.active_policy_path);
    println!(
        "Policy folder          : data/virtual_shift/VS17_MEMBER_POLICY_STATE/{}/policies",
        result.member_id
    );
    println!(
        "Previous policy history : data/virtual_shift/08_MEMBER_ACTIVE_POLICIES/{}/backup_history",
        result.member_id
    );
    println!(
        "Apply record            : data/virtual_shift/08_MEMBER_ACTIVE_POLICIES/{}/policy_deliveries/{}",
        result.member_id, result.alert_id
    );
    println!(
        "Apply JSON             : data/virtual_shift/VS17_MEMBER_POLICY_STATE/{}/{}/apply_result.json",
        result.member_id, result.alert_id
    );
    match result.status { PolicyApplyStatus::Applied => println!("SAFE STOP: local policy state updated. No firewall/OS command is executed by this standalone demo."), PolicyApplyStatus::Rejected => println!("STOP: VS17 did not apply an unverified or stale policy."), PolicyApplyStatus::RolledBack => println!("SAFE STOP: activation failed; prior policy was restored from backup.") }
    Ok(())
}
