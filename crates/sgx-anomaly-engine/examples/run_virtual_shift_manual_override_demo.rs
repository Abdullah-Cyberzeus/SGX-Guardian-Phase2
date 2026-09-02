use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{GuardianKeyManager, ManualOverrideService, VShiftAlert};
use std::time::{SystemTime, UNIX_EPOCH};
fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 4 {
        anyhow::bail!("usage: cargo run --example run_virtual_shift_manual_override_demo -- <vshift_alert.json> <member-node> <owner-node> <reason>");
    }
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(&a[0])?)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let service = ManualOverrideService::from_role_config(
        "data/virtual_shift/VS17_MEMBER_POLICY_STATE",
        "data/virtual_shift/VS19_OVERRIDES",
        "config/node_roles.json",
    )?;
    let signer = GuardianKeyManager::from_config(
        "config/guardian_signer.json",
        "data/virtual_shift/guardian_keys",
    )?;
    let r = service.create_signed_revert(&a[2], &a[1], &alert, &a[3], now, &signer)?;
    println!("TASK 2 - VS19 MANUAL FALSE-POSITIVE OVERRIDE\nOwner: {}\nMember: {}\nOriginal policy: v{}\nReplacement policy: v{}\nStatus: {}\nSaved: data/virtual_shift/VS19_OVERRIDES/{}/override_record.json", r.owner_id, r.member_id, r.original_policy_version, r.replacement_policy_version, r.status, r.override_id);
    Ok(())
}
