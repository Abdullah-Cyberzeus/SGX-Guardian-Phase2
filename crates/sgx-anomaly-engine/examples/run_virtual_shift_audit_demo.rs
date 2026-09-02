use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{AuditService, VShiftAlert};
use std::time::{SystemTime, UNIX_EPOCH};
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args.first().ok_or_else(|| anyhow::anyhow!("usage: cargo run --example run_virtual_shift_audit_demo -- <vshift_alert.json> <member-node>"))?;
    let member = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("member node is required"))?;
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let audit = AuditService::new("data/virtual_shift").build_and_write(member, &alert, now)?;
    println!(
        "TASK 2 - VS19 AUDIT TRAIL\nMember: {} | Alert: {}",
        audit.member_id, audit.alert_id
    );
    for step in audit.steps {
        println!(
            "{}: {}",
            if step.present { "OK" } else { "MISSING" },
            step.stage
        );
    }
    println!(
        "Saved: data/virtual_shift/VS19_AUDIT/{}/{}/audit_trail.json",
        audit.member_id, audit.alert_id
    );
    Ok(())
}
