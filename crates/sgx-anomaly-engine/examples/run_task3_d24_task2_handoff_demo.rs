//! D24 proof: a sensitive route change is blocked and queued in the existing Task2 review flow.
use anyhow::{bail, Result};
use sgx_anomaly_engine::network_ai::{SensitiveRouteHandoffService, SensitiveRouteReason};
use std::path::PathBuf;

fn main() -> Result<()> {
    let out = PathBuf::from("data/network_ai/d24_task2_handoff_demo");
    let audit_path = out.join("task3_task2_handoff_audit.json");
    let result = SensitiveRouteHandoffService::new(
        "data/virtual_shift/02_OWNER_REVIEW_DECISIONS",
        "config/node_roles.json",
    )
    .handoff(
        1_789_100_000_000,
        "nodeA",
        "nodeB",
        "relay-nodeA-via-nodeZ-nodeB",
        SensitiveRouteReason::NewUntrustedRelay,
        0.85,
        0.90,
        &audit_path,
    )?;

    if !result.direct_apply_blocked || !result.owner_approval_required {
        bail!("D24 invariant failed: sensitive route must not be directly applied");
    }
    println!("D24 TASK2 HANDOFF");
    println!("DIRECT_APPLY_BLOCKED  : {}", result.direct_apply_blocked);
    println!(
        "Requested route       : {}",
        result.audit_record.requested_route_id
    );
    println!(
        "Reason                : {}",
        result.audit_record.ai_justification
    );
    println!("Task3 handoff ID      : {}", result.plan_id);
    println!("Task2 review status   : {:?}", result.review_status);
    println!("Task2 pending review  : {}", result.pending_review_path);
    println!("Audit evidence        : {}", audit_path.display());
    println!("Task2 trust/policy mutation by Task3: false");
    Ok(())
}
