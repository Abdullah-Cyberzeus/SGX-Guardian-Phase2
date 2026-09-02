//! Combined VS19 + VS20 demo: build an audit timeline, then verify the
//! complete saved member lifecycle without mutating policy state.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{AuditService, FinalHardeningVerifier, VShiftAlert};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_audit_final_demo -- <vshift_alert.json> <member-node>"
    ))?;
    let member = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("member node is required"))?;
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;

    let audit = AuditService::new("data/virtual_shift").build_and_write(member, &alert, now)?;
    let report =
        FinalHardeningVerifier::new("data/virtual_shift").verify_and_write(member, &alert, now)?;

    println!("==========================================================================");
    println!("TASK 2 - VS19 AUDIT + VS20 FINAL VERIFICATION");
    println!("==========================================================================");
    println!("Member                 : {}", report.member_id);
    println!("Alert ID               : {}", report.alert_id);
    println!("Policy version         : {}", report.policy_version);
    println!("\nVS19 AUDIT EVIDENCE");
    for step in &audit.steps {
        println!(
            "  {:<8} {}",
            if step.present { "OK" } else { "MISSING" },
            step.stage
        );
    }
    println!("\nVS20 FINAL CHECK");
    println!(
        "  Alert signature/hash : {}",
        report.alert_signature_and_hash_valid
    );
    println!("  Audit complete       : {}", report.audit_complete);
    println!("  Policy applied       : {}", report.policy_applied);
    println!("  Identity rotated     : {}", report.identity_rotated);
    println!(
        "  Re-attestation trusted: {}",
        report.re_attestation_trusted
    );
    println!(
        "  STATUS               : {}",
        report.status.to_ascii_uppercase()
    );
    if !report.missing_stages.is_empty() {
        println!(
            "  Missing/failed       : {}",
            report.missing_stages.join(", ")
        );
    }
    println!(
        "\nAudit JSON  : data/virtual_shift/VS19_AUDIT/{}/{}/audit_trail.json",
        member, alert.alert_id
    );
    println!(
        "VS20 JSON   : data/virtual_shift/VS20_FINAL_VERIFICATION/{}/{}/vs20_report.json",
        member, alert.alert_id
    );
    Ok(())
}
