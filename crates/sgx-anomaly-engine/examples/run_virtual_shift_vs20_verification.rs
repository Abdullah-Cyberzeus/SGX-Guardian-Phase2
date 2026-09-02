use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{FinalHardeningVerifier, VShiftAlert};
use std::time::{SystemTime, UNIX_EPOCH};
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args.first().ok_or_else(|| anyhow::anyhow!("usage: cargo run --example run_virtual_shift_vs20_verification -- <vshift_alert.json> <member-node>"))?;
    let member = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("member node is required"))?;
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let report =
        FinalHardeningVerifier::new("data/virtual_shift").verify_and_write(member, &alert, now)?;
    println!("==========================================================================\nTASK 2 - VS20 FINAL VERIFICATION\n==========================================================================");
    println!("Member                 : {}\nAlert signature/hash    : {}\nAudit evidence complete : {}\nVS17 applied            : {}\nVS18 ID rotated         : {}\nRe-attestation trusted  : {}\nSTATUS                  : {}", report.member_id, report.alert_signature_and_hash_valid, report.audit_complete, report.policy_applied, report.identity_rotated, report.re_attestation_trusted, report.status);
    if !report.missing_stages.is_empty() {
        println!("Missing/failed: {}", report.missing_stages.join(", "));
    }
    println!(
        "Report JSON: data/virtual_shift/VS20_FINAL_VERIFICATION/{}/{}/vs20_report.json",
        report.member_id, report.alert_id
    );
    Ok(())
}
