//! VS11 demonstration: an authorised Circle Owner approves or rejects one
//! existing VS10 pending-review record.
//!
//! Run after `run_policy_recommendation_groups_demo` has created the queue:
//! cargo run --example run_virtual_shift_owner_decision_demo -- \
//!   vsr-nodeA-task1-nodeA-108 approve --owner nodeA --reason "Evidence reviewed"

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    ApprovalService, ReviewQueue, ReviewStatus, VS10_VS11_REVIEWS,
};

fn flag(args: &[String], name: &str) -> Result<Option<String>> {
    let Some(index) = args.iter().position(|value| value == name) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{name} needs a value"))?
        .trim();
    if value.is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    Ok(Some(value.to_owned()))
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let recommendation_id = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_owner_decision_demo -- <recommendation-id> <approve|reject> [--owner nodeA] [--reason text]"
    ))?;
    let decision = args
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("choose approve or reject"))?;
    let owner = flag(&args, "--owner")?.unwrap_or_else(|| "nodeA".into());
    let reason = flag(&args, "--reason")?;

    let queue = ReviewQueue::from_role_config(
        std::path::Path::new("data/virtual_shift").join(VS10_VS11_REVIEWS),
        "config/node_roles.json",
    )?;
    let service = ApprovalService::new(queue.clone());
    let before = queue.show(&owner, recommendation_id)?;

    println!("==========================================================================");
    println!("TASK 2 - VS11 CIRCLE OWNER DECISION");
    println!("==========================================================================");
    println!("Owner              : {owner}");
    println!("Recommendation ID  : {recommendation_id}");
    println!("Current status     : {:?}", before.status);
    println!("Anomaly ID         : {}", before.anomaly_id);
    println!("Node               : {}", before.source_node);
    println!(
        "VS8 final actions  : {}",
        before.proposal["vs8"]["actions"]
            .as_array()
            .map_or(0, Vec::len)
    );
    println!(
        "VS9 justification  : {}",
        before.proposal["vs9"]["human_summary"]
            .as_str()
            .unwrap_or("missing")
    );

    let decided_at_ms = now_ms()?;
    let after = match decision {
        "approve" => service.approve(&owner, recommendation_id, reason, decided_at_ms)?,
        "reject" => service.reject(&owner, recommendation_id, reason, decided_at_ms)?,
        _ => anyhow::bail!("decision must be approve or reject"),
    };
    let decision = after
        .owner_decision
        .as_ref()
        .expect("VS11 persisted decision");
    println!("\nVS11 RESULT");
    println!("Status             : {:?}", after.status);
    println!("Reviewer           : {}", decision.reviewer_id);
    println!("Decision time (ms) : {}", decision.decided_at_ms);
    println!(
        "Reason             : {}",
        decision.reason.as_deref().unwrap_or("not supplied")
    );
    println!(
        "Policy builder gate: {}",
        if after.status == ReviewStatus::Approved {
            "ALLOWED for future VS12 only"
        } else {
            "BLOCKED - rejected recommendation never reaches VS12/signing/gossip"
        }
    );
    println!("Saved review        : data/virtual_shift/02_OWNER_REVIEW_DECISIONS/{recommendation_id}/review.json");
    println!("No policy is built, signed, broadcast or applied in VS11.");
    Ok(())
}
