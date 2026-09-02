//! Backend equivalent of the future admin-dashboard "Trigger policy" button.
//! It finalizes one pending recommendation as approved and stores a separate,
//! auditable trigger record. It never builds, signs, broadcasts, or applies a
//! policy by itself.

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    ApprovalService, ReviewQueue, ReviewStatus, VS10_VS11_REVIEWS,
};

fn option(args: &[String], name: &str) -> Result<Option<String>> {
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

fn line() {
    println!("+------------------------+---------------------------------------------------------------+");
}

fn row(label: &str, value: impl AsRef<str>) {
    println!("| {label:<22} | {:<61} |", value.as_ref());
}

fn compact(value: &str, maximum: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(maximum).collect();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

/// Show the exact policy snapshot that the owner is about to approve.  It is
/// deliberately read from the pending-review JSON, not reconstructed from
/// terminal-only data, so the owner can inspect the same durable record that
/// will drive VS12 after approval.
fn print_policy_for_approval(review: &sgx_anomaly_engine::virtual_shift::ReviewRecord) {
    let draft = review
        .proposal
        .get("policy_for_owner_approval")
        // Old saved demos still work, but every new review uses the clearer
        // field name above.
        .or_else(|| review.proposal.get("system_network_policy_draft"));

    println!("\n2. POLICY TO REVIEW BEFORE TRIGGER");
    line();
    let Some(draft) = draft else {
        row(
            "Policy status",
            "No network policy is proposed for this anomaly.",
        );
        line();
        return;
    };
    row(
        "Policy status",
        draft
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing"),
    );
    row(
        "Detected pattern",
        draft
            .get("anomaly_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("not a network pattern"),
    );
    row(
        "Proposed action",
        draft
            .get("suggested_action")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("none"),
    );
    row(
        "Target peer/node",
        draft
            .get("suggested_target_peer")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("owner chooses target"),
    );
    row(
        "Why proposed",
        compact(
            draft
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("not supplied"),
            58,
        ),
    );
    line();

    let rules = draft
        .get("proposed_rules")
        .and_then(serde_json::Value::as_array);
    match rules {
        Some(rules) if !rules.is_empty() => {
            for (index, rule) in rules.iter().enumerate() {
                let action = rule
                    .get("action")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let protocol = rule
                    .get("protocol")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let port = rule
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .map_or("?".into(), |value| value.to_string());
                let src = rule
                    .get("src")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let dst = rule
                    .get("dst")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                row(
                    &format!("Rule {}", index + 1),
                    format!("{action} {protocol}:{port} | {src} -> {dst}"),
                );
                row(
                    "Rule reason",
                    compact(
                        rule.get("reason")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("not supplied"),
                        58,
                    ),
                );
            }
        }
        _ => row(
            "Network rules",
            "None suggested; owner may use a manual approved rule.",
        ),
    }
    line();
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let recommendation_id = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_admin_trigger_demo -- <pending-recommendation-id> [--owner nodeA] [--reason text]"
    ))?;
    let owner = option(&args, "--owner")?.unwrap_or_else(|| "nodeA".into());
    let reason = option(&args, "--reason")?
        .unwrap_or_else(|| "Owner manually triggered the reviewed policy recommendation.".into());

    let root = Path::new("data/virtual_shift");
    let queue =
        ReviewQueue::from_role_config(root.join(VS10_VS11_REVIEWS), "config/node_roles.json")?;
    let before = queue.show(&owner, recommendation_id)?;
    if before.status != ReviewStatus::PendingReview {
        anyhow::bail!(
            "'{recommendation_id}' is {:?}; the trigger button only accepts a pending review",
            before.status
        );
    }

    println!("==========================================================================");
    println!("TASK 2 - ADMIN TRIGGER POLICY");
    println!("==========================================================================");

    println!("\n1. PENDING REVIEW");
    line();
    row("Pending recommendation", recommendation_id);
    row("Source node", &before.source_node);
    row("Authorised owner", &owner);
    row("Anomaly evidence", &before.anomaly_id);
    line();
    print_policy_for_approval(&before);

    let triggered_at_ms = now_ms()?;
    let approved = ApprovalService::new(queue).approve(
        &owner,
        recommendation_id,
        Some(reason.clone()),
        triggered_at_ms,
    )?;
    let trigger_record = serde_json::json!({
        "schema_version": 1,
        "record_type": "admin_policy_approval",
        "policy_reference": {
            "recommendation_id": approved.recommendation_id,
            "anomaly_id": approved.anomaly_id,
            "source_node": approved.source_node
        },
        "approval": {
            "owner": owner,
            "decision": "approved",
            "reason": reason,
            "approved_at_ms": triggered_at_ms
        },
        "result": {
            "policy_build_allowed": true,
            "policy_applied": false,
            "next_step": "build_versioned_candidate_policy"
        }
    });
    let output = root
        .join("03_ADMIN_TRIGGER_RECORDS")
        .join(recommendation_id)
        .join("manual_trigger.json");
    std::fs::create_dir_all(output.parent().expect("trigger file parent"))?;
    std::fs::write(&output, serde_json::to_string_pretty(&trigger_record)?)?;

    println!("\n3. EXPLICIT ADMIN ACTION");
    line();
    row("Action", "Trigger Policy (manual owner approval)");
    row("Decision", "APPROVED for policy building");
    row("Why", &reason);
    line();

    println!("\n4. SAFE RESULT");
    line();
    row("What changed", "Pending review is now approved.");
    row(
        "What did not happen",
        "No policy was built, signed, sent, or applied here.",
    );
    row(
        "Next step",
        "Run the approved-policy lifecycle after review.",
    );
    row("Saved trigger record", output.display().to_string());
    line();
    Ok(())
}
