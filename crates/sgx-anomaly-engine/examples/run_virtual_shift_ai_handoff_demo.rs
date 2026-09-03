//! Task 2 Issue #1 proof demo: Task 1 AI remediation plan is durably handed
//! off into the Virtual Shift owner-review lifecycle.
//!
//! Run from crates/sgx-anomaly-engine:
//! cargo run --example run_virtual_shift_ai_handoff_demo -- pending
//! cargo run --example run_virtual_shift_ai_handoff_demo -- approve
//! cargo run --example run_virtual_shift_ai_handoff_demo -- reject

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use sgx_anomaly_engine::{
    roles::RoleRegistry,
    virtual_shift::{
        AiRemediationAction, AiRemediationPlan, ApprovalService, ReviewQueue, ReviewStatus,
        VS10_VS11_REVIEWS,
    },
};

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn line() {
    println!("+--------------------------+-------------------------------------------------------------+");
}

fn row(label: &str, value: impl AsRef<str>) {
    println!("| {label:<24} | {:<59} |", value.as_ref());
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let decision = args.first().map(String::as_str).unwrap_or("pending");
    if !matches!(decision, "approve" | "reject" | "pending") {
        anyhow::bail!(
            "usage: cargo run --example run_virtual_shift_ai_handoff_demo -- <pending|approve|reject>"
        );
    }

    let owner = "nodeA";
    let review_root = Path::new("data/virtual_shift").join(VS10_VS11_REVIEWS);
    let queue = ReviewQueue::new(
        review_root,
        RoleRegistry::from_path("config/node_roles.json")?,
    );
    let created_at_ms = now_ms()?;
    let plan = AiRemediationPlan {
        plan_id: format!("airp-nodeA-run_demo-task1-nodeA-3389-{created_at_ms}"),
        anomaly_id: "task1-nodeA-demo-row-3389".into(),
        source_node: "nodeA".into(),
        anomaly_score: 0.91,
        model_confidence: 0.88,
        severity: "High".into(),
        anomaly_metadata: serde_json::json!({
            "detector": "tier2_isolation_forest",
            "response_band": "high",
            "source_ip": "10.0.0.99",
            "target_ip": "10.0.0.25",
            "target_port": 3389,
            "evidence_features": ["conn_rate", "net_rx_pkts_rate", "active_peers"]
        }),
        justification: "Task 1 detected high-confidence suspicious network activity. The AI recommends a bounded policy change, but owner approval is mandatory before Virtual Shift can build/sign/broadcast a policy.".into(),
        created_at_ms,
        requires_approval: true,
        auto_execute: false,
        actions: vec![
            AiRemediationAction {
                action_type: "tighten_firewall_rules".into(),
                target: "nodeA".into(),
                parameters: serde_json::json!({
                    "action": "DENY_OR_RATE_LIMIT",
                    "src": "10.0.0.99",
                    "dst": "10.0.0.25",
                    "protocol": "TCP",
                    "port": 3389,
                    "duration_seconds": 900
                }),
                requires_approval: true,
                reason: "RDP-like target port received suspicious traffic; restrict only after owner review.".into(),
            },
            AiRemediationAction {
                action_type: "increase_attestation_frequency".into(),
                target: "nodeA".into(),
                parameters: serde_json::json!({
                    "interval_seconds": 120,
                    "immediate_reattest": true
                }),
                requires_approval: true,
                reason: "High-risk anomaly should prove the node remains trusted before wider enforcement.".into(),
            },
        ],
    };

    let (pending, handoff) = queue.enqueue_ai_remediation_plan(plan, "task1-live-runtime")?;

    println!("==========================================================================");
    println!("TASK 2 ISSUE #1 - AI REMEDIATION PLAN HANDOFF");
    println!("==========================================================================");
    println!("\n1. TASK 1 AI PLAN WAS PERSISTED FOR OWNER REVIEW");
    line();
    row("Plan / recommendation ID", &pending.recommendation_id);
    row("Anomaly ID", &pending.anomaly_id);
    row("Source node", &pending.source_node);
    row("Review status", format!("{:?}", pending.status));
    row("Duplicate replay", handoff.duplicate.to_string());
    row("Saved review JSON", &handoff.pending_review_path);
    row("Next step", &handoff.next_step);
    line();

    if decision == "pending" {
        println!("\nRESULT: plan is persisted as PendingReview; no policy was built.");
        return Ok(());
    }

    let service = ApprovalService::new(queue);
    let decided = match decision {
        "approve" => service.approve(
            owner,
            &pending.recommendation_id,
            Some("Owner reviewed exact persisted AI remediation plan.".into()),
            now_ms()?,
        )?,
        "reject" => service.reject(
            owner,
            &pending.recommendation_id,
            Some(
                "Owner rejected exact persisted AI remediation plan; no policy change allowed."
                    .into(),
            ),
            now_ms()?,
        )?,
        _ => unreachable!(),
    };

    println!("\n2. OWNER DECISION CONSUMED THE SAME PERSISTED PLAN ID");
    line();
    row("Owner", owner);
    row("Decision", format!("{:?}", decided.status));
    row("Same plan ID", &decided.recommendation_id);
    row(
        "Policy build allowed",
        (decided.status == ReviewStatus::Approved).to_string(),
    );
    row(
        "Rejected behavior",
        if decided.status == ReviewStatus::Rejected {
            "blocked before policy build/sign/broadcast"
        } else {
            "not applicable"
        },
    );
    line();

    println!(
        "\nRESULT: AI plan -> durable owner review -> exact approve/reject handoff is working."
    );
    Ok(())
}
