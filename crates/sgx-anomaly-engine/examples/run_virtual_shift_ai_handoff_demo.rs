//! Task 2 AI remediation owner-review proof demo: Task 1 AI remediation plan
//! is durably handed off, approved/rejected, audited, staged, and signed.
//!
//! Run from crates/sgx-anomaly-engine:
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
        build_candidate_from_approved_review, sign_approved_policy, verify_signed_policy,
        vshift_alert_from_signed_policy, write_built_candidate, write_signed_policy,
        write_vshift_alert, ActiveVirtualShiftPolicy, AiRemediationAction, AiRemediationPlan,
        ApprovalService, GuardianKeyManager, ReviewQueue, ReviewStatus, VShiftAlert,
        VS10_VS11_REVIEWS, VS12_CANDIDATES, VS13_SIGNED_POLICIES, VS14_ALERTS,
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
    let decision = args.first().map(String::as_str).unwrap_or("approve");
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
    println!("TASK 2 - AI REMEDIATION OWNER REVIEW HANDOFF");
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

    if decided.status == ReviewStatus::Rejected {
        println!(
            "\nRESULT: AI plan -> owner rejection -> policy build/sign/broadcast remains blocked."
        );
        return Ok(());
    }

    let active = ActiveVirtualShiftPolicy::from_path("config/active_virtual_shift_policy.json")?;
    let built = build_candidate_from_approved_review(&active, &decided)?;
    let candidate_path = write_built_candidate(
        Path::new("data/virtual_shift").join(VS12_CANDIDATES),
        &built,
    )?;

    println!("\n3. APPROVED AI PLAN ENTERED POLICY CANDIDATE STAGING");
    line();
    row("Policy candidate", &built.candidate.policy_id);
    row(
        "Parent version",
        built.candidate.parent_policy_version.to_string(),
    );
    row("New version", built.candidate.policy_version.to_string());
    row("Source plan ID", &built.candidate.source_recommendation_id);
    row("Source anomaly ID", &built.candidate.source_anomaly_id);
    row(
        "Candidate actions",
        built.candidate.actions.len().to_string(),
    );
    row("Candidate JSON", candidate_path.display().to_string());
    row(
        "Active policy changed",
        "false; staging only until sign/apply",
    );
    line();

    let keys = GuardianKeyManager::from_config(
        "config/guardian_signer.json",
        "data/virtual_shift/guardian_keys",
    )?;
    let signed = sign_approved_policy(&keys, &decided, &built, now_ms()?)?;
    verify_signed_policy(&signed)?;
    let signed_path = write_signed_policy(
        Path::new("data/virtual_shift").join(VS13_SIGNED_POLICIES),
        &signed,
    )?;
    let issued_at_ms = now_ms()?;
    let alert_id = format!(
        "vsa-{}-v{}-{}",
        built.candidate.circle_id,
        built.candidate.policy_version,
        built.candidate.source_recommendation_id
    );
    let alert = vshift_alert_from_signed_policy(
        &decided,
        &signed,
        alert_id,
        issued_at_ms,
        issued_at_ms + 300_000,
    )?;
    let encoded = alert.encode()?;
    let decoded = VShiftAlert::decode(&encoded)?;
    let (alert_json_path, alert_pb_path) =
        write_vshift_alert(Path::new("data/virtual_shift").join(VS14_ALERTS), &decoded)?;
    let mut tampered = decoded.clone();
    tampered.policy_blob.push(0);
    let tamper_rejected = tampered.validate().is_err();

    println!("\n4. GUARDIAN SIGNED THE EXACT CANDIDATE POLICY");
    line();
    row("Signer", &signed.signer_id);
    row("Algorithm", &signed.algorithm);
    row("Policy hash", &signed.canonical_sha256);
    row("Signature verified", "true");
    row("Signed policy JSON", signed_path.display().to_string());
    line();

    println!("\n5. SIGNED POLICY WAS PACKAGED AS VSHIFT_ALERT");
    line();
    row("Alert ID", &decoded.alert_id);
    row("Circle", &decoded.circle_id);
    row("Policy version", decoded.policy_version.to_string());
    row("Linked anomaly", &decoded.anomaly_id);
    row("Linked plan", &decoded.recommendation_id);
    row(
        "TTL seconds",
        ((decoded.expires_at_ms - decoded.issued_at_ms) / 1000).to_string(),
    );
    row("Encode/decode valid", "true");
    row("Tamper rejected", tamper_rejected.to_string());
    row("Alert JSON", alert_json_path.display().to_string());
    row("Alert protobuf", alert_pb_path.display().to_string());
    row("Next step", "ready for gossip delivery");
    line();

    println!(
        "\nRESULT: AI plan -> durable owner review -> exact approve/reject handoff is working."
    );
    Ok(())
}
