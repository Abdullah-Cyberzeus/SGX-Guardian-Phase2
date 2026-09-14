use anyhow::{bail, Result};
use sgx_anomaly_engine::network_ai::{SensitiveRouteHandoffService, SensitiveRouteReason};
use std::env;
use std::path::PathBuf;

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

fn usage() {
    eprintln!(
        "Usage: cargo run --example run_task3_sensitive_route_handoff_demo -- [--source-node nodeA] [--destination-node nodeB] [--route-id relay-nodeA-via-nodeZ-nodeB] [--reason new-untrusted-relay|policy-rule-change-needed|cross-boundary-route|quarantined-member-recovery|security-exception-required] [--out-dir data/network_ai/task3_deliverable_12_demo]"
    );
}

fn print_kv(label: &str, value: impl std::fmt::Display) {
    println!("{:<28}: {}", label, value);
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        usage();
        return Ok(());
    }
    let source_node = arg_value(&args, "--source-node").unwrap_or_else(|| "nodeA".to_string());
    let destination_node =
        arg_value(&args, "--destination-node").unwrap_or_else(|| "nodeB".to_string());
    let route_id =
        arg_value(&args, "--route-id").unwrap_or_else(|| "relay-nodeA-via-nodeZ-nodeB".to_string());
    let reason_value =
        arg_value(&args, "--reason").unwrap_or_else(|| "new-untrusted-relay".to_string());
    let reason = SensitiveRouteReason::parse(&reason_value).ok_or_else(|| {
        anyhow::anyhow!("unsupported sensitive reason '{reason_value}'; use --help")
    })?;
    let out_dir = PathBuf::from(
        arg_value(&args, "--out-dir")
            .unwrap_or_else(|| "data/network_ai/task3_deliverable_12_demo".to_string()),
    );

    let audit_path = out_dir.join("task3_sensitive_route_handoff_audit.json");
    let service = SensitiveRouteHandoffService::new(
        "data/virtual_shift/02_OWNER_REVIEW_DECISIONS",
        "config/node_roles.json",
    );
    let result = service.handoff(
        1_788_433_100_000,
        &source_node,
        &destination_node,
        &route_id,
        reason,
        0.85,
        0.90,
        &audit_path,
    )?;

    if !result.direct_apply_blocked || !result.owner_approval_required {
        bail!("sensitive route handoff safety invariant failed");
    }

    println!("==========================================================================");
    println!("TASK 3 - SENSITIVE ROUTE HANDOFF TO TASK 2 (DELIVERABLE 12)");
    println!("==========================================================================");
    print_kv("Requested route", &route_id);
    print_kv("Sensitive reason", reason_value);
    print_kv("Direct route apply", "BLOCKED");
    print_kv("Owner/admin approval", "REQUIRED");
    print_kv("Task2 plan ID", &result.plan_id);
    print_kv("Task2 review status", format!("{:?}", result.review_status));
    print_kv("Task2 pending review", &result.pending_review_path);
    print_kv("Task3 audit link", audit_path.display());
    print_kv("AI justification", &result.audit_record.ai_justification);
    println!();
    println!("No runtime route or Task2 policy was applied by this command.");
    Ok(())
}
