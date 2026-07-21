//! Enforcement executor
//!
//! Applies firewall rules atomically using nftables.
//! Fail-closed on any error.

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::enforcement::model::{Action, EnforcementRule, Protocol};
use crate::logging::log_event;
use anyhow::{anyhow, Result};
use std::fs::{remove_file, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// Apply enforcement rules atomically via nftables.
pub fn apply_rules(rules: &[EnforcementRule]) -> Result<()> {
    let node_id = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "unknown-node".to_string());

    log_event(&node_id, "Policy enforcement started (nftables apply)");

    log_audit(
        &node_id,
        AuditCategory::Enforcement,
        AuditSeverity::Info,
        AuditAction::Started,
        "Policy enforcement started (nftables apply)",
    );
    let ruleset = build_nft_ruleset(rules)?;

    let mut path = std::env::temp_dir();
    path.push("sgx_enforcement.nft");

    write_ruleset(&path, &ruleset)?;

    let status = Command::new("nft")
        .arg("-f")
        .arg(&path)
        .status()
        .map_err(|e| anyhow!("failed to execute nft: {}", e))?;

    // Cleanup temp file
    let _ = remove_file(&path);

    if !status.success() {
        log_event(&node_id, "Policy enforcement FAILED (nftables error)");

        log_audit(
            &node_id,
            AuditCategory::Enforcement,
            AuditSeverity::Critical,
            AuditAction::Failed,
            "Policy enforcement failed (nftables error)",
        );

        return Err(anyhow!("nftables rule application failed"));
    }
    log_event(
        &node_id,
        "Policy enforcement successfully applied (nftables)",
    );

    log_audit(
        &node_id,
        AuditCategory::Enforcement,
        AuditSeverity::Info,
        AuditAction::Applied,
        "Policy enforcement successfully applied (nftables)",
    );
    Ok(())
}

/// Build a full nftables ruleset (atomic).
fn build_nft_ruleset(rules: &[EnforcementRule]) -> Result<String> {
    let mut out = String::new();

    // Base table & chain
    out.push_str("table inet sgx_guardian {\n");
    out.push_str("  chain input {\n");
    out.push_str("    type filter hook input priority 0; policy drop;\n");

    // ---- DEV / SYSTEM SAFETY RULES ----
    // Allow loopback (critical for WSL & local IPC)
    out.push_str("    iif lo accept\n");

    // Allow established/related connections
    out.push_str("    ct state established,related accept\n");

    // Allow SSH (WSL / VS Code Remote)
    out.push_str("    tcp dport 22 accept\n");

    // Allow mDNS (discovery)
    out.push_str("    udp dport 5353 accept\n");

    // Allow local gRPC / node communication (example ports)
    out.push_str("    tcp dport {50051,50052,50053} accept\n");

    // Allow attestation ports
    out.push_str("    tcp dport {50151,50152,50153} accept\n");
    // Allow registry sync (Overlay IP assignment)
    out.push_str("    tcp dport 50062 accept\n");

    // Allow node discovery broadcast (UDP)
    out.push_str("    udp dport 9000 accept\n");
    out.push_str("    udp sport 9000 accept\n");

    // Allow config sync (TCP)
    out.push_str("    tcp dport 50070 accept\n");

    // Allow cert bootstrap
    out.push_str("    tcp dport 50061 accept\n");

    // Allow CRL gossip exchange for decentralized revocation propagation
    out.push_str("    tcp dport 50063 accept\n");

    // Allow in-Circle file transfer (chunked, resumable, signed manifest)
    out.push_str("    tcp dport 50064 accept\n");

    // Allow ICMP ping
    out.push_str("    ip protocol icmp accept\n");

    // Allow Nebula overlay mesh traffic (VERY IMPORTANT)
    out.push_str("    udp dport 4242 accept\n");
    out.push_str("    udp sport 4242 accept\n");
    // ---- END DEV SAFETY RULES ----

    for rule in rules {
        out.push_str("    ");
        out.push_str(&render_rule(rule)?);
        out.push('\n');
    }

    out.push_str("  }\n");
    out.push_str("}\n");

    Ok(out)
}

/// Render a single enforcement rule into nft syntax.
fn render_rule(rule: &EnforcementRule) -> Result<String> {
    let mut parts = Vec::new();

    // Source IP
    if let Some(ref src) = rule.src_ip {
        parts.push(format!("ip saddr {}", src));
    }

    // Destination IP
    if let Some(ref dst) = rule.dst_ip {
        parts.push(format!("ip daddr {}", dst));
    }

    // Protocol (ONLY if ports are specified)
    if rule.ports.is_some() {
        match rule.protocol {
            Protocol::Tcp => parts.push("tcp".to_string()),
            Protocol::Udp => parts.push("udp".to_string()),
        }
    }

    // Ports
    if let Some(ref ports) = rule.ports {
        if ports.start == ports.end {
            parts.push(format!("dport {}", ports.start));
        } else {
            parts.push(format!("dport {}-{}", ports.start, ports.end));
        }
    }

    // Action
    let action = match rule.action {
        Action::Allow => "accept",
        Action::Deny => "drop",
    };

    parts.push(action.to_string());

    Ok(parts.join(" "))
}

/// Write ruleset to disk.
fn write_ruleset(path: &PathBuf, data: &str) -> Result<()> {
    let mut file =
        File::create(path).map_err(|e| anyhow!("failed to create ruleset file: {}", e))?;

    file.write_all(data.as_bytes())
        .map_err(|e| anyhow!("failed to write ruleset file: {}", e))?;

    Ok(())
}
