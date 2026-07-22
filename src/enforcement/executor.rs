//! Enforcement executor
//!
//! Applies firewall rules atomically using nftables.
//! Fail-closed on any error.

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::enforcement::model::{Action, ConntrackState, Protocol};
use crate::enforcement::translator::TranslatedRules;
use crate::logging::log_event;
use anyhow::{anyhow, Result};
use std::fs::{remove_file, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// Apply enforcement rules atomically via nftables.
pub fn apply_rules(rules: &TranslatedRules) -> Result<()> {
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

/// Removes all sgx-guardian managed nftables rules.
pub fn cleanup_rules() -> Result<()> {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "sgx_guardian"])
        .output();
    let _ = Command::new("nft")
        .args(["delete", "table", "ip", "sgx_nat"])
        .output();
    Ok(())
}

pub fn build_nft_ruleset(rules: &TranslatedRules) -> Result<String> {
    let mut out = String::new();

    // Atomic cleanup - flush existing tables if they exist
    out.push_str("table inet sgx_guardian\n");
    out.push_str("delete table inet sgx_guardian\n");
    out.push_str("table ip sgx_nat\n");
    out.push_str("delete table ip sgx_nat\n\n");

    // ---- FILTER TABLE (inet) ----
    out.push_str("table inet sgx_guardian {\n");

    // 1. INPUT CHAIN (API Protection & Host Access)
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
    // Allow DHCP (Server/Client)
    out.push_str("    udp dport {67, 68} accept\n");
    out.push_str("    udp sport {67, 68} accept\n");
    // Allow DNS
    out.push_str("    udp dport 53 accept\n");
    out.push_str("    tcp dport 53 accept\n");
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
    // Allow ICMP ping
    out.push_str("    ip protocol icmp accept\n");
    // Allow Nebula overlay mesh traffic (VERY IMPORTANT)
    out.push_str("    udp dport 4242 accept\n");
    out.push_str("    udp sport 4242 accept\n");
    // ---- END DEV SAFETY RULES ----

    for rule in &rules.enforcement {
        out.push_str("    ");
        out.push_str(&render_enforcement(rule)?);
        out.push('\n');
    }
    out.push_str("  }\n\n");

    // 2. FORWARD CHAIN (Client Bridging & Isolation)
    out.push_str("  chain forward {\n");
    out.push_str("    type filter hook forward priority 0; policy drop;\n");

    for rule in &rules.forward {
        out.push_str("    ");
        out.push_str(&render_forward(rule)?);
        out.push('\n');
    }

    for rule in &rules.isolation {
        out.push_str("    ");
        out.push_str(&render_isolation(rule)?);
        out.push('\n');
    }
    out.push_str("  }\n");
    out.push_str("}\n");

    // ---- NAT TABLE (ip) ----
    out.push_str("\ntable ip sgx_nat {\n");

    // 3. POSTROUTING CHAIN (Masquerade)
    out.push_str("  chain postrouting {\n");
    out.push_str("    type nat hook postrouting priority 100; policy accept;\n");

    for rule in &rules.nat {
        out.push_str("    ");
        out.push_str(&render_nat(rule)?);
        out.push('\n');
    }

    out.push_str("  }\n");
    out.push_str("}\n");

    Ok(out)
}

pub fn render_enforcement(rule: &crate::enforcement::model::EnforcementRule) -> Result<String> {
    let mut parts = Vec::new();
    if let Some(ref iif) = rule.in_interface {
        parts.push(format!("iifname \"{}\"", iif));
    }
    if let Some(ref src) = rule.src_ip {
        parts.push(format!("ip saddr {}", src));
    }
    if let Some(ref dst) = rule.dst_ip {
        parts.push(format!("ip daddr {}", dst));
    }
    if rule.ports.is_some() {
        match rule.protocol {
            Protocol::Tcp => parts.push("tcp".to_string()),
            Protocol::Udp => parts.push("udp".to_string()),
        }
    }
    if let Some(ref ports) = rule.ports {
        if ports.start == ports.end {
            parts.push(format!("dport {}", ports.start));
        } else {
            parts.push(format!("dport {}-{}", ports.start, ports.end));
        }
    }
    match rule.action {
        Action::Allow => parts.push("accept".to_string()),
        Action::Deny => parts.push("drop".to_string()),
        Action::Masquerade => {
            return Err(anyhow!("masquerade action invalid in enforcement rules"))
        }
    }
    Ok(parts.join(" "))
}

pub fn render_forward(rule: &crate::enforcement::model::ForwardRule) -> Result<String> {
    let mut parts = Vec::new();
    if let Some(ref iif) = rule.interfaces.in_interface {
        parts.push(format!("iifname \"{}\"", iif));
    }
    if let Some(ref oif) = rule.interfaces.out_interface {
        parts.push(format!("oifname \"{}\"", oif));
    }
    if let Some(ref states) = rule.state {
        let state_strs: Vec<String> = states
            .iter()
            .map(|s| {
                match s {
                    ConntrackState::New => "new",
                    ConntrackState::Established => "established",
                    ConntrackState::Related => "related",
                    ConntrackState::Invalid => "invalid",
                }
                .to_string()
            })
            .collect();
        parts.push(format!("ct state {}", state_strs.join(",")));
    }
    match rule.action {
        Action::Allow => parts.push("accept".to_string()),
        Action::Deny => parts.push("drop".to_string()),
        Action::Masquerade => return Err(anyhow!("masquerade action invalid in forward rules")),
    }
    Ok(parts.join(" "))
}

pub fn render_isolation(rule: &crate::enforcement::model::IsolationRule) -> Result<String> {
    let mut parts = Vec::new();
    if let Some(ref iif) = rule.interfaces.in_interface {
        parts.push(format!("iifname \"{}\"", iif));
    }
    if let Some(ref oif) = rule.interfaces.out_interface {
        parts.push(format!("oifname \"{}\"", oif));
    }
    match rule.action {
        Action::Allow => parts.push("accept".to_string()),
        Action::Deny => parts.push("drop".to_string()),
        Action::Masquerade => return Err(anyhow!("masquerade action invalid in isolation rules")),
    }
    Ok(parts.join(" "))
}

pub fn render_nat(rule: &crate::enforcement::model::NatRule) -> Result<String> {
    let mut parts = Vec::new();
    if let Some(ref src) = rule.src_subnet {
        parts.push(format!("ip saddr {}", src));
    }
    if let Some(ref oif) = rule.out_interface {
        parts.push(format!("oifname \"{}\"", oif));
    }
    match rule.action {
        Action::Allow => parts.push("accept".to_string()),
        Action::Deny => parts.push("drop".to_string()),
        Action::Masquerade => parts.push("masquerade".to_string()),
    }
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
