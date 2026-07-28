//! Network Address Translation (NAT) Orchestrator
//!
//! Manages internet sharing between the local Access Point (ap0)
//! and the upstream Uplink (wlan1) by interacting dynamically
//! with the Enforcement engine.

use crate::enforcement;
use crate::policy::{Policy, Rule};
use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

fn merge_with_active_policy(dynamic_rules: Vec<Rule>) -> Policy {
    let mut policy = crate::policy::get_active_policy().unwrap_or_else(|| Policy {
        policy_id: "netbridge_dynamic_nat".to_string(),
        version: "1.0".to_string(),
        rules: Vec::new(),
    });

    // Re-applying NAT must be idempotent even if a previously composed policy was cached.
    policy.rules.retain(|rule| !rule.id.starts_with("dyn_"));
    policy.rules.extend(dynamic_rules);
    policy
}

fn parse_interface_network_cidr(output: &str) -> Option<String> {
    let cidr = output.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("inet ")?
            .split_whitespace()
            .next()
    })?;
    let (ip, prefix) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    Some(format!("{}/{}", network, prefix))
}

fn interface_network_cidr(interface: &str) -> Result<String> {
    let output = Command::new("ip")
        .args(["-4", "addr", "show", "dev", interface])
        .output()
        .map_err(|error| anyhow!("failed to inspect {}: {}", interface, error))?;
    if !output.status.success() {
        return Err(anyhow!(
            "failed to inspect {}: {}",
            interface,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    parse_interface_network_cidr(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| {
        anyhow!(
            "{} has no usable IPv4 subnet for hotspot masquerading",
            interface
        )
    })
}

pub struct NatManager {
    is_enabled: AtomicBool,
}

impl NatManager {
    pub fn new() -> Self {
        Self {
            is_enabled: AtomicBool::new(false),
        }
    }
}

impl Default for NatManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NatManager {
    /// Generates the dynamic policy required to share internet from the uplink
    /// to the internal AP clients, and applies it via the enforcement engine.
    pub fn enable_nat(
        &self,
        in_iface: &str,
        out_iface: &str,
        client_isolation: bool,
    ) -> Result<()> {
        tracing::debug!("Generating NAT, Forwarding, and Isolation policies...");
        let hotspot_cidr = interface_network_cidr(in_iface)?;

        // Cover the selected Wi-Fi uplink and the board's existing Ethernet/default
        // egress. The target kernel has no policy-routing support, so forwarded traffic
        // must be allowed to follow whichever route is already active without rewriting
        // the management routing table.
        let sibling_uplink = if out_iface == "wlan0" {
            "wlan1"
        } else {
            "wlan0"
        };
        let mut uplinks: Vec<&str> = vec![out_iface];
        for candidate in [sibling_uplink, "eth0"] {
            if !uplinks.contains(&candidate) {
                uplinks.push(candidate);
            }
        }

        let mut rules = Vec::new();

        for (idx, uplink) in uplinks.iter().enumerate() {
            // NAT Policy (Masquerade) — one per uplink
            rules.push(Rule {
                id: format!("dyn_nat_masquerade_{:02}", idx + 1),
                action: "masquerade".to_string(),
                src: hotspot_cidr.clone(),
                dst: uplink.to_string(),
                protocol: "any".to_string(),
                port: None,
            });

            // Forwarding Policy (Allow AP → Uplink)
            rules.push(Rule {
                id: format!("dyn_fwd_outbound_{:02}", idx + 1),
                action: "allow".to_string(),
                src: in_iface.to_string(),
                dst: uplink.to_string(),
                protocol: "any".to_string(),
                port: None,
            });

            // Forwarding Policy (Allow Established Uplink → AP)
            rules.push(Rule {
                id: format!("dyn_fwd_inbound_{:02}", idx + 1),
                action: "allow".to_string(),
                src: uplink.to_string(),
                dst: in_iface.to_string(),
                protocol: "state:established,related".to_string(),
                port: None,
            });

            // Isolation Policy (Deny all other untracked Uplink → AP traffic)
            rules.push(Rule {
                id: format!("dyn_isolate_inbound_{:02}", idx + 1),
                action: "deny".to_string(),
                src: uplink.to_string(),
                dst: in_iface.to_string(),
                protocol: "any".to_string(),
                port: None,
            });
        }

        // API Protection Policy — block hotspot clients from reaching the admin API port
        rules.push(Rule {
            id: "dyn_input_api_protection_01".to_string(),
            action: "deny".to_string(),
            src: in_iface.to_string(),
            dst: "local".to_string(),
            protocol: "tcp".to_string(),
            port: Some(8443),
        });

        // Client Isolation Policy (AP → AP drop) — prevents hotspot clients talking to each other
        if client_isolation {
            rules.push(Rule {
                id: "dyn_isolate_client_01".to_string(),
                action: "deny".to_string(),
                src: in_iface.to_string(),
                dst: in_iface.to_string(),
                protocol: "any".to_string(),
                port: None,
            });
        }

        // NAT and signed enforcement share the same atomic nftables tables. Compose them
        // instead of replacing the signed policy with a routing-only policy.
        let policy = merge_with_active_policy(rules);

        tracing::debug!("Applying NAT policies to enforcement engine...");
        if let Err(e) = enforcement::apply_policy(&policy) {
            return Err(anyhow!("Failed to enable NAT: {:?}", e));
        }

        self.is_enabled.store(true, Ordering::SeqCst);
        info!("✅ Network routing and Firewall rules successfully applied.");

        Ok(())
    }

    /// Removes all NAT and forwarding policies by clearing the enforcement rules.
    pub fn disable_nat(&self) -> Result<()> {
        tracing::debug!("Removing NAT and Forwarding policies...");
        let result = if let Some(active_policy) = crate::policy::get_active_policy() {
            enforcement::apply_policy(&active_policy)
        } else {
            enforcement::remove_policy()
        };
        if let Err(e) = result {
            warn!(
                "Failed to restore enforcement policy while disabling NAT: {}",
                e
            );
            return Err(anyhow!("Failed to disable NAT: {}", e));
        }

        self.is_enabled.store(false, Ordering::SeqCst);
        info!("🔴 Network routing safely disabled.");

        Ok(())
    }

    /// Tracks if NAT is currently enforced.
    pub fn is_enabled(&self) -> bool {
        self.is_enabled.load(Ordering::SeqCst)
    }

    /// Verifies the kernel rules rather than trusting only the in-memory flag.
    /// Another atomic policy application can replace the tables behind our back.
    pub fn kernel_rules_active(&self, in_iface: &str, out_iface: &str) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let hotspot_cidr = match interface_network_cidr(in_iface) {
            Ok(cidr) => cidr,
            Err(_) => return false,
        };

        let nat = Command::new("nft")
            .args(["list", "chain", "ip", "sgx_nat", "postrouting"])
            .output();
        let forward = Command::new("nft")
            .args(["list", "chain", "inet", "sgx_guardian", "forward"])
            .output();

        let nat = match nat {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).into_owned()
            }
            _ => return false,
        };
        let forward = match forward {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).into_owned()
            }
            _ => return false,
        };

        nat.contains("masquerade")
            && nat.contains(&format!("ip saddr {}", hotspot_cidr))
            && nat.contains(&format!("oifname \"{}\"", out_iface))
            && forward.contains(&format!("iifname \"{}\"", in_iface))
            && forward.contains(&format!("oifname \"{}\"", out_iface))
    }
}

#[cfg(test)]
mod tests {
    use super::{merge_with_active_policy, parse_interface_network_cidr};
    use crate::policy::Rule;

    fn rule(id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            action: "allow".to_string(),
            src: "any".to_string(),
            dst: "127.0.0.1".to_string(),
            protocol: "tcp".to_string(),
            port: Some(22),
        }
    }

    #[test]
    fn dynamic_rules_are_added_once() {
        let policy = merge_with_active_policy(vec![rule("dyn_fwd_outbound_01")]);
        let dynamic_count = policy
            .rules
            .iter()
            .filter(|rule| rule.id.starts_with("dyn_"))
            .count();

        assert_eq!(dynamic_count, 1);
    }

    #[test]
    fn derives_hotspot_network_from_interface_address() {
        let output = "3: uap1: <UP>\n    inet 192.168.200.1/24 scope global uap1\n";
        assert_eq!(
            parse_interface_network_cidr(output).as_deref(),
            Some("192.168.200.0/24")
        );
    }
}
