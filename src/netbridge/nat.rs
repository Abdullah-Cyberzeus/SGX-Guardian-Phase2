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
    use super::{merge_with_active_policy, parse_interface_network_cidr, NatManager};
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

    // Note: `merge_with_active_policy` reads the crate-wide `crate::policy`
    // runtime cache via `get_active_policy()`. That cache has no reset API and
    // is otherwise untouched anywhere in the `--lib` unit-test binary, so these
    // tests deliberately avoid `load_policy_runtime` (the only setter) to keep
    // this suite's cache observations (`None`) deterministic and independent of
    // test execution order, per the isolation rule against shared mutable
    // process-wide state.

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
    fn merge_uses_default_policy_metadata_when_no_active_policy_is_cached() {
        let policy = merge_with_active_policy(vec![rule("dyn_test_01")]);
        assert_eq!(policy.policy_id, "netbridge_dynamic_nat");
        assert_eq!(policy.version, "1.0");
    }

    #[test]
    fn merge_keeps_every_distinct_dynamic_rule() {
        let policy = merge_with_active_policy(vec![
            rule("dyn_nat_masquerade_01"),
            rule("dyn_fwd_outbound_01"),
            rule("dyn_fwd_inbound_01"),
            rule("dyn_isolate_inbound_01"),
        ]);
        assert_eq!(policy.rules.len(), 4);
        for id in [
            "dyn_nat_masquerade_01",
            "dyn_fwd_outbound_01",
            "dyn_fwd_inbound_01",
            "dyn_isolate_inbound_01",
        ] {
            assert!(policy.rules.iter().any(|r| r.id == id), "missing {}", id);
        }
    }

    #[test]
    fn merge_with_no_dynamic_rules_yields_no_dynamic_entries() {
        let policy = merge_with_active_policy(vec![]);
        assert!(policy.rules.iter().all(|r| !r.id.starts_with("dyn_")));
    }

    #[test]
    fn merge_is_idempotent_across_repeated_calls_with_the_same_rules() {
        let first = merge_with_active_policy(vec![rule("dyn_repeat_01")]);
        let second = merge_with_active_policy(vec![rule("dyn_repeat_01")]);
        assert_eq!(first.rules.len(), second.rules.len());
        assert_eq!(first.policy_id, second.policy_id);
    }

    #[test]
    fn derives_hotspot_network_from_interface_address() {
        let output = "3: uap1: <UP>\n    inet 192.168.200.1/24 scope global uap1\n";
        assert_eq!(
            parse_interface_network_cidr(output).as_deref(),
            Some("192.168.200.0/24")
        );
    }

    #[test]
    fn parse_interface_network_cidr_returns_none_without_an_inet_line() {
        let output = "3: uap1: <UP>\n    inet6 fe80::1/64 scope link\n";
        assert_eq!(parse_interface_network_cidr(output), None);
        assert_eq!(parse_interface_network_cidr(""), None);
    }

    #[test]
    fn parse_interface_network_cidr_rejects_malformed_and_out_of_range_prefixes() {
        // Missing "/prefix" entirely.
        let no_prefix = "3: uap1: <UP>\n    inet 192.168.200.1 scope global uap1\n";
        assert_eq!(parse_interface_network_cidr(no_prefix), None);

        // Prefix out of the valid 0..=32 range.
        let bad_prefix = "3: uap1: <UP>\n    inet 192.168.200.1/33 scope global uap1\n";
        assert_eq!(parse_interface_network_cidr(bad_prefix), None);
    }

    #[test]
    fn nat_manager_starts_disabled_and_kernel_check_short_circuits_without_syscalls() {
        let nat = NatManager::new();
        assert!(!nat.is_enabled());
        // `kernel_rules_active` must bail out on the in-memory flag before it
        // would otherwise shell out to `nft`/`ip`, so this is safe to assert
        // without touching real network or firewall state.
        assert!(!nat.kernel_rules_active("ap0", "wlan0"));

        let default_nat = NatManager::default();
        assert!(!default_nat.is_enabled());
    }
}

/// Tests for the live NAT bring-up path.
///
/// `enable_nat`/`disable_nat` end in `enforcement::apply_policy`, which drives
/// `nft` — not installed here — so both fail deterministically at that final
/// step. Everything before it (subnet discovery from a real interface, the
/// uplink fan-out, the full dynamic rule set, and the merge with the signed
/// policy) runs for real, which is the part with actual decision logic in it.
#[cfg(test)]
mod live_nat_tests {
    use super::{interface_network_cidr, NatManager};
    use std::sync::atomic::Ordering;

    const MISSING_IFACE: &str = "sgxtest-nodev0";

    fn nft_installed() -> bool {
        std::process::Command::new("nft").arg("--version").output().is_ok()
    }

    #[test]
    fn interface_network_cidr_derives_the_subnet_from_a_real_interface() {
        assert_eq!(interface_network_cidr("lo").unwrap(), "127.0.0.0/8");
    }

    #[test]
    fn interface_network_cidr_reports_an_absent_interface() {
        // `ip` exits non-zero for a device that does not exist, so this is the
        // "command ran but failed" branch rather than the spawn-failure branch.
        let error = interface_network_cidr(MISSING_IFACE)
            .expect_err("a missing interface has no subnet");
        assert!(
            error.to_string().contains(MISSING_IFACE),
            "the error must name the interface: {error}"
        );
    }

    #[test]
    fn enable_nat_rejects_an_interface_without_a_subnet() {
        let manager = NatManager::new();
        let error = manager
            .enable_nat(MISSING_IFACE, "wlan0", false)
            .expect_err("NAT needs the hotspot subnet before it can build any rule");
        assert!(error.to_string().contains(MISSING_IFACE));
        assert!(!manager.is_enabled(), "a failed enable must not flip the flag");
    }

    #[test]
    fn enable_nat_builds_the_full_rule_set_then_fails_at_the_enforcement_engine() {
        if nft_installed() {
            return; // a host with nftables would apply real firewall rules
        }
        let manager = NatManager::new();
        // `lo` yields 127.0.0.0/8, so the uplink fan-out (wlan0 -> wlan1, eth0)
        // and every masquerade/forward/isolation rule is constructed and merged
        // with the signed policy before `nft` is reached and refuses.
        let error = manager
            .enable_nat("lo", "wlan0", true)
            .expect_err("nftables is not installed, so the policy cannot be applied");
        assert!(
            error.to_string().starts_with("Failed to enable NAT"),
            "unexpected failure: {error}"
        );
        assert!(
            !manager.is_enabled(),
            "the enabled flag is only set after the policy actually applies"
        );

        // The sibling-uplink branch flips when the caller passes wlan1 instead,
        // producing a different fan-out through the same code path.
        assert!(manager.enable_nat("lo", "wlan1", false).is_err());
    }

    #[test]
    fn disable_nat_clears_the_flag_by_removing_the_policy_outright() {
        let manager = NatManager::new();
        manager.is_enabled.store(true, Ordering::SeqCst);
        // With no signed policy cached, disabling takes the `remove_policy`
        // branch rather than reapplying one. Unlike `apply_policy`, removal
        // succeeds with no enforcement backend present — there is nothing to
        // tear down — so this is the success path, and the flag must clear.
        manager
            .disable_nat()
            .expect("removing an absent policy must succeed");
        assert!(!manager.is_enabled());

        // Idempotent: disabling an already-disabled manager is still fine.
        manager.disable_nat().expect("disable must be idempotent");
        assert!(!manager.is_enabled());
    }

    #[test]
    fn kernel_rules_active_is_false_when_the_tables_cannot_be_read() {
        if nft_installed() {
            return;
        }
        let manager = NatManager::new();
        // The flag is the first gate: an un-enabled manager never shells out.
        assert!(!manager.kernel_rules_active("lo", "wlan0"));

        // Force the flag on to get past it. `lo` resolves a subnet, so both
        // `nft list chain` calls run — and fail to spawn, which the function
        // must read as "the kernel rules are not in place" rather than trusting
        // the in-memory flag.
        manager.is_enabled.store(true, Ordering::SeqCst);
        assert!(!manager.kernel_rules_active("lo", "wlan0"));
        assert!(manager.is_enabled(), "the check must not clear the flag");

        // An interface with no subnet fails the second gate, before any `nft`.
        assert!(!manager.kernel_rules_active(MISSING_IFACE, "wlan0"));

        manager.is_enabled.store(false, Ordering::SeqCst);
    }
}
