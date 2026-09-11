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
use std::sync::{Mutex, OnceLock};
use tracing::{info, warn};

/// Every interface that can plausibly hold the board's default route for a
/// given selected uplink: the selected interface itself, its sibling Wi-Fi
/// radio, Ethernet, and cellular. See `enable_nat` for why all of them stay
/// permitted rather than only the one selected when the mode started.
fn uplinks_for(out_iface: &str) -> Vec<&str> {
    let sibling_uplink = if out_iface == "wlan0" {
        "wlan1"
    } else {
        "wlan0"
    };
    let mut uplinks: Vec<&str> = vec![out_iface];
    for candidate in [sibling_uplink, "eth0", "wwan0"] {
        if !uplinks.contains(&candidate) {
            uplinks.push(candidate);
        }
    }
    uplinks
}

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
    /// Legacy-iptables FORWARD rules this manager inserted, kept so teardown
    /// removes exactly what was added.
    legacy_forward_rules: Mutex<Vec<Vec<String>>>,
}

impl NatManager {
    pub fn new() -> Self {
        Self {
            is_enabled: AtomicBool::new(false),
            legacy_forward_rules: Mutex::new(Vec::new()),
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

        // Cover every interface that can plausibly hold the board's default route
        // (Ethernet, either Wi-Fi radio, cellular). The target kernel has no
        // policy-routing support, so forwarded hotspot traffic must be allowed to
        // follow whichever egress the kernel's main routing table is actually using
        // right now — that can change on its own (Wi-Fi drops, cellular takes over)
        // without Guardian restarting NAT, so all of them stay permitted rather than
        // only the interface selected when this mode started.
        let uplinks = uplinks_for(out_iface);

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

        // Legacy iptables hooks FORWARD at the same priority as the nftables chain
        // above but is invisible to `nft list ruleset`. Docker sets its policy to
        // DROP, which silently discards hotspot traffic even when every nftables
        // rule permits it. A packet must be accepted by both layers, so Guardian's
        // nftables policy still governs what is allowed.
        self.allow_legacy_forward(in_iface, &uplinks);

        self.is_enabled.store(true, Ordering::SeqCst);
        info!("✅ Network routing and Firewall rules successfully applied.");

        Ok(())
    }

    /// True when a legacy `iptables` binary is present. Probed once: boards
    /// without it need no compatibility rules at all.
    fn legacy_iptables_present() -> bool {
        static PRESENT: OnceLock<bool> = OnceLock::new();
        *PRESENT.get_or_init(|| {
            Command::new("iptables")
                .arg("--version")
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        })
    }

    fn run_iptables(action: &[&str], spec: &[String]) -> bool {
        let mut args: Vec<&str> = action.to_vec();
        args.extend(spec.iter().map(|value| value.as_str()));
        Command::new("iptables")
            .args(&args)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn legacy_forward_specs(in_iface: &str, uplink: &str) -> [Vec<String>; 2] {
        [
            vec![
                "-i".to_owned(),
                in_iface.to_owned(),
                "-o".to_owned(),
                uplink.to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
            vec![
                "-i".to_owned(),
                uplink.to_owned(),
                "-o".to_owned(),
                in_iface.to_owned(),
                "-m".to_owned(),
                "conntrack".to_owned(),
                "--ctstate".to_owned(),
                "RELATED,ESTABLISHED".to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
        ]
    }

    fn allow_legacy_forward(&self, in_iface: &str, uplinks: &[&str]) {
        if !Self::legacy_iptables_present() {
            return;
        }

        let mut recorded = Vec::new();
        for uplink in uplinks {
            for spec in Self::legacy_forward_specs(in_iface, uplink) {
                if !Self::run_iptables(&["-C", "FORWARD"], &spec)
                    && !Self::run_iptables(&["-I", "FORWARD", "1"], &spec)
                {
                    warn!(
                        "Failed to add legacy iptables FORWARD accept for {} -> {}",
                        in_iface, uplink
                    );
                    continue;
                }
                recorded.push(spec);
            }
        }

        if let Ok(mut stored) = self.legacy_forward_rules.lock() {
            *stored = recorded;
        }
    }

    fn remove_legacy_forward(&self) {
        let rules = self
            .legacy_forward_rules
            .lock()
            .map(|mut stored| std::mem::take(&mut *stored))
            .unwrap_or_default();

        for spec in rules {
            // Delete duplicates too, including any left by an interrupted run.
            for _ in 0..8 {
                if !Self::run_iptables(&["-C", "FORWARD"], &spec) {
                    break;
                }
                if !Self::run_iptables(&["-D", "FORWARD"], &spec) {
                    break;
                }
            }
        }
    }

    /// Removes all NAT and forwarding policies by clearing the enforcement rules.
    pub fn disable_nat(&self) -> Result<()> {
        tracing::debug!("Removing NAT and Forwarding policies...");
        self.remove_legacy_forward();
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

        // A Docker restart rebuilds the legacy FORWARD chain and can drop Guardian's
        // accept rule, so verify that layer too rather than only the nftables tables.
        let legacy_ok = !Self::legacy_iptables_present()
            || Self::legacy_forward_specs(in_iface, out_iface)
                .iter()
                .all(|spec| Self::run_iptables(&["-C", "FORWARD"], spec));

        legacy_ok
            && nat.contains("masquerade")
            && nat.contains(&format!("ip saddr {}", hotspot_cidr))
            && nat.contains(&format!("oifname \"{}\"", out_iface))
            && forward.contains(&format!("iifname \"{}\"", in_iface))
            && forward.contains(&format!("oifname \"{}\"", out_iface))
    }
}

#[cfg(test)]
mod tests {
    use super::{merge_with_active_policy, parse_interface_network_cidr, uplinks_for, NatManager};
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
    fn uplinks_for_covers_selected_sibling_ethernet_and_cellular() {
        // wwan0 was once missing from this list, which silently broke cellular
        // NAT — the masquerade/forward rules simply never covered it.
        let uplinks = uplinks_for("wlan1");
        assert!(uplinks.contains(&"wlan1"));
        assert!(uplinks.contains(&"wlan0"));
        assert!(uplinks.contains(&"eth0"));
        assert!(uplinks.contains(&"wwan0"));
        assert_eq!(uplinks.len(), 4, "no duplicates expected: {:?}", uplinks);
    }

    #[test]
    fn uplinks_for_never_lists_the_selected_interface_twice() {
        // When wlan0 itself is selected, its "sibling" is wlan1 — wlan0 must not
        // also appear via the sibling-candidate slot.
        let uplinks = uplinks_for("wlan0");
        assert_eq!(uplinks.iter().filter(|&&iface| iface == "wlan0").count(), 1);
        assert!(uplinks.contains(&"wlan1"));
    }

    #[test]
    fn uplinks_for_deduplicates_when_selected_interface_is_ethernet() {
        // eth0 selected as uplink: it's both the selected interface and one of
        // the always-included candidates, so it must only appear once.
        let uplinks = uplinks_for("eth0");
        assert_eq!(uplinks.iter().filter(|&&iface| iface == "eth0").count(), 1);
    }

    #[test]
    fn legacy_forward_specs_allow_hotspot_to_uplink_and_established_return_traffic() {
        let [outbound, inbound] = NatManager::legacy_forward_specs("uap0", "wlan1");

        assert_eq!(outbound.join(" "), "-i uap0 -o wlan1 -j ACCEPT");
        assert_eq!(
            inbound.join(" "),
            "-i wlan1 -o uap0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        );
    }
}
