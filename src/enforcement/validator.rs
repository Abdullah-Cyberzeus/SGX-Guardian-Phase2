//! Enforcement safety validation.
//!
//! Ensures policy is sane BEFORE translation or execution.

use crate::policy::Policy;
use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::net::Ipv4Addr;

pub fn validate_policy(policy: &Policy) -> Result<()> {
    // Policy must contain at least one rule
    if policy.rules.is_empty() {
        return Err(anyhow!("policy contains no enforcement rules"));
    }

    let mut seen_rules = HashSet::new();

    for rule in &policy.rules {
        // Basic string presence checks
        if rule.action.trim().is_empty() {
            return Err(anyhow!("rule '{}' missing action", rule.id));
        }

        if rule.protocol.trim().is_empty() {
            return Err(anyhow!("rule '{}' missing protocol", rule.id));
        }

        if rule.src.trim().is_empty() {
            return Err(anyhow!("rule '{}' missing source address", rule.id));
        }

        if rule.dst.trim().is_empty() {
            return Err(anyhow!("rule '{}' missing destination address", rule.id));
        }

        // Port sanity
        if let Some(port) = rule.port {
            if port == 0 {
                return Err(anyhow!("rule '{}' has invalid port 0", rule.id));
            }
        }

        let action = rule.action.to_lowercase();
        let src = rule.src.to_lowercase();
        let dst = rule.dst.to_lowercase();
        let proto = rule.protocol.to_lowercase();

        // 1. Validate Interface Names
        let is_src_iface = is_ap_interface(&src) || is_uplink_interface(&src) || src == "any";
        let is_dst_iface =
            is_ap_interface(&dst) || is_uplink_interface(&dst) || dst == "any" || dst == "local";

        // 2. Validate IP/CIDR formats
        if !is_src_iface && !is_valid_ipv4_or_cidr(&src) {
            return Err(anyhow!(
                "rule '{}' has invalid source IP/CIDR format: {}",
                rule.id,
                src
            ));
        }
        if !is_dst_iface && !is_valid_ipv4_or_cidr(&dst) {
            return Err(anyhow!(
                "rule '{}' has invalid destination IP/CIDR format: {}",
                rule.id,
                dst
            ));
        }

        // 3. Validate Masquerade / NAT Configuration
        if action == "masquerade" {
            // Masquerade MUST egress via the uplink (e.g. wlan1, wlan0, eth0)
            if !is_uplink_interface(&dst) {
                return Err(anyhow!(
                    "rule '{}' (masquerade) must specify an uplink interface ('wlan1', 'wlan0', 'wwan0', or 'eth0') as destination",
                    rule.id
                ));
            }
            if !is_ap_interface(&src) && src != "any" && !is_valid_ipv4_or_cidr(&src) {
                return Err(anyhow!(
                    "rule '{}' (masquerade) must specify an AP interface, 'any', or a valid internal subnet as source",
                    rule.id
                ));
            }
        }

        // 4. Validate Forwarding Rules
        if action == "allow"
            && is_uplink_interface(&src)
            && is_ap_interface(&dst)
            && !proto.starts_with("state:")
        {
            // Strict check: inbound traffic from the untrusted uplink to the AP should be stateful
            // (e.g. state:established,related) to prevent unauthorized ingress.
            // We will warn or reject based on strictness. Let's reject to be safe.
            return Err(anyhow!(
                    "rule '{}' allows inbound forwarding from an uplink interface to an AP interface but lacks strict state tracking (e.g. 'state:established,related')",
                    rule.id
                ));
        }

        // 5. Validate Conntrack States
        if let Some(states_str) = proto.strip_prefix("state:") {
            for state in states_str.split(',') {
                let s = state.trim();
                if s != "new" && s != "established" && s != "related" && s != "invalid" {
                    return Err(anyhow!(
                        "rule '{}' has invalid conntrack state: {}",
                        rule.id,
                        s
                    ));
                }
            }
        } else if proto != "tcp" && proto != "udp" && proto != "any" {
            return Err(anyhow!(
                "rule '{}' has unsupported protocol: {}",
                rule.id,
                proto
            ));
        }

        // 6. Prevent Duplicate Rules
        let signature = format!("{}-{}-{}-{}-{:?}", action, src, dst, proto, rule.port);
        if !seen_rules.insert(signature) {
            return Err(anyhow!(
                "rule '{}' is an exact duplicate of a previously defined rule",
                rule.id
            ));
        }

        // 7. Validate no global drop-all mistakes
        if action == "deny" && src == "any" && dst == "any" && proto == "any" {
            return Err(anyhow!(
                "rule '{}' is a global drop-all which can dangerously lock out the system",
                rule.id
            ));
        }
    }

    Ok(())
}

/// Helper to validate standard IPv4 addresses and CIDR notation
fn is_valid_ipv4_or_cidr(ip_str: &str) -> bool {
    let parts: Vec<&str> = ip_str.split('/').collect();
    if parts.len() > 2 || parts.is_empty() {
        return false;
    }

    if parts[0].parse::<Ipv4Addr>().is_err() {
        return false;
    }

    if parts.len() == 2 {
        if let Ok(mask) = parts[1].parse::<u8>() {
            if mask > 32 {
                return false;
            }
        } else {
            return false;
        }
    }

    true
}

/// Helper to check if an interface is an AP interface (starts with ap, uap, or wlan2/wlan3 for virtual setups)
fn is_ap_interface(iface: &str) -> bool {
    iface.starts_with("ap") || iface.starts_with("uap") || iface == "wlan2" || iface == "wlan3"
}

/// Helper to check if an interface is an uplink interface (Ethernet, either
/// Wi-Fi radio, or cellular) — any interface that can plausibly carry the
/// board's default route.
fn is_uplink_interface(iface: &str) -> bool {
    iface == "wlan0" || iface == "wlan1" || iface == "wwan0" || iface.starts_with("eth")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, Rule};

    fn dummy_policy(rules: Vec<Rule>) -> Policy {
        Policy {
            policy_id: "test-policy".to_string(),
            version: "1.0".to_string(),
            rules,
        }
    }

    #[test]
    fn test_valid_policy() {
        let policy = dummy_policy(vec![Rule {
            id: "1".to_string(),
            action: "allow".to_string(),
            src: "192.168.1.0/24".to_string(),
            dst: "any".to_string(),
            protocol: "tcp".to_string(),
            port: Some(443),
        }]);
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_empty_policy() {
        let policy = dummy_policy(vec![]);
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_invalid_port_0() {
        let policy = dummy_policy(vec![Rule {
            id: "1".to_string(),
            action: "allow".to_string(),
            src: "any".to_string(),
            dst: "any".to_string(),
            protocol: "tcp".to_string(),
            port: Some(0),
        }]);
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_invalid_ip_cidr() {
        let policy = dummy_policy(vec![Rule {
            id: "1".to_string(),
            action: "allow".to_string(),
            src: "300.0.0.1/40".to_string(), // Invalid IP and CIDR
            dst: "any".to_string(),
            protocol: "tcp".to_string(),
            port: None,
        }]);
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_masquerade_invalid_destination() {
        let policy = dummy_policy(vec![Rule {
            id: "1".to_string(),
            action: "masquerade".to_string(),
            src: "ap0".to_string(),
            dst: "ap0".to_string(), // AP interface invalid as masquerade dest
            protocol: "any".to_string(),
            port: None,
        }]);
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_inbound_forwarding_needs_state() {
        let policy = dummy_policy(vec![Rule {
            id: "1".to_string(),
            action: "allow".to_string(),
            src: "wlan1".to_string(),
            dst: "ap0".to_string(),
            protocol: "tcp".to_string(), // Missing state
            port: None,
        }]);
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_inbound_forwarding_with_state() {
        let policy = dummy_policy(vec![Rule {
            id: "1".to_string(),
            action: "allow".to_string(),
            src: "wlan1".to_string(),
            dst: "ap0".to_string(),
            protocol: "state:established,related".to_string(),
            port: None,
        }]);
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_global_drop_all() {
        let policy = dummy_policy(vec![Rule {
            id: "1".to_string(),
            action: "deny".to_string(),
            src: "any".to_string(),
            dst: "any".to_string(),
            protocol: "any".to_string(),
            port: None,
        }]);
        assert!(validate_policy(&policy).is_err());
    }
}
