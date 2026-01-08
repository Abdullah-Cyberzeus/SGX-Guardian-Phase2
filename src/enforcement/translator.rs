//! Policy → EnforcementRule translator
//!
//! Converts a verified Policy into an internal,
//! OS-agnostic enforcement rule set.

use crate::enforcement::model::{Action, EnforcementRule, PortRange, Protocol};
use crate::policy::Policy;
use anyhow::{anyhow, Result};

pub fn translate(policy: &Policy) -> Result<Vec<EnforcementRule>> {
    let mut rules = Vec::new();

    for rule in &policy.rules {
        // --- Action ---
        let action = match rule.action.to_lowercase().as_str() {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            other => {
                return Err(anyhow!(
                    "rule '{}' has unsupported action '{}'",
                    rule.id,
                    other
                ))
            }
        };

        // --- Protocol ---
        let protocol = match rule.protocol.to_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => {
                return Err(anyhow!(
                    "rule '{}' has unsupported protocol '{}'",
                    rule.id,
                    other
                ))
            }
        };

        // --- Source IP ---
        let src_ip = match rule.src.to_lowercase().as_str() {
            "any" => None,
            value => Some(value.to_string()),
        };

        // --- Destination IP ---
        let dst_ip = match rule.dst.to_lowercase().as_str() {
            "any" => None,
            value => Some(value.to_string()),
        };

        // --- Port / Port Range ---
        let ports = rule.port.map(|p| PortRange { start: p, end: p });

        rules.push(EnforcementRule {
            action,
            protocol,
            src_ip,
            dst_ip,
            ports,
        });
    }

    Ok(rules)
}
