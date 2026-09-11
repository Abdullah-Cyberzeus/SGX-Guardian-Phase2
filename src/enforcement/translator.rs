//! Policy → EnforcementRule translator
//!
//! Converts a verified Policy into an internal,
//! OS-agnostic enforcement rule set.

use crate::enforcement::model::{
    Action, ConntrackState, EnforcementRule, ForwardRule, InterfaceMatch, IsolationRule, NatRule,
    PortRange, Protocol,
};
use crate::policy::Policy;
use anyhow::{anyhow, Result};

pub struct TranslatedRules {
    pub enforcement: Vec<EnforcementRule>,
    pub nat: Vec<NatRule>,
    pub forward: Vec<ForwardRule>,
    pub isolation: Vec<IsolationRule>,
}

pub fn translate(policy: &Policy) -> Result<TranslatedRules> {
    let mut rules = TranslatedRules {
        enforcement: Vec::new(),
        nat: Vec::new(),
        forward: Vec::new(),
        isolation: Vec::new(),
    };

    for rule in &policy.rules {
        // --- Action ---
        let action = match rule.action.to_lowercase().as_str() {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            "masquerade" => Action::Masquerade,
            other => {
                return Err(anyhow!(
                    "rule '{}' has unsupported action '{}'",
                    rule.id,
                    other
                ))
            }
        };

        // --- Interface Parsing ---
        let mut in_interface = None;
        let mut out_interface = None;

        let src_lower = rule.src.to_lowercase();
        if is_ap_interface(&src_lower) || is_uplink_interface(&src_lower) {
            in_interface = Some(src_lower.clone());
        }

        let dst_lower = rule.dst.to_lowercase();
        if is_ap_interface(&dst_lower) || is_uplink_interface(&dst_lower) {
            out_interface = Some(dst_lower.clone());
        }

        // --- Conntrack State Parsing ---
        let mut state = None;
        let mut protocol = None;
        let proto_lower = rule.protocol.to_lowercase();

        if let Some(stripped) = proto_lower.strip_prefix("state:") {
            let mut states = Vec::new();
            for s in stripped.split(',') {
                match s.trim() {
                    "new" => states.push(ConntrackState::New),
                    "established" => states.push(ConntrackState::Established),
                    "related" => states.push(ConntrackState::Related),
                    "invalid" => states.push(ConntrackState::Invalid),
                    other => {
                        return Err(anyhow!(
                            "rule '{}' has unsupported state '{}'",
                            rule.id,
                            other
                        ))
                    }
                }
            }
            state = Some(states);
        } else {
            protocol = match proto_lower.as_str() {
                "tcp" => Some(Protocol::Tcp),
                "udp" => Some(Protocol::Udp),
                "any" => None,
                other => {
                    return Err(anyhow!(
                        "rule '{}' has unsupported protocol '{}'",
                        rule.id,
                        other
                    ))
                }
            };
        }

        // --- Port / Port Range ---
        let ports = rule.port.map(|p| PortRange { start: p, end: p });

        // --- Categorization ---
        match action {
            Action::Masquerade => {
                rules.nat.push(NatRule {
                    action,
                    out_interface,
                    src_subnet: if src_lower != "any" && in_interface.is_none() {
                        Some(rule.src.clone())
                    } else {
                        None
                    },
                });
            }
            Action::Allow
                if in_interface.is_some() || out_interface.is_some() || state.is_some() =>
            {
                if ports.is_some() || protocol.is_some() {
                    return Err(anyhow!(
                        "rule '{}' is a forward rule but specifies protocol/port restrictions, which are not supported",
                        rule.id
                    ));
                }
                rules.forward.push(ForwardRule {
                    action,
                    interfaces: InterfaceMatch {
                        in_interface,
                        out_interface,
                    },
                    state,
                });
            }
            Action::Deny if in_interface.is_some() || out_interface.is_some() => {
                if dst_lower == "local" {
                    if let Some(proto) = protocol {
                        rules.enforcement.push(EnforcementRule {
                            action,
                            protocol: proto,
                            src_ip: None,
                            dst_ip: None,
                            ports,
                            in_interface,
                        });
                    } else {
                        return Err(anyhow!(
                            "API Protection rule '{}' requires a protocol",
                            rule.id
                        ));
                    }
                } else {
                    rules.isolation.push(IsolationRule {
                        action,
                        interfaces: InterfaceMatch {
                            in_interface,
                            out_interface,
                        },
                    });
                }
            }
            _ => {
                // Standard EnforcementRule
                if let Some(proto) = protocol {
                    rules.enforcement.push(EnforcementRule {
                        action,
                        protocol: proto,
                        src_ip: if src_lower == "any" {
                            None
                        } else {
                            Some(rule.src.clone())
                        },
                        dst_ip: if dst_lower == "any" {
                            None
                        } else {
                            Some(rule.dst.clone())
                        },
                        ports,
                        in_interface: None,
                    });
                } else {
                    return Err(anyhow!(
                        "rule '{}' requires a specific protocol (tcp/udp) for generic enforcement",
                        rule.id
                    ));
                }
            }
        }
    }

    Ok(rules)
}

/// Helper to check if an interface is an AP interface (starts with ap, uap, or wlan2/wlan3 for virtual setups)
fn is_ap_interface(iface: &str) -> bool {
    iface.starts_with("ap") || iface.starts_with("uap") || iface == "wlan2" || iface == "wlan3"
}

/// Helper to check if an interface is an uplink interface (Ethernet, either
/// Wi-Fi radio, or cellular).
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
    fn test_translate_masquerade() {
        let policy = dummy_policy(vec![Rule {
            id: "1".to_string(),
            action: "masquerade".to_string(),
            src: "192.168.200.0/24".to_string(),
            dst: "ap0".to_string(),
            protocol: "any".to_string(),
            port: None,
        }]);

        let translated = translate(&policy).unwrap();
        assert_eq!(translated.nat.len(), 1);
        let nat_rule = &translated.nat[0];
        assert_eq!(nat_rule.action, Action::Masquerade);
        assert_eq!(nat_rule.out_interface.as_deref(), Some("ap0"));
        assert_eq!(nat_rule.src_subnet.as_deref(), Some("192.168.200.0/24"));
    }

    #[test]
    fn test_translate_forward_allow() {
        let policy = dummy_policy(vec![Rule {
            id: "2".to_string(),
            action: "allow".to_string(),
            src: "ap0".to_string(),
            dst: "wlan1".to_string(),
            protocol: "any".to_string(),
            port: None,
        }]);

        let translated = translate(&policy).unwrap();
        assert_eq!(translated.forward.len(), 1);
        let fwd_rule = &translated.forward[0];
        assert_eq!(fwd_rule.action, Action::Allow);
        assert_eq!(fwd_rule.interfaces.in_interface.as_deref(), Some("ap0"));
        assert_eq!(fwd_rule.interfaces.out_interface.as_deref(), Some("wlan1"));
    }

    #[test]
    fn test_translate_conntrack_state() {
        let policy = dummy_policy(vec![Rule {
            id: "3".to_string(),
            action: "allow".to_string(),
            src: "wlan1".to_string(),
            dst: "ap0".to_string(),
            protocol: "state: established, related".to_string(),
            port: None,
        }]);

        let translated = translate(&policy).unwrap();
        assert_eq!(translated.forward.len(), 1);
        let fwd_rule = &translated.forward[0];
        assert_eq!(fwd_rule.action, Action::Allow);
        let states = fwd_rule.state.as_ref().unwrap();
        assert!(states.contains(&ConntrackState::Established));
        assert!(states.contains(&ConntrackState::Related));
    }

    #[test]
    fn test_translate_isolation_deny() {
        let policy = dummy_policy(vec![Rule {
            id: "4".to_string(),
            action: "deny".to_string(),
            src: "ap0".to_string(),
            dst: "ap0".to_string(),
            protocol: "any".to_string(),
            port: None,
        }]);

        let translated = translate(&policy).unwrap();
        assert_eq!(translated.isolation.len(), 1);
        let iso_rule = &translated.isolation[0];
        assert_eq!(iso_rule.action, Action::Deny);
        assert_eq!(iso_rule.interfaces.in_interface.as_deref(), Some("ap0"));
        assert_eq!(iso_rule.interfaces.out_interface.as_deref(), Some("ap0"));
    }

    #[test]
    fn test_translate_enforcement_allow() {
        let policy = dummy_policy(vec![Rule {
            id: "5".to_string(),
            action: "allow".to_string(),
            src: "any".to_string(),
            dst: "any".to_string(),
            protocol: "tcp".to_string(),
            port: Some(80),
        }]);

        let translated = translate(&policy).unwrap();
        assert_eq!(translated.enforcement.len(), 1);
        let enf_rule = &translated.enforcement[0];
        assert_eq!(enf_rule.action, Action::Allow);
        assert_eq!(enf_rule.protocol, Protocol::Tcp);
        assert_eq!(enf_rule.src_ip, None);
        assert_eq!(enf_rule.dst_ip, None);
        assert_eq!(enf_rule.ports.as_ref().unwrap().start, 80);
    }
}
