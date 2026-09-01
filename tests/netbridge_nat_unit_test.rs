use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule {
    id: String,
    action: String,
    src: String,
    dst: String,
    protocol: String,
    port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Policy {
    policy_id: String,
    version: String,
    rules: Vec<Rule>,
}

fn rule(id: &str) -> Rule {
    Rule {
        id: id.into(),
        action: "allow".into(),
        src: "src".into(),
        dst: "dst".into(),
        protocol: "tcp".into(),
        port: Some(443),
    }
}

fn merge_with_policy(active: Option<Policy>, dynamic_rules: Vec<Rule>) -> Policy {
    let mut policy = active.unwrap_or_else(|| Policy {
        policy_id: "netbridge_dynamic_nat".to_string(),
        version: "1.0".to_string(),
        rules: Vec::new(),
    });
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
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    Some(format!("{}/{}", network, prefix))
}

struct NatManagerShim {
    is_enabled: AtomicBool,
}

impl NatManagerShim {
    fn new() -> Self {
        Self {
            is_enabled: AtomicBool::new(false),
        }
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled.load(Ordering::SeqCst)
    }

    fn kernel_rules_active(&self) -> bool {
        self.is_enabled()
    }
}

impl Default for NatManagerShim {
    fn default() -> Self {
        Self::new()
    }
}

#[test]
fn new_manager_starts_disabled() {
    assert!(!NatManagerShim::new().is_enabled());
}

#[test]
fn default_manager_starts_disabled() {
    assert!(!NatManagerShim::default().is_enabled());
}

#[test]
fn kernel_rules_active_short_circuits_when_disabled() {
    assert!(!NatManagerShim::new().kernel_rules_active());
}

#[test]
fn parses_simple_ipv4_cidr() {
    assert_eq!(
        parse_interface_network_cidr("2: ap0\n    inet 192.168.200.1/24 scope global ap0\n")
            .as_deref(),
        Some("192.168.200.0/24")
    );
}

#[test]
fn parses_cidr_with_leading_spaces() {
    assert_eq!(
        parse_interface_network_cidr("    inet 10.10.5.99/16 brd 10.10.255.255").as_deref(),
        Some("10.10.0.0/16")
    );
}

#[test]
fn parses_first_ipv4_inet_line() {
    let output = "inet6 fe80::1/64\ninet 172.16.9.3/20 scope global\ninet 10.0.0.1/8\n";
    assert_eq!(parse_interface_network_cidr(output).as_deref(), Some("172.16.0.0/20"));
}

#[test]
fn prefix_zero_maps_to_default_network() {
    assert_eq!(
        parse_interface_network_cidr("inet 192.168.50.10/0 scope global").as_deref(),
        Some("0.0.0.0/0")
    );
}

#[test]
fn prefix_thirty_two_preserves_host_address() {
    assert_eq!(
        parse_interface_network_cidr("inet 192.168.50.10/32 scope global").as_deref(),
        Some("192.168.50.10/32")
    );
}

#[test]
fn rejects_prefix_above_thirty_two() {
    assert!(parse_interface_network_cidr("inet 192.168.50.10/33").is_none());
}

#[test]
fn rejects_missing_inet_line() {
    assert!(parse_interface_network_cidr("inet6 fe80::1/64").is_none());
}

#[test]
fn rejects_invalid_ip_address() {
    assert!(parse_interface_network_cidr("inet 999.1.1.1/24").is_none());
}

#[test]
fn rejects_invalid_prefix() {
    assert!(parse_interface_network_cidr("inet 192.168.50.10/not-a-prefix").is_none());
}

#[test]
fn rejects_missing_prefix_separator() {
    assert!(parse_interface_network_cidr("inet 192.168.50.10 scope global").is_none());
}

#[test]
fn merge_without_active_policy_uses_dynamic_nat_policy_identity() {
    let merged = merge_with_policy(None, vec![rule("dyn_nat_masquerade_01")]);
    assert_eq!(merged.policy_id, "netbridge_dynamic_nat");
    assert_eq!(merged.version, "1.0");
    assert_eq!(merged.rules.len(), 1);
}

#[test]
fn merge_preserves_static_active_rules_and_identity() {
    let active = Policy {
        policy_id: "signed".into(),
        version: "2".into(),
        rules: vec![rule("static_allow")],
    };
    let merged = merge_with_policy(Some(active), vec![rule("dyn_nat_masquerade_01")]);
    assert_eq!(merged.policy_id, "signed");
    assert_eq!(merged.version, "2");
    assert!(merged.rules.iter().any(|rule| rule.id == "static_allow"));
    assert!(merged.rules.iter().any(|rule| rule.id == "dyn_nat_masquerade_01"));
}

#[test]
fn merge_removes_previous_dynamic_rules_before_extending() {
    let active = Policy {
        policy_id: "signed".into(),
        version: "2".into(),
        rules: vec![rule("static_allow"), rule("dyn_old")],
    };
    let merged = merge_with_policy(Some(active), vec![rule("dyn_new_a"), rule("dyn_new_b")]);
    assert!(!merged.rules.iter().any(|rule| rule.id == "dyn_old"));
    assert_eq!(
        merged.rules.iter().filter(|rule| rule.id.starts_with("dyn_")).count(),
        2
    );
}
