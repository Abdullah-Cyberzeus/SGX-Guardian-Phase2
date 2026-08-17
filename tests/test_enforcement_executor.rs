use sgx_guardian_client::enforcement::executor::{
    build_nft_ruleset, render_enforcement, render_forward, render_isolation, render_nat,
};
use sgx_guardian_client::enforcement::model::{
    Action, ConntrackState, EnforcementRule, ForwardRule, InterfaceMatch, IsolationRule, NatRule,
    PortRange, Protocol,
};
use sgx_guardian_client::enforcement::translator::TranslatedRules;

#[test]
fn test_render_enforcement() {
    let rule = EnforcementRule {
        in_interface: Some("wlan1".to_string()),
        src_ip: None,
        dst_ip: Some("192.168.1.100".to_string()),
        protocol: Protocol::Tcp,
        ports: Some(PortRange { start: 80, end: 80 }),
        action: Action::Allow,
    };
    let res = render_enforcement(&rule).unwrap();
    assert_eq!(
        res,
        "iifname \"wlan1\" ip daddr 192.168.1.100 tcp dport 80 accept"
    );
}

#[test]
fn test_render_forward() {
    let rule = ForwardRule {
        interfaces: InterfaceMatch {
            in_interface: Some("wlan1".to_string()),
            out_interface: Some("uap1".to_string()),
        },
        state: Some(vec![ConntrackState::Established, ConntrackState::Related]),
        action: Action::Allow,
    };
    let res = render_forward(&rule).unwrap();
    assert_eq!(
        res,
        "iifname \"wlan1\" oifname \"uap1\" ct state established,related accept"
    );
}

#[test]
fn test_render_isolation() {
    let rule = IsolationRule {
        interfaces: InterfaceMatch {
            in_interface: Some("uap1".to_string()),
            out_interface: Some("uap1".to_string()),
        },
        action: Action::Deny,
    };
    let res = render_isolation(&rule).unwrap();
    assert_eq!(res, "iifname \"uap1\" oifname \"uap1\" drop");
}

#[test]
fn test_render_nat() {
    let rule = NatRule {
        src_subnet: Some("192.168.200.0/24".to_string()),
        out_interface: Some("wlan1".to_string()),
        action: Action::Masquerade,
    };
    let res = render_nat(&rule).unwrap();
    assert_eq!(
        res,
        "ip saddr 192.168.200.0/24 oifname \"wlan1\" masquerade"
    );
}

#[test]
fn test_build_nft_ruleset() {
    let rules = TranslatedRules {
        enforcement: vec![],
        forward: vec![ForwardRule {
            interfaces: InterfaceMatch {
                in_interface: Some("uap1".to_string()),
                out_interface: Some("wlan1".to_string()),
            },
            state: None,
            action: Action::Allow,
        }],
        isolation: vec![],
        nat: vec![NatRule {
            src_subnet: Some("192.168.200.0/24".to_string()),
            out_interface: Some("wlan1".to_string()),
            action: Action::Masquerade,
        }],
    };

    let ruleset = build_nft_ruleset(&rules).unwrap();
    assert!(ruleset.contains("table inet sgx_guardian {"));
    assert!(ruleset.contains("table ip sgx_nat {"));
    assert!(ruleset.contains("iifname \"uap1\" oifname \"wlan1\" accept"));
    assert!(ruleset.contains("ip saddr 192.168.200.0/24 oifname \"wlan1\" masquerade"));
    assert!(ruleset.contains("iifname \"nebula0\" tcp dport 8443 accept"));
    assert!(!ruleset.contains("    tcp dport 8443 accept\n"));
}
