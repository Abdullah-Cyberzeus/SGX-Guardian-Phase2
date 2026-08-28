use sgx_guardian_client::enforcement::executor::{
    build_nft_ruleset, render_enforcement, render_forward, render_isolation, render_nat,
};
use sgx_guardian_client::enforcement::model::{
    Action, ConntrackState, EnforcementRule, ForwardRule, InterfaceMatch, IsolationRule, NatRule,
    PortRange, Protocol,
};
use sgx_guardian_client::enforcement::translator::{self, TranslatedRules};
use sgx_guardian_client::enforcement::uep::{MediaType, RbacRule, Role, UepDecision, UepEngine};
use sgx_guardian_client::enforcement::validator;
use sgx_guardian_client::policy::{Policy, Rule};
use std::collections::HashSet;

fn rule(id: &str, action: &str, src: &str, dst: &str, protocol: &str, port: Option<u16>) -> Rule {
    Rule {
        id: id.into(),
        action: action.into(),
        src: src.into(),
        dst: dst.into(),
        protocol: protocol.into(),
        port,
    }
}

fn policy(rules: Vec<Rule>) -> Policy {
    Policy {
        policy_id: "coverage-policy".into(),
        version: "1.0".into(),
        rules,
    }
}

fn validation_error(rule: Rule) -> String {
    validator::validate_policy(&policy(vec![rule]))
        .unwrap_err()
        .to_string()
}

#[test]
fn validator_rejects_empty_policy_missing_fields_and_zero_port() {
    assert!(validator::validate_policy(&policy(vec![]))
        .unwrap_err()
        .to_string()
        .contains("no enforcement rules"));
    for (candidate, expected) in [
        (rule("a", " ", "any", "any", "tcp", None), "missing action"),
        (
            rule("b", "allow", "any", "any", " ", None),
            "missing protocol",
        ),
        (
            rule("c", "allow", " ", "any", "tcp", None),
            "missing source",
        ),
        (
            rule("d", "allow", "any", " ", "tcp", None),
            "missing destination",
        ),
        (
            rule("e", "allow", "any", "any", "tcp", Some(0)),
            "invalid port 0",
        ),
    ] {
        assert!(validation_error(candidate).contains(expected));
    }
}

#[test]
fn validator_accepts_ipv4_cidr_boundaries_interfaces_and_rejects_invalid_addresses() {
    for (src, dst) in [
        ("0.0.0.0/0", "255.255.255.255/32"),
        ("AP9", "ETH7"),
        ("uap0", "wlan0"),
        ("wlan2", "wlan1"),
        ("wlan3", "local"),
    ] {
        validator::validate_policy(&policy(vec![rule("ok", "deny", src, dst, "tcp", None)]))
            .unwrap();
    }
    for (src, dst, expected) in [
        ("300.1.1.1", "any", "invalid source"),
        ("10.0.0.0/33", "any", "invalid source"),
        ("10.0.0.0/not-a-mask", "any", "invalid source"),
        ("10.0.0.0/24/1", "any", "invalid source"),
        ("any", "999.0.0.1", "invalid destination"),
    ] {
        assert!(validation_error(rule("bad", "allow", src, dst, "tcp", None)).contains(expected));
    }
}

#[test]
fn validator_covers_nat_inbound_state_protocol_duplicate_and_global_drop_safety() {
    assert!(
        validation_error(rule("nat", "masquerade", "ap0", "ap1", "any", None))
            .contains("must specify an uplink")
    );
    validator::validate_policy(&policy(vec![rule(
        "nat-ok",
        "masquerade",
        "192.168.10.0/24",
        "eth0",
        "any",
        None,
    )]))
    .unwrap();
    assert!(
        validation_error(rule("in", "allow", "wlan1", "ap0", "tcp", None))
            .contains("lacks strict state tracking")
    );
    validator::validate_policy(&policy(vec![rule(
        "state-ok",
        "allow",
        "wlan1",
        "ap0",
        "state:new, established, related, invalid",
        None,
    )]))
    .unwrap();
    assert!(validation_error(rule(
        "state-bad",
        "allow",
        "wlan1",
        "ap0",
        "state:established,bogus",
        None,
    ))
    .contains("invalid conntrack state"));
    assert!(
        validation_error(rule("proto", "allow", "any", "any", "icmp", None))
            .contains("unsupported protocol")
    );

    let duplicate = rule("first", "allow", "10.0.0.1", "10.0.0.2", "udp", Some(53));
    let mut duplicate_two = duplicate.clone();
    duplicate_two.id = "second".into();
    assert!(
        validator::validate_policy(&policy(vec![duplicate, duplicate_two]))
            .unwrap_err()
            .to_string()
            .contains("exact duplicate")
    );
    assert!(
        validation_error(rule("drop", "deny", "any", "any", "any", None))
            .contains("global drop-all")
    );
}

#[test]
fn translator_builds_udp_tcp_nat_forward_state_isolation_and_local_protection() {
    let translated = translator::translate(&policy(vec![
        rule("tcp", "ALLOW", "10.0.0.1", "10.0.0.2", "TCP", Some(443)),
        rule("udp", "deny", "any", "10.0.0.3", "udp", Some(53)),
        rule("nat", "masquerade", "192.168.5.0/24", "ETH0", "any", None),
        rule("forward", "allow", "UAP0", "wlan1", "any", None),
        rule(
            "state",
            "allow",
            "wlan0",
            "ap0",
            "state:new,established,related,invalid",
            None,
        ),
        rule("isolate", "deny", "ap0", "uap1", "any", None),
        rule("local", "deny", "ap0", "local", "tcp", Some(8443)),
    ]))
    .unwrap();
    assert_eq!(translated.enforcement.len(), 3);
    assert_eq!(translated.nat.len(), 1);
    assert_eq!(translated.forward.len(), 2);
    assert_eq!(translated.isolation.len(), 1);
    assert_eq!(translated.enforcement[0].protocol, Protocol::Tcp);
    assert_eq!(
        translated.enforcement[0].src_ip.as_deref(),
        Some("10.0.0.1")
    );
    assert_eq!(translated.enforcement[1].protocol, Protocol::Udp);
    assert_eq!(translated.enforcement[1].src_ip, None);
    assert_eq!(
        translated.enforcement[2].in_interface.as_deref(),
        Some("ap0")
    );
    assert_eq!(translated.nat[0].out_interface.as_deref(), Some("eth0"));
    assert_eq!(
        translated.nat[0].src_subnet.as_deref(),
        Some("192.168.5.0/24")
    );
    assert_eq!(
        translated.forward[0].interfaces.in_interface.as_deref(),
        Some("uap0")
    );
    assert_eq!(
        translated.forward[1].state.as_ref().unwrap(),
        &vec![
            ConntrackState::New,
            ConntrackState::Established,
            ConntrackState::Related,
            ConntrackState::Invalid
        ]
    );
}

#[test]
fn translator_rejects_every_unsupported_or_ambiguous_shape() {
    for (candidate, expected) in [
        (
            rule("action", "audit", "any", "any", "tcp", None),
            "unsupported action",
        ),
        (
            rule("protocol", "allow", "any", "any", "icmp", None),
            "unsupported protocol",
        ),
        (
            rule("state", "allow", "ap0", "wlan1", "state:bogus", None),
            "unsupported state",
        ),
        (
            rule("generic", "allow", "any", "any", "any", None),
            "requires a specific protocol",
        ),
        (
            rule("local", "deny", "ap0", "local", "any", None),
            "requires a protocol",
        ),
        (
            rule("forward-port", "allow", "ap0", "wlan1", "any", Some(80)),
            "forward rule",
        ),
        (
            rule("forward-proto", "allow", "ap0", "wlan1", "tcp", None),
            "forward rule",
        ),
    ] {
        assert!(translator::translate(&policy(vec![candidate]))
            .err()
            .expect("translation should fail")
            .to_string()
            .contains(expected));
    }
}

#[test]
fn renderer_covers_all_optional_matches_ranges_actions_states_and_errors() {
    let ranged = EnforcementRule {
        action: Action::Deny,
        protocol: Protocol::Udp,
        src_ip: Some("10.0.0.0/24".into()),
        dst_ip: Some("10.0.1.1".into()),
        ports: Some(PortRange {
            start: 100,
            end: 200,
        }),
        in_interface: Some("ap0".into()),
    };
    assert_eq!(
        render_enforcement(&ranged).unwrap(),
        "iifname \"ap0\" ip saddr 10.0.0.0/24 ip daddr 10.0.1.1 udp dport 100-200 drop"
    );
    let no_port = EnforcementRule {
        action: Action::Allow,
        protocol: Protocol::Tcp,
        src_ip: None,
        dst_ip: None,
        ports: None,
        in_interface: None,
    };
    assert_eq!(render_enforcement(&no_port).unwrap(), "accept");
    let invalid = EnforcementRule {
        action: Action::Masquerade,
        ..no_port.clone()
    };
    assert!(render_enforcement(&invalid)
        .unwrap_err()
        .to_string()
        .contains("invalid"));

    let forward = ForwardRule {
        action: Action::Deny,
        interfaces: InterfaceMatch {
            in_interface: None,
            out_interface: Some("eth0".into()),
        },
        state: Some(vec![ConntrackState::New, ConntrackState::Invalid]),
    };
    assert_eq!(
        render_forward(&forward).unwrap(),
        "oifname \"eth0\" ct state new,invalid drop"
    );
    assert!(render_forward(&ForwardRule {
        action: Action::Masquerade,
        ..forward.clone()
    })
    .is_err());

    let isolation = IsolationRule {
        action: Action::Allow,
        interfaces: InterfaceMatch {
            in_interface: None,
            out_interface: None,
        },
    };
    assert_eq!(render_isolation(&isolation).unwrap(), "accept");
    assert!(render_isolation(&IsolationRule {
        action: Action::Masquerade,
        ..isolation.clone()
    })
    .is_err());

    assert_eq!(
        render_nat(&NatRule {
            action: Action::Allow,
            out_interface: None,
            src_subnet: None
        })
        .unwrap(),
        "accept"
    );
    assert_eq!(
        render_nat(&NatRule {
            action: Action::Deny,
            out_interface: None,
            src_subnet: None
        })
        .unwrap(),
        "drop"
    );
    assert_eq!(
        render_nat(&NatRule {
            action: Action::Masquerade,
            out_interface: None,
            src_subnet: None
        })
        .unwrap(),
        "masquerade"
    );
}

#[test]
fn full_ruleset_renders_each_collection_and_required_safety_rules() {
    let translated = translator::translate(&policy(vec![
        rule("input", "deny", "ap0", "local", "udp", Some(9999)),
        rule("forward", "allow", "ap0", "wlan1", "any", None),
        rule("isolate", "deny", "ap0", "ap1", "any", None),
        rule("nat", "masquerade", "192.168.10.0/24", "wlan1", "any", None),
    ]))
    .unwrap();
    let ruleset = build_nft_ruleset(&translated).unwrap();
    for expected in [
        "table inet sgx_guardian",
        "udp dport 9999 drop",
        "iifname \"ap0\" oifname \"wlan1\" accept",
        "iifname \"ap0\" oifname \"ap1\" drop",
        "ip saddr 192.168.10.0/24 oifname \"wlan1\" masquerade",
        "ct state established,related accept",
        "tcp dport 50065 accept",
        "udp dport 4242 counter accept",
    ] {
        assert!(ruleset.contains(expected), "missing {expected}");
    }
}

#[test]
fn uep_roles_media_decisions_defaults_custom_rules_and_serde_are_complete() {
    for (raw, role) in [
        ("admin", Role::Admin),
        ("operator", Role::Operator),
        ("sensor", Role::Sensor),
        ("camera", Role::Camera),
        ("robot", Role::Robot),
    ] {
        assert_eq!(Role::parse_str(raw), Some(role));
        assert_eq!(role.as_str(), raw);
        assert_eq!(
            serde_json::from_str::<Role>(&serde_json::to_string(&role).unwrap()).unwrap(),
            role
        );
    }
    assert_eq!(Role::parse_str("ADMIN"), None);
    for (raw, media) in [
        ("voice", MediaType::Voice),
        ("video", MediaType::Video),
        ("screen_share", MediaType::ScreenShare),
    ] {
        assert_eq!(MediaType::parse_str(raw), Some(media));
        assert_eq!(media.as_str(), raw);
        assert_eq!(
            serde_json::from_str::<MediaType>(&serde_json::to_string(&media).unwrap()).unwrap(),
            media
        );
    }
    assert_eq!(MediaType::parse_str("screen-share"), None);

    let engine = UepEngine::new(UepEngine::default_rules());
    assert!(
        engine
            .check_call(Role::Admin, Role::Robot, MediaType::Video)
            .allowed
    );
    let media_denied = engine.check_call(Role::Admin, Role::Robot, MediaType::ScreenShare);
    assert!(!media_denied.allowed);
    assert!(media_denied.reason.contains("media type not authorized"));
    assert!(
        !engine
            .check_call(Role::Robot, Role::Admin, MediaType::Voice)
            .allowed
    );

    let custom = RbacRule {
        caller_role: Role::Sensor,
        target_role: Role::Robot,
        allowed_media_types: HashSet::from([MediaType::ScreenShare]),
    };
    let json = serde_json::to_string(&custom).unwrap();
    let custom: RbacRule = serde_json::from_str(&json).unwrap();
    assert!(
        UepEngine::new(vec![custom])
            .check_call(Role::Sensor, Role::Robot, MediaType::ScreenShare)
            .allowed
    );
    assert_eq!(
        UepDecision::allow("yes"),
        UepDecision {
            allowed: true,
            reason: "yes".into()
        }
    );
    assert_eq!(
        UepDecision::deny("no"),
        UepDecision {
            allowed: false,
            reason: "no".into()
        }
    );
}

#[test]
fn translated_rule_models_cover_debug_clone_and_empty_ruleset() {
    let empty = TranslatedRules {
        enforcement: vec![],
        nat: vec![],
        forward: vec![],
        isolation: vec![],
    };
    let ruleset = build_nft_ruleset(&empty).unwrap();
    assert!(ruleset.contains("chain input"));
    assert!(ruleset.contains("chain forward"));
    assert!(ruleset.contains("chain postrouting"));
    assert_eq!(Action::Allow.clone(), Action::Allow);
    assert_ne!(Protocol::Tcp, Protocol::Udp);
    assert!(format!("{:?}", PortRange { start: 1, end: 2 }).contains("start"));
}
