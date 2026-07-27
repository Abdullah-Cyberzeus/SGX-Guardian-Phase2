use crate::rules::model::{Condition, Rule, RuleEvent};
use std::net::IpAddr;

pub fn evaluate(rule: &Rule, event: &RuleEvent) -> bool {
    rule.enabled && rule.trigger == event.trigger() && condition_matches(&rule.condition, event)
}

fn condition_matches(condition: &Condition, event: &RuleEvent) -> bool {
    match condition {
        Condition::SeverityAtLeast(minimum) => event
            .severity_name()
            .and_then(severity_rank)
            .zip(severity_rank(minimum))
            .is_some_and(|(actual, minimum)| actual >= minimum),
        Condition::CategoryIs(expected) => event
            .category_name()
            .is_some_and(|actual| normalized_eq(actual, expected)),
        Condition::SignatureIdIn(ids) => event
            .signature_id()
            .is_some_and(|signature_id| ids.contains(&signature_id)),
        Condition::SrcIpInCidr(cidr) => src_ip_in_cidr(event.src_ip(), cidr),
        Condition::PortIn(ports) => {
            let event_ports = event.ports();
            event_ports.iter().any(|port| ports.contains(port))
        }
        Condition::DeviceStatusIs(expected) => event
            .device_status()
            .is_some_and(|actual| normalized_eq(actual, expected)),
        Condition::ZoneIs(expected) => event
            .zone()
            .is_some_and(|actual| normalized_eq(actual, expected)),
        Condition::All(conditions) => conditions
            .iter()
            .all(|inner| condition_matches(inner, event)),
        Condition::Any(conditions) => conditions
            .iter()
            .any(|inner| condition_matches(inner, event)),
        Condition::Not(inner) => !condition_matches(inner, event),
    }
}

fn src_ip_in_cidr(ip: Option<&str>, cidr: &str) -> bool {
    let Some(ip) = ip.and_then(|value| value.parse::<IpAddr>().ok()) else {
        return false;
    };

    if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
        return net.contains(&ip);
    }

    cidr.parse::<IpAddr>().is_ok_and(|addr| addr == ip)
}

fn normalized_eq(left: &str, right: &str) -> bool {
    normalize(left) == normalize(right)
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn severity_rank(value: &str) -> Option<u8> {
    match normalize(value).as_str() {
        "info" => Some(0),
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "critical" => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::model::{Condition, Rule, RuleDraft, RuleTrigger};

    fn rule(condition: Condition) -> Rule {
        Rule::from_draft(RuleDraft {
            name: Some("matrix".to_string()),
            trigger: Some(RuleTrigger::ThreatAlert),
            condition: Some(condition),
            ..RuleDraft::default()
        })
    }

    #[test]
    fn evaluator_handles_nested_boolean_conditions() {
        let event = RuleEvent::sample_threat("nodeA");
        let condition = Condition::All(vec![
            Condition::SeverityAtLeast("medium".to_string()),
            Condition::Any(vec![
                Condition::SignatureIdIn(vec![1]),
                Condition::SignatureIdIn(vec![9_999_001]),
            ]),
            Condition::Not(Box::new(Condition::CategoryIs("malware".to_string()))),
        ]);

        assert!(evaluate(&rule(condition), &event));
    }

    #[test]
    fn evaluator_rejects_wrong_trigger_and_disabled_rule() {
        let event = RuleEvent::sample_threat("nodeA");
        let mut wrong_trigger = Rule::from_draft(RuleDraft {
            trigger: Some(RuleTrigger::DeviceDiscovered),
            ..RuleDraft::default()
        });
        assert!(!evaluate(&wrong_trigger, &event));

        wrong_trigger.trigger = RuleTrigger::ThreatAlert;
        wrong_trigger.enabled = false;
        assert!(!evaluate(&wrong_trigger, &event));
    }

    #[test]
    fn cidr_predicate_handles_boundaries_and_plain_ips() {
        let event = RuleEvent::sample_threat("nodeA");
        assert!(evaluate(
            &rule(Condition::SrcIpInCidr("203.0.113.0/24".to_string())),
            &event
        ));
        assert!(evaluate(
            &rule(Condition::SrcIpInCidr("203.0.113.55".to_string())),
            &event
        ));
        assert!(!evaluate(
            &rule(Condition::SrcIpInCidr("203.0.114.0/24".to_string())),
            &event
        ));
        assert!(!evaluate(
            &rule(Condition::SrcIpInCidr("not-a-cidr".to_string())),
            &event
        ));
    }

    fn device_rule(trigger: RuleTrigger, condition: Condition) -> Rule {
        Rule::from_draft(RuleDraft {
            trigger: Some(trigger),
            condition: Some(condition),
            ..RuleDraft::default()
        })
    }

    #[test]
    fn device_status_condition_is_case_insensitive() {
        let event = crate::rules::model::RuleEvent::DeviceDiscovered {
            node_id: "nodeA".to_string(),
            device_id: "dev-1".to_string(),
            ip: "192.168.1.10".to_string(),
            status: "unauthorized".to_string(),
            ports: vec![],
            zone: None,
        };

        assert!(evaluate(
            &device_rule(
                RuleTrigger::DeviceDiscovered,
                Condition::DeviceStatusIs("Unauthorized".to_string())
            ),
            &event
        ));
        assert!(!evaluate(
            &device_rule(
                RuleTrigger::DeviceDiscovered,
                Condition::DeviceStatusIs("approved".to_string())
            ),
            &event
        ));
    }

    #[test]
    fn category_condition_normalizes_dash_to_underscore() {
        let event = crate::rules::model::RuleEvent::CrlRevocation {
            node_id: "nodeA".to_string(),
            revoked_did: "did:guardian:abc".to_string(),
            reason: "key_compromise".to_string(),
            severity: "critical".to_string(),
        };

        assert!(evaluate(
            &device_rule(
                RuleTrigger::CrlRevocation,
                Condition::CategoryIs("key-compromise".to_string())
            ),
            &event
        ));
        assert!(!evaluate(
            &device_rule(
                RuleTrigger::CrlRevocation,
                Condition::CategoryIs("device-lost".to_string())
            ),
            &event
        ));
    }

    #[test]
    fn zone_condition_matches_geofence_events_only() {
        let entry = crate::rules::model::RuleEvent::GeofenceEntry {
            node_id: "nodeA".to_string(),
            device_id: "dev-1".to_string(),
            zone: "warehouse".to_string(),
        };

        assert!(evaluate(
            &device_rule(
                RuleTrigger::GeofenceEntry,
                Condition::ZoneIs("Warehouse".to_string())
            ),
            &entry
        ));
        assert!(!evaluate(
            &device_rule(
                RuleTrigger::GeofenceEntry,
                Condition::ZoneIs("office".to_string())
            ),
            &entry
        ));

        let threat = RuleEvent::sample_threat("nodeA");
        assert!(!evaluate(
            &device_rule(
                RuleTrigger::ThreatAlert,
                Condition::ZoneIs("warehouse".to_string())
            ),
            &threat
        ));
    }

    #[test]
    fn severity_condition_rejects_unrecognized_severity_strings() {
        let event = RuleEvent::sample_threat("nodeA");
        assert!(!evaluate(
            &rule(Condition::SeverityAtLeast("not-a-severity".to_string())),
            &event
        ));
    }

    #[test]
    fn category_condition_is_case_insensitive() {
        let event = RuleEvent::sample_threat("nodeA");
        assert!(evaluate(
            &rule(Condition::CategoryIs("Policy_Violation".to_string())),
            &event
        ));
        assert!(!evaluate(
            &rule(Condition::CategoryIs("exploit".to_string())),
            &event
        ));
    }
}
