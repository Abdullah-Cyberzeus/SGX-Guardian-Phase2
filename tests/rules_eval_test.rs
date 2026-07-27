use sgx_guardian_client::rules::RuleEvent;
use sgx_guardian_client::rules::{eval::evaluate, Condition, Rule, RuleDraft, RuleTrigger};

fn rule(condition: Condition) -> Rule {
    Rule::from_draft(RuleDraft {
        name: Some("High alert matrix".to_string()),
        trigger: Some(RuleTrigger::ThreatAlert),
        condition: Some(condition),
        ..RuleDraft::default()
    })
}

#[test]
fn rule_evaluator_matrix_is_pure_and_deterministic() {
    let event = RuleEvent::sample_threat("nodeA");

    assert!(evaluate(
        &rule(Condition::SeverityAtLeast("high".to_string())),
        &event
    ));
    assert!(!evaluate(
        &rule(Condition::SeverityAtLeast("critical".to_string())),
        &event
    ));
    assert!(evaluate(
        &rule(Condition::SignatureIdIn(vec![9_999_001])),
        &event
    ));
    assert!(!evaluate(&rule(Condition::PortIn(vec![22])), &event));
}

#[test]
fn nested_conditions_and_cidr_boundaries_work() {
    let event = RuleEvent::sample_threat("nodeA");
    let condition = Condition::All(vec![
        Condition::SrcIpInCidr("203.0.113.0/24".to_string()),
        Condition::Any(vec![
            Condition::PortIn(vec![443]),
            Condition::CategoryIs("malware".to_string()),
        ]),
        Condition::Not(Box::new(Condition::SrcIpInCidr(
            "203.0.114.0/24".to_string(),
        ))),
    ]);

    assert!(evaluate(&rule(condition), &event));
    assert!(!evaluate(
        &rule(Condition::SrcIpInCidr("203.0.112.0/24".to_string())),
        &event
    ));
    assert!(evaluate(
        &rule(Condition::SrcIpInCidr("203.0.113.55".to_string())),
        &event
    ));
}
