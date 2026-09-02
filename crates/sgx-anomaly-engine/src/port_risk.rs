//! Data-driven port risk calculator.  It uses the port-rule knowledge base and
//! a separate scoring-rule JSON; new ports or score factors do not require core-code changes.

use crate::port_recommendation;
use crate::port_security::{PortRuleSet, PortSeverity};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownVulnerability {
    pub id: String,
    #[serde(default)]
    pub cvss: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRiskInput {
    pub port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub service: Option<String>,
    pub internet_exposed: bool,
    pub authentication_enabled: bool,
    pub encryption_enabled: bool,
    #[serde(default)]
    pub software_version: Option<String>,
    #[serde(default)]
    pub configuration_status: String,
    #[serde(default)]
    pub known_vulnerabilities: Vec<KnownVulnerability>,
    pub firewall_restrictions: bool,
    pub network_zone: String,
    #[serde(default)]
    pub business_impact: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreRule {
    pub name: String,
    pub factor: String,
    pub when: String,
    pub points: i32,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreRuleSet {
    pub version: u32,
    pub base_scores: BaseScores,
    pub rules: Vec<ScoreRule>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseScores {
    pub low: i32,
    pub medium: i32,
    pub high: i32,
    pub critical: i32,
}
#[derive(Debug, Clone, Serialize)]
pub struct PortRiskResult {
    pub port: u16,
    pub service: String,
    pub base_risk: PortSeverity,
    pub final_risk: PortSeverity,
    pub risk_score: u8,
    pub reason: String,
    pub recommendation: String,
    pub confidence: u8,
    pub matched_rules: Vec<String>,
    pub software_version: Option<String>,
    pub cves: Vec<KnownVulnerability>,
}

impl ScoreRuleSet {
    pub fn load_or_default(path: impl AsRef<Path>) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(Self::default_rules)
    }
    fn default_rules() -> Self {
        Self {
            version: 1,
            base_scores: BaseScores {
                low: 20,
                medium: 40,
                high: 60,
                critical: 80,
            },
            rules: vec![],
        }
    }
}
pub fn evaluate(
    input: &PortRiskInput,
    port_rules: &PortRuleSet,
    score_rules: &ScoreRuleSet,
) -> PortRiskResult {
    let protocol = if input.protocol.is_empty() {
        "tcp"
    } else {
        &input.protocol
    };
    let policy = port_rules
        .matching_rule(input.port, protocol)
        .expect("generic policy rule");
    let service = input.service.clone().unwrap_or_else(|| policy.name.clone());
    let mut score = base_score(policy.severity, &score_rules.base_scores);
    let mut reasons = vec![policy.reason.clone()];
    let mut matched = vec![format!("port_policy:{}", policy.name)];
    for rule in &score_rules.rules {
        if matches(rule, input) {
            score += rule.points;
            reasons.push(rule.reason.clone());
            matched.push(rule.name.clone());
        }
    }
    let max_cvss = input
        .known_vulnerabilities
        .iter()
        .filter_map(|v| v.cvss)
        .max_by(|a, b| a.total_cmp(b));
    if let Some(cvss) = max_cvss {
        let cvss_score = (cvss * 10.0).round() as i32;
        if cvss_score > score {
            score = cvss_score
        };
        reasons.push(format!(
            "Known vulnerability evidence has maximum CVSS {cvss:.1}."
        ));
        matched.push("known_cve_cvss".into());
    }
    score = score.clamp(0, 100);
    let final_risk = score_to_risk(score);
    let confidence = confidence(input, max_cvss.is_some());
    let recommendation = port_recommendation::generate(
        policy.recommendation.as_str(),
        &service,
        input.port,
        input.internet_exposed,
        input.authentication_enabled,
        input.encryption_enabled,
        final_risk,
    );
    PortRiskResult {
        port: input.port,
        service,
        base_risk: policy.severity,
        final_risk,
        risk_score: score as u8,
        reason: reasons.join(" "),
        recommendation,
        confidence,
        matched_rules: matched,
        software_version: input.software_version.clone(),
        cves: input.known_vulnerabilities.clone(),
    }
}
fn matches(r: &ScoreRule, i: &PortRiskInput) -> bool {
    match r.factor.as_str() {
        "internet_exposed" => i.internet_exposed == parse_bool(&r.when),
        "authentication_enabled" => i.authentication_enabled == parse_bool(&r.when),
        "encryption_enabled" => i.encryption_enabled == parse_bool(&r.when),
        "firewall_restrictions" => i.firewall_restrictions == parse_bool(&r.when),
        "network_zone" => i.network_zone.eq_ignore_ascii_case(&r.when),
        "configuration_status" => i.configuration_status.eq_ignore_ascii_case(&r.when),
        "business_impact" => i.business_impact.eq_ignore_ascii_case(&r.when),
        _ => false,
    }
}
fn parse_bool(s: &str) -> bool {
    s.eq_ignore_ascii_case("true")
}
fn base_score(s: PortSeverity, b: &BaseScores) -> i32 {
    match s {
        PortSeverity::Low => b.low,
        PortSeverity::Medium => b.medium,
        PortSeverity::High => b.high,
        PortSeverity::Critical => b.critical,
    }
}
fn score_to_risk(s: i32) -> PortSeverity {
    if s >= 80 {
        PortSeverity::Critical
    } else if s >= 60 {
        PortSeverity::High
    } else if s >= 35 {
        PortSeverity::Medium
    } else {
        PortSeverity::Low
    }
}
fn confidence(i: &PortRiskInput, has_cve: bool) -> u8 {
    let mut c = 55;
    if !i.configuration_status.is_empty() {
        c += 10
    };
    if !i.network_zone.is_empty() {
        c += 10
    };
    if i.software_version.is_some() {
        c += 10
    };
    if has_cve {
        c += 15
    };
    c.min(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_smb_becomes_critical() {
        let ports = PortRuleSet::load_or_default("config/port_security_rules.json");
        let scores = ScoreRuleSet::load_or_default("config/port_risk_scoring_rules.json");
        let r = evaluate(
            &PortRiskInput {
                port: 445,
                protocol: "tcp".into(),
                service: Some("smb".into()),
                internet_exposed: true,
                authentication_enabled: false,
                encryption_enabled: false,
                software_version: None,
                configuration_status: "outdated".into(),
                known_vulnerabilities: vec![],
                firewall_restrictions: false,
                network_zone: "Public".into(),
                business_impact: "high".into(),
            },
            &ports,
            &scores,
        );
        assert_eq!(r.final_risk, PortSeverity::Critical);
        assert!(r.risk_score >= 80);
    }
}
