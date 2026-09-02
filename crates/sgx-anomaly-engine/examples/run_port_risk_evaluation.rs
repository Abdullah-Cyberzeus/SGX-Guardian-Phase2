//! Evaluate one port using the data-driven policy and score-rule files.
use sgx_anomaly_engine::port_risk::{evaluate, KnownVulnerability, PortRiskInput, ScoreRuleSet};
use sgx_anomaly_engine::port_security::PortRuleSet;
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port: u16 = args.first().map(String::as_str).unwrap_or("445").parse()?;
    let service = args.get(1).cloned().unwrap_or_else(|| "service".into());
    let rules = PortRuleSet::load_or_default("config/port_security_rules.json");
    let scores = ScoreRuleSet::load_or_default("config/port_risk_scoring_rules.json");
    let input = PortRiskInput {
        port,
        protocol: "tcp".into(),
        service: Some(service),
        internet_exposed: true,
        authentication_enabled: false,
        encryption_enabled: false,
        software_version: Some("demo-version".into()),
        configuration_status: "outdated".into(),
        known_vulnerabilities: if port == 443 {
            vec![KnownVulnerability {
                id: "CVE-DEMO-0001".into(),
                cvss: Some(9.8),
            }]
        } else {
            vec![]
        },
        firewall_restrictions: false,
        network_zone: "Public".into(),
        business_impact: "high".into(),
    };
    let result = evaluate(&input, &rules, &scores);
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
