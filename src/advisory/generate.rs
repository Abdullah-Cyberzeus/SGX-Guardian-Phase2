use crate::advisory::context::{
    anomaly_context_lines, cve_references, device_context_lines, normalize_anomaly_score,
};
use crate::advisory::kb::RecommendationRules;
use crate::advisory::model::{AnomalyContext, DeviceContext, RemediationRecommendation};
use crate::threat::threat_alert::ThreatAlert;
use sha2::{Digest, Sha256};

pub fn generate(
    alert: &ThreatAlert,
    anomaly: Option<&AnomalyContext>,
    device: Option<&DeviceContext>,
    rules: &RecommendationRules,
) -> RemediationRecommendation {
    let category = alert.category.as_str();
    let matched = rules
        .rules
        .iter()
        .find(|rule| rule.matches(category, &alert.signature, alert.severity));

    let (title, summary, steps, mut references, source) = match matched {
        Some(rule) => (
            rule.title.clone(),
            rule.summary.clone(),
            rule.steps(),
            rule.references.clone(),
            "signature-kb".to_string(),
        ),
        None => (
            rules.fallback.title.clone(),
            rules.fallback.summary.clone(),
            rules.fallback.steps(),
            rules.fallback.references.clone(),
            if anomaly.is_some() {
                "anomaly-kb".to_string()
            } else {
                "fallback".to_string()
            },
        ),
    };

    references.push(format!("suricata:sid:{}", alert.signature_id));
    references.extend(cve_references(device));
    references.sort();
    references.dedup();

    let mut context = vec![
        format!(
            "Signature: {} (sid {})",
            alert.signature, alert.signature_id
        ),
        format!(
            "Flow: {}:{} -> {}:{} {}",
            alert.src_ip, alert.src_port, alert.dst_ip, alert.dst_port, alert.protocol
        ),
        format!("Category: {}", category),
    ];
    context.extend(anomaly_context_lines(anomaly));
    context.extend(device_context_lines(device));

    let signature_confidence = match alert.severity {
        crate::threat::threat_alert::Severity::Critical => 0.95,
        crate::threat::threat_alert::Severity::High => 0.88,
        crate::threat::threat_alert::Severity::Medium => 0.72,
        crate::threat::threat_alert::Severity::Low => 0.55,
        crate::threat::threat_alert::Severity::Info => 0.35,
    };
    let confidence = anomaly
        .map(|score| (signature_confidence * 0.7) + (normalize_anomaly_score(score.score) * 0.3))
        .unwrap_or(signature_confidence)
        .clamp(0.0, 1.0);

    RemediationRecommendation {
        rec_id: recommendation_id(alert, &source),
        alert_id: alert.alert_id.clone(),
        title,
        summary,
        severity: alert.severity.as_str().to_string(),
        confidence,
        steps,
        context,
        references,
        source,
        generated_at: alert.timestamp,
    }
}

fn recommendation_id(alert: &ThreatAlert, source: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(alert.alert_id.as_bytes());
    hasher.update(source.as_bytes());
    hasher.update(alert.signature_id.to_be_bytes());
    format!("urn:sha256:{}", hex::encode(&hasher.finalize()[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::kb::RecommendationRules;
    use crate::advisory::model::AnomalyContext;
    use crate::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};
    use chrono::TimeZone;

    fn alert(
        category: ThreatCategory,
        severity: Severity,
        signature: &str,
        signature_id: u32,
    ) -> ThreatAlert {
        ThreatAlert {
            alert_id: "alert-1".into(),
            timestamp: chrono::Utc
                .with_ymd_and_hms(2026, 8, 24, 12, 0, 0)
                .single()
                .expect("fixed timestamp"),
            src_ip: "192.168.50.10".into(),
            src_port: 51514,
            dst_ip: "192.168.50.20".into(),
            dst_port: 443,
            protocol: "TCP".into(),
            signature_id,
            signature: signature.into(),
            category,
            severity,
            rev: 1,
            gid: 1,
            event_type: "alert".into(),
            blocked: false,
        }
    }

    #[test]
    fn task1_anomaly_context_uses_anomaly_kb_when_no_specific_rule_matches() {
        let rules = RecommendationRules::default_rules();
        let alert = alert(ThreatCategory::Other, Severity::High, "Suspicious burst", 9100001);
        let anomaly = AnomalyContext {
            score: 0.81,
            topk: vec![("burst_density".into(), 0.92), ("source_score".into(), 0.81)],
            model_version: Some("task1-alert-scorer".into()),
        };

        let rec = generate(&alert, Some(&anomaly), None, &rules);

        assert_eq!(rec.source, "anomaly-kb");
        assert_eq!(rec.title, rules.fallback.title);
        assert_eq!(rec.summary, rules.fallback.summary);
        assert_eq!(rec.generated_at, alert.timestamp);
        assert!(rec
            .context
            .iter()
            .any(|line| line.contains("Anomaly score 0.81")));
        assert!(rec
            .context
            .iter()
            .any(|line| line.contains("task1-alert-scorer")));
        assert!(rec
            .references
            .iter()
            .any(|reference| reference == "suricata:sid:9100001"));
    }
}
