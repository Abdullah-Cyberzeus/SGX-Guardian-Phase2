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
