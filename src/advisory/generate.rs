use crate::advisory::context::{
    anomaly_context_lines, anomaly_decision, cve_references, device_context_lines,
    normalize_anomaly_score,
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
    let advisory_confidence = anomaly
        .map(|score| (signature_confidence * 0.7) + (normalize_anomaly_score(score.score) * 0.3))
        .unwrap_or(signature_confidence)
        .clamp(0.0, 1.0);
    let advisory_basis = anomaly
        .map(|_| {
            "Derived for remediation ranking from alert severity (70%) and normalized anomaly score (30%); this is separate from Task 1 model confidence."
                .to_string()
        })
        .unwrap_or_else(|| {
            "Derived from alert severity because no Task 1 anomaly model decision was attached."
                .to_string()
        });

    RemediationRecommendation {
        rec_id: recommendation_id(alert, &source),
        alert_id: alert.alert_id.clone(),
        title,
        summary,
        severity: alert.severity.as_str().to_string(),
        confidence: advisory_confidence,
        advisory_confidence,
        advisory_basis,
        steps,
        context,
        references,
        source,
        anomaly: anomaly_decision(anomaly),
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
        let alert = alert(
            ThreatCategory::Other,
            Severity::High,
            "Suspicious burst",
            9100001,
        );
        let anomaly = AnomalyContext {
            score: 0.81,
            topk: vec![
                ("burst_density".into(), 0.92),
                ("source_score".into(), 0.81),
            ],
            model_version: Some("task1-alert-scorer".into()),
            scoring_runtime: None,
            source: Some(crate::advisory::AnomalySource {
                ip: "203.0.113.77".into(),
                alert_count: 5,
            }),
            top_signature: Some(crate::advisory::AnomalyTopSignature {
                id: 9100001,
                count: 5,
            }),
            category: Some("anomaly".into()),
            computed_at: Some(alert.timestamp),
            window_secs: Some(300),
            contributors: Vec::new(),
            decision: None,
        };

        let rec = generate(&alert, Some(&anomaly), None, &rules);

        assert_eq!(rec.source, "anomaly-kb");
        assert_eq!(rec.title, rules.fallback.title);
        assert_eq!(rec.summary, rules.fallback.summary);
        assert_eq!(rec.generated_at, alert.timestamp);
        assert_eq!(rec.confidence, rec.advisory_confidence);
        assert!(rec
            .advisory_basis
            .contains("separate from Task 1 model confidence"));
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
        let anomaly = rec.anomaly.expect("structured anomaly payload");
        assert!(anomaly.detected);
        assert_eq!(anomaly.detector, "task1-alert-scorer");
        assert!(anomaly.confidence.is_none());
        assert_eq!(
            anomaly.threshold,
            crate::task1_ai::DEFAULT_DETECTION_THRESHOLD
        );
        assert_eq!(
            anomaly.high_threshold,
            crate::task1_ai::DEFAULT_HIGH_THRESHOLD
        );
        assert_eq!(
            anomaly.critical_threshold,
            crate::task1_ai::DEFAULT_CRITICAL_THRESHOLD
        );
        assert_eq!(anomaly.category.as_deref(), Some("anomaly"));
    }
}
