//! Task 1 anomaly scoring and context bridging.
//!
//! This module keeps the Task 1 scoring logic isolated from the rest of SGX so
//! we can feed anomaly context into the existing advisory system without
//! changing the current REST storage shape.

use crate::advisory::AnomalyContext;
use crate::threat::{
    ai_bridge::AlertFeature,
    threat_alert::{Severity, ThreatAlert, ThreatCategory},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Alert-level anomaly score for a rolling source-IP burst.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertAnomalyScore {
    pub score: f32,
    pub contributing_ip: String,
    pub alert_count: u32,
    pub top_signature_id: u32,
    pub top_signature_count: u32,
    pub category: ThreatCategory,
    pub computed_at: DateTime<Utc>,
    pub window_secs: u64,
}

/// Rolling state for alert scoring.
#[derive(Debug, Clone)]
pub struct AlertScorerState {
    records: HashMap<String, Vec<AlertFeature>>,
    window_secs: u64,
}

impl AlertScorerState {
    pub fn new(window_secs: u64) -> Self {
        Self {
            records: HashMap::new(),
            window_secs,
        }
    }

    pub fn default_window() -> Self {
        Self::new(300)
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    pub fn active_ip_count(&self) -> usize {
        self.records.len()
    }

    pub fn cleanup(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.window_secs as i64);
        self.records.retain(|_, features| {
            features.retain(|feature| feature.ts > cutoff);
            !features.is_empty()
        });
    }
}

impl Default for AlertScorerState {
    fn default() -> Self {
        Self::default_window()
    }
}

/// Convert a `ThreatAlert` into the normalized feature shape used by the
/// anomaly tap.
pub fn feature_from_alert(alert: &ThreatAlert) -> AlertFeature {
    AlertFeature {
        ts: alert.timestamp,
        severity_score: match alert.severity {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        },
        signature_id: alert.signature_id,
        category: alert.category,
        src_ip: alert.src_ip.clone(),
        dst_ip: alert.dst_ip.clone(),
    }
}

/// Update the rolling score with a new feature.
pub fn process_feature(
    feature: &AlertFeature,
    state: &mut AlertScorerState,
) -> Option<AlertAnomalyScore> {
    let window_duration = chrono::Duration::seconds(state.window_secs as i64);
    let cutoff = feature.ts - window_duration;

    let features = state.records.entry(feature.src_ip.clone()).or_default();
    features.push(feature.clone());
    features.retain(|item| item.ts > cutoff);

    let count = features.len() as u32;
    if count == 0 {
        return None;
    }

    let mut sig_counts: HashMap<u32, u32> = HashMap::new();
    let mut severity_total: u32 = 0;
    let mut malware = 0u32;
    let mut exploit = 0u32;
    let mut policy_violation = 0u32;
    let mut reconnaissance = 0u32;
    let mut anomaly = 0u32;
    let mut other = 0u32;

    for item in features.iter() {
        *sig_counts.entry(item.signature_id).or_insert(0) += 1;
        severity_total += item.severity_score as u32;
        match item.category {
            ThreatCategory::Malware => malware += 1,
            ThreatCategory::Exploit => exploit += 1,
            ThreatCategory::PolicyViolation => policy_violation += 1,
            ThreatCategory::Reconnaissance => reconnaissance += 1,
            ThreatCategory::Anomaly => anomaly += 1,
            ThreatCategory::Other => other += 1,
        }
    }

    let (&top_signature_id, &top_signature_count) =
        sig_counts.iter().max_by_key(|&(_, count)| count)?;

    let (top_category, category_weight) = category_profile(
        malware,
        exploit,
        policy_violation,
        reconnaissance,
        anomaly,
        other,
    );

    let freq_factor = ((count as f32 - 1.0) / 49.0).clamp(0.0, 1.0);
    let sig_repeat_factor = (top_signature_count as f32 / count as f32).clamp(0.0, 1.0);
    let avg_severity = severity_total as f32 / count as f32;
    let sev_factor = (avg_severity / 4.0).clamp(0.0, 1.0);

    let raw_score = (freq_factor * 0.45)
        + (sig_repeat_factor * 0.25)
        + (sev_factor * 0.15)
        + (category_weight * 0.15);

    let score = raw_score.clamp(0.0, 1.0);
    if score < 0.50 {
        return None;
    }

    Some(AlertAnomalyScore {
        score,
        contributing_ip: feature.src_ip.clone(),
        alert_count: count,
        top_signature_id,
        top_signature_count,
        category: top_category,
        computed_at: feature.ts,
        window_secs: state.window_secs,
    })
}

/// Convert an alert score into the `AnomalyContext` consumed by the existing
/// advisory generator.
pub fn anomaly_context_from_score(score: &AlertAnomalyScore) -> AnomalyContext {
    let normalized_score = score.score.clamp(0.0, 1.0);
    let alert_pressure = (score.alert_count as f32 / 50.0).clamp(0.0, 1.0);
    let signature_repeat =
        (score.top_signature_count as f32 / score.alert_count.max(1) as f32).clamp(0.0, 1.0);
    let burst_density =
        (score.alert_count as f32 / (score.window_secs.max(1) as f32 / 6.0)).clamp(0.0, 1.0);

    AnomalyContext {
        score: normalized_score,
        topk: vec![
            ("alert_count".to_string(), alert_pressure),
            ("signature_repeat".to_string(), signature_repeat),
            ("burst_density".to_string(), burst_density),
            ("source_score".to_string(), normalized_score),
        ],
        model_version: Some("task1-alert-scorer".to_string()),
    }
}

fn category_profile(
    malware: u32,
    exploit: u32,
    policy_violation: u32,
    reconnaissance: u32,
    anomaly: u32,
    other: u32,
) -> (ThreatCategory, f32) {
    let mut best = (ThreatCategory::Other, other, 0.5f32);

    for (category, count, weight) in [
        (ThreatCategory::Malware, malware, 0.9f32),
        (ThreatCategory::Exploit, exploit, 1.0f32),
        (ThreatCategory::PolicyViolation, policy_violation, 0.7f32),
        (ThreatCategory::Reconnaissance, reconnaissance, 0.8f32),
        (ThreatCategory::Anomaly, anomaly, 0.75f32),
        (ThreatCategory::Other, other, 0.5f32),
    ] {
        if count > best.1 {
            best = (category, count, weight);
        }
    }

    (best.0, best.2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_alert(
        category: ThreatCategory,
        severity: Severity,
        src_ip: &str,
        sid: u32,
    ) -> ThreatAlert {
        ThreatAlert {
            alert_id: format!("alert-{}", sid),
            timestamp: Utc::now(),
            src_ip: src_ip.to_string(),
            src_port: 51514,
            dst_ip: "192.168.1.1".to_string(),
            dst_port: 8443,
            protocol: "TCP".to_string(),
            signature_id: sid,
            signature: "test".to_string(),
            category,
            severity,
            rev: 1,
            gid: 1,
            event_type: "alert".to_string(),
            blocked: false,
        }
    }

    #[test]
    fn single_alert_stays_below_threshold() {
        let mut state = AlertScorerState::default();
        let feature = feature_from_alert(&make_alert(
            ThreatCategory::Other,
            Severity::Low,
            "10.0.0.1",
            1001,
        ));
        assert!(process_feature(&feature, &mut state).is_none());
    }

    #[test]
    fn burst_alerts_cross_threshold() {
        let mut state = AlertScorerState::default();
        let mut last = None;
        for _ in 0..60 {
            let feature = feature_from_alert(&make_alert(
                ThreatCategory::Reconnaissance,
                Severity::High,
                "192.168.1.105",
                2009358,
            ));
            last = process_feature(&feature, &mut state);
        }

        let score = last.expect("expected an anomaly score");
        assert!(score.score >= 0.90);
        assert_eq!(score.contributing_ip, "192.168.1.105");
        assert_eq!(score.alert_count, 60);
        assert_eq!(score.top_signature_id, 2009358);

        let ctx = anomaly_context_from_score(&score);
        assert_eq!(ctx.model_version.as_deref(), Some("task1-alert-scorer"));
        assert!(ctx.score > 0.0);
        assert!(!ctx.topk.is_empty());
    }

    #[test]
    fn window_cleanup_removes_stale_sources() {
        let mut state = AlertScorerState::new(60);
        let old_alert = make_alert(
            ThreatCategory::Malware,
            Severity::Critical,
            "10.0.0.2",
            3001,
        );
        let mut feature = feature_from_alert(&old_alert);
        feature.ts = Utc::now() - chrono::Duration::seconds(120);
        state
            .records
            .entry(feature.src_ip.clone())
            .or_default()
            .push(feature);

        assert_eq!(state.active_ip_count(), 1);
        state.cleanup();
        assert_eq!(state.active_ip_count(), 0);
    }

    #[test]
    fn exploit_burst_crosses_threshold_and_marks_exploit_category() {
        let mut state = AlertScorerState::new(120);
        let mut last = None;

        for offset in 0..6 {
            let mut alert = make_alert(
                ThreatCategory::Exploit,
                Severity::Critical,
                "10.10.10.10",
                4001,
            );
            alert.timestamp = Utc
                .with_ymd_and_hms(2026, 8, 24, 12, 0, 0)
                .single()
                .expect("fixed timestamp")
                + chrono::Duration::seconds(offset);

            let feature = feature_from_alert(&alert);
            last = process_feature(&feature, &mut state);
        }

        let score = last.expect("expected exploit burst to trigger");
        assert_eq!(score.category, ThreatCategory::Exploit);
        assert_eq!(score.contributing_ip, "10.10.10.10");
        assert_eq!(score.alert_count, 6);
        assert_eq!(score.top_signature_id, 4001);
        assert_eq!(score.top_signature_count, 6);
        assert!(score.score >= 0.50);

        let ctx = anomaly_context_from_score(&score);
        assert_eq!(ctx.model_version.as_deref(), Some("task1-alert-scorer"));
        assert_eq!(ctx.topk.len(), 4);
        assert!(ctx
            .topk
            .iter()
            .any(|(name, value)| name == "source_score" && (*value - score.score).abs() < 1e-6));
    }

    #[test]
    fn anomaly_context_from_score_clamps_and_reports_topk_metrics() {
        let score = AlertAnomalyScore {
            score: 1.4,
            contributing_ip: "172.16.0.7".to_string(),
            alert_count: 25,
            top_signature_id: 9001,
            top_signature_count: 10,
            category: ThreatCategory::Anomaly,
            computed_at: Utc
                .with_ymd_and_hms(2026, 8, 24, 12, 30, 0)
                .single()
                .expect("fixed timestamp"),
            window_secs: 120,
        };

        let ctx = anomaly_context_from_score(&score);

        assert_eq!(ctx.score, 1.0);
        assert_eq!(ctx.model_version.as_deref(), Some("task1-alert-scorer"));
        assert_eq!(ctx.topk.len(), 4);
        assert!(ctx
            .topk
            .iter()
            .any(|(name, value)| name == "alert_count" && (*value - 0.5).abs() < 1e-6));
        assert!(ctx
            .topk
            .iter()
            .any(|(name, value)| name == "signature_repeat" && (*value - 0.4).abs() < 1e-6));
        assert!(ctx
            .topk
            .iter()
            .any(|(name, value)| name == "burst_density" && (*value - 1.0).abs() < 1e-6));
        assert!(ctx
            .topk
            .iter()
            .any(|(name, value)| name == "source_score" && (*value - 1.0).abs() < 1e-6));
    }

    #[test]
    fn malware_burst_crosses_threshold_and_marks_malware_category() {
        let mut state = AlertScorerState::new(120);
        let base = Utc
            .with_ymd_and_hms(2026, 8, 24, 13, 0, 0)
            .single()
            .expect("fixed timestamp");
        let mut last = None;

        for offset in 0..4 {
            let mut alert = make_alert(
                ThreatCategory::Malware,
                Severity::Critical,
                "10.10.10.11",
                5001,
            );
            alert.timestamp = base + chrono::Duration::seconds(offset);
            let feature = feature_from_alert(&alert);
            last = process_feature(&feature, &mut state);
        }

        let score = last.expect("expected malware burst to trigger");
        assert_eq!(score.category, ThreatCategory::Malware);
        assert_eq!(score.alert_count, 4);
        assert_eq!(score.top_signature_id, 5001);
        assert_eq!(score.top_signature_count, 4);
        assert!(score.score >= 0.50);
    }

    #[test]
    fn policy_violation_burst_crosses_threshold_and_marks_policy_violation_category() {
        let mut state = AlertScorerState::new(120);
        let base = Utc
            .with_ymd_and_hms(2026, 8, 24, 13, 30, 0)
            .single()
            .expect("fixed timestamp");
        let mut last = None;

        for offset in 0..5 {
            let mut alert = make_alert(
                ThreatCategory::PolicyViolation,
                Severity::Critical,
                "10.10.10.12",
                5002,
            );
            alert.timestamp = base + chrono::Duration::seconds(offset);
            let feature = feature_from_alert(&alert);
            last = process_feature(&feature, &mut state);
        }

        let score = last.expect("expected policy violation burst to trigger");
        assert_eq!(score.category, ThreatCategory::PolicyViolation);
        assert_eq!(score.alert_count, 5);
        assert_eq!(score.top_signature_id, 5002);
        assert_eq!(score.top_signature_count, 5);
        assert!(score.score >= 0.50);
    }
}
