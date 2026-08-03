//! Suricata Alert Anomaly Scorer
//! Subscribes to the `ai_bridge` feature tap and calculates normalized
//! anomaly scores (0.0 - 1.0) for bursts of related network threat alerts.

use crate::threat::{ai_bridge::AlertFeature, threat_alert::ThreatCategory};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Anomaly score result for a burst of network security alerts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertAnomalyScore {
    /// Normalized score between 0.0 (normal) and 1.0 (critical threat).
    pub score: f32,
    /// The source IP address driving the anomaly score.
    pub contributing_ip: String,
    /// Total count of High/Critical alerts in the scoring window.
    pub alert_count: u32,
    /// Most frequently occurring Suricata signature ID.
    pub top_signature_id: u32,
    /// Threat category associated with the alert burst.
    pub category: ThreatCategory,
    /// Timestamp when this anomaly score was calculated.
    pub computed_at: DateTime<Utc>,
    /// Scoring window duration in seconds (default: 300s = 5 min).
    pub window_secs: u64,
}

/// In-memory state for tracking rolling alert windows across source IPs.
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
}

impl Default for AlertScorerState {
    fn default() -> Self {
        Self::default_window()
    }
}

/// Processes an incoming `AlertFeature` and updates rolling window state.
/// Returns `Some(AlertAnomalyScore)` if the anomaly score exceeds the
/// minimum suspicious threshold (0.50). Returns `None` otherwise.
pub fn process_feature(
    feature: &AlertFeature,
    state: &mut AlertScorerState,
) -> Option<AlertAnomalyScore> {
    let now = feature.ts;
    let window_duration = chrono::Duration::seconds(state.window_secs as i64);
    let cutoff = now - window_duration;

    let features = state.records.entry(feature.src_ip.clone()).or_default();

    features.push(feature.clone());

    // Retain only features within the rolling time window
    features.retain(|f| f.ts > cutoff);

    let count = features.len() as u32;
    if count == 0 {
        return None;
    }

    // Identify top signature ID & category distribution
    let mut sig_counts: HashMap<u32, u32> = HashMap::new();
    let mut cat_counts: HashMap<ThreatCategory, u32> = HashMap::new();
    let mut total_severity: u32 = 0;

    for f in features.iter() {
        *sig_counts.entry(f.signature_id).or_insert(0) += 1;
        *cat_counts.entry(f.category).or_insert(0) += 1;
        total_severity += f.severity_score as u32;
    }

    let (&top_sig_id, &top_sig_count) = sig_counts.iter().max_by_key(|&(_, c)| c)?;
    let (&top_cat, _) = cat_counts.iter().max_by_key(|&(_, c)| c)?;

    // Calculate score factors:
    // 1. Frequency factor: baseline is 3 alerts/window. 50+ alerts maxes out to 1.0.
    let freq_factor = ((count as f32 - 1.0) / 49.0).clamp(0.0, 1.0);

    // 2. Signature repeat factor: ratio of top signature occurrences
    let sig_repeat_factor = (top_sig_count as f32 / count as f32).clamp(0.0, 1.0);

    // 3. Severity factor: average severity score (Critical=4, High=3) scaled to 0..1
    let avg_severity = total_severity as f32 / count as f32;
    let sev_factor = (avg_severity / 4.0).clamp(0.0, 1.0);

    // 4. Category factor: High-risk categories (Exploit/Malware) add weight
    let category_weight = match top_cat {
        ThreatCategory::Exploit => 1.0,
        ThreatCategory::Malware => 0.9,
        ThreatCategory::AttestationMismatch => 0.85,
        ThreatCategory::CertificateIssue => 0.8,
        ThreatCategory::Reconnaissance => 0.8,
        ThreatCategory::PolicyViolation => 0.7,
        ThreatCategory::Anomaly => 0.7,
        ThreatCategory::Other => 0.5,
    };

    // Combined score calculation (weighted formula matching doc spec)
    let raw_score = (freq_factor * 0.45)
        + (sig_repeat_factor * 0.25)
        + (sev_factor * 0.15)
        + (category_weight * 0.15);

    let score = raw_score.clamp(0.0, 1.0);

    if score >= 0.50 {
        Some(AlertAnomalyScore {
            score,
            contributing_ip: feature.src_ip.clone(),
            alert_count: count,
            top_signature_id: top_sig_id,
            category: top_cat,
            computed_at: now,
            window_secs: state.window_secs,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_feature(src_ip: &str, sid: u32, cat: ThreatCategory, sev_score: u8) -> AlertFeature {
        AlertFeature {
            ts: Utc::now(),
            severity_score: sev_score,
            signature_id: sid,
            category: cat,
            src_ip: src_ip.to_string(),
            dst_ip: "192.168.1.1".to_string(),
        }
    }

    #[test]
    fn test_single_alert_low_score() {
        let mut state = AlertScorerState::default();
        let feat = make_feature("10.0.0.1", 1001, ThreatCategory::Other, 1);
        let result = process_feature(&feat, &mut state);
        assert!(
            result.is_none(),
            "Single low-severity alert should be under 0.50 threshold"
        );
    }

    #[test]
    fn test_burst_alerts_critical_score() {
        let mut state = AlertScorerState::default();
        let now = Utc::now();
        let mut last_res = None;

        for _ in 0..60 {
            let feat = AlertFeature {
                ts: now,
                severity_score: 4, // Critical
                signature_id: 2009358,
                category: ThreatCategory::Reconnaissance,
                src_ip: "192.168.1.105".to_string(),
                dst_ip: "192.168.1.1".to_string(),
            };
            last_res = process_feature(&feat, &mut state);
        }

        assert!(last_res.is_some());
        let score_obj = last_res.unwrap();
        assert!(
            score_obj.score >= 0.90,
            "60 critical reconnaissance alerts should produce score >= 0.90, got {}",
            score_obj.score
        );
        assert_eq!(score_obj.contributing_ip, "192.168.1.105");
        assert_eq!(score_obj.alert_count, 60);
        assert_eq!(score_obj.top_signature_id, 2009358);
    }

    #[test]
    fn test_moderate_alerts_elevated_score() {
        let mut state = AlertScorerState::default();
        let now = Utc::now();
        let mut last_res = None;

        for _ in 0..20 {
            let feat = AlertFeature {
                ts: now,
                severity_score: 3, // High
                signature_id: 1002,
                category: ThreatCategory::PolicyViolation,
                src_ip: "172.16.0.5".to_string(),
                dst_ip: "172.16.0.1".to_string(),
            };
            last_res = process_feature(&feat, &mut state);
        }

        assert!(last_res.is_some());
        let score_obj = last_res.unwrap();
        assert!(
            score_obj.score >= 0.60 && score_obj.score <= 0.89,
            "20 moderate policy violation alerts should yield score in [0.60, 0.89], got {}",
            score_obj.score
        );
    }

    #[test]
    fn test_score_clamped_to_one() {
        let mut state = AlertScorerState::default();
        let now = Utc::now();
        let mut last_res = None;

        for _ in 0..200 {
            let feat = AlertFeature {
                ts: now,
                severity_score: 4,
                signature_id: 9999,
                category: ThreatCategory::Exploit,
                src_ip: "10.99.0.1".to_string(),
                dst_ip: "10.99.0.2".to_string(),
            };
            last_res = process_feature(&feat, &mut state);
        }

        assert!(last_res.is_some());
        let score_obj = last_res.unwrap();
        assert_eq!(score_obj.score, 1.0, "Score should be clamped to 1.0 max");
    }

    #[test]
    fn test_window_expiry() {
        let mut state = AlertScorerState::new(60); // 60-second window
        let old_time = Utc::now() - Duration::seconds(120); // 2 minutes ago
        let now = Utc::now();

        // Push old alerts
        for _ in 0..50 {
            let feat = AlertFeature {
                ts: old_time,
                severity_score: 4,
                signature_id: 1001,
                category: ThreatCategory::Exploit,
                src_ip: "10.0.0.50".to_string(),
                dst_ip: "10.0.0.1".to_string(),
            };
            let _ = process_feature(&feat, &mut state);
        }

        // Push 1 new alert now
        let new_feat = AlertFeature {
            ts: now,
            severity_score: 1,
            signature_id: 2002,
            category: ThreatCategory::Other,
            src_ip: "10.0.0.50".to_string(),
            dst_ip: "10.0.0.1".to_string(),
        };

        let result = process_feature(&new_feat, &mut state);
        assert!(
            result.is_none(),
            "Old alerts outside 60s window should expire, leaving only 1 alert"
        );
    }
}
