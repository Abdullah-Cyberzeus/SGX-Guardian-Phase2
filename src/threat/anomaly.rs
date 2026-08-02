/// Real-time Anomaly Detection
/// Detects unusual patterns and behavior
use crate::threat::errors::ThreatResult;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Types of anomalies
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AnomalyType {
    /// Unusual number of failed authentications
    BruteForceAttempt,
    /// Abnormal call volume
    CallVolumeAnomaly,
    /// Unusual peer communication patterns
    UnusualPattern,
    /// Rapid policy violations
    PolicyViolationSpike,
    /// Unusual media access patterns
    MediaAccessAnomaly,
    /// Suspicious certificate behavior
    CertificateBehavior,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyType::BruteForceAttempt => write!(f, "brute_force_attempt"),
            AnomalyType::CallVolumeAnomaly => write!(f, "call_volume_anomaly"),
            AnomalyType::UnusualPattern => write!(f, "unusual_pattern"),
            AnomalyType::PolicyViolationSpike => write!(f, "policy_violation_spike"),
            AnomalyType::MediaAccessAnomaly => write!(f, "media_access_anomaly"),
            AnomalyType::CertificateBehavior => write!(f, "certificate_behavior"),
        }
    }
}

/// Anomaly score result
#[derive(Debug, Clone)]
pub struct AnomalyScore {
    pub anomaly_type: AnomalyType,
    pub score: f32, // 0.0 to 100.0
    pub timestamp: u64,
}

/// Peer activity tracking
#[derive(Debug, Clone)]
pub struct PeerActivity {
    auth_failures: Vec<u64>,
    call_attempts: Vec<u64>,
    policy_violations: Vec<u64>,
    media_accesses: Vec<u64>,
}

impl PeerActivity {
    fn new() -> Self {
        PeerActivity {
            auth_failures: Vec::new(),
            call_attempts: Vec::new(),
            policy_violations: Vec::new(),
            media_accesses: Vec::new(),
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn count_recent(&self, events: &[u64], window_secs: u64) -> usize {
        let cutoff = Self::current_timestamp() - window_secs;
        events.iter().filter(|&&ts| ts > cutoff).count()
    }
}

/// Anomaly detector
#[derive(Clone)]
pub struct AnomalyDetector {
    peer_id: String,
    peer_activities: HashMap<String, PeerActivity>,
}

impl AnomalyDetector {
    /// Create new anomaly detector
    pub fn new(peer_id: String) -> Self {
        AnomalyDetector {
            peer_id,
            peer_activities: HashMap::new(),
        }
    }

    /// Detect anomalies in peer behavior
    pub fn detect(
        &mut self,
        peer_id: &str,
        event_type: &str,
        _event_data: &str,
    ) -> ThreatResult<AnomalyScore> {
        let activity = self
            .peer_activities
            .entry(peer_id.to_string())
            .or_insert_with(PeerActivity::new);

        let timestamp = PeerActivity::current_timestamp();
        let score;
        let anomaly_type;

        match event_type {
            "auth_failure" => {
                activity.auth_failures.push(timestamp);
                let failures_5min = activity.count_recent(&activity.auth_failures, 300);

                // Anomaly if 5+ failures in 5 minutes
                if failures_5min >= 5 {
                    score = std::cmp::min(100, (failures_5min as f32 * 15.0) as u32) as f32;
                    anomaly_type = AnomalyType::BruteForceAttempt;
                } else {
                    score = (failures_5min as f32 * 10.0).min(50.0);
                    anomaly_type = AnomalyType::BruteForceAttempt;
                }
            }
            "policy_violation" => {
                activity.policy_violations.push(timestamp);
                let violations_1min = activity.count_recent(&activity.policy_violations, 60);

                // Anomaly if 3+ violations in 1 minute
                if violations_1min >= 3 {
                    score = std::cmp::min(100, (violations_1min as f32 * 25.0) as u32) as f32;
                    anomaly_type = AnomalyType::PolicyViolationSpike;
                } else {
                    score = (violations_1min as f32 * 20.0).min(50.0);
                    anomaly_type = AnomalyType::PolicyViolationSpike;
                }
            }
            "call_attempt" => {
                activity.call_attempts.push(timestamp);
                let calls_5min = activity.count_recent(&activity.call_attempts, 300);

                // Anomaly if 20+ calls in 5 minutes
                if calls_5min >= 20 {
                    score = std::cmp::min(100, (calls_5min as f32 * 3.0) as u32) as f32;
                    anomaly_type = AnomalyType::CallVolumeAnomaly;
                } else {
                    score = (calls_5min as f32 * 2.0).min(50.0);
                    anomaly_type = AnomalyType::CallVolumeAnomaly;
                }
            }
            "media_access" => {
                activity.media_accesses.push(timestamp);
                let accesses_1min = activity.count_recent(&activity.media_accesses, 60);

                // Anomaly if 15+ media accesses in 1 minute
                if accesses_1min >= 15 {
                    score = std::cmp::min(100, (accesses_1min as f32 * 5.0) as u32) as f32;
                    anomaly_type = AnomalyType::MediaAccessAnomaly;
                } else {
                    score = (accesses_1min as f32 * 3.0).min(50.0);
                    anomaly_type = AnomalyType::MediaAccessAnomaly;
                }
            }
            _ => {
                // Unknown event type
                score = 10.0;
                anomaly_type = AnomalyType::UnusualPattern;
            }
        }

        Ok(AnomalyScore {
            anomaly_type,
            score: score.clamp(0.0, 100.0),
            timestamp,
        })
    }

    /// Clear old events (older than 1 hour)
    pub fn cleanup_old_events(&mut self) {
        let cutoff = PeerActivity::current_timestamp() - 3600;

        for activity in self.peer_activities.values_mut() {
            activity.auth_failures.retain(|&ts| ts > cutoff);
            activity.call_attempts.retain(|&ts| ts > cutoff);
            activity.policy_violations.retain(|&ts| ts > cutoff);
            activity.media_accesses.retain(|&ts| ts > cutoff);
        }
    }

    /// Get activity for a peer
    pub fn get_activity(&self, peer_id: &str) -> Option<&PeerActivity> {
        self.peer_activities.get(peer_id)
    }

    /// Get the peer id this detector was created for
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_detector_creation() {
        let detector = AnomalyDetector::new("test_peer".to_string());
        assert_eq!(detector.peer_id(), "test_peer");
    }

    #[test]
    fn test_anomaly_detection_single_failure() {
        let mut detector = AnomalyDetector::new("test_peer".to_string());
        let score = detector.detect("peer_a", "auth_failure", "");
        assert!(score.is_ok());
        let score = score.unwrap();
        assert!(score.score > 0.0);
        assert_eq!(score.anomaly_type, AnomalyType::BruteForceAttempt);
    }

    #[test]
    fn test_anomaly_detection_multiple_failures() {
        let mut detector = AnomalyDetector::new("test_peer".to_string());
        let mut final_score = AnomalyScore {
            anomaly_type: AnomalyType::BruteForceAttempt,
            score: 0.0,
            timestamp: 0,
        };

        for _ in 0..5 {
            let score = detector.detect("peer_b", "auth_failure", "");
            assert!(score.is_ok());
            final_score = score.unwrap();
        }

        // Should detect brute force after multiple failures
        assert!(final_score.score > 40.0);
    }

    #[test]
    fn test_anomaly_detection_policy_violations() {
        let mut detector = AnomalyDetector::new("test_peer".to_string());
        let _ = detector.detect("peer_c", "policy_violation", "");
        let _ = detector.detect("peer_c", "policy_violation", "");
        let score = detector.detect("peer_c", "policy_violation", "");

        assert!(score.is_ok());
        let score = score.unwrap();
        assert_eq!(score.anomaly_type, AnomalyType::PolicyViolationSpike);
        assert!(score.score > 40.0);
    }

    #[test]
    fn test_anomaly_detection_call_volume() {
        let mut detector = AnomalyDetector::new("test_peer".to_string());
        let _ = detector.detect("peer_d", "call_attempt", "");
        let _ = detector.detect("peer_d", "call_attempt", "");
        let score = detector.detect("peer_d", "call_attempt", "");

        assert!(score.is_ok());
        let score = score.unwrap();
        assert!(score.anomaly_type == AnomalyType::CallVolumeAnomaly);
    }

    #[test]
    fn test_anomaly_score_bounds() {
        let mut detector = AnomalyDetector::new("test_peer".to_string());
        let score = detector.detect("peer_e", "auth_failure", "");
        let score = score.unwrap();
        assert!(score.score >= 0.0 && score.score <= 100.0);
    }

    #[test]
    fn test_anomaly_detector_cleanup() {
        let mut detector = AnomalyDetector::new("test_peer".to_string());
        let _ = detector.detect("peer_f", "auth_failure", "");
        detector.cleanup_old_events();
        // Should not panic, old events cleaned up
        let _ = detector.peer_activities.len();
    }

    #[test]
    fn test_anomaly_detector_unknown_event() {
        let mut detector = AnomalyDetector::new("test_peer".to_string());
        let score = detector.detect("peer_g", "unknown_event", "");
        assert!(score.is_ok());
        let score = score.unwrap();
        assert_eq!(score.anomaly_type, AnomalyType::UnusualPattern);
    }
}
