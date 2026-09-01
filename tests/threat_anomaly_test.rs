use sgx_guardian_client::threat::anomaly::{AnomalyDetector, AnomalyType};

#[test]
fn detector_preserves_peer_id() {
    assert_eq!(AnomalyDetector::new("peer-main".into()).peer_id(), "peer-main");
}

#[test]
fn unknown_peer_activity_is_none() {
    assert!(AnomalyDetector::new("p".into()).get_activity("absent").is_none());
}

#[test]
fn unknown_event_creates_activity() {
    let mut detector = AnomalyDetector::new("p".into());
    detector.detect("peer", "unknown", "").unwrap();
    assert!(detector.get_activity("peer").is_some());
}

macro_rules! display_tests {
    ($($name:ident => $variant:expr, $text:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            assert_eq!($variant.to_string(), $text);
        }
    )+};
}

display_tests! {
    display_brute_force => AnomalyType::BruteForceAttempt, "brute_force_attempt",
    display_call_volume => AnomalyType::CallVolumeAnomaly, "call_volume_anomaly",
    display_unusual_pattern => AnomalyType::UnusualPattern, "unusual_pattern",
    display_policy_spike => AnomalyType::PolicyViolationSpike, "policy_violation_spike",
    display_media_access => AnomalyType::MediaAccessAnomaly, "media_access_anomaly",
    display_certificate_behavior => AnomalyType::CertificateBehavior, "certificate_behavior",
}

macro_rules! first_event_tests {
    ($($name:ident => $event:expr, $kind:expr, $score:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let mut detector = AnomalyDetector::new("p".into());
            let score = detector.detect("peer", $event, "data").unwrap();
            assert_eq!(score.anomaly_type, $kind);
            assert_eq!(score.score, $score);
            assert!(score.timestamp > 0);
        }
    )+};
}

first_event_tests! {
    first_auth_failure_scores_ten => "auth_failure", AnomalyType::BruteForceAttempt, 10.0,
    first_policy_violation_scores_twenty => "policy_violation", AnomalyType::PolicyViolationSpike, 20.0,
    first_call_attempt_scores_two => "call_attempt", AnomalyType::CallVolumeAnomaly, 2.0,
    first_media_access_scores_three => "media_access", AnomalyType::MediaAccessAnomaly, 3.0,
    first_unknown_scores_ten => "something_else", AnomalyType::UnusualPattern, 10.0,
}

#[test]
fn fifth_auth_failure_crosses_threshold() {
    let mut detector = AnomalyDetector::new("p".into());
    let mut score = 0.0;
    for _ in 0..5 {
        score = detector.detect("peer", "auth_failure", "").unwrap().score;
    }
    assert_eq!(score, 75.0);
}

#[test]
fn many_auth_failures_clamp_at_100() {
    let mut detector = AnomalyDetector::new("p".into());
    let mut score = 0.0;
    for _ in 0..20 {
        score = detector.detect("peer", "auth_failure", "").unwrap().score;
    }
    assert_eq!(score, 100.0);
}

#[test]
fn third_policy_violation_crosses_threshold() {
    let mut detector = AnomalyDetector::new("p".into());
    let mut score = 0.0;
    for _ in 0..3 {
        score = detector.detect("peer", "policy_violation", "").unwrap().score;
    }
    assert_eq!(score, 75.0);
}

#[test]
fn policy_violations_clamp_at_100() {
    let mut detector = AnomalyDetector::new("p".into());
    let mut score = 0.0;
    for _ in 0..8 {
        score = detector.detect("peer", "policy_violation", "").unwrap().score;
    }
    assert_eq!(score, 100.0);
}

#[test]
fn twentieth_call_attempt_uses_anomaly_formula() {
    let mut detector = AnomalyDetector::new("p".into());
    let mut score = 0.0;
    for _ in 0..20 {
        score = detector.detect("peer", "call_attempt", "").unwrap().score;
    }
    assert_eq!(score, 60.0);
}

#[test]
fn many_call_attempts_clamp_at_100() {
    let mut detector = AnomalyDetector::new("p".into());
    let mut score = 0.0;
    for _ in 0..40 {
        score = detector.detect("peer", "call_attempt", "").unwrap().score;
    }
    assert_eq!(score, 100.0);
}

#[test]
fn fifteenth_media_access_uses_anomaly_formula() {
    let mut detector = AnomalyDetector::new("p".into());
    let mut score = 0.0;
    for _ in 0..15 {
        score = detector.detect("peer", "media_access", "").unwrap().score;
    }
    assert_eq!(score, 75.0);
}

#[test]
fn many_media_accesses_clamp_at_100() {
    let mut detector = AnomalyDetector::new("p".into());
    let mut score = 0.0;
    for _ in 0..30 {
        score = detector.detect("peer", "media_access", "").unwrap().score;
    }
    assert_eq!(score, 100.0);
}

#[test]
fn peers_are_tracked_independently() {
    let mut detector = AnomalyDetector::new("p".into());
    detector.detect("a", "auth_failure", "").unwrap();
    detector.detect("b", "auth_failure", "").unwrap();
    detector.detect("b", "auth_failure", "").unwrap();
    assert!(detector.get_activity("a").is_some());
    assert!(detector.get_activity("b").is_some());
}

#[test]
fn cleanup_keeps_recent_activity() {
    let mut detector = AnomalyDetector::new("p".into());
    detector.detect("peer", "auth_failure", "").unwrap();
    detector.cleanup_old_events();
    assert!(detector.get_activity("peer").is_some());
}

#[test]
fn cloned_detector_preserves_peer_id() {
    let detector = AnomalyDetector::new("p".into());
    assert_eq!(detector.clone().peer_id(), "p");
}

#[test]
fn anomaly_type_round_trips_json() {
    let kind = AnomalyType::MediaAccessAnomaly;
    assert_eq!(serde_json::from_value::<AnomalyType>(serde_json::to_value(&kind).unwrap()).unwrap(), kind);
}

#[test]
fn anomaly_type_rejects_unknown_json_variant() {
    assert!(serde_json::from_str::<AnomalyType>("\"Unknown\"").is_err());
}

#[test]
fn event_data_does_not_change_unknown_event_score() {
    let mut detector = AnomalyDetector::new("p".into());
    assert_eq!(detector.detect("peer", "unknown", "a").unwrap().score, 10.0);
    assert_eq!(detector.detect("peer", "unknown", "b").unwrap().score, 10.0);
}
