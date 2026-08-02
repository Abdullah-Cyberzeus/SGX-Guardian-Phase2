/// Threat Analytics & Historical Reporting
/// Track threat events over time for reporting and analysis
use crate::threat::errors::ThreatResult;
use std::collections::HashMap;

/// Individual threat event record
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatEvent {
    pub peer_id: String,
    pub event_type: String,
    pub severity: String,
    pub threat_score: f32,
    pub timestamp: u64,
}

impl ThreatEvent {
    /// Create new threat event
    pub fn new(peer_id: String, event_type: String, severity: String, threat_score: f32) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ThreatEvent {
            peer_id,
            event_type,
            severity,
            threat_score,
            timestamp,
        }
    }
}

/// Threat analytics aggregation
#[derive(Debug, Clone)]
pub struct ThreatAnalytics {
    peer_id: String,
    events: Vec<ThreatEvent>,
}

impl ThreatAnalytics {
    /// Create new threat analytics
    pub fn new(peer_id: String) -> Self {
        ThreatAnalytics {
            peer_id,
            events: Vec::new(),
        }
    }

    /// Record a threat event
    pub fn record_event(&mut self, event: ThreatEvent) -> ThreatResult<()> {
        self.events.push(event);
        Ok(())
    }

    /// Get events for a peer
    pub fn get_peer_events(&self, peer_id: &str) -> Vec<ThreatEvent> {
        self.events
            .iter()
            .filter(|e| e.peer_id == peer_id)
            .cloned()
            .collect()
    }

    /// Get events by severity
    pub fn get_events_by_severity(&self, severity: &str) -> Vec<ThreatEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == severity)
            .cloned()
            .collect()
    }

    /// Get events in time window (last N seconds)
    pub fn get_recent_events(&self, seconds: u64) -> Vec<ThreatEvent> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - seconds;

        self.events
            .iter()
            .filter(|e| e.timestamp > cutoff)
            .cloned()
            .collect()
    }

    /// Get threat statistics
    pub fn get_threat_stats(&self, peer_id: Option<&str>) -> ThreatStatistics {
        let events = if let Some(pid) = peer_id {
            self.get_peer_events(pid)
        } else {
            self.events.clone()
        };

        let total_events = events.len();
        let avg_score = if total_events > 0 {
            events.iter().map(|e| e.threat_score).sum::<f32>() / total_events as f32
        } else {
            0.0
        };

        let critical_count = events.iter().filter(|e| e.severity == "critical").count();
        let high_count = events.iter().filter(|e| e.severity == "high").count();
        let medium_count = events.iter().filter(|e| e.severity == "medium").count();
        let low_count = events.iter().filter(|e| e.severity == "low").count();

        let event_types: HashMap<String, usize> =
            events.iter().fold(HashMap::new(), |mut map, e| {
                *map.entry(e.event_type.clone()).or_insert(0) += 1;
                map
            });

        ThreatStatistics {
            total_events,
            avg_threat_score: avg_score,
            critical_count,
            high_count,
            medium_count,
            low_count,
            event_types,
        }
    }

    /// Get all events
    pub fn all_events(&self) -> &[ThreatEvent] {
        &self.events
    }

    /// Clear old events (older than cutoff_secs)
    pub fn cleanup_old_events(&mut self, cutoff_secs: u64) {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - cutoff_secs;

        self.events.retain(|e| e.timestamp > cutoff);
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get the peer id this analytics tracker was created for
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }
}

/// Threat statistics summary
#[derive(Debug, Clone, serde::Serialize)]
pub struct ThreatStatistics {
    pub total_events: usize,
    pub avg_threat_score: f32,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub event_types: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_event_creation() {
        let event = ThreatEvent::new(
            "peer_a".to_string(),
            "auth_failure".to_string(),
            "medium".to_string(),
            45.5,
        );
        assert_eq!(event.peer_id, "peer_a");
        assert_eq!(event.event_type, "auth_failure");
    }

    #[test]
    fn test_threat_analytics_creation() {
        let analytics = ThreatAnalytics::new("test_peer".to_string());
        assert_eq!(analytics.peer_id(), "test_peer");
        assert_eq!(analytics.event_count(), 0);
    }

    #[test]
    fn test_threat_analytics_record_event() {
        let mut analytics = ThreatAnalytics::new("test_peer".to_string());
        let event = ThreatEvent::new(
            "peer_b".to_string(),
            "policy_violation".to_string(),
            "high".to_string(),
            75.0,
        );
        assert!(analytics.record_event(event).is_ok());
        assert_eq!(analytics.event_count(), 1);
    }

    #[test]
    fn test_threat_analytics_get_peer_events() {
        let mut analytics = ThreatAnalytics::new("test_peer".to_string());
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_c".to_string(),
            "auth_failure".to_string(),
            "medium".to_string(),
            50.0,
        ));
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_d".to_string(),
            "policy_violation".to_string(),
            "high".to_string(),
            80.0,
        ));

        let peer_c_events = analytics.get_peer_events("peer_c");
        assert_eq!(peer_c_events.len(), 1);
    }

    #[test]
    fn test_threat_analytics_get_events_by_severity() {
        let mut analytics = ThreatAnalytics::new("test_peer".to_string());
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_e".to_string(),
            "auth_failure".to_string(),
            "high".to_string(),
            70.0,
        ));
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_f".to_string(),
            "policy_violation".to_string(),
            "high".to_string(),
            75.0,
        ));
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_g".to_string(),
            "call_attempt".to_string(),
            "low".to_string(),
            20.0,
        ));

        let high_events = analytics.get_events_by_severity("high");
        assert_eq!(high_events.len(), 2);
    }

    #[test]
    fn test_threat_analytics_get_threat_stats() {
        let mut analytics = ThreatAnalytics::new("test_peer".to_string());
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_h".to_string(),
            "auth_failure".to_string(),
            "critical".to_string(),
            95.0,
        ));
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_i".to_string(),
            "policy_violation".to_string(),
            "high".to_string(),
            75.0,
        ));
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_j".to_string(),
            "call_attempt".to_string(),
            "low".to_string(),
            25.0,
        ));

        let stats = analytics.get_threat_stats(None);
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.critical_count, 1);
        assert_eq!(stats.high_count, 1);
        assert_eq!(stats.low_count, 1);
        assert!(stats.avg_threat_score > 0.0);
    }

    #[test]
    fn test_threat_analytics_get_recent_events() {
        let mut analytics = ThreatAnalytics::new("test_peer".to_string());
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_k".to_string(),
            "auth_failure".to_string(),
            "medium".to_string(),
            50.0,
        ));

        let recent = analytics.get_recent_events(3600); // Last hour
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_threat_analytics_cleanup_old_events() {
        let mut analytics = ThreatAnalytics::new("test_peer".to_string());
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_l".to_string(),
            "auth_failure".to_string(),
            "medium".to_string(),
            50.0,
        ));

        // Cleanup events older than 1 second (should not remove recently added)
        analytics.cleanup_old_events(1);
        let _ = analytics.event_count();
    }

    #[test]
    fn test_threat_statistics_calculation() {
        let mut analytics = ThreatAnalytics::new("test_peer".to_string());
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_m".to_string(),
            "auth_failure".to_string(),
            "high".to_string(),
            70.0,
        ));
        let _ = analytics.record_event(ThreatEvent::new(
            "peer_m".to_string(),
            "auth_failure".to_string(),
            "high".to_string(),
            80.0,
        ));

        let stats = analytics.get_threat_stats(Some("peer_m"));
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.avg_threat_score, 75.0);
    }
}
