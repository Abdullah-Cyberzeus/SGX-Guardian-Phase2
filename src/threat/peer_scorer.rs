/// Peer Threat Scoring
/// Calculate and track threat scores for peers
use crate::threat::anomaly::AnomalyType;
use crate::threat::errors::{ThreatError, ThreatResult};
use std::collections::HashMap;

/// Peer threat score
#[derive(Debug, Clone)]
pub struct PeerThreatScore {
    pub peer_id: String,
    pub score: f32, // 0.0 to 100.0
    pub last_updated: u64,
    pub incident_count: usize,
    pub is_blocked: bool,
}

impl PeerThreatScore {
    /// Create new peer threat score
    pub fn new(peer_id: String) -> Self {
        PeerThreatScore {
            peer_id,
            score: 0.0,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            incident_count: 0,
            is_blocked: false,
        }
    }

    /// Get severity level based on score
    pub fn severity_level(&self) -> &'static str {
        if self.is_blocked {
            return "blocked";
        }

        match self.score as u32 {
            0..=20 => "low",
            21..=50 => "medium",
            51..=75 => "high",
            76..=100 => "critical",
            _ => "unknown",
        }
    }

    /// Check if peer should be blocked
    pub fn should_block(&self) -> bool {
        self.score >= 80.0
    }
}

/// Peer threat scorer
#[derive(Clone)]
pub struct PeerScorer {
    scores: HashMap<String, PeerThreatScore>,
}

impl PeerScorer {
    /// Create new peer scorer
    pub fn new() -> Self {
        PeerScorer {
            scores: HashMap::new(),
        }
    }

    /// Update threat score for a peer based on anomaly
    pub fn update_threat_score(
        &mut self,
        peer_id: &str,
        anomaly_type: AnomalyType,
        anomaly_score: f32,
    ) -> ThreatResult<PeerThreatScore> {
        let score = self
            .scores
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerThreatScore::new(peer_id.to_string()));

        // Weight the anomaly score based on type
        let weight = match anomaly_type {
            AnomalyType::BruteForceAttempt => 0.3,
            AnomalyType::CallVolumeAnomaly => 0.2,
            AnomalyType::UnusualPattern => 0.15,
            AnomalyType::PolicyViolationSpike => 0.4,
            AnomalyType::MediaAccessAnomaly => 0.35,
            AnomalyType::CertificateBehavior => 0.5,
        };

        // Update score with exponential decay of old score
        let decay = 0.95; // 5% decay per update
        let increment = anomaly_score * weight;
        score.score = (score.score * decay) + increment;
        score.score = score.score.clamp(0.0, 100.0);

        // Auto-block if score exceeds threshold
        if score.should_block() {
            score.is_blocked = true;
        }

        score.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(score.clone())
    }

    /// Get score for a peer
    pub fn get_score(&self, peer_id: &str) -> ThreatResult<PeerThreatScore> {
        self.scores
            .get(peer_id)
            .cloned()
            .ok_or_else(|| ThreatError::PeerNotFound(peer_id.to_string()))
    }

    /// Get or create score for a peer
    pub fn get_or_create_score(&mut self, peer_id: &str) -> PeerThreatScore {
        self.scores
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerThreatScore::new(peer_id.to_string()))
            .clone()
    }

    /// Update incident count for a peer
    pub fn increment_incident(&mut self, peer_id: &str) -> ThreatResult<()> {
        let score = self
            .scores
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerThreatScore::new(peer_id.to_string()));

        score.incident_count += 1;

        // Increase threat score based on incident count
        let incident_impact = score.incident_count as f32 * 5.0;
        score.score = (score.score + incident_impact).min(100.0);

        if score.should_block() {
            score.is_blocked = true;
        }

        Ok(())
    }

    /// Block a peer
    pub fn block_peer(&mut self, peer_id: &str) -> ThreatResult<()> {
        let score = self
            .scores
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerThreatScore::new(peer_id.to_string()));

        score.is_blocked = true;
        score.score = 100.0;

        Ok(())
    }

    /// Unblock a peer
    pub fn unblock_peer(&mut self, peer_id: &str) -> ThreatResult<()> {
        if let Some(score) = self.scores.get_mut(peer_id) {
            score.is_blocked = false;
            score.score *= 0.5; // Reduce score by half when unblocked
            Ok(())
        } else {
            Err(ThreatError::PeerNotFound(peer_id.to_string()))
        }
    }

    /// Get all peer scores
    pub fn all_scores(&self) -> Vec<PeerThreatScore> {
        self.scores.values().cloned().collect()
    }

    /// Get blocked peers
    pub fn get_blocked_peers(&self) -> Vec<String> {
        self.scores
            .iter()
            .filter(|(_, score)| score.is_blocked)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Reset score for a peer
    pub fn reset_score(&mut self, peer_id: &str) -> ThreatResult<()> {
        if let Some(score) = self.scores.get_mut(peer_id) {
            score.score = 0.0;
            score.is_blocked = false;
            score.incident_count = 0;
            Ok(())
        } else {
            Err(ThreatError::PeerNotFound(peer_id.to_string()))
        }
    }
}

impl Default for PeerScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_threat_score_creation() {
        let score = PeerThreatScore::new("peer_a".to_string());
        assert_eq!(score.peer_id, "peer_a");
        assert_eq!(score.score, 0.0);
        assert!(!score.is_blocked);
    }

    #[test]
    fn test_peer_threat_severity_levels() {
        let mut score = PeerThreatScore::new("peer_b".to_string());
        assert_eq!(score.severity_level(), "low");

        score.score = 30.0;
        assert_eq!(score.severity_level(), "medium");

        score.score = 60.0;
        assert_eq!(score.severity_level(), "high");

        score.score = 85.0;
        assert_eq!(score.severity_level(), "critical");

        score.is_blocked = true;
        assert_eq!(score.severity_level(), "blocked");
    }

    #[test]
    fn test_peer_scorer_creation() {
        let scorer = PeerScorer::new();
        assert!(scorer.all_scores().is_empty());
    }

    #[test]
    fn test_peer_scorer_update_score() {
        let mut scorer = PeerScorer::new();
        let score = scorer.update_threat_score("peer_c", AnomalyType::BruteForceAttempt, 50.0);
        assert!(score.is_ok());
        let score = score.unwrap();
        assert!(score.score > 0.0);
    }

    #[test]
    fn test_peer_scorer_get_score() {
        let mut scorer = PeerScorer::new();
        let _ = scorer.update_threat_score("peer_d", AnomalyType::PolicyViolationSpike, 80.0);
        let score = scorer.get_score("peer_d");
        assert!(score.is_ok());
    }

    #[test]
    fn test_peer_scorer_block_peer() {
        let mut scorer = PeerScorer::new();
        let _ = scorer.update_threat_score("peer_e", AnomalyType::BruteForceAttempt, 20.0);
        assert!(scorer.block_peer("peer_e").is_ok());
        let score = scorer.get_score("peer_e").unwrap();
        assert!(score.is_blocked);
        assert_eq!(score.score, 100.0);
    }

    #[test]
    fn test_peer_scorer_incident_count() {
        let mut scorer = PeerScorer::new();
        let _ = scorer.update_threat_score("peer_f", AnomalyType::BruteForceAttempt, 20.0);
        assert!(scorer.increment_incident("peer_f").is_ok());
        let score = scorer.get_score("peer_f").unwrap();
        assert_eq!(score.incident_count, 1);
    }

    #[test]
    fn test_peer_scorer_auto_block() {
        let mut scorer = PeerScorer::new();
        // CertificateBehavior weight is 0.5, so 100.0 * 0.5 = 50.0
        // Update multiple times to reach threshold
        let _ = scorer.update_threat_score("peer_g", AnomalyType::CertificateBehavior, 100.0);
        let _ = scorer.update_threat_score("peer_g", AnomalyType::CertificateBehavior, 100.0);
        let score = scorer.get_score("peer_g").unwrap();
        assert!(score.is_blocked); // Should auto-block when score >= 80
    }

    #[test]
    fn test_peer_scorer_reset_score() {
        let mut scorer = PeerScorer::new();
        let _ = scorer.update_threat_score("peer_h", AnomalyType::BruteForceAttempt, 80.0);
        assert!(scorer.reset_score("peer_h").is_ok());
        let score = scorer.get_score("peer_h").unwrap();
        assert_eq!(score.score, 0.0);
        assert!(!score.is_blocked);
    }

    #[test]
    fn test_peer_scorer_get_blocked_peers() {
        let mut scorer = PeerScorer::new();
        let _ = scorer.block_peer("peer_i");
        let _ = scorer.block_peer("peer_j");
        let blocked = scorer.get_blocked_peers();
        assert_eq!(blocked.len(), 2);
    }
}
