/// Incident Management & Response
/// Track and respond to security incidents
use crate::threat::errors::{ThreatError, ThreatResult};
use std::collections::HashMap;

/// Incident severity level
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentSeverity::Low => write!(f, "low"),
            IncidentSeverity::Medium => write!(f, "medium"),
            IncidentSeverity::High => write!(f, "high"),
            IncidentSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl From<String> for IncidentSeverity {
    fn from(s: String) -> Self {
        match s.as_str() {
            "low" => IncidentSeverity::Low,
            "medium" => IncidentSeverity::Medium,
            "high" => IncidentSeverity::High,
            "critical" => IncidentSeverity::Critical,
            _ => IncidentSeverity::Medium,
        }
    }
}

/// Incident response actions
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IncidentResponse {
    /// Peer is isolated from network
    Isolated,
    /// Peer is blocked from connections
    Blocked,
    /// Peer is rate-limited
    RateLimited,
    /// Peer is disconnected
    Disconnected,
    /// Alert sent to administrators
    AlertSent,
    /// Under investigation
    Investigating,
    /// Resolved/Cleared
    Resolved,
}

impl std::fmt::Display for IncidentResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentResponse::Isolated => write!(f, "isolated"),
            IncidentResponse::Blocked => write!(f, "blocked"),
            IncidentResponse::RateLimited => write!(f, "rate_limited"),
            IncidentResponse::Disconnected => write!(f, "disconnected"),
            IncidentResponse::AlertSent => write!(f, "alert_sent"),
            IncidentResponse::Investigating => write!(f, "investigating"),
            IncidentResponse::Resolved => write!(f, "resolved"),
        }
    }
}

/// Security incident
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Incident {
    pub id: String,
    pub peer_id: String,
    pub severity: IncidentSeverity,
    pub description: String,
    pub timestamp: u64,
    pub response: IncidentResponse,
    pub resolved: bool,
}

impl Incident {
    /// Create new incident
    pub fn new(peer_id: String, severity: String, description: String) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Incident {
            id,
            peer_id,
            severity: IncidentSeverity::from(severity),
            description,
            timestamp,
            response: IncidentResponse::AlertSent,
            resolved: false,
        }
    }

    /// Mark incident as resolved
    pub fn resolve(&mut self) {
        self.resolved = true;
        self.response = IncidentResponse::Resolved;
    }
}

/// Incident manager
#[derive(Clone)]
pub struct IncidentManager {
    peer_id: String,
    incidents: HashMap<String, Incident>,
}

impl IncidentManager {
    /// Create new incident manager
    pub fn new(peer_id: String) -> Self {
        IncidentManager {
            peer_id,
            incidents: HashMap::new(),
        }
    }

    /// Report a new incident
    pub fn report_incident(&mut self, incident: Incident) -> ThreatResult<()> {
        self.incidents.insert(incident.id.clone(), incident);
        Ok(())
    }

    /// Get incident by id
    pub fn get_incident(&self, incident_id: &str) -> ThreatResult<Incident> {
        self.incidents
            .get(incident_id)
            .cloned()
            .ok_or_else(|| ThreatError::IncidentNotFound(incident_id.to_string()))
    }

    /// Get all active incidents for a peer
    pub fn get_active_incidents(&self, peer_id: &str) -> ThreatResult<Vec<Incident>> {
        let incidents: Vec<_> = self
            .incidents
            .values()
            .filter(|i| i.peer_id == peer_id && !i.resolved)
            .cloned()
            .collect();

        Ok(incidents)
    }

    /// Get all incidents for a peer
    pub fn get_peer_incidents(&self, peer_id: &str) -> ThreatResult<Vec<Incident>> {
        let incidents: Vec<_> = self
            .incidents
            .values()
            .filter(|i| i.peer_id == peer_id)
            .cloned()
            .collect();

        Ok(incidents)
    }

    /// Update incident response
    pub fn update_incident_response(
        &mut self,
        incident_id: &str,
        response: IncidentResponse,
    ) -> ThreatResult<()> {
        if let Some(incident) = self.incidents.get_mut(incident_id) {
            incident.response = response;
            Ok(())
        } else {
            Err(ThreatError::IncidentNotFound(incident_id.to_string()))
        }
    }

    /// Resolve incident
    pub fn resolve_incident(&mut self, incident_id: &str) -> ThreatResult<()> {
        if let Some(incident) = self.incidents.get_mut(incident_id) {
            incident.resolve();
            Ok(())
        } else {
            Err(ThreatError::IncidentNotFound(incident_id.to_string()))
        }
    }

    /// Get critical incidents (unresolved high/critical severity)
    pub fn get_critical_incidents(&self) -> Vec<Incident> {
        self.incidents
            .values()
            .filter(|i| {
                !i.resolved
                    && (i.severity == IncidentSeverity::Critical
                        || i.severity == IncidentSeverity::High)
            })
            .cloned()
            .collect()
    }

    /// Get all incidents
    pub fn all_incidents(&self) -> Vec<Incident> {
        self.incidents.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_creation() {
        let incident = Incident::new(
            "peer_a".to_string(),
            "high".to_string(),
            "Suspicious activity detected".to_string(),
        );
        assert_eq!(incident.peer_id, "peer_a");
        assert_eq!(incident.severity, IncidentSeverity::High);
        assert!(!incident.resolved);
    }

    #[test]
    fn test_incident_resolve() {
        let mut incident = Incident::new(
            "peer_b".to_string(),
            "medium".to_string(),
            "Test incident".to_string(),
        );
        incident.resolve();
        assert!(incident.resolved);
        assert_eq!(incident.response, IncidentResponse::Resolved);
    }

    #[test]
    fn test_incident_manager_creation() {
        let manager = IncidentManager::new("test_peer".to_string());
        assert_eq!(manager.peer_id, "test_peer");
    }

    #[test]
    fn test_incident_manager_report() {
        let mut manager = IncidentManager::new("test_peer".to_string());
        let incident = Incident::new(
            "peer_c".to_string(),
            "high".to_string(),
            "Test incident".to_string(),
        );
        assert!(manager.report_incident(incident).is_ok());
    }

    #[test]
    fn test_incident_manager_get_incident() {
        let mut manager = IncidentManager::new("test_peer".to_string());
        let incident = Incident::new(
            "peer_d".to_string(),
            "critical".to_string(),
            "Critical incident".to_string(),
        );
        let incident_id = incident.id.clone();
        assert!(manager.report_incident(incident).is_ok());
        let retrieved = manager.get_incident(&incident_id);
        assert!(retrieved.is_ok());
    }

    #[test]
    fn test_incident_manager_get_active_incidents() {
        let mut manager = IncidentManager::new("test_peer".to_string());
        let incident = Incident::new(
            "peer_e".to_string(),
            "high".to_string(),
            "Active incident".to_string(),
        );
        assert!(manager.report_incident(incident).is_ok());
        let active = manager.get_active_incidents("peer_e");
        assert!(active.is_ok());
        assert_eq!(active.unwrap().len(), 1);
    }

    #[test]
    fn test_incident_manager_update_response() {
        let mut manager = IncidentManager::new("test_peer".to_string());
        let incident = Incident::new(
            "peer_f".to_string(),
            "high".to_string(),
            "Test incident".to_string(),
        );
        let incident_id = incident.id.clone();
        assert!(manager.report_incident(incident).is_ok());
        assert!(manager
            .update_incident_response(&incident_id, IncidentResponse::Blocked)
            .is_ok());
    }

    #[test]
    fn test_incident_manager_resolve_incident() {
        let mut manager = IncidentManager::new("test_peer".to_string());
        let incident = Incident::new(
            "peer_g".to_string(),
            "low".to_string(),
            "Test incident".to_string(),
        );
        let incident_id = incident.id.clone();
        assert!(manager.report_incident(incident).is_ok());
        assert!(manager.resolve_incident(&incident_id).is_ok());
        let resolved = manager.get_incident(&incident_id).unwrap();
        assert!(resolved.resolved);
    }

    #[test]
    fn test_incident_manager_critical_incidents() {
        let mut manager = IncidentManager::new("test_peer".to_string());
        let _ = manager.report_incident(Incident::new(
            "peer_h".to_string(),
            "critical".to_string(),
            "Critical".to_string(),
        ));
        let _ = manager.report_incident(Incident::new(
            "peer_i".to_string(),
            "low".to_string(),
            "Low".to_string(),
        ));
        let critical = manager.get_critical_incidents();
        assert_eq!(critical.len(), 1);
    }
}
