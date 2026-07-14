// src/cot/session_manager.rs
// ============================================================
// Session Manager — Cross-Transport Continuity
// Sessions survive transport changes. Identity-based, NOT IP-based.
// ============================================================

use crate::cot::types::{CotError, CotResult, TransportType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Migrating,
    Suspended,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub local_device_id: String,
    pub remote_device_id: String,
    pub current_transport: TransportType,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub migration_count: u32,
    pub transport_history: Vec<(TransportType, DateTime<Utc>)>,
}

impl Session {
    pub fn new(
        local_device_id: String,
        remote_device_id: String,
        initial_transport: TransportType,
    ) -> Self {
        let now = Utc::now();
        Self {
            session_id: uuid::Uuid::new_v4().to_string(),
            local_device_id,
            remote_device_id,
            current_transport: initial_transport,
            state: SessionState::Active,
            created_at: now,
            last_activity: now,
            migration_count: 0,
            transport_history: vec![(initial_transport, now)],
        }
    }

    pub fn migrate_transport(&mut self, new_transport: TransportType) {
        let now = Utc::now();
        self.current_transport = new_transport;
        self.migration_count += 1;
        self.transport_history.push((new_transport, now));
        self.state = SessionState::Active;
        self.last_activity = now;
    }

    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn suspend(&mut self) {
        self.state = SessionState::Suspended;
    }

    pub fn resume(&mut self, transport: TransportType) {
        self.migrate_transport(transport);
        self.state = SessionState::Active;
    }

    pub fn is_expired(&self, timeout_secs: i64) -> bool {
        let elapsed = Utc::now()
            .signed_duration_since(self.last_activity)
            .num_seconds();
        elapsed > timeout_secs
    }
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    timeout_secs: i64,
}
impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-global handle to the running SessionManager, set once when the
/// CoT subsystem starts (see main.rs). Lets the CRL emergency channel drop
/// sessions for a revoked peer without threading the manager through every
/// call site. `None` when CoT is disabled (SGX_DISABLE_COT=1).
static GLOBAL_SESSION_MANAGER: once_cell::sync::OnceCell<std::sync::Arc<SessionManager>> =
    once_cell::sync::OnceCell::new();

/// Register the process-wide SessionManager. Idempotent; later calls are
/// ignored. Called once from the CoT startup block in main.rs.
pub fn set_global_session_manager(manager: std::sync::Arc<SessionManager>) {
    let _ = GLOBAL_SESSION_MANAGER.set(manager);
}

/// Fetch the process-wide SessionManager if CoT initialized one.
pub fn global_session_manager() -> Option<std::sync::Arc<SessionManager>> {
    GLOBAL_SESSION_MANAGER.get().cloned()
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            timeout_secs: 300,
        }
    }

    pub fn with_timeout(timeout_secs: i64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            timeout_secs,
        }
    }

    pub async fn get_or_create(
        &self,
        local_device_id: &str,
        remote_device_id: &str,
        transport: TransportType,
    ) -> Session {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(remote_device_id) {
            if session.is_expired(self.timeout_secs) {
                let new_session = Session::new(
                    local_device_id.to_string(),
                    remote_device_id.to_string(),
                    transport,
                );
                *session = new_session.clone();
                return new_session;
            }
            session.touch();
            return session.clone();
        }
        let session = Session::new(
            local_device_id.to_string(),
            remote_device_id.to_string(),
            transport,
        );
        sessions.insert(remote_device_id.to_string(), session.clone());
        session
    }

    pub async fn migrate_session(
        &self,
        remote_device_id: &str,
        new_transport: TransportType,
    ) -> CotResult<Session> {
        let mut sessions = self.sessions.write().await;
        match sessions.get_mut(remote_device_id) {
            Some(session) => {
                session.migrate_transport(new_transport);
                Ok(session.clone())
            }
            None => Err(CotError::SessionInvalid(format!(
                "No session for {}",
                remote_device_id
            ))),
        }
    }

    pub async fn get_session(&self, remote_device_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(remote_device_id).cloned()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, s| !s.is_expired(self.timeout_secs));
        before - sessions.len()
    }

    pub async fn active_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count()
    }

    /// Emergency Revocation (Sprint 7): terminate every session whose remote
    /// peer is `remote_device_id`. Returns the number of sessions dropped.
    /// Used when a critical revocation for that peer is applied — active
    /// breaches must be cut instantly, not on the next expiry sweep.
    pub async fn terminate_peer(&self, remote_device_id: &str) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|key, _| key != remote_device_id);
        before - sessions.len()
    }

    pub async fn total_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    pub async fn summary(&self) -> String {
        let sessions = self.sessions.read().await;
        let active = sessions
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count();
        let suspended = sessions
            .values()
            .filter(|s| s.state == SessionState::Suspended)
            .count();
        format!(
            "Sessions: {} total, {} active, {} suspended",
            sessions.len(),
            active,
            suspended
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_session() {
        let mgr = SessionManager::new();
        let session = mgr
            .get_or_create("local_id", "remote_id", TransportType::Ethernet)
            .await;
        assert_eq!(session.local_device_id, "local_id");
        assert_eq!(session.current_transport, TransportType::Ethernet);
        assert_eq!(session.state, SessionState::Active);
        assert_eq!(session.migration_count, 0);
    }

    #[tokio::test]
    async fn test_get_existing_session() {
        let mgr = SessionManager::new();
        let s1 = mgr
            .get_or_create("local", "remote", TransportType::Ethernet)
            .await;
        let s2 = mgr
            .get_or_create("local", "remote", TransportType::WiFi)
            .await;
        assert_eq!(s1.session_id, s2.session_id);
    }

    #[tokio::test]
    async fn test_migrate_transport() {
        let mgr = SessionManager::new();
        mgr.get_or_create("local", "remote", TransportType::Ethernet)
            .await;
        let migrated = mgr
            .migrate_session("remote", TransportType::WiFi)
            .await
            .unwrap();
        assert_eq!(migrated.current_transport, TransportType::WiFi);
        assert_eq!(migrated.migration_count, 1);
        assert_eq!(migrated.transport_history.len(), 2);
    }

    #[tokio::test]
    async fn test_active_count() {
        let mgr = SessionManager::new();
        mgr.get_or_create("local", "remote_a", TransportType::Ethernet)
            .await;
        mgr.get_or_create("local", "remote_b", TransportType::WiFi)
            .await;
        assert_eq!(mgr.active_count().await, 2);
    }

    #[tokio::test]
    async fn test_terminate_peer() {
        let mgr = SessionManager::new();
        mgr.get_or_create("local", "remote_a", TransportType::Ethernet)
            .await;
        mgr.get_or_create("local", "remote_b", TransportType::WiFi)
            .await;
        assert_eq!(mgr.terminate_peer("remote_a").await, 1);
        assert!(mgr.get_session("remote_a").await.is_none());
        assert_eq!(mgr.total_count().await, 1);
    }

    #[tokio::test]
    async fn test_session_survives_transport_change() {
        let mgr = SessionManager::new();
        let s1 = mgr
            .get_or_create("local", "remote", TransportType::Ethernet)
            .await;
        let migrated = mgr
            .migrate_session("remote", TransportType::WiFi)
            .await
            .unwrap();
        let s2 = mgr
            .get_or_create("local", "remote", TransportType::WiFi)
            .await;

        assert_eq!(s1.session_id, migrated.session_id);
        assert_eq!(migrated.session_id, s2.session_id);
        assert_eq!(s2.current_transport, TransportType::WiFi);
    }
}
