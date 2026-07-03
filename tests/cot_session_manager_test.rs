// tests/cot_session_manager_test.rs
// Integration tests for uncovered branches of src/cot/session_manager.rs

use sgx_guardian_client::cot::session_manager::{Session, SessionManager, SessionState};
use sgx_guardian_client::cot::types::TransportType;

// ── Session struct methods ────────────────────────────────────────────────────

#[test]
fn test_session_new_fields() {
    let session = Session::new("local".into(), "remote".into(), TransportType::WiFi);
    assert_eq!(session.local_device_id, "local");
    assert_eq!(session.remote_device_id, "remote");
    assert_eq!(session.current_transport, TransportType::WiFi);
    assert_eq!(session.state, SessionState::Active);
    assert_eq!(session.migration_count, 0);
    assert_eq!(session.transport_history.len(), 1);
}

#[test]
fn test_session_suspend_and_resume() {
    let mut session = Session::new("local".into(), "remote".into(), TransportType::Ethernet);
    session.suspend();
    assert_eq!(session.state, SessionState::Suspended);

    session.resume(TransportType::WiFi);
    assert_eq!(session.state, SessionState::Active);
    assert_eq!(session.current_transport, TransportType::WiFi);
    assert_eq!(session.migration_count, 1);
}

#[test]
fn test_session_migrate_transport_increments_count() {
    let mut session = Session::new("local".into(), "remote".into(), TransportType::Ethernet);
    session.migrate_transport(TransportType::Cellular);
    assert_eq!(session.migration_count, 1);
    assert_eq!(session.current_transport, TransportType::Cellular);
    assert_eq!(session.transport_history.len(), 2);

    session.migrate_transport(TransportType::Satellite);
    assert_eq!(session.migration_count, 2);
    assert_eq!(session.transport_history.len(), 3);
}

#[test]
fn test_session_is_not_expired_immediately() {
    let session = Session::new("local".into(), "remote".into(), TransportType::Ethernet);
    // 300 second timeout — a brand-new session should not be expired
    assert!(!session.is_expired(300));
}

#[test]
fn test_session_touch_updates_activity() {
    let mut session = Session::new("local".into(), "remote".into(), TransportType::Ethernet);
    let before = session.last_activity;
    std::thread::sleep(std::time::Duration::from_millis(10));
    session.touch();
    assert!(session.last_activity >= before);
}

// ── SessionManager ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_session_manager_with_timeout() {
    let mgr = SessionManager::with_timeout(60);
    let s = mgr
        .get_or_create("local", "remote", TransportType::Ethernet)
        .await;
    assert!(!s.is_expired(60));
}

#[tokio::test]
async fn test_session_manager_get_session_none() {
    let mgr = SessionManager::new();
    let result = mgr.get_session("nobody").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_session_manager_get_session_some() {
    let mgr = SessionManager::new();
    mgr.get_or_create("local", "remote", TransportType::Ethernet)
        .await;
    let result = mgr.get_session("remote").await;
    assert!(result.is_some());
}

#[tokio::test]
async fn test_session_manager_migrate_missing_peer() {
    let mgr = SessionManager::new();
    let result = mgr.migrate_session("nonexistent", TransportType::WiFi).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_session_manager_cleanup_expired_removes_none_if_fresh() {
    let mgr = SessionManager::with_timeout(300);
    mgr.get_or_create("local", "peer1", TransportType::Ethernet)
        .await;
    mgr.get_or_create("local", "peer2", TransportType::WiFi)
        .await;
    // Both sessions are fresh — none should be cleaned up
    let removed = mgr.cleanup_expired().await;
    assert_eq!(removed, 0);
    assert_eq!(mgr.total_count().await, 2);
}

#[tokio::test]
async fn test_session_manager_cleanup_expired_with_negative_timeout() {
    // Use -1 second timeout — any session is immediately considered expired
    // (elapsed >= 0 which is always > -1)
    let mgr = SessionManager::with_timeout(-1);
    mgr.get_or_create("local", "peer1", TransportType::Ethernet)
        .await;
    mgr.get_or_create("local", "peer2", TransportType::WiFi)
        .await;

    let removed = mgr.cleanup_expired().await;
    assert_eq!(removed, 2);
    assert_eq!(mgr.total_count().await, 0);
}

#[tokio::test]
async fn test_session_manager_summary_format() {
    let mgr = SessionManager::new();
    mgr.get_or_create("local", "remote_a", TransportType::Ethernet)
        .await;
    mgr.get_or_create("local", "remote_b", TransportType::WiFi)
        .await;

    let summary = mgr.summary().await;
    assert!(summary.contains("Sessions:"));
    assert!(summary.contains("total"));
    assert!(summary.contains("active"));
    assert!(summary.contains("suspended"));
}

#[tokio::test]
async fn test_session_manager_active_count_after_suspend() {
    let mgr = SessionManager::new();
    mgr.get_or_create("local", "peer1", TransportType::Ethernet)
        .await;
    mgr.get_or_create("local", "peer2", TransportType::WiFi)
        .await;

    // Both active
    assert_eq!(mgr.active_count().await, 2);
}

#[tokio::test]
async fn test_session_manager_total_count() {
    let mgr = SessionManager::new();
    assert_eq!(mgr.total_count().await, 0);
    mgr.get_or_create("local", "peer1", TransportType::Ethernet)
        .await;
    assert_eq!(mgr.total_count().await, 1);
    mgr.get_or_create("local", "peer2", TransportType::Bluetooth)
        .await;
    assert_eq!(mgr.total_count().await, 2);
}

#[tokio::test]
async fn test_session_manager_default_impl() {
    let mgr = SessionManager::default();
    assert_eq!(mgr.total_count().await, 0);
}
