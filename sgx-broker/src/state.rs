//! Shared application state for the VPS enrollment broker.

use crate::models::EnrollmentResponse;
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

/// Shared state accessible from all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    /// Active WebSocket senders from connected CA nodes, keyed by circle_id.
    /// When Node A connects its persistent WS, it registers a sender here.
    pub ca_senders: DashMap<String, mpsc::Sender<String>>,

    /// In-flight enrollment requests waiting for Node A's signed response.
    /// Keyed by request_id (UUID). The oneshot sender is resolved when
    /// Node A sends back an ENROLLMENT_RESPONSE with the matching request_id.
    pub pending: DashMap<String, oneshot::Sender<EnrollmentResponse>>,

    /// Whether at least one CA node is connected via WebSocket.
    pub ca_connected: AtomicBool,

    /// Server start time for uptime reporting.
    pub start_time: Instant,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                ca_senders: DashMap::new(),
                pending: DashMap::new(),
                ca_connected: AtomicBool::new(false),
                start_time: Instant::now(),
            }),
        }
    }

    // ── CA sender management ──────────────────────────────────────

    /// Register a WebSocket sender for a circle's CA node.
    pub fn register_ca(&self, circle_id: &str, sender: mpsc::Sender<String>) {
        self.inner
            .ca_senders
            .insert(circle_id.to_string(), sender);
        self.inner.ca_connected.store(true, Ordering::SeqCst);
        tracing::info!("CA bridge registered for circle: {}", circle_id);
    }

    /// Remove a CA sender when the WebSocket disconnects.
    pub fn unregister_ca(&self, circle_id: &str) {
        self.inner.ca_senders.remove(circle_id);
        let any_left = !self.inner.ca_senders.is_empty();
        self.inner.ca_connected.store(any_left, Ordering::SeqCst);
        tracing::info!("CA bridge unregistered for circle: {}", circle_id);
    }

    /// Get a clone of the sender for a specific circle (if connected).
    pub fn get_ca_sender(&self, circle_id: &str) -> Option<mpsc::Sender<String>> {
        self.inner.ca_senders.get(circle_id).map(|s| s.clone())
    }

    // ── Pending request management ────────────────────────────────

    /// Insert a pending enrollment request. Returns the oneshot receiver
    /// that will be resolved when Node A responds.
    pub fn insert_pending(
        &self,
        request_id: &str,
        sender: oneshot::Sender<EnrollmentResponse>,
    ) {
        self.inner
            .pending
            .insert(request_id.to_string(), sender);
    }

    /// Resolve a pending request with Node A's response.
    /// Returns true if the request was found and resolved.
    pub fn resolve_pending(&self, request_id: &str, response: EnrollmentResponse) -> bool {
        if let Some((_, sender)) = self.inner.pending.remove(request_id) {
            let _ = sender.send(response);
            true
        } else {
            tracing::warn!(
                "No pending request found for request_id: {}",
                request_id
            );
            false
        }
    }

    /// Remove a pending request without resolving it (e.g. on timeout).
    pub fn remove_pending(&self, request_id: &str) {
        self.inner.pending.remove(request_id);
    }

    // ── Health ─────────────────────────────────────────────────────

    pub fn is_ca_connected(&self) -> bool {
        self.inner.ca_connected.load(Ordering::SeqCst)
    }

    pub fn uptime_secs(&self) -> u64 {
        self.inner.start_time.elapsed().as_secs()
    }
}
