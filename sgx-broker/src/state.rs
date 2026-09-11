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
        self.inner.ca_senders.insert(circle_id.to_string(), sender);
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
    pub fn insert_pending(&self, request_id: &str, sender: oneshot::Sender<EnrollmentResponse>) {
        self.inner.pending.insert(request_id.to_string(), sender);
    }

    /// Resolve a pending request with Node A's response.
    /// Returns true if the request was found and resolved.
    pub fn resolve_pending(&self, request_id: &str, response: EnrollmentResponse) -> bool {
        if let Some((_, sender)) = self.inner.pending.remove(request_id) {
            let _ = sender.send(response);
            true
        } else {
            tracing::warn!("No pending request found for request_id: {}", request_id);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: &str) -> EnrollmentResponse {
        EnrollmentResponse {
            status: status.into(),
            overlay_ip: String::new(),
            cert: String::new(),
            key: String::new(),
            ca_cert: String::new(),
            config: String::new(),
            member_vc_json: String::new(),
            status_list_json: String::new(),
            did_doc_aggregate_json: String::new(),
            signing_pubkey_der_b64: String::new(),
            signed_policy_b64: String::new(),
            message: String::new(),
        }
    }

    #[test]
    fn ca_registration_is_scoped_to_its_circle() {
        let state = AppState::new();
        let (alpha_tx, _alpha_rx) = mpsc::channel(1);
        let (beta_tx, _beta_rx) = mpsc::channel(1);

        state.register_ca("alpha", alpha_tx);
        state.register_ca("beta", beta_tx);
        assert!(state.is_ca_connected());
        assert!(state.get_ca_sender("alpha").is_some());
        assert!(state.get_ca_sender("beta").is_some());
        assert!(state.get_ca_sender("unknown").is_none());

        state.unregister_ca("alpha");
        assert!(state.is_ca_connected());
        assert!(state.get_ca_sender("alpha").is_none());
        assert!(state.get_ca_sender("beta").is_some());

        state.unregister_ca("beta");
        assert!(!state.is_ca_connected());
    }

    #[tokio::test]
    async fn pending_response_is_delivered_once_and_removed() {
        let state = AppState::new();
        let (tx, rx) = oneshot::channel();
        state.insert_pending("request-1", tx);

        assert!(state.resolve_pending("request-1", response("APPROVED")));
        assert_eq!(rx.await.unwrap().status, "APPROVED");
        assert!(!state.resolve_pending("request-1", response("ERROR")));
    }

    #[tokio::test]
    async fn pending_requests_are_correlated_even_when_responses_arrive_out_of_order() {
        let state = AppState::new();
        let (first_tx, first_rx) = oneshot::channel();
        let (second_tx, second_rx) = oneshot::channel();
        state.insert_pending("first", first_tx);
        state.insert_pending("second", second_tx);

        assert!(state.resolve_pending("second", response("SECOND")));
        assert!(state.resolve_pending("first", response("FIRST")));
        assert_eq!(first_rx.await.unwrap().status, "FIRST");
        assert_eq!(second_rx.await.unwrap().status, "SECOND");
    }

    #[test]
    fn removing_pending_request_prevents_late_response_delivery() {
        let state = AppState::new();
        let (tx, _rx) = oneshot::channel();
        state.insert_pending("request-2", tx);
        state.remove_pending("request-2");
        assert!(!state.resolve_pending("request-2", response("APPROVED")));
    }
}
