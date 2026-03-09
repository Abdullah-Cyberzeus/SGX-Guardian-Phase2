// src/cot/transport_trait.rs
// ============================================================
// Transport Abstraction Trait
//
// Defines the contract all transport implementations must
// satisfy. The CoT router dispatches through this trait,
// making it completely transport-agnostic.
// ============================================================

use crate::cot::types::{CotResult, TransportPriority, TransportType};
use async_trait::async_trait;

/// A message that flows through the transport layer.
#[derive(Debug, Clone)]
pub struct TransportMessage {
    /// The sender's device_id (identity fingerprint)
    pub from_device_id: String,
    /// The recipient's device_id
    pub to_device_id: String,
    /// Target address (transport-specific format)
    pub target_address: String,
    /// Raw payload bytes (encrypted at a higher layer)
    pub payload: Vec<u8>,
    /// Message ID for deduplication / acknowledgment
    pub message_id: String,
}

impl TransportMessage {
    pub fn new(
        from_device_id: String,
        to_device_id: String,
        target_address: String,
        payload: Vec<u8>,
    ) -> Self {
        let message_id = uuid::Uuid::new_v4().to_string();
        Self {
            from_device_id,
            to_device_id,
            target_address,
            payload,
            message_id,
        }
    }
}

/// Health status of a transport.
#[derive(Debug, Clone)]
pub struct TransportHealth {
    pub is_healthy: bool,
    pub latency_ms: u64,
    pub bandwidth_kbps: u64,
    pub status_message: String,
}

impl TransportHealth {
    pub fn healthy(latency_ms: u64, bandwidth_kbps: u64) -> Self {
        Self {
            is_healthy: true,
            latency_ms,
            bandwidth_kbps,
            status_message: "OK".into(),
        }
    }

    pub fn unhealthy(reason: &str) -> Self {
        Self {
            is_healthy: false,
            latency_ms: 0,
            bandwidth_kbps: 0,
            status_message: reason.to_string(),
        }
    }
}

/// The core transport trait — THE CONTRACT.
/// Every transport (Ethernet, WiFi, etc.) implements this.
#[async_trait]
pub trait Transport: Send + Sync {
    fn transport_type(&self) -> TransportType;
    fn priority(&self) -> TransportPriority;
    async fn is_available(&self) -> bool;
    async fn send(&self, message: &TransportMessage) -> CotResult<()>;
    async fn health_check(&self) -> TransportHealth;
    fn display_name(&self) -> String;
}
