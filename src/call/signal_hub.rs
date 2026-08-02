//! Short-lived browser WebRTC signaling queues.

use crate::call::error::{CallError, CallResult};
use crate::call::protocol::{SignalKind, SignalingEnvelope};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{broadcast, RwLock};

const MAX_SIGNALS_PER_SESSION: usize = 256;
const SIGNAL_TTL_MINUTES: i64 = 5;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BrowserSignal {
    pub id: u64,
    pub session_id: String,
    #[serde(rename = "type")]
    pub kind: SignalKind,
    pub sender_device_id: String,
    pub payload: Value,
    pub received_at: DateTime<Utc>,
}

pub struct CallSignalHub {
    next_id: AtomicU64,
    queues: RwLock<HashMap<String, VecDeque<BrowserSignal>>>,
    quality: RwLock<HashMap<String, QualityReport>>,
    live: broadcast::Sender<BrowserSignal>,
}

impl Default for CallSignalHub {
    fn default() -> Self {
        let (live, _) = broadcast::channel(512);
        Self {
            next_id: AtomicU64::new(0),
            queues: RwLock::new(HashMap::new()),
            quality: RwLock::new(HashMap::new()),
            live,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityReport {
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default)]
    pub jitter_ms: Option<u32>,
    #[serde(default)]
    pub packet_loss_percent: Option<f32>,
    #[serde(default)]
    pub codec: Option<String>,
    #[serde(skip_deserializing, default = "Utc::now")]
    pub observed_at: DateTime<Utc>,
}

impl CallSignalHub {
    pub async fn push_remote(&self, envelope: &SignalingEnvelope) -> CallResult<BrowserSignal> {
        if !envelope.kind.is_browser_signal() {
            return Err(CallError::InvalidOffer {
                reason: "Message is not a browser media signal".into(),
            });
        }
        let signal = BrowserSignal {
            id: self.next_id.fetch_add(1, Ordering::Relaxed) + 1,
            session_id: envelope.session_id.clone(),
            kind: envelope.kind,
            sender_device_id: envelope.sender_device_id.clone(),
            payload: envelope.payload.clone(),
            received_at: Utc::now(),
        };
        let mut queues = self.queues.write().await;
        let queue = queues.entry(envelope.session_id.clone()).or_default();
        let cutoff = Utc::now() - Duration::minutes(SIGNAL_TTL_MINUTES);
        queue.retain(|existing| existing.received_at >= cutoff);
        while queue.len() >= MAX_SIGNALS_PER_SESSION {
            queue.pop_front();
        }
        queue.push_back(signal.clone());
        let _ = self.live.send(signal.clone());
        Ok(signal)
    }

    pub async fn list_after(&self, session_id: &str, after: u64) -> Vec<BrowserSignal> {
        self.queues
            .read()
            .await
            .get(session_id)
            .map(|queue| {
                queue
                    .iter()
                    .filter(|signal| signal.id > after)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn clear(&self, session_id: &str) {
        self.queues.write().await.remove(session_id);
        self.quality.write().await.remove(session_id);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BrowserSignal> {
        self.live.subscribe()
    }

    pub async fn record_quality(
        &self,
        session_id: &str,
        mut report: QualityReport,
    ) -> CallResult<()> {
        if report.rtt_ms.is_some_and(|value| value > 120_000)
            || report.jitter_ms.is_some_and(|value| value > 60_000)
            || report
                .packet_loss_percent
                .is_some_and(|value| !value.is_finite() || !(0.0..=100.0).contains(&value))
            || report.codec.as_ref().is_some_and(|value| value.len() > 64)
        {
            return Err(CallError::InvalidOffer {
                reason: "Media quality report contains out-of-range values".into(),
            });
        }
        report.observed_at = Utc::now();
        self.quality
            .write()
            .await
            .insert(session_id.to_string(), report);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn queues_only_new_remote_signals() {
        let hub = CallSignalHub::default();
        let first = SignalingEnvelope::new(
            SignalKind::SdpOffer,
            "session",
            "device-a",
            "virtual-a",
            2,
            "nonce-2",
            json!({"type": "offer", "sdp": "v=0"}),
        );
        let first = hub.push_remote(&first).await.unwrap();
        let second = SignalingEnvelope::new(
            SignalKind::IceCandidate,
            "session",
            "device-a",
            "virtual-a",
            3,
            "nonce-3",
            json!({"candidate": "candidate:1"}),
        );
        let second = hub.push_remote(&second).await.unwrap();
        assert_eq!(hub.list_after("session", first.id).await, vec![second]);
        hub.clear("session").await;
        assert!(hub.list_after("session", 0).await.is_empty());
    }

    #[tokio::test]
    async fn rejects_impossible_quality_values() {
        let hub = CallSignalHub::default();
        let invalid = QualityReport {
            rtt_ms: Some(10),
            jitter_ms: Some(5),
            packet_loss_percent: Some(101.0),
            codec: Some("audio/opus".into()),
            observed_at: Utc::now(),
        };
        assert!(hub.record_quality("session", invalid).await.is_err());
    }
}
