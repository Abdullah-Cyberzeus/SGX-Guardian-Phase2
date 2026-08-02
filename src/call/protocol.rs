//! Versioned, signed call-control envelope shared by signaling messages.

use crate::call::error::{CallError, CallResult};
use crate::key_manager::KeyManager;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

pub const CALL_PROTOCOL_VERSION: u16 = 1;
pub const MAX_SIGNAL_PAYLOAD_BYTES: usize = 48 * 1024;
pub const MAX_SIGNAL_AGE_SECS: i64 = 300;

#[derive(Default)]
pub struct ReplayProtector {
    state: Mutex<ReplayState>,
}

#[derive(Default)]
struct ReplayState {
    highest_sequence: HashMap<(String, String), u64>,
    seen_nonces: HashSet<(String, String, String)>,
}

impl ReplayProtector {
    /// Atomically accept a new sender/session sequence and nonce. Exact or
    /// older messages fail closed; retries must be handled above this layer.
    pub async fn check_and_record(&self, envelope: &SignalingEnvelope) -> CallResult<()> {
        let sender_session = (
            envelope.sender_device_id.clone(),
            envelope.session_id.clone(),
        );
        let nonce_key = (
            envelope.sender_device_id.clone(),
            envelope.session_id.clone(),
            envelope.nonce.clone(),
        );
        let mut state = self.state.lock().await;
        if state.seen_nonces.contains(&nonce_key)
            || state
                .highest_sequence
                .get(&sender_session)
                .is_some_and(|highest| envelope.sequence <= *highest)
        {
            return Err(CallError::NonceReused {
                nonce: envelope.nonce.clone(),
            });
        }
        state.seen_nonces.insert(nonce_key);
        state
            .highest_sequence
            .insert(sender_session, envelope.sequence);
        Ok(())
    }

    pub async fn forget_session(&self, session_id: &str) {
        let mut state = self.state.lock().await;
        state
            .highest_sequence
            .retain(|(_, stored_session), _| stored_session != session_id);
        state
            .seen_nonces
            .retain(|(_, stored_session, _)| stored_session != session_id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    Offer,
    Answer,
    SdpOffer,
    SdpAnswer,
    IceCandidate,
    IceComplete,
    MediaReady,
    Hangup,
    Heartbeat,
    Error,
    GroupControl,
}

impl SignalKind {
    pub fn is_browser_signal(self) -> bool {
        matches!(
            self,
            SignalKind::SdpOffer
                | SignalKind::SdpAnswer
                | SignalKind::IceCandidate
                | SignalKind::IceComplete
                | SignalKind::MediaReady
                | SignalKind::Hangup
                | SignalKind::Error
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalingEnvelope {
    pub version: u16,
    #[serde(rename = "type")]
    pub kind: SignalKind,
    pub session_id: String,
    pub sender_device_id: String,
    pub sender_virtual_id: String,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub payload: Value,
    pub signature: String,
}

impl SignalingEnvelope {
    pub fn new(
        kind: SignalKind,
        session_id: impl Into<String>,
        sender_device_id: impl Into<String>,
        sender_virtual_id: impl Into<String>,
        sequence: u64,
        nonce: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            version: CALL_PROTOCOL_VERSION,
            kind,
            session_id: session_id.into(),
            sender_device_id: sender_device_id.into(),
            sender_virtual_id: sender_virtual_id.into(),
            sequence,
            timestamp: Utc::now(),
            nonce: nonce.into(),
            payload,
            signature: String::new(),
        }
    }

    pub fn sign(mut self, signer: &KeyManager) -> CallResult<Self> {
        self.validate_shape()?;
        let signature = signer.sign(&self.canonical_bytes()?).map_err(|error| {
            CallError::KeyManagerError(format!("Failed to sign call envelope: {}", error))
        })?;
        self.signature = hex::encode(signature);
        Ok(self)
    }

    pub fn verify(&self, trusted_public_key_point: &[u8]) -> CallResult<()> {
        self.validate_shape()?;
        let signature =
            hex::decode(&self.signature).map_err(|_| CallError::SignatureVerificationFailed)?;
        KeyManager::verify_signature(
            &self.canonical_bytes()?,
            &signature,
            trusted_public_key_point,
        )
        .map_err(|_| CallError::SignatureVerificationFailed)
    }

    pub fn validate_freshness(&self, now: DateTime<Utc>) -> CallResult<()> {
        let age_ms = (now - self.timestamp).num_milliseconds().unsigned_abs();
        if age_ms > (MAX_SIGNAL_AGE_SECS as u64 * 1_000) {
            return Err(CallError::InvalidOffer {
                reason: "Signaling timestamp is outside the accepted window".into(),
            });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> CallResult<Vec<u8>> {
        let canonical_payload = canonical_json(&self.payload)?;
        let mut output = Vec::with_capacity(canonical_payload.len() + 256);
        append_field(&mut output, self.version.to_string().as_bytes());
        append_field(&mut output, signal_kind_name(self.kind).as_bytes());
        append_field(&mut output, self.session_id.as_bytes());
        append_field(&mut output, self.sender_device_id.as_bytes());
        append_field(&mut output, self.sender_virtual_id.as_bytes());
        append_field(&mut output, self.sequence.to_string().as_bytes());
        append_field(
            &mut output,
            self.timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
                .as_bytes(),
        );
        append_field(&mut output, self.nonce.as_bytes());
        append_field(&mut output, &canonical_payload);
        Ok(output)
    }

    fn validate_shape(&self) -> CallResult<()> {
        if self.version != CALL_PROTOCOL_VERSION {
            return Err(CallError::SerializationError(format!(
                "Unsupported call protocol version {}",
                self.version
            )));
        }
        if self.session_id.trim().is_empty()
            || self.sender_device_id.trim().is_empty()
            || self.sender_virtual_id.trim().is_empty()
            || self.nonce.trim().is_empty()
            || self.sequence == 0
        {
            return Err(CallError::SerializationError(
                "Call envelope contains invalid required fields".into(),
            ));
        }
        let payload_len = serde_json::to_vec(&self.payload)
            .map_err(|e| CallError::SerializationError(e.to_string()))?
            .len();
        if payload_len > MAX_SIGNAL_PAYLOAD_BYTES {
            return Err(CallError::SerializationError(
                "Call envelope payload exceeds 48 KiB".into(),
            ));
        }
        Ok(())
    }
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&(field.len() as u64).to_be_bytes());
    output.extend_from_slice(field);
}

fn signal_kind_name(kind: SignalKind) -> &'static str {
    match kind {
        SignalKind::Offer => "offer",
        SignalKind::Answer => "answer",
        SignalKind::SdpOffer => "sdp_offer",
        SignalKind::SdpAnswer => "sdp_answer",
        SignalKind::IceCandidate => "ice_candidate",
        SignalKind::IceComplete => "ice_complete",
        SignalKind::MediaReady => "media_ready",
        SignalKind::Hangup => "hangup",
        SignalKind::Heartbeat => "heartbeat",
        SignalKind::Error => "error",
        SignalKind::GroupControl => "group_control",
    }
}

fn canonical_json(value: &Value) -> CallResult<Vec<u8>> {
    fn write(value: &Value, output: &mut String) -> Result<(), serde_json::Error> {
        match value {
            Value::Object(map) => {
                output.push('{');
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key)?);
                    output.push(':');
                    write(&map[key], output)?;
                }
                output.push('}');
            }
            Value::Array(values) => {
                output.push('[');
                for (index, item) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write(item, output)?;
                }
                output.push(']');
            }
            primitive => output.push_str(&serde_json::to_string(primitive)?),
        }
        Ok(())
    }

    let mut output = String::new();
    write(value, &mut output).map_err(|e| CallError::SerializationError(e.to_string()))?;
    Ok(output.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;
    use tempfile::tempdir;

    fn signer(name: &str) -> (tempfile::TempDir, KeyManager) {
        let temp = tempdir().unwrap();
        let signer =
            KeyManager::load_or_generate(temp.path().join(name).to_str().unwrap()).unwrap();
        (temp, signer)
    }

    #[test]
    fn canonical_payload_ignores_object_key_order() {
        let a = SignalingEnvelope::new(
            SignalKind::Offer,
            "session",
            "device",
            "virtual",
            1,
            "nonce",
            json!({"z": 2, "a": {"y": 1, "b": 0}}),
        );
        let b = SignalingEnvelope {
            payload: serde_json::from_str(r#"{"a":{"b":0,"y":1},"z":2}"#).unwrap(),
            timestamp: a.timestamp,
            ..a.clone()
        };
        assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
    }

    #[test]
    fn signature_rejects_tampering_and_wrong_key() {
        let (_ta, a) = signer("a.pk8");
        let (_tb, b) = signer("b.pk8");
        let mut message = SignalingEnvelope::new(
            SignalKind::IceCandidate,
            "session",
            "device",
            "virtual",
            1,
            "nonce",
            json!({"candidate": "candidate:1"}),
        )
        .sign(&a)
        .unwrap();
        assert!(message.verify(&a.pubkey_der().unwrap()).is_ok());
        assert!(message.verify(&b.pubkey_der().unwrap()).is_err());
        message.payload["candidate"] = json!("tampered");
        assert!(message.verify(&a.pubkey_der().unwrap()).is_err());
    }

    #[test]
    fn stale_and_future_messages_fail() {
        let mut message = SignalingEnvelope::new(
            SignalKind::Heartbeat,
            "session",
            "device",
            "virtual",
            1,
            "nonce",
            json!({}),
        );
        message.timestamp = Utc::now() - Duration::seconds(MAX_SIGNAL_AGE_SECS + 1);
        assert!(message.validate_freshness(Utc::now()).is_err());
        message.timestamp = Utc::now() + Duration::seconds(MAX_SIGNAL_AGE_SECS + 1);
        assert!(message.validate_freshness(Utc::now()).is_err());
    }

    #[tokio::test]
    async fn replay_and_out_of_order_sequences_fail() {
        let replay = ReplayProtector::default();
        let first = SignalingEnvelope::new(
            SignalKind::Heartbeat,
            "session",
            "device",
            "virtual",
            2,
            "nonce-2",
            json!({}),
        );
        replay.check_and_record(&first).await.unwrap();
        assert!(replay.check_and_record(&first).await.is_err());

        let older = SignalingEnvelope::new(
            SignalKind::Heartbeat,
            "session",
            "device",
            "virtual",
            1,
            "nonce-1",
            json!({}),
        );
        assert!(replay.check_and_record(&older).await.is_err());

        replay.forget_session("session").await;
        assert!(replay.check_and_record(&older).await.is_ok());
    }
}
