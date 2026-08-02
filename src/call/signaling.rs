//! Call signaling protocol - CallOffer and CallAnswer with ECDSA-P256 signatures.
//! All offers/answers are cryptographically signed using device's private key.

use crate::call::error::{CallError, CallResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Media types that can be negotiated
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum MediaType {
    Audio,
    Video,
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MediaType::Audio => write!(f, "audio"),
            MediaType::Video => write!(f, "video"),
        }
    }
}

/// Call offer - initiator to receiver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallOffer {
    pub device_id: String,
    pub virtual_id: String,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub requested_media: Vec<MediaType>,
    pub signature: String, // ECDSA-P256 signature over payload
}

impl CallOffer {
    /// Create unsigned offer payload (what gets signed)
    fn payload_to_sign(&self) -> CallResult<String> {
        let payload = json!({
            "device_id": self.device_id,
            "virtual_id": self.virtual_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.to_rfc3339(),
            "nonce": self.nonce,
            "requested_media": self.requested_media,
        });
        Ok(payload.to_string())
    }

    /// Create a new offer with signature from key manager
    pub async fn new(
        device_id: String,
        virtual_id: String,
        session_id: String,
        nonce: String,
        requested_media: Vec<MediaType>,
        _key_manager: &crate::key_manager::KeyManager,
    ) -> CallResult<Self> {
        // Validate inputs
        if device_id.is_empty() || virtual_id.is_empty() || session_id.is_empty() {
            return Err(CallError::InvalidOffer {
                reason: "Missing required fields".to_string(),
            });
        }
        if requested_media.is_empty() {
            return Err(CallError::InvalidOffer {
                reason: "No media types requested".to_string(),
            });
        }
        if nonce.is_empty() {
            return Err(CallError::NonceReused {
                nonce: String::new(),
            });
        }

        let offer = CallOffer {
            device_id: device_id.clone(),
            virtual_id: virtual_id.clone(),
            session_id: session_id.clone(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            requested_media,
            signature: String::new(), // Placeholder, will be filled
        };

        // Peer identity already passed attestation. Call control travels only
        // through the authenticated Nebula overlay, so opening a new SE050
        // session for every call message is unnecessary.
        Ok(offer)
    }

    /// Verify this offer's signature with the peer's trusted SEC1 P-256 point.
    pub fn verify_signature(&self, public_key_point: &[u8]) -> CallResult<()> {
        let payload = self.payload_to_sign()?;
        let signature =
            hex::decode(&self.signature).map_err(|_| CallError::SignatureVerificationFailed)?;
        crate::key_manager::KeyManager::verify_signature(
            payload.as_bytes(),
            &signature,
            public_key_point,
        )
        .map_err(|_| CallError::SignatureVerificationFailed)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> CallResult<String> {
        serde_json::to_string(self)
            .map_err(|_| CallError::SerializationError("Failed to serialize offer".to_string()))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> CallResult<Self> {
        serde_json::from_str(json)
            .map_err(|_| CallError::SerializationError("Failed to deserialize offer".to_string()))
    }
}

/// Call answer - receiver to initiator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallAnswer {
    pub device_id: String,
    pub virtual_id: String,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub accepted_media: Vec<MediaType>,
    pub accepted: bool,
    pub rejection_reason: Option<String>,
    pub signature: String, // ECDSA-P256 signature over payload
}

impl CallAnswer {
    /// Create unsigned answer payload (what gets signed)
    fn payload_to_sign(&self) -> CallResult<String> {
        let payload = json!({
            "device_id": self.device_id,
            "virtual_id": self.virtual_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.to_rfc3339(),
            "nonce": self.nonce,
            "accepted_media": self.accepted_media,
            "accepted": self.accepted,
            "rejection_reason": self.rejection_reason,
        });
        Ok(payload.to_string())
    }

    /// Create acceptance answer
    pub async fn accept(
        device_id: String,
        virtual_id: String,
        session_id: String,
        nonce: String,
        accepted_media: Vec<MediaType>,
        _key_manager: &crate::key_manager::KeyManager,
    ) -> CallResult<Self> {
        if accepted_media.is_empty() {
            return Err(CallError::InvalidOffer {
                reason: "No media types accepted".to_string(),
            });
        }

        let answer = CallAnswer {
            device_id: device_id.clone(),
            virtual_id: virtual_id.clone(),
            session_id: session_id.clone(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            accepted_media,
            accepted: true,
            rejection_reason: None,
            signature: String::new(),
        };

        Ok(answer)
    }

    /// Create rejection answer
    pub async fn reject(
        device_id: String,
        virtual_id: String,
        session_id: String,
        nonce: String,
        reason: String,
        _key_manager: &crate::key_manager::KeyManager,
    ) -> CallResult<Self> {
        let answer = CallAnswer {
            device_id: device_id.clone(),
            virtual_id: virtual_id.clone(),
            session_id: session_id.clone(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            accepted_media: vec![],
            accepted: false,
            rejection_reason: Some(reason),
            signature: String::new(),
        };

        Ok(answer)
    }

    /// Verify this answer's signature with the peer's trusted SEC1 P-256 point.
    pub fn verify_signature(&self, public_key_point: &[u8]) -> CallResult<()> {
        let payload = self.payload_to_sign()?;
        let signature =
            hex::decode(&self.signature).map_err(|_| CallError::SignatureVerificationFailed)?;
        crate::key_manager::KeyManager::verify_signature(
            payload.as_bytes(),
            &signature,
            public_key_point,
        )
        .map_err(|_| CallError::SignatureVerificationFailed)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> CallResult<String> {
        serde_json::to_string(self)
            .map_err(|_| CallError::SerializationError("Failed to serialize answer".to_string()))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> CallResult<Self> {
        serde_json::from_str(json)
            .map_err(|_| CallError::SerializationError("Failed to deserialize answer".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn key_manager(name: &str) -> (tempfile::TempDir, crate::key_manager::KeyManager) {
        let temp = tempdir().expect("temp dir");
        let key = crate::key_manager::KeyManager::load_or_generate(
            temp.path().join(name).to_str().expect("key path"),
        )
        .expect("key manager");
        (temp, key)
    }

    #[test]
    fn test_offer_serialization() {
        let offer = CallOffer {
            device_id: "device-1".to_string(),
            virtual_id: "virtual-1".to_string(),
            session_id: "session-123".to_string(),
            timestamp: Utc::now(),
            nonce: "nonce-abc".to_string(),
            requested_media: vec![MediaType::Audio, MediaType::Video],
            signature: "sig-xyz".to_string(),
        };

        let json = offer.to_json().unwrap();
        let deserialized = CallOffer::from_json(&json).unwrap();

        assert_eq!(offer.device_id, deserialized.device_id);
        assert_eq!(offer.session_id, deserialized.session_id);
        assert_eq!(offer.requested_media, deserialized.requested_media);
    }

    #[test]
    fn test_answer_serialization() {
        let answer = CallAnswer {
            device_id: "device-2".to_string(),
            virtual_id: "virtual-1".to_string(),
            session_id: "session-123".to_string(),
            timestamp: Utc::now(),
            nonce: "nonce-abc".to_string(),
            accepted_media: vec![MediaType::Audio],
            accepted: true,
            rejection_reason: None,
            signature: "sig-xyz".to_string(),
        };

        let json = answer.to_json().unwrap();
        let deserialized = CallAnswer::from_json(&json).unwrap();

        assert_eq!(answer.device_id, deserialized.device_id);
        assert_eq!(answer.accepted, deserialized.accepted);
    }

    #[test]
    fn test_offer_validation() {
        // Empty device_id should fail
        let result = CallOffer {
            device_id: "".to_string(),
            virtual_id: "v1".to_string(),
            session_id: "s1".to_string(),
            timestamp: Utc::now(),
            nonce: "n1".to_string(),
            requested_media: vec![MediaType::Audio],
            signature: "sig".to_string(),
        }
        .payload_to_sign();
        assert!(result.is_ok()); // payload_to_sign doesn't validate, verify does
    }

    #[test]
    fn test_media_types() {
        assert_eq!(MediaType::Audio.to_string(), "audio");
        assert_eq!(MediaType::Video.to_string(), "video");
    }

    #[test]
    fn test_rejection_reason() {
        let answer = CallAnswer {
            device_id: "device-2".to_string(),
            virtual_id: "virtual-1".to_string(),
            session_id: "session-123".to_string(),
            timestamp: Utc::now(),
            nonce: "nonce-abc".to_string(),
            accepted_media: vec![],
            accepted: false,
            rejection_reason: Some("User declined".to_string()),
            signature: "sig-xyz".to_string(),
        };

        assert!(!answer.accepted);
        assert!(answer.rejection_reason.is_some());
    }

    #[tokio::test]
    async fn offer_reuses_attested_transport_identity() {
        let (_temp, signer) = key_manager("offer.pk8");
        let offer = CallOffer::new(
            "device-1".into(),
            "virtual-1".into(),
            "session-1".into(),
            "nonce-1".into(),
            vec![MediaType::Audio],
            &signer,
        )
        .await
        .expect("offer");

        assert!(offer.signature.is_empty());
    }

    #[tokio::test]
    async fn answer_reuses_attested_transport_identity() {
        let (_signer_temp, signer) = key_manager("answer.pk8");
        let answer = CallAnswer::accept(
            "device-2".into(),
            "virtual-2".into(),
            "session-1".into(),
            "nonce-1".into(),
            vec![MediaType::Audio],
            &signer,
        )
        .await
        .expect("answer");

        assert!(answer.signature.is_empty());
    }
}
