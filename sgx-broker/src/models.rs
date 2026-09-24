//! Shared message types for the VPS enrollment broker.
//!
//! These types are used between:
//! - Node C → VPS (HTTP POST /api/v1/enroll)
//! - VPS → Node A (WebSocket ENROLLMENT_REQUEST)
//! - Node A → VPS (WebSocket ENROLLMENT_RESPONSE)
//! - VPS → Node C (HTTP 200 response)

use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────
// HTTP API types (Node C ↔ VPS)
// ────────────────────────────────────────────────────────────────────

/// Payload sent by Node C to `POST /api/v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// Circle identifier (e.g. "guardian-circle-alpha")
    pub circle_id: String,
    /// Requesting node name (e.g. "nodeC")
    pub node_id: String,
    /// P0.1c: **the requesting Guardian's device P-256 identity key, as
    /// Base64-encoded DER** — despite the field name, this is not and never was
    /// a Nebula key. The CA decodes it as DER and checks it against the key
    /// that signed `did_doc_json` (`ca_broker::validate_enrollment_did`). The
    /// name is kept for wire compatibility with deployed brokers.
    pub public_key_pem: String,
    /// P0.1/B1: the requesting Guardian's **Nebula** public key PEM, produced
    /// by `nebula-cert keygen` on that Guardian. When present the CA signs it
    /// with `-in-pub`, so `EnrollmentResponse::key` comes back empty and no
    /// private key ever transits this broker.
    ///
    /// `#[serde(default)]` for pre-P0.1 Guardians, which the CA accepts only
    /// while `SGX_ALLOW_LEGACY_KEYGEN` is set.
    #[serde(default)]
    pub nebula_public_key_pem: String,
    /// The requesting Guardian's signed DID Document. The CA verifies this
    /// before issuing circle-membership trust material.
    #[serde(default)]
    pub did_doc_json: String,
}

/// Payload returned to Node C as the HTTP 200 body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    /// "APPROVED" | "REJECTED" | "ERROR"
    pub status: String,
    /// Assigned overlay IP with CIDR (e.g. "192.168.100.3/24")
    #[serde(default)]
    pub overlay_ip: String,
    /// Signed Nebula certificate PEM
    #[serde(default)]
    pub cert: String,
    /// DEPRECATED (P0.1/B1): the Nebula private key PEM. Empty whenever the
    /// request carried `nebula_public_key_pem`, which is the supported path —
    /// the Guardian generates and keeps its own key. Only the legacy path,
    /// gated by `SGX_ALLOW_LEGACY_KEYGEN` on the CA, still populates it.
    #[serde(default)]
    pub key: String,
    /// CA certificate PEM (shared trust anchor)
    #[serde(default)]
    pub ca_cert: String,
    /// Pre-built nebula.yaml config for the remote node
    #[serde(default)]
    pub config: String,
    /// Node-A-issued circle membership VC for the requesting Guardian.
    #[serde(default)]
    pub member_vc_json: String,
    /// Current signed VC status-list credential.
    #[serde(default)]
    pub status_list_json: String,
    /// Signed CA DID Document aggregate used to verify the VC issuer.
    #[serde(default)]
    pub did_doc_aggregate_json: String,
    /// Policy Authority public key, encoded as standard Base64 DER.
    #[serde(default)]
    pub signing_pubkey_der_b64: String,
    /// Signed policy bytes, encoded as standard Base64 when available.
    #[serde(default)]
    pub signed_policy_b64: String,
    /// Human-readable message or rejection reason
    #[serde(default)]
    pub message: String,
}

// ────────────────────────────────────────────────────────────────────
// WebSocket envelope (VPS ↔ Node A)
// ────────────────────────────────────────────────────────────────────

/// Message envelope sent over the CA bridge WebSocket.
///
/// The VPS sends `ENROLLMENT_REQUEST` events to Node A.
/// Node A replies with `ENROLLMENT_RESPONSE` events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsEnvelope {
    /// Event type: "ENROLLMENT_REQUEST" or "ENROLLMENT_RESPONSE"
    pub event: String,
    /// Correlation ID that ties a request to its response
    pub request_id: String,
    /// The enrollment request (present in ENROLLMENT_REQUEST events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<EnrollmentRequest>,
    /// The enrollment response (present in ENROLLMENT_RESPONSE events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<EnrollmentResponse>,
}

// ────────────────────────────────────────────────────────────────────
// Health check
// ────────────────────────────────────────────────────────────────────

/// Response from `GET /health`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub ca_connected: bool,
    pub uptime_secs: u64,
}
