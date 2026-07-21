use crate::api::auth::{
    middleware::AuthenticatedSession,
    pairing::{self, PairingUsage, DEFAULT_PAIRING_TTL_SECS},
    store::{PairedDevice, PairingChallengeRecord},
};
use crate::api::{error::ApiError, state::AppState};
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct PairingCodeQuery {
    pub serial: String,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PairingCodeResponse {
    pub serial: String,
    pub challenge: String,
    pub nonce: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    #[serde(rename = "pairingCode")]
    pub pairing_code: String,
}

#[derive(Debug, Deserialize)]
pub struct PairDeviceRequest {
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub qr: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub serial: String,
    pub did: String,
    pub status: String,
    #[serde(rename = "nodeId", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceDetailResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub serial: String,
    pub did: String,
    #[serde(rename = "nodeId", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub status: String,
    #[serde(rename = "bootstrapStatus")]
    pub bootstrap_status: String,
    #[serde(rename = "overlayIp", skip_serializing_if = "Option::is_none")]
    pub overlay_ip: Option<String>,
    #[serde(
        rename = "attestationEndpoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub attestation_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PairingStatusQuery {
    pub serial: String,
}

#[derive(Debug, Serialize)]
pub struct PairingStatusResponse {
    pub serial: String,
    pub status: String,
    #[serde(rename = "apiConsumed")]
    pub api_consumed: bool,
    #[serde(rename = "bootstrapConsumed")]
    pub bootstrap_consumed: bool,
    #[serde(rename = "deviceId", skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(rename = "nodeId", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UnpairResponse {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub status: String,
}

fn bootstrap_already_completed(device_did: &str) -> bool {
    crate::vc::persistence::find_issued_for_subject(device_did, crate::vc::issue::DEFAULT_CIRCLE_ID)
        .ok()
        .flatten()
        .is_some_and(|vc| vc.has_active_membership_status())
}

fn pairing_status_value(
    record: &PairingChallengeRecord,
    device: Option<&PairedDevice>,
    now: i64,
) -> &'static str {
    if device.is_some_and(|device| device.status == "failed") {
        return "failed";
    }
    if record.bootstrap_consumed || device.is_some_and(|device| device.status == "active") {
        return "completed";
    }
    if record.api_consumed {
        if device.is_some() {
            return "bootstrap_pending";
        }
        return "proof_verified";
    }
    if record.exp <= now {
        return "expired";
    }
    "pending"
}

fn bootstrap_status_value(
    record: Option<&PairingChallengeRecord>,
    device: &PairedDevice,
    now: i64,
) -> &'static str {
    if device.status == "active" || record.is_some_and(|record| record.bootstrap_consumed) {
        return "completed";
    }
    if record.is_some_and(|record| record.exp <= now && !record.bootstrap_consumed) {
        return "expired";
    }
    "pending"
}

fn load_device_document(device_did: &str) -> Option<crate::did::document::DidDocument> {
    let did = crate::did::Did::parse(device_did).ok()?;
    crate::did::doc_persistence::load_peer(&did)
        .ok()
        .flatten()
        .or_else(|| {
            crate::did::doc_persistence::load_ca_aggregate()
                .ok()
                .and_then(|docs| docs.into_iter().find(|doc| doc.id == device_did))
        })
        .or_else(|| {
            crate::did::doc_persistence::load_self()
                .ok()
                .flatten()
                .filter(|doc| doc.id == device_did)
        })
}

fn doc_service_endpoint(device_did: &str, svc_type: &str) -> Option<String> {
    load_device_document(device_did)?
        .service
        .into_iter()
        .find(|service| service.svc_type == svc_type)
        .map(|service| service.service_endpoint)
}

fn overlay_ip_for_device(device_did: &str) -> Option<String> {
    let mesh = doc_service_endpoint(device_did, "SGXNebulaMesh")?;
    mesh.strip_prefix("nebula://")
        .map(|endpoint| endpoint.split('/').next().unwrap_or(endpoint).to_string())
}

async fn pairing_record_for_serial(
    state: &AppState,
    owner_user_id: &str,
    serial: &str,
) -> Result<Option<PairingChallengeRecord>, ApiError> {
    let serial =
        pairing::validate_serial(serial).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(state
        .admin
        .pairings
        .list()
        .await?
        .into_iter()
        .filter(|record| record.owner_user_id == owner_user_id && record.serial == serial)
        .max_by_key(|record| record.exp))
}

async fn pairing_record_for_device(
    state: &AppState,
    device: &PairedDevice,
) -> Result<Option<PairingChallengeRecord>, ApiError> {
    Ok(state
        .admin
        .pairings
        .list()
        .await?
        .into_iter()
        .filter(|record| {
            record.owner_user_id == device.owner_user_id
                && (record.device_id.as_deref() == Some(device.device_id.as_str())
                    || record.did.as_deref() == Some(device.did.as_str())
                    || record.serial == device.serial)
        })
        .max_by_key(|record| record.exp))
}

pub async fn pairing_code(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(query): Query<PairingCodeQuery>,
) -> Result<Json<PairingCodeResponse>, ApiError> {
    let ttl_secs = query
        .ttl_secs
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_PAIRING_TTL_SECS)
        .min(3600);
    let challenge = pairing::issue_challenge(&query.serial, Duration::from_secs(ttl_secs))
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    state
        .admin
        .pairings
        .put(pairing::record_from_challenge(
            &challenge,
            &session.claims.sub,
        ))
        .await?;

    Ok(Json(PairingCodeResponse {
        serial: challenge.serial.clone(),
        challenge: challenge.challenge.clone(),
        nonce: challenge.nonce.clone(),
        expires_at: challenge.exp,
        pairing_code: pairing::encode_challenge(&challenge)
            .map_err(|e| ApiError::Internal(e.to_string()))?,
    }))
}

pub async fn pair(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(body): Json<PairDeviceRequest>,
) -> Result<Json<DeviceResponse>, ApiError> {
    let encoded_proof = match (&body.qr, &body.proof) {
        (Some(qr), _) if !qr.trim().is_empty() => qr.trim().to_string(),
        (_, Some(proof)) if !proof.trim().is_empty() => proof.trim().to_string(),
        _ if body.serial.is_some() => {
            return Err(ApiError::BadRequest(
                "serial pairing requires a signed challenge proof".into(),
            ))
        }
        _ => {
            return Err(ApiError::BadRequest(
                "pair request missing qr or proof".into(),
            ))
        }
    };

    let authorized =
        pairing::authorize_pairing_proof(state.admin.as_ref(), &encoded_proof, PairingUsage::Api)
            .await
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    if authorized.owner_user_id != session.claims.sub {
        return Err(ApiError::Forbidden(
            "pairing proof was issued for a different user".into(),
        ));
    }
    if let Some(serial) = body.serial {
        let requested =
            pairing::validate_serial(&serial).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        if requested != authorized.serial {
            return Err(ApiError::BadRequest(
                "serial does not match pairing proof".into(),
            ));
        }
    }

    if let Some(existing) = state.admin.devices.get(&authorized.device_id).await? {
        if existing.owner_user_id != session.claims.sub && existing.status != "unpaired" {
            return Err(ApiError::Conflict(
                "device is already paired to another user".into(),
            ));
        }
    }

    let mut device = PairedDevice {
        device_id: authorized.device_id.clone(),
        serial: authorized.serial.clone(),
        did: authorized.device_did.clone(),
        owner_user_id: session.claims.sub.clone(),
        paired_at: Utc::now().to_rfc3339(),
        status: "bootstrap_pending".into(),
        node_id: Some(authorized.node_id.clone()),
    };
    state.admin.devices.upsert(device.clone()).await?;

    if bootstrap_already_completed(&authorized.device_did) {
        state
            .admin
            .sync_bootstrap_by_identity(
                Some(authorized.serial.as_str()),
                Some(authorized.device_id.as_str()),
                Some(authorized.device_did.as_str()),
                Some(session.claims.sub.as_str()),
                Some(authorized.node_id.as_str()),
            )
            .await?;
        device.status = "active".into();
    }

    Ok(Json(DeviceResponse {
        device_id: device.device_id,
        serial: device.serial,
        did: device.did,
        status: device.status,
        node_id: device.node_id,
    }))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<Vec<DeviceResponse>>, ApiError> {
    let mut devices = state.admin.devices.list(&session.claims.sub).await?;
    devices.sort_by(|left, right| left.serial.cmp(&right.serial));
    Ok(Json(
        devices
            .into_iter()
            .map(|device| DeviceResponse {
                device_id: device.device_id,
                serial: device.serial,
                did: device.did,
                status: device.status,
                node_id: device.node_id,
            })
            .collect(),
    ))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceDetailResponse>, ApiError> {
    let device = state
        .admin
        .devices
        .get(&device_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("device not found".into()))?;
    if device.owner_user_id != session.claims.sub || device.status == "unpaired" {
        return Err(ApiError::NotFound("device not found".into()));
    }

    let pairing = pairing_record_for_device(state.as_ref(), &device).await?;
    let now = Utc::now().timestamp();
    Ok(Json(DeviceDetailResponse {
        device_id: device.device_id.clone(),
        serial: device.serial.clone(),
        did: device.did.clone(),
        node_id: device.node_id.clone(),
        status: device.status.clone(),
        bootstrap_status: bootstrap_status_value(pairing.as_ref(), &device, now).to_string(),
        overlay_ip: overlay_ip_for_device(&device.did),
        attestation_endpoint: doc_service_endpoint(&device.did, "SGXAttestation"),
    }))
}

pub async fn pairing_status(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(query): Query<PairingStatusQuery>,
) -> Result<Json<PairingStatusResponse>, ApiError> {
    let record = pairing_record_for_serial(state.as_ref(), &session.claims.sub, &query.serial)
        .await?
        .ok_or_else(|| ApiError::NotFound("pairing record not found".into()))?;
    let device = if let Some(device_id) = record.device_id.as_deref() {
        state
            .admin
            .devices
            .get(device_id)
            .await?
            .filter(|device| device.owner_user_id == session.claims.sub)
    } else {
        state
            .admin
            .devices
            .list(&session.claims.sub)
            .await?
            .into_iter()
            .find(|device| device.serial == record.serial)
    };
    let now = Utc::now().timestamp();

    Ok(Json(PairingStatusResponse {
        serial: record.serial.clone(),
        status: pairing_status_value(&record, device.as_ref(), now).to_string(),
        api_consumed: record.api_consumed,
        bootstrap_consumed: record.bootstrap_consumed,
        device_id: record
            .device_id
            .clone()
            .or_else(|| device.as_ref().map(|device| device.device_id.clone())),
        node_id: record
            .node_id
            .clone()
            .or_else(|| device.as_ref().and_then(|device| device.node_id.clone())),
        did: record
            .did
            .clone()
            .or_else(|| device.as_ref().map(|device| device.did.clone())),
    }))
}

pub async fn unpair(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(device_id): Path<String>,
) -> Result<Json<UnpairResponse>, ApiError> {
    if !matches!(session.claims.role.as_str(), "owner" | "admin") {
        return Err(ApiError::Forbidden("insufficient role for unpair".into()));
    }
    state
        .admin
        .devices
        .unbind(&session.claims.sub, &device_id)
        .await
        .map_err(|e| ApiError::NotFound(e.to_string()))?;
    Ok(Json(UnpairResponse {
        device_id,
        status: "unpaired".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::{
        middleware::AuthenticatedSession,
        pairing::{build_pairing_proof, encode_challenge, issue_challenge, record_from_challenge},
        session::Claims,
        store::PairingChallengeRecord,
    };
    use crate::did::document::Proof;
    use crate::key_manager::KeyManager;
    use crate::vc::credential::{
        CredentialRole, CredentialStatus, CredentialSubject, MembershipStatus,
        VerifiableCredential, TYPE_CIRCLE_MEMBERSHIP, TYPE_VC, VC_CONTEXT_CORE,
        VC_CONTEXT_JWS_2020, VC_CONTEXT_SGX_CIRCLE,
    };
    use tempfile::TempDir;

    struct VcEnvGuard {
        prev: Option<std::ffi::OsString>,
    }

    impl VcEnvGuard {
        fn new(path: &std::path::Path) -> Self {
            let prev = std::env::var_os(crate::vc::persistence::VC_BASE_ENV);
            std::env::set_var(crate::vc::persistence::VC_BASE_ENV, path);
            Self { prev }
        }
    }

    impl Drop for VcEnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.prev.take() {
                std::env::set_var(crate::vc::persistence::VC_BASE_ENV, value);
            } else {
                std::env::remove_var(crate::vc::persistence::VC_BASE_ENV);
            }
        }
    }

    fn test_session(state: &Arc<AppState>, user_id: &str) -> AuthenticatedSession {
        AuthenticatedSession {
            claims: Claims {
                sub: user_id.to_string(),
                role: "owner".into(),
                iss: state.device_did.clone(),
                iat: 0,
                exp: i64::MAX,
                jti: "test-jti".into(),
            },
            token: "test-token".into(),
        }
    }

    fn issued_membership_vc(device_did: &str, node_id: &str) -> VerifiableCredential {
        VerifiableCredential {
            context: vec![
                VC_CONTEXT_CORE.into(),
                VC_CONTEXT_JWS_2020.into(),
                VC_CONTEXT_SGX_CIRCLE.into(),
            ],
            id: "urn:uuid:test-issued-vc".into(),
            vc_type: vec![TYPE_VC.into(), TYPE_CIRCLE_MEMBERSHIP.into()],
            issuer: "did:guardian:issuer-test".into(),
            issuance_date: "2026-07-01T00:00:00Z".into(),
            expiration_date: "2030-07-01T00:00:00Z".into(),
            credential_subject: CredentialSubject::new(
                device_did.to_string(),
                CredentialRole::Member,
                vec!["mesh:join".into()],
                "2026-07-01T00:00:00Z".into(),
                crate::vc::issue::DEFAULT_CIRCLE_ID.into(),
                Some(node_id.to_string()),
                MembershipStatus::Active,
            ),
            credential_status: CredentialStatus {
                id: "did:guardian:issuer-test/status/1".into(),
                status_type: "StatusList2021Entry".into(),
                status_purpose: "revocation".into(),
                status_list_index: "1".into(),
                status_list_credential: "did:guardian:issuer-test/status-list".into(),
            },
            proof: Proof::default(),
        }
    }

    #[tokio::test]
    async fn pair_syncs_admin_state_when_bootstrap_already_completed() {
        let td = TempDir::new().expect("tempdir");
        let _vc_env = VcEnvGuard::new(&td.path().join("vc"));
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let session = test_session(&state, "user-1");
        let serial = "GX-2024-TX-042-B9F3";
        let node_id = "nodeB";
        let device_did = "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB";

        crate::vc::persistence::save_issued(&issued_membership_vc(device_did, node_id))
            .expect("save issued vc");

        let challenge = issue_challenge(serial, Duration::from_secs(300)).expect("challenge");
        state
            .admin
            .pairings
            .put(record_from_challenge(&challenge, "user-1"))
            .await
            .expect("store challenge");

        let key_path = td.path().join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("key path"))
                .expect("load key manager"),
        );
        let proof = build_pairing_proof(
            &encode_challenge(&challenge).expect("encode challenge"),
            node_id,
            device_did,
            &signer.pubkey_der().expect("pubkey"),
            signer,
        )
        .await
        .expect("build proof");

        let response = pair(
            State(state.clone()),
            Extension(session),
            Json(PairDeviceRequest {
                serial: Some(serial.into()),
                qr: None,
                proof: Some(proof),
            }),
        )
        .await
        .expect("pair device");

        let device = state
            .admin
            .devices
            .get(&response.0.device_id)
            .await
            .expect("load device")
            .expect("device exists");
        let pairings: Vec<PairingChallengeRecord> =
            state.admin.pairings.list().await.expect("list pairings");
        let pairing = pairings
            .into_iter()
            .find(|entry| entry.serial == serial)
            .expect("pairing exists");

        assert_eq!(response.0.status, "active");
        assert_eq!(device.status, "active");
        assert!(pairing.bootstrap_consumed);
    }
}
