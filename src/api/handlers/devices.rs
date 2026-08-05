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
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn devices_config_for_state(state: &AppState) -> crate::devices::DevicesConfig {
    let mut cfg = crate::devices::DevicesConfig::from_env();
    if std::env::var_os(crate::devices::DEVICES_BASE_ENV).is_none() {
        if let Some(root) = PathBuf::from(&state.keys_dir)
            .parent()
            .map(|path| path.to_path_buf())
        {
            cfg.base_dir = root.join("devices");
        }
    }
    cfg
}

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

fn optional_session(
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Option<AuthenticatedSession>, ApiError> {
    optional_session_for_gate(session, crate::runtime_gates::login_disabled())
}

fn optional_session_for_gate(
    session: Option<Extension<AuthenticatedSession>>,
    login_disabled: bool,
) -> Result<Option<AuthenticatedSession>, ApiError> {
    if login_disabled {
        return Ok(session.map(|Extension(session)| session));
    }
    session
        .map(|Extension(session)| Some(session))
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))
}

fn session_user_id(session: Option<&AuthenticatedSession>) -> &str {
    session
        .map(|session| session.claims.sub.as_str())
        .unwrap_or("")
}

pub async fn pairing_code(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<PairingCodeQuery>,
) -> Result<Json<PairingCodeResponse>, ApiError> {
    let session = optional_session(session)?;
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
            session_user_id(session.as_ref()),
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
    session: Option<Extension<AuthenticatedSession>>,
    Json(body): Json<PairDeviceRequest>,
) -> Result<Json<DeviceResponse>, ApiError> {
    let session = optional_session(session)?;
    let owner_user_id = session_user_id(session.as_ref());
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

    if authorized.owner_user_id != owner_user_id {
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

    let now = Utc::now().to_rfc3339();
    let existing = state
        .admin
        .devices
        .get_by_did(&authorized.device_did)
        .await?;
    let reactivated = existing.is_some();
    let mut device = match existing {
        Some(mut existing) if existing.status == "unpaired" => {
            // Reuse the original registry record so its stable device ID and history survive.
            existing.serial = authorized.serial.clone();
            existing.did = authorized.device_did.clone();
            existing.owner_user_id = owner_user_id.to_string();
            existing.paired_at = now.clone();
            existing.reactivated_at = Some(now.clone());
            existing.updated_at = Some(now.clone());
            existing.status = "active".into();
            existing.node_id = Some(authorized.node_id.clone());
            existing
        }
        Some(_) => {
            return Err(ApiError::DeviceAlreadyPaired(
                "device DID is already paired".into(),
            ));
        }
        None => PairedDevice {
            device_id: authorized.device_id.clone(),
            serial: authorized.serial.clone(),
            did: authorized.device_did.clone(),
            owner_user_id: owner_user_id.to_string(),
            paired_at: now,
            reactivated_at: None,
            updated_at: None,
            status: "bootstrap_pending".into(),
            node_id: Some(authorized.node_id.clone()),
        },
    };
    state.admin.devices.upsert(device.clone()).await?;

    if !reactivated && bootstrap_already_completed(&authorized.device_did) {
        state
            .admin
            .sync_bootstrap_by_identity(
                Some(authorized.serial.as_str()),
                Some(authorized.device_id.as_str()),
                Some(authorized.device_did.as_str()),
                Some(owner_user_id),
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

pub async fn paired_list(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<Vec<DeviceResponse>>, ApiError> {
    let session = optional_session(session)?;
    let mut devices = load_paired_devices_for_session(state.as_ref(), session.as_ref()).await?;
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

pub async fn unpaired_list(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<Vec<DeviceResponse>>, ApiError> {
    // Preserve the paired-list authentication contract while reading only devices.json.
    let _session = optional_session(session)?;
    let mut devices = state.admin.devices.list_unpaired().await?;
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

pub async fn all_list(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<Vec<DeviceResponse>>, ApiError> {
    // Preserve the paired-list authentication contract while reading only devices.json.
    let _session = optional_session(session)?;
    let mut devices = state.admin.devices.list_all_records().await?;
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

async fn load_paired_devices_for_session(
    state: &AppState,
    session: Option<&AuthenticatedSession>,
) -> Result<Vec<PairedDevice>, ApiError> {
    if let Some(session) = session {
        state
            .admin
            .devices
            .list(&session.claims.sub)
            .await
            .map_err(Into::into)
    } else {
        state.admin.devices.list_all().await.map_err(Into::into)
    }
}

pub async fn paired_detail(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceDetailResponse>, ApiError> {
    let session = optional_session(session)?;
    let device = state
        .admin
        .devices
        .get(&device_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("device not found".into()))?;
    if session
        .as_ref()
        .is_some_and(|session| device.owner_user_id != session.claims.sub)
    {
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

#[derive(Debug, Clone, Serialize)]
pub struct ManagedDeviceResponse {
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub manual: bool,
    pub monitoring_enabled: bool,
    pub blocked: bool,
    pub rejected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_fingerprint: Option<String>,
    #[serde(default)]
    pub os_cpe: Vec<String>,
    #[serde(default)]
    pub open_ports: Vec<crate::discovery::OpenPort>,
    #[serde(default)]
    pub host_scripts: Vec<crate::discovery::ScriptResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scan_intensity: Option<String>,
    #[serde(flatten)]
    pub scores: crate::devices::DeviceScores,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevicesSummary {
    pub total: usize,
    pub manual: usize,
    pub blocked: usize,
    pub monitoring_enabled: usize,
    pub critical_devices: usize,
    pub high_risk_devices: usize,
    pub medium_risk_devices: usize,
    pub low_risk_devices: usize,
    pub unknown_risk_devices: usize,
    pub security_score_distribution: ScoreDistribution,
    pub privacy_score_distribution: ScoreDistribution,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScoreDistribution {
    pub unavailable: usize,
    pub poor: usize,
    pub fair: usize,
    pub good: usize,
    pub excellent: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceActionResponse {
    pub device_id: String,
    pub success: bool,
    pub message: String,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ManagedDeviceResponse>>, ApiError> {
    Ok(Json(load_managed_devices(state.as_ref()).await?))
}

pub async fn index(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !load_inventory(state.as_ref()).await?.is_empty() {
        let devices = load_managed_devices(state.as_ref()).await?;
        return serde_json::to_value(devices)
            .map(Json)
            .map_err(|err| ApiError::Internal(format!("devices response serialize: {}", err)));
    }

    let session = optional_session(session)?;
    let mut devices = load_paired_devices_for_session(state.as_ref(), session.as_ref()).await?;
    devices.sort_by(|left, right| left.serial.cmp(&right.serial));
    let response = devices
        .into_iter()
        .map(|device| DeviceResponse {
            device_id: device.device_id,
            serial: device.serial,
            did: device.did,
            status: device.status,
            node_id: device.node_id,
        })
        .collect::<Vec<_>>();
    serde_json::to_value(response)
        .map(Json)
        .map_err(|err| ApiError::Internal(format!("paired devices response serialize: {}", err)))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> Result<Json<ManagedDeviceResponse>, ApiError> {
    load_managed_devices(state.as_ref())
        .await?
        .into_iter()
        .find(|device| device.device_id == device_id)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("device not found".into()))
}

pub async fn summary(State(state): State<Arc<AppState>>) -> Result<Json<DevicesSummary>, ApiError> {
    let devices = load_managed_devices(state.as_ref()).await?;
    let mut summary = DevicesSummary {
        total: devices.len(),
        manual: 0,
        blocked: 0,
        monitoring_enabled: 0,
        critical_devices: 0,
        high_risk_devices: 0,
        medium_risk_devices: 0,
        low_risk_devices: 0,
        unknown_risk_devices: 0,
        security_score_distribution: ScoreDistribution::default(),
        privacy_score_distribution: ScoreDistribution::default(),
    };

    for device in &devices {
        if device.manual {
            summary.manual += 1;
        }
        if device.blocked {
            summary.blocked += 1;
        }
        if device.monitoring_enabled {
            summary.monitoring_enabled += 1;
        }
        match device.scores.risk_level.as_str() {
            "critical" => summary.critical_devices += 1,
            "high" => summary.high_risk_devices += 1,
            "medium" => summary.medium_risk_devices += 1,
            "low" => summary.low_risk_devices += 1,
            _ => summary.unknown_risk_devices += 1,
        }
        bucket_score(
            device.scores.security_score,
            &mut summary.security_score_distribution,
        );
        bucket_score(
            device.scores.privacy_score,
            &mut summary.privacy_score_distribution,
        );
    }

    Ok(Json(summary))
}

pub async fn add_manual(
    State(state): State<Arc<AppState>>,
    Json(body): Json<crate::devices::registry::AddManualDevice>,
) -> Result<Json<crate::devices::DeviceRecord>, ApiError> {
    let cfg = devices_config_for_state(state.as_ref());
    let path = cfg.registry_path();
    let mut registry = crate::devices::registry::DeviceRegistry::load(&path)
        .await
        .map_err(devices_error)?;
    let record = registry.insert_manual(body).map_err(devices_error)?;
    registry.save_atomic(&path).await.map_err(devices_error)?;
    let _ = state;
    Ok(Json(record))
}

pub async fn edit(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Json(body): Json<crate::devices::registry::DevicePatch>,
) -> Result<Json<crate::devices::DeviceRecord>, ApiError> {
    let cfg = devices_config_for_state(state.as_ref());
    let path = cfg.registry_path();
    let mut registry = crate::devices::registry::DeviceRegistry::load(&path)
        .await
        .map_err(devices_error)?;
    ensure_record_exists(&mut registry, &device_id, None)?;
    let record = registry.patch(&device_id, body).map_err(devices_error)?;
    registry.save_atomic(&path).await.map_err(devices_error)?;
    Ok(Json(record))
}

pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceActionResponse>, ApiError> {
    let cfg = devices_config_for_state(state.as_ref());
    let path = cfg.registry_path();
    let mut registry = crate::devices::registry::DeviceRegistry::load(&path)
        .await
        .map_err(devices_error)?;
    let removed = registry.remove(&device_id);
    registry.save_atomic(&path).await.map_err(devices_error)?;
    let _ = remove_from_whitelist(state.as_ref(), &device_id).await;
    Ok(Json(DeviceActionResponse {
        device_id,
        success: removed,
        message: if removed {
            "device registry record removed".into()
        } else {
            "device had no registry record".into()
        },
    }))
}

pub async fn block(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceActionResponse>, ApiError> {
    let device = load_managed_devices(state.as_ref())
        .await?
        .into_iter()
        .find(|device| device.device_id == device_id)
        .ok_or_else(|| ApiError::NotFound("device not found".into()))?;
    let ip = device
        .ip
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("device has no IP target".into()))?;
    if is_protected_ip(ip).await {
        return Err(ApiError::Forbidden(
            "refused to block protected local, gateway, or overlay address".into(),
        ));
    }

    // Enforce on the firewall first; only persist registry state after success.
    let blocker = build_threat_blocker(state.as_ref()).await?;
    blocker
        .block_ip_manual(ip)
        .await
        .map_err(api_error_from_threat_blocker_error)?;

    let cfg = devices_config_for_state(state.as_ref());
    let path = cfg.registry_path();
    let mut registry = crate::devices::registry::DeviceRegistry::load(&path)
        .await
        .map_err(devices_error)?;
    ensure_record_exists(&mut registry, &device_id, Some(&device))?;
    registry
        .mark_blocked(&device_id, true)
        .map_err(devices_error)?;
    registry.save_atomic(&path).await.map_err(devices_error)?;

    Ok(Json(DeviceActionResponse {
        device_id,
        success: true,
        message: "device blocked (nftables) and persisted".into(),
    }))
}

pub async fn reject(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    body: Option<Json<crate::devices::registry::RejectDeviceRequest>>,
) -> Result<Json<DeviceActionResponse>, ApiError> {
    reject_device(
        state.as_ref(),
        &device_id,
        body.map(|Json(body)| body.reason).unwrap_or_default(),
    )
    .await?;
    Ok(Json(DeviceActionResponse {
        device_id,
        success: true,
        message: "device rejected and marked blocked".into(),
    }))
}

pub async fn unblock(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceActionResponse>, ApiError> {
    let device = load_managed_devices(state.as_ref())
        .await?
        .into_iter()
        .find(|device| device.device_id == device_id)
        .ok_or_else(|| ApiError::NotFound("device not found".into()))?;
    let ip = device
        .ip
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("device has no IP target".into()))?;

    // Enforce on the firewall first; only persist registry state after success.
    let blocker = build_threat_blocker(state.as_ref()).await?;
    blocker
        .unblock_ip(ip)
        .await
        .map_err(api_error_from_threat_blocker_error)?;

    let cfg = devices_config_for_state(state.as_ref());
    let path = cfg.registry_path();
    let mut registry = crate::devices::registry::DeviceRegistry::load(&path)
        .await
        .map_err(devices_error)?;
    registry
        .mark_blocked(&device_id, false)
        .map_err(devices_error)?;
    registry.save_atomic(&path).await.map_err(devices_error)?;
    Ok(Json(DeviceActionResponse {
        device_id,
        success: true,
        message: "device unblocked (nftables) and persisted".into(),
    }))
}

pub async fn start_scan(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> Result<Json<crate::devices::DeviceScanRun>, ApiError> {
    let device = load_managed_devices(state.as_ref())
        .await?
        .into_iter()
        .find(|device| device.device_id == device_id)
        .ok_or_else(|| ApiError::NotFound("device not found".into()))?;
    let mut run = crate::devices::scan::initial_run(device_id);
    let cfg = devices_config_for_state(state.as_ref());
    let scans_path = cfg.scans_path();
    crate::devices::scan::append_run(&scans_path, &run)
        .await
        .map_err(devices_error)?;
    let mut response = run.clone();
    response.progress_history = vec![crate::devices::model::DeviceScanProgressTransition {
        step: response.step,
        step_label: response.step_label.clone(),
        state: response.state.clone(),
        timestamp: response
            .updated_at
            .clone()
            .unwrap_or_else(|| response.started_at.clone()),
    }];

    if let Some(ip) = device.ip.clone() {
        let scans_path = scans_path.clone();
        let discovery_config_dir = state.discovery_config_dir.clone();
        let managed_device = device.clone();
        tokio::spawn(async move {
            let _ = run_targeted_scan_progress(
                scans_path,
                run,
                managed_device,
                discovery_config_dir,
                ip,
                cfg.scan_timeout_secs,
            )
            .await;
        });
    } else {
        set_scan_stage(&mut run, 1, "failed");
        run.finished_at = Some(Utc::now().to_rfc3339());
        run.firmware_assessment = Some(unsupported_firmware_assessment(
            "device has no IP target for firmware evidence collection",
        ));
        run.findings = vec!["device has no IP target".into()];
        run.recommendations = vec!["add an IP address before running a targeted scan".into()];
        crate::devices::scan::append_run(&scans_path, &run)
            .await
            .map_err(devices_error)?;
    }

    Ok(Json(response))
}

pub async fn scan_status(
    State(state): State<Arc<AppState>>,
    Path((device_id, scan_id)): Path<(String, String)>,
) -> Result<Json<crate::devices::DeviceScanRun>, ApiError> {
    let cfg = devices_config_for_state(state.as_ref());
    crate::devices::scan::find_run_with_history(&cfg.scans_path(), &device_id, &scan_id)
        .await
        .map(Json)
        .map_err(devices_error)
}

async fn reject_device(
    state: &AppState,
    device_id: &str,
    reason: Option<String>,
) -> Result<crate::devices::DeviceRecord, ApiError> {
    let device = load_managed_devices(state)
        .await?
        .into_iter()
        .find(|device| device.device_id == device_id)
        .ok_or_else(|| ApiError::NotFound("device not found".into()))?;
    let ip = device
        .ip
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("device has no IP target".into()))?;
    if is_protected_ip(ip).await {
        return Err(ApiError::Forbidden(
            "refused to reject protected local, gateway, or overlay address".into(),
        ));
    }

    // Enforce on the firewall first; only persist registry state after success.
    let blocker = build_threat_blocker(state).await?;
    blocker
        .block_ip_manual(ip)
        .await
        .map_err(api_error_from_threat_blocker_error)?;

    let cfg = devices_config_for_state(state);
    let path = cfg.registry_path();
    let mut registry = crate::devices::registry::DeviceRegistry::load(&path)
        .await
        .map_err(devices_error)?;
    ensure_record_exists(&mut registry, device_id, Some(&device))?;
    let record = registry.reject(device_id, reason).map_err(devices_error)?;
    registry.save_atomic(&path).await.map_err(devices_error)?;
    remove_from_whitelist(state, device_id).await?;
    Ok(record)
}

async fn build_threat_blocker(
    state: &AppState,
) -> Result<crate::threat::blocker::Blocker, ApiError> {
    let cfg = crate::threat::config::SuricataConfig::load(std::path::Path::new(
        &state.threat_config_path,
    ))
    .map_err(|err| ApiError::Internal(format!("load threat config: {err}")))?;

    let cfg_shared = Arc::new(tokio::sync::Mutex::new(cfg));
    let blocker = crate::threat::blocker::Blocker::new(
        cfg_shared,
        state.node_id.clone(),
        PathBuf::from(&state.threat_state_dir),
    );

    blocker
        .restore_state()
        .await
        .map_err(|err| ApiError::Internal(format!("threat restore_state: {err}")))?;
    Ok(blocker)
}

fn api_error_from_threat_blocker_error(err: crate::threat::error::ThreatError) -> ApiError {
    match err {
        crate::threat::error::ThreatError::ProtectedIp(_) => ApiError::Forbidden(
            "refused to block protected local, gateway, or overlay address".into(),
        ),
        crate::threat::error::ThreatError::InvalidCidr(msg) => {
            ApiError::BadRequest(format!("invalid IP: {msg}"))
        }
        other => ApiError::Internal(other.to_string()),
    }
}

async fn load_managed_devices(state: &AppState) -> Result<Vec<ManagedDeviceResponse>, ApiError> {
    let cfg = devices_config_for_state(state);
    let registry = crate::devices::registry::DeviceRegistry::load(&cfg.registry_path())
        .await
        .map_err(devices_error)?;
    let mut records = registry.devices.clone();
    let inventory = load_inventory(state).await?;
    let mut responses = Vec::new();

    for device in inventory {
        let record = records.remove(&device.device_id);
        let scores = crate::devices::scoring::score_device(&device);
        responses.push(ManagedDeviceResponse {
            device_id: device.device_id,
            ip: Some(device.ip),
            mac: device.mac,
            vendor: device.vendor,
            hostname: device.hostname,
            display_name: record
                .as_ref()
                .and_then(|record| record.display_name.clone()),
            manual: record.as_ref().is_some_and(|record| record.manual),
            monitoring_enabled: record
                .as_ref()
                .map(|record| record.monitoring_enabled)
                .unwrap_or(true),
            blocked: record.as_ref().is_some_and(|record| record.blocked),
            rejected: record.as_ref().is_some_and(|record| record.rejected),
            rejection_reason: record
                .as_ref()
                .and_then(|record| record.rejection_reason.clone()),
            status: Some(if record.as_ref().is_some_and(|record| record.rejected) {
                "rejected".to_string()
            } else {
                serde_json::to_value(device.status)
                    .unwrap_or_default()
                    .to_string()
                    .trim_matches('"')
                    .to_string()
            }),
            os_fingerprint: device.os_fingerprint,
            os_cpe: device.os_cpe,
            open_ports: device.open_ports,
            host_scripts: device.host_scripts,
            first_seen: Some(device.first_seen),
            last_seen: Some(device.last_seen),
            last_scan_intensity: device.last_scan_intensity,
            scores,
        });
    }

    for record in records.into_values() {
        let synthetic = synthetic_device(&record);
        let scores = crate::devices::scoring::score_device(&synthetic);
        responses.push(ManagedDeviceResponse {
            device_id: record.device_id,
            ip: record.ip,
            mac: record.mac,
            vendor: record.manufacturer,
            hostname: None,
            display_name: record.display_name,
            manual: record.manual,
            monitoring_enabled: record.monitoring_enabled,
            blocked: record.blocked,
            rejected: record.rejected,
            rejection_reason: record.rejection_reason,
            status: Some(if record.rejected {
                "rejected".into()
            } else {
                "manual".into()
            }),
            os_fingerprint: None,
            os_cpe: Vec::new(),
            open_ports: Vec::new(),
            host_scripts: Vec::new(),
            first_seen: Some(record.created_at),
            last_seen: Some(record.updated_at),
            last_scan_intensity: None,
            scores,
        });
    }

    responses.sort_by(|left, right| {
        left.display_name
            .as_deref()
            .unwrap_or("")
            .cmp(right.display_name.as_deref().unwrap_or(""))
            .then(
                left.ip
                    .as_deref()
                    .unwrap_or("")
                    .cmp(right.ip.as_deref().unwrap_or("")),
            )
            .then(left.device_id.cmp(&right.device_id))
    });
    Ok(responses)
}

async fn load_inventory(
    state: &AppState,
) -> Result<Vec<crate::discovery::ConnectedDevice>, ApiError> {
    let path = PathBuf::from(&state.discovery_state_dir).join("inventory.json");
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(ApiError::Internal(format!("inventory read: {}", err))),
    };
    serde_json::from_slice(&bytes)
        .map_err(|err| ApiError::Internal(format!("inventory parse: {}", err)))
}

fn synthetic_device(record: &crate::devices::DeviceRecord) -> crate::discovery::ConnectedDevice {
    crate::discovery::ConnectedDevice {
        device_id: record.device_id.clone(),
        ip: record.ip.clone().unwrap_or_default(),
        mac: record.mac.clone(),
        vendor: record.manufacturer.clone(),
        hostname: record.display_name.clone(),
        os_fingerprint: None,
        os_cpe: Vec::new(),
        open_ports: Vec::new(),
        host_scripts: Vec::new(),
        status: crate::discovery::DeviceStatus::Unauthorized,
        first_seen: record.created_at.clone(),
        last_seen: record.updated_at.clone(),
        vuln_triaged: false,
        last_scan_intensity: None,
    }
}

fn ensure_record_exists(
    registry: &mut crate::devices::registry::DeviceRegistry,
    device_id: &str,
    device: Option<&ManagedDeviceResponse>,
) -> Result<(), ApiError> {
    if registry.devices.contains_key(device_id) {
        return Ok(());
    }
    let now = Utc::now().to_rfc3339();
    let record = crate::devices::DeviceRecord {
        device_id: device_id.to_string(),
        display_name: device.and_then(|device| device.display_name.clone()),
        manual: false,
        ip: device.and_then(|device| device.ip.clone()),
        mac: device.and_then(|device| device.mac.clone()),
        manufacturer: device.and_then(|device| device.vendor.clone()),
        monitoring_enabled: true,
        blocked: false,
        rejected: false,
        rejection_reason: None,
        notes: None,
        created_at: now.clone(),
        updated_at: now,
    };
    registry.devices.insert(device_id.to_string(), record);
    Ok(())
}

fn devices_error(error: crate::devices::errors::DevicesError) -> ApiError {
    match error {
        crate::devices::errors::DevicesError::NotFound => {
            ApiError::NotFound("device not found".into())
        }
        crate::devices::errors::DevicesError::Invalid(message) => ApiError::BadRequest(message),
        crate::devices::errors::DevicesError::TamperedRegistry => {
            ApiError::Internal("device registry integrity check failed".into())
        }
        other => ApiError::Internal(other.to_string()),
    }
}

fn bucket_score(score: Option<u8>, distribution: &mut ScoreDistribution) {
    match score {
        None => distribution.unavailable += 1,
        Some(0..=39) => distribution.poor += 1,
        Some(40..=59) => distribution.fair += 1,
        Some(60..=79) => distribution.good += 1,
        Some(_) => distribution.excellent += 1,
    }
}

async fn targeted_scan_findings(
    config_dir: &str,
    ip: &str,
    timeout_secs: u64,
) -> Result<crate::discovery::ConnectedDevice, String> {
    let mut cfg = crate::discovery::NmapConfig::load(&PathBuf::from(config_dir).join("nmap.yaml"))
        .unwrap_or_else(|_| crate::discovery::NmapConfig::default());
    cfg.timeout_secs = timeout_secs;
    let xml = crate::discovery::NmapRunner::run_device_security_scan(&cfg, ip)
        .await
        .map_err(|err| err.to_string())?;
    let devices = crate::discovery::nmap_parser::parse(&xml).map_err(|err| err.to_string())?;
    let device = devices
        .into_iter()
        .find(|device| device.ip == ip)
        .ok_or_else(|| "target did not appear in scan result".to_string())?;
    Ok(device)
}

async fn run_targeted_scan_progress(
    scans_path: PathBuf,
    mut run: crate::devices::DeviceScanRun,
    managed_device: ManagedDeviceResponse,
    discovery_config_dir: String,
    ip: String,
    timeout_secs: u64,
) -> Result<(), crate::devices::errors::DevicesError> {
    set_scan_stage(&mut run, 1, "running");
    let is_local = is_local_device_ip(&ip).await;
    crate::devices::scan::append_run(&scans_path, &run).await?;
    run.firmware_assessment = Some(assess_firmware(&managed_device, None, is_local).await);
    set_scan_stage(&mut run, 1, "complete");
    crate::devices::scan::append_run(&scans_path, &run).await?;

    set_scan_stage(&mut run, 2, "running");
    crate::devices::scan::append_run(&scans_path, &run).await?;
    let observed_device = match targeted_scan_findings(&discovery_config_dir, &ip, timeout_secs)
        .await
    {
        Ok(device) => device,
        Err(err) => {
            run.findings = vec![format!("targeted scan failed: {}", err)];
            run.recommendations = vec!["verify nmap availability and target reachability".into()];
            set_scan_stage(&mut run, 2, "failed");
            run.finished_at = Some(Utc::now().to_rfc3339());
            crate::devices::scan::append_run(&scans_path, &run).await?;
            return Ok(());
        }
    };

    set_scan_stage(&mut run, 2, "complete");
    crate::devices::scan::append_run(&scans_path, &run).await?;

    run.firmware_assessment =
        Some(assess_firmware(&managed_device, Some(&observed_device), is_local).await);
    run.findings = open_port_findings(&observed_device);

    set_scan_stage(&mut run, 3, "running");
    crate::devices::scan::append_run(&scans_path, &run).await?;
    run.findings.extend(encryption_findings(&observed_device));
    set_scan_stage(&mut run, 3, "complete");
    crate::devices::scan::append_run(&scans_path, &run).await?;

    set_scan_stage(&mut run, 4, "running");
    crate::devices::scan::append_run(&scans_path, &run).await?;
    run.findings
        .extend(vulnerability_findings(&observed_device));
    set_scan_stage(&mut run, 4, "complete");
    crate::devices::scan::append_run(&scans_path, &run).await?;

    set_scan_stage(&mut run, 5, "running");
    crate::devices::scan::append_run(&scans_path, &run).await?;
    let scores = crate::devices::scoring::score_device(&observed_device);
    run.findings.extend(
        scores
            .security_reasons
            .iter()
            .chain(scores.privacy_reasons.iter())
            .cloned(),
    );
    run.findings.sort();
    run.findings.dedup();
    run.recommendations = final_recommendations(&observed_device, &scores);

    set_scan_stage(&mut run, 5, "complete");
    run.finished_at = Some(Utc::now().to_rfc3339());
    crate::devices::scan::append_run(&scans_path, &run).await?;
    Ok(())
}

fn set_scan_stage(run: &mut crate::devices::DeviceScanRun, step: u8, state: &str) {
    run.step = step;
    run.step_label = if state == "complete" && step == 5 {
        "Complete".to_string()
    } else {
        crate::devices::scan::SCAN_STEPS[(step - 1) as usize].to_string()
    };
    run.state = state.to_string();
    run.updated_at = Some(Utc::now().to_rfc3339());
}

fn open_port_findings(device: &crate::discovery::ConnectedDevice) -> Vec<String> {
    if device.open_ports.is_empty() {
        return vec!["no open TCP/UDP services observed by targeted scan".into()];
    }
    device
        .open_ports
        .iter()
        .map(|port| {
            format!(
                "observed open {} service on {}/{}",
                port.service.as_deref().unwrap_or("unknown"),
                port.protocol,
                port.port
            )
        })
        .collect()
}

fn encryption_findings(device: &crate::discovery::ConnectedDevice) -> Vec<String> {
    let mut findings = Vec::new();
    let cleartext = device
        .open_ports
        .iter()
        .filter(|port| {
            matches!(
                port.service.as_deref(),
                Some("http" | "ftp" | "telnet" | "pop3" | "imap")
            )
        })
        .map(|port| format!("{}/{}", port.protocol, port.port))
        .collect::<Vec<_>>();
    if !cleartext.is_empty() {
        findings.push(format!(
            "cleartext service exposure observed: {}",
            cleartext.join(", ")
        ));
    }

    let tls_evidence = device.open_ports.iter().any(|port| {
        matches!(
            port.service.as_deref(),
            Some("https" | "ssl" | "tls" | "imaps" | "pop3s")
        ) || port.scripts.iter().any(|script| script.id.contains("ssl"))
    });
    if tls_evidence {
        findings.push("TLS-capable service evidence observed".into());
    }
    if findings.is_empty() {
        findings.push("no encryption evidence observed from network scan".into());
    }
    findings
}

fn vulnerability_findings(device: &crate::discovery::ConnectedDevice) -> Vec<String> {
    let mut findings = device
        .open_ports
        .iter()
        .flat_map(|port| {
            port.scripts
                .iter()
                .filter(|script| script.id.contains("vuln") || script.id.contains("cve"))
                .map(|script| format!("vulnerability script evidence from {}", script.id))
        })
        .collect::<Vec<_>>();
    if findings.is_empty() {
        findings.push("no known vulnerability script findings observed".into());
    }
    findings
}

fn final_recommendations(
    device: &crate::discovery::ConnectedDevice,
    scores: &crate::devices::DeviceScores,
) -> Vec<String> {
    let mut recommendations = if scores.security_score.unwrap_or(100) < 60 {
        vec!["review exposed services and patch vulnerability findings".into()]
    } else {
        vec!["no immediate remediation from network-observable scan".into()]
    };
    if device
        .open_ports
        .iter()
        .any(|port| matches!(port.service.as_deref(), Some("http" | "ftp" | "telnet")))
    {
        recommendations.push("prefer encrypted management protocols for exposed services".into());
    }
    recommendations.sort();
    recommendations.dedup();
    recommendations
}

async fn assess_firmware(
    managed: &ManagedDeviceResponse,
    observed: Option<&crate::discovery::ConnectedDevice>,
    is_local: bool,
) -> crate::devices::model::FirmwareAssessment {
    if is_local {
        return local_guardian_firmware_assessment().await;
    }
    remote_firmware_assessment(managed, observed)
}

async fn local_guardian_firmware_assessment() -> crate::devices::model::FirmwareAssessment {
    let mut evidence = Vec::new();
    let mut vendor = None;
    let mut product = None;
    let mut version = None;
    let mut platform = None;

    if let Some(os_release) = read_os_release().await {
        vendor = os_release_value(&os_release, "ID");
        product = os_release_value(&os_release, "PRETTY_NAME")
            .or_else(|| os_release_value(&os_release, "NAME"));
        version = os_release_value(&os_release, "VERSION_ID")
            .or_else(|| os_release_value(&os_release, "VERSION"));
        evidence.push(crate::devices::model::FirmwareEvidenceSource {
            source: "local:/etc/os-release".into(),
            value: compact_evidence_value(&os_release),
        });
    }

    if let Some(model) =
        read_trimmed_env_or_file("SGX_TEST_DEVICE_TREE_MODEL_FILE", "/proc/device-tree/model")
            .await
            .or_else(|| {
                std::fs::read_to_string("/sys/firmware/devicetree/base/model")
                    .ok()
                    .map(|value| value.trim_matches(char::from(0)).trim().to_string())
                    .filter(|value| !value.is_empty())
            })
    {
        platform = Some(model.clone());
        evidence.push(crate::devices::model::FirmwareEvidenceSource {
            source: "local:device-tree-model".into(),
            value: model,
        });
    }

    let status = if evidence.is_empty() {
        crate::devices::model::FirmwareAssessmentStatus::Unknown
    } else {
        crate::devices::model::FirmwareAssessmentStatus::Observed
    };
    let confidence = match (product.is_some(), platform.is_some()) {
        (true, true) => 0.75,
        (true, false) | (false, true) => 0.55,
        (false, false) => 0.0,
    };
    let findings = if evidence.is_empty() {
        vec!["no local Guardian firmware or OS evidence was available".into()]
    } else {
        vec!["local Guardian board/OS evidence observed; integrity proof not available".into()]
    };
    let recommendations = if evidence.is_empty() {
        vec!["verify local OS and board metadata collection on the Guardian".into()]
    } else {
        vec![
            "use secure boot or signed firmware attestations before marking firmware verified"
                .into(),
        ]
    };

    crate::devices::model::FirmwareAssessment {
        status,
        vendor,
        product,
        version,
        platform,
        evidence_sources: evidence,
        confidence,
        integrity_verified: false,
        findings,
        recommendations,
    }
}

fn remote_firmware_assessment(
    managed: &ManagedDeviceResponse,
    observed: Option<&crate::discovery::ConnectedDevice>,
) -> crate::devices::model::FirmwareAssessment {
    let vendor = observed
        .and_then(|device| device.vendor.clone())
        .or_else(|| managed.vendor.clone());
    let platform = observed
        .and_then(|device| device.os_fingerprint.clone())
        .or_else(|| managed.os_fingerprint.clone());
    let mut product = None;
    let mut version = None;
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(value) = vendor.as_ref() {
        push_evidence(&mut evidence, &mut seen, "nmap:mac-vendor", value);
    }
    if let Some(value) = platform.as_ref() {
        push_evidence(&mut evidence, &mut seen, "nmap:os-fingerprint", value);
    }

    let os_cpe = observed
        .map(|device| device.os_cpe.as_slice())
        .unwrap_or(managed.os_cpe.as_slice());
    for cpe in os_cpe {
        push_evidence(&mut evidence, &mut seen, "nmap:os-cpe", cpe);
        if product.is_none() {
            if let Some((cpe_vendor, cpe_product, cpe_version)) = parse_cpe(cpe) {
                product = Some(cpe_product);
                version = cpe_version;
                if vendor.is_none() {
                    push_evidence(&mut evidence, &mut seen, "nmap:os-cpe-vendor", &cpe_vendor);
                }
            }
        }
    }

    let ports = observed
        .map(|device| device.open_ports.as_slice())
        .unwrap_or(managed.open_ports.as_slice());
    for port in ports {
        if let Some(service_product) = port.product_version.as_ref() {
            push_evidence(
                &mut evidence,
                &mut seen,
                "nmap:service-banner",
                service_product,
            );
        }
        for cpe in &port.cpe {
            push_evidence(&mut evidence, &mut seen, "nmap:service-cpe", cpe);
        }
    }

    let status = if evidence.is_empty() {
        crate::devices::model::FirmwareAssessmentStatus::Unknown
    } else {
        crate::devices::model::FirmwareAssessmentStatus::Observed
    };
    let findings = if evidence.is_empty() {
        vec!["no network-observable firmware evidence was available".into()]
    } else {
        vec!["remote firmware identity is inferred only from network-observable metadata".into()]
    };
    let recommendations = if evidence.is_empty() {
        vec!["run an authenticated vendor inventory check if firmware identity is required".into()]
    } else {
        vec![
            "confirm firmware version with authenticated device or vendor management evidence"
                .into(),
        ]
    };

    crate::devices::model::FirmwareAssessment {
        status,
        vendor,
        product,
        version,
        platform,
        evidence_sources: evidence,
        confidence: if observed.is_some() { 0.35 } else { 0.2 },
        integrity_verified: false,
        findings,
        recommendations,
    }
}

fn unsupported_firmware_assessment(reason: &str) -> crate::devices::model::FirmwareAssessment {
    crate::devices::model::FirmwareAssessment {
        status: crate::devices::model::FirmwareAssessmentStatus::Unsupported,
        vendor: None,
        product: None,
        version: None,
        platform: None,
        evidence_sources: Vec::new(),
        confidence: 0.0,
        integrity_verified: false,
        findings: vec![reason.into()],
        recommendations: vec!["provide a reachable IP or authenticated firmware source".into()],
    }
}

fn push_evidence(
    evidence: &mut Vec<crate::devices::model::FirmwareEvidenceSource>,
    seen: &mut BTreeSet<(String, String)>,
    source: &str,
    value: &str,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let key = (source.to_string(), value.to_string());
    if seen.insert(key.clone()) {
        evidence.push(crate::devices::model::FirmwareEvidenceSource {
            source: key.0,
            value: key.1,
        });
    }
}

fn parse_cpe(cpe: &str) -> Option<(String, String, Option<String>)> {
    let parts = cpe.strip_prefix("cpe:/")?.split(':').collect::<Vec<_>>();
    if parts.len() < 3 || !matches!(parts.first(), Some(&"o" | &"h")) {
        return None;
    }
    Some((
        parts[1].replace('_', " "),
        parts[2].replace('_', " "),
        parts
            .get(3)
            .filter(|value| !value.is_empty() && **value != "*")
            .map(|value| value.replace('_', " ")),
    ))
}

async fn read_os_release() -> Option<String> {
    read_trimmed_env_or_file("SGX_TEST_OS_RELEASE_FILE", "/etc/os-release").await
}

async fn read_trimmed_env_or_file(env_key: &str, fallback: &str) -> Option<String> {
    let path = std::env::var(env_key).unwrap_or_else(|_| fallback.to_string());
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .map(|value| value.trim_matches(char::from(0)).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn os_release_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (line_key, value) = line.split_once('=')?;
        if line_key == key {
            Some(value.trim_matches('"').to_string())
        } else {
            None
        }
    })
}

fn compact_evidence_value(value: &str) -> String {
    value
        .lines()
        .take(4)
        .collect::<Vec<_>>()
        .join("; ")
        .chars()
        .take(240)
        .collect()
}

async fn is_local_device_ip(ip: &str) -> bool {
    let Ok(target) = ip.parse::<IpAddr>() else {
        return false;
    };
    if let Ok(values) = std::env::var("SGX_TEST_LOCAL_DEVICE_IPS") {
        return values
            .split(',')
            .filter_map(|value| value.trim().parse::<IpAddr>().ok())
            .any(|addr| addr == target);
    }
    if let Ok(output) = tokio::process::Command::new("ip")
        .args(["addr", "show"])
        .output()
        .await
    {
        let text = String::from_utf8_lossy(&output.stdout);
        return text.lines().map(str::trim).any(|line| {
            (line.starts_with("inet ") || line.starts_with("inet6 "))
                && line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|cidr| cidr.split('/').next())
                    .and_then(|addr| addr.parse::<IpAddr>().ok())
                    .is_some_and(|addr| addr == target)
        });
    }
    false
}

async fn is_protected_ip(ip: &str) -> bool {
    let Ok(target) = ip.parse::<IpAddr>() else {
        return true;
    };
    crate::threat::blocker::is_runtime_protected_host_ip(target).await
}

async fn remove_from_whitelist(state: &AppState, device_id: &str) -> Result<(), ApiError> {
    let inventory = load_inventory(state).await?;
    let mac = inventory
        .iter()
        .find(|device| device.device_id == device_id)
        .and_then(|device| device.mac.clone());
    let Some(mac) = mac else {
        return Ok(());
    };
    let path = PathBuf::from(&state.discovery_config_dir).join("whitelist.yaml");
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(_) => return Ok(()),
    };
    let mut doc: serde_yaml::Value = serde_yaml::from_slice(&bytes)
        .map_err(|err| ApiError::Internal(format!("whitelist parse: {}", err)))?;
    if let Some(devices) = doc
        .get_mut("devices")
        .and_then(|value| value.as_sequence_mut())
    {
        devices.retain(|entry| {
            entry
                .get("mac")
                .and_then(|value| value.as_str())
                .map(|entry_mac| !entry_mac.eq_ignore_ascii_case(&mac))
                .unwrap_or(true)
        });
    }
    let yaml = serde_yaml::to_string(&doc)
        .map_err(|err| ApiError::Internal(format!("whitelist serialize: {}", err)))?;
    tokio::fs::write(path, yaml).await?;
    Ok(())
}

pub async fn pairing_status(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<PairingStatusQuery>,
) -> Result<Json<PairingStatusResponse>, ApiError> {
    let session = optional_session(session)?;
    let records = state.admin.pairings.list().await?;
    let record = records
        .into_iter()
        .filter(|record| record.serial == query.serial)
        .filter(|record| {
            session
                .as_ref()
                .is_none_or(|session| record.owner_user_id == session.claims.sub)
        })
        .max_by_key(|record| record.exp)
        .ok_or_else(|| ApiError::NotFound("pairing record not found".into()))?;
    let device = if let Some(device_id) = record.device_id.as_deref() {
        state.admin.devices.get(device_id).await?.filter(|device| {
            session
                .as_ref()
                .is_none_or(|session| device.owner_user_id == session.claims.sub)
        })
    } else {
        let devices = if let Some(session) = session.as_ref() {
            state.admin.devices.list(&session.claims.sub).await?
        } else {
            state.admin.devices.list_all().await?
        };
        devices
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
    session: Option<Extension<AuthenticatedSession>>,
    Path(device_id): Path<String>,
) -> Result<Json<UnpairResponse>, ApiError> {
    let session = optional_session(session)?;
    let owner_user_id = if let Some(session) = session.as_ref() {
        if !matches!(session.claims.role.as_str(), "owner" | "admin") {
            return Err(ApiError::Forbidden("insufficient role for unpair".into()));
        }
        session.claims.sub.clone()
    } else {
        state
            .admin
            .devices
            .get(&device_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("device not found".into()))?
            .owner_user_id
    };
    state
        .admin
        .devices
        .unbind(&owner_user_id, &device_id)
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
    use crate::api::handlers::discovery::{approve_device, ApproveRequest};
    use crate::did::document::Proof;
    use crate::discovery::{ConnectedDevice, DeviceStatus, OpenPort};
    use crate::key_manager::KeyManager;
    use crate::nebula::{
        lighthouse::LighthouseRegistry, overlay_registry::OverlayRegistry,
        relay_registry::RelayRegistry,
    };
    use crate::test_support::async_env_lock;
    use crate::vc::credential::{
        CredentialRole, CredentialStatus, CredentialSubject, MembershipStatus,
        VerifiableCredential, TYPE_CIRCLE_MEMBERSHIP, TYPE_VC, VC_CONTEXT_CORE,
        VC_CONTEXT_JWS_2020, VC_CONTEXT_SGX_CIRCLE,
    };
    use std::ffi::OsString;
    use tempfile::TempDir;

    struct ScopedEnvVar {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl ScopedEnvVar {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    struct ScopedEnvStrVar {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl ScopedEnvStrVar {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for ScopedEnvStrVar {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

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

    fn inventory_device(device_id: &str, ip: &str, mac: &str) -> ConnectedDevice {
        ConnectedDevice {
            device_id: device_id.into(),
            ip: ip.into(),
            mac: Some(mac.into()),
            vendor: Some("Acme".into()),
            hostname: Some("sensor-44".into()),
            os_fingerprint: Some("Linux".into()),
            os_cpe: Vec::new(),
            open_ports: vec![OpenPort {
                port: 80,
                protocol: "tcp".into(),
                service: Some("http".into()),
                product_version: None,
                cpe: Vec::new(),
                scripts: Vec::new(),
            }],
            host_scripts: Vec::new(),
            status: DeviceStatus::Unauthorized,
            first_seen: "2026-07-24T00:00:00Z".into(),
            last_seen: "2026-07-24T00:00:00Z".into(),
            vuln_triaged: false,
            last_scan_intensity: Some("standard".into()),
        }
    }

    fn write_inventory(state: &AppState, devices: Vec<ConnectedDevice>) {
        let inventory_path =
            std::path::PathBuf::from(&state.discovery_state_dir).join("inventory.json");
        std::fs::create_dir_all(inventory_path.parent().expect("inventory parent"))
            .expect("create discovery state dir");
        std::fs::write(
            &inventory_path,
            serde_json::to_vec(&devices).expect("serialize inventory"),
        )
        .expect("write inventory");
    }

    fn managed_device_from_connected(device: &ConnectedDevice) -> ManagedDeviceResponse {
        let scores = crate::devices::scoring::score_device(device);
        ManagedDeviceResponse {
            device_id: device.device_id.clone(),
            ip: Some(device.ip.clone()),
            mac: device.mac.clone(),
            vendor: device.vendor.clone(),
            hostname: device.hostname.clone(),
            display_name: None,
            manual: false,
            monitoring_enabled: true,
            blocked: false,
            rejected: false,
            rejection_reason: None,
            status: Some("unauthorized".into()),
            os_fingerprint: device.os_fingerprint.clone(),
            os_cpe: device.os_cpe.clone(),
            open_ports: device.open_ports.clone(),
            host_scripts: device.host_scripts.clone(),
            first_seen: Some(device.first_seen.clone()),
            last_seen: Some(device.last_seen.clone()),
            last_scan_intensity: device.last_scan_intensity.clone(),
            scores,
        }
    }

    fn nmap_fixture_xml(ip: &str) -> String {
        format!(
            r#"<nmaprun>
  <host>
    <status state="up"/>
    <address addr="{ip}" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:44" addrtype="mac" vendor="Acme"/>
    <hostnames><hostname name="sensor-44"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Boa" version="0.94"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24"/>
        <script id="ssl-cert" output="self signed certificate"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x">
        <osclass><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>"#
        )
    }

    fn write_nmap_fixture(dir: &std::path::Path, ip: &str) -> std::path::PathBuf {
        let path = dir.join("nmap-device.xml");
        std::fs::write(&path, nmap_fixture_xml(ip)).expect("write nmap fixture");
        path
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
            Some(Extension(session)),
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

    #[tokio::test]
    async fn pair_reactivates_unpaired_did_without_replacing_device_id() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let session = test_session(&state, "user-1");
        let serial = "GX-2024-TX-042-REACTIVATE";
        let node_id = "nodeB";
        let device_did = "did:guardian:reactivate-test-device";
        let preserved_device_id = "preserved-device-id";

        state
            .admin
            .devices
            .upsert(PairedDevice {
                device_id: preserved_device_id.into(),
                serial: "GX-2024-TX-042-OLD".into(),
                did: device_did.into(),
                owner_user_id: "former-owner".into(),
                paired_at: "2026-01-01T00:00:00Z".into(),
                reactivated_at: None,
                updated_at: None,
                status: "unpaired".into(),
                node_id: Some("nodeC".into()),
            })
            .await
            .expect("seed unpaired device");

        let key_path = td.path().join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("key path"))
                .expect("load key manager"),
        );
        let challenge = issue_challenge(serial, Duration::from_secs(300)).expect("challenge");
        state
            .admin
            .pairings
            .put(record_from_challenge(&challenge, "user-1"))
            .await
            .expect("store challenge");
        let proof = build_pairing_proof(
            &encode_challenge(&challenge).expect("encode challenge"),
            node_id,
            device_did,
            &signer.pubkey_der().expect("pubkey"),
            signer.clone(),
        )
        .await
        .expect("build proof");

        let response = pair(
            State(state.clone()),
            Some(Extension(session.clone())),
            Json(PairDeviceRequest {
                serial: Some(serial.into()),
                qr: None,
                proof: Some(proof),
            }),
        )
        .await
        .expect("reactivate device");
        assert_eq!(response.0.device_id, preserved_device_id);
        assert_eq!(response.0.status, "active");

        let reactivated = state
            .admin
            .devices
            .get_by_did(device_did)
            .await
            .expect("load reactivated device")
            .expect("reactivated device exists");
        assert_eq!(reactivated.device_id, preserved_device_id);
        assert_eq!(reactivated.owner_user_id, "user-1");
        assert_eq!(reactivated.serial, serial);
        assert_eq!(reactivated.status, "active");
        assert_ne!(reactivated.paired_at, "2026-01-01T00:00:00Z");
        assert!(reactivated.reactivated_at.is_some());
        assert!(reactivated.updated_at.is_some());

        let second_challenge =
            issue_challenge(serial, Duration::from_secs(300)).expect("second challenge");
        state
            .admin
            .pairings
            .put(record_from_challenge(&second_challenge, "user-1"))
            .await
            .expect("store second challenge");
        let second_proof = build_pairing_proof(
            &encode_challenge(&second_challenge).expect("encode second challenge"),
            node_id,
            device_did,
            &signer.pubkey_der().expect("pubkey"),
            signer,
        )
        .await
        .expect("build second proof");
        let error = match pair(
            State(state),
            Some(Extension(session)),
            Json(PairDeviceRequest {
                serial: Some(serial.into()),
                qr: None,
                proof: Some(second_proof),
            }),
        )
        .await
        {
            Ok(_) => panic!("reject already active device DID"),
            Err(error) => error,
        };
        assert!(matches!(error, ApiError::DeviceAlreadyPaired(_)));
    }

    #[tokio::test]
    async fn device_list_without_session_returns_401_when_login_enabled() {
        let error = optional_session_for_gate(None, false).expect_err("auth required");
        assert!(
            matches!(error, ApiError::Unauthorized(message) if message == "missing bearer token")
        );
    }

    #[tokio::test]
    async fn device_list_uses_unscoped_store_when_login_disabled() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        state
            .admin
            .devices
            .upsert(PairedDevice {
                device_id: "dev-login-disabled".into(),
                serial: "GX-2026-LOGIN-DISABLED".into(),
                did: "did:guardian:test-login-disabled".into(),
                owner_user_id: "real-owner-from-store".into(),
                paired_at: Utc::now().to_rfc3339(),
                reactivated_at: None,
                updated_at: None,
                status: "active".into(),
                node_id: Some("nodeB".into()),
            })
            .await
            .expect("seed device");

        let session = optional_session_for_gate(None, true).expect("login disabled allows no auth");
        let devices = load_paired_devices_for_session(state.as_ref(), session.as_ref())
            .await
            .expect("login disabled skips session");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "dev-login-disabled");
    }

    #[tokio::test]
    async fn device_inventory_list_loads_nmap_devices_when_registry_is_empty() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeC",
            td.path().join("config").to_string_lossy().to_string(),
        );
        write_inventory(
            state.as_ref(),
            vec![inventory_device(
                "nmap-device-1",
                "192.168.50.44",
                "AA:BB:CC:DD:EE:44",
            )],
        );

        let response = list(State(state))
            .await
            .expect("inventory list should not require registry");

        assert_eq!(response.0.len(), 1);
        assert_eq!(response.0[0].device_id, "nmap-device-1");
        assert_eq!(response.0[0].ip.as_deref(), Some("192.168.50.44"));
        assert!(!response.0[0].manual);
    }

    #[tokio::test]
    async fn targeted_scan_persists_all_live_steps_and_final_firmware_assessment() {
        let _guard = async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let target_ip = "192.0.2.44";
        let fixture = write_nmap_fixture(td.path(), target_ip);
        let _fixture_env = ScopedEnvVar::set("SGX_TEST_NMAP_XML_FILE", fixture.as_path());
        let device = inventory_device("scan-device-1", target_ip, "AA:BB:CC:DD:EE:44");
        let managed = managed_device_from_connected(&device);
        let scans_path = td.path().join("scans.jsonl");
        let run = crate::devices::scan::initial_run(device.device_id.clone());

        run_targeted_scan_progress(
            scans_path.clone(),
            run.clone(),
            managed,
            td.path().join("config").to_string_lossy().to_string(),
            target_ip.into(),
            30,
        )
        .await
        .expect("run staged scan");

        let runs = crate::devices::scan::load_runs(&scans_path)
            .await
            .expect("load scan runs")
            .into_iter()
            .filter(|entry| entry.scan_id == run.scan_id)
            .collect::<Vec<_>>();
        let steps = runs.iter().map(|entry| entry.step).collect::<Vec<_>>();
        assert_eq!(steps, vec![1, 1, 2, 2, 3, 3, 4, 4, 5, 5]);
        assert_eq!(runs[0].step_label, "Firmware Fingerprint");
        assert_eq!(runs[2].step_label, "Open Ports and Services");
        assert_eq!(runs[4].step_label, "Encryption Assessment");
        assert_eq!(runs[6].step_label, "Known Vulnerability Analysis");
        assert_eq!(runs[8].step_label, "Final Security Report");
        assert_eq!(runs[9].step_label, "Complete");
        assert_eq!(runs[9].step, 5);
        assert_eq!(runs[9].state, "complete");
        assert!(runs
            .iter()
            .all(|entry| entry.updated_at.as_deref().is_some_and(|ts| !ts.is_empty())));
        let latest =
            crate::devices::scan::find_run_with_history(&scans_path, &run.device_id, &run.scan_id)
                .await
                .expect("latest scan with history");
        assert_eq!(latest.step, 5);
        assert_eq!(latest.step_label, "Complete");
        assert_eq!(latest.state, "complete");
        assert_eq!(
            latest
                .progress_history
                .iter()
                .map(|entry| (entry.step, entry.step_label.as_str(), entry.state.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (1, "Firmware Fingerprint", "running"),
                (1, "Firmware Fingerprint", "complete"),
                (2, "Open Ports and Services", "running"),
                (2, "Open Ports and Services", "complete"),
                (3, "Encryption Assessment", "running"),
                (3, "Encryption Assessment", "complete"),
                (4, "Known Vulnerability Analysis", "running"),
                (4, "Known Vulnerability Analysis", "complete"),
                (5, "Final Security Report", "running"),
                (5, "Complete", "complete"),
            ]
        );
        assert!(latest
            .progress_history
            .iter()
            .all(|entry| !entry.timestamp.is_empty()));
        let firmware = latest
            .firmware_assessment
            .as_ref()
            .expect("firmware assessment");
        assert_eq!(
            firmware.status,
            crate::devices::model::FirmwareAssessmentStatus::Observed
        );
        assert!(!firmware.integrity_verified);
        assert!(firmware
            .evidence_sources
            .iter()
            .any(|source| source.source == "nmap:os-cpe"));
    }

    #[tokio::test]
    async fn scan_status_returns_progress_history_for_fast_completed_scan() {
        let _guard = async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let devices_base = td.path().join("devices");
        let _devices_env = ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, &devices_base);
        let scans_path = crate::devices::DevicesConfig::from_env().scans_path();
        let target_ip = "192.0.2.45";
        let fixture = write_nmap_fixture(td.path(), target_ip);
        let _fixture_env = ScopedEnvVar::set("SGX_TEST_NMAP_XML_FILE", fixture.as_path());
        let device = inventory_device("scan-device-2", target_ip, "AA:BB:CC:DD:EE:45");
        let managed = managed_device_from_connected(&device);
        let run = crate::devices::scan::initial_run(device.device_id.clone());
        let scan_id = run.scan_id.clone();

        run_targeted_scan_progress(
            scans_path,
            run,
            managed,
            td.path().join("config").to_string_lossy().to_string(),
            target_ip.into(),
            30,
        )
        .await
        .expect("run staged scan");

        let state = AppState::for_tests(&td.path().join("api"), "node-test", "");
        let response = scan_status(
            State(state),
            Path(("scan-device-2".to_string(), scan_id.clone())),
        )
        .await
        .expect("scan status")
        .0;

        assert_eq!(response.scan_id, scan_id);
        assert_eq!(response.step, 5);
        assert_eq!(response.step_label, "Complete");
        assert_eq!(response.state, "complete");
        assert!(response.firmware_assessment.is_some());
        assert_eq!(
            response
                .progress_history
                .iter()
                .map(|entry| entry.step)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 2, 3, 4, 5])
        );
        assert_eq!(
            response
                .progress_history
                .iter()
                .filter(|entry| entry.state == "running")
                .map(|entry| entry.step)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(
            response
                .progress_history
                .iter()
                .filter(|entry| entry.state == "complete")
                .map(|entry| entry.step)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
    }

    #[tokio::test]
    async fn local_guardian_firmware_uses_local_board_and_os_evidence() {
        let _guard = async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let os_release = td.path().join("os-release");
        let model = td.path().join("model");
        std::fs::write(
            &os_release,
            "ID=guardian-os\nPRETTY_NAME=\"SG-X Guardian OS\"\nVERSION_ID=\"2026.7\"\n",
        )
        .expect("write os-release");
        std::fs::write(&model, "Cervais Guardian Board RevA\n").expect("write model");
        let _os_env = ScopedEnvVar::set("SGX_TEST_OS_RELEASE_FILE", os_release.as_path());
        let _model_env = ScopedEnvVar::set("SGX_TEST_DEVICE_TREE_MODEL_FILE", model.as_path());

        let device = inventory_device("guardian-local", "192.0.2.10", "AA:AA:AA:AA:AA:10");
        let managed = managed_device_from_connected(&device);
        let assessment = assess_firmware(&managed, None, true).await;

        assert_eq!(
            assessment.status,
            crate::devices::model::FirmwareAssessmentStatus::Observed
        );
        assert_eq!(assessment.vendor.as_deref(), Some("guardian-os"));
        assert_eq!(assessment.product.as_deref(), Some("SG-X Guardian OS"));
        assert_eq!(assessment.version.as_deref(), Some("2026.7"));
        assert_eq!(
            assessment.platform.as_deref(),
            Some("Cervais Guardian Board RevA")
        );
        assert!(!assessment.integrity_verified);
        assert!(assessment.confidence > 0.7);
    }

    #[tokio::test]
    async fn firmware_assessment_reports_unknown_and_unsupported_without_evidence() {
        let empty_device = ConnectedDevice {
            device_id: "empty-device".into(),
            ip: "192.0.2.55".into(),
            mac: None,
            vendor: None,
            hostname: None,
            os_fingerprint: None,
            os_cpe: Vec::new(),
            open_ports: Vec::new(),
            host_scripts: Vec::new(),
            status: DeviceStatus::Unauthorized,
            first_seen: "2026-07-24T00:00:00Z".into(),
            last_seen: "2026-07-24T00:00:00Z".into(),
            vuln_triaged: false,
            last_scan_intensity: None,
        };
        let managed = managed_device_from_connected(&empty_device);

        let unknown = remote_firmware_assessment(&managed, Some(&empty_device));
        assert_eq!(
            unknown.status,
            crate::devices::model::FirmwareAssessmentStatus::Unknown
        );
        assert_eq!(unknown.confidence, 0.35);
        assert!(unknown.evidence_sources.is_empty());

        let unsupported = unsupported_firmware_assessment("no supported target");
        assert_eq!(
            unsupported.status,
            crate::devices::model::FirmwareAssessmentStatus::Unsupported
        );
        assert_eq!(unsupported.confidence, 0.0);
        assert!(!unsupported.integrity_verified);
    }

    #[tokio::test]
    async fn remote_service_banners_do_not_become_verified_firmware_versions() {
        let mut device = inventory_device("camera-1", "192.0.2.66", "AA:BB:CC:DD:EE:66");
        device.vendor = None;
        device.os_fingerprint = None;
        device.os_cpe = Vec::new();
        device.open_ports[0].product_version = Some("CameraFirmware 9.9".into());
        let managed = managed_device_from_connected(&device);

        let assessment = remote_firmware_assessment(&managed, Some(&device));
        assert_eq!(
            assessment.status,
            crate::devices::model::FirmwareAssessmentStatus::Observed
        );
        assert_eq!(assessment.product, None);
        assert_eq!(assessment.version, None);
        assert!(!assessment.integrity_verified);
        assert!(assessment.confidence < 0.5);
        assert!(assessment
            .evidence_sources
            .iter()
            .any(|source| source.source == "nmap:service-banner"));
        assert!(assessment
            .findings
            .iter()
            .any(|finding| finding.contains("inferred only")));
    }

    #[tokio::test]
    async fn reject_marks_device_rejected_blocks_and_removes_whitelist() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");
        let td = TempDir::new().expect("tempdir");
        let devices_base = td.path().join("devices");
        let _devices_env =
            ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, devices_base.as_path());
        let state = AppState::for_tests(
            td.path(),
            "nodeC",
            td.path().join("config").to_string_lossy().to_string(),
        );
        write_inventory(
            state.as_ref(),
            vec![inventory_device(
                "reject-device-1",
                "203.0.113.44",
                "AA:BB:CC:DD:EE:44",
            )],
        );
        std::fs::write(
            std::path::PathBuf::from(&state.discovery_config_dir).join("whitelist.yaml"),
            "version: '1.0'\ndevices:\n  - mac: AA:BB:CC:DD:EE:44\n    label: Sensor\n",
        )
        .expect("write whitelist");

        let _reject_response = reject(
            State(state.clone()),
            Path("reject-device-1".into()),
            Some(Json(crate::devices::registry::RejectDeviceRequest {
                reason: Some("Unauthorized device".into()),
            })),
        )
        .await
        .expect("reject device");

        let response = detail(State(state.clone()), Path("reject-device-1".into()))
            .await
            .expect("device detail");
        assert_eq!(response.0.status.as_deref(), Some("rejected"));
        assert!(response.0.rejected);
        assert!(response.0.blocked);
        assert_eq!(
            response.0.rejection_reason.as_deref(),
            Some("Unauthorized device")
        );
        let whitelist = std::fs::read_to_string(
            std::path::PathBuf::from(&state.discovery_config_dir).join("whitelist.yaml"),
        )
        .expect("read whitelist");
        assert!(!whitelist.contains("AA:BB:CC:DD:EE:44"));

        let _approve_response = approve_device(
            State(state.clone()),
            Json(ApproveRequest {
                mac: "AA:BB:CC:DD:EE:44".into(),
                label: Some("Sensor".into()),
            }),
        )
        .await
        .expect("approve device");

        let response = detail(State(state), Path("reject-device-1".into()))
            .await
            .expect("device detail after approve");
        assert!(!response.0.rejected);
        assert!(!response.0.blocked);
        assert_eq!(response.0.rejection_reason, None);
        assert_ne!(response.0.status.as_deref(), Some("rejected"));
    }

    #[tokio::test]
    async fn block_marks_device_blocked_and_persists_threat_record() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");

        let td = TempDir::new().expect("tempdir");
        let devices_base = td.path().join("devices");
        let _devices_env =
            ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, devices_base.as_path());

        let state = AppState::for_tests(
            td.path(),
            "nodeC",
            td.path().join("config").to_string_lossy().to_string(),
        );

        write_inventory(
            state.as_ref(),
            vec![inventory_device(
                "block-device-1",
                "203.0.113.44",
                "AA:BB:CC:DD:EE:44",
            )],
        );

        let _ = block(State(state.clone()), Path("block-device-1".into()))
            .await
            .expect("block device");

        let response = detail(State(state.clone()), Path("block-device-1".into()))
            .await
            .expect("device detail");
        assert!(response.0.blocked);
        assert!(!response.0.rejected);

        let blocked_path =
            std::path::PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
        let text = std::fs::read_to_string(&blocked_path).expect("read blocked_ips.json");
        let records: Vec<crate::threat::blocker::BlockRecord> =
            serde_json::from_str(&text).expect("parse blocked_ips.json");
        assert!(records.iter().any(|r| r.ip == "203.0.113.44"));
    }

    #[tokio::test]
    async fn unblock_clears_device_block_and_removes_threat_record() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");

        let td = TempDir::new().expect("tempdir");
        let devices_base = td.path().join("devices");
        let _devices_env =
            ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, devices_base.as_path());

        let state = AppState::for_tests(
            td.path(),
            "nodeC",
            td.path().join("config").to_string_lossy().to_string(),
        );

        write_inventory(
            state.as_ref(),
            vec![inventory_device(
                "unblock-device-1",
                "203.0.113.45",
                "AA:BB:CC:DD:EE:45",
            )],
        );

        let _ = block(State(state.clone()), Path("unblock-device-1".into()))
            .await
            .expect("block device");

        let _ = unblock(State(state.clone()), Path("unblock-device-1".into()))
            .await
            .expect("unblock device");

        let response = detail(State(state.clone()), Path("unblock-device-1".into()))
            .await
            .expect("device detail");
        assert!(!response.0.blocked);
        assert!(!response.0.rejected);

        let blocked_path =
            std::path::PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
        let text = std::fs::read_to_string(&blocked_path).expect("read blocked_ips.json");
        let records: Vec<crate::threat::blocker::BlockRecord> =
            serde_json::from_str(&text).expect("parse blocked_ips.json");
        assert!(!records.iter().any(|r| r.ip == "203.0.113.45"));
    }

    #[tokio::test]
    async fn block_does_not_persist_registry_when_nft_enforcement_fails() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");
        let _fail_match = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT_FAIL_MATCH", "203.0.113.46");

        let td = TempDir::new().expect("tempdir");
        let devices_base = td.path().join("devices");
        let _devices_env =
            ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, devices_base.as_path());

        let state = AppState::for_tests(
            td.path(),
            "nodeC",
            td.path().join("config").to_string_lossy().to_string(),
        );

        write_inventory(
            state.as_ref(),
            vec![inventory_device(
                "block-fail-device-1",
                "203.0.113.46",
                "AA:BB:CC:DD:EE:46",
            )],
        );

        let err = block(State(state.clone()), Path("block-fail-device-1".into()))
            .await
            .expect_err("block should fail with nft mock failure");

        match err {
            ApiError::Internal(_) => {}
            other => panic!("unexpected api error: {other:?}"),
        }

        let response = detail(State(state.clone()), Path("block-fail-device-1".into()))
            .await
            .expect("device detail");
        assert!(!response.0.blocked);
        assert!(!response.0.rejected);
    }

    #[tokio::test]
    async fn reject_unknown_device_returns_404() {
        let _guard = async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let devices_base = td.path().join("devices");
        let _devices_env =
            ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, devices_base.as_path());
        let state = AppState::for_tests(
            td.path(),
            "nodeC",
            td.path().join("config").to_string_lossy().to_string(),
        );

        let error = reject(State(state), Path("missing-device".into()), None)
            .await
            .expect_err("unknown device should fail");
        assert!(matches!(error, ApiError::NotFound(message) if message == "device not found"));
    }

    #[tokio::test]
    async fn block_allows_remote_peer_lan_ip_in_node_and_physical_endpoint_registries() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");

        let td = TempDir::new().expect("tempdir");
        let config_dir = td.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::write(
            config_dir.join("nodeB.yaml"),
            r#"---
node_id: "nodeB"
hostname: "guardian-node-B"
ip: "192.168.1.252"
port: 50052
public_key: "placeholder-key-B"

relay:
  enabled: true
  max_peers: 5
  max_bandwidth_mbps: 10
  alert_threshold_pct: 80
"#,
        )
        .expect("write nodeB config");

        let devices_base = td.path().join("devices");
        let _devices_env =
            ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, devices_base.as_path());
        let nebula_dir = td.path().join("nebula");
        std::fs::create_dir_all(&nebula_dir).expect("nebula dir");
        let _nebula_env =
            ScopedEnvStrVar::set("SGX_NEBULA_DIR", nebula_dir.to_str().expect("nebula path"));
        let overlay = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
        overlay
            .save(
                nebula_dir
                    .join("overlay_registry.json")
                    .to_str()
                    .expect("registry"),
            )
            .expect("save overlay registry");
        let lighthouse =
            LighthouseRegistry::new("alpha", "nodeB", "192.168.100.2", "192.168.1.252:4242");
        lighthouse
            .save(
                nebula_dir
                    .join("lighthouse_registry.json")
                    .to_str()
                    .expect("lighthouse registry"),
            )
            .expect("save lighthouse registry");
        let mut relay = RelayRegistry::new("alpha");
        relay.add_relay("nodeB", "192.168.100.2", "192.168.1.252:4242", 5, 10, false);
        relay
            .save(
                nebula_dir
                    .join("relay_registry.json")
                    .to_str()
                    .expect("relay registry"),
            )
            .expect("save relay registry");

        let state =
            AppState::for_tests(td.path(), "nodeC", config_dir.to_string_lossy().to_string());
        write_inventory(
            state.as_ref(),
            vec![inventory_device(
                "peer-nodeb",
                "192.168.1.252",
                "AA:BB:CC:DD:EE:52",
            )],
        );

        let _ = block(State(state.clone()), Path("peer-nodeb".into()))
            .await
            .expect("remote peer LAN IP should be blockable");

        let response = detail(State(state), Path("peer-nodeb".into()))
            .await
            .expect("device detail");
        assert!(response.0.blocked);
    }

    #[tokio::test]
    async fn block_refuses_overlay_ip_from_registry() {
        let _guard = async_env_lock().await;
        let _nft_mock = ScopedEnvStrVar::set("SGX_THREAT_MOCK_NFT", "1");

        let td = TempDir::new().expect("tempdir");
        let devices_base = td.path().join("devices");
        let _devices_env =
            ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, devices_base.as_path());
        let nebula_dir = td.path().join("nebula");
        std::fs::create_dir_all(&nebula_dir).expect("nebula dir");
        let _nebula_env =
            ScopedEnvStrVar::set("SGX_NEBULA_DIR", nebula_dir.to_str().expect("nebula path"));
        let mut overlay = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
        let overlay_cidr = overlay.assign_ip("nodeB").expect("assign overlay");
        let overlay_ip = overlay_cidr
            .split('/')
            .next()
            .expect("overlay ip")
            .to_string();
        overlay
            .save(
                nebula_dir
                    .join("overlay_registry.json")
                    .to_str()
                    .expect("registry"),
            )
            .expect("save overlay registry");

        let state = AppState::for_tests(
            td.path(),
            "nodeC",
            td.path().join("config").to_string_lossy().to_string(),
        );
        write_inventory(
            state.as_ref(),
            vec![inventory_device(
                "overlay-device",
                overlay_ip.as_str(),
                "AA:BB:CC:DD:EE:53",
            )],
        );

        let error = block(State(state), Path("overlay-device".into()))
            .await
            .expect_err("overlay IP should be protected");
        assert!(matches!(error, ApiError::Forbidden(message) if message.contains("protected")));
    }

    #[tokio::test]
    async fn reject_refuses_protected_address() {
        let _guard = async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let devices_base = td.path().join("devices");
        let _devices_env =
            ScopedEnvVar::set(crate::devices::DEVICES_BASE_ENV, devices_base.as_path());
        let state = AppState::for_tests(
            td.path(),
            "nodeC",
            td.path().join("config").to_string_lossy().to_string(),
        );
        write_inventory(
            state.as_ref(),
            vec![inventory_device(
                "protected-device",
                "127.0.0.1",
                "AA:BB:CC:DD:EE:45",
            )],
        );

        let error = reject(State(state), Path("protected-device".into()), None)
            .await
            .expect_err("protected address should fail");
        assert!(matches!(error, ApiError::Forbidden(message) if message.contains("protected")));
    }
}
