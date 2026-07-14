use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::did::{
    self, doc_distribution, doc_persistence, doc_sign, document::DidDocument, DidError,
};
use axum::{
    body::Bytes,
    extract::{Query, State},
    Json,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_DKP_PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";
const DID_PATH_ENV: &str = "SGX_GUARDIAN_DID_PATH";
const DKP_PUBKEY_PATH_ENV: &str = "SGX_GUARDIAN_DKP_PUBKEY_PATH";

#[derive(Serialize)]
pub struct DidStatusResponse {
    pub did: String,
    pub method: String,
    #[serde(rename = "methodVersion")]
    pub method_version: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "deactivatedAt")]
    pub deactivated_at: Option<String>,
    #[serde(rename = "currentDkpVersion")]
    pub current_dkp_version: u32,
    #[serde(rename = "se050UidSource")]
    pub se050_uid_source: String,
    #[serde(rename = "dikPubkeySha256B16")]
    pub dik_pubkey_sha256_b16: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct DidResolveResponse {
    pub did: String,
    pub status: String,
    #[serde(rename = "publicKeyPreview")]
    pub public_key_preview: String,
    #[serde(rename = "publicKeyBytes")]
    pub public_key_bytes: usize,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum DidResolveEnvelope {
    Local(DidResolveResponse),
    Peer(did::ResolutionResult),
}

#[derive(Deserialize)]
pub struct DeactivateRequest {
    pub reason: Option<String>,
    pub confirm: bool,
}

#[derive(Debug, Serialize)]
pub struct DeactivateResponse {
    pub ok: bool,
    pub message: String,
    #[serde(rename = "restartRequired")]
    pub restart_required: bool,
}

#[derive(Serialize)]
pub struct DidDocumentSummaryResponse {
    pub did: String,
    pub controller: String,
    pub node_name: String,
    pub version: u32,
    pub status: String,
    pub active_vms: usize,
    pub revoked_vms: usize,
    pub services: usize,
    pub proof_vm: String,
}

#[derive(Default, Deserialize)]
pub struct VerifyDocumentRequest {
    pub path: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyDocumentResponse {
    pub valid: bool,
    pub version: u32,
    pub message: String,
}

#[derive(Deserialize)]
pub struct PublishDocumentRequest {
    pub ca_host: String,
    pub node_name: String,
}

#[derive(Serialize)]
pub struct PublishDocumentResponse {
    pub success: bool,
    pub did: String,
    pub version: u32,
    pub ca_host: String,
    pub node_name: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct PeerDocumentSummary {
    pub did: String,
    pub node_name: String,
    pub version: u32,
    pub status: String,
    pub services: usize,
}

#[derive(Serialize)]
pub struct PeerDocumentsResponse {
    pub count: usize,
    pub peers: Vec<PeerDocumentSummary>,
}

#[derive(Deserialize)]
pub struct PeerDidQuery {
    pub did: Option<String>,
}

#[derive(Default, Deserialize)]
pub struct ResolveQuery {
    pub did: Option<String>,
    #[serde(default)]
    pub reject_deactivated: bool,
}

pub async fn status(_state: State<Arc<AppState>>) -> Result<Json<DidStatusResponse>, ApiError> {
    let did_path = did_path();
    let rec = did::DidRecord::load(&did_path).map_err(|e| did_error(e, &did_path))?;

    Ok(Json(DidStatusResponse {
        did: rec.did,
        method: rec.method,
        method_version: rec.method_version,
        created_at: rec.created_at,
        deactivated_at: rec.deactivated_at.clone(),
        current_dkp_version: rec.current_dkp_version,
        se050_uid_source: rec.derivation.se050_uid_source,
        dik_pubkey_sha256_b16: rec.derivation.dik_pubkey_sha256_b16,
        status: if rec.deactivated_at.is_none() {
            "active".to_string()
        } else {
            "deactivated".to_string()
        },
    }))
}

pub async fn resolve(
    State(s): State<Arc<AppState>>,
    Query(q): Query<ResolveQuery>,
) -> Result<Json<DidResolveEnvelope>, ApiError> {
    if let Some(raw_did) = q.did {
        let did_value = raw_did.trim();
        if did_value.is_empty() {
            return Err(ApiError::BadRequest(
                "did query parameter must not be empty".to_string(),
            ));
        }

        let resolver = s.did_resolver.with_reject_deactivated(q.reject_deactivated);
        let result = resolver
            .resolve(did_value)
            .await
            .map_err(did_resolution_error)?;
        log_audit(
            &s.node_id,
            AuditCategory::Did,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!(
                "DID resolved via {} (status={}, v{}, TTL={}s)",
                result.source.as_str(),
                result.status,
                result.version_id,
                result.ttl_remaining_sec
            ),
        );
        return Ok(Json(DidResolveEnvelope::Peer(result)));
    }

    let did_path = did_path();
    let dkp_pubkey_path = dkp_pubkey_path();
    let (resolved_did, public_key, active) =
        did::method::resolve_local(&did_path, &dkp_pubkey_path)
            .map_err(|e| did_error(e, &did_path))?;

    let public_key_hex = hex::encode(&public_key);
    let preview_len = public_key_hex.len().min(32);
    let mut public_key_preview = public_key_hex[..preview_len].to_string();
    if public_key_hex.len() > preview_len {
        public_key_preview.push_str("...");
    }

    Ok(Json(DidResolveEnvelope::Local(DidResolveResponse {
        did: resolved_did.as_str().to_string(),
        status: if active {
            "ACTIVE".to_string()
        } else {
            "DEACTIVATED".to_string()
        },
        public_key_preview,
        public_key_bytes: public_key.len(),
    })))
}

pub async fn deactivate(
    State(s): State<Arc<AppState>>,
    Json(body): Json<DeactivateRequest>,
) -> Result<Json<DeactivateResponse>, ApiError> {
    if !body.confirm {
        log_audit(
            &s.node_id,
            AuditCategory::Did,
            AuditSeverity::Warning,
            AuditAction::Rejected,
            "DID deactivation rejected: confirm was not true",
        );
        return Err(ApiError::BadRequest(
            "confirm must be true to deactivate DID".to_string(),
        ));
    }

    let reason = body
        .reason
        .unwrap_or_else(|| "manual-admin".to_string())
        .trim()
        .to_string();
    let reason = if reason.is_empty() {
        "manual-admin".to_string()
    } else {
        reason
    };

    let did_path = did_path();
    let message = match did::method::deactivate(&did_path, &reason) {
        Ok(()) => {
            log_audit(
                &s.node_id,
                AuditCategory::Did,
                AuditSeverity::Warning,
                AuditAction::Revoked,
                &format!("DID deactivated by admin (reason={})", reason),
            );
            "DID deactivated. Restart daemon to enforce runtime refusal.".to_string()
        }
        Err(DidError::Deactivated(at)) => {
            log_audit(
                &s.node_id,
                AuditCategory::Did,
                AuditSeverity::Info,
                AuditAction::Revoked,
                &format!("DID already deactivated at {}", at),
            );
            format!("DID already deactivated at {}", at)
        }
        Err(e) => return Err(did_error(e, &did_path)),
    };

    Ok(Json(DeactivateResponse {
        ok: true,
        message,
        restart_required: true,
    }))
}

pub async fn document(
    _state: State<Arc<AppState>>,
) -> Result<Json<DidDocumentSummaryResponse>, ApiError> {
    let doc = load_self_document()?;
    Ok(Json(summarize_document(&doc)))
}

pub async fn document_raw(_state: State<Arc<AppState>>) -> Result<Json<DidDocument>, ApiError> {
    Ok(Json(load_self_document()?))
}

pub async fn document_verify(
    _state: State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<VerifyDocumentResponse>, ApiError> {
    let req: VerifyDocumentRequest = parse_optional_json_body(&body)?;
    let path = verify_request_path(req.path)?;
    let doc = doc_persistence::load_doc_at_path(&path)
        .map_err(|e| did_document_verify_error(e, &path))?;
    let floor_version = known_floor_version(&doc);
    doc_sign::verify_with_replay_protection(&doc, floor_version)
        .map_err(did_document_verify_failure)?;

    Ok(Json(VerifyDocumentResponse {
        valid: true,
        version: doc.sgx_version_id,
        message: "DID Document proof valid".to_string(),
    }))
}

pub async fn document_publish(
    _state: State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<PublishDocumentResponse>, ApiError> {
    let req: PublishDocumentRequest = parse_required_json_body(&body)?;
    let ca_host = required_nonempty_field(&req.ca_host, "ca_host")?;
    let node_name = required_nonempty_field(&req.node_name, "node_name")?;
    let allowed_ca = std::env::var("SGX_CA_HOST").unwrap_or_else(|_| "192.168.50.101".to_string());
    if ca_host != allowed_ca {
        return Err(ApiError::BadRequest(format!(
            "ca_host must be {}",
            allowed_ca
        )));
    }
    let doc = load_self_document()?;
    let floor_version = known_floor_version(&doc);
    doc_sign::verify_with_replay_protection(&doc, floor_version)
        .map_err(did_document_verify_failure)?;
    doc_distribution::publish_to_ca(&ca_host, &node_name, &doc)
        .await
        .map_err(did_document_publish_error)?;

    Ok(Json(PublishDocumentResponse {
        success: true,
        did: doc.id.clone(),
        version: doc.sgx_version_id,
        ca_host,
        node_name,
        message: "DID Document published to CA registry".to_string(),
    }))
}

pub async fn document_peers(
    _state: State<Arc<AppState>>,
) -> Result<Json<PeerDocumentsResponse>, ApiError> {
    let mut peers: Vec<PeerDocumentSummary> = doc_persistence::list_peer_docs()
        .map_err(did_document_listing_error)?
        .into_iter()
        .filter(|doc| {
            let floor = known_floor_version(doc);
            doc_sign::verify_with_replay_protection(doc, floor).is_ok()
        })
        .map(|doc| PeerDocumentSummary {
            did: doc.id,
            node_name: doc.sgx_node_name.unwrap_or_default(),
            version: doc.sgx_version_id,
            status: doc.sgx_status.unwrap_or_else(|| "active".to_string()),
            services: doc.service.len(),
        })
        .collect();
    peers.sort_by(|a, b| a.did.cmp(&b.did));

    Ok(Json(PeerDocumentsResponse {
        count: peers.len(),
        peers,
    }))
}

pub async fn document_peer(
    _state: State<Arc<AppState>>,
    Query(q): Query<PeerDidQuery>,
) -> Result<Json<DidDocument>, ApiError> {
    let did_value = q
        .did
        .as_deref()
        .map(str::trim)
        .filter(|did| !did.is_empty())
        .ok_or_else(|| ApiError::BadRequest("did query parameter is required".to_string()))?;
    let did = did::Did::parse(did_value).map_err(did_query_error)?;
    let doc = doc_persistence::load_peer(&did).map_err(|e| did_peer_load_error(e, &did))?;
    let doc = doc.ok_or_else(|| {
        let path =
            doc_persistence::configured_peers_doc_dir().join(format!("did_doc_{}.json", did.msi()));
        ApiError::NotFound(format!("peer did document not found at {}", path.display()))
    })?;
    let floor = known_floor_version(&doc);
    doc_sign::verify_with_replay_protection(&doc, floor)
        .map_err(|e| ApiError::BadRequest(format!("peer DID doc verification failed: {}", e)))?;
    Ok(Json(doc))
}

fn did_path() -> String {
    std::env::var(DID_PATH_ENV).unwrap_or_else(|_| did::DEFAULT_DID_PATH.to_string())
}

fn dkp_pubkey_path() -> String {
    std::env::var(DKP_PUBKEY_PATH_ENV).unwrap_or_else(|_| DEFAULT_DKP_PUBKEY_PATH.to_string())
}

fn did_error(err: DidError, did_path: &str) -> ApiError {
    match err {
        DidError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(format!("did record not found at {}", did_path))
        }
        DidError::InvalidFormat(e)
        | DidError::WrongMethod(e)
        | DidError::Base58(e)
        | DidError::UidUnavailable(e)
        | DidError::Signing(e)
        | DidError::DkpPubkeyMissing(e) => ApiError::BadRequest(e),
        other => ApiError::Internal(other.to_string()),
    }
}

fn summarize_document(doc: &DidDocument) -> DidDocumentSummaryResponse {
    DidDocumentSummaryResponse {
        did: doc.id.clone(),
        controller: doc.controller.clone(),
        node_name: doc.sgx_node_name.clone().unwrap_or_default(),
        version: doc.sgx_version_id,
        status: doc
            .sgx_status
            .clone()
            .unwrap_or_else(|| "active".to_string()),
        active_vms: doc.verification_method.len(),
        revoked_vms: doc.sgx_revoked_vm.len(),
        services: doc.service.len(),
        proof_vm: doc
            .proof
            .as_ref()
            .map(|proof| proof.verification_method.clone())
            .unwrap_or_default(),
    }
}

fn load_self_document() -> Result<DidDocument, ApiError> {
    let path = doc_persistence::configured_self_doc_path();
    match doc_persistence::load_self() {
        Ok(Some(doc)) => Ok(doc),
        Ok(None) => Err(ApiError::NotFound(format!(
            "did document not found at {}",
            path.display()
        ))),
        Err(err) => Err(did_document_load_error(err, &path)),
    }
}

fn verify_request_path(path: Option<String>) -> Result<PathBuf, ApiError> {
    match path {
        Some(path) => {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                return Err(ApiError::BadRequest(
                    "path must not be empty when provided".to_string(),
                ));
            }

            // SECURITY: this path came straight from the request body with no
            // validation, straight into fs::read_to_string via
            // load_doc_at_path — an unauthenticated caller could point it at
            // any file on the host (e.g. /etc/shadow, the PA private key).
            // Resolve symlinks/".." and require the result to live under one
            // of the configured DID document directories (dynamic, not
            // hardcoded, so this also works under test env-var overrides).
            let resolved = Path::new(trimmed)
                .canonicalize()
                .map_err(|e| ApiError::BadRequest(format!("invalid path: {}", e)))?;

            let allowed_roots: Vec<PathBuf> = [
                doc_persistence::configured_self_doc_path()
                    .parent()
                    .map(Path::to_path_buf),
                Some(doc_persistence::configured_peers_doc_dir()),
            ]
            .into_iter()
            .flatten()
            .filter_map(|root| root.canonicalize().ok())
            .collect();

            if !allowed_roots.iter().any(|root| resolved.starts_with(root)) {
                return Err(ApiError::BadRequest(
                    "path must be under the configured DID document directories".to_string(),
                ));
            }

            Ok(resolved)
        }
        None => Ok(doc_persistence::configured_self_doc_path()),
    }
}

fn parse_optional_json_body<T>(body: &Bytes) -> Result<T, ApiError>
where
    T: Default + DeserializeOwned,
{
    if body.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice(body)
        .map_err(|e| ApiError::BadRequest(format!("invalid JSON body: {}", e)))
}

fn parse_required_json_body<T>(body: &Bytes) -> Result<T, ApiError>
where
    T: DeserializeOwned,
{
    if body.is_empty() {
        return Err(ApiError::BadRequest("request body is required".to_string()));
    }
    serde_json::from_slice(body)
        .map_err(|e| ApiError::BadRequest(format!("invalid JSON body: {}", e)))
}

fn required_nonempty_field(value: &str, field: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{} is required", field)));
    }
    Ok(trimmed.to_string())
}

fn known_floor_version(doc: &DidDocument) -> u32 {
    if let Ok(Some(self_doc)) = doc_persistence::load_self() {
        if self_doc.id == doc.id {
            return doc_persistence::read_self_floor_version();
        }
    }
    doc.did()
        .ok()
        .and_then(|did| {
            doc_persistence::load_peer(&did)
                .ok()
                .flatten()
                .map(|existing| existing.sgx_version_id)
        })
        .unwrap_or(0)
}

fn did_query_error(err: DidError) -> ApiError {
    match err {
        DidError::InvalidFormat(e) | DidError::WrongMethod(e) | DidError::Base58(e) => {
            ApiError::BadRequest(e)
        }
        other => ApiError::BadRequest(other.to_string()),
    }
}

fn did_resolution_error(err: DidError) -> ApiError {
    match err {
        DidError::Unresolvable(did) => ApiError::NotFound(format!("unresolvable DID: {}", did)),
        DidError::Io(e) => ApiError::Internal(format!("did resolve failed: {}", e)),
        DidError::ResolutionFailed(e) => ApiError::Internal(format!("did resolve failed: {}", e)),
        DidError::InvalidFormat(e)
        | DidError::WrongMethod(e)
        | DidError::Base58(e)
        | DidError::UidUnavailable(e)
        | DidError::Signing(e)
        | DidError::DkpPubkeyMissing(e)
        | DidError::Deactivated(e) => ApiError::BadRequest(e),
        other => ApiError::BadRequest(other.to_string()),
    }
}

fn did_document_load_error(err: DidError, path: &Path) -> ApiError {
    match err {
        DidError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(format!("did document not found at {}", path.display()))
        }
        other => ApiError::Internal(format!(
            "did document load failed at {}: {}",
            path.display(),
            other
        )),
    }
}

fn did_document_verify_error(err: DidError, path: &Path) -> ApiError {
    match err {
        DidError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(format!("did document not found at {}", path.display()))
        }
        DidError::Json(e) => ApiError::BadRequest(format!(
            "invalid DID document JSON at {}: {}",
            path.display(),
            e
        )),
        DidError::InvalidFormat(e)
        | DidError::WrongMethod(e)
        | DidError::Base58(e)
        | DidError::UidUnavailable(e)
        | DidError::Signing(e)
        | DidError::DkpPubkeyMissing(e) => ApiError::BadRequest(e),
        other => ApiError::BadRequest(other.to_string()),
    }
}

fn did_document_verify_failure(err: DidError) -> ApiError {
    match err {
        DidError::Io(e) => ApiError::Internal(format!("did document verify I/O failed: {}", e)),
        DidError::Json(e) => ApiError::BadRequest(format!("invalid DID document JSON: {}", e)),
        DidError::InvalidFormat(e)
        | DidError::WrongMethod(e)
        | DidError::Base58(e)
        | DidError::UidUnavailable(e)
        | DidError::Signing(e)
        | DidError::DkpPubkeyMissing(e) => ApiError::BadRequest(e),
        other => ApiError::BadRequest(other.to_string()),
    }
}

fn did_document_publish_error(err: DidError) -> ApiError {
    match err {
        DidError::Io(e) => ApiError::Internal(format!("did document publish failed: {}", e)),
        DidError::Json(e) => ApiError::BadRequest(format!("invalid DID document JSON: {}", e)),
        DidError::InvalidFormat(e)
        | DidError::WrongMethod(e)
        | DidError::Base58(e)
        | DidError::UidUnavailable(e)
        | DidError::Signing(e)
        | DidError::DkpPubkeyMissing(e) => ApiError::BadRequest(e),
        other => ApiError::BadRequest(other.to_string()),
    }
}

fn did_document_listing_error(err: DidError) -> ApiError {
    match err {
        DidError::Io(e) => ApiError::Internal(format!("peer did document listing failed: {}", e)),
        other => ApiError::Internal(other.to_string()),
    }
}

fn did_peer_load_error(err: DidError, did: &did::Did) -> ApiError {
    match err {
        DidError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let path = doc_persistence::configured_peers_doc_dir()
                .join(format!("did_doc_{}.json", did.msi()));
            ApiError::NotFound(format!("peer did document not found at {}", path.display()))
        }
        other => ApiError::Internal(format!("peer did document load failed: {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::persistence::{DerivationProof, DidRecord};
    use axum::extract::State;
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use once_cell::sync::Lazy;
    use std::ffi::OsString;
    use tokio::sync::Mutex;

    static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct EnvGuard {
        did_prev: Option<OsString>,
        dkp_prev: Option<OsString>,
    }

    impl EnvGuard {
        fn new(did_path: &str, dkp_path: &str) -> Self {
            let did_prev = std::env::var_os(DID_PATH_ENV);
            let dkp_prev = std::env::var_os(DKP_PUBKEY_PATH_ENV);
            std::env::set_var(DID_PATH_ENV, did_path);
            std::env::set_var(DKP_PUBKEY_PATH_ENV, dkp_path);
            Self { did_prev, dkp_prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            restore_env(DID_PATH_ENV, self.did_prev.take());
            restore_env(DKP_PUBKEY_PATH_ENV, self.dkp_prev.take());
        }
    }

    fn restore_env(key: &str, value: Option<OsString>) {
        if let Some(v) = value {
            std::env::set_var(key, v);
        } else {
            std::env::remove_var(key);
        }
    }

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            node_id: "nodeA".into(),
            config_dir: "/tmp/config".into(),
            boot_dir: "/tmp/boot".into(),
            keys_dir: "/tmp/keys".into(),
            pcr_dir: "/tmp/pcr".into(),
            pcr_baseline_dir: "/tmp".into(),
            log_dir_primary: "/tmp/logs".into(),
            log_dir_fallback: "/tmp/logs2".into(),
            did_resolver: crate::did::Resolver::new(Default::default()),
            vid_cache: crate::virtual_id_cache::VirtualIdCache::new(),
            discovery_config_dir: "/tmp/discovery-config".into(),
            discovery_state_dir: "/tmp/discovery-state".into(),
            threat_config_path: "/tmp/threat-config.yaml".into(),
            threat_state_dir: "/tmp/threat-state".into(),
        })
    }

    fn seed_did(path: &str, deactivated: Option<String>) {
        let did = crate::did::Did::from_id_bytes(&[1u8; 32]);
        let rec = DidRecord {
            did: did.as_str().to_string(),
            method: "guardian".into(),
            method_version: "1.0".into(),
            did_id_b58: did.msi().to_string(),
            did_id_hex: "01".repeat(32),
            created_at: "2026-04-26T10:00:00Z".into(),
            deactivated_at: deactivated,
            derivation: DerivationProof {
                se050_uid: "fixture-uid".into(),
                se050_uid_source: "fallback".into(),
                dkp_v1_pubkey_sha256_b16: "ab".repeat(32),
                dkp_v1_pubkey_path: "/tmp/dkp_pub.der".into(),
                dkp_v1_pubkey_der_b64: None,
                dik_pubkey_sha256_b16: "cd".repeat(32),
                dik_pubkey_der_b64: Some(general_purpose::STANDARD.encode([1u8; 64])),
            },
            current_dkp_version: 3,
            deriv_signature_b64: "Zm9v".into(),
        };
        rec.save(path).expect("save did");
    }

    #[tokio::test]
    async fn did_status_route_returns_expected_fields() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let did_path = tmp.path().join("identity").join("did.json");
        let dkp_path = tmp.path().join("keys").join("dkp_pub.der");
        let _env = EnvGuard::new(&did_path.to_string_lossy(), &dkp_path.to_string_lossy());
        seed_did(&did_path.to_string_lossy(), None);

        let Json(resp) = super::status(State(test_state())).await.expect("status");
        assert_eq!(resp.status, "active");
        assert_eq!(resp.method, "guardian");
        assert_eq!(resp.current_dkp_version, 3);
    }

    #[tokio::test]
    async fn did_resolve_marks_deactivated_record() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let did_path = tmp.path().join("identity").join("did.json");
        let dkp_path = tmp.path().join("keys").join("dkp_pub.der");
        let _env = EnvGuard::new(&did_path.to_string_lossy(), &dkp_path.to_string_lossy());
        seed_did(
            &did_path.to_string_lossy(),
            Some("2026-05-21T09:00:00Z".into()),
        );

        let Json(resp) = super::resolve(State(test_state()), Query(ResolveQuery::default()))
            .await
            .expect("resolve");
        match resp {
            DidResolveEnvelope::Local(resp) => {
                assert_eq!(resp.status, "DEACTIVATED");
                assert_eq!(resp.public_key_bytes, 64);
            }
            DidResolveEnvelope::Peer(_) => panic!("expected local resolve response"),
        }
    }

    #[tokio::test]
    async fn did_deactivate_requires_confirm_true() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let did_path = tmp.path().join("identity").join("did.json");
        let dkp_path = tmp.path().join("keys").join("dkp_pub.der");
        let _env = EnvGuard::new(&did_path.to_string_lossy(), &dkp_path.to_string_lossy());
        seed_did(&did_path.to_string_lossy(), None);

        let err = super::deactivate(
            State(test_state()),
            Json(DeactivateRequest {
                reason: Some("manual-admin".into()),
                confirm: false,
            }),
        )
        .await
        .expect_err("confirm rejection expected");

        let response = axum::response::IntoResponse::into_response(err);
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn did_deactivate_returns_restart_required() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let did_path = tmp.path().join("identity").join("did.json");
        let dkp_path = tmp.path().join("keys").join("dkp_pub.der");
        let _env = EnvGuard::new(&did_path.to_string_lossy(), &dkp_path.to_string_lossy());
        seed_did(&did_path.to_string_lossy(), None);

        let Json(resp) = super::deactivate(
            State(test_state()),
            Json(DeactivateRequest {
                reason: Some("manual-admin".into()),
                confirm: true,
            }),
        )
        .await
        .expect("deactivate");

        assert!(resp.ok);
        assert!(resp.restart_required);
    }
}
