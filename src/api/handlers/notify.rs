use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::notify;
use crate::notify::prefs::NotificationPrefs;
use axum::Extension;
use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[derive(Debug, Deserialize, Default)]
pub struct HistoryQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnreadCountResponse {
    pub unread: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MarkReadResponse {
    pub updated: bool,
    pub unread: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MarkAllReadResponse {
    pub marked: usize,
    pub unread: usize,
}

#[derive(Debug, Deserialize, Default)]
pub struct NotificationPrefsPatch {
    pub alerts: Option<AlertPrefsPatch>,
    pub devices: Option<DevicePrefsPatch>,
    pub circles: Option<CirclePrefsPatch>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AlertPrefsPatch {
    pub high: Option<bool>,
    pub medium: Option<bool>,
    pub low: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DevicePrefsPatch {
    pub new_device: Option<bool>,
    pub pending_approval: Option<bool>,
    pub guardian_offline: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct CirclePrefsPatch {
    pub new_message: Option<bool>,
    pub incoming_call: Option<bool>,
    pub member_joined: Option<bool>,
}

pub async fn stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<axum::response::Response, ApiError> {
    let member_session = is_member_session(&session);
    let prefs = notify::load_or_create_prefs(&state.node_id)
        .await
        .map_err(internal_notify)?;
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut replay = notify::replay_after(last_event_id.as_deref())
        .await
        .map_err(internal_notify)?;
    if member_session {
        replay.retain(member_notification_allowed);
    }
    let mut rx = notify::subscribe();
    let (tx, out_rx) = mpsc::channel(64);

    tokio::spawn(async move {
        let mut last_sent = last_event_id.as_deref().and_then(parse_event_id);

        if send_batch(&tx, &prefs, replay, &mut last_sent)
            .await
            .is_err()
        {
            return;
        }

        loop {
            match rx.recv().await {
                Ok(event) => {
                    if member_session && !member_notification_allowed(&event) {
                        continue;
                    }
                    if !prefs.allows(event.kind) {
                        continue;
                    }
                    if is_duplicate(&event.id, last_sent) {
                        continue;
                    }
                    if send_one(&tx, event, &mut last_sent).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let cursor = last_sent.map(|value| value.to_string());
                    match notify::replay_after(cursor.as_deref()).await {
                        Ok(mut events) => {
                            if member_session {
                                events.retain(member_notification_allowed);
                            }
                            if send_batch(&tx, &prefs, events, &mut last_sent)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!("notify stream replay recovery failed: {}", error);
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Ok(Sse::new(ReceiverStream::new(out_rx))
        .keep_alive(KeepAlive::default())
        .into_response())
}

pub async fn history(
    Query(query): Query<HistoryQuery>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<Vec<notify::model::NotificationEvent>>, ApiError> {
    let mut events = notify::history(query.limit)
        .await
        .map_err(internal_notify)?;
    if is_member_session(&session) {
        events.retain(member_notification_allowed);
    }
    Ok(Json(events))
}

pub async fn unread_count(
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<UnreadCountResponse>, ApiError> {
    let unread = if is_member_session(&session) {
        notify::history(None)
            .await
            .map_err(internal_notify)?
            .into_iter()
            .filter(|event| member_notification_allowed(event) && !event.read)
            .count()
    } else {
        notify::unread_count().await.map_err(internal_notify)?
    };
    Ok(Json(UnreadCountResponse { unread }))
}

pub async fn mark_read(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<MarkReadResponse>, ApiError> {
    if is_member_session(&session) {
        let allowed = notify::history(None)
            .await
            .map_err(internal_notify)?
            .into_iter()
            .any(|event| event.id == id && member_notification_allowed(&event));
        if !allowed {
            if let Some(Extension(session)) = session.as_ref() {
                crate::api::auth::authorization::audit_member_resource_denied(
                    &state.node_id,
                    &session.claims.sub,
                    "Circle notification",
                );
            }
            return Err(ApiError::Forbidden(
                "notification is outside member scope".into(),
            ));
        }
    }
    let (updated, unread) = notify::mark_read(&id).await.map_err(internal_notify)?;
    let unread = if is_member_session(&session) {
        member_unread_count().await?
    } else {
        unread
    };
    Ok(Json(MarkReadResponse { updated, unread }))
}

pub async fn mark_all_read(
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<MarkAllReadResponse>, ApiError> {
    if !is_member_session(&session) {
        let (marked, unread) = notify::mark_all_read().await.map_err(internal_notify)?;
        return Ok(Json(MarkAllReadResponse { marked, unread }));
    }

    let ids = notify::history(None)
        .await
        .map_err(internal_notify)?
        .into_iter()
        .filter(|event| member_notification_allowed(event) && !event.read)
        .map(|event| event.id)
        .collect::<Vec<_>>();
    for id in &ids {
        notify::mark_read(id).await.map_err(internal_notify)?;
    }
    Ok(Json(MarkAllReadResponse {
        marked: ids.len(),
        unread: 0,
    }))
}

pub async fn get_prefs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NotificationPrefs>, ApiError> {
    let prefs = notify::load_or_create_prefs(&state.node_id)
        .await
        .map_err(internal_notify)?;
    Ok(Json(prefs))
}

pub async fn put_prefs(
    State(state): State<Arc<AppState>>,
    Json(patch): Json<NotificationPrefsPatch>,
) -> Result<Json<NotificationPrefs>, ApiError> {
    let mut prefs = notify::load_or_create_prefs(&state.node_id)
        .await
        .map_err(internal_notify)?;
    apply_patch(&mut prefs, patch);
    prefs.sequence = prefs.sequence.saturating_add(1);
    let prefs = notify::save_prefs(&state.node_id, prefs)
        .await
        .map_err(internal_notify)?;

    log_audit(
        &state.node_id,
        AuditCategory::Notify,
        AuditSeverity::Info,
        AuditAction::Updated,
        "notification preferences updated",
    );

    Ok(Json(prefs))
}

fn apply_patch(prefs: &mut NotificationPrefs, patch: NotificationPrefsPatch) {
    if let Some(alerts) = patch.alerts {
        if let Some(value) = alerts.high {
            prefs.alerts.high = value;
        }
        if let Some(value) = alerts.medium {
            prefs.alerts.medium = value;
        }
        if let Some(value) = alerts.low {
            prefs.alerts.low = value;
        }
    }

    if let Some(devices) = patch.devices {
        if let Some(value) = devices.new_device {
            prefs.devices.new_device = value;
        }
        if let Some(value) = devices.pending_approval {
            prefs.devices.pending_approval = value;
        }
        if let Some(value) = devices.guardian_offline {
            prefs.devices.guardian_offline = value;
        }
    }

    if let Some(circles) = patch.circles {
        if let Some(value) = circles.new_message {
            prefs.circles.new_message = value;
        }
        if let Some(value) = circles.incoming_call {
            prefs.circles.incoming_call = value;
        }
        if let Some(value) = circles.member_joined {
            prefs.circles.member_joined = value;
        }
    }
}

fn is_member_session(session: &Option<Extension<AuthenticatedSession>>) -> bool {
    session
        .as_ref()
        .is_some_and(|Extension(session)| session.claims.role == "member")
}

fn member_notification_allowed(event: &notify::model::NotificationEvent) -> bool {
    event.kind.category() == notify::model::NotificationCategory::Circles
}

async fn member_unread_count() -> Result<usize, ApiError> {
    Ok(notify::history(None)
        .await
        .map_err(internal_notify)?
        .into_iter()
        .filter(|event| member_notification_allowed(event) && !event.read)
        .count())
}

async fn send_batch(
    tx: &mpsc::Sender<Result<Event, Infallible>>,
    prefs: &NotificationPrefs,
    events: Vec<notify::model::NotificationEvent>,
    last_sent: &mut Option<u64>,
) -> Result<(), ()> {
    for event in events {
        if !prefs.allows(event.kind) || is_duplicate(&event.id, *last_sent) {
            continue;
        }
        send_one(tx, event, last_sent).await?;
    }
    Ok(())
}

async fn send_one(
    tx: &mpsc::Sender<Result<Event, Infallible>>,
    event: notify::model::NotificationEvent,
    last_sent: &mut Option<u64>,
) -> Result<(), ()> {
    let serialized = serde_json::to_string(&event).map_err(|_| ())?;
    let sse = Event::default()
        .event("notification")
        .id(event.id.clone())
        .data(serialized);
    tx.send(Ok(sse)).await.map_err(|_| ())?;
    *last_sent = parse_event_id(&event.id).or(*last_sent);
    Ok(())
}

fn parse_event_id(value: &str) -> Option<u64> {
    value.parse::<u64>().ok()
}

fn is_duplicate(id: &str, last_sent: Option<u64>) -> bool {
    match (parse_event_id(id), last_sent) {
        (Some(id), Some(last_sent)) => id <= last_sent,
        _ => false,
    }
}

fn internal_notify(error: notify::errors::NotifyError) -> ApiError {
    ApiError::Internal(format!("notify: {}", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::routes::notify_router;
    use crate::did::doc_persistence;
    use crate::did::doc_sign;
    use crate::did::document::{DidDocument, DocBuildInput};
    use crate::did::{Did, DidRecord};
    use crate::key_manager::KeyManager;
    use crate::vc::issue::DEVICE_KEY_DIR_ENV;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;
    use tower::ServiceExt;

    static TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    /// Sets up a fully signed local DID document + prefs/notify storage in a
    /// tempdir, mirroring `crate::notify::tests::NotifyEnv`. Needed because
    /// `get_prefs`/`put_prefs`/`stream` sign and verify notification
    /// preferences against the node's own DID document.
    struct NotifyApiEnv {
        _guard: std::sync::MutexGuard<'static, ()>,
        _did_guard: std::sync::MutexGuard<'static, ()>,
        _td: TempDir,
        restore: Vec<(&'static str, Option<String>)>,
        node_id: String,
        state: Arc<AppState>,
    }

    impl NotifyApiEnv {
        fn new(node_id: &str, seed: u8) -> Self {
            let guard = TEST_ENV_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let did_guard = doc_persistence::lock_test_env();
            let td = TempDir::new().expect("notify api tempdir");
            let base = td.path();
            let notify_base = base.join("notify");
            let identity_dir = base.join("identity");
            let did_path = identity_dir.join("did.json");
            let self_doc_path = identity_dir.join("did_doc.json");
            let peers_dir = identity_dir.join("peers");
            let aggregate_path = identity_dir.join("circle_did_docs.json");
            let floor_path = identity_dir.join("self_version");
            let key_dir = base.join("keys");
            std::fs::create_dir_all(&peers_dir).expect("peers dir");
            std::fs::create_dir_all(&key_dir).expect("key dir");
            std::fs::create_dir_all(&notify_base).expect("notify dir");

            let restore = vec![
                (
                    "SGX_GUARDIAN_NOTIFY_BASE",
                    std::env::var("SGX_GUARDIAN_NOTIFY_BASE").ok(),
                ),
                (
                    "SGX_GUARDIAN_DID_PATH",
                    std::env::var("SGX_GUARDIAN_DID_PATH").ok(),
                ),
                (
                    doc_persistence::SELF_DOC_PATH_ENV,
                    std::env::var(doc_persistence::SELF_DOC_PATH_ENV).ok(),
                ),
                (
                    doc_persistence::PEERS_DOC_DIR_ENV,
                    std::env::var(doc_persistence::PEERS_DOC_DIR_ENV).ok(),
                ),
                (
                    doc_persistence::CA_AGGREGATE_PATH_ENV,
                    std::env::var(doc_persistence::CA_AGGREGATE_PATH_ENV).ok(),
                ),
                (
                    doc_persistence::VERSION_COUNTER_PATH_ENV,
                    std::env::var(doc_persistence::VERSION_COUNTER_PATH_ENV).ok(),
                ),
                (DEVICE_KEY_DIR_ENV, std::env::var(DEVICE_KEY_DIR_ENV).ok()),
            ];

            std::env::set_var("SGX_GUARDIAN_NOTIFY_BASE", &notify_base);
            std::env::set_var("SGX_GUARDIAN_DID_PATH", &did_path);
            std::env::set_var(doc_persistence::SELF_DOC_PATH_ENV, &self_doc_path);
            std::env::set_var(doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);
            std::env::set_var(doc_persistence::CA_AGGREGATE_PATH_ENV, &aggregate_path);
            std::env::set_var(doc_persistence::VERSION_COUNTER_PATH_ENV, &floor_path);
            std::env::set_var(DEVICE_KEY_DIR_ENV, &key_dir);

            let key_path = key_dir.join(format!("device_{}.key", node_id));
            let km =
                KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
            let pubkey = km.pubkey_der().expect("pubkey");
            let did = Did::from_id_bytes(&[seed; 32]);
            let did_str = did.to_string();
            let now = chrono::Utc::now().to_rfc3339();
            let record = DidRecord {
                did: did_str.clone(),
                method: "guardian".into(),
                method_version: "1.0".into(),
                did_id_b58: did.msi().to_string(),
                did_id_hex: hex::encode(did.id_bytes()),
                created_at: now.clone(),
                deactivated_at: None,
                derivation: crate::did::persistence::DerivationProof {
                    se050_uid: "01".into(),
                    se050_uid_source: "test".into(),
                    dkp_v1_pubkey_sha256_b16: "01".into(),
                    dkp_v1_pubkey_path: "test".into(),
                    dkp_v1_pubkey_der_b64: None,
                    dik_pubkey_sha256_b16: "01".into(),
                    dik_pubkey_der_b64: None,
                },
                current_dkp_version: 1,
                deriv_signature_b64: String::new(),
            };
            record
                .save(did_path.to_str().expect("did path"))
                .expect("save did record");

            let mut doc = DidDocument::build(DocBuildInput {
                did: &did_str,
                node_name: Some(node_id),
                current_dkp_version: 1,
                current_dkp_pubkey_der: &pubkey,
                overlay_ip_cidr: Some("127.0.0.1/32"),
                attestation_bind: None,
                cert_bootstrap_bind: None,
                revoked: vec![],
                previous_version_id: 0,
                created_at: Some(now),
                status: Some("active".into()),
            })
            .expect("build did doc");
            let vm_ref = doc.verification_method.first().expect("vm").id.clone();
            doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign did doc");
            doc_persistence::save_self(&doc).expect("save self doc");

            let config_dir = base.join("config");
            std::fs::create_dir_all(&config_dir).expect("config dir");
            let state = AppState::for_tests(base, node_id, config_dir.display().to_string());

            Self {
                _guard: guard,
                _did_guard: did_guard,
                _td: td,
                restore,
                node_id: node_id.to_string(),
                state,
            }
        }

        fn router(&self) -> axum::Router {
            notify_router().with_state(self.state.clone())
        }
    }

    impl Drop for NotifyApiEnv {
        fn drop(&mut self) {
            for (key, value) in self.restore.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[tokio::test]
    async fn history_route_returns_empty_list_by_default() {
        let env = NotifyApiEnv::new("nodeA", 1);
        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/notifications")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<notify::model::NotificationEvent> = serde_json::from_slice(&body).unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn history_route_returns_persisted_events() {
        let env = NotifyApiEnv::new("nodeA", 2);
        seed_persisted_event(
            "dev-hist-1",
            notify::model::NotificationKind::DevicePendingApproval,
        );

        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/notifications")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<notify::model::NotificationEvent> = serde_json::from_slice(&body).unwrap();
        assert!(events.iter().any(|event| event.id == "dev-hist-1"));
    }

    #[tokio::test]
    async fn history_route_rejects_malformed_query_param() {
        let env = NotifyApiEnv::new("nodeA", 3);
        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/notifications?limit=not-a-number")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unread_count_route_reflects_store_state() {
        let env = NotifyApiEnv::new("nodeA", 4);
        // `notify::publish_*` only broadcasts to the in-process bus; nothing in this test
        // environment runs `notify::spawn`'s persistence subscriber, so a bus publish alone
        // never reaches disk. Seed the store directly, like every other test in this file.
        seed_persisted_event(
            "dev-unread-1",
            notify::model::NotificationKind::DevicePendingApproval,
        );

        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/notifications/unread-count")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: UnreadCountResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed.unread >= 1);
    }

    /// Persists an event directly through the store (bypassing the bus,
    /// which has no synchronous "flush to disk" signal) so route tests have
    /// a deterministic on-disk event id to mark read.
    fn seed_persisted_event(id: &str, kind: notify::model::NotificationKind) {
        let path = notify::NotifyConfig::from_env().events_path();
        let mut store =
            notify::store::NotificationStore::load_from_path(&path, 100).unwrap_or_default();
        store.append(sample_event(id, kind), 100);
        store.save_atomic(&path).expect("seed event");
    }

    #[tokio::test]
    async fn mark_read_route_marks_existing_event() {
        let env = NotifyApiEnv::new("nodeA", 5);
        seed_persisted_event("mark-read-1", notify::model::NotificationKind::AlertLow);

        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/notifications/mark-read-1/read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: MarkReadResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed.updated);
        assert_eq!(parsed.unread, 0);
    }

    #[tokio::test]
    async fn mark_read_route_missing_id_reports_not_updated() {
        let env = NotifyApiEnv::new("nodeA", 13);

        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/notifications/does-not-exist/read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: MarkReadResponse = serde_json::from_slice(&body).unwrap();
        assert!(!parsed.updated);
    }

    #[tokio::test]
    async fn mark_all_read_route_returns_zero_when_store_empty() {
        let env = NotifyApiEnv::new("nodeA", 6);
        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/notifications/read-all")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: MarkAllReadResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.marked, 0);
        assert_eq!(parsed.unread, 0);
    }

    #[tokio::test]
    async fn get_prefs_route_auto_creates_signed_defaults() {
        let env = NotifyApiEnv::new("nodeA", 7);
        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/notifications/prefs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let prefs: NotificationPrefs = serde_json::from_slice(&body).unwrap();
        assert!(prefs.alerts.high);
        assert!(prefs.devices.new_device);
        assert!(prefs.circles.new_message);
    }

    #[tokio::test]
    async fn put_prefs_route_applies_partial_patch() {
        let env = NotifyApiEnv::new("nodeA", 8);
        let patch_body = serde_json::json!({
            "alerts": { "high": false },
            "circles": { "incoming_call": false }
        });

        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/notifications/prefs")
                    .header("content-type", "application/json")
                    .body(Body::from(patch_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let prefs: NotificationPrefs = serde_json::from_slice(&body).unwrap();
        assert!(!prefs.alerts.high);
        assert!(prefs.alerts.medium, "untouched fields keep their default");
        assert!(!prefs.circles.incoming_call);
        assert_eq!(prefs.sequence, 2, "sequence bumps on every save");
    }

    #[tokio::test]
    async fn put_prefs_route_rejects_malformed_json_body() {
        let env = NotifyApiEnv::new("nodeA", 9);
        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/notifications/prefs")
                    .header("content-type", "application/json")
                    .body(Body::from("{not valid json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn put_prefs_route_rejects_wrong_field_types() {
        let env = NotifyApiEnv::new("nodeA", 10);
        // `alerts.high` must be a bool; sending a string should be a
        // deserialization error, not a silently-accepted value.
        let bad_body = serde_json::json!({ "alerts": { "high": "not-a-bool" } });
        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/notifications/prefs")
                    .header("content-type", "application/json")
                    .body(Body::from(bad_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn put_prefs_route_rejects_missing_content_type() {
        let env = NotifyApiEnv::new("nodeA", 11);
        let patch_body = serde_json::json!({ "alerts": { "high": false } });
        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/notifications/prefs")
                    .body(Body::from(patch_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn stream_route_responds_with_event_stream_content_type() {
        let env = NotifyApiEnv::new("nodeA", 12);
        let response = env
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/notifications/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.contains("text/event-stream"));
    }

    #[test]
    fn apply_patch_updates_only_provided_fields() {
        let mut prefs = NotificationPrefs::default();
        apply_patch(
            &mut prefs,
            NotificationPrefsPatch {
                alerts: Some(AlertPrefsPatch {
                    high: Some(false),
                    medium: None,
                    low: None,
                }),
                devices: None,
                circles: None,
            },
        );
        assert!(!prefs.alerts.high);
        assert!(prefs.alerts.medium);
        assert!(prefs.alerts.low);
        assert!(prefs.devices.new_device);
        assert!(prefs.circles.new_message);
    }

    #[test]
    fn apply_patch_updates_devices_and_circles() {
        let mut prefs = NotificationPrefs::default();
        apply_patch(
            &mut prefs,
            NotificationPrefsPatch {
                alerts: None,
                devices: Some(DevicePrefsPatch {
                    new_device: Some(false),
                    pending_approval: None,
                    guardian_offline: Some(false),
                }),
                circles: Some(CirclePrefsPatch {
                    new_message: None,
                    incoming_call: Some(false),
                    member_joined: None,
                }),
            },
        );
        assert!(!prefs.devices.new_device);
        assert!(prefs.devices.pending_approval);
        assert!(!prefs.devices.guardian_offline);
        assert!(!prefs.circles.incoming_call);
        assert!(prefs.circles.member_joined);
    }

    #[test]
    fn apply_patch_with_empty_patch_changes_nothing() {
        let mut prefs = NotificationPrefs::default();
        let before = prefs.clone();
        apply_patch(&mut prefs, NotificationPrefsPatch::default());
        assert_eq!(prefs, before);
    }

    #[test]
    fn is_member_session_false_without_extension() {
        assert!(!is_member_session(&None));
    }

    #[test]
    fn member_notification_allowed_filters_by_category() {
        let circle_event = notify::model::NotificationEvent {
            id: "1".into(),
            kind: notify::model::NotificationKind::CircleNewMessage,
            title: "t".into(),
            body: "b".into(),
            severity: "info".into(),
            ref_id: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            read: false,
            actor_did: None,
        };
        let alert_event = notify::model::NotificationEvent {
            kind: notify::model::NotificationKind::AlertHigh,
            ..circle_event.clone()
        };
        assert!(member_notification_allowed(&circle_event));
        assert!(!member_notification_allowed(&alert_event));
    }

    #[test]
    fn parse_event_id_handles_numeric_and_non_numeric() {
        assert_eq!(parse_event_id("42"), Some(42));
        assert_eq!(parse_event_id("not-a-number"), None);
        assert_eq!(parse_event_id(""), None);
    }

    #[test]
    fn is_duplicate_detects_already_sent_ids() {
        assert!(is_duplicate("5", Some(5)));
        assert!(is_duplicate("3", Some(5)));
        assert!(!is_duplicate("6", Some(5)));
        // Non-numeric ids never count as duplicates.
        assert!(!is_duplicate("abc", Some(5)));
        assert!(!is_duplicate("5", None));
    }

    #[test]
    fn internal_notify_wraps_error_message() {
        let error = notify::errors::NotifyError::MissingSelfDocument;
        let mapped = internal_notify(error);
        assert!(matches!(mapped, ApiError::Internal(message) if message.contains("notify")));
    }

    #[tokio::test]
    async fn send_batch_skips_disallowed_and_duplicate_events() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut prefs = NotificationPrefs::default();
        prefs.alerts.low = false;
        let mut last_sent = Some(2);
        let events = vec![
            sample_event("1", notify::model::NotificationKind::AlertLow), // disallowed by prefs
            sample_event("2", notify::model::NotificationKind::AlertHigh), // duplicate (<= last_sent)
            sample_event("3", notify::model::NotificationKind::AlertHigh), // should send
        ];

        send_batch(&tx, &prefs, events, &mut last_sent)
            .await
            .expect("send batch");
        drop(tx);

        let mut received = Vec::new();
        while let Some(event) = rx.recv().await {
            received.push(event);
        }
        assert_eq!(received.len(), 1);
        assert_eq!(last_sent, Some(3));
    }

    fn sample_event(
        id: &str,
        kind: notify::model::NotificationKind,
    ) -> notify::model::NotificationEvent {
        notify::model::NotificationEvent {
            id: id.to_string(),
            kind,
            title: "sample".into(),
            body: "sample body".into(),
            severity: "info".into(),
            ref_id: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            read: false,
            actor_did: None,
        }
    }

    fn member_session(sub: &str) -> crate::api::auth::middleware::AuthenticatedSession {
        crate::api::auth::middleware::AuthenticatedSession {
            claims: crate::api::auth::session::Claims {
                sub: sub.to_string(),
                role: "member".to_string(),
                scopes: vec![],
                circle_ids: vec![],
                browser_registration_id: None,
                guardian_fingerprint: None,
                iss: "test".into(),
                iat: 0,
                exp: 0,
                jti: "jti".into(),
            },
            token: "test-token".into(),
        }
    }

    fn request_as_member(builder: axum::http::request::Builder, sub: &str) -> Request<Body> {
        let mut request = builder.body(Body::empty()).unwrap();
        request.extensions_mut().insert(member_session(sub));
        request
    }

    #[tokio::test]
    async fn history_route_filters_out_non_circle_events_for_a_member_session() {
        let env = NotifyApiEnv::new("nodeA", 14);
        seed_persisted_event("mem-hist-alert", notify::model::NotificationKind::AlertHigh);
        seed_persisted_event(
            "mem-hist-circle",
            notify::model::NotificationKind::CircleNewMessage,
        );

        let response = env
            .router()
            .oneshot(request_as_member(
                Request::builder().uri("/api/v1/notifications"),
                "member-1",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<notify::model::NotificationEvent> = serde_json::from_slice(&body).unwrap();
        assert!(events.iter().any(|event| event.id == "mem-hist-circle"));
        assert!(!events.iter().any(|event| event.id == "mem-hist-alert"));
    }

    #[tokio::test]
    async fn unread_count_route_counts_only_circle_events_for_a_member_session() {
        let env = NotifyApiEnv::new("nodeA", 15);
        seed_persisted_event(
            "mem-unread-alert",
            notify::model::NotificationKind::AlertHigh,
        );
        seed_persisted_event(
            "mem-unread-circle",
            notify::model::NotificationKind::CircleNewMessage,
        );

        let response = env
            .router()
            .oneshot(request_as_member(
                Request::builder().uri("/api/v1/notifications/unread-count"),
                "member-1",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: UnreadCountResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.unread, 1);
    }

    #[tokio::test]
    async fn mark_read_route_forbids_a_member_from_marking_an_out_of_scope_event() {
        let env = NotifyApiEnv::new("nodeA", 16);
        seed_persisted_event("mem-mark-alert", notify::model::NotificationKind::AlertHigh);

        let response = env
            .router()
            .oneshot(request_as_member(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/notifications/mem-mark-alert/read"),
                "member-1",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mark_read_route_allows_a_member_to_mark_an_in_scope_event() {
        let env = NotifyApiEnv::new("nodeA", 17);
        seed_persisted_event(
            "mem-mark-circle",
            notify::model::NotificationKind::CircleNewMessage,
        );

        let response = env
            .router()
            .oneshot(request_as_member(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/notifications/mem-mark-circle/read"),
                "member-1",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: MarkReadResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed.updated);
        assert_eq!(parsed.unread, 0);
    }

    #[tokio::test]
    async fn mark_all_read_route_only_marks_in_scope_events_for_a_member_session() {
        let env = NotifyApiEnv::new("nodeA", 18);
        seed_persisted_event("mem-all-alert", notify::model::NotificationKind::AlertHigh);
        seed_persisted_event(
            "mem-all-circle",
            notify::model::NotificationKind::CircleNewMessage,
        );

        let response = env
            .router()
            .oneshot(request_as_member(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/notifications/read-all"),
                "member-1",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: MarkAllReadResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.marked, 1, "only the circle event was in scope");
        assert_eq!(parsed.unread, 0);
    }
}
