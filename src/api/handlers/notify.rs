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

#[derive(Debug, Serialize)]
pub struct UnreadCountResponse {
    pub unread: usize,
}

#[derive(Debug, Serialize)]
pub struct MarkReadResponse {
    pub updated: bool,
    pub unread: usize,
}

#[derive(Debug, Serialize)]
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
