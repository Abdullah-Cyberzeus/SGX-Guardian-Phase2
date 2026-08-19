pub mod bus;
pub mod errors;
pub mod model;
pub mod prefs;
pub mod store;

#[cfg(test)]
mod tests;

use crate::discovery::ConnectedDevice;
use crate::notify::errors::{NotifyError, NotifyResult};
use crate::notify::model::{NotificationEvent, NotificationKind};
use crate::notify::prefs::NotificationPrefs;
use crate::threat::threat_alert::{Severity, ThreatAlert};
use chrono::Utc;
use std::path::PathBuf;

pub use bus::{publish, subscribe};
pub use model::{NotificationCategory, NotificationKind as Kind};
pub use prefs::{AlertPrefs, CirclePrefs, DevicePrefs, NotificationPrefs as Prefs};

#[derive(Debug, Clone)]
pub struct NotifyConfig {
    pub base: PathBuf,
    pub max_events: usize,
}

impl NotifyConfig {
    pub fn from_env() -> Self {
        let base = std::env::var("SGX_GUARDIAN_NOTIFY_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/notify"));
        Self {
            base,
            max_events: store::configured_max_events(),
        }
    }

    pub fn events_path(&self) -> PathBuf {
        self.base.join("events.jsonl")
    }

    pub fn prefs_path(&self) -> PathBuf {
        self.base.join("prefs.json")
    }
}

pub fn spawn(node_id: String) {
    let config = NotifyConfig::from_env();
    let events_path = config.events_path();
    if let Err(error) = store::prime_store(&events_path, config.max_events) {
        tracing::warn!("notify store prime failed: {}", error);
    }

    tokio::spawn(async move {
        let mut rx = bus::subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let events_path = events_path.clone();
                    let max_events = config.max_events;
                    if let Err(error) = tokio::task::spawn_blocking(move || {
                        let _guard = store::NOTIFY_WRITE_LOCK
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let mut current =
                            store::NotificationStore::load_from_path(&events_path, max_events)?;
                        current.append(event, max_events);
                        current.save_atomic(&events_path)?;
                        Ok::<(), NotifyError>(())
                    })
                    .await
                    .map_err(|error| NotifyError::TaskJoin(error.to_string()))
                    .and_then(|result| result)
                    {
                        tracing::warn!("notify persist failed on {}: {}", node_id, error);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!("notify persistence lagged; dropped {} event(s)", skipped);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

pub fn publish_alert(node_id: &str, alert: &ThreatAlert) {
    let kind = match alert.severity {
        Severity::Critical | Severity::High => NotificationKind::AlertHigh,
        Severity::Medium => NotificationKind::AlertMedium,
        Severity::Low => NotificationKind::AlertLow,
        Severity::Info => return,
    };

    publish(build_event(
        kind,
        format!("Threat alert on {}", node_id),
        format!(
            "{} from {}:{} to {}:{} ({})",
            alert.signature,
            alert.src_ip,
            alert.src_port,
            alert.dst_ip,
            alert.dst_port,
            alert.category.as_str()
        ),
        alert.severity.as_str(),
        Some(alert.alert_id.clone()),
    ));
}

pub fn publish_device_discovered(device: &ConnectedDevice) {
    publish(build_event(
        NotificationKind::DeviceDiscovered,
        "New device discovered".to_string(),
        format!("{} appeared at {}", device_label(device), device.ip),
        "info",
        Some(device.device_id.clone()),
    ));
}

pub fn publish_device_pending_approval(device: &ConnectedDevice) {
    publish(build_event(
        NotificationKind::DevicePendingApproval,
        "Device pending approval".to_string(),
        format!(
            "{} is not yet approved for this Guardian",
            device_label(device)
        ),
        "medium",
        Some(device.device_id.clone()),
    ));
}

pub fn publish_guardian_offline(device: &ConnectedDevice) {
    publish(build_event(
        NotificationKind::GuardianOffline,
        "Guardian offline".to_string(),
        format!(
            "{} has not been seen since {}",
            device_label(device),
            device.last_seen
        ),
        "high",
        Some(device.device_id.clone()),
    ));
}

/// `actor_did` is whoever *caused* this event (the sender/caller/joiner) —
/// stamped on the event so the client that originated it can skip showing
/// itself its own notification (this bus has no per-client delivery
/// targeting; every connected client gets every event).
pub fn publish_circle_new_message(actor_did: &str, sender_label: &str, message_id: &str) {
    publish(NotificationEvent {
        actor_did: Some(actor_did.to_string()),
        ..build_event(
            NotificationKind::CircleNewMessage,
            "New message".to_string(),
            format!("New message from {}", sender_label),
            "info",
            Some(message_id.to_string()),
        )
    });
}

pub fn publish_circle_incoming_call(actor_did: &str, caller_label: &str, call_id: &str) {
    publish(NotificationEvent {
        actor_did: Some(actor_did.to_string()),
        ..build_event(
            NotificationKind::CircleIncomingCall,
            "Incoming call".to_string(),
            format!("{} is calling", caller_label),
            "medium",
            Some(call_id.to_string()),
        )
    });
}

pub fn publish_circle_member_joined(
    actor_did: &str,
    member_label: &str,
    circle_label: &str,
    circle_id: &str,
) {
    publish(NotificationEvent {
        actor_did: Some(actor_did.to_string()),
        ..build_event(
            NotificationKind::CircleMemberJoined,
            "Member joined".to_string(),
            format!("{} joined {}", member_label, circle_label),
            "info",
            Some(circle_id.to_string()),
        )
    });
}

pub fn publish_circle_file_shared(actor_did: &str, sender_label: &str, file_name: &str, vault_id: &str) {
    publish(NotificationEvent {
        actor_did: Some(actor_did.to_string()),
        ..build_event(
            NotificationKind::CircleFileShared,
            "File shared".to_string(),
            format!("{} shared \"{}\"", sender_label, file_name),
            "info",
            Some(vault_id.to_string()),
        )
    });
}

pub async fn history(limit: Option<usize>) -> NotifyResult<Vec<NotificationEvent>> {
    let config = NotifyConfig::from_env();
    tokio::task::spawn_blocking(move || {
        let store =
            store::NotificationStore::load_from_path(&config.events_path(), config.max_events)?;
        Ok(store.history(limit.unwrap_or(100).min(config.max_events.max(1))))
    })
    .await
    .map_err(|error| NotifyError::TaskJoin(error.to_string()))?
}

pub async fn replay_after(last_event_id: Option<&str>) -> NotifyResult<Vec<NotificationEvent>> {
    let Some(last_event_id) = last_event_id.map(str::to_string) else {
        return Ok(Vec::new());
    };

    let config = NotifyConfig::from_env();
    tokio::task::spawn_blocking(move || {
        let store =
            store::NotificationStore::load_from_path(&config.events_path(), config.max_events)?;
        Ok(store.replay_after(&last_event_id))
    })
    .await
    .map_err(|error| NotifyError::TaskJoin(error.to_string()))?
}

pub async fn unread_count() -> NotifyResult<usize> {
    let config = NotifyConfig::from_env();
    tokio::task::spawn_blocking(move || {
        let store =
            store::NotificationStore::load_from_path(&config.events_path(), config.max_events)?;
        Ok(store.unread_count())
    })
    .await
    .map_err(|error| NotifyError::TaskJoin(error.to_string()))?
}

pub async fn mark_read(id: &str) -> NotifyResult<(bool, usize)> {
    let id = id.to_string();
    let config = NotifyConfig::from_env();
    tokio::task::spawn_blocking(move || {
        let _guard = store::NOTIFY_WRITE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = config.events_path();
        let mut store = store::NotificationStore::load_from_path(&path, config.max_events)?;
        let updated = store.mark_read(&id);
        if updated {
            store.save_atomic(&path)?;
        }
        Ok((updated, store.unread_count()))
    })
    .await
    .map_err(|error| NotifyError::TaskJoin(error.to_string()))?
}

pub async fn mark_all_read() -> NotifyResult<(usize, usize)> {
    let config = NotifyConfig::from_env();
    tokio::task::spawn_blocking(move || {
        let _guard = store::NOTIFY_WRITE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = config.events_path();
        let mut store = store::NotificationStore::load_from_path(&path, config.max_events)?;
        let marked = store.mark_all_read();
        if marked > 0 {
            store.save_atomic(&path)?;
        }
        Ok((marked, store.unread_count()))
    })
    .await
    .map_err(|error| NotifyError::TaskJoin(error.to_string()))?
}

pub async fn load_or_create_prefs(node_id: &str) -> NotifyResult<NotificationPrefs> {
    let node_id = node_id.to_string();
    let config = NotifyConfig::from_env();
    tokio::task::spawn_blocking(move || {
        let _guard = store::NOTIFY_WRITE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = config.prefs_path();
        match prefs::NotificationPrefs::load_from_path(&path)? {
            Some(prefs) => Ok(prefs),
            None => {
                let prefs = prefs::NotificationPrefs::create_signed_default(&node_id)?;
                prefs.save_atomic(&path)?;
                Ok(prefs)
            }
        }
    })
    .await
    .map_err(|error| NotifyError::TaskJoin(error.to_string()))?
}

pub async fn save_prefs(
    node_id: &str,
    mut prefs: NotificationPrefs,
) -> NotifyResult<NotificationPrefs> {
    let node_id = node_id.to_string();
    let config = NotifyConfig::from_env();
    tokio::task::spawn_blocking(move || {
        let _guard = store::NOTIFY_WRITE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = config.prefs_path();
        prefs.sign_for_node(&node_id)?;
        prefs.save_atomic(&path)?;
        Ok(prefs)
    })
    .await
    .map_err(|error| NotifyError::TaskJoin(error.to_string()))?
}

fn build_event(
    kind: NotificationKind,
    title: impl Into<String>,
    body: impl Into<String>,
    severity: impl Into<String>,
    ref_id: Option<String>,
) -> NotificationEvent {
    NotificationEvent {
        id: store::next_event_id(),
        kind,
        title: title.into(),
        body: body.into(),
        severity: severity.into(),
        ref_id,
        created_at: Utc::now().to_rfc3339(),
        read: false,
        actor_did: None,
    }
}

fn device_label(device: &ConnectedDevice) -> String {
    device
        .hostname
        .clone()
        .or_else(|| device.vendor.clone())
        .unwrap_or_else(|| device.device_id.clone())
}
