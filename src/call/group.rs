//! Group-call membership, moderation, audit logging, and event distribution.
//! Kept separate from one-to-one sessions so existing call behavior remains stable.

use crate::call::error::{CallError, CallResult};
use crate::call::signaling::MediaType;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

pub const MAX_GROUP_PARTICIPANTS: usize = 12;
pub const DEFAULT_GROUP_LOG_PATH: &str = "/var/log/sgx-guardian/group_calls.log";
pub const GROUP_HEARTBEAT_INTERVAL_SECS: i64 = 3;
pub const GROUP_DISCONNECTED_AFTER_SECS: i64 = 45;
pub const GROUP_RECONNECTING_AFTER_SECS: i64 = 20;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    Host,
    Member,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupMemberState {
    Invited,
    Joined,
    Reconnecting,
    Disconnected,
    Declined,
    Left,
    Kicked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupCallState {
    Ringing,
    Active,
    Ended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupParticipant {
    pub device_id: String,
    pub virtual_id: String,
    /// Empty for a browser member hosted on this same Guardian — see
    /// `is_local_browser`. Otherwise a Nebula overlay IP.
    pub nebula_ip: String,
    pub role: GroupRole,
    pub state: GroupMemberState,
    pub audio_allowed: bool,
    pub video_allowed: bool,
    pub media_ready: bool,
    pub joined_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_seen_at: Option<DateTime<Utc>>,
    /// True for a browser Circle member hosted on this same Guardian process.
    /// Such a participant has no Nebula identity at all — group-control
    /// delivery to them is in-process (they share this exact session store),
    /// never over Nebula, and their `device_id` (a DID) is already correct
    /// from the moment the invite is built, so it's exempt from the
    /// connection-address placeholder reconciliation device peers need (see
    /// `reconcile_participant_key`).
    #[serde(default)]
    pub is_local_browser: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupSession {
    pub group_id: String,
    pub title: String,
    pub host_device_id: String,
    pub requested_media: Vec<MediaType>,
    pub state: GroupCallState,
    pub participants: HashMap<String, GroupParticipant>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupEvent {
    pub event: String,
    pub session: GroupSession,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ModerationAction {
    Kick { device_id: String },
    SetAudio { device_id: String, allowed: bool },
    SetVideo { device_id: String, allowed: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GroupWireMessage {
    Invite { session: GroupSession },
    Join { group_id: String, device_id: String },
    Decline { group_id: String, device_id: String },
    Leave { group_id: String, device_id: String },
    End { group_id: String, device_id: String },
    Heartbeat { group_id: String, device_id: String },
    Snapshot { session: GroupSession },
}

#[derive(Debug, Serialize)]
struct GroupLogRecord<'a> {
    timestamp: DateTime<Utc>,
    event: &'a str,
    group_id: &'a str,
    actor: &'a str,
    target: Option<&'a str>,
    detail: &'a str,
}

/// The host cannot know an invitee's self-asserted `device_id` when it builds
/// the invite — it only knows them by the connection-address `peer_id` in its
/// trusted-peer registry (see `group_call.rs::create`), so a participant's map
/// entry may still be keyed by that placeholder instead of their real
/// device_id. Any lookup keyed by device_id must reconcile this first: match
/// the stale entry by Nebula IP, which is always reliably known, and re-key
/// it to the real device_id. A no-op once the entry is already correct.
fn reconcile_participant_key(session: &mut GroupSession, device_id: &str, nebula_ip: &str) {
    if device_id.is_empty() || nebula_ip.is_empty() || session.participants.contains_key(device_id)
    {
        return;
    }
    let stale_key = session
        .participants
        .iter()
        .find(|(key, participant)| key.as_str() != device_id && participant.nebula_ip == nebula_ip)
        .map(|(key, _)| key.clone());
    if let Some(stale_key) = stale_key {
        if let Some(mut participant) = session.participants.remove(&stale_key) {
            participant.device_id = device_id.to_string();
            session
                .participants
                .insert(device_id.to_string(), participant);
        }
    }
}

pub struct GroupSessionManager {
    sessions: RwLock<HashMap<String, GroupSession>>,
    events: broadcast::Sender<GroupEvent>,
    log_path: PathBuf,
    persistence_path: PathBuf,
    /// Same normalized, queryable history store direct calls persist to
    /// (`crate::call::history::CallHistoryStore`), so group calls show up
    /// alongside 1:1 calls instead of only in the append-only text log.
    history: std::sync::Arc<crate::call::history::CallHistoryStore>,
}

impl Default for GroupSessionManager {
    fn default() -> Self {
        Self::new(DEFAULT_GROUP_LOG_PATH)
    }
}

impl GroupSessionManager {
    pub fn new(log_path: impl Into<PathBuf>) -> Self {
        Self::with_history_store(
            log_path,
            std::sync::Arc::new(crate::call::history::CallHistoryStore::default()),
        )
    }

    pub fn with_history_store(
        log_path: impl Into<PathBuf>,
        history: std::sync::Arc<crate::call::history::CallHistoryStore>,
    ) -> Self {
        let (events, _) = broadcast::channel(512);
        let log_path = log_path.into();
        let persistence_path = log_path.with_extension("sessions.json");
        let mut sessions: HashMap<String, GroupSession> = std::fs::read(&persistence_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        // A crash can happen after the terminal snapshot is persisted but before
        // the handler removes it. Terminal calls must never come back as active
        // after a restart.
        sessions.retain(|_, session| session.state != GroupCallState::Ended);
        Self {
            sessions: RwLock::new(sessions),
            events,
            log_path,
            persistence_path,
            history,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GroupEvent> {
        self.events.subscribe()
    }

    pub async fn create(
        &self,
        title: String,
        host: GroupParticipant,
        invitees: Vec<GroupParticipant>,
        requested_media: Vec<MediaType>,
    ) -> CallResult<GroupSession> {
        if host.device_id.trim().is_empty() || requested_media.is_empty() {
            return Err(CallError::InvalidOffer {
                reason: "Group host and media are required".into(),
            });
        }
        if invitees.is_empty() || invitees.len() + 1 > MAX_GROUP_PARTICIPANTS {
            return Err(CallError::InvalidOffer {
                reason: format!(
                    "Group requires 2-{} total participants",
                    MAX_GROUP_PARTICIPANTS
                ),
            });
        }
        let now = Utc::now();
        let host_device_id = host.device_id.clone();
        let mut participants = HashMap::new();
        participants.insert(
            host.device_id.clone(),
            GroupParticipant {
                role: GroupRole::Host,
                state: GroupMemberState::Joined,
                joined_at: Some(now),
                last_seen_at: Some(now),
                ..host
            },
        );
        for invitee in invitees {
            if invitee.device_id == host_device_id
                || participants.contains_key(&invitee.device_id)
                || invitee.device_id.trim().is_empty()
                || (!invitee.is_local_browser
                    && invitee.nebula_ip.parse::<std::net::IpAddr>().is_err())
            {
                return Err(CallError::InvalidOffer {
                    reason: "Group contains duplicate or invalid participants".into(),
                });
            }
            participants.insert(
                invitee.device_id.clone(),
                GroupParticipant {
                    role: GroupRole::Member,
                    state: GroupMemberState::Invited,
                    joined_at: None,
                    last_seen_at: None,
                    ..invitee
                },
            );
        }
        let session = GroupSession {
            group_id: Uuid::new_v4().to_string(),
            title: if title.trim().is_empty() {
                "Guardian group call".into()
            } else {
                title
            },
            host_device_id: host_device_id.clone(),
            requested_media,
            state: GroupCallState::Ringing,
            participants,
            created_at: now,
            updated_at: now,
            ended_at: None,
        };
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.group_id.clone(), session.clone());
            self.persist(&sessions);
        }
        self.publish("group_created", &session);
        self.log(
            "group_created",
            &session.group_id,
            &host_device_id,
            None,
            "trusted members invited",
        );
        Ok(session)
    }

    pub async fn register_invite(
        &self,
        mut session: GroupSession,
        local_device_id: &str,
        local_nebula_ip: &str,
    ) -> CallResult<GroupSession> {
        reconcile_participant_key(&mut session, local_device_id, local_nebula_ip);
        let participant = session.participants.get(local_device_id).ok_or_else(|| {
            CallError::UnauthorizedDevice {
                reason: "Local node was not invited to this group".into(),
            }
        })?;
        if participant.state != GroupMemberState::Invited {
            return Err(CallError::InvalidOffer {
                reason: "Group invitation has an invalid member state".into(),
            });
        }
        {
            let mut sessions = self.sessions.write().await;
            // A newly generated group id from the same host supersedes that
            // host's older call for this participant. This also heals a missed
            // terminal snapshot without allowing an unrelated host to replace
            // a live call.
            sessions.retain(|group_id, existing| {
                group_id == &session.group_id
                    || existing.host_device_id != session.host_device_id
                    || !existing.participants.contains_key(local_device_id)
            });
            sessions.insert(session.group_id.clone(), session.clone());
            self.persist(&sessions);
        }
        self.publish("group_invited", &session);
        self.log(
            "group_invited",
            &session.group_id,
            &session.host_device_id,
            Some(local_device_id),
            "invitation received",
        );
        Ok(session)
    }

    pub async fn join(
        &self,
        group_id: &str,
        device_id: &str,
        sender_nebula_ip: &str,
    ) -> CallResult<GroupSession> {
        let session = self
            .update(group_id, "group_joined", |session| {
                reconcile_participant_key(session, device_id, sender_nebula_ip);
                let participant = session.participants.get_mut(device_id).ok_or_else(|| {
                    CallError::UnauthorizedDevice {
                        reason: "Device was not invited".into(),
                    }
                })?;
                if !matches!(
                    participant.state,
                    GroupMemberState::Invited
                        | GroupMemberState::Joined
                        | GroupMemberState::Reconnecting
                        | GroupMemberState::Disconnected
                        | GroupMemberState::Left
                ) {
                    return Err(CallError::InvalidOffer {
                        reason: "Invitation is no longer active".into(),
                    });
                }
                participant.state = GroupMemberState::Joined;
                participant.joined_at.get_or_insert_with(Utc::now);
                participant.last_seen_at = Some(Utc::now());
                participant.media_ready = false;
                session.state = GroupCallState::Active;
                Ok(())
            })
            .await?;
        self.log(
            "group_joined",
            group_id,
            device_id,
            Some(device_id),
            "member accepted invitation",
        );
        Ok(session)
    }

    pub async fn decline(
        &self,
        group_id: &str,
        device_id: &str,
        sender_nebula_ip: &str,
    ) -> CallResult<GroupSession> {
        let session = self
            .update(group_id, "group_declined", |session| {
                reconcile_participant_key(session, device_id, sender_nebula_ip);
                let participant = session.participants.get_mut(device_id).ok_or_else(|| {
                    CallError::UnauthorizedDevice {
                        reason: "Device was not invited".into(),
                    }
                })?;
                participant.state = GroupMemberState::Declined;
                Ok(())
            })
            .await?;
        self.log(
            "group_declined",
            group_id,
            device_id,
            Some(device_id),
            "member declined invitation",
        );
        Ok(session)
    }

    pub async fn leave(
        &self,
        group_id: &str,
        device_id: &str,
        sender_nebula_ip: &str,
    ) -> CallResult<GroupSession> {
        let session = self
            .update(group_id, "group_left", |session| {
                if device_id == session.host_device_id {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Host must end the group call".into(),
                    });
                }
                reconcile_participant_key(session, device_id, sender_nebula_ip);
                let participant = session.participants.get_mut(device_id).ok_or_else(|| {
                    CallError::UnauthorizedDevice {
                        reason: "Device is not a group member".into(),
                    }
                })?;
                participant.state = GroupMemberState::Left;
                participant.media_ready = false;
                participant.last_seen_at = Some(Utc::now());
                Ok(())
            })
            .await?;
        self.log(
            "group_left",
            group_id,
            device_id,
            Some(device_id),
            "member left",
        );
        Ok(session)
    }

    pub async fn moderate(
        &self,
        group_id: &str,
        actor: &str,
        action: ModerationAction,
    ) -> CallResult<GroupSession> {
        let target = match &action {
            ModerationAction::Kick { device_id }
            | ModerationAction::SetAudio { device_id, .. }
            | ModerationAction::SetVideo { device_id, .. } => device_id.clone(),
        };
        let session = self
            .update(group_id, "group_moderated", |session| {
                if session.host_device_id != actor {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Only the group host can moderate members".into(),
                    });
                }
                if target == session.host_device_id {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Host cannot moderate itself".into(),
                    });
                }
                let participant = session.participants.get_mut(&target).ok_or_else(|| {
                    CallError::UnauthorizedDevice {
                        reason: "Moderation target is not a group member".into(),
                    }
                })?;
                match action {
                    ModerationAction::Kick { .. } => {
                        participant.state = GroupMemberState::Kicked;
                        participant.media_ready = false;
                    }
                    ModerationAction::SetAudio { allowed, .. } => {
                        participant.audio_allowed = allowed
                    }
                    ModerationAction::SetVideo { allowed, .. } => {
                        participant.video_allowed = allowed
                    }
                }
                Ok(())
            })
            .await?;
        self.log(
            "group_moderated",
            group_id,
            actor,
            Some(&target),
            "host moderation applied",
        );
        Ok(session)
    }

    pub async fn mark_media_ready(
        &self,
        group_id: &str,
        device_id: &str,
        ready: bool,
        sender_nebula_ip: &str,
    ) -> CallResult<GroupSession> {
        let session = self
            .update(group_id, "group_media_ready", |session| {
                reconcile_participant_key(session, device_id, sender_nebula_ip);
                let participant = session.participants.get_mut(device_id).ok_or_else(|| {
                    CallError::UnauthorizedDevice {
                        reason: "Device is not a group member".into(),
                    }
                })?;
                if participant.state != GroupMemberState::Joined {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Only joined members can publish media".into(),
                    });
                }
                participant.media_ready = ready;
                participant.last_seen_at = Some(Utc::now());
                Ok(())
            })
            .await?;
        self.log(
            "group_media_ready",
            group_id,
            device_id,
            Some(device_id),
            if ready {
                "media connected"
            } else {
                "media disconnected"
            },
        );
        Ok(session)
    }

    pub async fn apply_snapshot(
        &self,
        mut incoming: GroupSession,
        local_device_id: &str,
        local_nebula_ip: &str,
    ) -> CallResult<GroupSession> {
        reconcile_participant_key(&mut incoming, local_device_id, local_nebula_ip);
        if !incoming.participants.contains_key(local_device_id) {
            return Err(CallError::UnauthorizedDevice {
                reason: "Local node is absent from group snapshot".into(),
            });
        }
        let mut sessions = self.sessions.write().await;
        if let Some(existing) = sessions.get(&incoming.group_id) {
            if existing.host_device_id != incoming.host_device_id
                || incoming.updated_at < existing.updated_at
            {
                return Err(CallError::InvalidOffer {
                    reason: "Stale or conflicting group snapshot".into(),
                });
            }
        }
        if incoming.state == GroupCallState::Ended {
            sessions.remove(&incoming.group_id);
        } else {
            sessions.insert(incoming.group_id.clone(), incoming.clone());
        }
        self.persist(&sessions);
        drop(sessions);
        self.publish("group_updated", &incoming);
        self.log(
            "group_updated",
            &incoming.group_id,
            &incoming.host_device_id,
            Some(local_device_id),
            "membership snapshot applied",
        );
        Ok(incoming)
    }

    /// Forget a terminal session after its final snapshot has been sent.
    pub async fn remove_ended(&self, group_id: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions
            .get(group_id)
            .is_some_and(|session| session.state == GroupCallState::Ended)
        {
            sessions.remove(group_id);
            self.persist(&sessions);
        }
    }

    pub async fn end(&self, group_id: &str, actor: &str) -> CallResult<GroupSession> {
        let session = self
            .update(group_id, "group_ended", |session| {
                let participant = session.participants.get(actor).ok_or_else(|| {
                    CallError::UnauthorizedDevice {
                        reason: "Only a group participant can end this call".into(),
                    }
                })?;
                if !matches!(
                    participant.state,
                    GroupMemberState::Joined
                        | GroupMemberState::Reconnecting
                        | GroupMemberState::Disconnected
                ) {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Only active group participants can end this call".into(),
                    });
                }
                session.state = GroupCallState::Ended;
                session.ended_at = Some(Utc::now());
                Ok(())
            })
            .await?;
        self.log(
            "group_ended",
            group_id,
            actor,
            None,
            "participant ended group call for everyone",
        );
        self.history.record_group(&session);
        Ok(session)
    }

    pub async fn get(&self, group_id: &str) -> CallResult<GroupSession> {
        self.sessions
            .read()
            .await
            .get(group_id)
            .cloned()
            .ok_or_else(|| CallError::SessionNotFound {
                session_id: group_id.into(),
            })
    }

    pub async fn active_for(&self, device_id: &str) -> Vec<GroupSession> {
        let mut active: Vec<_> = self
            .sessions
            .read()
            .await
            .values()
            .filter(|session| {
                session.state != GroupCallState::Ended
                    && session
                        .participants
                        .get(device_id)
                        .is_some_and(|participant| {
                            !matches!(
                                participant.state,
                                GroupMemberState::Declined
                                    | GroupMemberState::Left
                                    | GroupMemberState::Kicked
                            )
                        })
            })
            .cloned()
            .collect();
        // Consumers display the first active call. HashMap iteration order is
        // undefined, so always return the newest session first.
        active.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.group_id.cmp(&left.group_id))
        });
        active
    }

    /// Record liveness and restore a temporarily disconnected participant.
    /// Explicitly kicked or declined participants can never use heartbeat to rejoin.
    pub async fn heartbeat(
        &self,
        group_id: &str,
        device_id: &str,
        sender_nebula_ip: &str,
    ) -> CallResult<GroupSession> {
        self.update(group_id, "group_heartbeat", |session| {
            reconcile_participant_key(session, device_id, sender_nebula_ip);
            let participant = session.participants.get_mut(device_id).ok_or_else(|| {
                CallError::UnauthorizedDevice {
                    reason: "Device is not a group member".into(),
                }
            })?;
            if matches!(
                participant.state,
                GroupMemberState::Kicked | GroupMemberState::Declined
            ) {
                return Err(CallError::UnauthorizedDevice {
                    reason: "Participant is not allowed to rejoin".into(),
                });
            }
            participant.last_seen_at = Some(Utc::now());
            if matches!(
                participant.state,
                GroupMemberState::Disconnected | GroupMemberState::Reconnecting
            ) {
                participant.state = GroupMemberState::Joined;
            }
            Ok(())
        })
        .await
    }

    /// Host-side timeout processing. Returns changed snapshots for propagation.
    pub async fn expire_stale_for_host(&self, host_device_id: &str) -> Vec<GroupSession> {
        let now = Utc::now();
        let reconnecting_cutoff = now - Duration::seconds(GROUP_RECONNECTING_AFTER_SECS);
        let disconnected_cutoff = now - Duration::seconds(GROUP_DISCONNECTED_AFTER_SECS);
        let mut changed = Vec::new();
        let mut sessions = self.sessions.write().await;
        for session in sessions.values_mut().filter(|session| {
            session.host_device_id == host_device_id && session.state != GroupCallState::Ended
        }) {
            let mut session_changed = false;
            for participant in session.participants.values_mut() {
                if !matches!(
                    participant.state,
                    GroupMemberState::Joined | GroupMemberState::Reconnecting
                ) {
                    continue;
                }
                let last_seen = participant
                    .last_seen_at
                    .or(participant.joined_at)
                    .unwrap_or(session.updated_at);
                let next = if last_seen <= disconnected_cutoff {
                    Some(GroupMemberState::Disconnected)
                } else if last_seen <= reconnecting_cutoff
                    && participant.state == GroupMemberState::Joined
                {
                    Some(GroupMemberState::Reconnecting)
                } else {
                    None
                };
                if let Some(next) = next {
                    participant.state = next;
                    participant.media_ready = false;
                    session_changed = true;
                }
            }
            if session_changed {
                session.updated_at = now;
                changed.push(session.clone());
            }
        }
        if !changed.is_empty() {
            self.persist(&sessions);
        }
        drop(sessions);
        for session in &changed {
            self.publish("group_presence_changed", session);
        }
        changed
    }

    async fn update(
        &self,
        group_id: &str,
        event: &str,
        apply: impl FnOnce(&mut GroupSession) -> CallResult<()>,
    ) -> CallResult<GroupSession> {
        let snapshot = {
            let mut sessions = self.sessions.write().await;
            let session = sessions
                .get_mut(group_id)
                .ok_or_else(|| CallError::SessionNotFound {
                    session_id: group_id.into(),
                })?;
            if session.state == GroupCallState::Ended {
                return Err(CallError::InvalidOffer {
                    reason: "Group call already ended".into(),
                });
            }
            apply(session)?;
            session.updated_at = Utc::now();
            let snapshot = session.clone();
            self.persist(&sessions);
            snapshot
        };
        self.publish(event, &snapshot);
        Ok(snapshot)
    }

    fn publish(&self, event: &str, session: &GroupSession) {
        let _ = self.events.send(GroupEvent {
            event: event.into(),
            session: session.clone(),
        });
    }

    fn log(&self, event: &str, group_id: &str, actor: &str, target: Option<&str>, detail: &str) {
        if let Some(parent) = self.log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let record = GroupLogRecord {
            timestamp: Utc::now(),
            event,
            group_id,
            actor,
            target,
            detail,
        };
        if let Ok(line) = serde_json::to_string(&record) {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
            {
                let _ = writeln!(file, "{}", line);
            }
        }
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    fn persist(&self, sessions: &HashMap<String, GroupSession>) {
        let Some(parent) = self.persistence_path.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let temporary = self.persistence_path.with_extension("json.tmp");
        let Ok(bytes) = serde_json::to_vec_pretty(sessions) else {
            return;
        };
        if std::fs::write(&temporary, bytes).is_ok() {
            let _ = std::fs::rename(temporary, &self.persistence_path);
        }
    }

    pub fn record_log(
        &self,
        event: &str,
        group_id: &str,
        actor: &str,
        target: Option<&str>,
        detail: &str,
    ) {
        self.log(event, group_id, actor, target, detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn participant(device_id: &str, role: GroupRole) -> GroupParticipant {
        GroupParticipant {
            device_id: device_id.into(),
            virtual_id: format!("vid-{device_id}"),
            nebula_ip: if device_id == "nodeA" {
                "192.168.100.1".into()
            } else {
                "192.168.100.2".into()
            },
            role,
            state: GroupMemberState::Invited,
            audio_allowed: true,
            video_allowed: true,
            media_ready: false,
            joined_at: None,
            last_seen_at: None,
            is_local_browser: false,
        }
    }

    /// Reproduces the real bug: the host cannot know an invitee's
    /// self-asserted device_id when building the invite (it only knows them
    /// by the connection-address `peer_id` from its trusted-peer registry —
    /// see `group_call.rs::create`), so the participant map is keyed by that
    /// placeholder, not "nodeB". Both the invitee reconciling its own entry
    /// (`register_invite`) and the host reconciling the sender's entry when
    /// it later receives a Join must recover from this via Nebula IP.
    fn invitee_with_placeholder_key(nebula_ip: &str) -> GroupParticipant {
        GroupParticipant {
            device_id: format!("{nebula_ip}:50152"), // what group_call.rs::create currently does
            virtual_id: "vid-nodeb".into(),
            nebula_ip: nebula_ip.into(),
            role: GroupRole::Member,
            state: GroupMemberState::Invited,
            audio_allowed: true,
            video_allowed: true,
            media_ready: false,
            joined_at: None,
            last_seen_at: None,
            is_local_browser: false,
        }
    }

    #[tokio::test]
    async fn invitee_reconciles_placeholder_keyed_invite_to_its_real_device_id() {
        let dir = tempdir().unwrap();
        let host_manager = GroupSessionManager::new(dir.path().join("host.log"));
        let invite = host_manager
            .create(
                "Ops".into(),
                participant("nodeA", GroupRole::Host),
                vec![invitee_with_placeholder_key("192.168.100.2")],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        assert!(!invite.participants.contains_key("nodeB"));

        let receiver_manager = GroupSessionManager::new(dir.path().join("receiver.log"));
        let registered = receiver_manager
            .register_invite(invite, "nodeB", "192.168.100.2")
            .await
            .unwrap();
        assert!(registered.participants.contains_key("nodeB"));
        assert_eq!(registered.participants["nodeB"].device_id, "nodeB");
    }

    #[tokio::test]
    async fn host_reconciles_placeholder_keyed_participant_when_it_joins() {
        let dir = tempdir().unwrap();
        let manager = GroupSessionManager::new(dir.path().join("group.log"));
        let created = manager
            .create(
                "Ops".into(),
                participant("nodeA", GroupRole::Host),
                vec![invitee_with_placeholder_key("192.168.100.2")],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        assert!(!created.participants.contains_key("nodeB"));

        // Mirrors what process_group_control does: nodeB's Join arrives over
        // Nebula from 192.168.100.2, which is nodeB's real, unspoofable IP.
        let joined = manager
            .join(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .unwrap();
        assert_eq!(joined.participants["nodeB"].state, GroupMemberState::Joined);
        assert_eq!(joined.participants.len(), 2);
    }

    #[tokio::test]
    async fn host_can_create_join_moderate_and_end() {
        let dir = tempdir().unwrap();
        let manager = GroupSessionManager::new(dir.path().join("group.log"));
        let created = manager
            .create(
                "Ops".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio, MediaType::Video],
            )
            .await
            .unwrap();
        let joined = manager
            .join(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .unwrap();
        assert_eq!(joined.state, GroupCallState::Active);
        let muted = manager
            .moderate(
                &created.group_id,
                "nodeA",
                ModerationAction::SetAudio {
                    device_id: "nodeB".into(),
                    allowed: false,
                },
            )
            .await
            .unwrap();
        assert!(!muted.participants["nodeB"].audio_allowed);
        assert!(manager
            .moderate(
                &created.group_id,
                "nodeB",
                ModerationAction::Kick {
                    device_id: "nodeA".into()
                }
            )
            .await
            .is_err());
        assert_eq!(
            manager.end(&created.group_id, "nodeA").await.unwrap().state,
            GroupCallState::Ended
        );
        assert!(std::fs::read_to_string(manager.log_path())
            .unwrap()
            .contains("group_created"));
    }

    #[tokio::test]
    async fn ended_group_call_is_persisted_to_normalized_history() {
        let dir = tempdir().unwrap();
        let history = std::sync::Arc::new(crate::call::history::CallHistoryStore::new(
            dir.path().join("call_history.json"),
        ));
        let manager =
            GroupSessionManager::with_history_store(dir.path().join("group.log"), history.clone());
        let created = manager
            .create(
                "Ops".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        manager
            .join(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .unwrap();
        manager.end(&created.group_id, "nodeA").await.unwrap();

        let records = history.list();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, created.group_id);
        assert_eq!(records[0].kind, "group");
        assert_eq!(records[0].outcome, "completed");
        assert_eq!(records[0].participant_ids, vec!["nodeA", "nodeB"]);
    }

    #[tokio::test]
    async fn joined_member_can_end_group_call_for_everyone() {
        let dir = tempdir().unwrap();
        let manager = GroupSessionManager::new(dir.path().join("member-end.log"));
        let created = manager
            .create(
                "Member-ended room".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        manager
            .join(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .unwrap();

        let ended = manager.end(&created.group_id, "nodeB").await.unwrap();

        assert_eq!(ended.state, GroupCallState::Ended);
        assert!(manager.active_for("nodeA").await.is_empty());
        assert!(manager.active_for("nodeB").await.is_empty());
    }

    #[tokio::test]
    async fn group_call_nobody_joined_is_recorded_as_cancelled() {
        let dir = tempdir().unwrap();
        let history = std::sync::Arc::new(crate::call::history::CallHistoryStore::new(
            dir.path().join("call_history.json"),
        ));
        let manager =
            GroupSessionManager::with_history_store(dir.path().join("group.log"), history.clone());
        let created = manager
            .create(
                "Ops".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        manager.end(&created.group_id, "nodeA").await.unwrap();

        let records = history.list();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, "cancelled");
        assert_eq!(records[0].participant_ids, vec!["nodeA"]);
    }

    #[tokio::test]
    async fn invitation_rejects_unlisted_local_node() {
        let dir = tempdir().unwrap();
        let host_manager = GroupSessionManager::new(dir.path().join("host.log"));
        let receiver_manager = GroupSessionManager::new(dir.path().join("receiver.log"));
        let session = host_manager
            .create(
                "Trusted room".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        assert!(receiver_manager
            .register_invite(session.clone(), "nodeC", "192.168.100.3")
            .await
            .is_err());
        assert!(receiver_manager
            .register_invite(session, "nodeB", "192.168.100.2")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn newer_invite_from_same_host_replaces_old_session() {
        let dir = tempdir().unwrap();
        let host_manager = GroupSessionManager::new(dir.path().join("host.log"));
        let receiver_manager = GroupSessionManager::new(dir.path().join("receiver.log"));
        let old = host_manager
            .create(
                "Old room".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        receiver_manager
            .register_invite(old.clone(), "nodeB", "192.168.100.2")
            .await
            .unwrap();

        let replacement = host_manager
            .create(
                "New room".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        receiver_manager
            .register_invite(replacement.clone(), "nodeB", "192.168.100.2")
            .await
            .unwrap();

        assert!(receiver_manager.get(&old.group_id).await.is_err());
        let active = receiver_manager.active_for("nodeB").await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].group_id, replacement.group_id);
    }

    #[tokio::test]
    async fn ended_session_is_not_restored_from_persistence() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("terminal.log");
        let manager = GroupSessionManager::new(&log_path);
        let created = manager
            .create(
                "Finished room".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        manager.end(&created.group_id, "nodeA").await.unwrap();
        drop(manager);

        let restored = GroupSessionManager::new(&log_path);
        assert!(restored.active_for("nodeA").await.is_empty());
        assert!(restored.get(&created.group_id).await.is_err());
    }

    #[tokio::test]
    async fn stale_snapshot_cannot_replace_newer_membership() {
        let dir = tempdir().unwrap();
        let manager = GroupSessionManager::new(dir.path().join("group.log"));
        let created = manager
            .create(
                "Room".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        let stale = created.clone();
        manager
            .join(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .unwrap();
        assert!(manager
            .apply_snapshot(stale, "nodeA", "192.168.100.1")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn group_size_and_duplicate_members_fail_closed() {
        let dir = tempdir().unwrap();
        let manager = GroupSessionManager::new(dir.path().join("group.log"));
        assert!(manager
            .create(
                "Duplicate".into(),
                participant("nodeA", GroupRole::Host),
                vec![
                    participant("nodeB", GroupRole::Member),
                    participant("nodeB", GroupRole::Member),
                ],
                vec![MediaType::Audio],
            )
            .await
            .is_err());
        let too_many = (0..MAX_GROUP_PARTICIPANTS)
            .map(|index| GroupParticipant {
                device_id: format!("node-{index}"),
                virtual_id: format!("vid-{index}"),
                nebula_ip: format!("192.168.100.{}", index + 10),
                role: GroupRole::Member,
                state: GroupMemberState::Invited,
                audio_allowed: true,
                video_allowed: false,
                media_ready: false,
                joined_at: None,
                last_seen_at: None,
                is_local_browser: false,
            })
            .collect();
        assert!(manager
            .create(
                "Too large".into(),
                participant("nodeA", GroupRole::Host),
                too_many,
                vec![MediaType::Audio],
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn disconnected_and_left_members_can_rejoin_but_kicked_members_cannot() {
        let dir = tempdir().unwrap();
        let manager = GroupSessionManager::new(dir.path().join("rejoin.log"));
        let created = manager
            .create(
                "Recovery".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        manager
            .join(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .unwrap();
        manager
            .leave(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .unwrap();
        assert!(
            manager.active_for("nodeB").await.is_empty(),
            "a deliberately left session must not block a new call"
        );
        assert_eq!(
            manager
                .join(&created.group_id, "nodeB", "192.168.100.2")
                .await
                .unwrap()
                .participants["nodeB"]
                .state,
            GroupMemberState::Joined
        );
        manager
            .moderate(
                &created.group_id,
                "nodeA",
                ModerationAction::Kick {
                    device_id: "nodeB".into(),
                },
            )
            .await
            .unwrap();
        assert!(manager
            .join(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .is_err());
        assert!(manager
            .heartbeat(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn stale_members_disconnect_and_persisted_sessions_restore() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("persistent.log");
        let manager = GroupSessionManager::new(&log_path);
        let created = manager
            .create(
                "Persistent".into(),
                participant("nodeA", GroupRole::Host),
                vec![participant("nodeB", GroupRole::Member)],
                vec![MediaType::Audio],
            )
            .await
            .unwrap();
        manager
            .join(&created.group_id, "nodeB", "192.168.100.2")
            .await
            .unwrap();
        {
            let mut sessions = manager.sessions.write().await;
            sessions
                .get_mut(&created.group_id)
                .unwrap()
                .participants
                .get_mut("nodeB")
                .unwrap()
                .last_seen_at =
                Some(Utc::now() - Duration::seconds(GROUP_DISCONNECTED_AFTER_SECS + 1));
        }
        let changed = manager.expire_stale_for_host("nodeA").await;
        assert_eq!(
            changed[0].participants["nodeB"].state,
            GroupMemberState::Disconnected
        );
        drop(manager);

        let restored = GroupSessionManager::new(&log_path);
        assert_eq!(
            restored.get(&created.group_id).await.unwrap().participants["nodeB"].state,
            GroupMemberState::Disconnected
        );
        assert_eq!(
            restored
                .join(&created.group_id, "nodeB", "192.168.100.2")
                .await
                .unwrap()
                .participants["nodeB"]
                .state,
            GroupMemberState::Joined
        );
    }
}
