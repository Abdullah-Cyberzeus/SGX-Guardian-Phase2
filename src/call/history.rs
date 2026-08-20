use crate::call::session::CallSessionStatus;
use crate::call::signaling::MediaType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_CALL_HISTORY_PATH: &str = "/var/log/sgx-guardian/call_history.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallHistoryRecord {
    pub id: String,
    pub kind: String,
    pub outcome: String,
    pub media: Vec<MediaType>,
    pub participant_ids: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct CallHistoryStore {
    path: PathBuf,
}

impl Default for CallHistoryStore {
    fn default() -> Self {
        Self::new(DEFAULT_CALL_HISTORY_PATH)
    }
}

impl CallHistoryStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record_direct(&self, session: &CallSessionStatus) {
        let ended_at = session.ended_at.unwrap_or_else(Utc::now);
        let started_at = session.started_at.unwrap_or(session.created_at);
        let media = if session.accepted_media.is_empty() {
            session.requested_media.clone()
        } else {
            session.accepted_media.clone()
        };
        let outcome = if session.duration_seconds > 0 || session.media_connected {
            "completed"
        } else if session.state == "ended" {
            "cancelled"
        } else {
            "failed"
        };
        let record = CallHistoryRecord {
            id: session.session_id.clone(),
            kind: "direct".into(),
            outcome: outcome.into(),
            media,
            participant_ids: vec![
                session.initiator_device_id.clone(),
                session.receiver_device_id.clone(),
            ],
            started_at,
            ended_at,
            duration_seconds: session.duration_seconds,
        };
        let _ = self.upsert(record);
    }

    pub fn record_group(&self, session: &crate::call::group::GroupSession) {
        let ended_at = session.ended_at.unwrap_or_else(Utc::now);
        let joined_count = session
            .participants
            .values()
            .filter(|participant| participant.joined_at.is_some())
            .count();
        // A group call has no single "connected" instant the way a direct
        // call does (participants join/leave independently), so completion
        // is judged by whether anyone besides the host ever actually joined.
        let outcome = if joined_count > 1 {
            "completed"
        } else {
            "cancelled"
        };
        let record = CallHistoryRecord {
            id: session.group_id.clone(),
            kind: "group".into(),
            outcome: outcome.into(),
            media: session.requested_media.clone(),
            participant_ids: {
                let mut ids: Vec<String> = session
                    .participants
                    .iter()
                    .filter_map(|(id, participant)| {
                        participant.joined_at.is_some().then(|| id.clone())
                    })
                    .collect();
                ids.sort();
                ids
            },
            started_at: session.created_at,
            ended_at,
            duration_seconds: (ended_at - session.created_at).num_seconds().max(0) as u64,
        };
        let _ = self.upsert(record);
    }

    pub fn list(&self) -> Vec<CallHistoryRecord> {
        std::fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<CallHistoryRecord>>(&bytes).ok())
            .unwrap_or_default()
    }

    fn upsert(&self, record: CallHistoryRecord) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut records = self.list();
        if let Some(existing) = records.iter_mut().find(|item| item.id == record.id) {
            *existing = record;
        } else {
            records.push(record);
        }
        records.sort_by(|left, right| right.ended_at.cmp(&left.ended_at));
        records.truncate(500);
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(&records)?)?;
        std::fs::rename(temporary, &self.path)
    }
}
