use crate::notify::errors::NotifyResult;
use crate::notify::model::NotificationEvent;
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub static NOTIFY_WRITE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

static NEXT_EVENT_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_MAX_EVENTS: usize = 2000;

#[derive(Debug, Default)]
pub struct NotificationStore {
    buf: VecDeque<NotificationEvent>,
}

impl NotificationStore {
    pub fn load_from_path(path: &Path, max_events: usize) -> NotifyResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let text = std::fs::read_to_string(path)?;
        let mut store = Self::default();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let event: NotificationEvent = serde_json::from_str(line)?;
            store.buf.push_back(event);
        }
        store.truncate(max_events);
        if let Some(next_id) = store
            .buf
            .back()
            .and_then(|event| event.id.parse::<u64>().ok())
            .map(|id| id.saturating_add(1))
        {
            sync_next_event_id(next_id);
        }
        Ok(store)
    }

    pub fn append(&mut self, mut event: NotificationEvent, max_events: usize) {
        if event.id.trim().is_empty() {
            event.id = next_event_id();
        } else if let Ok(parsed) = event.id.parse::<u64>() {
            sync_next_event_id(parsed.saturating_add(1));
        }
        self.buf.push_back(event);
        self.truncate(max_events);
    }

    pub fn history(&self, limit: usize) -> Vec<NotificationEvent> {
        self.buf.iter().rev().take(limit).cloned().collect()
    }

    pub fn replay_after(&self, after_id: &str) -> Vec<NotificationEvent> {
        match after_id.parse::<u64>() {
            Ok(cursor) => self
                .buf
                .iter()
                .filter(|event| event.id.parse::<u64>().ok().unwrap_or(0) > cursor)
                .cloned()
                .collect(),
            Err(_) => self.buf.iter().cloned().collect(),
        }
    }

    pub fn unread_count(&self) -> usize {
        self.buf.iter().filter(|event| !event.read).count()
    }

    pub fn mark_read(&mut self, id: &str) -> bool {
        if let Some(event) = self.buf.iter_mut().find(|event| event.id == id) {
            if !event.read {
                event.read = true;
                return true;
            }
        }
        false
    }

    pub fn mark_all_read(&mut self) -> usize {
        let mut changed = 0usize;
        for event in &mut self.buf {
            if !event.read {
                event.read = true;
                changed += 1;
            }
        }
        changed
    }

    pub fn save_atomic(&self, path: &Path) -> NotifyResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp = path.with_extension("jsonl.tmp");
        {
            let mut file = std::fs::File::create(&tmp)?;
            for event in &self.buf {
                serde_json::to_writer(&mut file, event)?;
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
        }
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    fn truncate(&mut self, max_events: usize) {
        while self.buf.len() > max_events.max(1) {
            self.buf.pop_front();
        }
    }
}

pub fn configured_max_events() -> usize {
    std::env::var("SGX_NOTIFY_MAX_EVENTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_EVENTS)
}

pub fn next_event_id() -> String {
    NEXT_EVENT_ID.fetch_add(1, Ordering::Relaxed).to_string()
}

pub fn prime_store(path: &Path, max_events: usize) -> NotifyResult<()> {
    let store = NotificationStore::load_from_path(path, max_events)?;
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        store.save_atomic(path)?;
    }
    Ok(())
}

fn sync_next_event_id(candidate: u64) {
    let mut current = NEXT_EVENT_ID.load(Ordering::Relaxed);
    while current < candidate {
        match NEXT_EVENT_ID.compare_exchange(
            current,
            candidate,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(seen) => current = seen,
        }
    }
}
