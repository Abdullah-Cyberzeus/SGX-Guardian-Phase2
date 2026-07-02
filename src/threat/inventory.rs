use crate::threat::{error::ThreatResult, threat_alert::ThreatAlert};
use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;

pub const MAX_ALERTS: usize = 10_000;
pub const DEDUP_WINDOW: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Inserted,
    Updated,
    Duplicate,
}

#[derive(Default)]
pub struct AlertInventory {
    buf: VecDeque<ThreatAlert>,
}

impl AlertInventory {
    pub fn ingest(&mut self, alert: ThreatAlert) -> IngestOutcome {
        if let Some(seen) = self
            .buf
            .iter_mut()
            .rev()
            .take(DEDUP_WINDOW)
            .find(|seen| seen.alert_id == alert.alert_id)
        {
            if merge_alert(seen, alert) {
                return IngestOutcome::Updated;
            }
            return IngestOutcome::Duplicate;
        }

        self.buf.push_back(alert);
        while self.buf.len() > MAX_ALERTS {
            self.buf.pop_front();
        }
        IngestOutcome::Inserted
    }

    pub fn snapshot(&self) -> Vec<ThreatAlert> {
        self.buf.iter().cloned().collect()
    }

    pub fn save_atomic(&self, path: &Path) -> ThreatResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp = path.with_extension("jsonl.tmp");
        {
            let mut file = std::fs::File::create(&tmp)?;
            for alert in &self.buf {
                serde_json::to_writer(&mut file, alert)?;
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load_from_path(path: &Path) -> ThreatResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let text = std::fs::read_to_string(path)?;
        let mut inventory = Self::default();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let alert: ThreatAlert = serde_json::from_str(line)?;
            inventory.buf.push_back(alert);
        }
        while inventory.buf.len() > MAX_ALERTS {
            inventory.buf.pop_front();
        }
        Ok(inventory)
    }
}

fn merge_alert(existing: &mut ThreatAlert, incoming: ThreatAlert) -> bool {
    let mut changed = false;

    if incoming.blocked && !existing.blocked {
        existing.blocked = true;
        changed = true;
    }

    if severity_rank(incoming.severity) > severity_rank(existing.severity) {
        existing.severity = incoming.severity;
        changed = true;
    }

    if existing.category != incoming.category {
        existing.category = incoming.category;
        changed = true;
    }

    if existing.signature != incoming.signature {
        existing.signature = incoming.signature;
        changed = true;
    }

    if incoming.timestamp > existing.timestamp {
        existing.timestamp = incoming.timestamp;
        changed = true;
    }

    changed
}

fn severity_rank(severity: crate::threat::threat_alert::Severity) -> u8 {
    match severity {
        crate::threat::threat_alert::Severity::Info => 0,
        crate::threat::threat_alert::Severity::Low => 1,
        crate::threat::threat_alert::Severity::Medium => 2,
        crate::threat::threat_alert::Severity::High => 3,
        crate::threat::threat_alert::Severity::Critical => 4,
    }
}
