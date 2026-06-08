use crate::threat::{error::ThreatResult, threat_alert::ThreatAlert};
use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;

pub const MAX_ALERTS: usize = 10_000;
pub const DEDUP_WINDOW: usize = 100;

#[derive(Default)]
pub struct AlertInventory {
    buf: VecDeque<ThreatAlert>,
}

impl AlertInventory {
    pub fn ingest(&mut self, alert: ThreatAlert) -> bool {
        let duplicate = self
            .buf
            .iter()
            .rev()
            .take(DEDUP_WINDOW)
            .any(|seen| seen.alert_id == alert.alert_id);

        if duplicate {
            return false;
        }

        self.buf.push_back(alert);
        while self.buf.len() > MAX_ALERTS {
            self.buf.pop_front();
        }
        true
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
