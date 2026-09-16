//! Human-readable storage layout for Task3 run evidence.
//!
//! The AI modules remain responsible for their own logic. This small helper
//! gives demos/runtime a stable place for compact run packages without making
//! every internal calculation a top-level file.

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task3EvidenceStage {
    RouteDecisions,
    Task2Handoffs,
    Benchmarks,
}

impl Task3EvidenceStage {
    pub fn folder_name(self) -> &'static str {
        match self {
            Self::RouteDecisions => "01_ROUTE_DECISIONS",
            Self::Task2Handoffs => "02_TASK2_HANDOFFS",
            Self::Benchmarks => "03_BENCHMARKS",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Task3RunLayout {
    pub run_id: String,
    pub root: PathBuf,
}

impl Task3RunLayout {
    pub fn create(
        base: impl AsRef<Path>,
        stage: Task3EvidenceStage,
        source_node: &str,
        destination_node: &str,
    ) -> Result<Self> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let run_id = format!(
            "task3-run-{}-{}-to-{}",
            now_ms,
            safe_id(source_node),
            safe_id(destination_node)
        );
        let root = base.as_ref().join(stage.folder_name()).join(&run_id);
        fs::create_dir_all(&root)
            .with_context(|| format!("creating Task3 run directory {}", root.display()))?;
        Ok(Self { run_id, root })
    }

    pub fn run_summary_path(&self) -> PathBuf {
        self.root.join("run_summary.json")
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn decision_path(&self) -> PathBuf {
        self.root.join("decision.json")
    }

    pub fn history_path(&self) -> PathBuf {
        self.root.join("history.jsonl")
    }

    pub fn task2_link_path(&self) -> PathBuf {
        self.root.join("task2_link.json")
    }

    pub fn benchmark_path(&self) -> PathBuf {
        self.root.join("benchmark.json")
    }

    pub fn write_json(&self, path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
        let path = path.as_ref();
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(value)?)
            .with_context(|| format!("writing Task3 temporary JSON {}", temporary.display()))?;
        fs::rename(&temporary, path)
            .with_context(|| format!("activating Task3 JSON {}", path.display()))?;
        Ok(())
    }

    pub fn append_history(&self, value: &impl Serialize) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.history_path())
            .context("opening Task3 history JSONL")?;
        writeln!(file, "{}", serde_json::to_string(value)?)
            .context("appending Task3 history JSONL")?;
        Ok(())
    }
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_readable_stage_and_run_id() {
        let base = std::env::temp_dir().join(format!("task3-layout-{}", std::process::id()));
        let layout =
            Task3RunLayout::create(&base, Task3EvidenceStage::RouteDecisions, "nodeA", "nodeB")
                .unwrap();
        assert!(layout.root.ends_with(&layout.run_id));
        assert!(layout.root.to_string_lossy().contains("01_ROUTE_DECISIONS"));
        layout
            .write_json(
                layout.run_summary_path(),
                &serde_json::json!({"run_id": layout.run_id}),
            )
            .unwrap();
        layout
            .append_history(&serde_json::json!({"event": "decision"}))
            .unwrap();
        assert!(layout.decision_path().ends_with("decision.json"));
        assert!(layout.history_path().exists());
        let _ = fs::remove_dir_all(base);
    }
}
