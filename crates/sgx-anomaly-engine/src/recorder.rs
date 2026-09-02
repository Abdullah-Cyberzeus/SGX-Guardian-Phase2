//! Recorder: dumps FeatureVector rows to CSV in the collector schema
//! (ts, node, label, <19 features>) — same schema the synthetic generator
//! and the training pipeline expect.

use crate::features::FEATURE_NAMES;
use std::io::Write;

pub struct CsvRecorder {
    writer: std::fs::File,
}

impl CsvRecorder {
    pub fn create(path: &str) -> anyhow::Result<Self> {
        let mut f = std::fs::File::create(path)?;
        writeln!(f, "ts,node,label,{}", FEATURE_NAMES.join(","))?;
        Ok(Self { writer: f })
    }

    pub fn write_row(
        &mut self,
        ts: u64,
        node: &str,
        label: &str,
        vector: &[f64; 19],
    ) -> anyhow::Result<()> {
        let values: Vec<String> = vector.iter().map(|v| v.to_string()).collect();
        writeln!(self.writer, "{ts},{node},{label},{}", values.join(","))?;
        Ok(())
    }
}
