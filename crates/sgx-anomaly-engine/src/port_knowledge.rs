//! Parser and knowledge-base writer for the supplied common-port Markdown guide.

use crate::port_security::PortSeverity;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortKnowledgeEntry {
    pub port_number: String,
    pub service_name: String,
    pub purpose: String,
    pub typical_risk: PortSeverity,
    pub reason: String,
}

/// Parses the fixed-column `Common Ports` table used by the supplied guide.
/// Continuation lines are attached to the preceding record.
pub fn parse_common_ports_markdown(markdown: &str) -> Vec<PortKnowledgeEntry> {
    let mut entries: Vec<PortKnowledgeEntry> = Vec::new();
    for line in markdown.lines() {
        let bytes = line.as_bytes();
        if bytes.len() < 20 {
            continue;
        }
        let port = slice(line, 2, 16).trim();
        let service = slice(line, 16, 32).trim();
        let purpose = slice(line, 32, 51).trim();
        let risk = slice(line, 51, 70).trim();
        let reason = slice(line, 70, usize::MAX).trim();
        if let Some(typical_risk) = parse_risk(risk) {
            if looks_like_port(port) && !service.is_empty() {
                entries.push(PortKnowledgeEntry {
                    port_number: port.into(),
                    service_name: service.into(),
                    purpose: purpose.into(),
                    typical_risk,
                    reason: reason.into(),
                });
                continue;
            }
        }
        if let Some(last) = entries.last_mut() {
            if !purpose.is_empty() {
                join(&mut last.purpose, purpose);
            }
            if !reason.is_empty() {
                join(&mut last.reason, reason);
            }
        }
    }
    entries
}

pub fn parse_file(path: impl AsRef<Path>) -> anyhow::Result<Vec<PortKnowledgeEntry>> {
    Ok(parse_common_ports_markdown(&std::fs::read_to_string(path)?))
}
pub fn write_knowledge_base(
    path: impl AsRef<Path>,
    entries: &[PortKnowledgeEntry],
) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(entries)?)?;
    Ok(())
}

fn slice(s: &str, start: usize, end: usize) -> &str {
    let e = end.min(s.len());
    if start >= e {
        ""
    } else {
        &s[start..e]
    }
}
fn parse_risk(s: &str) -> Option<PortSeverity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "low" => Some(PortSeverity::Low),
        "medium" => Some(PortSeverity::Medium),
        "high" => Some(PortSeverity::High),
        "critical" | "critical concern" => Some(PortSeverity::Critical),
        _ => None,
    }
}
fn looks_like_port(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_digit() || c == '/' || c == '-' || c == ' ')
}
fn join(target: &mut String, extra: &str) {
    if !target.is_empty() {
        target.push(' ')
    }
    target.push_str(extra)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_fixed_width_guide_row() {
        let text="  22             SSH             Secure remote      Medium             SSH provides powerful\n                                 login / command                       remote access.";
        let x = parse_common_ports_markdown(text);
        assert_eq!(x.len(), 1);
        assert_eq!(x[0].service_name, "SSH");
        assert_eq!(x[0].typical_risk, PortSeverity::Medium);
        assert!(x[0].reason.contains("remote access"));
    }
}
