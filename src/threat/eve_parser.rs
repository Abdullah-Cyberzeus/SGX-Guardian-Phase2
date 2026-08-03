use crate::threat::{
    error::{ThreatError, ThreatResult},
    threat_alert::{Severity, ThreatAlert, ThreatCategory},
};
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Parse one EVE JSON line.
/// Returns `Ok(None)` for event types we ignore.
pub fn parse_line(line: &str, line_no: u64) -> ThreatResult<Option<ThreatAlert>> {
    if line.trim().is_empty() {
        return Ok(None);
    }

    let value: Value = serde_json::from_str(line).map_err(|err| ThreatError::JsonParse {
        line: line_no,
        msg: err.to_string(),
    })?;

    let event_type = value
        .get("event_type")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string();

    if event_type != "alert" && event_type != "anomaly" {
        return Ok(None);
    }

    let timestamp: DateTime<Utc> = value
        .get("timestamp")
        .and_then(|item| item.as_str())
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let src_ip = value
        .get("src_ip")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string();
    let dst_ip = value
        .get("dest_ip")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string();
    let src_port = value
        .get("src_port")
        .and_then(|item| item.as_u64())
        .unwrap_or(0) as u16;
    let dst_port = value
        .get("dest_port")
        .and_then(|item| item.as_u64())
        .unwrap_or(0) as u16;
    let protocol = value
        .get("proto")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string();

    let alert_obj = value.get("alert");
    let signature_id = alert_obj
        .and_then(|alert| alert.get("signature_id"))
        .and_then(|item| item.as_u64())
        .unwrap_or(0) as u32;
    let signature = alert_obj
        .and_then(|alert| alert.get("signature"))
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string();
    let severity_raw = alert_obj
        .and_then(|alert| alert.get("severity"))
        .and_then(|item| item.as_u64())
        .unwrap_or(3) as u8;
    let rev = alert_obj
        .and_then(|alert| alert.get("rev"))
        .and_then(|item| item.as_u64())
        .unwrap_or(0) as u32;
    let gid = alert_obj
        .and_then(|alert| alert.get("gid"))
        .and_then(|item| item.as_u64())
        .unwrap_or(1) as u32;

    let category = classify(&signature);
    let severity = severity_from_raw(severity_raw, category, &signature);
    let alert_id = ThreatAlert::compute_id(signature_id, &src_ip, &dst_ip);

    Ok(Some(ThreatAlert {
        alert_id,
        timestamp,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
        signature_id,
        signature,
        category,
        severity,
        rev,
        gid,
        event_type,
        blocked: false,
    }))
}

fn severity_from_raw(raw: u8, category: ThreatCategory, signature: &str) -> Severity {
    let lower = signature.to_lowercase();
    match raw {
        1 if matches!(category, ThreatCategory::Malware | ThreatCategory::Exploit)
            || lower.contains("ransom")
            || lower.contains("trojan") =>
        {
            Severity::Critical
        }
        1 => Severity::High,
        2 => Severity::Medium,
        3 => Severity::Low,
        4 => Severity::Info,
        _ => Severity::Low,
    }
}

fn classify(signature: &str) -> ThreatCategory {
    let lowered = signature.to_lowercase();
    if lowered.contains("attestation") || lowered.contains("pcr") {
        ThreatCategory::AttestationMismatch
    } else if lowered.contains("certificate") || lowered.contains("pki") || lowered.contains("cert") {
        ThreatCategory::CertificateIssue
    } else if lowered.contains("malware") || lowered.contains("trojan") || lowered.contains("ransom") {
        ThreatCategory::Malware
    } else if lowered.contains("exploit") || lowered.contains("cve") || lowered.contains("rce") {
        ThreatCategory::Exploit
    } else if lowered.contains("policy") || lowered.contains("user-agent") {
        ThreatCategory::PolicyViolation
    } else if lowered.contains("scan") || lowered.contains("recon") || lowered.contains("nmap") {
        ThreatCategory::Reconnaissance
    } else if lowered.contains("anomaly") {
        ThreatCategory::Anomaly
    } else {
        ThreatCategory::Other
    }
}
