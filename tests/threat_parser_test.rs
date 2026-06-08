use sgx_guardian_client::threat::{
    eve_parser::parse_line,
    threat_alert::{Severity, ThreatCategory},
};

#[test]
fn parser_maps_alert_event() {
    let line = r#"{"timestamp":"2026-06-04T10:00:00Z","event_type":"alert","src_ip":"192.0.2.10","src_port":4444,"dest_ip":"198.51.100.20","dest_port":80,"proto":"TCP","alert":{"signature_id":2001234,"signature":"ET MALWARE EICAR Test","severity":1,"rev":7,"gid":1}}"#;
    let parsed = parse_line(line, 1).expect("parse").expect("alert");
    assert_eq!(parsed.signature_id, 2001234);
    assert_eq!(parsed.category, ThreatCategory::Malware);
    assert_eq!(parsed.severity, Severity::Critical);
    assert_eq!(parsed.src_ip, "192.0.2.10");
    assert_eq!(parsed.dst_ip, "198.51.100.20");
}

#[test]
fn parser_maps_anomaly_event() {
    let line = r#"{"timestamp":"2026-06-04T10:05:00Z","event_type":"anomaly","src_ip":"203.0.113.5","src_port":53,"dest_ip":"198.51.100.20","dest_port":5353,"proto":"UDP","alert":{"signature_id":42,"signature":"Protocol anomaly observed","severity":3,"rev":1,"gid":1}}"#;
    let parsed = parse_line(line, 2).expect("parse").expect("anomaly");
    assert_eq!(parsed.event_type, "anomaly");
    assert_eq!(parsed.category, ThreatCategory::Anomaly);
    assert_eq!(parsed.severity, Severity::Low);
}

#[test]
fn parser_ignores_non_alert_events() {
    let line = r#"{"timestamp":"2026-06-04T10:10:00Z","event_type":"flow","src_ip":"203.0.113.5","dest_ip":"198.51.100.20"}"#;
    assert!(parse_line(line, 3).expect("parse").is_none());
}

#[test]
fn parser_reports_malformed_json() {
    let err = parse_line("{", 9).expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("line 9"));
}
