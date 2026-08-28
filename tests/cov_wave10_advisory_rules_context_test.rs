use chrono::{TimeZone, Utc};
use serde_json::json;
use sgx_guardian_client::advisory::context::{
    anomaly_context_lines, cve_references, device_context_from_connected_device,
    device_context_lines, load_device_context_for_alert_ip, normalize_anomaly_score,
};
use sgx_guardian_client::advisory::errors::AdvisoryError;
use sgx_guardian_client::advisory::generate;
use sgx_guardian_client::advisory::kb::{
    RecommendationRule, RecommendationRules, RecommendationTemplate, RuleMatch, RuleStep,
};
use sgx_guardian_client::advisory::model::{
    AnomalyContext, CveFinding, DeviceContext, RemediationRecommendation,
};
use sgx_guardian_client::advisory::{store, AdvisoryConfig};
use sgx_guardian_client::discovery::connected_device::{
    ConnectedDevice, DeviceStatus, OpenPort, ScriptResult,
};
use sgx_guardian_client::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::sync::{Mutex, MutexGuard};
use tempfile::tempdir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct AdvisoryEnv {
    base: Option<String>,
    max: Option<String>,
    _lock: MutexGuard<'static, ()>,
}

impl AdvisoryEnv {
    fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = std::env::var("SGX_GUARDIAN_ADVISORY_BASE").ok();
        let max = std::env::var("SGX_ADVISORY_MAX_RECS").ok();
        std::env::remove_var("SGX_GUARDIAN_ADVISORY_BASE");
        std::env::remove_var("SGX_ADVISORY_MAX_RECS");
        Self {
            base,
            max,
            _lock: lock,
        }
    }
}

impl Drop for AdvisoryEnv {
    fn drop(&mut self) {
        for (key, value) in [
            ("SGX_GUARDIAN_ADVISORY_BASE", &self.base),
            ("SGX_ADVISORY_MAX_RECS", &self.max),
        ] {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn script(id: &str, output: &str) -> ScriptResult {
    ScriptResult {
        id: id.into(),
        output: output.into(),
    }
}

fn device(ip: &str) -> ConnectedDevice {
    ConnectedDevice {
        device_id: ConnectedDevice::compute_id(ip, Some("aa:bb:cc:dd:ee:ff")),
        ip: ip.into(),
        mac: Some("aa:bb:cc:dd:ee:ff".into()),
        vendor: Some("Acme".into()),
        hostname: Some("gateway".into()),
        os_fingerprint: Some("Linux 6.x".into()),
        os_cpe: vec![],
        open_ports: vec![
            OpenPort {
                port: 443,
                protocol: "tcp".into(),
                service: Some("https".into()),
                product_version: None,
                cpe: vec![],
                scripts: vec![script(
                    "vulners",
                    "CVE-2024-12345 score 9.8 and cve-2023-9999 (7.1)",
                )],
            },
            OpenPort {
                port: 22,
                protocol: "tcp".into(),
                service: Some("ssh".into()),
                product_version: None,
                cpe: vec![],
                scripts: vec![],
            },
        ],
        host_scripts: vec![script(
            "host-vuln",
            "duplicate CVE-2024-12345 8.0 invalid CVE-20-X CVE-2022-0001 11.0",
        )],
        status: DeviceStatus::Drifted,
        first_seen: "2026-01-01T00:00:00Z".into(),
        last_seen: "2026-01-02T00:00:00Z".into(),
        vuln_triaged: false,
        last_scan_intensity: Some("aggressive".into()),
    }
}

fn alert(severity: Severity, category: ThreatCategory, signature: &str) -> ThreatAlert {
    ThreatAlert {
        alert_id: "alert-1".into(),
        timestamp: Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
        src_ip: "10.0.0.2".into(),
        src_port: 51515,
        dst_ip: "10.0.0.1".into(),
        dst_port: 443,
        protocol: "TCP".into(),
        signature_id: 9001,
        signature: signature.into(),
        category,
        severity,
        rev: 1,
        gid: 1,
        event_type: "alert".into(),
        blocked: false,
    }
}

fn signed_rules(mut rules: RecommendationRules) -> RecommendationRules {
    rules.signature_sha256 = None;
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&rules).unwrap()));
    rules.signature_sha256 = Some(digest);
    rules
}

#[test]
fn anomaly_score_and_context_cover_hints_clamps_defaults_and_limits() {
    for (input, expected) in [
        (-2.0, 0.0),
        (0.4, 0.4),
        (1.0, 1.0),
        (50.0, 0.5),
        (250.0, 1.0),
    ] {
        assert_eq!(normalize_anomaly_score(input), expected);
    }
    assert!(anomaly_context_lines(None).is_empty());
    let anomaly = AnomalyContext {
        score: 72.0,
        model_version: None,
        topk: vec![
            ("flow_rate".into(), 0.9),
            ("cmd_entropy".into(), 0.8),
            ("peer_diversity".into(), 0.7),
            ("attest_jitter".into(), 0.6),
            ("modbus_fc_mix".into(), 0.5),
            ("custom".into(), 0.4),
        ],
    };
    let lines = anomaly_context_lines(Some(&anomaly));
    assert_eq!(lines.len(), 6);
    assert!(lines[0].contains("0.72"));
    assert!(lines[0].contains("deterministic local detector"));
    assert!(lines.iter().any(|line| line.contains("traffic spike")));
    assert!(lines
        .iter()
        .any(|line| line.contains("unusual command mix")));
    assert!(lines
        .iter()
        .any(|line| line.contains("unusual peer spread")));
    assert!(lines
        .iter()
        .any(|line| line.contains("attestation timing drift")));
    assert!(lines.iter().any(|line| line.contains("Modbus")));

    let modeled = AnomalyContext {
        model_version: Some("model-v3".into()),
        ..anomaly
    };
    assert!(anomaly_context_lines(Some(&modeled))[0].contains("model-v3"));
}

#[test]
fn device_context_lines_cover_labels_cves_limits_and_references() {
    assert!(device_context_lines(None).is_empty());
    let variants = [
        (Some("host"), Some("vendor"), "10.0.0.2 (host, vendor)"),
        (Some("host"), None, "10.0.0.2 (host)"),
        (None, Some("vendor"), "10.0.0.2 (vendor)"),
        (None, None, "10.0.0.2"),
    ];
    for (hostname, vendor, label) in variants {
        let context = DeviceContext {
            ip: "10.0.0.2".into(),
            hostname: hostname.map(str::to_string),
            vendor: vendor.map(str::to_string),
            risk_reasons: (0..7).map(|idx| format!("risk-{idx}")).collect(),
            cves: vec![
                CveFinding {
                    cve: "CVE-2024-1234".into(),
                    cvss: Some(9.8),
                },
                CveFinding {
                    cve: "CVE-2023-9999".into(),
                    cvss: None,
                },
            ],
        };
        let lines = device_context_lines(Some(&context));
        assert_eq!(lines[0], format!("Device context: {label}"));
        assert_eq!(lines.len(), 8);
        assert!(lines.iter().any(|line| line.contains("CVSS 9.8")));
        assert!(lines.iter().any(|line| line == "Device has CVE-2023-9999"));
    }

    let context = DeviceContext {
        ip: "x".into(),
        hostname: None,
        vendor: None,
        risk_reasons: vec![],
        cves: (0..12)
            .map(|idx| CveFinding {
                cve: format!("CVE-2026-{idx:04}"),
                cvss: None,
            })
            .collect(),
    };
    assert_eq!(cve_references(Some(&context)).len(), 10);
    assert!(cve_references(None).is_empty());
}

#[test]
fn connected_device_context_extracts_sorted_ports_status_os_and_unique_cves() {
    let context = device_context_from_connected_device(device("10.0.0.2"));
    assert_eq!(context.ip, "10.0.0.2");
    assert_eq!(context.hostname.as_deref(), Some("gateway"));
    assert_eq!(context.vendor.as_deref(), Some("Acme"));
    assert!(context.risk_reasons[0].contains("22/tcp, 443/tcp"));
    assert!(context
        .risk_reasons
        .iter()
        .any(|line| line.contains("Drifted")));
    assert!(context
        .risk_reasons
        .iter()
        .any(|line| line.contains("Linux 6.x")));
    assert_eq!(
        context
            .cves
            .iter()
            .map(|item| item.cve.as_str())
            .collect::<Vec<_>>(),
        vec!["CVE-2022-0001", "CVE-2023-9999", "CVE-2024-12345"]
    );
    assert_eq!(context.cves[2].cvss, Some(8.0));

    let mut approved = device("10.0.0.3");
    approved.status = DeviceStatus::Approved;
    approved.open_ports.clear();
    approved.host_scripts.clear();
    approved.os_fingerprint = None;
    let context = device_context_from_connected_device(approved);
    assert!(context.risk_reasons.is_empty());
    assert!(context.cves.is_empty());
}

#[test]
fn inventory_context_loading_handles_missing_empty_invalid_src_dst_and_no_match() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("inventory.json");
    assert!(load_device_context_for_alert_ip(&path, "a", "b")
        .unwrap()
        .is_none());
    fs::write(&path, []).unwrap();
    assert!(load_device_context_for_alert_ip(&path, "a", "b")
        .unwrap()
        .is_none());
    fs::write(&path, "not-json").unwrap();
    assert!(matches!(
        load_device_context_for_alert_ip(&path, "a", "b"),
        Err(AdvisoryError::Json(_))
    ));

    fs::write(
        &path,
        serde_json::to_vec(&vec![device("10.0.0.2")]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        load_device_context_for_alert_ip(&path, "10.0.0.2", "x")
            .unwrap()
            .unwrap()
            .ip,
        "10.0.0.2"
    );
    assert!(load_device_context_for_alert_ip(&path, "x", "10.0.0.2")
        .unwrap()
        .is_some());
    assert!(load_device_context_for_alert_ip(&path, "x", "y")
        .unwrap()
        .is_none());
}

#[test]
fn default_rules_match_category_signature_and_every_severity_rank() {
    let rules = RecommendationRules::default_rules();
    assert_eq!(rules.rules.len(), 4);
    assert!(rules.rules[0].matches("MALWARE", "anything", Severity::High));
    assert!(!rules.rules[0].matches("exploit", "anything", Severity::Critical));
    assert!(!rules.rules[0].matches("malware", "anything", Severity::Medium));

    let rule = RecommendationRule {
        rule_match: RuleMatch {
            category: None,
            signature_contains: Some("PowerShell".into()),
            severity_at_least: Some("unknown".into()),
        },
        title: "title".into(),
        summary: "summary".into(),
        steps: vec![],
        references: vec![],
    };
    assert!(rule.matches("other", "suspicious POWERSHELL command", Severity::Info));
    assert!(!rule.matches("other", "shell", Severity::Critical));

    for (name, accepted, rejected) in [
        ("low", Severity::Low, Severity::Info),
        ("medium", Severity::Medium, Severity::Low),
        ("high", Severity::High, Severity::Medium),
        ("critical", Severity::Critical, Severity::High),
    ] {
        let mut threshold = rule.clone();
        threshold.rule_match.signature_contains = None;
        threshold.rule_match.severity_at_least = Some(name.into());
        assert!(threshold.matches("x", "x", accepted));
        assert!(!threshold.matches("x", "x", rejected));
    }
}

#[test]
fn rule_steps_are_ordered_and_saturate_at_u8_max() {
    let steps = (0..260)
        .map(|idx| RuleStep {
            action: format!("action-{idx}"),
            rationale: "reason".into(),
            automatable: idx % 2 == 0,
        })
        .collect::<Vec<_>>();
    let rule = RecommendationRule {
        rule_match: RuleMatch {
            category: None,
            signature_contains: None,
            severity_at_least: None,
        },
        title: "x".into(),
        summary: "y".into(),
        steps: steps.clone(),
        references: vec![],
    };
    let ordered = rule.steps();
    assert_eq!(ordered[0].order, 1);
    assert_eq!(ordered[254].order, 255);
    assert_eq!(ordered[259].order, 255);
    assert!(ordered[0].automatable);

    let template = RecommendationTemplate {
        title: "fallback".into(),
        summary: "summary".into(),
        steps,
        references: vec![],
    };
    assert_eq!(template.steps().len(), 260);
}

#[test]
fn signed_rules_save_load_verify_reject_tamper_and_fallback_on_bad_files() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nested/rules.json");
    let rules = signed_rules(RecommendationRules::default_rules());
    rules.validate_signature().unwrap();
    rules.save_atomic(&path).unwrap();
    assert_eq!(RecommendationRules::load_verified(&path).unwrap(), rules);

    let mut tampered = rules.clone();
    tampered.fallback.title = "tampered".into();
    assert!(matches!(
        tampered.validate_signature(),
        Err(AdvisoryError::InvalidRules(_))
    ));
    assert!(tampered.save_atomic(&path).is_err());

    fs::write(&path, "bad json").unwrap();
    assert_eq!(RecommendationRules::load_or_default(&path).rules.len(), 4);
    assert_eq!(
        RecommendationRules::load_or_default(&dir.path().join("missing"))
            .fallback
            .title,
        "Security alert requires review"
    );
}

#[test]
fn recommendation_generation_covers_matches_fallback_anomaly_device_and_confidence() {
    let rules = RecommendationRules::default_rules();
    let device = DeviceContext {
        ip: "10.0.0.2".into(),
        hostname: Some("gateway".into()),
        vendor: Some("Acme".into()),
        risk_reasons: vec!["drifted".into()],
        cves: vec![
            CveFinding {
                cve: "CVE-2024-1234".into(),
                cvss: Some(9.8),
            },
            CveFinding {
                cve: "CVE-2024-1234".into(),
                cvss: None,
            },
        ],
    };
    let anomaly = AnomalyContext {
        score: 100.0,
        topk: vec![("flow_rate".into(), 0.9)],
        model_version: Some("v1".into()),
    };
    let matched = generate::generate(
        &alert(
            Severity::Critical,
            ThreatCategory::Malware,
            "malware callback",
        ),
        Some(&anomaly),
        Some(&device),
        &rules,
    );
    assert_eq!(matched.source, "signature-kb");
    assert_eq!(matched.severity, "critical");
    assert!((matched.confidence - 0.965).abs() < 0.001);
    assert!(matched.rec_id.starts_with("urn:sha256:"));
    assert_eq!(matched.rec_id.len(), 43);
    assert!(matched.context.iter().any(|line| line.contains("Flow:")));
    assert_eq!(
        matched
            .references
            .iter()
            .filter(|reference| reference.contains("CVE-2024-1234"))
            .count(),
        1
    );

    let fallback = generate::generate(
        &alert(Severity::Info, ThreatCategory::Other, "unknown"),
        None,
        None,
        &rules,
    );
    assert_eq!(fallback.source, "fallback");
    assert_eq!(fallback.confidence, 0.35);
    let anomaly_fallback = generate::generate(
        &alert(Severity::Low, ThreatCategory::Other, "unknown"),
        Some(&AnomalyContext {
            score: -1.0,
            topk: vec![],
            model_version: None,
        }),
        None,
        &rules,
    );
    assert_eq!(anomaly_fallback.source, "anomaly-kb");
    assert!((anomaly_fallback.confidence - 0.385).abs() < 0.001);

    for (severity, expected) in [(Severity::Medium, 0.72), (Severity::High, 0.88)] {
        assert_eq!(
            generate::generate(
                &alert(severity, ThreatCategory::Other, "unknown"),
                None,
                None,
                &rules,
            )
            .confidence,
            expected
        );
    }
}

#[tokio::test]
async fn advisory_store_handles_cap_zero_duplicates_limits_missing_and_corruption() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nested/recommendations.jsonl");
    assert!(store::list_recent(&path, 10).await.unwrap().is_empty());
    assert!(store::find_for_alert(&path, "missing")
        .await
        .unwrap()
        .is_none());

    let rules = RecommendationRules::default_rules();
    let first = generate::generate(
        &alert(Severity::High, ThreatCategory::Other, "one"),
        None,
        None,
        &rules,
    );
    store::append_capped(&path, first.clone(), 2).await.unwrap();
    let mut replacement = first.clone();
    replacement.title = "replacement".into();
    store::append_capped(&path, replacement.clone(), 2)
        .await
        .unwrap();
    assert_eq!(store::list_recent(&path, 10).await.unwrap().len(), 1);
    assert_eq!(
        store::find_for_alert(&path, "alert-1")
            .await
            .unwrap()
            .unwrap()
            .title,
        "replacement"
    );

    let mut second = replacement.clone();
    second.alert_id = "alert-2".into();
    second.rec_id = "rec-2".into();
    store::append_capped(&path, second, 2).await.unwrap();
    let mut third = replacement;
    third.alert_id = "alert-3".into();
    third.rec_id = "rec-3".into();
    store::append_capped(&path, third, 2).await.unwrap();
    let recent = store::list_recent(&path, 1).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].alert_id, "alert-3");

    let zero_path = dir.path().join("zero.jsonl");
    store::append_capped(&zero_path, first, 0).await.unwrap();
    assert!(store::list_recent(&zero_path, 10).await.unwrap().is_empty());
    fs::write(&path, "{broken}\n").unwrap();
    assert!(matches!(
        store::list_recent(&path, 10).await,
        Err(AdvisoryError::Json(_))
    ));
}

#[test]
fn advisory_config_paths_environment_and_errors_are_stable() {
    let _env = AdvisoryEnv::new();
    let config = AdvisoryConfig::from_state_dirs("/var/lib/guardian/threat");
    assert_eq!(
        config.base_dir,
        std::path::PathBuf::from("/var/lib/guardian/advisory")
    );
    assert_eq!(config.max_recommendations, 2_000);
    assert!(config
        .recommendations_path()
        .ends_with("recommendations.jsonl"));
    assert!(config.rules_path().ends_with("recommendation_rules.json"));

    std::env::set_var("SGX_GUARDIAN_ADVISORY_BASE", "/tmp/custom-advisory");
    std::env::set_var("SGX_ADVISORY_MAX_RECS", "25");
    let config = AdvisoryConfig::from_state_dirs("ignored");
    assert_eq!(
        config.base_dir,
        std::path::PathBuf::from("/tmp/custom-advisory")
    );
    assert_eq!(config.max_recommendations, 25);
    std::env::set_var("SGX_ADVISORY_MAX_RECS", "0");
    assert_eq!(
        AdvisoryConfig::from_state_dirs("ignored").max_recommendations,
        2_000
    );
    std::env::set_var("SGX_ADVISORY_MAX_RECS", "invalid");
    assert_eq!(
        AdvisoryConfig::from_state_dirs("ignored").max_recommendations,
        2_000
    );

    let invalid = AdvisoryError::InvalidRules("bad signature".into());
    assert_eq!(invalid.to_string(), "invalid advisory rules: bad signature");
    assert!(invalid.source().is_none());
    let io: AdvisoryError = std::io::Error::other("disk").into();
    assert!(io.to_string().contains("disk"));
    assert!(io.source().is_some());
    let json: AdvisoryError = serde_json::from_str::<serde_json::Value>("{")
        .unwrap_err()
        .into();
    assert!(json.to_string().starts_with("json:"));
    assert!(json.source().is_some());

    let model = RemediationRecommendation {
        rec_id: "rec".into(),
        alert_id: "alert".into(),
        title: "title".into(),
        summary: "summary".into(),
        severity: "low".into(),
        confidence: 0.5,
        steps: vec![],
        context: vec![],
        references: vec![],
        source: "test".into(),
        generated_at: Utc::now(),
    };
    assert_eq!(
        serde_json::from_value::<RemediationRecommendation>(json!(model)).unwrap(),
        model
    );
}
