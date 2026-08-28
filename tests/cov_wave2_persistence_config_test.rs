//! Coverage for deterministic persistence, configuration, parsing, and error paths.

use axum::body::to_bytes;
use axum::response::IntoResponse;
use chrono::{TimeZone, Utc};
use serde_json::{json, Value};
use sgx_guardian_client::advisory::model::{RemediationRecommendation, RemediationStep};
use sgx_guardian_client::advisory::store as advisory_store;
use sgx_guardian_client::api::error::ApiError;
use sgx_guardian_client::contacts::store::{self as contacts, ContactDraft, ContactPatch};
use sgx_guardian_client::dusage::counters::{parse_nft_counters_json, read_interface_counters};
use sgx_guardian_client::dusage::quota::{
    next_period_start, normalize_period, period_has_rolled, period_start_for, usage_band, used_pct,
};
use sgx_guardian_client::secure_element::pcr_config::{
    default_measurement_sources, software_measurement_sources,
};
use tempfile::TempDir;

fn recommendation(alert_id: &str, rec_id: &str, confidence: f32) -> RemediationRecommendation {
    RemediationRecommendation {
        rec_id: rec_id.into(),
        alert_id: alert_id.into(),
        title: format!("Recommendation {rec_id}"),
        summary: "deterministic test recommendation".into(),
        severity: "high".into(),
        confidence,
        steps: vec![RemediationStep {
            order: 1,
            action: "isolate".into(),
            rationale: "contain the test alert".into(),
            automatable: true,
        }],
        context: vec!["test".into()],
        references: vec!["urn:test:reference".into()],
        source: "coverage-test".into(),
        generated_at: Utc::now(),
    }
}

#[tokio::test]
async fn contacts_crud_is_sorted_trimmed_and_isolated_by_owner() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("nested/contacts.json");

    assert!(contacts::list(&path, None).await.unwrap().is_empty());

    let admin_zed = contacts::create(
        &path,
        None,
        ContactDraft {
            did: "  did:guardian:zed  ".into(),
            name: Some("  Zed  ".into()),
            alias: Some("   ".into()),
            notes: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(admin_zed.did, "did:guardian:zed");
    assert_eq!(admin_zed.name.as_deref(), Some("Zed"));
    assert_eq!(admin_zed.alias, None);

    contacts::create(
        &path,
        None,
        ContactDraft {
            did: "did:guardian:alpha".into(),
            name: None,
            alias: Some(" Alpha ".into()),
            notes: Some(" note ".into()),
        },
    )
    .await
    .unwrap();
    contacts::create(
        &path,
        Some("did:guardian:member"),
        ContactDraft {
            did: "did:guardian:zed".into(),
            name: Some("Private Zed".into()),
            alias: None,
            notes: None,
        },
    )
    .await
    .unwrap();

    let admin = contacts::list(&path, None).await.unwrap();
    assert_eq!(
        admin
            .iter()
            .map(|item| item.did.as_str())
            .collect::<Vec<_>>(),
        vec!["did:guardian:alpha", "did:guardian:zed"]
    );
    let member = contacts::list(&path, Some("did:guardian:member"))
        .await
        .unwrap();
    assert_eq!(member.len(), 1);
    assert_eq!(member[0].name.as_deref(), Some("Private Zed"));

    let updated = contacts::update(
        &path,
        None,
        " did:guardian:zed ",
        ContactPatch {
            name: Some("  Updated  ".into()),
            alias: Some(String::new()),
            notes: Some("  memo  ".into()),
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.name.as_deref(), Some("Updated"));
    assert_eq!(updated.alias, None);
    assert_eq!(updated.notes.as_deref(), Some("memo"));
    assert_eq!(
        contacts::get(&path, None, "did:guardian:zed")
            .await
            .unwrap()
            .name
            .as_deref(),
        Some("Updated")
    );

    assert!(contacts::delete(&path, None, "did:guardian:zed")
        .await
        .unwrap());
    assert_eq!(contacts::list(&path, None).await.unwrap().len(), 1);
    assert_eq!(
        contacts::list(&path, Some("did:guardian:member"))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn contacts_reject_invalid_duplicates_missing_and_malformed_storage() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("contacts.json");

    for did in ["", "guardian:missing-prefix"] {
        let error = contacts::create(
            &path,
            None,
            ContactDraft {
                did: did.into(),
                ..ContactDraft::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ApiError::BadRequest(_)));
    }

    let draft = ContactDraft {
        did: "did:guardian:duplicate".into(),
        ..ContactDraft::default()
    };
    contacts::create(&path, None, draft.clone()).await.unwrap();
    assert!(matches!(
        contacts::create(&path, None, draft).await.unwrap_err(),
        ApiError::Conflict(_)
    ));
    assert!(matches!(
        contacts::get(&path, Some("another-owner"), "did:guardian:duplicate")
            .await
            .unwrap_err(),
        ApiError::NotFound(_)
    ));
    assert!(matches!(
        contacts::update(&path, None, "did:guardian:missing", ContactPatch::default())
            .await
            .unwrap_err(),
        ApiError::NotFound(_)
    ));
    assert!(matches!(
        contacts::delete(&path, None, "did:guardian:missing")
            .await
            .unwrap_err(),
        ApiError::NotFound(_)
    ));

    tokio::fs::write(&path, b"not json").await.unwrap();
    assert!(matches!(
        contacts::list(&path, None).await.unwrap_err(),
        ApiError::Internal(_)
    ));
}

#[tokio::test]
async fn advisory_store_caps_replaces_finds_and_reports_bad_json() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("nested/advisories.jsonl");

    assert!(advisory_store::list_recent(&path, 10)
        .await
        .unwrap()
        .is_empty());
    assert!(advisory_store::find_for_alert(&path, "missing")
        .await
        .unwrap()
        .is_none());

    advisory_store::append_capped(&path, recommendation("alert-1", "rec-1", 0.5), 2)
        .await
        .unwrap();
    advisory_store::append_capped(&path, recommendation("alert-2", "rec-2", 0.6), 2)
        .await
        .unwrap();
    advisory_store::append_capped(&path, recommendation("alert-3", "rec-3", 0.7), 2)
        .await
        .unwrap();
    let recent = advisory_store::list_recent(&path, 1).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].alert_id, "alert-3");
    assert!(advisory_store::find_for_alert(&path, "alert-1")
        .await
        .unwrap()
        .is_none());

    advisory_store::append_capped(&path, recommendation("alert-3", "replacement", 0.9), 2)
        .await
        .unwrap();
    let replaced = advisory_store::find_for_alert(&path, "alert-3")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replaced.rec_id, "replacement");
    assert_eq!(advisory_store::list_recent(&path, 0).await.unwrap(), vec![]);

    tokio::fs::write(&path, b"{bad json}\n").await.unwrap();
    assert!(advisory_store::list_recent(&path, 2).await.is_err());
}

#[tokio::test]
async fn interface_and_nft_counter_parsers_cover_missing_invalid_and_sorted_inputs() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("net");
    for iface in ["zeta0", "alpha0", ".hidden", "missing-tx", "invalid-rx"] {
        tokio::fs::create_dir_all(root.join(iface).join("statistics"))
            .await
            .unwrap();
    }
    for (iface, rx, tx, rx_packets, tx_packets) in [
        ("zeta0", "20", "30", Some("2"), Some("3")),
        ("alpha0", "10\n", "11\n", None, None),
        (".hidden", "99", "99", None, None),
        ("missing-tx", "4", "", None, None),
        ("invalid-rx", "nope", "4", None, None),
    ] {
        let stats = root.join(iface).join("statistics");
        tokio::fs::write(stats.join("rx_bytes"), rx).await.unwrap();
        if iface != "missing-tx" {
            tokio::fs::write(stats.join("tx_bytes"), tx).await.unwrap();
        }
        if let Some(value) = rx_packets {
            tokio::fs::write(stats.join("rx_packets"), value)
                .await
                .unwrap();
        }
        if let Some(value) = tx_packets {
            tokio::fs::write(stats.join("tx_packets"), value)
                .await
                .unwrap();
        }
    }
    let counters = read_interface_counters(&root).await.unwrap();
    assert_eq!(counters.len(), 2);
    assert_eq!(counters[0].iface, "alpha0");
    assert_eq!((counters[0].rx_packets, counters[0].tx_packets), (0, 0));
    assert_eq!(counters[1].iface, "zeta0");
    assert_eq!((counters[1].rx_bytes, counters[1].tx_bytes), (20, 30));
    assert!(read_interface_counters(&temp.path().join("absent"))
        .await
        .unwrap()
        .is_empty());

    let parsed = parse_nft_counters_json(
        br#"{"nftables":[{"metainfo":{}},{"counter":{"name":"zeta","bytes":9}},{"counter":{"name":"skip-name"}},{"counter":{"name":"alpha","bytes":3}}]}"#,
    )
    .unwrap();
    assert_eq!(
        parsed
            .iter()
            .map(|counter| (counter.category.as_str(), counter.bytes))
            .collect::<Vec<_>>(),
        vec![("alpha", 3), ("zeta", 9)]
    );
    assert!(parse_nft_counters_json(br#"{"other":[]}"#)
        .unwrap()
        .is_empty());
    assert!(parse_nft_counters_json(b"invalid").is_err());
}

#[test]
fn quota_period_math_handles_boundaries_invalid_values_and_bands() {
    assert_eq!(normalize_period(" DAILY ").unwrap(), "daily");
    assert_eq!(normalize_period("Weekly").unwrap(), "weekly");
    assert_eq!(normalize_period("monthly").unwrap(), "monthly");
    assert!(normalize_period("yearly").is_err());

    let now = Utc.with_ymd_and_hms(2024, 12, 31, 23, 59, 59).unwrap();
    assert_eq!(
        period_start_for(now, "daily").unwrap(),
        Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap()
    );
    assert_eq!(
        period_start_for(now, "weekly").unwrap(),
        Utc.with_ymd_and_hms(2024, 12, 30, 0, 0, 0).unwrap()
    );
    let monthly = period_start_for(now, "monthly").unwrap();
    assert_eq!(monthly, Utc.with_ymd_and_hms(2024, 12, 1, 0, 0, 0).unwrap());
    assert_eq!(
        next_period_start(monthly, "monthly").unwrap(),
        Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
    );
    assert_eq!(
        next_period_start(now, "daily").unwrap(),
        now + chrono::Duration::days(1)
    );
    assert_eq!(
        next_period_start(now, "weekly").unwrap(),
        now + chrono::Duration::weeks(1)
    );
    assert!(next_period_start(now, "invalid").is_err());
    assert!(period_has_rolled("bad timestamp", "daily", now));
    assert!(period_has_rolled("2024-11-01T00:00:00Z", "monthly", now));
    assert!(!period_has_rolled("2024-12-31T00:00:00Z", "daily", now));
    assert!(period_has_rolled("2024-12-01T00:00:00Z", "invalid", now));

    assert_eq!(used_pct(1, None), None);
    assert_eq!(used_pct(1, Some(0)), None);
    assert_eq!(used_pct(3, Some(4)), Some(75.0));
    assert_eq!(usage_band(None), "none");
    assert_eq!(usage_band(Some(50.0)), "green");
    assert_eq!(usage_band(Some(50.1)), "amber");
    assert_eq!(usage_band(Some(80.0)), "amber");
    assert_eq!(usage_band(Some(80.1)), "red");
}

#[test]
fn pcr_source_sets_are_complete_stable_and_serializable() {
    let hardware = default_measurement_sources("node-a");
    assert_eq!(hardware.len(), 5);
    assert_eq!(
        hardware
            .iter()
            .map(|source| source.pcr_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(hardware[0].source_type, "boot_chain");
    assert!(hardware[0].critical);
    assert_eq!(hardware[4].source, "/etc/sgx-guardian/config/node-a.yaml");
    let encoded = serde_json::to_vec(&hardware).unwrap();
    let decoded: Vec<sgx_guardian_client::secure_element::pcr_config::PcrMeasurementSource> =
        serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded[4].label, "Guardian config (static)");

    let software = software_measurement_sources();
    assert_eq!(software.len(), 5);
    assert!(software.iter().all(|source| !source.critical));
    assert_eq!(software[0].source, "software-boot-v1.0");
    assert_eq!(software[4].source_type, "file");
}

async fn response_json(error: ApiError) -> (axum::http::StatusCode, Value) {
    let response = error.into_response();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn every_api_error_variant_has_the_expected_status_and_code() {
    use axum::http::StatusCode;

    let cases = vec![
        (
            ApiError::NotFound("m".into()),
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
        ),
        (
            ApiError::BadRequest("m".into()),
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
        ),
        (
            ApiError::Unauthorized("m".into()),
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
        ),
        (ApiError::Locked("m".into()), StatusCode::LOCKED, "LOCKED"),
        (
            ApiError::TooManyRequests("m".into()),
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_REQUESTS",
        ),
        (
            ApiError::Forbidden("m".into()),
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
        ),
        (
            ApiError::Conflict("m".into()),
            StatusCode::CONFLICT,
            "CONFLICT",
        ),
        (
            ApiError::DeviceAlreadyPaired("m".into()),
            StatusCode::CONFLICT,
            "DEVICE_ALREADY_PAIRED",
        ),
        (
            ApiError::PayloadTooLarge("m".into()),
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
        ),
        (ApiError::Gone("m".into()), StatusCode::GONE, "GONE"),
        (
            ApiError::ServiceUnavailable {
                code: "OFFLINE",
                message: "m".into(),
            },
            StatusCode::SERVICE_UNAVAILABLE,
            "OFFLINE",
        ),
        (
            ApiError::Internal("m".into()),
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
        ),
    ];
    for (error, expected_status, expected_code) in cases {
        let (status, body) = response_json(error).await;
        assert_eq!(status, expected_status);
        assert_eq!(body, json!({"error":{"code":expected_code,"message":"m"}}));
    }

    assert!(matches!(
        ApiError::from(std::io::Error::other("disk")),
        ApiError::Internal(message) if message.contains("disk")
    ));
    assert!(matches!(
        ApiError::from(serde_json::from_str::<Value>("{").unwrap_err()),
        ApiError::Internal(message) if message.starts_with("json:")
    ));
    assert!(matches!(
        ApiError::from(anyhow::anyhow!("context")),
        ApiError::Internal(message) if message == "context"
    ));
}
