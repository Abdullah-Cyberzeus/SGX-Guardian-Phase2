use chrono::{TimeZone, Utc};
use sgx_guardian_client::advisory::model::{RemediationRecommendation, RemediationStep};
use sgx_guardian_client::advisory::store::{append_capped, find_for_alert, list_recent};

fn rec(id: &str) -> RemediationRecommendation {
    RemediationRecommendation {
        rec_id: format!("rec-{id}"),
        alert_id: format!("alert-{id}"),
        title: format!("title-{id}"),
        summary: format!("summary-{id}"),
        severity: "medium".into(),
        confidence: 0.5,
        steps: vec![RemediationStep {
            order: 1,
            action: "act".into(),
            rationale: "why".into(),
            automatable: false,
        }],
        context: vec![format!("ctx-{id}")],
        references: vec![format!("ref-{id}")],
        source: "test".into(),
        generated_at: Utc.with_ymd_and_hms(2026, 3, 4, 5, 6, 7).unwrap(),
    }
}

#[tokio::test]
async fn list_recent_missing_file_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    assert!(list_recent(&dir.path().join("missing.jsonl"), 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn find_for_alert_missing_file_is_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(find_for_alert(&dir.path().join("missing.jsonl"), "alert-1")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn append_creates_parent_directories() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    assert!(path.exists());
}

#[tokio::test]
async fn append_then_list_returns_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    assert_eq!(list_recent(&path, 10).await.unwrap()[0].alert_id, "alert-1");
}

#[tokio::test]
async fn append_writes_json_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    let content = std::fs::read_to_string(path).unwrap();
    assert!(content.ends_with('\n'));
    assert_eq!(content.lines().count(), 1);
}

#[tokio::test]
async fn append_preserves_insertion_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    append_capped(&path, rec("2"), 10).await.unwrap();
    let ids: Vec<_> = list_recent(&path, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|item| item.alert_id)
        .collect();
    assert_eq!(ids, vec!["alert-1", "alert-2"]);
}

#[tokio::test]
async fn append_replaces_existing_alert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    let mut replacement = rec("replacement");
    replacement.alert_id = "alert-1".into();
    append_capped(&path, replacement, 10).await.unwrap();
    let items = list_recent(&path, 10).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].rec_id, "rec-replacement");
}

#[tokio::test]
async fn append_replaces_last_matching_alert_when_duplicates_exist() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    std::fs::write(
        &path,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&rec("1")).unwrap(),
            serde_json::to_string(&rec("1")).unwrap()
        ),
    )
    .unwrap();
    let mut replacement = rec("x");
    replacement.alert_id = "alert-1".into();
    append_capped(&path, replacement, 10).await.unwrap();
    let items = list_recent(&path, 10).await.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[1].rec_id, "rec-x");
}

#[tokio::test]
async fn cap_zero_drops_all_items() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 0).await.unwrap();
    assert!(list_recent(&path, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn cap_one_keeps_latest_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 1).await.unwrap();
    append_capped(&path, rec("2"), 1).await.unwrap();
    assert_eq!(list_recent(&path, 10).await.unwrap()[0].alert_id, "alert-2");
}

#[tokio::test]
async fn cap_two_rotates_oldest_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 2).await.unwrap();
    append_capped(&path, rec("2"), 2).await.unwrap();
    append_capped(&path, rec("3"), 2).await.unwrap();
    let ids: Vec<_> = list_recent(&path, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|item| item.alert_id)
        .collect();
    assert_eq!(ids, vec!["alert-2", "alert-3"]);
}

#[tokio::test]
async fn list_recent_zero_limit_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    assert!(list_recent(&path, 0).await.unwrap().is_empty());
}

#[tokio::test]
async fn list_recent_limit_less_than_len_keeps_tail() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    for id in ["1", "2", "3"] {
        append_capped(&path, rec(id), 10).await.unwrap();
    }
    let ids: Vec<_> = list_recent(&path, 2)
        .await
        .unwrap()
        .into_iter()
        .map(|item| item.alert_id)
        .collect();
    assert_eq!(ids, vec!["alert-2", "alert-3"]);
}

#[tokio::test]
async fn list_recent_limit_equal_len_returns_all() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    append_capped(&path, rec("2"), 10).await.unwrap();
    assert_eq!(list_recent(&path, 2).await.unwrap().len(), 2);
}

#[tokio::test]
async fn find_for_alert_returns_latest_matching_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    assert_eq!(
        find_for_alert(&path, "alert-1").await.unwrap().unwrap().rec_id,
        "rec-1"
    );
}

#[tokio::test]
async fn find_for_alert_returns_none_for_absent_alert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    assert!(find_for_alert(&path, "absent").await.unwrap().is_none());
}

#[tokio::test]
async fn empty_existing_file_loads_as_empty() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(list_recent(file.path(), 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn blank_lines_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    std::fs::write(&path, b"\n\n").unwrap();
    assert!(list_recent(&path, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn malformed_json_line_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    std::fs::write(&path, b"{\n").unwrap();
    assert!(list_recent(&path, 10).await.is_err());
}

#[tokio::test]
async fn missing_required_field_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    std::fs::write(&path, br#"{"rec_id":"r"}"#).unwrap();
    assert!(find_for_alert(&path, "x").await.is_err());
}

#[tokio::test]
async fn line_without_trailing_newline_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    std::fs::write(&path, serde_json::to_vec(&rec("1")).unwrap()).unwrap();
    assert_eq!(list_recent(&path, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn appending_after_line_without_trailing_newline_rewrites_valid_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    std::fs::write(&path, serde_json::to_vec(&rec("1")).unwrap()).unwrap();
    append_capped(&path, rec("2"), 10).await.unwrap();
    let items = list_recent(&path, 10).await.unwrap();
    assert_eq!(items.len(), 2);
}

#[tokio::test]
async fn append_preserves_nested_recommendation_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    let item = list_recent(&path, 10).await.unwrap().remove(0);
    assert_eq!(item.steps[0].rationale, "why");
    assert_eq!(item.context, vec!["ctx-1"]);
    assert_eq!(item.references, vec!["ref-1"]);
}

#[tokio::test]
async fn append_with_large_cap_keeps_all_items() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    for id in 0..5 {
        append_capped(&path, rec(&id.to_string()), 99).await.unwrap();
    }
    assert_eq!(list_recent(&path, 99).await.unwrap().len(), 5);
}

#[tokio::test]
async fn replacement_does_not_move_item_position() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("items.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    append_capped(&path, rec("2"), 10).await.unwrap();
    let mut replacement = rec("z");
    replacement.alert_id = "alert-1".into();
    append_capped(&path, replacement, 10).await.unwrap();
    let ids: Vec<_> = list_recent(&path, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|item| item.alert_id)
        .collect();
    assert_eq!(ids, vec!["alert-1", "alert-2"]);
}

#[tokio::test]
async fn append_to_path_without_parent_component_works() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flat.jsonl");
    append_capped(&path, rec("1"), 10).await.unwrap();
    assert_eq!(list_recent(&path, 10).await.unwrap().len(), 1);
}
