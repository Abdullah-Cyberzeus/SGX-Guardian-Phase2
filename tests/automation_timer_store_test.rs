use chrono::{Duration, TimeZone, Utc};
use sgx_guardian_client::automation::schema::{FailurePolicy, RuleAction};
use sgx_guardian_client::automation::timer_store::{PendingAction, PendingActionStore};

fn action() -> RuleAction {
    RuleAction::Command {
        entity_id: "light.kitchen".into(),
        domain: "light".into(),
        command: "turn_on".into(),
        service_data: Some(serde_json::json!({"brightness": 10})),
        on_failure: FailurePolicy::Retry,
    }
}

fn pending(id: &str) -> PendingAction {
    PendingAction {
        id: id.into(),
        rule_id: format!("rule-{id}"),
        action: action(),
        execute_at: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
        created_at: Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap(),
    }
}

#[tokio::test]
async fn new_store_missing_file_starts_empty() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        PendingActionStore::new(dir.path().join("p.json").to_str().unwrap())
            .get_all_pending()
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn add_pending_action_stores_item() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = PendingActionStore::new(file.path().to_str().unwrap());
    store.add_pending_action(pending("a")).await.unwrap();
    assert_eq!(store.get_all_pending().await.len(), 1);
}

#[tokio::test]
async fn add_pending_action_replaces_same_id() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = PendingActionStore::new(file.path().to_str().unwrap());
    store.add_pending_action(pending("a")).await.unwrap();
    let mut replacement = pending("a");
    replacement.rule_id = "replacement".into();
    store.add_pending_action(replacement).await.unwrap();
    let all = store.get_all_pending().await;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].rule_id, "replacement");
}

#[tokio::test]
async fn remove_existing_action_deletes_item() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = PendingActionStore::new(file.path().to_str().unwrap());
    store.add_pending_action(pending("a")).await.unwrap();
    store.remove_pending_action("a").await.unwrap();
    assert!(store.get_all_pending().await.is_empty());
}

#[tokio::test]
async fn remove_missing_action_is_ok() {
    let file = tempfile::NamedTempFile::new().unwrap();
    PendingActionStore::new(file.path().to_str().unwrap())
        .remove_pending_action("missing")
        .await
        .unwrap();
}

#[tokio::test]
async fn persistence_round_trips_one_item() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    PendingActionStore::new(&path)
        .add_pending_action(pending("a"))
        .await
        .unwrap();
    assert_eq!(
        PendingActionStore::new(&path).get_all_pending().await[0].id,
        "a"
    );
}

#[tokio::test]
async fn persistence_round_trips_multiple_items() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    let store = PendingActionStore::new(&path);
    store.add_pending_action(pending("a")).await.unwrap();
    store.add_pending_action(pending("b")).await.unwrap();
    assert_eq!(
        PendingActionStore::new(&path).get_all_pending().await.len(),
        2
    );
}

#[tokio::test]
async fn malformed_existing_file_starts_empty() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"{").unwrap();
    assert!(PendingActionStore::new(file.path().to_str().unwrap())
        .get_all_pending()
        .await
        .is_empty());
}

#[tokio::test]
async fn empty_existing_file_starts_empty() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(PendingActionStore::new(file.path().to_str().unwrap())
        .get_all_pending()
        .await
        .is_empty());
}

#[tokio::test]
async fn wrong_shape_existing_file_starts_empty() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), br#"{"items":[]}"#).unwrap();
    assert!(PendingActionStore::new(file.path().to_str().unwrap())
        .get_all_pending()
        .await
        .is_empty());
}

#[tokio::test]
async fn persisted_json_contains_pending_key() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = PendingActionStore::new(file.path().to_str().unwrap());
    store.add_pending_action(pending("a")).await.unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
    assert!(value.get("pending").is_some());
}

#[tokio::test]
async fn persisted_command_action_keeps_service_data() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = PendingActionStore::new(file.path().to_str().unwrap());
    store.add_pending_action(pending("a")).await.unwrap();
    let loaded = PendingActionStore::new(file.path().to_str().unwrap())
        .get_all_pending()
        .await;
    match &loaded[0].action {
        RuleAction::Command { service_data, .. } => {
            assert_eq!(service_data.as_ref().unwrap()["brightness"], 10)
        }
        _ => panic!("expected command"),
    }
}

#[tokio::test]
async fn delay_action_round_trips() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut pa = pending("a");
    pa.action = RuleAction::Delay { delay_secs: 0 };
    PendingActionStore::new(file.path().to_str().unwrap())
        .add_pending_action(pa)
        .await
        .unwrap();
    assert_eq!(
        PendingActionStore::new(file.path().to_str().unwrap())
            .get_all_pending()
            .await[0]
            .action,
        RuleAction::Delay { delay_secs: 0 }
    );
}

#[tokio::test]
async fn notification_action_round_trips() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut pa = pending("a");
    pa.action = RuleAction::Notification {
        message: "m".into(),
        severity: "warning".into(),
        on_failure: FailurePolicy::Log,
    };
    PendingActionStore::new(file.path().to_str().unwrap())
        .add_pending_action(pa)
        .await
        .unwrap();
    assert!(matches!(
        PendingActionStore::new(file.path().to_str().unwrap())
            .get_all_pending()
            .await[0]
            .action,
        RuleAction::Notification { .. }
    ));
}

#[tokio::test]
async fn execute_at_past_value_is_preserved() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut pa = pending("a");
    pa.execute_at = Utc::now() - Duration::seconds(1);
    PendingActionStore::new(file.path().to_str().unwrap())
        .add_pending_action(pa.clone())
        .await
        .unwrap();
    assert_eq!(
        PendingActionStore::new(file.path().to_str().unwrap())
            .get_all_pending()
            .await[0]
            .execute_at,
        pa.execute_at
    );
}

#[tokio::test]
async fn execute_at_future_value_is_preserved() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut pa = pending("a");
    pa.execute_at = Utc::now() + Duration::days(1);
    PendingActionStore::new(file.path().to_str().unwrap())
        .add_pending_action(pa.clone())
        .await
        .unwrap();
    assert_eq!(
        PendingActionStore::new(file.path().to_str().unwrap())
            .get_all_pending()
            .await[0]
            .execute_at,
        pa.execute_at
    );
}

#[tokio::test]
async fn empty_id_is_allowed_as_map_key() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = PendingActionStore::new(file.path().to_str().unwrap());
    store.add_pending_action(pending("")).await.unwrap();
    assert_eq!(store.get_all_pending().await[0].id, "");
}

#[tokio::test]
async fn removing_one_item_keeps_other_item() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = PendingActionStore::new(file.path().to_str().unwrap());
    store.add_pending_action(pending("a")).await.unwrap();
    store.add_pending_action(pending("b")).await.unwrap();
    store.remove_pending_action("a").await.unwrap();
    assert_eq!(store.get_all_pending().await[0].id, "b");
}

#[tokio::test]
async fn remove_persists_deletion() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    let store = PendingActionStore::new(&path);
    store.add_pending_action(pending("a")).await.unwrap();
    store.remove_pending_action("a").await.unwrap();
    assert!(PendingActionStore::new(&path)
        .get_all_pending()
        .await
        .is_empty());
}

#[tokio::test]
async fn get_all_pending_returns_clones() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = PendingActionStore::new(file.path().to_str().unwrap());
    store.add_pending_action(pending("a")).await.unwrap();
    let mut all = store.get_all_pending().await;
    all[0].id = "changed".into();
    assert_eq!(store.get_all_pending().await[0].id, "a");
}

#[tokio::test]
async fn store_instances_are_isolated_by_path() {
    let a = tempfile::NamedTempFile::new().unwrap();
    let b = tempfile::NamedTempFile::new().unwrap();
    PendingActionStore::new(a.path().to_str().unwrap())
        .add_pending_action(pending("a"))
        .await
        .unwrap();
    assert!(PendingActionStore::new(b.path().to_str().unwrap())
        .get_all_pending()
        .await
        .is_empty());
}

#[tokio::test]
async fn store_loads_preseeded_valid_data() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let pa = pending("seed");
    std::fs::write(
        file.path(),
        serde_json::to_vec(&serde_json::json!({"pending": {"seed": pa}})).unwrap(),
    )
    .unwrap();
    assert_eq!(
        PendingActionStore::new(file.path().to_str().unwrap())
            .get_all_pending()
            .await[0]
            .id,
        "seed"
    );
}

#[tokio::test]
async fn store_ignores_preseeded_pending_with_invalid_value() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), br#"{"pending":{"bad":{"id":"bad"}}}"#).unwrap();
    assert!(PendingActionStore::new(file.path().to_str().unwrap())
        .get_all_pending()
        .await
        .is_empty());
}

#[tokio::test]
async fn replacing_preserves_single_map_entry_after_reload() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    let store = PendingActionStore::new(&path);
    store.add_pending_action(pending("a")).await.unwrap();
    store.add_pending_action(pending("a")).await.unwrap();
    assert_eq!(
        PendingActionStore::new(&path).get_all_pending().await.len(),
        1
    );
}

#[tokio::test]
async fn persisted_json_is_pretty_object() {
    let file = tempfile::NamedTempFile::new().unwrap();
    PendingActionStore::new(file.path().to_str().unwrap())
        .add_pending_action(pending("a"))
        .await
        .unwrap();
    let content = std::fs::read_to_string(file.path()).unwrap();
    assert!(content.starts_with("{\n"));
    assert!(content.contains("\"pending\""));
}
