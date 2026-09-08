use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::api::handlers::pagination::{PaginatedResponse, PaginationParams};
use crate::api::state::AppState;
use crate::automation::schema::AutomationRule;

#[derive(Deserialize)]
pub struct RuleQueryParams {
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

/// GET /api/automations?page=1&per_page=20
pub async fn list_automations(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RuleQueryParams>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let engine = match state.get_automation_engine().await {
        Some(e) => e,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "AutomationEngine not initialized" })),
            ));
        }
    };

    let rules = engine.get_rules().await;
    let paginated = PaginatedResponse::paginate(rules, &query.pagination, 20);

    Ok((StatusCode::OK, Json(serde_json::json!(paginated))))
}

/// POST /api/automations
pub async fn create_automation(
    State(state): State<Arc<AppState>>,
    Json(rule): Json<AutomationRule>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let engine = match state.get_automation_engine().await {
        Some(e) => e,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "AutomationEngine not initialized" })),
            ));
        }
    };

    engine.add_rule(rule.clone()).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "created",
            "rule_id": rule.id,
            "message": format!("Automation rule '{}' created successfully", rule.name)
        })),
    ))
}

/// PUT /api/automations/{id}
pub async fn update_automation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(mut rule): Json<AutomationRule>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let engine = match state.get_automation_engine().await {
        Some(e) => e,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "AutomationEngine not initialized" })),
            ));
        }
    };

    rule.id = id.clone();

    engine.update_rule(rule.clone()).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e })),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "updated",
            "rule_id": id,
            "message": format!("Automation rule '{}' updated successfully", rule.name)
        })),
    ))
}

/// DELETE /api/automations/{id}
pub async fn delete_automation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let engine = match state.get_automation_engine().await {
        Some(e) => e,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "AutomationEngine not initialized" })),
            ));
        }
    };

    engine.delete_rule(&id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e })),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "deleted",
            "rule_id": id,
            "message": format!("Automation rule '{}' deleted successfully", id)
        })),
    ))
}

/// POST /api/automations/{id}/enable
pub async fn enable_automation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let engine = match state.get_automation_engine().await {
        Some(e) => e,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "AutomationEngine not initialized" })),
            ));
        }
    };

    engine.toggle_rule(&id, true).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e })),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "enabled",
            "rule_id": id,
            "message": format!("Automation rule '{}' enabled", id)
        })),
    ))
}

/// POST /api/automations/{id}/disable
pub async fn disable_automation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let engine = match state.get_automation_engine().await {
        Some(e) => e,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "AutomationEngine not initialized" })),
            ));
        }
    };

    engine.toggle_rule(&id, false).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e })),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "disabled",
            "rule_id": id,
            "message": format!("Automation rule '{}' disabled", id)
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::schema::{AutomationRule, RuleAction, RuleTrigger};

    fn rule() -> AutomationRule {
        AutomationRule {
            id: "rule_test_001".to_string(),
            name: "Test Rule".to_string(),
            priority: 100,
            enabled: true,
            trigger: RuleTrigger::StateChanged {
                entity_id: "input_boolean.1".to_string(),
                to_state: Some("on".to_string()),
            },
            conditions: vec![],
            actions: vec![RuleAction::Command {
                entity_id: "input_boolean.2".to_string(),
                domain: "input_boolean".to_string(),
                command: "turn_on".to_string(),
                service_data: None,
                on_failure: Default::default(),
            }],
        }
    }

    #[test]
    fn test_automation_rule_json_roundtrip() {
        let rule = rule();

        let json_str = serde_json::to_string(&rule).unwrap();
        let deserialized: AutomationRule = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deserialized.id, "rule_test_001");
        assert_eq!(deserialized.priority, 100);
        assert!(deserialized.enabled);
    }

    #[tokio::test]
    async fn every_handler_reports_service_unavailable_without_an_engine() {
        let temp = tempfile::tempdir().expect("state directory");
        let state = AppState::for_tests(temp.path(), "nodeA", temp.path().to_string_lossy());
        let pagination = PaginationParams {
            page: None,
            per_page: None,
        };

        let list_error =
            list_automations(State(state.clone()), Query(RuleQueryParams { pagination }))
                .await
                .err()
                .expect("missing engine");
        assert_eq!(list_error.0, StatusCode::SERVICE_UNAVAILABLE);

        let calls = [
            create_automation(State(state.clone()), Json(rule()))
                .await
                .err()
                .expect("create without engine")
                .0,
            update_automation(State(state.clone()), Path("other".into()), Json(rule()))
                .await
                .err()
                .expect("update without engine")
                .0,
            delete_automation(State(state.clone()), Path("rule".into()))
                .await
                .err()
                .expect("delete without engine")
                .0,
            enable_automation(State(state.clone()), Path("rule".into()))
                .await
                .err()
                .expect("enable without engine")
                .0,
            disable_automation(State(state), Path("rule".into()))
                .await
                .err()
                .expect("disable without engine")
                .0,
        ];
        assert!(calls
            .into_iter()
            .all(|status| status == StatusCode::SERVICE_UNAVAILABLE));
    }

    async fn state_with_engine(temp: &std::path::Path) -> Arc<AppState> {
        use crate::automation::engine::AutomationEngine;
        use crate::automation::presence::PresenceTracker;
        use crate::automation::timer_store::PendingActionStore;
        use crate::device::manager::DeviceManager;
        use crate::device::registry::DeviceRegistry;
        use crate::homeassistant::events::EventBus;
        use crate::homeassistant::rest::HaRestClient;
        use crate::homeassistant::HomeAssistantConfig;

        let registry = Arc::new(DeviceRegistry::new(
            temp.join("devices.json").to_str().unwrap(),
        ));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: "http://127.0.0.1:1".to_string(),
            token: "t".into(),
        }));
        let event_bus = EventBus::new();
        let dm = DeviceManager::new(registry, ha_rest, event_bus.clone(), None);
        let engine = AutomationEngine::new(
            temp.join("automations.json").to_str().unwrap(),
            dm,
            PresenceTracker::new(),
            PendingActionStore::new(temp.join("timers.json").to_str().unwrap()),
            event_bus,
        );
        let state = AppState::for_tests(temp, "nodeA", temp.to_string_lossy());
        state.automation_engine.write().await.replace(engine);
        state
    }

    async fn response_status(
        result: Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)>,
    ) -> (StatusCode, serde_json::Value) {
        let response = match result {
            Ok(ok) => ok.into_response(),
            Err(err) => err.into_response(),
        };
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON body")
        };
        (status, body)
    }

    #[tokio::test]
    async fn create_list_update_enable_disable_and_delete_round_trip() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = state_with_engine(temp.path()).await;

        let (status, body) =
            response_status(create_automation(State(state.clone()), Json(rule())).await).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["rule_id"], "rule_test_001");

        let (status, body) = response_status(
            list_automations(
                State(state.clone()),
                Query(RuleQueryParams {
                    pagination: PaginationParams {
                        page: None,
                        per_page: None,
                    },
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The engine seeds one default rule on first run, plus the one just created.
        assert_eq!(body["items"].as_array().unwrap().len(), 2);

        let mut updated = rule();
        updated.name = "Renamed Rule".into();
        let (status, body) = response_status(
            update_automation(
                State(state.clone()),
                Path("rule_test_001".into()),
                Json(updated),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["message"].as_str().unwrap().contains("Renamed Rule"));

        let (status, _) = response_status(
            disable_automation(State(state.clone()), Path("rule_test_001".into())).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = response_status(
            enable_automation(State(state.clone()), Path("rule_test_001".into())).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = response_status(
            delete_automation(State(state.clone()), Path("rule_test_001".into())).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Deleted: further operations on it 404.
        let (status, _) = response_status(
            update_automation(State(state), Path("rule_test_001".into()), Json(rule())).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_replaces_an_existing_rule_with_the_same_id() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = state_with_engine(temp.path()).await;
        let (status, _) =
            response_status(create_automation(State(state.clone()), Json(rule())).await).await;
        assert_eq!(status, StatusCode::CREATED);

        let mut replacement = rule();
        replacement.name = "Replaced Rule".into();
        let (status, body) =
            response_status(create_automation(State(state.clone()), Json(replacement)).await).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let (status, body) = response_status(
            list_automations(
                State(state),
                Query(RuleQueryParams {
                    pagination: PaginationParams {
                        page: None,
                        per_page: None,
                    },
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let items = body["items"].as_array().unwrap();
        // Still one default rule plus one "rule_test_001" (replaced, not duplicated).
        assert_eq!(items.len(), 2);
        assert!(items
            .iter()
            .any(|r| r["id"] == "rule_test_001" && r["name"] == "Replaced Rule"));
    }

    #[tokio::test]
    async fn enable_disable_and_delete_404_for_unknown_rule() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = state_with_engine(temp.path()).await;

        let (status, _) =
            response_status(enable_automation(State(state.clone()), Path("missing".into())).await)
                .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) =
            response_status(disable_automation(State(state.clone()), Path("missing".into())).await)
                .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) =
            response_status(delete_automation(State(state), Path("missing".into())).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
