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
            ))
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
            ))
        }
    };

    engine
        .add_rule(rule.clone())
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))))?;

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
            ))
        }
    };

    rule.id = id.clone();

    engine
        .update_rule(rule.clone())
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": e }))))?;

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
            ))
        }
    };

    engine
        .delete_rule(&id)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": e }))))?;

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
            ))
        }
    };

    engine
        .toggle_rule(&id, true)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": e }))))?;

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
            ))
        }
    };

    engine
        .toggle_rule(&id, false)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": e }))))?;

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
    use crate::automation::schema::{AutomationRule, RuleAction, RuleTrigger};

    #[test]
    fn test_automation_rule_json_roundtrip() {
        let rule = AutomationRule {
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
        };

        let json_str = serde_json::to_string(&rule).unwrap();
        let deserialized: AutomationRule = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deserialized.id, "rule_test_001");
        assert_eq!(deserialized.priority, 100);
        assert!(deserialized.enabled);
    }
}
