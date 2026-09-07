use crate::api::{error::ApiError, state::AppState};
use crate::rules::RulesConfig;
use crate::rules::errors::RulesError;
use crate::rules::eval::evaluate;
use crate::rules::exec;
use crate::rules::model::{Rule, RuleDraft, RuleEvent, RulePatch};
use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct EnabledBody {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ExecutionsQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub success: bool,
    pub rule_id: String,
}

#[derive(Debug, Serialize)]
pub struct RuleTestResponse {
    pub rule_id: String,
    pub would_fire: bool,
    pub dry_run: bool,
    pub trigger_summary: String,
    pub actions: Vec<String>,
    pub outcome: String,
}

pub async fn list(State(state): State<Arc<AppState>>) -> Result<Json<Vec<Rule>>, ApiError> {
    let base = rules_base();
    let signer = runtime_signer(&state.node_id)?;
    let rules = crate::rules::store::list_rules(&base, &state.node_id, signer.as_ref())
        .map_err(map_rules_error)?;
    Ok(Json(rules))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RuleDraft>,
) -> Result<Json<Rule>, ApiError> {
    let base = rules_base();
    let signer = runtime_signer(&state.node_id)?;
    let rule = crate::rules::store::create_rule(&base, &state.node_id, signer.as_ref(), body)
        .map_err(map_rules_error)?;
    Ok(Json(rule))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Rule>, ApiError> {
    let base = rules_base();
    let signer = runtime_signer(&state.node_id)?;
    let rule = crate::rules::store::get_rule(&base, &state.node_id, signer.as_ref(), &id)
        .map_err(map_rules_error)?;
    Ok(Json(rule))
}

pub async fn edit(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<RulePatch>,
) -> Result<Json<Rule>, ApiError> {
    let base = rules_base();
    let signer = runtime_signer(&state.node_id)?;
    let rule = crate::rules::store::edit_rule(&base, &state.node_id, signer.as_ref(), &id, body)
        .map_err(map_rules_error)?;
    Ok(Json(rule))
}

pub async fn set_enabled(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<EnabledBody>,
) -> Result<Json<Rule>, ApiError> {
    let base = rules_base();
    let signer = runtime_signer(&state.node_id)?;
    let rule =
        crate::rules::store::set_enabled(&base, &state.node_id, signer.as_ref(), &id, body.enabled)
            .map_err(map_rules_error)?;
    Ok(Json(rule))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let base = rules_base();
    let signer = runtime_signer(&state.node_id)?;
    crate::rules::store::delete_rule(&base, &state.node_id, signer.as_ref(), &id)
        .map_err(map_rules_error)?;
    Ok(Json(DeleteResponse {
        success: true,
        rule_id: id,
    }))
}

pub async fn test(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<RuleEvent>>,
) -> Result<Json<RuleTestResponse>, ApiError> {
    let base = rules_base();
    let signer = runtime_signer(&state.node_id)?;
    let rule = crate::rules::store::get_rule(&base, &state.node_id, signer.as_ref(), &id)
        .map_err(map_rules_error)?;
    let event = body
        .map(|Json(event)| event)
        .unwrap_or_else(|| RuleEvent::sample_threat(&state.node_id));
    let would_fire = evaluate(&rule, &event);
    let reports = if would_fire {
        exec::dry_run_plan(&rule)
    } else {
        Vec::new()
    };
    let outcome = if !would_fire {
        "no-match".to_string()
    } else if reports.iter().any(|report| report.outcome == "downgraded") {
        "downgraded".to_string()
    } else {
        "dry-run".to_string()
    };
    Ok(Json(RuleTestResponse {
        rule_id: rule.rule_id,
        would_fire,
        dry_run: true,
        trigger_summary: event.summary(),
        actions: reports
            .into_iter()
            .map(|report| format!("{}: {}", report.action, report.message))
            .collect(),
        outcome,
    }))
}

pub async fn executions(
    Query(query): Query<ExecutionsQuery>,
) -> Result<Json<Vec<crate::rules::RuleExecution>>, ApiError> {
    let limit = query.limit.unwrap_or(500).min(10_000);
    let executions = exec::list_executions(Some(limit)).map_err(map_rules_error)?;
    Ok(Json(executions))
}

fn rules_base() -> PathBuf {
    RulesConfig::from_env().paths.base
}

fn runtime_signer(
    node_id: &str,
) -> Result<std::sync::Arc<crate::key_manager::KeyManager>, ApiError> {
    crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| ApiError::Internal(format!("load rules signer: {}", error)))
}

fn map_rules_error(error: RulesError) -> ApiError {
    match error {
        RulesError::NotFound(message) => ApiError::NotFound(message),
        RulesError::InvalidRule(message) => ApiError::BadRequest(message),
        RulesError::MissingProof
        | RulesError::InvalidProof(_)
        | RulesError::RegistryRejected(_) => ApiError::BadRequest(error.to_string()),
        RulesError::Io(_)
        | RulesError::Json(_)
        | RulesError::Yaml(_)
        | RulesError::Base64(_)
        | RulesError::Threat(_)
        | RulesError::Discovery(_)
        | RulesError::Crl(_)
        | RulesError::Action(_) => ApiError::Internal(error.to_string()),
    }
}
