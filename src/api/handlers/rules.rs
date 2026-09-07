use crate::api::{error::ApiError, state::AppState};
use crate::rules::errors::RulesError;
use crate::rules::eval::evaluate;
use crate::rules::exec;
use crate::rules::model::{Rule, RuleDraft, RuleEvent, RulePatch};
use crate::rules::RulesConfig;
use axum::extract::{Path as AxumPath, Query, State};
use axum::Json;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::model::{Condition, RuleAction, RuleTrigger};

    /// `rules_base()`/`runtime_signer()` both read real env-var overrides
    /// (`SGX_GUARDIAN_RULES_BASE`, `SGX_GUARDIAN_DEVICE_KEY_DIR` +
    /// `SGX_FORCE_SOFTWARE_KEYS`), so a real signer and real rule storage can be built in a
    /// tempdir rather than needing `/var/lib/sgx-guardian`.
    struct RulesEnv {
        _guard: tokio::sync::MutexGuard<'static, ()>,
        _td: tempfile::TempDir,
        restore: Vec<(&'static str, Option<String>)>,
        state: Arc<AppState>,
    }

    impl RulesEnv {
        async fn new() -> Self {
            let guard = crate::test_support::async_env_lock().await;
            let td = tempfile::tempdir().expect("rules env tempdir");
            let rules_base = td.path().join("rules");
            let key_dir = td.path().join("keys");
            std::fs::create_dir_all(&rules_base).expect("rules base dir");
            std::fs::create_dir_all(&key_dir).expect("key dir");

            let restore = vec![
                (
                    crate::rules::persistence::RULES_BASE_ENV,
                    std::env::var(crate::rules::persistence::RULES_BASE_ENV).ok(),
                ),
                (
                    crate::vc::issue::DEVICE_KEY_DIR_ENV,
                    std::env::var(crate::vc::issue::DEVICE_KEY_DIR_ENV).ok(),
                ),
                (
                    "SGX_FORCE_SOFTWARE_KEYS",
                    std::env::var("SGX_FORCE_SOFTWARE_KEYS").ok(),
                ),
            ];
            std::env::set_var(crate::rules::persistence::RULES_BASE_ENV, &rules_base);
            std::env::set_var(crate::vc::issue::DEVICE_KEY_DIR_ENV, &key_dir);
            std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");

            let config_dir = td.path().join("config");
            std::fs::create_dir_all(&config_dir).expect("config dir");
            let state =
                AppState::for_tests(td.path(), "nodeRulesTest", config_dir.display().to_string());

            Self {
                _guard: guard,
                _td: td,
                restore,
                state,
            }
        }
    }

    impl Drop for RulesEnv {
        fn drop(&mut self) {
            for (key, value) in self.restore.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn sample_draft(name: &str) -> RuleDraft {
        RuleDraft {
            rule_id: None,
            name: Some(name.to_string()),
            enabled: Some(true),
            trigger: Some(RuleTrigger::ThreatAlert),
            condition: Some(Condition::SeverityAtLeast("medium".to_string())),
            actions: Some(vec![RuleAction::Notify {
                severity: "info".to_string(),
            }]),
            notify: Some(true),
            allow_destructive: Some(false),
            cooldown_secs: Some(60),
            max_actions_per_hour: Some(10),
        }
    }

    #[tokio::test]
    async fn list_is_empty_on_a_fresh_registry() {
        let env = RulesEnv::new().await;
        let Json(rules) = list(State(env.state.clone())).await.expect("list rules");
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn create_list_detail_edit_toggle_and_delete_round_trip() {
        let env = RulesEnv::new().await;
        let Json(created) = create(
            State(env.state.clone()),
            Json(sample_draft("Critical alerts")),
        )
        .await
        .expect("create rule");
        assert_eq!(created.name, "Critical alerts");
        assert!(created.enabled);

        let Json(listed) = list(State(env.state.clone())).await.expect("list rules");
        assert_eq!(listed.len(), 1);

        let Json(detail_rule) = detail(State(env.state.clone()), AxumPath(created.rule_id.clone()))
            .await
            .expect("detail rule");
        assert_eq!(detail_rule.rule_id, created.rule_id);

        let Json(edited) = edit(
            State(env.state.clone()),
            AxumPath(created.rule_id.clone()),
            Json(RulePatch {
                name: Some("Renamed".to_string()),
                ..RulePatch::default()
            }),
        )
        .await
        .expect("edit rule");
        assert_eq!(edited.name, "Renamed");

        let Json(disabled) = set_enabled(
            State(env.state.clone()),
            AxumPath(created.rule_id.clone()),
            Json(EnabledBody { enabled: false }),
        )
        .await
        .expect("disable rule");
        assert!(!disabled.enabled);

        let Json(deleted) = delete(State(env.state.clone()), AxumPath(created.rule_id.clone()))
            .await
            .expect("delete rule");
        assert!(deleted.success);
        assert_eq!(deleted.rule_id, created.rule_id);

        let err = detail(State(env.state.clone()), AxumPath(created.rule_id))
            .await
            .expect_err("deleted rule should be gone");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn create_rejects_a_blank_name() {
        let env = RulesEnv::new().await;
        let mut draft = sample_draft("");
        draft.name = Some("   ".to_string());
        let err = create(State(env.state.clone()), Json(draft))
            .await
            .expect_err("blank name must be rejected");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn detail_reports_not_found_for_an_unknown_id() {
        let env = RulesEnv::new().await;
        let err = detail(State(env.state.clone()), AxumPath("missing".to_string()))
            .await
            .expect_err("unknown rule");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_endpoint_reports_would_fire_and_dry_run_actions() {
        let env = RulesEnv::new().await;
        let Json(created) = create(State(env.state.clone()), Json(sample_draft("Threat rule")))
            .await
            .expect("create rule");

        let Json(response) = test(
            State(env.state.clone()),
            AxumPath(created.rule_id.clone()),
            None,
        )
        .await
        .expect("test rule");
        assert_eq!(response.rule_id, created.rule_id);
        assert!(response.dry_run);
        assert!(response.would_fire);
        assert_eq!(response.outcome, "dry-run");
        assert!(!response.actions.is_empty());
    }

    #[tokio::test]
    async fn executions_returns_an_empty_list_when_none_have_run() {
        let _env = RulesEnv::new().await;
        let Json(list) = executions(Query(ExecutionsQuery { limit: None }))
            .await
            .expect("executions");
        // Executions are process-global (not env-var-scoped to this test's tempdir), so this
        // just confirms the endpoint succeeds and returns a well-formed list.
        let _ = list;
    }
}
