use crate::advisory::{AdvisoryConfig, AdvisoryRules, store};
use crate::api::{error::ApiError, state::AppState};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<crate::advisory::RemediationRecommendation>>, ApiError> {
    let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
    let limit = query.limit.unwrap_or(500).min(10_000);
    let recommendations = store::list_recent(&config.recommendations_path(), limit)
        .await
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(Json(recommendations))
}

pub async fn for_alert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<crate::advisory::RemediationRecommendation>, ApiError> {
    let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
    let recommendation = store::find_for_alert(&config.recommendations_path(), &id)
        .await
        .map_err(|err| ApiError::Internal(err.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("no recommendation for alert {}", id)))?;
    Ok(Json(recommendation))
}

pub async fn get_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AdvisoryRules>, ApiError> {
    let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
    Ok(Json(AdvisoryRules::load_or_default(&config.rules_path())))
}

pub async fn put_rules(
    State(state): State<Arc<AppState>>,
    Json(rules): Json<AdvisoryRules>,
) -> Result<Json<AdvisoryRules>, ApiError> {
    let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
    rules
        .save_atomic(&config.rules_path())
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    Ok(Json(rules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::model::{RemediationRecommendation, RemediationStep};
    use chrono::Utc;
    use tempfile::TempDir;

    fn test_state(td: &TempDir) -> Arc<AppState> {
        let mut state = (*AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        ))
        .clone();
        let threat_dir = td.path().join("threat-state");
        std::fs::create_dir_all(&threat_dir).expect("threat state dir");
        state.threat_state_dir = threat_dir.to_string_lossy().to_string();
        Arc::new(state)
    }

    fn recommendation(alert_id: &str) -> RemediationRecommendation {
        RemediationRecommendation {
            rec_id: format!("rec-{alert_id}"),
            alert_id: alert_id.to_string(),
            title: "Isolate the host".into(),
            summary: "Traffic pattern matches a known exfiltration signature".into(),
            severity: "high".into(),
            confidence: 0.8,
            steps: vec![RemediationStep {
                order: 1,
                action: "Block the destination".into(),
                rationale: "Stops the transfer while it is investigated".into(),
                automatable: true,
            }],
            context: vec!["seen on eth0".into()],
            references: vec!["https://example.test/advisory".into()],
            source: "rules".into(),
            generated_at: Utc::now(),
        }
    }

    async fn seed(state: &AppState, recommendations: Vec<RemediationRecommendation>) {
        let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
        for entry in recommendations {
            store::append_capped(&config.recommendations_path(), entry, 100)
                .await
                .expect("append recommendation");
        }
    }

    #[tokio::test]
    async fn list_is_empty_before_anything_is_recorded() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        let listed = list(State(state), Query(ListQuery { limit: None }))
            .await
            .expect("list succeeds with no store on disk");
        assert!(listed.0.is_empty());
    }

    #[tokio::test]
    async fn list_returns_recorded_recommendations_and_honours_the_limit() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);
        seed(
            state.as_ref(),
            vec![
                recommendation("alert-1"),
                recommendation("alert-2"),
                recommendation("alert-3"),
            ],
        )
        .await;

        let listed = list(State(state.clone()), Query(ListQuery { limit: None }))
            .await
            .expect("list succeeds");
        assert_eq!(listed.0.len(), 3);

        let limited = list(State(state), Query(ListQuery { limit: Some(2) }))
            .await
            .expect("list succeeds");
        assert_eq!(limited.0.len(), 2, "the limit is applied");
    }

    #[tokio::test]
    async fn for_alert_finds_a_recommendation_and_reports_unknown_alerts() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);
        seed(state.as_ref(), vec![recommendation("alert-1")]).await;

        let found = for_alert(State(state.clone()), Path("alert-1".to_string()))
            .await
            .expect("recommendation found");
        assert_eq!(found.0.alert_id, "alert-1");
        assert_eq!(found.0.severity, "high");

        let missing = for_alert(State(state), Path("no-such-alert".to_string()))
            .await
            .err()
            .expect("unknown alert");
        assert!(
            matches!(&missing, ApiError::NotFound(message) if message.contains("no-such-alert")),
            "{missing:?}"
        );
    }

    #[tokio::test]
    async fn rules_fall_back_to_the_built_in_set_then_round_trip_through_put() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        // Nothing on disk: the built-in rules are served rather than an error.
        let defaults = get_rules(State(state.clone()))
            .await
            .expect("built-in rules");
        assert!(
            !defaults.0.fallback.title.is_empty(),
            "the fallback template is populated"
        );

        // Saving an edited copy persists it, and the next read serves it back.
        let mut edited = defaults.0.clone();
        edited.fallback.title = "Custom fallback".to_string();
        let saved = put_rules(State(state.clone()), Json(edited))
            .await
            .expect("put_rules succeeds");
        assert_eq!(saved.0.fallback.title, "Custom fallback");

        let reloaded = get_rules(State(state)).await.expect("reload rules");
        assert_eq!(
            reloaded.0.fallback.title, "Custom fallback",
            "the edited rules were actually persisted"
        );
    }

    #[tokio::test]
    async fn put_rules_rejects_a_body_whose_signature_does_not_match() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        let mut tampered = AdvisoryRules::load_or_default(std::path::Path::new("/nonexistent"));
        tampered.signature_sha256 = Some("0".repeat(64));

        let error = put_rules(State(state), Json(tampered))
            .await
            .err()
            .expect("a mismatched signature must be refused");
        assert!(matches!(error, ApiError::BadRequest(_)), "{error:?}");
    }
}
