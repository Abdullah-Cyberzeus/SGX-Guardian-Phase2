use crate::api::error::ApiError;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct PutQuotaRequest {
    pub quota_bytes: u64,
    pub period: String,
}

#[derive(Debug, Serialize)]
pub struct ResetResponse {
    pub status: String,
    pub snapshot: crate::dusage::model::UsageSnapshot,
}

pub async fn current(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<crate::dusage::model::UsageSnapshot>, ApiError> {
    Ok(Json(crate::dusage::current_snapshot().await?))
}

pub async fn history(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<Vec<crate::dusage::model::UsageSnapshot>>, ApiError> {
    Ok(Json(crate::dusage::history().await?))
}

pub async fn get_quota(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<Option<crate::dusage::model::DusageQuota>>, ApiError> {
    Ok(Json(crate::dusage::get_quota().await?))
}

pub async fn put_quota(
    State(_state): State<Arc<crate::api::state::AppState>>,
    Json(body): Json<PutQuotaRequest>,
) -> Result<Json<crate::dusage::model::DusageQuota>, ApiError> {
    Ok(Json(
        crate::dusage::put_quota(body.quota_bytes, body.period).await?,
    ))
}

pub async fn reset(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<ResetResponse>, ApiError> {
    let snapshot = crate::dusage::reset_now().await?;
    Ok(Json(ResetResponse {
        status: "success".to_string(),
        snapshot,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::state::AppState;
    use tempfile::TempDir;

    /// Points the data-usage state directory and the interface-counter source
    /// at a tempdir. `sample_once` reads counters from a `/sys/class/net`-shaped
    /// tree, so a synthetic one makes sampling deterministic and offline.
    struct DusageEnv {
        base: Option<std::ffi::OsString>,
        sysfs: Option<std::ffi::OsString>,
    }

    impl DusageEnv {
        fn set(dir: &std::path::Path) -> Self {
            let base = std::env::var_os(crate::dusage::state::DUSAGE_BASE_ENV);
            let sysfs = std::env::var_os(crate::dusage::counters::SYS_CLASS_NET_ENV);

            // One interface with fixed rx/tx byte counters.
            let iface = dir.join("sysfs").join("eth0").join("statistics");
            std::fs::create_dir_all(&iface).expect("sysfs tree");
            std::fs::write(iface.join("rx_bytes"), b"1024\n").expect("rx_bytes");
            std::fs::write(iface.join("tx_bytes"), b"2048\n").expect("tx_bytes");

            std::env::set_var(crate::dusage::state::DUSAGE_BASE_ENV, dir.join("state"));
            std::env::set_var(
                crate::dusage::counters::SYS_CLASS_NET_ENV,
                dir.join("sysfs"),
            );
            Self { base, sysfs }
        }
    }

    impl Drop for DusageEnv {
        fn drop(&mut self) {
            match self.base.take() {
                Some(value) => std::env::set_var(crate::dusage::state::DUSAGE_BASE_ENV, value),
                None => std::env::remove_var(crate::dusage::state::DUSAGE_BASE_ENV),
            }
            match self.sysfs.take() {
                Some(value) => {
                    std::env::set_var(crate::dusage::counters::SYS_CLASS_NET_ENV, value)
                }
                None => std::env::remove_var(crate::dusage::counters::SYS_CLASS_NET_ENV),
            }
        }
    }

    fn test_state(td: &TempDir) -> Arc<AppState> {
        AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        )
    }

    #[tokio::test]
    async fn current_and_history_serve_snapshots_from_the_configured_state_dir() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let _env = DusageEnv::set(td.path());
        let state = test_state(&td);

        let snapshot = current(State(state.clone()))
            .await
            .expect("current snapshot");
        // The synthetic sysfs tree above is the only counter source, so the
        // sampled interface set comes from it rather than the real host.
        let eth0 = snapshot
            .0
            .interfaces
            .iter()
            .find(|iface| iface.iface == "eth0")
            .unwrap_or_else(|| {
                panic!(
                    "expected the synthetic eth0 counters, saw {:?}",
                    snapshot.0.interfaces.iter().map(|i| i.iface.as_str()).collect::<Vec<_>>()
                )
            });
        // The totals come straight from the files written above.
        assert_eq!(eth0.rx_total, 1024);
        assert_eq!(eth0.tx_total, 2048);
        assert!(!snapshot.0.period.is_empty());
        assert!(!snapshot.0.usage_band.is_empty());
        assert!(!snapshot.0.sampled_at.is_empty());
        assert_eq!(
            snapshot.0.quota_bytes, None,
            "no quota has been configured yet"
        );

        // History is served from the same state dir rather than erroring.
        let history = history(State(state)).await.expect("history");
        assert!(
            history.0.iter().all(|entry| !entry.period.is_empty()),
            "every stored snapshot carries its period"
        );
    }

    #[tokio::test]
    async fn quota_round_trips_through_put_and_get() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let _env = DusageEnv::set(td.path());
        let state = test_state(&td);

        let stored = put_quota(
            State(state.clone()),
            Json(PutQuotaRequest {
                quota_bytes: 5_000_000,
                period: "monthly".to_string(),
            }),
        )
        .await
        .expect("put_quota");
        assert_eq!(stored.0.quota_bytes, 5_000_000);

        let fetched = get_quota(State(state.clone()))
            .await
            .expect("get_quota")
            .0
            .expect("a quota was just stored");
        assert_eq!(fetched.quota_bytes, 5_000_000);

        // Re-putting bumps the sequence rather than duplicating the record.
        let updated = put_quota(
            State(state),
            Json(PutQuotaRequest {
                quota_bytes: 9_000_000,
                period: "monthly".to_string(),
            }),
        )
        .await
        .expect("put_quota again");
        assert_eq!(updated.0.quota_bytes, 9_000_000);
        assert!(updated.0.sequence > stored.0.sequence);
    }

    #[tokio::test]
    async fn put_quota_rejects_an_unknown_period() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let _env = DusageEnv::set(td.path());
        let state = test_state(&td);

        assert!(
            put_quota(
                State(state),
                Json(PutQuotaRequest {
                    quota_bytes: 1,
                    period: "fortnightly".to_string(),
                }),
            )
            .await
            .is_err(),
            "an unrecognised period must be refused"
        );
    }

    #[tokio::test]
    async fn reset_reports_success_and_returns_the_new_snapshot() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        let _env = DusageEnv::set(td.path());
        let state = test_state(&td);

        let response = reset(State(state)).await.expect("reset");
        assert_eq!(response.0.status, "success");
    }
}
