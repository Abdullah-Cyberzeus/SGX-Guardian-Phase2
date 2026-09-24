use crate::api::auth::{
    password,
    store::{normalize_email, User},
};
use crate::api::{error::ApiError, state::AppState};
use async_trait::async_trait;
use chrono::Utc;
use sgx_anomaly_engine::threat_prediction::{
    EventSeverity, EvidenceSource, SecurityEvent, SecurityEventType, SECURITY_EVENT_SCHEMA_VERSION,
};
use std::collections::HashMap;
use std::sync::Arc;

pub const LOCAL_PROVIDER_NAME: &str = "local";
pub const CYLENIUM_PROVIDER_NAME: &str = "cylenium";

#[derive(Debug, Clone)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn enabled(&self) -> bool;
    async fn authenticate(&self, state: &AppState, creds: Credentials) -> Result<User, ApiError>;
}

pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn AuthProvider>>,
}

impl ProviderRegistry {
    pub fn from_env() -> Arc<Self> {
        let providers: Vec<Arc<dyn AuthProvider>> = vec![
            Arc::new(LocalAuthProvider),
            Arc::new(CyleniumProvider::new(env_flag("SGX_SSO_CYLENIUM_ENABLED"))),
        ];
        let providers = providers
            .into_iter()
            .map(|provider| (provider.name().to_string(), provider))
            .collect();
        Arc::new(Self { providers })
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn AuthProvider>> {
        self.providers.get(name).cloned()
    }

    pub fn local(&self) -> Option<Arc<dyn AuthProvider>> {
        self.get(LOCAL_PROVIDER_NAME)
    }

    pub fn cylenium(&self) -> Option<Arc<dyn AuthProvider>> {
        self.get(CYLENIUM_PROVIDER_NAME)
    }
}

#[derive(Debug, Default)]
pub struct LocalAuthProvider;

#[async_trait]
impl AuthProvider for LocalAuthProvider {
    fn name(&self) -> &'static str {
        LOCAL_PROVIDER_NAME
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn authenticate(&self, state: &AppState, creds: Credentials) -> Result<User, ApiError> {
        let email = normalize_email(&creds.email);
        let now = Utc::now().timestamp();
        let rate_limit_key = format!("login:{}", email);
        if !state
            .login_rate_limiter
            .check_and_record(&rate_limit_key, now, state.auth_rate_limit)
        {
            return Err(ApiError::TooManyRequests(
                "too many login attempts; try again later".into(),
            ));
        }

        let user = prepare_login_user(state, &email, now).await?;
        let Some(user) = user else {
            return Err(ApiError::Unauthorized("invalid email or password".into()));
        };
        if is_locked(&user, now) {
            return Err(locked_error());
        }

        let verified = password::verify_password(creds.password, user.pw_hash.clone())
            .await
            .map_err(|e| ApiError::Unauthorized(e.to_string()))?;
        if !verified {
            return Err(record_failed_login(state, &email, Utc::now().timestamp()).await?);
        }

        let now = Utc::now().timestamp();
        let user = prepare_login_user(state, &email, now).await?;
        let Some(user) = user else {
            return Err(ApiError::Unauthorized("invalid email or password".into()));
        };
        if is_locked(&user, now) {
            return Err(locked_error());
        }

        state.admin.users.reset_login_failures(&email).await?;
        state.login_rate_limiter.clear(&rate_limit_key);
        Ok(user)
    }
}

#[derive(Debug, Clone)]
pub struct CyleniumProvider {
    enabled: bool,
}

impl CyleniumProvider {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

#[async_trait]
impl AuthProvider for CyleniumProvider {
    fn name(&self) -> &'static str {
        CYLENIUM_PROVIDER_NAME
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    async fn authenticate(&self, _state: &AppState, _creds: Credentials) -> Result<User, ApiError> {
        Err(ApiError::Forbidden(
            "cylenium SSO provider is disabled".into(),
        ))
    }
}

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

async fn record_failed_login(
    state: &AppState,
    email: &str,
    now: i64,
) -> Result<ApiError, ApiError> {
    // Preserve the existing authentication/lockout persistence path first.
    let user = state
        .admin
        .users
        .record_login_failure(
            email,
            now,
            state.auth_lockout.max_failed_attempts,
            state.auth_lockout.attempt_window_secs,
            state.auth_lockout.lockout_secs,
        )
        .await?;

    let account_locked = user.as_ref().is_some_and(|user| is_locked(user, now));

    // Task4 receives only failures for a real local account that were
    // persisted by the existing authentication subsystem. Unknown-account
    // probes are intentionally not promoted into this precursor here.
    //
    // This is a best-effort observability side-channel: failure to publish
    // Task4 evidence must never alter authentication or lockout behavior.
    if user.is_some() {
        let task4 = { state.task4_threat_prediction.read().await.as_ref().cloned() };

        if let Some(task4) = task4 {
            let observed_at_ms = u64::try_from(now)
                .ok()
                .and_then(|seconds| seconds.checked_mul(1_000));

            if let Some(observed_at_ms) = observed_at_ms {
                let mut attributes = std::collections::BTreeMap::new();

                attributes.insert("auth_provider".to_string(), LOCAL_PROVIDER_NAME.to_string());
                attributes.insert("account_locked".to_string(), account_locked.to_string());

                // Deliberately exclude email, password, password hash,
                // bearer token, session token, and other account secrets.
                let mut event = SecurityEvent {
                    schema_version: SECURITY_EVENT_SCHEMA_VERSION,
                    event_id: "task4-auth-failure-pending".to_string(),
                    observed_at_ms,
                    source: EvidenceSource::GuardianThreat,
                    node_id: state.node_id.clone(),
                    peer_id: None,

                    // The provider operates on credentials and does not own
                    // trustworthy socket attribution. Do not fabricate IPs.
                    source_ip: None,
                    destination_ip: None,
                    source_port: None,
                    destination_port: None,

                    event_type: SecurityEventType::AuthenticationFailure,
                    severity: if account_locked {
                        EventSeverity::High
                    } else {
                        EventSeverity::Medium
                    },
                    confidence: 1.0,
                    attributes,
                };

                // Unique per persisted failure. The collector's normal
                // canonical deduplication remains authoritative.
                event.event_id =
                    format!("task4-auth-failure-v1:{}:{}", state.node_id, observed_at_ms);

                match event.validate() {
                    Ok(()) => {
                        if let Err(error) = task4.try_publish(event) {
                            tracing::warn!(
                                %error,
                                "Task4 AuthenticationFailure publish failed"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "dropping invalid Task4 AuthenticationFailure event"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    timestamp = now,
                    "failed login timestamp cannot be represented as Task4 milliseconds"
                );
            }
        }
    }

    if account_locked {
        return Ok(locked_error());
    }

    Ok(ApiError::Unauthorized("invalid email or password".into()))
}

async fn prepare_login_user(
    state: &AppState,
    email: &str,
    now: i64,
) -> Result<Option<User>, ApiError> {
    state
        .admin
        .users
        .prepare_login(email, now, state.auth_lockout.attempt_window_secs)
        .await
        .map_err(Into::into)
}

fn is_locked(user: &User, now: i64) -> bool {
    user.locked_until
        .is_some_and(|locked_until| locked_until > now)
}

fn locked_error() -> ApiError {
    ApiError::Locked("account temporarily locked".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::{
        password,
        store::{NewUser, UserRole},
    };
    use crate::api::state::AppState;
    use tempfile::TempDir;

    #[tokio::test]
    async fn local_provider_authenticates_existing_user() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let pw_hash = password::hash_password("GuardianPass123!".into())
            .await
            .expect("hash password");
        state
            .admin
            .users
            .create_initial_owner(NewUser {
                name: "Admin".into(),
                email: "admin@example.com".into(),
                pw_hash,
                role: UserRole::Owner,
                oidc_sub: None,
            })
            .await
            .expect("create user");

        let user = LocalAuthProvider
            .authenticate(
                state.as_ref(),
                Credentials {
                    email: "admin@example.com".into(),
                    password: "GuardianPass123!".into(),
                },
            )
            .await
            .expect("authenticate local provider");

        assert_eq!(user.email, "admin@example.com");
    }

    #[tokio::test]
    async fn cylenium_provider_is_disabled_by_default() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let err = CyleniumProvider::new(false)
            .authenticate(
                state.as_ref(),
                Credentials {
                    email: "admin@example.com".into(),
                    password: "GuardianPass123!".into(),
                },
            )
            .await
            .expect_err("cylenium should be disabled");

        match err {
            ApiError::Forbidden(message) => {
                assert!(message.contains("disabled"));
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
