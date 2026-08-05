use crate::api::auth::{
    password,
    store::{normalize_email, User},
};
use crate::api::{error::ApiError, state::AppState};
use async_trait::async_trait;
use chrono::Utc;
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
    if user.as_ref().is_some_and(|user| is_locked(user, now)) {
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
