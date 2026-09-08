//! Shared state passed to every handler.
//! Keeps all filesystem paths in one place so tests can swap them out.

use crate::api::auth::{provider::ProviderRegistry, store::AdminStores};
use crate::call::nebula_signaling::NebulaClient;
use crate::call::{
    CallSignalHub, DidPeerIdentityResolver, GroupSessionManager, NebulaSignaling, SessionManager,
};
use crate::chat::models::ChatEvent;
use crate::key_manager::KeyManager;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthLockoutConfig {
    pub max_failed_attempts: u32,
    pub attempt_window_secs: i64,
    pub lockout_secs: i64,
}

impl Default for AuthLockoutConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            attempt_window_secs: 900,
            lockout_secs: 300,
        }
    }
}

impl AuthLockoutConfig {
    fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            max_failed_attempts: std::env::var("SGX_GUARDIAN_AUTH_MAX_FAILED_ATTEMPTS")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(defaults.max_failed_attempts),
            attempt_window_secs: std::env::var("SGX_GUARDIAN_AUTH_ATTEMPT_WINDOW_SECS")
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(defaults.attempt_window_secs),
            lockout_secs: std::env::var("SGX_GUARDIAN_AUTH_LOCKOUT_SECS")
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(defaults.lockout_secs),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthRateLimitConfig {
    pub max_attempts: u32,
    pub window_secs: i64,
}

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            window_secs: 60,
        }
    }
}

impl AuthRateLimitConfig {
    fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            max_attempts: std::env::var("SGX_GUARDIAN_AUTH_RATE_LIMIT_MAX_ATTEMPTS")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(defaults.max_attempts),
            window_secs: std::env::var("SGX_GUARDIAN_AUTH_RATE_LIMIT_WINDOW_SECS")
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(defaults.window_secs),
        }
    }
}

#[derive(Default)]
pub struct LoginRateLimiter {
    attempts: DashMap<String, Vec<i64>>,
}

impl LoginRateLimiter {
    pub fn check_and_record(&self, key: &str, now: i64, config: AuthRateLimitConfig) -> bool {
        let mut entry = self.attempts.entry(key.to_string()).or_default();
        entry.retain(|attempt| now.saturating_sub(*attempt) < config.window_secs);
        if entry.len() >= config.max_attempts as usize {
            return false;
        }
        entry.push(now);
        true
    }

    pub fn clear(&self, key: &str) {
        self.attempts.remove(key);
    }
}

#[derive(Clone)]
pub struct AppState {
    pub node_id: String,
    pub config_dir: String,       // /etc/sgx-guardian/config
    pub boot_dir: String,         // /var/lib/sgx-guardian/boot
    pub keys_dir: String,         // /var/lib/sgx-guardian/keys
    pub pcr_dir: String,          // /var/lib/sgx-guardian/pcr
    pub pcr_baseline_dir: String, // /etc/sgx-guardian
    pub log_dir_primary: String,  // /var/log/sgx-guardian
    pub log_dir_fallback: String, // logs
    pub did_resolver: crate::did::Resolver,
    pub vid_cache: crate::virtual_id_cache::VirtualIdCache,
    pub discovery_config_dir: String, // /etc/sgx-guardian/discovery
    pub discovery_state_dir: String,  // /var/lib/sgx-guardian/discovery
    pub threat_config_path: String,   // /etc/sgx-guardian/threat/config.yaml
    pub threat_state_dir: String,     // /var/lib/sgx-guardian/threat
    pub admin_dir: String,            // /var/lib/sgx-guardian/admin
    pub admin: Arc<AdminStores>,
    pub signer: Arc<KeyManager>,
    pub call_session_manager: Arc<SessionManager>,
    pub call_signal_hub: Arc<CallSignalHub>,
    pub call_nebula_signaling: Arc<NebulaSignaling>,
    pub group_session_manager: Arc<GroupSessionManager>,
    pub chat_events: broadcast::Sender<ChatEvent>,
    pub device_pubkey_point: Vec<u8>,
    pub device_did: String,
    pub session_ttl_secs: u64,
    pub auth_lockout: AuthLockoutConfig,
    pub auth_rate_limit: AuthRateLimitConfig,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    pub auth_providers: Arc<ProviderRegistry>,
    pub device_manager:
        Arc<tokio::sync::RwLock<Option<Arc<crate::device::manager::DeviceManager>>>>,
    pub automation_engine:
        Arc<tokio::sync::RwLock<Option<Arc<crate::automation::engine::AutomationEngine>>>>,
    pub integration_manager:
        Arc<tokio::sync::RwLock<Option<Arc<crate::integration::manager::IntegrationManager>>>>,
    pub ha_event_bus: Arc<tokio::sync::RwLock<Option<Arc<crate::homeassistant::events::EventBus>>>>,
    pub device_rate_limiter: Arc<crate::api::auth::rate_limiter::DeviceRateLimiter>,
    pub notification_manager:
        Arc<tokio::sync::RwLock<Option<Arc<crate::notification::manager::NotificationManager>>>>,
}

impl AppState {
    pub fn from_env(
        node_id: String,
        did_resolver: crate::did::Resolver,
        signer: Arc<KeyManager>,
        admin: Arc<AdminStores>,
        device_did: String,
        device_pubkey_point: Vec<u8>,
    ) -> Arc<Self> {
        let call_identity_resolver = Arc::new(DidPeerIdentityResolver::new(
            did_resolver.clone(),
            "/var/log/sgx-guardian",
            "logs",
        ));
        Arc::new(Self {
            node_id,
            config_dir: "/etc/sgx-guardian/config".into(),
            boot_dir: "/var/lib/sgx-guardian/boot".into(),
            keys_dir: "/var/lib/sgx-guardian/keys".into(),
            pcr_dir: "/var/lib/sgx-guardian/pcr".into(),
            pcr_baseline_dir: "/etc/sgx-guardian".into(),
            log_dir_primary: "/var/log/sgx-guardian".into(),
            log_dir_fallback: "logs".into(),
            did_resolver,
            vid_cache: crate::attestation_service::VID_CACHE
                .get()
                .cloned()
                .unwrap_or_default(),
            discovery_config_dir: std::env::var("SGX_GUARDIAN_DISCOVERY_CONFIG_DIR")
                .unwrap_or_else(|_| "/etc/sgx-guardian/discovery".into()),
            discovery_state_dir: std::env::var("SGX_GUARDIAN_DISCOVERY_STATE_DIR")
                .unwrap_or_else(|_| "/var/lib/sgx-guardian/discovery".into()),
            threat_config_path: "/etc/sgx-guardian/threat/config.yaml".into(),
            threat_state_dir: "/var/lib/sgx-guardian/threat".into(),
            admin_dir: "/var/lib/sgx-guardian/admin".into(),
            admin,
            signer: signer.clone(),
            call_session_manager: Arc::new(SessionManager::new()),
            call_signal_hub: Arc::new(CallSignalHub::default()),
            call_nebula_signaling: Arc::new(NebulaSignaling::new_secure(
                Arc::new(NebulaClient),
                signer.clone(),
                call_identity_resolver,
            )),
            group_session_manager: Arc::new(GroupSessionManager::default()),
            chat_events: broadcast::channel(100).0,
            device_pubkey_point,
            device_did,
            session_ttl_secs: std::env::var("SGX_GUARDIAN_SESSION_TTL_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(3600),
            auth_lockout: AuthLockoutConfig::from_env(),
            auth_rate_limit: AuthRateLimitConfig::from_env(),
            login_rate_limiter: Arc::new(LoginRateLimiter::default()),
            auth_providers: ProviderRegistry::from_env(),
            device_manager: Arc::new(tokio::sync::RwLock::new(None)),
            automation_engine: Arc::new(tokio::sync::RwLock::new(None)),
            integration_manager: Arc::new(tokio::sync::RwLock::new(None)),
            ha_event_bus: Arc::new(tokio::sync::RwLock::new(None)),
            device_rate_limiter: Arc::new(
                crate::api::auth::rate_limiter::DeviceRateLimiter::default(),
            ),
            notification_manager: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    pub async fn get_device_manager(&self) -> Option<Arc<crate::device::manager::DeviceManager>> {
        self.device_manager.read().await.clone()
    }

    pub async fn get_automation_engine(
        &self,
    ) -> Option<Arc<crate::automation::engine::AutomationEngine>> {
        self.automation_engine.read().await.clone()
    }

    pub async fn get_integration_manager(
        &self,
    ) -> Option<Arc<crate::integration::manager::IntegrationManager>> {
        self.integration_manager.read().await.clone()
    }

    pub async fn get_ha_event_bus(&self) -> Option<Arc<crate::homeassistant::events::EventBus>> {
        self.ha_event_bus.read().await.clone()
    }

    pub async fn get_notification_manager(
        &self,
    ) -> Option<Arc<crate::notification::manager::NotificationManager>> {
        self.notification_manager.read().await.clone()
    }

    #[doc(hidden)]
    pub fn for_tests(
        base_dir: &std::path::Path,
        node_id: &str,
        config_dir: impl Into<String>,
    ) -> Arc<Self> {
        let key_dir = base_dir.join("keys");
        let boot_dir = base_dir.join("boot");
        let pcr_dir = base_dir.join("pcr");
        let log_dir = base_dir.join("logs");
        let discovery_config_dir = base_dir.join("discovery-config");
        let discovery_state_dir = base_dir.join("discovery-state");
        let threat_dir = base_dir.join("threat");
        let admin_dir = base_dir.join("admin");
        let signer_dir = base_dir.join("sgx-agent");
        std::fs::create_dir_all(&key_dir).expect("test key dir");
        std::fs::create_dir_all(&boot_dir).expect("test boot dir");
        std::fs::create_dir_all(&pcr_dir).expect("test pcr dir");
        std::fs::create_dir_all(&log_dir).expect("test log dir");
        std::fs::create_dir_all(&discovery_config_dir).expect("test discovery config dir");
        std::fs::create_dir_all(&discovery_state_dir).expect("test discovery state dir");
        std::fs::create_dir_all(&threat_dir).expect("test threat dir");
        std::fs::create_dir_all(&admin_dir).expect("test admin dir");
        std::fs::create_dir_all(&signer_dir).expect("test signer dir");
        let signer = Arc::new(
            KeyManager::load_or_generate(
                signer_dir
                    .join(format!("device_{}.key", node_id))
                    .to_str()
                    .expect("test signer path"),
            )
            .expect("test signer"),
        );
        let device_pubkey_point = signer.pubkey_der().expect("test signer pubkey");
        let mut did_bytes = [0u8; 32];
        for (idx, byte) in node_id.bytes().enumerate() {
            did_bytes[idx % did_bytes.len()] ^= byte;
        }
        let device_did = crate::did::Did::from_id_bytes(&did_bytes).to_string();

        Arc::new(Self {
            node_id: node_id.to_string(),
            config_dir: config_dir.into(),
            boot_dir: boot_dir.to_string_lossy().to_string(),
            keys_dir: key_dir.to_string_lossy().to_string(),
            pcr_dir: pcr_dir.to_string_lossy().to_string(),
            pcr_baseline_dir: base_dir.to_string_lossy().to_string(),
            log_dir_primary: log_dir.to_string_lossy().to_string(),
            log_dir_fallback: log_dir.to_string_lossy().to_string(),
            did_resolver: crate::did::Resolver::new(Default::default()),
            vid_cache: crate::virtual_id_cache::VirtualIdCache::new(),
            discovery_config_dir: discovery_config_dir.to_string_lossy().to_string(),
            discovery_state_dir: discovery_state_dir.to_string_lossy().to_string(),
            threat_config_path: threat_dir.join("config.yaml").to_string_lossy().to_string(),
            threat_state_dir: threat_dir.to_string_lossy().to_string(),
            admin_dir: admin_dir.to_string_lossy().to_string(),
            admin: AdminStores::new(&admin_dir),
            signer,
            call_session_manager: Arc::new(SessionManager::new()),
            call_signal_hub: Arc::new(CallSignalHub::default()),
            call_nebula_signaling: Arc::new(NebulaSignaling::new(Arc::new(NebulaClient))),
            group_session_manager: Arc::new(GroupSessionManager::new(
                log_dir.join("group_calls.log"),
            )),
            chat_events: broadcast::channel(100).0,
            device_pubkey_point,
            device_did,
            session_ttl_secs: 3600,
            auth_lockout: AuthLockoutConfig::default(),
            auth_rate_limit: AuthRateLimitConfig::default(),
            login_rate_limiter: Arc::new(LoginRateLimiter::default()),
            auth_providers: ProviderRegistry::from_env(),
            device_manager: Arc::new(tokio::sync::RwLock::new(None)),
            automation_engine: Arc::new(tokio::sync::RwLock::new(None)),
            integration_manager: Arc::new(tokio::sync::RwLock::new(None)),
            ha_event_bus: Arc::new(tokio::sync::RwLock::new(None)),
            device_rate_limiter: Arc::new(
                crate::api::auth::rate_limiter::DeviceRateLimiter::default(),
            ),
            notification_manager: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    /// Seeds an Owner admin user and returns a `reqwest::Client` carrying a
    /// valid bearer token for it, for integration tests exercising routes
    /// behind `auth::middleware::require_auth`.
    pub async fn authed_client_for_tests(state: &Arc<Self>) -> reqwest::Client {
        use crate::api::auth::store::{NewUser, UserRole};

        let user = state
            .admin
            .users
            .create(NewUser {
                name: "API Test Admin".into(),
                email: format!("api-test-{}@example.com", uuid::Uuid::new_v4()),
                pw_hash: "test-hash".into(),
                role: UserRole::Owner,
                oidc_sub: None,
            })
            .await
            .expect("seed API test user");
        let (token, _, session_rec) = crate::api::auth::session::issue(
            state.signer.clone(),
            &state.device_did,
            &user,
            std::time::Duration::from_secs(300),
        )
        .await
        .expect("issue API test token");
        state
            .admin
            .sessions
            .put(session_rec)
            .await
            .expect("store API test session");

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                .expect("authorization header"),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("authorized API test client")
    }

    /// Seeds an active browser Member of `circle_id` and returns a
    /// `reqwest::Client` carrying a valid bearer token for it, for
    /// integration tests exercising member-scoped authorization (roster
    /// privacy, Circle-restricted chat/call/file access) rather than the
    /// full-access Owner client above.
    pub async fn member_client_for_tests(state: &Arc<Self>, circle_id: &str) -> reqwest::Client {
        use crate::api::auth::store::NewMemberRegistration;

        let registration_id = uuid::Uuid::new_v4().to_string();
        let fingerprint =
            crate::api::handlers::pwa::guardian_fingerprint(&state.device_pubkey_point);
        let user = state
            .admin
            .users
            .create_or_reactivate_member(NewMemberRegistration {
                name: "API Test Member".into(),
                email: format!("api-test-member-{}@example.com", uuid::Uuid::new_v4()),
                pw_hash: "test-hash".into(),
                circle_id: circle_id.to_string(),
                browser_registration_id: registration_id,
                guardian_fingerprint: fingerprint,
                registration_expires_at: chrono::Utc::now().timestamp() + 3600,
                invite_id: uuid::Uuid::new_v4().to_string(),
                pending_approval: false,
            })
            .await
            .expect("seed API test member");
        let (token, _, session_rec) = crate::api::auth::session::issue(
            state.signer.clone(),
            &state.device_did,
            &user,
            std::time::Duration::from_secs(300),
        )
        .await
        .expect("issue API test member token");
        state
            .admin
            .sessions
            .put(session_rec)
            .await
            .expect("store API test member session");

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                .expect("authorization header"),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("authorized API test member client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Sets an environment variable for the duration of a test and puts the
    /// previous value back afterwards.
    struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EnvGuard {
        fn set(pairs: &[(&'static str, &str)]) -> Self {
            let saved = pairs
                .iter()
                .map(|(key, value)| {
                    let previous = std::env::var_os(key);
                    std::env::set_var(key, value);
                    (*key, previous)
                })
                .collect();
            Self(saved)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.0.drain(..) {
                match previous {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn auth_lockout_config_reads_the_environment_and_ignores_nonsense() {
        let _guard = EnvGuard::set(&[
            ("SGX_GUARDIAN_AUTH_MAX_FAILED_ATTEMPTS", "9"),
            ("SGX_GUARDIAN_AUTH_ATTEMPT_WINDOW_SECS", "120"),
            ("SGX_GUARDIAN_AUTH_LOCKOUT_SECS", "not-a-number"),
        ]);
        let config = AuthLockoutConfig::from_env();
        assert_eq!(config.max_failed_attempts, 9);
        assert_eq!(config.attempt_window_secs, 120);
        assert_eq!(
            config.lockout_secs,
            AuthLockoutConfig::default().lockout_secs,
            "an unparseable value falls back to the default"
        );

        // Zero is rejected the same way a non-numeric value is: a lockout
        // threshold of zero would lock every account out immediately.
        let _guard = EnvGuard::set(&[("SGX_GUARDIAN_AUTH_MAX_FAILED_ATTEMPTS", "0")]);
        assert_eq!(
            AuthLockoutConfig::from_env().max_failed_attempts,
            AuthLockoutConfig::default().max_failed_attempts
        );
    }

    #[test]
    fn auth_rate_limit_config_reads_the_environment_and_ignores_nonsense() {
        let _guard = EnvGuard::set(&[
            ("SGX_GUARDIAN_AUTH_RATE_LIMIT_MAX_ATTEMPTS", "3"),
            ("SGX_GUARDIAN_AUTH_RATE_LIMIT_WINDOW_SECS", "0"),
        ]);
        let config = AuthRateLimitConfig::from_env();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(
            config.window_secs,
            AuthRateLimitConfig::default().window_secs
        );
    }

    #[test]
    fn login_rate_limiter_blocks_a_burst_and_forgets_it_after_the_window() {
        let limiter = LoginRateLimiter::default();
        let config = AuthRateLimitConfig {
            max_attempts: 2,
            window_secs: 60,
        };
        assert!(limiter.check_and_record("user@example.com", 1_000, config));
        assert!(limiter.check_and_record("user@example.com", 1_001, config));
        assert!(
            !limiter.check_and_record("user@example.com", 1_002, config),
            "the third attempt inside the window is refused"
        );
        // A different key has its own budget.
        assert!(limiter.check_and_record("other@example.com", 1_002, config));
        // Once the window has passed, the earlier attempts are dropped.
        assert!(limiter.check_and_record("user@example.com", 1_100, config));
        // An explicit clear (a successful login) resets the counter too.
        limiter.clear("user@example.com");
        assert!(limiter.check_and_record("user@example.com", 1_101, config));
        assert!(limiter.check_and_record("user@example.com", 1_102, config));
    }

    #[tokio::test]
    async fn from_env_wires_production_paths_and_session_settings() {
        let temp = TempDir::new().expect("tempdir");
        let key_path = temp.path().join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("signer"),
        );
        let admin = AdminStores::new(temp.path().join("admin"));
        let _guard = EnvGuard::set(&[("SGX_GUARDIAN_SESSION_TTL_SECS", "120")]);

        let state = AppState::from_env(
            "nodeA".to_string(),
            crate::did::Resolver::new(Default::default()),
            signer,
            admin,
            "did:guardian:test".to_string(),
            vec![4, 5, 6],
        );

        assert_eq!(state.node_id, "nodeA");
        assert_eq!(state.config_dir, "/etc/sgx-guardian/config");
        assert_eq!(state.keys_dir, "/var/lib/sgx-guardian/keys");
        assert_eq!(state.log_dir_fallback, "logs");
        assert_eq!(state.device_did, "did:guardian:test");
        assert_eq!(state.device_pubkey_point, vec![4, 5, 6]);
        assert_eq!(state.session_ttl_secs, 120);
        // The optional subsystems start empty; they are attached later during
        // startup, and every accessor must tolerate that.
        assert!(state.get_device_manager().await.is_none());
        assert!(state.get_automation_engine().await.is_none());
        assert!(state.get_integration_manager().await.is_none());
        assert!(state.get_ha_event_bus().await.is_none());
        assert!(state.get_notification_manager().await.is_none());
    }

    #[tokio::test]
    async fn from_env_falls_back_to_the_default_session_ttl() {
        let temp = TempDir::new().expect("tempdir");
        let key_path = temp.path().join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("signer"),
        );
        let admin = AdminStores::new(temp.path().join("admin"));
        let _guard = EnvGuard::set(&[("SGX_GUARDIAN_SESSION_TTL_SECS", "0")]);
        let state = AppState::from_env(
            "nodeB".to_string(),
            crate::did::Resolver::new(Default::default()),
            signer,
            admin,
            "did:guardian:other".to_string(),
            Vec::new(),
        );
        assert_eq!(state.session_ttl_secs, 3600);
    }
}
