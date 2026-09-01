use chrono::Utc;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use crate::integration::manager::IntegrationManager;
use crate::integration::provider::{IntegrationStatus, VendorProvider};

pub struct TokenRefreshWorker {
    manager: Arc<IntegrationManager>,
    check_interval: Duration,
    expiry_window_secs: i64,
}

impl TokenRefreshWorker {
    pub fn new(manager: Arc<IntegrationManager>) -> Self {
        Self {
            manager,
            check_interval: Duration::from_secs(60),
            expiry_window_secs: 300, // 5 minutes before expiration
        }
    }

    /// Spawns the background token auto-refresh loop
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            println!("🔄 Integration Token Refresh Worker started.");
            info!("🔄 Integration Token Refresh Worker started.");
            loop {
                sleep(self.check_interval).await;
                self.check_and_refresh_tokens().await;
            }
        });
    }

    /// Checks all integrations for expiring tokens and refreshes them
    pub async fn check_and_refresh_tokens(&self) {
        let integrations = self.manager.list_integrations().await;
        let now = Utc::now();

        for meta in integrations {
            if meta.status == IntegrationStatus::Disconnected {
                continue;
            }

            if let Some(ref creds) = meta.credentials {
                if let Some(expires_at) = creds.expires_at {
                    let time_remaining = expires_at.signed_duration_since(now).num_seconds();

                    if time_remaining <= self.expiry_window_secs {
                        info!(
                            "⏳ OAuth token for {} expires in {}s. Triggering refresh...",
                            meta.provider.display_name(),
                            time_remaining
                        );

                        if let Err(e) = self.refresh_provider_token(meta.provider).await {
                            warn!(
                                "❌ OAuth token refresh failed for {}: {}. Transitioning integration to Expired.",
                                meta.provider.display_name(),
                                e
                            );

                            let _ = self
                                .manager
                                .update_integration_status(
                                    meta.provider,
                                    IntegrationStatus::Expired,
                                    Some(format!("OAuth token expired & refresh failed: {}", e)),
                                )
                                .await;
                        }
                    }
                }
            } else if let Some(ref nest_creds) = meta.nest_credentials {
                if crate::nest::NestTokenRefresher::is_expiring_soon(
                    nest_creds,
                    self.expiry_window_secs,
                ) {
                    info!(
                        "⏳ Nest OAuth token for {} expires soon. Triggering Google OAuth refresh...",
                        meta.provider.display_name()
                    );

                    match crate::nest::NestTokenRefresher::refresh_access_token(nest_creds).await {
                        Ok(new_creds) => {
                            if let Err(e) = self.manager.update_nest_credentials(new_creds).await {
                                warn!("❌ Failed to save refreshed Nest credentials: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("❌ Nest OAuth token refresh failed: {}", e);
                            let err_msg = format!("Token refresh failed: {}", e);
                            let _ = self
                                .manager
                                .update_integration_status(
                                    meta.provider,
                                    IntegrationStatus::Error(err_msg.clone()),
                                    Some(err_msg),
                                )
                                .await;
                        }
                    }
                }
            }
        }
    }

    /// Simulates/Performs OAuth token refresh for vendor provider
    async fn refresh_provider_token(&self, provider: VendorProvider) -> Result<(), String> {
        let mut meta = self
            .manager
            .get_integration(provider)
            .await
            .ok_or_else(|| "Integration not found".to_string())?;

        let creds = meta
            .credentials
            .as_mut()
            .ok_or_else(|| "No credentials available for refresh".to_string())?;

        let refresh_token = creds
            .refresh_token
            .as_ref()
            .ok_or_else(|| "No refresh_token present for provider".to_string())?;

        if refresh_token.contains("invalid") || refresh_token.contains("fail") {
            return Err("401 Unauthorized: Invalid refresh token".to_string());
        }

        // Renew token: extend expiration by 1 hour
        creds.access_token = format!("renewed_access_token_{}", uuid::Uuid::new_v4().simple());
        creds.expires_at = Some(Utc::now() + chrono::Duration::hours(1));

        info!(
            "✅ OAuth token refreshed successfully for {}",
            provider.display_name()
        );

        self.manager
            .set_credentials(provider, creds.clone())
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::provider::OAuthCredentials;

    fn new_manager() -> Arc<IntegrationManager> {
        let temp_dir = tempfile::tempdir().unwrap();
        let int_file = temp_dir.path().join("integrations_refresh_worker.json");
        // Leak the TempDir so the backing file survives for the life of the test — cheap and
        // fine for a short-lived unit test.
        std::mem::forget(temp_dir);
        IntegrationManager::new(int_file.to_str().unwrap())
    }

    fn oauth_creds(refresh_token: Option<&str>, expires_in_secs: i64) -> OAuthCredentials {
        OAuthCredentials {
            access_token: "initial_access_token".to_string(),
            refresh_token: refresh_token.map(|s| s.to_string()),
            expires_at: Some(Utc::now() + chrono::Duration::seconds(expires_in_secs)),
            token_type: "Bearer".to_string(),
            scope: None,
        }
    }

    #[tokio::test]
    async fn test_refresh_provider_token_no_credentials_at_all() {
        let manager = new_manager();
        let worker = TokenRefreshWorker::new(manager);

        let err = worker
            .refresh_provider_token(VendorProvider::GoogleNest)
            .await
            .unwrap_err();
        assert!(
            err.contains("No credentials available for refresh"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_refresh_provider_token_missing_refresh_token() {
        let manager = new_manager();
        manager
            .connect_integration(VendorProvider::GoogleNest, oauth_creds(None, 3600))
            .await
            .unwrap();

        let worker = TokenRefreshWorker::new(manager);
        let err = worker
            .refresh_provider_token(VendorProvider::GoogleNest)
            .await
            .unwrap_err();
        assert!(
            err.contains("No refresh_token present for provider"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_refresh_provider_token_invalid_token_fails() {
        let manager = new_manager();
        manager
            .connect_integration(
                VendorProvider::GoogleNest,
                oauth_creds(Some("this_refresh_token_is_invalid"), 3600),
            )
            .await
            .unwrap();

        let worker = TokenRefreshWorker::new(manager.clone());
        let err = worker
            .refresh_provider_token(VendorProvider::GoogleNest)
            .await
            .unwrap_err();
        assert!(
            err.contains("401 Unauthorized"),
            "unexpected error: {err}"
        );

        // A failed refresh must not silently rewrite the stored access token.
        let meta = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert_eq!(
            meta.credentials.unwrap().access_token,
            "initial_access_token"
        );
    }

    #[tokio::test]
    async fn test_refresh_provider_token_success_renews_credentials() {
        let manager = new_manager();
        manager
            .connect_integration(
                VendorProvider::TpLinkKasa,
                oauth_creds(Some("good_refresh_token"), 100),
            )
            .await
            .unwrap();

        let worker = TokenRefreshWorker::new(manager.clone());
        worker
            .refresh_provider_token(VendorProvider::TpLinkKasa)
            .await
            .unwrap();

        let meta = manager
            .get_integration(VendorProvider::TpLinkKasa)
            .await
            .unwrap();
        let creds = meta.credentials.unwrap();
        assert!(creds.access_token.starts_with("renewed_access_token_"));
        assert!(creds.expires_at.unwrap() > Utc::now() + chrono::Duration::minutes(30));
    }

    #[tokio::test]
    async fn test_check_and_refresh_tokens_skips_disconnected_integrations() {
        // Fresh manager: both providers start Disconnected with no credentials, so the sweep
        // must not touch (or panic on) either of them.
        let manager = new_manager();
        let worker = TokenRefreshWorker::new(manager.clone());

        worker.check_and_refresh_tokens().await;

        let nest = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        let kasa = manager
            .get_integration(VendorProvider::TpLinkKasa)
            .await
            .unwrap();
        assert_eq!(nest.status, IntegrationStatus::Disconnected);
        assert_eq!(kasa.status, IntegrationStatus::Disconnected);
    }

    #[tokio::test]
    async fn test_check_and_refresh_tokens_refreshes_expiring_token() {
        let manager = new_manager();
        // Expires in 100s, well within the worker's 300s expiry window -> must be refreshed.
        manager
            .connect_integration(
                VendorProvider::TpLinkKasa,
                oauth_creds(Some("good_refresh_token"), 100),
            )
            .await
            .unwrap();

        let worker = TokenRefreshWorker::new(manager.clone());
        worker.check_and_refresh_tokens().await;

        let meta = manager
            .get_integration(VendorProvider::TpLinkKasa)
            .await
            .unwrap();
        assert_eq!(meta.status, IntegrationStatus::Connected);
        assert!(meta
            .credentials
            .unwrap()
            .access_token
            .starts_with("renewed_access_token_"));
    }

    #[tokio::test]
    async fn test_check_and_refresh_tokens_marks_expired_on_failed_refresh() {
        let manager = new_manager();
        manager
            .connect_integration(
                VendorProvider::TpLinkKasa,
                oauth_creds(Some("this_will_fail_refresh"), 100),
            )
            .await
            .unwrap();

        let worker = TokenRefreshWorker::new(manager.clone());
        worker.check_and_refresh_tokens().await;

        let meta = manager
            .get_integration(VendorProvider::TpLinkKasa)
            .await
            .unwrap();
        assert_eq!(meta.status, IntegrationStatus::Expired);
        assert!(meta.error_message.is_some());
        assert!(meta
            .error_message
            .as_ref()
            .unwrap()
            .contains("OAuth token expired & refresh failed"));
    }

    #[tokio::test]
    async fn test_check_and_refresh_tokens_ignores_token_not_yet_expiring() {
        let manager = new_manager();
        // Expires in a full hour: well outside the 300s expiry window, so no refresh should fire.
        manager
            .connect_integration(
                VendorProvider::TpLinkKasa,
                oauth_creds(Some("good_refresh_token"), 3600),
            )
            .await
            .unwrap();

        let worker = TokenRefreshWorker::new(manager.clone());
        worker.check_and_refresh_tokens().await;

        let meta = manager
            .get_integration(VendorProvider::TpLinkKasa)
            .await
            .unwrap();
        assert_eq!(meta.status, IntegrationStatus::Connected);
        assert_eq!(meta.credentials.unwrap().access_token, "initial_access_token");
    }

    #[tokio::test]
    async fn test_check_and_refresh_tokens_nest_credentials_not_expiring_skips_refresh() {
        // Nest credentials route through a *real* Google OAuth HTTP call when a refresh is
        // due, which this suite must never trigger. Using a token that is not yet expiring
        // (NestCredentials::new sets expires_at ~1h out) exercises the decision branch
        // without ever reaching the network call.
        let manager = new_manager();
        let nest_creds = crate::nest::NestCredentials::new(
            Some("client".to_string()),
            Some("secret".to_string()),
            Some("project".to_string()),
            Some("access_token_fresh".to_string()),
            Some("refresh_token_fresh".to_string()),
        );
        manager.connect_nest(nest_creds, None, None).await.unwrap();

        let worker = TokenRefreshWorker::new(manager.clone());
        worker.check_and_refresh_tokens().await;

        let meta = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert_eq!(meta.status, IntegrationStatus::Connected);
        assert_eq!(
            meta.nest_credentials.unwrap().access_token.as_deref(),
            Some("access_token_fresh"),
            "credentials must be untouched when not expiring soon"
        );
    }

    #[tokio::test]
    async fn test_check_and_refresh_tokens_nest_credentials_expiring_but_unrefreshable_marks_error(
    ) {
        // `refresh_access_token` validates required fields (refresh_token first) before ever
        // making the real Google OAuth network call, so a token with no refresh_token exercises
        // the "expiring soon -> attempt refresh -> fails" branch deterministically, with no
        // network access.
        let manager = new_manager();
        let mut nest_creds = crate::nest::NestCredentials::new(
            Some("client".to_string()),
            Some("secret".to_string()),
            Some("project".to_string()),
            Some("access_token_expiring".to_string()),
            None,
        );
        nest_creds.expires_at = Some(Utc::now() + chrono::Duration::seconds(10));
        manager.connect_nest(nest_creds, None, None).await.unwrap();

        let worker = TokenRefreshWorker::new(manager.clone());
        worker.check_and_refresh_tokens().await;

        let meta = manager
            .get_integration(VendorProvider::GoogleNest)
            .await
            .unwrap();
        assert!(
            matches!(meta.status, IntegrationStatus::Error(_)),
            "unexpected status: {:?}",
            meta.status
        );
        assert!(meta
            .error_message
            .as_ref()
            .unwrap()
            .contains("Token refresh failed"));
    }
}
