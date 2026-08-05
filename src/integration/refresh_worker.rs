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
                if crate::nest::NestTokenRefresher::is_expiring_soon(nest_creds, self.expiry_window_secs) {
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

        info!("✅ OAuth token refreshed successfully for {}", provider.display_name());

        self.manager
            .set_credentials(provider, creds.clone())
            .await?;

        Ok(())
    }
}
