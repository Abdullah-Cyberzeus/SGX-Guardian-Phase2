use crate::nest::credentials::NestCredentials;
use chrono::{Duration, Utc};
use reqwest::Client;
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct GoogleOAuthTokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

pub struct NestTokenRefresher;

impl NestTokenRefresher {
    /// Returns true if the access token is missing, expired, or expiring within `threshold_secs` (default 300s).
    pub fn is_expiring_soon(creds: &NestCredentials, threshold_secs: i64) -> bool {
        if creds.access_token.is_none() {
            return true;
        }

        match creds.expires_at {
            Some(expires) => {
                let now = Utc::now();
                expires <= now + Duration::seconds(threshold_secs)
            }
            None => false, // If no expiration set, assume valid until Google returns 401
        }
    }

    /// Performs OAuth 2.0 token refresh call to Google's token endpoint (`https://oauth2.googleapis.com/token`).
    pub async fn refresh_access_token(creds: &NestCredentials) -> Result<NestCredentials, String> {
        let refresh_token = creds
            .refresh_token
            .as_deref()
            .ok_or_else(|| "No refresh_token available in NestCredentials".to_string())?;

        let client_id_env = std::env::var("SGX_NEST_CLIENT_ID").ok();
        let client_id = creds
            .client_id
            .as_deref()
            .or(client_id_env.as_deref())
            .ok_or_else(|| {
                "Google Nest client_id is required but missing from credentials and environment"
                    .to_string()
            })?;

        let client_secret_env = std::env::var("SGX_NEST_CLIENT_SECRET").ok();
        let client_secret = creds
            .client_secret
            .as_deref()
            .or(client_secret_env.as_deref())
            .ok_or_else(|| {
                "Google Nest client_secret is required but missing from credentials and environment"
                    .to_string()
            })?;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| format!("Failed to build reqwest HTTP client: {}", e))?;

        let params = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ];

        info!("🔄 Requesting Google Nest OAuth 2.0 token refresh...");

        let resp = client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Google OAuth token refresh HTTP request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Google OAuth token refresh error (HTTP {}): {}",
                status, err_text
            ));
        }

        let token_data: GoogleOAuthTokenResponse = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Google OAuth token response: {}", e))?;

        let expires_at = Utc::now() + Duration::seconds(token_data.expires_in);

        let mut updated_creds = creds.clone();
        updated_creds.access_token = Some(token_data.access_token);
        updated_creds.expires_at = Some(expires_at);

        if let Some(new_refresh) = token_data.refresh_token {
            updated_creds.refresh_token = Some(new_refresh);
        }

        info!(
            "✅ Google Nest OAuth access token refreshed successfully (expires at {})",
            expires_at
        );
        Ok(updated_creds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nest_token_expiration_check() {
        let mut creds = NestCredentials::new(
            Some("client".to_string()),
            Some("secret".to_string()),
            Some("project".to_string()),
            Some("access_123".to_string()),
            Some("refresh_456".to_string()),
        );

        // No expires_at set -> not expiring soon
        assert!(!NestTokenRefresher::is_expiring_soon(&creds, 300));

        // Expires in 100s -> expiring soon (threshold 300s)
        creds.expires_at = Some(Utc::now() + Duration::seconds(100));
        assert!(NestTokenRefresher::is_expiring_soon(&creds, 300));

        // Expires in 1000s -> not expiring soon (threshold 300s)
        creds.expires_at = Some(Utc::now() + Duration::seconds(1000));
        assert!(!NestTokenRefresher::is_expiring_soon(&creds, 300));
    }

    #[test]
    fn test_google_oauth_response_deserialization() {
        let json_data = r#"{
            "access_token": "ya29.a0AfH6SMB...",
            "expires_in": 3599,
            "token_type": "Bearer",
            "scope": "https://www.googleapis.com/auth/sdm.service"
        }"#;

        let parsed: GoogleOAuthTokenResponse = serde_json::from_str(json_data).unwrap();
        assert_eq!(parsed.access_token, "ya29.a0AfH6SMB...");
        assert_eq!(parsed.expires_in, 3599);
        assert_eq!(parsed.token_type, Some("Bearer".to_string()));
    }
}
