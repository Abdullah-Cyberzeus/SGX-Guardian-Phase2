use serde::{Deserialize, Serialize};

/// Represents Google Nest SDM & OAuth 2.0 Credentials (stored AES-GCM-256 encrypted at rest).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NestCredentials {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub project_id: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub config_entry_id: Option<String>,
}

impl NestCredentials {
    pub fn new(
        client_id: Option<String>,
        client_secret: Option<String>,
        project_id: Option<String>,
        access_token: Option<String>,
        refresh_token: Option<String>,
    ) -> Self {
        let expires_at = if access_token.is_some() {
            Some(chrono::Utc::now() + chrono::Duration::seconds(3600))
        } else {
            None
        };

        Self {
            client_id,
            client_secret,
            project_id,
            access_token,
            refresh_token,
            expires_at,
            config_entry_id: None,
        }
    }

    /// Validates Nest OAuth credentials payload
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref token) = self.access_token {
            if token.trim().is_empty() {
                return Err("Nest access_token cannot be empty".to_string());
            }
        }
        if let Some(ref token) = self.refresh_token {
            if token.trim().is_empty() {
                return Err("Nest refresh_token cannot be empty".to_string());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nest_credentials_validation() {
        let valid = NestCredentials::new(
            Some("client_123".to_string()),
            Some("secret_456".to_string()),
            Some("project_789".to_string()),
            Some("access_token_demo".to_string()),
            Some("refresh_token_demo".to_string()),
        );
        assert!(valid.validate().is_ok());

        let invalid = NestCredentials::new(
            None,
            None,
            None,
            Some("".to_string()),
            None,
        );
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_nest_credentials_serialization() {
        let creds = NestCredentials::new(
            Some("client_id".to_string()),
            Some("client_secret".to_string()),
            Some("project_id".to_string()),
            Some("access_token".to_string()),
            Some("refresh_token".to_string()),
        );
        let serialized = serde_json::to_string(&creds).unwrap();
        let deserialized: NestCredentials = serde_json::from_str(&serialized).unwrap();
        assert_eq!(creds, deserialized);
    }
}
