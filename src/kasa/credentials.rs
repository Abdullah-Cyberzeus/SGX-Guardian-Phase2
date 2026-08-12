use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KasaCredentials {
    pub mode: String, // "cloud" or "local"
    pub username: Option<String>,
    pub password: Option<String>,
    pub config_entry_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl KasaCredentials {
    pub fn new(mode: Option<String>, username: Option<String>, password: Option<String>) -> Self {
        let mode_str = mode.unwrap_or_else(|| "cloud".to_string()).to_lowercase();
        Self {
            mode: mode_str,
            username: username.filter(|s| !s.trim().is_empty()),
            password: password.filter(|s| !s.trim().is_empty()),
            config_entry_id: None,
            created_at: Utc::now(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.mode == "cloud" {
            let has_user = self
                .username
                .as_ref()
                .map_or(false, |u| !u.trim().is_empty());
            let has_pass = self
                .password
                .as_ref()
                .map_or(false, |p| !p.trim().is_empty());
            if !has_user || !has_pass {
                return Err("Username and password are required for cloud mode".to_string());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_mode_validation() {
        let valid = KasaCredentials::new(
            Some("cloud".to_string()),
            Some("user@kasa.com".to_string()),
            Some("pass123".to_string()),
        );
        assert!(valid.validate().is_ok());

        let invalid = KasaCredentials::new(
            Some("cloud".to_string()),
            Some("user@kasa.com".to_string()),
            None,
        );
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_local_mode_validation() {
        let local = KasaCredentials::new(Some("local".to_string()), None, None);
        assert!(local.validate().is_ok());
    }
}
