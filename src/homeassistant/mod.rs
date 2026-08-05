pub mod rest;
pub mod websocket;
pub mod events;
pub mod circuit_breaker;


use dotenvy::dotenv;
use std::env;

/// Configuration for Home Assistant connection
#[derive(Debug, Clone)]
pub struct HomeAssistantConfig {
    pub url: String,
    pub token: String,
}

impl HomeAssistantConfig {
    /// Loads the Home Assistant configuration from environment variables (.env)
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        // Attempt to load .env file, ignoring error if it doesn't exist
        // so it can fall back to system environment variables.
        let _ = dotenv();

        let url = env::var("HA_URL").map_err(|_| "HA_URL environment variable is not set")?;
        let url = url.trim_end_matches('/').to_string();
        let token = env::var("HA_TOKEN").map_err(|_| "HA_TOKEN environment variable is not set")?;

        Ok(Self { url, token })
    }
}
