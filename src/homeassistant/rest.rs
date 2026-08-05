use crate::homeassistant::circuit_breaker::CircuitBreaker;
use crate::homeassistant::HomeAssistantConfig;
use reqwest::{Client, Error, Response};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// REST Client for sending commands to Home Assistant with Retries and Circuit Breaker
#[derive(Clone)]
pub struct HaRestClient {
    client: Client,
    config: HomeAssistantConfig,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl HaRestClient {
    pub fn new(config: HomeAssistantConfig) -> Self {
        Self {
            // Requirement: 10s timeout on REST calls
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
            circuit_breaker: Arc::new(CircuitBreaker::default()),
        }
    }

    /// Internal wrapper to handle Circuit Breaker logic
    async fn execute_with_circuit_breaker<F, Fut>(&self, req_fn: F) -> Result<Response, String>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Response, Error>>,
    {
        // 1. Check Circuit Breaker State
        self.circuit_breaker.can_execute().await.map_err(|e| e.to_string())?;

        // 2. Execute with Retry (3 attempts with exponential backoff: 1s, 2s, 4s)
        let mut attempt = 0;
        let mut backoff = 1;
        let mut last_err = String::new();

        while attempt < 3 {
            match req_fn().await {
                Ok(resp) => {
                    self.circuit_breaker.on_success().await;
                    return Ok(resp);
                }
                Err(e) => {
                    last_err = e.to_string();
                    attempt += 1;
                    if attempt < 3 {
                        sleep(Duration::from_secs(backoff)).await;
                        backoff *= 2; // 1s, 2s, 4s
                    }
                }
            }
        }

        // 3. Request failed all retries -> increment failures
        self.circuit_breaker.on_failure().await;
        Err(format!("Request failed after 3 attempts: {}", last_err))
    }

    /// Fetches the status of the Home Assistant API to verify connectivity
    pub async fn check_api_status(&self) -> Result<bool, String> {
        let url = format!("{}/api/", self.config.url);
        let token = self.config.token.clone();
        
        let client_clone = self.client.clone();
        let resp = self.execute_with_circuit_breaker(move || {
            let req = client_clone
                .get(&url)
                .bearer_auth(&token);
            req.send()
        }).await?;

        Ok(resp.status().is_success())
    }
    /// Fetches all current states from Home Assistant
    pub async fn get_states(&self) -> Result<Vec<serde_json::Value>, String> {
        let url = format!("{}/api/states", self.config.url);
        let token = self.config.token.clone();
        
        let client_clone = self.client.clone();
        let resp = self.execute_with_circuit_breaker(move || {
            let req = client_clone
                .get(&url)
                .bearer_auth(&token);
            req.send()
        }).await?;

        if resp.status().is_success() {
            resp.json::<Vec<serde_json::Value>>().await.map_err(|e| e.to_string())
        } else {
            Err(format!("Failed to get states: HTTP {}", resp.status()))
        }
    }

    /// Calls a Home Assistant service (e.g., lock.lock, light.turn_on)
    pub async fn call_service(&self, domain: &str, service: &str, entity_id: &str, mut service_data: Option<serde_json::Value>) -> Result<(), String> {
        let url = format!("{}/api/services/{}/{}", self.config.url, domain, service);
        let token = self.config.token.clone();
        
        let payload = match &mut service_data {
            Some(serde_json::Value::Object(map)) => {
                map.insert("entity_id".to_string(), serde_json::Value::String(entity_id.to_string()));
                serde_json::Value::Object(map.clone())
            }
            _ => {
                let mut map = serde_json::Map::new();
                map.insert("entity_id".to_string(), serde_json::Value::String(entity_id.to_string()));
                serde_json::Value::Object(map)
            }
        };

        let client_clone = self.client.clone();
        let resp = self.execute_with_circuit_breaker(move || {
            let req = client_clone
                .post(&url)
                .bearer_auth(&token)
                .json(&payload);
            req.send()
        }).await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to call service {}.{}: HTTP {}", domain, service, resp.status()))
        }
    }
}
