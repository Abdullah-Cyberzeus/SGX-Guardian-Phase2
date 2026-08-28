use crate::homeassistant::circuit_breaker::CircuitBreaker;
use crate::homeassistant::HomeAssistantConfig;
use reqwest::{Client, Error, Response};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Read timeout. Kept short so polling stays responsive.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Service-call timeout. A cloud thermostat command blocks on the vendor round-trip
/// (Home Assistant → Google SDM → device), which regularly exceeds 10s.
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether a failed request may be safely re-sent.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RetryPolicy {
    /// Reads: safe to repeat freely.
    Idempotent,
    /// Service calls: a mid-flight failure is ambiguous — the request may already have
    /// executed at HA — so only provably pre-send (connect) errors are retried. Re-sending
    /// `lock.unlock` or `cover.open_cover` on a timeout would be a safety bug.
    NonIdempotent,
}

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
            client: Client::builder()
                // Per-request timeouts are set on each builder; this is the ceiling.
                .timeout(SERVICE_TIMEOUT)
                .connect_timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
            circuit_breaker: Arc::new(CircuitBreaker::default()),
        }
    }

    /// Internal wrapper to handle Circuit Breaker logic
    async fn execute_with_circuit_breaker<F, Fut>(
        &self,
        policy: RetryPolicy,
        req_fn: F,
    ) -> Result<Response, String>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Response, Error>>,
    {
        // 1. Check Circuit Breaker State
        self.circuit_breaker
            .can_execute()
            .await
            .map_err(|e| e.to_string())?;

        let max_attempts = match policy {
            RetryPolicy::Idempotent => 3,
            RetryPolicy::NonIdempotent => 2,
        };

        // 2. Execute with Retry (idempotent: exponential backoff 1s, 2s)
        let mut attempt = 0;
        let mut backoff = 1;
        let mut last_err = String::new();

        while attempt < max_attempts {
            match req_fn().await {
                Ok(resp) => {
                    self.circuit_breaker.on_success().await;
                    return Ok(resp);
                }
                Err(e) => {
                    // Only a connection error is guaranteed not to have reached HA.
                    let retryable = policy == RetryPolicy::Idempotent || e.is_connect();
                    last_err = e.to_string();
                    attempt += 1;

                    if !retryable {
                        break;
                    }
                    if attempt < max_attempts {
                        if policy == RetryPolicy::Idempotent {
                            sleep(Duration::from_secs(backoff)).await;
                            backoff *= 2;
                        }
                    }
                }
            }
        }

        // 3. Request failed all retries -> increment failures
        self.circuit_breaker.on_failure().await;
        Err(format!(
            "Request failed after {} attempt(s): {}",
            attempt, last_err
        ))
    }

    /// Fetches the status of the Home Assistant API to verify connectivity
    pub async fn check_api_status(&self) -> Result<bool, String> {
        let url = format!("{}/api/", self.config.url);
        let token = self.config.token.clone();

        let client_clone = self.client.clone();
        let resp = self
            .execute_with_circuit_breaker(RetryPolicy::Idempotent, move || {
                let req = client_clone
                    .get(&url)
                    .timeout(READ_TIMEOUT)
                    .bearer_auth(&token);
                req.send()
            })
            .await?;

        Ok(resp.status().is_success())
    }

    /// Fetches all current states from Home Assistant
    pub async fn get_states(&self) -> Result<Vec<serde_json::Value>, String> {
        let url = format!("{}/api/states", self.config.url);
        let token = self.config.token.clone();

        let client_clone = self.client.clone();
        let resp = self
            .execute_with_circuit_breaker(RetryPolicy::Idempotent, move || {
                let req = client_clone
                    .get(&url)
                    .timeout(READ_TIMEOUT)
                    .bearer_auth(&token);
                req.send()
            })
            .await?;

        if resp.status().is_success() {
            resp.json::<Vec<serde_json::Value>>()
                .await
                .map_err(|e| e.to_string())
        } else {
            Err(format!("Failed to get states: HTTP {}", resp.status()))
        }
    }

    /// Fetches a single entity's current state (including its full attribute object).
    pub async fn get_state(&self, entity_id: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}/api/states/{}", self.config.url, entity_id);
        let token = self.config.token.clone();

        let client_clone = self.client.clone();
        let resp = self
            .execute_with_circuit_breaker(RetryPolicy::Idempotent, move || {
                let req = client_clone
                    .get(&url)
                    .timeout(READ_TIMEOUT)
                    .bearer_auth(&token);
                req.send()
            })
            .await?;

        if resp.status().is_success() {
            resp.json::<serde_json::Value>()
                .await
                .map_err(|e| e.to_string())
        } else {
            Err(format!(
                "Failed to get state for {}: HTTP {}",
                entity_id,
                resp.status()
            ))
        }
    }

    /// Fetches Home Assistant's configuration, which carries the active unit system.
    ///
    /// `unit_system.temperature` ("°C" or "°F") drives every temperature label and bound in
    /// the UI, so SGX presents the same scale the user sees in HA.
    pub async fn get_config(&self) -> Result<serde_json::Value, String> {
        let url = format!("{}/api/config", self.config.url);
        let token = self.config.token.clone();

        let client_clone = self.client.clone();
        let resp = self
            .execute_with_circuit_breaker(RetryPolicy::Idempotent, move || {
                let req = client_clone
                    .get(&url)
                    .timeout(READ_TIMEOUT)
                    .bearer_auth(&token);
                req.send()
            })
            .await?;

        if resp.status().is_success() {
            resp.json::<serde_json::Value>()
                .await
                .map_err(|e| e.to_string())
        } else {
            Err(format!("Failed to get HA config: HTTP {}", resp.status()))
        }
    }

    /// Calls a Home Assistant service (e.g., lock.lock, light.turn_on)
    pub async fn call_service(
        &self,
        domain: &str,
        service: &str,
        entity_id: &str,
        mut service_data: Option<serde_json::Value>,
    ) -> Result<(), String> {
        let url = format!("{}/api/services/{}/{}", self.config.url, domain, service);
        let token = self.config.token.clone();

        let payload = match &mut service_data {
            Some(serde_json::Value::Object(map)) => {
                map.insert(
                    "entity_id".to_string(),
                    serde_json::Value::String(entity_id.to_string()),
                );
                serde_json::Value::Object(map.clone())
            }
            _ => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "entity_id".to_string(),
                    serde_json::Value::String(entity_id.to_string()),
                );
                serde_json::Value::Object(map)
            }
        };

        let client_clone = self.client.clone();
        let resp = self
            .execute_with_circuit_breaker(RetryPolicy::NonIdempotent, move || {
                let req = client_clone
                    .post(&url)
                    .timeout(SERVICE_TIMEOUT)
                    .bearer_auth(&token)
                    .json(&payload);
                req.send()
            })
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let error_text = resp.text().await.unwrap_or_default();
            Err(format!(
                "Failed to call service {}.{}: HTTP {} - {}",
                domain, service, status, error_text
            ))
        }
    }
}
