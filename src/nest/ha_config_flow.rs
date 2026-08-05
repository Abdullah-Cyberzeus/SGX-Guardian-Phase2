use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tracing::info;

use crate::nest::credentials::NestCredentials;

#[derive(Debug, Clone)]
pub struct NestHaConfigFlowClient {
    client: Client,
    ha_url: String,
    ha_token: String,
}

#[derive(Debug, Deserialize)]
struct FlowInitiateResponse {
    flow_id: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FlowStepResponse {
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    result: Option<FlowResult>,
    #[serde(default)]
    entry_id: Option<String>,
    #[serde(default)]
    errors: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct FlowResult {
    entry_id: String,
}

impl NestHaConfigFlowClient {
    pub fn new(ha_url: String, ha_token: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_else(|_| Client::new()),
            ha_url,
            ha_token,
        }
    }

    /// Programmatically establishes the Google Nest integration in Home Assistant.
    pub async fn setup_nest_config_entry(&self, creds: &NestCredentials) -> Result<String, String> {
        let flow_url = format!("{}/api/config/config_entries/flow", self.ha_url.trim_end_matches('/'));

        // Step 1: Initiate 'nest' config flow
        let init_resp = self
            .client
            .post(&flow_url)
            .header("Authorization", format!("Bearer {}", self.ha_token))
            .json(&serde_json::json!({
                "handler": "nest",
                "show_advanced_options": false
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to send Nest config flow request to HA: {}", e))?;

        if !init_resp.status().is_success() {
            let err_text = init_resp.text().await.unwrap_or_default();
            return Err(format!("HA config flow initiate failed for Nest: {}", err_text));
        }

        let init_data: FlowInitiateResponse = init_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Nest flow response: {}", e))?;

        let flow_id = init_data.flow_id;
        info!("🔑 Initiated HA config flow for Nest (flow_id: {})", flow_id);

        let step_url = format!(
            "{}/api/config/config_entries/flow/{}",
            self.ha_url.trim_end_matches('/'),
            flow_id
        );

        let project_id_env = std::env::var("SGX_NEST_PROJECT_ID").ok();
        let project_id = creds
            .project_id
            .as_deref()
            .or(project_id_env.as_deref())
            .ok_or_else(|| "Google Nest project_id is required for HA config flow setup".to_string())?;

        let client_id_env = std::env::var("SGX_NEST_CLIENT_ID").ok();
        let client_id = creds
            .client_id
            .as_deref()
            .or(client_id_env.as_deref())
            .ok_or_else(|| "Google Nest client_id is required for HA config flow setup".to_string())?;

        let client_secret_env = std::env::var("SGX_NEST_CLIENT_SECRET").ok();
        let client_secret = creds
            .client_secret
            .as_deref()
            .or(client_secret_env.as_deref())
            .ok_or_else(|| "Google Nest client_secret is required for HA config flow setup".to_string())?;

        // Step 2: Submit SDM Project & OAuth credentials
        let step_payload = serde_json::json!({
            "project_id": project_id,
            "client_id": client_id,
            "client_secret": client_secret,
            "access_token": creds.access_token,
            "refresh_token": creds.refresh_token
        });

        let step_resp = self
            .client
            .post(&step_url)
            .header("Authorization", format!("Bearer {}", self.ha_token))
            .json(&step_payload)
            .send()
            .await
            .map_err(|e| format!("Failed to submit Nest credentials to HA: {}", e))?;

        if !step_resp.status().is_success() {
            let err_text = step_resp.text().await.unwrap_or_default();
            return Err(format!("HA config flow submission failed for Nest: {}", err_text));
        }

        let step_data: FlowStepResponse = step_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Nest flow step response: {}", e))?;

        if let Some(entry_id) = step_data.entry_id {
            info!("✅ Successfully created HA Nest config entry: {}", entry_id);
            return Ok(entry_id);
        }

        if let Some(res) = step_data.result {
            info!("✅ Successfully created HA Nest config entry: {}", res.entry_id);
            return Ok(res.entry_id);
        }

        Err("Nest HA config flow completed but no entry_id was returned".to_string())
    }

    /// Programmatically unbinds/removes the Nest integration entry from HA.
    pub async fn remove_nest_config_entry(&self, entry_id: &str) -> Result<(), String> {
        let delete_url = format!(
            "{}/api/config/config_entries/entry/{}",
            self.ha_url.trim_end_matches('/'),
            entry_id
        );

        let resp = self
            .client
            .delete(&delete_url)
            .header("Authorization", format!("Bearer {}", self.ha_token))
            .send()
            .await
            .map_err(|e| format!("Failed to send delete config entry request to HA for Nest: {}", e))?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(format!("Failed to remove HA Nest config entry '{}': {}", entry_id, err_text));
        }

        info!("🗑️ Successfully removed HA Nest config entry '{}'", entry_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nest_flow_response_parsing() {
        let json_init = r#"{ "flow_id": "flow_nest_123" }"#;
        let parsed_init: FlowInitiateResponse = serde_json::from_str(json_init).unwrap();
        assert_eq!(parsed_init.flow_id, "flow_nest_123");

        let json_step = r#"{
            "result": { "entry_id": "nest_entry_456" }
        }"#;
        let parsed_step: FlowStepResponse = serde_json::from_str(json_step).unwrap();
        assert_eq!(parsed_step.result.unwrap().entry_id, "nest_entry_456");
    }
}
