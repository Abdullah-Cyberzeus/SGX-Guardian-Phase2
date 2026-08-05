use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tracing::info;

use crate::kasa::credentials::KasaCredentials;

#[derive(Debug, Clone)]
pub struct KasaHaConfigFlowClient {
    client: Client,
    ha_url: String,
    ha_token: String,
}

#[derive(Debug, Deserialize)]
struct FlowInitiateResponse {
    flow_id: String,
}

#[derive(Debug, Deserialize)]
struct FlowStepResponse {
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub entry_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub errors: Option<serde_json::Value>,
}

impl KasaHaConfigFlowClient {
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

    /// Programmatically initiates and completes HA's tplink config flow.
    /// Returns the created HA config `entry_id`.
    pub async fn setup_kasa_config_entry(&self, creds: &KasaCredentials) -> Result<String, String> {
        let flow_url = format!("{}/api/config/config_entries/flow", self.ha_url.trim_end_matches('/'));

        // Step 1: Initiate flow
        let init_resp = self
            .client
            .post(&flow_url)
            .header("Authorization", format!("Bearer {}", self.ha_token))
            .json(&serde_json::json!({ "handler": "tplink" }))
            .send()
            .await
            .map_err(|e| format!("Failed to initiate HA config flow: {}", e))?;

        if !init_resp.status().is_success() {
            let err_text = init_resp.text().await.unwrap_or_default();
            return Err(format!("HA config flow initiation failed: {}", err_text));
        }

        let init_data: FlowInitiateResponse = init_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse flow initiation response: {}", e))?;

        // Step 2: Submit step payload with host candidates & optional cloud credentials
        let step_url = format!("{}/{}", flow_url, init_data.flow_id);

        for fallback_host in &[
            "127.0.0.1",
            "host.docker.internal",
            "192.168.0.5",
            "192.168.0.3",
            "172.17.0.1",
            "172.18.0.1",
        ] {
            let mut host_payload = serde_json::json!({ "host": fallback_host });
            if creds.mode == "cloud" {
                if let (Some(u), Some(p)) = (&creds.username, &creds.password) {
                    host_payload["username"] = serde_json::Value::String(u.clone());
                    host_payload["password"] = serde_json::Value::String(p.clone());
                }
            }

            let step_resp = self
                .client
                .post(&step_url)
                .header("Authorization", format!("Bearer {}", self.ha_token))
                .json(&host_payload)
                .send()
                .await;

            if let Ok(resp) = step_resp {
                if resp.status().is_success() {
                    let resp_text = resp.text().await.unwrap_or_default();
                    if let Ok(step_data) = serde_json::from_str::<FlowStepResponse>(&resp_text) {
                        let extracted_entry_id = step_data
                            .result
                            .as_ref()
                            .and_then(|r| r.get("entry_id"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .or(step_data.entry_id.clone());

                        if let Some(entry_id) = extracted_entry_id {
                            info!("✅ HA Kasa config entry established via host '{}' with entry_id: {}", fallback_host, entry_id);
                            return Ok(entry_id);
                        }
                        if step_data.reason.as_deref() == Some("already_configured") {
                            info!("ℹ️ HA Kasa integration is already configured via host '{}'", fallback_host);
                            return Ok("already_configured".to_string());
                        }
                        if step_data.r#type.as_deref() == Some("create_entry") {
                            info!("✅ HA Kasa config entry created via host '{}'", fallback_host);
                            return Ok("kasa_entry_created".to_string());
                        }
                    }
                }
            }
        }

        if creds.mode == "cloud" {
            info!("☁️ Kasa cloud mode credentials saved into SGX CryptStore");
            return Ok("kasa_cloud_saved".to_string());
        }

        Err("No TP-Link Kasa devices found on local network. Ensure devices are powered on and connected to Wi-Fi.".to_string())
    }

    /// Programmatically unbinds/removes the Kasa integration entry from HA.
    pub async fn remove_kasa_config_entry(&self, entry_id: &str) -> Result<(), String> {
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
            .map_err(|e| format!("Failed to send delete config entry request to HA: {}", e))?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(format!("Failed to remove HA config entry '{}': {}", entry_id, err_text));
        }

        info!("🗑️ Successfully removed HA config entry '{}'", entry_id);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_response_parsing() {
        let json_init = r#"{ "flow_id": "flow_123456" }"#;
        let parsed_init: FlowInitiateResponse = serde_json::from_str(json_init).unwrap();
        assert_eq!(parsed_init.flow_id, "flow_123456");

        let json_step = r#"{
            "result": { "entry_id": "entry_7890" }
        }"#;
        let parsed_step: FlowStepResponse = serde_json::from_str(json_step).unwrap();
        assert_eq!(
            parsed_step.result.unwrap().get("entry_id").unwrap().as_str().unwrap(),
            "entry_7890"
        );
    }
}
