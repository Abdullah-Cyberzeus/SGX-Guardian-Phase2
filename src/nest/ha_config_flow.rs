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
    ///
    /// Returns `(entry_id, restarted)`. `restarted` is true when the entry was created via
    /// direct storage injection, which requires an HA restart before it takes effect (see
    /// `inject_direct_storage_entry`) — callers must wait for HA to come back before
    /// expecting entities to exist. It is false for the config-flow fallback below, which
    /// creates a live entry directly in HA's running process.
    pub async fn setup_nest_config_entry(
        &self,
        creds: &NestCredentials,
    ) -> Result<(String, bool), String> {
        // Step 0: Try direct storage injection if local HA volume is accessible (instant, 100% reliable)
        if let Some(entry_id) = self.inject_direct_storage_entry(creds).await {
            info!("✅ Successfully established HA Nest config entry via direct storage provisioning: {}", entry_id);
            return Ok((entry_id, true));
        }

        let flow_url = format!(
            "{}/api/config/config_entries/flow",
            self.ha_url.trim_end_matches('/')
        );

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
            return Err(format!(
                "HA config flow initiate failed for Nest: {}",
                err_text
            ));
        }

        let init_data: FlowInitiateResponse = init_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Nest flow response: {}", e))?;

        let flow_id = init_data.flow_id;
        info!(
            "🔑 Initiated HA config flow for Nest (flow_id: {})",
            flow_id
        );

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
            .ok_or_else(|| {
                "Google Nest project_id is required for HA config flow setup".to_string()
            })?;

        let client_id_env = std::env::var("SGX_NEST_CLIENT_ID").ok();
        let client_id = creds
            .client_id
            .as_deref()
            .or(client_id_env.as_deref())
            .ok_or_else(|| {
                "Google Nest client_id is required for HA config flow setup".to_string()
            })?;

        let client_secret_env = std::env::var("SGX_NEST_CLIENT_SECRET").ok();
        let client_secret = creds
            .client_secret
            .as_deref()
            .or(client_secret_env.as_deref())
            .ok_or_else(|| {
                "Google Nest client_secret is required for HA config flow setup".to_string()
            })?;

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
            return Err(format!(
                "HA config flow submission failed for Nest: {}",
                err_text
            ));
        }

        let step_data: FlowStepResponse = step_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Nest flow step response: {}", e))?;

        if let Some(entry_id) = step_data.entry_id {
            info!("✅ Successfully created HA Nest config entry: {}", entry_id);
            return Ok((entry_id, false));
        }

        if let Some(res) = step_data.result {
            info!(
                "✅ Successfully created HA Nest config entry: {}",
                res.entry_id
            );
            return Ok((res.entry_id, false));
        }

        Err("Nest HA config flow completed but no entry_id was returned".to_string())
    }

    /// Directly injects the Nest config entry into Home Assistant storage volume.
    pub async fn inject_direct_storage_entry(&self, creds: &NestCredentials) -> Option<String> {
        let storage_dirs = [
            "/ha-config/.storage",
            "./ha-dev-config/.storage",
            "./ha-config/.storage",
            "/config/.storage",
        ];

        let storage_path = storage_dirs
            .iter()
            .find(|p| std::path::Path::new(p).exists())?;

        let project_id_env = std::env::var("SGX_NEST_PROJECT_ID").ok();
        let project_id = creds.project_id.as_deref().or(project_id_env.as_deref())?;

        let client_id_env = std::env::var("SGX_NEST_CLIENT_ID").ok();
        let client_id = creds.client_id.as_deref().or(client_id_env.as_deref())?;

        let client_secret_env = std::env::var("SGX_NEST_CLIENT_SECRET").ok();
        let client_secret = creds
            .client_secret
            .as_deref()
            .or(client_secret_env.as_deref())?;

        let access_token = creds.access_token.as_deref()?;
        let refresh_token = creds.refresh_token.as_deref().unwrap_or("");

        let auth_impl_id = format!("nest_{}", client_id.replace('-', "_").replace('.', "_"));

        // 1. Update application_credentials
        let app_creds_path = format!("{}/application_credentials", storage_path);
        let mut app_creds_json: serde_json::Value =
            if let Ok(data) = std::fs::read_to_string(&app_creds_path) {
                serde_json::from_str(&data).unwrap_or_else(|_| {
                    serde_json::json!({
                        "version": 1,
                        "minor_version": 1,
                        "key": "application_credentials",
                        "data": { "items": [] }
                    })
                })
            } else {
                serde_json::json!({
                    "version": 1,
                    "minor_version": 1,
                    "key": "application_credentials",
                    "data": { "items": [] }
                })
            };

        if let Some(items_arr) = app_creds_json
            .get_mut("data")
            .and_then(|d| d.get_mut("items"))
            .and_then(|i| i.as_array_mut())
        {
            items_arr.retain(|it| it.get("domain").and_then(|d| d.as_str()) != Some("nest"));
            items_arr.push(serde_json::json!({
                "id": auth_impl_id,
                "domain": "nest",
                "name": "Google Nest SGX",
                "client_id": client_id,
                "client_secret": client_secret
            }));
            let _ = std::fs::write(
                &app_creds_path,
                serde_json::to_string_pretty(&app_creds_json).unwrap_or_default(),
            );
        }

        // 2. Update core.config_entries
        let entries_path = format!("{}/core.config_entries", storage_path);
        let mut entries_json: serde_json::Value =
            if let Ok(data) = std::fs::read_to_string(&entries_path) {
                serde_json::from_str(&data).ok()?
            } else {
                return None;
            };

        let entry_id = format!("01M09NESTENTRY{:010x}", chrono::Utc::now().timestamp());
        let entries = entries_json
            .get_mut("data")
            .and_then(|d| d.get_mut("entries"))
            .and_then(|e| e.as_array_mut())?;

        // Remove old nest entries if present
        entries.retain(|it| it.get("domain").and_then(|d| d.as_str()) != Some("nest"));

        let now_str = chrono::Utc::now().to_rfc3339();
        let expires_at_ts = chrono::Utc::now().timestamp() + 3600;

        let cloud_project_id =
            std::env::var("SGX_NEST_CLOUD_PROJECT_ID").unwrap_or_else(|_| "sgx-home".to_string());
        let subscriber_id = std::env::var("SGX_NEST_SUBSCRIBER_ID").unwrap_or_else(|_| {
            format!(
                "projects/{}/subscriptions/home-assistant-{}",
                cloud_project_id, project_id
            )
        });

        entries.push(serde_json::json!({
            "created_at": now_str,
            "modified_at": now_str,
            "domain": "nest",
            "entry_id": entry_id,
            "title": "Google Nest",
            "source": "user",
            "state": "loaded",
            "disabled_by": null,
            "discovery_keys": {},
            "subentries": [],
            "options": {},
            "minor_version": 1,
            "version": 1,
            "pref_disable_new_entities": false,
            "pref_disable_polling": false,
            "unique_id": null,
            "data": {
                "sdm": {},
                "project_id": project_id,
                "cloud_project_id": cloud_project_id,
                "subscriber_id": subscriber_id,
                "auth_implementation": auth_impl_id,
                "token": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    // Must match what was actually granted, including the Pub/Sub scope —
                    // HA replays this on refresh, and a narrower value fails with
                    // `invalid_scope`, silently killing device state updates.
                    "scope": crate::nest::NEST_OAUTH_SCOPES,
                    "token_type": "Bearer",
                    "expires_at": expires_at_ts
                }
            }
        }));

        if let Ok(json_str) = serde_json::to_string_pretty(&entries_json) {
            let _ = std::fs::write(&entries_path, json_str);
        }

        // 3. Make HA pick up the entry we just wrote.
        //
        // Home Assistant only loads config entries from `.storage` at startup — the entry_id
        // above was never created through HA's own config-flow manager, so it has no
        // in-memory representation. A `/reload` call against an entry HA doesn't know about
        // is a silent no-op (HA returns "Unknown entry", which the old code discarded),
        // which is exactly why devices did not appear until the container was restarted by
        // hand. Restarting is the only way to get HA to (re)read the file and instantiate it.
        //
        // The HTTP response to this call is not meaningful — HA closes the connection as
        // part of shutting down, so a transport error here is the expected outcome of a
        // successful restart request, not a failure.
        let restart_url = format!(
            "{}/api/services/homeassistant/restart",
            self.ha_url.trim_end_matches('/')
        );
        let _ = self
            .client
            .post(&restart_url)
            .timeout(Duration::from_secs(5))
            .header("Authorization", format!("Bearer {}", self.ha_token))
            .json(&serde_json::json!({}))
            .send()
            .await;

        Some(entry_id)
    }

    /// Waits for a specific config entry to finish loading after a restart.
    ///
    /// It is not enough to wait for HA's web server to respond: the HTTP API comes back
    /// (and returns a healthy 200/401) well before the Nest integration has finished calling
    /// the SDM API and registering its entities. Reconciling in that gap sees zero Nest
    /// entities and reads it as "these devices were deleted" — deleting them from the
    /// registry it was trying to populate. So this polls the entry's own `state` field
    /// instead, and only reports ready once HA says `"loaded"`.
    pub async fn wait_for_entry_loaded(&self, entry_id: &str, timeout: Duration) -> bool {
        #[derive(Deserialize)]
        struct EntrySummary {
            entry_id: String,
            #[serde(default)]
            state: Option<String>,
        }

        let deadline = tokio::time::Instant::now() + timeout;
        // HA needs a moment to actually go down first; an immediate poll can otherwise hit
        // the still-shutting-down process and see the *old* entry's "loaded" state.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let list_url = format!(
            "{}/api/config/config_entries/entry",
            self.ha_url.trim_end_matches('/')
        );
        while tokio::time::Instant::now() < deadline {
            let resp = self
                .client
                .get(&list_url)
                .timeout(Duration::from_secs(5))
                .header("Authorization", format!("Bearer {}", self.ha_token))
                .send()
                .await;

            let entries: Option<Vec<EntrySummary>> = match resp {
                Ok(r) if r.status().is_success() => r.json().await.ok(),
                _ => None, // HA still down / not accepting connections yet — keep polling
            };

            if let Some(entries) = entries {
                match entries
                    .iter()
                    .find(|e| e.entry_id == entry_id)
                    .and_then(|e| e.state.as_deref())
                {
                    Some("loaded") => return true,
                    Some(s @ ("setup_error" | "migration_error" | "failed_unload")) => {
                        tracing::warn!(
                            "Nest config entry {} reached terminal state '{}' after restart",
                            entry_id,
                            s
                        );
                        return false;
                    }
                    _ => {} // setup_in_progress, not found yet, etc. — keep polling
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        false
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
            .map_err(|e| {
                format!(
                    "Failed to send delete config entry request to HA for Nest: {}",
                    e
                )
            })?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Failed to remove HA Nest config entry '{}': {}",
                entry_id, err_text
            ));
        }

        info!(
            "🗑️ Successfully removed HA Nest config entry '{}'",
            entry_id
        );
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

    fn sample_creds() -> NestCredentials {
        NestCredentials::new(
            Some("client_id_x".to_string()),
            Some("client_secret_x".to_string()),
            Some("project_x".to_string()),
            Some("access_x".to_string()),
            Some("refresh_x".to_string()),
        )
    }

    /// Spawns a tiny loopback HTTP server that answers each accepted connection with the
    /// next queued (status, body) pair, in order. Purely local (127.0.0.1, ephemeral port) —
    /// no real network, no external process.
    async fn spawn_queue_server(responses: Vec<(u16, String)>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            for (status, body) in responses {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 8192];
                    let _ = socket.read(&mut buf).await;
                    let reason = match status {
                        200 => "OK",
                        400 => "Bad Request",
                        404 => "Not Found",
                        _ => "Error",
                    };
                    let response = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        reason,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                }
            }
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_inject_direct_storage_entry_none_without_storage_volume() {
        // Sandbox has none of the hardcoded HA storage directories mounted, so the direct
        // injection fast-path must decline and let the caller fall back to the config flow.
        let client =
            NestHaConfigFlowClient::new("http://127.0.0.1:1".to_string(), "tok".to_string());
        let result = client.inject_direct_storage_entry(&sample_creds()).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_success() {
        let base_url = spawn_queue_server(vec![
            (200, r#"{"flow_id":"flow_nest_ok"}"#.to_string()),
            (
                200,
                r#"{"result":{"entry_id":"nest_entry_ok_1"}}"#.to_string(),
            ),
        ])
        .await;

        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.setup_nest_config_entry(&sample_creds()).await;
        assert!(result.is_ok());
        let (entry_id, restarted) = result.unwrap();
        assert_eq!(entry_id, "nest_entry_ok_1");
        assert!(!restarted);
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_initiate_rejected() {
        let base_url =
            spawn_queue_server(vec![(400, r#"{"message":"unknown handler"}"#.to_string())]).await;

        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.setup_nest_config_entry(&sample_creds()).await;
        let err = result.unwrap_err();
        assert!(
            err.contains("HA config flow initiate failed for Nest"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_missing_project_id() {
        let base_url = spawn_queue_server(vec![(
            200,
            r#"{"flow_id":"flow_nest_missing_project"}"#.to_string(),
        )])
        .await;

        let mut creds = sample_creds();
        creds.project_id = None;
        std::env::remove_var("SGX_NEST_PROJECT_ID");

        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.setup_nest_config_entry(&creds).await;
        let err = result.unwrap_err();
        assert!(
            err.contains("project_id is required"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_missing_client_credentials() {
        let base_url = spawn_queue_server(vec![(
            200,
            r#"{"flow_id":"flow_nest_missing_client"}"#.to_string(),
        )])
        .await;

        let mut creds = sample_creds();
        creds.client_id = None;
        std::env::remove_var("SGX_NEST_CLIENT_ID");

        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.setup_nest_config_entry(&creds).await;
        let err = result.unwrap_err();
        assert!(
            err.contains("client_id is required"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_step_rejected() {
        let base_url = spawn_queue_server(vec![
            (200, r#"{"flow_id":"flow_nest_step_fail"}"#.to_string()),
            (400, r#"{"message":"invalid credentials"}"#.to_string()),
        ])
        .await;

        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.setup_nest_config_entry(&sample_creds()).await;
        let err = result.unwrap_err();
        assert!(
            err.contains("HA config flow submission failed for Nest"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_no_entry_id_in_response() {
        let base_url = spawn_queue_server(vec![
            (200, r#"{"flow_id":"flow_nest_no_entry"}"#.to_string()),
            (200, r#"{"type":"form"}"#.to_string()),
        ])
        .await;

        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.setup_nest_config_entry(&sample_creds()).await;
        let err = result.unwrap_err();
        assert!(
            err.contains("no entry_id was returned"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_unreachable_ha() {
        // Port 1 on loopback: nothing is listening, so the connection is refused immediately.
        // This is local-only (never leaves the loopback interface) and requires no privileges.
        let client =
            NestHaConfigFlowClient::new("http://127.0.0.1:1".to_string(), "tok".to_string());
        let result = client.setup_nest_config_entry(&sample_creds()).await;
        let err = result.unwrap_err();
        assert!(
            err.contains("Failed to send Nest config flow request to HA"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_remove_nest_config_entry_success() {
        let base_url = spawn_queue_server(vec![(200, "{}".to_string())]).await;
        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.remove_nest_config_entry("nest_entry_1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_remove_nest_config_entry_failure() {
        let base_url =
            spawn_queue_server(vec![(404, r#"{"message":"not found"}"#.to_string())]).await;
        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.remove_nest_config_entry("nest_entry_missing").await;
        let err = result.unwrap_err();
        assert!(
            err.contains("Failed to remove HA Nest config entry"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_remove_nest_config_entry_unreachable_ha() {
        let client =
            NestHaConfigFlowClient::new("http://127.0.0.1:1".to_string(), "tok".to_string());
        let result = client.remove_nest_config_entry("nest_entry_1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_missing_client_secret() {
        let base_url = spawn_queue_server(vec![(
            200,
            r#"{"flow_id":"flow_nest_missing_secret"}"#.to_string(),
        )])
        .await;

        let mut creds = sample_creds();
        creds.client_secret = None;
        std::env::remove_var("SGX_NEST_CLIENT_SECRET");

        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.setup_nest_config_entry(&creds).await;
        let err = result.unwrap_err();
        assert!(
            err.contains("client_secret is required"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_setup_nest_config_entry_top_level_entry_id() {
        let base_url = spawn_queue_server(vec![
            (200, r#"{"flow_id":"flow_nest_top_level"}"#.to_string()),
            (200, r#"{"entry_id":"nest_entry_top_level"}"#.to_string()),
        ])
        .await;

        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let result = client.setup_nest_config_entry(&sample_creds()).await;
        let (entry_id, restarted) = result.expect("setup should succeed");
        assert_eq!(entry_id, "nest_entry_top_level");
        assert!(!restarted);
    }

    #[tokio::test]
    async fn test_wait_for_entry_loaded_returns_true_once_ha_reports_loaded() {
        let base_url = spawn_queue_server(vec![(
            200,
            r#"[{"entry_id":"nest_entry_1","state":"loaded"}]"#.to_string(),
        )])
        .await;
        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let ready = client
            .wait_for_entry_loaded("nest_entry_1", Duration::from_secs(10))
            .await;
        assert!(ready);
    }

    #[tokio::test]
    async fn test_wait_for_entry_loaded_returns_false_on_terminal_error_state() {
        let base_url = spawn_queue_server(vec![(
            200,
            r#"[{"entry_id":"nest_entry_1","state":"setup_error"}]"#.to_string(),
        )])
        .await;
        let client = NestHaConfigFlowClient::new(base_url, "tok".to_string());
        let ready = client
            .wait_for_entry_loaded("nest_entry_1", Duration::from_secs(10))
            .await;
        assert!(!ready);
    }

    #[tokio::test]
    async fn test_wait_for_entry_loaded_times_out_when_ha_never_responds() {
        // Port 1 on loopback: nothing listens there, so every poll fails immediately and the
        // deadline (shorter than the mandatory initial 3s settle sleep) is already passed by
        // the time the loop would run, so this returns false without a real hang.
        let client =
            NestHaConfigFlowClient::new("http://127.0.0.1:1".to_string(), "tok".to_string());
        let ready = client
            .wait_for_entry_loaded("nest_entry_1", Duration::from_millis(100))
            .await;
        assert!(!ready);
    }
}
