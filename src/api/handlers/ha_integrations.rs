use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::state::AppState;
use crate::integration::provider::{OAuthCredentials, VendorProvider};

#[derive(Deserialize)]
pub struct ConnectPayload {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in_secs: Option<i64>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
}

#[derive(Deserialize)]
pub struct KasaConnectPayload {
    pub mode: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct NestConnectPayload {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub project_id: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct IntegrationStatusResponse {
    pub status: String,
    pub message: String,
}

/// GET /api/integrations
pub async fn list_integrations(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let manager = match state.get_integration_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "IntegrationManager not initialized" })),
            ))
        }
    };

    let summary = manager.get_status_summary().await;
    Ok((StatusCode::OK, Json(summary)))
}

/// GET /api/integrations/{provider}/status
pub async fn get_integration_status(
    State(state): State<Arc<AppState>>,
    Path(provider_str): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let manager = match state.get_integration_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "IntegrationManager not initialized" })),
            ))
        }
    };

    let provider = VendorProvider::from_str(&provider_str).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Unknown vendor provider '{}'", provider_str) })),
        )
    })?;

    let meta = manager.get_integration(provider).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Provider not found" })),
        )
    })?;

    let mode = meta.kasa_credentials.as_ref().map(|k| k.mode.clone());

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "provider": meta.provider.as_str(),
            "name": meta.name,
            "status": meta.status.as_str(),
            "mode": mode,
            "device_count": meta.device_count,
            "last_synced": meta.last_synced,
            "error_message": meta.error_message,
            "has_credentials": meta.credentials.is_some() || meta.kasa_credentials.is_some() || meta.nest_credentials.is_some(),
        })),
    ))
}

fn get_ha_flow_client() -> Option<crate::kasa::KasaHaConfigFlowClient> {
    let url = std::env::var("HA_URL").ok()?;
    let token = std::env::var("HA_TOKEN").ok()?;
    Some(crate::kasa::KasaHaConfigFlowClient::new(url, token))
}

fn get_nest_ha_flow_client() -> Option<crate::nest::NestHaConfigFlowClient> {
    let url = std::env::var("HA_URL").ok()?;
    let token = std::env::var("HA_TOKEN").ok()?;
    Some(crate::nest::NestHaConfigFlowClient::new(url, token))
}

/// POST /api/integrations/{provider}/connect
pub async fn connect_integration(
    State(state): State<Arc<AppState>>,
    Path(provider_str): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let manager = match state.get_integration_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "IntegrationManager not initialized" })),
            ))
        }
    };

    let provider = VendorProvider::from_str(&provider_str).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Unknown vendor provider '{}'", provider_str) })),
        )
    })?;

    if provider == VendorProvider::TpLinkKasa {
        let kasa_payload: KasaConnectPayload = serde_json::from_value(body).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Invalid Kasa connect payload: {}", e) })),
            )
        })?;

        let creds = crate::kasa::KasaCredentials::new(
            kasa_payload.mode,
            kasa_payload.username,
            kasa_payload.password,
        );

        creds.validate().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            )
        })?;

        let mode = creds.mode.clone();
        let flow_client = get_ha_flow_client();
        let device_manager = state.get_device_manager().await;

        let discovered_count = manager
            .connect_kasa(creds, flow_client.as_ref(), device_manager.as_ref())
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))))?;

        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "connected",
                "provider": provider.as_str(),
                "mode": mode,
                "message": format!("Successfully connected integration for {}", provider.display_name()),
                "devices_discovered": discovered_count
            })),
        ));
    }

    if provider == VendorProvider::GoogleNest {
        let nest_payload: NestConnectPayload = serde_json::from_value(body).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Invalid Nest connect payload: {}", e) })),
            )
        })?;

        let creds = crate::nest::NestCredentials::new(
            nest_payload
                .client_id
                .or_else(|| std::env::var("SGX_NEST_CLIENT_ID").ok()),
            nest_payload
                .client_secret
                .or_else(|| std::env::var("SGX_NEST_CLIENT_SECRET").ok()),
            nest_payload
                .project_id
                .or_else(|| std::env::var("SGX_NEST_PROJECT_ID").ok()),
            nest_payload.access_token,
            nest_payload.refresh_token,
        );

        creds.validate().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            )
        })?;

        let flow_client = get_nest_ha_flow_client();
        let device_manager = state.get_device_manager().await;

        let (discovered_count, ha_restarting) = manager
            .connect_nest(creds, flow_client.as_ref(), device_manager.as_ref())
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))))?;

        let message = if ha_restarting {
            format!(
                "Connected {} — Home Assistant is restarting to load your devices. They'll appear automatically within about a minute.",
                provider.display_name()
            )
        } else {
            format!("Successfully connected integration for {}", provider.display_name())
        };

        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "connected",
                "provider": provider.as_str(),
                "message": message,
                "devices_discovered": discovered_count,
                "ha_restarting": ha_restarting
            })),
        ));
    }

    let payload: ConnectPayload = serde_json::from_value(body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Invalid OAuth payload: {}", e) })),
        )
    })?;

    let expires_at = payload.expires_in_secs.map(|s| chrono::Utc::now() + chrono::Duration::seconds(s));

    let creds = OAuthCredentials {
        access_token: payload.access_token,
        refresh_token: payload.refresh_token,
        expires_at,
        token_type: payload.token_type.unwrap_or_else(|| "Bearer".to_string()),
        scope: payload.scope,
    };

    manager
        .connect_integration(provider, creds)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "connected",
            "provider": provider.as_str(),
            "message": format!("Successfully connected integration for {}", provider.display_name())
        })),
    ))
}

/// POST /api/integrations/{provider}/disconnect
pub async fn disconnect_integration(
    State(state): State<Arc<AppState>>,
    Path(provider_str): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let manager = match state.get_integration_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "IntegrationManager not initialized" })),
            ))
        }
    };

    let provider = VendorProvider::from_str(&provider_str).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Unknown vendor provider '{}'", provider_str) })),
        )
    })?;

    let flow_client = get_ha_flow_client();
    let nest_flow_client = get_nest_ha_flow_client();
    let device_manager = state.get_device_manager().await;

    let devices_removed = manager
        .disconnect_integration(provider, flow_client.as_ref(), nest_flow_client.as_ref(), device_manager.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "disconnected",
            "provider": provider.as_str(),
            "message": format!("Successfully disconnected integration for {}", provider.display_name()),
            "devices_removed": devices_removed
        })),
    ))
}

/// GET /api/v1/ha/integrations/google_nest/oauth/auth_url
pub async fn get_nest_oauth_url() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let client_id = std::env::var("SGX_NEST_CLIENT_ID").ok();
    let project_id = std::env::var("SGX_NEST_PROJECT_ID").ok();

    let redirect_uri = std::env::var("SGX_NEST_REDIRECT_URI")
        .unwrap_or_else(|_| "https://localhost:8443/api/v1/ha/integrations/google_nest/oauth/callback".to_string());

    let is_configured = client_id.is_some() && project_id.is_some();

    let cid = client_id
        .as_deref()
        .unwrap_or("826937801762-i23ak49q222h42sffqmgvemb9pnl5jvr.apps.googleusercontent.com");
    let pid = project_id
        .as_deref()
        .unwrap_or("be666f67-3423-4a5d-b82d-38ec2865e1fa");

    // Both SDM and Pub/Sub scopes are required — see `nest::NEST_OAUTH_SCOPES`. The space
    // separator must be percent-encoded for the authorization URL.
    let scope = crate::nest::NEST_OAUTH_SCOPES.replace(' ', "%20");

    let auth_url = format!(
        "https://nestservices.google.com/partnerconnections/{}/auth?redirect_uri={}&response_type=code&client_id={}&scope={}&access_type=offline&prompt=consent",
        pid, redirect_uri, cid, scope
    );

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "auth_url": auth_url,
            "configured": is_configured,
            "redirect_uri": redirect_uri
        })),
    ))
}

#[derive(Deserialize)]
pub struct NestOAuthCallbackQuery {
    pub code: Option<String>,
    pub error: Option<String>,
}

/// GET /api/v1/ha/integrations/google_nest/oauth/callback
pub async fn nest_oauth_callback(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<NestOAuthCallbackQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if let Some(err) = query.error {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Google OAuth access denied: {}", err)
            })),
        ));
    }

    let code = query.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing required 'code' parameter in OAuth callback" })),
        )
    })?;

    let client_id = std::env::var("SGX_NEST_CLIENT_ID")
        .unwrap_or_else(|_| "826937801762-i23ak49q222h42sffqmgvemb9pnl5jvr.apps.googleusercontent.com".to_string());

    let client_secret = std::env::var("SGX_NEST_CLIENT_SECRET")
        .unwrap_or_default();

    let project_id = std::env::var("SGX_NEST_PROJECT_ID")
        .ok()
        .or_else(|| Some("be666f67-3423-4a5d-b82d-38ec2865e1fa".to_string()));

    let redirect_uri = std::env::var("SGX_NEST_REDIRECT_URI")
        .unwrap_or_else(|_| "https://localhost:8443/api/v1/ha/integrations/google_nest/oauth/callback".to_string());

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))))?;

    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code", code.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri.as_str()),
    ];

    let resp = http_client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": format!("Google token exchange HTTP request failed: {}", e) }))))?;

    if !resp.status().is_success() {
        let err_body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Google OAuth token exchange failed: {}", err_body) })),
        ));
    }

    let token_resp: crate::nest::GoogleOAuthTokenResponse = resp
        .json()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Failed to parse Google OAuth token response: {}", e) }))))?;

    let creds = crate::nest::NestCredentials::new(
        Some(client_id),
        Some(client_secret),
        project_id,
        Some(token_resp.access_token),
        token_resp.refresh_token,
    );

    let manager = state.get_integration_manager().await.ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "IntegrationManager not initialized" })),
        )
    })?;

    let flow_client = get_nest_ha_flow_client();
    let device_manager = state.get_device_manager().await;

    let (discovered_count, ha_restarting) = manager
        .connect_nest(creds, flow_client.as_ref(), device_manager.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))))?;

    let body_text = if ha_restarting {
        "Home Assistant is restarting to load your Nest device(s). This takes under a minute — \
         you can close this window now, and they'll appear automatically in SG-X Guardian."
            .to_string()
    } else {
        format!("Discovered {} device(s). You may now close this window.", discovered_count)
    };

    let html_content = format!(
        "<!DOCTYPE html><html><head><title>SG-X Guardian</title><style>body{{font-family:sans-serif;text-align:center;padding:50px;background:#121212;color:#fff;}}h1{{color:#4caf50;}}</style></head><body><h1>🎉 Google Nest Connected Successfully!</h1><p>{}</p></body></html>",
        body_text
    );

    Ok((StatusCode::OK, axum::response::Html(html_content)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_payload_parsing() {
        let json_data = r#"{
            "access_token": "token_abc123",
            "refresh_token": "refresh_xyz789",
            "expires_in_secs": 3600,
            "token_type": "Bearer",
            "scope": "nest.thermostat"
        }"#;

        let parsed: ConnectPayload = serde_json::from_str(json_data).unwrap();
        assert_eq!(parsed.access_token, "token_abc123");
        assert_eq!(parsed.refresh_token, Some("refresh_xyz789".to_string()));
        assert_eq!(parsed.expires_in_secs, Some(3600));
        assert_eq!(parsed.token_type, Some("Bearer".to_string()));
    }

    #[test]
    fn test_kasa_connect_payload_parsing_and_validation() {
        let cloud_json = r#"{
            "mode": "cloud",
            "username": "user@kasa.com",
            "password": "secret_kasa_password"
        }"#;

        let parsed: KasaConnectPayload = serde_json::from_str(cloud_json).unwrap();
        let creds = crate::kasa::KasaCredentials::new(parsed.mode, parsed.username, parsed.password);
        assert!(creds.validate().is_ok());
        assert_eq!(creds.mode, "cloud");

        let missing_pass_json = r#"{
            "mode": "cloud",
            "username": "user@kasa.com"
        }"#;
        let parsed_invalid: KasaConnectPayload = serde_json::from_str(missing_pass_json).unwrap();
        let creds_invalid = crate::kasa::KasaCredentials::new(parsed_invalid.mode, parsed_invalid.username, parsed_invalid.password);
        assert!(creds_invalid.validate().is_err());

        let local_json = r#"{ "mode": "local" }"#;
        let parsed_local: KasaConnectPayload = serde_json::from_str(local_json).unwrap();
        let creds_local = crate::kasa::KasaCredentials::new(parsed_local.mode, parsed_local.username, parsed_local.password);
        assert!(creds_local.validate().is_ok());
        assert_eq!(creds_local.mode, "local");
    }
}
