use super::dkp::{run_cli, ActionResponse};
use crate::api::{error::ApiError, state::AppState};
use axum::{
    extract::{Multipart, State},
    Json,
};
use std::sync::Arc;

/// POST /api/v1/policy/sign
/// multipart fields: `policy` (the YAML file), `key` (the private key PKCS8)
pub async fn sign(
    State(_): State<Arc<AppState>>,
    mut mp: Multipart,
) -> Result<Json<ActionResponse>, ApiError> {
    let tmpdir = tempdir()?;
    let (mut policy_path, mut key_path) = (None, None);
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        let bytes = field
            .bytes()
            .await
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
        match name.as_str() {
            "policy" => {
                let p = tmpdir.path().join("policy.yaml");
                tokio::fs::write(&p, &bytes).await?;
                policy_path = Some(p);
            }
            "key" => {
                let p = tmpdir.path().join("key.pkcs8");
                tokio::fs::write(&p, &bytes).await?;
                key_path = Some(p);
            }
            _ => {}
        }
    }
    let policy = policy_path.ok_or_else(|| ApiError::BadRequest("missing policy field".into()))?;
    let _ = key_path.take();
    Ok(Json(
        run_cli(&["sign", policy.to_str().unwrap_or("")]).await?,
    ))
}

/// POST /api/v1/policy/verify
/// multipart: `policy` (the .sig file)
pub async fn verify(
    State(_): State<Arc<AppState>>,
    mut mp: Multipart,
) -> Result<Json<ActionResponse>, ApiError> {
    let tmpdir = tempdir()?;
    let mut sig_path = None;
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?
    {
        if field.name() == Some("policy") {
            let bytes = field
                .bytes()
                .await
                .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            let p = tmpdir.path().join("policy.sig");
            tokio::fs::write(&p, &bytes).await?;
            sig_path = Some(p);
        }
    }
    let sig = sig_path.ok_or_else(|| ApiError::BadRequest("missing policy field".into()))?;
    Ok(Json(
        run_cli(&["verify", "--signed", sig.to_str().unwrap_or("")]).await?,
    ))
}

fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir()
}
