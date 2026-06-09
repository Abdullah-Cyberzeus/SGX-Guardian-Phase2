use crate::did::doc_distribution;
use crate::nebula::registry_sync::RegistryRequest;
use crate::vc::errors::VcError;
use crate::vc::persistence;
use crate::vc::status_list::StatusListCredential;
use std::time::Duration;

pub async fn pull_status_list(ca_host: &str) -> Result<bool, VcError> {
    let request = RegistryRequest {
        action: "status_list_snapshot".to_string(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        doc_distribution::send_request(ca_host, &request),
    )
    .await
    .map_err(|_| VcError::StatusListUnavailable("CA timeout".to_string()))??;

    let body = response.status_list_body.ok_or_else(|| {
        VcError::StatusListUnavailable("CA did not return a status list".to_string())
    })?;
    let _: StatusListCredential = serde_json::from_str(&body)?;
    persistence::save_status_list_raw(&body)?;
    Ok(true)
}
