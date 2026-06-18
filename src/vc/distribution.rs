use crate::did::doc_distribution;
use crate::did::resolver::{DEFAULT_TTL, NETWORK_TIMEOUT};
use crate::did::{Resolver, ResolverConfig};
use crate::nebula::registry_sync::RegistryRequest;
use crate::vc::errors::VcError;
use crate::vc::persistence;
use crate::vc::status_list;
use crate::vc::status_list::StatusListCredential;
use std::time::Duration;

pub async fn pull_status_list(ca_host: &str) -> Result<bool, VcError> {
    let resolver = Resolver::new(ResolverConfig {
        ttl: DEFAULT_TTL,
        ca_host: ca_host.to_string(),
        network_timeout: NETWORK_TIMEOUT,
        reject_deactivated: false,
    });
    let expected_issuer = crate::vc::issue::known_ca_did().ok();
    pull_status_list_verified(&resolver, ca_host, expected_issuer.as_deref()).await?;
    Ok(true)
}

pub async fn pull_status_list_verified(
    resolver: &Resolver,
    ca_host: &str,
    expected_issuer_did: Option<&str>,
) -> Result<StatusListCredential, VcError> {
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
    let credential: StatusListCredential = serde_json::from_str(&body)?;
    status_list::verify_status_list_credential(&credential, resolver, expected_issuer_did).await?;
    persistence::save_status_list_raw(&body)?;
    Ok(credential)
}
