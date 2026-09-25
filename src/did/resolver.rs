//! DID resolution service for peer document discovery.

use crate::did::doc_distribution;
use crate::did::doc_persistence;
use crate::did::doc_sign;
use crate::did::document::{DidDocument, Jwk};
use crate::did::resolver_cache::{CacheEntry, ResolverCache};
use crate::did::{Did, DidError};
use crate::nebula::registry_sync::{RegistryRequest, REGISTRY_SYNC_PORT};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionSource {
    MemCache,
    LocalPeerDoc,
    LocalAggregate,
    CaNetwork,
}

impl ResolutionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MemCache => "mem_cache",
            Self::LocalPeerDoc => "local_peer_doc",
            Self::LocalAggregate => "local_aggregate",
            Self::CaNetwork => "ca_network",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    pub r#type: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionResult {
    pub did: String,
    pub public_key_der_b64: String,
    pub services: Vec<ServiceEndpoint>,
    pub source: ResolutionSource,
    pub fetched_at: String,
    pub ttl_remaining_sec: i64,
    pub status: String,
    pub version_id: u32,
    pub dkp_version: u32,
}

#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub ttl: Duration,
    pub ca_host: String,
    pub network_timeout: Duration,
    pub reject_deactivated: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_TTL,
            ca_host: String::new(),
            network_timeout: NETWORK_TIMEOUT,
            reject_deactivated: false,
        }
    }
}

/// The `cfg` behind a shared lock, not an owned value (P1.4).
///
/// Before Phase 1 this was a plain `ResolverConfig`, set once at construction
/// and never touched again — fine while `main()` ran enrollment to completion
/// before building `AppState`. Splitting boot into a local stage and a mesh
/// activation stage means `AppState`'s resolver is constructed *before* the
/// CA host is known, and `mesh::activation` must be able to fill it in once
/// enrollment discovers or is assigned one. `Arc<RwLock<_>>` makes every clone
/// of a `Resolver` see [`Resolver::set_ca_host`] immediately, which a plain
/// `#[derive(Clone)]` over an owned `cfg` could not.
#[derive(Clone)]
pub struct Resolver {
    cfg: Arc<RwLock<ResolverConfig>>,
    cache: Arc<Mutex<ResolverCache>>,
}

impl Resolver {
    pub fn new(cfg: ResolverConfig) -> Self {
        Self {
            cfg: Arc::new(RwLock::new(cfg)),
            cache: Arc::new(Mutex::new(ResolverCache::new())),
        }
    }

    /// A clone that shares this resolver's cache but has its own,
    /// independently-mutable config — used where a caller wants a temporarily
    /// different `reject_deactivated` without affecting every other holder of
    /// the original `Resolver` (unlike [`Resolver::set_ca_host`], which is
    /// deliberately shared).
    pub fn with_reject_deactivated(&self, reject_deactivated: bool) -> Self {
        let mut cfg = self.cfg.read().expect("resolver config lock poisoned").clone();
        cfg.reject_deactivated = reject_deactivated;
        Self {
            cfg: Arc::new(RwLock::new(cfg)),
            cache: self.cache.clone(),
        }
    }

    /// Sets the CA host every clone of this `Resolver` resolves against, from
    /// this point on. Called once by `mesh::activation` after enrollment
    /// determines (or is assigned) the circle's CA address — before that call,
    /// a `Resolver` built during `boot_local()` simply has no CA network
    /// fallback and resolves from cache/local documents only, which is the
    /// correct behaviour for an unenrolled Guardian.
    pub fn set_ca_host(&self, ca_host: impl Into<String>) {
        self.cfg.write().expect("resolver config lock poisoned").ca_host = ca_host.into();
    }

    /// The CA host currently in effect, for callers (like the lifecycle API)
    /// that want to report it without triggering a resolution.
    pub fn ca_host(&self) -> String {
        self.cfg.read().expect("resolver config lock poisoned").ca_host.clone()
    }

    pub async fn resolve(&self, did_str: &str) -> Result<ResolutionResult, DidError> {
        let did = Did::parse(did_str)?;

        let ttl = self.cfg.read().expect("resolver config lock poisoned").ttl;
        if let Some(entry) = self.cache.lock().await.get_fresh(&did, ttl) {
            return self.finish(entry.doc, ResolutionSource::MemCache, entry.fetched_at);
        }

        if let Some(doc) = doc_persistence::load_peer(&did)? {
            let fetched_at = SystemTime::now();
            let result = self.finish(doc.clone(), ResolutionSource::LocalPeerDoc, fetched_at)?;
            self.put_cache(&did, &doc, ResolutionSource::LocalPeerDoc, fetched_at)
                .await;
            return Ok(result);
        }

        let docs = doc_persistence::load_ca_aggregate()?;
        if let Some(doc) = docs.into_iter().find(|doc| doc.id == did.as_str()) {
            let fetched_at = SystemTime::now();
            let result = self.finish(doc.clone(), ResolutionSource::LocalAggregate, fetched_at)?;
            self.put_cache(&did, &doc, ResolutionSource::LocalAggregate, fetched_at)
                .await;
            return Ok(result);
        }

        let ca_host_for_network = self.cfg.read().expect("resolver config lock poisoned").ca_host.clone();
        if !ca_host_for_network.is_empty() {
            if let Some(doc) = self.fetch_from_ca_network(&did).await? {
                let fetched_at = SystemTime::now();
                let result = self.finish(doc.clone(), ResolutionSource::CaNetwork, fetched_at)?;
                self.put_cache(&did, &doc, ResolutionSource::CaNetwork, fetched_at)
                    .await;
                return Ok(result);
            }
        }

        Err(DidError::Unresolvable(did_str.to_string()))
    }

    pub async fn invalidate(&self, did_str: &str) {
        if let Ok(did) = Did::parse(did_str) {
            self.cache.lock().await.invalidate(&did);
        }
    }

    pub async fn invalidate_all(&self) {
        self.cache.lock().await.clear();
    }

    async fn put_cache(
        &self,
        did: &Did,
        doc: &DidDocument,
        source: ResolutionSource,
        fetched_at: SystemTime,
    ) {
        let entry = CacheEntry {
            doc: doc.clone(),
            fetched_at,
            source,
        };
        self.cache.lock().await.put(did.clone(), entry);
    }

    fn finish(
        &self,
        doc: DidDocument,
        source: ResolutionSource,
        fetched_at: SystemTime,
    ) -> Result<ResolutionResult, DidError> {
        match source {
            ResolutionSource::MemCache => doc_sign::verify(&doc)?,
            ResolutionSource::LocalPeerDoc
            | ResolutionSource::LocalAggregate
            | ResolutionSource::CaNetwork => {
                let floor = known_floor_version(&doc)?;
                doc_sign::verify_with_replay_protection(&doc, floor)?;
            }
        }

        let status = doc
            .sgx_status
            .clone()
            .unwrap_or_else(|| "active".to_string());
        let reject_deactivated =
            self.cfg.read().expect("resolver config lock poisoned").reject_deactivated;
        if reject_deactivated && status == "deactivated" {
            return Err(DidError::Deactivated(doc.sgx_updated.clone()));
        }

        let active_vm = doc
            .verification_method
            .first()
            .ok_or_else(|| DidError::InvalidFormat("no verificationMethod".to_string()))?;
        let public_key_der_b64 = jwk_to_sec1_der_b64(&active_vm.public_key_jwk)?;
        let services = doc
            .service
            .iter()
            .map(|service| ServiceEndpoint {
                id: service.id.clone(),
                r#type: service.svc_type.clone(),
                endpoint: service.service_endpoint.clone(),
            })
            .collect();

        let fetched_at_dt: DateTime<Utc> = fetched_at.into();
        let age = SystemTime::now()
            .duration_since(fetched_at)
            .unwrap_or(Duration::from_secs(0));
        let ttl = self.cfg.read().expect("resolver config lock poisoned").ttl;
        let ttl_remaining = ttl.checked_sub(age).unwrap_or(Duration::from_secs(0));

        Ok(ResolutionResult {
            did: doc.id.clone(),
            public_key_der_b64,
            services,
            source,
            fetched_at: fetched_at_dt.to_rfc3339(),
            ttl_remaining_sec: ttl_remaining.as_secs() as i64,
            status,
            version_id: doc.sgx_version_id,
            dkp_version: active_vm
                .public_key_jwk
                .kid
                .strip_prefix("dkp-v")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        })
    }

    async fn fetch_from_ca_network(&self, did: &Did) -> Result<Option<DidDocument>, DidError> {
        let request = RegistryRequest {
            action: "resolve_did".to_string(),
            node_name: String::new(),
            pubkey_prefix: None,
            did_doc_json: None,
            did_query: Some(did.as_str().to_string()),
            status_list_body: None,
        };

        let (network_timeout, ca_host) = {
            let cfg = self.cfg.read().expect("resolver config lock poisoned");
            (cfg.network_timeout, cfg.ca_host.clone())
        };
        let response = tokio::time::timeout(
            network_timeout,
            doc_distribution::send_request(&ca_host, &request),
        )
        .await
        .map_err(|_| ca_registry_unavailable_error(&ca_host))?;
        let response = response.map_err(|err| match err {
            DidError::Io(_) => ca_registry_unavailable_error(&ca_host),
            other => other,
        })?;

        if !response.success {
            return Ok(None);
        }

        let Some(body) = response.did_doc_json else {
            return Ok(None);
        };

        let doc: DidDocument = serde_json::from_str(&body)?;
        Ok(Some(doc))
    }
}

fn ca_registry_unavailable_error(ca_host: &str) -> DidError {
    DidError::ResolutionFailed(format!(
        "CA registry unavailable at {}:{}.",
        ca_host, REGISTRY_SYNC_PORT
    ))
}

fn known_floor_version(doc: &DidDocument) -> Result<u32, DidError> {
    if let Some(self_doc) = doc_persistence::load_self()? {
        if self_doc.id == doc.id {
            return Ok(doc_persistence::read_self_floor_version());
        }
    }

    Ok(doc_persistence::load_peer(&doc.did()?)?
        .map(|existing| existing.sgx_version_id)
        .unwrap_or(0))
}

fn jwk_to_sec1_der_b64(jwk: &Jwk) -> Result<String, DidError> {
    let x = general_purpose::URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|e| DidError::InvalidFormat(format!("jwk.x decode: {}", e)))?;
    let y = general_purpose::URL_SAFE_NO_PAD
        .decode(&jwk.y)
        .map_err(|e| DidError::InvalidFormat(format!("jwk.y decode: {}", e)))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(DidError::InvalidFormat(
            "P-256 jwk x|y not 32 bytes".to_string(),
        ));
    }

    let mut der = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200")
        .map_err(|e| DidError::InvalidFormat(format!("der prefix decode: {}", e)))?;
    der.push(0x04);
    der.extend_from_slice(&x);
    der.extend_from_slice(&y);
    Ok(general_purpose::STANDARD.encode(der))
}
