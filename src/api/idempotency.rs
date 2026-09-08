//! Generic server-side dedup for client-retried mutations.
//!
//! A client that times out waiting for a response cannot tell whether its
//! request actually landed, so it retries with the same payload. For most
//! mutations that's harmless (setting a status twice is a no-op), but for
//! ones with a real side effect — issuing a credential, starting a transfer,
//! rotating a key — a naive retry duplicates that side effect. Handlers that
//! matter opt in by reading an `Idempotency-Key` header the client attaches
//! to every non-GET request (see `frontend/src/api/http.ts`) and wrapping
//! their mutation with `lookup`/`store` below, replaying the first response
//! instead of repeating the effect.
//!
//! Cache is process-local and unbounded by design, matching the existing
//! `vault.rs` idempotency cache it's modeled on: keys are one-shot
//! client-generated UUIDs, not something an attacker can usefully exhaust
//! from outside an already-authenticated session.

use axum::http::HeaderMap;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

type CacheEntries = HashMap<(String, String), Vec<u8>>;

static CACHE: OnceLock<Mutex<CacheEntries>> = OnceLock::new();

fn cache() -> &'static Mutex<CacheEntries> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The client-supplied `Idempotency-Key` header value, if present and
/// non-empty.
pub fn header_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// A previously cached response for `scope` + `key`, if this exact mutation
/// was already handled once. `scope` namespaces the cache per endpoint so
/// two different handlers never collide on the same client-generated key.
pub fn lookup<T: serde::de::DeserializeOwned>(scope: &str, key: &str) -> Option<T> {
    let bytes = cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&(scope.to_string(), key.to_string()))
        .cloned()?;
    serde_json::from_slice(&bytes).ok()
}

/// Records the response produced for `scope` + `key` so a retry can replay
/// it instead of re-running the mutation.
pub fn store<T: serde::Serialize>(scope: &str, key: &str, value: &T) {
    if let Ok(bytes) = serde_json::to_vec(value) {
        cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert((scope.to_string(), key.to_string()), bytes);
    }
}
