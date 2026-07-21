
# SG-X Guardian — Phase D — HTTPS/TLS Termination + Cylenium SSO Seam — Development Plan

**Objective:** Terminate TLS on the admin API (`:8443`), stop serving plaintext HTTP there, keep the API on NodeA only, and add a pluggable auth-provider seam (local login kept working, Cylenium SSO stubbed + disabled).
**Branch context:** anchored to the currently-synced snapshot, which already contains your implemented and tested **Phase A/B/C** (`pub mod auth`, `/auth/*` + `/devices/*` routes, `require_auth`, `session::issue`, `password::hash_password`, extended `AppState`).

---

## 0. Why your precheck is failing (read this first)

Your three symptoms all have one cause — **the server is speaking plaintext HTTP on `:8443`**:

- `https://127.0.0.1:8443/api/v1/health` → OpenSSL `wrong version number`: the client sends a TLS ClientHello, the server answers with a plain-HTTP response, and OpenSSL can't parse that as a TLS record.
- `openssl s_client -connect 127.0.0.1:8443` → `no peer certificate available`: there's no TLS layer, so no certificate is ever presented.
- Confirmed in source — `src/api/mod.rs::serve()` binds a plain `tokio::net::TcpListener` and calls `axum::serve(...)` (no TLS), logging `listening on http://{}`.

Phase D terminates TLS on that same port. Afterward `s_client` shows the NodeA device cert, `https` health returns `200`, and a plaintext `http` request to `:8443` is rejected at the TLS handshake — which is exactly the "stop serving HTTP on `:8443`" behavior (same port, now TLS-only; there is no separate HTTP port to disable).

---

## 1. Key finding — DER is enough, no PEM conversion needed (resolves requirement #4)

The project's TLS stack is **rustls 0.23** (`Cargo.toml`: `rustls = { version = "0.23.38", default-features=false, features=["ring","std","tls12"] }`), and rustls consumes **DER directly**:

- cert: `CertificateDer::from(std::fs::read("device_nodeA_cert.der")?)`
- key: your `device_nodeA.key` is **PKCS#8 DER** (written by `key_manager.rs` as `pkcs8.as_ref()`, and read raw in `main.rs` before PEM-wrapping for tonic) → `PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read("device_nodeA.key")?))`

So the admin HTTPS path loads the **existing DER cert + DER key as-is**. The `der_to_pem()` helper in `src/tls.rs` exists (tonic needed PEM), but the admin API does **not** need it. This is why PEM files aren't present and don't need to be created.

> The device cert is an ECDSA P-256 self-signed rcgen cert (SAN includes `127.0.0.1` + hostname). rustls+ring supports P-256 server auth, so it works directly. It will read as self-signed/untrusted (expected) — `s_client` still shows a presented peer cert, which satisfies the goal. CA-trust or shipping the cert to clients is a later hardening step.

---

## 2. Approach & crate choice

Serve axum 0.7 over rustls via **`axum-server`** (stable, integrates with the axum `Router` + `ConnectInfo` we already use). Add:

```toml
axum-server = { version = "0.7", default-features = false, features = ["tls-rustls-no-provider"] }
```

**Provider nuance (important):** the project already installs the **ring** rustls crypto provider (`server.rs::ensure_rustls_crypto_provider()` → `rustls::crypto::ring::default_provider().install_default()`), and rustls is built `default-features=false, features=["ring"]`. Use `tls-rustls-no-provider` so `axum-server` does **not** pull a second backend (aws-lc-rs). Build the `ServerConfig` ourselves (it uses the installed ring provider) and hand it to `RustlsConfig::from_config(Arc<ServerConfig>)`. Confirm the exact `no-provider` feature name against the axum-server 0.7.x you resolve.

*Fallback if you'd rather not add axum-server:* add `tokio-rustls` (wraps the existing rustls/ring) and hand-roll the accept loop with `hyper-util`. More code; axum-server is the cleaner path.

---

## 3. Deliverables (mapped to your 13 requirements)

| # | Your requirement | Change |
|---|---|---|
| 1 | HTTPS/TLS on `:8443` | `axum_server::bind_rustls` in `serve()` (§7) |
| 2 | Stop plaintext HTTP on `:8443` | TLS-only listener rejects plaintext at handshake (§7); no HTTP fallback |
| 3 | Load NodeA device cert | read `device_nodeA_cert.der` (§1, §6) |
| 4 | DER→PEM if needed | **not needed** with rustls — load DER directly (§1) |
| 5 | Load key securely + validate perms | `validate_key_permissions()` (0600) before load (§6) |
| 6 | `api.tls.{enabled,cert_path,key_path,require_https}` | `NodeConfig.api.tls` (§5) |
| 7 | Admin API on NodeA only | gate spawn `if node_id == "nodeA"` (§6) |
| 8 | NodeB/NodeC don't expose admin API | same gate (§6) |
| 9 | Auth provider abstraction | `AuthProvider` trait + registry (§8) |
| 10 | Local login kept working | `LocalAuthProvider` wraps existing flow (§8) |
| 11 | Cylenium disabled/pluggable | `CyleniumProvider` stub, `enabled()=false` (§8) |
| 12 | Tests | 6 tests (§9) |
| 13 | Docs + config examples | update `docs/REST API Details.md` + `nodeA.yaml` (§10) |

---

## 4. File structure

```
src/api/
  tls.rs            # NEW — build_admin_server_config (server-auth only) + key-perm check
  auth/
    provider.rs     # NEW — AuthProvider trait, LocalAuthProvider, CyleniumProvider(stub), registry
  mod.rs            # EDIT — serve() TLS termination; pub mod tls;
src/
  config_loader.rs  # EDIT — NodeConfig.api: Option<ApiConfig> { tls }
  main.rs           # EDIT — nodeA gate + load api.tls + perm check + pass TLS settings
Cargo.toml          # EDIT — add axum-server
docs/REST API Details.md  # EDIT — HTTPS base URL, HTTP rejection, config example
config/nodeA.yaml   # EDIT/EXAMPLE — api.tls block
```

---

## 5. Config schema — `api.tls.*` (requirement #6)

Anchor (verbatim `src/config_loader.rs`):

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    pub metrics: Option<MetricsConfig>,
    pub relay: Option<RelayLimitsConfig>,
}
```

Add (mirrors the existing `Option<MetricsConfig>` pattern — additive, old configs still parse):

```rust
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ApiTlsConfig {
    #[serde(default)] pub enabled: bool,
    #[serde(default)] pub cert_path: Option<String>,
    #[serde(default)] pub key_path: Option<String>,
    #[serde(default)] pub require_https: bool,
}
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ApiConfig {
    #[serde(default)] pub tls: ApiTlsConfig,
}
// add field to NodeConfig:
    #[serde(default)] pub api: Option<ApiConfig>,
```

Semantics:
- `enabled=false` → plaintext HTTP (dev only), logs a warning.
- `enabled=true` → build TLS; serve **HTTPS-only**. On cert/key failure with `require_https=true` → **fail-closed** (don't start). Recommended NodeA production: both `true`.
- `require_https=true` → never accept plaintext, never downgrade (enforces security req "no silent HTTP fallback").

Cert/key paths default (when unset) to the existing device identity:
`/var/lib/sgx-guardian/sgx-agent/device_<node_id>_cert.der` and `.../device_<node_id>.key`.

---

## 6. `src/api/tls.rs` (NEW) — server-auth TLS config + key-perm validation (requirements #3, #4, #5)

This is **separate** from `src/tls.rs::build_server_config` (that one requires client certs for gRPC mTLS). The admin API is browser-facing → **server auth only, no client cert**.

```rust
use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

/// Refuse a key readable by group/other (fail-closed). Requirement #5.
pub fn validate_key_permissions(key_path: &str) -> Result<()> {
    let meta = std::fs::metadata(key_path)
        .with_context(|| format!("cannot stat key {}", key_path))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("insecure key permissions {:o} on {} (require 0600)", mode, key_path);
    }
    Ok(())
}

/// Build a browser-facing (no client-auth) rustls ServerConfig from DER cert + PKCS8 DER key.
/// No PEM conversion (requirement #4). Uses the process ring provider.
pub fn build_admin_server_config(cert_der_path: &str, key_der_path: &str) -> Result<Arc<ServerConfig>> {
    crate::server::ensure_rustls_crypto_provider(); // reuse existing ring installer

    validate_key_permissions(key_der_path)?;         // requirement #5 (fail-closed)

    let cert_der = std::fs::read(cert_der_path)
        .with_context(|| format!("read admin TLS cert {}", cert_der_path))?;
    let key_der = std::fs::read(key_der_path)
        .with_context(|| format!("read admin TLS key {}", key_der_path))?;

    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid admin TLS cert/key")?;   // fail-closed on bad cert/key
    Ok(Arc::new(config))
}
```

> Expose `ensure_rustls_crypto_provider` as `pub` in `src/server.rs` (it's currently a private fn) — a one-line visibility change, additive.

---

## 7. `serve()` TLS termination (requirements #1, #2)

Anchor (verbatim current `src/api/mod.rs`):

```rust
pub async fn serve(state: Arc<AppState>, bind: SocketAddr) -> anyhow::Result<()> {
    let app = build_router(state.clone()).layer(axum::middleware::from_fn_with_state(
        state,
        auth::middleware::require_auth,
    ));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("Admin REST API listening on http://{}", bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
```

Replace with a TLS-aware version (keeps the existing middleware layer untouched):

```rust
pub struct AdminTls { pub cert_path: String, pub key_path: String }

pub async fn serve(state: Arc<AppState>, bind: SocketAddr, tls: Option<AdminTls>) -> anyhow::Result<()> {
    let app = build_router(state.clone()).layer(axum::middleware::from_fn_with_state(
        state,
        auth::middleware::require_auth,
    ));
    let make = app.into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        Some(t) => {
            // Fail-closed: any error here propagates; caller must NOT fall back to HTTP.
            let cfg = crate::api::tls::build_admin_server_config(&t.cert_path, &t.key_path)?;
            let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(cfg);
            tracing::info!("Admin REST API listening on https://{} (TLS)", bind);
            axum_server::bind_rustls(bind, rustls_cfg).serve(make).await?;
        }
        None => {
            tracing::warn!("Admin REST API on http://{} (TLS DISABLED — dev only)", bind);
            let listener = tokio::net::TcpListener::bind(bind).await?;
            axum::serve(listener, make).await?;
        }
    }
    Ok(())
}
```

TLS-only listener ⇒ a plaintext `http` request to `:8443` fails the handshake (requirement #2 satisfied without a second port). Log strings say `https`, never the cert/key bytes (security req).

---

## 8. `main.rs` — NodeA gate + config load + perm check + fail-closed (requirements #5, #7, #8)

Anchor (verbatim current `src/main.rs`):

```rust
    let api_bind: std::net::SocketAddr = "0.0.0.0:8443".parse().unwrap();
    tokio::spawn({
        let state = api_state.clone();
        async move {
            if let Err(e) = sgx_guardian_client::api::serve(state, api_bind).await {
                eprintln!("❌ REST API server failed: {:?}", e);
            }
        }
    });
    println!("✅ REST admin API listening on http://{}/api/v1", api_bind);
```

Replace with NodeA-gated + TLS-configured spawn:

```rust
    if node_id == "nodeA" {
        let api_bind: std::net::SocketAddr = "0.0.0.0:8443".parse().unwrap();

        // Resolve TLS settings from node config (defaults to the device identity cert/key).
        let tls = {
            let cfg_path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);
            let tls_cfg = sgx_guardian_client::config_loader::NodeConfig::load(&cfg_path)
                .ok()
                .and_then(|c| c.api)
                .map(|a| a.tls)
                .unwrap_or_default();

            if tls_cfg.enabled {
                let cert = tls_cfg.cert_path.unwrap_or_else(||
                    format!("/var/lib/sgx-guardian/sgx-agent/device_{}_cert.der", node_id));
                let key = tls_cfg.key_path.unwrap_or_else(||
                    format!("/var/lib/sgx-guardian/sgx-agent/device_{}.key", node_id));
                Some((sgx_guardian_client::api::AdminTls { cert_path: cert, key_path: key },
                      tls_cfg.require_https))
            } else {
                None
            }
        };

        tokio::spawn({
            let state = api_state.clone();
            async move {
                let (tls_opt, require_https) = match tls {
                    Some((t, req)) => (Some(t), req),
                    None => (None, false),
                };
                if let Err(e) = sgx_guardian_client::api::serve(state, api_bind, tls_opt).await {
                    eprintln!("❌ REST API server failed: {:?}", e);
                    // Security req: if HTTPS is required, do NOT fall back — the task simply ends.
                    if require_https { eprintln!("TLS required; admin API not started (fail-closed)."); }
                }
            }
        });
        println!("✅ REST admin API (NodeA) starting on :8443");
    } else {
        println!("ℹ️ Admin API disabled on member node {}", node_id);
    }
```

NodeB/NodeC never bind `:8443` (requirements #7, #8), mirroring the existing `if node_id == "nodeA"` cert-bootstrap gate. Fail-closed is inherent: on cert/key error `serve()` returns `Err` and never binds plaintext.

---

## 9. AuthProvider seam (requirements #9, #10, #11)

Today `handlers::auth::login` runs the local flow inline (verbatim): `normalize_email` → `prepare_login_user` → `is_locked`/`locked_error` → `password::verify_password` → `record_failed_login` → `reset_login_failures` → `session::issue` → `sessions.put`. Keep all of that; move the **credential-verification** portion behind a trait; keep **session issuance** in the handler (shared by all providers — SSO also mints a local session after federated auth).

`src/api/auth/provider.rs` (NEW):

```rust
#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn enabled(&self) -> bool;
    /// Verify credentials and return the local User (no token yet).
    async fn authenticate(&self, state: &AppState, creds: Credentials)
        -> Result<crate::api::auth::store::User, ApiError>;
}

pub struct LocalAuthProvider;   // wraps the EXISTING email/password + lockout flow verbatim
pub struct CyleniumProvider { pub enabled: bool }  // stub; enabled=false for now

#[async_trait::async_trait]
impl AuthProvider for CyleniumProvider {
    fn name(&self) -> &'static str { "cylenium" }
    fn enabled(&self) -> bool { self.enabled }        // false by default
    async fn authenticate(&self, _s: &AppState, _c: Credentials)
        -> Result<crate::api::auth::store::User, ApiError> {
        Err(ApiError::Forbidden("cylenium SSO provider is disabled".into()))
    }
}
```

- `login` handler: call `LocalAuthProvider.authenticate(state, creds)` (same verify+lockout logic it runs today, now inside the provider), then keep the existing `session::issue` + `sessions.put` + `AuthResponse`. **Zero behavior change for local login** (requirement #10).
- Cylenium registered but disabled (requirement #11). Gate via env `SGX_SSO_CYLENIUM_ENABLED` (default `false`) — consistent with the project's `SGX_*` flag pattern; can move into `api.auth` config later. A future `/api/v1/auth/sso/cylenium` route dispatches to it only when `enabled()`.
- Registry: a small `Vec<Box<dyn AuthProvider>>` (or map by `name()`) built at startup and stored in `AppState` (additive field) or a module `OnceCell`.

---

## 10. Docs + config example (requirement #13)

- `docs/REST API Details.md`: note the base URL is now `https://<nodeA-ip>:8443`; plaintext `http` to `:8443` is rejected; member nodes expose no admin API; add the disabled Cylenium provider note.
- `config/nodeA.yaml` example block:

```yaml
api:
  tls:
    enabled: true
    require_https: true
    # optional — default to the device identity cert/key when omitted:
    cert_path: /var/lib/sgx-guardian/sgx-agent/device_nodeA_cert.der
    key_path:  /var/lib/sgx-guardian/sgx-agent/device_nodeA.key
```

---

## 11. Security requirements — explicit mapping

- **No silent HTTP fallback:** `serve()` with `Some(tls)` only serves TLS; on error it returns `Err` (never binds plaintext). `require_https` documents/enforces the intent. ✔
- **Fail-closed on cert/key load failure:** `build_admin_server_config` returns `Err` on missing/invalid cert or bad key perms → API doesn't start. ✔
- **No admin API on member nodes:** `if node_id == "nodeA"` gate. ✔
- **Never log secrets:** new log lines emit only `https://{bind}` — no key/cert/token/JWT. Add a checklist item to confirm no `tracing::debug!`/`println!` prints `token`, `pw_hash`, `jti` (full), or key bytes anywhere on this path. Session logs, if any, use a short `jti` prefix only. ✔
- **Linux board compatibility:** DER cert/key already exist on the board; `PermissionsExt` is Linux-native; no new hardware calls; runtime stays tokio-async. ✔

---

## 12. Tests (requirement #12)

Add to `src/api/tls.rs` / `src/api/mod.rs` test modules (use rcgen to mint a throwaway P-256 cert for `127.0.0.1`, write DER cert + PKCS8 DER key to a TempDir):

1. **HTTPS health success** — `bind_rustls` the router on `127.0.0.1:0`; `reqwest` client trusting the test cert → `GET https://…/api/v1/health` == `200`.
2. **HTTP rejected on TLS port** — plaintext `http://…` to the TLS listener → assert connection/handshake error (no `200`).
3. **Missing cert fail-closed** — `build_admin_server_config("/nonexistent.der", key)` → `Err`; `serve(Some(tls))` never binds.
4. **Invalid key/cert fail-closed** — write garbage bytes → `build_admin_server_config` → `Err`.
5. **Insecure key perms rejected** — `chmod 0644` the test key → `validate_key_permissions` → `Err`.
6. **Local auth provider still works** — existing login→token test passes through `LocalAuthProvider` (login returns a valid bearer; protected route accepts it).

---

## 13. On-board verification (expected final behavior)

Board workflow (binary direct):

```
./sgx_guardian_client nodeA           # TLS on per config
# peer cert now presented:
openssl s_client -connect 127.0.0.1:8443 </dev/null 2>/dev/null | openssl x509 -noout -subject
#   -> subject=CN=nodeA (or hostname)   [was: "no peer certificate available"]

curl -k https://127.0.0.1:8443/api/v1/health      # -> ok (200)   [-k: self-signed]
curl    http://127.0.0.1:8443/api/v1/health       # -> fails (TLS-only rejects plaintext)

# authenticated flow over HTTPS still works:
TOKEN=$(curl -k -s -X POST https://127.0.0.1:8443/api/v1/auth/login \
  -H 'content-type: application/json' -d '{"email":"admin@sgx.local","password":"..."}' | jq -r .token)
curl -k -s https://127.0.0.1:8443/api/v1/devices -H "authorization: Bearer $TOKEN"   # -> 200

# member node: no admin API
./sgx_guardian_client nodeB
curl -k https://<nodeB-ip>:8443/api/v1/health     # -> connection refused (not bound)
```

Freeze/regression check: after enabling TLS, daemon stays up (`pgrep -f sgx_guardian_client`), no panic/reboot loop; Phase A login/session, Phase B pairing, Phase C multi-node onboarding all still pass over HTTPS.

---

## 14. Async / board-freeze + regression checklist

- [ ] `build_admin_server_config` is sync CPU work called once at startup (not per-request) — fine; no blocking on the request path.
- [ ] No `std::thread::sleep`, no sync `Command::output()` added; runtime stays tokio-async.
- [ ] No edits to `NebulaDaemon::start()` / daemon lifecycle blocking-sensitive code.
- [ ] `ensure_rustls_crypto_provider()` called before building the admin config (avoids "no default crypto provider" panic).
- [ ] `axum-server` uses the `no-provider` feature so only the ring provider is present (no aws-lc-rs double-install).
- [ ] Existing gRPC mTLS on `:50051` untouched (separate `src/tls.rs` / `ServerTlsConfig` path).
- [ ] No secret ever logged on the TLS/auth path.

---

## 15. Effort estimate

| Task | Effort |
|---|---|
| TLS config builder + serve() TLS termination + Cargo dep | 0.5–1 d |
| Config schema (`api.tls`) + main.rs NodeA gate + perm check + fail-closed | 0.5–1 d |
| AuthProvider seam (Local wrap + Cylenium stub + registry) | 1–1.5 d |
| Tests (6) + docs/config examples | 1 d |
| On-board verification (3-node: NodeA HTTPS, NodeB/C no-API, regression) | 0.5–1 d |
| **Total (1 dev)** | **3.5–5.5 d** |

Cylenium's actual OIDC/SSO integration is **out of scope here** — Phase D only lands the provider seam with Cylenium disabled/pluggable, per requirements #9–#11.
