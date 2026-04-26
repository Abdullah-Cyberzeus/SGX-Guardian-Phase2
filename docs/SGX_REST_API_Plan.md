# SG-X Guardian — Frontend-Driven REST API Plan (Rust / axum)

**Document version:** 1.0
**Date:** April 15, 2026
**Author:** Asad Ali — Backend / Security Engineering
**Audience:** Internal engineering + pre-meeting notes for the frontend team
**Scope:** Code-level audit of `SGX-gaurdian-admi-console-FE` @ `develop` branch, mapped to the 15 `sgx-pa-cli` commands, plus exact Rust implementation plan that slots into the existing `sgx_guardian_client` repo without breaking anything.

---

## 0. TL;DR

- We inspected the frontend repo the Indian team delivered (`SGX_Frontend.zip`, Express mock on `:3001`, React hooks in `src/app/hooks/useApiData.ts`, 11 service files in `src/app/services/`, and actual screen wiring under `src/app/screens/**`).
- Their own gap-analysis doc dated Apr 8 claims **15/15 CLI commands "DONE"**. The code tells a different story. Only **5 commands are actually wired end-to-end** today. Another **7 have UI controls (dialogs, buttons) but the click handlers are never connected to the service layer**. Two commands have dead code (service + hook defined, zero screens import them). One has no frontend footprint at all.
- The frontend also consumes **four endpoint groups that have no backend equivalent** today: `/api/alerts`, `/api/circles`, `/api/devices`, `/api/guardian/threat-intel`. We need to decide whether these are ours to build or theirs.
- Recommendation: build **12 REST endpoints** (5 USED + 7 PARTIAL) in axum inside the existing binary. Ignore `keygen` (it's an offline PA workstation command, not a board-side API). Send the email at the end of this doc to Aditya/Karan before we cut a single line of handler code.

---

## 1. Frontend Command Usage Table (verified from actual code)

Classification rules I used:
- **USED** — a hook in `useApiData.ts` is invoked by at least one `.tsx` screen **and** renders returned data.
- **PARTIAL** — either (a) a UI control/dialog exists on screen but the click handler never calls the corresponding service method, or (b) the hook/service is defined but no screen consumes it.
- **NOT USED** — no service method, no hook, no UI element found.

| # | CLI command | Mock route | Service method | Hook (useApiData) | Screen that imports the hook | Click handler wired? | **Status** |
|---|---|---|---|---|---|---|---|
| 1 | `status` | `GET /api/node/status` | `nodeService.getStatus` | `useNodeStatus` | **none** (dashboard uses `useGuardianInfo` instead) | n/a | **PARTIAL** (dead hook) |
| 2 | `boot-status` | `GET /api/node/boot-status` | `nodeService.getBootStatus` | `useBootStatus` | `SC01BootStatus.tsx` | n/a (read-only) | **USED** |
| 3 | `peers` | `GET /api/peers` | `peerService.getAll` | `usePeers` | **none** (topology uses `useDevices`+`useCircles`) | n/a | **PARTIAL** (dead hook) |
| 4 | `attestation` | `GET /api/attestation` | `attestationService.getResults` | `useAttestationResults` | `SC02AttestationStatus.tsx` | n/a | **USED** |
| 5 | `logs` | `GET /api/logs` | `logService.getLogs` | `useLogs` | `LG01LogsViewer.tsx` | n/a | **USED** |
| 6 | `keygen` | (no route) | (no method) | (no hook) | (no screen) | n/a | **NOT USED** |
| 7 | `sign` | `POST /api/policy/sign` | `policyService.sign` | — | `PL01PolicyManagement.tsx` has `isSigning` state | **NO** — no `policyService.sign()` call anywhere in the screen | **PARTIAL** |
| 8 | `verify` | `POST /api/policy/verify` | `policyService.verify` | — | `PL01PolicyManagement.tsx` has `isVerifying` state | **NO** — not wired | **PARTIAL** |
| 9 | `dkp-status` | `GET /api/dkp/status` | `dkpService.getStatus` | `useDKPStatus` | `KM01KeyManagement.tsx` | n/a | **USED** |
| 10 | `dkp-rotate` | `POST /api/dkp/rotate` | `dkpService.rotate` | — | `KM01KeyManagement.tsx` has `showRotateDialog` | **NO** — dialog opens, never calls rotate | **PARTIAL** |
| 11 | `dkp-revoke` | `POST /api/dkp/revoke` | `dkpService.revoke` | — | `KM01KeyManagement.tsx` has `showRevokeDialog` | **NO** | **PARTIAL** |
| 12 | `emergency-rotate` | `POST /api/dkp/emergency-rotate` | `dkpService.emergencyRotate` | — | `KM01KeyManagement.tsx` has `showEmergencyDialog` | **NO** | **PARTIAL** |
| 13 | `pcr-status` | `GET /api/pcr/status` | `pcrService.getStatus` | `usePCRStatus` | `IN01IntegrityDashboard.tsx` | n/a | **USED** |
| 14 | `pcr-baseline-create` | `POST /api/pcr/baseline/update` (name mismatch) | `pcrService.updateBaseline` | — | `IN01IntegrityDashboard.tsx` has `showCreateBaselineDialog` | **NO** | **PARTIAL** |
| 15 | `pcr-baseline-verify` | `POST /api/pcr/verify` | `pcrService.verify` | — | `IN01IntegrityDashboard.tsx` has `isVerifying` state | **NO** | **PARTIAL** |

### Extra frontend endpoints with no CLI equivalent

These drive major UI surfaces but have no backend origin in `sgx-pa-cli`:

| Mock route | Hook | Used in screens | Our backend has it? |
|---|---|---|---|
| `GET /api/guardian/info` | `useGuardianInfo` | Dashboard, GuardianDetail, NetworkTopology | Partially (node config) |
| `GET /api/guardian/threat-intel` | `useThreatIntel` | Dashboard (Security Health Score) | **No** |
| `GET /api/alerts`, `PUT /api/alerts/:id/read`, etc. | `useAlerts` | Dashboard, AL01, AL06, AL07 | **No** |
| `GET /api/circles`, `POST/PUT/DELETE` members | `useCircles` | NW01, NW04, Dashboard | **No** (Nebula CoT registry is closest) |
| `GET /api/devices`, attest | `useDevices` | DV01, DV03, DV06, NetworkTopology | Partially (trusted_peers.json) |

---

## 2. Filtered API Scope — What We Build Now

**Build these 12 endpoints in phase 1** (5 USED + 7 PARTIAL that have visible UI):

```
Phase 1 - Read endpoints (unblock the 5 working screens today):
  GET  /api/v1/node/status
  GET  /api/v1/node/boot-status
  GET  /api/v1/peers
  GET  /api/v1/attestation
  GET  /api/v1/logs
  GET  /api/v1/dkp/status
  GET  /api/v1/pcr/status

Phase 2 - Action endpoints (light up the existing UI dialogs):
  POST /api/v1/policy/sign
  POST /api/v1/policy/verify
  POST /api/v1/dkp/rotate
  POST /api/v1/dkp/revoke
  POST /api/v1/dkp/emergency-rotate
  POST /api/v1/pcr/baseline/create
  POST /api/v1/pcr/baseline/verify
```

**Deferred / not building yet:**
- `keygen` — offline PA workstation command, not appropriate to expose over the network.
- `alerts`, `circles`, `devices`, `guardian/threat-intel` — confirm ownership with frontend team (see email draft at end).

---

## 3. API Design (Phase 1 read-only — exact shapes)

Base URL on the board: `https://<board-ip>:8443`
Base path: `/api/v1`
All responses are JSON. Errors follow a single envelope:

```json
{ "error": { "code": "string", "message": "string" } }
```

### 3.1 `GET /api/v1/node/status`
Maps to: `sgx-pa-cli status --node <node>`
Handler reads: `/etc/sgx-guardian/config/<node>.yaml`
Query params: `?node=nodeA` (default `nodeA`)

```json
{
  "nodeId": "guardian-node-a-001",
  "hostname": "guardian-tx-042",
  "ip": "192.168.50.101",
  "port": 50051,
  "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
  "timestamp": "2026-04-15T09:14:32.000Z"
}
```

### 3.2 `GET /api/v1/node/boot-status`
Maps to: `sgx-pa-cli boot-status`
Handler reads: `/var/lib/sgx-guardian/boot/<node>_chain_status.json`

```json
{
  "habEnabled": true,
  "deviceClosed": true,
  "habEventsFound": false,
  "deviceModel": "Variscite VAR-SOM-MX8M-PLUS",
  "kernelVersion": "Linux 5.15.71-imx8mp",
  "bootChainIntact": true,
  "guardianBinaryHash": "a3f4b2c81e9d7a02...",
  "trustChain": [
    { "stage": "Boot ROM",    "status": "verified" },
    { "stage": "HAB",         "status": "verified" },
    { "stage": "U-Boot",      "status": "verified" },
    { "stage": "Kernel",      "status": "verified" },
    { "stage": "Guardian",    "status": "verified" },
    { "stage": "SE050",       "status": "verified" }
  ],
  "timestamp": "2026-04-15T09:14:32.000Z"
}
```

### 3.3 `GET /api/v1/peers`
Maps to: `sgx-pa-cli peers`
Handler reads: `/var/log/sgx-guardian/trusted_peers.json` (falls back to `logs/trusted_peers.json`)

```json
{
  "peers": [
    {
      "peerId": "192.168.50.115:50052",
      "ip": "192.168.50.115",
      "status": "verified",
      "lastSeen": "2026-04-15T09:14:32.000Z"
    }
  ],
  "total": 1,
  "timestamp": "2026-04-15T09:14:32.000Z"
}
```

### 3.4 `GET /api/v1/attestation`
Maps to: `sgx-pa-cli attestation`
Handler reads: `/var/log/sgx-guardian/last_attestation.json`

```json
{
  "peerId": "192.168.50.115:50052",
  "policyDigest": "a7b9c3e4f5d6...",
  "result": "success",
  "timestamp": "2026-04-15T09:14:32.000Z"
}
```

### 3.5 `GET /api/v1/logs`
Maps to: `sgx-pa-cli logs --node <node> --tail <n>`
Handler reads: latest file in `logs/` matching `<node>*`
Query params: `?node=nodeA&tail=100&level=error&search=attest`

```json
{
  "node": "nodeA",
  "file": "logs/nodeA.log",
  "entries": [
    { "timestamp": "2026-04-15T09:14:32.000Z", "level": "info",  "message": "Peer 192.168.50.115 attested successfully." }
  ],
  "total": 20,
  "timestamp": "2026-04-15T09:14:32.000Z"
}
```

### 3.6 `GET /api/v1/dkp/status`
Maps to: `sgx-pa-cli dkp-status`
Handler reads: `/var/lib/sgx-guardian/keys/dkp_metadata.json`

```json
{
  "totalVersions": 2,
  "activeVersion": 2,
  "se050Available": true,
  "activePublicKeyPath": "/var/lib/sgx-guardian/keys/dkp_pub.der",
  "activePublicKeySize": 91,
  "keys": [
    {
      "version": 2,
      "keyId": "0x20000011",
      "algorithm": "ECDSA-P256",
      "status": "Active",
      "createdAt": "2026-03-15T10:30:00Z",
      "rotatedFrom": "0x20000010"
    },
    {
      "version": 1,
      "keyId": "0x20000010",
      "algorithm": "ECDSA-P256",
      "status": "Deprecated",
      "createdAt": "2026-02-01T08:00:00Z"
    }
  ]
}
```

### 3.7 `GET /api/v1/pcr/status`
Maps to: `sgx-pa-cli pcr-status`
Handler reads: `/var/lib/sgx-guardian/pcr/<node>_current.json`

```json
{
  "node": "nodeA",
  "registers": [
    { "index": 0, "name": "BIOS/Bootloader", "value": "a3f4b2c81e9d7a02..." },
    { "index": 1, "name": "Firmware/DTB",    "value": "b7c9d1e2f3a45678..." },
    { "index": 2, "name": "Kernel",          "value": "c8d2e3f4a5b67890..." },
    { "index": 3, "name": "RootFS",          "value": "d9e3f4a5b6c78901..." },
    { "index": 4, "name": "Configuration",   "value": "e0f4a5b6c7d89012..." }
  ],
  "compositeDigest": "f1a5b6c7d8e90123...",
  "compositeSignature": "base64-signature",
  "integrityStatus": "PASS",
  "deviceUid": "SE050-UID-A9F3...",
  "keyVersion": 2,
  "measuredAt": "2026-04-15T09:14:00Z",
  "schemaVersion": 1
}
```

### 3.8 Phase-2 action endpoints — shapes

**`POST /api/v1/dkp/rotate`** → body `{}`
```json
{ "success": true, "oldVersion": 1, "newVersion": 2, "newKeyId": "0x20000011", "restartRequired": true, "timestamp": "..." }
```

**`POST /api/v1/dkp/revoke`** → body `{ "version": 1, "reason": "compromised key" }`
```json
{ "success": true, "version": 1, "reason": "compromised key", "timestamp": "..." }
```

**`POST /api/v1/dkp/emergency-rotate`** → body `{ "reason": "incident-2026-04-15" }`
```json
{ "success": true, "rotated": ["dkp","software_key","tls_cert"], "failed": [], "restartRequired": true, "auditLog": "/var/log/sgx-guardian/emergency_rotation.log", "timestamp": "..." }
```

**`POST /api/v1/policy/sign`** → multipart upload of policy YAML + key
```json
{ "success": true, "digest": "a7b9...", "signature": "base64...", "outputPath": "policy.yaml.sig", "timestamp": "..." }
```

**`POST /api/v1/policy/verify`** → multipart upload of `.sig` file
```json
{ "success": true, "digestValid": true, "signatureValid": true, "timestamp": "..." }
```

**`POST /api/v1/pcr/baseline/create`** → body `{}`
```json
{ "success": true, "node": "nodeA", "compositeDigest": "f1a5...", "signed": true, "baselinePath": "/etc/sgx-guardian/pcr_nodeA_baseline.json", "timestamp": "..." }
```

**`POST /api/v1/pcr/baseline/verify`** → body `{}`
```json
{ "success": true, "allMatch": true, "mismatches": [], "timestamp": "..." }
```

---

## 4. Rust Implementation — File-by-File

### 4.1 New file tree inside existing repo

Everything goes **under `src/api/`** as a new module. Nothing in the existing tree changes except two lines in `src/lib.rs` and a `tokio::spawn` block in `src/main.rs`.

```
sgx_guardian_client/
├── Cargo.toml                         # + 2 deps (axum already transitive, tower-http for CORS)
├── src/
│   ├── lib.rs                         # +1 line: pub mod api;
│   ├── main.rs                        # +10 lines: spawn api::serve task
│   ├── server.rs                      # UNCHANGED - existing gRPC stays on :50051
│   ├── attestation_service.rs         # UNCHANGED
│   ├── key_manager.rs                 # UNCHANGED
│   ├── secure_element/                # UNCHANGED
│   └── api/                           # NEW MODULE
│       ├── mod.rs                     # Router wiring + serve() entry
│       ├── error.rs                   # ApiError + IntoResponse impl
│       ├── state.rs                   # AppState (paths, node_id)
│       └── handlers/
│           ├── mod.rs
│           ├── node.rs                # status, boot-status
│           ├── peers.rs               # peers
│           ├── attestation.rs         # attestation
│           ├── logs.rs                # logs
│           ├── dkp.rs                 # dkp-status, rotate, revoke, emergency
│           ├── pcr.rs                 # pcr-status, baseline create/verify
│           └── policy.rs              # sign, verify
```

### 4.2 `Cargo.toml` — additions

`axum 0.7` is already pulled in transitively by `tonic 0.12.3`, but we make it explicit so the build doesn't break if tonic bumps its internal dep. `tower-http` is new (CORS). `tokio-util` we already have indirectly.

```toml
# Add to [dependencies] in the ROOT Cargo.toml
axum = { version = "0.7", features = ["macros", "multipart"] }
tower-http = { version = "0.5", features = ["cors", "trace"] }
```

### 4.3 `src/lib.rs` — one-line addition

```rust
// Add this line alongside the existing `pub mod` declarations:
pub mod api;
```

### 4.4 `src/api/mod.rs`

```rust
//! REST API module for the SG-X Guardian admin console.
//! Runs as a tokio task alongside the existing gRPC server.
//! Port: 8443 (separate listener from the :50051 mTLS gRPC endpoint).

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub mod error;
pub mod handlers;
pub mod state;

use state::AppState;

/// Build the full axum router with all v1 routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Phase 1 - read endpoints
        .route("/api/v1/node/status", get(handlers::node::status))
        .route("/api/v1/node/boot-status", get(handlers::node::boot_status))
        .route("/api/v1/peers", get(handlers::peers::list))
        .route("/api/v1/attestation", get(handlers::attestation::last))
        .route("/api/v1/logs", get(handlers::logs::tail))
        .route("/api/v1/dkp/status", get(handlers::dkp::status))
        .route("/api/v1/pcr/status", get(handlers::pcr::status))
        // Phase 2 - action endpoints
        .route("/api/v1/dkp/rotate", post(handlers::dkp::rotate))
        .route("/api/v1/dkp/revoke", post(handlers::dkp::revoke))
        .route("/api/v1/dkp/emergency-rotate", post(handlers::dkp::emergency_rotate))
        .route("/api/v1/pcr/baseline/create", post(handlers::pcr::baseline_create))
        .route("/api/v1/pcr/baseline/verify", post(handlers::pcr::baseline_verify))
        .route("/api/v1/policy/sign", post(handlers::policy::sign))
        .route("/api/v1/policy/verify", post(handlers::policy::verify))
        // Health
        .route("/api/v1/health", get(|| async { "ok" }))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Entry point. Spawned from main.rs as a tokio task.
pub async fn serve(state: Arc<AppState>, bind: SocketAddr) -> anyhow::Result<()> {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("🌐 Admin REST API listening on http://{}", bind);
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
```

### 4.5 `src/api/state.rs`

```rust
//! Shared state passed to every handler.
//! Keeps all filesystem paths in one place so tests can swap them out.

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub node_id: String,
    pub config_dir: String,                 // /etc/sgx-guardian/config
    pub boot_dir: String,                   // /var/lib/sgx-guardian/boot
    pub keys_dir: String,                   // /var/lib/sgx-guardian/keys
    pub pcr_dir: String,                    // /var/lib/sgx-guardian/pcr
    pub pcr_baseline_dir: String,           // /etc/sgx-guardian
    pub log_dir_primary: String,            // /var/log/sgx-guardian
    pub log_dir_fallback: String,           // logs
}

impl AppState {
    pub fn from_env(node_id: String) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            config_dir: "/etc/sgx-guardian/config".into(),
            boot_dir: "/var/lib/sgx-guardian/boot".into(),
            keys_dir: "/var/lib/sgx-guardian/keys".into(),
            pcr_dir: "/var/lib/sgx-guardian/pcr".into(),
            pcr_baseline_dir: "/etc/sgx-guardian".into(),
            log_dir_primary: "/var/log/sgx-guardian".into(),
            log_dir_fallback: "logs".into(),
        })
    }
}
```

### 4.6 `src/api/error.rs`

```rust
//! Uniform API error envelope.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::NotFound(m)   => (StatusCode::NOT_FOUND,            "NOT_FOUND",   m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST,          "BAD_REQUEST", m),
            ApiError::Internal(m)   => (StatusCode::INTERNAL_SERVER_ERROR,"INTERNAL",    m),
        };
        let body = Json(json!({ "error": { "code": code, "message": message } }));
        (status, body).into_response()
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self { ApiError::Internal(format!("io: {}", e)) }
}
impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self { ApiError::Internal(format!("json: {}", e)) }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self { ApiError::Internal(e.to_string()) }
}
```

### 4.7 `src/api/handlers/mod.rs`

```rust
pub mod attestation;
pub mod dkp;
pub mod logs;
pub mod node;
pub mod pcr;
pub mod peers;
pub mod policy;
```

### 4.8 `src/api/handlers/node.rs`

```rust
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::{Query, State}, Json};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

#[derive(Deserialize)]
pub struct NodeQuery { pub node: Option<String> }

#[derive(Serialize)]
pub struct NodeStatus {
    #[serde(rename = "nodeId")]   pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    #[serde(rename = "publicKey")] pub public_key: String,
    pub timestamp: String,
}

pub async fn status(
    State(s): State<Arc<AppState>>,
    Query(q): Query<NodeQuery>,
) -> Result<Json<NodeStatus>, ApiError> {
    let node = q.node.unwrap_or_else(|| s.node_id.clone());
    if !node.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
    }
    let path: PathBuf = [&s.config_dir, &format!("{}.yaml", node)].iter().collect();
    let text = tokio::fs::read_to_string(&path).await
        .map_err(|_| ApiError::NotFound(format!("config for {} not found", node)))?;
    // Reuse the existing NodeConfig loader from the library crate.
    let cfg: crate::config::NodeConfig = serde_yaml::from_str(&text)
        .map_err(|e| ApiError::Internal(format!("yaml parse: {}", e)))?;
    Ok(Json(NodeStatus {
        node_id: cfg.node_id,
        hostname: cfg.hostname,
        ip: cfg.ip,
        port: cfg.port,
        public_key: cfg.public_key,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

#[derive(Serialize)]
pub struct TrustStage { pub stage: String, pub status: String }

#[derive(Serialize)]
pub struct BootStatus {
    #[serde(rename = "habEnabled")]         pub hab_enabled: bool,
    #[serde(rename = "deviceClosed")]       pub device_closed: bool,
    #[serde(rename = "habEventsFound")]     pub hab_events_found: bool,
    #[serde(rename = "deviceModel")]        pub device_model: String,
    #[serde(rename = "kernelVersion")]      pub kernel_version: String,
    #[serde(rename = "bootChainIntact")]    pub boot_chain_intact: bool,
    #[serde(rename = "guardianBinaryHash")] pub guardian_binary_hash: Option<String>,
    #[serde(rename = "trustChain")]         pub trust_chain: Vec<TrustStage>,
    pub timestamp: String,
}

pub async fn boot_status(State(s): State<Arc<AppState>>) -> Result<Json<BootStatus>, ApiError> {
    // Find any *_chain_status.json in the boot dir (daemon writes <node>_chain_status.json)
    let mut entries = tokio::fs::read_dir(&s.boot_dir).await
        .map_err(|_| ApiError::NotFound("boot status directory missing - daemon not started?".into()))?;
    let mut selected: Option<std::path::PathBuf> = None;
    while let Some(e) = entries.next_entry().await? {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with("_chain_status.json") { selected = Some(e.path()); break; }
    }
    let path = selected.ok_or_else(|| ApiError::NotFound("no chain_status.json found".into()))?;
    let text = tokio::fs::read_to_string(&path).await?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let b = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    let s_ = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let trust_chain = vec![
        TrustStage { stage: "Boot ROM".into(), status: "verified".into() },
        TrustStage { stage: "HAB".into(),      status: if b("hab_enabled")   { "verified".into() } else { "warning".into() } },
        TrustStage { stage: "U-Boot".into(),   status: if b("device_closed") { "verified".into() } else { "warning".into() } },
        TrustStage { stage: "Kernel".into(),   status: "verified".into() },
        TrustStage { stage: "Guardian".into(), status: "verified".into() },
        TrustStage { stage: "SE050".into(),    status: "verified".into() },
    ];
    Ok(Json(BootStatus {
        hab_enabled: b("hab_enabled"),
        device_closed: b("device_closed"),
        hab_events_found: b("hab_events_found"),
        device_model: s_("device_model"),
        kernel_version: s_("kernel_version"),
        boot_chain_intact: b("boot_chain_intact"),
        guardian_binary_hash: v.get("guardian_binary_hash").and_then(|x| x.as_str()).map(String::from),
        trust_chain,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}
```

### 4.9 `src/api/handlers/peers.rs`

```rust
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct Peer {
    #[serde(rename = "peerId")]    pub peer_id: String,
    pub ip: String,
    pub status: String,
    #[serde(rename = "lastSeen")]  pub last_seen: String,
}

#[derive(Serialize)]
pub struct PeersResponse {
    pub peers: Vec<Peer>,
    pub total: usize,
    pub timestamp: String,
}

pub async fn list(State(s): State<Arc<AppState>>) -> Result<Json<PeersResponse>, ApiError> {
    let primary = format!("{}/trusted_peers.json", s.log_dir_primary);
    let fallback = format!("{}/trusted_peers.json", s.log_dir_fallback);
    let text = match tokio::fs::read_to_string(&primary).await {
        Ok(t) => t,
        Err(_) => tokio::fs::read_to_string(&fallback).await.unwrap_or_else(|_| "[]".into()),
    };
    let raw: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let peers: Vec<Peer> = raw.into_iter().map(|v| Peer {
        peer_id:   v.get("peer_id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        ip:        v.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        status:    v.get("status").and_then(|x| x.as_str()).unwrap_or("unknown").to_string(),
        last_seen: v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    }).collect();
    let total = peers.len();
    Ok(Json(PeersResponse { peers, total, timestamp: chrono::Utc::now().to_rfc3339() }))
}
```

### 4.10 `src/api/handlers/attestation.rs`

```rust
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct LastAttestation {
    #[serde(rename = "peerId")]       pub peer_id: String,
    #[serde(rename = "policyDigest")] pub policy_digest: String,
    pub result: String,
    pub timestamp: String,
}

pub async fn last(State(s): State<Arc<AppState>>) -> Result<Json<LastAttestation>, ApiError> {
    let primary  = format!("{}/last_attestation.json", s.log_dir_primary);
    let fallback = format!("{}/last_attestation.json", s.log_dir_fallback);
    let text = tokio::fs::read_to_string(&primary).await
        .or_else(|_| std::fs::read_to_string(&fallback))
        .map_err(|_| ApiError::NotFound("no attestation result recorded yet".into()))?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    Ok(Json(LastAttestation {
        peer_id:       v.get("peer_id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        policy_digest: v.get("policy_digest").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        result:        v.get("result").and_then(|x| x.as_str()).unwrap_or("unknown").to_string(),
        timestamp:     v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    }))
}
```

### 4.11 `src/api/handlers/logs.rs`

```rust
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::{Query, State}, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Deserialize)]
pub struct LogsQuery {
    pub node: Option<String>,
    pub tail: Option<usize>,
    pub level: Option<String>,
    pub search: Option<String>,
}

#[derive(Serialize)]
pub struct LogEntry { pub timestamp: String, pub level: String, pub message: String }

#[derive(Serialize)]
pub struct LogsResponse {
    pub node: String,
    pub file: String,
    pub entries: Vec<LogEntry>,
    pub total: usize,
    pub timestamp: String,
}

pub async fn tail(
    State(s): State<Arc<AppState>>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<LogsResponse>, ApiError> {
    let node = q.node.unwrap_or_else(|| s.node_id.clone());
    let n    = q.tail.unwrap_or(100).min(1000);

    // Pick newest log file matching `<node>*` in either log dir
    let mut candidate: Option<std::path::PathBuf> = None;
    for dir in [&s.log_dir_primary, &s.log_dir_fallback] {
        if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
            let mut newest_mtime: Option<std::time::SystemTime> = None;
            while let Some(e) = rd.next_entry().await? {
                let name = e.file_name().to_string_lossy().to_string();
                if !name.starts_with(&node) { continue; }
                let meta = match e.metadata().await { Ok(m) => m, Err(_) => continue };
                let mt = meta.modified().ok();
                if mt > newest_mtime { newest_mtime = mt; candidate = Some(e.path()); }
            }
        }
        if candidate.is_some() { break; }
    }
    let path = candidate.ok_or_else(|| ApiError::NotFound(format!("no log file for node {}", node)))?;
    let file = path.to_string_lossy().to_string();

    let f = tokio::fs::File::open(&path).await?;
    let mut reader = BufReader::new(f).lines();
    let mut all: Vec<String> = Vec::new();
    while let Some(line) = reader.next_line().await? { all.push(line); }

    let start = all.len().saturating_sub(n);
    let mut entries: Vec<LogEntry> = all[start..]
        .iter()
        .map(|raw| parse_log_line(raw))
        .collect();

    if let Some(lvl) = q.level.as_deref() {
        if lvl != "all" { entries.retain(|e| e.level.eq_ignore_ascii_case(lvl)); }
    }
    if let Some(needle) = q.search.as_deref() {
        let n = needle.to_lowercase();
        entries.retain(|e| e.message.to_lowercase().contains(&n));
    }

    let total = entries.len();
    Ok(Json(LogsResponse { node, file, entries, total, timestamp: chrono::Utc::now().to_rfc3339() }))
}

fn parse_log_line(raw: &str) -> LogEntry {
    // Try JSON first (tracing-subscriber JSON format), fall back to plain text.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        return LogEntry {
            timestamp: v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            level:     v.get("level").and_then(|x| x.as_str()).unwrap_or("info").to_string(),
            message:   v.get("fields").and_then(|f| f.get("message")).and_then(|x| x.as_str())
                       .or_else(|| v.get("message").and_then(|x| x.as_str()))
                       .unwrap_or(raw).to_string(),
        };
    }
    LogEntry { timestamp: "".into(), level: "info".into(), message: raw.to_string() }
}
```

### 4.12 `src/api/handlers/dkp.rs`

```rust
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct DkpKey {
    pub version: u32,
    #[serde(rename = "keyId")]       pub key_id: String,
    pub algorithm: String,
    pub status: String,
    #[serde(rename = "createdAt")]   pub created_at: String,
    #[serde(rename = "rotatedFrom", skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
}

#[derive(Serialize)]
pub struct DkpStatus {
    #[serde(rename = "totalVersions")]      pub total_versions: usize,
    #[serde(rename = "activeVersion")]      pub active_version: Option<u32>,
    #[serde(rename = "se050Available")]     pub se050_available: bool,
    #[serde(rename = "activePublicKeyPath")]pub active_pub_path: Option<String>,
    #[serde(rename = "activePublicKeySize")]pub active_pub_size: Option<u64>,
    pub keys: Vec<DkpKey>,
}

pub async fn status(State(s): State<Arc<AppState>>) -> Result<Json<DkpStatus>, ApiError> {
    let meta_path = format!("{}/dkp_metadata.json", s.keys_dir);
    let pub_path  = format!("{}/dkp_pub.der",       s.keys_dir);
    let text = tokio::fs::read_to_string(&meta_path).await
        .map_err(|_| ApiError::NotFound("no DKP found - daemon not started?".into()))?;
    let raw: serde_json::Value = serde_json::from_str(&text)?;
    let arr: Vec<serde_json::Value> = if raw.is_array() {
        raw.as_array().cloned().unwrap_or_default()
    } else { vec![raw] };

    let keys: Vec<DkpKey> = arr.iter().map(|k| DkpKey {
        version:      k.get("version").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        key_id:       k.get("key_id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        algorithm:    k.get("algorithm").and_then(|x| x.as_str()).unwrap_or("ECDSA-P256").to_string(),
        status:       k.get("status").and_then(|x| x.as_str()).unwrap_or("unknown").to_string(),
        created_at:   k.get("created_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        rotated_from: k.get("rotated_from").and_then(|x| x.as_str()).map(String::from),
    }).collect();

    let active_version = keys.iter().find(|k| k.status == "Active").map(|k| k.version);
    let se050_available = std::process::Command::new("ssscli").arg("--version").output()
        .map(|o| o.status.success()).unwrap_or(false);
    let active_pub_size = tokio::fs::metadata(&pub_path).await.ok().map(|m| m.len());
    let active_pub_path = if active_pub_size.is_some() { Some(pub_path) } else { None };
    let total_versions = keys.len();

    Ok(Json(DkpStatus { total_versions, active_version, se050_available, active_pub_path, active_pub_size, keys }))
}

// ---- Phase 2 action handlers ----
// These shell out to `sgx-pa-cli` on the board because the CLI already
// encapsulates the full rotation/revoke logic including SE050 calls and
// audit logging. DO NOT re-implement inline - it duplicates security-sensitive
// code paths. If we ever remove the CLI, move these routines into the library
// and call them directly.

#[derive(Deserialize)]
pub struct RevokeBody { pub version: u32, pub reason: Option<String> }

#[derive(Deserialize)]
pub struct EmergencyBody { pub reason: Option<String> }

#[derive(Serialize)]
pub struct ActionResponse {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "restartRequired")]
    pub restart_required: bool,
    pub timestamp: String,
}

async fn run_cli(args: &[&str]) -> Result<ActionResponse, ApiError> {
    let out = tokio::process::Command::new("sgx-pa-cli")
        .args(args).output().await
        .map_err(|e| ApiError::Internal(format!("sgx-pa-cli spawn: {}", e)))?;
    Ok(ActionResponse {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        restart_required: true,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

pub async fn rotate(State(_): State<Arc<AppState>>) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["dkp-rotate"]).await?))
}

pub async fn revoke(State(_): State<Arc<AppState>>, Json(b): Json<RevokeBody>)
    -> Result<Json<ActionResponse>, ApiError>
{
    let v = b.version.to_string();
    let reason = b.reason.unwrap_or_else(|| "admin revocation".into());
    Ok(Json(run_cli(&["dkp-revoke", "--version", &v, "--reason", &reason]).await?))
}

pub async fn emergency_rotate(State(_): State<Arc<AppState>>, Json(_b): Json<EmergencyBody>)
    -> Result<Json<ActionResponse>, ApiError>
{
    Ok(Json(run_cli(&["emergency-rotate"]).await?))
}
```

### 4.13 `src/api/handlers/pcr.rs`

```rust
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct PcrRegister { pub index: usize, pub name: String, pub value: String }

#[derive(Serialize)]
pub struct PcrStatus {
    pub node: String,
    pub registers: Vec<PcrRegister>,
    #[serde(rename = "compositeDigest")]    pub composite_digest: String,
    #[serde(rename = "compositeSignature", skip_serializing_if = "Option::is_none")]
    pub composite_signature: Option<String>,
    #[serde(rename = "integrityStatus")]    pub integrity_status: String,
    #[serde(rename = "deviceUid")]          pub device_uid: String,
    #[serde(rename = "keyVersion")]         pub key_version: u32,
    #[serde(rename = "measuredAt")]         pub measured_at: String,
    #[serde(rename = "schemaVersion")]      pub schema_version: u8,
}

const PCR_NAMES: [&str; 5] = ["BIOS/Bootloader","Firmware/DTB","Kernel","RootFS","Configuration"];

pub async fn status(State(s): State<Arc<AppState>>) -> Result<Json<PcrStatus>, ApiError> {
    let path = format!("{}/{}_current.json", s.pcr_dir, s.node_id);
    let text = tokio::fs::read_to_string(&path).await
        .map_err(|_| ApiError::NotFound("no PCR snapshot - daemon not started?".into()))?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let empty = vec![];
    let values = v.get("pcr_values").and_then(|x| x.as_array()).unwrap_or(&empty);
    let registers: Vec<PcrRegister> = values.iter().enumerate().map(|(i, val)| PcrRegister {
        index: i,
        name: PCR_NAMES.get(i).copied().unwrap_or("?").to_string(),
        value: val.as_str().unwrap_or("").to_string(),
    }).collect();
    Ok(Json(PcrStatus {
        node: s.node_id.clone(),
        registers,
        composite_digest:    v.get("composite_digest").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        composite_signature: v.get("composite_signature").and_then(|x| x.as_str()).map(String::from),
        integrity_status:    v.get("integrity_status").and_then(|x| x.as_str()).unwrap_or("UNKNOWN").to_string(),
        device_uid:          v.get("device_uid").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        key_version:         v.get("key_version").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        measured_at:         v.get("measured_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        schema_version:      v.get("schema_version").and_then(|x| x.as_u64()).unwrap_or(1) as u8,
    }))
}

use super::dkp::{run_cli, ActionResponse};

pub async fn baseline_create(State(_): State<Arc<AppState>>) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["pcr-baseline-create"]).await?))
}
pub async fn baseline_verify(State(_): State<Arc<AppState>>) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["pcr-baseline-verify"]).await?))
}
```

> Note: `run_cli` and `ActionResponse` are declared in `dkp.rs`. For that to be imported like above, either keep the `super::dkp` path or move those two items into `handlers/mod.rs`. I chose to keep them in `dkp.rs` and just mark them `pub` so the module path works.

### 4.14 `src/api/handlers/policy.rs`

```rust
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::{Multipart, State}, Json};
use std::sync::Arc;
use super::dkp::{run_cli, ActionResponse};

/// POST /api/v1/policy/sign
/// multipart fields: `policy` (the YAML file), `key` (the private key PKCS8)
pub async fn sign(State(_): State<Arc<AppState>>, mut mp: Multipart)
    -> Result<Json<ActionResponse>, ApiError>
{
    let tmpdir = tempdir()?;
    let (mut policy_path, mut key_path) = (None, None);
    while let Some(field) = mp.next_field().await.map_err(|e| ApiError::BadRequest(e.to_string()))? {
        let name = field.name().unwrap_or("").to_string();
        let bytes = field.bytes().await.map_err(|e| ApiError::BadRequest(e.to_string()))?;
        match name.as_str() {
            "policy" => {
                let p = tmpdir.path().join("policy.yaml");
                tokio::fs::write(&p, &bytes).await?; policy_path = Some(p);
            }
            "key" => {
                let p = tmpdir.path().join("key.pkcs8");
                tokio::fs::write(&p, &bytes).await?; key_path = Some(p);
            }
            _ => {}
        }
    }
    let policy = policy_path.ok_or_else(|| ApiError::BadRequest("missing policy field".into()))?;
    let key    = key_path.ok_or_else(|| ApiError::BadRequest("missing key field".into()))?;
    Ok(Json(run_cli(&[
        "sign",
        "--policy", policy.to_str().unwrap(),
        "--key",    key.to_str().unwrap(),
    ]).await?))
}

/// POST /api/v1/policy/verify
/// multipart: `policy` (the .sig file)
pub async fn verify(State(_): State<Arc<AppState>>, mut mp: Multipart)
    -> Result<Json<ActionResponse>, ApiError>
{
    let tmpdir = tempdir()?;
    let mut sig_path = None;
    while let Some(field) = mp.next_field().await.map_err(|e| ApiError::BadRequest(e.to_string()))? {
        if field.name() == Some("policy") {
            let bytes = field.bytes().await.map_err(|e| ApiError::BadRequest(e.to_string()))?;
            let p = tmpdir.path().join("policy.sig");
            tokio::fs::write(&p, &bytes).await?;
            sig_path = Some(p);
        }
    }
    let sig = sig_path.ok_or_else(|| ApiError::BadRequest("missing policy field".into()))?;
    Ok(Json(run_cli(&["verify", "--policy", sig.to_str().unwrap()]).await?))
}

fn tempdir() -> std::io::Result<tempfile::TempDir> { tempfile::tempdir() }
```

> Requires `tempfile` as a regular dep (it's already in `[dev-dependencies]` — promote it to `[dependencies]`).

### 4.15 `src/main.rs` — integration patch

Find the section in `main.rs` where the existing gRPC server task is spawned (`let server_task = task::spawn({ ... start_server(...) ... });`). Add the following **directly below it**:

```rust
// === REST Admin API (axum) on :8443 ===
let api_state = sgx_guardian_client::api::state::AppState::from_env(node_id.clone());
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

The new task is independent of the gRPC server. If it dies, gRPC keeps running. If gRPC dies, the API keeps running. No shared state between them beyond the filesystem.

---

## 5. Integration Details

**Port layout on a running board:**

| Port | Protocol | Purpose | Who talks to it |
|---|---|---|---|
| 50051 | gRPC + mTLS | Ping / cert / peer exchange (existing) | Other boards |
| 50061 | gRPC plaintext | Cert bootstrap (existing, nodeA only) | Boards joining Circle |
| 50062 | gRPC | Registry sync (existing) | Other boards |
| 50151-53 | gRPC | Attestation (existing) | Other boards |
| 4242 | UDP | Nebula overlay (existing) | Other boards |
| **8443** | **HTTPS + JWT** | **Admin REST API (new)** | **Admin console / mobile app** |
| 9090 | HTTP | Prometheus metrics (existing, localhost only) | Prometheus scraper |

**TLS:** for phase 1 use the same `device_<node>_cert.der` the gRPC server uses. axum wraps it with `axum-server` + rustls. For phase 1.5 we issue a CN=admin.sgx-guardian.local cert signed by the CA so browsers accept it. JWT auth middleware is scoped for phase 2; for phase 1 we rely on the mobile app shipping a pre-shared JWT the board validates.

**Startup order:** The API server waits on nothing. It can boot before the daemon has written any state files — each handler returns `404 NOT_FOUND` with a clear message ("daemon not started?") if its source file is missing. This is intentional so the frontend never hangs during board boot.

**Graceful shutdown:** axum's `serve()` respects tokio task cancellation. On SIGTERM, the main task cancels both tasks and exits.

---

## 6. Testing Guide

### 6.1 Local dev (no board, software mode)

```bash
# Terminal 1 - build + run the daemon in software mode
cargo build --release
./target/release/sgx_guardian_client nodeA 50051

# Terminal 2 - check the API is live
curl -s http://localhost:8443/api/v1/health
# -> "ok"
```

### 6.2 Cross-check each endpoint against the CLI

For every endpoint, the test is: **run the CLI command, run the HTTP call, diff the payload**. Payloads should carry the same information even if shapes differ.

```bash
# 1. Node status
sgx-pa-cli status --node nodeA
curl -s "http://localhost:8443/api/v1/node/status?node=nodeA" | jq

# 2. Boot status
sgx-pa-cli boot-status
curl -s http://localhost:8443/api/v1/node/boot-status | jq

# 3. Peers
sgx-pa-cli peers
curl -s http://localhost:8443/api/v1/peers | jq '.peers'

# 4. Attestation
sgx-pa-cli attestation
curl -s http://localhost:8443/api/v1/attestation | jq

# 5. Logs
sgx-pa-cli logs --node nodeA --tail 20
curl -s "http://localhost:8443/api/v1/logs?node=nodeA&tail=20" | jq '.entries | length'

# 6. DKP status
sgx-pa-cli dkp-status
curl -s http://localhost:8443/api/v1/dkp/status | jq

# 7. PCR status
sgx-pa-cli pcr-status
curl -s http://localhost:8443/api/v1/pcr/status | jq '.integrityStatus'
```

### 6.3 Action endpoints

```bash
# DKP rotate
curl -s -X POST http://localhost:8443/api/v1/dkp/rotate | jq
# Expect: { "success": true, "stdout": "... DKP rotated: v1 > v2 ...", "restartRequired": true, ... }

# DKP revoke
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"version":1,"reason":"testing"}' \
  http://localhost:8443/api/v1/dkp/revoke | jq

# PCR baseline create
curl -s -X POST http://localhost:8443/api/v1/pcr/baseline/create | jq

# PCR baseline verify
curl -s -X POST http://localhost:8443/api/v1/pcr/baseline/verify | jq

# Sign a policy (multipart)
curl -s -X POST \
  -F "policy=@/etc/sgx-guardian/policies/policy.yaml" \
  -F "key=@/home/admin/guardian_private.key" \
  http://localhost:8443/api/v1/policy/sign | jq

# Verify a signed policy
curl -s -X POST \
  -F "policy=@/etc/sgx-guardian/policies/policy.yaml.sig" \
  http://localhost:8443/api/v1/policy/verify | jq
```

### 6.4 Pointing the frontend at our board

Frontend repo uses `VITE_API_URL` env var (see `src/app/services/api.ts` line 3). To point it at a real board:

```bash
cd SGX-gaurdian-admi-console-FE
VITE_API_URL=http://192.168.50.101:8443/api/v1 make run
```

If our response shapes differ from the mock's shapes, the React components will render blank/wrong. We follow the shapes in section 3 as closely as possible to the mock, but there **are minor differences** (we use `peerId`/`lastSeen`/`camelCase` consistently where the mock has `peer_id`/`timestamp`/mixed). Karan will have to tweak field names in his hooks — call this out in the email.

---

## 7. Email Draft for Frontend Team

> **To:** Aditya Sharma, Karan Panchal, Kartikaye Madhok
> **Cc:** Abdullah, Manish, James, Pouya, Haroon
> **Subject:** SG-X Guardian — Backend REST API scope, questions before we start coding

Hi Aditya, Karan, Kartikaye,

Thanks for pushing the mock server + hooks to the `develop` branch — it gave us exactly what we needed to plan the real backend API cleanly. We finished walking through the repo (hooks in `useApiData.ts`, services in `src/app/services/`, every screen under `src/app/screens/`) and mapped each of the 15 `sgx-pa-cli` commands to the places you actually call them from.

Before we cut the first Rust handler, we need to lock down a few things so we don't build endpoints that nobody consumes, or skip ones you're about to wire up.

**1. Confirm the 12 endpoints we're building in phase 1**

From the code audit, these are the only commands currently hitting a service method or about to (via UI dialogs that exist but aren't wired yet):

- Read, already wired and working: `boot-status`, `attestation`, `logs`, `dkp-status`, `pcr-status`
- Action, UI exists but handler not yet connected: `dkp-rotate`, `dkp-revoke`, `emergency-rotate`, `pcr-baseline-create`, `pcr-baseline-verify`, `policy/sign`, `policy/verify`

Can you confirm (a) this list is correct and (b) you will wire up the click handlers for the action dialogs (KM01KeyManagement, IN01IntegrityDashboard, PL01PolicyManagement) once we ship those endpoints? Right now the `showRotateDialog`, `showRevokeDialog`, `showEmergencyDialog`, `isSigning`, `isVerifying`, `showCreateBaselineDialog` states open the dialogs but the service methods (`dkpService.rotate`, `policyService.sign`, etc.) are never called.

**2. Two dead hooks — are they intentional?**

We see `useNodeStatus` and `usePeers` defined in `useApiData.ts` but not imported by any screen. Dashboard uses `useGuardianInfo` instead of `useNodeStatus`, and NetworkTopology uses `useDevices`+`useCircles` instead of `usePeers`. Are these (a) deprecated, (b) held for a future screen, or (c) an oversight we should wire up? We'll skip them if they're deprecated.

**3. Four endpoint groups with no backend equivalent**

These are hit heavily by your hooks but have no `sgx-pa-cli` command backing them today:

- `GET /api/guardian/info` — dashboard device info card
- `GET /api/guardian/threat-intel` — Security Health Score on the dashboard
- `GET /api/alerts` + `PUT :id/read` + `PUT :id/dismiss` + `/summary` — Alerts tab, 4 screens
- `GET /api/circles` + POST/PUT/DELETE members — Circles tab, 3 screens
- `GET /api/devices` + POST `:id/attest` — Devices tab, 4 screens

Three questions: (a) where is the source of truth for alerts — are they device-generated security events (our side) or user-created notifications (your side)? (b) is "circles" in your model the same entity as our Circle of Trust (Nebula overlay peer group)? If yes, we own it; if it's a UI grouping concept, you own it. (c) `/guardian/threat-intel` returns a score — where does that number come from?

We can either build all four endpoint groups on our side if they're device-data, or leave them on your mock/Supabase if they're app-layer data. We just need to know.

**4. API shape differences vs your mock**

We're going to match your mock field names where possible, but there are a few places we'll use camelCase consistently (`peerId`, `lastSeen`) where the mock mixes styles (`peer_id`, `timestamp`). We can send you the exact OpenAPI schema before shipping, or we can match the mock exactly — your call. Recommend we go with a clean schema since the mock is disposable.

**5. Logistics**

- **Repo access** — Pouya, any update on the Cyberzeus team getting read access to `Cervais/SGX-gaurdian-admi-console-FE`? We've been working off the ZIP, but for real integration we need to track your branch.
- **Base URL / discovery** — how does the mobile app find the board IP? Manual entry, mDNS, or cloud relay? This affects whether we need a discovery endpoint.
- **Auth** — your `Auth_and_Realtime.docx` mentions JWT. Who issues tokens and where does the user DB live? The board doesn't have user accounts today.
- **Real-time** — for peer-status changes, attestation events, and PCR mismatches, we'd like to ship a WebSocket endpoint `/api/v1/ws/events`. Does that fit your plan or are you polling?

Once we have answers on 1-4, we'll cut a branch `feature/rest-api` off main and have the phase-1 read endpoints up on a test board within the week. Phase 2 (action endpoints) follows right after once you confirm the dialog handlers.

Thanks,
Asad
CyberZeus Backend / Security Engineering

---

## 8. Repo Integration Checklist (for the PR)

- [ ] `Cargo.toml`: add `axum = { version = "0.7", features = ["macros","multipart"] }`, `tower-http = { version = "0.5", features = ["cors","trace"] }`, promote `tempfile` from dev-deps to deps.
- [ ] `src/lib.rs`: add `pub mod api;`
- [ ] `src/api/`: create module tree as in section 4.1.
- [ ] `src/main.rs`: insert the `tokio::spawn` block from section 4.15 **directly below** the existing `start_server` task spawn.
- [ ] Verify gRPC server at `:50051` still responds to `grpcurl` after the change.
- [ ] Run `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`.
- [ ] Add integration test `tests/test_api.rs` that boots the router on a random port, hits `/health`, and expects `200 ok`.
- [ ] Run the CI pipeline — no new Clippy warnings, Semgrep clean, cargo-audit clean.
- [ ] Create a branch `feature/rest-api`, open a PR, request review before the meeting with the frontend team.
