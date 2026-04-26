# SG-X Guardian — REST API Development & Deployment Plan

**Date:** April 26, 2026
**Author:** Asad Ali — Backend / Security Engineering
**Status:** Phase 1 (7 read endpoints) — LIVE and confirmed by frontend team
**Scope:** Complete all 15 endpoints, test, deploy, and hand off to frontend

---

## Executive Summary

The frontend team (Karan, April 25) confirmed 7 read-only endpoints are live and rendering real data from our Rust/axum backend on `:8443`. Mock data has been completely removed from their codebase. Every page now shows "Server" or "Offline" — no more fake data.

After auditing the updated frontend code (`SGX_Frontend.zip` received April 25), here is the verified state of all 15 API endpoints:

| Status | Count | Endpoints |
|--------|-------|-----------|
| **LIVE & CONFIRMED** | 7 | node/status, node/boot-status, peers, attestation, logs, dkp/status, pcr/status |
| **CODED but not yet tested on board** | 7 | dkp/rotate, dkp/revoke, dkp/emergency-rotate, pcr/baseline/create, pcr/baseline/verify, policy/sign, policy/verify |
| **NOT YET CODED** | 1 | node/restart |
| **TOTAL** | **15** | |

Key finding: the 7 action endpoints are **already written** in our `src/api/handlers/` (dkp.rs, pcr.rs, policy.rs) and **already registered** in `src/api/mod.rs`. They shell out to `sgx-pa-cli` subcommands. What remains is: add the missing `node/restart` endpoint, test all 8 action endpoints on hardware, and tell the frontend team to wire up their click handlers.

---

## 1. Frontend Audit — What Changed (April 25 Update)

### What they DID (confirmed from code):

1. **Removed ALL mock data** — `useApiData.ts` no longer imports any mock data. The `fetchWithFallback` helper now throws errors instead of falling back.
2. **Hardcoded our API URL** — `api.ts` line 3: `const API_BASE_URL = "http://localhost:8443/api/v1"`
3. **Added backend response type mappings** — each updated service file now has a `BackendXxxResponse` interface that maps our camelCase JSON fields to their internal display model. They did this for: `nodeService`, `peerService`, `attestationService`, `logService`, `dkpService`, `pcrService`, `guardianService`.
4. **`guardianService.getInfo()`** now calls our `/node/status` endpoint (not a separate `/guardian/info`), which is smart — they reuse our existing endpoint.

### What they did NOT do:

1. **Action handlers still fake** — `KM01KeyManagement.tsx` `handleRotate()` still creates a fake key in local React state. It does NOT call `dkpService.rotate()`. Same for revoke, emergency-rotate.
2. **Integrity actions still fake** — `IN01IntegrityDashboard.tsx` has `showCreateBaselineDialog` and `isVerifying` but never calls `pcrService.verify()` or `pcrService.updateBaseline()`.
3. **Policy actions still fake** — `PL01PolicyManagement.tsx` has `isSigning`/`isVerifying` flags but no service call.
4. **Services not updated**: `alertService.ts`, `circleService.ts`, `deviceService.ts`, `policyService.ts` — still from April 13 (unchanged, still pointing to mock-style endpoints that don't exist on our backend).
5. **Four endpoint groups with no backend**: `/alerts`, `/circles`, `/devices`, `/guardian/threat-intel` — they acknowledge this with comments in `useApiData.ts`: "Note: No backend endpoint exists yet".

---

## 2. Complete API Endpoint Matrix (All 15)

### Phase 1 — Read Endpoints (DONE, LIVE)

| # | Method | Path | CLI command | Handler file | Frontend service | Frontend hook | Screen | Status |
|---|--------|------|-------------|-------------|-----------------|--------------|--------|--------|
| 1 | GET | `/api/v1/node/status` | `status` | `node.rs` | `nodeService.getStatus()` | `useNodeStatus` + `useGuardianInfo` | Dashboard, GuardianDetail | **LIVE** |
| 2 | GET | `/api/v1/node/boot-status` | `boot-status` | `node.rs` | `nodeService.getBootStatus()` | `useBootStatus` | SC01BootStatus | **LIVE** |
| 3 | GET | `/api/v1/peers` | `peers` | `peers.rs` | `peerService.getAll()` | `usePeers` | NW03PeersList | **LIVE** |
| 4 | GET | `/api/v1/attestation` | `attestation` | `attestation.rs` | `attestationService.getResults()` | `useAttestationResults` | SC02AttestationStatus | **LIVE** |
| 5 | GET | `/api/v1/logs` | `logs` | `logs.rs` | `logService.getLogs()` | `useLogs` | LG01LogsViewer | **LIVE** |
| 6 | GET | `/api/v1/dkp/status` | `dkp-status` | `dkp.rs` | `dkpService.getStatus()` | `useDKPStatus` | KM01KeyManagement | **LIVE** |
| 7 | GET | `/api/v1/pcr/status` | `pcr-status` | `pcr.rs` | `pcrService.getStatus()` | `usePCRStatus` | IN01IntegrityDashboard | **LIVE** |

### Phase 2 — Action Endpoints (CODED in backend, need testing + frontend wiring)

| # | Method | Path | CLI command | Handler file | Frontend service method | Frontend click handler | Status |
|---|--------|------|-------------|-------------|------------------------|----------------------|--------|
| 8 | POST | `/api/v1/dkp/rotate` | `dkp-rotate` | `dkp.rs` | `dkpService.rotate()` | `handleRotate()` — local state only | **CODED, UNTESTED** |
| 9 | POST | `/api/v1/dkp/revoke` | `dkp-revoke` | `dkp.rs` | `dkpService.revoke()` | `handleRevoke()` — local state only | **CODED, UNTESTED** |
| 10 | POST | `/api/v1/dkp/emergency-rotate` | `emergency-rotate` | `dkp.rs` | `dkpService.emergencyRotate()` | `handleEmergencyRotate()` — toast only | **CODED, UNTESTED** |
| 11 | POST | `/api/v1/pcr/baseline/create` | `pcr-baseline-create` | `pcr.rs` | `pcrService.updateBaseline()` | `showCreateBaselineDialog` — not connected | **CODED, UNTESTED** |
| 12 | POST | `/api/v1/pcr/baseline/verify` | `pcr-baseline-verify` | `pcr.rs` | `pcrService.verify()` | `isVerifying` flag — not connected | **CODED, UNTESTED** |
| 13 | POST | `/api/v1/policy/sign` | `sign` | `policy.rs` | `policyService.sign()` | `isSigning` flag — not connected | **CODED, UNTESTED** |
| 14 | POST | `/api/v1/policy/verify` | `verify` | `policy.rs` | `policyService.verify()` | `isVerifying` flag — not connected | **CODED, UNTESTED** |

### Phase 3 — Missing Endpoint (NEEDS IMPLEMENTATION)

| # | Method | Path | Purpose | Handler file | Frontend service method |
|---|--------|------|---------|-------------|------------------------|
| 15 | POST | `/api/v1/node/restart` | Restart guardian daemon | `node.rs` (ADD) | `nodeService.restart()` |

---

## 3. Development Plan — Tasks & Timeline

### Task 1: Implement `POST /node/restart` (Day 1)

Add to `src/api/handlers/node.rs`:

```rust
pub async fn restart(State(_): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, ApiError> {
    // Kill the daemon — systemd will auto-restart it (if configured),
    // otherwise the board will need manual restart.
    let out = tokio::process::Command::new("pkill")
        .args(&["-f", "sgx_guardian_client"])
        .output().await
        .map_err(|e| ApiError::Internal(format!("restart failed: {}", e)))?;
    Ok(Json(serde_json::json!({
        "success": out.status.success(),
        "message": "Guardian daemon restart initiated",
        "expectedDowntime": "5-10 seconds",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}
```

Add route to `src/api/mod.rs`:
```rust
.route("/api/v1/node/restart", post(handlers::node::restart))
```

### Task 2: Test All 8 Action Endpoints on Hardware (Day 1-2)

SSH into each board via AnyDesk and run these verification commands:

```bash
# 8. DKP Rotate
curl -s -X POST http://localhost:8443/api/v1/dkp/rotate | jq
# Verify: success=true, stdout contains "DKP rotated"

# 9. DKP Revoke
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"version":1,"reason":"testing"}' \
  http://localhost:8443/api/v1/dkp/revoke | jq

# 10. Emergency Rotate
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"reason":"test"}' \
  http://localhost:8443/api/v1/dkp/emergency-rotate | jq

# 11. PCR Baseline Create
curl -s -X POST http://localhost:8443/api/v1/pcr/baseline/create | jq

# 12. PCR Baseline Verify
curl -s -X POST http://localhost:8443/api/v1/pcr/baseline/verify | jq

# 13. Policy Sign (multipart)
curl -s -X POST \
  -F "policy=@/etc/sgx-guardian/policies/policy.yaml" \
  -F "key=@guardian_private.key" \
  http://localhost:8443/api/v1/policy/sign | jq

# 14. Policy Verify
curl -s -X POST \
  -F "policy=@/etc/sgx-guardian/policies/policy.yaml.sig" \
  http://localhost:8443/api/v1/policy/verify | jq

# 15. Node Restart
curl -s -X POST http://localhost:8443/api/v1/node/restart | jq
```

### Task 3: Fix Any Path/Permission Issues on Board (Day 2)

Known risks from previous sprints:
- `sgx-pa-cli` must be on `$PATH` for the `run_cli()` helper to find it
- Action endpoints need write permissions to `/var/lib/sgx-guardian/keys/` and `/etc/sgx-guardian/`
- `tempfile` crate must be in regular deps (not just dev-deps) for policy sign/verify multipart handling

### Task 4: Validate Frontend Field Mapping (Day 2)

Cross-check our response shapes against the `BackendXxxResponse` interfaces the frontend defined. Confirmed matching fields:

| Endpoint | Our field names | Their mapping interface | Match? |
|----------|----------------|----------------------|--------|
| /node/status | `nodeId`, `hostname`, `ip`, `port`, `publicKey`, `timestamp` | `BackendNodeStatus` | **YES** |
| /node/boot-status | `habEnabled`, `deviceClosed`, `habEventsFound`, `deviceModel`, `kernelVersion`, `bootChainIntact`, `guardianBinaryHash`, `trustChain[].stage/status`, `timestamp` | `BackendBootStatus` | **YES** |
| /peers | `peers[].peerId/ip/status/lastSeen`, `total`, `timestamp` | `PeersResponse` | **YES** |
| /attestation | `peerId`, `policyDigest`, `result`, `timestamp` | `BackendLastAttestation` | **YES** |
| /logs | `node`, `file`, `entries[].timestamp/level/message`, `total`, `timestamp` | `BackendLogsResponse` | **YES** |
| /dkp/status | `totalVersions`, `activeVersion`, `se050Available`, `activePublicKeyPath`, `activePublicKeySize`, `keys[].version/keyId/algorithm/status/createdAt/rotatedFrom` | `BackendDkpStatus` | **YES** |
| /pcr/status | `node`, `registers[].index/name/value`, `compositeDigest`, `compositeSignature`, `integrityStatus`, `deviceUid`, `keyVersion`, `measuredAt`, `schemaVersion` | `BackendPcrStatus` | **YES** |

All 7 read endpoints have confirmed matching shapes. The frontend does the internal transformation in each service file.

### Task 5: Deploy Updated Binary to All 3 Boards (Day 3)

```bash
# Cross-compile
cargo build --release --target aarch64-unknown-linux-gnu

# Deploy to each board
scp target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@192.168.50.101:/usr/local/bin/
scp target/aarch64-unknown-linux-gnu/release/sgx-pa-cli root@192.168.50.101:/usr/local/bin/

# Restart daemon
ssh root@192.168.50.101 "systemctl restart sgx-guardian || pkill -f sgx_guardian_client && nohup sgx_guardian_client nodeA 50051 &"
```

### Task 6: Send Confirmation Email to Frontend Team (Day 3)

See email draft in Section 5.

---

## 4. Route Path Alignment Note

The frontend uses paths like `/dkp/rotate` while our router registers `/api/v1/dkp/rotate`. This works because their `api.ts` sets `API_BASE_URL = "http://localhost:8443/api/v1"` and their service calls use relative paths like `api.post('/dkp/rotate')`. The client prepends the base URL, so the final request is `POST http://localhost:8443/api/v1/dkp/rotate` — exactly what our router expects.

One mismatch to watch: their `pcrService.updateBaseline()` calls `POST /pcr/baseline/update` but our route is `POST /pcr/baseline/create`. We either need to:
- **(A)** Add an alias route: `.route("/api/v1/pcr/baseline/update", post(handlers::pcr::baseline_create))` — **recommended, 1 line**
- **(B)** Ask frontend to change their path

Same for `pcrService.verify()` → they call `POST /pcr/verify` but our route is `POST /pcr/baseline/verify`. Add alias:
```rust
.route("/api/v1/pcr/verify", post(handlers::pcr::baseline_verify))
```

---

## 5. Email Draft — Confirmation to Frontend Team

> **To:** Aditya Sharma, Karan Panchal, Kartikaye Madhok
> **Cc:** Abdullah, Manish, James, Pouya, Haroon
> **Subject:** RE: SG-X Guardian — All 15 Backend REST API Endpoints Ready

Hi Karan,

Great work on removing the mock data and wiring up the 7 read endpoints. We confirmed everything is working correctly — your field mappings in `nodeService`, `peerService`, `attestationService`, `logService`, `dkpService`, `pcrService`, and `guardianService` all align perfectly with our response shapes.

We now have **all 15 backend API endpoints implemented and deployed** on port 8443. Here's the complete list:

**Already live (7 read endpoints — you confirmed these):**
1. `GET /api/v1/node/status`
2. `GET /api/v1/node/boot-status`
3. `GET /api/v1/peers`
4. `GET /api/v1/attestation`
5. `GET /api/v1/logs`
6. `GET /api/v1/dkp/status`
7. `GET /api/v1/pcr/status`

**Now also available (8 action endpoints — ready for you to wire up):**
8. `POST /api/v1/dkp/rotate` — rotates DKP key, returns `{ success, stdout, stderr, restartRequired, timestamp }`
9. `POST /api/v1/dkp/revoke` — body: `{ version: number, reason: string }`, revokes a deprecated key
10. `POST /api/v1/dkp/emergency-rotate` — body: `{ reason: string }`, rotates ALL keys (DKP + attestation + TLS)
11. `POST /api/v1/pcr/baseline/create` — creates golden PCR baseline from current snapshot
12. `POST /api/v1/pcr/baseline/verify` — verifies current PCRs against golden baseline
13. `POST /api/v1/policy/sign` — multipart: `policy` (YAML file) + `key` (private key file)
14. `POST /api/v1/policy/verify` — multipart: `policy` (signed .sig file)
15. `POST /api/v1/node/restart` — restarts the Guardian daemon, returns `{ success, message, expectedDowntime, timestamp }`

**Two route aliases we added for your convenience** (same handler, different paths to match what your services already call):
- `POST /api/v1/pcr/baseline/update` → same as `/pcr/baseline/create`
- `POST /api/v1/pcr/verify` → same as `/pcr/baseline/verify`

**Action items for your side:**
From our code review of your updated screens, we noticed the action handlers in `KM01KeyManagement.tsx`, `IN01IntegrityDashboard.tsx`, and `PL01PolicyManagement.tsx` currently do local state changes only (e.g., `handleRotate()` creates a fake new key in React state instead of calling `dkpService.rotate()`). Now that the endpoints are live, please wire those handlers to the actual service methods. All the service methods (`dkpService.rotate()`, `pcrService.verify()`, `policyService.sign()`, etc.) are already defined correctly in your service files — they just need to be called from the click handlers.

**Response format for action endpoints:**
All POST action endpoints (8-15) return the same shape:
```json
{
  "success": true,
  "stdout": "CLI output text...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-04-26T12:00:00Z"
}
```
Your UI can use `success` to show pass/fail, `stdout` for detailed output, and `restartRequired` to trigger the restart banner you already have.

**Still pending (not blocking):**
- Alerts, Circles, Devices, and Threat-Intel endpoints — we see your comments in `useApiData.ts` that these have no backend yet. We'll discuss ownership and timeline on the next call.

Let us know once you've wired up the action handlers and we'll do a joint end-to-end test.

Best,
Asad
CyberZeus Backend / Security Engineering

---

## 6. Summary Checklist

- [x] Phase 1: 7 read endpoints — LIVE, confirmed by frontend
- [x] Phase 2: 7 action endpoints — CODED in `src/api/handlers/` (dkp.rs, pcr.rs, policy.rs)
- [ ] Add `POST /node/restart` handler (15th endpoint)
- [ ] Add route aliases: `/pcr/baseline/update` and `/pcr/verify`
- [ ] Promote `tempfile` from `[dev-dependencies]` to `[dependencies]` in Cargo.toml
- [ ] Ensure `sgx-pa-cli` is on `$PATH` on all 3 boards
- [ ] Test all 8 action endpoints via curl on Board 1 (192.168.50.101)
- [ ] Cross-compile and deploy updated binary to all 3 boards
- [ ] Send confirmation email to frontend team
- [ ] Schedule joint end-to-end testing session with Karan