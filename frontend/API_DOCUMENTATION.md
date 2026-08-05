# SGX Guardian Admin Console — API Documentation

## Overview

| Property | Value |
|----------|-------|
| Base URL | `http://127.0.0.1:8443/api/v1` |
| Env Variable | `VITE_API_URL` |
| Content-Type | `application/json` (file uploads: `multipart/form-data`) |
| Backend Source | `https://github.com/Cervais/new-guardian` — branch `api` |
| Backend Framework | Axum (Rust), port `8443` |

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| BE | Implemented in backend (`api` branch) |
| BE | **Not implemented** in backend — endpoint does not exist yet |
| FE | Connected from a real UI component with user interaction |
| FE | Hook only — wired in `useApiData.ts` but no screen uses it yet |
| FE | Not connected in frontend |

---

## Summary Table

| Endpoint | Method | BE | FE | Notes |
|----------|--------|-------|-------|-------|
| `/health` | GET | | | Inline handler |
| `/node/status` | GET | | | Guardian detail screen + 30s polling |
| `/node/boot-status` | GET | | | Hook exists, no screen renders it |
| `/peers` | GET | | | Peers list screen |
| `/attestation` | GET | | | Hook exists, no screen renders it |
| `/logs` | GET | | | Hook exists, no screen renders it |
| `/dkp/status` | GET | | | Key Management screen |
| `/dkp/rotate` | POST | | | Rotate Key button |
| `/dkp/revoke` | POST | | | Revoke button |
| `/dkp/emergency-rotate` | POST | | | Emergency Rotation button |
| `/pcr/status` | GET | | | Integrity Dashboard |
| `/pcr/baseline/create` | POST | | | Create Golden Baseline button |
| `/pcr/baseline/verify` | POST | | | Verify Against Baseline button |
| `/policy/sign` | POST | | | Sign Policy file upload |
| `/policy/verify` | POST | | | Verify Policy button |
| `/attestation/verify` | POST | BE | FE | Not yet built |
| `/attestation/history` | GET | BE | FE | Not yet built |
| `/peers/:id` | GET | BE | FE | Not yet built |
| `/peers/:id/attest` | POST | BE | FE | FE calls it, BE missing |
| `/dkp/keys` | GET | BE | FE | Not yet built |
| `/dkp/shares` | GET | BE | FE | Not yet built |
| `/pcr/baseline` | GET | BE | FE | FE hook exists, BE missing |
| `/pcr/history` | GET | BE | FE | FE hook exists, BE missing |
| `/pcr/baseline/update` | POST | BE | FE | FE calls it, BE uses `/pcr/baseline/create` |
| `/policy/current` | GET | BE | FE | FE calls it, BE not built |
| `/policy/current` | PUT | BE | FE | FE calls it, BE not built |
| `/policy/sign-deploy-current` | POST | BE | FE | FE calls it, BE not built |
| `/policy/verify-deployed` | POST | BE | FE | FE calls it, BE not built |
| `/policy/backup` | GET | BE | FE | FE calls it, BE not built |
| `/policy/:id` | GET | BE | FE | Not yet built |
| `/policy` | GET | BE | FE | FE hook exists, BE not built |
| `/policy` | POST | BE | FE | Not yet built |
| `/policy/:id` | PUT | BE | FE | Not yet built |
| `/policy/:id` | DELETE | BE | FE | Not yet built |
| `/guardian/key/status` | GET | BE | FE | FE calls it, BE not built |
| `/guardian/key/generate` | POST | BE | FE | FE calls it, BE not built |
| `/guardian/status` | GET | BE | FE | Not yet built |
| `/guardian/health` | GET | BE | FE | Not yet built |
| `/guardian/metrics` | GET | BE | FE | Not yet built |
| `/guardian/restart` | POST | BE | FE | Not yet built |
| `/guardian/threat-intel` | GET | BE | FE | Not yet built |
| `/alerts` | GET | BE | FE | Not yet built |
| `/alerts/:id` | GET | BE | FE | Not yet built |
| `/alerts/:id/read` | PUT | BE | FE | Not yet built |
| `/alerts/:id/dismiss` | PUT | BE | FE | Not yet built |
| `/alerts/read-all` | PUT | BE | FE | Not yet built |
| `/alerts/:id` | DELETE | BE | FE | Not yet built |
| `/alerts/summary` | GET | BE | FE | Not yet built |
| `/circles` | GET | BE | FE | Not yet built |
| `/circles/:id` | GET | BE | FE | Not yet built |
| `/circles` | POST | BE | FE | Not yet built |
| `/circles/:id` | PUT | BE | FE | Not yet built |
| `/circles/:id` | DELETE | BE | FE | Not yet built |
| `/circles/:circleId/members` | POST | BE | FE | Not yet built |
| `/circles/:circleId/members/:memberId` | DELETE | BE | FE | Not yet built |
| `/circles/:circleId/devices` | GET | BE | FE | Not yet built |
| `/devices` | GET | BE | FE | Not yet built |
| `/devices/:id` | GET | BE | FE | Not yet built |
| `/devices` | POST | BE | FE | Not yet built |
| `/devices/:id` | PUT | BE | FE | Not yet built |
| `/devices/:id` | DELETE | BE | FE | Not yet built |
| `/devices/:id/attest` | POST | BE | FE | Not yet built |
| `/discovery/devices` | GET | | | Network Discovery screen — inventory (30s polling) |
| `/discovery/list` | GET | | | Alias of `/discovery/devices` (service method) |
| `/discovery/inventory/list` | GET | | | Alias of `/discovery/devices` (service method) |
| `/discovery/devices/unauthorized` | GET | | | Network Discovery — "flagged only" filter |
| `/discovery/unauthorized` | GET | | | Alias of unauthorized list (service method) |
| `/discovery/scan` | POST | | | Default-intensity scan button |
| `/discovery/scan/stealth` | POST | | | Stealth scan button |
| `/discovery/scan/standard` | POST | | | Standard scan button |
| `/discovery/scan/aggressive` | POST | | | Aggressive scan button |
| `/discovery/approve` | POST | | | Approve device dialog |
| `/discovery/whitelist` | GET | | | Whitelist tab (editor) |
| `/discovery/whitelist` | PUT | | | Save whitelist |
| `/discovery/schedule` | GET | | | Schedule tab (config form) |
| `/discovery/schedule` | PUT | | | Save schedule |

---

## Endpoint Details

---

### 1. Health

#### BE · FE — `GET /health`
Verify API server availability.

**Response**
```
"ok"
```

---

### 2. Node

**Backend:** `src/api/handlers/node.rs`

#### BE · FE — `GET /node/status`
Get SGX Guardian node status. Called in `HM02GuardianDetail.tsx` with 30-second polling.
Reads `{config_dir}/{node}.yaml`.

**Query Params**

| Param | Type | Description |
|-------|------|-------------|
| `node` | string | Node name (defaults to current node ID) |

**Response**
```json
{
 "nodeId": "string",
 "hostname": "string",
 "ip": "string",
 "port": 8443,
 "publicKey": "string",
 "timestamp": "2026-01-01T00:00:00Z"
}
```

---

#### BE · FE — `GET /node/boot-status`
Get node boot / HAB status. Hook `useBootStatus()` exists but no screen renders it.
Reads HAB fuse, kernel version, and binary hash from system.

**Response**
```json
{
 "habEnabled": true,
 "deviceClosed": true,
 "habEventsFound": true,
 "deviceModel": "string",
 "kernelVersion": "string",
 "bootChainIntact": true,
 "guardianBinaryHash": "string",
 "trustChain": [
 { "stage": "string", "status": "string" }
 ],
 "timestamp": "2026-01-01T00:00:00Z"
}
```

---

### 3. Peers

**Backend:** `src/api/handlers/peers.rs`
Reads `trusted_peers.json` from log directories.

#### BE · FE — `GET /peers`
List all peers. Displayed in `NW03PeersList.tsx`.

**Response**
```json
{
 "peers": [
 {
 "peerId": "string",
 "ip": "string",
 "status": "string",
 "lastSeen": "string"
 }
 ],
 "total": 0,
 "timestamp": "2026-01-01T00:00:00Z"
}
```

---

#### BE · FE — `POST /peers/:id/attest`
Attest a peer. FE calls this from the **Attest** button in `NW03PeersList.tsx`. **Backend not yet implemented.**

**Path Params** — `id`: peer ID

**Expected Response**
```json
{
 "success": true,
 "peerId": "string",
 "message": "string",
 "timestamp": "string"
}
```

---

#### BE · FE — `GET /peers/:id`
Get peer details. Not built on either side.

---

### 4. Attestation

**Backend:** `src/api/handlers/attestation.rs`
Reads `last_attestation.json` from log directories.

#### BE · FE — `GET /attestation`
Get last attestation result. Hook `useAttestationResults()` exists but no screen renders it.

**Response**
```json
{
 "peerId": "string",
 "policyDigest": "string",
 "result": "string",
 "timestamp": "string"
}
```

---

#### BE · FE — `POST /attestation/verify`
Not built on either side.

---

#### BE · FE — `GET /attestation/history`
Not built on either side.

---

### 5. Logs

**Backend:** `src/api/handlers/logs.rs`
Reads log files from primary and fallback log directories, parses JSON or plain-text lines.

#### BE · FE — `GET /logs`
Get SGX Guardian logs. Hook `useLogs()` exists but no screen renders it.

**Query Params**

| Param | Type | Description |
|-------|------|-------------|
| `node` | string | Node name (defaults to current node ID) |
| `tail` | number | Number of recent lines to return (max 1000, default 100) |
| `level` | string | Filter by log level (`info`, `warn`, `error`, `all`) |
| `search` | string | Search term (case-insensitive substring match on message) |

**Response**
```json
{
 "node": "string",
 "file": "string",
 "entries": [
 {
 "timestamp": "string",
 "level": "string",
 "message": "string"
 }
 ],
 "total": 0,
 "timestamp": "2026-01-01T00:00:00Z"
}
```

---

### 6. DKP (Distributed Key Protocol)

**Backend:** `src/api/handlers/dkp.rs`
All action endpoints invoke `sgx-pa-cli` as a subprocess.

#### BE · FE — `GET /dkp/status`
Get DKP key management status. Displayed in `KM01KeyManagement.tsx`.
Reads `dkp_metadata.json` and `dkp_pub.der` from keys directory.

**Response**
```json
{
 "totalVersions": 0,
 "activeVersion": 1,
 "se050Available": true,
 "activePublicKeyPath": "string",
 "activePublicKeySize": 91,
 "keys": [
 {
 "version": 1,
 "keyId": "string",
 "algorithm": "ECDSA-P256",
 "status": "Active",
 "createdAt": "string",
 "rotatedFrom": "string"
 }
 ]
}
```

---

#### BE · FE — `POST /dkp/rotate`
Rotate the DKP key. Triggered by **Rotate Key** button in `KM01KeyManagement.tsx`.
Runs: `sgx-pa-cli dkp-rotate`

**Response**
```json
{
 "success": true,
 "stdout": "string",
 "stderr": "string",
 "restartRequired": true,
 "timestamp": "2026-01-01T00:00:00Z"
}
```

---

#### BE · FE — `POST /dkp/revoke`
Revoke a DKP key version. Triggered by **Revoke** button in `KM01KeyManagement.tsx`.
Runs: `sgx-pa-cli dkp-revoke --version <v> --reason <r>`

**Request Body**
```json
{ "version": 1, "reason": "string (optional)" }
```

**Response** — same as `/dkp/rotate`

---

#### BE · FE — `POST /dkp/emergency-rotate`
Emergency rotate the DKP key. Triggered by **Emergency Rotation** button in `KM01KeyManagement.tsx`.
Runs: `sgx-pa-cli emergency-rotate --reason <r>`

**Request Body**
```json
{ "reason": "string (optional)" }
```

**Response** — same as `/dkp/rotate`

---

#### BE · FE — `GET /dkp/keys`
Not built on either side.

#### BE · FE — `GET /dkp/shares`
Not built on either side.

---

### 7. PCR (Platform Configuration Registers)

**Backend:** `src/api/handlers/pcr.rs`
Action endpoints invoke `sgx-pa-cli` as a subprocess.

> **Note:** The backend uses `/pcr/baseline/create` and `/pcr/baseline/verify`. The frontend calls `/pcr/baseline/update` and `/pcr/verify` — these paths need to be aligned.

#### BE · FE — `GET /pcr/status`
Get PCR / TPM status. Displayed in `IN01IntegrityDashboard.tsx`.
Reads `{node_id}_current.json` from PCR directory.

**Response**
```json
{
 "node": "string",
 "registers": [
 { "index": 0, "name": "BIOS/Bootloader", "value": "string" },
 { "index": 1, "name": "Firmware/DTB", "value": "string" },
 { "index": 2, "name": "Kernel", "value": "string" },
 { "index": 3, "name": "RootFS", "value": "string" },
 { "index": 4, "name": "Configuration", "value": "string" }
 ],
 "compositeDigest": "string",
 "compositeSignature": "string",
 "integrityStatus": "VERIFIED | MISMATCH | UNKNOWN",
 "deviceUid": "string",
 "keyVersion": 1,
 "measuredAt": "string",
 "schemaVersion": 1
}
```

---

#### BE · FE — `POST /pcr/baseline/create`
Create a PCR golden baseline. Triggered by **Create Golden Baseline** button in `IN01IntegrityDashboard.tsx`.
Runs: `sgx-pa-cli pcr-baseline-create`

> **Path mismatch:** FE calls `/pcr/baseline/update` — needs to be updated to `/pcr/baseline/create`.

**Response**
```json
{
 "success": true,
 "stdout": "string",
 "stderr": "string",
 "restartRequired": true,
 "timestamp": "2026-01-01T00:00:00Z"
}
```

---

#### BE · FE — `POST /pcr/baseline/verify`
Verify PCR against the baseline. Triggered by **Verify Against Baseline** button in `IN01IntegrityDashboard.tsx`.
Runs: `sgx-pa-cli pcr-baseline-verify`

> **Path mismatch:** FE calls `/pcr/verify` — needs to be updated to `/pcr/baseline/verify`.

**Response** — same as `/pcr/baseline/create`

---

#### BE · FE — `GET /pcr/baseline`
FE hook `usePCRBaseline()` exists and is used in the Integrity Dashboard. Backend not implemented.

#### BE · FE — `GET /pcr/history`
FE hook `usePCRHistory()` exists and is used in the Integrity Dashboard. Backend not implemented.

---

### 8. Policy

**Backend:** `src/api/handlers/policy.rs`
Both endpoints accept `multipart/form-data` and invoke `sgx-pa-cli`.

#### BE · FE — `POST /policy/sign`
Sign a policy file. Triggered by **Sign Policy** file upload in `PL01PolicyManagement.tsx`.
Runs: `sgx-pa-cli sign --policy <file> --key <key_file>`

**Content-Type:** `multipart/form-data`

| Field | Type | Required |
|-------|------|----------|
| `policy` | File (YAML) | Yes |
| `key` | File (PKCS8) | Yes |

**Response**
```json
{
 "success": true,
 "stdout": "string",
 "stderr": "string",
 "restartRequired": true,
 "timestamp": "2026-01-01T00:00:00Z"
}
```

---

#### BE · FE — `POST /policy/verify`
Verify a signed policy. Triggered by **Verify Policy** button in `PL01PolicyManagement.tsx`.
Runs: `sgx-pa-cli verify --policy <sig_file>`

**Content-Type:** `multipart/form-data`

| Field | Type | Required |
|-------|------|----------|
| `policy` | File (`.sig`) | Yes |

**Response** — same as `/policy/sign`

---

#### BE · FE — `GET /policy/current`
FE loads active policy YAML for editing. Backend not implemented.

#### BE · FE — `PUT /policy/current`
FE saves edited policy YAML. Backend not implemented.

#### BE · FE — `POST /policy/sign-deploy-current`
FE triggers sign + deploy of current policy. Backend not implemented.

#### BE · FE — `POST /policy/verify-deployed`
FE verifies deployed policy signature. Backend not implemented.

#### BE · FE — `GET /policy/backup`
FE loads backup policy YAML. Backend not implemented.

#### BE · FE — `GET /policy` / `GET /policy/:id` / `POST /policy` / `PUT /policy/:id` / `DELETE /policy/:id`
Not built on either side.

---

### 9. Guardian

#### BE · FE — `GET /guardian/key/status`
FE loads key status on the **Keys** tab of `PL01PolicyManagement.tsx`. Backend not implemented.

**Expected Response**
```json
{
 "exists": true,
 "privateKeyExists": true,
 "publicKeyExists": true,
 "privateKeyPath": "string",
 "publicKeyPath": "string",
 "provider": "string",
 "algorithm": "string",
 "fingerprint": "string"
}
```

---

#### BE · FE — `POST /guardian/key/generate`
FE triggers key generation. Backend not implemented.

**Request Body**
```json
{ "force": false }
```

**Expected Response**
```json
{
 "success": true,
 "alreadyExists": false,
 "provider": "string",
 "algorithm": "string",
 "stdout": "string",
 "stderr": "string",
 "privateKeyPath": "string",
 "publicKeyPath": "string",
 "restartRequired": false,
 "fingerprint": "string",
 "backups": []
}
```

---

#### BE · FE — `GET /guardian/status`
Not built on either side.

#### BE · FE — `GET /guardian/health`
Not built on either side.

#### BE · FE — `GET /guardian/metrics`
Not built on either side.

#### BE · FE — `POST /guardian/restart`
Not built on either side.

#### BE · FE — `GET /guardian/threat-intel`
FE hook exists with a note: "no backend endpoint exists yet."

---

### 10. Alerts

All alert endpoints — `GET /alerts`, `GET /alerts/:id`, `PUT /alerts/:id/read`, `PUT /alerts/:id/dismiss`, `PUT /alerts/read-all`, `DELETE /alerts/:id`, `GET /alerts/summary` — are ** BE · FE** (not built on either side).

---

### 11. Circles

All circle endpoints — `GET /circles`, `GET /circles/:id`, `POST /circles`, `PUT /circles/:id`, `DELETE /circles/:id`, `POST /circles/:circleId/members`, `DELETE /circles/:circleId/members/:memberId`, `GET /circles/:circleId/devices` — are ** BE · FE** (not built on either side).

---

### 12. Devices

All device endpoints — `GET /devices`, `GET /devices/:id`, `POST /devices`, `PUT /devices/:id`, `DELETE /devices/:id`, `POST /devices/:id/attest` — are ** BE · FE** (not built on either side).

---

### 13. Network Discovery (NMAP)

NMAP-based network discovery subsystem (Sprint 6, NMP-series). Backend handlers live on branch `feat/60_nmap`; the frontend integration is in `src/app/services/discoveryService.ts`, hooks in `useApiData.ts`, and the **Network Discovery** screen (`src/app/screens/network/NW07Discovery.tsx`), reachable at `/network/discovery` and via Settings → Network → Network Discovery.

**Inventory (read)**

- `GET /discovery/devices` — full inventory; returns a raw JSON array of `ConnectedDevice` (`device_id`, `ip`, `mac`, `vendor`, `hostname`, `os_fingerprint`, `os_cpe[]`, `open_ports[]`, `host_scripts[]`, `status`, `first_seen`, `last_seen`, `vuln_triaged`). `404` when no inventory exists yet.
- `GET /discovery/list`, `GET /discovery/inventory/list` — aliases of `/discovery/devices`.
- `GET /discovery/devices/unauthorized` — inventory filtered to `unauthorized` / `drifted` devices.
- `GET /discovery/unauthorized` — alias of the unauthorized list.

**Scan (actions)** — all return `{ success, stdout, stderr, timestamp }`; a non-zero CLI exit is still `200 OK` with `success=false`.

- `POST /discovery/scan` — default ad-hoc intensity.
- `POST /discovery/scan/stealth`, `/discovery/scan/standard`, `/discovery/scan/aggressive` — fixed intensities.

**Whitelist / approve**

- `POST /discovery/approve` — body `{ mac, label? }` (mac required). Adds the MAC to the whitelist and reclassifies matching inventory records. Returns `{ success, created, inventory_updated, entry }`.
- `GET /discovery/whitelist` — `{ version, devices[] }` where each device is `{ mac, label, expected_os, expected_ports[], expected_ips[] }`.
- `PUT /discovery/whitelist` — replace whitelist (same schema); refreshes matching inventory statuses.

**Schedule**

- `GET /discovery/schedule` — `{ enabled, target_cidr, timeout_secs, exclude[], schedules: { hourly: { intensity }, daily: { intensity } } }`. `target_cidr: null` ⇒ runtime LAN auto-detection.
- `PUT /discovery/schedule` — partial update; any omitted field keeps its current value. `400` on invalid intensity/CIDR/timeout.

**UI** — the Network Discovery screen has three tabs:
- **Inventory** — device cards with status badges (approved / unauthorized / drifted), open-port chips, a "flagged only" filter, the four scan-intensity buttons, and an Approve dialog.
- **Whitelist** — a `Table ⇄ JSON` toggle: a structured card view (MAC, label, expected OS/ports/IPs, with per-entry Remove) and the raw JSON editor, both backed by the same editable document.
- **Schedule** — a config form (enabled, target CIDR, timeout, excludes, hourly/daily intensity) that degrades to defaults with a warning if the current config can't load.

Both FE and BE are implemented (BE on `feat/60_nmap`). All 14 endpoints are exercised from the UI except the three pure GET aliases, which exist as service methods for completeness.

See **`docs/nmap-discovery.md`** for the full implementation notes and local run/setup steps.

---

## Known Mismatches (FE ↔ BE)

These need to be fixed so the frontend and backend align:

| Issue | FE Path | BE Path |
|-------|---------|---------|
| PCR baseline create | `POST /pcr/baseline/update` | `POST /pcr/baseline/create` |
| PCR verify | `POST /pcr/verify` | `POST /pcr/baseline/verify` |

---

## Error Response Format

```json
{
 "error": {
 "code": "string",
 "message": "string"
 }
}
```

---

## Notes

- Backend runs on Axum (Rust). All action endpoints invoke `sgx-pa-cli` as a subprocess.
- `restartRequired: true` is hardcoded in all action responses — daemon restart is always needed after DKP/PCR/Policy changes.
- No `Authorization` headers required — security enforced at backend level.
- Frontend falls back to mock data if backend is unreachable (read-only operations only).
- FE source: `src/app/services/` and `src/app/hooks/useApiData.ts`
- BE source: `src/api/handlers/` on branch `api` of `https://github.com/Cervais/new-guardian`
