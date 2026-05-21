# SG-X Guardian REST API Details

**Version:** 2.1  
**Port:** `8443`  
**Base URL:** `http://<board-ip>:8443/api/v1`  
**Example Board IP:** `192.168.1.10`

## 1. Implemented Endpoints 

| # | Method | Path | Purpose |
|---|---|---|---|
| 1 | GET | `/health` | API health check |
| 2 | GET | `/node/status` | Node identity and network config |
| 3 | GET | `/node/boot-status` | Boot/HAB trust chain snapshot |
| 4 | POST | `/node/restart` | Restart Guardian daemon process |
| 5 | GET | `/peers` | Trusted peers list |
| 6 | GET | `/attestation` | Last attestation result |
| 7 | GET | `/logs` | Tail node logs with filters |
| 8 | GET | `/dkp/status` | DKP metadata and active public key details |
| 9 | POST | `/dkp/rotate` | Rotate DKP |
| 10 | POST | `/dkp/revoke` | Revoke DKP version |
| 11 | POST | `/dkp/emergency-rotate` | Emergency rotate DKP |
| 12 | GET | `/guardian/key/status` | Guardian software key presence/status |
| 13 | POST | `/guardian/key/generate` | Generate or regenerate Guardian key pair |
| 14 | GET | `/pcr/status` | Current PCR snapshot |
| 15 | POST | `/pcr/baseline/create` | Create PCR baseline |
| 16 | POST | `/pcr/baseline/update` | Alias of baseline create |
| 17 | POST | `/pcr/baseline/verify` | Verify PCR baseline |
| 18 | POST | `/pcr/verify` | Alias of baseline verify |
| 19 | GET | `/did/status` | DID record status |
| 20 | GET | `/did/resolve` | Resolve local DID |
| 21 | POST | `/did/deactivate` | Deactivate local DID |
| 22 | GET | `/transport/list` | Enumerate transport interfaces |
| 23 | GET | `/transport/status` | Active transport and lock state |
| 24 | GET | `/relay/list` | Relay registry/runtime snapshot |
| 25 | POST | `/relay/limits` | Update relay runtime limits |
| 26 | POST | `/policy/sign` | Sign uploaded policy file |
| 27 | POST | `/policy/verify` | Verify uploaded signed policy |
| 28 | POST | `/policy/verify-deployed` | Verify deployed on-disk policy signature |
| 29 | GET | `/policy/current` | Fetch current active policy YAML |
| 30 | PUT | `/policy/current` | Validate and stage pending policy YAML |
| 31 | GET | `/policy/backup` | Fetch backup policy YAML |
| 32 | POST | `/policy/sign-deploy-current` | Sign+deploy staged pending policy |

## 2. NEW Endpoints 

| Method | Path | Purpose |
|---|---|---|
| GET | `/did/status` | DID record status |
| GET | `/did/resolve` | Resolve local DID |
| POST | `/did/deactivate` | Deactivate local DID |
| GET | `/transport/list` | Enumerate transport interfaces |
| GET | `/transport/status` | Active transport and lock state |
| GET | `/relay/list` | Relay registry/runtime snapshot |
| POST | `/relay/limits` | Update relay runtime limits |

---

## 2. Standard Error Envelope

All handler-generated API errors use this JSON envelope:

```json
{
  "error": {
    "code": "NOT_FOUND | BAD_REQUEST | INTERNAL",
    "message": "human-readable message"
  }
}
```

Typical HTTP status mapping:

- `400 BAD_REQUEST`
- `404 NOT_FOUND`
- `500 INTERNAL_SERVER_ERROR`


### 2.1 Standard ActionResponse Schema

Used by command/action endpoints that execute CLI-backed operations.

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

Field notes:

- `success` (`boolean`): `true` when command completed successfully.
- `stdout` (`string`): captured command stdout.
- `stderr` (`string`): captured command stderr.
- `restartRequired` (`boolean`): whether daemon restart is required after action.
- `timestamp` (`string`, RFC3339 UTC): action completion timestamp.

---

## 3. Endpoint Contracts

### 3.1 GET `/health`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):
  - Plain text: `ok`
- Error responses:
  - None expected from handler

### 3.2 GET `/node/status`

- Request:
  - Query params:
    - `node` (optional, string). Defaults to server `node_id`.
  - Body: none
- Success response (`200 OK`):

```json
{
  "nodeId": "nodeA",
  "hostname": "sgx-node-a",
  "ip": "192.168.100.1",
  "port": 50051,
  "publicKey": "BASE64_OR_HEX",
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `400 BAD_REQUEST`: invalid `node` format
  - `404 NOT_FOUND`: config file for node not found
  - `500 INTERNAL_SERVER_ERROR`: config dir invalid or YAML parse failure

### 3.3 GET `/node/boot-status`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "habEnabled": true,
  "deviceClosed": true,
  "habEventsFound": false,
  "deviceModel": "i.MX8",
  "kernelVersion": "6.1.x",
  "bootChainIntact": true,
  "guardianBinaryHash": "sha256:...",
  "trustChain": [
    { "stage": "Boot ROM", "status": "verified" },
    { "stage": "HAB", "status": "verified" }
  ],
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `400 BAD_REQUEST`: boot status directory configuration invalid
  - `404 NOT_FOUND`: boot directory/status file missing
  - `500 INTERNAL_SERVER_ERROR`: I/O or JSON parse failure

### 3.4 POST `/node/restart`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "message": "Guardian daemon restart initiated",
  "expectedDowntime": "5-10 seconds",
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: restart command spawn failed

### 3.5 GET `/peers`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "peers": [
    {
      "peerId": "nodeB",
      "ip": "192.168.100.2",
      "status": "trusted",
      "lastSeen": "2026-05-21T09:59:00Z"
    }
  ],
  "total": 1,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - None expected from handler (falls back to empty list when files are unavailable)

### 3.6 GET `/attestation`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "peerId": "nodeB",
  "policyDigest": "sha256:...",
  "result": "PASS",
  "timestamp": "2026-05-21T09:58:00Z"
}
```

- Error responses:
  - `404 NOT_FOUND`: no attestation result recorded / source file missing
  - `500 INTERNAL_SERVER_ERROR`: JSON parse failure

### 3.7 GET `/logs`

- Request:
  - Query params:
    - `node` (optional, string)
    - `tail` (optional, integer, max effective value `1000`, default `100`)
    - `level` (optional, string, `all` disables level filtering)
    - `search` (optional, string substring filter)
  - Body: none
- Success response (`200 OK`):

```json
{
  "node": "nodeA",
  "file": "/var/log/.../nodeA.log",
  "entries": [
    {
      "timestamp": "2026-05-21T10:00:00Z",
      "level": "info",
      "message": "sample log"
    }
  ],
  "total": 1,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `400 BAD_REQUEST`: invalid node name
  - `404 NOT_FOUND`: no matching log file for node
  - `500 INTERNAL_SERVER_ERROR`: file read errors

### 3.8 GET `/dkp/status`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

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
      "keyId": "dkp-v2",
      "algorithm": "ECDSA-P256",
      "status": "Active",
      "createdAt": "2026-05-20T12:00:00Z",
      "rotatedFrom": "dkp-v1"
    }
  ]
}
```

- Error responses:
  - `404 NOT_FOUND`: DKP metadata/snapshot unavailable
  - `500 INTERNAL_SERVER_ERROR`: JSON parse failure

### 3.9 POST `/dkp/rotate`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` missing or spawn failed

### 3.10 POST `/dkp/revoke`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "version": 2,
  "reason": "optional reason"
}
```

  - Required fields: `version`
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` missing or spawn failed
  - `415`/`422`: invalid or missing JSON body

### 3.11 POST `/dkp/emergency-rotate`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "reason": "optional reason"
}
```

  - Required fields: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` missing or spawn failed
  - `415`/`422`: invalid JSON body

### 3.12 GET `/guardian/key/status`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "exists": true,
  "privateKeyExists": true,
  "publicKeyExists": true,
  "privateKeyPath": "/etc/sgx-guardian/guardian_private.key",
  "publicKeyPath": "/etc/sgx-guardian/guardian_public.key",
  "provider": "software",
  "algorithm": "ECDSA-P256",
  "fingerprint": "a1b2c3d4e5f60708"
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: key file read failure while calculating fingerprint

### 3.13 POST `/guardian/key/generate`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "force": false
}
```

  - Required fields: none (`force` defaults to `false`)
- Success response (`200 OK`):

```json
{
  "success": true,
  "alreadyExists": false,
  "provider": "software",
  "algorithm": "ECDSA-P256",
  "stdout": "...",
  "stderr": "",
  "privateKeyPath": "/etc/sgx-guardian/guardian_private.key",
  "publicKeyPath": "/etc/sgx-guardian/guardian_public.key",
  "restartRequired": true,
  "fingerprint": "a1b2c3d4e5f60708",
  "backups": [
    {
      "originalPath": "/etc/sgx-guardian/guardian_private.key",
      "backupPath": "/etc/sgx-guardian/guardian_private.key.bak.20260521T100000000Z"
    }
  ]
}
```

- Notes:
  - If keys already exist and `force=false`, endpoint returns `200` with:
    - `success=false`
    - `alreadyExists=true`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: CLI spawn failure, file backup/restore failure, key install/write failures
  - `415`/`422`: invalid JSON body

### 3.14 GET `/pcr/status`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "node": "nodeA",
  "registers": [
    { "index": 0, "name": "BIOS/Bootloader", "value": "..." }
  ],
  "compositeDigest": "...",
  "compositeSignature": "...",
  "integrityStatus": "OK",
  "deviceUid": "...",
  "keyVersion": 3,
  "measuredAt": "2026-05-21T09:59:30Z",
  "schemaVersion": 1
}
```

- Error responses:
  - `404 NOT_FOUND`: PCR snapshot not available
  - `500 INTERNAL_SERVER_ERROR`: JSON parse failure

### 3.15 POST `/pcr/baseline/create`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` missing or spawn failed

### 3.16 POST `/pcr/baseline/update` 

- Same request/response/errors as `/pcr/baseline/create`

### 3.17 POST `/pcr/baseline/verify`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` missing or spawn failed

### 3.18 POST `/pcr/verify` 

- Same request/response/errors as `/pcr/baseline/verify`

### 3.19 GET `/did/status`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "did": "did:guardian:...",
  "method": "guardian",
  "methodVersion": "1.0",
  "createdAt": "2026-04-26T10:00:00Z",
  "deactivatedAt": null,
  "currentDkpVersion": 3,
  "se050UidSource": "fallback",
  "dikPubkeySha256B16": "abcd...",
  "status": "active"
}
```

- Error responses:
  - `404 NOT_FOUND`: DID record file not found
  - `400 BAD_REQUEST`: DID record format/method/derivation errors
  - `500 INTERNAL_SERVER_ERROR`: internal DID handling failures

### 3.20 GET `/did/resolve`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "did": "did:guardian:...",
  "status": "ACTIVE",
  "publicKeyPreview": "00112233445566778899aabbccddeeff...",
  "publicKeyBytes": 64
}
```

- Error responses:
  - `404 NOT_FOUND`: DID record file not found
  - `400 BAD_REQUEST`: DID record/public key validation errors
  - `500 INTERNAL_SERVER_ERROR`: internal DID handling failures

### 3.21 POST `/did/deactivate`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "reason": "manual-admin",
  "confirm": true
}
```

  - Required fields: `confirm` (must be `true`)
- Success response (`200 OK`):

```json
{
  "ok": true,
  "message": "DID deactivated. Restart daemon to enforce runtime refusal.",
  "restartRequired": true
}
```

- Error responses:
  - `400 BAD_REQUEST`: `confirm` missing/false or DID input validation errors
  - `404 NOT_FOUND`: DID record file not found
  - `500 INTERNAL_SERVER_ERROR`: internal DID handling failures

### 3.22 GET `/transport/list`

- Request:
  - Query params:
    - `node` (optional, string). Defaults to server `node_id`.
  - Body: none
- Success response (`200 OK`):

```json
{
  "node": "nodeA",
  "interfaces": [
    {
      "name": "eth0",
      "transport": "Ethernet",
      "priority": 10,
      "status": "UP",
      "ip": "192.168.1.10",
      "available": true
    }
  ],
  "active": {
    "name": "eth0",
    "transport": "Ethernet"
  },
  "lock": "null"
}
```

- Error responses:
  - `400 BAD_REQUEST`: invalid `node` format

### 3.23 GET `/transport/status`

- Request:
  - Query params:
    - `node` (optional, string). Defaults to server `node_id`.
  - Body: none
- Success response (`200 OK`):

```json
{
  "node": "nodeA",
  "active": {
    "name": "eth0",
    "transport": "Ethernet"
  },
  "lock": "null"
}
```

- Error responses:
  - `400 BAD_REQUEST`: invalid `node` format

### 3.24 GET `/relay/list`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "relays": [
    {
      "node": "nodeA",
      "overlayIp": "192.168.100.1",
      "active": true,
      "maxPeers": 5,
      "maxBandwidthMbps": 10,
      "currentMbps": 4.25
    }
  ]
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: relay registry/stats read/parse/write issues

### 3.25 POST `/relay/limits`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "node": "nodeA",
  "maxPeers": 7,
  "maxBandwidthMbps": 15
}
```

  - Required fields: `node`, `maxPeers`, `maxBandwidthMbps`
- Success response (`200 OK`):

```json
{
  "ok": true,
  "node": "nodeA",
  "maxPeers": 7,
  "maxBandwidthMbps": 15,
  "pcrSafe": true
}
```

- Error responses:
  - `400 BAD_REQUEST`: invalid `node` format
  - `500 INTERNAL_SERVER_ERROR`: relay registry persistence failure

### 3.26 POST `/policy/sign`

- Request:
  - Query params: none
  - Multipart form-data body:
    - `policy` (required, uploaded policy YAML file)
    - `key` (optional, accepted but currently unused by handler)
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `400 BAD_REQUEST`: multipart parse error or missing `policy` field
  - `500 INTERNAL_SERVER_ERROR`: temp file write / CLI spawn errors
  - `415`/`400`: missing/invalid multipart content-type/body

### 3.27 POST `/policy/verify`

- Request:
  - Query params: none
  - Multipart form-data body:
    - `policy` (required, uploaded signed policy artifact)
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `400 BAD_REQUEST`: multipart parse error or missing `policy` field
  - `500 INTERNAL_SERVER_ERROR`: temp file write / CLI spawn errors
  - `415`/`400`: missing/invalid multipart content-type/body

### 3.28 POST `/policy/verify-deployed`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `404 NOT_FOUND`: deployed policy signature file missing
  - `500 INTERNAL_SERVER_ERROR`: CLI spawn errors

### 3.29 GET `/policy/current`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "source_path": "/etc/sgx-guardian/policies/active_policy.yaml",
  "content": "policy_id: ...\nversion: ...",
  "version": "1.0.0",
  "updated_at": "2026-05-21T09:55:00Z"
}
```

- Error responses:
  - `404 NOT_FOUND`: policy file cannot be read
  - `400 BAD_REQUEST`: policy YAML on disk is invalid

### 3.30 PUT `/policy/current`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "content": "policy_id: ...\nversion: ..."
}
```

  - Required fields: `content`
- Success response (`200 OK`):

```json
{
  "success": true,
  "source_path": "/etc/sgx-guardian/policies/pending_policy.yaml",
  "version": "1.0.1",
  "bytes_written": 428,
  "updated_at": "2026-05-21T10:00:00Z"
}
```

- Error responses:
  - `400 BAD_REQUEST`: policy validation failed
  - `500 INTERNAL_SERVER_ERROR`: failed to create parent dir or stage pending policy
  - `415`/`422`: invalid JSON body

### 3.31 GET `/policy/backup`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`): same schema as `/policy/current`
- Error responses:
  - `404 NOT_FOUND`: backup policy file cannot be read
  - `400 BAD_REQUEST`: backup policy YAML invalid

### 3.32 POST `/policy/sign-deploy-current`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-05-21T10:00:00Z"
}
```

- Notes:
  - If pending policy is semantically identical to active policy:
    - returns `success=true`
    - `restartRequired=false`
    - pending file is cleaned up
  - If CLI command exits non-zero:
    - returns `200` with `success=false` in body

- Error responses:
  - `400 BAD_REQUEST`: pending policy missing or invalid
  - `500 INTERNAL_SERVER_ERROR`: active/backup file handling or CLI spawn failures

---
