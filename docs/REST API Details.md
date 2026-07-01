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
| 20 | GET | `/did/resolve` | Resolve local DID or a peer DID via query |
| 21 | POST | `/did/deactivate` | Deactivate local DID |
| 22 | GET | `/transport/list` | Enumerate transport interfaces |
| 23 | GET | `/transport/status` | Active transport and lock state |
| 24 | POST | `/transport/lock` | Lock active transport to a specific interface |
| 25 | POST | `/transport/unlock` | Remove manual transport lock |
| 26 | GET | `/relay/list` | Relay-role nodes from lighthouse registry plus runtime relay fields |
| 27 | GET | `/lighthouse/list` | Lighthouse-role nodes from lighthouse registry |
| 28 | GET | `/member/list` | Pure member nodes from lighthouse registry |
| 29 | GET | `/relay-lighthouse/list` | Nodes that are both relay and lighthouse |
| 30 | POST | `/relay/toggle` | Enable/disable relay role for node |
| 31 | POST | `/lighthouse/toggle` | Enable/disable lighthouse role for node |
| 32 | POST | `/relay/limits` | Update relay runtime limits |
| 33 | POST | `/policy/sign` | Sign uploaded policy file |
| 34 | POST | `/policy/verify` | Verify uploaded signed policy |
| 35 | POST | `/policy/verify-deployed` | Verify deployed on-disk policy signature |
| 36 | GET | `/policy/current` | Fetch current active policy YAML |
| 37 | PUT | `/policy/current` | Validate and stage pending policy YAML |
| 38 | GET | `/policy/backup` | Fetch backup policy YAML |
| 39 | POST | `/policy/sign-deploy-current` | Sign+deploy staged pending policy |
| 40 | GET | `/did/document` | Local DID Document summary |
| 41 | GET | `/did/document/raw` | Raw local DID Document |
| 42 | POST | `/did/document/verify` | Verify DID Document proof and replay floor |
| 43 | POST | `/did/document/publish` | Force publish local DID Document to CA registry (maintenance/recovery endpoint) |
| 44 | GET | `/did/document/peers` | List cached peer DID Documents |
| 45 | GET | `/did/document/peer` | Fetch cached peer DID Document by DID |
| 46 | POST | `/vc/issue` | Issue a circle-membership VC for a subject DID |
| 47 | POST | `/vc/renew` | Renew an existing VC expiration without changing its status-list index |
| 48 | POST | `/vc/revoke` | Revoke an issued VC and update the status list |
| 49 | POST | `/vc/verify` | Verify a cached VC against proof, issuer, circle, expiry, and status-list state |
| 50 | GET | `/vc/show` | List VC metadata across issued, own, and peer caches with filters |
| 51 | GET | `/vc/status/{vc_id}` | Fetch computed active/revoked/expired status for one VC |
| 52 | POST | `/vc/status-list/pull` | Pull and verify the latest VC status list from the CA |
| 53 | GET | `/vc/files/issued` | List metadata for VCs stored in the issued-file cache |
| 54 | GET | `/vc/files/own` | List metadata for VCs stored in the local own-credential cache |
| 55 | GET | `/vc/files/peers` | List metadata for VCs stored in the peer VC cache |
| 56 | GET | `/vc/files/issued/{vc_id}` | Fetch full issued VC JSON by VC ID |
| 57 | GET | `/vc/files/own/{vc_id}` | Fetch full own VC JSON by VC ID |
| 58 | GET | `/vc/files/peer/{did}` | Fetch full peer VC JSON by peer DID |
| 59 | GET | `/vc/status-list` | Fetch the local VC status-list credential |
| 60 | GET | `/vc/status-list-index` | Fetch the local VC status-list index counter |
| 61 | GET | `/vc/summary` | Return dashboard summary of issued, own, peer, active, revoked, and expired VC counts |
| 62 | GET | `/vc/audit` | Return VC-related audit events with optional filters |
| 63 | GET | `/vid/show` | Show the single current nonce-bound VirtualID and its input digests |
| 64 | GET | `/vid/peers` | List cached peer VirtualIDs and last observed rotation reasons |
| 65 | GET | `/discovery/devices` | Full NMAP device inventory |
| 66 | GET | `/discovery/list` | Alias of discovery inventory list |
| 67 | GET | `/discovery/inventory/list` | Alias of discovery inventory list |
| 68 | GET | `/discovery/devices/unauthorized` | Unauthorized or drifted discovered devices |
| 69 | GET | `/discovery/unauthorized` | Alias of unauthorized discovery list |
| 70 | POST | `/discovery/scan` | Run discovery scan using default ad-hoc intensity |
| 71 | POST | `/discovery/scan/stealth` | Run one stealth NMAP discovery scan |
| 72 | POST | `/discovery/scan/standard` | Run one standard NMAP discovery scan |
| 73 | POST | `/discovery/scan/aggressive` | Run one aggressive NMAP discovery scan |
| 74 | POST | `/discovery/approve` | Authorize a discovered device by MAC and add it to whitelist |
| 75 | GET | `/discovery/whitelist` | Fetch discovery whitelist YAML content as JSON |
| 76 | PUT | `/discovery/whitelist` | Replace discovery whitelist and refresh inventory statuses |
| 77 | GET | `/discovery/schedule` | Fetch scheduled NMAP discovery configuration |
| 78 | PUT | `/discovery/schedule` | Update scheduled NMAP discovery configuration |


## 2. NEW Endpoints 

| Method | Path | Purpose |
|---|---|---|
| GET | `/vc/files/own` | List local own-VC file metadata |
| GET | `/vc/files/peers` | List peer-VC file metadata |
| GET | `/vc/files/issued/{vc_id}` | Fetch the stored issued VC JSON document |
| GET | `/vc/files/own/{vc_id}` | Fetch the stored own VC JSON document |
| GET | `/vc/files/peer/{did}` | Fetch the stored peer VC JSON document by DID |
| GET | `/vc/status-list` | Fetch the stored VC status-list credential JSON |
| GET | `/vc/status-list-index` | Fetch the stored status-list next-index JSON |
| GET | `/vc/summary` | Return aggregate VC cache and lifecycle counts |
| GET | `/vc/audit` | Return VC audit-log entries with optional filtering |
| GET | `/vid/show` | Show the single current nonce-bound VirtualID and its input digests |
| GET | `/vid/peers` | List cached peer VirtualIDs and last observed rotation reasons |
| GET | `/audit/logs` | Fetch secure tamper-evident audit logs with filters |
---

## 2. Standard Error Envelope

All handler-generated API errors use this JSON envelope:

```json
{
  "error": {
    "code": "NOT_FOUND | BAD_REQUEST | UNAUTHORIZED | FORBIDDEN | CONFLICT | INTERNAL",
    "message": "human-readable message"
  }
}
```

Typical HTTP status mapping:

- `400 BAD_REQUEST`
- `401 UNAUTHORIZED`
- `403 FORBIDDEN`
- `409 CONFLICT`
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
  - Query params:
    - none for local self resolution
    - `did` (optional, string) for peer DID resolution
    - `reject_deactivated` (optional, bool, default `false`) when `did` is provided
  - Body: none
- Success response (`200 OK`):

Local self resolution response (no `did` query):

```json
{
  "did": "did:guardian:...",
  "status": "ACTIVE",
  "publicKeyPreview": "00112233445566778899aabbccddeeff...",
  "publicKeyBytes": 64
}
```

Peer DID resolution response (`?did=did:guardian:...`):

```json
{
  "did": "did:guardian:...",
  "public_key_der_b64": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
  "services": [
    {
      "id": "did:guardian:...#sgx-attestation",
      "type": "SGXAttestation",
      "endpoint": "tcp://192.168.100.10:50051"
    }
  ],
  "source": "local_peer_doc",
  "fetched_at": "2026-06-03T10:00:00Z",
  "ttl_remaining_sec": 3599,
  "status": "active",
  "version_id": 7,
  "dkp_version": 4
}
```

- Error responses:
  - `404 NOT_FOUND`: DID record missing for self path, or peer DID is unresolvable
  - `400 BAD_REQUEST`: malformed DID, empty `did`, deactivated peer rejection, or DID/public key validation errors
  - `500 INTERNAL_SERVER_ERROR`: internal DID handling or CA/network resolution failures

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
  "lock": null
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
  "lock": null
}
```

- Error responses:
  - `400 BAD_REQUEST`: invalid `node` format

### 3.24 POST `/transport/lock`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "node": "nodeA",
  "interfaceName": "eth0"
}
```

  - Required fields: `node`, `interfaceName`
- Success response (`200 OK`):

```json
{
  "ok": true,
  "node": "nodeA",
  "lock": "eth0",
  "message": "Transport locked to eth0"
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing/invalid `node` or `interfaceName`
  - `404 NOT_FOUND`: interface not found
  - `500 INTERNAL_SERVER_ERROR`: lock directory/file write failure
  - `415`/`422`: invalid JSON body

### 3.25 POST `/transport/unlock`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "node": "nodeA"
}
```

  - Required fields: `node`
- Success response (`200 OK`):

```json
{
  "ok": true,
  "node": "nodeA",
  "lock": null,
  "message": "Transport unlocked"
}
```

- Notes:
  - If lock file does not exist, endpoint still returns `200` with:
    - `message`: `Transport already unlocked for <node>`
- Error responses:
  - `400 BAD_REQUEST`: missing/invalid `node`
  - `500 INTERNAL_SERVER_ERROR`: lock file delete failure
  - `415`/`422`: invalid JSON body

### 3.26 GET `/relay/list`

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
      "relayEnabled": true,
      "lighthouseEnabled": true,
      "maxPeers": 5,
      "maxBandwidthMbps": 10,
      "currentMbps": 4.25
    }
  ]
}
```

- Notes:
  - Source of truth: `/var/lib/sgx-guardian/nebula/lighthouse_registry.json`
  - Only entries with `am_relay == true` are returned
  - Runtime relay fields come from `relay_registry.json` when present, then node YAML, then defaults
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: lighthouse registry or relay stats read/parse issues

### 3.26.1 GET `/lighthouse/list`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "lighthouses": [
    {
      "node": "nodeB",
      "overlayIp": "192.168.100.2",
      "active": true,
      "relayEnabled": false,
      "lighthouseEnabled": true
    }
  ]
}
```

- Notes:
  - Source of truth: `/var/lib/sgx-guardian/nebula/lighthouse_registry.json`
  - Only entries with `is_lighthouse == true` are returned
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: lighthouse registry read/parse issues

### 3.26.2 GET `/member/list`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "members": [
    {
      "node": "nodeC",
      "overlayIp": "192.168.100.3",
      "active": false,
      "relayEnabled": false,
      "lighthouseEnabled": false
    }
  ]
}
```

- Notes:
  - Source of truth: `/var/lib/sgx-guardian/nebula/lighthouse_registry.json`
  - Only entries with `am_relay == false && is_lighthouse == false` are returned
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: lighthouse registry read/parse issues

### 3.26.3 GET `/relay-lighthouse/list`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "relayLighthouses": [
    {
      "node": "nodeA",
      "overlayIp": "192.168.100.1",
      "active": true,
      "relayEnabled": true,
      "lighthouseEnabled": true,
      "maxPeers": 5,
      "maxBandwidthMbps": 10,
      "currentMbps": 4.25
    }
  ]
}
```

- Notes:
  - Source of truth: `/var/lib/sgx-guardian/nebula/lighthouse_registry.json`
  - Only entries with `am_relay == true && is_lighthouse == true` are returned
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: lighthouse registry or relay stats read/parse issues

### 3.27 POST `/relay/toggle`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "node": "nodeA",
  "enabled": true
}
```

  - Required fields: `node`, `enabled`
- Success response (`200 OK`):

```json
{
  "ok": true,
  "node": "nodeA",
  "enabled": true,
  "message": "Relay enabled for nodeA"
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing/invalid `node` or missing `enabled`
  - `404 NOT_FOUND`: node config file not found
  - `500 INTERNAL_SERVER_ERROR`: config YAML, relay registry, or lighthouse registry update failure
  - `415`/`422`: invalid JSON body

### 3.27.1 POST `/lighthouse/toggle`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "node": "nodeB",
  "enabled": true
}
```

  - Required fields: `node`, `enabled`
- Success response (`200 OK`):

```json
{
  "ok": true,
  "node": "nodeB",
  "enabled": true,
  "message": "Lighthouse enabled for nodeB"
}
```

- Notes:
  - Updates `<config_dir>/<node>.yaml` so `lighthouse.enabled` matches the request
  - Updates or upserts the node in `/var/lib/sgx-guardian/nebula/lighthouse_registry.json`
  - Disabling does not remove the registry entry; it only flips `is_lighthouse` to `false`
- Error responses:
  - `400 BAD_REQUEST`: missing/invalid `node` or missing `enabled`
  - `404 NOT_FOUND`: node config file not found
  - `500 INTERNAL_SERVER_ERROR`: config YAML or lighthouse registry update failure
  - `415`/`422`: invalid JSON body

### 3.28 POST `/relay/limits`

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

### 3.29 POST `/policy/sign`

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

### 3.30 POST `/policy/verify`

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

### 3.31 POST `/policy/verify-deployed`

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

### 3.32 GET `/policy/current`

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

### 3.33 PUT `/policy/current`

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

### 3.34 GET `/policy/backup`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`): same schema as `/policy/current`
- Error responses:
  - `404 NOT_FOUND`: backup policy file cannot be read
  - `400 BAD_REQUEST`: backup policy YAML invalid

### 3.35 POST `/policy/sign-deploy-current`

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

### 3.36 GET `/did/document`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "did": "did:guardian:...",
  "controller": "did:guardian:...",
  "node_name": "nodeA",
  "version": 5,
  "status": "active",
  "active_vms": 1,
  "revoked_vms": 2,
  "services": 3,
  "proof_vm": "did:guardian:...#dkp-v3"
}
```

- Error responses:
  - `404 NOT_FOUND`: local DID Document file not found
  - `500 INTERNAL_SERVER_ERROR`: local DID Document load failure

### 3.37 GET `/did/document/raw`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:guardian:...",
  "controller": "did:guardian:...",
  "verificationMethod": [
    {
      "id": "did:guardian:...#dkp-v3",
      "type": "JsonWebKey2020",
      "controller": "did:guardian:...",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "...",
        "kid": "dkp-v3"
      }
    }
  ],
  "authentication": [
    "did:guardian:...#dkp-v3"
  ],
  "assertionMethod": [
    "did:guardian:...#dkp-v3"
  ],
  "service": [
    {
      "id": "did:guardian:...#sgx-mesh",
      "type": "SGXNebulaMesh",
      "serviceEndpoint": "nebula://10.0.0.2/24"
    }
  ],
  "sgx:nodeName": "nodeA",
  "sgx:created": "2026-05-20T08:00:00Z",
  "sgx:updated": "2026-05-21T10:00:00Z",
  "sgx:versionId": 5,
  "sgx:methodSpecVersion": "1.0",
  "sgx:status": "active",
  "sgx:revokedVerificationMethod": [
    {
      "id": "did:guardian:...#dkp-v2",
      "revokedAt": "2026-05-20T09:00:00Z",
      "reason": "rotation"
    }
  ],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jcs-2019",
    "verificationMethod": "did:guardian:...#dkp-v3",
    "created": "2026-05-21T10:00:00Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "..."
  }
}
```

- Error responses:
  - `404 NOT_FOUND`: local DID Document file not found
  - `500 INTERNAL_SERVER_ERROR`: local DID Document load failure

### 3.38 POST `/did/document/verify`

- Request:
  - Query params: none
  - JSON body (optional):

```json
{
  "path": "/var/lib/sgx-guardian/identity/did_doc.json"
}
```

  - Required fields: none
- Notes:
  - If body is omitted, the handler verifies the local DID Document at the configured self-document path.
- Success response (`200 OK`):

```json
{
  "valid": true,
  "version": 5,
  "message": "DID Document proof valid"
}
```

- Error responses:
  - `400 BAD_REQUEST`: invalid JSON body, empty `path`, invalid DID Document JSON, proof/signature validation failure, or replayed older version
  - `404 NOT_FOUND`: DID Document file not found at requested path
  - `500 INTERNAL_SERVER_ERROR`: unexpected DID Document verify I/O failure

### 3.39 POST `/did/document/publish`

- Purpose:
  - Force publish local DID Document to CA registry (maintenance/recovery endpoint)
- Important Usage Notes:
  - Normal DID Document publishing is automatic.
  - Guardian daemon automatically publishes DID Documents during:
    - First boot DID Document creation
    - DID Document refresh/update
    - DKP rotation
    - DID deactivation
    - Circle synchronization events
  - This endpoint is mainly intended for member nodes (`nodeB`/`nodeC`) to manually republish a DID Document to the CA registry.
  - Typical use cases:
    - Recovery
    - Troubleshooting
    - Registry repair
    - Development/testing
  - Admin Console users normally do not need to call this endpoint.

- Request:
  - Query params: none
  - JSON body:

```json
{
  "ca_host": "127.0.0.1",
  "node_name": "nodeB"
}
```

  - Required fields: `ca_host`, `node_name`
- Success response (`200 OK`):

```json
{
  "success": true,
  "did": "did:guardian:...",
  "version": 5,
  "ca_host": "127.0.0.1",
  "node_name": "nodeB",
  "message": "DID Document published to CA registry"
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing/invalid JSON body, missing `ca_host`/`node_name`, DID Document verification failure, or CA-side rejection
  - `404 NOT_FOUND`: local DID Document file not found
  - `500 INTERNAL_SERVER_ERROR`: publish/connect/read/write timeout or other publish I/O failure

### 3.40 GET `/did/document/peers`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "count": 1,
  "peers": [
    {
      "did": "did:guardian:...",
      "node_name": "nodeB",
      "version": 4,
      "status": "active",
      "services": 2
    }
  ]
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: peer DID Document directory read failure

### 3.41 GET `/did/document/peer`

- Request:
  - Query params:
    - `did` (required, string, full `did:guardian:...` value)
  - Body: none
- Success response (`200 OK`):
  - Same schema as `GET /did/document/raw`
- Error responses:
  - `400 BAD_REQUEST`: missing/empty `did` query parameter or invalid DID format
  - `404 NOT_FOUND`: peer DID Document file not found
  - `500 INTERNAL_SERVER_ERROR`: peer DID Document load failure

### 3.42 POST `/vc/issue`

- Purpose:
  - Issue a verifiable circle-membership credential for a subject DID.
- Request:
  - Query params: none
  - JSON body:

```json
{
  "to": "did:guardian:z6Mkmember123",
  "role": "member",
  "days": 30
}
```

  - Required fields:
    - `to` (`string`, DID). Alias: `subject_did`
  - Optional fields:
    - `role` (`string`): `owner` or `member`. Defaults to `member`.
    - `permissions` (`string[]`): if omitted, the built-in default permission set for the selected role is used.
    - `days` (`integer`): validity duration in days. Defaults to `365`. Allowed range: `1..=3650`.
- Notes:
  - This is a CA-only/admin endpoint.
  - If an active issued VC already exists for the same subject+role with the same permission set, the handler reuses it instead of creating a new credential.
- Success response:
  - `201 Created` when a new VC is issued.
  - `200 OK` when an existing active VC is reused.

```json
{
  "status": "success",
  "message": "Issued new VC",
  "vc_id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "subject": "did:guardian:z6Mkmember123",
  "role": "member",
  "expires": "2026-07-12T09:00:00Z",
  "reused": false,
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://w3id.org/vc/status-list/2021/v1",
      "https://schemas.cyberzeus.io/sgx/v1/circle-membership"
    ],
    "id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
    "type": [
      "VerifiableCredential",
      "CircleMembershipCredential"
    ],
    "issuer": "did:guardian:z6Mkowner456",
    "issuanceDate": "2026-06-12T09:00:00Z",
    "expirationDate": "2026-07-12T09:00:00Z",
    "credentialSubject": {
      "id": "did:guardian:z6Mkmember123",
      "role": "member",
      "permissions": [
        "mesh:join",
        "cert:request",
        "cert:renew",
        "attest:peer",
        "did:resolve",
        "status:read"
      ],
      "joinDate": "2026-06-12T09:00:00Z",
      "circleId": "guardian-circle-alpha",
      "membershipStatus": "active"
    },
    "credentialStatus": {
      "id": "did:guardian:z6Mkowner456/status-list#12",
      "type": "StatusList2021Entry",
      "statusPurpose": "revocation",
      "statusListIndex": "12",
      "statusListCredential": "did:guardian:z6Mkowner456/status-list"
    },
    "proof": {
      "type": "DataIntegrityProof",
      "verificationMethod": "did:guardian:z6Mkowner456#dkp-v3",
      "created": "2026-06-12T09:00:00Z",
      "proofValue": "..."
    }
  }
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing/invalid `to`/`subject_did`, invalid DID, unsupported `role`, invalid `days`, or invalid permission set
  - `403 FORBIDDEN`: local node is not authorized as the circle owner/CA for issuance
  - `500 INTERNAL_SERVER_ERROR`: issuer DID/key material, status-list update, signing, or persistence failure

### 3.43 POST `/vc/renew`

- Purpose:
  - Extend the expiration date of an existing VC without changing its VC id or status-list index.
- Request:
  - Query params: none
  - JSON body:

```json
{
  "id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "days": 90
}
```

  - Required fields:
    - `id` (`string`, VC id). Alias: `vc_id`
    - `days` (`integer`): new validity duration in days from renewal time. Allowed range: `1..=3650`.
- Notes:
  - This is a CA-only/admin endpoint.
  - Renewal keeps the original `issuanceDate` and `credentialStatus.statusListIndex`, but updates `expirationDate` and re-signs the VC proof.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "message": "VC renewed",
  "vc_id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "old_expiration": "2026-07-12T09:00:00Z",
  "new_expiration": "2026-09-10T09:00:00Z",
  "vc": {
    "id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
    "issuer": "did:guardian:z6Mkowner456",
    "issuanceDate": "2026-06-12T09:00:00Z",
    "expirationDate": "2026-09-10T09:00:00Z",
    "credentialStatus": {
      "statusListIndex": "12"
    },
    "proof": {
      "created": "2026-06-20T09:00:00Z",
      "proofValue": "..."
    }
  }
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing/invalid `id`, malformed VC id, or invalid `days`
  - `403 FORBIDDEN`: local node is not authorized as the circle owner/CA for renewal
  - `404 NOT_FOUND`: target VC not found in issued/own/peer caches
  - `409 CONFLICT`: VC is revoked or already expired and cannot be renewed through this endpoint
  - `500 INTERNAL_SERVER_ERROR`: issuer DID/key material, status-list load, signing, or persistence failure

### 3.44 POST `/vc/revoke`

- Purpose:
  - Revoke a VC and mark its status-list entry as revoked.
- Request:
  - Query params: none
  - JSON body:

```json
{
  "id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "reason": "member removed from circle"
}
```

  - Required fields:
    - `id` (`string`, VC id). Alias: `vc_id`
  - Optional fields:
    - `reason` (`string`): defaults to `"manual revoke"`. Maximum length `256`.
- Notes:
  - This is a CA-only/admin endpoint.
- Success response (`200 OK`):

```json
{
  "success": true,
  "status": "success",
  "message": "VC revoked",
  "vc_id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "revoked": true,
  "reason": "member removed from circle"
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing/invalid `id`, malformed VC id, empty reason, or reason longer than `256` characters
  - `403 FORBIDDEN`: local node is not authorized as the circle owner/CA for revocation
  - `404 NOT_FOUND`: target VC not found
  - `500 INTERNAL_SERVER_ERROR`: status-list update, issuer DID/key material, or persistence failure

### 3.45 POST `/vc/verify`

- Purpose:
  - Verify a cached VC against proof signature, issuer DID resolution, circle binding, expiration, and status-list revocation state.
- Request:
  - Query params: none
  - JSON body:

```json
{
  "id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8"
}
```

  - Required fields:
    - `id` (`string`, VC id)
- Notes:
  - Verification failures are reported as `200 OK` with `valid=false` and a human-readable `reason`.
  - The handler verifies against the locally available status-list credential and the configured/known CA DID.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "valid": true,
  "vc_id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "reason": null
}
```

- Example failed verification response (`200 OK`):

```json
{
  "status": "success",
  "valid": false,
  "vc_id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "reason": "VC revoked at status list index 12"
}
```

- Error responses:
  - `400 BAD_REQUEST`: malformed VC id
  - `404 NOT_FOUND`: VC id not found in issued/own/peer caches
  - `500 INTERNAL_SERVER_ERROR`: unexpected persistence failure before verification begins

### 3.46 GET `/vc/show`

- Purpose:
  - Return summarized VC metadata from the local caches with optional filtering by source scope, role, and computed status.
- Request:
  - Query params:
    - `scope` (optional, string): `issued`, `own`, `peers`, or `all`. Default: `all`
    - `role` (optional, string): `owner` or `member`
    - `status` (optional, string): `active`, `revoked`, `expired`, or `all`. Default: `all`
  - Body: none
- Notes:
  - `scope=all` concatenates the issued, own, and peer views.
  - This endpoint returns metadata only, not the full VC JSON document.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "count": 1,
  "items": [
    {
      "vc_id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
      "subject": "did:guardian:z6Mkmember123",
      "issuer": "did:guardian:z6Mkowner456",
      "role": "member",
      "circle_id": "guardian-circle-alpha",
      "membership_status": "active",
      "issuance_date": "2026-06-12T09:00:00Z",
      "expiration_date": "2026-07-12T09:00:00Z",
      "status_list_index": "12",
      "revoked": false,
      "source_scope": "issued"
    }
  ]
}
```

- Error responses:
  - `400 BAD_REQUEST`: unsupported `scope`, `role`, or `status` filter value
  - `500 INTERNAL_SERVER_ERROR`: VC cache scan/persistence failure

### 3.47 GET `/vc/status/{vc_id}`

- Purpose:
  - Compute and return the current effective status for one VC id.
- Request:
  - Path params:
    - `vc_id` (required, string, full `urn:uuid:...` value)
  - Query params: none
  - Body: none
- Notes:
  - This is the path-parameter form of the legacy query-based `GET /vc/status?id=...` route.
  - The handler checks local cache presence, expiration, membership status, and the locally stored status-list credential.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "vc_id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "subject_did": "did:guardian:z6Mkmember123",
  "issuer_did": "did:guardian:z6Mkowner456",
  "active": true,
  "revoked": false,
  "expired": false,
  "membership_status": "active",
  "status_list_index": "12",
  "reason": null
}
```

- Error responses:
  - `400 BAD_REQUEST`: malformed VC id or invalid stored status-list index
  - `404 NOT_FOUND`: VC id not found or required backing file (for example the stored status list) is missing
  - `500 INTERNAL_SERVER_ERROR`: status-list verification, issuer resolution, or persistence failure

### 3.48 POST `/vc/status-list/pull`

- Purpose:
  - Pull the latest VC status-list snapshot from the CA, verify its proof, and store it locally.
- Request:
  - Query params: none
  - JSON body (optional):

```json
{
  "ca_host": "192.168.1.10"
}
```

  - Optional fields:
    - `ca_host` (`string`): CA host/IP to contact
    - `owner_addr` (`string`): legacy alias for `ca_host`
- Notes:
  - If both body fields are omitted, the handler falls back to `SGX_CA_HOST` and then to configured nodeA YAML IP values.
  - The returned `sgx_next_index` reflects the next unallocated revocation index advertised by the pulled status-list credential.
- Success response (`200 OK`):

```json
{
  "success": true,
  "status": "success",
  "message": "Pulled VC status list",
  "ca_host": "192.168.1.10",
  "issuer": "did:guardian:z6Mkowner456",
  "sgx_next_index": 13
}
```

- Error responses:
  - `400 BAD_REQUEST`: CA host not configured anywhere, or returned status list issuer does not match the expected CA DID
  - `500 INTERNAL_SERVER_ERROR`: CA timeout/network failure, returned status list JSON/proof verification failure, or local save failure

### 3.49 GET `/vc/files/issued`

- Purpose:
  - List metadata for VCs stored under the local issued-file cache.
- Request:
  - Query params: none
  - Body: none
- Notes:
  - This endpoint returns the same `items` metadata shape as `GET /vc/show`, but only for the issued cache.
  - To fetch the full JSON document for a specific issued VC, use `GET /vc/files/issued/{vc_id}`.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "count": 1,
  "items": [
    {
      "vc_id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
      "subject": "did:guardian:z6Mkmember123",
      "issuer": "did:guardian:z6Mkowner456",
      "role": "member",
      "circle_id": "guardian-circle-alpha",
      "membership_status": "active",
      "issuance_date": "2026-06-12T09:00:00Z",
      "expiration_date": "2026-07-12T09:00:00Z",
      "status_list_index": "12",
      "revoked": false,
      "source_scope": "issued"
    }
  ]
}
```

- Error responses:
  - None expected when the issued directory is absent; the handler returns an empty list
  - `500 INTERNAL_SERVER_ERROR`: issued-cache directory scan failure

---

### 3.50 GET `/vc/files/own`

- Purpose:
  - List metadata for VCs stored under the local own-credential cache.
- Request:
  - Query params: none
  - Body: none
- Notes:
  - This endpoint returns the same `items` metadata shape as `GET /vc/show`, but only for the own cache.
  - To fetch the full JSON document for a specific own VC, use `GET /vc/files/own/{vc_id}`.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "count": 1,
  "items": [
    {
      "vc_id": "urn:uuid:81fc34d3-0d9e-4e88-8e3f-a3f9202a3e54",
      "subject": "did:guardian:z6Mklocalmember123",
      "issuer": "did:guardian:z6Mkowner456",
      "role": "member",
      "circle_id": "guardian-circle-alpha",
      "membership_status": "active",
      "issuance_date": "2026-06-12T09:05:00Z",
      "expiration_date": "2026-07-12T09:05:00Z",
      "status_list_index": "13",
      "revoked": false,
      "source_scope": "own"
    }
  ]
}
```

- Error responses:
  - None expected when the own directory is absent; the handler returns an empty list
  - `500 INTERNAL_SERVER_ERROR`: own-cache directory scan failure

### 3.51 GET `/vc/files/peers`

- Purpose:
  - List metadata for VCs stored under the local peer-credential cache.
- Request:
  - Query params: none
  - Body: none
- Notes:
  - This endpoint returns the same `items` metadata shape as `GET /vc/show`, but only for the peer cache.
  - To fetch the full JSON document for a specific peer VC, use `GET /vc/files/peer/{did}`.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "count": 1,
  "items": [
    {
      "vc_id": "urn:uuid:ba4692a0-0a63-44fd-b5db-e81c7abda6af",
      "subject": "did:guardian:z6Mkpeer789",
      "issuer": "did:guardian:z6Mkowner456",
      "role": "member",
      "circle_id": "guardian-circle-alpha",
      "membership_status": "active",
      "issuance_date": "2026-06-11T15:30:00Z",
      "expiration_date": "2026-07-11T15:30:00Z",
      "status_list_index": "9",
      "revoked": false,
      "source_scope": "peers"
    }
  ]
}
```

- Error responses:
  - None expected when the peers directory is absent; the handler returns an empty list
  - `500 INTERNAL_SERVER_ERROR`: peer-cache directory scan failure

### 3.52 GET `/vc/files/issued/{vc_id}`

- Purpose:
  - Fetch the full stored issued VC JSON document by VC id.
- Request:
  - Path params:
    - `vc_id` (`string`): VC identifier. Must start with `urn:uuid:`.
  - Query params: none
  - Body: none
- Notes:
  - Returns the persisted issued-credential JSON exactly as stored on disk.
  - This is the document-level companion to `GET /vc/files/issued`.
- Success response (`200 OK`):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/vc/status-list/2021/v1",
    "https://schemas.cyberzeus.io/sgx/v1/circle-membership"
  ],
  "id": "urn:uuid:6c36a672-b4d5-432d-a440-0eb90ce8d6d8",
  "type": [
    "VerifiableCredential",
    "CircleMembershipCredential"
  ],
  "issuer": "did:guardian:z6Mkowner456",
  "issuanceDate": "2026-06-12T09:00:00Z",
  "expirationDate": "2026-07-12T09:00:00Z",
  "credentialSubject": {
    "id": "did:guardian:z6Mkmember123",
    "role": "member",
    "permissions": [
      "mesh:join",
      "cert:request",
      "cert:renew",
      "attest:peer",
      "did:resolve",
      "status:read"
    ],
    "joinDate": "2026-06-12T09:00:00Z",
    "circleId": "guardian-circle-alpha",
    "membershipStatus": "active"
  },
  "credentialStatus": {
    "id": "did:guardian:z6Mkowner456/status-list#12",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "12",
    "statusListCredential": "did:guardian:z6Mkowner456/status-list"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "verificationMethod": "did:guardian:z6Mkowner456#dkp-v3",
    "created": "2026-06-12T09:00:00Z",
    "proofValue": "..."
  }
}
```

- Error responses:
  - `400 BAD_REQUEST`: malformed `vc_id`
  - `404 NOT_FOUND`: no issued VC file exists for that id
  - `500 INTERNAL_SERVER_ERROR`: stored JSON is unreadable/invalid

### 3.53 GET `/vc/files/own/{vc_id}`

- Purpose:
  - Fetch the full stored own VC JSON document by VC id.
- Request:
  - Path params:
    - `vc_id` (`string`): VC identifier. Must start with `urn:uuid:`.
  - Query params: none
  - Body: none
- Notes:
  - Returns the persisted own-credential JSON exactly as stored on disk.
  - The success body has the same raw VC JSON shape as `GET /vc/files/issued/{vc_id}`.
- Success response (`200 OK`):
  - Same raw VC JSON shape shown in `GET /vc/files/issued/{vc_id}`.
- Error responses:
  - `400 BAD_REQUEST`: malformed `vc_id`
  - `404 NOT_FOUND`: no own VC file exists for that id
  - `500 INTERNAL_SERVER_ERROR`: stored JSON is unreadable/invalid

### 3.54 GET `/vc/files/peer/{did}`

- Purpose:
  - Fetch the full stored peer VC JSON document by peer DID.
- Request:
  - Path params:
    - `did` (`string`): peer DID used as the peer-cache lookup key.
  - Query params: none
  - Body: none
- Notes:
  - Returns the persisted peer-credential JSON exactly as stored on disk.
  - URL-encode the DID if your client/framework does not allow raw `:` characters in the path segment.
  - The success body has the same raw VC JSON shape as `GET /vc/files/issued/{vc_id}`.
- Success response (`200 OK`):
  - Same raw VC JSON shape shown in `GET /vc/files/issued/{vc_id}`.
- Error responses:
  - `400 BAD_REQUEST`: malformed DID
  - `404 NOT_FOUND`: no peer VC file exists for that DID
  - `500 INTERNAL_SERVER_ERROR`: stored JSON is unreadable/invalid

### 3.55 GET `/vc/status-list`

- Purpose:
  - Fetch the locally stored VC status-list credential JSON.
- Request:
  - Query params: none
  - Body: none
- Notes:
  - This returns the raw `status_list.json` document as stored on disk.
  - The JSON field name for the local allocator hint is `sgxNextIndex` because this endpoint returns the stored credential, not the REST wrapper used by `POST /vc/status-list/pull`.
- Success response (`200 OK`):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "id": "did:guardian:z6Mkowner456/status-list",
  "type": [
    "VerifiableCredential",
    "StatusList2021Credential"
  ],
  "issuer": "did:guardian:z6Mkowner456",
  "issuanceDate": "2026-06-12T09:00:00Z",
  "credentialSubject": {
    "id": "did:guardian:z6Mkowner456/status-list#list",
    "type": "StatusList2021",
    "statusPurpose": "revocation",
    "encodedList": "H4sIAAAAA..."
  },
  "proof": {
    "type": "DataIntegrityProof",
    "verificationMethod": "did:guardian:z6Mkowner456#dkp-v3",
    "created": "2026-06-12T09:00:00Z",
    "proofValue": "..."
  },
  "sgxNextIndex": 13
}
```

- Error responses:
  - `404 NOT_FOUND`: local status-list credential file is missing
  - `500 INTERNAL_SERVER_ERROR`: stored JSON is unreadable/invalid

### 3.56 GET `/vc/status-list-index`

- Purpose:
  - Fetch the locally stored status-list next-index counter JSON.
- Request:
  - Query params: none
  - Body: none
- Notes:
  - This returns the raw `status_list_index.json` file as stored on disk.
  - Use this endpoint when you need the allocator counter alone without the full status-list credential payload.
- Success response (`200 OK`):

```json
{
  "next_index": 13
}
```

- Error responses:
  - `404 NOT_FOUND`: local status-list index file is missing
  - `500 INTERNAL_SERVER_ERROR`: stored JSON is unreadable/invalid

### 3.57 GET `/vc/summary`

- Purpose:
  - Return dashboard-style VC counts across issued, own, and peer caches.
- Request:
  - Query params: none
  - Body: none
- Notes:
  - `issued_total`, `own_total`, and `peer_total` are per-cache totals.
  - `active_total`, `revoked_total`, and `expired_total` are computed across unique VC ids to avoid double-counting the same credential if it appears in multiple caches.
  - `next_index` falls back to `0` if the local index file is unavailable.
  - `owner_did` falls back to the local issuer DID, then `"unknown"`, if a configured CA DID is not available.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "issued_total": 2,
  "own_total": 1,
  "peer_total": 1,
  "active_total": 1,
  "revoked_total": 1,
  "expired_total": 0,
  "next_index": 2,
  "owner_did": "did:guardian:z6Mkowner456",
  "circle_id": "guardian-circle-alpha"
}
```

- Error responses:
  - None expected when VC cache directories are absent; totals simply return `0`
  - `500 INTERNAL_SERVER_ERROR`: cache directory scan failure

### 3.58 GET `/vc/audit`

- Purpose:
  - Return VC-related audit events with optional filters.
- Request:
  - Query params:
    - `limit` (optional, integer): maximum number of items to return. Default `100`; capped at `1000`.
    - `action` (optional, string): exact-match action filter.
  - Body: none
- Notes:
  - Returns newest events first.
  - Only VC-category audit records are included.
  - Known derived `action` values include `VC_ISSUED`, `VC_REUSED_NO_CHANGE`, `VC_RENEWED`, `VC_REVOKED`, `VC_VERIFY_SUCCESS`, `VC_VERIFY_FAILED`, `VC_FILE_READ`, `VC_SUMMARY_READ`, and `VC_STATUS_LIST_PULLED`.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "count": 2,
  "items": [
    {
      "timestamp": 3,
      "node_id": "nodeA",
      "severity": "Info",
      "action": "VC_ISSUED",
      "message": "Issued VC urn:uuid:test to did:guardian:test (role=Member, idx=1)"
    },
    {
      "timestamp": 2,
      "node_id": "nodeA",
      "severity": "Info",
      "action": "VC_SUMMARY_READ",
      "message": "VC_SUMMARY_READ: summary requested"
    }
  ]
}
```

- Error responses:
  - `404 NOT_FOUND`: no audit log file could be discovered
  - `500 INTERNAL_SERVER_ERROR`: audit log read failure

---
### 3.59 GET `/vid/show`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "node": "nodeA",
  "did": "did:guardian:abc123...",
  "dkpBytes": 91,
  "dkpVersion": 3,
  "pcrDigest": "3c0d...f9",
  "policyDigest": "9b71...42",
  "nonceI": "6b7d1c8e5f0a1b2c3d4e5f60718293a4",
  "nonceR": "3a29181706f5e4d3c2b1a0f5e8c1d7b6",
  "virtualId": "0f8f3f8f0f1f8c8b6a5d4c3b2a1908076e5d4c3b2a1908076e5d4c3b2a190807",
  "changeReason": "nonce_refreshed",
  "sessionExpiresAt": "2026-06-22T12:01:00Z",
  "sessionTtl": 60
}
```

- Notes:
  - VirtualID is computed as `SHA256(DID || CurrentDKP_PubKey || PCR_values || policy_digest || Nonce_I || Nonce_R)`
  - There is only one VirtualID. It is session-bound and rotates when the daemon refreshes the nonce pair or when DID/DKP/PCR/policy inputs change
  - The current nonce refresh interval is 60 seconds
  - The daemon initializes and maintains this session in the background; this endpoint is a read-only snapshot of the daemon-maintained state
  - `changeReason` is one of `initial_observation`, `dkp_rotated`, `pcr_changed`, `policy_changed`, or `nonce_refreshed`
  - `changeReason` remains the last real reason the current VirtualID changed; steady-state reads do not replace it with `unchanged`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: current VirtualID state could not be loaded

### 3.60 GET `/vid/peers`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "peers": [
    {
      "did": "did:guardian:peer-b",
      "virtualId": "9f0e...1c",
      "observedAt": "2026-06-22T12:00:30Z",
      "lastRotationReason": "nonce_refreshed"
    }
  ]
}
```
---

### 3.61 GET `/discovery/devices`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
[
  {
    "device_id": "7f2c5b1a3d4e90c1",
    "ip": "192.168.50.103",
    "mac": "AA:BB:CC:11:22:33",
    "vendor": "Acme",
    "hostname": "printer",
    "os_fingerprint": "Linux 5.x",
    "os_cpe": [
      "cpe:/o:linux:linux_kernel:5"
    ],
    "open_ports": [
      {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "product_version": "OpenSSH 9.0",
        "cpe": [
          "cpe:/a:openbsd:openssh:9.0"
        ],
        "scripts": []
      }
    ],
    "host_scripts": [],
    "status": "approved",
    "first_seen": "2026-06-12T08:00:00Z",
    "last_seen": "2026-06-12T08:15:00Z",
    "vuln_triaged": false
  }
]
```

- Notes:
  - Reads `/var/lib/sgx-guardian/discovery/inventory.json`
  - Response is a raw JSON array of `ConnectedDevice`
- Error responses:
  - `404 NOT_FOUND`: no discovery inventory exists yet
  - `500 INTERNAL_SERVER_ERROR`: inventory JSON parse failure

### 3.62 GET `/discovery/list`

- Same request/response/errors as `GET /discovery/devices`

### 3.63 GET `/discovery/inventory/list`

- Same request/response/errors as `GET /discovery/devices`

### 3.64 GET `/discovery/devices/unauthorized`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):
  - Same JSON array schema as `GET /discovery/devices`
- Notes:
  - Filters inventory to devices whose `status` is `unauthorized` or `drifted`
- Error responses:
  - `404 NOT_FOUND`: no discovery inventory exists yet
  - `500 INTERNAL_SERVER_ERROR`: inventory JSON parse failure

### 3.65 GET `/discovery/unauthorized`

- Same request/response/errors as `GET /discovery/devices/unauthorized`

### 3.66 POST `/discovery/scan`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "✅ Discovery scan completed\ntarget: 192.168.50.0/24\nintensity: standard\nnew_devices: 1\nupdated_devices: 2\ninventory: /var/lib/sgx-guardian/discovery/inventory.json\n",
  "stderr": "",
  "timestamp": "2026-06-12T08:15:00+00:00"
}
```

- Notes:
  - Executes `sgx-pa-cli discovery scan`
  - If the CLI process exits non-zero, endpoint still returns `200 OK` with `success=false`
  - Ad-hoc scan intensity follows the current discovery config's effective manual/default intensity
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` not found or command spawn failed

### 3.67 POST `/discovery/scan/stealth`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):
  - Same schema as `POST /discovery/scan`
- Notes:
  - Executes `sgx-pa-cli discovery scan --intensity stealth`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` not found or command spawn failed

### 3.68 POST `/discovery/scan/standard`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):
  - Same schema as `POST /discovery/scan`
- Notes:
  - Executes `sgx-pa-cli discovery scan --intensity standard`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` not found or command spawn failed

### 3.69 POST `/discovery/scan/aggressive`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):
  - Same schema as `POST /discovery/scan`
- Notes:
  - Executes `sgx-pa-cli discovery scan --intensity aggressive`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` not found or command spawn failed

### 3.70 POST `/discovery/approve`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "mac": "AA:BB:CC:11:22:33",
  "label": "Office printer"
}
```

  - Required fields: `mac`
- Success response (`200 OK`):

```json
{
  "success": true,
  "created": true,
  "inventory_updated": 1,
  "entry": {
    "mac": "AA:BB:CC:11:22:33",
    "label": "Office printer",
    "expected_os": null,
    "expected_ports": [],
    "expected_ips": []
  }
}
```

- Notes:
  - Adds or updates the MAC inside `/etc/sgx-guardian/discovery/whitelist.yaml`
  - Immediately reclassifies matching non-stale inventory records so approved devices become authorized without waiting for the next scan
- Error responses:
  - `400 BAD_REQUEST`: invalid or empty MAC address
  - `500 INTERNAL_SERVER_ERROR`: whitelist read/write or inventory refresh failure
  - `415`/`422`: invalid JSON body

### 3.71 GET `/discovery/whitelist`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "version": "1.0",
  "devices": [
    {
      "mac": "AA:BB:CC:11:22:33",
      "label": "Office printer",
      "expected_os": "Linux",
      "expected_ports": [
        22,
        9100
      ],
      "expected_ips": [
        "192.168.50.103/32"
      ]
    }
  ]
}
```

- Notes:
  - Missing or empty whitelist file returns the default empty document
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: whitelist YAML parse failure or file I/O error

### 3.72 PUT `/discovery/whitelist`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "version": "1.0",
  "devices": [
    {
      "mac": "AA:BB:CC:11:22:33",
      "label": "Office printer",
      "expected_os": "Linux",
      "expected_ports": [
        22,
        9100
      ],
      "expected_ips": [
        "192.168.50.103/32"
      ]
    }
  ]
}
```

  - Required fields: none (`version` defaults to `"1.0"` when empty)
- Success response (`200 OK`):
  - Same schema as `GET /discovery/whitelist`
- Notes:
  - Writes `/etc/sgx-guardian/discovery/whitelist.yaml` atomically
  - Refreshes matching non-stale inventory statuses after the whitelist update
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: whitelist serialization/write or inventory refresh failure
  - `415`/`422`: invalid JSON body

### 3.73 GET `/discovery/schedule`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "enabled": false,
  "target_cidr": null,
  "timeout_secs": 600,
  "exclude": [],
  "schedules": {
    "hourly": {
      "intensity": "standard"
    },
    "daily": {
      "intensity": "aggressive"
    }
  }
}
```

- Notes:
  - `target_cidr: null` means the scheduler auto-detects the device's active LAN CIDR at runtime
  - For legacy YAML files, an additional optional field may appear:
    - `legacy_schedule_mode`
- Error responses:
  - `400 BAD_REQUEST`: existing `nmap.yaml` is invalid

### 3.74 PUT `/discovery/schedule`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "enabled": true,
  "target_cidr": "192.168.50.0/24",
  "timeout_secs": 600,
  "exclude": [
    "192.168.50.1"
  ],
  "schedules": {
    "hourly": {
      "intensity": "standard"
    },
    "daily": {
      "intensity": "aggressive"
    }
  }
}
```

### 3.75 GET `/audit/logs`

- Request:
  - Query params:
    - `node` (string, optional): Node ID to query (e.g. `nodeA`, `nodeB`). Defaults to the local node.
    - `tail` (integer, optional): Number of recent log lines to fetch from the end of the file.
    - `category` (string, optional): Filter by event category (e.g. `Node`, `Network`, `Tls`, `Attestation`). Case-insensitive.
    - `severity` (string, optional): Filter by severity level (`info`, `warn` / `warning`, `error` / `critical`, or `all` to disable filtering). Case-insensitive.
    - `search` (string, optional): Search keyword to filter messages containing this string. Case-insensitive.
  - Body: none
- Success response (`200 OK`):

```json
{
  "status": "success",
  "count": 1,
  "items": [
    {
      "event": {
        "timestamp": 1782890986,
        "node_id": "nodeA",
        "category": "Network",
        "severity": "Info",
        "action": "Started",
        "message": "Outbound TLS ping attempt to 127.0.0.1:50053"
      },
      "hash": "15bf4c872ab11b791f441e30048be704769c94fd2f635d18f03312d7ea768063",
      "previous_hash": "ab349eda70ce23a12db7293365bccf6f4adcfd3649fb0ece1e23b30425642777"
    }
  ]
}
```

- Notes:
  - Reads secure tamper-evident audit logs from `/var/log/sgx-guardian/audit-{node}.log` (production) or `logs/audit-{node}.log` (development).
  - Returns entries in reverse chronological order (newest first).
- Error responses:
  - `404 NOT_FOUND`: no audit log file found for node `{node}`
  - `500 INTERNAL_SERVER_ERROR`: failed to open, read, or parse audit log file

