# SG-X Guardian REST API Details

**Version:** 2.2
**Port:** `8443`
**Base URL:** `https://<nodeA-ip>:8443/api/v1`
**Example NodeA IP:** `192.168.1.10`

Transport notes:

- Each Guardian exposes its own authenticated admin/service API on `:8443`; examples use `nodeA` where the owner/CA role is being described.
- Plaintext `http://<nodeA-ip>:8443` is rejected; use HTTPS on `:8443`.
- The NodeA device certificate is self-signed by default, so clients must trust or pin it explicitly.
- Local email/password login remains active. Cylenium SSO is stubbed and disabled by default.

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
| 69a | GET | `/discovery/runs?view=history` | List persisted NMAP discovery scan run history |
| 70 | POST | `/discovery/scan` | Run discovery scan using default ad-hoc intensity |
| 71 | POST | `/discovery/scan/stealth` | Run one stealth NMAP discovery scan |
| 72 | POST | `/discovery/scan/standard` | Run one standard NMAP discovery scan |
| 73 | POST | `/discovery/scan/aggressive` | Run one aggressive NMAP discovery scan |
| 74 | POST | `/discovery/approve` | Authorize a discovered device by MAC and add it to whitelist |
| 75 | GET | `/discovery/whitelist` | Fetch whitelist policy enriched with current inventory matches |
| 76 | PUT | `/discovery/whitelist` | Replace discovery whitelist and refresh inventory statuses |
| 77 | GET | `/discovery/schedule` | Fetch scheduled NMAP discovery configuration |
| 78 | PUT | `/discovery/schedule` | Update scheduled NMAP discovery configuration |
| 79 | GET | `/discovery/summary` | Aggregate inventory stats: totals, open ports, risk counts, last_seen_at |
| 80 | GET | `/discovery/devices/{device_id}` | Full device detail with risk_level, risk_reasons, and flagged_ports |
| 81 | GET | `/discovery/runs?view=raw` | Actual scan run history from raw XML archive (default mode) |
| 82 | GET | `/threat/status` | Suricata service state, block mode, alert and block counts |
| 83 | GET | `/threat/alerts` | List parsed Suricata alerts from Guardian threat inventory |
| 84 | GET | `/threat/modbus` | Group recent Modbus alerts into the 5 Guardian Modbus rule buckets |
| 85 | GET | `/threat/blocks` | List currently blocked IPs from the threat blocker |
| 86 | POST | `/threat/blocks` | Manually block an IP and persist the block record |
| 87 | POST | `/threat/blocks/unblock` | Remove one IP from the active threat block list |
| 88 | POST | `/threat/rules/update` | Trigger `suricata-update` and reload validated rules |
| 89 | POST | `/threat/validate` | Validate Guardian threat config and Suricata YAML |
| 90 | GET | `/threat/config` | Read current Guardian threat config |
| 91 | POST | `/threat/config` | Patch threat config fields; effective within 5 seconds |
| 92 | POST | `/threat/start` | Start Suricata via `systemctl start suricata` when offline |
| 92a | GET | `/advisory/recommendations` | List recent AI alert remediation advisory recommendations |
| 92b | GET | `/threat/alerts/{id}/recommendation` | Fetch the advisory recommendation for one threat alert |
| 92c | GET | `/advisory/rules` | Read the active advisory recommendation rules |
| 92d | PUT | `/advisory/rules` | Replace the advisory recommendation rules |
| 93 | POST | `/crl/revoke` | Issue a DID revocation entry and rebuild the signed CRL |
| 94 | GET | `/crl/list` | List all locally persisted CRL entries |
| 95 | GET | `/crl/entry` | Fetch one CRL entry by entry ID |
| 96 | GET | `/crl/check` | Check whether a DID is currently revoked |
| 97 | POST | `/crl/verify` | Verify CRL entry signatures and aggregate root |
| 98 | GET | `/crl/root` | Return current CRL sequence and Merkle root |
| 99 | POST | `/crl/unrevoke` | Reverse a mistaken revocation (Circle Owner only) |
| 100 | GET | `/wifi/mode` | Retrieve active network orchestration mode, status, and module configurations |
| 101 | POST | `/wifi/mode` | Update network orchestration mode (DualWifi, HotspotOnly, ClientOnly, Off) |
| 102 | GET | `/wifi/scan` | Perform Wi-Fi scan for visible access points in range |
| 103 | GET | `/wifi/clients` | Retrieve active hotspot connected DHCP client leases |
| 104 | GET | `/crl/offline/status` | Offline CRL sync status, counters, and per-peer version-vector view |
| 105 | GET | `/crl/offline/pending` | List queued offline revocations with retry metadata |
| 106 | POST | `/crl/offline/sync` | Trigger one offline CRL sync cycle immediately |
| 107 | POST | `/backup/create` | Create an encrypted backup bundle |
| 107a | POST | `/backup/import` | Import an existing encrypted backup bundle |
| 108 | GET | `/backup/history` | List local backup bundle history |
| 109 | GET | `/backup/download/{id}` | Download one encrypted backup bundle |
| 110 | DELETE | `/backup/{id}` | Delete one local backup bundle |
| 111 | POST | `/backup/validate` | Validate and inspect an encrypted backup bundle |
| 112 | POST | `/backup/restore` | Legacy restore endpoint; returns migration guidance |
| 113 | POST | `/restore/validate` | Preflight a restore plan without modifying files |
| 114 | GET | `/restore/status` | Return current restore journal status |
| 115 | POST | `/restore/apply` | Apply a confirmed restore transaction |
| 116 | POST | `/restore/undo` | Undo the last committed restore from its snapshot |
| 117 | GET | `/managed-devices` | List Managed Devices |
| 118 | GET | `/managed-devices/{device_id}` | Get Managed Device Details and Scores |
| 119 | POST | `/managed-devices` | Create Manual Managed Device |
| 120 | DELETE | `/managed-devices/{device_id}` | Remove Managed Device |
| 121 | POST | `/managed-devices/{device_id}/scan` | Start Per-Device Security Scan |
| 122 | GET | `/managed-devices/{device_id}/scan/{scan_id}` | Get Live Per-Device Scan Progress and Final Report |
| 123 | POST | `/managed-devices/{device_id}/reject` | Reject and Block Managed Device |
| 124 | POST | `/managed-devices/{device_id}/block` | Block Device Using nftables |
| 125 | POST | `/managed-devices/{device_id}/unblock` | Unblock Device and Remove nftables Rule |
| 79 | GET | `/cert/requests` | List all active/pending node certificate requests |
| 80 | POST | `/cert/approve` | Approve or reject a pending certificate request |


## 2. NEW Endpoints

### 2.1 Auth, Session & Paired Devices

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/signup` | Create the initial operator account when no local admin exists yet |
| POST | `/auth/login` | Authenticate an operator and issue a bearer session token |
| GET | `/auth/session` | Validate the current session token and return operator/session summary |
| POST | `/auth/logout` | Revoke the current session token |
| GET | `/audit/logs` | Fetch secure tamper-evident audit logs with filters |
| GET | `/devices` | List all paired Guardian devices visible to the signed-in operator |
| GET | `/devices/paired` | Alias of paired-device list for frontend compatibility |
| GET | `/devices/unpaired` | List unpaired Guardian records from the admin device registry |
| GET | `/devices/all` | List all Guardian records from the admin device registry |
| POST | `/devices/pair` | Submit pairing proof and bind a Guardian device to the current operator |
| GET | `/devices/pairing-code` | Generate a short-lived pairing code for QR or serial onboarding |
| GET | `/devices/pairing-status` | Poll pairing/bootstrap status for a device serial |
| GET | `/devices/{device_id}` | Return one paired device detail by device ID |
| GET | `/devices/paired/{device_id}` | Alias of paired-device detail lookup |
| GET | `/devices/{device_id}/status` | Read current persisted/runtime status available for a paired Guardian |
| POST | `/devices/{id}/unpair` | Unpair one Guardian device from the current operator account |

### 2.2 Discovery & Threat

| Method | Path | Purpose |
|---|---|---|
| GET | `/discovery/summary` | Aggregate inventory stats: totals, open ports, risk counts, last_seen_at |
| GET | `/discovery/devices/{device_id}` | Full device detail with risk_level, risk_reasons, and flagged_ports |
| GET | `/discovery/runs?view=raw` | Actual scan run history from raw XML archive (default mode) |
| GET | `/discovery/runs?view=history` | Persisted NMAP discovery scan run history |
| GET | `/threat/status` | Suricata service state, block mode, alert and block counts |
| GET | `/threat/alerts` | Read recent Suricata alerts with optional `limit` and `severity` filters |
| GET | `/threat/modbus` | Group recent Modbus alerts into the 5 Guardian Modbus rule buckets |
| GET | `/threat/blocks` | Return the currently blocked IP list from nftables or persisted state |
| POST | `/threat/blocks` | Manually block an IP with nftables + persisted TTL |
| POST | `/threat/blocks/unblock` | Remove a blocked IP and rebuild the threat nftables chain |
| POST | `/threat/rules/update` | Run `sgx-pa-cli threat rules-update` and return command output |
| POST | `/threat/validate` | Run `sgx-pa-cli threat validate` to validate threat + Suricata config |
| GET | `/threat/config` | Read full Guardian threat config as JSON |
| POST | `/threat/config` | Patch threat config fields; live-reloaded within 5 seconds |
| POST | `/threat/start` | Start Suricata if offline via `systemctl start suricata` |
| GET | `/advisory/recommendations` | List recent AI alert remediation advisory recommendations |
| GET | `/threat/alerts/{id}/recommendation` | Fetch the advisory recommendation for one threat alert |
| GET | `/advisory/rules` | Read the active advisory recommendation rules |
| PUT | `/advisory/rules` | Replace the advisory recommendation rules |

### 2.3 Identity, CRL & Network Control

| Method | Path | Purpose |
|---|---|---|
| POST | `/crl/revoke` | Issue a CRL revocation entry for a DID |
| GET | `/crl/list` | Return all CRL entries |
| GET | `/crl/entry` | Return one CRL entry by `id` |
| GET | `/crl/check` | Return `{ revoked, entry }` for a DID |
| POST | `/crl/verify` | Verify CRL signatures, role rules, and Merkle root |
| GET | `/crl/root` | Return CRL sequence and Merkle root |
| POST | `/crl/unrevoke` | Reverse a mistaken revocation (Circle Owner only) |
| GET | `/crl/gossip/status` | Return CRL gossip engine counters, thresholds, and last-round summary |
| POST | `/crl/gossip/trigger` | Trigger one CRL gossip round immediately |
| GET | `/crl/emergency/status` | Return emergency revocation channel health and last-notice summary |
| POST | `/crl/emergency/broadcast` | Broadcast a critical CRL revocation immediately to active peers |
| GET | `/crl/emergency/notifications` | Return the durable emergency-revocation notification feed |
| GET | `/crl/emergency/debug/session` | Inspect seeded emergency session state for a DID |
| POST | `/crl/emergency/debug/session` | Seed a test emergency session for debug validation |
| GET | `/crl/offline/status` | Return offline sync enablement, counters, and peer sync-state snapshot |
| GET | `/crl/offline/pending` | Return queued revocations with attempts, timestamps, and parked state |
| POST | `/crl/offline/sync` | Run one offline fetch-and-flush cycle on demand |
| GET | `/wifi/mode` | Retrieve active network orchestration mode, status, and module configurations |
| POST | `/wifi/mode` | Update network orchestration mode (DualWifi, HotspotOnly, ClientOnly, Off) |
| GET | `/wifi/scan` | Perform Wi-Fi scan for visible access points in range |
| GET | `/wifi/clients` | Retrieve active hotspot connected DHCP client leases |
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
| GET | `/dusage/current` | Return current-period bandwidth usage snapshot |
| GET | `/dusage/history` | Return completed period usage history |
| GET | `/dusage/quota` | Return configured signed data-usage quota |
| PUT | `/dusage/quota` | Update configured signed data-usage quota |
| POST | `/dusage/reset` | Reset or re-baseline the current usage period |

### 2.4 Geofencing

| Method | Path | Purpose |
|---|---|---|
| GET | `/geofence/zones` | List configured geofence zones |
| POST | `/geofence/zones` | Create a new geofence zone |
| PATCH | `/geofence/zones/{id}` | Edit one geofence zone definition |
| DELETE | `/geofence/zones/{id}` | Delete one geofence zone |
| POST | `/geofence/zones/{id}/capture-rf` | Capture RF fingerprint data for a zone |
| GET | `/geofence/location` | Return the current computed device/location state |
| POST | `/geofence/location` | Report or update the latest observed location sample |
| GET | `/geofence/status` | Return current geofence engine status and active zone decision |
| GET | `/geofence/events` | List geofence transition events |
| GET | `/geofence/alerts` | List geofence alert history |
| GET | `/geofence/zones/{id}/actions` | Return configured actions for one geofence zone |
| PUT | `/geofence/zones/{id}/actions` | Replace or update action rules for one geofence zone |
| POST | `/geofence/actions/test` | Trigger a dry-run/test execution of geofence actions |

### 2.5 Backup & Restore

| Method | Path | Purpose |
|---|---|---|
| POST | `/backup/create` | Create an encrypted backup bundle |
| POST | `/backup/import` | Import an existing encrypted backup bundle |
| GET | `/backup/history` | List local backup bundle history |
| GET | `/backup/download/{id}` | Download one encrypted backup bundle |
| DELETE | `/backup/{id}` | Delete one local backup bundle |
| POST | `/backup/validate` | Validate and inspect an encrypted backup bundle |
| POST | `/backup/restore` | Legacy restore endpoint; returns migration guidance |
| POST | `/restore/validate` | Preflight a restore plan without modifying files |
| GET | `/restore/status` | Return current restore journal status |
| POST | `/restore/apply` | Apply a confirmed restore transaction |
| POST | `/restore/undo` | Undo the last committed restore from its snapshot |

### 2.6 Device Security & Fleet Operations

| Method | Path | Purpose |
|---|---|---|
| GET | `/managed-devices` | List Managed Devices |
| GET | `/managed-devices/summary` | Return managed-device fleet totals, risk posture, and block counters |
| GET | `/managed-devices/{device_id}` | Get Managed Device Details and Scores |
| POST | `/managed-devices` | Create Manual Managed Device |
| PATCH | `/managed-devices/{device_id}` | Edit managed-device metadata or operator-maintained fields |
| DELETE | `/managed-devices/{device_id}` | Remove Managed Device |
| POST | `/managed-devices/{device_id}/scan` | Start Per-Device Security Scan |
| GET | `/managed-devices/{device_id}/scan/{scan_id}` | Get Live Per-Device Scan Progress and Final Report |
| POST | `/managed-devices/{device_id}/reject` | Reject and Block Managed Device |
| POST | `/managed-devices/{device_id}/block` | Block Device Using nftables |
| POST | `/managed-devices/{device_id}/unblock` | Unblock Device and Remove nftables Rule |

### 2.7 Circles, Notifications & Automation Rules

| Method | Path | Purpose |
|---|---|---|
| GET | `/circles` | List circles available to the current operator |
| POST | `/circles` | Create a new circle |
| GET | `/circles/{id}` | Return one circle detail and membership summary |
| PATCH | `/circles/{id}` | Edit one circle's metadata or settings |
| POST | `/circles/{id}/archive` | Archive an existing circle |
| POST | `/circles/{id}/unarchive` | Unarchive an archived circle and return it to active state |
| DELETE | `/circles/{id}` | Delete a non-mesh circle and revoke every membership VC issued for that circle |
| GET | `/circles/{id}/members` | List members of a circle |
| POST | `/circles/{id}/members` | Add a member to a circle |
| PATCH | `/circles/{id}/members/{did}` | Change one member's circle role |
| DELETE | `/circles/{id}/members/{did}` | Remove one member from a circle |
| GET | `/circles/{id}/invites` | List active circle invites |
| POST | `/circles/{id}/invites` | Mint and deliver a DID-targeted invite for a circle |
| DELETE | `/circles/{id}/invites/{invite_id}` | Revoke one circle invite |
| GET | `/circles/invites/inbox` | List circle invitations received by the local Guardian |
| POST | `/circles/invites/inbox` | Receive a delivered circle invite from a trusted Guardian service peer |
| POST | `/circles/invites/{invite_id}/accept` | Accept one received circle invitation |
| POST | `/circles/invites/{invite_id}/reject` | Reject one received circle invitation |
| POST | `/circles/join/preview` | Validate or preview an inbound circle invite before joining |
| POST | `/circles/join` | Join a circle using invite material |
| POST | `/circles/redeem` | Redeem a circle invite token |
| GET | `/notifications/stream` | Open the live notification event stream |
| GET | `/notifications` | List notification history |
| GET | `/notifications/unread-count` | Return unread notification counters |
| POST | `/notifications/{id}/read` | Mark one notification as read |
| POST | `/notifications/read-all` | Mark all notifications as read |
| GET | `/notifications/prefs` | Fetch notification preference settings |
| PUT | `/notifications/prefs` | Update notification preference settings |
| GET | `/rules` | List automation rules |
| POST | `/rules` | Create a new automation rule |
| GET | `/rules/executions` | List automation rule execution history |
| GET | `/rules/{id}` | Return one automation rule definition |
| PATCH | `/rules/{id}` | Edit one automation rule |
| DELETE | `/rules/{id}` | Delete one automation rule |
| POST | `/rules/{id}/enable` | Enable or disable one automation rule |
| POST | `/rules/{id}/test` | Execute a dry-run test for one automation rule |

#### Circle Invite Flow

Circle invitations are DID-based. The Guardian DID is the canonical member identity; IP address, host, and port are transport metadata only.

Owner flow:

```text
Create Circle
→ select target Guardian DID
→ POST /circles/{id}/invites
→ backend resolves/delivers invite to target Guardian
→ target sees pending inbox invite
→ Accept/Reject
→ Accept issues membership VC
→ member becomes active on both nodes
```

QR/share-link fallback must not depend on `owner_host=127.0.0.1` for cross-device use. Automatic DID-based backend delivery is the primary path; QR/link is fallback.

Frontend/operator calls use:

```http
Authorization: Bearer <session-token>
```

Guardian-to-Guardian invite delivery uses authenticated/signed service requests between trusted Guardians. The frontend user bearer token must not be blindly reused as Node-B authentication. Remote invite delivery and accept/redeem requests are verified with Guardian DID/DKP proofs, target-DID binding, expiry/replay checks, and CRL/security-state checks. Circle receive endpoints are not public; missing operator or trusted peer/service authentication returns `401 UNAUTHORIZED`.

Frontend integration:

```text
POST /circles/{id}/invites
GET  /circles/invites/inbox
POST /circles/invites/{invite_id}/accept
POST /circles/invites/{invite_id}/reject
GET  /circles
GET  /circles/{id}/members
```

Incoming invite notifications should be surfaced through the existing notification stream/history UI, then reconciled with `GET /circles/invites/inbox` for the actionable Accept/Reject state.

Expected UI behavior:

```text
Owner:
Select DID → Send Invite → Invited/Pending

Member:
Incoming Invite notification
→ Accept / Reject

Accept:
VC issued → Circle appears → Active member
```

#### POST `/circles/{id}/invites`

Purpose:

- Mint a signed invite for a specific target Guardian DID.
- Resolve `target_did` to its DID Document service endpoint and deliver the invite to the target Guardian.
- Keep the member in `invited`/pending state until the target Guardian accepts.

Request:

- Auth: `Authorization: Bearer <session-token>` required
- Path params:
  - `id` (`string`): Circle id
- JSON body:

```json
{
  "target_did": "did:guardian:...",
  "role": "member"
}
```

- Required fields:
  - `target_did` (`string`, DID): canonical invite target and future member identity.
- Optional fields:
  - `role` (`string`): `member` or `owner`. Defaults to `member`.
  - `expires_in_minutes` (`integer`): invite TTL.
  - `max_uses` (`integer`): defaults to `1`.
  - `deliver` (`boolean`): defaults to `true`; when `false`, only QR/link fallback material is produced.
  - `owner_host` (`string`): legacy/fallback share-link metadata only; not the member identity.

Success response (`201 Created`):

```json
{
  "status": "success",
  "invite_id": "urn:uuid:...",
  "token_b64": "...",
  "qr_payload": "sgx-guardian://circle/join?...",
  "link": "sgx-guardian://circle/join?...",
  "expires_at": "2026-08-12T12:00:00Z",
  "delivered": true,
  "delivery_error": null,
  "invite": {
    "circleId": "circle-ops",
    "issuerDid": "did:guardian:owner...",
    "targetDid": "did:guardian:member...",
    "role": "Member",
    "expiresAt": "2026-08-12T12:00:00Z",
    "nonce": "...",
    "proof": {}
  }
}
```

Notes:

- `delivered: true` means the remote Guardian successfully received and stored the invite.
- `delivered: false` with `delivery_error` means QR/link fallback material was still generated, but automatic backend delivery failed or was disabled.
- DID is the canonical member identity. IP/host is transport metadata only.
- The owner UI should show the target member as `invited`/pending until acceptance. Membership becomes `active` only after signed acceptance is verified and a membership VC is issued.

Error responses:

- `400 BAD_REQUEST`: missing/invalid `target_did`, invalid role/TTL, DID resolution failure, expired/invalid invite, unreachable endpoint, or invalid delivery response
- `401 UNAUTHORIZED`: missing operator token or missing trusted peer/service authentication for Guardian-to-Guardian delivery
- `403 FORBIDDEN`: local Guardian is not authorized to invite for this Circle
- `404 NOT_FOUND`: Circle not found
- `409 CONFLICT`: Circle is archived or target DID is revoked by CRL
- `500 INTERNAL_SERVER_ERROR`: DID/key material, signing, persistence, or state-sync failure

#### GET `/circles/invites/inbox`

Purpose:

- List Circle invitations received by the local Guardian.

Request:

- Auth: `Authorization: Bearer <session-token>` required
- Query params: none
- Body: none

Success response (`200 OK`):

```json
{
  "status": "success",
  "count": 1,
  "invites": [
    {
      "invite": {
        "id": "urn:uuid:...",
        "circleId": "circle-ops",
        "circleName": "Ops",
        "issuerDid": "did:guardian:owner...",
        "targetDid": "did:guardian:member...",
        "role": "Member",
        "expiresAt": "2026-08-12T12:00:00Z"
      },
      "receivedAt": "2026-08-12T10:00:00Z",
      "state": "pending",
      "updatedAt": "2026-08-12T10:00:00Z"
    }
  ]
}
```

States:

- `pending`
- `accepted`
- `rejected`
- `expired`

Error responses:

- `401 UNAUTHORIZED`: missing or invalid operator session token
- `500 INTERNAL_SERVER_ERROR`: inbox persistence read failure

#### POST `/circles/invites/inbox`

Purpose:

- Receive and store a signed Circle invitation delivered by another trusted Guardian.
- Verify the invite proof before placing it in the local pending inbox.
- Verify the invite `targetDid`/`target_did` matches the local Guardian DID.

Request:

- Auth: Guardian-to-Guardian trusted peer/service authentication required. This endpoint is not public and is not a frontend/operator call.
- Query params: none
- JSON body: signed invite token

```json
{
  "id": "urn:uuid:...",
  "circleId": "circle-ops",
  "issuerDid": "did:guardian:owner...",
  "targetDid": "did:guardian:member...",
  "role": "Member",
  "expiresAt": "2026-08-12T12:00:00Z",
  "nonce": "...",
  "proof": {}
}
```

Success response (`201 Created`):

```json
{
  "status": "success",
  "message": "Circle invite received",
  "invite": {
    "state": "pending"
  }
}
```

Error responses:

- `400 BAD_REQUEST`: invalid signed invite, target DID mismatch, expired invite, or DID resolution/proof failure
- `401 UNAUTHORIZED`: missing trusted peer/service authentication
- `409 CONFLICT`: issuer or target DID is revoked by CRL
- `500 INTERNAL_SERVER_ERROR`: inbox persistence failure

#### POST `/circles/invites/{invite_id}/accept`

Purpose:

- Verify the signed invite.
- Verify target DID matches the local Guardian DID.
- Verify expiry, replay, security state, and CRL status.
- Send signed acceptance to the owner Guardian.
- Issue/store Circle membership VC.
- Persist the Circle locally.
- Change membership to `active`.

Request:

- Auth: `Authorization: Bearer <session-token>` required
- Path params:
  - `invite_id` (`string`): invite id. Values such as `urn:uuid:...` should be URL-encoded when used in the path.
- Body: none

Success response (`201 Created`):

```json
{
  "status": "success",
  "message": "Circle membership issued",
  "vc": {},
  "circle": {}
}
```

Error responses:

- `400 BAD_REQUEST`: invalid/expired/replayed invite, target DID mismatch, signature failure, owner endpoint resolution failure, or owner redeem failure
- `401 UNAUTHORIZED`: missing operator token or missing trusted peer/service authentication
- `404 NOT_FOUND`: invite id not found in local inbox
- `409 CONFLICT`: invite rejected, Circle archived, or DID revoked by CRL
- `500 INTERNAL_SERVER_ERROR`: signing, VC persistence, Circle persistence, or state-sync failure

#### POST `/circles/invites/{invite_id}/reject`

Purpose:

- Reject a pending invitation.
- Update inbox state to `rejected`.
- Do not issue a membership VC.
- Do not activate Circle membership.

Request:

- Auth: `Authorization: Bearer <session-token>` required
- Path params:
  - `invite_id` (`string`): invite id. Values such as `urn:uuid:...` should be URL-encoded when used in the path.
- Body: none

Success response (`200 OK`):

```json
{
  "status": "success",
  "message": "Circle invite rejected",
  "invite": {
    "state": "rejected"
  }
}
```

Error responses:

- `401 UNAUTHORIZED`: missing or invalid operator session token
- `404 NOT_FOUND`: invite id not found in local inbox
- `500 INTERNAL_SERVER_ERROR`: inbox persistence update failure

### 2.8 File Transfer & Vault

| Method | Path | Purpose |
|---|---|---|
| POST | `/xfer/send` | Send a file transfer to an in-circle peer |
| GET | `/xfer/transfers` | List file transfer jobs and statuses |
| GET | `/xfer/transfers/{id}` | Return one file transfer detail |
| POST | `/xfer/transfers/{id}/cancel` | Cancel an in-flight file transfer |
| GET | `/xfer/inbox` | List received file transfers or inbox items |
| GET | `/vault/overview` | Return encrypted vault overview and storage totals |
| GET | `/vault/quota` | Return vault quota usage and remaining capacity |
| GET | `/vault/tree` | Return the vault folder tree |
| GET | `/vault/search` | Search vault files and folders |
| POST | `/vault/upload` | Upload a file into the encrypted vault |
| GET | `/vault/folders` | List vault folders |
| POST | `/vault/folders` | Create a vault folder |
| PATCH | `/vault/folders/{folder_id}` | Rename or move a vault folder |
| DELETE | `/vault/folders/{folder_id}` | Delete a vault folder |
| GET | `/vault/files` | List vault files |
| GET | `/vault/files/{id}` | Return one vault file detail |
| PATCH | `/vault/files/{id}` | Rename or move a vault file |
| DELETE | `/vault/files/{id}` | Delete a vault file |
| GET | `/vault/files/{id}/download` | Download one vault file |
| GET | `/vault/files/{id}/preview` | Stream or render a vault file preview |
| POST | `/vault/files/{id}/star` | Toggle the starred state for a vault file |

### 2.9 Chat & Calling

| Method | Path | Purpose |
|---|---|---|
| POST | `/chat/send` | Send a chat message to a peer or conversation |
| POST | `/chat/read` | Mark one or more chat messages as read |
| POST | `/chat/sync` | Trigger chat sync across nodes/peers |
| GET | `/chat/history` | Return chat history for the requested conversation view |
| GET | `/chat/ws` | Open the live chat WebSocket stream |
| POST | `/chat/upload` | Upload a chat attachment |
| GET | `/chat/download/{attachment_id}` | Download a stored chat attachment |
| POST | `/call/initiate` | Initiate a direct call session |
| GET | `/calls` | List call sessions |
| POST | `/calls/initiate` | Initiate a browser/WebRTC call session |
| GET | `/calls/active` | List active call sessions |
| GET | `/calls/events` | Stream or poll live call events |
| GET | `/calls/ice-servers` | Return ICE/TURN server configuration for call setup |
| POST | `/call/{session_id}/signal` | Submit a signaling message for a call session |
| GET | `/call/{session_id}/signals` | Read buffered signaling messages for a call session |
| GET | `/call/{session_id}/ws` | Open the call signaling WebSocket channel |
| POST | `/call/{session_id}/media-ready` | Mark direct-call media readiness for a session |
| POST | `/call/{session_id}/quality` | Report call quality metrics for a session |
| POST | `/call/accept` | Accept a direct call invitation |
| POST | `/call/{session_id}/accept` | Accept a browser/WebRTC call session |
| POST | `/call/reject` | Reject a direct call invitation |
| POST | `/call/{session_id}/reject` | Reject a browser/WebRTC call session |
| POST | `/call/end` | End a direct call session |
| GET | `/call/{session_id}/status` | Return current status for one call session |
| POST | `/call/policy-check` | Verify whether a call may proceed under active policy |
| POST | `/group-calls` | Create a group call session |
| GET | `/group-calls/active` | List active group call sessions |
| GET | `/group-calls/events` | Stream or poll live group-call events |
| POST | `/group-call/{group_id}/join` | Join a group call |
| POST | `/group-call/{group_id}/decline` | Decline a group call invite |
| POST | `/group-call/{group_id}/leave` | Leave a group call session |
| POST | `/group-call/{group_id}/end` | End a group call session |
| POST | `/group-call/{group_id}/moderate` | Perform moderator actions for a group call |
| POST | `/group-call/{group_id}/signal` | Submit a signaling message for a group call |
| GET | `/group-call/{group_id}/signals` | Read buffered signaling messages for a group call |
| POST | `/group-call/{group_id}/media-ready` | Mark group-call media readiness |
| POST | `/group-call/{group_id}/heartbeat` | Send a presence heartbeat for a group call participant |
| GET | `/group-call/{group_id}/ws` | Open the group-call WebSocket signaling channel |
---

## 6. Backup & Restore Endpoint Contracts

### 3.86 POST `/backup/create`

- Purpose: Create an encrypted local backup bundle and append it to backup history.
- Method: `POST`
- Full path: `/api/v1/backup/create`
- Path parameters: none
- Request body:

```json
{
  "passphrase": "correct horse battery staple",
  "portable": true
}
```

- Success response (`200 OK`):

```json
{
  "id": "backup-...",
  "created_at": "2026-07-27T12:00:00Z",
  "source_node_id": "nodeA",
  "source_did": "did:guardian:...",
  "portable": true,
  "components": ["policy", "config", "credentials", "crl"],
  "bundle_path": "/var/lib/sgx-guardian/backup/bundles/backup-....sgxbak",
  "size_bytes": 123456
}
```

- Error responses:
  - `400 BAD_REQUEST`: `passphrase` is empty
  - `413 PAYLOAD_TOO_LARGE`: generated bundle exceeds configured maximum size
  - `500 INTERNAL_SERVER_ERROR`: backup gathering, encryption, filesystem, or history write failure

### 3.86a POST `/backup/import`

- Purpose: Import an existing encrypted `.sgxbak` bundle into the local backup store.
- Method: `POST`
- Full path: `/api/v1/backup/import`
- Request body: `multipart/form-data`
  - `file` (required): `.sgxbak` bundle upload. Filenames containing paths, traversal, or non-`.sgxbak` names are rejected.
  - `passphrase` (required): passphrase used to decrypt and validate the bundle.
- Behavior:
  - Upload is first written to a temporary import directory under the backup base.
  - Bundle size is capped by the configured backup bundle limit.
  - The bundle is decrypted and validated before registration, including HMAC, passphrase, manifest schema, backup ID, source DID, component schemas, and manifest paths.
  - If the source DID differs from the target DID, the bundle manifest must have `portable: true`.
  - Existing backup IDs are rejected and existing bundle files are never overwritten.
  - The validated bundle is atomically published to `/var/lib/sgx-guardian/backup/bundles/<backup-id>.sgxbak` and registered through the backup history persistence model.
- Success response (`200 OK`):

```json
{
  "id": "backup-...",
  "created_at": "2026-07-27T12:00:00Z",
  "source_node_id": "nodeA",
  "source_did": "did:guardian:...",
  "target_did": "did:guardian:...",
  "portable": true,
  "components": ["policy", "config", "credentials", "crl"],
  "bundle_path": "/var/lib/sgx-guardian/backup/bundles/backup-....sgxbak",
  "size_bytes": 123456
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing required fields, extra multipart fields, empty passphrase, invalid filename, or unsafe backup ID
  - `409 CONFLICT`: integrity/schema validation fails, source DID differs and bundle is not portable, or backup ID already exists
  - `413 PAYLOAD_TOO_LARGE`: uploaded bundle exceeds configured maximum size
  - `500 INTERNAL_SERVER_ERROR`: filesystem, decrypt, parse, move, or history persistence failure

### 3.87 GET `/backup/history`

- Purpose: Return the local backup history index.
- Method: `GET`
- Full path: `/api/v1/backup/history`
- Path parameters: none
- Request body: none
- Success response (`200 OK`):

```json
{
  "records": [
    {
      "id": "backup-...",
      "created_at": "2026-07-27T12:00:00Z",
      "source_node_id": "nodeA",
      "source_did": "did:guardian:...",
      "portable": true,
      "components": ["policy", "config", "credentials", "crl"],
      "bundle_path": "/var/lib/sgx-guardian/backup/bundles/backup-....sgxbak",
      "size_bytes": 123456
    }
  ]
}
```

- Error responses:
  - `404 NOT_FOUND`: backup history file is missing
  - `500 INTERNAL_SERVER_ERROR`: backup history cannot be read or parsed

### 3.88 GET `/backup/download/{id}`

- Purpose: Download one encrypted backup bundle as an opaque binary file.
- Method: `GET`
- Full path: `/api/v1/backup/download/{id}`
- Path parameters:
  - `id` (required, string): backup ID. Unsafe path characters are sanitized before lookup.
- Request body: none
- Success response (`200 OK`):
  - `Content-Type: application/octet-stream`
  - `Content-Disposition: attachment; filename="<id>.sgxbak"`
  - Body: encrypted backup bundle bytes.
- Error responses:
  - `400 BAD_REQUEST`: sanitized backup ID is empty
  - `404 NOT_FOUND`: backup bundle is not found
  - `413 PAYLOAD_TOO_LARGE`: bundle exceeds configured download size limit
  - `500 INTERNAL_SERVER_ERROR`: filesystem read or response construction failure

### 3.89 DELETE `/backup/{id}`

- Purpose: Delete one local backup bundle and remove it from backup history.
- Method: `DELETE`
- Full path: `/api/v1/backup/{id}`
- Path parameters:
  - `id` (required, string): backup ID. Unsafe path characters are sanitized before lookup.
- Request body: none
- Success response (`200 OK`):

```json
{
  "status": "deleted",
  "id": "backup-..."
}
```

- Error responses:
  - `400 BAD_REQUEST`: sanitized backup ID is empty
  - `404 NOT_FOUND`: backup bundle or history record is not found
  - `500 INTERNAL_SERVER_ERROR`: filesystem or history update failure

### 3.90 POST `/backup/validate`

- Purpose: Decrypt and validate a backup bundle without applying it.
- Method: `POST`
- Full path: `/api/v1/backup/validate`
- Path parameters: none
- Request body:

```json
{
  "id": "backup-...",
  "passphrase": "correct horse battery staple"
}
```

- Success response (`200 OK`):

```json
{
  "status": "ok",
  "backup_id": "backup-...",
  "source_node_id": "nodeA",
  "source_did": "did:guardian:...",
  "target_did": "did:guardian:...",
  "same_device_identity": true,
  "portable": true,
  "components": [
    {
      "component": "policy",
      "schema_version": 1,
      "paths": [
        "policy/active_policy.yaml",
        "policy/backup_policy.yaml",
        "policy/policy.sig",
        "policy/pa_admin_pub.der"
      ]
    }
  ],
  "warnings": []
}
```

- Error responses:
  - `400 BAD_REQUEST`: `passphrase` is empty or request is invalid
  - `404 NOT_FOUND`: backup bundle is not found
  - `409 CONFLICT`: integrity validation fails or backup schema is unsupported
  - `413 PAYLOAD_TOO_LARGE`: bundle exceeds configured maximum size
  - `500 INTERNAL_SERVER_ERROR`: decrypt, parse, or filesystem failure

### 3.91 POST `/backup/restore`

- Purpose: Legacy restore endpoint retained for compatibility; it does not perform destructive restore.
- Method: `POST`
- Full path: `/api/v1/backup/restore`
- Path parameters: none
- Request body:

```json
{
  "id": "backup-...",
  "passphrase": "correct horse battery staple"
}
```

- Success response: none in current implementation.
- Error responses:
  - `409 CONFLICT`: endpoint is unavailable; use `/api/v1/restore/validate` and `/api/v1/restore/apply` with `confirm: true`

### 3.92 POST `/restore/validate`

- Purpose: Build a restore preflight plan without modifying files.
- Method: `POST`
- Full path: `/api/v1/restore/validate`
- Path parameters: none
- Request body:

```json
{
  "id": "backup-...",
  "passphrase": "correct horse battery staple",
  "components": ["policy", "config", "credentials", "crl"],
  "allow_policy_rollback": false
}
```

- Success response (`200 OK`):

```json
{
  "status": "ok",
  "backup": {
    "status": "ok",
    "backup_id": "backup-...",
    "source_node_id": "nodeA",
    "source_did": "did:guardian:...",
    "target_did": "did:guardian:...",
    "same_device_identity": true,
    "portable": true,
    "components": [],
    "warnings": []
  },
  "mode": "same_device",
  "plan": [
    {
      "component": "policy",
      "action": "policy_last",
      "reason": "policy applies last and must preserve monotonic sequence/signature checks",
      "paths": ["policy/active_policy.yaml", "policy/policy.sig"]
    }
  ],
  "destructive_apply_enabled": true,
  "warnings": [
    "policy rollback is not authorised; older policy sequences will be skipped during apply"
  ]
}
```

- Error responses:
  - `400 BAD_REQUEST`: backup `id` or `passphrase` is empty, or request options are invalid
  - `404 NOT_FOUND`: backup bundle is not found
  - `409 CONFLICT`: integrity validation fails or backup schema is unsupported
  - `413 PAYLOAD_TOO_LARGE`: bundle exceeds configured maximum size
  - `500 INTERNAL_SERVER_ERROR`: decrypt, parse, or filesystem failure

### 3.93 GET `/restore/status`

- Purpose: Return the current restore journal status.
- Method: `GET`
- Full path: `/api/v1/restore/status`
- Path parameters: none
- Request body: none
- Success response (`200 OK`):

```json
{
  "status": "journal_present",
  "journal_path": "/var/lib/sgx-guardian/backup/restore/journal.json",
  "journal": {
    "restore_id": "restore-...",
    "bundle_id": "backup-...",
    "node_id": "nodeA",
    "phase": "committed",
    "component_index": null,
    "snapshot_path": "/var/lib/sgx-guardian/backup/pre-restore/restore-...",
    "updated_at": "2026-07-27T12:00:00Z",
    "message": "restore committed; applied 4 files"
  }
}
```

- Notes:
  - When no journal exists, `status` is `idle` and `journal` is `null`.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: restore journal cannot be read or parsed

### 3.94 POST `/restore/apply`

- Purpose: Apply a confirmed restore transaction after repeating validation and destructive safety checks.
- Method: `POST`
- Full path: `/api/v1/restore/apply`
- Path parameters: none
- Request body:

```json
{
  "id": "backup-...",
  "passphrase": "correct horse battery staple",
  "confirm": true,
  "components": ["policy", "config", "credentials", "crl"],
  "allow_policy_rollback": false
}
```

- Success response (`200 OK`):

```json
{
  "status": "committed",
  "message": "restore restore-... committed; applied 4 files; restart required for in-memory state",
  "restart_required": true
}
```

- Success response when an older policy rollback is denied (`200 OK`):

```json
{
  "status": "committed_policy_skipped",
  "message": "restore restore-... committed; applied 0 files; policy skipped (backup policy version 1.0.0 is older than active policy version 1.0.1; rollback not authorised); restart required for in-memory state",
  "restart_required": true
}
```

- Error responses:
  - `400 BAD_REQUEST`: backup `id` or `passphrase` is empty, `confirm` is not `true`, another restore is in progress, or request options are invalid
  - `401 UNAUTHORIZED`: authentication is required and no valid session is provided
  - `403 FORBIDDEN`: caller is not owner or admin
  - `404 NOT_FOUND`: backup bundle or restore journal dependency is not found
  - `409 CONFLICT`: integrity validation fails, backup schema is unsupported, restore is unavailable, or policy signature validation fails
  - `413 PAYLOAD_TOO_LARGE`: bundle exceeds configured maximum size
  - `500 INTERNAL_SERVER_ERROR`: snapshot, staging, filesystem swap, rollback, or journal write failure

### 3.95 POST `/restore/undo`

- Purpose: Restore the pre-restore snapshot captured by the last restore transaction.
- Method: `POST`
- Full path: `/api/v1/restore/undo`
- Path parameters: none
- Request body:

```json
{
  "confirm": true
}
```

- Success response (`200 OK`):

```json
{
  "status": "undone",
  "message": "restore restore-... undone from snapshot",
  "restart_required": true
}
```

- Error responses:
  - `400 BAD_REQUEST`: `confirm` is not `true`, another restore is in progress, or the journal has no snapshot path
  - `401 UNAUTHORIZED`: authentication is required and no valid session is provided
  - `403 FORBIDDEN`: caller is not owner or admin
  - `404 NOT_FOUND`: restore journal or snapshot file is not found
  - `500 INTERNAL_SERVER_ERROR`: snapshot load, filesystem write, or permission update failure

## 2. Standard Error Envelope

All handler-generated API errors use this JSON envelope:

```json
{
  "error": {
    "code": "NOT_FOUND | BAD_REQUEST | UNAUTHORIZED | LOCKED | TOO_MANY_REQUESTS | FORBIDDEN | CONFLICT | INTERNAL",
    "message": "human-readable message"
  }
}
```

Typical HTTP status mapping:

- `400 BAD_REQUEST`
- `401 UNAUTHORIZED`
- `423 LOCKED`
- `429 TOO_MANY_REQUESTS`
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

## 2.2 Guardian Admin Console Phase A-C (Authoritative)

This section is the authoritative contract for the operator-facing admin-console flow covering:

- Phase A: operator signup, login, session validation, logout, auth middleware
- Phase B: Guardian QR/serial pairing, signed proof verification, binding, listing, unpairing
- Phase C: authenticated Guardian onboarding into the existing cert-bootstrap workflow, plus bootstrap status visibility for the dashboard

If a later legacy section in this document differs from this Phase A-C section, use this section.

### Endpoint contracts

#### GET `/health`

Purpose:
Check whether the Guardian admin API is alive.

Request:

- Auth: Public
- Query params: none
- Body: none

Success response (`200 OK`):

```json
{
  "status": "ok"
}
```

Error responses:

- None expected from handler

#### POST `/auth/signup`

Purpose:
Create the first operator account as the initial `owner`.

Request:

- Auth: Public
- Query params: none
- JSON body:
```json
{
  "name": "Admin",
  "email": "admin@sgx.local",
  "password": "SgxGuardian@2026!"
}
```

Success response (`200 OK`):

```json
{
  "userId": "user-id",
  "email": "admin@sgx.local",
  "role": "owner",
  "token": "jwt-token",
  "expiresAt": 1783060200
}
```

Error responses:

- `400 BAD_REQUEST`: missing name/email or password policy violation
- `403 FORBIDDEN`: signup is only allowed before the first user exists
- `409 CONFLICT`: conflicting user creation state
- `500 INTERNAL_SERVER_ERROR`: user store, session persistence, or token issuance failure

#### POST `/auth/login`

Purpose:
Authenticate an operator and issue a bearer session token.

Request:

- Auth: Public
- Query params: none
- JSON body:
```json
{
  "email": "admin@sgx.local",
  "password": "SgxGuardian@2026!"
}
```

Success response (`200 OK`):

```json
{
  "token": "jwt-token",
  "user": {
    "id": "user-id",
    "email": "admin@sgx.local",
    "role": "owner"
  },
  "expiresAt": 1783060200
}
```

Error responses:

- `401 UNAUTHORIZED`: invalid email or password
- `423 LOCKED`: account temporarily locked after repeated failed logins
- `429 TOO_MANY_REQUESTS`: login rate limit exceeded
- `500 INTERNAL_SERVER_ERROR`: user store, session persistence, or token issuance failure

#### GET `/auth/session`

Purpose:
Validate the current JWT session and return the authenticated user/session summary.

Request:

- Auth: `Authorization: Bearer <token>` required
- Query params: none
- Body: none
```http
Authorization: Bearer <token>
```

Success response (`200 OK`):

```json
{
  "valid": true,
  "userId": "user-id",
  "email": "admin@sgx.local",
  "role": "owner",
  "expiresAt": 1783060200
}
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `500 INTERNAL_SERVER_ERROR`: user/session store failure

#### POST `/auth/logout`

Purpose:
Revoke the current session token.

Request:

- Auth: `Authorization: Bearer <token>` required
- Query params: none
- Body: none
```http
Authorization: Bearer <token>
```

Success response (`200 OK`):

```json
{
  "status": "logged_out"
}
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `500 INTERNAL_SERVER_ERROR`: session revoke persistence failure

#### GET `/node/status`

Purpose:
Show the current Guardian node status for the dashboard.

Request:

- Auth: `Authorization: Bearer <token>` required
```http
Authorization: Bearer <token>
```

Success response (`200 OK`):

```json
{
  "nodeId": "nodeA",
  "hostname": "guardian-node-A",
  "ip": "192.168.50.103",
  "port": 50051,
  "publicKey": "placeholder-key-A",
  "timestamp": "2026-07-03T05:17:56Z"
}
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `400 BAD_REQUEST`: invalid node format
- `404 NOT_FOUND`: node config not found
- `500 INTERNAL_SERVER_ERROR`: config directory, file read, or YAML parse failure

#### GET `/devices/pairing-code`

Purpose:
Generate a secure time-limited pairing code for QR or serial pairing.

Request:

- Auth: `Authorization: Bearer <token>` required
- Query params:
  - `serial` (required, string)
  - `ttl_secs` (optional, integer). Defaults to `300`; capped at `3600`.
- Body: none

Success response (`200 OK`):

```json
{
  "serial": "GX-2024-TX-042-B9F3",
  "challenge": "random-challenge",
  "nonce": "random-nonce",
  "expiresAt": 1783059476,
  "pairingCode": "base64url-pairing-payload"
}
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `400 BAD_REQUEST`: invalid serial
- `500 INTERNAL_SERVER_ERROR`: pairing store persistence or pairing-code encoding failure

#### POST `/devices/pair`

Purpose:
Submit a signed pairing proof and bind a Guardian device to the authenticated owner account. When the proof DID matches an existing `unpaired` record, the existing record is reactivated with its original `deviceId` and refreshed `paired_at`, `reactivated_at`, and `updated_at` values.

Request:

- Auth: `Authorization: Bearer <token>` required
- Query params: none
- JSON body:
```json
{
  "serial": "GX-2024-TX-042-B9F3",
  "proof": "signed-proof-from-device"
}
```

Success response (`200 OK`):

```json
{
  "deviceId": "device-id",
  "serial": "GX-2024-TX-042-B9F3",
  "did": "did:guardian:EtFW3...",
  "status": "bootstrap_pending",
  "nodeId": "nodeB"
}
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `400 BAD_REQUEST`: missing proof, serial mismatch, invalid proof, missing pairing challenge, expired pairing challenge, or replayed proof
- `403 FORBIDDEN`: pairing proof was issued for a different user
- `409 DEVICE_ALREADY_PAIRED`: a record with the proof DID is already active
- `500 INTERNAL_SERVER_ERROR`: device store persistence failure

#### GET `/devices`

Purpose:
Return all paired Guardians for the authenticated user dashboard.

Request:

- Auth: `Authorization: Bearer <token>` required
- Query params: none
- Body: none

Success response (`200 OK`):

```json
[
  {
    "deviceId": "0299cc0d31a127a3de2a8ac66ac2bf7c5fb3eed4e06102e75b841fbb12124b1d",
    "serial": "GX-2024-TX-042-B9F3",
    "did": "did:guardian:EtFW3...",
    "status": "active",
    "nodeId": "nodeB"
  },
  {
    "deviceId": "d29f0ca7641c76f1e71a0ea767992a42db629a8e389512ae4de8520446567c0f",
    "serial": "GX-2024-TX-042-C9F3",
    "did": "did:guardian:C2txw...",
    "status": "active",
    "nodeId": "nodeC"
  }
]
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `500 INTERNAL_SERVER_ERROR`: device store read failure

#### GET `/devices/unpaired`

Purpose:
Return unpaired Guardian records from `/var/lib/sgx-guardian/admin/devices.json`. The endpoint is read-only and includes only records whose `status` is exactly `"unpaired"`.

Request:

- Auth: `Authorization: Bearer <token>` required
- Query params: none
- Body: none

Success response (`200 OK`):

```json
[
  {
    "deviceId": "d29f0ca7641c76f1e71a0ea767992a42db629a8e389512ae4de8520446567c0f",
    "serial": "GX-2024-TX-042-C9F3",
    "did": "did:guardian:C2txw...",
    "status": "unpaired",
    "nodeId": "nodeC"
  }
]
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `500 INTERNAL_SERVER_ERROR`: device store read failure

#### GET `/devices/all`

Purpose:
Return every record in `/var/lib/sgx-guardian/admin/devices.json` without status filtering. This endpoint is read-only and is intended for frontend device counts.

Request:

- Auth: `Authorization: Bearer <token>` required
- Query params: none
- Body: none

Success response (`200 OK`):
The response is an array in the same format as `/devices/paired`, containing both active and unpaired records.

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `500 INTERNAL_SERVER_ERROR`: device store read failure

#### GET `/devices/{deviceId}`

Purpose:
Return detailed information for one Guardian record from `devices.json`, including records whose status is `"unpaired"`.

Request:

- Auth: `Authorization: Bearer <token>` required
- Path params:
  - `deviceId` (required, string)
- Query params: none
- Body: none

Success response (`200 OK`):

```json
{
  "deviceId": "device-id",
  "serial": "GX-2024-TX-042-B9F3",
  "did": "did:guardian:EtFW3...",
  "nodeId": "nodeB",
  "status": "active",
  "bootstrapStatus": "completed",
  "overlayIp": "192.168.100.2",
  "attestationEndpoint": "tcp://192.168.100.2:50152"
}
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `404 NOT_FOUND`: device does not exist or is not visible to the authenticated user
- `500 INTERNAL_SERVER_ERROR`: device store read failure

#### GET `/devices/{deviceId}/status`

Purpose:
Return the paired Guardian's status using the binding record, persisted peer DID document, and Nebula registries. Remote fields that are not currently published by a Guardian are returned as `"unknown"`; this endpoint never writes pairing data or returns private key material.

Request:

- Auth: `Authorization: Bearer <token>` required
- Path params:
  - `deviceId` (required, string)

Success response (`200 OK`):
Structured `pairing`, `identity`, `runtime`, `network`, `nebula`, `hardware`, and `security` sections. `/guardians/{deviceId}/status` is an equivalent compatibility alias.

Error responses:

- `401 UNAUTHORIZED`: missing or invalid bearer token
- `404 NOT_FOUND`: device does not exist or is not visible to the authenticated user

#### GET `/devices/pairing-status`

Purpose:
Allow the frontend to poll pairing and bootstrap status for a device serial.

Request:

- Auth: `Authorization: Bearer <token>` required
- Query params:
  - `serial` (required, string)
- Body: none

Success response (`200 OK`):

```json
{
  "serial": "GX-2024-TX-042-B9F3",
  "status": "completed",
  "apiConsumed": true,
  "bootstrapConsumed": true,
  "deviceId": "device-id",
  "nodeId": "nodeB",
  "did": "did:guardian:EtFW3..."
}
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `400 BAD_REQUEST`: invalid serial
- `404 NOT_FOUND`: pairing record not found
- `500 INTERNAL_SERVER_ERROR`: pairing or device store read failure

#### POST `/devices/{deviceId}/unpair`

Purpose:
Remove or unpair a Guardian device from the authenticated owner account.

Request:

- Auth: `Authorization: Bearer <token>` required
- Path params:
  - `deviceId` (required, string)
- Query params: none
- Body: none

Success response (`200 OK`):

```json
{
  "deviceId": "device-id",
  "status": "unpaired"
}
```

Error responses:

- `401 UNAUTHORIZED`: missing, invalid, expired, tampered, unknown, or revoked bearer token
- `403 FORBIDDEN`: caller is not authorized to unpair the device
- `404 NOT_FOUND`: device not found for the authenticated user
- `500 INTERNAL_SERVER_ERROR`: device store persistence failure

---

## 3. Endpoint Contracts

### 3.1 GET `/health`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):
```json
{
  "status": "ok"
}
```
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
  - Query params:
    - `peer_did` (optional, string): Filter by peer DID.
    - `result` (optional, string: `success`, `failed`): Filter by attestation status.
  - Body: none
- Success response (`200 OK`):

```json
[
  {
    "peerId": "192.168.134.129:50051",
    "policyDigest": "10b2dc837e9a2a766d57edc1be6676b79f24828d5745ef0fb9930306766e8a26",
    "result": "success",
    "timestamp": "2026-07-01T15:30:46.123456+00:00",
    "peerDid": "did:guardian:nodeB",
    "virtualId": "vid:94f4a30e8c899c72e61a6c11db84e9d564fa78cb103f6ebc9a3d4632c02741ab",
    "dkpPubkeySha256B16": "a3b9d07fbc16b8e3a241ee83d9876251b5c9288f61c3608104dfc8091a18274d",
    "pcrCompositeDigest": "a9deb3227421cb1b3c990264b3ef81c81ef40d89280d84a7e937dbeab10372df",
    "count": 5
  }
]
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
  - Query params:
    - `target` (optional, string): one-off override for this scan's target CIDR, host IP, `/32`, or hostname
  - JSON body (optional):

```json
{
  "target": "192.168.50.248/32"
}
```

  - When both query and body specify `target`, the JSON body wins
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
  - Supports both subnet scans and single-host scans through the optional `target` override
  - If the CLI process exits non-zero, endpoint still returns `200 OK` with `success=false`
  - Ad-hoc scan intensity follows the current discovery config's effective manual/default intensity
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` not found or command spawn failed

### 3.67 POST `/discovery/scan/stealth`

- Request:
  - Same optional `target` query param / JSON body as `POST /discovery/scan`
- Success response (`200 OK`):
  - Same schema as `POST /discovery/scan`
- Notes:
  - Executes `sgx-pa-cli discovery scan --intensity stealth`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` not found or command spawn failed

### 3.68 POST `/discovery/scan/standard`

- Request:
  - Same optional `target` query param / JSON body as `POST /discovery/scan`
- Success response (`200 OK`):
  - Same schema as `POST /discovery/scan`
- Notes:
  - Executes `sgx-pa-cli discovery scan --intensity standard`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` not found or command spawn failed

### 3.69 POST `/discovery/scan/aggressive`

- Request:
  - Same optional `target` query param / JSON body as `POST /discovery/scan`
- Success response (`200 OK`):
  - Same schema as `POST /discovery/scan`
- Notes:
  - Executes `sgx-pa-cli discovery scan --intensity aggressive`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: `sgx-pa-cli` not found or command spawn failed

### 3.69a GET `/discovery/runs`

- Request:
  - Query params:
    - `view` (optional, string): set to `history` to force persisted run-history mode
    - `limit` (optional, default `50`, max `500`): when provided, the handler also switches to persisted run-history mode
  - Body: none
- Success response (`200 OK`):

```json
[
  {
    "run_id": "20260701T050842Z-standard-550e8400-e29b-41d4-a716-446655440000",
    "started_at": "2026-07-01T05:08:42Z",
    "completed_at": "2026-07-01T05:09:12Z",
    "duration_ms": 30000,
    "source": "manual",
    "schedule_kind": null,
    "intensity": "standard",
    "target": "192.168.50.0/24",
    "success": true,
    "error": null,
    "new_devices": 1,
    "updated_devices": 27,
    "marked_stale": 0,
    "total_devices": 28,
    "approved": 2,
    "unauthorized": 26,
    "drifted": 0,
    "stale": 0,
    "raw_xml_path": "/var/lib/sgx-guardian/discovery/raw/1782911322.xml",
    "inventory_path": "/var/lib/sgx-guardian/discovery/inventory.json",
    "devices": [
      {
        "device_id": "5245c334a84abcb2",
        "ip": "192.168.50.103",
        "mac": null,
        "vendor": null,
        "hostname": null,
        "os_fingerprint": "Linux 5.0 - 6.2",
        "os_cpe": [
          "cpe:/o:linux:linux_kernel:5",
          "cpe:/o:linux:linux_kernel:6"
        ],
        "open_ports": [
          {
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "product_version": "OpenSSH 9.3",
            "cpe": ["cpe:/a:openbsd:openssh:9.3"],
            "scripts": []
          }
        ],
        "host_scripts": [],
        "status": "unauthorized",
        "first_seen": "2026-07-01T05:09:12+00:00",
        "last_seen": "2026-07-01T05:09:12+00:00",
        "vuln_triaged": false,
        "last_scan_intensity": "standard"
      }
    ]
  }
]
```

- Notes:
  - Reads `/var/lib/sgx-guardian/discovery/runs.jsonl`
  - Returns newest scan runs first
  - History records are written by manual scan commands and scheduled discovery scans
  - When `raw_xml_path` is still available, each run is enriched with a `devices` array reconstructed from that scan's raw NMAP XML, without changing the current `inventory.json`-backed endpoints
  - If a historical raw XML file has been pruned or is unreadable, the run stays in the response and includes `devices_error` instead of failing the whole endpoint
  - `GET /discovery/runs` without `view=history` and without `limit` uses the raw-archive response documented in `3.72c`
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: run history read/parse failure

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
  },
  "current_devices": [
    {
      "device_id": "a1b2c3d4e5f60708",
      "ip": "192.168.50.103",
      "vendor": "Acme",
      "hostname": "printer.local",
      "status": "approved",
      "os_fingerprint": "Linux 5.x",
      "open_ports": [
        "22/tcp ssh"
      ],
      "first_seen": "2026-06-30T10:00:00Z",
      "last_seen": "2026-06-30T11:00:00Z",
      "vuln_triaged": false
    }
  ]
}
```

- Notes:
  - Adds or updates the MAC inside `/etc/sgx-guardian/discovery/whitelist.yaml`
  - If `label` is omitted, the API attempts to infer a readable label from the matching inventory vendor or hostname
  - Immediately reclassifies matching non-stale inventory records so approved devices become authorized without waiting for the next scan
  - Returns current inventory matches for that MAC in `current_devices`
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
      ],
      "inventory_match": true,
      "current_devices": [
        {
          "device_id": "a1b2c3d4e5f60708",
          "ip": "192.168.50.103",
          "vendor": "Acme",
          "hostname": "printer.local",
          "status": "approved",
          "os_fingerprint": "Linux 5.x",
          "open_ports": [
            "22/tcp ssh",
            "9100/tcp jetdirect"
          ],
          "first_seen": "2026-06-30T10:00:00Z",
          "last_seen": "2026-06-30T11:00:00Z",
          "vuln_triaged": false
        }
      ]
    }
  ]
}
```

- Notes:
  - Missing or empty whitelist file returns the default empty document
  - Stored whitelist remains policy-only; `inventory_match` and `current_devices` are read-only fields joined from `/var/lib/sgx-guardian/discovery/inventory.json`
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
  - Same policy schema as the request body
- Notes:
  - Writes `/etc/sgx-guardian/discovery/whitelist.yaml` atomically
  - Refreshes matching non-stale inventory statuses after the whitelist update
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: whitelist serialization/write or inventory refresh failure
  - `415`/`422`: invalid JSON body

### 3.72a GET `/discovery/summary`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "total": 28,
  "approved": 2,
  "unauthorized": 26,
  "drifted": 0,
  "stale": 0,
  "devices_with_open_ports": 14,
  "total_open_ports": 38,
  "critical_devices": 1,
  "high_risk_devices": 5,
  "medium_risk_devices": 1,
  "low_risk_devices": 7,
  "unknown_risk_devices": 14,
  "last_seen_at": "2026-07-01T05:08:42+00:00"
}
```

- Notes:
  - `critical_devices`: unauthorized + has `vulners` NSE script output (actual CVE findings)
  - `high_risk_devices`: unauthorized + has risky ports (21, 22, 445, 1433, 3389, 8080, 8443, etc.)
  - `medium_risk_devices`: approved but has open ports
  - `low_risk_devices`: no risky ports or no ports at all but OS detected
  - `unknown_risk_devices`: no OS fingerprint and no open ports (stealth-scan-only data)
  - `last_seen_at`: RFC-3339 timestamp of most recently seen device; `null` when no inventory
- Error responses:
  - `404 NOT_FOUND`: no discovery inventory exists yet
  - `500 INTERNAL_SERVER_ERROR`: inventory JSON parse failure

### 3.72b GET `/discovery/devices/{device_id}`

- Request:
  - Path params:
    - `device_id` (required, string): 16-char hex device id from inventory
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "device_id": "5245c334a84abcb2",
  "ip": "192.168.50.103",
  "mac": null,
  "vendor": null,
  "hostname": null,
  "os_fingerprint": "Linux 5.0 - 6.2",
  "os_cpe": [
    "cpe:/o:linux:linux_kernel:5",
    "cpe:/o:linux:linux_kernel:6"
  ],
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "product_version": "OpenSSH 9.3",
      "cpe": ["cpe:/a:openbsd:openssh:9.3"],
      "scripts": [
        {
          "id": "vulners",
          "output": "cpe:/a:openbsd:openssh:9.3:\n  CVE-2023-38408  9.8  ..."
        }
      ]
    },
    {
      "port": 53,
      "protocol": "tcp",
      "service": "domain",
      "product_version": "dnsmasq 2.89",
      "cpe": ["cpe:/a:thekelleys:dnsmasq:2.89"],
      "scripts": []
    },
    {
      "port": 111,
      "protocol": "tcp",
      "service": "rpcbind",
      "product_version": null,
      "cpe": [],
      "scripts": []
    },
    {
      "port": 8080,
      "protocol": "tcp",
      "service": "http-proxy",
      "product_version": null,
      "cpe": [],
      "scripts": []
    },
    {
      "port": 8443,
      "protocol": "tcp",
      "service": "https-alt",
      "product_version": null,
      "cpe": [],
      "scripts": []
    }
  ],
  "host_scripts": [
    {
      "id": "fcrdns",
      "output": "FAIL (No PTR record)"
    },
    {
      "id": "dns-blacklist",
      "output": "SPAM\n  l2.apews.org - FAIL\n  list.quorum.to - SPAM"
    }
  ],
  "status": "unauthorized",
  "first_seen": "2026-07-01T05:08:42+00:00",
  "last_seen": "2026-07-01T05:08:42+00:00",
  "vuln_triaged": false,
  "last_scan_intensity": "aggressive",
  "risk_level": "critical",
  "risk_reasons": [
    "unauthorized device",
    "vulnerability findings detected",
    "risky ports exposed: 22, 111, 8080, 8443"
  ],
  "flagged_ports": [22, 111, 8080, 8443]
}
```

- Notes:
  - Response is `ConnectedDevice` (flattened) plus `risk_level`, `risk_reasons`, `flagged_ports`
  - `risk_level` values: `critical` | `high` | `medium` | `low` | `unknown`
  - `flagged_ports`: port numbers that triggered the risk classification
  - `last_scan_intensity`: `stealth` | `standard` | `aggressive` — present only after next scan run
- Error responses:
  - `404 NOT_FOUND`: device_id not found in inventory, or no inventory yet
  - `500 INTERNAL_SERVER_ERROR`: inventory JSON parse failure

### 3.72c GET `/discovery/runs`

- Request:
  - Query params:
    - `view` (optional, string): set to `raw` to force raw-archive mode; this is also the default when neither `view=history` nor `limit` is supplied
  - Body: none
- Success response (`200 OK`):

```json
{
  "runs": [
    {
      "timestamp": "2026-07-01T05:08:30+00:00",
      "unix_ts": 1751346510,
      "source": "raw_xml"
    },
    {
      "timestamp": "2026-07-01T04:05:12+00:00",
      "unix_ts": 1751342712,
      "source": "raw_xml"
    }
  ],
  "total_in_inventory": 28
}
```

- Notes:
  - `source: "raw_xml"` means the timestamp comes from the forensic NMAP XML archive at `/var/lib/sgx-guardian/discovery/raw/<unix_ts>.xml` — these are exact scan completion timestamps, not inferred
  - The archive keeps the last 10 scans. Older runs are pruned automatically.
  - `total_in_inventory`: current device count from inventory for context
  - Runs are sorted newest-first
  - Use `view=history` or provide `limit` to receive the persisted `runs.jsonl` array documented in `3.69a`
- Error responses:
  - None expected when raw directory is empty; returns `{ "runs": [], "total_in_inventory": N }`
  - `500 INTERNAL_SERVER_ERROR`: inventory read failure

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

- Success response (`200 OK`):
  - Same schema as `GET /discovery/schedule`
- Error responses:
  - `400 BAD_REQUEST`: invalid `target_cidr`, `timeout_secs`, or schedule intensity
  - `500 INTERNAL_SERVER_ERROR`: schedule serialization/write failure

## 4. Threat Endpoint Contracts

### GET `/threat/alerts`

- Request:
  - Query params:
    - `limit` (optional, integer, default `500`, max `10000`)
    - `severity` (optional, string, case-insensitive: `info`, `low`, `medium`, `high`, `critical`)
  - Body: none
- Success response (`200 OK`):

```json
[
  {
    "alert_id": "838deb6e032238c8",
    "timestamp": "2026-07-02T06:01:25.533459328Z",
    "src_ip": "fe80::1d23:97c0:76be:19d9",
    "src_port": 0,
    "dst_ip": "ff02::16",
    "dst_port": 0,
    "protocol": "IPv6-ICMP",
    "signature_id": 10000131,
    "signature": "SGX MALWARE TEST TROJAN",
    "category": "malware",
    "severity": "critical",
    "rev": 1,
    "gid": 1,
    "event_type": "alert",
    "blocked": false
  }
]
```

- Notes:
  - Reads newline-delimited JSON alerts from `alerts.jsonl` in `threat_state_dir`.
  - Returns the most recent matching alerts when `limit` is smaller than the stored inventory.
  - `category` values are snake_case enum strings such as `malware`, `exploit`, `policy_violation`, `reconnaissance`, `anomaly`, `other`.
- Error responses:
  - `404 NOT_FOUND`: no alert inventory exists yet (`"no alerts yet - has Suricata produced events?"`)
  - `500 INTERNAL_SERVER_ERROR`: storage read failure or malformed runtime state

### GET `/threat/modbus`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "total_matches": 5,
  "rules": [
    {
      "rule_id": 1,
      "name": "Unauthorized Write to PLC Coils",
      "function_codes": ["FC5", "FC15"],
      "matched": true,
      "match_count": 2,
      "matched_signatures": [
        "SGX OT Modbus Unauthorized Write Single Coil FC5",
        "SGX OT Modbus Unauthorized Write Multiple Coils FC15"
      ],
      "recent_alerts": [
        {
          "alert_id": "8c9dd2bfa6a6fd71",
          "timestamp": "2026-07-05T12:14:11Z",
          "src_ip": "192.168.50.115",
          "src_port": 43000,
          "dst_ip": "192.168.50.248",
          "dst_port": 502,
          "protocol": "TCP",
          "signature_id": 10000201,
          "signature": "SGX OT Modbus Unauthorized Write Single Coil FC5",
          "category": "policy_violation",
          "severity": "high",
          "rev": 1,
          "gid": 1,
          "event_type": "alert",
          "blocked": false
        }
      ]
    }
  ]
}
```

- Notes:
  - Reads the same `alerts.jsonl` threat inventory used by `GET /threat/alerts`.
  - Groups matching alerts into the 5 logical Guardian Modbus rule buckets:
    - Rule 1: FC5 / FC15
    - Rule 2: FC6 / FC16
    - Rule 3: FC65 / FC66 / FC67 / FC68
    - Rule 4: FC129
    - Rule 5: FC5 audit
  - Each rule bucket includes:
    - `matched` (`boolean`): whether at least one matching alert exists
    - `match_count` (`integer`): total number of matching alerts for that logical rule
    - `matched_signatures` (`string[]`): distinct Suricata signatures seen for that rule
    - `recent_alerts` (`ThreatAlert[]`): up to 5 most recent matching alerts
  - Unlike `GET /threat/alerts`, this endpoint returns an empty summary instead of `404` when no alert inventory exists yet.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: storage read failure or malformed runtime state

### GET `/threat/blocks`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "blocked": [
    "192.168.50.115",
    "fe80::3fab:243d:7d08:e3c8"
  ]
}
```

- Notes:
  - Reads active block IPs from nftables chain `inet sgx_threat input`.
  - Falls back to persisted `blocked_ips.json` when nftables returns no active entries.
  - Output is sorted and deduplicated before response.
- Error responses:
  - None expected from handler; empty list is returned when no active blocks are present

### POST `/threat/blocks/unblock`

- Request:
  - Query params: none
  - Body:

```json
{
  "ip": "192.168.50.115"
}
```

- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "unblocked 192.168.50.115\n",
  "stderr": "",
  "restartRequired": false,
  "timestamp": "2026-07-02T07:10:00Z"
}
```

- Notes:
  - Delegates to `sgx-pa-cli threat unblock <ip>`.
  - Removes the IP from persisted block records, flushes the threat nftables chain, then restores any remaining blocks.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: CLI command failed, IP was not blocked, or nftables restore failed

### POST `/threat/rules/update`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "suricata-update completed ...",
  "stderr": "",
  "restartRequired": true,
  "timestamp": "2026-07-02T07:10:00Z"
}
```

- Notes:
  - Delegates to `sgx-pa-cli threat rules-update`.
  - Runs Suricata rule update workflow and validates/reloads the updated ruleset.
  - Uses the standard action envelope shown in `2.1`.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: CLI command failed, Suricata validation failed, or service restart/reload failed

### POST `/threat/validate`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "ok\n",
  "stderr": "",
  "restartRequired": false,
  "timestamp": "2026-07-02T07:10:00Z"
}
```

- Notes:
  - Delegates to `sgx-pa-cli threat validate`.
  - Loads `/etc/sgx-guardian/threat/config.yaml`, then validates the configured Suricata YAML.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: CLI command failed, threat config is invalid, or Suricata config test failed

### GET `/threat/status`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "suricata": "active",
  "enabled": true,
  "block_mode": "inline_block",
  "alert_count": 124,
  "block_count": 3
}
```

- Field notes:
  - `suricata` (`string`): output of `systemctl is-active suricata` - `"active"`, `"inactive"`, or `"unknown"`.
  - `enabled` (`boolean`): whether Guardian's threat integration is enabled in config.
  - `block_mode` (`string`): `"alert_only"` or `"inline_block"`.
  - `alert_count` (`integer`): number of alerts in `alerts.jsonl`.
  - `block_count` (`integer`): number of entries in `blocked_ips.json`.
- Error responses:
  - None expected; config load failures fall back to defaults silently.

### GET `/threat/config`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "enabled": true,
  "interface": "wlan0",
  "eve_path": "/var/log/suricata/eve.json",
  "suricata_yaml": "/etc/suricata/suricata.yaml",
  "block_mode": "inline_block",
  "block_ttl_secs": 86400,
  "block_exempt": ["127.0.0.0/8", "192.168.100.0/24"],
  "rule_update_hours": 24
}
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: config file exists but is invalid YAML or fails validation

### POST `/threat/config`

- Request:
  - Query params: none
  - JSON body (all fields optional - only supplied fields are patched):

```json
{
  "enabled": true,
  "block_mode": "inline_block",
  "rule_update_hours": 12,
  "block_ttl_secs": 43200,
  "block_exempt": ["127.0.0.0/8", "10.0.0.0/8"]
}
```

- `block_mode` accepted values: `"alert_only"`, `"inline_block"`
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "config updated - effective within 5 seconds",
  "stderr": "",
  "restartRequired": false,
  "timestamp": "2026-07-03T17:10:00Z"
}
```

- Notes:
  - Loads existing config, applies only the provided fields, validates, and writes back to `/etc/sgx-guardian/threat/config.yaml`.
  - Guardian's `config_refresh_tick` (every 5 seconds) picks up the change automatically - no restart required.
  - `block_ttl_secs` must be between 1 and 604800 (7 days).
  - Each entry in `block_exempt` must be a valid CIDR or IP address.
- Error responses:
  - `400 BAD_REQUEST`: config validation failed (invalid TTL, invalid CIDR in exempt list)
  - `500 INTERNAL_SERVER_ERROR`: config file write failure

### POST `/threat/blocks`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "ip": "192.168.50.115"
}
```

  - Required fields: `ip` (valid IPv4 or IPv6 address)
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "blocked 192.168.50.115 (ttl=86400s)",
  "stderr": "",
  "restartRequired": false,
  "timestamp": "2026-07-03T17:10:00Z"
}
```

- Notes:
  - Delegates to `sgx-pa-cli threat block <ip>`.
  - Adds an nft drop rule to `inet sgx_threat input` and persists to `blocked_ips.json` with TTL from current config.
  - If the IP is already blocked, returns `success=true` with `stdout: "<ip> is already blocked"`.
  - Block expires automatically after `block_ttl_secs`; Blocker's sweep task cleans it up.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: invalid IP format, nft command failure, or file write error

### POST `/threat/start`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "success": true,
  "stdout": "suricata started",
  "stderr": "",
  "restartRequired": false,
  "timestamp": "2026-07-03T17:10:00Z"
}
```

- Notes:
  - Runs `systemctl start suricata`.
  - If Suricata is already active, `systemctl start` is a no-op and returns success.
  - Use `GET /threat/status` to confirm `suricata` field becomes `"active"` after calling this endpoint.

## 4.1 AI Alert Remediation Advisory Endpoint Contracts

New advisory surface total: 3 API paths, 4 HTTP operations.

Authentication for all advisory endpoints:

- Auth: `Authorization: Bearer <token>` required.
- These routes are not public in `require_auth`; only global login-disabled mode bypasses auth.
- Missing, invalid, expired, revoked, or wrong-issuer sessions return:

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "missing bearer token"
  }
}
```

### GET `/advisory/recommendations`

- Full path: `/api/v1/advisory/recommendations`
- Request:
  - Query params:
    - `limit` (optional, integer, default `500`, max `10000`)
  - Body: none
- Success response (`200 OK`): array of `RemediationRecommendation`

```json
[
  {
    "rec_id": "urn:sha256:8b55f177bf4b6bbdc47cb8775f93b2b4",
    "alert_id": "838deb6e032238c8",
    "title": "Suspected malware or command-and-control activity",
    "summary": "A device is communicating in a pattern associated with malware control channels.",
    "severity": "critical",
    "confidence": 0.95,
    "steps": [
      {
        "order": 1,
        "action": "Isolate the affected device from the Circle network",
        "rationale": "Contain potential command-and-control traffic",
        "automatable": true
      },
      {
        "order": 2,
        "action": "Run a full endpoint and service scan",
        "rationale": "Identify persistence, payloads, and exposed services",
        "automatable": true
      }
    ],
    "context": [
      "Signature: ET MALWARE Possible C2 Checkin (sid 2024001)",
      "Flow: 192.168.50.10:51514 -> 192.168.50.20:443 TCP",
      "Category: malware",
      "Device context: 192.168.50.20 (plc-1, Acme)",
      "Device has CVE-2023-38408 (CVSS 9.8)"
    ],
    "references": [
      "cve",
      "signature",
      "suricata:sid:2024001",
      "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"
    ],
    "source": "signature-kb",
    "generated_at": "2026-07-02T06:01:25.533459328Z"
  }
]
```

- Response schema:
  - `rec_id` (`string`): deterministic recommendation ID.
  - `alert_id` (`string`): linked `ThreatAlert.alert_id`.
  - `title` (`string`): recommendation title from matched rule or fallback.
  - `summary` (`string`): human-readable advisory summary.
  - `severity` (`string`): copied from alert severity (`info`, `low`, `medium`, `high`, `critical`).
  - `confidence` (`number`): `0.0` to `1.0`.
  - `steps` (`RemediationStep[]`): ordered remediation steps.
  - `context` (`string[]`): signature, flow, anomaly, and device/CVE evidence lines.
  - `references` (`string[]`): signature, CVE, policy, or URL references.
  - `source` (`string`): `signature-kb`, `anomaly-kb`, or `fallback`.
  - `generated_at` (`string`, RFC3339 UTC): generation timestamp.
- Validation rules:
  - `limit` must parse as an unsigned integer.
  - Values above `10000` are clamped to `10000`.
- Error responses:
  - `400 BAD_REQUEST`: query string cannot deserialize, e.g. `limit=abc`
  - `401 UNAUTHORIZED`: missing or invalid bearer session
  - `500 INTERNAL_SERVER_ERROR`: failed to read or parse `recommendations.jsonl`

Example:

```bash
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  "https://192.168.1.10:8443/api/v1/advisory/recommendations?limit=25"
```

### GET `/threat/alerts/{id}/recommendation`

- Full path: `/api/v1/threat/alerts/{id}/recommendation`
- Request:
  - Path params:
    - `id` (`string`, required): exact `ThreatAlert.alert_id`
  - Query params: none
  - Body: none
- Success response (`200 OK`): one `RemediationRecommendation`

```json
{
  "rec_id": "urn:sha256:8b55f177bf4b6bbdc47cb8775f93b2b4",
  "alert_id": "838deb6e032238c8",
  "title": "Suspected malware or command-and-control activity",
  "summary": "A device is communicating in a pattern associated with malware control channels.",
  "severity": "critical",
  "confidence": 0.95,
  "steps": [
    {
      "order": 1,
      "action": "Isolate the affected device from the Circle network",
      "rationale": "Contain potential command-and-control traffic",
      "automatable": true
    }
  ],
  "context": [
    "Signature: ET MALWARE Possible C2 Checkin (sid 2024001)",
    "Flow: 192.168.50.10:51514 -> 192.168.50.20:443 TCP",
    "Category: malware"
  ],
  "references": [
    "signature",
    "suricata:sid:2024001"
  ],
  "source": "signature-kb",
  "generated_at": "2026-07-02T06:01:25.533459328Z"
}
```

- Validation rules:
  - `id` is accepted as a string and is not further validated by the handler.
- Error responses:
  - `401 UNAUTHORIZED`: missing or invalid bearer session
  - `404 NOT_FOUND`: no stored recommendation exists for the alert ID
  - `500 INTERNAL_SERVER_ERROR`: failed to read or parse `recommendations.jsonl`

Example:

```bash
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  "https://192.168.1.10:8443/api/v1/threat/alerts/838deb6e032238c8/recommendation"
```

Example `404 NOT_FOUND`:

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "no recommendation for alert missing-alert-id"
  }
}
```

### GET `/advisory/rules`

- Full path: `/api/v1/advisory/rules`
- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`): `RecommendationRules`

```json
{
  "rules": [
    {
      "match": {
        "category": "malware",
        "signature_contains": null,
        "severity_at_least": "high"
      },
      "title": "Suspected malware or command-and-control activity",
      "summary": "A device is communicating in a pattern associated with malware control channels.",
      "steps": [
        {
          "action": "Isolate the affected device from the Circle network",
          "rationale": "Contain potential command-and-control traffic",
          "automatable": true
        }
      ],
      "references": [
        "signature",
        "cve"
      ]
    }
  ],
  "fallback": {
    "title": "Security alert requires review",
    "summary": "Guardian detected a security alert that does not match a more specific advisory rule.",
    "steps": [
      {
        "action": "Review the alert signature, endpoints, and recent device changes",
        "rationale": "Manual triage can separate expected activity from a new threat",
        "automatable": false
      }
    ],
    "references": [
      "signature"
    ]
  }
}
```

- Response schema:
  - `rules` (`RecommendationRule[]`): ordered rule list.
  - `rules[].match.category` (`string|null`, optional): category match, compared case-insensitively.
  - `rules[].match.signature_contains` (`string|null`, optional): substring match against alert signature.
  - `rules[].match.severity_at_least` (`string|null`, optional): minimum severity.
  - `rules[].title` (`string`): recommendation title.
  - `rules[].summary` (`string`): recommendation summary.
  - `rules[].steps` (`RuleStep[]`): step templates without `order`; order is assigned during generation.
  - `rules[].references` (`string[]`): static references added by the rule.
  - `fallback` (`RecommendationTemplate`): used when no rule matches.
  - `signature_sha256` (`string`, optional): SHA-256 over the same JSON body with `signature_sha256` removed.
- Notes:
  - If the runtime rules file is missing, unreadable, invalid JSON, or has a bad `signature_sha256`, the handler returns the built-in default rules with `200 OK`.
- Error responses:
  - `401 UNAUTHORIZED`: missing or invalid bearer session

Example:

```bash
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  "https://192.168.1.10:8443/api/v1/advisory/rules"
```

### PUT `/advisory/rules`

- Full path: `/api/v1/advisory/rules`
- Request:
  - Query params: none
  - JSON body: `RecommendationRules`

```json
{
  "rules": [
    {
      "match": {
        "category": "exploit",
        "signature_contains": "OpenSSH",
        "severity_at_least": "medium"
      },
      "title": "Possible exploit attempt against SSH",
      "summary": "Traffic matched exploit behavior for an exposed SSH service.",
      "steps": [
        {
          "action": "Patch or disable the affected SSH service",
          "rationale": "Known vulnerable service versions are common exploit targets",
          "automatable": false
        }
      ],
      "references": [
        "signature",
        "cve"
      ]
    }
  ],
  "fallback": {
    "title": "Security alert requires review",
    "summary": "Guardian detected a security alert that does not match a more specific advisory rule.",
    "steps": [
      {
        "action": "Preserve logs before taking remediation action",
        "rationale": "Evidence helps confirm scope and supports later audit review",
        "automatable": true
      }
    ],
    "references": [
      "signature"
    ]
  }
}
```

- Success response (`200 OK`): echoes the saved `RecommendationRules`
- Validation rules:
  - Body must deserialize as `RecommendationRules`.
  - `fallback` is required.
  - Each rule requires `match`, `title`, and `summary`.
  - Each rule/fallback step requires `action`, `rationale`, and `automatable`.
  - Optional `signature_sha256`, when provided, must equal SHA-256 of the JSON body after removing `signature_sha256`.
  - Unknown severity strings are accepted by the schema; during matching they rank as `info`.
- Error responses:
  - `400 BAD_REQUEST`: JSON body cannot deserialize, `signature_sha256` mismatch, or rules write/serialization failure
  - `401 UNAUTHORIZED`: missing or invalid bearer session
  - `415 UNSUPPORTED_MEDIA_TYPE`: JSON body is sent without an accepted JSON content type

Example:

```bash
curl -k -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @recommendation_rules.json \
  "https://192.168.1.10:8443/api/v1/advisory/rules"
```

Example `400 BAD_REQUEST`:

```json
{
  "error": {
    "code": "BAD_REQUEST",
    "message": "invalid advisory rules: signature_sha256 does not match rules body"
  }
}
```

## 5. CRL Endpoint Contracts

### 3.75 POST `/crl/revoke`

- Full path: `/api/v1/crl/revoke`
- Request:
  - Query params: none
  - JSON body:

```json
{
  "did": "did:guardian:TARGET",
  "reason": "compromised",
  "severity": "critical",
  "device_id": "device-001",
  "user_id": "user-001",
  "note": "reported key compromise",
  "audit_ref": "audit:123",
  "attestation_ref": "attestation:456",
  "evidence_digest": "sha256:..."
}
```

- Success response (`200 OK`):

```json
{
  "status": "success",
  "message": "CRL entry issued",
  "entry": {
    "id": "urn:uuid:...",
    "revoked_did": "did:guardian:TARGET",
    "circle_id": "guardian-circle-alpha",
    "reason": "compromised",
    "severity": "critical",
    "revoker_did": "did:guardian:OWNER",
    "revoker_role": "owner",
    "timestamp": "2026-06-30T10:00:00Z"
  },
  "sequence": 1,
  "merkle_root": "hex-sha256-root"
}
```

- Notes:
  - Owner revokers can issue any reason/severity.
  - Member revokers are limited to security-critical reasons and `critical` or `high` severity.
  - Owner-issued revocations also flip VC status-list bits for VCs issued to the revoked DID.
- Error responses:
  - `400 BAD_REQUEST`: invalid reason, severity, circle, or local membership state
  - `403 FORBIDDEN`: self-revocation, invalid proof, or member policy violation
  - `409 CONFLICT`: DID already revoked
  - `500 INTERNAL_SERVER_ERROR`: local DID/key/audit/persistence failure

### 3.76 GET `/crl/list`

- Full path: `/api/v1/crl/list`
- Request:
  - Query params: none
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
  "entries": [
    {
      "id": "urn:uuid:...",
      "revoked_did": "did:guardian:TARGET",
      "reason": "compromised",
      "severity": "critical",
      "revoker_did": "did:guardian:OWNER"
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

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: CRL persistence load failure

### 3.77 GET `/crl/entry`

- Full path: `/api/v1/crl/entry?id=urn:uuid:...`
- Request:
  - Query params:
    - `id` (required, string): CRL entry ID.
  - Body: none
- Success response (`200 OK`):

```json
{
  "id": "urn:uuid:...",
  "revoked_did": "did:guardian:TARGET",
  "reason": "compromised",
  "severity": "critical",
  "revoker_did": "did:guardian:OWNER"
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing or empty `id`
  - `404 NOT_FOUND`: CRL entry not found
  - `500 INTERNAL_SERVER_ERROR`: CRL persistence load failure

### 3.78 GET `/crl/check`

- Full path: `/api/v1/crl/check?did=did:guardian:TARGET`
- Request:
  - Query params:
    - `did` (required, string): DID to check.
  - Body: none
- Success response (`200 OK`):

```json
{
  "status": "success",
  "did": "did:guardian:TARGET",
  "revoked": true,
  "entry": {
    "id": "urn:uuid:...",
    "reason": "compromised",
    "severity": "critical"
  }
}
```

- Error responses:
  - `400 BAD_REQUEST`: missing or empty `did`
  - `500 INTERNAL_SERVER_ERROR`: CRL persistence load failure

### 3.79 POST `/crl/verify`

- Full path: `/api/v1/crl/verify`
- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "ok": true,
  "errors": []
}
```

- Failure response (`200 OK` with verification details):

```json
{
  "ok": false,
  "errors": [
    "invalid signature on CRL entry urn:uuid:..."
  ]
}
```

- Notes:
  - Verifies each entry signature against resolved DID public keys.
  - Recomputes the CRL Merkle root and rejects mismatches.
  - Re-applies member role restrictions and circle checks.

### 3.80 GET `/crl/root`

- Full path: `/api/v1/crl/root`
- Notes:
  - Reads secure tamper-evident audit logs from `/var/log/sgx-guardian/audit-{node}.log` (production) or `logs/audit-{node}.log` (development).
  - Returns entries in reverse chronological order (newest first).
- Error responses:
  - `404 NOT_FOUND`: no audit log file found for node `{node}`
  - `500 INTERNAL_SERVER_ERROR`: failed to open, read, or parse audit log file

### 3.76 GET `/cert/requests`

- Request:
  - Query params: none
  - Body: none
- Success response (`200 OK`):

```json
{
  "sequence": 1,
  "merkle_root": "hex-sha256-root"
}
```

- Notes:
  - Empty local CRL state returns `sequence: 0` and an empty `merkle_root`.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: CRL persistence load failure

### 3.81 POST `/crl/unrevoke`

- Full path: `/api/v1/crl/unrevoke`
[
  {
    "node_id": "nodeB",
    "requested_at": "2026-07-02T12:00:00.000Z",
    "overlay_ip": "192.168.100.2/24",
    "public_key_fingerprint": "ca8594035f65f328",
    "requested_role": "member",
    "approve": "false"
  }
]
```

- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: Failed to read requests directory or files.

### 3.77 POST `/cert/approve`

- Request:
  - Query params: none
  - JSON body:

```json
{
  "did": "did:guardian:TARGET"
}
```

  "node_id": "nodeB",
  "decision": "member"
}
```

  - Required fields: `node_id`, `decision`
  - Valid `decision` values: `"false"`, `"reject"`, `"deny"`, `"member"`, `"lighthouse"`, `"relay"`, `"lh_relay"`.
- Success response (`200 OK`):

```json
{
  "status": "success",
  "message": "CRL entry unrevoked",
  "did": "did:guardian:TARGET",
  "sequence": 2,
  "merkle_root": "hex-sha256-root"
}
```

- Notes:
  - Admin-only rollback for a mistakenly-issued revocation — reverses `POST /crl/revoke`.
  - Only the Circle **Owner** may call this, regardless of which role originally issued the revocation.
  - Removes the entry from the live `entries` list (`sequence` bumps, `merkle_root` recomputes and re-signs); the original per-entry file under `entries/<id>.json` is left untouched as append-only history.
  - If the original revocation flipped VC status-list bits for the revoked DID (owner-issued revocations only), those bits are restored (unset) as well.
- Error responses:
  - `400 BAD_REQUEST`: empty `did`, or other local CRL/DID state error
  - `403 FORBIDDEN`: caller's local role is Member, not Owner
  - `404 NOT_FOUND`: DID is not currently revoked
  - `500 INTERNAL_SERVER_ERROR`: local DID/key/audit/persistence failure

## 6. Network Orchestration Wi-Fi Endpoint Contracts

### 3.82 GET `/wifi/mode`

- Full path: `/api/v1/wifi/mode`
- Request:
  - Query params: none
  - Body: none
  - Headers: `Accept: application/json`
- Request Example:

```bash
curl -X GET http://localhost:8443/api/v1/wifi/mode
```

- Success response (`200 OK` - Dual Active):

```json
{
  "mode": "dual",
  "status": {
    "state": "DualActive",
    "metadata": {
      "message": null,
      "error_code": null
    }
  },
  "module1": {
    "role": "ap",
    "ssid": "MySecureHotspot",
    "channel": 6
  },
  "module2": {
    "role": "client",
    "saved_networks": [
      "HomeWiFi",
      "OfficeNetwork"
    ]
  },
  "security": {
    "zero_trust_active": true,
    "suricata_running": false
  }
}
```

- Success response (`200 OK` - Off State):

```json
{
  "mode": "off",
  "status": {
    "state": "Idle",
    "metadata": {
      "message": null,
      "error_code": null
    }
  },
  "module1": {
    "role": "ap",
    "ssid": "",
    "channel": 1
  },
  "module2": {
    "role": "client",
    "saved_networks": []
  },
  "security": {
    "zero_trust_active": false,
    "suricata_running": false
  }
}
```

- Notes:
  - Retrieves active orchestration mode (`off`, `hotspot_only`, `client_only`, `dual`), health state of internal state machine, and basic module configurations.
  - The `status.state` field represents the exact phase of the state machine. Possible values:
    - `Idle`: No active orchestration.
    - `ApplyingChange`: Actively transitioning states.
    - `HotspotStarting`: AP starting up.
    - `HotspotActive`: AP is broadcasted but no client/internet is active yet.
    - `ClientConnecting`: Uplink is attempting to associate.
    - `ClientConnected`: Uplink associated and obtained IP.
    - `DualStarting`: Bootstrapping Dual Wi-Fi mode.
    - `DualActive`: Both AP and client connected with NAT/Firewall routing active.
    - `Error`: Transition failed. Check `status.metadata.message` for details.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: Internal orchestrator state retrieval failure

### 3.83 POST `/wifi/mode`

- Full path: `/api/v1/wifi/mode`
- Request:
  - Query params: none
  - Headers: `Content-Type: application/json`
  - JSON body schema:
    - `mode` (string, required): Target mode (`DualWifi`, `HotspotOnly`, `ClientOnly`, `Off`).
    - `flags` (object): Flags such as `restore_on_boot`.
    - `hotspot` (object): AP settings (`interface`, `ssid`, `password`, `channel`, `band`, `client_isolation`).
    - `uplink` (object): Wi-Fi client settings (`interface`, `networks`).

- Request Examples:

  - **Dual Wi-Fi Mode (2.4GHz Hotspot)**:

```bash
curl -X POST http://localhost:8443/api/v1/wifi/mode \
-H "Content-Type: application/json" \
-d '{
  "mode": "DualWifi",
  "flags": {
    "restore_on_boot": true
  },
  "hotspot": {
    "interface": "uap0",
    "ssid": "SGX_Hotspot",
    "password": "SecurePassword123!",
    "channel": 6,
    "band": "2.4GHz",
    "client_isolation": true
  },
  "uplink": {
    "interface": "wlan1",
    "networks": [
      {
        "ssid": "HomeWiFi",
        "bssid": null,
        "password": "HomePassword123"
      }
    ]
  }
}'
```

  - **Dual Wi-Fi Mode (5GHz Hotspot)**:

```bash
curl -X POST http://localhost:8443/api/v1/wifi/mode \
-H "Content-Type: application/json" \
-d '{
  "mode": "DualWifi",
  "flags": {
    "restore_on_boot": true
  },
  "hotspot": {
    "interface": "uap0",
    "ssid": "SGX_Hotspot_5G",
    "password": "SecurePassword123!",
    "channel": 36,
    "band": "5GHz",
    "client_isolation": true
  },
  "uplink": {
    "interface": "wlan1",
    "networks": [
      {
        "ssid": "HomeWiFi",
        "bssid": null,
        "password": "HomePassword123"
      }
    ]
  }
}'
```

  - **HotspotOnly Mode (2.4GHz Band)**:

```bash
curl -X POST http://localhost:8443/api/v1/wifi/mode \
-H "Content-Type: application/json" \
-d '{
  "mode": "HotspotOnly",
  "flags": {
    "restore_on_boot": false
  },
  "hotspot": {
    "interface": "uap0",
    "ssid": "SGX_Hotspot_2.4G",
    "password": "SecurePassword123!",
    "channel": 6,
    "band": "2.4GHz",
    "client_isolation": true
  },
  "uplink": {
    "interface": "wlan1",
    "networks": []
  }
}'
```

  - **HotspotOnly Mode (5GHz Band)**:

```bash
curl -X POST http://localhost:8443/api/v1/wifi/mode \
-H "Content-Type: application/json" \
-d '{
  "mode": "HotspotOnly",
  "flags": {
    "restore_on_boot": false
  },
  "hotspot": {
    "interface": "uap0",
    "ssid": "SGX_Hotspot_5G",
    "password": "SecurePassword123!",
    "channel": 36,
    "band": "5GHz",
    "client_isolation": true
  },
  "uplink": {
    "interface": "wlan1",
    "networks": []
  }
}'
```

  - **ClientOnly Mode**:

```bash
curl -X POST http://localhost:8443/api/v1/wifi/mode \
-H "Content-Type: application/json" \
-d '{
  "mode": "ClientOnly",
  "flags": {
    "restore_on_boot": true
  },
  "hotspot": {
    "interface": "uap0",
    "ssid": "",
    "password": "",
    "channel": 1,
    "band": "2.4GHz",
    "client_isolation": false
  },
  "uplink": {
    "interface": "wlan1",
    "networks": [
      {
        "ssid": "OfficeWiFi",
        "bssid": "aa:bb:cc:dd:ee:11",
        "password": "OfficePasswordSecret"
      }
    ]
  }
}'
```

  - **Off Mode**:

```bash
curl -X POST http://localhost:8443/api/v1/wifi/mode \
-H "Content-Type: application/json" \
-d '{
  "mode": "Off",
  "flags": {
    "restore_on_boot": false
  },
  "hotspot": {
    "interface": "uap0",
    "ssid": "",
    "password": "",
    "channel": 1,
    "band": "2.4GHz",
    "client_isolation": false
  },
  "uplink": {
    "interface": "wlan1",
    "networks": []
  }
}'
```

- Success response (`200 OK`):

```json
{
  "status": "applying",
  "estimated_downtime_seconds": 3
}
```

- Notes:
  - Transition runs asynchronously in the background; query `GET /api/v1/wifi/mode` to track progress.
  - Hotspot AP password validation rules:
    - Minimum **8 characters** long.
    - Must contain at least **one non-alphanumeric character** (e.g. `!`, `@`, `#`, `$`).
    - Must not match common passwords in the embedded `rockyou` list.
  - Resilient Hotspot (Fail-Open): In `DualWifi` mode, local Hotspot is broadcasted *first* so local admin access is preserved even if uplink association fails.
  - Event-Driven NAT: Automatic patching of routing and Zero Trust policies upon uplink IP acquisition.
- Error responses:
  - `400 BAD_REQUEST`: Invalid payload format or password failed security constraints
  - `500 INTERNAL_SERVER_ERROR`: State machine transition initialization failed

### 3.84 GET `/wifi/scan`

- Full path: `/api/v1/wifi/scan`
- Request:
  - Query params: none
  - Body: none
- Request Example:

```bash
curl -X GET http://localhost:8443/api/v1/wifi/scan
```

- Success response (`200 OK`):

```json
{
  "networks": [
    {
      "ssid": "HomeWiFi",
      "bssid": "78:f5:05:8e:ec:74",
      "signal_dbm": -45,
      "band": "5GHz",
      "security": "WPA2"
    },
    {
      "ssid": "OfficeWiFi",
      "bssid": "24:cd:8d:89:f7:d1",
      "signal_dbm": -68,
      "band": "2.4GHz",
      "security": "WPA2"
    }
  ]
}
```

- Notes:
  - Forces the Wi-Fi module (`wlan0`) to perform a wireless network scan for visible access points in range.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: Wi-Fi scan operation failed or interface unavailable

### 3.85 GET `/wifi/clients`

- Full path: `/api/v1/wifi/clients`
- Request:
  - Query params: none
  - Body: none
- Request Example:

```bash
curl -X GET http://localhost:8443/api/v1/wifi/clients
```

- Success response (`200 OK`):

```json
{
  "clients": [
    {
      "expiry": 1720875323,
      "mac_address": "de:ad:be:ef:00:11",
      "ip_address": "192.168.200.101",
      "hostname": "android-device-xyz",
      "client_id": "01:de:ad:be:ef:00:11"
    },
    {
      "expiry": 1720875999,
      "mac_address": "11:22:33:44:55:66",
      "ip_address": "192.168.200.102",
      "hostname": "Iphone-15",
      "client_id": "01:11:22:33:44:55:66"
    }
  ]
}
```

- Notes:
  - Retrieves the list of active network clients currently connected to the local Hotspot by parsing dynamic DHCP leases assigned by `dnsmasq`.
- Error responses:
  - `500 INTERNAL_SERVER_ERROR`: Failed to parse DHCP lease table
  "message": "Request for node nodeB set to Member"
}
```

- Error responses:
  - `400 BAD_REQUEST`: Invalid `node_id` path traversal or invalid `decision` value.
  - `404 NOT_FOUND`: Request YAML file not found for specified `node_id`.
  - `500 INTERNAL_SERVER_ERROR`: Failed to read/write/parse request file on disk.

## 7. Connected Devices Management

Detailed request/response reference for the managed-device surface is maintained in `docs/device.md`.

Covered endpoints:

- `GET /api/v1/managed-devices`
- `GET /api/v1/managed-devices/{device_id}`
- `POST /api/v1/managed-devices`
- `DELETE /api/v1/managed-devices/{device_id}`
- `POST /api/v1/managed-devices/{device_id}/scan`
- `GET /api/v1/managed-devices/{device_id}/scan/{scan_id}`
- `POST /api/v1/managed-devices/{device_id}/reject`
- `POST /api/v1/managed-devices/{device_id}/block`
- `POST /api/v1/managed-devices/{device_id}/unblock`

Operational notes:

- Managed-device responses merge the signed device registry with discovery inventory enrichment and computed security/privacy scoring.
- Per-device scan progress is persisted and can be polled by `scan_id`.
- Block, reject, and unblock operations reuse the threat blocker state and nftables enforcement path.
- Protected-address checks prevent blocking this host, the active default gateway, loopback/unspecified addresses, and assigned Nebula overlay IPs.
