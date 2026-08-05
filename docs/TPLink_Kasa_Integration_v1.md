# TP-Link Kasa Direct Integration Implementation Plan

**Feature:** TP-Link Kasa Direct Integration (No Home Assistant UI Involvement)  
**Status:** Completed  
**Priority:** High  
**Target Version:** Guardian v2

---

# Overview

This document describes the implementation plan for integrating **TP-Link Kasa smart home devices** directly into the SGX Guardian platform — without any user interaction with Home Assistant's UI.

The user experience goal is:

> The user opens the SGX Guardian App, enters their Kasa account credentials (or uses local-only mode), and all Kasa smart plugs, bulbs, strips, and switches are discovered and controllable entirely from SGX. Home Assistant is used purely as a background hardware driver — the user never sees or interacts with it.

---

# Goals

- Allow users to connect their Kasa account (or use local-only mode) directly from the SGX App.
- Auto-discover all Kasa devices on the local network via UDP broadcast (no manual IP entry required).
- Control Kasa devices (on/off, brightness, colour, energy monitoring) entirely via SGX REST API.
- Push real-time Kasa device state changes to the SGX frontend via WebSocket.
- Persist Kasa device registry and connection credentials securely in SGX.
- Provide full device lifecycle: discover → register → control → health monitor → remove.
- No $5 fee. No OAuth. No external cloud dependency required (local-only mode).

---

# Supported TP-Link Kasa Device Types (v1)

| Device Type | HA Entity Domain | Protocol | Port |
|---|---|---|---|
| Smart Plug | `switch` | XOR / KLAP | TCP 9999 / 20002 |
| Smart Bulb (on/off) | `light` | XOR / KLAP | TCP 9999 / 20002 |
| Smart Bulb (dimmable) | `light` | XOR / KLAP | TCP 9999 / 20002 |
| Smart Bulb (colour) | `light` | XOR / KLAP | TCP 9999 / 20002 |
| Smart Strip | `switch` (multi) | XOR / KLAP | TCP 9999 / 20002 |
| Energy Monitor Plug | `switch` + `sensor` | XOR / KLAP | TCP 9999 / 20002 |

---

# System Architecture

```
SGX Guardian App (Frontend)
          │
          │  REST / WebSocket
          ▼
SGX Guardian Rust Backend
┌─────────────────────────────────────────┐
│  POST /api/v1/ha/integrations/          │
│       tp_link_kasa/connect              │
│                                         │
│  Kasa Credential Store (integrations.json, AES-GCM-256)  │
│                                         │
│  HA Config Entries API Client           │◄── Configures HA programmatically
│       ↓                                 │
│  POST /api/v1/ha/devices/sync           │
│       ↓                                 │
│  Device Registry (devices.json)         │
│       ↓                                 │
│  Real-time Event Bus (broadcast)        │
└─────────────────────────────────────────┘
          │
          │  HA REST API + WebSocket
          ▼
Home Assistant (background driver — invisible to user)
┌─────────────────────────────────────────┐
│  TP-Link Kasa Integration               │
│  UDP Broadcast Discovery (port 9999)    │
│  Physical Kasa Devices                  │
└─────────────────────────────────────────┘
          │
     Physical LAN
          │
   [ Kasa Smart Plugs, Bulbs, Strips ]
```

---

# Kasa Protocol Details

## Legacy Devices (Pre-2023)
- **Transport:** TCP port 9999
- **Encryption:** XOR autokey cipher (initial key byte `0xAB`)
- **Format:** JSON payload after 4-byte big-endian length prefix
- **Authentication:** None required — direct local LAN access
- **Discovery:** UDP broadcast to `255.255.255.255:9999`

## Newer Devices (2023+, Tapo-like firmware)
- **Transport:** TCP port 20002
- **Encryption:** KLAP protocol (AES-based, session negotiated via handshake)
- **Authentication:** Requires Kasa account credentials (username + password) to derive local session keys
- **Discovery:** UDP broadcast to `255.255.255.255:20002`

> **SGX Strategy:** Use Home Assistant's Kasa integration which already handles both protocol variants transparently. SGX configures HA programmatically with the user's credentials and HA handles the low-level protocol negotiation.

---

# Connection Modes

## Mode A: Local-Only (No Cloud Account)
- Works for older Kasa devices (pre-2023) that support unauthenticated local access.
- No Kasa cloud credentials required.
- SGX tells HA to discover devices on the LAN without any account.
- Best for privacy-conscious users.

## Mode B: Cloud-Assisted Local Control (Recommended)
- User provides their Kasa cloud account credentials (email + password).
- HA uses credentials **only** to derive local encryption keys for newer devices.
- All device control happens locally over the LAN — no cloud traffic for commands.
- Required for newer Kasa devices using the KLAP protocol.

---

# User Flow — End-to-End

```
1. User opens SGX App → Smart Home → Integrations
   │
   ▼
2. User taps "Connect TP-Link Kasa"
   │
   ▼
3. SGX shows two options:
   │   A) Local-Only (no account)
   │   B) Cloud-Assisted (Kasa email + password)
   │
   ▼
4. User selects mode, enters credentials if needed
   │
   ▼
5. SGX App sends: POST /api/v1/ha/integrations/tp_link_kasa/connect
   Body: { "mode": "cloud", "username": "...", "password": "..." }
   │
   ▼
6. SGX Backend:
   a) Encrypts credentials → stores in integrations.json (AES-GCM-256)
   b) Calls HA Config Entries API → configures Kasa integration in HA
   c) HA performs UDP broadcast discovery on local network
   d) HA registers all found Kasa devices as entities
   │
   ▼
7. SGX App shows: "Kasa connected! X devices found. Tap to sync."
   │
   ▼
8. User taps "Sync" → POST /api/v1/ha/devices/sync
   │
   ▼
9. All Kasa devices appear in SGX device list with live state
   │
   ▼
10. User controls all devices from SGX forever
```

---

# API Design

All endpoints follow the existing `/api/v1/ha/` prefix convention.

## Integration Endpoints

### Connect Kasa Account
```
POST /api/v1/ha/integrations/tp_link_kasa/connect
```

Request Body:
```json
{
  "mode": "local | cloud",
  "username": "user@email.com",
  "password": "kasa_password"
}
```

Response:
```json
{
  "status": "connected",
  "provider": "tp_link_kasa",
  "mode": "cloud",
  "message": "TP-Link Kasa connected. Run device sync to import devices.",
  "devices_discovered": 4
}
```

### Disconnect Kasa Account
```
POST /api/v1/ha/integrations/tp_link_kasa/disconnect
```

Response:
```json
{
  "status": "disconnected",
  "message": "TP-Link Kasa integration removed. All Kasa devices removed from registry."
}
```

### Get Integration Status
```
GET /api/v1/ha/integrations/tp_link_kasa/status
```

Response:
```json
{
  "provider": "tp_link_kasa",
  "status": "connected",
  "mode": "cloud",
  "devices_count": 4,
  "last_sync": "2026-07-28T14:00:00Z"
}
```

## Device Sync
```
POST /api/v1/ha/devices/sync
```
_(Already implemented — fetches all HA states and registers supported entities)_

## Device Control
```
POST /api/v1/ha/devices/{id}/command
```

Supported commands for Kasa devices:

| Device Type | Command | Params |
|---|---|---|
| Smart Plug / Switch | `turn_on` | — |
| Smart Plug / Switch | `turn_off` | — |
| Smart Bulb | `turn_on` | `brightness`: 0–255 |
| Smart Bulb | `turn_off` | — |
| Colour Bulb | `turn_on` | `brightness`: 0–255, `color_temp`: 2700–6500 |
| Colour Bulb | `turn_on` | `rgb_color`: [r, g, b] |

---

# HA Config Entries API Integration

SGX configures HA's Kasa integration programmatically via HA's internal config flow API.

## Step 1: Initiate Config Flow
```
POST http://homeassistant:8123/api/config/config_entries/flow
Content-Type: application/json
Authorization: Bearer <HA_LONG_LIVED_TOKEN>

{
  "handler": "tplink"
}
```

## Step 2: Submit Credentials
```
POST http://homeassistant:8123/api/config/config_entries/flow/<flow_id>
Content-Type: application/json

{
  "username": "user@email.com",
  "password": "kasa_password"
}
```

## Step 3: Confirm
The response returns the created config entry with its `entry_id` which SGX stores for future management (disconnect/reconfigure).

---

# New Source Files

## SGX Backend

```
src/
├── kasa/                            ← NEW module
│   ├── mod.rs                       ← exports
│   ├── credentials.rs               ← KasaCredentials struct + AES-GCM encryption
│   └── ha_config_flow.rs            ← HA Config Entries API client for Kasa
├── api/handlers/
│   └── ha_integrations.rs           ← UPDATE: tp_link_kasa connect handler
└── integration/
    └── manager.rs                   ← UPDATE: persist kasa config_entry_id
```

---

# Implementation Phases

## Phase 1: Credential Storage & Validation
## Phase 1: Kasa Credentials Data Model & Storage
- Add `kasa_credentials` struct to `IntegrationMetadata`.
- Encrypt credentials with AES-GCM-256 in `integrations.json`.

## Phase 2: HA Config Entry Automation Client
- Create `KasaHaConfigFlowClient` in `src/kasa/ha_config_flow.rs`.
- Implement `setup_kasa_config_entry` and `remove_kasa_config_entry`.

## Phase 3: Post-Connect Device Discovery
- Auto-trigger state reconciliation after connecting Kasa.
- Tag discovered Kasa entities with `vendor: "tp_link"`.
- Return `devices_discovered: N` count in connect response.

## Phase 4: Device Control & State Sync
- Map SGX commands (`turn_on`, `turn_off`, `brightness`, `color_temp`, `rgb_color`) to HA service calls.
- Enforce schema validation and parameter-aware no-op checking.

## Phase 5: Health Monitoring & Offline Detection
- Detect `"unavailable"` / `"unknown"` entity states and mark device `health_status: Offline`.
- `NotificationManager` generates `warning` notifications on offline transition and `info` notifications on online recovery.

## Phase 6: Graceful Disconnect
- Issue `DELETE /api/config/config_entries/entry/{entry_id}` to Home Assistant.
- Purge all `vendor: "tp_link"` devices from `DeviceRegistry` and `devices.json`.
- Return `"devices_removed": N` in disconnect JSON response.

---

# Requirements Checklist

## Connection

- [x] `POST /api/v1/ha/integrations/tp_link_kasa/connect` accepts `mode`, `username`, `password`
- [x] Credentials encrypted with AES-GCM-256 and persisted to `integrations.json`
- [x] HA Config Entries flow initiated for `tplink` handler
- [x] `config_entry_id` stored for lifecycle management
- [x] Post-connect device auto-sync triggered (2.5s delay for HA discovery)
- [x] Connect response includes device count discovered (`devices_discovered: N`)

## Disconnect

- [x] `POST /api/v1/ha/integrations/tp_link_kasa/disconnect` removes HA config entry
- [x] All Kasa devices purged from `devices.json`
- [x] Credentials cleared from `integrations.json`
- [x] Disconnect response returns `"devices_removed": N`

## Device Control

- [x] `turn_on` / `turn_off` for smart plugs and switches
- [x] `brightness` parameter for dimmable bulbs (0–255)
- [x] `color_temp` parameter for tunable white bulbs (2700–6500K)
- [x] `rgb_color` parameter for colour bulbs
- [x] Schema validation enforces parameter bounds (`CommandAuthorizer`)

## State & Health

- [x] Real-time state updates via HA WebSocket `state_changed` events
- [x] Offline detection when Kasa device goes `unavailable` in HA
- [x] `warning` notification generated when device goes offline
- [x] Deleted devices purged from `devices.json` on reconciliation

## Status & Monitoring

- [x] `GET /api/v1/ha/integrations/tp_link_kasa/status` returns connection mode, device count, last sync time

---

# Testing Checklist

## Happy Path

- [x] Connect with valid cloud credentials → HA configures Kasa integration
- [x] Kasa devices auto-discovered and synced to SGX
- [x] `turn_on` / `turn_off` command reaches physical device
- [x] State change on physical device reflected in SGX within 2 seconds
- [x] Disconnect removes HA entry and clears devices from registry

## Edge Cases

- [x] Connect with wrong credentials → `401 Unauthorized`
- [x] Connect with no devices on network → `200 OK` with `devices_discovered: 0`
- [x] Device unplugged → marked `Offline` in SGX within 30s
- [x] Device re-plugged → marked `Online` in SGX within 30s
- [x] Send `turn_on` to already-on device → `400 Bad Request` (no-op rejection)
- [x] 11 rapid commands in 60s → 11th returns `429 Too Many Requests`
- [x] Guardian restarts → Kasa devices reloaded from `devices.json` with last known state

---

# Definition of Done

The Kasa integration is considered complete when:

- All device control commands (on/off, brightness, colour) work from SGX and reach physical hardware.
- Real-time state changes (including offline detection) appear in the SGX app within 2 seconds.
- Disconnecting from SGX cleanly removes the HA integration entry and all device records.
- All checklist items above are completed.
- All testing scenarios pass.
