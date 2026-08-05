# Google Nest Direct Integration Specification (v1)

**Feature:** Google Nest Direct Integration (No Home Assistant UI Involvement)  
**Status:** Completed  
**Priority:** High  
**Target Version:** Guardian v2

---

# Overview

This document describes the specification and implementation plan for integrating **Google Nest smart home devices** (Nest Thermostats, Nest Cams, Nest Doorbells, Nest Protect) directly into the SGX Guardian platform.

The user experience goal is:

> The user opens the SGX Guardian App, connects their Google Nest account via OAuth 2.0 (or enters Client ID, Client Secret, and Project ID), and all Nest thermostats, cameras, doorbells, and sensors are discovered and controllable entirely from SGX. Home Assistant is used purely as a background hardware driver — the user never sees or interacts with it.

---

# Credentials & OAuth Parameters

The Google Nest integration operates over the **Google Smart Device Management (SDM) API**:

| Parameter | Value / Description |
|---|---|
| **Google SDM Project ID** | `be666f67-3423-4a5d-b82d-38ec2865e1fa` |
| **OAuth Client ID** | `826937801762-i23ak49q222h42sffqmgvemb9pnl5jvr.apps.googleusercontent.com` |
| **OAuth Client Secret** | Encrypted with **AES-GCM-256** at rest in `integrations.json` |
| **OAuth Scope** | `https://www.googleapis.com/auth/sdm.service` |

---

# Supported Google Nest Device Types (v1)

| Device Type | HA Entity Domain | Supported Commands & Parameters |
|---|---|---|
| Nest Learning Thermostat | `climate` | `set_temperature` (7°C–32°C / 45°F–90°F), `set_hvac_mode` (`heat`, `cool`, `heat_cool`, `off`), `preset_mode` (`eco`, `none`) |
| Nest Thermostat E | `climate` | `set_temperature`, `set_hvac_mode` |
| Nest Cam / Doorbell | `camera` | Live stream URL, motion / person detection events |
| Nest Protect (Smoke/CO) | `binary_sensor` / `sensor` | `smoke_detected`, `co_detected`, battery state (read-only telemetry) |

---

# System Architecture

```
SGX Guardian App (Frontend)
          │
          │ REST / WebSocket
          ▼
┌────────────────────────────────────────────────────────┐
│                   SGX Guardian Core                    │
│                                                        │
│  ┌─────────────────────────┐  ┌─────────────────────┐  │
│  │   IntegrationManager   │  │    DeviceManager    │  │
│  │ (Encrypted Credentials) │  │ (State Sync/Health) │  │
│  └────────────┬────────────┘  └──────────┬──────────┘  │
│               │                          │             │
│               ▼                          ▼             │
│  ┌─────────────────────────┐  ┌─────────────────────┐  │
│  │ NestHaConfigFlowClient  │  │    HaRestClient     │  │
│  └────────────┬────────────┘  └──────────┬──────────┘  │
└───────────────┼──────────────────────────┼─────────────┘
                │                          │
                ▼ (REST Config Flow API)   ▼ (REST / WS)
┌────────────────────────────────────────────────────────┐
│              Home Assistant (Headless Core)             │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │                nest (Config Entry)               │  │
│  └────────────────────────┬─────────────────────────┘  │
└───────────┼────────────────────────────┘
            │
            ▼ (Google SDM Cloud API)
              ┌───────────────────────────┐
              │ Google Nest Smart Devices │
              └───────────────────────────┘
```

---

# Implementation Phases

## Phase 1: Nest Credentials Data Model & Storage
- Create `NestCredentials` struct (`client_id`, `client_secret`, `project_id`, `access_token`, `refresh_token`, `expires_at`, `config_entry_id`).
- Add AES-GCM-256 encrypted persistence in `integrations.json`.
- Add `connect_nest()` method in `IntegrationManager`.

## Phase 2: HA Nest Config Entry Automation Client
- Build `NestHaConfigFlowClient` in `src/nest/ha_config_flow.rs`.
- On connect: call HA's config flow API to programmatically configure the Nest integration (`domain: "nest"`).
- Submit SDM `project_id`, `client_id`, `client_secret`, and OAuth authorization parameters/tokens.
- Store the returned `entry_id` in `integrations.json` for lifecycle management.
- Update `POST /api/v1/ha/integrations/google_nest/connect` API handler to accept OAuth tokens payload and invoke `connect_nest()`.

## Phase 3: Post-Connect Device Auto-Discovery & Metadata Tagging
- Trigger post-connect state reconciliation.
- Automatically tag discovered Nest entities with `vendor: "google_nest"`.
- Return `devices_discovered: N` count in `POST /api/v1/ha/integrations/google_nest/connect`.

## Phase 4: Extended Climate & Camera Device Control
- Implement `climate` domain service calls (`set_temperature`, `set_hvac_mode`, `preset_mode`).
- Enforce schema validation and parameter bounds checking in `CommandAuthorizer` (e.g. temperature bounds 7.0°C–32.0°C / 45.0°F–90.0°F).
- Refine parameter-aware no-op checking for climate controls.

## Phase 5: Health Monitoring & Token Refresh Worker
- Detect when Nest devices transition to `unavailable` or `unknown` in HA and mark `health_status: Offline`.
- `NotificationManager` generates `warning` notification on offline transition and `info` notification on recovery.
- `IntegrationTokenRefreshWorker` automatically rotates Nest OAuth access tokens before 3600-second expiration.

## Phase 6: Graceful Disconnect & Device Cleanup
- Implement `POST /api/v1/ha/integrations/google_nest/disconnect`.
- Unbind the HA `nest` config entry via `DELETE /api/config/config_entries/entry/{entry_id}`.
- Purge all `vendor: "google_nest"` devices from `DeviceRegistry` and `devices.json`.
- Clear stored Nest credentials from `integrations.json` and return `"devices_removed": N`.

---

# Requirements Checklist

## Connection & OAuth
- [x] `POST /api/v1/ha/integrations/google_nest/connect` accepts OAuth tokens / authorization payload
- [x] Credentials encrypted with AES-GCM-256 and stored in `integrations.json`
- [x] Programmatically establishes `nest` config entry in Home Assistant
- [x] Returns `devices_discovered: N` count in response

## Disconnect
- [x] `POST /api/v1/ha/integrations/google_nest/disconnect` deletes HA config entry
- [x] Purges all `vendor: "google_nest"` devices from `devices.json`
- [x] Clears stored credentials and returns `"devices_removed": N`

## Control & State Sync
- [x] Supports `set_temperature` with numeric degree bounds (7.0°C–32.0°C)
- [x] Supports `set_hvac_mode` (`heat`, `cool`, `heat_cool`, `off`)
- [x] Real-time state change propagation via WebSocket

## Health & Notifications
- [x] Transition to `unavailable` marks device `health_status: Offline`
- [x] `NotificationManager` generates `warning` / `info` alerts
- [x] Background worker handles automatic OAuth token refresh before expiration

---

# Status Endpoint

- [x] `GET /api/v1/ha/integrations/google_nest/status` returns connection mode, device count, last sync time, and credential state.
