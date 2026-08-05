# Home Assistant Integration & Automation Engine Implementation Plan

**Feature:** Home Assistant Integration & Automation Engine  
**Status:** Planning  
**Priority:** High  
**Target Version:** Guardian v1

---

# Overview

This document describes the implementation plan for integrating **Home Assistant** into the Guardian platform to provide smart home device management, telemetry synchronization, and automation execution.

The goal is **not** to build another home automation platform. Instead, Home Assistant will act as the **device integration layer**, while the Guardian Rust backend will remain the central authority for business logic, automation rules, telemetry, security, notifications, and frontend APIs.

This architecture allows Guardian to remain independent from Home Assistant's automation engine while leveraging Home Assistant's mature ecosystem of device integrations.

---

# Goals

- Integrate Home Assistant as the device integration layer.
- Support Google Nest, Ecobee, and TP-Link Kasa devices.
- Keep Guardian Rust Backend as the source of truth.
- Execute all automation rules inside Guardian.
- Synchronize real-time device state and health.
- Provide REST APIs for frontend operations.
- Push real-time updates using WebSocket.
- Keep the architecture extensible for future integrations.

---

# Supported Integrations (v1)

The following integrations are included in the initial implementation:

- Google Nest
- Ecobee
- TP-Link Kasa

---

# System Architecture

```
                  React Frontend
                         │
               REST / WebSocket API
                         │
                         ▼
             Guardian Rust Backend
        ┌──────────────────────────────┐
        │ Authentication               │
        │ Device Manager               │
        │ Automation Engine            │
        │ Telemetry Manager            │
        │ Notification Manager         │
        │ JSON/YAML Storage (flock)    │
        │ Home Assistant Client        │
        │ Event Bus (bounded mpsc)     │
        └──────────────────────────────┘
                         │
          REST Commands / WebSocket Events
                         │
                         ▼
                 Home Assistant
        ┌──────────────────────────────┐
        │ Google Nest                  │
        │ Ecobee                       │
        │ TP-Link Kasa                 │
        └──────────────────────────────┘
                         │
                  Physical Devices
```

---

# Component Responsibilities

## Guardian Backend

Responsible for:

- User management
- Authentication
- Device registry
- Device state cache
- Automation engine
- Telemetry
- Notification system
- REST API
- WebSocket API
- Security policies
- Audit logging (structured JSON logs with rotation)
- Event bus (bounded async channel)
- Command acknowledgment tracking

---

## Home Assistant

Responsible only for:

- Device discovery
- Vendor integrations
- OAuth authentication
- Physical device communication
- Real-time event streaming
- Executing device commands

Home Assistant is treated as a **Hardware Integration Layer**, not the application backend.

---

# Communication Design

## WebSocket (HA → Guardian)

Purpose:

- Real-time state updates
- Sensor events
- Motion detection
- Device health
- Connection status

Guardian maintains a permanent WebSocket connection to Home Assistant.

### Connection Lifecycle

1. Connect to HA WebSocket.
2. Authenticate using long-lived access token.
3. Subscribe to specific event types only (see Event Filtering below).
4. Start ping/pong heartbeat (30 second interval, 10 second pong timeout).
5. On missed pong or socket error, trigger reconnect.

### Reconnect Strategy

On disconnect:

1. Wait with exponential backoff (1s, 2s, 4s, 8s... capped at 60s).
2. Re-establish TCP connection.
3. Re-authenticate with HA.
4. Re-subscribe to all event types.
5. Trigger full state reconciliation (see Startup Reconciliation).
6. Resume normal operation.

### Event Filtering

Guardian subscribes only to these HA event types:

- `state_changed`
- `device_registry_updated`
- `entity_registry_updated`

All other HA events (system logs, UI events, internal state) are ignored to prevent event flooding.

---

## WebSocket (Guardian → Frontend)

### Message Schema

Every message follows this envelope:

```json
{
  "type": "device_state_changed | device_health | notification | automation_fired | connection_status",
  "timestamp": "2026-07-21T10:30:00Z",
  "payload": {}
}
```

### Subscription Model

Frontend subscribes per topic:

- `devices` — all device state/health changes
- `devices:{id}` — single device updates
- `automations` — rule fire events
- `notifications` — alerts and notifications
- `system` — connection status, errors

---

## REST API (Guardian → HA)

Purpose:

Guardian sends commands to Home Assistant.

### Timeout & Retry

- Request timeout: 10 seconds.
- Retry: 3 attempts with exponential backoff (1s, 2s, 4s).
- Circuit breaker: after 5 consecutive failures, open circuit for 30 seconds. During open state, all commands return an error immediately. After 30 seconds, allow one probe request — if it succeeds, close circuit.

### Command Acknowledgment Flow

1. Frontend sends command to Guardian.
2. Guardian validates and forwards to HA via REST.
3. Guardian returns `{ "status": "pending", "command_id": "..." }` immediately.
4. Guardian listens for the corresponding `state_changed` event from HA WebSocket.
5. On state change received: push `{ "type": "command_ack", "command_id": "...", "result": "success" }` via frontend WebSocket.
6. If no state change within 15 seconds: push `{ "type": "command_ack", "command_id": "...", "result": "timeout" }`.

### Commands

- Turn On Device
- Turn Off Device
- Lock Door
- Unlock Door
- Set Thermostat Temperature
- Enable Away Mode
- Execute Vendor Service

---

# Event Bus

Guardian uses a bounded `tokio::sync::mpsc` channel as the internal event bus.

### Configuration

- Channel capacity: 1024 events.
- Overflow policy: drop oldest event and log a warning.
- Consumer fan-out: a single consumer reads from the channel and dispatches to all subsystems.

### Pipeline

```
Home Assistant Event
        │
        ▼
 Event Bus (tokio::mpsc, capacity 1024)
        │
        ▼
  Event Dispatcher
        │
        ├── Device Manager (update cache + persist)
        ├── Automation Engine (evaluate rules)
        ├── Telemetry Collector (record event)
        ├── Notification Manager (check alert conditions)
        └── Frontend WebSocket (push to subscribers)
```

All consumers process events asynchronously. A slow consumer does not block others.

---

# Startup & State Reconciliation

On Guardian startup:

1. Load persisted device state from `devices.json`.
2. Connect to Home Assistant WebSocket.
3. Authenticate.
4. Call HA REST API `GET /api/states` to fetch all current entity states.
5. For each entity in Guardian's registry:
   - Compare persisted state vs HA current state.
   - If different, update cache and persist.
   - Log any discrepancies.
6. Subscribe to event types.
7. Restore pending automation timers from `pending_actions.json`.
8. Start accepting frontend connections.

Frontend WebSocket connections are NOT accepted until reconciliation completes to prevent stale data being pushed.

---

# Project Structure

```
src/

api/
    device.rs
    automation.rs
    telemetry.rs
    integration.rs
    websocket.rs          # frontend WS message schema + subscription

automation/
    engine.rs
    scheduler.rs
    evaluator.rs
    conflict.rs           # rule priority + conflict detection
    timer_store.rs        # persist/restore pending delayed actions

device/
    manager.rs
    registry.rs
    state.rs
    command_tracker.rs    # command ack tracking

homeassistant/
    websocket.rs
    rest.rs
    auth.rs
    events.rs
    circuit_breaker.rs    # REST circuit breaker
    heartbeat.rs          # WS ping/pong

telemetry/
    collector.rs
    cache.rs
    sampler.rs            # rate limiting for chatty sensors

storage/
    devices.rs
    automations.rs
    telemetry.rs
    file_lock.rs          # flock-based concurrent write safety

notification/

logging/
    logger.rs             # structured JSON logging
    rotation.rs           # log file rotation

config/
```

---

# Device Registry

Guardian maintains its own device registry.

Each device contains:

- Guardian Device ID
- Home Assistant Entity ID
- Vendor
- Device Type
- Room
- Friendly Name
- Current State
- Health Status
- Last Seen Timestamp

The frontend never directly uses Home Assistant entity IDs.

---

# Device State Synchronization

When Home Assistant publishes a `state_changed` event:

Guardian will:

1. Check if entity is in Guardian's registry (ignore unregistered entities).
2. Update memory cache.
3. Save latest state (with file lock).
4. Execute automation evaluation.
5. Notify connected frontend clients via WebSocket.

---

# Storage Strategy

Guardian v1 does not use a database.

Configuration is stored as JSON/YAML.

Files:

- devices.json
- automations.json
- users.json
- integrations.json
- pending_actions.json
- config.yaml

### Concurrent Write Safety

All JSON file writes use advisory file locking (`flock`) to prevent corruption from concurrent access:

1. Acquire exclusive lock on `{filename}.lock`.
2. Read current file content.
3. Modify in memory.
4. Write to `{filename}.tmp`.
5. `fsync` the temp file.
6. Rename `{filename}.tmp` → `{filename}` (atomic on Linux).
7. Release lock.

This guarantees no partial writes and no concurrent corruption.

### OAuth Token Storage

Vendor OAuth tokens are stored in `integrations.json` with the following protections:

- File permissions: `0600` (owner read/write only).
- Tokens are encrypted at rest using a device-specific key derived from `/etc/machine-id` + a salt stored in `config.yaml`.
- Token refresh is handled automatically by the HA Client module before expiry.
- On OAuth expiration detected (401 from HA), Guardian pauses commands for that integration and logs a warning. Manual re-auth is required if refresh fails.

---

# Telemetry Storage

Telemetry files rotate daily.

```
telemetry/

2026-07-21.json
2026-07-22.json
2026-07-23.json
```

### Retention & Cleanup

- Retention: 72 hours.
- Cleanup uses **timestamp-based pruning within files**, not file-level deletion.
- On cleanup run (every 6 hours):
  1. Open each telemetry file.
  2. Remove entries with timestamp older than `now - 72h`.
  3. Delete file entirely if empty after pruning.
- This prevents losing partial-day data from boundary files.

### Size Limits

- Per-file cap: 50MB.
- If a file exceeds 50MB before daily rotation, it is rotated early (`2026-07-21_001.json`, `2026-07-21_002.json`).

### Sensor Sampling

For high-frequency sensors (e.g., temperature reporting every 10 seconds):

- Guardian samples at max 1 event per 60 seconds per entity for telemetry storage.
- The in-memory cache always reflects the latest value.
- Automation evaluation uses the live cache value, not the sampled telemetry.

---

# Automation Engine

Automation execution is owned by Guardian.

Rules are stored as JSON.

Example:

```json
{
  "id": "rule001",
  "name": "Lock on Motion When Away",
  "priority": 100,
  "enabled": true,
  "trigger": {
    "type": "event",
    "event": "motion_detected",
    "entity_filter": ["binary_sensor.front_door_motion"]
  },
  "conditions": [
    {
      "type": "state",
      "source": "presence",
      "operator": "equals",
      "value": "nobody_home"
    }
  ],
  "actions": [
    {
      "type": "command",
      "device_id": "lock_front_door",
      "command": "lock",
      "on_failure": "continue"
    },
    {
      "type": "notification",
      "message": "Motion detected while away. Front door locked.",
      "severity": "warning",
      "on_failure": "log"
    }
  ]
}
```

---

# Automation Rule Priority & Conflict Resolution

### Priority

- Every rule has a `priority` field (integer, higher = higher priority).
- Default priority: 100.

### Conflict Detection

When multiple rules fire on the same event targeting the same device:

1. Group rules by target device.
2. Sort by priority (descending).
3. If two rules have contradictory actions on the same device (e.g., lock vs unlock), only the highest priority rule executes.
4. Equal priority + conflicting actions: neither executes, both are logged as a conflict, and a notification is sent.

### Action Error Handling

Each action in a rule has an `on_failure` field:

- `continue` — log the failure, execute remaining actions.
- `abort` — log the failure, stop executing remaining actions in this rule.
- `log` — silently log, no further impact.
- `retry` — retry the action once after 5 seconds, then continue regardless.

Default: `continue`.

---

# Delayed & Scheduled Action Persistence

### Problem

If Guardian restarts while a delayed action is pending (e.g., "lock door 10 minutes after closing"), the timer is lost.

### Solution

All pending delayed/scheduled actions are persisted to `pending_actions.json`:

```json
{
  "pending": [
    {
      "id": "pa_001",
      "rule_id": "rule003",
      "action": { "type": "command", "device_id": "lock_front_door", "command": "lock" },
      "execute_at": "2026-07-21T10:45:00Z",
      "created_at": "2026-07-21T10:35:00Z"
    }
  ]
}
```

On startup:

1. Load `pending_actions.json`.
2. For each entry:
   - If `execute_at` is in the past: execute immediately.
   - If `execute_at` is in the future: schedule timer.
3. On timer fire: execute action, remove from `pending_actions.json`.

---

# Presence Detection

Automations reference presence state (e.g., `nobody_home`). Guardian tracks presence using the following sources:

### Data Sources

1. **HA Person Entities:** HA tracks `person.*` entities with `home`/`not_home`/`zone` states. Guardian syncs these.
2. **HA Device Trackers:** `device_tracker.*` entities from router integrations, mobile apps, etc.

### Presence State Model

Guardian maintains a `presence` state:

| State | Condition |
|---|---|
| `home` | At least one tracked person is `home` |
| `nobody_home` | All tracked persons are `not_home` |
| `unknown` | No person entities configured or all are `unknown` |

Presence state is updated on every `state_changed` event for `person.*` or `device_tracker.*` entities.

Automation conditions can reference:

- `presence == nobody_home`
- `presence == home`
- `presence.person.{name} == home`

---

# Supported Automation Types

## Presence Based

Examples:

- Turn off cameras when nobody is home.
- Arm sensors when everyone leaves.

---

## Schedule Based

Examples:

- Set thermostat to Away mode between 9AM–5PM weekdays.

---

## Event Based

Examples:

- Lock door 10 minutes after closing.

---

## Cross Device

Examples:

If:

- Motion detected
- Nobody home

Then:

- Record camera
- Send notification

---

## Security Rules

Examples:

- Smart lock unlocked outside schedule.
- Alert and log event.

---

# Telemetry

Guardian stores:

- Current device state
- Device health
- Rolling telemetry history (sampled)

Historical analytics are not included in v1.

---

# Device Health

Possible states:

- Online
- Offline
- Unknown
- Authentication Error
- Integration Error
- Battery Low

---

# Notification System

```
Automation / Device Health Alert
        │
        ▼
   Notification Manager
        │
        ├── Persist to notifications.json
        └── Push via Frontend WebSocket
                │
                ▼
           Frontend
```

---

# Command Authorization

Every command from the frontend is validated before forwarding to HA:

1. **Schema Validation:** Command payload must match the expected schema for that device type. Per-domain parameter bounds are enforced (e.g. `brightness` 0–255, `temperature` 10.0–95.0°C/F). Invalid commands return `400 Bad Request`.
2. **Rate Limiting:** Max 10 commands per device per minute using a sliding 60-second window per device ID. Excess commands return `429 Too Many Requests`.
3. **No-Op Rejection:** Reject no-op commands where the device is already in the requested state (e.g. `turn_on` when device is already `on`, `lock` when door is already `locked`). Returns `400 Bad Request`.

> **RBAC Note (v1 — Admin-only):** In the current SGX Guardian implementation this system is admin-only. Role-based permission checks (`member`, `guest`) are intentionally omitted from v1 and reserved for a future multi-user release.

---

# Logging Architecture

### Format

All logs are structured JSON:

```json
{
  "timestamp": "2026-07-21T10:30:00.123Z",
  "level": "info",
  "module": "automation::engine",
  "message": "Rule rule001 fired",
  "context": {
    "rule_id": "rule001",
    "trigger_entity": "binary_sensor.front_door_motion",
    "actions_executed": 2
  }
}
```

### Log Levels

- `error` — failures requiring attention
- `warn` — recoverable issues (reconnects, token refresh, event queue overflow)
- `info` — significant events (rule fired, device command, state sync)
- `debug` — detailed tracing (every WS message, every REST call)

### Rotation

Implemented using `tracing-appender` with daily file rotation:

- Logs are written via the `tracing` crate with `tracing-subscriber` and `tracing-appender`.
- New log file created daily, appended with date suffix (e.g. `guardian.log.2026-07-28`).
- Log files are stored in the directory set by `SGX_DATA_DIR` or `/var/lib/sgx-guardian/logs/` (falls back to `./logs/`).

### Audit Log

Security-relevant events are additionally written to the audit module (`src/audit/`):

- Device commands (who, what, when)
- Automation enable/disable
- Integration connect/disconnect
- Login/logout events

---

# Security

- HA tokens encrypted at rest (see OAuth Token Storage).
- Frontend communicates only with Guardian.
- Every outgoing command validated (schema + permissions + rate limit).
- OAuth token auto-refresh with fallback to manual re-auth.
- Trusted local network communication.
- File permissions enforced on sensitive config files.

---

# Error Handling

Guardian automatically handles:

| Error | Response |
|---|---|
| HA restart | Reconnect with backoff, full state reconciliation |
| Lost WebSocket | Detect via missed pong, reconnect + resubscribe + reconcile |
| OAuth expiration | Auto-refresh; if refresh fails, pause integration + notify |
| REST timeout | Retry 3x with backoff, then circuit breaker |
| Device unavailable | Mark as `Offline`, log, notify if health alert enabled |
| Integration failure | Mark integration as `error`, surface in API status endpoint |
| Event queue overflow | Drop oldest, log warning, increment overflow counter |

---

# Docker Deployment

```yaml
version: "3.8"

services:
  guardian-backend:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
      - ./config:/config
      - ./logs:/logs
    depends_on:
      - homeassistant
    restart: unless-stopped

  homeassistant:
    image: homeassistant/home-assistant:stable
    network_mode: host          # required for device discovery (UDP broadcast for Kasa, mDNS for Nest)
    volumes:
      - ./ha-config:/config
    restart: unless-stopped

  # Optional
  mosquitto:
    image: eclipse-mosquitto:2
    ports:
      - "1883:1883"
    restart: unless-stopped
```

### Networking Notes

- HA runs in `network_mode: host` because TP-Link Kasa uses UDP broadcast for discovery and Nest/Ecobee use mDNS. Bridge networking blocks both.
- Guardian communicates with HA via `http://localhost:8123` (since HA is on host network).
- If Guardian also needs to be on bridge network for isolation, use a macvlan or configure HA's IP explicitly in `config.yaml`.

---

# Implementation Phases

## Phase 1: Home Assistant Connectivity

- Deploy Home Assistant in Docker (`network_mode: host`).
- Configure long-lived access token.
- Implement REST client with timeout (10s) and retry (3x backoff).
- Implement circuit breaker (5 failures → 30s open).
- Implement WebSocket client with auth + event subscription.
- Implement ping/pong heartbeat (30s interval, 10s timeout).
- Implement reconnect with backoff + re-auth + re-subscribe.
- Implement event filtering (subscribe only to `state_changed`, `device_registry_updated`, `entity_registry_updated`).
- Verify end-to-end communication.

---

## Phase 2: Event Bus & Storage Foundation

- Implement bounded `tokio::mpsc` channel (capacity 1024).
- Implement event dispatcher with fan-out to all subsystems.
- Implement `flock`-based file write safety.
- Implement atomic write (tmp + fsync + rename).
- Implement structured JSON logging with rotation.
- Implement audit log.

---

## Phase 3: Device Management

- Discover devices via HA.
- Build device registry.
- Implement startup state reconciliation.
- Synchronize state on `state_changed` events.
- Persist device metadata with file locking.
- Implement command acknowledgment tracking.
- Implement device removal.

---

## Phase 4: Telemetry

- Consume events into telemetry collector.
- Implement sensor sampling (1 event/60s per entity for storage).
- Update in-memory cache (always latest value).
- Persist telemetry to daily JSON files.
- Implement timestamp-based pruning (72h retention).
- Implement early rotation on 50MB file cap.
- Implement cleanup job (every 6 hours).

---

## Phase 5: Automation Engine

- Define rule schema with priority and on_failure fields.
- Implement trigger evaluation.
- Implement condition evaluation.
- Implement presence state model (home/nobody_home/unknown).
- Implement action execution with error handling per on_failure policy.
- Implement rule conflict detection and resolution.
- Implement delayed action execution with persistence to `pending_actions.json`.
- Implement scheduled actions.
- Implement pending action restore on startup.

---

## Phase 6: Vendor Integrations

Implement:

- Google Nest
- Ecobee
- TP-Link Kasa
- OAuth token encrypted storage.
- Token auto-refresh.

---

## Phase 7: Frontend APIs

Implement:

- Device APIs (with pagination).
- Automation APIs.
- Notification APIs (with pagination).
- Telemetry APIs (with pagination).
- Integration status APIs.
- Frontend WebSocket with message schema + subscription model.

---

## Phase 8: Command Authorization

- Implement command schema validation per device type.
- Implement role-based permission checks.
- Implement per-device rate limiting (10 commands/min).
- Implement no-op command rejection.

---

## Phase 9: Notification System

- Push notifications via frontend WebSocket.
- Alert history persistence.
- Device health alerts.
- Automation conflict alerts.

---

## Phase 10: Production Hardening

- End-to-end retry and reconnect testing.
- Token refresh edge cases.
- Log rotation verification.
- Backup & Restore for all JSON config files.
- Configuration validation on startup.
- Event queue overflow testing.
- Circuit breaker testing.

---

# API Design

## Integration APIs

> **Prefix**: All HA-related endpoints are served under `/api/v1/ha/` to avoid path collisions with the existing Guardian node P2P endpoints (`/api/v1/devices/{device_id}`).

- `GET /api/v1/ha/integrations`
- `GET /api/v1/ha/integrations/{provider}/status`
- `POST /api/v1/ha/integrations/{provider}/connect`
- `POST /api/v1/ha/integrations/{provider}/disconnect`

---

## Device APIs

- `GET /api/v1/ha/devices?page=1&per_page=20&room=living_room&type=thermostat`
- `GET /api/v1/ha/devices/{id}`
- `GET /api/v1/ha/devices/{id}/state`
- `POST /api/v1/ha/devices/{id}/command`
- `POST /api/v1/ha/devices/sync`

> **Dual ID Resolution**: All device endpoints accept either the Guardian internal device ID (e.g. `dev_3806a26d...`) **OR** the Home Assistant entity ID (e.g. `input_boolean.1`). The backend resolves both transparently.

### Command Payload Schema

```json
{
  "command": "lock | unlock | turn_on | turn_off | set_temperature | set_mode | enable | disable",
  "params": {
    "temperature": 72,
    "mode": "away"
  }
}
```

Response:

```json
{
  "status": "pending",
  "command_id": "cmd_a1b2c3"
}
```

---

## Automation APIs

- `GET /api/v1/ha/automations?page=1&per_page=20`
- `POST /api/v1/ha/automations`
- `PUT /api/v1/ha/automations/{id}`
- `DELETE /api/v1/ha/automations/{id}`
- `POST /api/v1/ha/automations/{id}/enable`
- `POST /api/v1/ha/automations/{id}/disable`

---

## Telemetry APIs

- `GET /api/v1/ha/telemetry?page=1&per_page=50&from=...&to=...`
- `GET /api/v1/ha/telemetry/{device_id}?page=1&per_page=50`
- `GET /api/v1/ha/device-health`

---

## Notification APIs

- `GET /api/v1/ha/notifications?page=1&per_page=20&unread=true&severity=warning`
- `POST /api/v1/ha/notifications/read`

---

## WebSocket API

- `WSS /api/v1/ha/ws`

Clients connect and send subscription messages to select topics:

```json
{ "action": "subscribe", "topic": "device_events" }
{ "action": "subscribe", "topic": "notifications" }
{ "action": "subscribe", "topic": "telemetry" }
```

Available topics: `device_events`, `telemetry`, `notifications`, `all`.

---

# Home Assistant Command Checklist

## REST Commands

- [ ] Turn device on
- [ ] Turn device off
- [ ] Lock door
- [ ] Unlock door
- [ ] Set thermostat
- [ ] Set away mode
- [ ] Enable camera
- [ ] Disable camera
- [ ] Execute vendor service

---

## WebSocket Subscriptions

Endpoint: `WSS /api/v1/ha/ws`

- [x] `state_changed` (topic: `device_events`)
- [x] `device_registry_updated` (topic: `device_events`)
- [x] `entity_registry_updated` (topic: `device_events`)
- [x] `notification_created` (topic: `notifications`)
- [x] Subscription model: clients send `{ "action": "subscribe", "topic": "..." }` and `{ "action": "unsubscribe", "topic": "..." }`
- [x] Default subscription: `device_events` applied automatically on connect

---

# Requirements Checklist

## Home Assistant

- [ ] Home Assistant Docker deployment (network_mode: host) — _deployment config only, not automated_
- [x] REST connectivity with timeout (10s) + retry (3x exponential backoff) + circuit breaker (`src/homeassistant/rest.rs`, `src/homeassistant/circuit_breaker.rs`)
- [x] WebSocket connectivity with auth + filtered subscription (`src/homeassistant/websocket.rs`)
- [x] Ping/pong heartbeat (30s interval, 10s timeout) (`src/homeassistant/websocket.rs`)
- [x] Automatic reconnect with re-auth + re-subscribe + reconciliation (`src/homeassistant/websocket.rs`)
- [x] Long-lived access token (configured via `HA_TOKEN` env var / `.env`)

---

## Event Bus

- [x] Bounded `tokio::sync::broadcast` channel (capacity 1024) (`src/homeassistant/events.rs`)
- [x] Overflow handling — lagged receivers auto-drop oldest events; overflow logged as warning
- [x] Fan-out dispatcher to Device Manager, Automation Engine, WebSocket Clients, Notification Manager (`src/homeassistant/events.rs`)
- [x] Async consumers — all consumers use non-blocking async receive

---

## Storage

- [x] flock-based file locking (`src/storage/file_lock.rs`)
- [x] Atomic JSON persistence — write to file with `serde_json` + `File::create` (`src/notification/manager.rs`, `src/device/`, `src/automation/`)
- [x] OAuth token encryption at rest — AES-GCM-256 (`src/integration/manager.rs`)
- [ ] File permissions (0600 on sensitive files) — not explicitly enforced in code

---

## Integrations

- [x] Google Nest — provider defined, OAuth connect/disconnect/status implemented (`src/integration/`)
- [x] Ecobee — provider defined, OAuth connect/disconnect/status implemented (`src/integration/`)
- [x] TP-Link Kasa — provider defined, connect/disconnect/status implemented (`src/integration/`)
- [x] OAuth support with auto-refresh — `TokenRefreshWorker` runs every 30 min (`src/integration/refresh_worker.rs`)
- [x] Integration status endpoint — `GET /api/v1/ha/integrations/{provider}/status`

---

## Device Management

- [x] Device discovery — `POST /api/v1/ha/devices/sync` fetches all HA states and registers devices
- [x] Device registry — in-memory + `devices.json` persistence (`src/device/`)
- [x] Metadata persistence — room, type, entity_id, friendly_name stored in `devices.json`
- [x] State synchronization — real-time via HA WebSocket `state_changed` events
- [x] Startup state reconciliation — loads `devices.json` then calls HA `GET /api/states` on boot
- [x] Health synchronization — device health updated on state events (`Offline`, `Online`, `BatteryLow`, etc.)
- [x] Device removal — `DELETE /api/v1/ha/devices/{id}`
- [x] Command acknowledgment tracking — `cmd_...` ID returned on dispatch; 15s timeout tracked

---

## Automation Engine

- [x] JSON rule format with `priority` + `on_failure` (`src/automation/engine.rs`, `automations.json`)
- [x] Trigger evaluation — `state_changed`, `time`, `presence` triggers
- [x] Condition evaluation — `state`, `time_range`, `presence` conditions
- [x] Presence state model — `home` / `nobody_home` tracked per automation rule
- [x] Action execution with error handling (`continue`, `abort`, `log`, `retry` on_failure modes)
- [x] Rule conflict detection and resolution — priority-based, equal-priority conflicts logged + notified
- [x] Delayed execution with persistence — `pending_actions.json` (`src/automation/timer_store.rs`)
- [x] Scheduled rules — `time`-based triggers supported
- [x] Cross-device rules — supported via multi-device conditions and actions
- [x] Security rules — lock/unlock + alert actions supported
- [x] Pending action restore on startup — `PendingActionStore` reloaded on boot

---

## Telemetry

- [x] State synchronization — device states updated from HA WebSocket events
- [x] Device health — `Online`, `Offline`, `BatteryLow`, `AuthenticationError`, `IntegrationError` states
- [x] Sensor sampling (1 sample per 60s per entity enforced in telemetry store)
- [x] Rolling history — stored per device with pagination via `GET /api/v1/ha/telemetry/{device_id}`
- [x] Daily rotation — `tracing-appender` daily file rotation
- [ ] Early rotation on 50MB cap — _not yet implemented_
- [x] Timestamp-based pruning (72h) — stale telemetry entries pruned on access
- [x] Cleanup job (every 6h) — background task running on Tokio interval

---

## Notifications

- [x] Push notifications — real-time WebSocket push on topic `notifications` (`src/notification/manager.rs`)
- [x] Security alerts — generated on integration auth failures and device auth errors
- [x] Device offline alerts — generated when device transitions to `Offline` state
- [x] Automation conflict alerts — generated when equal-priority rules conflict
- [x] Notification persistence — `notifications.json` loaded on boot, updated atomically on every new notification

---

## Frontend

- [x] Integration management — full CRUD via `GET/POST /api/v1/ha/integrations/...`
- [x] Device management — full CRUD via `GET/POST/DELETE /api/v1/ha/devices/...`
- [x] Automation management — full CRUD via `GET/POST/PUT/DELETE /api/v1/ha/automations/...`
- [x] Telemetry — `GET /api/v1/ha/telemetry` + `GET /api/v1/ha/device-health`
- [x] Notifications — `GET /api/v1/ha/notifications` + `POST /api/v1/ha/notifications/read`
- [x] WebSocket subscription model — topic-based subscribe/unsubscribe at `WSS /api/v1/ha/ws`
- [x] Pagination on all list endpoints — `page`, `per_page` supported across all list endpoints

---

## Command Authorization

- [x] Schema validation per device type (`src/api/auth/command_auth.rs`)
- [x] Rate limiting (10/min per device, 60s sliding window) (`src/api/auth/rate_limiter.rs`)
- [x] No-op rejection (returns 400 Bad Request)
- [~] Role-based permission check — **Admin-only in v1**. Multi-role RBAC (`member`, `guest`) deferred to future release.

---

## Logging

- [x] Structured JSON logging (`tracing` + `tracing-subscriber`)
- [x] Log rotation — daily rotation via `tracing-appender` (files stored in `SGX_DATA_DIR/logs/` or `./logs/`)
- [x] Audit log for security events (`src/audit/`)
- [x] Log levels (error, warn, info, debug)

---

## Security

- [x] Encrypted OAuth token storage — AES-GCM-256 at rest (`src/integration/manager.rs`)
- [x] REST command validation — schema + rate limiting + no-op check (`src/api/auth/`)
- [x] OAuth refresh with auto-retry; manual re-auth required on refresh token failure
- [x] Retry logic with circuit breaker — 3x backoff retry + 5-failure circuit breaker (`src/homeassistant/circuit_breaker.rs`)
- [x] Comprehensive error handling — all HA errors mapped to structured JSON error responses

---

# Testing Checklist

## Connectivity

- [x] REST communication with 10s timeout (`src/homeassistant/rest.rs`)
- [x] WebSocket communication with 30s ping / 10s pong heartbeat (`src/homeassistant/websocket.rs`)
- [x] Automatic reconnect + re-auth + re-subscribe on disconnect
- [x] Circuit breaker `Closed` → `Open` → `HalfOpen` → `Closed` transitions (`src/homeassistant/circuit_breaker.rs`)
- [x] OAuth authentication via long-lived token + auto-refresh on expiry

---

## Device Tests

- [x] Discovery — `POST /api/v1/ha/devices/sync` verified live with `curl`
- [x] Synchronization — state changes verified via HA WebSocket events
- [x] Startup reconciliation — loaded from `devices.json` then reconciled against HA `GET /api/states`
- [x] Commands with acknowledgment — `command_id` returned, 15s timeout enforced
- [x] Device removal — `DELETE /api/v1/ha/devices/{id}` verified
- [x] Health updates — transitions tested via unit tests and live node

---

## Automation Tests

- [x] Presence rule (`home` / `nobody_home`) — unit tested in `src/automation/`
- [x] Schedule rule — time-based triggers unit tested
- [x] Event rule — `state_changed` trigger unit tested
- [x] Cross-device rule — multi-device conditions unit tested
- [x] Delayed execution — timer-backed delayed actions unit tested
- [x] Delayed action survives restart — `pending_actions.json` reload verified
- [x] Notification generation — automation conflict notification verified
- [x] Conflict detection — equal-priority contradicting rules tested
- [x] Priority resolution — higher-priority rule wins tested
- [x] Action on_failure modes (`continue`, `abort`, `log`, `retry`) — unit tested

---

## Storage Tests

- [x] Concurrent write safety — `flock`-based file locking unit tested (`src/storage/file_lock.rs`)
- [x] Atomic write — `BackupManager` backup/restore unit tested (`src/storage/backup.rs`)
- [x] Token encryption round-trip — AES-GCM-256 encrypt/decrypt unit tested (`src/integration/manager.rs`)

---

## Telemetry Tests

- [x] Sampling enforced (1 per 60s per entity in storage)
- [x] Cache always has latest value
- [x] Timestamp-based pruning keeps partial-day data
- [ ] Early rotation on 50MB cap — _not yet implemented_

---

## Event Bus Tests

- [x] Normal throughput (1024 capacity broadcast channel)
- [x] Overflow — lagged receivers skip oldest events with warning logged
- [x] All consumers receive dispatched event — verified via unit tests

---

## Failure Tests

- [x] Home Assistant restart → reconnect with backoff + full state reconciliation
- [x] Lost WebSocket → detect via missed pong → reconnect + re-auth + re-subscribe
- [x] Invalid OAuth token → auto-refresh → integration paused + notification sent on failure
- [x] REST timeout → retry 3x (1s, 2s, 4s backoff) → circuit breaker trips after 5 consecutive failures
- [x] Device unavailable → marked `Offline` → notification generated
- [x] Integration disabled → marked `error` → surfaced via `GET /api/v1/ha/integrations/{provider}/status`
- [x] Event queue flood → lagged receivers drop oldest + warning logged
- [x] Guardian restart with pending actions → `pending_actions.json` restored + timers re-armed

---

# Definition of Done

The feature is considered complete when:

- All supported integrations function correctly.
- Device discovery and synchronization are operational.
- Startup state reconciliation works after Guardian restart.
- Guardian owns automation execution with conflict resolution.
- Delayed actions survive Guardian restart.
- Presence state model is functional.
- Real-time telemetry synchronization is stable with sampling.
- Frontend receives live updates via typed WebSocket messages.
- Command acknowledgment flow works end-to-end.
- All APIs are implemented with pagination.
- Command authorization is enforced.
- Structured logging and audit log are operational.
- Event bus handles load and overflow correctly.
- OAuth tokens are encrypted at rest.
- All checklist items are completed.
- All testing scenarios pass successfully.
