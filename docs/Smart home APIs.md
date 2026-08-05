Here is the complete guide for **`GET /api/v1/ha/devices`**, explaining what is needed in Home Assistant (HA) and giving `curl` examples for every parameter combination.

---

# 1. What is Needed in Home Assistant (HA)?

To make `GET /api/v1/ha/devices` populate and filter devices correctly:

1. **Home Assistant Connection (`.env`)**
   - Guardian needs `HA_URL=http://192.168.0.3:8123` and `HA_TOKEN=<long_lived_token>` in `.env`.

2. **Entities in Home Assistant**
   - Devices/entities created in HA (e.g. `input_boolean`, `light`, `switch`, `climate`, `lock`, `sensor`).
   - Home Assistant syncs these entities into Guardian's `devices.json` registry during boot or when calling `/api/v1/ha/devices/sync`.

3. **For `device_type` Filtering**
   - HA entity domains automatically determine the `device_type` (e.g., `light.living_room` $\rightarrow$ `device_type: "light"`, `input_boolean.toggle1` $\rightarrow$ `device_type: "input_boolean"`).

4. **For `room` Filtering**
   - In Home Assistant, assign entities to **Areas** under *Settings $\rightarrow$ Areas & Zones $\rightarrow$ Areas* (e.g., "Living Room", "Kitchen", "Bedroom"), or set `"room": "Living Room"` in Guardian's `devices.json`.

5. **For `search` Filtering**
   - Set **Friendly Names** in HA (e.g. `"friendly_name": "Main Hall Lamp"`). `search` searches across both `friendly_name` and `ha_entity_id`.

---

# 2. All `curl` Examples (Every Combination)

*Note: Make sure your `TOKEN` variable is set or replace `$TOKEN` with your Bearer token.*

### Combination 1: Basic Request (Default 20 per page)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices"
```

---

### Combination 2: Pagination (`page` & `per_page`)
Fetch Page 2 with 5 devices per page:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices?page=2&per_page=5"
```

---

### Combination 3: Filter by Device Type (`device_type`)
Get only thermostats, lights, switches, or input booleans:
```bash
# Get all input_boolean devices
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices?device_type=input_boolean"

# Get all light devices
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices?device_type=light"
```

---

### Combination 4: Filter by Room (`room`)
Get devices located in the "Living Room":
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices?room=Living%20Room"
```

---

### Combination 5: Search Query (`search`)
Search for any device matching "toggle" or "boolean" in its name or entity ID:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices?search=boolean"
```

---

### Combination 6: Combined `device_type` + `room`
Get only `light` devices in the `Kitchen`:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices?device_type=light&room=Kitchen"
```

---

### Combination 7: Combined `device_type` + `search`
Search for `input_boolean` devices matching search term `1`:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices?device_type=input_boolean&search=1"
```

---

### Combination 8: Full Filter (Pagination + Room + Type + Search)
Page 1, 10 items per page, `input_boolean` in `Living Room` matching `toggle`:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices?page=1&per_page=10&device_type=input_boolean&room=Living%20Room&search=toggle"
```

---

### Sample Paginated JSON Response Output

```json
{
  "items": [
    {
      "id": "dev_3806a26d469d491e886b9408236c6a84",
      "ha_entity_id": "input_boolean.1",
      "vendor": "Unknown",
      "device_type": "input_boolean",
      "room": "Living Room",
      "friendly_name": "1",
      "current_state": "off",
      "health_status": "online",
      "last_seen": "2026-07-27T11:35:52.664Z"
    }
  ],
  "total_count": 1,
  "page": 1,
  "per_page": 10,
  "total_pages": 1
}
```

Viewed docker-compose.ha.yml:1-10

Here is the complete guide for **`GET /api/v1/ha/devices/{id}`**.

---

# 1. What is Needed in Home Assistant (HA)?

To make `GET /api/v1/ha/devices/{id}` return full device details:

1. **Device Registered in Guardian**
   - The device must exist in Home Assistant and be synchronized into Guardian's `devices.json` registry.

2. **Dual ID Resolution (Guardian ID or HA Entity ID)**
   - You do **NOT** need to lookup Guardian's internal ID first. You can pass **EITHER**:
     - **Home Assistant Entity ID**: e.g., `input_boolean.1`, `light.living_room`, `climate.thermostat`
     - **Guardian Internal ID**: e.g., `dev_3806a26d469d491e886b9408236c6a84`

---

# 2. All `curl` Examples

### Example 1: Fetch Device by Home Assistant Entity ID
Query directly using HA entity ID (`input_boolean.1`):
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices/input_boolean.1"
```

---

### Example 2: Fetch Device by Guardian Internal ID
Query using Guardian's generated unique device ID (`dev_3806a26d469d491e886b9408236c6a84`):
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices/dev_3806a26d469d491e886b9408236c6a84"
```

---

### Example 3: Fetch a Light or Thermostat Device
Query a light or climate entity from Home Assistant:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices/light.living_room"
```

---

### Example 4: Non-Existent Device (404 Not Found Handling)
Querying a device ID that doesn't exist returns a clean `404 Not Found` response:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices/non_existent_device"
```

---

# 3. Expected JSON Responses

### Successful Response (`200 OK`)
```json
{
  "id": "dev_3806a26d469d491e886b9408236c6a84",
  "ha_entity_id": "input_boolean.1",
  "vendor": "Unknown",
  "device_type": "input_boolean",
  "room": "Living Room",
  "friendly_name": "1",
  "current_state": "off",
  "health_status": "online",
  "last_seen": "2026-07-27T11:35:52.664Z"
}
```

### Error Response (`404 Not Found`)
```json
{
  "error": "Device 'non_existent_device' not found"
}
```

Here is the complete guide for **`GET /api/v1/ha/devices/{id}/state`**.

---

# 1. What is Needed in Home Assistant (HA)?

To make `GET /api/v1/ha/devices/{id}/state` return accurate live state:

1. **Active WebSocket Subscription in Guardian**
   - When Guardian is running, it subscribes to Home Assistant's real-time WebSocket event stream (`state_changed`).
   - Whenever an entity state changes in HA (e.g. turning a switch on/off or adjusting a thermostat), HA pushes the state update to Guardian, updating `current_state`, `health_status`, and `last_seen`.

2. **Dual ID Resolution (Guardian ID or HA Entity ID)**
   - You can pass **EITHER**:
     - **Home Assistant Entity ID**: e.g., `input_boolean.1`, `light.living_room`, `switch.outlet`
     - **Guardian Internal ID**: e.g., `dev_3806a26d469d491e886b9408236c6a84`

---

# 2. All `curl` Examples

### Example 1: Query Live State by Home Assistant Entity ID
Query state using HA entity ID (`input_boolean.1`):
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices/input_boolean.1/state"
```

---

### Example 2: Query Live State by Guardian Internal ID
Query state using Guardian's generated unique device ID (`dev_3806a26d469d491e886b9408236c6a84`):
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices/dev_3806a26d469d491e886b9408236c6a84/state"
```

---

### Example 3: Query Live State for a Light or Smart Switch
Query live state for a light entity:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices/light.living_room/state"
```

---

### Example 4: Non-Existent Device (404 Not Found Handling)
Querying state for a non-existent device returns `404 Not Found`:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices/invalid_entity/state"
```

---

# 3. Expected JSON Responses

### Successful Response (`200 OK`)
Returns a focused state payload containing ID, entity ID, current state, health status, and ISO timestamp:
```json
{
  "id": "dev_3806a26d469d491e886b9408236c6a84",
  "ha_entity_id": "input_boolean.1",
  "current_state": "on",
  "health_status": "online",
  "last_seen": "2026-07-27T11:35:52.664Z"
}
```

### Error Response (`404 Not Found`)
```json
{
  "error": "Device 'invalid_entity' not found"
}
```
Here is the complete guide for **`POST /api/v1/ha/devices/{id}/command`**.

---

# 1. What is Needed in Home Assistant (HA)?

To make `POST /api/v1/ha/devices/{id}/command` dispatch commands to real hardware:

1. **Home Assistant REST Client (`.env`)**
   - Guardian uses Home Assistant's REST API endpoint (`POST /api/services/<domain>/<command>`) to execute device control commands.
   - `HA_URL` and `HA_TOKEN` must be set in `.env`.

2. **Command Payload Schema**
   ```json
   {
     "command": "<command_name>",
     "domain": "<optional_domain>",
     "params": { "<param_name>": <value> }
   }
   ```
   - **`command`** *(required)*: HA service to execute (`turn_on`, `turn_off`, `set_temperature`, `lock`, `unlock`, `set_hvac_mode`).
   - **`domain`** *(optional)*: HA domain (`light`, `switch`, `climate`, `lock`, `input_boolean`). If omitted, Guardian automatically extracts the domain from entity ID (e.g. `light.hall` $\rightarrow$ `light`).
   - **`params`** *(optional)*: Additional parameters (e.g. brightness, temperature, HVAC mode).

3. **Dual ID Resolution (Guardian ID or HA Entity ID)**
   - You can pass **EITHER** HA entity ID (`input_boolean.1`) **OR** Guardian internal ID (`dev_3806a26d469d491e886b9408236c6a84`).

---

# 2. All `curl` Examples

### Example 1: Turn On an `input_boolean` or `switch`
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_off",
    "domain": "switch"
  }'
```

---

### Example 2: Turn Off a Light (Domain Auto-Detected)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/light.living_room/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_off"
  }'
```

---

### Example 3: Set Light Brightness (With `params`)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/light.living_room/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "params": {
      "brightness": 180
    }
  }'
```

---

### Example 4: Set Thermostat Temperature (`climate`)
Set target temperature to 22.5°C on a Nest or Ecobee thermostat:
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/climate.living_room/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "set_temperature",
    "domain": "climate",
    "params": {
      "temperature": 22.5
    }
  }'
```

---

### Example 5: Lock a Smart Door Lock (`lock`)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/lock.front_door/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "lock",
    "domain": "lock"
  }'
```

---

### Example 6: Target Device by Guardian Internal ID
Using Guardian's unique generated device ID (`dev_3806a26d469d491e886b9408236c6a84`):
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/dev_3806a26d469d491e886b9408236c6a84/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_off"
  }'
```

---

# 3. Expected JSON Responses

### Successful Response (`200 OK`)
Returns `status: pending`, a generated `command_id`, and confirmation message:
```json
{
  "status": "pending",
  "command_id": "cmd_a8f9c73d12044e99",
  "message": "Command 'turn_on' dispatched to 1"
}
```

### Error Response (`404 Not Found`)
```json
{
  "error": "Device 'input_boolean.invalid' not found"
}
```

Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/devices/light.living_room/command -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "command": "turn_off"
  }'`
Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/devices/light.bed_light/command -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "command": "turn_off"
  }'`
Ran command: `clear`
Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/devices/light.bed_light/command   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{
    "command": "turn_off"
  }'`
Ran command: `
hp@DESKTOP-V2D24I2:~/SGX$ curl -k -X POST https://localhost:8443/api/v1/ha/devices/light.bed_light/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "params": {
      "brightness": 180
    }
  }'`

Here is the complete guide for **`POST /api/v1/ha/devices/sync`**.

---

# 1. What Does This API Do?

`POST /api/v1/ha/devices/sync` forces Guardian to connect to Home Assistant's REST API (`GET /api/states`), discover any new entities added to Home Assistant, update all device states in `devices.json`, and reconcile live state across all nodes.

### When to Use It?
- After adding a new light, switch, thermostat, or sensor in Home Assistant.
- To immediately refresh all device states in Guardian's registry.

---

# 2. Plain HTTPS API Specification

- **URL**: `https://localhost:8443/api/v1/ha/devices/sync`
- **HTTP Method**: `POST`
- **Headers**:
  - `Authorization: Bearer <your_token>`
- **Request Body**: None (Empty)

---

# 3. `curl` Example

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/sync \
  -H "Authorization: Bearer $TOKEN"
```

---

# 4. Expected Response JSON Payload

### Success Response (`200 OK`)
```json
{
  "status": "synced",
  "total_devices": 3,
  "message": "Successfully reconciled 3 devices with Home Assistant"
}
```

Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/devices/sync -H "Authorization: Bearer $TOKEN"`

Here is the complete guide with `curl` commands for **`GET /api/v1/ha/automations`**.

---

# 1. What Does This API Do?

`GET /api/v1/ha/automations` retrieves a paginated list of all automation rules stored in Guardian's engine (`automations.json`), showing rule triggers, conditions, actions, priority, and enabled/disabled status.

---

# 2. `curl` Command Examples

### Example 1: Basic Request (Default Page 1, 20 rules per page)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/automations"
```

---

### Example 2: Custom Pagination (Page 1, 5 rules per page)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/automations?page=1&per_page=5"
```

---

### Example 3: Fetch Page 2 (10 rules per page)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/automations?page=2&per_page=10"
```

---

# 3. Expected JSON Response Payload (`200 OK`)

```json
{
  "items": [
    {
      "id": "rule_sync_toggles",
      "name": "Sync Toggle 1 to Toggle 2",
      "priority": 100,
      "enabled": true,
      "trigger": {
        "type": "state_changed",
        "entity_id": "input_boolean.1",
        "to_state": null
      },
      "conditions": [],
      "actions": [
        {
          "type": "command",
          "entity_id": "input_boolean.2",
          "domain": "input_boolean",
          "command": "turn_on",
          "service_data": null,
          "on_failure": "continue"
        }
      ]
    }
  ],
  "total_count": 1,
  "page": 1,
  "per_page": 20,
  "total_pages": 1
}
```

Here is the complete guide for **`POST /api/v1/ha/automations`**.

---

# 1. What Does This API Do?

`POST /api/v1/ha/automations` creates a new automation rule, activates it immediately in Guardian's real-time event loop, and persists it into `automations.json`.

---

# 2. Automation Rule JSON Schema

```json
{
  "id": "rule_unique_id",
  "name": "Human Readable Rule Name",
  "priority": 100,
  "enabled": true,
  "trigger": {
    "type": "state_changed",
    "entity_id": "binary_sensor.motion_sensor",
    "to_state": "on"
  },
  "conditions": [],
  "actions": [
    {
      "type": "command",
      "entity_id": "light.living_room",
      "domain": "light",
      "command": "turn_on",
      "service_data": {
        "brightness": 255
      },
      "on_failure": "continue"
    }
  ]
}
```

---

# 3. `curl` Command Examples

### Example 1: Create a Toggle Sync Rule
Automatically turns on `input_boolean.2` when `input_boolean.1` changes to `"on"`:

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/automations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "rule_sync_toggles_01",
    "name": "Sync Toggle 1 to Toggle 2",
    "priority": 100,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "input_boolean.1",
      "to_state": "on"
    },
    "conditions": [],
    "actions": [
      {
        "type": "command",
        "entity_id": "input_boolean.2",
        "domain": "input_boolean",
        "command": "turn_on"
      }
    ]
  }'
```

---

### Example 2: Create a Motion Lighting Rule (Light Brightness Action)
Automatically turns on `light.bed_light` at 75% brightness when `binary_sensor.motion` turns `"on"`:

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/automations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "rule_motion_bed_light",
    "name": "Motion Bed Light",
    "priority": 50,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "binary_sensor.motion",
      "to_state": "on"
    },
    "conditions": [],
    "actions": [
      {
        "type": "command",
        "entity_id": "light.bed_light",
        "domain": "light",
        "command": "turn_on",
        "service_data": {
          "brightness": 190
        }
      }
    ]
  }'
```

---

# 4. Expected Response JSON Payload

### Success Response (`201 Created`)
```json
{
  "status": "created",
  "rule_id": "rule_sync_toggles_01",
  "message": "Automation rule 'Sync Toggle 1 to Toggle 2' created successfully"
}
```

### Error Response (`400 Bad Request`)
If the JSON payload contains invalid syntax or missing required fields:
```json
{
  "error": "Failed to parse automation rule: missing field `trigger`"
}
```

Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/automations -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "id": "rule_sync_toggles_01",
    "name": "Sync Toggle 1 to Toggle 2",
    "priority": 100,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "input_boolean.1",
      "to_state": "on"
    },
    "conditions": [],
    "actions": [
      {
        "type": "command",
        "entity_id": "input_boolean.2",
        "domain": "input_boolean",
        "command": "turn_on"
      }
    ]
  }'`
Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/automations -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "id": "rule_motion_bed_light",
    "name": "Motion Bed Light",
    "priority": 50,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "binary_sensor.motion",
      "to_state": "on"
    },
    "conditions": [],
    "actions": [
      {
        "type": "command",
        "entity_id": "light.bed_light",
        "domain": "light",
        "command": "turn_on",
        "service_data": {
          "brightness": 190
        }
      }
    ]
  }'`
Ran command: `clear`

Here is the complete guide for **`PUT /api/v1/ha/automations/{id}`**.

---

# 1. What Does This API Do?

`PUT /api/v1/ha/automations/{id}` updates an existing automation rule matching `{id}` with new triggers, actions, conditions, priority, or name. Guardian updates the rule live in the engine event loop and persists it to `automations.json`.

---

# 2. `curl` Command Examples

### Example 1: Update Rule Action Command (Change `turn_on` to `turn_off`)
Update `rule_sync_toggles_01` so that when `input_boolean.1` turns `"on"`, `input_boolean.2` turns `"off"`:

```bash
curl -k -X PUT https://localhost:8443/api/v1/ha/automations/rule_sync_toggles_01 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "rule_sync_toggles_01",
    "name": "Sync Toggle 1 to Turn Off Toggle 2",
    "priority": 100,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "input_boolean.1",
      "to_state": "on"
    },
    "conditions": [],
    "actions": [
      {
        "type": "command",
        "entity_id": "input_boolean.2",
        "domain": "input_boolean",
        "command": "turn_off"
      }
    ]
  }'
```

---

### Example 2: Update Light Brightness & Priority
Update `rule_motion_bed_light` brightness parameter to 255 (100% full brightness) and increase priority to 80:

```bash
curl -k -X PUT https://localhost:8443/api/v1/ha/automations/rule_motion_bed_light \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "rule_motion_bed_light",
    "name": "Max Brightness Motion Light",
    "priority": 80,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "binary_sensor.motion",
      "to_state": "on"
    },
    "conditions": [],
    "actions": [
      {
        "type": "command",
        "entity_id": "light.bed_light",
        "domain": "light",
        "command": "turn_on",
        "service_data": {
          "brightness": 255
        }
      }
    ]
  }'
```

---

### Example 3: Non-Existent Rule (404 Not Found Handling)
Attempting to update a rule ID that does not exist returns `404 Not Found`:

```bash
curl -k -X PUT https://localhost:8443/api/v1/ha/automations/non_existent_rule \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "non_existent_rule",
    "name": "Invalid Rule",
    "priority": 10,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "input_boolean.1",
      "to_state": "on"
    },
    "conditions": [],
    "actions": []
  }'
```

---

# 3. Expected Response JSON Payload

### Success Response (`200 OK`)
```json
{
  "status": "updated",
  "rule_id": "rule_sync_toggles_01",
  "message": "Automation rule 'Sync Toggle 1 to Turn Off Toggle 2' updated successfully"
}
```

### Error Response (`404 Not Found`)
```json
{
  "error": "Rule with ID 'non_existent_rule' not found"
}
```

Ran command: `curl -k -X PUT https://localhost:8443/api/v1/ha/automations/rule_sync_toggles_01 -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "id": "rule_sync_toggles_01",
    "name": "Sync Toggle 1 to Turn Off Toggle 2",
    "priority": 100,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "input_boolean.1",
      "to_state": "on"
    },
    "conditions": [],
    "actions": [
      {
        "type": "command",
        "entity_id": "input_boolean.2",
        "domain": "input_boolean",
        "command": "turn_off"
      }
    ]
  }'`
Ran command: `curl -k -X PUT https://localhost:8443/api/v1/ha/automations/rule_motion_bed_light -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "id": "rule_motion_bed_light",
    "name": "Max Brightness Motion Light",
    "priority": 80,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "binary_sensor.motion",
      "to_state": "on"
    },
    "conditions": [],
    "actions": [
      {
        "type": "command",
        "entity_id": "light.bed_light",
        "domain": "light",
        "command": "turn_on",
        "service_data": {
          "brightness": 255
        }
      }
    ]
  }'`
Ran command: `curl -k -X PUT https://localhost:8443/api/v1/ha/automations/non_existent_rule -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "id": "non_existent_rule",
    "name": "Invalid Rule",
    "priority": 10,
    "enabled": true,
    "trigger": {
      "type": "state_changed",
      "entity_id": "input_boolean.1",
      "to_state": "on"
    },
    "conditions": [],
    "actions": []
  }'`

Here is the complete guide for **`DELETE /api/v1/ha/automations/{id}`**.

---

# 1. What Does This API Do?

`DELETE /api/v1/ha/automations/{id}` deletes an automation rule matching `{id}`. Guardian immediately stops evaluating triggers for this rule and updates `automations.json`.

---

# 2. `curl` Command Examples

### Example 1: Delete `rule_sync_toggles_01`
```bash
curl -k -X DELETE https://localhost:8443/api/v1/ha/automations/rule_sync_toggles_01 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Example 2: Delete `rule_motion_bed_light`
```bash
curl -k -X DELETE https://localhost:8443/api/v1/ha/automations/rule_motion_bed_light \
  -H "Authorization: Bearer $TOKEN"
```

---

### Example 3: Non-Existent Rule (404 Not Found Handling)
Attempting to delete a rule ID that does not exist returns `404 Not Found`:

```bash
curl -k -X DELETE https://localhost:8443/api/v1/ha/automations/non_existent_rule \
  -H "Authorization: Bearer $TOKEN"
```

---

# 3. Expected Response JSON Payload

### Success Response (`200 OK`)
```json
{
  "status": "deleted",
  "rule_id": "rule_sync_toggles_01",
  "message": "Automation rule 'rule_sync_toggles_01' deleted successfully"
}
```

### Error Response (`404 Not Found`)
```json
{
  "error": "Rule with ID 'non_existent_rule' not found"
}
```

Here is the complete guide for **`POST /api/v1/ha/automations/{id}/enable`**.

---

# 1. What Does This API Do?

`POST /api/v1/ha/automations/{id}/enable` toggles an automation rule's `enabled` state to `true` in real time and persists it to `automations.json`. Guardian immediately resumes evaluating triggers and executing actions for this rule.

---

# 2. `curl` Command Examples

### Example 1: Enable Automation Rule (`rule_sync_toggles_01`)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/automations/rule_sync_toggles_01/enable \
  -H "Authorization: Bearer $TOKEN"
```

---

### Example 2: Non-Existent Rule (404 Not Found Handling)
Attempting to enable a rule ID that does not exist returns `404 Not Found`:

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/automations/non_existent_rule/enable \
  -H "Authorization: Bearer $TOKEN"
```

---

# 3. Expected Response JSON Payload

### Success Response (`200 OK`)
```json
{
  "status": "enabled",
  "rule_id": "rule_sync_toggles_01",
  "message": "Automation rule 'rule_sync_toggles_01' enabled"
}
```

### Error Response (`404 Not Found`)
```json
{
  "error": "Rule with ID 'non_existent_rule' not found"
}
```

Here is the complete guide for **`POST /api/v1/ha/automations/{id}/disable`**.

---

# 1. What Does This API Do?

`POST /api/v1/ha/automations/{id}/disable` toggles an automation rule's `enabled` state to `false` in real time without deleting the rule schema, and persists `enabled: false` to `automations.json`. Guardian stops evaluating triggers for this rule until it is re-enabled.

---

# 2. `curl` Command Examples

### Example 1: Disable Automation Rule (`rule_sync_toggles_01`)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/automations/rule_sync_toggles_01/disable \
  -H "Authorization: Bearer $TOKEN"
```

---

### Example 2: Non-Existent Rule (404 Not Found Handling)
Attempting to disable a rule ID that does not exist returns `404 Not Found`:

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/automations/non_existent_rule/disable \
  -H "Authorization: Bearer $TOKEN"
```

---

# 3. Expected Response JSON Payload

### Success Response (`200 OK`)
```json
{
  "status": "disabled",
  "rule_id": "rule_sync_toggles_01",
  "message": "Automation rule 'rule_sync_toggles_01' disabled"
}
```

### Error Response (`404 Not Found`)
```json
{
  "error": "Rule with ID 'non_existent_rule' not found"
}
```

Here is the complete guide for **`GET /api/v1/ha/telemetry`**.

---

# 1. What Does This API Do?

`GET /api/v1/ha/telemetry` returns paginated telemetry event logs (such as entity state changes, sensor readings, and reconciliation events) recorded by Guardian's Telemetry Collector. Logs are returned **newest-first**.

---

# 2. Supported Query Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| **`page`** | `integer` | `1` | Page number to retrieve. |
| **`per_page`** | `integer` | `50` | Number of telemetry records per page (clamped 1–200). |
| **`device_id`** | `string` | `none` | Filter logs by Home Assistant entity ID (e.g. `input_boolean.1`). |
| **`from`** | `ISO string` | `none` | Filter start timestamp (e.g. `2026-07-27T00:00:00Z`). |
| **`to`** | `ISO string` | `none` | Filter end timestamp (e.g. `2026-07-27T23:59:59Z`). |

---

# 3. `curl` Command Examples

### Example 1: Basic Request (Default 50 items per page)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry"
```

---

### Example 2: Custom Pagination (Page 1, 10 items per page)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry?page=1&per_page=10"
```

---

### Example 3: Filter Telemetry for a Specific Entity (`input_boolean.1`)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry?device_id=input_boolean.1&page=1&per_page=10"
```

---

# 4. Expected Response JSON Payload (`200 OK`)

```json
{
  "items": [
    {
      "entity_id": "input_boolean.1",
      "state": "on",
      "attributes": {
        "friendly_name": "1"
      },
      "timestamp": "2026-07-27T14:48:55Z"
    },
    {
      "entity_id": "light.bed_light",
      "state": "off",
      "attributes": {
        "friendly_name": "Bed Light"
      },
      "timestamp": "2026-07-27T14:35:10Z"
    }
  ],
  "total_count": 2,
  "page": 1,
  "per_page": 50,
  "total_pages": 1
}
```

Ran command: `curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:8443/api/v1/ha/telemetry"`
Ran command: `
hp@DESKTOP-V2D24I2:~/SGX$
hp@DESKTOP-V2D24I2:~/SGX$ curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry?page=1&per_page=10"`
Ran command: `curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:8443/api/v1/ha/telemetry?device_id=input_boolean.1&page=1&per_page=10"`
Ran command: `
hp@DESKTOP-V2D24I2:~/SGX$ clear`

Here is the complete guide for **`GET /api/v1/ha/telemetry/{device_id}`**.

---

# 1. What Does This API Do?

`GET /api/v1/ha/telemetry/{device_id}` returns a paginated list of telemetry event logs specifically recorded for `{device_id}` (e.g. state transitions, timestamped events, and attribute updates). Logs are returned **newest-first**.

---

# 2. Supported Path & Query Parameters

- **`{device_id}`** *(path parameter)*: Home Assistant entity ID (e.g. `input_boolean.1`, `light.bed_light`, `sensor.total_energy_kwh`).
- **`page`** *(query parameter)*: Page number to retrieve (default: `1`).
- **`per_page`** *(query parameter)*: Number of logs per page (default: `50`, max `200`).

---

# 3. `curl` Command Examples

### Example 1: Fetch Telemetry for `input_boolean.1`
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry/input_boolean.1"
```

---

### Example 2: Custom Pagination for `input_boolean.1` (Page 1, 10 items per page)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry/input_boolean.1?page=1&per_page=10"
```

---

### Example 3: Fetch Telemetry for a Light Device (`light.bed_light`)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry/light.bed_light?page=1&per_page=10"
```

---

### Example 4: Fetch Telemetry for a Sensor Device (`sensor.total_energy_kwh`)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry/sensor.total_energy_kwh?page=1&per_page=10"
```

---

# 4. Expected Response JSON Payload (`200 OK`)

```json
{
  "items": [
    {
      "entity_id": "input_boolean.1",
      "state": "on",
      "attributes": {
        "editable": true,
        "friendly_name": "1"
      },
      "timestamp": "2026-07-27T17:30:41.674657394+05:00"
    },
    {
      "entity_id": "input_boolean.1",
      "state": "off",
      "attributes": {
        "editable": true,
        "friendly_name": "1"
      },
      "timestamp": "2026-07-27T17:26:11.963242250+05:00"
    }
  ],
  "total_count": 5,
  "page": 1,
  "per_page": 10,
  "total_pages": 1
}
```

Ran command: `curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry/input_boolean.1"`
Ran command: `curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:8443/api/v1/ha/telemetry/input_boolean.1?page=1&per_page=10"`
Ran command: `curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:8443/api/v1/ha/telemetry/light.bed_light?page=1&per_page=10"`
Ran command: `
hp@DESKTOP-V2D24I2:~/SGX$ curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry/sensor.total_energy_kwh?page=1&per_page=10"`

Here is the complete guide for **`GET /api/v1/ha/device-health`**.

---

# 1. What Does This API Do?

`GET /api/v1/ha/device-health` returns a real-time aggregate health metrics report across all registered smart home devices in Guardian, calculating total devices, online devices, offline/error devices, and overall system health percentage.

---

# 2. `curl` Command Example

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/device-health"
```

---

# 3. Expected Response JSON Payload (`200 OK`)

```json
{
  "total_devices": 55,
  "online_devices": 54,
  "offline_devices": 1,
  "error_devices": 0,
  "healthy_percentage": 98.18
}
```

---

# 4. JSON Response Field Explanations

| Field | Type | Description |
| :--- | :--- | :--- |
| **`total_devices`** | `integer` | Total number of registered devices in Guardian's registry. |
| **`online_devices`** | `integer` | Count of active, responding devices (`health_status: "online"`). |
| **`offline_devices`** | `integer` | Count of unreachable devices (`health_status: "offline"`). |
| **`error_devices`** | `integer` | Count of devices in error or authentication failure state. |
| **`healthy_percentage`** | `float` | Percentage of online vs total devices (`(online_devices / total_devices) * 100`). |

Ran command: `curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/telemetry/input_boolean.1"`
Ran command: `clear`
Ran command: `curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/device-health"`

Here is the complete guide for **`GET /api/v1/ha/notifications`**.

---

# 1. What Does This API Do?

`GET /api/v1/ha/notifications` returns a paginated list of system alerts and event notifications (e.g., device offline alerts, automation failures, token expiration warnings, or security events) stored in Guardian.

---

# 2. Supported Query Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| **`page`** | `integer` | `1` | Page number to retrieve. |
| **`per_page`** | `integer` | `20` | Notifications per page (clamped 1–200). |
| **`unread`** | `boolean` | `none` | If set to `true`, returns only unread notifications. |
| **`severity`** | `string` | `none` | Filter by severity (`info`, `warning`, `critical`). |

---

# 3. `curl` Command Examples

### Example 1: List All Notifications (Default Page 1, 20 items per page)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications"
```

---

### Example 2: List Unread Notifications Only (`unread=true`)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications?unread=true"
```

---

### Example 3: Filter Notifications by Severity (`severity=warning`)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications?severity=warning"
```

---

### Example 4: Full Combination (Unread Critical Notifications)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications?unread=true&severity=critical&page=1&per_page=10"
```

---

# 4. Expected Response JSON Payload (`200 OK`)

```json
{
  "items": [
    {
      "id": "notif_01j001",
      "title": "Device Offline Alert",
      "message": "Device 'input_button.3' went offline",
      "severity": "warning",
      "read": false,
      "created_at": "2026-07-27T11:28:18Z"
    }
  ],
  "total_count": 1,
  "page": 1,
  "per_page": 20,
  "total_pages": 1
}
```

Ran command: `curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications"`
Ran command: `curl -k -H "curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications?unread=true"`
Ran command: `curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:8443/api/v1/ha/notifications?severity=warning"`
Ran command: `curl -k -H "Authorization: Bearer $TOKEN" curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications?unread=true&severity=critical&page=1&per_page=10"`
Ran command: `clear`

Here is the complete guide for **`POST /api/v1/ha/notifications/read`**.

---

# 1. What Does This API Do?

`POST /api/v1/ha/notifications/read` marks a batch of notifications (by their IDs) as `read: true` in Guardian's notification store. Once marked read, they will no longer appear when filtering for unread notifications (`unread=true`).

---

# 2. Request JSON Schema

```json
{
  "notification_ids": [
    "notif_001",
    "notif_002"
  ]
}
```

---

# 3. `curl` Command Example

Mark notifications `notif_001` and `notif_002` as read:

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/notifications/read \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "notification_ids": ["notif_001", "notif_002"]
  }'
```

---

# 4. Expected Response JSON Payload (`200 OK`)

```json
{
  "status": "success",
  "marked_read_count": 2,
  "message": "Marked 2 notification(s) as read"
}
```

Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/notifications/read -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "notification_ids": ["notif_001", "notif_002"]
  }'`
Ran command: `
hp@DESKTOP-V2D24I2:~/SGX$ curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications?unread=true"`
Ran command: `clea`
Ran command: `clear`

Here is the complete guide for **`GET /api/v1/ha/integrations`**.

---

# 1. What Does This API Do?

`GET /api/v1/ha/integrations` returns a high-level summary of all vendor integration providers configured in Guardian (**Google Nest**, **Ecobee**, and **TP-Link Kasa**), showing their connection status, stored credential flags, device counts, and last sync timestamps.

---

# 2. `curl` Command Example

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations"
```

---

# 3. Expected Response JSON Payload (`200 OK`)

```json
{
  "providers": {
    "ecobee": {
      "name": "Ecobee Thermostats",
      "status": "disconnected",
      "has_credentials": false,
      "device_count": 0,
      "last_synced": null,
      "error_message": null
    },
    "google_nest": {
      "name": "Google Nest",
      "status": "disconnected",
      "has_credentials": false,
      "device_count": 0,
      "last_synced": null,
      "error_message": null
    },
    "tp_link_kasa": {
      "name": "TP-Link Kasa Smart Home",
      "status": "disconnected",
      "has_credentials": false,
      "device_count": 0,
      "last_synced": null,
      "error_message": null
    }
  },
  "total_integrations": 3
}
```

---

# 4. JSON Response Field Explanations

| Field | Type | Description |
| :--- | :--- | :--- |
| **`status`** | `string` | `"connected"` or `"disconnected"`. |
| **`has_credentials`** | `boolean` | `true` if encrypted OAuth tokens are stored in `integrations.json`. |
| **`device_count`** | `integer` | Number of active smart devices synced from this vendor. |
| **`last_synced`** | `string / null` | ISO timestamp of the last successful token refresh or data sync. |
| **`error_message`** | `string / null` | Error description if OAuth authentication or refresh failed. |

Ran command: `curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations"`

Here is the complete guide for **`GET /api/v1/ha/integrations/{provider}/status`**.

---

# 1. What Does This API Do?

`GET /api/v1/ha/integrations/{provider}/status` returns detailed connection status, credential status, linked device count, and error messages for a specific vendor provider specified in `{provider}`.

---

# 2. Supported Vendor Providers

- **`google_nest`**: Google Nest Smart Thermostats & Cameras.
- **`ecobee`**: Ecobee Smart Thermostats & Sensors.
- **`tp_link_kasa`**: TP-Link Kasa Smart Plugs, Switches & Bulbs.

---

# 3. `curl` Command Examples

### Example 1: Check Google Nest Status
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations/google_nest/status"
```

---

### Example 2: Check Ecobee Status
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations/ecobee/status"
```

---

### Example 3: Check TP-Link Kasa Status
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/status"
```

---

### Example 4: Invalid Provider (404 Not Found Handling)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations/unknown_vendor/status"
```

---

# 4. Expected Response JSON Payload

### Success Response (`200 OK`)
```json
{
  "name": "Google Nest",
  "provider": "google_nest",
  "status": "disconnected",
  "has_credentials": false,
  "device_count": 0,
  "last_synced": null,
  "error_message": null
}
```

### Error Response (`404 Not Found`)
```json
{
  "error": "Integration provider 'unknown_vendor' not found"
}
```

Ran command: `curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations/google_nest/status"`
Ran command: `curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/status"`

**Yes! It is 100% ready to use.**

When you submit OAuth credentials via `POST /api/v1/ha/integrations/{provider}/connect`:
1. Guardian encrypts the access and refresh tokens using AES-GCM-256 (`src/integration/crypto.rs`).
2. Persists the encrypted tokens securely to disk (`integrations.json` / `integrations.lock`).
3. Updates the provider's status live to `"connected"` and sets `has_credentials: true`.
4. Activates Guardian's background Token Refresh Worker to automatically maintain OAuth session health.

---

# 📖 Complete Guide for `POST /api/v1/ha/integrations/{provider}/connect`

### Supported Providers (`{provider}`)
- `google_nest`
- `ecobee`
- `tp_link_kasa`

---

# 1. Request JSON Schema

```json
{
  "access_token": "your_oauth_access_token_string",
  "refresh_token": "your_oauth_refresh_token_string",
  "expires_in_secs": 3600
}
```

---

# 2. `curl` Command Examples

### Example 1: Connect Google Nest
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/google_nest/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "nest_access_token_demo_987654321",
    "refresh_token": "nest_refresh_token_demo_123456789",
    "expires_in_secs": 3600
  }'
```

*Response*:
```json
{
  "message": "Successfully connected provider 'google_nest'",
  "provider": "google_nest",
  "status": "connected"
}
```

---

### Example 2: Connect Ecobee
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/ecobee/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "ecobee_access_token_demo_11223344",
    "refresh_token": "ecobee_refresh_token_demo_55667788",
    "expires_in_secs": 3600
  }'
```

---

### Example 3: Connect TP-Link Kasa
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "kasa_access_token_demo_998877",
    "refresh_token": "kasa_refresh_token_demo_665544",
    "expires_in_secs": 7200
  }'
```

---

# 3. Verify Connection Status

After connecting a provider, verify its status with `GET`:

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations/google_nest/status"
```

*Response Output*:
```json
{
  "device_count": 0,
  "error_message": null,
  "has_credentials": true,
  "last_synced": "2026-07-27T20:12:30.123Z",
  "name": "Google Nest",
  "provider": "google_nest",
  "status": "connected"
}
```

Ran command: `
hp@DESKTOP-V2D24I2:~/SGX$ clear`
Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/integrations/google_nest/connect -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "access_token": "nest_access_token_demo_987654321",
    "refresh_token": "nest_refresh_token_demo_123456789",
    "expires_in_secs": 3600
  }'`
Ran command: `url -k -H "Authorization: Bearer $TOKEN" \\
  "https://localhost:8443/api/v1/ha/integrations/google_nest/status"`

Here is the complete guide for **`POST /api/v1/ha/integrations/{provider}/disconnect`**.

---

# 1. What Does This API Do?

`POST /api/v1/ha/integrations/{provider}/disconnect` disconnects a vendor provider, safely wipes stored encrypted OAuth tokens (`access_token` and `refresh_token`) from memory and disk (`integrations.json`), and resets the provider's status to `"disconnected"` with `has_credentials: false`.

---

# 2. `curl` Command Examples

### Example 1: Disconnect Google Nest
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/google_nest/disconnect \
  -H "Authorization: Bearer $TOKEN"
```

*Response*:
```json
{
  "message": "Successfully disconnected integration for Google Nest",
  "provider": "google_nest",
  "status": "disconnected"
}
```

---

### Example 2: Disconnect Ecobee
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/ecobee/disconnect \
  -H "Authorization: Bearer $TOKEN"
```

---

### Example 3: Disconnect TP-Link Kasa
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/disconnect \
  -H "Authorization: Bearer $TOKEN"
```

---

# 3. Verify Disconnection Status

After disconnecting, verify that credentials have been wiped:

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/integrations/google_nest/status"
```

*Expected Output*:
```json
{
  "device_count": 0,
  "error_message": null,
  "has_credentials": false,
  "last_synced": null,
  "name": "Google Nest",
  "provider": "google_nest",
  "status": "disconnected"
}
```

Ran command: `curl -k -X POST https://localhost:8443/api/v1/ha/integrations/google_nest/disconnect \
  -H "Authorization: Bearer $TOKEN"`
Ran command: ` -H "Authorization: Bearer $TOKEN" \OKEN" \
  "https://localhost:8443/api/v1/ha/integrations/google_nest/status"`

Here is the complete guide for the Real-Time WebSocket API: **`WSS /api/v1/ha/ws`**.

---

# 1. What Does This WebSocket API Do?

`wss://localhost:8443/api/v1/ha/ws` provides a high-performance, full-duplex persistent WebSocket connection. Frontend applications (dashboards, mobile apps) subscribe to event topics to receive **instant, zero-latency push updates** whenever:
- A device state changes in Home Assistant (e.g. lights turned on/off, temperature adjusted).
- An automation rule fires or fails.
- A system alert notification is created.

---

# 2. WebSocket Protocol & Message Actions

### 2.1 Subscribe to Event Topics
Send a JSON text message after connecting:
```json
{
  "action": "subscribe",
  "topic": "device_events"
}
```

**Supported Topics**:
- **`device_events`**: Real-time device state changes.
- **`telemetry_stream`**: Continuous telemetry logs stream.
- **`notifications`**: Live system alerts and notifications.
- **`rule_triggers`**: Automation rule execution events.
- **`all`**: Subscribe to all system events.

---

### 2.2 Unsubscribe from Topics
```json
{
  "action": "unsubscribe",
  "topic": "device_events"
}
```

---

### 2.3 Ping / Keepalive
```json
{
  "action": "ping"
}
```
*Server Response*: `{"event": "pong"}`

---

# 3. How to Test (2 Easy Methods)

### Method 1: Using Browser Console (Developer Tools F12)

Open Chrome/Firefox, navigate to `https://localhost:8443`, open **F12 $\rightarrow$ Console tab**, and paste this snippet:

```javascript
const ws = new WebSocket('wss://localhost:8443/api/v1/ha/ws');

ws.onopen = () => {
  console.log('✅ WebSocket Connected!');
  // Subscribe to device events & notifications
  ws.send(JSON.stringify({ action: 'subscribe', topic: 'device_events' }));
  ws.send(JSON.stringify({ action: 'subscribe', topic: 'notifications' }));
};

ws.onmessage = (event) => {
  console.log('📡 Live Push Received:', JSON.parse(event.data));
};

ws.onclose = () => {
  console.log('❌ WebSocket Disconnected');
};
```

---

### Method 2: Using `websocat` CLI

If you have `websocat` installed in your Linux terminal:

```bash
websocat -k wss://localhost:8443/api/v1/ha/ws
```

Then type and press Enter to subscribe:
```json
{"action": "subscribe", "topic": "device_events"}
```

---

# 4. Live Broadcast Event Output Examples

When a device state changes in Home Assistant (e.g., toggling `input_boolean.1`), Guardian instantly pushes this JSON message to all subscribed WebSocket clients:

```json
{
  "topic": "device_events",
  "event": "state_changed",
  "data": {
    "entity_id": "input_boolean.1",
    "new_state": "on",
    "old_state": "off",
    "timestamp": "2026-07-27T15:14:00Z"
  }
}
```
## Phase 8

## 🧪 How to Test Phase 8 Features

### 1. Test No-Op Command Rejection (`400 Bad Request`)
Try sending `turn_on` to `input_boolean.1` when it is already `"on"`:

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/input_boolean.1/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "domain": "input_boolean"
  }'
```

*Expected Output*:
```json
{
  "error": "No-op command: Device is already on"
}
```

---

### 2. Test Invalid Parameter Bounds (`400 Bad Request`)
Try setting brightness to `999` (exceeding max 255):

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/devices/light.bed_light/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "params": {
      "brightness": 999
    }
  }'
```

*Expected Output*:
```json
{
  "error": "Invalid schema: Invalid brightness 999: must be between 0 and 255"
}
```

---

### 3. Test Per-Device Rate Limiting (`429 Too Many Requests`)
Execute 11 rapid commands to the same device within 60 seconds. On the 11th request:

*Expected Output*:
```json
{
  "error": "Rate limit exceeded: Rate limit exceeded for device 'dev_...'. Max 10 commands per minute."
}
```
## Phase 9

## 🧪 How to Test Phase 9 Features

### 1. Query Notifications API (`GET`)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/notifications?unread=true"
```

*Expected Output*:
```json
{
  "items": [
    {
      "id": "notif_boot_001",
      "title": "System Booted",
      "message": "SGX Guardian Node A initialized successfully.",
      "severity": "info",
      "read": false,
      "created_at": "2026-07-28T05:17:42Z"
    }
  ],
  "page": 1,
  "per_page": 20,
  "total_count": 1,
  "total_pages": 1
}
```

---

### 2. Mark Notification as Read (`POST`)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/notifications/read \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "notification_ids": ["notif_boot_001"]
  }'
```

*Expected Output*:
```json
{
  "status": "success",
  "marked_read_count": 1,
  "message": "Marked 1 notification(s) as read"
}
```

---

### 3. Test Real-Time WebSocket Push
Connect to `wss://localhost:8443/api/v1/ha/ws` in Chrome/Firefox F12 console and subscribe:
```javascript
const ws = new WebSocket('wss://localhost:8443/api/v1/ha/ws');
ws.onopen = () => {
  ws.send(JSON.stringify({ action: 'subscribe', topic: 'notifications' }));
};
ws.onmessage = (e) => console.log('📡 Push Received:', JSON.parse(e.data));
```
When a system event occurs, a live push JSON payload arrives instantly!

# Walkthrough — TP-Link Kasa Integration (Phase 1: Credential Storage & Validation)

## 🧪 How to Test Phase 1 Features

### 1. Test Cloud Mode Missing Credentials (`400 Bad Request`)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "cloud",
    "username": "user@kasa.com"
  }'
```

*Expected Response*:
```json
{
  "error": "Username and password are required for cloud mode"
}
```

---

### 2. Test Valid Cloud Mode Connect (`200 OK`)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "cloud",
    "username": "user@kasa.com",
    "password": "secret_kasa_password"
  }'
```

*Expected Response*:
```json
{
  "status": "connected",
  "provider": "tp_link_kasa",
  "mode": "cloud",
  "message": "Successfully connected integration for TP-Link Kasa Smart Home"
}
```

---

### 3. Test Local Mode Connect (`200 OK`)
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "local"
  }'
```

*Expected Response*:
```json
{
  "status": "connected",
  "provider": "tp_link_kasa",
  "mode": "local",
  "message": "Successfully connected integration for TP-Link Kasa Smart Home"
}
```

---

### 4. Query Kasa Status Endpoint (`GET`)
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/status
```

*Expected Response*:
```json
{
  "device_count": 0,
  "error_message": null,
  "has_credentials": true,
  "last_synced": "2026-07-29T05:14:00Z",
  "mode": "cloud",
  "name": "TP-Link Kasa Smart Home",
  "provider": "tp_link_kasa",
  "status": "connected"
}
```

# TP-Link Kasa Direct Integration — Phase 1, Phase 2, & Phase 3 Walkthrough

## Completed Features

### 1. Phase 1: Credential Storage & Security
- **Data Model**: `KasaCredentials` struct with `mode` (`cloud` vs `local`), optional `username` / `password`, and `config_entry_id`.
- **Validation**: Strict input validation (`cloud` mode requires non-empty username + password; `local` mode allows empty).
- **AES-GCM-256 Encryption at Rest**: Encrypted storage in `integrations.json` with secure decryption on startup.

### 2. Phase 2: Programmatic HA Config Entry Management
- **`KasaHaConfigFlowClient`**: Programmatic HA Config Entries API integration ([src/kasa/ha_config_flow.rs](file:///home/hp/SGX/src/kasa/ha_config_flow.rs)).
- **Dual Protocol Support**: Automatic candidate host evaluation (`127.0.0.1`, `host.docker.internal`, `172.17.0.1`, `172.18.0.1`) to establish the HA `tplink` config entry without requiring Home Assistant UI.
- **Unbind Lifecycle**: `DELETE /api/config/config_entries/{entry_id}` removes HA config entries cleanly on disconnect.

### 3. Phase 3: Post-Connect Device Auto-Discovery & Discovered Count Response
- **Auto-Discovery Window**: 2.5-second async pause after HA config entry establishment to allow Home Assistant's `tplink` driver time for UDP/TCP device discovery.
- **Automatic State Reconciliation**: Triggered `reconcile_state()` to register discovered entities into `devices.json`.
- **Vendor Classification**: Automatically tagged Kasa devices with `vendor: "tp_link"`.
- **Count Response**: Returned `devices_discovered: N` count in the `POST /api/v1/ha/integrations/tp_link_kasa/connect` API response.
- **Metadata Sync**: Updated `device_count` and `last_synced` fields in `integrations.json`.

---

## Verification Results

### Connect API Response (with Discovered Device Count)

```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode": "cloud", "username": "user@example.com", "password": "secret_password"}'
```

```json
{
  "devices_discovered": 2,
  "message": "Successfully connected integration for TP-Link Kasa Smart Home",
  "mode": "cloud",
  "provider": "tp_link_kasa",
  "status": "connected"
}
```

### Device Control Verification

#### 1. Turn On Command
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "turn_on", "domain": "switch"}'
```
**Response**: `HTTP/2 200 OK`
```json
{
  "command_id": "cmd_9c36c52ddee5419f9e92556b4b5ad981",
  "message": "Command 'turn_on' dispatched to Mock Kasa Smart Plug LED",
  "status": "pending"
}
```

#### 2. Turn Off Command
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "turn_off", "domain": "switch"}'
```
**Response**: `HTTP/2 200 OK`
```json
{
  "command_id": "cmd_cecaf309ddeb4e2dad1f89af3a309cfc",
  "message": "Command 'turn_off' dispatched to Mock Kasa Smart Plug LED",
  "status": "pending"
}
```
### Phase 4 Verification & Testing Guide

Here is a step-by-step guide to verify all Phase 4 features (device control, parameter bounds validation, parameter-aware no-op checking, and real-time state sync).

---

### Step 1: Ensure Background Services Are Running

#### Terminal 1 — Kasa Simulator in HA Container
```bash
docker exec -d homeassistant python3 /tmp/mock_kasa_plug.py
```

#### Terminal 2 — SGX Node A
```bash
sudo env "PATH=$PATH" "HOME=$HOME" SGX_DISABLE_LOGIN=1 cargo run -- nodeA
```

---

### Step 2: Verify Integration Connection & Discovered Devices

Run the connect request:
```bash
curl -k -X POST https://localhost:8443/api/v1/ha/integrations/tp_link_kasa/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode": "cloud", "username": "user@example.com", "password": "secret_password"}'
```

**Expected Response**:
```json
{
  "devices_discovered": 2,
  "message": "Successfully connected integration for TP-Link Kasa Smart Home",
  "mode": "cloud",
  "provider": "tp_link_kasa",
  "status": "connected"
}
```

---

### Step 3: Test Basic Smart Plug & Switch Commands (`turn_on` / `turn_off`)

#### 1. Turn ON the Kasa LED Switch:
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "turn_on", "domain": "switch"}'
```
**Expected Output**: `HTTP/2 200 OK`
```json
{
  "command_id": "cmd_...",
  "message": "Command 'turn_on' dispatched to Mock Kasa Smart Plug LED",
  "status": "pending"
}
```

#### 2. Turn OFF the Kasa LED Switch:
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "turn_off", "domain": "switch"}'
```
**Expected Output**: `HTTP/2 200 OK`
```json
{
  "command_id": "cmd_...",
  "message": "Command 'turn_off' dispatched to Mock Kasa Smart Plug LED",
  "status": "pending"
}
```

---

### Step 4: Test Parameter Bounds Validation (Bulb Controls)

#### 1. Test Valid `brightness` (0–255):
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "domain": "light",
    "params": { "brightness": 180 }
  }'
```
**Expected Output**: `HTTP/2 200 OK`

#### 2. Test Invalid `brightness` (> 255 Rejection):
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "domain": "light",
    "params": { "brightness": 999 }
  }'
```
**Expected Output**: `HTTP/2 400 Bad Request`
```json
{"error":"Invalid schema: Invalid brightness 999: must be between 0 and 255"}
```

#### 3. Test Invalid `color_temp` Out-of-Bounds (< 2700K Rejection):
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "domain": "light",
    "params": { "color_temp": 1200 }
  }'
```
**Expected Output**: `HTTP/2 400 Bad Request`
```json
{"error":"Invalid schema: Invalid color_temp 1200: must be between 2700K and 6500K"}
```

#### 4. Test Invalid `rgb_color` Out-of-Bounds (> 255 Rejection):
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "domain": "light",
    "params": { "rgb_color": [255, 300, 0] }
  }'
```
**Expected Output**: `HTTP/2 400 Bad Request`
```json
{"error":"Invalid schema: RGB color values must be between 0 and 255, got 300"}
```

---

### Step 5: Test Parameter-Aware No-Op Rejection

#### 1. Turn on device:
```bash
curl -k -s -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "turn_on", "domain": "switch"}'
```

#### 2. Repeat `turn_on` without parameters (Triggers No-Op Guard):
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "turn_on", "domain": "switch"}'
```
**Expected Output**: `HTTP/2 400 Bad Request`
```json
{"error":"No-op command: Device is already on"}
```

#### 3. Repeat `turn_on` with brightness parameter (Bypasses No-Op Guard to adjust light):
```bash
curl -k -i -X POST https://localhost:8443/api/v1/ha/devices/switch.mock_kasa_smart_plug_led/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "turn_on",
    "domain": "light",
    "params": { "brightness": 128 }
  }'
```
**Expected Output**: `HTTP/2 200 OK` (Accepted!)

---

### Step 6: Verify Device List & State Persistence

Query the device registry:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/api/v1/ha/devices"
```

**Expected Result**:
- `vendor`: `"tp_link"` for Kasa devices.
- `current_state`: Updated in real-time (`"on"` or `"off"`).

Manual Verification
Start Node A:
bash

sudo env "PATH=$PATH" "HOME=$HOME" SGX_DISABLE_LOGIN=1 cargo run -- nodeA
Check initial health status:
bash

curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/v1/ha/device-health
Stop mock Kasa plug simulator inside HA container to simulate device offline / unplugged state:
bash

docker exec homeassistant pkill -f mock_kasa_plug.py
Confirm DeviceManager logs ⚠️ Device 'Mock Kasa Smart Plug' transitioned to Offline.
Check notifications endpoint:
bash

curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/v1/ha/notifications
Verify notification "Kasa device 'Mock Kasa Smart Plug' went offline" with severity: "warning".
Restart mock plug:
bash

docker exec -d homeassistant python3 /tmp/mock_kasa_plug.py
Confirm recovery notification "Kasa device 'Mock Kasa Smart Plug' is back online" is generated.