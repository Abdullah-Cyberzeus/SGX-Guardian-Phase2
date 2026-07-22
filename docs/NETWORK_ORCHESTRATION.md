# SGX Guardian: Network Orchestration & API Reference

The Network Orchestration subsystem (`src/netbridge` and `src/runtime`) is responsible for managing the physical Wi-Fi interfaces, the local Access Point (Hotspot), uplink connections (Wi-Fi client), DHCP, DNS routing, and NAT (Network Address Translation).

It dynamically switches between the following modes:
- **Off**: Network orchestration is disabled completely.
- **HotspotOnly**: Broadcasts a local Wi-Fi Access Point (supporting 2.4GHz or 5GHz bands) and routes traffic through Ethernet.
- **ClientOnly**: Connects to an upstream Wi-Fi network for internet access.
- **DualWifi**: Operates both a local Hotspot (on `uap0`) and connects to an upstream Wi-Fi network (on `wlan1`), applying NAT and Zero Trust enforcement rules between them.

---

## Wi-Fi Security & Password Constraints
When configuring the AP Hotspot password, it is validated against the following security constraints:
- **Length**: Must be at least **8 characters** long.
- **Complexity**: Must contain at least **one non-alphanumeric character** (e.g., `!`, `@`, `#`, `$`, etc.).
- **Common Passwords**: Must not match any of the common passwords in the embedded `rockyou` list.

---

## Runtime API Reference

The orchestrator exposes a local HTTP JSON REST API to monitor and control network modes, scan networks, and track connected clients. By default, the server binds to `http://localhost:8443/api/v1/wifi`.

> [!NOTE]
> All REST endpoints are prefixed with `/api/v1/wifi`.

### 1. Get Current Mode & Status
Retrieves the active orchestration mode, the health state of the internal state machine, and basic module configurations.

- **Endpoint**: `GET /mode`
- **Headers**: `Accept: application/json`
- **Request Example**:
  ```bash
  curl -X GET http://localhost:8443/api/v1/wifi/mode
  ```

- **Response Example (200 OK - Dual Active)**:
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

- **Response Example (200 OK - Off State)**:
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

> [!IMPORTANT]
> The `status.state` field represents the exact phase of the state machine. Possible values include:
> - `Idle`: No active orchestration.
> - `ApplyingChange`: Actively transitioning states.
> - `HotspotStarting`: AP starting up.
> - `HotspotActive`: AP is broadcasted but no client/internet is active yet.
> - `ClientConnecting`: Uplink is attempting to associate.
> - `ClientConnected`: Uplink associated and obtained IP.
> - `DualStarting`: Bootstrapping Dual Wi-Fi mode.
> - `DualActive`: Both AP and client connected with NAT/Firewall routing active.
> - `Error`: Transition failed. Check `status.metadata.message` for details.

---

### 2. Set Mode (Apply Configuration)
Updates the network orchestration mode. The payload specifies the target `mode`, validation flags, as well as configuration for the `hotspot` and `uplink` profiles.

- **Endpoint**: `POST /mode`
- **Headers**: `Content-Type: application/json`
- **Response (200 OK)**:
  ```json
  {
    "status": "applying",
    "estimated_downtime_seconds": 3
  }
  ```

*Below are complete configurations and payloads for all supported runtime modes:*

#### A1. Dual Wi-Fi Mode (2.4GHz Hotspot)
Simultaneously broadcasts a local hotspot (configured on the 2.4GHz band) and connects to an upstream Wi-Fi network.
- **Request Example**:
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

#### A2. Dual Wi-Fi Mode (5GHz Hotspot)
Simultaneously broadcasts a local hotspot (configured on the 5GHz band) and connects to an upstream Wi-Fi network.
- **Request Example**:
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

#### B. HotspotOnly Mode (2.4GHz Band)
Broadcasts a local AP on the 2.4GHz band. Uplink/Wi-Fi client is disabled.
- **Request Example**:
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

#### C. HotspotOnly Mode (5GHz Band)
Broadcasts a local AP on the 5GHz band. Uplink/Wi-Fi client is disabled.
- **Request Example**:
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

#### D. ClientOnly Mode Configuration
Acts solely as a client connecting to an upstream Wi-Fi network. Hotspot is disabled.
- **Request Example**:
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

#### E. Off Mode Configuration
Tears down all active network setups (APs and client connections) and disables routing.
- **Request Example**:
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

> [!NOTE]
> The transition runs asynchronously in the background. You can query `GET /mode` to monitor the progress of the state machine.

---

### 3. Scan Visible Networks
Forces the Wi-Fi module (`wlan0`) to perform a wireless network scan for visible access points in range.

- **Endpoint**: `GET /scan`
- **Request Example**:
  ```bash
  curl -X GET http://localhost:8443/api/v1/wifi/scan
  ```

- **Response Example (200 OK)**:
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

---

### 4. Get Connected Clients (DHCP Leases)
Retrieves the list of active network clients currently connected to the local Hotspot. This parses the dynamic leases assigned by the local DHCP server (`dnsmasq`).

- **Endpoint**: `GET /clients`
- **Request Example**:
  ```bash
  curl -X GET http://localhost:8443/api/v1/wifi/clients
  ```

- **Response Example (200 OK)**:
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

---

## Architectural Highlights

- **Resilient Hotspot (Fail-Open):** When starting `DualWifi` mode, the orchestrator guarantees that the local Hotspot (AP) is broadcasted *first*. Even if the Uplink connection fails (e.g., due to a changed password or router reboot), the Hotspot remains online, allowing administrators to connect locally to debug or submit new credentials via the API.
- **Event-Driven NAT:** The orchestrator utilizes a non-blocking `watch` channel to monitor Uplink connectivity. The moment the Wi-Fi client establishes a connection and secures an IP via DHCP, the NAT engine automatically patches routing and enforces Zero-Trust policies. If the Wi-Fi drops, NAT is immediately severed to protect the Hotspot from exposing unrouted packets.
