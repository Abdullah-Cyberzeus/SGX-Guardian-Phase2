# SGX Guardian: Network Orchestration & API Reference

The Network Orchestration subsystem (`src/netbridge` and `src/runtime`) is responsible for managing the physical Wi-Fi interfaces, the local Access Point (Hotspot), uplink connections (Wi-Fi client), DHCP, DNS routing, and NAT (Network Address Translation).

It dynamically switches between the following modes:
- **Off**: Network orchestration is disabled completely.
- **HotspotOnly**: Broadcasts a local Wi-Fi Access Point (supporting 2.4GHz or 5GHz bands) and routes traffic through Ethernet.
- **ClientOnly**: Connects to an upstream Wi-Fi network for internet access.
- **DualWifi**: Operates both a local Hotspot (on `uap1`) and connects to an upstream Wi-Fi network (on `wlan0`), applying NAT, policy routing, and Zero Trust enforcement rules between them.

## Canonical LAN Names and HTTPS

Every Guardian derives one stable LAN name from its node ID:

| Node ID | LAN URL |
|---|---|
| `nodeA` | `https://nodea.guardian` |
| `nodeB` | `https://nodeb.guardian` |
| `nodeC` | `https://nodec.guardian` |

The same name is used by DHCP, hotspot DNS, the HTTPS certificate and Docker's
TLS proxy.

### Physical board

- A client connected directly to a Guardian hotspot receives that board as its
  DNS server. The board's `dnsmasq` resolves its own canonical name to the
  hotspot gateway automatically; no IP needs to be entered in the browser.
- On a shared upstream LAN, each board advertises `nodea`, `nodeb` or `nodec`
  through DHCP. Configure the router's local DNS domain as `guardian` and enable
  DNS registration for DHCP leases. The router then publishes
  `nodea.guardian`, etc., even when a board's lease address changes.
- A custom suffix such as `.guardian` is unicast DNS, not mDNS. The existing
  Guardian mDNS discovery service cannot make arbitrary `.guardian` browser
  names resolvable; the LAN's DHCP-provided DNS resolver must be authoritative
  for this suffix.
- On the first boot after this change, an older node certificate that lacks the
  canonical DNS SAN is backed up as `device_<node>_cert.der.pre-lan-name.bak`
  and reissued with the existing private key. Install/trust the new certificate
  on member devices before installing the PWA.

### Docker

`docker-compose.dev.yml` includes Caddy as the HTTPS boundary. Caddy routes all
three names over the private Compose network while Guardian itself remains HTTP
inside Docker. The old ports `18443`, `28443` and `38443` remain available for
localhost diagnostics only; member/PWA access should use the HTTPS names.

The Docker host's LAN DNS/router needs three records pointing to the Docker
host. For a router with DHCP host overrides, create these once:

```text
nodea.guardian -> Docker host
nodeb.guardian -> Docker host
nodec.guardian -> Docker host
```

For testing on the Docker host only, equivalent `/etc/hosts` entries are also
sufficient. LAN phones and laptops still need the router/DNS records.

Start the cohort and export Caddy's local root CA:

```bash
docker compose -f docker-compose.dev.yml up -d --build
mkdir -p build/certs
docker compose -f docker-compose.dev.yml cp \
  caddy:/data/caddy/pki/authorities/local/root.crt \
  build/certs/guardian-docker-root-ca.crt
```

Install `guardian-docker-root-ca.crt` as a trusted root CA on each LAN client.
Then use `https://nodea.guardian`, `https://nodeb.guardian` or
`https://nodec.guardian`. Trusting the CA is required for service workers,
PWA installation, camera, microphone and WebRTC.

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
      "interface": "uap1",
      "ssid": "SGX_Hotspot_5G",
      "password": "SecurePassword123!",
      "channel": 36,
      "band": "5GHz",
      "client_isolation": true
    },
    "uplink": {
      "interface": "wlan0",
      "networks": [
        {
          "ssid": "CervaisRouter",
          "bssid": null,
          "password": "toggle0705"
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

## Dual Wi-Fi Verification

Run these commands on the board after the API reports `DualActive`:

```bash
iw dev wlan0 link
ip -4 addr show dev uap1
ip -4 rule show
ip -4 route show table 200
ip -4 route show default
ip route get 8.8.8.8 from 192.168.200.160 iif uap1
nft list chain ip sgx_nat postrouting
nft list chain inet sgx_guardian forward
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.all.arp_ignore net.ipv4.conf.all.arp_announce
ping -I wlan0 -c 20 8.8.8.8
systemctl is-active suricata
```

Expected results:

- `wlan0` is connected to the configured upstream SSID.
- `uap1` owns `192.168.200.1/24`.
- With policy-routing kernel support, rule priority `22000` sends `192.168.200.0/24` through table `200`.
- On this board kernel, unsupported `ip rule` is treated as a capability fallback and the existing main routing table is left unchanged.
- nftables contains forwarding and masquerade rules for `uap1` through `wlan0`, `wlan1`, and `eth0`, so traffic can follow the active default egress.
- `rp_filter=2`, `arp_ignore=1`, and `arp_announce=2` protect the same-subnet `eth0`/`wlan0` topology.
- Suricata is `inactive` when threat integration has `enabled: false`.

On a laptop connected to the Guardian hotspot, disable any competing Ethernet interface for the definitive forwarding test, then run:

```powershell
ipconfig
ping -n 100 192.168.200.1
ping -n 100 8.8.8.8
nslookup google.com 192.168.200.1
curl.exe --connect-timeout 10 --max-time 20 -I https://www.google.com
```

## Architectural Highlights

- **Validated Dual Startup:** The AP is started first, but `DualActive` is reported only after the AP, uplink, policy route, and NAT rules are all active. Partial startup is cleaned up and retried instead of leaving duplicate daemons or reporting a false healthy state.
- **Routing-Preserving NAT:** Policy routing is used when supported. Otherwise Guardian leaves the management routing table unchanged and permits NAT through each valid board egress.
- **Self-Healing NAT:** The orchestrator checks the actual nftables rules instead of relying only on memory state. If signed-policy enforcement replaces the NAT tables, the combined security and NAT policy is restored automatically.
- **Managed Daemon Recovery:** Unexpected exits from `hostapd`, `dnsmasq`, `wpa_supplicant`, or `udhcpc` are treated as failures and retried with bounded backoff.
