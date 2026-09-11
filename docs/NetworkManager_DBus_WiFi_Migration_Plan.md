# NetworkManager D-Bus Wi-Fi Migration Plan

## Goal

Replace Guardian's direct control of Wi-Fi interfaces, `hostapd`,
`wpa_supplicant`, and `udhcpc` with NetworkManager's D-Bus API without changing
the existing REST API, security policy, local hotspot DNS, or client lease
behavior.

Work must stop at every gate until that gate passes on both a development host
and the target dual-radio board.

## Remote-safe first scope

The first implementation is deliberately hybrid because boards 192 and 195
are administered through `wlan0`:

- `wlan0` is protected management access and must never be changed by Guardian.
- NetworkManager D-Bus will initially manage only `wlan1` as the Wi-Fi uplink.
- SGX continues to manage `uap0` as the AP using the current hostapd/dnsmasq
  path.
- Board 252, which has Ethernet management, is the first hardware target.
- Board 195 is second and board 192 is last. Board 192 currently reports
  `wlan1` as unmanaged and cannot pass preflight until that board configuration
  is corrected outside the daemon.

Moving the AP from `uap0` to a NetworkManager-controlled `wlan*` interface is a
later migration. It is not part of the remote-safe first cut.

## Final ownership boundary

| Responsibility | Owner after migration |
|---|---|
| Wi-Fi device discovery and capability/state reporting | NetworkManager |
| `wlan1` scan, station association, disconnect, DHCP client, route received from DHCP, automatic reconnect | NetworkManager |
| `uap0` AP radio, channel/band, WPA security, AP isolation, activation/deactivation | Guardian legacy AP path during the first cut |
| Hotspot gateway address | Guardian legacy AP path during the first cut |
| Hotspot DHCP leases, canonical `*.guardian` DNS, blocklist integration | Guardian-managed `dnsmasq` |
| SGX forwarding, policy routing, NAT, API protection, signed policy composition | Guardian nftables/routing layer |
| Runtime modes, encrypted configuration, audit/events, REST/WebSocket API | Guardian |

When the later AP migration begins, its profile must initially use
`ipv4.method=manual`, not `shared`.
NetworkManager's shared mode also creates DHCP, DNS, forwarding, and NAT. That
would overlap with `DnsmasqOrchestrator`, `LeaseManager`, `NatManager`, and the
atomic SGX nftables tables. Moving those responsibilities to NetworkManager can
be evaluated later as a separate project.

Production code will use D-Bus through `zbus`. `nmcli` is allowed only for the
initial hardware proof and operator troubleshooting.

## Migration rules

- Keep `SGX_WIFI_BACKEND=legacy|networkmanager` until the final cutover.
- Default to `legacy` until all four runtime modes pass on target hardware.
- Create only in-memory NetworkManager profiles; Guardian remains the encrypted
  source of truth for passwords.
- Give profiles deterministic IDs/UUIDs prefixed with `sgx-guardian-` and only
  deactivate/delete profiles carrying that identity.
- Never disconnect, modify, or checkpoint `eth0` or an interface that is not in
  the requested Guardian mode.
- In the remote-safe first cut, reject any NetworkManager operation whose
  target is not exactly `wlan1`; explicitly reject `wlan0`, `uap0`, and `eth0`.
- Never log a PSK or return it through status APIs.
- Do not remove legacy modules or templates until the rollback release has
  completed its soak period.

## M0 — Hardware and OS feasibility gate

### M0.1 Record the target baseline

On every supported board image, record:

- NetworkManager version and whether `NetworkManager.service` is enabled.
- D-Bus API availability and `GetPermissions` results for the service user.
- Whether both configured interfaces appear as managed Wi-Fi devices.
- Driver, PHY mapping, AP and managed-mode support, valid interface
  combinations, supported bands/channels, and regulatory domain.
- Whether `802-11-wireless.ap-isolation` works with the installed version and
  driver.

**Gate:** a checked-in compatibility report identifies the minimum supported
NetworkManager version. Prefer `AddConnection2` with in-memory profiles
(NetworkManager 1.20+). If the board is older, decide explicitly whether to
upgrade the image or implement an `AddConnectionUnsaved` compatibility path.

### M0.2 Prove the intended profile model manually

Using temporary `nmcli` profiles only for this experiment:

1. Activate a station profile with DHCP on the uplink radio.
2. Activate an AP profile on the hotspot radio with a manual gateway address.
3. Start the existing Guardian `dnsmasq` against the AP interface.
4. Connect a phone/laptop and verify DHCP, DNS, and upstream internet.
5. Drop and restore the upstream AP and confirm NetworkManager reconnects.
6. Apply the current SGX nftables policy and verify both NetworkManager
   connections stay active.

**Gate:** both radios operate simultaneously for 30 minutes; a hotspot client
gets an address, resolves the canonical Guardian name, reaches the internet,
and the board's wired management session remains alive.

If this gate fails because NetworkManager cannot manage the vendor `uap*`
interface or enforce AP isolation, stop the migration and retain the legacy
backend for that board image.

## M1 — Add a testable backend seam

### M1.1 Define backend-neutral contracts

Add `src/netbridge/backend.rs` with an async `NetworkBackend` trait and plain
types for:

- preflight/capabilities;
- device inventory;
- scan results;
- create/update AP and station profiles;
- activate, deactivate, and query a profile;
- device/active-connection events;
- assigned IPv4 address and gateway.

Add a `FakeNetworkBackend` under test support. Refactor no runtime mode yet.

**Test:** unit tests prove the fake can model success, timeout, disconnect,
wrong password, missing SSID, and reconnect events. Existing tests remain
green.

### M1.2 Add the D-Bus transport

Add `zbus`, then create `src/netbridge/network_manager/` containing narrowly
scoped proxies for Manager, Settings, Settings.Connection, Device, Wireless,
ActiveConnection, IP4Config, and checkpoint methods.

Implement:

- one shared system-bus connection;
- typed object paths and D-Bus value conversion;
- bounded call timeouts;
- NetworkManager owner-loss/restart detection;
- stable error mapping with no secret-bearing debug output.

**Test:** pure conversion tests plus a private test bus/fake service contract
test. On a real host, an ignored integration test must list devices and read
NetworkManager version/state without changing networking.

### M1.3 Implement preflight and permissions

Validate service availability, minimum version, device management state,
device type, AP capability, distinct interfaces, and required permissions.
Return explicit errors such as `E_NM_UNAVAILABLE`, `E_NM_PERMISSION`,
`E_WIFI_AP_UNSUPPORTED`, and `E_WIFI_INTERFACE_CONFLICT`.

**Test:** table-driven tests for every failed precondition, followed by a board
test run as the actual `sgxguardian` systemd user.

## M2 — Build profiles without activating them

### M2.1 Station profile builder

Create a pure builder for one profile per saved network:

- mode `infrastructure`, exact SSID bytes, optional validated BSSID;
- WPA-PSK or open security matching the existing behavior;
- `ipv4.method=auto`, suitable route metric, IPv6 policy made explicit;
- power saving disabled;
- deterministic Guardian ID/UUID and in-memory storage;
- PSK marked not-saved and redacted from diagnostics;
- saved-network order converted to explicit autoconnect priority.

**Test:** snapshot the resulting `a{sa{sv}}` maps for open, WPA2, BSSID-pinned,
invalid SSID/BSSID/password, and multiple-priority cases.

### M2.2 Hotspot profile builder

Create a pure builder with:

- mode `ap`, SSID bytes, requested `bg`/`a` band and channel;
- WPA-PSK and AP isolation;
- manual gateway `/24`, no default route, and IPv6 disabled initially;
- power saving disabled and explicit interface binding;
- deterministic Guardian identity and in-memory storage.

Keep the existing subnet-conflict selector as a pure function.

**Test:** snapshots for 2.4 GHz, 5 GHz, isolation on/off, invalid channel,
invalid password, and all subnet-conflict candidates.

**M2 gate:** profile snapshots match the NetworkManager D-Bus setting schema
and can be added/deleted on a disposable host without activating a device.

## M3 — Migrate scan and ClientOnly

### M3.1 D-Bus scanning

Request a scan on the configured uplink device, wait for `LastScan`/property
change with a timeout, read AccessPoint objects, deduplicate by BSSID, and map
signal, band, and security into the existing `WifiNetwork` JSON shape.

Also fix the current `/scan` hard-coded `wlan0`; use
`config.uplink.interface`.

**Test:** fake AP-object mapping tests and the existing API schema test. Board
test must find a known 2.4 GHz and 5 GHz SSID while the other radio is an AP.

### M3.2 Station activation/deactivation

Add/update in-memory profiles, activate the highest-priority available saved
network, and wait for `ActiveConnection.State=ACTIVATED` and usable IP4Config.
Use Device/ActiveConnection state-change reasons to distinguish bad password,
SSID not found, timeout, and device failure.

Deactivation must target only the active Guardian connection object; do not
bring the raw interface down or flush its addresses manually.

**Test:** fake event-sequence tests for activate, timeout, bad password,
disconnect during activation, cancellation, and idempotent stop.

### M3.3 Cut ClientOnly over behind the backend flag

Wire `RuntimeManager::start_client_mode` and `stop_all` through the injected
backend. NetworkManager owns DHCP and reconnection. Keep an internet probe only
for reporting `NoInternet`; it must not restart NetworkManager or renew DHCP.

**Gate:** on the board, test correct password, wrong password, missing AP,
DHCP renewal, upstream reboot, NetworkManager restart, Guardian restart, and 20
ClientOnly/Off cycles. Wired SSH must survive every case.

## M4 — Migrate HotspotOnly

### M4.1 AP activation/deactivation

Activate the NetworkManager AP profile and wait for both device activation and
the expected gateway address. Replace hostapd polling/restart logic with D-Bus
state events. On stop, deactivate only the Guardian AP connection.

**Test:** fake activation/failure/cancellation tests, then board tests verifying
SSID, band, channel, WPA authentication, and AP isolation.

### M4.2 Attach existing DHCP/DNS behavior

Start `DnsmasqOrchestrator` only after the AP address is active; stop it before
deactivating the AP. Preserve its lease file and canonical Guardian DNS record.
Do not start NetworkManager shared mode.

**Test:** existing dnsmasq and lease parser tests, plus a real client test for
address range, lease reporting, DNS resolution, reconnect, and expiry.

### M4.3 Preserve Ethernet NAT behavior

After AP and dnsmasq are healthy, apply the existing `NatManager` and routing
behavior for the selected Ethernet uplink. Roll it back if the mode fails.

**Gate:** HotspotOnly supplies local DNS with Ethernet absent and internet with
Ethernet present; client isolation and port 8443 protection are verified from
two hotspot clients.

## M5 — Migrate DualWifi orchestration

### M5.1 Transactional startup

Use this order:

1. preflight both devices and reject identical/unsupported assignments;
2. create a NetworkManager checkpoint for Guardian Wi-Fi devices only;
3. activate AP and start Guardian dnsmasq;
4. activate uplink and wait for DHCP;
5. detect subnet overlap from D-Bus IP4Config; if needed, rebuild/reactivate
   the AP with a safe subnet and restart dnsmasq;
6. apply Guardian policy routing, NAT, forwarding, and isolation;
7. run end-to-end health checks, then destroy the checkpoint.

Any failure unwinds completed steps in reverse order. The checkpoint timeout is
the final safety net.

**Test:** a fake failure injected after every numbered step must leave no
Guardian active profile, dnsmasq child, policy route, or dynamic NAT rules.

### M5.2 Event-driven recovery

Subscribe to D-Bus signals instead of polling `wpa_cli`/`iw`:

- keep the AP active while the uplink reconnects;
- publish `UplinkDisconnected` and accurate runtime state;
- after uplink reactivation/IP change, verify and reapply only SGX policy
  routing/NAT rules;
- resubscribe and reconcile state if NetworkManager restarts;
- debounce duplicate signals and rate-limit retries.

**Test:** deterministic fake event streams for loss/recovery, IP change,
NetworkManager restart, duplicate events, and shutdown races.

### M5.3 Dual-radio hardware acceptance

Verify:

- hotspot client internet and canonical DNS;
- upstream loss for 1, 10, and 120 seconds while hotspot stays available;
- automatic recovery without Guardian restarting;
- uplink DHCP address/gateway change;
- default hotspot/uplink subnet collision and AP subnet migration;
- signed policy reapplication while DualWifi is active;
- NetworkManager and Guardian service restarts;
- 20 mode cycles and an 8-hour soak.

**M5 gate:** zero stale profiles/processes/routes, no loss of wired management,
no secret in journal output, and all security checks pass.

## M6 — Runtime/API correctness

### M6.1 Make actual state authoritative

Keep the existing public mode names, but derive active health from D-Bus
connection/device state instead of only the saved config. Do not report
`DualActive` until AP, dnsmasq, uplink IP, routing, and security rules are all
healthy.

**Test:** API tests distinguish desired mode from applying, active, degraded,
and error states.

### M6.2 Preserve API compatibility

Keep these endpoints and existing JSON fields:

- `GET/POST /api/v1/wifi/mode`;
- `GET /api/v1/wifi/scan`;
- `GET /api/v1/wifi/clients`;
- `GET /api/v1/wifi/stream`.

Extend responses only with optional fields such as backend, active SSID,
uplink address, and NetworkManager reason code.

**Test:** backend contract tests run the same API suite once with the fake
legacy backend and once with the fake NetworkManager backend. Run frontend
tests and verify no schema break.

### M6.3 Audit and observability

Emit redacted events for preflight, profile creation/update, activation,
deactivation, reconnect, rollback, and terminal failure. Add counters for
transition failures and reconnects.

**Test:** captured logs/events contain IDs, interface, and reason but never PSK
values.

## M7 — Packaging and service permissions

### M7.1 Dependencies and service ordering

- Add NetworkManager, D-Bus, and PolicyKit runtime dependencies to DEB/RPM.
- Keep `dnsmasq`, `nftables`, and routing tools while they remain owned by
  Guardian.
- Order Guardian after `NetworkManager.service` and D-Bus availability.
- Install a narrow PolicyKit rule for the `sgxguardian` service identity.
  Grant only the permissions confirmed by `GetPermissions`: network control,
  protected hotspot creation, Wi-Fi scan, in-memory system-profile changes,
  and checkpoint rollback.
- Preserve the non-root systemd service and current capability restrictions.

**Test:** fresh DEB and RPM installs pass package lint, start without an
interactive authorization agent, and fail clearly if permissions are removed.

### M7.2 Upgrade behavior

On upgrade, do not kill global daemons or delete user-created NetworkManager
profiles. Clean only stale Guardian-generated profiles/sockets after verifying
their identity. Keep legacy templates for one rollback release.

**Gate:** test fresh install, upgrade from legacy, downgrade/rollback, reboot,
uninstall, and reinstall on a disposable board image.

## M8 — Controlled cutover

1. Ship `networkmanager` backend as opt-in to internal boards.
2. Run the full matrix and soak on every supported board/driver image.
3. Make NetworkManager the default while retaining `legacy` override.
4. Observe one release cycle and compare activation time, reconnect count,
   failures, and support logs.
5. Remove the legacy override only after explicit release approval.

**Gate:** no open critical regression, rollback has been exercised, and the
NetworkManager backend meets or improves the legacy success/recovery rates.

## M9 — Legacy cleanup

Only after M8 passes, remove or reduce:

- `wifi_client.rs`, `wpa_config.rs`, and `dhcp_client.rs`;
- hostapd-specific parts of `Netbridge`, bootstrap, validator, and process
  health monitoring;
- `uplink_monitor` reconnect/DHCP manipulation;
- hostapd and wpa_supplicant templates and package entries;
- tests that only validate deleted config generation/process control.

Retain `process.rs` if `DnsmasqOrchestrator` still uses it, along with
`dhcp_dns.rs`, `leases.rs`, `nat.rs`, and the SGX-specific portions of
`routing.rs`.

**Final test:** full Rust and frontend suites, package tests, the complete
hardware matrix, reboot restore, NetworkManager restart, upstream outage,
policy reload, and the 8-hour DualWifi soak all pass from a clean image.

## Standard gate checklist for every task

Before merging each task:

1. `cargo fmt --check`
2. focused unit/contract tests for the changed module
3. `cargo test --all --tests`
4. `cargo clippy --all-targets --all-features -- -D warnings`
5. no new plaintext credential files or credential-bearing logs
6. legacy-backend smoke test until M9
7. board test when the task changes D-Bus calls, profiles, lifecycle, routing,
   firewall, packaging, or permissions

Do not begin the next milestone when its predecessor's gate has a known failure.
