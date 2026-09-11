# NetworkManager M0 Compatibility Report

## Chosen first deployment shape

- Current NetworkManager uplink default: `wlan0`.
- Allowed station targets: `wlan0` and `wlan1`; runtime configuration selects one.
- Guardian-managed AP: `uap0` using the existing hostapd/dnsmasq path.
- First hardware target: board 252 over Ethernet.

The daemon must reject NetworkManager mutations targeting `uap0`, `uap1`, or
`eth0` during this first cut.

## Board evidence supplied on 2026-09-08

All three boards run NetworkManager 1.42.4 with the NXP `wlan_sdio` driver. Each
board exposes two PHYs. Both PHYs support managed and AP modes, up to four
virtual interfaces, and one channel per PHY.

| Board | Management path observed | `wlan0` | `wlan1` | `uap0/uap1` | Initial conclusion |
|---|---|---|---|---|---|
| 192 | `wlan0` (`CervaisRouter`) | NM managed/connected | unmanaged | unmanaged | Do not deploy until `wlan1` is intentionally made NM-managed |
| 195 | `wlan0` (`wifi-wan`) | NM managed/connected | NM managed, currently AP (`hotspot`) | unmanaged | NM already proves simultaneous use of the two physical radios |
| 252 | `eth0` | NM managed/disconnected | NM managed/disconnected | unmanaged | Safest first board for the hybrid uplink test |

`uap*` being unmanaged does not block the hybrid plan because SGX retains AP
ownership. NetworkManager D-Bus must address `wlan1`, not `uap0`.

## Local test environment

The development host is WSL2. Network namespaces are available through Docker,
but its kernel does not ship `mac80211_hwsim`, and the host does not have
NetworkManager installed.

`tests/networkmanager_lab` therefore provides two levels of evidence:

1. A real NetworkManager 1.42.4 instance in an isolated container controls a
   veth named `wlan1` and receives DHCP from a nested upstream namespace.
2. Real Wi-Fi scan, WPA association, NXP driver behavior, and `uap0` coexistence
   remain board-252 gates and cannot honestly be certified by the veth lab.

## M0 gate

- [x] NetworkManager version matches across the three boards (1.42.4).
- [x] Two suitable physical radios are present on all boards.
- [x] `wlan0` is identified as protected remote management on boards 192/195.
- [x] Board 252 is identified as the safe first hardware target.
- [x] Board 252 read-only preflight confirms `wlan1` is a managed Wi-Fi device,
  `uap0` remains unmanaged, and the two interfaces are on separate PHYs.
- [x] The installed Guardian service identity was checked. Its systemd unit has
  no `User=` directive, so it currently runs as root; a PolicyKit rule is only
  required if the service is hardened to a non-root account later.
- [x] Local isolated NetworkManager lifecycle lab passes. NetworkManager 1.42.4
  activated the isolated `wlan1` veth, obtained `10.77.0.10/24` by DHCP,
  passed peer reachability, disconnected, and reactivated successfully.
- [ ] Board 252 proves NM-managed `wlan1` uplink while SGX owns `uap0` AP.
- [ ] Board 192 `wlan1` management configuration is understood and corrected.

M1 production D-Bus wiring must not be enabled on remote boards until the
remaining relevant gates pass.

## M1 read-only D-Bus milestone

The first implementation adds a `zbus` system-bus transport, backend-neutral
device/preflight types, bounded calls, stable errors, and an exact `wlan1`
target guard. The standalone `nm_m1_probe` binary performs inventory or
preflight without activating, deactivating, scanning, or changing a device.

The isolated lab runs that Rust probe against the real NetworkManager 1.42.4
D-Bus service. Its veth is intentionally reported as non-Wi-Fi, so full
preflight remains a board-252 test.

The next read-only increment adds `scan wlan1`. It requests a fresh scan,
waits up to 20 seconds, reads AccessPoint objects, removes hidden/duplicate
entries, and maps SSID, BSSID, approximate signal dBm, band, and security into
the existing `WifiNetwork` shape. It does not create or activate a connection.

## M2.1 station profile builder

The pure station-profile builder produces NetworkManager `a{sa{sv}}` settings
without making a D-Bus call. It supports open and WPA-PSK networks, optional
binary BSSID pinning, DHCP, an explicit route metric, disabled IPv6 and Wi-Fi
power saving, deterministic Guardian IDs/UUIDs, and saved-network priority.

Profiles carry the `AddConnection2` in-memory and block-autoconnect flags. The
PSK uses NetworkManager's normal secret flag so no desktop secret agent is
required, but the complete profile (including the PSK) exists only in
NetworkManager memory and is deleted during teardown. Debug output is
explicitly redacted. The M2 schema probe additionally sets `autoconnect=false`,
ensuring its add/delete validation cannot associate with a network. Production
profiles enable autoconnect only after their first explicit activation.

The disposable NetworkManager 1.42.4 schema gate found and corrected an
initial out-of-range autoconnect priority (`1000`); NetworkManager accepts a
maximum of `999`. With that correction, the Rust probe added the dummy WPA
profile in memory, verified `Unsaved=true`, proved it was not active, deleted
it, and confirmed the connection list was unchanged.

Build and run the board probe from an ARM64 build of this repository:

```bash
cargo build --release --bin nm_m1_probe
sudo ./target/release/nm_m1_probe preflight wlan1
sudo ./target/release/nm_m1_probe scan wlan1
```

Expected success output includes the NetworkManager version, `wlan1`, managed
Wi-Fi status, and confirmation that the operation was read-only.

## Local verification record

On 2026-09-09:

- `tests/networkmanager_lab/run.sh`: passed with Rust D-Bus inventory, stale
  Guardian profile replacement, explicit activation, DHCP, reachability,
  deactivation, and residue checks against NetworkManager 1.42.4.
- Shell syntax validation: passed for the lab and board-preflight scripts.
- `git diff --check`: passed.
- Wi-Fi HTTP API tests: 3 passed, 0 failed.
- Runtime-manager tests: 6 passed, 0 failed.
- NetworkManager backend/profile tests: 14 passed, 0 failed.
- Rust D-Bus inventory against the isolated NetworkManager service: passed.
- Rust protected-interface rejection (`wlan0`): passed.
- M2.1 station-profile builder tests: 6 passed, 0 failed.
- M2 station-profile add/verify/delete D-Bus schema gate: passed with no
  remaining profile and no activation.
- Scan mapping and deduplication tests: passed.
- Scan-specific protected-interface rejection in the isolated D-Bus lab:
  passed.
- Focused existing netbridge/Wi-Fi regression suite after scan support:
  17 passed, 0 failed.
- M3.2 station activation/deactivation and granular StateReason failure mapping: passed.
- M3.2 isolated NetworkManager D-Bus lifecycle (activation, DHCP assignment, deactivation, cleanup): passed with zero residual profiles.
- M3.2 physical hardware gate is proceeding on `wlan0`. The second adapter,
  `wlan1`, currently fails WPA authentication in the NXP firmware/HostMLME path
  with both the router and an independent hotspot, while the same credentials
  work on `wlan0`; that board issue is deferred.

## M3.2 station activation and deactivation

The station activation lifecycle implements:
1. Building an in-memory station profile via `StationProfileBuilder` bound to `wlan1`.
2. Adding the profile via `Settings.AddConnection2` with in-memory volatile flags.
3. Activating the connection on `wlan1` via `Manager.ActivateConnection`.
4. Polling `ActiveConnection.State` and extracting DHCP IP address and Gateway from `IP4Config`.
5. Granular failure reason mapping: queries `Device.StateReason` and `ActiveConnection.StateReason` to differentiate bad password/auth failures (`E_WIFI_AUTH_FAILED`), missing SSID (`E_WIFI_SSID_NOT_FOUND`), DHCP lease failure (`E_WIFI_IP_CONFIG_FAILED`), and timeouts (`E_NM_TIMEOUT`).
6. Deactivation via `Manager.DeactivateConnection` and deletion of the in-memory profile with zero residue.
7. Verification CLI support via `nm_m1_probe connect wlan1 <SSID> [password] [hold_seconds]`.
8. Physical hardware validation on Board 252 confirmed successful WPA2 station association, DHCP IP assignment, and clean teardown.

## M3.3 ClientOnly runtime mode cutover

The ClientOnly runtime cutover integrates NetworkManager D-Bus into `RuntimeManager`:
1. Environment flag `SGX_WIFI_BACKEND=networkmanager` toggles between NetworkManager D-Bus and the legacy process orchestrator (defaults to `legacy` for backwards compatibility).
2. `RuntimeManager::start_client_mode` builds and activates in-memory station profiles on `wlan1` across prioritized saved networks over D-Bus, transitions state to `ClientConnected`, and stores active session references.
3. `RuntimeManager::stop_all` cleanly deactivates the NetworkManager session and deletes the in-memory profile.
4. `perform_system_cleanup` skips disruptive link-down and address flushing on `wlan1` when managed by NetworkManager.
5. REST API `/api/v1/wifi/scan` dynamically utilizes NetworkManager D-Bus scanning when active on `wlan1`.

## Reconnect bug fix (2026-09-09)

A firmware-level radio reset on `wlan1` (NXP HostMLME "WiFi Reset due to auth
timeout", visible in board dmesg) can tear the NetworkManager active
connection down before Guardian's health-check loop notices. `deactivate_active_path`
previously called `DeactivateConnection` unconditionally and mapped any
failure to `E_WIFI_DEACTIVATION_FAILED`; when the connection had already
vanished, `stop_all` then restored the stale session instead of clearing it,
so the ClientOnly rebuild loop spun forever on a dead reference instead of
reconnecting. Fixed by checking `ActiveConnections` before and after the
`DeactivateConnection` call and treating an already-vanished active path as
already deactivated. Verified: 15 `netbridge::network_manager` unit tests,
isolated D-Bus lab activate/deactivate/reactivate cycle, and the 17-test
legacy regression suite all pass.

## M5-lite: hybrid DualWifi (NM uplink + legacy AP)

`RuntimeManager::start_dual_wifi_mode` now branches on `SGX_WIFI_BACKEND`:

- Legacy path (`legacy`, default): unchanged `DualWifiOrchestrator`
  (hostapd/dnsmasq AP + wpa_supplicant uplink), untouched by this change.
- NetworkManager path (`networkmanager`): new `start_dual_wifi_mode_nm`.
  - Hotspot leg (`uap0`) still starts via the existing `Netbridge`
    (hostapd/dnsmasq), matching the remote-safe hybrid decision — AP
    migration to NetworkManager is out of scope for this cut.
  - Uplink leg (`wlan1`) activates via `NetworkManagerBackend::activate_station`
    across the saved-network priority list, reusing the same profile builder
    and station-session type as ClientOnly (M3.2/M3.3).
  - Subnet-conflict detection reuses `select_non_conflicting_dns_settings`
    against the NetworkManager-assigned uplink address; on conflict the AP is
    restarted on a non-overlapping subnet, exactly as the legacy orchestrator
    does.
  - Policy routing (`RoutingManager::configure_hotspot_uplink`) and NAT
    (`NatManager::enable_nat`) are applied the same way as the legacy path.
  - A dedicated recovery task polls `station_session_is_viable` every 5s.
    On 3 consecutive failures it rebuilds only the NetworkManager station
    session (deactivate + reactivate across saved networks) and reapplies
    routing/NAT — it never touches `self.ap`, so the hotspot stays up while
    the uplink self-heals, per the plan's M5.2 intent ("keep the AP active
    while the uplink reconnects").
  - `stop_all` aborts the new recovery task and now unconditionally calls
    `RoutingManager::remove_hotspot_uplink()` when a NAT manager was stored
    (a safe no-op for HotspotOnly, which never configures policy routing).

**Scope note:** this is a hybrid implementation, not the plan's full M4/M5
(those assume the AP itself also migrates off `uap0` onto a NetworkManager
profile, which the remote-safe first cut deliberately deferred). M4 as
written does not apply until that later AP migration is scheduled.

**Local verification:** compiles clean, `cargo fmt --check` passes, 28
`netbridge::` unit tests pass (up from 15 — includes the reconnect fix and
unaffected pre-existing tests), 6 `runtime::runtime_manager` unit tests pass,
the isolated NetworkManager D-Bus lab passes, and the 17-test legacy
regression suite passes. No dual-radio hardware test has been run yet — the
recovery task's rebuild-while-AP-stays-up behavior and the subnet-conflict
restart path both need verification on board 252 with `SGX_WIFI_BACKEND=networkmanager`
and `RuntimeMode::DualWifi`.

**Not implemented in this pass (explicitly out of scope):**
- M4 (AP migrated onto NetworkManager) — deferred per the remote-safe hybrid decision.
- M5.1's NetworkManager checkpoint/rollback transactionality — the existing
  fail-closed manual rollback (mirroring the legacy orchestrator's pattern)
  is used instead.
- M6 (derive `DualActive`/`ClientConnected` health from live D-Bus state
  rather than saved config), M7 (packaging/PolicyKit), M8 (staged rollout),
  M9 (legacy removal) — unstarted.

## Hotspot client internet: three-layer failure found on hardware (2026-09-10)

Hotspot clients had no internet in DualWifi despite correct-looking nftables
rules. Three independent causes, found in this order on boards 195 and 192:

1. **Kernel IP forwarding was off.** `start_dual_wifi_mode_nm` never called
   `RoutingManager::enable_forwarding()`. The legacy path got it as a side
   effect of `UplinkOrchestrator::start()`; replacing the uplink leg with
   NetworkManager D-Bus dropped it. Symptom: `ip route get <dst> from
   <client> iif <ap>` returned `No route to host`, and no packet was routed.
   `HotspotOnly` was never affected — it already called it.

2. **`wwan0` was not an allowed uplink.** `NatManager::enable_nat` covered
   only the selected uplink, its sibling Wi-Fi radio, and `eth0`; and the
   enforcement layer kept its *own* duplicate allowlist in both
   `enforcement/validator.rs` and `enforcement/translator.rs`, which rejected
   `wwan0` outright (`invalid destination IP/CIDR format: wwan0`). All three
   lists now include cellular.

3. **Legacy iptables `FORWARD` policy DROP (the actual blocker).** Docker sets
   `iptables -P FORWARD DROP`. Legacy iptables (`v1.8.9 (legacy)`) hooks
   FORWARD at the same priority as Guardian's nftables chain but is *invisible
   to `nft list ruleset`*, so every inspection looked correct while the drop
   counter climbed. Hotspot traffic (`uap0 -> wlan1`) matches none of Docker's
   `docker0` rules, falls through `DOCKER-USER`/`DOCKER-ISOLATION-STAGE-1`
   (both RETURN), and hits the policy DROP. `NatManager` now inserts matching
   ACCEPT rules into the legacy FORWARD chain, removes them on teardown, and
   `kernel_rules_active` verifies them so a Docker restart is self-healed.
   Both layers must accept, so the nftables policy still governs access.

**Diagnosing this class of bug:** `nft` counters in a separate throwaway table
at hook priorities around Guardian's own chain (e.g. forward `-150` vs `+10`)
localise the drop precisely. Note `conntrack` is **not installed** on these
boards — `conntrack -L` returns nothing, which is not evidence of anything.

## Board kernel constraints (all three boards, verified 2026-09-10)

All boards run the identical kernel `6.1.36-imx8mp+g662f7a7a2748`:

- **No policy routing.** `ip rule` returns `Operation not supported`
  (`CONFIG_IP_MULTIPLE_TABLES` absent), so per-source routing into a dedicated
  table is impossible. `configure_hotspot_uplink` therefore falls back to
  forcing the uplink as the main-table default route at metric 1, beating any
  competing default (e.g. cellular at metric 10), and removes it on teardown.
  This is a board-wide routing change, which is the deliberate trade-off for
  having no FIB rules.
- `/proc/config.gz` is not exposed, so kernel config must be inferred.
- `conntrack` userspace tooling is absent.
