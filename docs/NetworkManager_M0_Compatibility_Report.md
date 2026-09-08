# NetworkManager M0 Compatibility Report

## Chosen first deployment shape

- Protected remote management: `wlan0` on boards 192 and 195.
- NetworkManager-managed uplink target: `wlan1` only.
- Guardian-managed AP: `uap0` using the existing hostapd/dnsmasq path.
- First hardware target: board 252 over Ethernet.

The daemon must reject NetworkManager mutations targeting `wlan0`, `uap0`, or
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
- [x] Local isolated NetworkManager lifecycle lab passes. NetworkManager 1.42.4
  activated the isolated `wlan1` veth, obtained `10.77.0.10/24` by DHCP,
  passed peer reachability, disconnected, and reactivated successfully.
- [ ] Board 252 proves NM-managed `wlan1` uplink while SGX owns `uap0` AP.
- [ ] NetworkManager D-Bus permissions are verified for the `sgxguardian` user.
- [ ] Board 192 `wlan1` management configuration is understood and corrected.

M1 production D-Bus wiring must not be enabled on remote boards until the
remaining relevant gates pass.

Run `scripts/nm_m0_board_preflight.sh` on board 252 next. It is read-only and
does not activate, deactivate, or reconfigure an interface.

## Local verification record

On 2026-09-08:

- `tests/networkmanager_lab/run.sh`: passed twice; the cached repeat completed
  in approximately six seconds.
- Shell syntax validation: passed for the lab and board-preflight scripts.
- `git diff --check`: passed.
- Focused existing netbridge/Wi-Fi regression suite: 17 passed, 0 failed.
