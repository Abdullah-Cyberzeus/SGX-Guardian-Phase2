# CoT Transport Admin Guide

## Transport Mapping
- `eth*`, `en*`, `eno*`, `enp*` => `Ethernet`
- `wlan*`, `wl*`, `wlp*` => `WiFi`
- `bnep*`, `bt*`, `hci*` => `Bluetooth`
- `wwan*`, `rmnet*`, `usb*` => `Cellular`
- `sat*`, `ppp*`, known satellite USB VID => `Satellite`
- `SGX_SATELLITE_INTERFACES=ens37,starlink0` can force specific interfaces to `Satellite`

## Priority Order
- `Cellular` = 5
- `Ethernet` = 10
- `WiFi` = 20
- `Bluetooth` = 40
- `Satellite` = 50

Lower value means higher preference.

## Failover Behavior
- Probe interval: 10s
- Switch away threshold: 3 consecutive failures
- Return/upgrade threshold: 5 consecutive successes
- Minimum interval between switches: 30s

## CLI Commands
- `cargo run -p sgx-pa-cli -- transport-list --node nodeA`
- `cargo run -p sgx-pa-cli -- transport-stats --node nodeA`
- `cargo run -p sgx-pa-cli -- transport-show --node nodeA`
- `cargo run -p sgx-pa-cli -- transport-lock <interface-name> --node nodeA`
- `cargo run -p sgx-pa-cli -- transport-unlock --node nodeA`

## Transport Lock
- Lock file path: `/var/lib/sgx-guardian/cot/transport_lock_<node>.txt`
- The running node polls this file every 5 seconds.

## Mock Satellite Harness
- Setup: `./tests/mock_satellite.sh`
- Cleanup: `./tests/mock_satellite_cleanup.sh`
- Flap test: `./tests/satellite_flap.sh`

## Troubleshooting
- Missing interface in list:
  - Check `ip link`, `ip addr`, and ensure interface is UP with an IPv4 address.
- No failover observed:
  - Confirm active interface has 3 failed probes and at least one alternative is available.
- Stuck on wrong interface:
  - Check for active lock via `transport-show` and remove with `transport-unlock`.
- Satellite not detected:
  - For Ethernet-like Starlink adapters, set `SGX_SATELLITE_INTERFACES`.
