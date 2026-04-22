# Sprint 4 CoT Runbook (VMware)

## Goal
Validate interface-aware registration, hotplug handling, link monitoring, and failover behavior with two Ethernet interfaces (`ens33`, `ens37`).

## Prerequisites
- VMware guest with two NICs enabled.
- Build dependencies installed.
- Run as a user allowed to execute `cargo run` via `sudo`.

## Start Node
```bash
scripts/cot_vmware_failover_test.sh nodeA
```

Expected startup lines:
- `📡 Detected 2 network interfaces:`
- `🚛 Transport Registry: [ens33:Ethernet(...), ens37:Ethernet(...)]`
- `✅ Initial active transport: ...`

There should be no false baseline hotplug event such as `interface ens33 appeared` immediately at startup.

## Test Phases
1. Disconnect VMware Adapter 2 (`ens37`).
2. Confirm logs show `ens37` down while `ens33` remains up.
3. Ensure there is no `All transports down` while `ens33` is healthy.
4. Disconnect Adapter 1 (`ens33`) and verify failover to available alternative interface.
5. Reconnect `ens33` and wait for stable recovery + hysteresis; verify upgrade back.

## Useful Log Checks
```bash
grep -n 'Transport Registry' logs/cot_nodeA_*.log
grep -n 'All transports down' logs/cot_nodeA_*.log
grep -n 'Failover:' logs/cot_nodeA_*.log
grep -n 'Upgrade:' logs/cot_nodeA_*.log
grep -n 'Link monitor:' logs/cot_nodeA_*.log
```

## Admin CLI
List interfaces:
```bash
cargo run -p sgx-pa-cli -- transport list --node nodeA
```

Lock to specific interface:
```bash
cargo run -p sgx-pa-cli -- transport lock ens33 --node nodeA
```

Unlock automatic selection:
```bash
cargo run -p sgx-pa-cli -- transport unlock --node nodeA
```

Lock state file:
- `/var/lib/sgx-guardian/cot/transport_lock_<node>.txt`
