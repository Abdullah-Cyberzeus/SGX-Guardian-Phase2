# Dual Wifi Commit — File Change Report

**Commit:** `4cb6157e59e43db772224dce921a8b9b87fae3c0` — "Dual Wifi Testing in Progress"
**Branch (per initial session snapshot):** `wifi_testing` (`origin/wifi_testing`)
**Note:** The actual checked-out branch in this worktree (`/home/asad/SGX`) is currently `feat/112-116-emergency-addons`, not `wifi_testing`. Confirm which branch you're actually working on before merging.
**Scope:** `optional/container-cohort/*` and binary build artifacts (`build/*`, `.deb`) are **excluded** from this report — already confirmed separately, part of a different task.

---

## 1. Summary

| Category | Count |
|---|---|
| Total files touched by commit (incl. excluded scope) | 309 |
| **Excluding `optional/` and `build/`:** | |
| New files (Added) | 48 |
| Files with real content change (Modified) | 19 |
| Mode-only "fake modified" (chmod noise, zero content diff) | 189 |
| Deleted / Renamed | 0 / 0 |

---

## 2. New Files (48) — Genuine Dual-Wifi Task Work

### Network bridge module — `src/netbridge/` (13 files)
```
src/netbridge/bootstrap.rs
src/netbridge/config.rs
src/netbridge/dhcp_client.rs
src/netbridge/dhcp_dns.rs
src/netbridge/leases.rs
src/netbridge/mod.rs
src/netbridge/nat.rs
src/netbridge/process.rs
src/netbridge/routing.rs
src/netbridge/types.rs
src/netbridge/uplink_monitor.rs
src/netbridge/validator.rs
src/netbridge/wifi_client.rs
src/netbridge/wpa_config.rs
```

### Runtime/daemon module — `src/runtime/` (16 files)
```
src/runtime/config_store.rs
src/runtime/crypto.rs
src/runtime/daemon.rs
src/runtime/errors.rs
src/runtime/event_bus.rs
src/runtime/mod.rs
src/runtime/mode_controller.rs
src/runtime/models.rs
src/runtime/paths.rs
src/runtime/rockyou_top1000.txt   ⚠ see note below (legit, not risky)
src/runtime/runtime_api.rs
src/runtime/runtime_manager.rs
src/runtime/server.rs
src/runtime/state.rs
src/runtime/state_machine.rs
src/runtime/watchdog.rs
```

### Tests (13 files)
```
tests/test_enforcement_executor.rs
tests/test_netbridge_config.rs
tests/test_netbridge_dhcp_dns.rs
tests/test_netbridge_leases.rs
tests/test_netbridge_nat.rs
tests/test_netbridge_wifi_client.rs
tests/test_netbridge_wpa_config.rs
tests/test_runtime_config_store.rs
tests/test_runtime_crypto.rs
tests/test_runtime_manager.rs
tests/test_runtime_state_machine.rs
tests/test_wifi_api.rs
test_policy.rs   🚩 FLAGGED — see Red Flags section
```

### Config templates (3 files)
```
config/dnsmasq/dnsmasq.conf.template
config/hostapd/hostapd.conf.template
config/wpa_supplicant/wpa_supplicant.conf.template
```

### Docs (1 file)
```
docs/NETWORK_ORCHESTRATION.md
```

### Stray/unrelated (1 file)
```
scripts/__pycache__/verify_audit_chain.cpython-38.pyc   🚩 FLAGGED — see Red Flags section
```

**Note on `rockyou_top1000.txt`:** At first glance this looks suspicious (a password wordlist), but it was verified — it's legitimately loaded via `include_str!` in `src/runtime/crypto.rs:13` to reject hotspot wifi passwords found in a "common/weak password" list (`crypto.rs:104`). **This is a genuine security feature, not a risk.**

---

## 3. Modified Files (19) — Real Content Changes

| File | +/- | Note |
|---|---|---|
| `docs/REST API Details.md` | +4104 / -43 | New wifi/runtime API endpoints documented |
| `Cargo.lock` | +325 / -506 | Dependency graph reshuffle — verify before merge |
| `src/enforcement/translator.rs` | +275 / -32 | Genuine — wifi interface (wlan0/1/2) NAT/routing rules |
| `src/enforcement/validator.rs` | +245 / -2 | Genuine — interface & CIDR validation for masquerade rules (content verified) |
| `src/enforcement/executor.rs` | +136 / -33 | Genuine — enforcement execution wiring |
| `src/logging.rs` | +58 / -18 | Likely wiring for new runtime/netbridge logging |
| `src/enforcement/model.rs` | +38 / -2 | Genuine — rule model extended |
| `src/enforcement/mod.rs` | +36 / -19 | Genuine — module wiring |
| `src/main.rs` | +23 / -2 | Entry point wiring for new runtime daemon |
| `deny.toml` | +14 / -16 | 🚩 FLAGGED — see Red Flags section |
| `packaging/rpm/SPECS/sgx-guardian-client.spec` | +12 / -0 | Packaging update |
| `src/api/mod.rs` | +10 / -4 | API routes wiring |
| `.gitignore` | +3 / -0 | Adds `.env`, `ha-dev-config/` — good hygiene change |
| `packaging/deb/scripts/install_layout.sh` | +3 / -0 | Packaging update |
| `Cargo.toml` | +2 / -1 | Dependency declaration |
| `src/lib.rs` | +2 / -0 | Module export wiring |
| `src/policy_manager.rs` | +2 / -2 | Minor |
| `src/runtime_gates.rs` | +2 / -2 | Minor |
| `src/p2p_discovery.rs` | +0 / -1 | 🚩 FLAGGED — see Red Flags section |

---

## 4. Mode-only Changes (189 files) — Noise, No Action Needed

These files only show a permission-bit change (`100644` → `100755`, i.e. `chmod +x`), with **zero content diff**. It's spread across the entire repo (config files, docs, README, PDFs, `.github/workflows/*`, etc.) — it looks like someone ran a `chmod -R +x .`-type command over the whole working copy before committing. This is the exact "useless modified" tag you noticed. No review or merge risk here — content is identical.

---

## 5. 🚩 Red Flags — Unrelated to the Task / Useless / Risky

### 5.1 `test_policy.rs` (repo root) — **DEAD FILE, delete before merge**
- A scratch/debug script: `fn main()`, hardcoded `wlan2`/`wlan1` interfaces.
- Not in the `tests/` folder, and `Cargo.toml` has no `[[bin]]`/`[[example]]` entry referencing it.
- Cargo doesn't auto-build loose root-level `.rs` files — **this file isn't part of the build at all; it's 100% orphan/dead code.**
- **Why flagged:** Looks like someone's local manual-testing scratch file got committed by accident. No value in merging it, just clutter.

### 5.2 `scripts/__pycache__/verify_audit_chain.cpython-38.pyc` — **Accidental commit, remove**
- A compiled Python bytecode file — should never be committed to version control.
- **Why flagged:** Unrelated to the task; `__pycache__/` should have been in `.gitignore`, but this slipped in by accident.

### 5.3 `src/p2p_discovery.rs` — **Scope creep, unrelated to the task**
- Only a one-line change: a `println!` debug/log statement removed from the P2P/mDNS discovery module.
- **Why flagged:** Has no connection to the dual-wifi netbridge/runtime task — looks like a leftover from an unrelated cleanup that got mixed into this commit. Harmless by itself, but it contaminates the commit's scope (confusing for task tracking/review).

### 5.4 `deny.toml` — **Security/dependency policy change, verify before merging**
- The suppression for advisory `RUSTSEC-2025-0134` was removed (`ignore = [...]` → `ignore = []`). This means the advisory will now surface again in `cargo deny check`.
  - **Why flagged:** If that advisory isn't actually resolved yet, CI could fail after merge. Needs manual verification before merging.
- New crates added to the skip-list: `axum, axum-core, h2, http, http-body, hyper, matchit, tower-http, thiserror, base64`.
  - **Why flagged:** A new HTTP/API server stack was added (for `src/runtime/server.rs`). If the target branch already has a different `axum`/`hyper` version, this can create duplicate-version conflicts.

### 5.5 `Cargo.lock` — **Large reshuffle, verify at merge time**
- +325/-506 lines. Significant dependency version changes.
- **Why flagged:** At actual merge time, confirm no crate got downgraded or ended up incompatible with the target branch.

---

## 6. Recommendation (summary, no action taken yet)

1. `test_policy.rs` and `scripts/__pycache__/*.pyc` — worth dropping before merge (dead/junk).
2. `src/p2p_discovery.rs` — consider keeping in a separate commit if desired; it's outside dual-wifi scope.
3. `deny.toml`'s `RUSTSEC-2025-0134` removal — manually verify the advisory is actually resolved before merging.
4. `Cargo.lock` — review the dependency diff carefully at merge time.
5. Everything else (`netbridge/*`, `runtime/*`, `enforcement/*`, tests, config templates, docs) — verified as genuine dual-wifi task work, no red flags.
