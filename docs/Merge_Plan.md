# SG-X Guardian — Sprint 4 Multi-Hop Relay: COMPLETE Merge Plan (v2)

**Source:** `Multi_Hop_Relay.zip` (28 files, analyzed 2026-04-20)  
**Target Branch:** `main` (latest pull verified via project knowledge)  
**Correction:** v1 plan was incomplete — only 5 new files identified. This v2 covers ALL 23 modified + 5 new files with exact per-file instructions.

---

## Pre-Merge Checklist

```bash
# 1. Pull latest main
git pull origin main && git log --oneline -5

# 2. Confirm no relay files exist yet
ls src/nebula/ | grep -E "relay|stats|tunnel"
# Expected: nothing found

# 3. Baseline compile must be clean
cargo check 2>&1 | grep -E "^error" | wc -l
# Expected: 0
```

---

## Full Classification of All 28 ZIP Files

| ZIP File | Destination in Repo | Action |
|----------|---------------------|--------|
| `relay_registry.rs` | `src/nebula/relay_registry.rs` | **NEW FILE** |
| `relay_tc.rs` | `src/nebula/relay_tc.rs` | **NEW FILE** |
| `stats.rs` | `src/nebula/stats.rs` | **NEW FILE** |
| `tunnel_state.rs` | `src/nebula/tunnel_state.rs` | **NEW FILE** |
| `relay.rs` | `sgx-pa-cli/src/commands/relay.rs` | **NEW FILE** |
| `config (2).rs` | `src/nebula/config.rs` | **FULL REPLACE** |
| `lighthouse.rs` | `src/nebula/lighthouse.rs` | **FULL REPLACE** |
| `registry_sync.rs` | `src/nebula/registry_sync.rs` | **FULL REPLACE** |
| `metrics.rs` | `src/metrics.rs` | **FULL REPLACE** |
| `dynamic_config.rs` | `src/dynamic_config.rs` | **FULL REPLACE** |
| `p2p_discovery.rs` | `src/p2p_discovery.rs` | **FULL REPLACE** |
| `cert_client.rs` | `src/cert_client.rs` | **FULL REPLACE** |
| `cert_service.rs` | `src/cert_service.rs` | **FULL REPLACE** |
| `main (2).rs` | `src/bin/main.rs` | **FULL REPLACE** |
| `mod (2).rs` | `src/nebula/mod.rs` | **SURGICAL** — add 4 lines |
| `config_loader.rs` | `src/config_loader.rs` | **SURGICAL** — add RelayLimitsConfig |
| `config.rs` | `sgx-pa-cli/src/config.rs` | **SURGICAL** — add RelayConfig |
| `mod.rs` | `sgx-pa-cli/src/commands/mod.rs` | **SURGICAL** — add 1 line |
| `main.rs` | `sgx-pa-cli/src/main.rs` | **SURGICAL** — add relay commands |
| `status.rs` | `sgx-pa-cli/src/commands/status.rs` | **SURGICAL** — add relay display |
| `nodeA.yaml` | `config/nodeA.yaml` | **SURGICAL** — add relay block |
| `nodeB.yaml` | `config/nodeB.yaml` | **SURGICAL** — add relay block |
| `nodeC.yaml` | `config/nodeC.yaml` | **SURGICAL** — add relay block |
| `test_config_loader.rs` | `tests/test_config_loader.rs` | **SURGICAL** — add relay tests |
| `test_metrics.rs` | `tests/test_metrics.rs` | **SURGICAL** — add relay test |
| `attestation_service.rs` | `src/attestation_service.rs` | **DO NOT TOUCH** ✅ |

> **Attestation verdict:** ZIP's `attestation_service.rs` has zero relay references. The attestation challenge-response, PCR, DKP, and nonce logic is identical to main. The cert flow extensions (`cert_client.rs` / `cert_service.rs`) only ADD relay-role approval (`wants_relay`, `relay`/`lh_relay` in approval YAML) — they do NOT modify the attestation evidence or verification paths.

---

## PHASE 1 — New Files (Copy Directly, No Conflicts)

```bash
ZIP="/tmp/zip_extract/Multi_Hop_Relay"

# Step 1a — New nebula modules
cp "$ZIP/relay_registry.rs"  src/nebula/relay_registry.rs
cp "$ZIP/relay_tc.rs"        src/nebula/relay_tc.rs
cp "$ZIP/stats.rs"           src/nebula/stats.rs
cp "$ZIP/tunnel_state.rs"    src/nebula/tunnel_state.rs

# Step 1b — New CLI command module
cp "$ZIP/relay.rs"           sgx-pa-cli/src/commands/relay.rs
```

**Quick content summary of new files:**

- **`relay_registry.rs`** — `RelayRegistry` (HashMap of `RelayEntry`): add/remove/mark active-inactive/health_check_all via TCP + nebula0 ping. Persists to `relay_registry.json`.
- **`relay_tc.rs`** — `RelayTrafficControl`: wraps Linux `tc` HTB to apply/clear bandwidth limits on `nebula0`. Parses `tc -s class show` output.
- **`stats.rs`** — `NebulaStats`: GETs `http://127.0.0.1:8625/metrics` (Nebula Prometheus), parses relay bytes/tunnels/peers with multiple fallback metric names. Delta Mbps via static `LAST_SAMPLE`.
- **`tunnel_state.rs`** — `TunnelState`: reads Prometheus metrics to classify peers as direct vs relay. `detect_relay_usage()` async helper.
- **`relay.rs` (CLI)** — `RelayArgs/RelayCommand` (clap): `list`, `stats`, `set-limit`, `toggle`. Reads `relay_registry.json` for display; mutates node YAML `relay:` section via serde_yaml.

---

## PHASE 2 — Full Replacements (9 files)

> For each file: git-backup the original, then overwrite.

```bash
ZIP="/tmp/zip_extract/Multi_Hop_Relay"

# Backup originals first
for f in \
  src/nebula/config.rs \
  src/nebula/lighthouse.rs \
  src/nebula/registry_sync.rs \
  src/metrics.rs \
  src/dynamic_config.rs \
  src/p2p_discovery.rs \
  src/cert_client.rs \
  src/cert_service.rs; do
  cp "$f" "${f}.bak"
done
cp src/bin/main.rs src/bin/main.rs.bak
```

---

### FILE R1: `src/nebula/config.rs` ← `config (2).rs`

```bash
cp "$ZIP/config (2).rs" src/nebula/config.rs
```

**What changed vs main:**

| Area | Main Branch | ZIP Version |
|------|-------------|-------------|
| Imports | No relay import | Adds `use crate::nebula::relay_registry::RelayRegistry;` |
| `static_host_map` | From LH registry only | Also merges active entries from `relay_registry.json` (defensive fallback) |
| Relay section | Simple `am_relay=true/false` based on `is_lighthouse` | Complex: env var `SGX_FORCE_RELAY`, `/var/lib/sgx-guardian/nebula/am_relay` sentinel, `relay_role_for()`, dedicated relay priority over LH relay |
| `use_relays` logic | Simple boolean | `relay-only nodes do not chain via other relays` rule added |
| Prometheus stats | **MISSING** | Adds `stats:` block → `127.0.0.1:8625/metrics` |
| `env_bool()` helper | Missing | New private helper for `SGX_FORCE_RELAY` etc. |
| Tests | 6 tests | 13 tests including relay_section_decoupled, dedicated vs lh relay preference, relay-only-no-relay-via-relay |

**Critical net-new feature:** The `stats:` block in generated `nebula.yaml` enables Nebula's built-in Prometheus exporter at `127.0.0.1:8625` — this is what `src/nebula/stats.rs` reads. Without this block in the config, `NebulaStats::fetch()` always fails.

**Regression check:** `generate_config_from_pool_with_lighthouse()` signature unchanged. `generate_config_with_lighthouse()` signature unchanged. Existing callers in `main.rs` are unaffected.

---

### FILE R2: `src/nebula/lighthouse.rs` ← `lighthouse.rs`

```bash
cp "$ZIP/lighthouse.rs" src/nebula/lighthouse.rs
```

**What changed vs main:**

| Area | Main Branch | ZIP Version |
|------|-------------|-------------|
| `LighthouseEntry` struct | 5 fields | +2 fields: `is_lighthouse: bool` (`serde default=true`), `am_relay: bool` (`serde default=true`) |
| `new()` | Doesn't set new fields | Sets `is_lighthouse: true, am_relay: true` |
| `add_secondary()` | No duplicate guard per role | Checks `is_lighthouse` flag; upserts existing entries |
| New methods | None | `add_relay()`, `upsert_node()`, `upsert_endpoint_only()`, `set_relay_role()`, `set_lighthouse_role()`, `set_primary_lighthouse()`, `is_relay()`, `relay_role_for()`, `active_relays()` |
| `health_check_all()` | Missing | async: TCP check + nebula0 ping fallback, then `reconcile_primary_lighthouse()` |
| `reconcile_primary_lighthouse()` | Missing | Promotes first active lighthouse (lexical) if primary goes inactive |
| `summary()` | Basic | Includes relay node count |
| Tests | 6 tests | 12 tests including dual-role, health_check, relay-only, upsert_endpoint_only |

**Backward-compat note:** `#[serde(default = "default_true")]` on both new fields means existing `lighthouse_registry.json` files on boards deserialize cleanly — both fields default to `true`, so existing lighthouses continue acting as relay-capable nodes.

**Regression check:** `new()`, `add_secondary()`, `is_lighthouse()`, `active()`, `static_host_map_entries()`, `save()`, `load()`, `load_or_create()`, `summary()`, `update_endpoint()`, `mark_active()`, `mark_inactive()`, `primary_physical_endpoint()` all preserved with compatible signatures.

---

### FILE R3: `src/nebula/registry_sync.rs` ← `registry_sync.rs`

```bash
cp "$ZIP/registry_sync.rs" src/nebula/registry_sync.rs
```

**What changed vs main:**

| Area | Main Branch | ZIP Version |
|------|-------------|-------------|
| Imports | No relay import | `use crate::nebula::relay_registry::RelayRegistry;` |
| Constants | `REGISTRY_SYNC_PORT`, `REGISTRY_PATH`, `LIGHTHOUSE_REGISTRY_PATH`, `CACHE_PATH` | +`RELAY_REGISTRY_PATH = ".../relay_registry.json"` |
| `RegistryRequest.action` | `"assign" \| "query" \| "list" \| "snapshot" \| "snapshot_lh"` | +`"snapshot_relay"` |
| New functions | None | `apply_relay_snapshot(raw, path)` — validates + writes relay registry JSON; `pull_relay_snapshot_from_ca(ca_host)` — member pulls relay snapshot from nodeA |
| Server handler | Handles `snapshot_lh` | +handles `snapshot_relay` → reads and returns `RELAY_REGISTRY_PATH` |
| Tests | Existing tests | +`test_apply_relay_snapshot_rejects_control_response`, `test_apply_relay_snapshot_refuses_empty_overwrite` |

**Regression check:** All existing functions (`start_registry_server()`, `handle_registry_connection()`, `resolve_overlay_ip()`, `pull_snapshot_from_ca()`, `clear_local_ip_cache()`, etc.) are preserved with identical signatures.

---

### FILE R4: `src/metrics.rs` ← `metrics.rs`

```bash
cp "$ZIP/metrics.rs" src/metrics.rs
```

**What changed vs main:**

| Area | Main Branch | ZIP Version |
|------|-------------|-------------|
| `Metrics` struct | 5 fields | +9 relay fields (`relay_active_peers`, `relay_bytes_total`, `relay_current_mbps_x100`, `relay_limit_breaches_total`, `relay_max_peers`, `relay_max_bandwidth_mbps`, `relay_alert_threshold_pct`, `relay_direct_tunnels`, `relay_relay_tunnels`) |
| `Default` impl | 5 zero values | +9 relay zero/defaults |
| New methods | None | `set_relay_limits()`, `update_relay_stats()`, `record_relay_limit_breach()` |
| `MetricsSnapshot` struct | 5 fields | +9 relay fields |
| `snapshot()` | 5 fields | +9 relay fields |
| `to_prometheus()` | 5 metrics | +9 relay Prometheus metrics (`sgx_relay_active_peers`, `sgx_relay_bytes_total`, `sgx_relay_current_mbps`, etc.) |

**Note on `relay_current_mbps_x100`:** Fixed-point integer (Mbps × 100) to avoid storing `f64` in the struct. `to_prometheus()` renders it as `{:.2}` float divided by 100.

**Regression check:** All existing methods (`record_connection()`, `record_error()`, `set_policy_active()`, `record_enforcement_failure()`, `uptime()`, `snapshot()`, `to_prometheus()`) preserved. Additive only.

---

### FILE R5: `src/dynamic_config.rs` ← `dynamic_config.rs`

```bash
cp "$ZIP/dynamic_config.rs" src/dynamic_config.rs
```

**What changed vs main (V2 overhaul):**

The ZIP's header comment explicitly documents V2 changes:
- Startup broadcast from `main.rs` is removed (was causing failures when config had `127.0.0.1`)
- `p2p_discovery.rs` is the authoritative source for config sync when a real peer is discovered
- `broadcast_to_real_ip()` added for manual broadcast to a known real IP
- `overlay_is_reachable()` and `reachable_lighthouse_name()` helpers added (used by `p2p_discovery.rs` overlay gating)
- `is_routable_ip()` helper added

**Regression check:** `latest_known_ca_ip()` preserved. `broadcast_own_config_to_peers()` preserved. The change is in how `main.rs` calls these (startup broadcast removal is in `main (2).rs`).

---

### FILE R6: `src/p2p_discovery.rs` ← `p2p_discovery.rs`

```bash
cp "$ZIP/p2p_discovery.rs" src/p2p_discovery.rs
```

**What changed vs main:**

| Area | Main Branch | ZIP Version |
|------|-------------|-------------|
| Config paths | Relative only (`config/nodeA.yaml`) | **Absolute first** (`/etc/sgx-guardian/config/nodeA.yaml`), relative fallback — **this was the board bug** |
| mDNS usage | Was driving peer queue | **Log-only** — mDNS observation only, self-attestation loop eliminated |
| Overlay gating | Not present | Members gate discovery on `overlay_is_reachable()` — prevents stale attestation before Nebula is up |
| Peer reachability | Not checked before queueing | `peer_is_reachable()` TCP check before queuing a peer — prevents "discovered" logs for stopped nodes |
| Sim mode | Controlled by `SGX_SIM_MODE` env | Same, but skips non-routable IPs |
| Rate limiting | Not present | `last_sent` HashMap — 30-second minimum between re-queuing same peer |

**Regression check:** `P2PDiscovery::run(tx, node_id, logger)` signature unchanged. Internal logic fixed, not replaced. Zero impact on attestation service which only receives queued peer strings via the channel.

---

### FILE R7: `src/cert_client.rs` ← `cert_client.rs`

```bash
cp "$ZIP/cert_client.rs" src/cert_client.rs
```

**What changed vs main:**

| Area | Main Branch | ZIP Version |
|------|-------------|-------------|
| `try_request()` signature | `wants_lh: bool` | `wants_lh: bool, wants_relay: bool` |
| Request to CA | Sends `wants_lighthouse` | Also sends `wants_relay` |
| After approval | Saves cert only | Also: saves `relay_registry_json` from CA response, sets `am_relay` file sentinel via `sync_role_marker()`, calls `set_relay_enabled_in_node_config()` |
| New function | None | `set_relay_enabled_in_node_config()` — mutates node YAML to set `relay.enabled = true` |
| `sync_role_marker()` | None | Creates/removes `/var/lib/sgx-guardian/nebula/am_relay` file |
| Approval YAML hint | Shows `member \| lighthouse` options | Shows `member \| lighthouse \| relay \| lh_relay` options |

**Attestation integrity:** The cert request is separate from the attestation challenge-response. Attestation (PCR, DKP, nonce) is in `attestation_service.rs` which is unchanged. The cert client only handles Nebula certificate issuance, not device attestation.

---

### FILE R8: `src/cert_service.rs` ← `cert_service.rs`

```bash
cp "$ZIP/cert_service.rs" src/cert_service.rs
```

**What changed vs main:**

| Area | Main Branch | ZIP Version |
|------|-------------|-------------|
| Imports | No relay import | `use crate::nebula::relay_registry::RelayRegistry;` |
| `ApproveRole` enum | `member`, `lighthouse` | +`relay`, `lh_relay` variants |
| `relay_limits_for_node()` | Missing | Reads relay limits from node YAML |
| Request processing | Assigns `member` or `lighthouse` | Also assigns `relay`/`lh_relay`; reads `wants_relay` from request |
| Approval YAML | Shows 2 role options | Shows 4 role options including `relay`, `lh_relay` |
| Response | `signed_cert_pem`, `assigned_lighthouse` | +`assigned_relay: bool`, `relay_registry_json: String` |

**Attestation integrity:** Same comment as cert_client — cert issuance is separate from attestation evidence. The attestation service receives a nonce, signs PCR+DKP, and returns a quote. That flow is completely unmodified.

---

### FILE R9: `src/bin/main.rs` ← `main (2).rs`

```bash
cp "$ZIP/main (2).rs" src/bin/main.rs
```

**What changed vs main (relay-specific additions only):**

| Area | Main Branch | ZIP Version |
|------|-------------|-------------|
| `RELAY_SYNC_INTERVAL_SECS` const | Missing | `const RELAY_SYNC_INTERVAL_SECS: u64 = 10` |
| Approval YAML cleanup | Accepts `member \| lighthouse` | Also accepts `relay \| lh_relay` (removes incompatible old YAMLs) |
| Default node config YAML | No `relay:` section | Generates `relay: enabled: false, max_peers: 5, max_bandwidth_mbps: 10, alert_threshold_pct: 80` |
| `RelayLimitsConfig` loading | Missing | Loads per-node relay config at startup |
| `Metrics.set_relay_limits()` | Missing | Called with relay cfg values |
| Relay imports | None | `use sgx_guardian_client::nebula::relay_registry::RelayRegistry; use sgx_guardian_client::nebula::relay_tc::RelayTrafficControl;` |
| Cert bootstrap | `wants_lh` only | + `wants_relay` derived from `SGX_WANTS_RELAY` env var |
| Relay registry init | Missing | After Nebula starts: loads/creates `relay_registry.json`, registers self if `relay.enabled == true`, applies `tc` bandwidth limit |
| LH/relay change watcher | Watches only `lighthouse_registry.json` | Also watches `relay_registry.json` — reloads Nebula on either change |
| Relay health check loop | Missing | Every `RELAY_SYNC_INTERVAL_SECS`: loads relay registry, calls `health_check_all(2)`, saves |
| Member relay pull loop | Missing | Members pull `snapshot_relay` from CA every sync interval, call `apply_relay_snapshot()` |
| Relay stats loop | Missing | Every sync interval: calls `NebulaStats::fetch()`, updates `Metrics.update_relay_stats()`, saves to `relay_stats.json` |
| `json_equivalent()` helper | Missing | JSON-aware comparison to prevent Nebula restarts on insignificant whitespace changes |

**Attestation preserved:** `attestation_service::run()` call and all its arguments are identical. PCR measurement, secure boot chain, and attestation service startup are unmodified.

---

## PHASE 3 — Surgical Merges (10 files)

---

### FILE S1: `src/nebula/mod.rs`

→ **FIND:**
```rust
pub mod registry_sync;
pub mod utils;
```

→ **REPLACE WITH:**
```rust
pub mod registry_sync;
pub mod relay_registry;
pub mod relay_tc;
pub mod stats;
pub mod tunnel_state;
pub mod utils;
```

---

### FILE S2: `src/config_loader.rs`

→ **FIND (after the MetricsConfig struct closing brace):**
```rust
#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    pub metrics: Option<MetricsConfig>,
}
```

→ **REPLACE WITH:**
```rust
#[derive(Debug, Deserialize, Clone)]
pub struct RelayLimitsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_relay_max_peers")]
    pub max_peers: u32,
    #[serde(default = "default_relay_max_bandwidth_mbps")]
    pub max_bandwidth_mbps: u32,
    #[serde(default = "default_relay_alert_threshold_pct")]
    pub alert_threshold_pct: u8,
}

fn default_relay_max_peers() -> u32 { 5 }
fn default_relay_max_bandwidth_mbps() -> u32 { 10 }
fn default_relay_alert_threshold_pct() -> u8 { 80 }

impl Default for RelayLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_peers: default_relay_max_peers(),
            max_bandwidth_mbps: default_relay_max_bandwidth_mbps(),
            alert_threshold_pct: default_relay_alert_threshold_pct(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    pub metrics: Option<MetricsConfig>,
    pub relay: Option<RelayLimitsConfig>,
}
```

Then inside `impl NodeConfig` → **FIND** the end of `validate()`:
```rust
        Ok(())
    }
}
```

→ **REPLACE WITH:**
```rust
        if let Some(relay) = &self.relay {
            if relay.alert_threshold_pct > 100 {
                return Err(format!(
                    "relay.alert_threshold_pct must be 0-100, got {}",
                    relay.alert_threshold_pct
                ));
            }
            if relay.max_peers == 0 {
                return Err("relay.max_peers cannot be 0".into());
            }
        }
        Ok(())
    }

    pub fn relay_or_default(&self) -> RelayLimitsConfig {
        self.relay.clone().unwrap_or_default()
    }
}
```

---

### FILE S3: `sgx-pa-cli/src/config.rs`

→ **FIND:**
```rust
#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
}
```

→ **REPLACE WITH:**
```rust
#[derive(Debug, Deserialize)]
pub struct RelayConfig {
    pub enabled: bool,
    pub max_peers: u32,
    pub max_bandwidth_mbps: u32,
    pub alert_threshold_pct: u8,
}

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    pub relay: Option<RelayConfig>,
}
```

---

### FILE S4: `sgx-pa-cli/src/commands/mod.rs`

→ **FIND:**
```rust
pub mod peers;
pub mod sign;
```

→ **REPLACE WITH:**
```rust
pub mod peers;
pub mod relay;
pub mod sign;
```

---

### FILE S5: `sgx-pa-cli/src/main.rs`

⚠️ Main branch has `AttestGenerate` + `AttestVerify` commands. ZIP's `main.rs` does NOT have them. Surgical only — do NOT overwrite.

**Step A** — Add relay variants to `enum Commands` (before closing `}`):

→ **FIND:**
```rust
    /// Verify current PCR values against golden baseline
    PcrBaselineVerify,
}
```

→ **REPLACE WITH:**
```rust
    /// Verify current PCR values against golden baseline
    PcrBaselineVerify,
    /// Relay management commands (subcommand router)
    Relay(commands::relay::RelayArgs),
    /// List relay nodes from registry
    RelayList,
    /// Show relay stats for a specific node
    RelayStats(commands::relay::RelayStatsArgs),
    /// Set relay bandwidth/peer limits for a node
    RelaySetLimit(commands::relay::RelaySetLimitArgs),
    /// Enable or disable relay for a node
    RelayToggle(commands::relay::RelayToggleArgs),
}
```

**Step B** — Add relay match arms in `fn main()` (before closing `}`):

→ **FIND:**
```rust
        Commands::PcrBaselineCreate => commands::pcr_baseline::run_create(),
        Commands::PcrBaselineVerify => commands::pcr_baseline::run_verify(),
    }
}
```

→ **REPLACE WITH:**
```rust
        Commands::PcrBaselineCreate => commands::pcr_baseline::run_create(),
        Commands::PcrBaselineVerify => commands::pcr_baseline::run_verify(),
        Commands::Relay(args) => {
            if let Err(e) = commands::relay::run(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::RelayList => {
            if let Err(e) = commands::relay::run_list() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::RelayStats(args) => {
            if let Err(e) = commands::relay::run_stats(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::RelaySetLimit(args) => {
            if let Err(e) = commands::relay::run_set_limit(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::RelayToggle(args) => {
            if let Err(e) = commands::relay::run_toggle(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
```

---

### FILE S6: `sgx-pa-cli/src/commands/status.rs`

→ **FIND** (at end of `run()`, after the main `println!`):
```rust
    println!(
        " - ID: {}\n - Hostname: {}\n - IP: {}\n - Port: {}\n - Public Key: {}",
        node_config.node_id,
        node_config.hostname,
        node_config.ip,
        node_config.port,
        node_config.public_key
    );
}
```

→ **REPLACE WITH:**
```rust
    println!(
        " - ID: {}\n - Hostname: {}\n - IP: {}\n - Port: {}\n - Public Key: {}",
        node_config.node_id,
        node_config.hostname,
        node_config.ip,
        node_config.port,
        node_config.public_key
    );
    if let Some(relay) = node_config.relay {
        println!(
            " - Relay: enabled={}, max_peers={}, max_bw={} Mbps, alert={}%",
            relay.enabled, relay.max_peers, relay.max_bandwidth_mbps, relay.alert_threshold_pct
        );
    }
}
```

---

### FILE S7: `config/nodeA.yaml`, `config/nodeB.yaml`, `config/nodeC.yaml`

Add `relay:` section before the `secure_element:` block in each file:

```yaml
relay:
  enabled: false
  max_peers: 5
  max_bandwidth_mbps: 10
  alert_threshold_pct: 80
```

Final YAML structure for each node:
```yaml
---
node_id: "nodeA"          # (or nodeB / nodeC)
hostname: "guardian-node-A"
ip: "127.0.0.1"
port: 50051
public_key: "placeholder-key-A"

relay:
  enabled: false
  max_peers: 5
  max_bandwidth_mbps: 10
  alert_threshold_pct: 80

secure_element:
  enabled: true
  scp_key_path: "~/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt"
  interface: "t1oi2c"
  auth_type: "PlatformSCP"
  connection_type: "se05x"
```

---

### FILE S8: `tests/test_config_loader.rs`

Append to the end of the existing test file:

```rust
#[test]
fn test_node_config_parses_relay_limits() {
    let yaml = r#"
node_id: nodeB
hostname: relay-node
ip: 10.0.0.2
port: 50052
public_key: "PUBKEY456"
relay:
  enabled: true
  max_peers: 9
  max_bandwidth_mbps: 25
  alert_threshold_pct: 70
"#;
    let p = write_temp_config("relay_cfg", yaml);
    let cfg = load_config(&p).expect("relay config should parse");
    let relay = cfg.relay.expect("relay section should exist");
    assert!(relay.enabled);
    assert_eq!(relay.max_peers, 9);
    assert_eq!(relay.max_bandwidth_mbps, 25);
    assert_eq!(relay.alert_threshold_pct, 70);
    let _ = fs::remove_file(&p);
}

#[test]
fn test_default_relay_limits() {
    let yaml = r#"
node_id: nodeC
hostname: relay-node
ip: 10.0.0.3
port: 50053
public_key: "PUBKEY789"
"#;
    let p = write_temp_config("relay_defaults", yaml);
    let cfg = load_config(&p).expect("config should parse without relay section");
    let relay = cfg.relay_or_default();
    assert!(!relay.enabled);
    assert_eq!(relay.max_peers, 5);
    assert_eq!(relay.max_bandwidth_mbps, 10);
    assert_eq!(relay.alert_threshold_pct, 80);
    let _ = fs::remove_file(&p);
}
```

---

### FILE S9: `tests/test_metrics.rs`

Append to the end of the existing test file:

```rust
#[test]
fn test_metrics_relay_prometheus_fields() {
    let mut m = Metrics::default();
    m.set_relay_limits(7, 15, 85);
    m.update_relay_stats(2, 1024, 3.5, 1, 1);
    m.record_relay_limit_breach();

    let s = m.snapshot().to_prometheus();
    assert!(s.contains("sgx_relay_active_peers 2"));
    assert!(s.contains("sgx_relay_bytes_total 1024"));
    assert!(s.contains("sgx_relay_limit_breaches_total 1"));
    assert!(s.contains("sgx_relay_max_peers 7"));
    assert!(s.contains("sgx_relay_max_bandwidth_mbps 15"));
}
```

---

## PHASE 4 — Cargo.toml Dependency Checks

```bash
# Check lib crate (src/) Cargo.toml
grep -E "reqwest|chrono|once_cell" Cargo.toml

# Check CLI crate Cargo.toml
grep -E "anyhow|comfy-table|serde_yaml" sgx-pa-cli/Cargo.toml
```

If any are missing, add to the respective `[dependencies]`:

**`Cargo.toml` (lib/daemon):**
```toml
reqwest  = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
chrono   = { version = "0.4", features = ["serde"] }
once_cell = "1"
```

**`sgx-pa-cli/Cargo.toml`:**
```toml
anyhow       = "1"
comfy-table  = "7"
serde_yaml   = "0.9"
```

---

## PHASE 5 — Build & Test Sequence

Run in strict order — stop and fix before proceeding:

```bash
# Step 1 — Type-check lib crate
cargo check -p sgx-guardian-client 2>&1 | grep "^error"

# Step 2 — Type-check CLI crate
cargo check -p sgx-pa-cli 2>&1 | grep "^error"

# Step 3 — Full release build
cargo build --release 2>&1 | tail -20

# Step 4 — All unit tests
cargo test 2>&1 | tail -40

# Step 5 — Critical: attestation tests must still pass
cargo test attestation 2>&1
cargo test p2p        2>&1

# Step 6 — New relay module tests
cargo test relay      2>&1
cargo test tc_stats   2>&1
cargo test prometheus 2>&1
cargo test lighthouse 2>&1

# Step 7 — CLI relay command smoke test
./target/release/sgx-pa-cli relay list
./target/release/sgx-pa-cli relay-list
./target/release/sgx-pa-cli relay toggle nodeA --help
./target/release/sgx-pa-cli attest-generate --help   # Must still exist
./target/release/sgx-pa-cli attest-verify --help     # Must still exist
```

---

## PHASE 6 — Board Deployment

```bash
# Cross-compile for ARM64 (i.MX8MP)
cargo build --release --target aarch64-unknown-linux-gnu

# Deploy to all three boards
for BOARD in 192.168.50.101 192.168.50.115 192.168.50.248; do
  scp target/aarch64-unknown-linux-gnu/release/sgx-guardian-client root@$BOARD:/usr/local/bin/
  scp target/aarch64-unknown-linux-gnu/release/sgx-pa-cli root@$BOARD:/usr/local/bin/
done

# Copy updated node configs
scp config/nodeA.yaml root@192.168.50.101:/etc/sgx-guardian/config/
scp config/nodeB.yaml root@192.168.50.115:/etc/sgx-guardian/config/
scp config/nodeC.yaml root@192.168.50.248:/etc/sgx-guardian/config/

# Restart and verify relay list on each board
for BOARD in 192.168.50.101 192.168.50.115 192.168.50.248; do
  ssh root@$BOARD "systemctl restart sgx-guardian && sgx-pa-cli relay list"
done
```

---

## New CLI Commands After Merge

| Command | Description |
|---------|-------------|
| `sgx-pa-cli relay list` | List all relay nodes from registry |
| `sgx-pa-cli relay-list` | Alias |
| `sgx-pa-cli relay stats nodeB` | Show Prometheus-sourced stats for nodeB |
| `sgx-pa-cli relay set-limit nodeB --max-peers 10 --max-bandwidth-mbps 20` | Update relay limits in node YAML |
| `sgx-pa-cli relay toggle nodeA --enable` | Enable relay in node YAML |
| `sgx-pa-cli relay toggle nodeA --disable` | Disable relay |
| `sgx-pa-cli status --node nodeB` | Now also shows relay config if present |

---

## Approval Role Reference (Updated Cert Flow)

After this merge, the cert approval YAML on nodeA supports:

```yaml
# config/requests/<node>.yaml
approve: member      # standard peer
approve: lighthouse  # peer acts as lighthouse
approve: relay       # peer acts as dedicated relay (not lighthouse)
approve: lh_relay    # peer acts as both lighthouse + relay
approve: reject      # deny
```

---

## Scope Boundary (What the ZIP Does NOT Build)

These are Nebula-internal and cannot be built by the SG-X team:

- Multi-hop packet forwarding engine
- Relay path selection algorithm
- Double-encryption of relayed packets

The SG-X layer handles: relay role declaration, bandwidth enforcement via `tc HTB`, relay registry tracking, Prometheus observability, and admin CLI. Nebula binary handles actual routing.

---

*End of Complete Merge Plan v2 — All 28 ZIP files accounted for*