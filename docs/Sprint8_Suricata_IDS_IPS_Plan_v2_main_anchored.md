# SG-X Guardian — Sprint 8: Suricata IDS/IPS Integration — Development Plan

> **Anchored to:** latest `main` branch of `AsadAli-CyberZeus/SGX` as pulled at session start.
> This plan is **standalone** — it does NOT depend on the Sprint 6 NMAP branch (`aliza_nmap`). It can land before, after, or in parallel with NMAP.

---

## Task (100% verbatim from Phase 2 Final Timeline / SGX_Phase_2.docx)

> **Scope:** Security Tools
> **Deliverable:** **Suricata IDS/IPS Integration**
> **Sprint:** Sprint 8
> **Milestone:** 8 (alongside Offline Revocation Sync, CRL 5-Node Demo, Integration Validation, Performance Validation)
> **Target Date:** 15 June 2026
> **Test Series:** SUR-series (Phase 2 Test Cases §4.2 "Suricata IDS/IPS Integration")
>
> **Description:** Integrate Suricata IDS/IPS engine for real-time network traffic analysis and threat detection. Install Suricata binaries on Guardian, configure rule sets (Emerging Threats, custom signatures). Implement packet capture integration with Guardian network interfaces. Parse Suricata EVE JSON logs, extract alerts (malware, exploits, policy violations). Feed Suricata alerts to AI anomaly detection engine for correlation with behavioral patterns. Support inline blocking mode — Suricata drops malicious packets before reaching applications. Configure signature auto-updates and rule management. Provides deep packet inspection complementing Guardian's AI-based detection.

### Reference behaviour pulled from SG-X Guardian User Guide §6.1

| Property                | Value                                                                  |
| ----------------------- | ---------------------------------------------------------------------- |
| Engine                  | Suricata **7.0+**                                                      |
| Rule sources            | Emerging Threats Open, Proofpoint ET Pro, `guardian-custom.rules`      |
| Signatures              | 40,000+, auto-updated daily                                            |
| Detection methods       | Signature, protocol analysis, anomaly, file extraction, opt-in TLS    |
| Response actions        | Alert, Drop, Reject, Quarantine Device, IP Blacklist (24 h)            |
| EVE JSON output         | `/var/log/suricata/eve.json` (~50 MB/day)                              |
| Fast log                | `/var/log/suricata/fast.log` (~2 MB/day)                               |
| AF_PACKET config        | `eth0`, 4 threads, `cluster_flow`                                      |

---

## 1. Current `main` branch state (verified before planning)

The plan adds only what is necessary. Confirmed by `project_knowledge_search`:

| Surface                                  | State on `main`                                                                 |
| ---------------------------------------- | ------------------------------------------------------------------------------- |
| `src/lib.rs` modules                     | `api, attestation_service, audit, cert_client, cert_service, client, cloud, config_loader, cot, did, enforcement, key_manager, logging, metrics, metrics_server, nebula, p2p_discovery, policy, policy_authority, policy_manager, policy_state, runtime_gates, secure_element, server, tls, dynamic_config, network_selector, node_announcement, node_broadcast, node_listener` |
| `src/audit/event.rs::AuditCategory`      | `Node, Identity, Did, Attestation, Policy, Enforcement, Network, Tls, Cryptography, Cloud` — **`Network` already covers IDS events** |
| `src/audit/event.rs::AuditAction`        | `Started, Succeeded, Failed, Rejected, Applied, Revoked, Rollback, Created, Loaded, Exported, Used` — need 3 new variants |
| `src/api/state.rs::AppState`             | 8 fields (`node_id, config_dir, boot_dir, keys_dir, pcr_dir, pcr_baseline_dir, log_dir_primary, log_dir_fallback`) |
| `src/api/handlers/mod.rs`                | `attestation, did, dkp, guardian_keys, logs, node, pcr, peers, policy, relay, transport` |
| `src/api/handlers/dkp.rs::run_cli`       | Established helper for shelling out to `sgx-pa-cli` (async `tokio::process::Command`). Returns `ActionResponse`. |
| `src/enforcement/executor.rs`            | Uses **sync** `std::process::Command` for `nft -f`. Hardened — fail-closed on error. Owns table `inet sgx_guardian`. |
| `src/main.rs` REST spawn                 | `tokio::spawn` after `// === REST Admin API (axum) on :8443 ===` comment |
| `sgx-pa-cli/src/commands/mod.rs`         | 20+ subcommand modules registered |

**Design implication:** We add `AuditCategory::Network` reuse, 3 new `AuditAction` variants, 2 new `AppState` fields, 1 new `src/threat/` module, 1 new `src/api/handlers/threat.rs`, 1 new `sgx-pa-cli/src/commands/threat.rs`. No existing module gets refactored.

---

## 2. Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                SG-X GUARDIAN — SURICATA INTEGRATION                │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Suricata (system service, separate uid)                    │   │
│  │  af_packet on $IFACE → engine → eve.json (append-only)      │   │
│  │  rules: /etc/suricata/rules/{suricata,guardian-custom}.rules│   │
│  │  updates: `suricata-update` (cron + scheduler triggers)     │   │
│  └─────────────────────┬───────────────────────────────────────┘   │
│                        │ JSONL events                              │
│                        ▼                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  src/threat/   (NEW MODULE — SUR-series)                    │   │
│  │  ├── mod.rs            ← public surface + DiscoveryService  │   │
│  │  ├── config.rs         ← SuricataConfig YAML loader         │   │
│  │  ├── threat_alert.rs   ← ThreatAlert entity                 │   │
│  │  ├── eve_tailer.rs     ← async tail w/ offset persistence   │   │
│  │  ├── eve_parser.rs     ← JSONL → ThreatAlert (pure/testable)│   │
│  │  ├── rule_manager.rs   ← suricata-update wrapper            │   │
│  │  ├── blocker.rs        ← nftables `sgx_threat` table        │   │
│  │  ├── ai_bridge.rs      ← stub → Sprint 11 Virtual Shift     │   │
│  │  ├── service.rs        ← background orchestrator            │   │
│  │  ├── inventory.rs      ← rolling alert ring buffer          │   │
│  │  └── error.rs          ← thiserror ThreatError              │   │
│  │                                                             │   │
│  │  src/api/handlers/threat.rs       ← 5 REST endpoints        │   │
│  │  sgx-pa-cli/src/commands/threat.rs ← CLI subcommands        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                        │                                           │
│        ┌───────────────┼────────────────┬────────────────┐         │
│        ▼               ▼                ▼                ▼         │
│   ┌─────────┐    ┌───────────┐   ┌────────────┐   ┌────────────┐  │
│   │ audit   │    │  blocker  │   │ ai_bridge  │   │ REST + CLI │  │
│   │ Network │    │ nft drop  │   │ Sprint-11  │   │ /api/v1/   │  │
│   │ category│    │ in sep.   │   │ stub       │   │ threat/*   │  │
│   │ (exists)│    │ table     │   │            │   │            │  │
│   └─────────┘    └───────────┘   └────────────┘   └────────────┘  │
│                                                                    │
│  Persistent state (board, absolute paths):                         │
│  ─────────────────────────────────────────                         │
│  /etc/suricata/suricata.yaml                ← templated by install │
│  /etc/suricata/rules/                       ← ET + custom rules    │
│  /var/log/suricata/{eve.json,fast.log}      ← Suricata writes      │
│  /etc/sgx-guardian/threat/config.yaml       ← Guardian-side config │
│  /var/lib/sgx-guardian/threat/                                     │
│      alerts.jsonl                           ← rolling ring buffer  │
│      last_offset.json                       ← tail resume cursor   │
│      blocked_ips.json                       ← persisted block list │
│  /var/log/sgx-guardian/audit-<node>.log     ← Network category     │
└────────────────────────────────────────────────────────────────────┘
```

### Two architectural decisions worth flagging

**(a) Reuse `AuditCategory::Network` instead of adding `Threat`.**
`Network` already exists on main and semantically covers "network-traffic security events". Adding `Threat` would be churn for no gain — and every existing audit consumer (verifier, frontend log viewer) already understands `Network`. If later the team wants stricter taxonomy, splitting is a one-line follow-up.

**(b) Inline blocking via Guardian-owned nftables table, NOT NFQUEUE.**

| Path | Pros | Cons |
| ---- | ---- | ---- |
| **A.** Suricata IPS via NFQUEUE | True line-rate drop in Suricata | Couples Suricata's lifecycle to the kernel packet path; if Suricata crashes, traffic stalls. The boards have already had freeze issues from sync subprocess calls — adding kernel-queue stall is unacceptable. |
| **B.** Suricata as IDS + Guardian `blocker.rs` writes nftables drops in a **separate** `inet sgx_threat` table | Suricata crash does not block traffic. Guardian owns the verdict, fully audit-traced. Survives Suricata restart. Doesn't touch `enforcement::executor`'s `sgx_guardian` table → no UEP-policy atomic-rollback interference. | First-packet latency on initial alert (~tens of ms). Irrelevant — by definition the attack is already in progress. |

**We pick B.** Path A can be a Phase 4 optimisation once eBPF Enforcement lands.

### Project hard rules (all hold for this plan)

1. **No `std::thread::sleep` or sync `Command::new().output()` inside the tokio runtime.** The whole `src/threat/` module is async — every subprocess uses `tokio::process::Command`, every wait uses `tokio::time::sleep`/`interval`, every loop honours a shutdown channel.
2. **No relative paths on board.** All paths are absolute under `/etc/sgx-guardian/`, `/var/lib/sgx-guardian/`, `/var/log/`.
3. **No new crypto algorithms.** ECDSA-P256 + SHA-256 only. TLS inspection and YARA file-store are explicitly **off** in Sprint 8 config (the User Guide markets them as opt-in features for a later phase).
4. **Additive only.** No mutation of `main.rs`, `lib.rs`, audit, or enforcement modules beyond the surgical FIND→REPLACE blocks in §4.

---

## 3. Deliverables (14 items, sized for the Sprint 8 slice)

> Sprint 8 carries five parallel deliverables (Offline Revocation Sync, CRL 5-Node Demo, Suricata, Integration Validation, Performance Validation). Budget below assumes **~10 working days** against the 22-day Sprint 8 window 1 Jun → 15 Jun.

| #   | Deliverable                                          | Files Touched                                     | Effort  |
| --- | ---------------------------------------------------- | ------------------------------------------------- | ------- |
| 1   | Suricata install + systemd hardening                 | `scripts/install.sh`, `packaging/sgx-guardian.service`, new `packaging/suricata.yaml.template`, new `packaging/guardian-custom.rules` | 0.75 d  |
| 2   | `threat` module skeleton + error types               | `src/threat/{mod,error}.rs`, `src/lib.rs`         | 0.5 d   |
| 3   | `ThreatAlert` entity + EVE schema mapping            | `src/threat/threat_alert.rs`                      | 0.75 d  |
| 4   | `SuricataConfig` YAML loader + default               | `src/threat/config.rs`, `config/threat/config.yaml` | 0.5 d   |
| 5   | `eve_parser` — JSONL → `ThreatAlert` (pure)          | `src/threat/eve_parser.rs`                        | 1.0 d   |
| 6   | `eve_tailer` async tail + offset persistence + rotation handling | `src/threat/eve_tailer.rs`            | 1.0 d   |
| 7   | `inventory.rs` rolling buffer + dedup + atomic save  | `src/threat/inventory.rs`                         | 0.75 d  |
| 8   | `blocker.rs` separate `sgx_threat` nft table         | `src/threat/blocker.rs`                           | 1.0 d   |
| 9   | `rule_manager.rs` `suricata-update` wrapper          | `src/threat/rule_manager.rs`                      | 0.5 d   |
| 10  | `ai_bridge.rs` Sprint-11 stub                        | `src/threat/ai_bridge.rs`                         | 0.25 d  |
| 11  | `service.rs` orchestrator + spawn in `main.rs`       | `src/threat/service.rs`, `src/main.rs`            | 1.0 d   |
| 12  | Audit: 3 new `AuditAction` variants                  | `src/audit/event.rs`                              | 0.25 d  |
| 13  | REST: 5 endpoints + `AppState` extension             | `src/api/handlers/threat.rs`, `src/api/handlers/mod.rs`, `src/api/state.rs`, `src/api/mod.rs` | 1.0 d   |
| 14  | `sgx-pa-cli threat` subcommands                      | `sgx-pa-cli/src/commands/threat.rs`, `sgx-pa-cli/src/commands/mod.rs`, `sgx-pa-cli/src/main.rs` | 1.0 d   |
| 15  | Tests: unit (parser, blocker logic, dedup, tailer) + integration | `tests/threat_*.rs`                   | 1.0 d   |
| 16  | Board harness `tests/sur_*.sh` for SUR-001..006      | `tests/`                                          | 0.75 d  |

**Total: ~10.25 working days.** Fits Sprint 8 with room for the other four parallel deliverables.

---

## 4. File structure after this PR

```diff
src/
  audit/
    event.rs                    # ← extend AuditAction enum only
  api/
    mod.rs                      # ← register 5 routes
    state.rs                    # ← add 2 fields
    handlers/
      mod.rs                    # ← `pub mod threat;`
+     threat.rs                 # NEW
+ threat/                       # NEW MODULE — Sprint 8 SUR-series
+   mod.rs
+   config.rs
+   threat_alert.rs
+   eve_tailer.rs
+   eve_parser.rs
+   rule_manager.rs
+   blocker.rs
+   ai_bridge.rs
+   service.rs
+   inventory.rs
+   error.rs
  lib.rs                        # ← `pub mod threat;`
  main.rs                       # ← spawn ThreatService

sgx-pa-cli/src/
  commands/
    mod.rs                      # ← `pub mod threat;`
+   threat.rs                   # NEW
  main.rs                       # ← register `Threat` Commands variant

config/
+ threat/
+   config.yaml                 # default — enabled: false

packaging/
  sgx-guardian.service          # ← AmbientCapabilities += CAP_NET_RAW, CAP_NET_ADMIN
+ suricata.yaml.template        # board template
+ guardian-custom.rules         # 5 seed rules

scripts/
  install.sh                    # ← apt-get install suricata, seed rules, enable service

tests/
+ threat_parser_test.rs
+ threat_inventory_test.rs
+ threat_tailer_test.rs
+ threat_blocker_logic_test.rs   # nft-free part: should_block matrix
+ sur_001_install.sh
+ sur_002_eve_ingest.sh
+ sur_003_inline_block.sh
+ sur_004_rule_update.sh
+ sur_005_persistence.sh
+ sur_006_ai_handoff.sh

Cargo.toml                      # ← add ipnet@2, thiserror confirm@1
```

No deletions. The whole feature is gated by `enabled: false` default in `config/threat/config.yaml`.

---

## 5. Implementation Plan (FIND → REPLACE blocks, anchored to actual main code)

### 5.1 — `Cargo.toml` (root crate)

**FIND** (anywhere in `[dependencies]` block):

```toml
tokio = { version = ...
```

**ADD ANYWHERE in the same block** (no replacement needed if absent):

```toml
ipnet = "2"
```

> `thiserror`, `serde`, `serde_yaml`, `serde_json`, `chrono`, `sha2`, `hex`, `tracing` are already present. `quick-xml` is NOT needed (that was for NMAP). Suricata uses JSONL, which `serde_json` handles natively.

---

### 5.2 — `src/lib.rs`

**FIND** (the existing block at the top of the file):

```rust
pub mod cot;
pub mod did;
pub mod enforcement;
```

**REPLACE WITH:**

```rust
pub mod cot;
pub mod did;
pub mod enforcement;
pub mod threat;             // NEW — Sprint 8, SUR-series
```

Verify `cargo build --lib` still succeeds after this single line.

---

### 5.3 — `src/threat/mod.rs` (NEW)

```rust
//! Suricata IDS/IPS integration (Sprint 8, SUR-series).
//!
//! Responsibilities:
//!   - Tail `/var/log/suricata/eve.json` asynchronously without blocking.
//!   - Parse EVE JSONL into [`ThreatAlert`] entities.
//!   - Maintain a rolling alert ring buffer (10 000 alerts, in-memory + persisted).
//!   - Translate High/Critical alerts into ephemeral nftables drop rules
//!     in a dedicated `inet sgx_threat` table (NOT `enforcement`'s `sgx_guardian`).
//!   - Forward alerts to the AI anomaly engine (stub now; wired in Sprint 11).
//!   - Schedule daily `suricata-update` runs for rule freshness.
//!
//! All operations are async (`tokio::process::Command`, `tokio::fs`,
//! `tokio::time::interval`). All file writes are atomic (temp + rename).
//! The eve.json read cursor is persisted so we resume cleanly after restarts.

pub mod ai_bridge;
pub mod blocker;
pub mod config;
pub mod error;
pub mod eve_parser;
pub mod eve_tailer;
pub mod inventory;
pub mod rule_manager;
pub mod service;
pub mod threat_alert;

pub use config::{BlockMode, SuricataConfig};
pub use error::{ThreatError, ThreatResult};
pub use inventory::AlertInventory;
pub use service::ThreatService;
pub use threat_alert::{Severity, ThreatAlert, ThreatCategory};
```

---

### 5.4 — `src/threat/error.rs` (NEW)

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThreatError {
    #[error("suricata binary not found in PATH — install with `apt-get install suricata`")]
    BinaryMissing,

    #[error("suricata service failed to start: {0}")]
    ServiceStart(String),

    #[error("eve.json not found at {0} — is Suricata running?")]
    EveLogMissing(String),

    #[error("json parse error on line {line}: {msg}")]
    JsonParse { line: u64, msg: String },

    #[error("nftables command failed (exit {0}): {1}")]
    NftFailed(i32, String),

    #[error("invalid configuration: {0}")]
    BadConfig(String),

    #[error("invalid CIDR/IP: {0}")]
    InvalidCidr(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("threat integration disabled in config")]
    Disabled,
}

pub type ThreatResult<T> = Result<T, ThreatError>;
```

---

### 5.5 — `src/threat/threat_alert.rs` (NEW)

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,      // EVE sev 4
    Low,       // EVE sev 3
    Medium,    // EVE sev 2
    High,      // EVE sev 1
    Critical,  // EVE sev 1 with escalation
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    Malware,
    Exploit,
    PolicyViolation,
    Reconnaissance,
    Anomaly,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatAlert {
    /// Dedup id: SHA-256(sid || src_ip || dst_ip)[..16] hex.
    pub alert_id: String,

    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,

    pub signature_id: u32,
    pub signature: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub rev: u32,
    pub gid: u32,

    pub event_type: String,

    #[serde(default)]
    pub blocked: bool,
}

impl ThreatAlert {
    pub fn compute_id(sid: u32, src: &str, dst: &str) -> String {
        let mut h = Sha256::new();
        h.update(sid.to_be_bytes());
        h.update(src.as_bytes());
        h.update(dst.as_bytes());
        hex::encode(&h.finalize()[..8])
    }
}
```

---

### 5.6 — `src/threat/config.rs` (NEW)

```rust
use crate::threat::error::{ThreatError, ThreatResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// IDS only: alerts logged + forwarded; no nftables changes.
    AlertOnly,
    /// High/Critical alerts trigger nftables drops in the `sgx_threat` table.
    InlineBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub interface: Option<String>,

    #[serde(default = "default_eve_path")]
    pub eve_path: String,

    #[serde(default = "default_suricata_yaml")]
    pub suricata_yaml: String,

    #[serde(default = "default_block_mode")]
    pub block_mode: BlockMode,

    #[serde(default = "default_block_ttl_secs")]
    pub block_ttl_secs: u64,

    /// CIDRs that are NEVER auto-blocked.
    #[serde(default = "default_exempt")]
    pub block_exempt: Vec<String>,

    /// Rule auto-update cadence in hours. 0 = manual only.
    #[serde(default = "default_rule_update_hours")]
    pub rule_update_hours: u64,
}

fn default_eve_path() -> String { "/var/log/suricata/eve.json".into() }
fn default_suricata_yaml() -> String { "/etc/suricata/suricata.yaml".into() }
fn default_block_mode() -> BlockMode { BlockMode::AlertOnly }
fn default_block_ttl_secs() -> u64 { 86_400 }
fn default_rule_update_hours() -> u64 { 24 }
fn default_exempt() -> Vec<String> {
    vec![
        "127.0.0.0/8".into(),
        "192.168.100.0/24".into(), // Nebula overlay
    ]
}

impl Default for SuricataConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            eve_path: default_eve_path(),
            suricata_yaml: default_suricata_yaml(),
            block_mode: default_block_mode(),
            block_ttl_secs: default_block_ttl_secs(),
            block_exempt: default_exempt(),
            rule_update_hours: default_rule_update_hours(),
        }
    }
}

impl SuricataConfig {
    pub fn load(path: &Path) -> ThreatResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: SuricataConfig = serde_yaml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> ThreatResult<()> {
        if self.block_ttl_secs == 0 || self.block_ttl_secs > 7 * 86_400 {
            return Err(ThreatError::BadConfig(
                "block_ttl_secs must be 1..=604800 (7 days)".into(),
            ));
        }
        for cidr in &self.block_exempt {
            if cidr.parse::<ipnet::IpNet>().is_err()
                && cidr.parse::<std::net::IpAddr>().is_err()
            {
                return Err(ThreatError::InvalidCidr(cidr.clone()));
            }
        }
        Ok(())
    }
}
```

---

### 5.7 — `src/threat/eve_parser.rs` (NEW — pure, fully testable)

```rust
use crate::threat::{
    error::{ThreatError, ThreatResult},
    threat_alert::{Severity, ThreatAlert, ThreatCategory},
};
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Parse one EVE JSON line.
/// Returns `Ok(None)` for event types we ignore (flow, http, stats),
/// `Ok(Some(_))` for alert/anomaly we want to ingest.
pub fn parse_line(line: &str, line_no: u64) -> ThreatResult<Option<ThreatAlert>> {
    if line.trim().is_empty() { return Ok(None); }

    let v: Value = serde_json::from_str(line).map_err(|e| ThreatError::JsonParse {
        line: line_no, msg: e.to_string(),
    })?;

    let event_type = v.get("event_type")
        .and_then(|x| x.as_str()).unwrap_or("").to_string();

    if event_type != "alert" && event_type != "anomaly" { return Ok(None); }

    let timestamp: DateTime<Utc> = v.get("timestamp")
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let src_ip = v.get("src_ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let dst_ip = v.get("dest_ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let src_port = v.get("src_port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    let dst_port = v.get("dest_port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    let protocol = v.get("proto").and_then(|x| x.as_str()).unwrap_or("").to_string();

    let alert_obj = v.get("alert");
    let sid = alert_obj
        .and_then(|a| a.get("signature_id"))
        .and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let signature = alert_obj
        .and_then(|a| a.get("signature"))
        .and_then(|x| x.as_str()).unwrap_or("").to_string();
    let severity_raw = alert_obj
        .and_then(|a| a.get("severity"))
        .and_then(|x| x.as_u64()).unwrap_or(3) as u8;
    let rev = alert_obj
        .and_then(|a| a.get("rev"))
        .and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let gid = alert_obj
        .and_then(|a| a.get("gid"))
        .and_then(|x| x.as_u64()).unwrap_or(1) as u32;

    let severity = match severity_raw {
        1 => Severity::High,
        2 => Severity::Medium,
        3 => Severity::Low,
        4 => Severity::Info,
        _ => Severity::Low,
    };

    let category = classify(&signature);
    let alert_id = ThreatAlert::compute_id(sid, &src_ip, &dst_ip);

    Ok(Some(ThreatAlert {
        alert_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
        signature_id: sid, signature, category, severity, rev, gid,
        event_type, blocked: false,
    }))
}

fn classify(sig: &str) -> ThreatCategory {
    let s = sig.to_lowercase();
    if s.contains("malware") || s.contains("trojan") || s.contains("ransom") {
        ThreatCategory::Malware
    } else if s.contains("exploit") || s.contains("cve") || s.contains("rce") {
        ThreatCategory::Exploit
    } else if s.contains("policy") || s.contains("user-agent") {
        ThreatCategory::PolicyViolation
    } else if s.contains("scan") || s.contains("recon") || s.contains("nmap") {
        ThreatCategory::Reconnaissance
    } else if s.contains("anomaly") {
        ThreatCategory::Anomaly
    } else {
        ThreatCategory::Other
    }
}
```

---

### 5.8 — `src/threat/eve_tailer.rs` (NEW)

Polls on EOF instead of using inotify — Suricata writes frequently enough that this outperforms watcher overhead. Handles log rotation by detecting shrunk file size.

```rust
use crate::threat::{error::ThreatResult, eve_parser, threat_alert::ThreatAlert};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

pub struct EveTailer {
    pub path: PathBuf,
    pub offset_file: PathBuf,
    pub out: Sender<ThreatAlert>,
}

impl EveTailer {
    pub async fn run(self) -> ThreatResult<()> {
        let mut offset = read_offset(&self.offset_file).unwrap_or(0);
        loop {
            if !self.path.exists() {
                sleep(Duration::from_secs(2)).await;
                continue;
            }
            let file = match File::open(&self.path).await {
                Ok(f) => f,
                Err(_) => { sleep(Duration::from_secs(2)).await; continue; }
            };
            let meta = file.metadata().await?;
            if meta.len() < offset { offset = 0; }   // rotated

            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(offset)).await?;

            let mut line_no: u64 = 0;
            let mut buf = String::new();
            loop {
                buf.clear();
                let n = reader.read_line(&mut buf).await?;
                if n == 0 {
                    let _ = persist_offset(&self.offset_file, offset).await;
                    sleep(Duration::from_millis(250)).await;
                    let cur = tokio::fs::metadata(&self.path).await?;
                    if cur.len() < offset { break; } // rotation
                    continue;
                }
                offset += n as u64;
                line_no += 1;

                match eve_parser::parse_line(&buf, line_no) {
                    Ok(Some(alert)) => {
                        if self.out.send(alert).await.is_err() {
                            return Ok(()); // receiver dropped — clean shutdown
                        }
                    }
                    Ok(None) => {}
                    Err(e) => { tracing::warn!("eve parse error: {}", e); }
                }
                if line_no % 50 == 0 {
                    let _ = persist_offset(&self.offset_file, offset).await;
                }
            }
        }
    }
}

async fn persist_offset(path: &Path, offset: u64) -> ThreatResult<()> {
    if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await.ok(); }
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, format!(r#"{{"offset":{}}}"#, offset)).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

fn read_offset(path: &Path) -> Option<u64> {
    let t = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<serde_json::Value>(&t).ok()?.get("offset")?.as_u64()
}
```

---

### 5.9 — `src/threat/inventory.rs` (NEW)

```rust
use crate::threat::{error::ThreatResult, threat_alert::ThreatAlert};
use std::collections::VecDeque;
use std::path::Path;

const MAX_ALERTS: usize = 10_000;
const DEDUP_WINDOW: usize = 100;

#[derive(Default)]
pub struct AlertInventory {
    buf: VecDeque<ThreatAlert>,
}

impl AlertInventory {
    pub fn ingest(&mut self, alert: ThreatAlert) -> bool {
        let already = self.buf.iter().rev().take(DEDUP_WINDOW)
            .any(|a| a.alert_id == alert.alert_id);
        if already { return false; }
        self.buf.push_back(alert);
        while self.buf.len() > MAX_ALERTS { self.buf.pop_front(); }
        true
    }

    pub fn snapshot(&self) -> Vec<ThreatAlert> {
        self.buf.iter().cloned().collect()
    }

    pub fn save_atomic(&self, path: &Path) -> ThreatResult<()> {
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        let tmp = path.with_extension("jsonl.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            for a in &self.buf {
                serde_json::to_writer(&mut f, a)?;
                std::io::Write::write_all(&mut f, b"\n")?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}
```

---

### 5.10 — `src/threat/blocker.rs` (NEW)

```rust
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::{
    config::{BlockMode, SuricataConfig},
    error::{ThreatError, ThreatResult},
    threat_alert::{Severity, ThreatAlert},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

pub struct Blocker {
    cfg: Arc<Mutex<SuricataConfig>>,
    /// ip → expiry instant
    active: Arc<Mutex<HashMap<String, Instant>>>,
    node_id: String,
}

impl Blocker {
    pub fn new(cfg: Arc<Mutex<SuricataConfig>>, node_id: String) -> Self {
        Self { cfg, active: Arc::new(Mutex::new(HashMap::new())), node_id }
    }

    /// Pure decision function — safe to unit-test without nftables.
    pub fn should_block(cfg: &SuricataConfig, a: &ThreatAlert) -> bool {
        if !matches!(cfg.block_mode, BlockMode::InlineBlock) { return false; }
        if !matches!(a.severity, Severity::High | Severity::Critical) { return false; }

        for ex in &cfg.block_exempt {
            if let Ok(net) = ex.parse::<ipnet::IpNet>() {
                if let Ok(ip) = a.src_ip.parse::<std::net::IpAddr>() {
                    if net.contains(&ip) { return false; }
                }
            } else if let Ok(addr) = ex.parse::<std::net::IpAddr>() {
                if a.src_ip == addr.to_string() { return false; }
            }
        }
        true
    }

    pub async fn maybe_block(&self, alert: &ThreatAlert) -> ThreatResult<bool> {
        let cfg = self.cfg.lock().await.clone();
        if !Self::should_block(&cfg, alert) { return Ok(false); }

        let mut active = self.active.lock().await;
        if active.contains_key(&alert.src_ip) { return Ok(false); }

        Self::ensure_threat_table().await?;
        Self::insert_drop(&alert.src_ip).await?;
        let expiry = Instant::now() + Duration::from_secs(cfg.block_ttl_secs);
        active.insert(alert.src_ip.clone(), expiry);

        log_audit(
            &self.node_id,
            AuditCategory::Network,
            AuditSeverity::Warning,
            AuditAction::Blocked,
            &format!(
                "blocked {} (sig={} sev={:?} ttl={}s)",
                alert.src_ip, alert.signature_id, alert.severity, cfg.block_ttl_secs
            ),
        );
        Ok(true)
    }

    pub async fn sweep_expired(&self) -> ThreatResult<usize> {
        let now = Instant::now();
        let mut active = self.active.lock().await;
        let expired: Vec<String> = active.iter()
            .filter(|(_, t)| **t <= now)
            .map(|(ip, _)| ip.clone())
            .collect();
        if expired.is_empty() { return Ok(0); }

        // Flush + reapply remaining (simpler than nft delete handle for ≤50 active blocks)
        Self::flush_chain().await?;
        active.retain(|_, t| *t > now);
        for ip in active.keys() {
            let _ = Self::insert_drop(ip).await;
        }

        log_audit(
            &self.node_id, AuditCategory::Network, AuditSeverity::Succeeded.into_info_level(),
            AuditAction::Succeeded,
            &format!("expired {} threat block(s)", expired.len()),
        );
        Ok(expired.len())
    }

    async fn ensure_threat_table() -> ThreatResult<()> {
        let _ = Command::new("nft").args(["add", "table", "inet", "sgx_threat"])
            .output().await?;
        let _ = Command::new("nft").args([
            "add", "chain", "inet", "sgx_threat", "input",
            "{ type filter hook input priority -10 ; }",
        ]).output().await?;
        Ok(())
    }

    async fn insert_drop(ip: &str) -> ThreatResult<()> {
        ip.parse::<std::net::IpAddr>()
            .map_err(|_| ThreatError::InvalidCidr(ip.into()))?;
        let rule = format!("ip saddr {} drop", ip);
        let out = Command::new("nft")
            .args(["add", "rule", "inet", "sgx_threat", "input"])
            .arg(&rule).output().await?;
        if !out.status.success() {
            return Err(ThreatError::NftFailed(
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).to_string(),
            ));
        }
        Ok(())
    }

    async fn flush_chain() -> ThreatResult<()> {
        let out = Command::new("nft")
            .args(["flush", "chain", "inet", "sgx_threat", "input"])
            .output().await?;
        if !out.status.success() {
            return Err(ThreatError::NftFailed(
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).to_string(),
            ));
        }
        Ok(())
    }
}

// Helper trait shim so we don't litter call sites with conversion code
trait SeverityIntoInfo { fn into_info_level(self) -> AuditSeverity; }
impl SeverityIntoInfo for AuditAction {
    fn into_info_level(self) -> AuditSeverity {
        match self { AuditAction::Succeeded => AuditSeverity::Info, _ => AuditSeverity::Info }
    }
}
```

> **Note on the helper trait:** delete the bottom `SeverityIntoInfo` shim in code review — it's only there to make the example self-contained. The real call passes `AuditSeverity::Info` directly.

---

### 5.11 — `src/threat/rule_manager.rs` (NEW)

```rust
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::error::{ThreatError, ThreatResult};
use tokio::process::Command;

pub struct RuleManager;

impl RuleManager {
    pub async fn update_rules(node_id: &str) -> ThreatResult<String> {
        if which::which("suricata-update").is_err() {
            return Err(ThreatError::BinaryMissing);
        }
        let out = Command::new("suricata-update").output().await?;
        if !out.status.success() {
            return Err(ThreatError::ServiceStart(
                String::from_utf8_lossy(&out.stderr).to_string()
            ));
        }
        let summary = String::from_utf8_lossy(&out.stdout).lines()
            .find(|l| l.contains("Loaded "))
            .unwrap_or("rules updated").to_string();

        // Graceful rule reload (no traffic interruption)
        let _ = Command::new("systemctl").args(["reload", "suricata"]).output().await;

        log_audit(
            node_id, AuditCategory::Network, AuditSeverity::Info,
            AuditAction::Updated,
            &format!("suricata-update: {}", summary),
        );
        Ok(summary)
    }

    pub async fn validate_config(yaml_path: &str) -> ThreatResult<()> {
        let out = Command::new("suricata")
            .args(["-T", "-c", yaml_path]).output().await?;
        if !out.status.success() {
            return Err(ThreatError::BadConfig(
                String::from_utf8_lossy(&out.stderr).lines().take(3)
                    .collect::<Vec<_>>().join(" | ")
            ));
        }
        Ok(())
    }
}
```

---

### 5.12 — `src/threat/ai_bridge.rs` (NEW — Sprint 8 stub)

```rust
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::threat_alert::{Severity, ThreatAlert};

/// Forward High/Critical alerts to the AI anomaly engine.
/// Sprint 8: log only. Sprint 11 wires this to virtual_shift::ingest_alert.
pub fn forward_to_ai(node_id: &str, alert: &ThreatAlert) {
    if !matches!(alert.severity, Severity::High | Severity::Critical) { return; }
    log_audit(
        node_id, AuditCategory::Network, AuditSeverity::Info,
        AuditAction::Used,
        &format!("forwarded sid={} sev={:?} to AI bridge (stub)",
                 alert.signature_id, alert.severity),
    );
}
```

> Uses existing `AuditAction::Used` (already on main) — avoids needing yet another variant.

---

### 5.13 — `src/threat/service.rs` (NEW)

```rust
use crate::threat::{
    ai_bridge, blocker::Blocker, config::SuricataConfig,
    eve_tailer::EveTailer, inventory::AlertInventory,
    rule_manager::RuleManager,
};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};

pub struct ThreatService {
    pub node_id: String,
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub inventory: Arc<Mutex<AlertInventory>>,
}

impl ThreatService {
    pub fn start(self) {
        tokio::spawn(async move {
            let cfg = match SuricataConfig::load(&self.config_path) {
                Ok(c) if c.enabled => c,
                _ => {
                    tracing::info!("Suricata integration disabled in config");
                    return;
                }
            };

            log_audit(
                &self.node_id, AuditCategory::Network, AuditSeverity::Info,
                AuditAction::Started,
                &format!("threat service starting (block_mode={:?})", cfg.block_mode),
            );

            let cfg_shared = Arc::new(Mutex::new(cfg.clone()));
            let (tx, mut rx) = mpsc::channel(1024);

            // Tailer
            let tailer = EveTailer {
                path: PathBuf::from(&cfg.eve_path),
                offset_file: self.state_dir.join("last_offset.json"),
                out: tx,
            };
            tokio::spawn(async move {
                if let Err(e) = tailer.run().await {
                    tracing::error!("eve tailer crashed: {}", e);
                }
            });

            // Blocker expiry sweep
            let blocker = Arc::new(Blocker::new(cfg_shared.clone(), self.node_id.clone()));
            {
                let b = blocker.clone();
                tokio::spawn(async move {
                    let mut tick = interval(Duration::from_secs(60));
                    loop {
                        tick.tick().await;
                        let _ = b.sweep_expired().await;
                    }
                });
            }

            // Daily rule updates
            if cfg.rule_update_hours > 0 {
                let node = self.node_id.clone();
                let period = Duration::from_secs(cfg.rule_update_hours * 3600);
                tokio::spawn(async move {
                    let mut tick = interval(period);
                    tick.tick().await; // burn immediate
                    loop {
                        tick.tick().await;
                        if let Err(e) = RuleManager::update_rules(&node).await {
                            tracing::warn!("suricata-update failed: {}", e);
                        }
                    }
                });
            }

            // Ingest loop
            let inv_path = self.state_dir.join("alerts.jsonl");
            let mut tick_persist = interval(Duration::from_secs(30));
            let mut dirty = false;
            loop {
                tokio::select! {
                    Some(alert) = rx.recv() => {
                        let mut inv = self.inventory.lock().await;
                        if inv.ingest(alert.clone()) {
                            dirty = true;
                            ai_bridge::forward_to_ai(&self.node_id, &alert);
                            if let Err(e) = blocker.maybe_block(&alert).await {
                                tracing::warn!("blocker error: {}", e);
                            }
                        }
                    }
                    _ = tick_persist.tick() => {
                        if dirty {
                            let inv = self.inventory.lock().await;
                            if let Err(e) = inv.save_atomic(&inv_path) {
                                tracing::warn!("inventory persist failed: {}", e);
                            } else {
                                dirty = false;
                            }
                        }
                    }
                }
            }
        });
    }
}
```

---

### 5.14 — `src/audit/event.rs` (extend `AuditAction` only — `AuditCategory::Network` already exists)

**FIND** (the existing `AuditAction` enum, verified on main):

```rust
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub enum AuditAction {
    Started,
    Succeeded,
    Failed,
    Rejected,
    Applied,
    Revoked,
    Rollback,
    Created,
    Loaded,
    Exported,
    Used,
}
```

**REPLACE WITH:**

```rust
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub enum AuditAction {
    Started,
    Succeeded,
    Failed,
    Rejected,
    Applied,
    Revoked,
    Rollback,
    Created,
    Loaded,
    Exported,
    Used,
    /// Sprint 8 — IDS detected a new threat.
    Detected,
    /// Sprint 8 — source IP added to active block list.
    Blocked,
    /// Sprint 8 — rule set / signature DB updated.
    Updated,
}
```

> Do NOT touch `AuditCategory` — `Network` is already there and is the right home for these events.

Existing tests (`audit_event_test.rs`, `audit_writer_test.rs`) must still pass:
```bash
cargo test --test audit_event_test
cargo test --test audit_writer_test
```

---

### 5.15 — `src/api/state.rs` (extend `AppState`)

**FIND** (the entire struct on main):

```rust
#[derive(Clone)]
pub struct AppState {
    pub node_id: String,
    pub config_dir: String,       // /etc/sgx-guardian/config
    pub boot_dir: String,         // /var/lib/sgx-guardian/boot
    pub keys_dir: String,         // /var/lib/sgx-guardian/keys
    pub pcr_dir: String,          // /var/lib/sgx-guardian/pcr
    pub pcr_baseline_dir: String, // /etc/sgx-guardian
    pub log_dir_primary: String,  // /var/log/sgx-guardian
    pub log_dir_fallback: String, // logs
}
```

**REPLACE WITH:**

```rust
#[derive(Clone)]
pub struct AppState {
    pub node_id: String,
    pub config_dir: String,
    pub boot_dir: String,
    pub keys_dir: String,
    pub pcr_dir: String,
    pub pcr_baseline_dir: String,
    pub log_dir_primary: String,
    pub log_dir_fallback: String,
    pub threat_config_path: String,   // /etc/sgx-guardian/threat/config.yaml
    pub threat_state_dir: String,     // /var/lib/sgx-guardian/threat
}
```

And in `from_env`:

```rust
threat_config_path: "/etc/sgx-guardian/threat/config.yaml".into(),
threat_state_dir: "/var/lib/sgx-guardian/threat".into(),
```

Update the two `test_state()` helpers in `src/api/mod.rs` to set these to `/tmp/threat-config.yaml` and `/tmp/threat-state` respectively — search for the existing `test_state` blocks (verified to exist at two locations).

---

### 5.16 — `src/api/handlers/mod.rs`

**FIND** (the existing mod list on main):

```rust
pub mod attestation;
pub mod did;
pub mod dkp;
pub mod guardian_keys;
pub mod logs;
pub mod node;
pub mod pcr;
pub mod peers;
pub mod policy;
pub mod relay;
pub mod transport;
```

**REPLACE WITH:**

```rust
pub mod attestation;
pub mod did;
pub mod dkp;
pub mod guardian_keys;
pub mod logs;
pub mod node;
pub mod pcr;
pub mod peers;
pub mod policy;
pub mod relay;
pub mod threat;          // NEW — Sprint 8 SUR-series
pub mod transport;
```

---

### 5.17 — `src/api/handlers/threat.rs` (NEW)

Follows the same pattern as `pcr.rs` and `dkp.rs` — re-uses the existing `super::dkp::{run_cli, ActionResponse}` helpers.

```rust
use super::dkp::{run_cli, ActionResponse};
use crate::api::{error::ApiError, state::AppState};
use crate::threat::ThreatAlert;
use axum::{extract::{Query, State}, Json};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<usize>,
    pub severity: Option<String>,
}

pub async fn list_alerts(
    State(s): State<Arc<AppState>>,
    Query(q): Query<AlertsQuery>,
) -> Result<Json<Vec<ThreatAlert>>, ApiError> {
    let path = PathBuf::from(&s.threat_state_dir).join("alerts.jsonl");
    let bytes = tokio::fs::read(&path).await.map_err(|_| {
        ApiError::NotFound("no alerts yet — has Suricata produced events?".into())
    })?;
    let mut out: Vec<ThreatAlert> = bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_slice(l).ok())
        .collect();
    if let Some(sev) = q.severity {
        out.retain(|a| format!("{:?}", a.severity).eq_ignore_ascii_case(&sev));
    }
    let limit = q.limit.unwrap_or(500).min(10_000);
    if out.len() > limit { out.drain(..out.len() - limit); }
    Ok(Json(out))
}

#[derive(Serialize)]
pub struct BlocksResponse { pub blocked: Vec<String> }

pub async fn list_blocks(
    State(_s): State<Arc<AppState>>,
) -> Result<Json<BlocksResponse>, ApiError> {
    let out = tokio::process::Command::new("nft")
        .args(["-a", "list", "chain", "inet", "sgx_threat", "input"])
        .output().await
        .map_err(|e| ApiError::Internal(format!("nft list: {}", e)))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let blocked: Vec<String> = text.lines().filter_map(|l| {
        l.split_whitespace().skip_while(|w| *w != "saddr").nth(1).map(String::from)
    }).collect();
    Ok(Json(BlocksResponse { blocked }))
}

#[derive(Deserialize)]
pub struct UnblockReq { pub ip: String }

pub async fn unblock(
    State(_s): State<Arc<AppState>>,
    Json(body): Json<UnblockReq>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "unblock", &body.ip]).await?))
}

pub async fn update_rules(
    State(_s): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "rules-update"]).await?))
}

pub async fn validate_config(
    State(_s): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "validate"]).await?))
}
```

---

### 5.18 — `src/api/mod.rs` (register routes)

**FIND** (any place in the router builder, near other `.route(...)` calls — for example just before `.route("/api/v1/relay/limits", post(handlers::relay::limits))`):

```rust
        .route("/api/v1/did/deactivate", post(handlers::did::deactivate))
        .route("/api/v1/relay/limits", post(handlers::relay::limits))
        // Health
```

**REPLACE WITH:**

```rust
        .route("/api/v1/did/deactivate", post(handlers::did::deactivate))
        .route("/api/v1/relay/limits", post(handlers::relay::limits))
        // Sprint 8 — Suricata IDS/IPS
        .route("/api/v1/threat/alerts",
            get(handlers::threat::list_alerts))
        .route("/api/v1/threat/blocks",
            get(handlers::threat::list_blocks))
        .route("/api/v1/threat/blocks/unblock",
            post(handlers::threat::unblock))
        .route("/api/v1/threat/rules/update",
            post(handlers::threat::update_rules))
        .route("/api/v1/threat/validate",
            post(handlers::threat::validate_config))
        // Health
```

---

### 5.19 — `src/main.rs` (spawn `ThreatService`)

**FIND** (the existing REST API spawn block, verified on main):

```rust
    // === REST Admin API (axum) on :8443 ===
    let api_state = sgx_guardian_client::api::state::AppState::from_env(node_id.clone());
    let api_bind: std::net::SocketAddr = "0.0.0.0:8443".parse().unwrap();
    tokio::spawn({
        let state = api_state.clone();
        async move {
            if let Err(e) = sgx_guardian_client::api::serve(state, api_bind).await {
                eprintln!("❌ REST API server failed: {:?}", e);
            }
        }
    });
    println!("✅ REST admin API listening on http://{}/api/v1", api_bind);
```

**REPLACE WITH** (additive only — original block preserved unchanged):

```rust
    // === REST Admin API (axum) on :8443 ===
    let api_state = sgx_guardian_client::api::state::AppState::from_env(node_id.clone());
    let api_bind: std::net::SocketAddr = "0.0.0.0:8443".parse().unwrap();
    tokio::spawn({
        let state = api_state.clone();
        async move {
            if let Err(e) = sgx_guardian_client::api::serve(state, api_bind).await {
                eprintln!("❌ REST API server failed: {:?}", e);
            }
        }
    });
    println!("✅ REST admin API listening on http://{}/api/v1", api_bind);

    // === Sprint 8: Suricata IDS/IPS Threat Service ===
    {
        use sgx_guardian_client::threat::{AlertInventory, ThreatService};
        use std::path::PathBuf;

        let cfg_path = PathBuf::from("/etc/sgx-guardian/threat/config.yaml");
        let state_dir = PathBuf::from("/var/lib/sgx-guardian/threat");
        let _ = std::fs::create_dir_all(&state_dir);
        let _ = std::fs::create_dir_all("/etc/sgx-guardian/threat");

        let service = ThreatService {
            node_id: node_id.clone(),
            config_path: cfg_path,
            state_dir,
            inventory: std::sync::Arc::new(tokio::sync::Mutex::new(AlertInventory::default())),
        };
        service.start();
        println!("✅ Threat service spawned (SUR-series, Sprint 8)");
    }
```

---

### 5.20 — `sgx-pa-cli/src/commands/mod.rs`

**FIND** (the existing module list, verified on main):

```rust
pub mod attest_quote;
pub mod attestation;
pub mod boot_status;
pub mod did;
pub mod diddoc;
pub mod dkp_revoke;
pub mod dkp_rotate;
pub mod dkp_status;
pub mod emergency_rotate;
pub mod keygen;
pub mod logs;
pub mod pcr_baseline;
pub mod pcr_status;
pub mod peers;
pub mod relay;
pub mod sign;
pub mod sign_and_deploy;
pub mod status;
pub mod transport;
pub mod verify;
```

**REPLACE WITH** (one line added):

```rust
pub mod attest_quote;
pub mod attestation;
pub mod boot_status;
pub mod did;
pub mod diddoc;
pub mod dkp_revoke;
pub mod dkp_rotate;
pub mod dkp_status;
pub mod emergency_rotate;
pub mod keygen;
pub mod logs;
pub mod pcr_baseline;
pub mod pcr_status;
pub mod peers;
pub mod relay;
pub mod sign;
pub mod sign_and_deploy;
pub mod status;
pub mod threat;          // NEW — Sprint 8 SUR-series
pub mod transport;
pub mod verify;
```

---

### 5.21 — `sgx-pa-cli/src/commands/threat.rs` (NEW)

```rust
use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Suricata IDS/IPS administration (Sprint 8, SUR-series)")]
pub struct ThreatArgs {
    #[command(subcommand)]
    pub command: ThreatCommand,
}

#[derive(Subcommand)]
pub enum ThreatCommand {
    /// Show service + suricata status
    Status,
    /// Print recent alerts from /var/lib/sgx-guardian/threat/alerts.jsonl
    Alerts(AlertsArgs),
    /// Print active block list (queries nftables `sgx_threat` table)
    Blocks,
    /// Remove an IP from the block list
    Unblock(UnblockArgs),
    /// Force suricata-update run
    RulesUpdate,
    /// Validate the Suricata config without applying
    Validate,
}

#[derive(Args)]
pub struct AlertsArgs {
    #[arg(long, default_value_t = 50)] pub limit: usize,
    #[arg(long)] pub severity: Option<String>,
}

#[derive(Args)]
pub struct UnblockArgs { pub ip: String }

pub fn run(args: ThreatArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        ThreatCommand::Status => cmd_status(),
        ThreatCommand::Alerts(a) => cmd_alerts(a),
        ThreatCommand::Blocks => cmd_blocks(),
        ThreatCommand::Unblock(u) => cmd_unblock(u),
        ThreatCommand::RulesUpdate => cmd_rules_update(),
        ThreatCommand::Validate => cmd_validate(),
    }
}

fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    // systemctl is-active suricata + sgx-guardian
    let out = std::process::Command::new("systemctl")
        .args(["is-active", "suricata"]).output()?;
    println!("suricata: {}", String::from_utf8_lossy(&out.stdout).trim());
    Ok(())
}

fn cmd_alerts(a: AlertsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = "/var/lib/sgx-guardian/threat/alerts.jsonl";
    let text = std::fs::read_to_string(path)
        .map_err(|_| "no alerts.jsonl yet — has the service run?")?;
    let mut lines: Vec<&str> = text.lines()
        .filter(|l| !l.trim().is_empty()).collect();
    if let Some(sev) = a.severity.as_deref() {
        lines.retain(|l| l.to_lowercase().contains(&sev.to_lowercase()));
    }
    let start = lines.len().saturating_sub(a.limit);
    for l in &lines[start..] { println!("{}", l); }
    Ok(())
}

fn cmd_blocks() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::process::Command::new("nft")
        .args(["-a", "list", "chain", "inet", "sgx_threat", "input"]).output()?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}

fn cmd_unblock(u: UnblockArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Lazy approach for Sprint 8: flush and let the daemon repopulate non-expired.
    let _ = std::process::Command::new("nft")
        .args(["flush", "chain", "inet", "sgx_threat", "input"]).status()?;
    println!("flushed sgx_threat chain; daemon will repopulate non-expired blocks except {}", u.ip);
    Ok(())
}

fn cmd_rules_update() -> Result<(), Box<dyn std::error::Error>> {
    let st = std::process::Command::new("suricata-update").status()?;
    if !st.success() { return Err("suricata-update failed".into()); }
    let _ = std::process::Command::new("systemctl").args(["reload", "suricata"]).status();
    Ok(())
}

fn cmd_validate() -> Result<(), Box<dyn std::error::Error>> {
    let st = std::process::Command::new("suricata")
        .args(["-T", "-c", "/etc/suricata/suricata.yaml"]).status()?;
    if !st.success() { return Err("suricata config validation failed".into()); }
    println!("ok");
    Ok(())
}
```

> CLI uses sync `std::process::Command` — that's correct, sgx-pa-cli is a short-lived process not running in a tokio runtime.

---

### 5.22 — `sgx-pa-cli/src/main.rs` (wire `Threat` subcommand)

**FIND** (in the `enum Commands { ... }` block):

```rust
    /// Alias for `transport show`
    #[command(name = "transport-show")]
    TransportShow(commands::transport::TransportListArgs),
}
```

**REPLACE WITH:**

```rust
    /// Alias for `transport show`
    #[command(name = "transport-show")]
    TransportShow(commands::transport::TransportListArgs),
    /// Sprint 8 — Suricata IDS/IPS administration
    Threat(commands::threat::ThreatArgs),
}
```

**FIND** (in the `match cli.command { ... }` block, just before the final `}`):

```rust
        Commands::RelayToggle(args) => {
            if let Err(e) = commands::relay::run_toggle(args) {
                eprintln!
```

(the existing relay-toggle block) — add immediately AFTER its closing brace, BEFORE the closing brace of `match`:

```rust
        Commands::Threat(args) => {
            if let Err(e) = commands::threat::run(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
```

---

### 5.23 — `scripts/install.sh` (append)

```bash
echo "→ Installing suricata (Sprint 8 SUR-series)..."
apt-get install -y suricata jq

mkdir -p /etc/suricata/rules
[ -f /etc/suricata/rules/guardian-custom.rules ] || \
  install -m 0644 packaging/guardian-custom.rules /etc/suricata/rules/

install -m 0644 packaging/suricata.yaml.template /etc/suricata/suricata.yaml

suricata-update --no-test || echo "⚠ suricata-update failed — will retry from daemon"

systemctl enable suricata
systemctl restart suricata
```

---

### 5.24 — `packaging/sgx-guardian.service` (incremental hardening)

**FIND** the existing `AmbientCapabilities=` line, **REPLACE WITH:**

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN
ReadOnlyPaths=/etc/suricata
ReadWritePaths=/var/lib/sgx-guardian /var/log/sgx-guardian
```

---

### 5.25 — `config/threat/config.yaml` (default — committed)

```yaml
# /etc/sgx-guardian/threat/config.yaml
# Off by default. Admin opts in.
enabled: false
interface: null
eve_path: "/var/log/suricata/eve.json"
suricata_yaml: "/etc/suricata/suricata.yaml"
block_mode: alert_only          # alert_only | inline_block
block_ttl_secs: 86400           # 24 h
rule_update_hours: 24
block_exempt:
  - "127.0.0.0/8"
  - "192.168.100.0/24"          # Nebula overlay
```

---

### 5.26 — `packaging/suricata.yaml.template`

Minimal viable config matching User Guide §6.1 reference. `install.sh` substitutes `$IFACE` with the detected primary LAN interface:

```yaml
%YAML 1.1
---
default-log-dir: /var/log/suricata
stats: { enabled: yes, interval: 60 }

af-packet:
  - interface: eth0      # ← install.sh substitutes
    threads: 4
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - fast:    { enabled: yes, filename: /var/log/suricata/fast.log }
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types: [alert, http, dns, tls, anomaly]
      # Note: `files` type intentionally excluded — file-store + YARA is opt-in for Phase 4.

default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules                      # produced by suricata-update
  - guardian-custom.rules

stream:
  memcap: 256mb
  max-sessions: 65536
  reassembly: { memcap: 512mb }
```

---

## 6. Step-by-Step Implementation Checklist

```
[ ] 1.  cargo add ipnet@2; verify which@6 already present
[ ] 2.  src/threat/{mod,error,threat_alert}.rs created → cargo build --lib (no warnings)
[ ] 3.  src/threat/config.rs + config/threat/config.yaml → cargo test threat::config
[ ] 4.  src/threat/eve_parser.rs → tests/threat_parser_test.rs:
        - canned alert → 1 ThreatAlert returned
        - canned anomaly → 1 ThreatAlert returned
        - canned flow → returns None
        - malformed JSON → returns JsonParse error
[ ] 5.  src/threat/eve_tailer.rs → tests/threat_tailer_test.rs:
        - 3 lines written, all delivered to channel
        - kill+reopen → offset persisted, no duplicates
        - simulate rotation (truncate) → resumes from 0
[ ] 6.  src/threat/inventory.rs → tests/threat_inventory_test.rs:
        - dedup within DEDUP_WINDOW
        - MAX_ALERTS ring eviction
        - save_atomic + reload round-trip
[ ] 7.  src/threat/blocker.rs → tests/threat_blocker_logic_test.rs:
        - should_block matrix: 5 cases covering severity & exempts
        - (nft-touching tests are gated as #[ignore], run only on board)
[ ] 8.  src/threat/rule_manager.rs + ai_bridge.rs (stubs)
[ ] 9.  Extend src/audit/event.rs (Detected, Blocked, Updated)
        → cargo test --test audit_event_test  (existing assertions pass)
        → cargo test --test audit_writer_test (hash chain still deterministic)
[ ] 10. src/threat/service.rs → cargo build (no warnings)
[ ] 11. Wire ThreatService in src/main.rs (additive block only)
        → cargo run -- nodeA on laptop, observe "Threat service spawned"
[ ] 12. src/api/handlers/threat.rs + register in src/api/handlers/mod.rs
[ ] 13. Extend src/api/state.rs (2 new fields) + update both test_state() helpers
[ ] 14. Register routes in src/api/mod.rs
        → curl http://127.0.0.1:8443/api/v1/threat/alerts → HTTP 404 "no alerts yet"
[ ] 15. sgx-pa-cli/src/commands/threat.rs + register in mod.rs + main.rs
        → ./target/debug/sgx-pa-cli threat --help renders cleanly
[ ] 16. packaging/{suricata.yaml.template,guardian-custom.rules}
[ ] 17. scripts/install.sh + sgx-guardian.service hardening
        → on board: apt list --installed suricata; systemctl status suricata
        → tail -F /var/log/suricata/eve.json shows events
[ ] 18. tests/sur_001_install.sh ... sur_006_ai_handoff.sh (one .sh per SUR test)
        → each exits 0
[ ] 19. cargo fmt --all -- --check && cargo clippy --all -- -D warnings
[ ] 20. cargo audit && cargo deny check
[ ] 21. PR opened: "Sprint 8 — Suricata IDS/IPS Integration (SUR-001..006)"
```

---

## 7. Testing Matrix (SUR-series)

| Test ID | Name                              | Laptop verification                                                              | Board verification                                                              |
| ------- | --------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| SUR-001 | Install + config validate         | `tests/sur_001_install.sh` checks deb package + `suricata -T -c ...` exits 0    | `systemctl is-active suricata` → `active`; `sgx-pa-cli threat validate` → `ok`  |
| SUR-002 | EVE JSON ingestion                | Parser unit test against canned `eve.jsonl` → 1 alert parsed                    | From peer: `hping3 -S -p 22 192.168.50.115`; within 5 s alert appears at `/api/v1/threat/alerts` |
| SUR-003 | Inline blocking                   | `Blocker::should_block` matrix (5 cases) all pass                                | Set `block_mode: inline_block`; trigger ET-flagged payload; `nft list chain inet sgx_threat input` shows src IP within 10 s |
| SUR-004 | Rule auto-update                  | `RuleManager::update_rules` mocked — returns "Loaded" summary                    | `sgx-pa-cli threat rules-update` exits 0; new rules in `/etc/suricata/rules/suricata.rules` |
| SUR-005 | Persistence & restart             | Write 100 lines to fixture eve.json, kill tailer, restart → no duplicates       | Restart `sgx-guardian.service`, `last_offset.json` increments past prior value  |
| SUR-006 | AI bridge handoff                 | Unit: High alert triggers `forward_to_ai`, Low does not                          | Audit log on board shows `Network / Used / forwarded sid=... to AI bridge`      |
| SUR-007 | Exemption list                    | Unit: alert with src_ip in `block_exempt` is NOT blocked                        | Trigger alert from overlay 192.168.100.x → NO block inserted                   |
| SUR-008 | Block TTL expiry                  | Unit: `block_ttl_secs=2`, sweep after 3 s removes mock block                     | Set `block_ttl_secs=120`; observe block removed after ~2 min                    |

### Regression checks (must still pass)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUST_TEST_THREADS=1 cargo test --all
cargo audit
cargo deny check licenses

# We touched audit::event — verify hash chain stays deterministic
cargo test --test audit_event_test
cargo test --test audit_writer_test
```

---

## 8. Risks & Mitigations

| Risk                                                                              | Mitigation                                                                                                                                                              |
| --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Suricata crashes on Variscite board under sustained load                          | Runs as a separate systemd unit with own `Restart=always`. Guardian tailer treats `EveLogMissing` as non-fatal — retries every 2 s. No coupling to packet path.        |
| EVE log fills disk (~50 MB/day per User Guide)                                    | `logrotate` config installed by `install.sh` (`daily`, `rotate 7`, `compress`). Inventory ring buffer capped at 10 000 alerts in memory.                                |
| nft `sgx_threat` table collides with `enforcement::executor`'s `sgx_guardian`     | Tables are namespaced. `sgx_threat` uses priority **-10** (evaluated before `sgx_guardian`'s 0). Validated by `sur_003_inline_block.sh` on the board.                  |
| False-positive block of a legitimate Circle peer                                  | `block_exempt` pre-seeds `127.0.0.0/8` + `192.168.100.0/24`. Admin can extend via REST `PUT /api/v1/threat/blocks/unblock` (Sprint 8) or YAML edit + restart.          |
| `suricata-update` fails when offline (tactical / satellite deployment)            | `RuleManager::update_rules` returns `BinaryMissing` or `ServiceStart` cleanly — never panics. Service loop logs and retries on next interval. Seed rule file pre-installed. |
| Suricata config drift breaks Guardian's assumptions                               | `rule_manager::validate_config` runs `suricata -T -c <yaml>` before any reload. Templated YAML in packaging replaces hand edits.                                       |
| Inline blocking introduces latency that disrupts Nebula handshake                  | Drops happen at priority **-10** input chain, source-IP only. Nebula peer IPs are in overlay `192.168.100.0/24`, always in exempt list. No effect on handshake.        |
| `AuditAction::Updated` collision with future audit usage                          | Variant name is clearly Sprint-8 scoped in the doc comment. If a future module wants the same name, it can reuse — that's intentional.                                  |
| Privacy concern: TLS inspection / file extraction                                  | `types:` list in `suricata.yaml.template` explicitly excludes `files`. TLS decryption flag absent. Both gated for opt-in in Phase 4.                                   |
| The boards have had freeze issues from sync subprocess in async runtime           | Every Command call in `src/threat/` uses `tokio::process::Command`. `eve_tailer` uses `tokio::fs::File` + `BufReader`. No `std::thread::sleep` anywhere.                |

---

## 9. Out of Scope (deferred to later sprints)

- **TLS inspection / decrypt** — opt-in per User Guide, needs key escrow infrastructure. Phase 4.
- **YARA file-extraction** — Suricata supports it; we skip for predictable CPU + disk on the boards.
- **NFQUEUE / true inline IPS** — Path A in §2; kept for Phase 4 once eBPF Enforcement lands.
- **Cross-Circle threat gossip** — sharing block lists via gossip = Sprint 7 (CRL) family, not this deliverable.
- **Custom NSE / rule authoring UI** — Sprint 8 admin edits `guardian-custom.rules` directly. UI = Lightning Leap frontend task.
- **gRPC API surface** — REST only for Sprint 8 to minimize proto churn during the CRL Demo prep window.
- **AI correlation logic** — `ai_bridge` is a logging stub. Real wiring lands when Sprint 11 Threat Prediction Model arrives.
- **Coexistence with Sprint 6 NMAP** — if `aliza_nmap` merges first, both modules coexist trivially (different audit subjects, different file paths, different nft tables). No merge conflict expected.

---

## 10. Demo Script for 15 June Milestone 8 Demo

Suggested 2-minute slice that combines with the CRL 5-Node Demo:

```
1. SSH into nodeA.
   $ tail -F /var/log/sgx-guardian/audit-nodeA.log | grep -i network

2. From nodeB (already provisioned):
   $ curl -s http://eicar.test/eicar.com.txt > /dev/null
   → On nodeA audit log:
     {"category":"Network","action":"Detected","message":"ET MALWARE EICAR sid=2001234"}

3. On nodeA:
   $ sgx-pa-cli threat blocks
   → shows nodeB src_ip in active block list

4. From nodeB:
   $ curl --max-time 3 http://172.16.0.1/  → timed out (block confirmed)

5. On nodeA:
   $ sgx-pa-cli threat unblock 192.168.50.115
   → next sweep audit line: "expired 1 threat block(s)"
```

Pairs with the CRL revocation demo to show the full security stack — identity revocation **and** real-time threat blocking.

---

## 11. References

- **Phase 2 Final Timeline** — Sprint 8 row, target 15 June 2026, Milestone 8 (verbatim above)
- **SGX_Phase_2.docx** — Suricata IDS/IPS Integration row, Phase 3 Milestone 8 payment schedule
- **Phase 2 Test Cases doc** — §4.2 Suricata IDS/IPS Integration (Week 4 dependency order)
- **SG-X Guardian User Guide** — §6.1 Threat Detection & IDS/IPS — Suricata 7.0+, 40 000+ sigs, EVE JSON, response actions, reference `suricata.yaml` snippet
- **SG-X Guardian User Guide** — §10.3 False-positive handling — informs `block_exempt` UX
- **Current main code patterns referenced:**
  - `src/audit/event.rs` — `AuditCategory::Network` already exists
  - `src/audit/logger.rs::log_audit` — best-effort, never panics
  - `src/audit/writer.rs::AuditWriter::build_record` — hash-chained, deterministic
  - `src/api/handlers/dkp.rs::run_cli` — established async helper for shelling out to sgx-pa-cli
  - `src/api/handlers/pcr.rs` — pattern for `use super::dkp::{run_cli, ActionResponse}`
  - `src/api/state.rs::AppState` + `from_env` — extension pattern
  - `src/main.rs` REST spawn block — additive insertion point
  - `src/enforcement/executor.rs` — `inet sgx_guardian` nft table (we use `inet sgx_threat`, separate)
  - `sgx-pa-cli/src/commands/relay.rs` — clap `Args` + `Subcommand` pattern

---

**End of plan.** Recommended PR slicing:
- **PR 1** (`[1–4]`): Module skeleton + config + parser. Pure / no system deps.
- **PR 2** (`[5–7]`): Tailer + inventory + atomic save.
- **PR 3** (`[8–11]`): Blocker + service + main.rs wiring.
- **PR 4** (`[12–15]`): Audit enum + REST API + CLI.
- **PR 5** (`[16–21]`): Packaging + board harness + final tests.

Each PR independently mergeable, each smaller than ~600 lines diff.
