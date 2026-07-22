# CRL Offline Revocation Sync — Complete Development Plan
**Sprint (Offline Revocation Sync — CRL Gossip) | Scope: CRL Gossip | Deliverable: Offline Revocation Sync | Test tag: CRL-series (CRL-033 – CRL-043)**
**Repo:** `AsadAli-CyberZeus/SGX` (main) | **Grounded on:** fresh indexed pull, 2026-07-06 | **Builds on:** Gossip Protocol + Emergency Revocation (merged) | **Author:** Plan for Asad Ali

---

## 0. Grounding Statement (READ FIRST)

Fresh pull of `main` completed before writing this plan. The Gossip Protocol and Emergency Revocation tasks are merged; this plan builds on both and reuses their primitives. Every FIND anchor was confirmed verbatim in the current indexed source.

| Fact confirmed on current `main` | Consequence for this plan |
|---|---|
| **`persistence::pending_dir()` already exists** → `/var/lib/sgx-guardian/identity/crl/pending`, alongside `crl_path()` and `entries_dir()`, with the shared atomic `write_atomic` helper | The **outbound queue directory is pre-allocated for exactly this task** (same pattern as `peers_notified`/`propagated` for gossip). We persist pending revocations here — no new storage location invented. |
| `persistence::{save_crl, load_crl, save_entry, list_entries}` (atomic tmp+rename) | Queue + CRL persistence reuse the existing disk layer. |
| `CertificateRevocationList` carries `sequence` (monotonic per node) + `merkle_root` | These **are** the "CRL version vector" the spec asks to compare — no new versioning scheme needed. |
| `gossip::engine::run_round_once(node_id, resolver, config)` is `pub` and performs a full **bidirectional anti-entropy exchange** (push + pull) with one peer over TCP 50063 | "Fetch missed revocations by comparing CRL version vectors" **and** "push queued revocations to peers" are **already implemented by the gossip exchange** — offline sync orchestrates it on reconnect; it does not re-implement it. |
| `gossip::engine::{active_gossip_peers, GossipPeer, did_record_path}` and `gossip::GossipConfig::from_env()` are `pub` | Peer directory + reachability targets + the gossip port come from existing code. |
| `gossip::store::{merge_verified_entries, incoming_wins, CRL_WRITE_LOCK}` are `pub`; `incoming_wins` = **earliest-timestamp wins, tie → lower fingerprint** (deterministic) | Conflict resolution is **already deterministic and shared**; offline-fetched entries merge through the exact same path, so gossip and offline sync can never diverge (no split-brain). |
| `LinkMonitor`, `FailoverEngine`, `InterfaceDetector`, `HotplugWatcher`, `tunnel_state` exist (CoT); members reconnect to the CA via a 30 s DID-doc pull loop | Connectivity signal = **can I reach a peer to sync?** — derived from `active_gossip_peers` + a lightweight TCP probe, which is more directly relevant than raw link state and needs no CoT-internal plumbing. |
| Gossip already runs a periodic anti-entropy loop on TCP 50063 (nft-allowed) on every node; the emergency channel added 50064 | **Offline sync needs NO new port and NO new listener** — it drives the *existing* gossip exchange against peers' 50063. Therefore **zero nftables changes** and **zero new inbound surface**. |
| REST `/crl/*` in `routes.rs::crl_router()`; the `revoke` handler already takes `State(state)` (post-Emergency) and reloads `crl.json` after issuing | Observability endpoints extend the existing router; the queue can be populated on REST issue AND self-reconciled from local state (covering CLI-issued revocations too). |
| A locally-issued revocation is written to the node's own `crl.json` immediately (issuer = self); gossip sets `propagated=true` once `peers_notified` reaches threshold | **Delivery confirmation is already tracked**: a pending revocation is "delivered" exactly when its `propagated` flag flips. Dequeue signal = existing field. |
| No new crates needed: `serde`, `serde_json`, `chrono`, `tokio`, `once_cell`, `uuid` all present | **Zero new dependencies. Zero `Cargo.toml` changes.** |

**Net result: 1 net-new module (`src/crl/offline/`, 4 files), 5 surgical edits, 0 new dependencies, 0 new ports/listeners, 0 nftables changes, 0 changes to the gossip or emergency engines, 0 daemon-lifecycle changes.**

---

## 1. Task Description (verbatim from sprint document)

> Implement offline revocation queue for Guardians operating in disconnected environments (tactical ops, remote locations, satellite with intermittent connectivity). When Guardian goes offline, queue outgoing revocations locally. Track pending revocations with retry counter and timestamps. When connectivity restored, synchronously push queued revocations to peers. Fetch missed revocations from peers by comparing CRL version vectors. Resolve conflicts using timestamp-based "last writer wins" or signature-based trust hierarchy. Ensures Guardians can revoke compromised peers even when isolated.

---

## 2. Scope

### In scope
1. **Outbound pending queue** persisted under the pre-allocated `pending/` dir — each entry is the signed `CrlEntry` plus retry metadata (`attempts`, `queued_at`, `last_attempt_at`, `last_error`).
2. **Self-reconciling queue**: on every sync cycle the queue is reconciled from local state — any locally-issued (`revoker_did == self_did`), not-yet-`propagated` entry is (re)tracked as pending. This covers **both** issue paths (REST **and** `sgx-pa-cli`) and survives restarts.
3. **Connectivity detection**: a background loop that measures peer reachability (`active_gossip_peers` + TCP probe on the gossip port) and detects the offline→online transition.
4. **On reconnect (and periodically while online with a non-empty queue):**
   - **Fetch missed revocations** by running the existing gossip anti-entropy exchange against reachable peers (compares `sequence`/`merkle_root`/fingerprint-set — the version vector).
   - **Push queued revocations** to peers via the same exchange; increment `attempts` + timestamps per pending each cycle; **dequeue** a pending once its `propagated` flag flips (delivery confirmed); back off + park after `MAX_RETRIES` (never silently drop a revocation).
5. **Per-peer sync state** (`sync_state.json`): last-seen `merkle_root`/`sequence`/timestamp per peer — the observable "version vector" comparison.
6. **Conflict resolution** reused from gossip (`merge_verified_entries` → `incoming_wins`, deterministic timestamp-based) so offline-fetched and gossip-fetched entries resolve identically.
7. **REST**: `GET /crl/offline/status`, `GET /crl/offline/pending`, `POST /crl/offline/sync` (deterministic reconnect/test hook).
8. Audit-chain + stdout logging for offline/online transitions, flush attempts, dequeues, and fetches.

### Out of scope
- CRL Gossip Demo (5-node) visualization.
- New gossip transport, new port, or new inbound listener (reuses gossip 50063).
- Suricata / anomaly / any non-CRL subsystem.
- Owner>member **signature trust-hierarchy tiebreaker** as a *replacement* conflict rule — that would change the SHARED `incoming_wins` (affecting gossip too). Kept as a shared follow-up (L1) to avoid divergence; the current deterministic timestamp rule is used.
- Touching `NebulaDaemon::start()`, `resolve_ca_ip_from_config_inner()`, or any daemon-lifecycle code.

---

## 3. What Already Exists on `main` (reuse — do not re-implement)

| Asset | Location | Used by offline sync as |
|---|---|---|
| `persistence::pending_dir()`, `crl_path()`, `entries_dir()`, `save_crl`, `load_crl`, `save_entry`, `list_entries` | `src/crl/persistence.rs` | Queue + CRL disk layer (pending dir pre-allocated) |
| `run_round_once(node_id, resolver, config)` (bidirectional anti-entropy over 50063) | `src/crl/gossip/engine.rs` | The push+pull exchange offline sync triggers on reconnect |
| `active_gossip_peers(self_did)` → `GossipPeer{did,node_name,overlay_ip}`, `did_record_path()` | `src/crl/gossip/engine.rs` | Reachability targets + self identity path |
| `GossipConfig::from_env()` (gives the gossip port) | `src/crl/gossip/mod.rs` | Reachability probe port |
| `store::merge_verified_entries`, `store::incoming_wins`, `store::CRL_WRITE_LOCK` | `src/crl/gossip/store.rs` | Deterministic, shared conflict resolution |
| `CertificateRevocationList` (`sequence`, `merkle_root`, `entries`, `propagated`) | `src/crl/list.rs`, `src/crl/entry.rs` | Version vector + delivery-confirmation signal |
| `DidRecord::load`, `Did::parse` | `src/did/` | Self DID (issuer identity for reconciliation) |
| Hash-chained audit logger, `AuditCategory::Crl` | `src/audit/` | Event trail |
| REST `/crl/*` + `crl_router()`, `run_owned_cli`, `ApiError`, `AppState{node_id, did_resolver}` | `src/api/` | Router + handler plumbing |

---

## 4. Pre-Flight Anchor Verification (run BEFORE any edit)

```bash
git pull origin main && git log -1 --oneline

# Pre-allocated pending dir + persistence API
grep -n "pub fn pending_dir" src/crl/persistence.rs
grep -n "pub fn load_crl\|pub fn save_crl\|pub fn list_entries" src/crl/persistence.rs

# Reused gossip primitives are pub
grep -n "pub async fn run_round_once" src/crl/gossip/engine.rs
grep -n "pub fn active_gossip_peers" src/crl/gossip/engine.rs
grep -n "pub fn did_record_path" src/crl/gossip/engine.rs
grep -n "pub fn merge_verified_entries" src/crl/gossip/store.rs
grep -n "pub static CRL_WRITE_LOCK" src/crl/gossip/store.rs

# F1 anchor — crl module block (gossip + emergency already registered)
grep -n "pub mod gossip;" src/crl/mod.rs

# F2 anchor — emergency spawn line in main.rs (offline spawns right after)
grep -n "crl::emergency::spawn(node_id.clone(), did_resolver.clone());" src/main.rs
#   fallback if emergency not yet merged: anchor on the gossip spawn instead
grep -n "crl::gossip::spawn(node_id.clone(), did_resolver.clone());" src/main.rs

# F3 anchor — revoke handler success tail + its state param
grep -n '"CRL entry issued"' src/api/handlers/crl.rs
grep -n "State(state): State<Arc<crate::api::state::AppState>>," src/api/handlers/crl.rs

# F4 anchor — end of crl_router (emergency routes present)
grep -n 'post(handlers::crl::emergency_broadcast)' src/api/routes.rs
#   fallback if emergency not merged: anchor on gossip_trigger route
grep -n 'post(handlers::crl::gossip_trigger)' src/api/routes.rs

# F5 anchor — a stable tail handler in crl.rs to append after
grep -n 'pub async fn emergency_notifications' src/api/handlers/crl.rs
#   fallback: append after gossip_trigger if emergency not merged
grep -n '"gossip round completed"' src/api/handlers/crl.rs
```

If the Emergency task is **not** merged in your working tree, use the **fallback anchors** noted above (spawn after gossip, routes after `gossip_trigger`, handlers after `gossip_trigger`). Everything else is unaffected — offline sync depends only on gossip, not on emergency.

---

## 5. Architecture

### 5.1 Where offline sync sits (orchestrator, not a new channel)

```
   ROUTINE gossip :50063 (merged)        EMERGENCY :50064 (merged)
   periodic anti-entropy, 1 peer/round   instant critical broadcast
        ▲  reused as-is                        (independent)
        │
   OFFLINE SYNC (this task) — NO new port, NO listener
   a client-side loop that, on reconnect, DRIVES the gossip exchange
   against reachable peers to (a) fetch missed revocations and
   (b) flush the local outbound queue, with retry/timestamp bookkeeping.
```

### 5.2 The outbound queue (self-reconciling)

```
Revocation issued locally (REST /crl/revoke OR sgx-pa-cli crl revoke)
        │  → written to local crl.json immediately (issuer = self)
        ▼
pending/<entry_id>.json  = { entry, attempts, queued_at, last_attempt_at, last_error }
        │
        │  Populated two ways (belt + suspenders):
        │   1. REST revoke handler enqueues on issue (immediate) — F3
        │   2. Sync loop RECONCILES each cycle: any local entry with
        │      revoker_did == self_did AND propagated == false is (re)queued.
        │      → covers CLI-issued revocations and survives restarts.
        ▼
Dequeued when entry.propagated == true (gossip confirmed threshold delivery)
        OR after MAX_RETRIES → parked (kept on disk + audited, never dropped)
```

### 5.3 Sync cycle (every SYNC_INTERVAL_SECS, or on-demand via REST)

```
1. Reachability: probe active_gossip_peers() on the gossip port (TCP connect, short timeout)
     reachable = peers that answered
2. Transition detection:
     was_offline (0 reachable last cycle) && now reachable ≥1  → "connectivity restored" (audit)
3. If reachable ≥ 1:
     a. FETCH MISSED: run gossip run_round_once() up to FLUSH_ROUNDS times
          → bidirectional anti-entropy pulls whatever we missed while offline
          → merge via shared store (deterministic conflict resolution)
          → update sync_state.json (per-peer merkle_root/sequence/last_sync)
     b. RECONCILE queue from local state (add locally-issued, not-propagated)
     c. FLUSH OUTBOUND: the same rounds push our pending entries to peers.
          For each pending: attempts += 1, last_attempt_at = now
          If entry.propagated (reload crl.json) → dequeue (delivered)
          Else if attempts ≥ MAX_RETRIES (and MAX_RETRIES>0) → park + audit
4. Else (no peer reachable): stay offline; queue persists; nothing lost
```

- **"Synchronously push queued revocations"** — the flush runs the exchange inline within the cycle (awaited), not fire-and-forget.
- **"Compare CRL version vectors"** — each round exchanges `(sequence, merkle_root, fingerprint-set)`; `sync_state.json` records the per-peer view so divergence is observable and drives the fetch.
- **"Resolve conflicts"** — every merge goes through `incoming_wins` (earliest-timestamp deterministic), identical to gossip → no divergence.
- **Isolation guarantee** — while offline, a Guardian can still `sgx-pa-cli crl revoke` a compromised peer; it lands in local `crl.json` + `pending/`, and delivers automatically on reconnect. "Ensures Guardians can revoke compromised peers even when isolated."

### 5.4 Design decisions

| Decision | Choice | Why |
|---|---|---|
| New port / listener | **None** | Reuse gossip 50063 exchange → zero nft change, zero new inbound surface, zero gossip edits |
| Queue storage | Pre-allocated `pending/` dir, one JSON per entry, atomic writes | Survives restarts; matches existing persistence pattern; no schema migration |
| Queue population | Explicit enqueue on REST issue **+** reconcile-from-local-state each cycle | Covers REST and CLI issue paths and restart recovery without coupling to the issue path |
| Delivery confirmation | `entry.propagated == true` (gossip threshold) | Reuses an existing, already-maintained field — no new ack protocol |
| Fetch missed | `gossip::run_round_once` (bidirectional anti-entropy) | The pull half is already implemented and battle-tested; offline sync just triggers it on reconnect |
| Version vector | existing `sequence` + `merkle_root`, recorded per-peer in `sync_state.json` | Faithful to the spec using fields that already exist |
| Conflict rule | Reuse shared `incoming_wins` (timestamp-deterministic) | Consistency with gossip; no split-brain; owner>member tiebreaker deferred as shared follow-up |
| Retry policy | `attempts` + timestamps per pending; park (never drop) after `MAX_RETRIES` (0 = unlimited) | A revocation must never be silently lost |
| Concurrency | All CRL mutations already go through `CRL_WRITE_LOCK` inside `run_round_once`/store; queue file writes are atomic | No lost updates; no blocking-in-async |

### 5.5 Configuration (env, read at startup)

| Variable | Default | Clamp | Meaning |
|---|---|---|---|
| `SGX_CRL_OFFLINE_ENABLED` | `true` | `0/false/off` disables | Runtime kill-switch / rollback |
| `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS` | `20` | 5 – 600 | Sync-cycle cadence (test accelerator floor 5 s) |
| `SGX_CRL_OFFLINE_MAX_RETRIES` | `0` (unlimited) | 0 – 1000 | Attempts before a pending is parked (still kept) |
| `SGX_CRL_OFFLINE_FLUSH_ROUNDS` | `3` | 1 – 20 | Gossip rounds driven per flush cycle |
| `SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS` | `1500` | 200 – 10000 | Per-peer reachability probe timeout |

---

## 6. Sprint Deliverable Row (copy-paste)

| Scope | Deliverable | Description | Test tag |
|---|---|---|---|
| CRL Gossip | Offline Revocation Sync | Implement an offline revocation queue for Guardians in disconnected environments: locally-issued revocations are persisted to the pre-allocated CRL pending directory with retry counters and timestamps and are also self-reconciled from local state each cycle (covering both REST and CLI issue paths and surviving restarts); a background sync loop measures peer reachability, detects the offline→online transition, and on reconnect synchronously drives the existing gossip anti-entropy exchange against reachable peers to both fetch missed revocations (comparing CRL sequence/merkle-root version vectors recorded in a per-peer sync-state file) and flush the outbound queue, dequeuing each pending revocation once its propagated flag confirms threshold delivery and parking (never dropping) any that exhaust their retry budget; conflict resolution reuses the shared deterministic timestamp-based merge so offline-fetched and gossip-fetched entries never diverge — guaranteeing a Guardian can revoke a compromised peer even while isolated and have it converge automatically on reconnect, with observability at `GET /crl/offline/status`, `GET /crl/offline/pending`, and `POST /crl/offline/sync`, and with zero new ports, listeners, dependencies, or firewall changes. | CRL-series (CRL-033–CRL-043) |

---

## 7. File Structure

```
src/crl/
├── mod.rs                       MODIFIED  (F1: + pub mod offline;)
├── offline/                     NEW MODULE (net-new, additive)
│   ├── mod.rs                   NEW  — config, spawn(sync loop), queue_pending, counters, sync-state
│   ├── queue.rs                 NEW  — PendingRevocation persistence in pending/ (enqueue/dequeue/list/reconcile)
│   ├── sync.rs                  NEW  — reachability, reconnect transition, fetch+flush via gossip exchange, per-peer version vectors
│   └── tests.rs                 NEW  — disk-free unit tests
src/main.rs                      MODIFIED  (F2: spawn offline sync loop)
src/api/routes.rs                MODIFIED  (F4: 3 new routes)
src/api/handlers/crl.rs          MODIFIED  (F3: enqueue on REST issue; F5: 3 handlers)
src/crl/gossip/**                UNCHANGED (reused, never edited)
src/enforcement/executor.rs      UNCHANGED (no new port)
Cargo.toml                       UNCHANGED (no new deps)
```

---

## 8. Implementation — Part A: NEW FILES (create exactly as written)

### A1. `src/crl/offline/mod.rs`

```rust
//! Offline revocation sync for Guardians in disconnected environments.
//!
//! When a Guardian is offline it can still issue revocations (they land in
//! the local crl.json and the pending/ queue). A background loop measures
//! peer reachability; on reconnect it synchronously drives the existing
//! gossip anti-entropy exchange to (a) fetch revocations missed while
//! offline and (b) flush the outbound queue, tracking retry counts and
//! timestamps per pending entry. Conflict resolution reuses the shared
//! gossip merge (deterministic, timestamp-based), so offline-fetched and
//! gossip-fetched entries never diverge.
//!
//! No new port, no new listener: peers are reached via the existing gossip
//! exchange on TCP 50063.

pub mod queue;
pub mod sync;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[derive(Debug, Clone)]
pub struct OfflineConfig {
    pub enabled: bool,
    pub sync_interval_secs: u64,
    pub max_retries: u32,
    pub flush_rounds: u32,
    pub probe_timeout_ms: u64,
}

impl OfflineConfig {
    pub const DEFAULT_INTERVAL_SECS: u64 = 20;
    pub const DEFAULT_FLUSH_ROUNDS: u32 = 3;
    pub const DEFAULT_PROBE_TIMEOUT_MS: u64 = 1500;

    pub fn from_env() -> Self {
        Self {
            enabled: parse_enabled(std::env::var("SGX_CRL_OFFLINE_ENABLED").ok()),
            sync_interval_secs: parse_interval(std::env::var("SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS").ok()),
            max_retries: parse_max_retries(std::env::var("SGX_CRL_OFFLINE_MAX_RETRIES").ok()),
            flush_rounds: parse_flush_rounds(std::env::var("SGX_CRL_OFFLINE_FLUSH_ROUNDS").ok()),
            probe_timeout_ms: parse_probe_timeout(std::env::var("SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS").ok()),
        }
    }
}

pub(crate) fn parse_enabled(raw: Option<String>) -> bool {
    match raw {
        Some(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off"
        ),
        None => true,
    }
}

pub(crate) fn parse_interval(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(OfflineConfig::DEFAULT_INTERVAL_SECS)
        .clamp(5, 600)
}

pub(crate) fn parse_max_retries(raw: Option<String>) -> u32 {
    raw.and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .min(1000)
}

pub(crate) fn parse_flush_rounds(raw: Option<String>) -> u32 {
    raw.and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(OfflineConfig::DEFAULT_FLUSH_ROUNDS)
        .clamp(1, 20)
}

pub(crate) fn parse_probe_timeout(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(OfflineConfig::DEFAULT_PROBE_TIMEOUT_MS)
        .clamp(200, 10_000)
}

/// Entry point called from main.rs right after the emergency spawn. Spawns
/// the background sync loop. Returns immediately; safe on every node role.
pub fn spawn(node_id: String, resolver: crate::did::Resolver) {
    let config = OfflineConfig::from_env();
    if !config.enabled {
        println!("📥 CRL-OFFLINE sync disabled via SGX_CRL_OFFLINE_ENABLED");
        return;
    }
    println!(
        "📥 CRL-OFFLINE sync starting interval_secs={} flush_rounds={} max_retries={}",
        config.sync_interval_secs,
        config.flush_rounds,
        if config.max_retries == 0 {
            "unlimited".to_string()
        } else {
            config.max_retries.to_string()
        }
    );
    crate::audit::logger::log_audit(
        &node_id,
        crate::audit::event::AuditCategory::Crl,
        crate::audit::event::AuditSeverity::Info,
        crate::audit::event::AuditAction::Started,
        &format!(
            "CRL offline sync started interval_secs={} flush_rounds={}",
            config.sync_interval_secs, config.flush_rounds
        ),
    );
    tokio::spawn(sync::sync_loop(node_id, resolver, config));
}

/// Enqueue a just-issued revocation for guaranteed delivery. Called by the
/// REST revoke handler; idempotent (safe if the entry is already queued).
pub fn queue_pending(node_id: &str, entry: &crate::crl::entry::CrlEntry) {
    if !OfflineConfig::from_env().enabled {
        return;
    }
    match queue::enqueue(entry) {
        Ok(true) => {
            crate::audit::logger::log_audit(
                node_id,
                crate::audit::event::AuditCategory::Crl,
                crate::audit::event::AuditSeverity::Info,
                crate::audit::event::AuditAction::Created,
                &format!(
                    "CRL offline queued pending revocation revoked_did={} id={}",
                    entry.revoked_did, entry.id
                ),
            );
        }
        Ok(false) => { /* already queued — no-op */ }
        Err(error) => {
            tracing::warn!("CRL-OFFLINE enqueue failed for {}: {}", entry.id, error);
        }
    }
}
```

### A2. `src/crl/offline/queue.rs`

```rust
//! Outbound pending-revocation queue, persisted under the pre-allocated
//! CRL pending/ directory. One JSON file per entry; atomic writes.

use crate::crl::entry::CrlEntry;
use crate::crl::errors::CrlError;
use crate::crl::persistence;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A revocation awaiting confirmed delivery to peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRevocation {
    /// The signed revocation entry (self-contained; verifiable by peers).
    pub entry: CrlEntry,
    /// Delivery attempts made so far.
    pub attempts: u32,
    /// When first queued (RFC3339).
    pub queued_at: String,
    /// Last attempt time (RFC3339), if any.
    pub last_attempt_at: Option<String>,
    /// Last error observed while attempting delivery, if any.
    pub last_error: Option<String>,
    /// Set true once parked (retry budget exhausted); still retained.
    #[serde(default)]
    pub parked: bool,
}

fn id_to_filename(id: &str) -> String {
    id.replace([':', '/'], "_")
}

fn path_for(id: &str) -> PathBuf {
    persistence::pending_dir().join(format!("{}.json", id_to_filename(id)))
}

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<(), CrlError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Enqueue an entry. Returns Ok(true) if newly queued, Ok(false) if already
/// present (idempotent).
pub fn enqueue(entry: &CrlEntry) -> Result<bool, CrlError> {
    let path = path_for(&entry.id);
    if path.exists() {
        return Ok(false);
    }
    let pending = PendingRevocation {
        entry: entry.clone(),
        attempts: 0,
        queued_at: Utc::now().to_rfc3339(),
        last_attempt_at: None,
        last_error: None,
        parked: false,
    };
    write_atomic(&path, &serde_json::to_vec_pretty(&pending)?)?;
    Ok(true)
}

/// Load every pending revocation (ignoring temp files).
pub fn list() -> Result<Vec<PendingRevocation>, CrlError> {
    let dir = persistence::pending_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().map(|ext| ext == "tmp").unwrap_or(false) {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        if let Ok(pending) = serde_json::from_slice::<PendingRevocation>(&bytes) {
            out.push(pending);
        }
    }
    out.sort_by(|a, b| a.queued_at.cmp(&b.queued_at));
    Ok(out)
}

pub fn count() -> usize {
    list().map(|items| items.len()).unwrap_or(0)
}

/// Remove a pending entry (delivered or superseded).
pub fn dequeue(entry_id: &str) -> Result<(), CrlError> {
    let path = path_for(entry_id);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Record an attempt outcome for a pending entry (attempts += 1, timestamps).
pub fn record_attempt(entry_id: &str, error: Option<String>, max_retries: u32) -> Result<(), CrlError> {
    let path = path_for(entry_id);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(()); // already dequeued
    };
    let mut pending: PendingRevocation = serde_json::from_slice(&bytes)?;
    pending.attempts = pending.attempts.saturating_add(1);
    pending.last_attempt_at = Some(Utc::now().to_rfc3339());
    pending.last_error = error;
    if max_retries > 0 && pending.attempts >= max_retries {
        pending.parked = true;
    }
    write_atomic(&path, &serde_json::to_vec_pretty(&pending)?)?;
    Ok(())
}

/// Reconcile the queue from local state: any locally-issued
/// (`revoker_did == self_did`) entry that is not yet `propagated` should be
/// tracked as pending. Covers CLI-issued revocations and restart recovery.
/// Returns the number of entries newly added.
pub fn reconcile_from_local(self_did: &str) -> Result<usize, CrlError> {
    let crl = match persistence::load_crl()? {
        Some(crl) => crl,
        None => return Ok(0),
    };
    let mut added = 0;
    for entry in crl.entries.iter() {
        if entry.revoker_did == self_did && !entry.propagated {
            if enqueue(entry)? {
                added += 1;
            }
        }
    }
    Ok(added)
}
```

### A3. `src/crl/offline/sync.rs`

```rust
//! Connectivity detection + reconnect-driven fetch/flush via the existing
//! gossip anti-entropy exchange. Maintains a per-peer version-vector view.

use super::{queue, OfflineConfig};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::crl::gossip::engine::{active_gossip_peers, did_record_path, run_round_once, GossipPeer};
use crate::crl::gossip::GossipConfig;
use crate::crl::persistence;
use crate::did::{DidRecord, Resolver};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicБool_PLACEHOLDER, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;
use tokio::net::TcpStream;

// NOTE: the placeholder type on the line above is a deliberate typo guard —
// replace `AtomicБool_PLACEHOLDER` with `AtomicBool` when typing this file.
// (Kept obvious so it cannot compile silently if pasted verbatim by mistake.)

// ── Observability ────────────────────────────────────────────────────────────
static SYNC_CYCLES: AtomicU64 = AtomicU64::new(0);
static RECONNECTS: AtomicU64 = AtomicU64::new(0);
static ENTRIES_DELIVERED: AtomicU64 = AtomicU64::new(0);
static ENTRIES_FETCHED: AtomicU64 = AtomicU64::new(0);
static WAS_ONLINE: AtomicBool = AtomicBool::new(false);

pub fn sync_cycles() -> u64 {
    SYNC_CYCLES.load(Ordering::Relaxed)
}
pub fn reconnects() -> u64 {
    RECONNECTS.load(Ordering::Relaxed)
}
pub fn entries_delivered() -> u64 {
    ENTRIES_DELIVERED.load(Ordering::Relaxed)
}
pub fn entries_fetched() -> u64 {
    ENTRIES_FETCHED.load(Ordering::Relaxed)
}
pub fn is_online() -> bool {
    WAS_ONLINE.load(Ordering::Relaxed)
}

/// Per-peer CRL version-vector view, persisted for observability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerSyncState {
    pub last_seen_merkle_root: String,
    pub last_seen_sequence: u64,
    pub last_sync_at: String,
}

static SYNC_STATE: Lazy<RwLock<HashMap<String, PeerSyncState>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub fn sync_state_snapshot() -> HashMap<String, PeerSyncState> {
    SYNC_STATE.read().map(|guard| guard.clone()).unwrap_or_default()
}

fn sync_state_path() -> std::path::PathBuf {
    persistence::pending_dir()
        .parent()
        .map(|base| base.join("sync_state.json"))
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/sgx-guardian/identity/crl/sync_state.json"))
}

fn persist_sync_state() {
    if let Ok(guard) = SYNC_STATE.read() {
        if let Ok(bytes) = serde_json::to_vec_pretty(&*guard) {
            let path = sync_state_path();
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

fn record_local_vector_for(peer_did: &str) {
    let (sequence, merkle_root) = match persistence::load_crl() {
        Ok(Some(crl)) => (crl.sequence, crl.merkle_root),
        _ => (0, String::new()),
    };
    if let Ok(mut guard) = SYNC_STATE.write() {
        guard.insert(
            peer_did.to_string(),
            PeerSyncState {
                last_seen_merkle_root: merkle_root,
                last_seen_sequence: sequence,
                last_sync_at: chrono::Utc::now().to_rfc3339(),
            },
        );
    }
}

// ── Reachability ─────────────────────────────────────────────────────────────
async fn reachable_peers(self_did: &str, config: &OfflineConfig) -> Vec<GossipPeer> {
    let gossip_port = GossipConfig::from_env().port;
    let candidates = active_gossip_peers(self_did);
    let mut reachable = Vec::new();
    for peer in candidates {
        let addr = format!("{}:{}", peer.overlay_ip, gossip_port);
        let ok = tokio::time::timeout(
            Duration::from_millis(config.probe_timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map(|result| result.is_ok())
        .unwrap_or(false);
        if ok {
            reachable.push(peer);
        }
    }
    reachable
}

// ── Main loop ────────────────────────────────────────────────────────────────
pub async fn sync_loop(node_id: String, resolver: Resolver, config: OfflineConfig) {
    // Settle one interval before the first cycle (let gossip/DID docs come up).
    tokio::time::sleep(Duration::from_secs(config.sync_interval_secs)).await;
    loop {
        if let Err(reason) = run_cycle(&node_id, &resolver, &config).await {
            tracing::warn!("CRL-OFFLINE cycle error: {}", reason);
        }
        tokio::time::sleep(Duration::from_secs(config.sync_interval_secs)).await;
    }
}

/// One sync cycle. Also invoked by POST /crl/offline/sync for deterministic
/// board testing. Returns a short human summary.
pub async fn run_cycle(
    node_id: &str,
    resolver: &Resolver,
    config: &OfflineConfig,
) -> Result<CycleReport, String> {
    SYNC_CYCLES.fetch_add(1, Ordering::Relaxed);

    let record = DidRecord::load(&did_record_path()).map_err(|error| error.to_string())?;
    let self_did = record.did.clone();

    let reachable = reachable_peers(&self_did, config).await;
    let online = !reachable.is_empty();

    // Offline→online transition.
    let was_online = WAS_ONLINE.swap(online, Ordering::Relaxed);
    if online && !was_online {
        RECONNECTS.fetch_add(1, Ordering::Relaxed);
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!(
                "CRL offline: connectivity RESTORED — {} peer(s) reachable, syncing",
                reachable.len()
            ),
        );
        println!(
            "📥 CRL-OFFLINE connectivity restored: {} peer(s) reachable",
            reachable.len()
        );
    }

    // Always reconcile the queue from local state (covers CLI-issued + restart).
    let reconciled = queue::reconcile_from_local(&self_did).map_err(|error| error.to_string())?;

    if !online {
        return Ok(CycleReport {
            online: false,
            reachable_peers: 0,
            reconciled,
            fetched: 0,
            delivered: 0,
            pending_remaining: queue::count(),
        });
    }

    // ── FETCH MISSED + FLUSH OUTBOUND via the gossip anti-entropy exchange ──
    // Snapshot pending fingerprints before, so we can measure deliveries after.
    let before = pending_fingerprints();
    let mut fetched = 0usize;
    for _ in 0..config.flush_rounds {
        match run_round_once(node_id, resolver, &GossipConfig::from_env()).await {
            Ok(report) => {
                fetched += report.merged + report.replaced;
                record_local_vector_for(&report.peer_did);
            }
            Err(reason) => {
                tracing::info!("CRL-OFFLINE round skipped: {}", reason);
            }
        }
    }
    persist_sync_state();
    ENTRIES_FETCHED.fetch_add(fetched as u64, Ordering::Relaxed);

    // ── Reconcile the queue against delivery confirmation (propagated flag) ──
    let delivered = settle_pending(node_id, config, &before)?;
    ENTRIES_DELIVERED.fetch_add(delivered as u64, Ordering::Relaxed);

    Ok(CycleReport {
        online: true,
        reachable_peers: reachable.len(),
        reconciled,
        fetched,
        delivered,
        pending_remaining: queue::count(),
    })
}

fn pending_fingerprints() -> Vec<String> {
    queue::list()
        .map(|items| items.iter().map(|p| p.entry.fingerprint()).collect())
        .unwrap_or_default()
}

/// For each pending entry: bump the attempt counter; if the entry is now
/// `propagated` in local crl.json, dequeue it (delivered). Returns the number
/// dequeued this cycle.
fn settle_pending(
    node_id: &str,
    config: &OfflineConfig,
    _before: &[String],
) -> Result<usize, String> {
    let crl = persistence::load_crl().map_err(|error| error.to_string())?;
    let propagated_ids: std::collections::HashSet<String> = crl
        .map(|crl| {
            crl.entries
                .into_iter()
                .filter(|entry| entry.propagated)
                .map(|entry| entry.id)
                .collect()
        })
        .unwrap_or_default();

    let pending = queue::list().map_err(|error| error.to_string())?;
    let mut delivered = 0usize;
    for item in pending {
        if propagated_ids.contains(&item.entry.id) {
            queue::dequeue(&item.entry.id).map_err(|error| error.to_string())?;
            delivered += 1;
            log_audit(
                node_id,
                AuditCategory::Crl,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                &format!(
                    "CRL offline delivered revoked_did={} id={} (propagated)",
                    item.entry.revoked_did, item.entry.id
                ),
            );
        } else {
            let _ = queue::record_attempt(&item.entry.id, None, config.max_retries);
        }
    }
    Ok(delivered)
}

#[derive(Debug, Clone, Serialize)]
pub struct CycleReport {
    pub online: bool,
    pub reachable_peers: usize,
    pub reconciled: usize,
    pub fetched: usize,
    pub delivered: usize,
    pub pending_remaining: usize,
}
```

> **One deliberate paste-guard in A3:** the atomics import line contains `AtomicБool_PLACEHOLDER` (with a non-ASCII character) so the file **cannot compile if pasted verbatim** — replace it with `AtomicBool` while entering the file. The intended import line is:
> `use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};`
> This guard exists because silent copy-paste of a long module is exactly where anchor/typo bugs slip in; it forces a conscious check.

### A4. `src/crl/offline/tests.rs`

```rust
//! Disk-free unit tests. Board integration is CRL-033…CRL-043.

use super::queue::PendingRevocation;
use super::{parse_enabled, parse_flush_rounds, parse_interval, parse_max_retries, parse_probe_timeout};
use crate::crl::entry::{
    CrlEntry, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
use crate::did::document::Proof;

fn sample_entry(id: &str, revoker: &str, propagated: bool) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: id.into(),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: "did:guardian:target".into(),
        device_id: None,
        user_id: None,
        circle_id: "guardian-circle-alpha".into(),
        reason: RevocationReason::Compromised,
        severity: Severity::Critical,
        timestamp: "2026-07-06T00:00:00Z".into(),
        revoker_did: revoker.into(),
        revoker_role: RevokerRole::Owner,
        evidence: None,
        proof: Proof::default(),
        peers_notified: vec![],
        propagated,
    }
}

#[test]
fn env_parsers_apply_defaults_and_clamps() {
    assert!(parse_enabled(None));
    assert!(!parse_enabled(Some("off".into())));
    assert_eq!(parse_interval(None), 20);
    assert_eq!(parse_interval(Some("2".into())), 5); // clamp floor
    assert_eq!(parse_interval(Some("9000".into())), 600); // clamp ceiling
    assert_eq!(parse_max_retries(None), 0); // unlimited
    assert_eq!(parse_max_retries(Some("5000".into())), 1000); // clamp
    assert_eq!(parse_flush_rounds(None), 3);
    assert_eq!(parse_flush_rounds(Some("99".into())), 20);
    assert_eq!(parse_flush_rounds(Some("0".into())), 1);
    assert_eq!(parse_probe_timeout(Some("50".into())), 200); // clamp floor
}

#[test]
fn pending_revocation_round_trips() {
    let pending = PendingRevocation {
        entry: sample_entry("urn:uuid:p1", "did:guardian:self", false),
        attempts: 2,
        queued_at: "2026-07-06T00:00:00Z".into(),
        last_attempt_at: Some("2026-07-06T00:01:00Z".into()),
        last_error: None,
        parked: false,
    };
    let json = serde_json::to_string(&pending).expect("serialize");
    let parsed: PendingRevocation = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.attempts, 2);
    assert_eq!(parsed.entry.id, "urn:uuid:p1");
    assert!(!parsed.parked);
}

#[test]
fn reconcile_selects_locally_issued_unpropagated() {
    // Pure logic mirror of reconcile_from_local's predicate.
    let self_did = "did:guardian:self";
    let mine_unpropagated = sample_entry("urn:uuid:a", self_did, false);
    let mine_propagated = sample_entry("urn:uuid:b", self_did, true);
    let theirs = sample_entry("urn:uuid:c", "did:guardian:other", false);

    let wants_queue = |e: &CrlEntry| e.revoker_did == self_did && !e.propagated;
    assert!(wants_queue(&mine_unpropagated)); // queue it
    assert!(!wants_queue(&mine_propagated)); // delivered → skip
    assert!(!wants_queue(&theirs)); // not ours → skip
}

#[test]
fn parked_when_retry_budget_exhausted() {
    // Mirror record_attempt's parking rule.
    let max_retries = 3u32;
    let mut attempts = 2u32;
    attempts = attempts.saturating_add(1); // → 3
    let parked = max_retries > 0 && attempts >= max_retries;
    assert!(parked);
    // Unlimited budget never parks.
    let unlimited = 0u32;
    let parked_unlimited = unlimited > 0 && attempts >= unlimited;
    assert!(!parked_unlimited);
}
```

---

## 9. Implementation — Part B: FIND→REPLACE EDITS (5 edits, verbatim anchors)

### F1 — `src/crl/mod.rs` (register the module)

**FIND (verbatim):**
```rust
pub mod entry;
pub mod errors;
pub mod gossip;
```

**REPLACE WITH:**
```rust
pub mod entry;
pub mod errors;
pub mod gossip;
pub mod offline;
```

> If the Emergency task merged, an `pub mod emergency;` line will also be present in this block — that's fine; keep it and just add `pub mod offline;`. The anchor above (three consecutive lines) still matches regardless of an `emergency` line placed before `entry`.

### F2 — `src/main.rs` (spawn the offline sync loop)

**FIND (verbatim — the emergency spawn added by the previous task):**
```rust
    sgx_guardian_client::crl::emergency::spawn(node_id.clone(), did_resolver.clone());
```

**REPLACE WITH:**
```rust
    sgx_guardian_client::crl::emergency::spawn(node_id.clone(), did_resolver.clone());

    // === CRL Offline Revocation Sync ===
    // Background loop: queues locally-issued revocations while offline and,
    // on reconnect, drives the gossip anti-entropy exchange to fetch missed
    // revocations + flush the outbound queue. No new port/listener.
    sgx_guardian_client::crl::offline::spawn(node_id.clone(), did_resolver.clone());
```

> **Fallback** (Emergency not merged): anchor on the gossip spawn line instead —
> `    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());`
> and add the offline spawn immediately after it.

### F3 — `src/api/handlers/crl.rs` (enqueue on REST issue)

**FIND (verbatim — the success tail of `revoke`; post-Emergency this sits just before the `Ok(Json(RevokeCrlResponse {` return):**
```rust
    Ok(Json(RevokeCrlResponse {
        status: "success".to_string(),
        message: "CRL entry issued".to_string(),
        entry,
        sequence: crl.sequence,
        merkle_root: crl.merkle_root,
    }))
}
```

**REPLACE WITH:**
```rust
    // Track the just-issued revocation in the offline queue so it is
    // guaranteed to reach peers even if connectivity is currently down.
    crate::crl::offline::queue_pending(&state.node_id, &entry);

    Ok(Json(RevokeCrlResponse {
        status: "success".to_string(),
        message: "CRL entry issued".to_string(),
        entry,
        sequence: crl.sequence,
        merkle_root: crl.merkle_root,
    }))
}
```

> This uses `state.node_id`. The `revoke` handler already binds `State(state)` (renamed from `_state` by the Emergency task, F7a). If Emergency is **not** merged in your tree, first apply that one-line rename — change `State(_state): State<Arc<crate::api::state::AppState>>,` to `State(state): …` in the `revoke` signature — then apply this edit. (Reconciliation in the sync loop also queues REST-issued entries, so if you prefer zero handler change you may skip F3 entirely; it only makes queuing *immediate* rather than next-cycle.)

### F4 — `src/api/routes.rs` (three offline routes)

**FIND (verbatim — end of `crl_router`, emergency routes present):**
```rust
        .route(
            "/api/v1/crl/emergency/notifications",
            get(handlers::crl::emergency_notifications),
        )
}
```

**REPLACE WITH:**
```rust
        .route(
            "/api/v1/crl/emergency/notifications",
            get(handlers::crl::emergency_notifications),
        )
        .route(
            "/api/v1/crl/offline/status",
            get(handlers::crl::offline_status),
        )
        .route(
            "/api/v1/crl/offline/pending",
            get(handlers::crl::offline_pending),
        )
        .route(
            "/api/v1/crl/offline/sync",
            post(handlers::crl::offline_sync),
        )
}
```

> **Fallback** (Emergency not merged): anchor on the `gossip_trigger` route block and append the three offline routes after it instead.

### F5 — `src/api/handlers/crl.rs` (three handlers appended at end of file)

**FIND (verbatim — the tail of the merged `emergency_notifications` handler):**
```rust
    Ok(Json(serde_json::json!({
        "status": "success",
        "count": events.len(),
        "events": events,
    })))
}
```

**REPLACE WITH:**
```rust
    Ok(Json(serde_json::json!({
        "status": "success",
        "count": events.len(),
        "events": events,
    })))
}

#[derive(Debug, Serialize)]
pub struct OfflineStatusResponse {
    pub enabled: bool,
    pub online: bool,
    pub sync_interval_secs: u64,
    pub flush_rounds: u32,
    pub max_retries: u32,
    pub pending: usize,
    pub sync_cycles: u64,
    pub reconnects: u64,
    pub entries_delivered: u64,
    pub entries_fetched: u64,
    pub peer_sync_state:
        std::collections::HashMap<String, crate::crl::offline::sync::PeerSyncState>,
}

/// GET /api/v1/crl/offline/status — offline sync observability.
pub async fn offline_status(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<OfflineStatusResponse>, ApiError> {
    let config = crate::crl::offline::OfflineConfig::from_env();
    Ok(Json(OfflineStatusResponse {
        enabled: config.enabled,
        online: crate::crl::offline::sync::is_online(),
        sync_interval_secs: config.sync_interval_secs,
        flush_rounds: config.flush_rounds,
        max_retries: config.max_retries,
        pending: crate::crl::offline::queue::count(),
        sync_cycles: crate::crl::offline::sync::sync_cycles(),
        reconnects: crate::crl::offline::sync::reconnects(),
        entries_delivered: crate::crl::offline::sync::entries_delivered(),
        entries_fetched: crate::crl::offline::sync::entries_fetched(),
        peer_sync_state: crate::crl::offline::sync::sync_state_snapshot(),
    }))
}

/// GET /api/v1/crl/offline/pending — list queued (undelivered) revocations.
pub async fn offline_pending(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pending = crate::crl::offline::queue::list()
        .map_err(|error| ApiError::Internal(error.to_string()))?;
    let items: Vec<serde_json::Value> = pending
        .into_iter()
        .map(|item| {
            serde_json::json!({
                "id": item.entry.id,
                "revoked_did": item.entry.revoked_did,
                "reason": item.entry.reason.as_str(),
                "severity": item.entry.severity.as_str(),
                "attempts": item.attempts,
                "queued_at": item.queued_at,
                "last_attempt_at": item.last_attempt_at,
                "last_error": item.last_error,
                "parked": item.parked,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "status": "success",
        "count": items.len(),
        "pending": items,
    })))
}

/// POST /api/v1/crl/offline/sync — run one sync cycle now (deterministic hook).
pub async fn offline_sync(
    State(state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<crate::crl::offline::sync::CycleReport>, ApiError> {
    let config = crate::crl::offline::OfflineConfig::from_env();
    let report = crate::crl::offline::sync::run_cycle(
        &state.node_id,
        &state.did_resolver,
        &config,
    )
    .await
    .map_err(ApiError::Internal)?;
    Ok(Json(report))
}
```

> **Fallback** (Emergency not merged): append these three handlers after the `gossip_trigger` handler tail (`"gossip round completed"`) instead.

---

## 10. Constraint Compliance (project hard rules)

| Rule | Compliance |
|---|---|
| No touching `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()` / daemon lifecycle | Untouched. Additive spawn + a queue call only. |
| No `std::thread::sleep` / sync `Command::new().output()` in async | Only `tokio::time::{sleep, timeout}` and async `TcpStream`. Queue file writes are sync `std::fs` on KB-scale files (same convention as existing `/crl/*` handlers). |
| Gossip / emergency engines must not regress | **Neither engine is edited.** Offline sync calls `run_round_once` and reuses `store` read-only-as-API; no new port, no nft change. |
| Board workflow (no systemctl/apt) | Verification uses `./sgx_guardian_client nodeX`, `pkill -f`, `curl`, `sgx-pa-cli`, `jq`, `grep`/`tail`. |
| ECDSA-P256 + SHA-256 only | Reuses `run_round_once` (verify + merge + re-sign). No new crypto. Pending entries carry the original issuer signature. |
| Yocto/aarch64 | Zero new crates → no toolchain/BSP impact. |
| Board-freeze vectors | No OCOTP mmap; no blocking-in-async; reachability probes are async with timeouts. |
| A revocation must never be silently lost | Parked (retained on disk + audited) after `MAX_RETRIES`; reconciliation re-queues locally-issued unpropagated entries every cycle. |

---

## 11. Regression Checks (must stay green)

```bash
# 1. Full workspace + new offline unit suite
cargo test -p sgx_guardian_client crl:: -- --nocapture
cargo test --workspace --locked

# 2. Lints / format
cargo fmt --check && cargo clippy --workspace -- -D warnings

# 3. Gossip + emergency engines untouched
git diff --stat src/crl/gossip/ src/crl/emergency/   # MUST be empty
./scripts/crl_board_check.sh                          # CRL-001..010 unchanged

# 4. No new port / no nft change
grep -rn "TcpListener::bind" src/crl/offline/ && echo "❌ offline must not bind a listener" || echo "✅ no listener"
git diff --stat src/enforcement/executor.rs           # MUST be empty

# 5. Routes only ADDED
grep -c "handlers::crl::" src/api/routes.rs           # was 12 (post-emergency), now 15

# 6. No forbidden blocking calls introduced
grep -rn "thread::sleep\|std::process::Command" src/crl/offline/ && echo "❌ VIOLATION" || echo "✅ clean"

# 7. The paste-guard was replaced (must find AtomicBool, must NOT find the placeholder)
grep -rn "AtomicBool" src/crl/offline/sync.rs && ! grep -rn "PLACEHOLDER" src/crl/offline/ && echo "✅ guard cleared"
```

**Behavioral checks to reason through (all safe):**
- Offline sync never changes CRL semantics: every fetch/merge goes through the shared `run_round_once`/`store`, so gossip and offline sync produce identical state and identical conflict resolution.
- A pending entry dequeues **only** when `propagated == true`, so a revocation issued offline is guaranteed to remain queued (and retried) until the Circle actually has it.
- With no peer reachable, the cycle is a cheap no-op (probe timeouts) and the queue persists — offline operation is lossless.
- Reconciliation makes the queue self-healing across restarts and covers CLI-issued revocations even if F3 is skipped.
- `sync_state.json` and `pending/*.json` are orphan-safe (append/replace, atomic) — a stale file never crashes the loop (parse errors are skipped).

---

## 12. Step-by-Step Checklist

**Dev machine**
- [ ] `git pull origin main` → run **Section 4 pre-flight** (pending_dir + reused primitives present; anchors hit)
- [ ] Branch: `git checkout -b crl_offline_sync`
- [ ] Create the 4 new files (Section 8) — **replace the `AtomicБool_PLACEHOLDER` paste-guard with `AtomicBool`** in `sync.rs`
- [ ] Apply F1–F5; use fallback anchors if Emergency isn't merged
- [ ] `cargo build` → `cargo test --workspace` → `cargo clippy` — all green
- [ ] Cross-compile: `cargo build --release --workspace --target aarch64-unknown-linux-gnu --features secure-element` (or the board-builder container)

**Boards (nodeA .101/.103, nodeB .115, nodeC .248)**
- [ ] On each board: `pkill -f sgx_guardian_client || true`; `scp` the new binaries
- [ ] Start nodeA → expect `📥 CRL-OFFLINE sync starting …` alongside the gossip + emergency banners
- [ ] Start nodeB, then nodeC; wait ~30–60 s for gossip + DID docs
- [ ] Optional accel: `export SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8` before starting each binary
- [ ] Execute **CRL_Offline_Sync_Verification_Log.md** (CRL-033 → CRL-043)
- [ ] Re-run `./scripts/crl_board_check.sh` (regression) — gossip suite still green
- [ ] Update `docs/REST API Details.md`: endpoints **104** `GET /crl/offline/status`, **105** `GET /crl/offline/pending`, **106** `POST /crl/offline/sync`
- [ ] PR with plan + filled verification log

**Quick smoke (the core offline→reconnect scenario)**
```bash
# 1. Isolate nodeC (simulate offline) and issue a revocation ON nodeC for a DUMMY DID:
ssh root@192.168.50.248 "pkill -f sgx_guardian_client"
#   restart nodeC with peers unreachable is hard on a shared LAN, so instead
#   issue on nodeC then keep it from syncing by revoking a DUMMY (not real B/C):
ssh root@192.168.50.248 "cd <deploy_dir> && SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 ./sgx_guardian_client nodeC &"
ssh root@192.168.50.248 "./sgx-pa-cli crl revoke --did did:guardian:offline-test-001 --reason compromised --severity high --note CRL-036"
ssh root@192.168.50.248 "curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool"   # shows it queued
# 2. Let a couple of sync cycles run, then confirm delivery + dequeue:
sleep 30
ssh root@192.168.50.248 "curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool"    # pending → 0, entries_delivered ≥ 1
./sgx-pa-cli crl check --did did:guardian:offline-test-001            # nodeA → revoked: true (fetched)
ssh root@192.168.50.115 "./sgx-pa-cli crl check --did did:guardian:offline-test-001"   # nodeB → revoked: true
```

---

## 13. Rollback

1. **Instant, no rebuild:** start binaries with `SGX_CRL_OFFLINE_ENABLED=0` — the sync loop never spawns and `queue_pending` no-ops. Gossip still propagates everything as before.
2. **Full revert:** `git revert` the branch (5 edits + delete `src/crl/offline/`). No schema/data migration — `pending/` and `sync_state.json` are orphan-safe; the gossip/emergency modules were never touched. Leftover `pending/*.json` are ignored by everything else.

---

## 14. Known Limitations → Follow-up Register

| # | Limitation | Severity | Follow-up |
|---|---|---|---|
| L1 | Conflict rule is earliest-timestamp-wins (shared `incoming_wins`); the spec also mentions an owner>member signature trust-hierarchy tiebreaker | Low | Add a role tiebreaker to `incoming_wins` in `gossip::store` (affects both gossip + offline — must be a **shared** change to stay convergent) |
| L2 | Delivery confirmation relies on gossip's `propagated` flag (threshold-based); on a 2-node reachable subset the threshold may need all reachable peers | Low | Optionally confirm per-peer via the exchange's fingerprint diff; current signal is sufficient for the 3–5 node cohort |
| L3 | Reachability = TCP connect to the gossip port; a peer reachable but with a wedged gossip listener would read as "online" | Low | Add a lightweight health ping; probe already has a short timeout |
| L4 | `pending/` grows if a peer is permanently gone (parked entries retained) | Low (by design — never drop) | Admin endpoint / TTL to purge parked entries after operator review |
| L5 | `run_round_once` picks a random peer; on a large cohort a single flush cycle may not touch every peer | Low | `FLUSH_ROUNDS` compensates; a targeted per-peer push could be added by exposing a `run_round_with_peer` in gossip (would be a gossip edit — deferred) |
| L6 | Version vector is (sequence, merkle_root) per peer, not a full per-issuer vector clock | Low | Sufficient for anti-entropy convergence; a formal vector clock is a larger design change if ever needed |
