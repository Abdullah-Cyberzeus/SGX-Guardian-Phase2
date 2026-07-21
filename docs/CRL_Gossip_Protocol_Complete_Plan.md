# CRL Gossip Protocol — Complete Development Plan
**Sprint 4 Task 2 (Distributed Coordination — CRL Gossip) | Scope: CRL Gossip | Deliverable: Gossip Protocol | Test tag: CRL-series (CRL-011 – CRL-021)**
**Repo:** `AsadAli-CyberZeus/SGX` (main) | **Grounded on:** latest indexed pull, 2026-07-05 | **Author:** Plan for Asad Ali

---

## 0. Grounding Statement (READ FIRST)

This plan was generated **after a full fresh pull of `main` via project knowledge**. Every FIND block below was confirmed **verbatim** in the current indexed source. Key facts confirmed on this pull:

| Fact confirmed on `main` | Consequence for this plan |
|---|---|
| `src/crl/{mod,entry,errors,issue,list,persistence,verify}.rs` fully merged (Sprint 4 Task 1) | Gossip builds **on top** — no schema changes needed |
| `CrlEntry` already has `peers_notified: Vec<String>` + `propagated: bool`, and **both `fingerprint()` and `canonical_bytes_for_sign()` deliberately exclude them** | Gossip can mutate these fields **without breaking entry signatures or Merkle-root convergence** — the schema was pre-allocated for exactly this task |
| `crl.json` at `/var/lib/sgx-guardian/identity/crl/crl.json`, per-entry history under `entries/`, atomic tmp+rename writes | Gossip persists through the same `crl::persistence` layer |
| `verify::verify_entry(entry, resolver, circle_id)` (async, ECDSA-P256 vs issuer DID Doc) exists | Received entries are re-verified with **existing** code — no new crypto |
| Peer DID Documents cached locally (`doc_persistence::list_peer_docs()`), each carrying an `SGXNebulaMesh` service endpoint `nebula://<overlay-ip>/24`, `sgx:status`, `sgx:nodeName`; synced from CA every 30 s (`DID_DOC_PULL_INTERVAL_SECS`) | Peer directory for gossip = cached peer docs. **No new discovery mechanism.** |
| House transport pattern = newline-delimited JSON over TCP (`nebula::registry_sync` on 50062, `did::doc_distribution`) with 10 s timeouts | Gossip uses the **same pattern** on a new dedicated port **50063** (grep confirmed: 50063 unused anywhere in `src/`) |
| `rand = "0.8"` already in `Cargo.toml` | **Zero new dependencies. Zero `Cargo.toml` changes. Zero cross-compile risk.** |
| `src/enforcement/executor.rs` builds an nftables `input` chain with **`policy drop`** and explicit port allows (50051-53, 50061, 50062, 50070, 4242, …) | **Regression caught:** port 50063 MUST be added to the allow list or enforcement apply will silently kill gossip. Edit F5 handles it. |
| REST API on 8443 runs on **all** nodes; `/crl/*` routes live in `routes.rs::crl_router()`; handlers in `src/api/handlers/crl.rs` | Observability endpoints extend the existing router. Gossip **node-to-node traffic is NOT on 8443** — deliberately, so the upcoming Phase-D auth middleware can never break inter-node gossip. |
| `scripts/crl_board_check.sh` covers CRL-001…CRL-010 | Gossip tests continue the series: **CRL-011…CRL-021** |
| `AuditCategory::Crl` + hash-chained audit logger exist and are used by `crl::issue` | All gossip events land in the same tamper-evident audit chain |

**Why TCP 50063 and not gRPC/8443:** (a) registry-sync line-JSON is the proven house pattern and is already tokio-native; (b) 8443 is about to gain auth middleware (Phase D) which would break unauthenticated node-to-node calls; (c) gossip must be symmetric/decentralized — every node is client **and** server, which the CA-centric 50062 service is not. Traffic rides the encrypted Nebula overlay, and trust comes from **per-entry ECDSA-P256 proofs re-verified on receipt**, never from the channel.

---

## 1. Task Description (verbatim from sprint document)

> Implement epidemic-style gossip protocol for decentralized CRL propagation without central authority. Each Guardian maintains local CRL copy. Periodically (every 1-5 minutes), Guardian randomly selects peer and exchanges CRL updates. Peer merges received revocations into local CRL, then forwards to other peers. Uses probabilistic flooding with anti-entropy mechanisms. Track which peers received each revocation in "peers_notified" list. Mark CRL entry as "propagated" after reaching threshold (e.g., 80% of Circle). Achieves eventual consistency across all Circle members even with network partitions.

---

## 2. Scope

### In scope (this task)
1. Background **gossip listener** on every node (TCP `50063`, all roles — nodeA is an ordinary peer, no central authority).
2. Background **round task**: every `interval` (default **60 s**, spec window 1–5 min, ±20 % jitter) pick **one random active peer** and run a push–pull **anti-entropy** exchange.
3. **Merge** received revocations after per-entry signature re-verification; deterministic conflict resolution so entry sets (and Merkle roots) **converge**.
4. **`peers_notified`** ack tracking per entry; **`propagated = true`** at `ceil(80 % × other Circle members)`.
5. Revoked peers excluded **both directions** (never dialed; inbound rejected).
6. REST observability: `GET /api/v1/crl/gossip/status`, `POST /api/v1/crl/gossip/trigger` (deterministic board-test hook).
7. Audit-chain + stdout logging for every round, merge, propagation flip, and rejection.
8. nftables allow rule for 50063 (regression fix).

### Out of scope (separate sprint tasks — do NOT bleed in)
- **Emergency Revocation** (Task 3): instant REVOCATION_NOTICE broadcast, session termination, push notifications.
- **Offline Revocation Sync** (Task 4): pending queue, retry counters, version vectors. *(Note: anti-entropy here already gives partition **convergence**; Task 4 adds the offline **outbound queue**.)*
- Demo visualization (Task 5).

---

## 3. What Already Exists on `main` (do not re-implement)

| Asset | Location | Used by gossip as |
|---|---|---|
| `CrlEntry` (+ `peers_notified`, `propagated`, `fingerprint()`) | `src/crl/entry.rs` | Wire payload + dedup key |
| `CertificateRevocationList` (`sequence`, `merkle_root`, `recompute_root()`, `upsert()`, pub `entries`) | `src/crl/list.rs` | Local state container |
| `persistence::{load_crl, save_crl, save_entry}` (atomic writes) | `src/crl/persistence.rs` | Disk layer |
| `verify::verify_entry` (async, resolver-based) | `src/crl/verify.rs` | Inbound trust gate |
| `issue::{current_circle_id, DEFAULT_CIRCLE_ID}` | `src/crl/issue.rs` | Circle scoping |
| `is_revoked(did)` | `src/crl/mod.rs` | Peer filtering |
| `DidRecord::load`, `DEFAULT_DID_PATH` | `src/did/` | Self identity |
| `vc::issue::load_runtime_key_manager(node_id)` | `src/vc/issue.rs` | Container re-signing key |
| `doc_sign::sign_in_place_generic` | `src/did/doc_sign.rs` | Container proof refresh |
| `doc_persistence::list_peer_docs()` + `SGXNebulaMesh` endpoints | `src/did/` | Peer directory |
| Hash-chained audit logger, `AuditCategory::Crl` | `src/audit/` | Event trail |
| REST `/crl/*` (endpoints 92–98) + `crl_router()` | `src/api/` | Router to extend |

---

## 4. Pre-Flight Anchor Verification (run BEFORE applying any edit)

Run from repo root on a **fresh `git pull origin main`**. **Every command must print a match** (except the collision check, which must print `port free`). If any anchor fails, STOP — the plan needs re-anchoring against the newer main.

```bash
git pull origin main && git log -1 --oneline

# F1 anchor — crl module block
grep -n "pub mod persistence;" src/crl/mod.rs

# F2 anchor — main.rs REST spawn block
grep -n "=== REST Admin API (axum) on :8443 ===" src/main.rs

# F3 anchor — crl_router
grep -n '"/api/v1/crl/root", get(handlers::crl::root)' src/api/routes.rs

# F4 anchor — handlers struct
grep -n "pub struct CrlRootResponse" src/api/handlers/crl.rs

# F5 anchor — nft allow list
grep -n 'tcp dport 50061 accept' src/enforcement/executor.rs

# Port collision check — MUST print "port free"
grep -rn "50063" src/ sgx-pa-cli/src/ && echo "❌ PORT COLLISION — pick another port" || echo "✅ port free"

# Confirm gossip fields pre-allocated (sanity)
grep -n "peers_notified" src/crl/entry.rs | head -3
grep -n "rand = " Cargo.toml
```

---

## 5. Architecture

### 5.1 Topology — fully symmetric, no hub

```
        nodeA (192.168.100.1)          Every node runs BOTH:
        ├─ gossip listener :50063        • listener_task  (serve inbound)
        ├─ round task (60s ± jitter)     • round_task     (dial 1 random peer)
        │
   ┌────┴─────────┬──────────────┐      Peer directory = cached peer DID Docs
   ▼              ▼              ▼      (already synced from CA every 30 s;
 nodeB          nodeC          nodeN     gossip itself never touches the CA)
 :50063         :50063         :50063
```

### 5.2 One exchange (push–pull anti-entropy, single TCP connection)

```
Initiator (A)                                   Responder (B)
─────────────                                   ─────────────
SyncRequest  {circle_id, sender_did,   ───▶     validate: kind, circle match,
              sequence, merkle_root,             sender ≠ self, sender not revoked,
              fingerprints[]}                    sender in local peer directory
                                                 diff against local set
             ◀───  SyncResponse {entries: B-has/A-lacks (full records),
                                  want:    A-has/B-lacks (fingerprints),
                                  merkle_root, sequence}
verify_entry() each ▸ merge ▸ resign
SyncPush {entries matching want}       ───▶     verify_entry() each ▸ merge ▸ resign
             ◀───  SyncAck {merged, merkle_root}
both sides: mark_peer_notified(other) ▸ flip propagated at threshold
```

- **Fast path:** equal Merkle roots ⇒ empty `entries` + empty `want` ⇒ the exchange is a cheap heartbeat that still records the ack (so `propagated` converges even when no data moves).
- **“Forwards to other peers”** emerges transitively: whatever B merged this round, B’s own next random round pushes onward (epidemic spread).
- **Probabilistic flooding:** uniform-random peer choice + ±20 % round jitter (both via existing `rand 0.8`).
- **Anti-entropy:** full fingerprint-set diff every round — any divergence (partition, restart, missed round, crash) self-heals on the next successful exchange. This is what delivers *eventual consistency across all Circle members even with network partitions*.

### 5.3 Design decisions

| Decision | Choice | Why |
|---|---|---|
| Transport | Line-JSON over TCP :50063 (registry-sync pattern) | Tokio-native, zero deps, symmetric, immune to future 8443 auth middleware |
| Trust anchor | Per-entry ECDSA-P256 proof re-verified via `verify_entry` on **every** receipt | Channel is never trusted; poisoning one entry cannot poison a batch (bad entries skipped + audited) |
| Dedup key | `entry.fingerprint()` (excludes proof + gossip fields) | Re-signed copies of the same fact dedup correctly |
| Conflict (two verified entries revoke same DID) | **Earlier `timestamp` wins; tie → lower fingerprint** — applied identically by all nodes | Deterministic ⇒ entry sets converge ⇒ Merkle roots converge (root equality is the CRL-014 pass gate) |
| `peers_notified` / `propagated` from remote copies | **Reset on ingest** (`normalized()`) | These are *local* bookkeeping; trusting remote values would let a peer fake propagation progress |
| Threshold | `ceil(pct% × other_members)`, floor 1; `other_members` = active, non-revoked cached peer docs excluding self | 3-node cohort: `ceil(0.8×2)=2` ⇒ `propagated` flips exactly when **both** peers have ack’d — cleanly demonstrable |
| Revoked-DID handling | Excluded from dial list, inbound rejected, never counted in `peers_notified` | Containment; matches spec intent |
| Container proof | After ANY mutation: `sequence += 1`, `generated_at`, `recompute_root()`, re-sign with local DKP (identical to `issue.rs` flow) | Local `crl.json` always self-consistent; `POST /crl/verify` stays green on every node |
| Concurrency | All read-modify-writes behind one process-global `tokio::sync::Mutex` (`CRL_WRITE_LOCK`); state reloaded from disk at the start of every mutation | Listener, round loop, and REST trigger can never lose each other’s updates |
| Self-revocation learned via gossip | Merge + Critical audit, nothing else | Session teardown belongs to Task 3 |

### 5.4 Configuration (env, read at startup)

| Variable | Default | Clamp | Meaning |
|---|---|---|---|
| `SGX_CRL_GOSSIP_ENABLED` | `true` | `0/false/off` disables | Runtime kill-switch (also the rollback path) |
| `SGX_CRL_GOSSIP_PORT` | `50063` | ≠ 0 | Listener + dial port |
| `SGX_CRL_GOSSIP_INTERVAL_SECS` | `60` | 10 – 300 | Round interval. Spec window is 60–300 s; the 10 s floor exists **only** as a board-test accelerator |
| `SGX_CRL_GOSSIP_THRESHOLD_PCT` | `80` | 1 – 100 | `propagated` threshold |

---

## 6. Sprint Deliverable Row (copy-paste)

| Scope | Deliverable | Description | Test tag |
|---|---|---|---|
| CRL Gossip | Gossip Protocol | Implement epidemic-style gossip for decentralized CRL propagation: every Guardian runs a gossip listener (TCP 50063) plus a periodic anti-entropy round task (default 60 s within the 1–5 min spec window, ±20 % jitter) that selects one random active peer from cached DID Documents and performs a push–pull fingerprint-set exchange; received entries are re-verified against issuer DID Documents (ECDSA-P256) before merge, deterministic earliest-timestamp conflict resolution keeps Merkle roots convergent, per-entry `peers_notified` acks flip `propagated` at ceil(80 % × Circle), revoked peers are excluded in both directions, and observability lands at `GET /crl/gossip/status` + `POST /crl/gossip/trigger` — achieving eventual consistency across all Circle members through partitions and restarts with zero new dependencies. | CRL-series (CRL-011–CRL-021) |

---

## 7. File Structure

```
src/crl/
├── mod.rs                     MODIFIED  (F1: + pub mod gossip;)
├── gossip/                    NEW MODULE (net-new, additive)
│   ├── mod.rs                 NEW  — config, env parsing, spawn()
│   ├── protocol.rs            NEW  — wire messages + line framing
│   ├── store.rs               NEW  — locked merge / ack / threshold ops
│   ├── engine.rs              NEW  — listener + rounds + peer directory
│   └── tests.rs               NEW  — disk-free unit tests
src/main.rs                    MODIFIED  (F2: spawn after REST API block)
src/api/routes.rs              MODIFIED  (F3: 2 new routes)
src/api/handlers/crl.rs        MODIFIED  (F4: 2 new handlers)
src/enforcement/executor.rs    MODIFIED  (F5: allow tcp 50063)
Cargo.toml                     UNCHANGED (rand 0.8 already present)
src/lib.rs                     UNCHANGED (crl already pub)
```

---

## 8. Implementation — Part A: NEW FILES (create exactly as written)

### A1. `src/crl/gossip/mod.rs`

```rust
//! Epidemic-style gossip protocol for decentralized CRL propagation
//! (Sprint 4 Task 2 — "Gossip Protocol", CRL-series).
//!
//! * Every Guardian keeps its local CRL copy (Sprint 4 Task 1 layer at
//!   /var/lib/sgx-guardian/identity/crl/). No central authority — nodeA
//!   participates as an ordinary peer.
//! * `round_task` fires every SGX_CRL_GOSSIP_INTERVAL_SECS (default 60 s,
//!   spec window 1–5 min) plus ±20 % jitter, picks ONE random active peer
//!   from cached peer DID Documents, and runs a push–pull anti-entropy
//!   exchange with it.
//! * `listener_task` serves inbound exchanges on SGX_CRL_GOSSIP_PORT
//!   (default 50063) on every node.
//! * Received entries are individually re-verified
//!   (`crl::verify::verify_entry`) against the issuer's DID Document
//!   before merging — the TCP channel is never trusted (it rides the
//!   encrypted Nebula overlay, but authenticity comes from per-entry
//!   ECDSA-P256 proofs).
//! * After each successful exchange both sides record the counterpart in
//!   every entry's `peers_notified` and flip `propagated` once
//!   peers_notified >= ceil(threshold_pct% × other Circle members).
//! * Anti-entropy = full fingerprint-set diff each round, so nodes
//!   converge to identical Merkle roots even after partitions, restarts,
//!   or missed rounds (eventual consistency).

pub mod engine;
pub mod protocol;
pub mod store;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// Runtime configuration sourced from environment with safe defaults.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub enabled: bool,
    pub port: u16,
    pub interval_secs: u64,
    pub threshold_pct: u8,
}

impl GossipConfig {
    pub const DEFAULT_PORT: u16 = 50063;
    pub const DEFAULT_INTERVAL_SECS: u64 = 60;
    pub const DEFAULT_THRESHOLD_PCT: u8 = 80;

    pub fn from_env() -> Self {
        Self {
            enabled: parse_enabled(std::env::var("SGX_CRL_GOSSIP_ENABLED").ok()),
            port: parse_port(std::env::var("SGX_CRL_GOSSIP_PORT").ok()),
            interval_secs: parse_interval(std::env::var("SGX_CRL_GOSSIP_INTERVAL_SECS").ok()),
            threshold_pct: parse_threshold(std::env::var("SGX_CRL_GOSSIP_THRESHOLD_PCT").ok()),
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

pub(crate) fn parse_port(raw: Option<String>) -> u16 {
    raw.and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(GossipConfig::DEFAULT_PORT)
}

/// Spec window is 1–5 minutes; the 10 s floor is relaxed strictly as a
/// board-testing accelerator (documented in the verification log).
pub(crate) fn parse_interval(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(GossipConfig::DEFAULT_INTERVAL_SECS)
        .clamp(10, 300)
}

pub(crate) fn parse_threshold(raw: Option<String>) -> u8 {
    raw.and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(GossipConfig::DEFAULT_THRESHOLD_PCT)
        .clamp(1, 100)
}

/// Entry point called from `main.rs` right after the REST API spawn.
/// Spawns two background tokio tasks and returns immediately. Never
/// blocks, never panics, safe on every node role (CA and members alike).
pub fn spawn(node_id: String, resolver: crate::did::Resolver) {
    let config = GossipConfig::from_env();
    if !config.enabled {
        println!("🗣️ CRL-GOSSIP disabled via SGX_CRL_GOSSIP_ENABLED");
        return;
    }
    println!(
        "🗣️ CRL-GOSSIP engine starting port={} interval_secs={} threshold_pct={}",
        config.port, config.interval_secs, config.threshold_pct
    );
    crate::audit::logger::log_audit(
        &node_id,
        crate::audit::event::AuditCategory::Crl,
        crate::audit::event::AuditSeverity::Info,
        crate::audit::event::AuditAction::Started,
        &format!(
            "CRL gossip engine started port={} interval_secs={} threshold_pct={}",
            config.port, config.interval_secs, config.threshold_pct
        ),
    );
    tokio::spawn(engine::listener_task(
        node_id.clone(),
        resolver.clone(),
        config.clone(),
    ));
    tokio::spawn(engine::round_task(node_id, resolver, config));
}
```

### A2. `src/crl/gossip/protocol.rs`

```rust
//! Wire protocol for the CRL gossip exchange.
//!
//! Transport: newline-delimited JSON over TCP — the same house pattern as
//! `nebula::registry_sync` (port 50062) and `did::doc_distribution`. The
//! stream rides the encrypted Nebula overlay, but the channel is NEVER the
//! trust anchor: every `CrlEntry` carries its own issuer signature and is
//! re-verified on receipt via `crl::verify::verify_entry`.
//!
//! Exchange shape (push–pull anti-entropy, one connection):
//!   initiator → responder : SyncRequest  { fingerprints, merkle_root, .. }
//!   responder → initiator : SyncResponse { entries (initiator-missing),
//!                                          want (responder-missing) }
//!   initiator → responder : SyncPush     { entries matching `want` }
//!   responder → initiator : SyncAck      { merged, merkle_root }

use crate::crl::entry::CrlEntry;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single protocol line (memory-abuse guard).
pub const MAX_LINE_BYTES: usize = 1_048_576;
/// Hard cap on entries carried in one message.
pub const MAX_ENTRIES_PER_MESSAGE: usize = 1000;
/// Per-read timeout (mirrors `doc_distribution::REQ_TIMEOUT_SECS`).
pub const IO_TIMEOUT_SECS: u64 = 10;

pub const KIND_REQUEST: &str = "crl_sync_request";
pub const KIND_RESPONSE: &str = "crl_sync_response";
pub const KIND_PUSH: &str = "crl_sync_push";
pub const KIND_ACK: &str = "crl_sync_ack";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub kind: String,
    pub circle_id: String,
    pub sender_did: String,
    pub sequence: u64,
    pub merkle_root: String,
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub kind: String,
    pub circle_id: String,
    pub sender_did: String,
    pub sequence: u64,
    pub merkle_root: String,
    /// Full entries the initiator is missing (responder-has / initiator-lacks).
    pub entries: Vec<CrlEntry>,
    /// Fingerprints the responder is missing (initiator-has / responder-lacks).
    pub want: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPush {
    pub kind: String,
    pub entries: Vec<CrlEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncAck {
    pub kind: String,
    pub merged: usize,
    pub merkle_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn write_json_line<W, T>(writer: &mut W, message: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line = serde_json::to_string(message).map_err(std::io::Error::other)?;
    if line.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::other(
            "gossip message exceeds MAX_LINE_BYTES",
        ));
    }
    line.push('\n');
    writer.write_all(line.as_bytes()).await
}

pub async fn read_json_line<R>(reader: &mut R) -> std::io::Result<String>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut line = String::new();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(IO_TIMEOUT_SECS),
        reader.read_line(&mut line),
    )
    .await
    .map_err(|_| std::io::Error::other("gossip read timeout"))??;
    if bytes == 0 {
        return Err(std::io::Error::other("gossip peer closed connection"));
    }
    if line.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::other("gossip line exceeds MAX_LINE_BYTES"));
    }
    Ok(line)
}
```

### A3. `src/crl/gossip/store.rs`

```rust
//! Serialized read–modify–write operations on the local CRL for gossip.
//!
//! All mutations from the listener task, the periodic round task, and the
//! REST trigger handler go through `CRL_WRITE_LOCK`, preventing lost
//! updates between concurrent exchanges inside this process.
//!
//! Known cross-process window: `POST /api/v1/crl/revoke` shells out to
//! `sgx-pa-cli`, which writes `crl.json` from a separate process. Both
//! writers use atomic tmp+rename (no torn files) and this module reloads
//! from disk at the start of every mutation, shrinking the lost-update
//! window to milliseconds. A cross-process advisory lock is a listed
//! follow-up hardening item.

use crate::crl::entry::CrlEntry;
use crate::crl::errors::CrlError;
use crate::crl::list::CertificateRevocationList;
use crate::crl::persistence;
use crate::did::DidRecord;
use crate::key_manager::KeyManager;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use tokio::sync::Mutex;

/// Serializes every CRL read–modify–write in this process.
pub static CRL_WRITE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Debug, Default)]
pub struct MergeOutcome {
    pub added: usize,
    pub replaced: usize,
    pub skipped: usize,
    /// Clones of the entries actually added or replaced (for audit).
    pub merged_entries: Vec<CrlEntry>,
    pub newly_propagated: Vec<String>,
    pub merkle_root: String,
    pub sequence: u64,
}

/// Deterministic conflict rule when two independently-issued, verified
/// entries revoke the SAME DID: earlier `timestamp` wins; ties break on
/// the lexicographically lower fingerprint. Every node applies the same
/// rule, so entry sets (and therefore Merkle roots) converge.
pub fn incoming_wins(existing: &CrlEntry, incoming: &CrlEntry) -> bool {
    let existing_ts = DateTime::parse_from_rfc3339(&existing.timestamp).ok();
    let incoming_ts = DateTime::parse_from_rfc3339(&incoming.timestamp).ok();
    match (incoming_ts, existing_ts) {
        (Some(incoming), Some(existing)) if incoming != existing => incoming < existing,
        _ => incoming.fingerprint() < existing.fingerprint(),
    }
}

/// Gossip-mutable fields are LOCAL bookkeeping. A remote copy's
/// `peers_notified` / `propagated` must never be inherited (a peer could
/// otherwise fake propagation progress) — reset them on ingest. The
/// fingerprint (dedup key) is unaffected because `fingerprint()` already
/// excludes these fields.
pub fn normalized(entry: &CrlEntry) -> CrlEntry {
    let mut cleaned = entry.clone();
    cleaned.peers_notified.clear();
    cleaned.propagated = false;
    cleaned
}

fn load_or_new(self_did: &str, circle_id: &str) -> Result<CertificateRevocationList, CrlError> {
    Ok(persistence::load_crl()?
        .unwrap_or_else(|| CertificateRevocationList::new(self_did, circle_id)))
}

fn resign_and_save(
    crl: &mut CertificateRevocationList,
    record: &DidRecord,
    km: &KeyManager,
) -> Result<(), CrlError> {
    crl.sequence += 1;
    crl.generated_at = Utc::now().to_rfc3339();
    crl.recompute_root();
    let canonical = crl.canonical_bytes_for_sign()?;
    let vm_ref = format!(
        "{}#dkp-v{}",
        record.did,
        record.current_dkp_version.max(1)
    );
    crate::did::doc_sign::sign_in_place_generic(&mut crl.proof, &canonical, km, &vm_ref)?;
    persistence::save_crl(crl)?;
    Ok(())
}

/// Merge entries that the CALLER HAS ALREADY VERIFIED
/// (`crl::verify::verify_entry`) into the local CRL.
pub fn merge_verified_entries(
    record: &DidRecord,
    km: &KeyManager,
    circle_id: &str,
    incoming: &[CrlEntry],
) -> Result<MergeOutcome, CrlError> {
    let mut crl = load_or_new(&record.did, circle_id)?;
    let mut outcome = MergeOutcome::default();

    for entry in incoming
        .iter()
        .take(super::protocol::MAX_ENTRIES_PER_MESSAGE)
    {
        let fingerprint = entry.fingerprint();
        if crl.entries.iter().any(|e| e.fingerprint() == fingerprint) {
            outcome.skipped += 1;
            continue;
        }
        if let Some(position) = crl
            .entries
            .iter()
            .position(|e| e.revoked_did == entry.revoked_did)
        {
            if incoming_wins(&crl.entries[position], entry) {
                crl.entries[position] = normalized(entry);
                persistence::save_entry(entry)?; // append-only history
                outcome.merged_entries.push(entry.clone());
                outcome.replaced += 1;
            } else {
                outcome.skipped += 1;
            }
            continue;
        }
        crl.entries.push(normalized(entry));
        persistence::save_entry(entry)?; // append-only history
        outcome.merged_entries.push(entry.clone());
        outcome.added += 1;
    }

    if outcome.added + outcome.replaced == 0 {
        outcome.merkle_root = crl.merkle_root.clone();
        outcome.sequence = crl.sequence;
        return Ok(outcome);
    }

    crl.entries
        .sort_by(|a, b| a.revoked_did.cmp(&b.revoked_did));
    resign_and_save(&mut crl, record, km)?;
    outcome.merkle_root = crl.merkle_root.clone();
    outcome.sequence = crl.sequence;
    Ok(outcome)
}

/// After a successful exchange with `peer_did`, record the ack on every
/// entry and flip `propagated` where `peers_notified` reaches
/// `threshold_count`. The revoked DID itself never counts as a recipient.
/// No-op writes are skipped, so steady state costs zero disk churn.
pub fn mark_peer_notified(
    record: &DidRecord,
    km: &KeyManager,
    circle_id: &str,
    peer_did: &str,
    threshold_count: usize,
) -> Result<MergeOutcome, CrlError> {
    let mut crl = load_or_new(&record.did, circle_id)?;
    let mut changed = false;
    let mut outcome = MergeOutcome::default();

    for entry in crl.entries.iter_mut() {
        if entry.revoked_did == peer_did {
            continue;
        }
        if !entry.peers_notified.iter().any(|did| did == peer_did) {
            entry.peers_notified.push(peer_did.to_string());
            changed = true;
        }
        if !entry.propagated && entry.peers_notified.len() >= threshold_count {
            entry.propagated = true;
            outcome.newly_propagated.push(entry.id.clone());
            changed = true;
        }
    }

    if changed {
        resign_and_save(&mut crl, record, km)?;
    }
    outcome.merkle_root = crl.merkle_root.clone();
    outcome.sequence = crl.sequence;
    Ok(outcome)
}

/// (sequence, merkle_root, fingerprints) of the local CRL.
pub fn snapshot() -> Result<(u64, String, Vec<String>), CrlError> {
    Ok(match persistence::load_crl()? {
        Some(crl) => (
            crl.sequence,
            crl.merkle_root.clone(),
            crl.entries.iter().map(|e| e.fingerprint()).collect(),
        ),
        None => (0, String::new(), Vec::new()),
    })
}

/// Local entries whose fingerprints are NOT in `known` (what the peer lacks).
pub fn entries_not_in(known: &HashSet<String>) -> Result<Vec<CrlEntry>, CrlError> {
    Ok(match persistence::load_crl()? {
        Some(crl) => crl
            .entries
            .iter()
            .filter(|e| !known.contains(&e.fingerprint()))
            .take(super::protocol::MAX_ENTRIES_PER_MESSAGE)
            .cloned()
            .collect(),
        None => Vec::new(),
    })
}

/// Local entries whose fingerprints ARE in `want` (what the peer asked for).
pub fn entries_matching(want: &HashSet<String>) -> Result<Vec<CrlEntry>, CrlError> {
    Ok(match persistence::load_crl()? {
        Some(crl) => crl
            .entries
            .iter()
            .filter(|e| want.contains(&e.fingerprint()))
            .take(super::protocol::MAX_ENTRIES_PER_MESSAGE)
            .cloned()
            .collect(),
        None => Vec::new(),
    })
}
```

### A4. `src/crl/gossip/engine.rs`

```rust
//! Gossip engine: inbound listener + periodic outbound rounds.

use super::protocol::{
    self, SyncAck, SyncPush, SyncRequest, SyncResponse, KIND_ACK, KIND_PUSH, KIND_REQUEST,
    KIND_RESPONSE,
};
use super::store;
use super::GossipConfig;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::crl::entry::{CrlEntry, Severity};
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};

// ── Runtime observability (read by GET /api/v1/crl/gossip/status) ──────────

static ROUNDS_INITIATED: AtomicU64 = AtomicU64::new(0);
static ROUNDS_SERVED: AtomicU64 = AtomicU64::new(0);
static ENTRIES_MERGED: AtomicU64 = AtomicU64::new(0);
static LAST_ROUND: Lazy<RwLock<Option<LastRound>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, Clone, Serialize)]
pub struct LastRound {
    pub direction: String, // "initiated" | "served"
    pub peer_did: String,
    pub peer_node: String,
    pub merged: usize,
    pub sent: usize,
    pub merkle_root: String,
    pub at: String, // RFC3339
}

pub fn rounds_initiated() -> u64 {
    ROUNDS_INITIATED.load(Ordering::Relaxed)
}
pub fn rounds_served() -> u64 {
    ROUNDS_SERVED.load(Ordering::Relaxed)
}
pub fn entries_merged_total() -> u64 {
    ENTRIES_MERGED.load(Ordering::Relaxed)
}
pub fn last_round() -> Option<LastRound> {
    LAST_ROUND.read().ok().and_then(|guard| guard.clone())
}

fn record_last_round(round: LastRound) {
    if let Ok(mut guard) = LAST_ROUND.write() {
        *guard = Some(round);
    }
}

// ── Identity / peer directory ───────────────────────────────────────────────

pub fn did_record_path() -> String {
    std::env::var("SGX_GUARDIAN_DID_PATH")
        .unwrap_or_else(|_| crate::did::DEFAULT_DID_PATH.to_string())
}

fn load_identity(node_id: &str) -> Result<(DidRecord, KeyManager, String), String> {
    let record =
        DidRecord::load(&did_record_path()).map_err(|error| format!("did record: {}", error))?;
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| format!("key manager: {}", error))?;
    let circle_id = crate::crl::issue::current_circle_id()
        .unwrap_or_else(|_| crate::crl::issue::DEFAULT_CIRCLE_ID.to_string());
    Ok((record, km, circle_id))
}

#[derive(Debug, Clone)]
pub struct GossipPeer {
    pub did: String,
    pub node_name: String,
    pub overlay_ip: String,
}

/// `"nebula://192.168.100.7/24"` → `Some("192.168.100.7")`
pub fn parse_nebula_endpoint(endpoint: &str) -> Option<String> {
    endpoint
        .strip_prefix("nebula://")
        .and_then(|cidr| cidr.split('/').next())
        .filter(|ip| !ip.is_empty())
        .map(|ip| ip.to_string())
}

/// Gossip candidates = cached peer DID Documents that are (a) not self,
/// (b) status "active", (c) not currently revoked, (d) advertising an
/// `SGXNebulaMesh` overlay endpoint. Revoked peers are excluded in BOTH
/// directions (never dialed here; inbound rejected in `handle_inbound`).
pub fn active_gossip_peers(self_did: &str) -> Vec<GossipPeer> {
    let docs = match crate::did::doc_persistence::list_peer_docs() {
        Ok(docs) => docs,
        Err(_) => return Vec::new(),
    };
    let mut peers = Vec::new();
    for doc in docs {
        if doc.id == self_did {
            continue;
        }
        if doc.sgx_status.as_deref() != Some("active") {
            continue;
        }
        if crate::crl::is_revoked(&doc.id) {
            continue;
        }
        let Some(overlay_ip) = doc
            .service
            .iter()
            .find(|service| service.svc_type == "SGXNebulaMesh")
            .and_then(|service| parse_nebula_endpoint(&service.service_endpoint))
        else {
            continue;
        };
        peers.push(GossipPeer {
            did: doc.id.clone(),
            node_name: doc.sgx_node_name.clone().unwrap_or_default(),
            overlay_ip,
        });
    }
    peers
}

/// `ceil(threshold_pct% × other_members)`, floored at 1.
/// 3-node cohort → other_members = 2 → ceil(1.6) = 2 acks flip `propagated`.
pub fn threshold_count(other_members: usize, threshold_pct: u8) -> usize {
    if other_members == 0 {
        return 1;
    }
    let raw = (other_members as f64) * (threshold_pct as f64) / 100.0;
    (raw.ceil() as usize).max(1)
}

#[derive(Debug, Clone, Serialize)]
pub struct RoundReport {
    pub peer_did: String,
    pub peer_node: String,
    pub merged: usize,
    pub replaced: usize,
    pub pushed: usize,
    pub peer_merged: usize,
    pub merkle_root: String,
    pub sequence: u64,
    pub newly_propagated: Vec<String>,
}

// ── Periodic round loop ─────────────────────────────────────────────────────

pub async fn round_task(node_id: String, resolver: Resolver, config: GossipConfig) {
    let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await; // consume the immediate first tick — settle one interval
    loop {
        tick.tick().await;
        // ±20 % jitter desynchronizes cohort rounds (probabilistic flooding).
        let jitter_ms = {
            let mut rng = rand::thread_rng();
            rng.gen_range(0..=config.interval_secs.saturating_mul(200))
        };
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
        match run_round_once(&node_id, &resolver, &config).await {
            Ok(report) => {
                println!(
                    "🗣️ CRL-GOSSIP round ok peer={} node={} merged={} pushed={} root={}",
                    report.peer_did,
                    report.peer_node,
                    report.merged + report.replaced,
                    report.pushed,
                    report.merkle_root
                );
            }
            Err(reason) => {
                tracing::warn!("CRL-GOSSIP round skipped: {}", reason);
            }
        }
    }
}

/// One full initiator-side exchange with ONE random active peer. Also
/// invoked by `POST /api/v1/crl/gossip/trigger` for deterministic board
/// testing. Stateless per call — all durable state lives in `crl.json`.
pub async fn run_round_once(
    node_id: &str,
    resolver: &Resolver,
    config: &GossipConfig,
) -> Result<RoundReport, String> {
    let (record, km, circle_id) = load_identity(node_id)?;
    let peers = active_gossip_peers(&record.did);
    if peers.is_empty() {
        return Err("no active gossip peers yet (peer DID documents not synced)".into());
    }
    let other_members = peers.len();
    let peer = {
        let mut rng = rand::thread_rng();
        peers
            .choose(&mut rng)
            .cloned()
            .expect("peer list verified non-empty")
    };
    exchange_with_peer(
        node_id,
        &record,
        &km,
        &circle_id,
        resolver,
        config,
        &peer,
        other_members,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn exchange_with_peer(
    node_id: &str,
    record: &DidRecord,
    km: &KeyManager,
    circle_id: &str,
    resolver: &Resolver,
    config: &GossipConfig,
    peer: &GossipPeer,
    other_members: usize,
) -> Result<RoundReport, String> {
    let addr = format!("{}:{}", peer.overlay_ip, config.port);
    let stream = tokio::time::timeout(
        Duration::from_secs(protocol::IO_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("timeout connecting {}", addr))?
    .map_err(|error| format!("connect {}: {}", addr, error))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // 1) advertise local snapshot
    let (sequence, merkle_root, fingerprints) = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::snapshot().map_err(|error| error.to_string())?
    };
    let local_set: HashSet<String> = fingerprints.iter().cloned().collect();
    let request = SyncRequest {
        kind: KIND_REQUEST.to_string(),
        circle_id: circle_id.to_string(),
        sender_did: record.did.clone(),
        sequence,
        merkle_root,
        fingerprints,
    };
    protocol::write_json_line(&mut write_half, &request)
        .await
        .map_err(|error| error.to_string())?;

    // 2) receive the peer's diff
    let line = protocol::read_json_line(&mut reader)
        .await
        .map_err(|error| error.to_string())?;
    let response: SyncResponse = serde_json::from_str(line.trim())
        .map_err(|error| format!("bad sync response: {}", error))?;
    if let Some(error) = response.error.as_deref() {
        return Err(format!("peer {} rejected exchange: {}", peer.did, error));
    }
    if response.kind != KIND_RESPONSE {
        return Err(format!("unexpected message kind '{}'", response.kind));
    }
    if response.circle_id != circle_id {
        return Err(format!(
            "circle mismatch: local={} peer={}",
            circle_id, response.circle_id
        ));
    }
    if response.sender_did != peer.did {
        return Err(format!(
            "peer identity mismatch: directory={} announced={}",
            peer.did, response.sender_did
        ));
    }

    // 3) verify + merge what the peer had that we lacked
    let verified = verify_batch(node_id, &response.entries, resolver, circle_id).await;
    let merge = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::merge_verified_entries(record, km, circle_id, &verified)
            .map_err(|error| error.to_string())?
    };
    audit_merged_entries(node_id, &merge.merged_entries, &peer.did);

    // 4) push what the peer asked for. `want` is filtered against OUR
    //    pre-merge set, so entries just received from this peer are never
    //    echoed back.
    let want: HashSet<String> = response
        .want
        .iter()
        .filter(|fingerprint| local_set.contains(*fingerprint))
        .cloned()
        .collect();
    let push_entries = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::entries_matching(&want).map_err(|error| error.to_string())?
    };
    let pushed = push_entries.len();
    let push = SyncPush {
        kind: KIND_PUSH.to_string(),
        entries: push_entries,
    };
    protocol::write_json_line(&mut write_half, &push)
        .await
        .map_err(|error| error.to_string())?;

    // 5) ack
    let ack_line = protocol::read_json_line(&mut reader)
        .await
        .map_err(|error| error.to_string())?;
    let ack: SyncAck = serde_json::from_str(ack_line.trim())
        .map_err(|error| format!("bad sync ack: {}", error))?;
    if let Some(error) = ack.error.as_deref() {
        return Err(format!("peer {} failed to merge push: {}", peer.did, error));
    }

    // 6) record the ack + propagation threshold on our side
    let threshold = threshold_count(other_members, config.threshold_pct);
    let noted = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::mark_peer_notified(record, km, circle_id, &peer.did, threshold)
            .map_err(|error| error.to_string())?
    };
    audit_propagated(node_id, &noted.newly_propagated, threshold);

    ROUNDS_INITIATED.fetch_add(1, Ordering::Relaxed);
    ENTRIES_MERGED.fetch_add((merge.added + merge.replaced) as u64, Ordering::Relaxed);
    record_last_round(LastRound {
        direction: "initiated".into(),
        peer_did: peer.did.clone(),
        peer_node: peer.node_name.clone(),
        merged: merge.added + merge.replaced,
        sent: pushed,
        merkle_root: noted.merkle_root.clone(),
        at: chrono::Utc::now().to_rfc3339(),
    });
    log_audit(
        node_id,
        AuditCategory::Crl,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "CRL gossip round peer={} node={} merged={} pushed={} peer_merged={} root={}",
            peer.did,
            peer.node_name,
            merge.added + merge.replaced,
            pushed,
            ack.merged,
            noted.merkle_root
        ),
    );

    Ok(RoundReport {
        peer_did: peer.did.clone(),
        peer_node: peer.node_name.clone(),
        merged: merge.added,
        replaced: merge.replaced,
        pushed,
        peer_merged: ack.merged,
        merkle_root: noted.merkle_root,
        sequence: noted.sequence,
        newly_propagated: noted.newly_propagated,
    })
}

// ── Inbound listener (runs on every node) ───────────────────────────────────

pub async fn listener_task(node_id: String, resolver: Resolver, config: GossipConfig) {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => {
            println!("🗣️ CRL-GOSSIP listener on {}", addr);
            listener
        }
        Err(error) => {
            eprintln!("❌ CRL-GOSSIP bind failed on {}: {}", addr, error);
            log_audit(
                &node_id,
                AuditCategory::Crl,
                AuditSeverity::Critical,
                AuditAction::Failed,
                &format!("CRL gossip listener bind failed on {}: {}", addr, error),
            );
            return;
        }
    };
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let node_id = node_id.clone();
                let resolver = resolver.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(reason) = handle_inbound(stream, &node_id, &resolver, &config).await
                    {
                        tracing::warn!("CRL-GOSSIP inbound from {} failed: {}", peer_addr, reason);
                    }
                });
            }
            Err(error) => eprintln!("CRL-GOSSIP accept error: {}", error),
        }
    }
}

async fn handle_inbound(
    stream: TcpStream,
    node_id: &str,
    resolver: &Resolver,
    config: &GossipConfig,
) -> Result<(), String> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let line = protocol::read_json_line(&mut reader)
        .await
        .map_err(|error| error.to_string())?;
    let request: SyncRequest = serde_json::from_str(line.trim())
        .map_err(|error| format!("bad sync request: {}", error))?;

    let (record, km, circle_id) = match load_identity(node_id) {
        Ok(identity) => identity,
        Err(reason) => {
            reject(&mut write_half, node_id, &request.circle_id, &reason).await;
            return Err(reason);
        }
    };

    // ── Zero-trust inbound validation ───────────────────────────────────────
    if request.kind != KIND_REQUEST {
        let reason = format!("unexpected message kind '{}'", request.kind);
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    }
    if request.circle_id != circle_id {
        let reason = format!(
            "circle mismatch: local={} peer={}",
            circle_id, request.circle_id
        );
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    }
    if request.sender_did == record.did {
        let reason = "sender_did equals local DID".to_string();
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    }
    if crate::crl::is_revoked(&request.sender_did) {
        let reason = format!("sender is revoked: {}", request.sender_did);
        audit_reject(node_id, &request.sender_did, &reason);
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    }
    let peers = active_gossip_peers(&record.did);
    let Some(sender) = peers
        .iter()
        .find(|peer| peer.did == request.sender_did)
        .cloned()
    else {
        let reason = format!("sender not in local peer directory: {}", request.sender_did);
        audit_reject(node_id, &request.sender_did, &reason);
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    };
    let other_members = peers.len();

    // ── Diff: what they lack / what we lack ─────────────────────────────────
    let their_set: HashSet<String> = request.fingerprints.iter().cloned().collect();
    let (sequence, merkle_root, local_fps, entries_for_them) = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        let (sequence, merkle_root, local_fps) =
            store::snapshot().map_err(|error| error.to_string())?;
        let entries_for_them =
            store::entries_not_in(&their_set).map_err(|error| error.to_string())?;
        (sequence, merkle_root, local_fps, entries_for_them)
    };
    let local_set: HashSet<String> = local_fps.into_iter().collect();
    let want: Vec<String> = request
        .fingerprints
        .iter()
        .filter(|fingerprint| !local_set.contains(*fingerprint))
        .cloned()
        .collect();
    let sent = entries_for_them.len();

    let response = SyncResponse {
        kind: KIND_RESPONSE.to_string(),
        circle_id: circle_id.clone(),
        sender_did: record.did.clone(),
        sequence,
        merkle_root,
        entries: entries_for_them,
        want,
        error: None,
    };
    protocol::write_json_line(&mut write_half, &response)
        .await
        .map_err(|error| error.to_string())?;

    // ── Receive + verify + merge their push ─────────────────────────────────
    let push_line = protocol::read_json_line(&mut reader)
        .await
        .map_err(|error| error.to_string())?;
    let push: SyncPush = serde_json::from_str(push_line.trim())
        .map_err(|error| format!("bad sync push: {}", error))?;
    if push.kind != KIND_PUSH {
        return Err(format!("unexpected message kind '{}'", push.kind));
    }
    let verified = verify_batch(node_id, &push.entries, resolver, &circle_id).await;
    let merge_result = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::merge_verified_entries(&record, &km, &circle_id, &verified)
    };
    let outcome = match merge_result {
        Ok(outcome) => outcome,
        Err(error) => {
            let message = error.to_string();
            let ack = SyncAck {
                kind: KIND_ACK.to_string(),
                merged: 0,
                merkle_root: String::new(),
                error: Some(message.clone()),
            };
            protocol::write_json_line(&mut write_half, &ack)
                .await
                .map_err(|error| error.to_string())?;
            return Err(message);
        }
    };
    audit_merged_entries(node_id, &outcome.merged_entries, &sender.did);
    let merged_count = outcome.added + outcome.replaced;
    let ack = SyncAck {
        kind: KIND_ACK.to_string(),
        merged: merged_count,
        merkle_root: outcome.merkle_root.clone(),
        error: None,
    };
    protocol::write_json_line(&mut write_half, &ack)
        .await
        .map_err(|error| error.to_string())?;

    // ── Record the ack + propagation threshold on our side ──────────────────
    let threshold = threshold_count(other_members, config.threshold_pct);
    let noted = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::mark_peer_notified(&record, &km, &circle_id, &sender.did, threshold)
            .map_err(|error| error.to_string())?
    };
    audit_propagated(node_id, &noted.newly_propagated, threshold);

    ROUNDS_SERVED.fetch_add(1, Ordering::Relaxed);
    ENTRIES_MERGED.fetch_add(merged_count as u64, Ordering::Relaxed);
    record_last_round(LastRound {
        direction: "served".into(),
        peer_did: sender.did.clone(),
        peer_node: sender.node_name.clone(),
        merged: merged_count,
        sent,
        merkle_root: noted.merkle_root.clone(),
        at: chrono::Utc::now().to_rfc3339(),
    });
    log_audit(
        node_id,
        AuditCategory::Crl,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "CRL gossip served peer={} node={} sent={} merged={} root={}",
            sender.did, sender.node_name, sent, merged_count, noted.merkle_root
        ),
    );
    Ok(())
}

// ── Shared helpers ──────────────────────────────────────────────────────────

async fn reject(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    local_identity: &str,
    circle_id: &str,
    reason: &str,
) {
    let response = SyncResponse {
        kind: KIND_RESPONSE.to_string(),
        circle_id: circle_id.to_string(),
        sender_did: local_identity.to_string(),
        sequence: 0,
        merkle_root: String::new(),
        entries: Vec::new(),
        want: Vec::new(),
        error: Some(reason.to_string()),
    };
    let _ = protocol::write_json_line(writer, &response).await;
}

/// Verify each received entry against the issuer's resolved DID Document.
/// Invalid entries are skipped (and audited) — one bad entry must never
/// poison a whole exchange.
async fn verify_batch(
    node_id: &str,
    entries: &[CrlEntry],
    resolver: &Resolver,
    circle_id: &str,
) -> Vec<CrlEntry> {
    let mut verified = Vec::new();
    for entry in entries.iter().take(protocol::MAX_ENTRIES_PER_MESSAGE) {
        match crate::crl::verify::verify_entry(entry, resolver, circle_id).await {
            Ok(()) => verified.push(entry.clone()),
            Err(error) => {
                tracing::warn!("CRL-GOSSIP rejected entry {}: {}", entry.id, error);
                log_audit(
                    node_id,
                    AuditCategory::Crl,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("CRL gossip rejected entry {}: {}", entry.id, error),
                );
            }
        }
    }
    verified
}

fn audit_merged_entries(node_id: &str, merged: &[CrlEntry], peer_did: &str) {
    for entry in merged {
        let severity = match entry.severity {
            Severity::Critical => AuditSeverity::Critical,
            Severity::High => AuditSeverity::Warning,
            Severity::Medium | Severity::Low => AuditSeverity::Info,
        };
        log_audit(
            node_id,
            AuditCategory::Crl,
            severity,
            AuditAction::Succeeded,
            &format!(
                "CRL gossip merged revocation revoked_did={} reason={} severity={} via_peer={}",
                entry.revoked_did,
                entry.reason.as_str(),
                entry.severity.as_str(),
                peer_did
            ),
        );
        println!(
            "🗣️ CRL-GOSSIP merged revocation revoked_did={} severity={} via_peer={}",
            entry.revoked_did,
            entry.severity.as_str(),
            peer_did
        );
    }
}

fn audit_propagated(node_id: &str, newly_propagated: &[String], threshold: usize) {
    for entry_id in newly_propagated {
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Info,
            AuditAction::Updated,
            &format!("CRL entry propagated id={} threshold={}", entry_id, threshold),
        );
        println!(
            "🗣️ CRL-GOSSIP entry propagated id={} threshold={}",
            entry_id, threshold
        );
    }
}

fn audit_reject(node_id: &str, sender_did: &str, reason: &str) {
    log_audit(
        node_id,
        AuditCategory::Crl,
        AuditSeverity::Warning,
        AuditAction::Failed,
        &format!("CRL gossip rejected sender={}: {}", sender_did, reason),
    );
}
```

### A5. `src/crl/gossip/tests.rs`

```rust
//! Disk-free unit tests for the gossip layer. Board integration is covered
//! by CRL-011…CRL-021 in CRL_Gossip_Verification_Log.md.

use super::engine::{parse_nebula_endpoint, threshold_count};
use super::store::{incoming_wins, normalized};
use super::{parse_enabled, parse_interval, parse_port, parse_threshold};
use crate::crl::entry::{
    CrlEntry, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
use crate::did::document::Proof;

fn sample_entry(revoked: &str, timestamp: &str, entry_id: &str) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: entry_id.to_string(),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: revoked.to_string(),
        device_id: None,
        user_id: None,
        circle_id: "guardian-circle-alpha".to_string(),
        reason: RevocationReason::Compromised,
        severity: Severity::Critical,
        timestamp: timestamp.to_string(),
        revoker_did: "did:guardian:issuer".to_string(),
        revoker_role: RevokerRole::Owner,
        evidence: None,
        proof: Proof::default(),
        peers_notified: vec!["did:guardian:peerX".to_string()],
        propagated: true,
    }
}

#[test]
fn threshold_math_matches_spec() {
    assert_eq!(threshold_count(2, 80), 2); // 3-node cohort: ceil(1.6)
    assert_eq!(threshold_count(4, 80), 4); // 5-node cohort: ceil(3.2)
    assert_eq!(threshold_count(1, 80), 1);
    assert_eq!(threshold_count(0, 80), 1); // degenerate: never zero
    assert_eq!(threshold_count(10, 100), 10);
    assert_eq!(threshold_count(10, 1), 1);
}

#[test]
fn nebula_endpoint_parsing() {
    assert_eq!(
        parse_nebula_endpoint("nebula://192.168.100.7/24"),
        Some("192.168.100.7".to_string())
    );
    assert_eq!(
        parse_nebula_endpoint("nebula://192.168.100.7"),
        Some("192.168.100.7".to_string())
    );
    assert_eq!(parse_nebula_endpoint("tcp://192.168.100.7:50061"), None);
    assert_eq!(parse_nebula_endpoint("nebula://"), None);
}

#[test]
fn conflict_rule_is_deterministic_and_symmetric() {
    let older = sample_entry("did:guardian:target", "2026-07-01T00:00:00Z", "urn:uuid:a");
    let newer = sample_entry("did:guardian:target", "2026-07-02T00:00:00Z", "urn:uuid:b");
    // Earlier timestamp wins from both perspectives.
    assert!(incoming_wins(&newer, &older));
    assert!(!incoming_wins(&older, &newer));
    // Identical timestamps: fingerprint tiebreak agrees from both sides —
    // exactly one direction can win.
    let twin_a = sample_entry("did:guardian:t2", "2026-07-01T00:00:00Z", "urn:uuid:c");
    let twin_b = sample_entry("did:guardian:t2", "2026-07-01T00:00:00Z", "urn:uuid:d");
    assert_ne!(
        incoming_wins(&twin_a, &twin_b),
        incoming_wins(&twin_b, &twin_a)
    );
}

#[test]
fn normalized_resets_remote_gossip_bookkeeping() {
    let entry = sample_entry("did:guardian:target", "2026-07-01T00:00:00Z", "urn:uuid:e");
    let cleaned = normalized(&entry);
    assert!(cleaned.peers_notified.is_empty());
    assert!(!cleaned.propagated);
    // Fingerprint (dedup key) is unchanged by normalization.
    assert_eq!(cleaned.fingerprint(), entry.fingerprint());
}

#[test]
fn env_parsers_apply_defaults_and_clamps() {
    assert!(parse_enabled(None));
    assert!(!parse_enabled(Some("0".into())));
    assert!(!parse_enabled(Some("false".into())));
    assert!(parse_enabled(Some("1".into())));
    assert_eq!(parse_port(None), 50063);
    assert_eq!(parse_port(Some("50099".into())), 50099);
    assert_eq!(parse_port(Some("junk".into())), 50063);
    assert_eq!(parse_interval(None), 60);
    assert_eq!(parse_interval(Some("3".into())), 10); // clamp floor
    assert_eq!(parse_interval(Some("900".into())), 300); // clamp ceiling
    assert_eq!(parse_threshold(None), 80);
    assert_eq!(parse_threshold(Some("0".into())), 1);
}

#[test]
fn protocol_messages_round_trip() {
    let request = super::protocol::SyncRequest {
        kind: super::protocol::KIND_REQUEST.to_string(),
        circle_id: "guardian-circle-alpha".into(),
        sender_did: "did:guardian:nodeA".into(),
        sequence: 7,
        merkle_root: "abc123".into(),
        fingerprints: vec!["fp1".into(), "fp2".into()],
    };
    let json = serde_json::to_string(&request).expect("serialize request");
    let parsed: super::protocol::SyncRequest =
        serde_json::from_str(&json).expect("parse request");
    assert_eq!(parsed.fingerprints.len(), 2);
    assert_eq!(parsed.merkle_root, "abc123");

    let ack = super::protocol::SyncAck {
        kind: super::protocol::KIND_ACK.to_string(),
        merged: 3,
        merkle_root: "def456".into(),
        error: None,
    };
    let json = serde_json::to_string(&ack).expect("serialize ack");
    assert!(!json.contains("error")); // skip_serializing_if respected
    let parsed: super::protocol::SyncAck = serde_json::from_str(&json).expect("parse ack");
    assert_eq!(parsed.merged, 3);
}
```

---

## 9. Implementation — Part B: FIND→REPLACE EDITS (5 edits, verbatim anchors)

### F1 — `src/crl/mod.rs` (register the module)

**FIND (verbatim):**
```rust
pub mod entry;
pub mod errors;
pub mod issue;
pub mod list;
pub mod persistence;
pub mod verify;
```

**REPLACE WITH:**
```rust
pub mod entry;
pub mod errors;
pub mod gossip;
pub mod issue;
pub mod list;
pub mod persistence;
pub mod verify;
```

### F2 — `src/main.rs` (spawn the engine on every node)

**FIND (verbatim):**
```rust
    // === REST Admin API (axum) on :8443 ===
    let api_state =
        sgx_guardian_client::api::state::AppState::from_env(node_id.clone(), did_resolver.clone());
    let api_bind: std::net::SocketAddr = "0.0.0.0:8443".parse().unwrap();
    tokio::spawn({
        let state = api_state.clone();
        async move {
            if let Err(e) = sgx_guardian_client::api::serve(state, api_bind).await {
                eprintln!("❌ REST API server failed: {:?}", e);
            }
        }
    });
```

**REPLACE WITH:**
```rust
    // === REST Admin API (axum) on :8443 ===
    let api_state =
        sgx_guardian_client::api::state::AppState::from_env(node_id.clone(), did_resolver.clone());
    let api_bind: std::net::SocketAddr = "0.0.0.0:8443".parse().unwrap();
    tokio::spawn({
        let state = api_state.clone();
        async move {
            if let Err(e) = sgx_guardian_client::api::serve(state, api_bind).await {
                eprintln!("❌ REST API server failed: {:?}", e);
            }
        }
    });

    // === CRL Gossip engine (Sprint 4 Task 2) ===
    // Decentralized epidemic revocation propagation: listener on
    // SGX_CRL_GOSSIP_PORT (default 50063) + periodic anti-entropy rounds.
    // Spawns two background tokio tasks; returns immediately; runs on
    // every node role (nodeA is an ordinary gossip peer, not a hub).
    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());
```

### F3 — `src/api/routes.rs` (two observability routes)

**FIND (verbatim):**
```rust
pub fn crl_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/crl/revoke", post(handlers::crl::revoke))
        .route("/api/v1/crl/unrevoke", post(handlers::crl::unrevoke))
        .route("/api/v1/crl/list", get(handlers::crl::list))
        .route("/api/v1/crl/entry", get(handlers::crl::entry))
        .route("/api/v1/crl/check", get(handlers::crl::check))
        .route("/api/v1/crl/verify", post(handlers::crl::verify))
        .route("/api/v1/crl/root", get(handlers::crl::root))
}
```

**REPLACE WITH:**
```rust
pub fn crl_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/crl/revoke", post(handlers::crl::revoke))
        .route("/api/v1/crl/unrevoke", post(handlers::crl::unrevoke))
        .route("/api/v1/crl/list", get(handlers::crl::list))
        .route("/api/v1/crl/entry", get(handlers::crl::entry))
        .route("/api/v1/crl/check", get(handlers::crl::check))
        .route("/api/v1/crl/verify", post(handlers::crl::verify))
        .route("/api/v1/crl/root", get(handlers::crl::root))
        .route(
            "/api/v1/crl/gossip/status",
            get(handlers::crl::gossip_status),
        )
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}
```

### F4 — `src/api/handlers/crl.rs` (two new handlers appended after `CrlRootResponse`)

**FIND (verbatim):**
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct CrlRootResponse {
    pub sequence: u64,
    pub merkle_root: String,
}
```

**REPLACE WITH:**
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct CrlRootResponse {
    pub sequence: u64,
    pub merkle_root: String,
}

#[derive(Debug, Serialize)]
pub struct GossipStatusResponse {
    pub enabled: bool,
    pub port: u16,
    pub interval_secs: u64,
    pub threshold_pct: u8,
    pub self_did: String,
    pub circle_id: String,
    pub other_members: usize,
    pub threshold_count: usize,
    pub sequence: u64,
    pub merkle_root: String,
    pub entries: usize,
    pub propagated: usize,
    pub rounds_initiated: u64,
    pub rounds_served: u64,
    pub entries_merged: u64,
    pub last_round: Option<crate::crl::gossip::engine::LastRound>,
}

#[derive(Debug, Serialize)]
pub struct GossipTriggerResponse {
    pub success: bool,
    pub peer_did: String,
    pub peer_node: String,
    pub merged: usize,
    pub pushed: usize,
    pub peer_merged: usize,
    pub merkle_root: String,
    pub newly_propagated: Vec<String>,
    pub message: String,
}

/// GET /api/v1/crl/gossip/status — gossip engine observability.
pub async fn gossip_status(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<GossipStatusResponse>, ApiError> {
    let config = crate::crl::gossip::GossipConfig::from_env();
    let self_did = crate::did::DidRecord::load(&crate::crl::gossip::engine::did_record_path())
        .map(|record| record.did)
        .unwrap_or_default();
    let circle_id = crate::crl::issue::current_circle_id()
        .unwrap_or_else(|_| crate::crl::issue::DEFAULT_CIRCLE_ID.to_string());
    let other_members = crate::crl::gossip::engine::active_gossip_peers(&self_did).len();
    let threshold_count =
        crate::crl::gossip::engine::threshold_count(other_members, config.threshold_pct);
    let (sequence, merkle_root, entries, propagated) =
        match persistence::load_crl().map_err(|error| ApiError::Internal(error.to_string()))? {
            Some(crl) => (
                crl.sequence,
                crl.merkle_root.clone(),
                crl.entries.len(),
                crl.entries.iter().filter(|entry| entry.propagated).count(),
            ),
            None => (0, String::new(), 0, 0),
        };
    Ok(Json(GossipStatusResponse {
        enabled: config.enabled,
        port: config.port,
        interval_secs: config.interval_secs,
        threshold_pct: config.threshold_pct,
        self_did,
        circle_id,
        other_members,
        threshold_count,
        sequence,
        merkle_root,
        entries,
        propagated,
        rounds_initiated: crate::crl::gossip::engine::rounds_initiated(),
        rounds_served: crate::crl::gossip::engine::rounds_served(),
        entries_merged: crate::crl::gossip::engine::entries_merged_total(),
        last_round: crate::crl::gossip::engine::last_round(),
    }))
}

/// POST /api/v1/crl/gossip/trigger — run ONE gossip round immediately with
/// a random active peer. Deterministic board-testing hook; the periodic
/// loop keeps running untouched.
pub async fn gossip_trigger(
    State(state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<GossipTriggerResponse>, ApiError> {
    let config = crate::crl::gossip::GossipConfig::from_env();
    let report =
        crate::crl::gossip::engine::run_round_once(&state.node_id, &state.did_resolver, &config)
            .await
            .map_err(ApiError::Internal)?;
    Ok(Json(GossipTriggerResponse {
        success: true,
        peer_did: report.peer_did,
        peer_node: report.peer_node,
        merged: report.merged + report.replaced,
        pushed: report.pushed,
        peer_merged: report.peer_merged,
        merkle_root: report.merkle_root,
        newly_propagated: report.newly_propagated,
        message: "gossip round completed".to_string(),
    }))
}
```

### F5 — `src/enforcement/executor.rs` (nftables allow — REGRESSION FIX)

**FIND (verbatim):**
```rust
    // Allow cert bootstrap
    out.push_str("    tcp dport 50061 accept\n");
```

**REPLACE WITH:**
```rust
    // Allow cert bootstrap
    out.push_str("    tcp dport 50061 accept\n");

    // Allow CRL gossip exchange (Sprint 4 Task 2 — decentralized revocation propagation)
    out.push_str("    tcp dport 50063 accept\n");
```

---

## 10. Constraint Compliance (project hard rules)

| Rule | How this plan complies |
|---|---|
| **No `std::thread::sleep()` / sync `Command::new().output()` in tokio runtime** | Only `tokio::time::{interval, sleep, timeout}` and async `TcpStream`/`TcpListener`. Zero process spawns. The interval uses the exact house pattern from `main.rs` (`set_missed_tick_behavior(Skip)` + consume-first-tick). |
| No touching `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()` / daemon lifecycle | Untouched. Insertion is a fire-and-forget spawn after the REST block. |
| Board workflow (no systemctl/journalctl/apt) | All verification commands use `./sgx_guardian_client nodeX`, `pkill -f`, `pgrep`, `grep`/`tail` on flat logs, `curl`, `./sgx-pa-cli`. |
| Yocto/aarch64 cross-compile | Zero new crates, zero native libs → no BSP/toolchain impact. |
| ECDSA-P256 + SHA-256 only | Reuses `verify_entry` / `sign_in_place_generic` / `fingerprint()` — no new crypto paths. |
| Blocking `std::fs` in async | Same convention the existing `/crl/*` handlers already use (`persistence::load_crl()` directly in async fns); files are KB-scale. Documented; no new pattern introduced. |

---

## 11. Regression Checks (run all — must stay green)

```bash
# 1. Full library tests (existing crl entry/list/issue/verify suites + new gossip suite)
cargo test -p sgx_guardian_client crl:: -- --nocapture
cargo test -p sgx_guardian_client

# 2. Lints/format
cargo fmt --check && cargo clippy -p sgx_guardian_client -- -D warnings

# 3. Existing CRL board suite (CRL-001…CRL-010) — unchanged behavior expected
./scripts/crl_board_check.sh

# 4. nft ruleset now carries the gossip allow
grep -n "50063" src/enforcement/executor.rs   # exactly one hit (the new allow)

# 5. Existing /crl/* endpoints untouched (routes only ADDED)
grep -c "handlers::crl::" src/api/routes.rs    # was 7, now 9

# 6. No forbidden blocking calls introduced in the new module
grep -rn "thread::sleep\|Command::new" src/crl/gossip/ && echo "❌ VIOLATION" || echo "✅ clean"

# 7. Registry sync (50062) / cert bootstrap (50061) untouched
git diff --stat src/nebula/ src/cert_service.rs src/server.rs   # must be empty
```

**Behavioral regressions to reason through (all safe):**
- `is_revoked()` consumers now see gossip-fresh data sooner — strictly an improvement, no interface change.
- A local `crl revoke` of a DID already merged via gossip correctly returns `AlreadyRevoked` (existing guard, intended).
- `POST /crl/verify` stays green on every node: merged entries keep original issuer proofs; container is re-signed locally after each mutation; Merkle root recomputed.
- CRL-009 (manual root parity via `scp`) still passes — gossip converges the roots anyway.
- Gossip fields never enter `fingerprint()` or the entry signing surface (confirmed in `entry.rs`), so `peers_notified`/`propagated` divergence across nodes can never block root convergence.

---

## 12. Step-by-Step Checklist

**Dev machine**
- [ ] `git pull origin main` → run **Section 4 pre-flight** (all anchors green, port free)
- [ ] Create branch: `git checkout -b crl_gossip`
- [ ] Create the 5 new files (Section 8, exactly as written)
- [ ] Apply F1–F5 (Section 9)
- [ ] `cargo build` → `cargo test -p sgx_guardian_client` → `cargo clippy` — all green
- [ ] Cross-compile: `cargo build --release --target aarch64-unknown-linux-gnu`

**Boards (nodeA 192.168.50.101/103, nodeB .115, nodeC .248)**
- [ ] On each board: `pkill -f sgx_guardian_client || true`
- [ ] `scp target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@<board>:<deploy_dir>/` (and `sgx-pa-cli` if workspace rebuilt it)
- [ ] Start nodeA first: `./sgx_guardian_client nodeA` → expect `🗣️ CRL-GOSSIP listener on 0.0.0.0:50063`
- [ ] Start nodeB, then nodeC the same way
- [ ] Optional test acceleration: `export SGX_CRL_GOSSIP_INTERVAL_SECS=15` before starting each binary
- [ ] Execute **CRL_Gossip_Verification_Log.md** (CRL-011 → CRL-021), filling Results/Verdicts
- [ ] Re-run `./scripts/crl_board_check.sh` (regression)
- [ ] Update `docs/REST API Details.md`: add endpoints **99** `GET /crl/gossip/status`, **100** `POST /crl/gossip/trigger`
- [ ] Commit + PR with plan + filled verification log attached

**Quick smoke (2 minutes, after all 3 nodes up)**
```bash
# nodeA
./sgx-pa-cli crl revoke --did did:guardian:gossipsmoke01 --reason compromised --severity critical --note "smoke"
curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger | python3 -m json.tool
# nodeB and nodeC (within seconds if trigger chained, else ≤ 2 intervals)
./sgx-pa-cli crl check --did did:guardian:gossipsmoke01     # → "revoked": true
./sgx-pa-cli crl root                                        # → identical merkle_root on A/B/C
```

---

## 13. Rollback

1. **Instant, no rebuild:** start binaries with `SGX_CRL_GOSSIP_ENABLED=0` — engine never spawns; everything else identical.
2. **Full revert:** `git revert` the branch commits (5 edits + delete `src/crl/gossip/`). No schema/data migration needed — `peers_notified`/`propagated` were already in the Task-1 schema with `#[serde(default)]`, so old binaries read gossip-touched `crl.json` files without issue.

---

## 14. Known Limitations → Follow-up Register

| # | Limitation | Severity | Follow-up |
|---|---|---|---|
| L1 | `sender_did` in the hello is channel-unauthenticated (same trust model as registry-sync 50062; overlay-encrypted; entries individually signed regardless) | Low | Signed hello / challenge-response — candidate for Task 3 hardening |
| L2 | Cross-process write window vs `sgx-pa-cli crl revoke` (atomic writes + reload-before-write shrink it to ms) | Low | Advisory `flock` on `crl.json` |
| L3 | `peers_notified` reflects only exchanges **this node** performed or served (remote values deliberately discarded) | By design | Task 5 demo can aggregate per-node views |
| L4 | Session termination / user push on merge of a critical revocation | Out of scope | **Emergency Revocation (Task 3)** owns this |
| L5 | Outbound revocation queue while fully offline | Out of scope | **Offline Revocation Sync (Task 4)**; anti-entropy already handles re-join convergence |
| L6 | `read_line` memory bound relies on the 10 s timeout + post-read length check (house pattern) | Low | Length-prefixed framing if cohorts grow |
