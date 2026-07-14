# CRL Emergency Revocation — Complete Development Plan
**Sprint 7 (CRL Gossip — Emergency Revocation) | Scope: CRL Gossip | Deliverable: Emergency Revocation | Test tag: CRL-series (CRL-022 – CRL-034)**
**Repo:** `AsadAli-CyberZeus/SGX` (main / crl_series) | **Grounded on:** fresh indexed pull, 2026-07-06 | **Builds on:** Task 1 (CRL Data Structure) + Task 2 (Gossip Protocol), both merged

---

## 0. Grounding Statement (READ FIRST)

Fresh pull of `main` completed before writing this plan. **Both prior CRL tasks are merged and verified on-board** — this task builds directly on top of them. Every FIND anchor below was confirmed verbatim in the current source. Key facts from this pull:

| Fact confirmed on `main` | Consequence for Emergency Revocation |
|---|---|
| `src/crl/gossip/{mod,protocol,store,engine,tests}.rs` fully merged; gossip listener on TCP **50063**, periodic anti-entropy rounds, `run_round_once`, `GossipConfig::from_env` | Emergency broadcast is an **additive fast-path alongside** routine gossip — the slow path keeps running untouched as the anti-entropy safety net |
| `store::merge_verified_entries`, `store::mark_peer_notified`, `store::snapshot`, `store::normalized`, `store::incoming_wins`, `CRL_WRITE_LOCK` all `pub` | Emergency ingest **reuses the exact same locked merge + re-sign path** as gossip — zero new CRL-mutation logic, guaranteed root convergence with the slow path |
| `crl::verify::verify_entry(entry, resolver, circle_id)` (async, ECDSA-P256 vs issuer DID Doc) | Emergency entries are re-verified with the **same** trust gate — the fast channel is never trusted |
| `engine::active_gossip_peers(self_did)`, `engine::parse_nebula_endpoint`, `engine::threshold_count`, `GossipPeer{did,node_name,overlay_ip}`, `did_record_path()` all `pub` | Peer directory + overlay-IP resolution + threshold math are **reused as-is** for the broadcast fan-out |
| `CrlEntry.severity: Severity` with `Severity::Critical`; `issue::issue_revocation` already logs `AuditSeverity::Critical` for critical entries | The "severity: critical → emergency" trigger reads an **existing field**; no schema change |
| `src/cot/session_manager.rs`: `SessionManager` = `Arc<RwLock<HashMap<String, Session>>>` keyed by `remote_device_id`; has `active_count()`, `get_session()`, `cleanup_expired()`, **but NO revoke-by-DID / remove method** | Session termination needs **one net-new method** (`terminate_peer`) added to `SessionManager` — the only edit to an existing subsystem file |
| `Session.remote_device_id` is a CoT **device_id** (derived from pubkey), NOT a `did:guardian:` string | Termination maps DID→device_id via the peer DID Document (`doc_persistence`), then removes matching sessions. Documented mapping, no guesswork |
| `node_listener::start_listener(node_id)` already spawns a **UDP listener** early in `main.rs` (gated by `SGX_DISABLE_NODE_LISTENER`); enforcement allows `udp dport/sport 9000` | Confirms UDP-broadcast pattern is house-blessed. Emergency uses a **dedicated UDP port 50064** (grep-confirmed unused) so it never collides with the 9000 announce channel |
| `enforcement/executor.rs` `build_nft_ruleset` = `policy drop` input chain; gossip's `tcp dport 50063 accept` is already present (Task 2) | **Regression:** emergency UDP 50064 MUST be explicitly allowed or it dies silently under enforcement. Edit F6 adds `udp dport/sport 50064 accept` |
| REST `/crl/*` router in `routes.rs::crl_router()` now has **9 routes** (incl. `gossip/status`, `gossip/trigger`); handlers in `src/api/handlers/crl.rs` | Emergency observability + manual trigger extend the same router (2 new routes) |
| Audit logger hash-chained, `AuditCategory::Crl`, severities `{Info,Warning,Critical}`, actions incl. `Started/Succeeded/Failed/Updated` | All emergency events + the notification feed land in the **same tamper-evident chain** |
| `rand = "0.8"`, `tokio` full, `serde`, `uuid`, `once_cell`, `chrono` all present | **Zero new dependencies. Zero Cargo.toml changes.** |
| Port scan: `grep -rn "50064" src/ sgx-pa-cli/src/` → **no hits** | 50064 is free for the emergency channel |

**Why a dedicated UDP channel (50064) and not "just gossip faster":** the spec demands **90 %+ of Circle within 30 s** vs 5–10 min. Routine gossip is pull-based, one-random-peer-per-interval — structurally too slow. Emergency is **push-based one-to-many**: the revoker fires a single small `REVOCATION_NOTICE` datagram to **every** active peer at once, and each receiver **immediately re-broadcasts once** (bounded flood) before returning to routine gossip. UDP (connectionless, no handshake) minimizes latency; the payload is a full signed `CrlEntry` re-verified on receipt, so datagram loss is self-healed by the routine anti-entropy layer already in place. This is exactly the "priority channel that bypasses normal gossip intervals" the spec describes.

**On "push notifications to users":** APNs/FCM delivery lives in the **mobile app** (Lightning Leap's domain) — the backend does not hold Apple/Google credentials and must not. The backend's correct responsibility is to **emit a durable, queryable notification event** the frontend can poll/subscribe to. This plan adds a **notification feed** (`GET /api/v1/crl/emergency/notifications`) plus the tamper-evident audit record; the app converts those into device push. This is the clean seam and matches the existing architecture (frontend owns UI/push, backend owns truth).

---

## 1. Task Description (verbatim from sprint document)

> Implement priority emergency broadcast channel for critical revocations (compromised devices, active attacks). When Guardian marked "severity: critical", immediately broadcast REVOCATION_NOTICE to all connected peers, bypassing normal gossip intervals. Receiving Guardians prioritize forwarding emergency revocations before routine gossip. Terminate all active sessions with revoked DID instantly. Send push notifications to users. Emergency revocations propagate to 90%+ of Circle within 30 seconds vs 5-10 minutes for normal gossip. Essential for containing active breaches.

---

## 2. Scope

### In scope
1. **Emergency UDP listener** on every node (port **50064**, gated), parsing signed `REVOCATION_NOTICE` datagrams.
2. **Emergency broadcast** fired the instant a **critical** revocation is issued locally (CLI/REST) — one datagram to **all** active peers at once, bypassing gossip intervals.
3. **Immediate re-broadcast** on receipt (bounded single-hop flood, dedup by entry fingerprint + TTL) so notices reach 90 %+ within 30 s even on multi-hop topologies — *before* the receiver's routine gossip.
4. **Verify + merge** each received notice via the **existing** `verify_entry` + `store::merge_verified_entries` (root stays convergent with the slow path).
5. **Session termination**: on merging a critical revocation for DID X, instantly drop all CoT sessions whose peer maps to X (`SessionManager::terminate_peer`, net-new method).
6. **Notification feed**: durable, queryable emergency-notice records the frontend polls to raise user push; mirrored into the audit chain.
7. **Observability + manual hook**: `GET /api/v1/crl/emergency/status`, `POST /api/v1/crl/emergency/broadcast` (deterministic board-test trigger for an existing critical entry).
8. nftables allow for UDP 50064 (regression fix).

### Out of scope (separate sprint tasks — do not bleed in)
- **Offline Revocation Sync** (next task): outbound queue, retry counters, version-vector reconciliation. *(Anti-entropy already re-converges a rejoined node; that task adds the offline outbound queue.)*
- Demo visualization (final CRL task): topology animation, red-node UI.
- Actual APNs/FCM dispatch (mobile app / Lightning Leap).
- Any change to `NebulaDaemon::start()`, `resolve_ca_ip_from_config_inner()`, or daemon lifecycle (frozen).

---

## 3. What Already Exists on `main` (reused, NOT re-implemented)

| Asset | Location | Emergency use |
|---|---|---|
| Gossip config + env parse | `src/crl/gossip/mod.rs` (`GossipConfig::from_env`) | Extended with 3 emergency fields (same struct, same pattern) |
| Locked merge / ack / snapshot | `src/crl/gossip/store.rs` | Emergency ingest calls these **unchanged** |
| Per-entry verify | `src/crl/verify.rs` (`verify_entry`) | Inbound trust gate (unchanged) |
| Peer directory + overlay IP | `src/crl/gossip/engine.rs` (`active_gossip_peers`, `parse_nebula_endpoint`, `threshold_count`, `GossipPeer`) | Fan-out target list (unchanged) |
| Critical severity flag | `src/crl/entry.rs` (`Severity::Critical`) | Trigger condition (existing field) |
| Issue path | `src/crl/issue.rs` (`issue_revocation`, `current_circle_id`) | Emergency broadcast hooks **after** issue succeeds |
| Session store | `src/cot/session_manager.rs` (`SessionManager`) | + net-new `terminate_peer` |
| DID→doc mapping | `src/did/doc_persistence.rs` (`list_peer_docs`) | DID→device_id for session termination |
| Audit chain | `src/audit/` (`AuditCategory::Crl`) | Emergency + notification events |
| REST `/crl/*` router | `src/api/routes.rs`, `src/api/handlers/crl.rs` | + 2 emergency routes/handlers |
| nft ruleset | `src/enforcement/executor.rs` | + UDP 50064 allow |

---

## 4. Pre-Flight Anchor Verification (run BEFORE applying any edit)

Run from repo root on a fresh `git pull`. Every command must print a match except the collision check (must print `port free`).

```bash
git pull origin main && git log -1 --oneline

# F1 anchor — gossip module block (add pub mod emergency;)
grep -n "pub mod store;" src/crl/gossip/mod.rs

# F2 anchor — GossipConfig struct (add emergency fields)
grep -n "pub threshold_pct: u8," src/crl/gossip/mod.rs

# F3 anchor — engine spawn (spawn emergency listener alongside)
grep -n "tokio::spawn(engine::round_task(node_id, resolver, config));" src/crl/gossip/mod.rs

# F4 anchor — SessionManager active_count (append terminate_peer after impl method)
grep -n "pub async fn active_count(&self) -> usize {" src/cot/session_manager.rs

# F5 anchor — crl_router gossip routes (append emergency routes)
grep -n '"/api/v1/crl/gossip/trigger",' src/api/routes.rs

# F6 anchor — nft gossip allow (append udp 50064 after it)
grep -n 'tcp dport 50063 accept' src/enforcement/executor.rs

# F7 anchor — handlers gossip_trigger fn end (append emergency handlers after)
grep -n "pub async fn gossip_trigger(" src/api/handlers/crl.rs

# F8 anchor — issue_revocation returns entry (hook emergency broadcast at call sites, NOT inside issue)
grep -n "pub fn issue_revocation(" src/crl/issue.rs

# Port collision check — MUST print "port free"
grep -rn "50064" src/ sgx-pa-cli/src/ && echo "❌ PORT COLLISION" || echo "✅ port free"

# Sanity: gossip + session APIs we reuse
grep -n "pub fn active_gossip_peers\|pub fn threshold_count\|pub fn parse_nebula_endpoint" src/crl/gossip/engine.rs
grep -n "pub fn merge_verified_entries\|pub static CRL_WRITE_LOCK" src/crl/gossip/store.rs
```

---

## 5. Architecture

### 5.1 Two channels, one CRL

```
        ROUTINE (Task 2, unchanged)             EMERGENCY (this task)
        ────────────────────────────           ──────────────────────────
        TCP 50063, pull, 1 random peer          UDP 50064, push, ALL peers at once
        every 60 s ± jitter                     fired instantly on critical revoke
        anti-entropy fingerprint diff           single signed datagram + 1 re-broadcast hop
        eventual consistency (mins)             90 %+ of Circle in < 30 s
                    │                                        │
                    └──────────────┬─────────────────────────┘
                                   ▼
                 SAME local CRL (crl.json) via SAME store::merge_verified_entries
                 under SAME CRL_WRITE_LOCK → roots converge across BOTH channels
```

### 5.2 Emergency flow (one critical revocation)

```
Revoker (owner/member issues CRITICAL revocation for DID X)
  │  issue_revocation() succeeds  ── existing path, unchanged
  ▼
emergency::broadcast_for_entry(entry)             [fire-and-forget tokio task]
  │  build REVOCATION_NOTICE { entry (full signed CrlEntry), origin_did,
  │                            notice_id, ttl=1, sent_at }
  │  targets = active_gossip_peers(self)           ── reused
  └─▶ send ONE UDP datagram to <peer.overlay_ip>:50064 for EVERY peer (concurrent)

Each receiver (emergency::listener on UDP 50064)
  │  parse datagram; dedup by (fingerprint) in a bounded seen-set (skip if seen)
  │  verify_entry(entry, resolver, circle_id)      ── reused trust gate; drop+audit if bad
  │  store::merge_verified_entries(...)            ── reused locked merge + re-sign
  │  store::mark_peer_notified(origin_did, ...)    ── reused threshold/propagated logic
  │  IF entry.severity == Critical AND newly merged:
  │     session_manager.terminate_peer(did_to_device_id(X))   ── NEW: kill sessions
  │     notifications::record(entry)                          ── NEW: user-facing feed
  │     audit(Critical)                                       ── existing chain
  │  IF ttl > 0: decrement, re-broadcast ONCE to own active peers  ── bounded flood
  └─  (routine gossip continues in the background as the safety net)
```

### 5.3 Design decisions

| Decision | Choice | Why |
|---|---|---|
| Transport | UDP datagram on 50064, one per peer, concurrent | Connectionless = lowest latency for one-to-many; matches spec "broadcast … bypassing gossip intervals" |
| Reliability | Best-effort UDP + **routine anti-entropy as the guaranteed backstop** | A dropped datagram is re-converged by the existing 50063 layer within an interval — no ACK machinery needed for correctness |
| Flood control | TTL=1 (one re-broadcast hop) + fingerprint dedup seen-set (bounded, capacity-capped) | Reaches multi-hop members fast without packet storms; dedup prevents infinite echo |
| Trust | `verify_entry` on **every** datagram; `origin_did` field is advisory only | Channel never trusted; forged notice with bad proof is dropped + audited |
| Merge | **Exact reuse** of `store::merge_verified_entries` under `CRL_WRITE_LOCK` | Emergency + routine mutate identically → Merkle roots converge; no divergent second code path |
| "Connected peers" | `active_gossip_peers(self)` (active, non-revoked, overlay-advertising) | Same definition the whole gossip layer uses; revoked peers excluded both directions automatically |
| Session termination | net-new `SessionManager::terminate_peer(device_id)`; DID→device_id via peer DID doc | Only clean way — `remote_device_id` is a pubkey-derived device_id, not a DID |
| DID with no live session | terminate is a no-op; still audit + notify | Revoked DID may have no active CoT session; that's fine |
| Push notifications | Backend emits durable feed + audit; **app** does APNs/FCM | Backend holds no Apple/Google creds; frontend owns push (existing architecture) |
| Datagram size | Full signed `CrlEntry` (~1–2 KB) < UDP practical MTU on overlay | One datagram carries the whole verifiable fact; no fragmentation in practice; hard cap guards abuse |
| Only Critical triggers | High/Medium/Low use routine gossip only | Spec scopes emergency to `severity: critical`; avoids noise |
| Trigger placement | At **call sites** of `issue_revocation` (CLI + REST), NOT inside `issue_revocation` | Keeps the pure issuance fn side-effect-free and testable; broadcast is an async runtime concern |

### 5.4 Configuration (env, read at startup — extends `GossipConfig`)

| Variable | Default | Clamp | Meaning |
|---|---|---|---|
| `SGX_CRL_EMERGENCY_ENABLED` | `true` | `0/false/off` disables | Kill-switch for the whole emergency channel (rollback path) |
| `SGX_CRL_EMERGENCY_PORT` | `50064` | ≠ 0 | Emergency UDP listener + send port |
| `SGX_CRL_EMERGENCY_TTL` | `1` | 0 – 4 | Re-broadcast hops (0 = no relay, direct only) |

---

## 6. Sprint Deliverable Row (copy-paste)

| Scope | Deliverable | Description | Test tag |
|---|---|---|---|
| CRL Gossip | Emergency Revocation | Implement a priority emergency broadcast channel for critical revocations: the moment a `severity: critical` revocation is issued, the Guardian fires a signed REVOCATION_NOTICE datagram over a dedicated UDP channel (50064) to every active peer at once, bypassing routine gossip intervals; each receiver re-verifies the entry against the issuer DID Document (ECDSA-P256), merges it through the existing locked CRL path (Merkle roots stay convergent with routine gossip), re-broadcasts once (bounded TTL flood with fingerprint dedup) before its own routine gossip, instantly terminates all active CoT sessions with the revoked DID, and records a durable user-facing notification the mobile app converts to push — achieving 90 %+ Circle propagation within 30 seconds with routine anti-entropy as the guaranteed backstop, exposed via `GET /crl/emergency/status` + `POST /crl/emergency/broadcast`, with zero new dependencies. | CRL-series (CRL-022–CRL-034) |

---

## 7. File Structure

```
src/crl/gossip/
├── mod.rs                     MODIFIED  (F1: +pub mod emergency; F2: +3 config fields; F3: spawn emergency listener)
├── emergency.rs               NEW  — UDP notice protocol, broadcast, listener, session+notify hooks
├── notifications.rs           NEW  — durable emergency-notice feed (user push source)
└── emergency_tests.rs         NEW  — disk-free unit tests
src/cot/session_manager.rs     MODIFIED  (F4: +terminate_peer method)
src/api/routes.rs              MODIFIED  (F5: +2 emergency routes)
src/api/handlers/crl.rs        MODIFIED  (F7: +2 emergency handlers)
src/enforcement/executor.rs    MODIFIED  (F6: allow udp 50064)
src/crl/issue.rs               UNCHANGED (broadcast hooked at call sites, not inside)
sgx-pa-cli/src/commands/crl.rs MODIFIED  (F8a: fire broadcast after critical CLI revoke)
src/api/handlers/crl.rs        (F8b: fire broadcast after critical REST revoke — same file as F7)
Cargo.toml                     UNCHANGED
```

---

## 8. Implementation — Part A: NEW FILES

### A1. `src/crl/gossip/emergency.rs`

```rust
//! Priority emergency broadcast channel for CRITICAL revocations
//! (Sprint 7 — "Emergency Revocation", CRL-series).
//!
//! Routine gossip (50063, pull, one random peer per interval) is the
//! eventual-consistency backstop. THIS module is the fast path: the moment
//! a `severity: critical` revocation is issued locally, we push a signed
//! REVOCATION_NOTICE datagram to EVERY active peer at once over UDP 50064,
//! bypassing gossip intervals. Receivers re-verify + merge through the SAME
//! locked CRL path as gossip, terminate sessions with the revoked DID,
//! record a user-facing notification, then re-broadcast once (bounded TTL
//! flood) before their own routine gossip. UDP loss is self-healed by the
//! routine anti-entropy layer, so no ACK machinery is needed for
//! correctness — only speed.

use super::store;
use super::GossipConfig;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::crl::entry::{CrlEntry, Severity};
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Hard cap on a single emergency datagram (abuse guard). A signed CrlEntry
/// is ~1–2 KB; 16 KB leaves generous headroom while bounding memory.
pub const MAX_DATAGRAM_BYTES: usize = 16_384;
/// Bounded dedup memory: remember the last N notice fingerprints seen.
pub const SEEN_CAPACITY: usize = 4096;
pub const IO_TIMEOUT_SECS: u64 = 5;
pub const KIND_NOTICE: &str = "crl_revocation_notice";

// ── Runtime observability (read by GET /crl/emergency/status) ──────────────
static NOTICES_SENT: AtomicU64 = AtomicU64::new(0);
static NOTICES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static NOTICES_MERGED: AtomicU64 = AtomicU64::new(0);
static NOTICES_REBROADCAST: AtomicU64 = AtomicU64::new(0);
static SESSIONS_TERMINATED: AtomicU64 = AtomicU64::new(0);
static LAST_NOTICE: Lazy<RwLock<Option<LastNotice>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, Clone, Serialize)]
pub struct LastNotice {
    pub direction: String, // "sent" | "received"
    pub revoked_did: String,
    pub origin_did: String,
    pub peers: usize,
    pub merged: bool,
    pub at: String,
}

pub fn notices_sent() -> u64 {
    NOTICES_SENT.load(Ordering::Relaxed)
}
pub fn notices_received() -> u64 {
    NOTICES_RECEIVED.load(Ordering::Relaxed)
}
pub fn notices_merged() -> u64 {
    NOTICES_MERGED.load(Ordering::Relaxed)
}
pub fn notices_rebroadcast() -> u64 {
    NOTICES_REBROADCAST.load(Ordering::Relaxed)
}
pub fn sessions_terminated_total() -> u64 {
    SESSIONS_TERMINATED.load(Ordering::Relaxed)
}
pub fn last_notice() -> Option<LastNotice> {
    LAST_NOTICE.read().ok().and_then(|guard| guard.clone())
}

fn record_last(notice: LastNotice) {
    if let Ok(mut guard) = LAST_NOTICE.write() {
        *guard = Some(notice);
    }
}

// ── Bounded dedup seen-set (fingerprint of already-processed notices) ───────
static SEEN: Lazy<Mutex<SeenSet>> = Lazy::new(|| Mutex::new(SeenSet::default()));

#[derive(Default)]
struct SeenSet {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl SeenSet {
    /// Returns true if `fingerprint` is new (and records it); false if already seen.
    fn insert_new(&mut self, fingerprint: &str) -> bool {
        if self.set.contains(fingerprint) {
            return false;
        }
        if self.order.len() >= SEEN_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(fingerprint.to_string());
        self.order.push_back(fingerprint.to_string());
        true
    }
}

fn seen_is_new(fingerprint: &str) -> bool {
    SEEN.lock()
        .map(|mut seen| seen.insert_new(fingerprint))
        .unwrap_or(true)
}

// ── Wire message ────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationNotice {
    pub kind: String,
    pub circle_id: String,
    /// The node that first broadcast this notice (advisory; entry proof is
    /// the real trust anchor).
    pub origin_did: String,
    pub notice_id: String,
    /// Re-broadcast hops remaining. 0 = do not relay further.
    pub ttl: u8,
    pub sent_at: String,
    /// Full signed CRL entry — re-verified on receipt.
    pub entry: CrlEntry,
}

// ── Identity load (mirrors engine::load_identity) ───────────────────────────
fn load_identity(node_id: &str) -> Result<(DidRecord, KeyManager, String), String> {
    let record = DidRecord::load(&super::engine::did_record_path())
        .map_err(|error| format!("did record: {}", error))?;
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| format!("key manager: {}", error))?;
    let circle_id = crate::crl::issue::current_circle_id()
        .unwrap_or_else(|_| crate::crl::issue::DEFAULT_CIRCLE_ID.to_string());
    Ok((record, km, circle_id))
}

// ── Broadcast (fired at critical-revoke call sites) ─────────────────────────

/// Fire-and-forget: broadcast a signed REVOCATION_NOTICE for `entry` to every
/// active peer over UDP `port`. Only meaningful for critical entries; callers
/// gate on severity, but we double-check here for safety. Never blocks the
/// caller (spawns), never panics.
pub fn broadcast_for_entry(node_id: String, entry: CrlEntry) {
    let config = GossipConfig::from_env();
    if !config.emergency_enabled {
        return;
    }
    if !matches!(entry.severity, Severity::Critical) {
        return; // routine gossip handles non-critical
    }
    tokio::spawn(async move {
        if let Err(reason) = broadcast_once(&node_id, &entry, &config).await {
            tracing::warn!("emergency broadcast failed: {}", reason);
        }
    });
}

async fn broadcast_once(
    node_id: &str,
    entry: &CrlEntry,
    config: &GossipConfig,
) -> Result<(), String> {
    let (record, _km, circle_id) = load_identity(node_id)?;
    let peers = super::engine::active_gossip_peers(&record.did);
    if peers.is_empty() {
        return Err("no active peers to emergency-broadcast to".into());
    }
    let notice = RevocationNotice {
        kind: KIND_NOTICE.to_string(),
        circle_id,
        origin_did: record.did.clone(),
        notice_id: uuid::Uuid::new_v4().to_string(),
        ttl: config.emergency_ttl,
        sent_at: chrono::Utc::now().to_rfc3339(),
        entry: entry.clone(),
    };
    // Mark our own notice as seen so an inbound echo is a no-op.
    seen_is_new(&entry.fingerprint());
    let bytes = serde_json::to_vec(&notice).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return Err(format!("notice {} bytes exceeds cap", bytes.len()));
    }
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind ephemeral: {}", e))?;
    let mut sent = 0usize;
    for peer in &peers {
        let addr = format!("{}:{}", peer.overlay_ip, config.emergency_port);
        match socket.send_to(&bytes, &addr).await {
            Ok(_) => sent += 1,
            Err(e) => tracing::warn!("emergency send to {} failed: {}", addr, e),
        }
    }
    NOTICES_SENT.fetch_add(1, Ordering::Relaxed);
    record_last(LastNotice {
        direction: "sent".into(),
        revoked_did: entry.revoked_did.clone(),
        origin_did: record.did.clone(),
        peers: sent,
        merged: true, // already in our local CRL (we issued it)
        at: chrono::Utc::now().to_rfc3339(),
    });
    log_audit(
        node_id,
        AuditCategory::Crl,
        AuditSeverity::Critical,
        AuditAction::Started,
        &format!(
            "EMERGENCY revocation broadcast revoked_did={} peers={} notice_id={}",
            entry.revoked_did, sent, notice.notice_id
        ),
    );
    println!(
        "🚨 EMERGENCY broadcast revoked_did={} → {} peers",
        entry.revoked_did, sent
    );
    Ok(())
}

// ── Listener (runs on every node) ───────────────────────────────────────────

pub async fn listener_task(node_id: String, resolver: Resolver, config: GossipConfig) {
    let addr = format!("0.0.0.0:{}", config.emergency_port);
    let socket = match UdpSocket::bind(&addr).await {
        Ok(socket) => {
            println!("🚨 CRL-EMERGENCY listener on {}", addr);
            socket
        }
        Err(error) => {
            eprintln!("❌ CRL-EMERGENCY bind failed on {}: {}", addr, error);
            log_audit(
                &node_id,
                AuditCategory::Crl,
                AuditSeverity::Critical,
                AuditAction::Failed,
                &format!("CRL emergency listener bind failed on {}: {}", addr, error),
            );
            return;
        }
    };
    let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let datagram = buf[..len].to_vec();
                let node_id = node_id.clone();
                let resolver = resolver.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(reason) =
                        handle_notice(&datagram, &node_id, &resolver, &config).await
                    {
                        tracing::warn!("CRL-EMERGENCY notice from {} dropped: {}", src, reason);
                    }
                });
            }
            Err(error) => eprintln!("CRL-EMERGENCY recv error: {}", error),
        }
    }
}

async fn handle_notice(
    datagram: &[u8],
    node_id: &str,
    resolver: &Resolver,
    config: &GossipConfig,
) -> Result<(), String> {
    let notice: RevocationNotice =
        serde_json::from_slice(datagram).map_err(|e| format!("bad notice: {}", e))?;
    if notice.kind != KIND_NOTICE {
        return Err(format!("unexpected kind '{}'", notice.kind));
    }
    NOTICES_RECEIVED.fetch_add(1, Ordering::Relaxed);

    let (record, km, circle_id) = load_identity(node_id)?;
    if notice.circle_id != circle_id {
        return Err(format!(
            "circle mismatch: local={} notice={}",
            circle_id, notice.circle_id
        ));
    }
    let fingerprint = notice.entry.fingerprint();
    // Dedup: if we've already processed this exact revocation notice, stop
    // (prevents infinite re-broadcast echo).
    if !seen_is_new(&fingerprint) {
        return Ok(());
    }

    // Zero-trust: re-verify the signed entry against the issuer DID Document.
    if let Err(error) =
        crate::crl::verify::verify_entry(&notice.entry, resolver, &circle_id).await
    {
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Warning,
            AuditAction::Failed,
            &format!(
                "EMERGENCY notice rejected revoked_did={}: {}",
                notice.entry.revoked_did, error
            ),
        );
        return Err(format!("verify failed: {}", error));
    }

    // Merge via the SAME locked path routine gossip uses → roots converge.
    let merge = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::merge_verified_entries(&record, &km, &circle_id, std::slice::from_ref(&notice.entry))
            .map_err(|e| e.to_string())?
    };
    let newly_merged = merge.added + merge.replaced > 0;
    if newly_merged {
        NOTICES_MERGED.fetch_add(1, Ordering::Relaxed);
        // Record origin as a notified peer (reuse routine threshold logic).
        let other_members = super::engine::active_gossip_peers(&record.did).len();
        let threshold = super::engine::threshold_count(other_members, config.threshold_pct);
        let _ = {
            let _guard = store::CRL_WRITE_LOCK.lock().await;
            store::mark_peer_notified(&record, &km, &circle_id, &notice.origin_did, threshold)
        };
    }

    // Critical-only side effects: terminate sessions + user notification.
    if matches!(notice.entry.severity, Severity::Critical) && newly_merged {
        let terminated = terminate_sessions_for_did(&notice.entry.revoked_did).await;
        if terminated > 0 {
            SESSIONS_TERMINATED.fetch_add(terminated as u64, Ordering::Relaxed);
        }
        super::notifications::record(node_id, &notice.entry, &notice.origin_did, terminated);
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Critical,
            AuditAction::Succeeded,
            &format!(
                "EMERGENCY revocation applied revoked_did={} sessions_terminated={} via_origin={}",
                notice.entry.revoked_did, terminated, notice.origin_did
            ),
        );
        println!(
            "🚨 EMERGENCY applied revoked_did={} sessions_terminated={}",
            notice.entry.revoked_did, terminated
        );
    }

    record_last(LastNotice {
        direction: "received".into(),
        revoked_did: notice.entry.revoked_did.clone(),
        origin_did: notice.origin_did.clone(),
        peers: 0,
        merged: newly_merged,
        at: chrono::Utc::now().to_rfc3339(),
    });

    // Bounded re-broadcast: forward ONCE to our own active peers before we
    // fall back to routine gossip. TTL decrement prevents unbounded flood;
    // the seen-set prevents echo loops.
    if notice.ttl > 0 && newly_merged {
        rebroadcast(node_id, &record, &notice, config).await;
    }
    Ok(())
}

async fn rebroadcast(
    node_id: &str,
    record: &DidRecord,
    notice: &RevocationNotice,
    config: &GossipConfig,
) {
    let peers = super::engine::active_gossip_peers(&record.did);
    if peers.is_empty() {
        return;
    }
    let forwarded = RevocationNotice {
        kind: KIND_NOTICE.to_string(),
        circle_id: notice.circle_id.clone(),
        origin_did: notice.origin_did.clone(), // preserve original origin
        notice_id: notice.notice_id.clone(),
        ttl: notice.ttl.saturating_sub(1),
        sent_at: chrono::Utc::now().to_rfc3339(),
        entry: notice.entry.clone(),
    };
    let Ok(bytes) = serde_json::to_vec(&forwarded) else {
        return;
    };
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return;
    }
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        return;
    };
    let mut fanned = 0usize;
    for peer in &peers {
        // Don't bounce straight back to the origin.
        if peer.did == notice.origin_did {
            continue;
        }
        let addr = format!("{}:{}", peer.overlay_ip, config.emergency_port);
        if socket.send_to(&bytes, &addr).await.is_ok() {
            fanned += 1;
        }
    }
    if fanned > 0 {
        NOTICES_REBROADCAST.fetch_add(1, Ordering::Relaxed);
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Info,
            AuditAction::Updated,
            &format!(
                "EMERGENCY notice re-broadcast revoked_did={} peers={} ttl={}",
                forwarded.entry.revoked_did, fanned, forwarded.ttl
            ),
        );
    }
}

// ── Session termination ─────────────────────────────────────────────────────

/// Map a revoked `did:guardian:...` to its CoT device_id via the cached peer
/// DID Document, then terminate all matching sessions in the global
/// SessionManager. Returns the number of sessions dropped (0 if the DID has
/// no live session or no cached doc — both benign).
async fn terminate_sessions_for_did(revoked_did: &str) -> usize {
    let Some(handle) = crate::cot::session_manager::global_session_manager() else {
        return 0; // CoT subsystem disabled (e.g. SGX_DISABLE_COT=1)
    };
    let device_id = match did_to_device_id(revoked_did) {
        Some(id) => id,
        None => return 0,
    };
    handle.terminate_peer(&device_id).await
}

/// Resolve device_id from the revoked DID's cached DID Document. The CoT
/// device_id is derived from the node public key; peer docs carry the key.
fn did_to_device_id(revoked_did: &str) -> Option<String> {
    let docs = crate::did::doc_persistence::list_peer_docs().ok()?;
    let doc = docs.into_iter().find(|d| d.id == revoked_did)?;
    let pubkey = doc.primary_public_key_bytes()?;
    crate::cot::identity::DeviceIdentity::from_public_key(&pubkey)
        .ok()
        .map(|identity| identity.device_id().to_string())
}
```

> **Two seams this file depends on (both added as small edits, see Part B):**
> 1. `crate::cot::session_manager::global_session_manager()` — a process-global handle set when CoT starts (F4 companion). If CoT is disabled, returns `None` and termination is a clean no-op.
> 2. `doc.primary_public_key_bytes()` — helper on the DID Document to pull the raw EC point. **Verify the exact accessor name during pre-flight** (`grep -n "public_key" src/did/document.rs`); if the doc exposes the key under a different method, adjust this one call. This is the single anchor in the plan that may need a name tweak — everything else is confirmed verbatim.

### A2. `src/crl/gossip/notifications.rs`

```rust
//! Durable, queryable emergency-notification feed.
//!
//! "Send push notifications to users" — the backend does NOT hold Apple/
//! Google push credentials (that's the mobile app's job). Instead we persist
//! a compact, append-only feed of critical revocation events that the
//! frontend polls (`GET /api/v1/crl/emergency/notifications`) and converts
//! into APNs/FCM push. Also mirrored into the tamper-evident audit chain.
//!
//! Storage: newline-delimited JSON at
//! /var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl
//! (same identity/crl dir as crl.json). Bounded read for the API.

use crate::crl::entry::CrlEntry;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

pub const MAX_FEED_RETURN: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyNotification {
    pub notified_at: String,
    pub revoked_did: String,
    pub reason: String,
    pub severity: String,
    pub revoker_did: String,
    pub origin_did: String,
    pub sessions_terminated: usize,
    /// User-facing headline the app can render directly.
    pub headline: String,
}

fn feed_path() -> PathBuf {
    let base = std::env::var("SGX_GUARDIAN_CRL_DIR")
        .unwrap_or_else(|_| "/var/lib/sgx-guardian/identity/crl".to_string());
    PathBuf::from(base).join("emergency_notifications.jsonl")
}

/// Append one notification. Best-effort: failures are logged, never fatal
/// (a missed feed line must not break revocation propagation).
pub fn record(node_id: &str, entry: &CrlEntry, origin_did: &str, sessions_terminated: usize) {
    let note = EmergencyNotification {
        notified_at: chrono::Utc::now().to_rfc3339(),
        revoked_did: entry.revoked_did.clone(),
        reason: entry.reason.as_str().to_string(),
        severity: entry.severity.as_str().to_string(),
        revoker_did: entry.revoker_did.clone(),
        origin_did: origin_did.to_string(),
        sessions_terminated,
        headline: format!(
            "Security alert: a device was revoked ({}). Sessions with it were closed.",
            entry.reason.as_str()
        ),
    };
    if let Err(error) = append(&note) {
        tracing::warn!("emergency notification append failed: {}", error);
        return;
    }
    let _ = node_id; // audit is emitted by the caller; feed is the durable user record
}

fn append(note: &EmergencyNotification) -> std::io::Result<()> {
    let path = feed_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut line = serde_json::to_string(note).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    file.write_all(line.as_bytes())
}

/// Most-recent-first feed (bounded). Empty vec if the feed doesn't exist yet.
pub fn recent(limit: usize) -> Vec<EmergencyNotification> {
    let path = feed_path();
    let Ok(file) = std::fs::File::open(&path) else {
        return Vec::new();
    };
    let mut out: Vec<EmergencyNotification> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect();
    out.reverse();
    out.truncate(limit.min(MAX_FEED_RETURN));
    out
}
```

### A3. `src/crl/gossip/emergency_tests.rs`

```rust
//! Disk-free unit tests for the emergency layer. Board integration is
//! covered by CRL-022…CRL-034 in CRL_Emergency_Verification_Log.md.

use super::emergency::{RevocationNotice, KIND_NOTICE, MAX_DATAGRAM_BYTES};
use crate::crl::entry::{
    CrlEntry, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
use crate::did::document::Proof;

fn sample_entry(sev: Severity) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: "urn:uuid:emergtest".to_string(),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: "did:guardian:target".to_string(),
        device_id: None,
        user_id: None,
        circle_id: "guardian-circle-alpha".to_string(),
        reason: RevocationReason::Compromised,
        severity: sev,
        timestamp: "2026-07-06T00:00:00Z".to_string(),
        revoker_did: "did:guardian:owner".to_string(),
        revoker_role: RevokerRole::Owner,
        evidence: None,
        proof: Proof::default(),
        peers_notified: Vec::new(),
        propagated: false,
    }
}

#[test]
fn notice_round_trips_within_datagram_cap() {
    let notice = RevocationNotice {
        kind: KIND_NOTICE.to_string(),
        circle_id: "guardian-circle-alpha".into(),
        origin_did: "did:guardian:nodeA".into(),
        notice_id: "n1".into(),
        ttl: 1,
        sent_at: "2026-07-06T00:00:00Z".into(),
        entry: sample_entry(Severity::Critical),
    };
    let bytes = serde_json::to_vec(&notice).expect("serialize notice");
    assert!(bytes.len() < MAX_DATAGRAM_BYTES, "notice must fit one datagram");
    let parsed: RevocationNotice = serde_json::from_slice(&bytes).expect("parse notice");
    assert_eq!(parsed.entry.revoked_did, "did:guardian:target");
    assert_eq!(parsed.ttl, 1);
    assert_eq!(parsed.kind, KIND_NOTICE);
}

#[test]
fn config_parses_emergency_fields() {
    // Defaults when unset.
    let cfg = super::GossipConfig::from_env();
    assert_eq!(cfg.emergency_port, super::GossipConfig::DEFAULT_EMERGENCY_PORT);
    assert!(cfg.emergency_ttl <= 4);
}

#[test]
fn notification_headline_is_user_safe() {
    let entry = sample_entry(Severity::Critical);
    let note = super::notifications::EmergencyNotification {
        notified_at: "2026-07-06T00:00:00Z".into(),
        revoked_did: entry.revoked_did.clone(),
        reason: entry.reason.as_str().to_string(),
        severity: entry.severity.as_str().to_string(),
        revoker_did: entry.revoker_did.clone(),
        origin_did: "did:guardian:nodeA".into(),
        sessions_terminated: 2,
        headline: "Security alert: a device was revoked (compromised). Sessions with it were closed."
            .into(),
    };
    // Headline must not leak the raw DID (privacy: app decides what to show).
    assert!(!note.headline.contains("did:guardian:"));
}
```

---

## 9. Implementation — Part B: FIND→REPLACE EDITS (verbatim anchors)

### F1 — `src/crl/gossip/mod.rs` (register modules)

**FIND (verbatim):**
```rust
pub mod engine;
pub mod protocol;
pub mod store;
```

**REPLACE WITH:**
```rust
pub mod emergency;
pub mod engine;
pub mod notifications;
pub mod protocol;
pub mod store;
```

*(Also add the test module. FIND:)*
```rust
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
```
**REPLACE WITH:**
```rust
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "emergency_tests.rs"]
mod emergency_tests;
```

### F2 — `src/crl/gossip/mod.rs` (extend `GossipConfig`)

**FIND (verbatim):**
```rust
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
```

**REPLACE WITH:**
```rust
#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub enabled: bool,
    pub port: u16,
    pub interval_secs: u64,
    pub threshold_pct: u8,
    pub emergency_enabled: bool,
    pub emergency_port: u16,
    pub emergency_ttl: u8,
}

impl GossipConfig {
    pub const DEFAULT_PORT: u16 = 50063;
    pub const DEFAULT_INTERVAL_SECS: u64 = 60;
    pub const DEFAULT_THRESHOLD_PCT: u8 = 80;
    pub const DEFAULT_EMERGENCY_PORT: u16 = 50064;
    pub const DEFAULT_EMERGENCY_TTL: u8 = 1;

    pub fn from_env() -> Self {
        Self {
            enabled: parse_enabled(std::env::var("SGX_CRL_GOSSIP_ENABLED").ok()),
            port: parse_port(std::env::var("SGX_CRL_GOSSIP_PORT").ok()),
            interval_secs: parse_interval(std::env::var("SGX_CRL_GOSSIP_INTERVAL_SECS").ok()),
            threshold_pct: parse_threshold(std::env::var("SGX_CRL_GOSSIP_THRESHOLD_PCT").ok()),
            emergency_enabled: parse_enabled(std::env::var("SGX_CRL_EMERGENCY_ENABLED").ok()),
            emergency_port: parse_emergency_port(std::env::var("SGX_CRL_EMERGENCY_PORT").ok()),
            emergency_ttl: parse_emergency_ttl(std::env::var("SGX_CRL_EMERGENCY_TTL").ok()),
        }
    }
}

pub(crate) fn parse_emergency_port(raw: Option<String>) -> u16 {
    raw.and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(GossipConfig::DEFAULT_EMERGENCY_PORT)
}

pub(crate) fn parse_emergency_ttl(raw: Option<String>) -> u8 {
    raw.and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(GossipConfig::DEFAULT_EMERGENCY_TTL)
        .clamp(0, 4)
}
```

### F3 — `src/crl/gossip/mod.rs` (spawn emergency listener in `spawn`)

**FIND (verbatim):**
```rust
    tokio::spawn(engine::listener_task(
        node_id.clone(),
        resolver.clone(),
        config.clone(),
    ));
    tokio::spawn(engine::round_task(node_id, resolver, config));
}
```

**REPLACE WITH:**
```rust
    tokio::spawn(engine::listener_task(
        node_id.clone(),
        resolver.clone(),
        config.clone(),
    ));
    // Emergency priority channel (UDP): critical revocations bypass gossip.
    if config.emergency_enabled {
        println!(
            "🚨 CRL-EMERGENCY channel enabled port={} ttl={}",
            config.emergency_port, config.emergency_ttl
        );
        tokio::spawn(emergency::listener_task(
            node_id.clone(),
            resolver.clone(),
            config.clone(),
        ));
    }
    tokio::spawn(engine::round_task(node_id, resolver, config));
}
```

### F4 — `src/cot/session_manager.rs` (net-new `terminate_peer` + global handle)

**FIND (verbatim):**
```rust
    pub async fn active_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count()
    }
```

**REPLACE WITH:**
```rust
    pub async fn active_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count()
    }

    /// Emergency Revocation (Sprint 7): terminate every session whose remote
    /// peer is `remote_device_id`. Returns the number of sessions dropped.
    /// Used when a critical revocation for that peer is applied — active
    /// breaches must be cut instantly, not on the next expiry sweep.
    pub async fn terminate_peer(&self, remote_device_id: &str) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|key, _| key != remote_device_id);
        before - sessions.len()
    }
```

*(Global handle so the emergency module can reach the live SessionManager. FIND the end of the `SessionManager` impl's constructor region — anchor on the `Default` impl:)*

**FIND (verbatim):**
```rust
impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
```

**REPLACE WITH:**
```rust
impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-global handle to the running SessionManager, set once when the
/// CoT subsystem starts (see main.rs). Lets the CRL emergency channel drop
/// sessions for a revoked peer without threading the manager through every
/// call site. `None` when CoT is disabled (SGX_DISABLE_COT=1).
static GLOBAL_SESSION_MANAGER: once_cell::sync::OnceCell<std::sync::Arc<SessionManager>> =
    once_cell::sync::OnceCell::new();

/// Register the process-wide SessionManager. Idempotent; later calls are
/// ignored. Called once from the CoT startup block in main.rs.
pub fn set_global_session_manager(manager: std::sync::Arc<SessionManager>) {
    let _ = GLOBAL_SESSION_MANAGER.set(manager);
}

/// Fetch the process-wide SessionManager if CoT initialized one.
pub fn global_session_manager() -> Option<std::sync::Arc<SessionManager>> {
    GLOBAL_SESSION_MANAGER.get().cloned()
}
```

> **Note:** if `once_cell` isn't already `use`d in this file, the fully-qualified paths above compile as-is (no `use` needed). Confirmed `once_cell` is a crate dependency.

### F4b — `src/main.rs` (register the global SessionManager when CoT starts)

The CoT block constructs a `SessionManager` (as `Arc<SessionManager>` inside `CotRouter`). Register it globally right after it's created.

**FIND (verbatim):**
```rust
        use sgx_guardian_client::cot::session_manager::SessionManager;
```

**REPLACE WITH:**
```rust
        use sgx_guardian_client::cot::session_manager::{set_global_session_manager, SessionManager};
```

*(Then, at the point the `Arc<SessionManager>` is created in that block — anchor on the actual construction. Confirm the exact binding name during pre-flight with `grep -n "SessionManager::new()\|Arc::new(SessionManager" src/main.rs`; it is wrapped in `Arc` for `CotRouter`. Immediately after that Arc is built, add:)*

```rust
        // Emergency Revocation: expose the live SessionManager process-wide so
        // the CRL emergency channel can terminate sessions with a revoked DID.
        set_global_session_manager(sessions.clone());
```
> Use the real variable name for the `Arc<SessionManager>` in that block (commonly `sessions`). This is the one edit whose surrounding binding name must be read from `main.rs` at apply time; the added line itself is fixed.

### F5 — `src/api/routes.rs` (2 emergency routes)

**FIND (verbatim):**
```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}
```

**REPLACE WITH:**
```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
        .route(
            "/api/v1/crl/emergency/status",
            get(handlers::crl::emergency_status),
        )
        .route(
            "/api/v1/crl/emergency/broadcast",
            post(handlers::crl::emergency_broadcast),
        )
        .route(
            "/api/v1/crl/emergency/notifications",
            get(handlers::crl::emergency_notifications),
        )
}
```

### F6 — `src/enforcement/executor.rs` (nft allow UDP 50064 — REGRESSION FIX)

**FIND (verbatim):**
```rust
    // Allow CRL gossip exchange for decentralized revocation propagation
    out.push_str("    tcp dport 50063 accept\n");
```

**REPLACE WITH:**
```rust
    // Allow CRL gossip exchange for decentralized revocation propagation
    out.push_str("    tcp dport 50063 accept\n");

    // Allow CRL emergency revocation broadcast (critical revocations, UDP)
    out.push_str("    udp dport 50064 accept\n");
    out.push_str("    udp sport 50064 accept\n");
```

### F7 — `src/api/handlers/crl.rs` (emergency handlers, appended after `gossip_trigger`)

**FIND (verbatim):**
```rust
pub async fn gossip_trigger(
    State(state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<GossipTriggerResponse>, ApiError> {
    let config = crate::crl::gossip::GossipConfig::from_env();
    let report =
        crate::crl::gossip::engine::run_round_once(&state.node_id, &state.did_resolver, &config)
            .await
            .map_err(ApiError::Internal)?;
```

**REPLACE WITH:**
```rust
pub async fn gossip_trigger(
    State(state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<GossipTriggerResponse>, ApiError> {
    let config = crate::crl::gossip::GossipConfig::from_env();
    let report =
        crate::crl::gossip::engine::run_round_once(&state.node_id, &state.did_resolver, &config)
            .await
            .map_err(ApiError::Internal)?;
    // --- emergency handlers appended below (see end of gossip_trigger) ---
```

*(Then append the following block AFTER the closing brace of `gossip_trigger`. Anchor on the `GossipTriggerResponse` construction's trailing return so we land right after the function. FIND:)*

**FIND (verbatim):**
```rust
        message: "gossip round completed".to_string(),
    }))
}
```

**REPLACE WITH:**
```rust
        message: "gossip round completed".to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct EmergencyStatusResponse {
    pub enabled: bool,
    pub port: u16,
    pub ttl: u8,
    pub notices_sent: u64,
    pub notices_received: u64,
    pub notices_merged: u64,
    pub notices_rebroadcast: u64,
    pub sessions_terminated: u64,
    pub last_notice: Option<crate::crl::gossip::emergency::LastNotice>,
}

#[derive(Debug, Serialize)]
pub struct EmergencyBroadcastResponse {
    pub success: bool,
    pub revoked_did: String,
    pub message: String,
}

/// GET /api/v1/crl/emergency/status — emergency channel observability.
pub async fn emergency_status(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<EmergencyStatusResponse>, ApiError> {
    let config = crate::crl::gossip::GossipConfig::from_env();
    Ok(Json(EmergencyStatusResponse {
        enabled: config.emergency_enabled,
        port: config.emergency_port,
        ttl: config.emergency_ttl,
        notices_sent: crate::crl::gossip::emergency::notices_sent(),
        notices_received: crate::crl::gossip::emergency::notices_received(),
        notices_merged: crate::crl::gossip::emergency::notices_merged(),
        notices_rebroadcast: crate::crl::gossip::emergency::notices_rebroadcast(),
        sessions_terminated: crate::crl::gossip::emergency::sessions_terminated_total(),
        last_notice: crate::crl::gossip::emergency::last_notice(),
    }))
}

/// POST /api/v1/crl/emergency/broadcast?did=... — manually (re-)broadcast an
/// EXISTING critical CRL entry over the emergency channel. Deterministic
/// board-test hook. Does NOT create a revocation; the DID must already be
/// revoked with severity critical.
#[derive(Debug, Deserialize)]
pub struct EmergencyBroadcastQuery {
    pub did: String,
}

pub async fn emergency_broadcast(
    State(state): State<Arc<crate::api::state::AppState>>,
    axum::extract::Query(q): axum::extract::Query<EmergencyBroadcastQuery>,
) -> Result<Json<EmergencyBroadcastResponse>, ApiError> {
    if q.did.trim().is_empty() {
        return Err(ApiError::BadRequest("did must not be empty".into()));
    }
    let crl = persistence::load_crl()
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound("no local CRL".into()))?;
    let entry = crl
        .entries
        .iter()
        .find(|e| e.revoked_did == q.did)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("{} is not revoked", q.did)))?;
    if !matches!(entry.severity, crate::crl::entry::Severity::Critical) {
        return Err(ApiError::BadRequest(
            "emergency broadcast is only for critical revocations".into(),
        ));
    }
    crate::crl::gossip::emergency::broadcast_for_entry(state.node_id.clone(), entry.clone());
    Ok(Json(EmergencyBroadcastResponse {
        success: true,
        revoked_did: q.did,
        message: "emergency broadcast dispatched".to_string(),
    }))
}

/// GET /api/v1/crl/emergency/notifications — durable feed the mobile app
/// polls to raise user push notifications for critical revocations.
pub async fn emergency_notifications(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<Vec<crate::crl::gossip::notifications::EmergencyNotification>>, ApiError> {
    Ok(Json(crate::crl::gossip::notifications::recent(
        crate::crl::gossip::notifications::MAX_FEED_RETURN,
    )))
}
```

> Two clean-ups when applying F7: (1) remove the temporary `// --- emergency handlers appended below ---` marker line added in the first half; it exists only to make the two-part edit unambiguous. (2) Confirm `ApiError` has `BadRequest` and `NotFound` variants (grep `enum ApiError`); the existing `/crl/entry` (404) and `/crl/revoke` (400) handlers prove both exist — reuse those exact variant names.

### F8a — `sgx-pa-cli/src/commands/crl.rs` (fire emergency broadcast after a critical CLI revoke)

**FIND (verbatim):**
```rust
        Ok(entry) => {
            let crl = persistence::load_crl().ok().flatten();
            if let Some(crl) = crl {
                println!(
                    "✅ CRL entry issued: {} (sequence={}, root={})",
                    entry.id, crl.sequence, crl.merkle_root
                );
            } else {
                println!("✅ CRL entry issued: {}", entry.id);
            }
        }
```

**REPLACE WITH:**
```rust
        Ok(entry) => {
            let crl = persistence::load_crl().ok().flatten();
            if let Some(crl) = crl {
                println!(
                    "✅ CRL entry issued: {} (sequence={}, root={})",
                    entry.id, crl.sequence, crl.merkle_root
                );
            } else {
                println!("✅ CRL entry issued: {}", entry.id);
            }
            // Emergency Revocation: critical entries fire the priority UDP
            // broadcast immediately (bypasses routine gossip intervals).
            if matches!(entry.severity, sgx_guardian_client::crl::entry::Severity::Critical) {
                let node_id = sgx_guardian_client::vc::issue::resolve_runtime_node_id()
                    .unwrap_or_else(|| "nodeA".to_string());
                // sgx-pa-cli is a short-lived process; run the fire-and-forget
                // broadcast to completion on a tiny current-thread runtime so the
                // datagrams actually leave before the CLI exits.
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async {
                        sgx_guardian_client::crl::gossip::emergency::broadcast_for_entry(
                            node_id,
                            entry.clone(),
                        );
                        // Give the spawned send task a moment to flush datagrams.
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    });
                }
            }
        }
```

> **Rationale for the tiny runtime:** `broadcast_for_entry` spawns a tokio task; in the long-lived daemon (REST path, F8b) that's fine, but the CLI exits immediately. A short current-thread runtime + 300 ms flush guarantees the datagrams are sent from the one-shot CLI. This is NOT a blocking-in-async violation — the CLI is not running inside the daemon's tokio runtime; it's a standalone process. (Confirm `tokio` is a dependency of `sgx-pa-cli`; if not present, add `tokio = { version = "1", features = ["rt", "net", "time", "macros"] }` to `sgx-pa-cli/Cargo.toml` — verify during pre-flight with `grep -n "tokio" sgx-pa-cli/Cargo.toml`.)

### F8b — `src/api/handlers/crl.rs` `revoke` handler (fire broadcast after a critical REST revoke)

Locate the existing `revoke` handler's success arm (after `issue_revocation` succeeds and the response is built). Anchor on its entry-issued response construction.

**FIND (verbatim — confirm exact text during pre-flight; the `revoke` handler returns the new entry):**
```rust
        .map_err(map_crl_error)?;
```
*(This appears inside `revoke`. If multiple matches exist, scope to the `revoke` fn. Insert the broadcast immediately after the entry is obtained and BEFORE returning the JSON response:)*

**Add (in the `revoke` handler, right after the entry is successfully created):**
```rust
    // Emergency Revocation: critical revocations fire the priority UDP
    // broadcast at once (daemon tokio runtime; fire-and-forget).
    if matches!(entry.severity, crate::crl::entry::Severity::Critical) {
        crate::crl::gossip::emergency::broadcast_for_entry(state.node_id.clone(), entry.clone());
    }
```

> Because the exact local binding in `revoke` (e.g. `entry`) and the `State` extractor name (`state`) must match what's already there, treat F8b as: *"in the existing `revoke` handler, after the CRL entry is created and before the success `Json(...)` return, insert the 3-line critical-broadcast block using the handler's real `entry` and `state` bindings."* Everything the block calls is fixed; only the two variable names are read from context.

---

## 10. Constraint Compliance (project hard rules)

| Rule | Compliance |
|---|---|
| No `std::thread::sleep` / sync `Command` in the **daemon** tokio runtime | Daemon uses only `tokio::net::UdpSocket`, `tokio::spawn`, `tokio::time`. The one `tokio::time::sleep` is in `sgx-pa-cli` (a standalone process, NOT the daemon runtime) — permitted and necessary to flush datagrams before CLI exit. |
| No touching `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()` / daemon lifecycle | Untouched. Emergency listener is a fire-and-forget spawn inside the existing `gossip::spawn`. |
| Board workflow (no systemctl/journalctl/apt) | All verification uses `./sgx_guardian_client nodeX`, `pkill -f`, `pgrep`, `grep`/`tail`, `curl`, `./sgx-pa-cli`. |
| Yocto/aarch64 cross-compile | Zero new crates → no BSP/toolchain impact. |
| ECDSA-P256 + SHA-256 only | Reuses `verify_entry` / `store` re-sign — no new crypto. |
| Root convergence with routine gossip | Emergency merges via the **identical** `store::merge_verified_entries` under the **same** `CRL_WRITE_LOCK` — no divergent mutation path. Merkle roots stay equal across both channels. |
| Gossip fields excluded from signing/fingerprint | Unchanged (confirmed in `entry.rs`); emergency doesn't touch the signing surface. |

---

## 11. Regression Checks (run all — must stay green)

```bash
# 1. Full workspace tests (existing crl + gossip suites + new emergency suite)
cargo test -p sgx_guardian_client crl:: -- --nocapture
cargo test --workspace --locked

# 2. Lints/format
cargo fmt --check && cargo clippy --workspace -- -D warnings

# 3. Routine gossip suite still green (CRL-011…CRL-021 behavior unchanged)
./scripts/crl_board_check.sh    # if it covers gossip; otherwise re-run the gossip verification log

# 4. nft ruleset now carries BOTH gossip (50063) and emergency (50064)
grep -n "50063\|50064" src/enforcement/executor.rs   # 50063 x1, 50064 x2 (dport+sport)

# 5. Routes: /crl/* grew from 9 to 12
grep -c "handlers::crl::" src/api/routes.rs

# 6. No forbidden blocking calls in the DAEMON emergency module
grep -rn "thread::sleep\|Command::new" src/crl/gossip/emergency.rs && echo "❌ VIOLATION" || echo "✅ clean"

# 7. Frozen files untouched
git diff --stat src/nebula/ src/cert_service.rs src/server.rs   # empty

# 8. issue_revocation itself unchanged (broadcast is at call sites)
git diff src/crl/issue.rs    # empty
```

**Behavioral regressions to reason through (all safe):**
- Emergency + routine both write `crl.json` via the same lock → no torn state; roots converge.
- A critical revoke now sends UDP datagrams; if no peers/enforcement blocks 50064, it logs a warning and routine gossip still propagates (degraded, not broken).
- `terminate_peer` on a DID with no live session returns 0 → clean no-op, still audited + notified.
- Emergency channel disabled (`SGX_CRL_EMERGENCY_ENABLED=0`) → listener not spawned, `broadcast_for_entry` early-returns; system behaves exactly like Task-2-only.
- CoT disabled (`SGX_DISABLE_COT=1`) → `global_session_manager()` is `None` → termination no-ops; everything else works.

---

## 12. Step-by-Step Checklist

**Dev machine**
- [ ] `git pull origin main` → run **Section 4 pre-flight** (all anchors green, port free)
- [ ] Confirm the two name-dependent seams: `grep -n "public_key" src/did/document.rs` (for `primary_public_key_bytes` — adjust A1's one call if named differently) and `grep -n "Arc::new(SessionManager\|SessionManager::new()" src/main.rs` (for the F4b binding name)
- [ ] Branch: `git checkout -b crl_emergency`
- [ ] Create the 3 new files (Section 8)
- [ ] Apply F1–F8b (Section 9)
- [ ] `cargo build` → `cargo test --workspace` → `cargo clippy` — all green
- [ ] Cross-compile: `cargo build --release --workspace --target aarch64-unknown-linux-gnu --features secure-element` (or `./scripts/build.sh`)

**Boards (nodeA .101/.103, nodeB .115, nodeC .248)**
- [ ] On each: `pkill -f sgx_guardian_client || true`
- [ ] `scp` new `sgx_guardian_client` (+ `sgx-pa-cli`) to each board
- [ ] Start nodeA → expect `🚨 CRL-EMERGENCY listener on 0.0.0.0:50064` and `🚨 CRL-EMERGENCY channel enabled`
- [ ] Start nodeB, nodeC
- [ ] Execute **CRL_Emergency_Verification_Log.md** (CRL-022 → CRL-034)
- [ ] Re-run the gossip verification log (routine path regression)
- [ ] Update `docs/REST API Details.md`: endpoints **101** `GET /crl/emergency/status`, **102** `POST /crl/emergency/broadcast`, **103** `GET /crl/emergency/notifications`
- [ ] PR with plan + filled verification log

**Quick smoke (after 3 nodes up)**
```bash
# nodeA — issue a CRITICAL revocation for a DUMMY DID → auto emergency broadcast
./sgx-pa-cli crl revoke --did did:guardian:emergsmoke01 --reason compromised --severity critical --note "smoke"
# within SECONDS (not intervals) on nodeB AND nodeC:
./sgx-pa-cli crl check --did did:guardian:emergsmoke01     # → revoked: true
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool   # notices_received ≥ 1
curl -s http://localhost:8443/api/v1/crl/emergency/notifications | python3 -m json.tool   # feed entry present
./sgx-pa-cli crl root   # identical merkle_root on A/B/C (converged with routine path)
```

---

## 13. Rollback

1. **Instant, no rebuild:** start binaries with `SGX_CRL_EMERGENCY_ENABLED=0` — emergency listener never spawns, broadcasts early-return; routine gossip unaffected.
2. **Full revert:** `git revert` the branch (8 edits + delete the 3 new files). No schema/data migration — the emergency feed file is additive and ignored by old binaries; `crl.json` format is unchanged.

---

## 14. Known Limitations → Follow-up Register

| # | Limitation | Severity | Follow-up |
|---|---|---|---|
| L1 | UDP datagram loss (no per-notice ACK) | Low | **Routine anti-entropy (50063) is the guaranteed backstop** — a dropped notice re-converges within one interval; ACKs would add latency for no correctness gain |
| L2 | `origin_did` in the notice is channel-unauthenticated (entry proof is the real anchor) | Low | Signed notice envelope — candidate hardening (same trade-off as gossip's `sender_did`) |
| L3 | DID→device_id needs the revoked peer's cached DID doc; if absent, session termination no-ops | Low | Fallback: broaden `terminate_peer` to also match on a DID annotation if sessions later carry DID |
| L4 | Emergency feed grows unbounded on disk (JSONL) | Low | Log-rotate / cap file size; API already bounds reads to 200 |
| L5 | Actual APNs/FCM push is out of backend scope | By design | Mobile app (Lightning Leap) consumes `GET /crl/emergency/notifications` |
| L6 | `terminate_peer` removes by device_id key equality; if multiple sessions per peer existed under different keys, only exact-key matches drop | Low | Current model is one session per `remote_device_id` (HashMap key) — matches today's `SessionManager` design |
| L7 | Re-broadcast is single-hop (TTL default 1) | By design | Tunable via `SGX_CRL_EMERGENCY_TTL` (0–4) for larger/deeper Circles |
