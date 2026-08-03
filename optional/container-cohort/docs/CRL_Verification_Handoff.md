# CRL Gossip Protocol — Verification Handoff

**Scope:** Backend gossip engine (9 requirements) + 2 real REST APIs + frontend integration.
**Reference doc in repo:** `optional/container-cohort/docs/CRL_Gossip_Docker_Verification_Log.md` (already-passed baseline run, 2026-07-17).

---

## 1. What this feature is

Epidemic-style gossip protocol so every Guardian node keeps its local CRL (revocation list) in sync **without a central server**. Nodes periodically pick a random peer, exchange CRL diffs, merge new revocations, and forward them onward. An entry is marked `propagated=true` once 80% of the Circle has acknowledged it.

## 2. Environment setup

```bash
cd <repo-root>
docker compose -f docker-compose.dev.yml up -d
docker compose -f docker-compose.dev.yml ps
```

Node ports (adjust if your cohort uses different names/ports):
- nodeA (Owner/CA) → `http://localhost:18443`
- nodeB (Member) → `http://localhost:28443`
- nodeC (Member) → `http://localhost:38443` (may be absent if running a 2-node cohort)

Get each node's DID (needed for some checks):
```bash
docker exec <container> cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])"
```

---

## 3. Backend requirements checklist (9 items) — what to verify

| # | Requirement | How to check |
|---|---|---|
| 1 | Each Guardian keeps its own local CRL, no central authority | `ss -ltn \| grep 50063` + audit log `"CRL gossip engine started"` on every node |
| 2 | Periodic rounds every 1–5 min, random peer selection | audit log `"CRL gossip round"` timestamps + peer rotation |
| 3 | Peer merges received revocations into local CRL | revoke on nodeA → `crl check` on nodeB shows `revoked=true` |
| 4 | Forwards to other peers (transitive relay) | stop nodeC, seed revoke on nodeA→nodeB, start nodeC, confirm nodeC learns it **via nodeB** (`via_peer=<nodeB DID>` in audit log), not directly from nodeA |
| 5 | Probabilistic flooding + anti-entropy | trigger gossip in converged state → `merged=0, pushed=0` no-op round |
| 6 | `peers_notified` tracked per entry | `crl check --did <x>` shows list of peer DIDs that acked it |
| 7 | `propagated=true` at 80% Circle threshold | once `peers_notified` count ≥ `threshold_count`, entry flips to `propagated=true` |
| 8 | Eventual consistency across partitions/restarts | partition nodeC, revoke twice on nodeA, rejoin nodeC, confirm all 3 nodes converge to same `merkle_root`; restart nodeA, confirm entry survives |
| 9 | Fully decentralized (works without CA/owner online) | stop nodeA, have nodeB (member) issue + gossip a revocation to nodeC — must succeed with nodeA down |

Exact ready-to-run bash sequences for all 9 already exist and passed — see `optional/container-cohort/docs/CRL_Gossip_Docker_Verification_Log.md` sections "Requirement 1" through "Requirement 9". Reuse those verbatim.

---

## 4. REST API verification (2 real endpoints)

**Important clarification for whoever verifies this:** the verification checklist historically lists "4 Gossip APIs," but only 2 are actual REST endpoints. The other 2 are protocol/security behavior checks (not HTTP routes) — confirmed against `docs/REST API Details.md` rows 8–11 and `CRL_Gossip_Protocol_Complete_Plan.md:43`. Don't treat missing REST routes for #3/#4 as a bug.

### API 1 — `GET /api/v1/crl/gossip/status` (read-only, no side effects)
```bash
curl -s http://localhost:18443/api/v1/crl/gossip/status | python3 -m json.tool
```
Expect JSON with: `enabled, port, interval_secs, threshold_pct, self_did, circle_id, other_members, threshold_count, sequence, merkle_root, entries, propagated, rounds_initiated, rounds_served, entries_merged, last_round`.
**Pass:** same call on all nodes returns valid JSON with consistent `threshold_pct=80`, matching `merkle_root` when converged.

### API 2 — `POST /api/v1/crl/gossip/trigger` (forces one live gossip round now)
```bash
curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool
```
Expect JSON with: `success, peer_did, peer_node, merged, pushed, peer_merged, merkle_root, newly_propagated, message`.
**Pass:** `success=true`; in converged state `merged=pushed=peer_merged=0`; after seeding a fresh revoke elsewhere, a trigger here should show `merged>0` or `peer_merged>0`.

### API 3 — Security: tampered entry rejected (protocol-level, not a route)
Seed a revocation, hand-craft a raw gossip-protocol push with a tampered field (e.g. flipped `severity`) directly over TCP port 50063, and confirm the receiving node's audit log shows `"CRL gossip rejected entry ... invalid signature"` and `merkle_root` is unchanged before/after. Full script is in the reference doc, "API 4 — ..." section is mislabeled in some copies — use the doc's "API 3" block, it has the working Python snippet.

### API 4 — Revoked peer excluded both directions (protocol-level, not a route)
Revoke a peer's own DID via `/crl/revoke`, confirm:
- `other_members` / `threshold_count` in `/gossip/status` drop by 1
- outbound: revoked peer never gets selected by `trigger`
- inbound: audit log shows `"CRL gossip rejected sender=<revoked DID>: sender is revoked"`
Then `unrevoke` and confirm status counters recover.
**Known caveat (already documented, not a new bug):** full cluster-wide *unrevoke* convergence is only partial in Docker — unrevoke deletes the entry locally instead of gossiping a tombstone/delete, so one peer may still show `revoked=true` after restore. This is a documented implementation gap, not something the verifier needs to re-discover.

---

## 5. Frontend verification (new — this is what needs fresh testing)

UI screen: **"Certificate Revocation List"** → **"Gossip engine"** panel, with a **"Trigger round"** button and a page-level **"Refresh all"** button (auto-refreshes every 30s).

### 5a. Status display — field-by-field cross-check
The panel currently shows: `enabled, port, interval_secs, threshold_pct, self_did, circle_id, other_members, threshold_count`.

For every field, compare the UI value against:
```bash
curl -s http://<node-host>:<node-port>/api/v1/crl/gossip/status | python3 -m json.tool
```
They must match exactly. **Also check whether the UI shows the remaining response fields** (`sequence, merkle_root, entries, propagated, rounds_initiated, rounds_served, entries_merged, last_round`) — if not visible anywhere on the page, flag this as a gap, since `entries`/`propagated`/`merkle_root` are the fields that actually prove propagation is working.

### 5b. Trigger round — action test
1. Note current `entries` / `propagated` / `merkle_root` (from status, curl or UI).
2. Seed a fresh revocation on the node under test (or a peer):
   ```bash
   docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 <container> sgx-pa-cli crl revoke --did "did:guardian:fe-test-$(date +%s)" --reason compromised --severity high
   ```
3. Click **"Trigger round"** in the UI.
4. Confirm the UI reflects (or the network response contains) `success=true`, non-zero `merged`/`pushed`/`peer_merged`, and updated `merkle_root`.
5. Click **"Refresh all"** (or wait for the 30s auto-refresh) and confirm `entries` count increased and, once threshold met, `propagated` increased too.

### 5c. Multi-node convergence (if UI instances for 2+ nodes are available)
Open the panel pointed at each node, trigger on one, refresh both, confirm `merkle_root` converges to the same value on all — this is the visual proof of Requirement 8 (eventual consistency).

### 5d. Error/edge states to click through
- Only 1 node reachable → trigger should show a graceful error (`"no active gossip peers yet"`), not a crash/blank screen.
- Node unreachable entirely → loading/error state should degrade gracefully, not hang forever.
- Rapid repeated clicks on "Trigger round" → no duplicate/racing requests, button should ideally disable while in-flight.

---

## 6. Pass criteria summary to report back

- [ ] All 9 backend requirements PASS (reuse existing doc's proven commands)
- [ ] API 1 (`status`) PASS on all nodes
- [ ] API 2 (`trigger`) PASS, merges/pushes correctly
- [ ] API 3 tamper-rejection PASS
- [ ] API 4 exclusion PASS (unrevoke full convergence is a **known partial**, not a new failure)
- [ ] Frontend status panel matches backend JSON field-for-field
- [ ] Frontend trigger button produces correct merge/propagation and UI updates
- [ ] Multi-node UI convergence visually confirmed
- [ ] Error/edge states handled gracefully in UI

---
---

# 7. CRL Emergency Revocation — Verification Handoff

**Scope:** Backend emergency-broadcast engine (8 requirements) + 4 real REST APIs + frontend integration.
**Reference docs in repo:**
- `docs/CRL_Emergency_Verification_Log.md` — iMX8MP board hardware run, 2026-07-21.
- `optional/container-cohort/docs/CRL_Emergency_Docker_Verification_log.md` — Docker cohort run, latest fix verified 2026-08-03.

---

## 7.1 What this feature is

Priority emergency broadcast channel for **critical** revocations (compromised devices, active attacks) — the fast path that sits alongside routine gossip (section 1-6 above). The moment a `severity: critical` revocation is issued, the node pushes a signed `REVOCATION_NOTICE` to **every** active peer at once over UDP `50064`, bypassing the normal gossip interval. Receivers re-verify + merge through the same locked CRL path as gossip, **terminate any active CoT session with the revoked DID**, record a durable notification for frontend/mobile push, then re-broadcast once (bounded by TTL) before falling back to routine gossip. Non-critical revocations never touch this channel.

## 7.2 Environment setup

Same cohort as section 2 above:
```bash
cd <repo-root>
docker compose -f docker-compose.dev.yml up -d --build
docker compose -f docker-compose.dev.yml ps
```

Node ports (same cohort, plain HTTP in this dev profile — no TLS, no mixed-content/cert issues to worry about from a browser):
- nodeA (Owner/CA) → `http://localhost:18443`
- nodeB (Member) → `http://localhost:28443`
- nodeC (Member) → `http://localhost:38443`

Emergency-specific port: UDP `50064` (routine gossip stays on `50063`).

**Auth gotcha (discovered 2026-08-03, not in the feature itself):** this branch also carries a new bearer-token auth middleware (`require_auth`) that now guards every REST route except `/auth/signup`, `/auth/login`, `/health`, `/circles/redeem`. If `nodeA`/`nodeB` already have an owner user seeded from earlier circle-management testing, fresh `/auth/signup` will 403. Fastest unblock for a pure backend/API verification pass: add `SGX_DISABLE_LOGIN: "1"` to the `environment:` block in `docker-compose.dev.yml` (same pattern as the other `SGX_DISABLE_*` dev flags already there) and recreate (`up -d`, no rebuild needed). **A proper frontend pass should NOT use this bypass** — the frontend needs to exercise the real login flow (`POST /api/v1/auth/signup` once, then `POST /api/v1/auth/login`) and attach `Authorization: Bearer <token>` to every call below, since that's what production will require.

Debug helper needed for the session-termination check (Requirement 5 / API 7 below): `POST /api/v1/crl/emergency/debug/session` seeds a fake-but-real CoT session for a peer DID so the test doesn't need a live radio/Bluetooth/cellular link.

---

## 7.3 Backend requirements checklist (8 items) — what to verify

| # | Requirement | How to check |
|---|---|---|
| 1 | Emergency UDP listener on port `50064` with env gating | `ss -lun \| grep 50064` + `/crl/emergency/status` shows `enabled=true, port=50064` on every node |
| 2 | Critical local revoke triggers immediate one-to-many emergency broadcast | `sgx-pa-cli crl revoke --severity critical` (or REST) on nodeA → console/audit shows `EMERGENCY broadcast ... -> N peers` right away, not after the gossip interval |
| 3 | Receiving Guardian re-verifies and merges notice through the existing locked CRL path | receiver `crl check --did <x>` shows `revoked=true`; tampered notice (flipped field over raw UDP) is rejected — audit shows `"EMERGENCY notice rejected ... invalid signature"`, entry never merges |
| 4 | Receiver re-broadcast is bounded by TTL and fingerprint dedup | manual duplicate rebroadcast (API 3 below) of the same entry → `notices_received` increments but `notices_merged`/`notices_rebroadcast` do **not** increment again |
| 5 | Critical revoke terminates active CoT sessions for the revoked DID | seed a debug session (`POST .../debug/session`), revoke that peer's DID as critical, confirm session is gone (`GET .../debug/session?did=` → `exists=false`) and `sessions_terminated` counter increments |
| 6 | Durable emergency notification feed is recorded for frontend/mobile push | `GET /crl/emergency/notifications` returns the event with `headline`, `revoked_did`, `severity`, `sessions_terminated`; also check `/var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl` on the receiver |
| 7 | Emergency observability and manual rebroadcast endpoints work | `GET .../status` exposes all counters + `last_notice`; `POST .../broadcast?did=` re-dispatches an existing critical entry (`success=true`) |
| 8 | Emergency path coexists with routine gossip and enforcement; Merkle roots still converge | with `SGX_DISABLE_POLICY_ENFORCEMENT=0`, confirm nftables allow-list has `udp dport/sport 50064 accept`; after emergency + routine gossip settle, all nodes' `/crl/gossip/status` show identical `sequence` and `merkle_root` |

**Known caveat — read before re-testing Requirement 5:** the iMX8MP board run (`docs/CRL_Emergency_Verification_Log.md`) found Requirement 5 failing intermittently: `src/crl/gossip/emergency.rs` used to gate session-termination on `newly_merged`, so if routine gossip won the CRL-merge lock race a moment before the emergency notice arrived, the session-termination side effect was silently skipped (routine gossip itself never terminates sessions). **Fixed 2026-08-03** (gate removed, dedup already caps the block to one run per entry) and re-verified PASS in the Docker cohort — see `optional/container-cohort/docs/CRL_Emergency_Docker_Verification_log.md`, Requirement 5 / CRL-029 section. **The board hardware retest with the fixed binary is still outstanding** — don't be surprised if the board doc still shows the old FAIL entry; that's expected until someone reruns it on real iMX8MP hardware.

Exact ready-to-run bash sequences for CRL-022 through CRL-034 + both runtime hooks already exist — reuse `optional/container-cohort/docs/CRL_Emergency_Docker_Verification_log.md` verbatim for the Docker cohort.

---

## 7.4 REST API verification (4 real endpoints)

**Important clarification for whoever verifies this:** unlike the Gossip section above (2 real routes + 2 protocol-level checks), **all 4 Emergency APIs are real REST endpoints** — confirmed against `docs/REST API Details.md` rows 12-15. Don't apply the Gossip section's "not REST" pattern here by mistake.

### API 1 — `POST /api/v1/crl/revoke` (critical path)
```bash
curl -s -X POST http://localhost:18443/api/v1/crl/revoke \
  -H 'Content-Type: application/json' \
  -d '{"did":"did:guardian:...","reason":"compromised","severity":"critical","note":"..."}' \
  | python3 -m json.tool
```
Request fields: `did, reason, severity, device_id?, user_id?, note?, audit_ref?, attestation_ref?, evidence_digest?`.
Response: `status, message, entry{...}, sequence, merkle_root`.
**Pass:** for `severity=critical`, an emergency broadcast fires immediately (console/audit `EMERGENCY broadcast ... -> N peers`) — the revoked peer itself is correctly excluded from the peer list if it's a member of the Circle. For non-critical severities, no broadcast should fire at all (verify counters on all nodes stay flat).

### API 2 — `GET /api/v1/crl/emergency/status` (read-only, no side effects)
```bash
curl -s http://localhost:18443/api/v1/crl/emergency/status | python3 -m json.tool
```
Expect JSON with: `enabled, port, ttl, notices_sent, notices_received, notices_merged, notices_rebroadcast, sessions_terminated, last_notice{direction, revoked_did, origin_did, peers, merged, at}`.
**Pass:** same call on all nodes returns valid JSON; counters only move on nodes actually involved in a given broadcast.

### API 3 — `POST /api/v1/crl/emergency/broadcast?did=<did>` (manual re-dispatch)
```bash
curl -s -X POST "http://localhost:18443/api/v1/crl/emergency/broadcast?did=did:guardian:..." | python3 -m json.tool
```
**Pass conditions (test both):**
- Existing critical-revoked DID → `{"success":true,"revoked_did":"...","message":"emergency broadcast dispatched"}`, receivers' fingerprint-dedup prevents a second merge.
- Non-existent or non-critical DID → `404 NOT_FOUND` / `400 BadRequest` respectively — frontend must handle both as user-visible errors, not crash.

### API 4 — `GET /api/v1/crl/emergency/notifications` (mobile push source)
```bash
curl -s http://localhost:28443/api/v1/crl/emergency/notifications | python3 -m json.tool
```
Response: JSON array (most-recent-first, capped at 200), each item: `notified_at, revoked_did, reason, severity, revoker_did, origin_did, sessions_terminated, headline`.
**Pass:** array grows by one durable entry per critical revocation this node received/applied; `headline` is a ready-to-render string (e.g. `"Security alert: a device was revoked (compromised). Sessions with it were closed."`).

---

## 7.5 Frontend verification (new — this is what needs fresh testing)

UI screen: **"Certificate Revocation List"** → **"Emergency"** panel — expected to show a live counters card, a "Revoke (critical)" action, a "Resend alert" button per revoked entry, and a notifications feed list.

### 7.5a. Status display — field-by-field cross-check
Panel should show at least: `enabled, port, ttl, notices_sent, notices_received, notices_merged, notices_rebroadcast, sessions_terminated`. Compare every field against:
```bash
curl -s http://<node-host>:<node-port>/api/v1/crl/emergency/status | python3 -m json.tool
```
**Also check whether `last_notice` is surfaced anywhere** (e.g. "Last emergency: revoked X, 2 peers, 3 mins ago") — if not shown, flag as a gap, since it's the one field that proves the last action actually happened.

### 7.5b. Critical revoke — action test
1. Trigger a critical revoke from the UI (API 1) against a real peer DID.
2. Confirm the UI reflects the response (`entry`, `sequence`, `merkle_root`) without waiting for a page refresh.
3. Confirm peer nodes' status panels update `notices_received`/`notices_merged` within a couple seconds — **not** after a 60s gossip-interval delay. This is the visual proof that emergency actually bypasses routine gossip timing.

### 7.5c. Manual resend — action test
1. Click "Resend alert" (API 3) on an already-critical-revoked entry.
2. Confirm `success=true` in the UI and that receiver counters do **not** double-merge the same entry (dedup).
3. Click resend on a non-critical or unrevoked DID and confirm the UI shows a clean error state, not a crash.

### 7.5d. Session-termination — action test (the one that was recently fixed)
1. Seed a debug CoT session for a peer DID: `POST /api/v1/crl/emergency/debug/session` with `{"did":"<peer DID>","transport":"Ethernet"}`.
2. If the UI has any "active sessions / connected devices" view, confirm it shows this session as active.
3. Critically revoke that same peer DID.
4. Confirm the UI's session/device view drops it, and the status panel's `sessions_terminated` increments. If the UI has no session view at all, at minimum confirm via `GET .../debug/session?did=` that `exists` flips to `false`.

### 7.5e. Notifications feed — mobile/push simulation
1. Poll `GET /api/v1/crl/emergency/notifications` (or however the UI wires this) after each critical revoke above.
2. Confirm a new item appears with the correct `headline`, and that the UI can render it as a notification/toast/banner directly from that string.
3. Confirm ordering is most-recent-first and the list doesn't unbounded-grow the DOM (pagination or cap matching the 200-item API cap).

### 7.5f. Multi-node convergence
Open the panel against 2+ nodes, fire a critical revoke on one, confirm the others' counters and `last_notice` update within seconds, and that `/crl/gossip/status` `merkle_root` on all nodes still converges afterward (emergency path must not break routine gossip convergence — Requirement 8).

### 7.5g. Error/edge states to click through
- Revoke with empty/malformed DID → graceful validation error, not a raw 400 dump.
- Resend on a DID with no critical entry → graceful error.
- Node unreachable → status/notifications panels degrade gracefully, not an infinite spinner.
- Rapid repeated clicks on "Revoke" or "Resend" → no duplicate broadcasts; buttons should disable while in-flight.

---

## 7.6 Pass criteria summary to report back

- [ ] All 8 backend requirements PASS (reuse existing Docker/board docs' proven commands)
- [ ] API 1 (`revoke`, critical path) PASS — broadcast fires immediately, non-critical stays silent
- [ ] API 2 (`status`) PASS on all nodes, all fields present
- [ ] API 3 (`broadcast` manual resend) PASS — valid + invalid cases both handled
- [ ] API 4 (`notifications`) PASS — durable, correctly ordered, renderable `headline`
- [ ] Requirement 5 / session-termination: Docker-verified PASS (2026-08-03 fix) — **board hardware retest still outstanding**, don't mark it done in the board doc until actually rerun there
- [ ] Frontend status panel matches backend JSON field-for-field, including `last_notice`
- [ ] Frontend revoke action produces immediate cross-node updates (not gossip-interval-delayed)
- [ ] Frontend resend button handles both valid and invalid cases
- [ ] Frontend session-termination is visually confirmable (or gap flagged if no session UI exists)
- [ ] Frontend notifications feed renders correctly and stays bounded
- [ ] Multi-node UI convergence visually confirmed
- [ ] Error/edge states handled gracefully in UI

---
---

# 8. CRL Offline Revocation Sync — Verification Handoff

**Scope:** Backend offline queue / reconnect-sync engine (8 requirements) + 3 real REST APIs + frontend integration.
**Reference docs in repo:**
- `docs/CRL_Offline_Sync_Verification_Log_EN.md` — iMX8MP board hardware run, English copy, last updated 2026-07-29 (11/11 PASS).
- `optional/container-cohort/docs/CRL_Offline_Doker_Verification-Log.md` — Docker cohort run (11/11 PASS).

---

## 8.1 What this feature is

Offline revocation queue for Guardians operating in disconnected environments (tactical ops, remote locations, satellite links with intermittent connectivity). When a Guardian goes offline it can still issue revocations locally — they land in `crl.json` and a durable `pending/` queue, each entry tracked with a retry counter and timestamps. A background loop probes peer reachability; on reconnect it synchronously drives the **existing gossip anti-entropy exchange** (no new port, no new listener — reuses gossip TCP `50063`) to both fetch revocations missed while offline (comparing CRL version vectors) and flush the outbound queue. Conflict resolution is not reimplemented — it reuses the same deterministic, timestamp-based gossip merge, so offline-fetched and gossip-fetched entries never diverge.

## 8.2 Environment setup

Same cohort as sections 2 and 7.2 above:
```bash
cd <repo-root>
docker compose -f docker-compose.dev.yml up -d --build
docker compose -f docker-compose.dev.yml ps
```

Node ports: nodeA `http://localhost:18443`, nodeB `http://localhost:28443`, nodeC `http://localhost:38443`.

**Same auth gotcha as section 7.2 applies here too** — every `/crl/offline/*` route is behind the bearer-token middleware. Use `SGX_DISABLE_LOGIN=1` for a pure backend/API pass; a proper frontend pass must go through real login and attach `Authorization: Bearer <token>`.

Relevant env vars (all optional, sane defaults):
- `SGX_CRL_OFFLINE_ENABLED` (default on)
- `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS` (default `20`, clamped 5-600) — lower this (e.g. `8`) to speed up manual testing instead of waiting on the background loop.
- `SGX_CRL_OFFLINE_MAX_RETRIES` (default `0` = unlimited; set a small number like `2` to see parking behavior quickly)
- `SGX_CRL_OFFLINE_FLUSH_ROUNDS` (default `3`)
- `SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS` (default `1500`)

**Simulating "offline" in Docker:** `docker stop sgx-nodeC` (or disconnect it from the `sgxnet` network) makes that node unreachable to its peers. `docker start sgx-nodeC` restores it — this is the reconnect moment the whole feature is built around.

---

## 8.3 Backend requirements checklist (8 items) — what to verify

| # | Requirement | How to check |
|---|---|---|
| 1 | Locally queue outgoing revocations; pending queue persists | revoke on an isolated node → entry appears in `crl.json` (`propagated:false`) **and** in `GET /crl/offline/pending` |
| 2 | Track pending revocations with retry counter and timestamps | after a couple of sync cycles with the peer still unreachable, the same pending item's `attempts` increases and `last_attempt_at` populates; `queued_at` stays stable |
| 3 | Queue works while offline; nothing is lost while isolated | with the node fully isolated (`online:false`, `reachable_peers:0`), issue a fresh critical revocation — it must still queue locally and the pre-existing pending entry must remain intact |
| 4 | On reconnect, synchronously push queued revocations to peers | restore connectivity, trigger `POST /crl/offline/sync` (or wait for the loop) → `pending_remaining` drains to `0`, `entries_delivered` increments, and each entry flips to `propagated:true` with peers recorded in `peers_notified` |
| 5 | Fetch missed revocations from peers via CRL version vectors | while node was offline, have another node issue revocations; on reconnect confirm those DIDs become `revoked:true` on the rejoining node and `entries_fetched` increments |
| 6 | Deterministic conflict resolution — CRL converges, no split-brain | two isolated nodes independently revoke the **same** DID with different reasons; after reconnect all nodes must converge on one identical `merkle_root` and the same single surviving entry (later-timestamp wins) |
| 7 | Retry budget + never silently drop (parking) + restart persistence | with `SGX_CRL_OFFLINE_MAX_RETRIES` set low and delivery kept impossible, the pending item reaches the retry budget, gets marked `parked:true`, stays on disk (never deleted), and survives a daemon restart with the same queued/attempt state |
| 8 | Self-reconcile queue from local state (covers CLI-issued + restart) | manually delete a pending JSON file while its `crl.json` entry is still `propagated:false`, then run a sync cycle → `reconciled` count is non-zero and the missing pending file reappears |

Exact ready-to-run bash sequences for all 8 (CRL-033 through CRL-040) already exist and passed — reuse `optional/container-cohort/docs/CRL_Offline_Doker_Verification-Log.md` verbatim for the Docker cohort, or `docs/CRL_Offline_Sync_Verification_Log_EN.md` for the board-hardware command pack.

---

## 8.4 REST API verification (3 real endpoints)

### API 1 — `GET /api/v1/crl/offline/status` (read-only, no side effects)
```bash
curl -s http://localhost:18443/api/v1/crl/offline/status | python3 -m json.tool
```
Expect JSON with: `enabled, online, sync_interval_secs, flush_rounds, max_retries, pending, sync_cycles, reconnects, entries_delivered, entries_fetched, peer_sync_state{<peer_did>: {last_seen_merkle_root, last_seen_sequence, last_sync_at}}`.
**Pass:** `online` correctly reflects real reachability; `pending` matches API 2's count; `peer_sync_state` has one entry per peer this node has successfully synced with at least once.

### API 2 — `GET /api/v1/crl/offline/pending` (read-only, no side effects)
```bash
curl -s http://localhost:18443/api/v1/crl/offline/pending | python3 -m json.tool
```
Expect JSON with: `status, count, pending[]` — each item: `id, revoked_did, reason, severity, attempts, queued_at, last_attempt_at, last_error, parked`.
**Pass:** list matches what's actually on disk in the node's `pending/` directory; `parked` entries are still present (not silently dropped).

### API 3 — `POST /api/v1/crl/offline/sync` (deterministic cycle, forces one cycle now)
```bash
curl -s -X POST http://localhost:18443/api/v1/crl/offline/sync | python3 -m json.tool
```
Expect JSON with: `online, reachable_peers, reconciled, fetched, delivered, pending_remaining`.

**What one cycle actually does, in order (useful for explaining behavior to whoever is testing the UI):**
1. Probes every gossip peer with a raw TCP connect (bounded by `probe_timeout_ms`) → determines `online`.
2. If the node just came back online, logs a "connectivity restored" event (this is what `reconnects` counts).
3. Self-reconciles: any locally-issued, not-yet-propagated entry in `crl.json` gets (re-)added to the pending queue.
4. If offline, stops here — only `reconciled` is meaningful in the response.
5. If online, runs `flush_rounds` gossip pull/push rounds to fetch anything missed (`fetched`), then walks the pending queue: entries now `propagated:true` get dequeued (`delivered`), everything else gets an attempt-counter bump and parks once `max_retries` is hit.

**Pass:** `success` implied by valid JSON; in a converged/online state with nothing pending, `reconciled=fetched=delivered=0`; right after a fresh revoke + reconnect, all three counters should be non-zero as appropriate.

---

## 8.5 Frontend verification (new — this is what needs fresh testing)

UI screen: **"Certificate Revocation List"** → **"Offline Sync"** panel — expected to show a connectivity badge (online/offline), a live pending-queue table, a "Sync now" button, and per-peer version-vector info.

### 8.5a. Status display — field-by-field cross-check
Panel should show at least: `enabled, online, sync_interval_secs, pending, sync_cycles, reconnects, entries_delivered, entries_fetched`. Compare every field against:
```bash
curl -s http://<node-host>:<node-port>/api/v1/crl/offline/status | python3 -m json.tool
```
**Also check whether `peer_sync_state` is surfaced anywhere** (even a simple "last synced with nodeB: 3s ago, root abc123..." line) — if not shown, flag as a gap, since it's the field that proves per-peer convergence, not just aggregate counters.

### 8.5b. Pending queue table — display test
1. Cross-check the UI's pending table row-for-row against `GET /crl/offline/pending`.
2. Confirm each row shows `attempts`, `queued_at`, and (if present) `last_error` — not just the DID.
3. Confirm `parked` entries are visually distinguished (e.g. a badge), not just silently listed like any other pending row.

### 8.5c. Manual "Sync now" — action test
1. Click "Sync now" (API 3).
2. Confirm the UI reflects the response (`reconciled/fetched/delivered/pending_remaining`) without needing a manual page refresh.
3. Click it again immediately — repeated clicks should not stack up duplicate in-flight requests; button should ideally disable while a cycle is running.

### 8.5d. Offline → reconnect — the core scenario, end to end
1. Take one node offline (`docker stop sgx-nodeC`, or the board-equivalent connectivity block).
2. From another node, issue a critical revoke targeting a **dummy** test DID (never a real peer DID — revoking a real peer excludes it from the mesh and breaks the rest of the test).
3. Confirm the UI on the offline node still lets you issue a **local** revoke too, and it shows up as `pending` (not propagated) while offline.
4. Bring the node back (`docker start sgx-nodeC`).
5. Watch the panel (auto-refresh or manual "Sync now"): `online` flips true, `reconnects` increments, the pending table drains, and the previously-missed DID from step 2 becomes visible as revoked on this node.
6. Confirm `/crl/gossip/status` `merkle_root` converges across all nodes afterward.

### 8.5e. Retry/parking — visual test
1. Temporarily lower `SGX_CRL_OFFLINE_MAX_RETRIES` (e.g. to `2`) and keep the target peer unreachable.
2. Watch a pending entry's `attempts` climb across sync cycles in the UI.
3. Once it hits the budget, confirm the UI shows it as `parked` rather than making it disappear — parking must never look like silent data loss to whoever's watching the panel.

### 8.5f. Multi-node convergence
Open the panel against 2+ nodes, run the offline→reconnect scenario (8.5d), and confirm all nodes' `entries_delivered`/`entries_fetched` counters and the gossip `merkle_root` all agree once settled.

### 8.5g. Error/edge states to click through
- "Sync now" clicked while the node has zero reachable peers → graceful "still offline" state, not an error dump.
- Pending table with zero entries → clean empty state, not a blank/broken table.
- Node unreachable entirely → panel degrades gracefully, not an infinite spinner.

---

## 8.6 Pass criteria summary to report back

- [ ] All 8 backend requirements PASS (reuse existing Docker/board docs' proven commands)
- [ ] API 1 (`status`) PASS on all nodes, all fields present including `peer_sync_state`
- [ ] API 2 (`pending`) PASS, matches on-disk queue exactly
- [ ] API 3 (`sync`) PASS — reconcile/fetch/deliver counts behave correctly both offline and online
- [ ] Frontend status panel matches backend JSON field-for-field, including per-peer sync state
- [ ] Frontend pending table matches the API list row-for-row, with `parked` visually distinct
- [ ] Frontend "Sync now" action produces correct counts and UI updates without manual refresh
- [ ] Frontend offline→reconnect scenario fully demoable end to end (queue grows offline, drains on reconnect)
- [ ] Frontend retry/parking is visually confirmable, never reads as silent data loss
- [ ] Multi-node UI convergence visually confirmed
- [ ] Error/edge states handled gracefully in UI
