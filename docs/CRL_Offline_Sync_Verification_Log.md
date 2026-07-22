# CRL Offline Revocation Sync — Verification Log
**Boards:** nodeA (192.168.50.101/103) · nodeB (192.168.50.115) · nodeC (192.168.50.248) — iMX8MP (ARM64) | **Date:** ____ | **Tester:** Asad Ali
**Test tag:** CRL-series (CRL-033 – CRL-043) | **Plan:** `CRL_Offline_Revocation_Sync_Complete_Plan.md`

---

## 📌 Task Description

> Implement offline revocation queue for Guardians operating in disconnected environments (tactical ops, remote locations, satellite with intermittent connectivity). When Guardian goes offline, queue outgoing revocations locally. Track pending revocations with retry counter and timestamps. When connectivity restored, synchronously push queued revocations to peers. Fetch missed revocations from peers by comparing CRL version vectors. Resolve conflicts using timestamp-based "last writer wins" or signature-based trust hierarchy. Ensures Guardians can revoke compromised peers even when isolated.

---

## 📋 How to Use This File

**Jab bhi koi Requirement ya API verify ho jaye (PASS):**
1. `[ ]` ko `[x]` karo aur `## ⏳` ko `## ✅` kar do
2. **Commands:** section mein woh exact command likhna jo run kiya
3. **Result:** section mein terminal output paste karna
4. **Verdict:** ek line mein confirm karna — kya pass hua

**Jab koi Requirement ya API FAIL ho:**
1. **Pehle command side verify karo** — command galat bhi ho sakti hai, code galat nahi bhi ho sakta:
   - Kya teeno nodes chal rahe hain (`pgrep -f sgx_guardian_client`)?
   - Kya offline sync banner aaya start pe (`grep "CRL-OFFLINE sync starting"`)?
   - Kya sync interval ka wait kiya (default 20 s; ya `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8` set karke accelerate karo; ya `POST /crl/offline/sync` se instant cycle chalao)?
   - Kya gossip pehle se kaam kar raha hai (offline sync usi ke exchange pe depend karta hai — pehle `POST /crl/gossip/trigger` try karke dekho gossip theek hai)?
   - Alternate command se dobara try karo
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/crl/offline/sync.rs::run_cycle`) (cross-check khud bhi karo — issue doosri file mein bhi ho sakta hai, e.g. gossip `run_round_once`)
   - Exact error message jo aaya
   - Kya try kiya aur kya nahi chala

**⚠️ Common mistakes jo dobara na karein:**
- **DID hamesha poora `did:guardian:...` prefix ke sath likhna** — truncated ID galat (non-existent) DID check karega, result misleading hoga.
- **`<...>` angle brackets literally mat likhna** — placeholder markers hain, shell mein redirection operators.
- **Propagation/offline tests mein hamesha DUMMY target DIDs use karo** (e.g. `did:guardian:offline-test-001`) — real nodeB/nodeC DID revoke karoge to woh node mesh se exclude ho jayega aur sync tests kharab honge.
- **Entry IDs / pending IDs hamesha CURRENT session ke run se lena** — har fresh test run mein naye UUIDs bante hain.

**Requirements count ke baare mein:**
- Requirements task description ke distinct verifiable claims se derive hoti hain — fixed count nahi.
- Artificially pad mat karo, koi genuine requirement miss bhi mat karo.

**Symbols:** `✅` = Verified and passed · `❌` = Confirmed code-side failure (command side ruled out) · `⏳` = Not yet tested

---

## ⚡ Test Setup (run once before Requirement 1)

```bash
# Har board pe: purana process band, naya binary deploy, phir start (offline sync accelerated):
pkill -f sgx_guardian_client || true
# (scp new binary here)
export SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8    # test accelerator (prod default 20 s)
./sgx_guardian_client nodeA                    # nodeB / nodeC on their boards

# Handy paths / vars:
CRL_BASE=/var/lib/sgx-guardian/identity/crl
PENDING_DIR=$CRL_BASE/pending
SELF_DID=$(jq -r .did /var/lib/sgx-guardian/identity/did.json)
```

> **Simulating "offline":** shared LAN pe pura network kaatna mushkil hai. Do practical tareeqe: (a) issue a revocation for a **dummy** DID on a node and observe it sit in `pending/` until sync cycles flush it (delivery to peers); (b) for a true partition, `pkill` a node, issue on another, then restart the killed node and watch it fetch missed revocations. Dono neeche cover hain.

---

## ⏳ Requirement 1 — [ ] Locally queue outgoing revocations (pending queue persists)

> Jab koi revocation issue hoti hai, woh local `pending/` queue mein persist hoti hai (retry + timestamp metadata ke saath), aur `crl.json` mein bhi immediately aa jati hai.

**Commands (nodeC):**
```bash
./sgx-pa-cli crl revoke --did did:guardian:offline-test-001 --reason compromised --severity high --note "CRL-033 queue"
ls -la $PENDING_DIR/
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool
jq '.entries[] | select(.revoked_did=="did:guardian:offline-test-001") | {id, propagated}' $CRL_BASE/crl.json
```

**Expected:**
```
pending/urn_uuid_<...>.json file present
/crl/offline/pending → count ≥ 1, entry shows attempts, queued_at, parked:false
crl.json has the entry with propagated:false (not yet delivered)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 2 — [ ] Track pending revocations with retry counter and timestamps

> Har pending entry apna `attempts` counter aur `queued_at`/`last_attempt_at` timestamps track karti hai; har sync cycle pe attempt bump hota hai (jab tak delivered na ho).

**Commands (nodeC — while peers reachable, let 2 cycles run):**
```bash
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool
sleep 20   # ~2 accelerated cycles
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool
cat $PENDING_DIR/*.json | python3 -m json.tool
```

**Expected:**
```
attempts increments across cycles (until delivered); last_attempt_at updates each cycle
queued_at stays fixed; last_error null on success
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 3 — [ ] Queue works when offline; nothing lost while isolated

> Jab koi peer reachable nahi (offline), sync cycle no-op karta hai aur queue persist rehti hai — koi revocation lost nahi hoti. Guardian isolated hone pe bhi compromised peer ko revoke kar sakta hai.

**Commands:**
```bash
# nodeC ko isolate karo: baaki dono band kar do (nodeC ke liye koi reachable peer nahi)
ssh root@192.168.50.101 "pkill -f sgx_guardian_client"
ssh root@192.168.50.115 "pkill -f sgx_guardian_client"
sleep 12   # nodeC ka agla cycle → offline detect

# nodeC pe (isolated) revoke + status:
ssh root@192.168.50.248 "./sgx-pa-cli crl revoke --did did:guardian:offline-test-002 --reason stolen --severity critical --note 'CRL-035 isolated'"
ssh root@192.168.50.248 "curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool | grep -E '\"online\"|\"pending\"|\"reconnects\"'"
ssh root@192.168.50.248 "ls -la $PENDING_DIR/"
```

**Expected:**
```
status: "online": false, "pending" ≥ 1 (entry retained while isolated)
revoke succeeds locally even with zero reachable peers (crl.json updated)
audit shows offline cycle no-op; nothing dropped
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 4 — [ ] On connectivity restored, synchronously push queued revocations to peers

> Jab connectivity wapas aati hai (offline→online transition), sync loop reconnect detect karta hai aur queued revocations ko peers tak push karta hai (gossip exchange ke through), phir delivery confirm hone pe dequeue.

**Commands (continue from Requirement 3):**
```bash
# nodeA + nodeB wapas start karo → nodeC ke liye connectivity restore
ssh root@192.168.50.101 "cd <deploy_dir> && ./sgx_guardian_client nodeA &"
sleep 20
ssh root@192.168.50.115 "cd <deploy_dir> && ./sgx_guardian_client nodeB &"
sleep 30   # nodeC ke ~3-4 cycles + gossip

# nodeC: reconnect + delivery confirm
ssh root@192.168.50.248 "grep -a 'connectivity RESTORED' /var/log/sgx-guardian/audit-nodeC.log | tail -1"
ssh root@192.168.50.248 "curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool | grep -E '\"online\"|\"pending\"|\"reconnects\"|\"entries_delivered\"'"

# Peers ko revocation mil gayi?
./sgx-pa-cli crl check --did did:guardian:offline-test-002                          # nodeA → revoked: true
ssh root@192.168.50.115 "./sgx-pa-cli crl check --did did:guardian:offline-test-002"   # nodeB → revoked: true
```

**Expected:**
```
audit: "CRL offline: connectivity RESTORED — N peer(s) reachable, syncing"; reconnects ≥ 1
pending drops toward 0; entries_delivered ≥ 1 (dequeued once propagated)
nodeA + nodeB both show offline-test-002 revoked
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 5 — [ ] Fetch missed revocations from peers by comparing CRL version vectors

> Jab node offline tha, uss dauran doosre nodes pe issue hui revocations ko reconnect pe fetch karta hai — CRL version vectors (sequence/merkle_root) compare karke. Per-peer sync-state observable hai.

**Commands:**
```bash
# nodeC band karo; is dauran nodeA pe 2 revocations issue karo (nodeC ko yeh MISS hongi):
ssh root@192.168.50.248 "pkill -f sgx_guardian_client"
./sgx-pa-cli crl revoke --did did:guardian:offline-test-003 --reason compromised --severity critical --note "CRL-037 missed"
./sgx-pa-cli crl revoke --did did:guardian:offline-test-004 --reason lost --severity high --note "CRL-037 missed"
sleep 5

# nodeC wapas start → sirf wait (koi manual pull command NAHI):
ssh root@192.168.50.248 "cd <deploy_dir> && SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 ./sgx_guardian_client nodeC &"
sleep 40

# nodeC ne missed revocations fetch kar li?
ssh root@192.168.50.248 "./sgx-pa-cli crl check --did did:guardian:offline-test-003"   # → revoked: true
ssh root@192.168.50.248 "./sgx-pa-cli crl check --did did:guardian:offline-test-004"   # → revoked: true
ssh root@192.168.50.248 "curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool | grep -A20 'peer_sync_state'"
ssh root@192.168.50.248 "cat $CRL_BASE/sync_state.json | python3 -m json.tool"
```

**Expected:**
```
nodeC picks up BOTH missed revocations after reconnect (zero manual pull)
peer_sync_state / sync_state.json shows per-peer last_seen_merkle_root + last_seen_sequence + last_sync_at
entries_fetched ≥ 2 in status
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 6 — [ ] Resolve conflicts (deterministic) — CRL converges, no split-brain

> Agar do nodes independently same DID revoke karein (offline dauran), reconnect pe conflict deterministically resolve hota hai (earliest-timestamp wins, shared gossip rule) — teeno nodes ka Merkle root identical.

**Commands:**
```bash
# nodeB aur nodeC dono ko band karke, dono pe SAME dummy DID revoke karo (different timestamps):
ssh root@192.168.50.115 "pkill -f sgx_guardian_client"
ssh root@192.168.50.248 "pkill -f sgx_guardian_client"
ssh root@192.168.50.115 "cd <deploy_dir> && ./sgx_guardian_client nodeB & sleep 5; ./sgx-pa-cli crl revoke --did did:guardian:conflict-test-001 --reason compromised --severity high --note 'B first'"
sleep 3
ssh root@192.168.50.248 "cd <deploy_dir> && ./sgx_guardian_client nodeC & sleep 5; ./sgx-pa-cli crl revoke --did did:guardian:conflict-test-001 --reason stolen --severity high --note 'C later'"
sleep 40   # let gossip + offline sync converge across all three

# Convergence check — teeno nodes:
./sgx-pa-cli crl root
ssh root@192.168.50.115 "./sgx-pa-cli crl root"
ssh root@192.168.50.248 "./sgx-pa-cli crl root"
# The surviving entry (earliest timestamp) same on all three:
for h in "" "root@192.168.50.115" "root@192.168.50.248"; do
  ${h:+ssh $h} bash -c "jq '.entries[] | select(.revoked_did==\"did:guardian:conflict-test-001\") | {reason, timestamp, revoker_did}' $CRL_BASE/crl.json" 2>/dev/null
done
```

**Expected:**
```
Identical merkle_root on all three nodes after convergence
The same single entry survives everywhere (earliest timestamp wins — deterministic)
No split-brain: offline-fetched + gossip-fetched resolve identically
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 7 — [ ] Retry budget + never silently drop (parking) + restart persistence

> Undelivered revocation retry hoti rehti hai; `MAX_RETRIES` set ho to exhaust hone pe **parked** hoti hai (disk pe retained + audited, dropped NAHI). Queue restart survive karti hai.

**Commands:**
```bash
# nodeC pe MAX_RETRIES=2 ke saath, ek revocation aisi jo deliver na ho sake (peers band):
ssh root@192.168.50.101 "pkill -f sgx_guardian_client"; ssh root@192.168.50.115 "pkill -f sgx_guardian_client"
ssh root@192.168.50.248 "pkill -f sgx_guardian_client"
ssh root@192.168.50.248 "cd <deploy_dir> && SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=6 SGX_CRL_OFFLINE_MAX_RETRIES=2 ./sgx_guardian_client nodeC &"
ssh root@192.168.50.248 "./sgx-pa-cli crl revoke --did did:guardian:offline-test-005 --reason compromised --severity high --note 'CRL-039 park'"
sleep 30   # several cycles with no reachable peer
ssh root@192.168.50.248 "curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool"   # attempts ≥ 2, parked:true

# Restart persistence: nodeC restart, pending survive kare:
ssh root@192.168.50.248 "pkill -f sgx_guardian_client && sleep 3 && cd <deploy_dir> && ./sgx_guardian_client nodeC &"
sleep 10
ssh root@192.168.50.248 "ls -la $PENDING_DIR/ && curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool"
```

**Expected:**
```
Pending entry reaches parked:true after 2 attempts — but STILL present (not dropped)
After daemon restart the pending file survives; entry still queued
audit trail shows attempts, no silent loss
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 8 — [ ] Self-reconcile queue from local state (covers CLI-issued + restart)

> Sync loop har cycle local `crl.json` reconcile karta hai: koi bhi locally-issued (`revoker_did == self`) aur `propagated == false` entry automatically pending ban jati hai — chahe woh CLI se issue hui ho (REST handler ke baghair).

**Commands (nodeA — issue via CLI, then confirm auto-reconcile even if pending file wasn't pre-seeded):**
```bash
# Fresh CLI revoke (CLI path), then delete its pending file to prove reconcile re-adds it:
./sgx-pa-cli crl revoke --did did:guardian:offline-test-006 --reason policy_violation --severity high --note "CRL-040 reconcile"
ID=$(jq -r '.entries[] | select(.revoked_did=="did:guardian:offline-test-006") | .id' $CRL_BASE/crl.json)
rm -f "$PENDING_DIR/$(echo $ID | tr ':/' '__').json"    # simulate missing queue file
# Wait one cycle → reconcile should re-add it (until propagated):
sleep 12
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool | grep offline-test-006 || echo "check: may already be propagated+dequeued if peers up"
grep -a "CRL offline queued\|reconcil" /var/log/sgx-guardian/audit-nodeA.log | tail -3
```

**Expected:**
```
Reconcile re-adds the locally-issued, not-yet-propagated entry to pending
(If peers were reachable and it propagated within the cycle, it's correctly dequeued instead — either outcome proves reconcile ran)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

# 🔌 API Verification

## ⏳ API 1 — [ ] GET `/api/v1/crl/offline/status`

**Command:**
```bash
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool
```

**Expected:**
```json
{
    "enabled": true,
    "online": true,
    "sync_interval_secs": 8,
    "flush_rounds": 3,
    "max_retries": 0,
    "pending": 0,
    "sync_cycles": 12,
    "reconnects": 1,
    "entries_delivered": 2,
    "entries_fetched": 2,
    "peer_sync_state": { "did:guardian:...": {"last_seen_merkle_root": "...", "last_seen_sequence": 6, "last_sync_at": "2026-..."} }
}
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 2 — [ ] GET `/api/v1/crl/offline/pending`

**Command:**
```bash
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool
```

**Expected:**
```json
{
    "status": "success",
    "count": 1,
    "pending": [
        {"id":"urn:uuid:...","revoked_did":"did:guardian:...","reason":"compromised","severity":"high","attempts":2,"queued_at":"2026-...","last_attempt_at":"2026-...","last_error":null,"parked":false}
    ]
}
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 3 — [ ] POST `/api/v1/crl/offline/sync` (deterministic cycle)

**Command:**
```bash
curl -s -X POST http://localhost:8443/api/v1/crl/offline/sync | python3 -m json.tool
```

**Expected:**
```json
{
    "online": true,
    "reachable_peers": 2,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 0
}
```
**Note:** Agar abhi koi pending nahi aur sab converged hai to `fetched`/`delivered` 0 honge (steady state) — yeh sahi hai. Pending hone pe `delivered` badhega.

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## 🗺️ Test-Tag Mapping (CRL-series continuation)

| Tag | What it proves | Section above |
|---|---|---|
| CRL-033 | Locally queue outgoing revocations (pending persists) | Req 1 |
| CRL-034 | Retry counter + timestamps per pending | Req 2 |
| CRL-035 | Offline operation lossless (isolated revoke) | Req 3 |
| CRL-036 | Reconnect → synchronous push + dequeue on delivery | Req 4 |
| CRL-037 | Fetch missed revocations via version vectors | Req 5 |
| CRL-038 | Deterministic conflict resolution → root convergence | Req 6 |
| CRL-039 | Retry budget + parking (never drop) + restart persistence | Req 7 |
| CRL-040 | Self-reconcile from local state (CLI-issued coverage) | Req 8 |
| CRL-041 | `/crl/offline/status` observability | API 1 |
| CRL-042 | `/crl/offline/pending` listing | API 2 |
| CRL-043 | `/crl/offline/sync` deterministic cycle | API 3 |

---

## ⚙️ Known Issue Placeholders (fill during testing)

### Issue 1 — ____
```
(symptoms / root cause / fix)
```

---

## 🧰 Emergency & Debug Commands

```bash
# Kill-switch (no rebuild): restart with offline sync OFF
SGX_CRL_OFFLINE_ENABLED=0 ./sgx_guardian_client nodeA

# Watch the offline sync trail:
grep -a "CRL offline\|CRL-OFFLINE\|connectivity RESTORED" /var/log/sgx-guardian/audit-nodeA.log | tail -20

# Inspect the queue + version vectors directly:
ls -la /var/lib/sgx-guardian/identity/crl/pending/
cat /var/lib/sgx-guardian/identity/crl/pending/*.json | python3 -m json.tool
cat /var/lib/sgx-guardian/identity/crl/sync_state.json | python3 -m json.tool

# Force one sync cycle immediately (instead of waiting for the interval):
curl -s -X POST http://localhost:8443/api/v1/crl/offline/sync | python3 -m json.tool

# Is gossip healthy? (offline sync rides the gossip exchange — check this first if fetch/flush stalls)
curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger | python3 -m json.tool

# Manually clear a parked/stuck pending entry after operator review (dummy DIDs only):
rm -f /var/lib/sgx-guardian/identity/crl/pending/urn_uuid_<...>.json

# Reset offline test state (unrevoke dummy DIDs on nodeA/Owner):
for d in offline-test-001 offline-test-002 offline-test-003 offline-test-004 offline-test-005 offline-test-006 conflict-test-001; do
  curl -s -X POST http://localhost:8443/api/v1/crl/unrevoke -H "Content-Type: application/json" -d "{\"did\":\"did:guardian:$d\"}"
done
```

**Timing cheat-sheet:** default sync interval 20 s → reconnect flush within ~1 cycle · `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8` → faster · `POST /crl/offline/sync` → instant. Delivery confirmation needs gossip to reach the `propagated` threshold, so allow gossip a round or two after the push.
