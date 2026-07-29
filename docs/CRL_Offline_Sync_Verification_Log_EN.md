# CRL Offline Revocation Sync — Verification Log (English)
**Boards:** nodeA (192.168.1.92) · nodeB (192.168.1.195) · nodeC (192.168.1.252) — iMX8MP (ARM64) | **Date:** `2026-07-22`; updated board rerun `2026-07-29` | **Tester:** Aliza Malik
**Test tag:** CRL-series (CRL-033 – CRL-043) | **Plan:** `CRL_Offline_Revocation_Sync_Complete_Plan.md` | **Language:** English companion copy

---

## 📌 Task Description

> Implement offline revocation queue for Guardians operating in disconnected environments (tactical ops, remote locations, satellite with intermittent connectivity). When Guardian goes offline, queue outgoing revocations locally. Track pending revocations with retry counter and timestamps. When connectivity restored, synchronously push queued revocations to peers. Fetch missed revocations from peers by comparing CRL version vectors. Resolve conflicts using timestamp-based "last writer wins" or signature-based trust hierarchy. Ensures Guardians can revoke compromised peers even when isolated.

---

## 📋 How to Use This File

**When any Requirement or API is verified (PASS):**
1. Change `[ ]` to `[x]` and change `## ⏳` to `## ✅`
2. In the **Commands:** section, write the exact command that was run
3. In the **Result:** section, paste the terminal output
4. In **Verdict:** confirm in one line what passed

**When any Requirement or API fails:**
1. **Verify the command side first** — the command may be wrong even if the code is not:
   - Are all three nodes running (`pgrep -f sgx_guardian_client`)?
   - Did the offline sync startup banner appear (`grep "CRL-OFFLINE sync starting"`)?
   - Did you wait for the sync interval (default 20 s; or set `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8` to accelerate; or run an instant cycle with `POST /crl/offline/sync`)?
   - Is gossip already working (offline sync depends on the same exchange — first try `POST /crl/gossip/trigger` to confirm gossip is healthy)?
   - Retry with an alternate command
2. **Only mark `❌`** after fully confirming the issue is code-side, not command-side
3. **When marking `❌`, also write:**
   - Which file/function likely contains the issue (e.g. `src/crl/offline/sync.rs::run_cycle`) (cross-check it yourself too — the issue may also be in another file, e.g. gossip `run_round_once`)
   - The exact error message observed
   - What was tried and what did not work

**⚠️ Common mistakes to avoid repeating:**
- **Always write the full DID with the `did:guardian:...` prefix** — a truncated ID checks the wrong/non-existent DID and produces misleading results.
- **Do not type `<...>` angle brackets literally** — they are placeholder markers and shell redirection operators.
- **Always use DUMMY target DIDs in propagation/offline tests** (e.g. `did:guardian:offline-test-001`) — revoking a real nodeB/nodeC DID excludes that node from the mesh and breaks sync tests.
- **Always take entry IDs / pending IDs from the CURRENT test session** — each fresh test run creates new UUIDs.

**About the requirements count:**
- Requirements are derived from the distinct verifiable claims in the task description; the count is not fixed.
- Do not pad the list artificially, and do not miss any genuine requirement.

**Symbols:** `✅` = Verified and passed · `❌` = Confirmed code-side failure (command side ruled out) · `⏳` = Not yet tested

---

## ✅ Quick Pass / Remaining Summary

**Last updated:** `2026-07-29` after updated-IP rerun through Requirement 8.

**Counts:**
- Requirements: `8 / 8 PASS`, `0 remaining`, `0 confirmed FAIL`
- APIs: `3 / 3 PASS`, `0 remaining`, `0 confirmed FAIL`
- Total: `11 / 11 PASS`, `0 remaining`, `0 confirmed FAIL`

**Requirements list:**
| Item | Status |
|---|---|
| Req 1 — Locally queue outgoing revocations | ✅ PASS |
| Req 2 — Retry counter + timestamps | ✅ PASS |
| Req 3 — Queue works while offline / nothing lost | ✅ PASS |
| Req 4 — Reconnect pushes queued revocations + dequeue | ✅ PASS |
| Req 5 — Fetch missed revocations via version vectors | ✅ PASS |
| Req 6 — Deterministic conflict resolution + convergence | ✅ PASS |
| Req 7 — Retry budget / parking / restart persistence | ✅ PASS |
| Req 8 — Self-reconcile from local state / CLI path | ✅ PASS |

**API list:**
| Item | Status |
|---|---|
| API 1 — `GET /api/v1/crl/offline/status` | ✅ PASS |
| API 2 — `GET /api/v1/crl/offline/pending` | ✅ PASS |
| API 3 — `POST /api/v1/crl/offline/sync` | ✅ PASS |

---

## ⚡ Test Setup (run once before Requirement 1)

```bash
# On each board: stop the old process, deploy the new binary, then start (offline sync accelerated):
pkill -f sgx_guardian_client || true
# (scp new binary here)
export SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8    # test accelerator (prod default 20 s)
cd /home/root && ./sgx_guardian_client nodeA   # nodeB / nodeC on their boards

# Handy paths / vars:
CRL_BASE=/var/lib/sgx-guardian/identity/crl
PENDING_DIR=$CRL_BASE/pending
SELF_DID=$(python3 - <<'PY'
import json
print(json.load(open("/var/lib/sgx-guardian/identity/did.json")).get("did", ""))
PY
)
```

> **Simulating "offline":** On a shared LAN it is difficult to cut the entire network. There are two practical methods: (a) issue a revocation for a **dummy** DID on one node and observe it remain in `pending/` until sync cycles flush it (delivery to peers); (b) for a true partition, `pkill` a node, issue on another node, then restart the killed node and watch it fetch missed revocations. Both methods are covered below.
>
> **Board correction from actual testing (`2026-07-22`):** Do not turn nodeA OFF before startup. nodeA provides the CA / registry-sync / lighthouse role; nodeC required nodeA to be reachable for a clean bootstrap. For `Requirement 3/4`, the preferred board-safe method is also to keep `nodeA` ON and simulate the offline condition by temporarily blocking only the CRL sync ports on `nodeC`.
>
> **Runtime observation (`2026-07-22`):** the nodeC foreground log loaded nodeB from `192.168.4.3:50052`, while the board test inventory lists nodeB as `192.168.1.195`. This does not block the current nodeA↔nodeC tests, but runtime config should be cross-checked before nodeB-dependent requirements (Req 4–6).

## Board Verification Command Pack (current working commands)

Use this section for the next board pass. Older evidence is preserved below; this section provides a clean node-by-node run order. Run commands in a root shell. Use dummy DIDs only.

**Board map:**
- nodeA / owner / CA: `192.168.1.92`
- nodeB / member: `192.168.1.195`
- nodeC / member: `192.168.1.252`

**Important verification rules:**
- Do not use `GET /health`; the current board route returned `404`. Use `/api/v1/crl/offline/status` for readiness.
- `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8` is a board-test accelerator. `SGX_CRL_GOSSIP_INTERVAL_SECS=10` makes routine gossip faster; still use `POST /api/v1/crl/offline/sync` for deterministic checks.
- Fully offline cycles (`reachable_peers=0`) retain the queue, but the current code does not increment attempts. To verify parking, use a one-peer-reachable / threshold-not-met setup (Req 7).
- In the current implementation, the conflict rule in `src/crl/gossip/store.rs::incoming_wins` is **later timestamp wins**, with lower fingerprint as the tie-breaker. If the acceptance criteria require "earliest timestamp wins", that is a requirement/code wording mismatch.

### 0) Clean boot + readiness

**Node A (192.168.1.92):**
```bash
pkill -f sgx_guardian_client || true
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p tcp --sport 50063 -j REJECT 2>/dev/null || true
iptables -D OUTPUT -p udp --dport 50064 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p udp --sport 50064 -j REJECT 2>/dev/null || true
cd /home/root
nohup env SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 SGX_CRL_GOSSIP_INTERVAL_SECS=10 ./sgx_guardian_client nodeA >/tmp/crl-offline-nodeA.log 2>&1 &
sleep 6
grep -aE "CRL-OFFLINE sync starting|REST admin API listening|CRL-GOSSIP engine starting" /tmp/crl-offline-nodeA.log | tail -5
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/gossip/status | python3 -m json.tool
```

**Node B (192.168.1.195):**
```bash
pkill -f sgx_guardian_client || true
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p tcp --sport 50063 -j REJECT 2>/dev/null || true
iptables -D OUTPUT -p udp --dport 50064 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p udp --sport 50064 -j REJECT 2>/dev/null || true
cd /home/root
nohup env SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 SGX_CRL_GOSSIP_INTERVAL_SECS=10 ./sgx_guardian_client nodeB >/tmp/crl-offline-nodeB.log 2>&1 &
sleep 6
grep -aE "CRL-OFFLINE sync starting|REST admin API listening|CRL-GOSSIP engine starting" /tmp/crl-offline-nodeB.log | tail -5
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/gossip/status | python3 -m json.tool
```

**Node C (192.168.1.252):**
```bash
pkill -f sgx_guardian_client || true
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p tcp --sport 50063 -j REJECT 2>/dev/null || true
iptables -D OUTPUT -p udp --dport 50064 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p udp --sport 50064 -j REJECT 2>/dev/null || true
cd /home/root
nohup env SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 SGX_CRL_GOSSIP_INTERVAL_SECS=10 ./sgx_guardian_client nodeC >/tmp/crl-offline-nodeC.log 2>&1 &
sleep 6
grep -aE "CRL-OFFLINE sync starting|REST admin API listening|CRL-GOSSIP engine starting" /tmp/crl-offline-nodeC.log | tail -5
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/gossip/status | python3 -m json.tool
```

**Control terminal from nodeA/laptop (optional all-node sanity):**
```bash
ssh root@192.168.1.195 "pgrep -af sgx_guardian_client; curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool"
ssh root@192.168.1.252 "pgrep -af sgx_guardian_client; curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool"
```

### 1) Req 1 + API 1 + API 2: local REST revoke queues pending entry

**Node B (keep it OFF so nodeC has pending work and does not instantly reach full threshold):**
```bash
pkill -f sgx_guardian_client || true
pgrep -af sgx_guardian_client || true
```

**Node C:**
```bash
API=http://localhost:8443/api/v1
CRL_BASE=/var/lib/sgx-guardian/identity/crl
PENDING_DIR=$CRL_BASE/pending
RUN_ID=$(date -u +%Y%m%d%H%M%S)
DID_Q="did:guardian:offline-board-q-$RUN_ID"
echo "$DID_Q" >/tmp/crl-offline-req1-did

curl -s -X POST "$API/crl/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$DID_Q\",\"reason\":\"compromised\",\"severity\":\"high\",\"note\":\"CRL-033 board queue $RUN_ID\"}" | python3 -m json.tool

curl -s "$API/crl/offline/pending" | python3 -m json.tool
curl -s "$API/crl/offline/status" | python3 -m json.tool
ls -la "$PENDING_DIR"/

python3 - "$DID_Q" <<'PY'
import json, sys
did = sys.argv[1]
p = "/var/lib/sgx-guardian/identity/crl/crl.json"
d = json.load(open(p))
hits = [
    {
        "id": e.get("id"),
        "revoked_did": e.get("revoked_did"),
        "propagated": e.get("propagated"),
        "peers_notified": e.get("peers_notified", []),
    }
    for e in d.get("entries", [])
    if e.get("revoked_did") == did
]
print(hits)
assert hits and hits[-1]["propagated"] is False
PY
```

**Expected PASS:**
- `/crl/offline/pending` returns `status: success`, `count >= 1`.
- The fresh `DID_Q` appears with `attempts`, `queued_at`, `last_attempt_at`, `last_error`, `parked`.
- Local `crl.json` contains `DID_Q` immediately with `propagated:false`.

### 2) Req 2: retry counter + timestamp metadata

**Node C (continue from Req 1 while nodeA is ON and nodeB is OFF):**
```bash
API=http://localhost:8443/api/v1
DID_Q=$(cat /tmp/crl-offline-req1-did)
ID_Q=$(python3 - "$DID_Q" <<'PY'
import json, sys
did = sys.argv[1]
d = json.load(open("/var/lib/sgx-guardian/identity/crl/crl.json"))
for e in d.get("entries", []):
    if e.get("revoked_did") == did:
        print(e.get("id", ""))
        break
PY
)
echo "ID_Q=$ID_Q"

for i in 1 2 3; do
  curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
  sleep 3
done

curl -s "$API/crl/offline/pending" | python3 -m json.tool
python3 - "$ID_Q" <<'PY'
import json, sys
entry_id = sys.argv[1]
path = "/var/lib/sgx-guardian/identity/crl/pending/" + entry_id.replace(":", "_").replace("/", "_") + ".json"
p = json.load(open(path))
print({"id": p["entry"]["id"], "attempts": p["attempts"], "queued_at": p["queued_at"], "last_attempt_at": p["last_attempt_at"], "parked": p["parked"]})
assert p["attempts"] >= 1
assert p["queued_at"]
assert p["last_attempt_at"]
PY
```

**Expected PASS:**
- `attempts >= 1`.
- `queued_at` remains fixed and `last_attempt_at` is populated.
- `parked:false` unless this node was started with a small max retry budget.

### 3) Req 3: true isolated queue, no revocation lost while offline

**Node A:** keep daemon ON.

**Node C (block CRL sync/emergency channels only):**
```bash
API=http://localhost:8443/api/v1
RUN_ID=$(date -u +%Y%m%d%H%M%S)
DID_ISO="did:guardian:offline-board-isolated-$RUN_ID"
echo "$DID_ISO" >/tmp/crl-offline-req3-did

iptables -I OUTPUT -p tcp --dport 50063 -j REJECT
iptables -I INPUT  -p tcp --sport 50063 -j REJECT
iptables -I OUTPUT -p udp --dport 50064 -j REJECT
iptables -I INPUT  -p udp --sport 50064 -j REJECT

curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
curl -s "$API/crl/offline/status" | python3 -m json.tool

curl -s -X POST "$API/crl/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$DID_ISO\",\"reason\":\"stolen\",\"severity\":\"critical\",\"note\":\"CRL-035 isolated board $RUN_ID\"}" | python3 -m json.tool

curl -s "$API/crl/offline/pending" | python3 -m json.tool
python3 - "$DID_ISO" <<'PY'
import json, sys
did = sys.argv[1]
d = json.load(open("/var/lib/sgx-guardian/identity/crl/crl.json"))
hits = [{"id": e.get("id"), "revoked_did": e.get("revoked_did"), "propagated": e.get("propagated")} for e in d.get("entries", []) if e.get("revoked_did") == did]
print(hits)
assert hits and hits[-1]["propagated"] is False
PY
```

**Expected PASS:**
- Status shows `"online": false`.
- Revoke still succeeds locally.
- Pending list contains `DID_ISO`; local CRL contains the same DID with `propagated:false`.
- Queue remains on disk until reconnect; no entry is silently dropped.

### 4) Req 4: restore connectivity, push queued revocation, dequeue on propagated

**Node B (bring third node back before restore so nodeC can reach threshold 2):**
```bash
pkill -f sgx_guardian_client || true
cd /home/root
nohup env SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 SGX_CRL_GOSSIP_INTERVAL_SECS=10 ./sgx_guardian_client nodeB >/tmp/crl-offline-nodeB.log 2>&1 &
sleep 8
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool
```

**Node C (remove blocks, force several deterministic cycles):**
```bash
API=http://localhost:8443/api/v1
DID_ISO=$(cat /tmp/crl-offline-req3-did)

iptables -D OUTPUT -p tcp --dport 50063 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p tcp --sport 50063 -j REJECT 2>/dev/null || true
iptables -D OUTPUT -p udp --dport 50064 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p udp --sport 50064 -j REJECT 2>/dev/null || true

for i in 1 2 3 4 5 6; do
  curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
  sleep 4
done

curl -s "$API/crl/offline/status" | python3 -m json.tool
curl -s "$API/crl/offline/pending" | python3 -m json.tool
python3 - "$DID_ISO" <<'PY'
import json, sys
did = sys.argv[1]
d = json.load(open("/var/lib/sgx-guardian/identity/crl/crl.json"))
hits = [{"id": e.get("id"), "propagated": e.get("propagated"), "peers_notified": e.get("peers_notified", [])} for e in d.get("entries", []) if e.get("revoked_did") == did]
print(hits)
assert hits and hits[-1]["propagated"] is True
assert len(hits[-1]["peers_notified"]) >= 2
PY
```

**Control terminal from nodeA/laptop (peer receipt proof on nodeA and nodeB):**
```bash
scp root@192.168.1.252:/tmp/crl-offline-req3-did /tmp/crl-offline-req3-did
DID_ISO=$(cat /tmp/crl-offline-req3-did)
for HOST in 192.168.1.92 192.168.1.195; do
  echo "===== $HOST ====="
  ssh root@$HOST "curl -s 'http://localhost:8443/api/v1/crl/check?did=$DID_ISO' | python3 -m json.tool"
done
```

**Expected PASS:**
- nodeC status eventually shows `pending: 0` and `entries_delivered` advanced.
- nodeC local CRL shows `propagated:true` and at least two `peers_notified`.
- nodeA and nodeB both return `"revoked": true` for `DID_ISO`.

### 5) Req 5: fetch missed revocations using version vectors

This isolates the proof from routine gossip by starting nodeC with `SGX_CRL_GOSSIP_ENABLED=0`; offline sync can still initiate `run_round_once` to nodeA/nodeB on TCP `50063`.

**Node C (offline during source revocations):**
```bash
pkill -f sgx_guardian_client || true
pgrep -af sgx_guardian_client || true
```

**Node A (issue two revocations while nodeC is down):**
```bash
API=http://localhost:8443/api/v1
RUN_ID=$(date -u +%Y%m%d%H%M%S)
DID_MISS_1="did:guardian:offline-board-missed-a-$RUN_ID"
DID_MISS_2="did:guardian:offline-board-missed-b-$RUN_ID"
printf "%s\n%s\n" "$DID_MISS_1" "$DID_MISS_2" >/tmp/crl-offline-req5-dids

curl -s -X POST "$API/crl/revoke" -H "Content-Type: application/json" \
  -d "{\"did\":\"$DID_MISS_1\",\"reason\":\"compromised\",\"severity\":\"high\",\"note\":\"CRL-037 missed A $RUN_ID\"}" | python3 -m json.tool
curl -s -X POST "$API/crl/revoke" -H "Content-Type: application/json" \
  -d "{\"did\":\"$DID_MISS_2\",\"reason\":\"lost\",\"severity\":\"high\",\"note\":\"CRL-037 missed B $RUN_ID\"}" | python3 -m json.tool

curl -s "http://localhost:8443/api/v1/crl/check?did=$DID_MISS_1" | python3 -m json.tool
curl -s "http://localhost:8443/api/v1/crl/check?did=$DID_MISS_2" | python3 -m json.tool
```

**Copy DIDs to nodeC if needed:**
```bash
scp /tmp/crl-offline-req5-dids root@192.168.1.252:/tmp/crl-offline-req5-dids
```

**Node C (restart, then force offline-sync pull):**
```bash
cd /home/root
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p tcp --sport 50063 -j REJECT 2>/dev/null || true
nohup env SGX_CRL_GOSSIP_ENABLED=0 SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 ./sgx_guardian_client nodeC >/tmp/crl-offline-nodeC-req5.log 2>&1 &
sleep 8
API=http://localhost:8443/api/v1

for i in 1 2 3 4; do
  curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
  sleep 4
done

while read DID; do
  curl -s "$API/crl/check?did=$DID" | python3 -m json.tool
done </tmp/crl-offline-req5-dids

curl -s "$API/crl/offline/status" | python3 -m json.tool
cat /var/lib/sgx-guardian/identity/crl/sync_state.json | python3 -m json.tool
```

**Expected PASS:**
- nodeC returns `"revoked": true` for both missed DIDs.
- `/crl/offline/status` has `peer_sync_state` entries with non-empty `last_seen_merkle_root`, `last_seen_sequence > 0`, and fresh `last_sync_at`.
- `entries_fetched >= 2` is ideal. If it is `0` but both DIDs are present, check nodeC log for routine/inbound gossip; rerun this block with nodeC `SGX_CRL_GOSSIP_ENABLED=0` from first startup.

**Node C (return to normal after Req 5):**
```bash
pkill -f sgx_guardian_client || true
cd /home/root
nohup env SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 SGX_CRL_GOSSIP_INTERVAL_SECS=10 ./sgx_guardian_client nodeC >/tmp/crl-offline-nodeC.log 2>&1 &
sleep 8
```

### 6) Req 6: deterministic conflict resolution + root convergence

Precondition: all three boards should start from the same Merkle root. If roots differ before the test, run the convergence loop first; otherwise old dirty CRL state can create a false failure.

**All nodes (root baseline):**
```bash
curl -s http://localhost:8443/api/v1/crl/root | python3 -m json.tool
```

**If baseline roots differ, run this on each node 5-10 times until roots match:**
```bash
API=http://localhost:8443/api/v1
for i in 1 2 3 4 5; do
  curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
  curl -s -X POST "$API/crl/gossip/trigger" | python3 -m json.tool
  sleep 4
done
curl -s "$API/crl/root" | python3 -m json.tool
```

**Node B (isolate from CRL sync, then issue first conflict):**
```bash
API=http://localhost:8443/api/v1
RUN_ID=$(date -u +%Y%m%d%H%M%S)
DID_CONFLICT="did:guardian:offline-board-conflict-$RUN_ID"
echo "$DID_CONFLICT" >/tmp/crl-offline-req6-did

iptables -I OUTPUT -p tcp --dport 50063 -j REJECT
iptables -I INPUT  -p tcp --sport 50063 -j REJECT
iptables -I OUTPUT -p udp --dport 50064 -j REJECT
iptables -I INPUT  -p udp --sport 50064 -j REJECT
curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool

curl -s -X POST "$API/crl/revoke" -H "Content-Type: application/json" \
  -d "{\"did\":\"$DID_CONFLICT\",\"reason\":\"compromised\",\"severity\":\"high\",\"note\":\"CRL-038 B first $RUN_ID\"}" | python3 -m json.tool
```

**Copy same DID to nodeC:**
```bash
scp /tmp/crl-offline-req6-did root@192.168.1.252:/tmp/crl-offline-req6-did
```

**Node C (isolate, wait a few seconds, issue second conflict):**
```bash
API=http://localhost:8443/api/v1
DID_CONFLICT=$(cat /tmp/crl-offline-req6-did)

iptables -I OUTPUT -p tcp --dport 50063 -j REJECT
iptables -I INPUT  -p tcp --sport 50063 -j REJECT
iptables -I OUTPUT -p udp --dport 50064 -j REJECT
iptables -I INPUT  -p udp --sport 50064 -j REJECT
curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
sleep 5

curl -s -X POST "$API/crl/revoke" -H "Content-Type: application/json" \
  -d "{\"did\":\"$DID_CONFLICT\",\"reason\":\"stolen\",\"severity\":\"high\",\"note\":\"CRL-038 C later $DID_CONFLICT\"}" | python3 -m json.tool
```

**Node B and Node C (unblock):**
```bash
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p tcp --sport 50063 -j REJECT 2>/dev/null || true
iptables -D OUTPUT -p udp --dport 50064 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p udp --sport 50064 -j REJECT 2>/dev/null || true
```

**All nodes (force convergence loop):**
```bash
API=http://localhost:8443/api/v1
for i in 1 2 3 4 5 6 7 8; do
  curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
  curl -s -X POST "$API/crl/gossip/trigger" | python3 -m json.tool
  sleep 4
done
```

**Node A before final conflict/root check (copy DID from nodeB if not already present):**
```bash
scp root@192.168.1.195:/tmp/crl-offline-req6-did /tmp/crl-offline-req6-did
```

**All nodes (final conflict/root check):**
```bash
DID_CONFLICT=$(cat /tmp/crl-offline-req6-did)
curl -s http://localhost:8443/api/v1/crl/root | python3 -m json.tool
python3 - "$DID_CONFLICT" <<'PY'
import json, sys
did = sys.argv[1]
d = json.load(open("/var/lib/sgx-guardian/identity/crl/crl.json"))
print({"sequence": d.get("sequence"), "merkle_root": d.get("merkle_root")})
hits = [
    {
        "id": e.get("id"),
        "reason": e.get("reason"),
        "timestamp": e.get("timestamp"),
        "revoker_did": e.get("revoker_did"),
        "propagated": e.get("propagated"),
    }
    for e in d.get("entries", [])
    if e.get("revoked_did") == did
]
print(hits)
assert len(hits) == 1
PY
```

**Expected PASS:**
- All three nodes report the same `merkle_root`.
- All three nodes show exactly one surviving conflict entry for `DID_CONFLICT`.
- With current code, the later nodeC entry should win (`reason: stolen`). If your final requirement says earliest timestamp must win, mark this as a requirement/code mismatch, not a board-command failure.

### 7) Req 7: retry budget, parking, restart persistence

This verifies parking in the path the current implementation actually counts as attempts: at least one peer reachable, but propagation threshold not satisfied.

**Node A:** keep daemon ON.

**Node B (OFF, but its DID document remains in nodeC peer directory):**
```bash
pkill -f sgx_guardian_client || true
```

**Node C (restart with max retries 2):**
```bash
pkill -f sgx_guardian_client || true
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p tcp --sport 50063 -j REJECT 2>/dev/null || true
cd /home/root
nohup env SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=6 SGX_CRL_OFFLINE_MAX_RETRIES=2 SGX_CRL_GOSSIP_INTERVAL_SECS=10 ./sgx_guardian_client nodeC >/tmp/crl-offline-nodeC-req7.log 2>&1 &
sleep 8
API=http://localhost:8443/api/v1
curl -s "$API/crl/gossip/status" | python3 -m json.tool
curl -s "$API/crl/offline/status" | python3 -m json.tool
```

`/crl/gossip/status` should show `other_members: 2` and `threshold_count: 2`. If it shows `threshold_count: 1`, bring nodeB up once to refresh peer DID documents, then stop nodeB again and rerun this block.

**Node C (issue pending and let it park):**
```bash
API=http://localhost:8443/api/v1
RUN_ID=$(date -u +%Y%m%d%H%M%S)
DID_PARK="did:guardian:offline-board-park-$RUN_ID"
echo "$DID_PARK" >/tmp/crl-offline-req7-did

curl -s -X POST "$API/crl/revoke" -H "Content-Type: application/json" \
  -d "{\"did\":\"$DID_PARK\",\"reason\":\"policy_violation\",\"severity\":\"high\",\"note\":\"CRL-039 park $RUN_ID\"}" | python3 -m json.tool

for i in 1 2 3; do
  curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
  sleep 3
done

curl -s "$API/crl/offline/pending" | python3 -m json.tool
python3 - "$DID_PARK" <<'PY'
import json, sys
did = sys.argv[1]
pending = json.load(open("/var/lib/sgx-guardian/identity/crl/pending/" + next(
    e["id"].replace(":", "_").replace("/", "_") + ".json"
    for e in json.load(open("/var/lib/sgx-guardian/identity/crl/crl.json")).get("entries", [])
    if e.get("revoked_did") == did
)))
print({"attempts": pending["attempts"], "parked": pending["parked"], "last_attempt_at": pending["last_attempt_at"]})
assert pending["attempts"] >= 2
assert pending["parked"] is True
PY
```

**Node C (restart persistence check):**
```bash
pkill -f sgx_guardian_client || true
sleep 3
cd /home/root
nohup env SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=6 SGX_CRL_OFFLINE_MAX_RETRIES=2 SGX_CRL_GOSSIP_INTERVAL_SECS=10 ./sgx_guardian_client nodeC >/tmp/crl-offline-nodeC-req7-restart.log 2>&1 &
sleep 8
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool
ls -la /var/lib/sgx-guardian/identity/crl/pending/
```

**Expected PASS:**
- Pending entry reaches `attempts >= 2`, `parked:true`, and is still present.
- After restart, pending file is still present and REST still lists it.
- If fully isolated status is `online:false`, attempts remaining `0` is current behavior; use this one-peer-reachable setup for parking acceptance.

### 8) Req 8: self-reconcile local CLI-issued revocation

This proves CLI path coverage by bypassing REST queueing. Keep nodeC isolated so the entry cannot propagate/dequeue before reconcile is inspected.

**Node C:**
```bash
API=http://localhost:8443/api/v1
RUN_ID=$(date -u +%Y%m%d%H%M%S)
DID_CLI="did:guardian:offline-board-cli-reconcile-$RUN_ID"
echo "$DID_CLI" >/tmp/crl-offline-req8-did

iptables -I OUTPUT -p tcp --dport 50063 -j REJECT
iptables -I INPUT  -p tcp --sport 50063 -j REJECT
curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
curl -s "$API/crl/offline/status" | python3 -m json.tool

/home/root/sgx-pa-cli crl revoke --did "$DID_CLI" --reason policy_violation --severity high --note "CRL-040 CLI reconcile $RUN_ID"

ID_CLI=$(python3 - "$DID_CLI" <<'PY'
import json, sys
did = sys.argv[1]
d = json.load(open("/var/lib/sgx-guardian/identity/crl/crl.json"))
for e in d.get("entries", []):
    if e.get("revoked_did") == did:
        print(e.get("id", ""))
        break
PY
)
test -n "$ID_CLI" || { echo "CLI revoke did not create CRL entry"; exit 1; }

PENDING_FILE="/var/lib/sgx-guardian/identity/crl/pending/$(python3 - "$ID_CLI" <<'PY'
import sys
print(sys.argv[1].replace(":", "_").replace("/", "_") + ".json")
PY
)"
[ -f "$PENDING_FILE" ] && mv "$PENDING_FILE" "/tmp/reconcile-$RUN_ID.json.bak"

curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool
curl -s "$API/crl/offline/pending" | python3 -m json.tool
python3 - "$DID_CLI" <<'PY'
import json, sys
did = sys.argv[1]
p = json.load(open("/var/lib/sgx-guardian/identity/crl/pending/" + next(
    e["id"].replace(":", "_").replace("/", "_") + ".json"
    for e in json.load(open("/var/lib/sgx-guardian/identity/crl/crl.json")).get("entries", [])
    if e.get("revoked_did") == did
)))
print({"id": p["entry"]["id"], "revoked_did": p["entry"]["revoked_did"], "attempts": p["attempts"], "parked": p["parked"]})
assert p["entry"]["revoked_did"] == did
PY
```

**Expected PASS:**
- CLI command creates a local CRL entry for `DID_CLI`.
- After moving any existing pending file aside, `POST /crl/offline/sync` recreates it from local `crl.json`.
- Pending list includes `DID_CLI`; this proves self-reconcile covers CLI-issued revocations.

**Node C (cleanup after isolation tests):**
```bash
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p tcp --sport 50063 -j REJECT 2>/dev/null || true
iptables -D OUTPUT -p udp --dport 50064 -j REJECT 2>/dev/null || true
iptables -D INPUT  -p udp --sport 50064 -j REJECT 2>/dev/null || true
```

### 9) API final verification (run on nodeC, repeat on nodeA if required)

**Node C:**
```bash
API=http://localhost:8443/api/v1

curl -s "$API/crl/offline/status" | python3 -m json.tool
curl -s "$API/crl/offline/pending" | python3 -m json.tool
curl -s -X POST "$API/crl/offline/sync" | python3 -m json.tool

python3 - <<'PY'
import json, urllib.request
base = "http://localhost:8443/api/v1"
status = json.load(urllib.request.urlopen(base + "/crl/offline/status"))
pending = json.load(urllib.request.urlopen(base + "/crl/offline/pending"))
for key in ["enabled", "online", "sync_interval_secs", "flush_rounds", "max_retries", "pending", "sync_cycles", "reconnects", "entries_delivered", "entries_fetched", "peer_sync_state"]:
    assert key in status, key
assert pending.get("status") == "success"
assert "count" in pending and "pending" in pending
print("offline API shape OK")
PY
```

**Expected PASS:**
- API 1 (`status`) has config, counters, pending count, and `peer_sync_state`.
- API 2 (`pending`) has `status`, `count`, and per-entry retry metadata.
- API 3 (`sync`) returns `online`, `reachable_peers`, `reconciled`, `fetched`, `delivered`, `pending_remaining`.

## ⚡ Fast Grouped Run Order

### Block 1 — Req 1 + Req 2 + API 1 + API 2

**Goal:** keep nodeA ON and prove local queueing + retry metadata + offline REST observability on nodeC:
- the pending queue persists
- attempts / timestamps update
- both `/crl/offline/status` and `/crl/offline/pending` return the expected shape

**Node A (192.168.1.157):**
```bash
# nodeA should remain ON; foreground execution in this terminal worked best
cd /home/root
./sgx_guardian_client nodeA
```

**Node B (192.168.1.195):**
```bash
pkill -f sgx_guardian_client || true
pgrep -af sgx_guardian_client || true
```

**Node C (192.168.1.196):**
```bash
pkill -f sgx_guardian_client || true
cd /home/root
export SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8
./sgx_guardian_client nodeC
```

**Node C (second terminal after `CRL-OFFLINE sync starting` and `REST admin API listening` appear):**
```bash
CRL_BASE=/var/lib/sgx-guardian/identity/crl
PENDING_DIR=$CRL_BASE/pending
DID_033="did:guardian:offline-test-001-20260722-rest-01"

curl -s -X POST http://localhost:8443/api/v1/crl/revoke \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$DID_033\",\"reason\":\"compromised\",\"severity\":\"high\",\"note\":\"CRL-033 via REST\"}" | python3 -m json.tool

echo "===== PENDING ====="
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool

echo "===== STATUS ====="
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool

echo "===== LOCAL CRL ENTRY ====="
python3 - <<'PY'
import json
did="did:guardian:offline-test-001-20260722-rest-01"
p="/var/lib/sgx-guardian/identity/crl/crl.json"
d=json.load(open(p))
print([{"id":e.get("id"),"revoked_did":e.get("revoked_did"),"propagated":e.get("propagated")} for e in d.get("entries",[]) if e.get("revoked_did")==did])
PY

echo "===== PENDING FILES ====="
ls -la "$PENDING_DIR"/
```

**Expected summary for Block 1:**
```text
Req 1 PASS:
- pending/*.json file present
- crl.json contains did:guardian:offline-test-001-20260722-rest-01 with propagated:false

Req 2 PASS:
- existing pending entries have attempts >= 1
- queued_at remains fixed
- last_attempt_at is populated; the daemon log shows the attempt counter increasing on later cycles

API 1 PASS:
- GET /api/v1/crl/offline/status returns enabled/online/pending/sync counters

API 2 PASS:
- GET /api/v1/crl/offline/pending returns count + pending[] with attempts/timestamps/parked
```

> **Note:** this block is intentionally not the full-isolation proof; follow the corrected nodeA/nodeC boot sequence separately for Requirement 3.

---

## ✅ Requirement 1 — [x] Locally queue outgoing revocations (pending queue persists)

> When any revocation is issued, it persists in the local `pending/` queue with retry and timestamp metadata, and it is also written immediately to `crl.json`.

**Commands (nodeC):**
```bash
/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-001 --reason compromised --severity high --note "CRL-033 queue"
ls -la $PENDING_DIR/
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool
python3 - <<'PY'
import json
d=json.load(open("/var/lib/sgx-guardian/identity/crl/crl.json"))
print([{"id":e.get("id"),"propagated":e.get("propagated")} for e in d.get("entries", []) if e.get("revoked_did")=="did:guardian:offline-test-001"])
PY
```

**Expected:**
```
pending/urn_uuid_UUID.json file present
/crl/offline/pending → count ≥ 1, entry shows attempts, queued_at, parked:false
crl.json has the entry with propagated:false (not yet delivered)
```

**Result:**
```
Attempt 1 on nodeC (`2026-07-22`):

root@imx8mp-var-dart:~# /home/root/sgx-pa-cli crl revoke --did "$DID_033" --reason compromised --severity high --note "CRL-033 queue"
  ⚠️ SE050 not reachable this boot — keeping existing DKP (v1) from metadata (no regeneration)
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
❌ did: DID derivation signature failed: DKP sign: SE050 sign failed: ssscli failed: ssscli sign 0x20000010 /tmp/guardian_se_sign_72d80bc4_in.bin /tmp/guardian_se_sign_72d80bc4_out.bin — ERROR:sss.session:No open session, try connecting first
ERROR:sss.session:Run 'ssscli connect --help' for more information.
ERROR:cli.cli:No open session, try connecting first
ERROR:cli.cli:'Context' object has no attribute 'session'

Post-checks from the same attempt:
- `ls -la /var/lib/sgx-guardian/identity/crl/pending/` → `No such file or directory`
- `GET /api/v1/crl/offline/pending` → empty / non-JSON response (`python3 -m json.tool` failed at column 1)
- `jq` not installed on the board (`jq: command not found`)
- `GET /api/v1/crl/offline/status` → empty / non-JSON response (`python3 -m json.tool` failed at column 1)
```

**Verdict:** ⏳ Blocked / retry required — this attempt did not prove Requirement 1 because the local revoke never succeeded. The first blocker is board-side SE050 signing/session failure (`No open session`), so no CRL entry was created and no pending queue file could exist in this run. The REST checks are also not usable from this attempt because `/crl/offline/*` returned empty output and `jq` is not available on the board.

**Recovery / environment evidence after the blocked attempt:**
```text
NodeC manual SE050 recovery probe (`2026-07-22`):
- `ssscli se05x uid` succeeded
- `ssscli se05x readidlist | grep -i 20000010` showed DKP key slot present
- `ssscli sign 0x20000010 /tmp/offline_req1_probe.bin /tmp/offline_req1_probe.sig` succeeded
- `/tmp/offline_req1_probe.sig` was created successfully

NodeC daemon rerun in foreground:
- `✅ SE050 tamper check: OK`
- `✅ DID active: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB`
- `🗣️ CRL-GOSSIP engine starting port=50063 interval_secs=60 threshold_pct=80`
- `🚨 CRL-EMERGENCY channel enabled port=50064 ttl=1`
- `CRL-OFFLINE sync starting interval_secs=20 flush_rounds=3 max_retries=unlimited`
- `✅ REST admin API listening on http://0.0.0.0:8443/api/v1`
- `CRL-OFFLINE connectivity restored: 2 peer(s) reachable`
```

**Recovery verdict:** ✅ NodeC environment recovered enough for a clean Requirement 1 retry. The original blocker was board/runtime state, not a confirmed offline-sync code defect.

**Retry attempt 2 on nodeC (`2026-07-22`):**
```text
/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-001-20260722-02 --reason compromised --severity high --note "CRL-033 queue retry"
  No existing DKP found — generating new DKP inside SE050...
✅ CRL entry issued: urn:uuid:520e3c28-9aaa-4d5d-9af0-d06722f5a574 (sequence=1, root=e0dc86ae424fe2c2bb557388845b5d71b138fddf51872af8215b289419b4428c)

Immediate post-issue checks:
- `pending/` listing was empty
- `GET /api/v1/crl/offline/pending` still returned empty / non-JSON output
- local `crl.json` DID lookup succeeded and showed:
  `{'id': 'urn:uuid:520e3c28-9aaa-4d5d-9af0-d06722f5a574', 'revoked_did': 'did:guardian:offline-test-001-20260722-02', 'propagated': False}`
- `GET /api/v1/crl/offline/status` still returned empty / non-JSON output

Interpretation:
- Local CRL issuance now works
- This retry checked the queue immediately after CLI issuance, before proving the next offline-sync reconcile cycle / REST readiness
- For CLI-issued revocations, the plan relies on self-reconcile each cycle, so a short wait or forced `/crl/offline/sync` cycle is still required to prove pending-queue persistence
```

**Retry verdict:** ⏳ Partial / retry required — Requirement 1 is closer to proven now because the local CRL entry was successfully created and remained `propagated:false`, but the queue was checked too early for the CLI self-reconcile path and the REST API was not returning usable JSON at the moment of inspection. Re-run once the daemon is fully healthy, then wait one sync cycle (or trigger `POST /crl/offline/sync`) before checking `pending/`.

**Retry attempt 3 on nodeC (`2026-07-22`):**
```text
Daemon startup pattern during automated retry:
- `./sgx_guardian_client nodeC > /tmp/crl-offline-nodeC.log 2>&1 &`
- background job exited before `/health` became reachable (`[1]+ Done ...`)
- `curl http://localhost:8443/health` returned empty

Revoke attempt on the same retry:
/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-001-20260722-03 --reason compromised --severity high --note "CRL-033 queue final"
❌ failed again before local issuance:
  `ERROR:sss.session:No open session, try connecting first`

Post-checks:
- `POST /api/v1/crl/offline/sync` → empty / non-JSON output
- `GET /api/v1/crl/offline/pending` → empty / non-JSON output
- local `crl.json` lookup for `did:guardian:offline-test-001-20260722-03` returned `[]`
- audit log still shows historical offline-sync start / connectivity events, but this retry did not create a fresh queued entry
```

**Retry verdict:** ⏳ Still blocked — Requirement 1 remains unproven. This retry did not create a CRL entry or pending queue item because the NodeC daemon exited before REST became healthy and the CLI revoke again failed with an SE050 session error. At this point the blocker is board runtime stability / SE050 session state, not a confirmed offline-sync logic defect.

**Retry attempt 4 on nodeC (`2026-07-22`):**
```text
Manual two-terminal retry:
- `/home/root/sgx-pa-cli crl revoke --did "$DID_033" --reason compromised --severity high --note "CRL-033 manual"`
- Result:
  `✅ CRL entry issued: urn:uuid:a980f383-eb5c-46e7-b9d0-97f6026b0159 (sequence=2, root=3fb246791f70205fa573c144fd1b585d952889db0e36216cd5c51dde83d608fe)`

Local CRL proof:
- Python lookup in `/var/lib/sgx-guardian/identity/crl/crl.json` returned:
  `{'id': 'urn:uuid:a980f383-eb5c-46e7-b9d0-97f6026b0159', 'revoked_did': 'did:guardian:offline-test-001-20260722-manual-01', 'propagated': False}`

But offline-sync proof still missing at the same moment:
- `POST /api/v1/crl/offline/sync` → empty / non-JSON response
- `GET /api/v1/crl/offline/pending` → empty / non-JSON response
- `GET /api/v1/crl/offline/status` → empty / non-JSON response
- `ls -la /var/lib/sgx-guardian/identity/crl/pending` → `No such file or directory`
```

**Retry verdict:** ⏳ Partial / retry required — this run proves the board can now issue the local CRL entry and keep it at `propagated:false`, but Requirement 1 itself is still not fully proven because the offline queue directory and offline REST endpoints were not reachable/observable during the same run.

**Successful attempt 5 on nodeC with nodeA kept ON (`2026-07-22`):**
```text
Working topology correction:
- nodeA kept ON in foreground as CA / registry-sync / lighthouse
- nodeB kept OFF
- nodeC started cleanly, reached:
  `CRL-OFFLINE sync starting interval_secs=8 flush_rounds=3 max_retries=unlimited`
  `✅ REST admin API listening on http://0.0.0.0:8443/api/v1`

REST revoke on nodeC:
curl -s -X POST http://localhost:8443/api/v1/crl/revoke ...
→ success JSON:
  `status: success`
  `message: CRL entry issued`
  `entry.id: urn:uuid:b0fac4d2-a544-47ab-8574-3bc40af610b2`
  `entry.revoked_did: did:guardian:offline-test-001-20260722-rest-01`
  `entry.propagated: false`

Queue persistence proof from the same run:
- `GET /api/v1/crl/offline/pending` returned `status: success`, `count: 3`
- pending list included:
  `urn:uuid:b0fac4d2-a544-47ab-8574-3bc40af610b2` for `did:guardian:offline-test-001-20260722-rest-01`
  with `attempts: 0`, `queued_at: 2026-07-22T07:47:08.617006612+00:00`, `parked: false`
- local Python lookup in `crl.json` returned:
  `{'id': 'urn:uuid:b0fac4d2-a544-47ab-8574-3bc40af610b2', 'revoked_did': 'did:guardian:offline-test-001-20260722-rest-01', 'propagated': False}`
- `ls -la /var/lib/sgx-guardian/identity/crl/pending` showed:
  `urn_uuid_b0fac4d2-a544-47ab-8574-3bc40af610b2.json`
```

**Updated-IP quiet-mode rerun on nodeC (`2026-07-29`, nodeC `192.168.1.252`):**
```text
Pre-check:
- `GET /api/v1/crl/offline/status` returned HTTP 200 JSON:
  - `"enabled": true`
  - `"online": false`
  - `"sync_interval_secs": 600`
  - `"pending": 0`

REST revoke on nodeC:
- `POST /api/v1/crl/revoke` for `did:guardian:offline-req1-20260729064340`
  returned success:
  - `"status": "success"`
  - `"message": "CRL entry issued"`
  - `entry.id: urn:uuid:d6c7f49e-7151-4fbc-bd6e-a2ca993d5813`
  - `entry.revoked_did: did:guardian:offline-req1-20260729064340`
  - `entry.propagated: false`
  - `sequence: 1`
  - `merkle_root: 1b6d61f5ca61d4dfcb6b08f7f867d6f185e07c84ed6823bc85a18b4c41d72524`

Queue persistence proof from same run:
- `GET /api/v1/crl/offline/pending` returned:
  - `"status": "success"`
  - `"count": 1`
  - pending id `urn:uuid:d6c7f49e-7151-4fbc-bd6e-a2ca993d5813`
  - `attempts: 0`
  - `queued_at: 2026-07-29T06:43:54.323309762+00:00`
  - `last_attempt_at: null`
  - `last_error: null`
  - `parked: false`
- `ls -la /var/lib/sgx-guardian/identity/crl/pending/` showed:
  - `urn_uuid_d6c7f49e-7151-4fbc-bd6e-a2ca993d5813.json`
- local Python CRL proof returned:
  - `{'id': 'urn:uuid:d6c7f49e-7151-4fbc-bd6e-a2ca993d5813', 'revoked_did': 'did:guardian:offline-req1-20260729064340', 'propagated': False}`
```

**Verdict:** ✅ PASS — Requirement 1 is proven on-board with the updated NodeC IP. The local REST revoke created the signed CRL entry, persisted the same entry into the offline `pending/` queue, exposed it through `/api/v1/crl/offline/pending`, and kept the canonical local CRL entry at `propagated:false`.

---

## ✅ Requirement 2 — [x] Track pending revocations with retry counter and timestamps

> Each pending entry tracks its own `attempts` counter and `queued_at` / `last_attempt_at` timestamps; each sync cycle increments the attempt count until the entry is delivered.

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
```text
NodeC `GET /api/v1/crl/offline/pending` (`2026-07-22`) returned live retry metadata:
- `urn:uuid:520e3c28-9aaa-4d5d-9af0-d06722f5a574`
  `attempts: 1`
  `queued_at: 2026-07-22T07:46:46.468350175+00:00`
  `last_attempt_at: 2026-07-22T07:46:56.916169043+00:00`
  `last_error: null`
- `urn:uuid:a980f383-eb5c-46e7-b9d0-97f6026b0159`
  `attempts: 1`
  `queued_at: 2026-07-22T07:46:46.468869313+00:00`
  `last_attempt_at: 2026-07-22T07:46:56.916837059+00:00`
  `last_error: null`
- fresh REST-issued entry `urn:uuid:b0fac4d2-a544-47ab-8574-3bc40af610b2`
  initially showed `attempts: 0`, `last_attempt_at: null`

Then nodeC foreground daemon log showed cycle-by-cycle bumping:
- `CRL-OFFLINE flush attempt id=urn:uuid:b0fac4d2-a544-47ab-8574-3bc40af610b2 attempt=1`
- `... attempt=2`
- `... attempt=3`
- `... attempt=4`
- `... attempt=5`
- `... attempt=6`

This proves:
- `queued_at` stays fixed
- `attempts` increments across sync cycles
- `last_attempt_at` becomes populated once retry loop touches the entry
```

**Verdict:** ✅ PASS — retry counter and timestamp bookkeeping are observable both via REST and live daemon logs.

**Updated-IP quiet-mode rerun on nodeC (`2026-07-29`, nodeC `192.168.1.252`):**
```text
Before forced sync:
- `GET /api/v1/crl/offline/pending` returned `count: 1`
- pending id `urn:uuid:d6c7f49e-7151-4fbc-bd6e-a2ca993d5813`
- `revoked_did: did:guardian:offline-req1-20260729064340`
- `attempts: 0`
- `queued_at: 2026-07-29T06:43:54.323309762+00:00`
- `last_attempt_at: null`
- `last_error: null`
- `parked: false`

Forced sync cycles:
- `POST /api/v1/crl/offline/sync` #1 returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"pending_remaining": 1`
- `POST /api/v1/crl/offline/sync` #2 returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"pending_remaining": 1`

After forced sync:
- `GET /api/v1/crl/offline/pending` still returned `count: 1`
- same pending id `urn:uuid:d6c7f49e-7151-4fbc-bd6e-a2ca993d5813`
- `attempts: 2`
- `queued_at: 2026-07-29T06:43:54.323309762+00:00` (unchanged)
- `last_attempt_at: 2026-07-29T06:47:49.997786798+00:00`
- `last_error: null`
- `parked: false`
```

**Updated-IP verdict:** ✅ PASS — Requirement 2 is proven on-board with the updated NodeC IP. The pending entry's retry counter advanced from `0` to `2`, `last_attempt_at` was populated, `queued_at` remained stable, and the entry stayed unparked.

---

## ✅ Requirement 3 — [x] Queue works when offline; nothing lost while isolated

> When no peer is reachable (offline), the sync cycle is a no-op and the queue persists; no revocation is lost. Even while isolated, a Guardian can still revoke a compromised peer.

**Commands:**
```bash
# Keep nodeA ON (CA / lighthouse / relay role). nodeB can remain stopped.
# On nodeC, block only the CRL sync channels so the overlay/CA stays alive while offline-sync is isolated.
iptables -I OUTPUT -p tcp --dport 50063 -j REJECT
iptables -I INPUT  -p tcp --sport 50063 -j REJECT
iptables -I OUTPUT -p udp --dport 50064 -j REJECT
iptables -I INPUT  -p udp --sport 50064 -j REJECT
sleep 12   # nodeC next cycle -> offline detected

# On nodeC (isolated): revoke + status
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool
curl -s -X POST http://localhost:8443/api/v1/crl/revoke -H "Content-Type: application/json" -d '{"did":"did:guardian:offline-test-002-20260722","reason":"stolen","severity":"critical","note":"CRL-035 isolated"}' | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool
ls -la $PENDING_DIR/
```

**Expected:**
```
status: "online": false, "pending" ≥ 1 (entry retained while isolated)
revoke succeeds locally even with zero reachable peers (crl.json updated)
audit shows offline cycle no-op; nothing dropped
```

**Result:**
```
Attempt 1 on nodeC (`2026-07-22`) after trying to isolate nodeC:

Pre-issue offline status:
- `GET /api/v1/crl/offline/status` returned:
  - `"online": true`
  - `"pending": 3`
  - `"sync_cycles": 51`
  - `"reconnects": 2`
  - peer sync state for `did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE` showed:
    - `last_seen_merkle_root: 088b6891f5b5b6961c720e311c437d34a3a7d4fd22f08c6271c99123ae39db79`
    - `last_seen_sequence: 4`
    - `last_sync_at: 2026-07-22T07:57:27.616170838+00:00`

Local revoke during the same run:
- `POST /api/v1/crl/revoke` for `did:guardian:offline-test-002-20260722`
  returned success:
  - `entry.id: urn:uuid:04e3df35-55bb-4b70-bd73-8aae6b3220c9`
  - `severity: critical`
  - `propagated: false`
  - `sequence: 5`
  - `merkle_root: 6938f6a698bef1d09adaeeeb4d7f802675c0bd39ba24b580f2a313612905dee3`

Pending queue proof:
- `GET /api/v1/crl/offline/pending` returned `count: 4`
- new entry present with:
  - `id: urn:uuid:04e3df35-55bb-4b70-bd73-8aae6b3220c9`
  - `revoked_did: did:guardian:offline-test-002-20260722`
  - `attempts: 0`
  - `last_attempt_at: null`
  - `parked: false`
  - `queued_at: 2026-07-22T07:57:55.889715722+00:00`

Local CRL proof:
- Python lookup in `crl.json` returned:
  `{'id': 'urn:uuid:04e3df35-55bb-4b70-bd73-8aae6b3220c9', 'revoked_did': 'did:guardian:offline-test-002-20260722', 'propagated': False}`

Attempt 2 on nodeC with CRL ports blocked (`2026-07-22`):

Isolation proof succeeded:
- after blocking TCP `50063` and UDP `50064`, `GET /api/v1/crl/offline/status` returned:
  - `"online": false`
  - `"pending": 4`
  - `"sync_cycles": 2`
  - `"reconnects": 1`
  - peer sync state still retained last-seen metadata, but the offline-sync reachability state was now correctly offline

Fresh isolated revoke did NOT succeed in this run:
- `POST /api/v1/crl/revoke` for `did:guardian:offline-test-003-20260722` returned:
  - `BAD_REQUEST`
  - `DID derivation signature failed`
  - `ERROR:sss.session: No open session, try connecting first`

Queue persistence while isolated still held:
- `GET /api/v1/crl/offline/pending` continued returning `count: 4`
- prior queued entries remained present with growing `attempts` counters:
  - `urn:uuid:520e3c28-9aaa-4d5d-9af0-d06722f5a574` → `attempts: 95`
  - `urn:uuid:a980f383-eb5c-46e7-b9d0-97f6026b0159` → `attempts: 95`
  - `urn:uuid:b0fac4d2-a544-47ab-8574-3bc40af610b2` → `attempts: 94`
  - `urn:uuid:04e3df35-55bb-4b70-bd73-8aae6b3220c9` → `attempts: 46`
- local lookup for `did:guardian:offline-test-003-20260722` returned `[]`, confirming no new CRL entry was created in this failed isolated issue attempt

Foreground nodeC log after restart showed the board-side cause:
- `CRL-OFFLINE connectivity restored: 1 peer(s) reachable`
- later `CRL-OFFLINE connectivity lost: no reachable gossip peers`
- repeated `🔴 SE050 TAMPER DETECTED — all crypto operations blocked`

Attempt 3 on nodeC with fresh DID `did:guardian:offline-test-004-20260722-r4` (`2026-07-22`):

Fresh local revoke + queue persistence succeeded cleanly:
- `POST /api/v1/crl/revoke` returned success for:
  - `id: urn:uuid:79d86d71-7884-4bf6-8a23-10ff3ed5e48e`
  - `revoked_did: did:guardian:offline-test-004-20260722-r4`
  - `severity: critical`
  - `propagated: false`
  - `sequence: 7`
  - `merkle_root: 282f1bedfe02a14397aa77ea526f97fc47be7947120fb29b31c48bb3fd62bf15`
- `GET /api/v1/crl/offline/pending` immediately returned `count: 5`
- new entry appeared with:
  - `attempts: 0`
  - `last_attempt_at: null`
  - `parked: false`
  - `queued_at: 2026-07-22T09:27:12.201018272+00:00`

But isolation signal was not clean in this exact run:
- after inserting the CRL port blocks and waiting 12s, `GET /api/v1/crl/offline/status` still reported `"online": true`
- so this run alone cannot prove the "fresh revoke while isolated" sub-claim, even though it does prove fresh local queueing of the new DID
```

**Updated-IP quiet-mode rerun on nodeC (`2026-07-29`, nodeC `192.168.1.252`):**
```text
Offline isolation proof before fresh revoke:
- CRL sync ports were blocked on nodeC:
  - TCP 50063
  - UDP 50064
- forced `POST /api/v1/crl/offline/sync` returned:
  - `"online": false`
  - `"reachable_peers": 0`
  - `"pending_remaining": 1`
- `GET /api/v1/crl/offline/status` returned:
  - `"online": false`
  - `"pending": 1`

Fresh isolated revoke:
- `POST /api/v1/crl/revoke` for `did:guardian:offline-req3-isolated-20260729064955`
  returned success:
  - `"status": "success"`
  - `"message": "CRL entry issued"`
  - `entry.id: urn:uuid:c9295830-6c37-40ef-905f-db2464fb9f41`
  - `entry.reason: stolen`
  - `entry.severity: critical`
  - `entry.propagated: false`
  - `sequence: 3`
  - `merkle_root: f28224a5c07866d5f359196615b9502ce51131c614b2140e1cd9529c8389d545`

Queue persistence while isolated:
- `GET /api/v1/crl/offline/status` after revoke returned:
  - `"online": false`
  - `"pending": 2`
- `GET /api/v1/crl/offline/pending` returned `count: 2`, including the fresh isolated entry:
  - `id: urn:uuid:c9295830-6c37-40ef-905f-db2464fb9f41`
  - `revoked_did: did:guardian:offline-req3-isolated-20260729064955`
  - `attempts: 0`
  - `queued_at: 2026-07-29T06:50:09.328827690+00:00`
  - `last_attempt_at: null`
  - `last_error: null`
  - `parked: false`
- `ls -la /var/lib/sgx-guardian/identity/crl/pending/` showed:
  - `urn_uuid_c9295830-6c37-40ef-905f-db2464fb9f41.json`
  - existing prior Req1 pending file also remained present
- local Python CRL proof returned:
  - `{'id': 'urn:uuid:c9295830-6c37-40ef-905f-db2464fb9f41', 'revoked_did': 'did:guardian:offline-req3-isolated-20260729064955', 'propagated': False, 'peers_notified': []}`
```

**Verdict:** ✅ PASS — Requirement 3 is now fully proven on-board with the updated NodeC IP. NodeC was offline from the offline-sync perspective (`online:false`, `reachable_peers:0`), still issued a fresh local critical revocation, persisted it in the offline pending queue, retained the existing pending entry, and did not lose any revocation while isolated.

---

## ✅ Requirement 4 — [x] On connectivity restored, synchronously push queued revocations to peers

> When connectivity returns (offline -> online transition), the sync loop detects the reconnect and pushes queued revocations to peers through gossip exchange, then dequeues entries after delivery is confirmed.

**Commands (continue from Requirement 3):**
```bash
# Remove nodeC blocks = connectivity restore for offline-sync
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT
iptables -D INPUT  -p tcp --sport 50063 -j REJECT
iptables -D OUTPUT -p udp --dport 50064 -j REJECT
iptables -D INPUT  -p udp --sport 50064 -j REJECT
sleep 12

# deterministic cycle chalao + status check
curl -s -X POST http://localhost:8443/api/v1/crl/offline/sync | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool

# audit + peer verification
grep -aiE 'connectivity restored|flush attempt|cycle complete' /var/log/sgx-guardian/audit-nodeC.log | tail -20
ssh root@192.168.1.157 "/home/root/sgx-pa-cli crl check --did did:guardian:offline-test-002-20260722"
```

**Expected:**
```
`POST /crl/offline/sync` returns deterministic cycle summary
audit/status show connectivity restored / sync activity
pending drops toward 0; `entries_delivered` increases once delivery confirms
nodeA check shows `did:guardian:offline-test-002-20260722` revoked
```

**Result:**
```
Restore attempt on nodeC (`2026-07-22`) after removing CRL port blocks:

Deterministic sync endpoint responded successfully:
```json
{
    "online": true,
    "reachable_peers": 1,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 4
}
```

Post-restore status on nodeC:
```json
{
    "enabled": true,
    "online": true,
    "sync_interval_secs": 8,
    "flush_rounds": 3,
    "max_retries": 0,
    "pending": 4,
    "sync_cycles": 501,
    "reconnects": 2,
    "entries_delivered": 0,
    "entries_fetched": 0,
    "peer_sync_state": {
        "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa": {
            "last_seen_merkle_root": "",
            "last_seen_sequence": 0,
            "last_sync_at": "2026-07-22T07:02:30.396976754+00:00"
        },
        "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE": {
            "last_seen_merkle_root": "6938f6a698bef1d09adaeeeb4d7f802675c0bd39ba24b580f2a313612905dee3",
            "last_seen_sequence": 6,
            "last_sync_at": "2026-07-22T09:19:12.143625600+00:00"
        }
    }
}
```

Pending queue after restore remained non-empty:
- `count: 4`
- all four entries still present
- retry counters continued increasing:
  - `urn:uuid:520e3c28-9aaa-4d5d-9af0-d06722f5a574` → `attempts: 99`
  - `urn:uuid:a980f383-eb5c-46e7-b9d0-97f6026b0159` → `attempts: 99`
  - `urn:uuid:b0fac4d2-a544-47ab-8574-3bc40af610b2` → `attempts: 98`
  - `urn:uuid:04e3df35-55bb-4b70-bd73-8aae6b3220c9` → `attempts: 50`

Peer-side check on nodeA:
- `/home/root/sgx-pa-cli crl check --did did:guardian:offline-test-002-20260722`
  returned:
  - `"revoked": true`
  - entry id `urn:uuid:04e3df35-55bb-4b70-bd73-8aae6b3220c9`
  - `propagated: false`

Fresh restore-proof run with DID `did:guardian:offline-test-004-20260722-r4` (`2026-07-22`):
- while the new entry was first queued on nodeC, it appeared in `/crl/offline/pending` as:
  - `id: urn:uuid:79d86d71-7884-4bf6-8a23-10ff3ed5e48e`
  - `attempts: 0`
  - `queued_at: 2026-07-22T09:27:12.201018272+00:00`
- after removing the CRL port blocks and forcing `POST /api/v1/crl/offline/sync`, nodeC returned:
```json
{
    "online": true,
    "reachable_peers": 1,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 5
}
```
- `GET /api/v1/crl/offline/status` then showed:
  - `"online": true`
  - `"pending": 5`
  - `"sync_cycles": 5`
  - `"reconnects": 2`
  - `"entries_delivered": 0`
  - `"entries_fetched": 0`
  - peer sync state advanced to:
    - `last_seen_merkle_root: 282f1bedfe02a14397aa77ea526f97fc47be7947120fb29b31c48bb3fd62bf15`
    - `last_seen_sequence: 8`
    - `last_sync_at: 2026-07-22T09:27:29.815545846+00:00`
- `GET /api/v1/crl/offline/pending` after restore still contained the same entry, now with:
  - `attempts: 2`
  - `last_attempt_at: 2026-07-22T09:27:29.820047331+00:00`
  - `parked: false`
- nodeA check for the same fresh DID returned:
  - `"revoked": true`
  - exact same `id: urn:uuid:79d86d71-7884-4bf6-8a23-10ff3ed5e48e`
  - note `CRL-036 restore proof`
  - `propagated: false`
```

**Verdict:** ⏳ Partial / retry required — this fresh-DID run is much stronger evidence that restore-triggered pushing is happening: the same new entry id `urn:uuid:79d86d71-7884-4bf6-8a23-10ff3ed5e48e` appeared on nodeA after the restore sequence, and nodeC's attempt counter for that entry advanced from `0` to `2`. Even so, Requirement 4 is still not fully complete because queue delivery confirmation did not happen: `pending_remaining` stayed `5`, `entries_delivered` stayed `0`, and the entry was not dequeued / marked propagated.

Current full-mesh runtime evidence after bringing nodeB back (`2026-07-22`):
- nodeC startup showed:
  - `Loaded Node B: nodeB ... at 192.168.4.3:50052`
  - `CRL-OFFLINE connectivity restored: 2 peer(s) reachable`
- nodeB startup showed:
  - `CRL-OFFLINE connectivity restored: 2 peer(s) reachable`
  - `CRL-GOSSIP merged revocation revoked_did=did:guardian:offline-test-004-20260722-r4 severity=critical via_peer=did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB`
  - `CRL-GOSSIP entry propagated id=urn:uuid:79d86d71-7884-4bf6-8a23-10ff3ed5e48e threshold=2`
  - `CRL-OFFLINE cycle complete peers=2 reconciled=0 fetched=0 delivered=0 pending=0`
- nodeA startup showed:
  - `CRL-OFFLINE connectivity restored: 2 peer(s) reachable`
  - `CRL-GOSSIP entry propagated id=urn:uuid:79d86d71-7884-4bf6-8a23-10ff3ed5e48e threshold=2`
  - `CRL-OFFLINE cycle complete peers=2 reconciled=0 fetched=0 delivered=0 pending=0`

Interpretation:
- the fresh restore-proof DID definitely reached nodeB from nodeC
- the entry crossed the propagation threshold once the third node rejoined

Final close-check on nodeC (`2026-07-22`):
- `GET /api/v1/crl/offline/status` returned:
  - `"online": true`
  - `"pending": 0`
  - `"sync_cycles": 36`
  - `"reconnects": 1`
  - `"entries_delivered": 5`
  - `"entries_fetched": 0`
  - both peer sync states at:
    - `last_seen_merkle_root: 282f1bedfe02a14397aa77ea526f97fc47be7947120fb29b31c48bb3fd62bf15`
    - `last_seen_sequence: 9`
- `GET /api/v1/crl/offline/pending` returned:
  - `count: 0`
  - `pending: []`
- local CRL lookup for `did:guardian:offline-test-004-20260722-r4` returned:
  - `id: urn:uuid:79d86d71-7884-4bf6-8a23-10ff3ed5e48e`
  - `propagated: True`
  - `peers_notified: ['did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE', 'did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa']`

**Verdict:** ✅ PASS — Requirement 4 is now fully proven on-board. After full mesh was restored, the queue drained to zero, `entries_delivered` advanced to `5`, and the fresh restore-proof entry `urn:uuid:79d86d71-7884-4bf6-8a23-10ff3ed5e48e` became `propagated:true` with both peers recorded in `peers_notified`.

**Updated-IP reconnect rerun on nodeC (`2026-07-29`, nodeC `192.168.1.252`):**
```text
Reconnect setup:
- nodeC CRL sync blocks were removed:
  - TCP 50063
  - UDP 50064
- nodeA and nodeB were reachable as gossip peers.

Forced reconnect sync rounds:
- round 1 returned:
  - `"online": true`
  - `"reachable_peers": 2`
  - `"delivered": 2`
  - `"pending_remaining": 0`
- rounds 2-7 remained steady-state:
  - `"online": true`
  - `"pending_remaining": 0`
- round 8 returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"pending_remaining": 0`
  - this happened after delivery had already completed, so it does not affect the pass result.

Final status:
- `GET /api/v1/crl/offline/status` returned:
  - `"online": true`
  - `"pending": 0`
  - `"sync_cycles": 13`
  - `"reconnects": 2`
  - `"entries_delivered": 2`
  - both peer sync states had:
    - `last_seen_merkle_root: f28224a5c07866d5f359196615b9502ce51131c614b2140e1cd9529c8389d545`
    - `last_seen_sequence: 5`

Queue drained:
- `GET /api/v1/crl/offline/pending` returned:
  - `"count": 0`
  - `"pending": []`

Local propagated proof:
- `did:guardian:offline-req1-20260729064340`
  - `id: urn:uuid:d6c7f49e-7151-4fbc-bd6e-a2ca993d5813`
  - `propagated: True`
  - `peers_notified`: both peer DIDs present
- `did:guardian:offline-req3-isolated-20260729064955`
  - `id: urn:uuid:c9295830-6c37-40ef-905f-db2464fb9f41`
  - `propagated: True`
  - `peers_notified`: both peer DIDs present
```

**Updated-IP verdict:** ✅ PASS — Requirement 4 is proven on the updated board topology. Reconnect pushed both queued revocations to peers, marked both entries `propagated:true`, recorded both peer DIDs in `peers_notified`, incremented `entries_delivered` to `2`, and drained `/crl/offline/pending` to zero.

---

## ✅ Requirement 5 — [x] Fetch missed revocations from peers by comparing CRL version vectors

> When a node was offline, it fetches revocations issued on other nodes after reconnect by comparing CRL version vectors (`sequence` / `merkle_root`). Per-peer sync state is observable.

**Commands:**
```bash
# Stop nodeC; while it is down, issue two revocations on nodeA (nodeC will miss these):
ssh root@192.168.1.196 "pkill -f sgx_guardian_client"
/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-003 --reason compromised --severity critical --note "CRL-037 missed"
/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-004 --reason lost --severity high --note "CRL-037 missed"
sleep 5

# Start nodeC again -> only wait; do not run any manual pull command:
ssh root@192.168.1.196 "cd /home/root && SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8 ./sgx_guardian_client nodeC &"
sleep 40

# nodeC ne missed revocations fetch kar li?
ssh root@192.168.1.196 "/home/root/sgx-pa-cli crl check --did did:guardian:offline-test-003"   # → revoked: true
ssh root@192.168.1.196 "/home/root/sgx-pa-cli crl check --did did:guardian:offline-test-004"   # → revoked: true
ssh root@192.168.1.196 "curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool | grep -A20 'peer_sync_state'"
ssh root@192.168.1.196 "cat $CRL_BASE/sync_state.json | python3 -m json.tool"
```

**Expected:**
```
nodeC picks up BOTH missed revocations after reconnect (zero manual pull)
peer_sync_state / sync_state.json shows per-peer last_seen_merkle_root + last_seen_sequence + last_sync_at
entries_fetched ≥ 2 in status
```

**Result:**
```
Attempt 1 (`2026-07-22`) was invalid because the source revocations were never issued on nodeA:

NodeA REST revoke attempts:
- `POST /api/v1/crl/revoke` for `did:guardian:offline-test-005-20260722-r5a`
  returned:
  - `BAD_REQUEST`
  - `DID derivation signature failed`
  - `ERROR:sss.session: No open session, try connecting first`
- `POST /api/v1/crl/revoke` for `did:guardian:offline-test-006-20260722-r5b`
  returned the same SE050 session failure

NodeC follow-up checks therefore correctly showed no fetched revocations:
- `/home/root/sgx-pa-cli crl check --did did:guardian:offline-test-005-20260722-r5a` → `"revoked": false`
- `/home/root/sgx-pa-cli crl check --did did:guardian:offline-test-006-20260722-r5b` → `"revoked": false`
- `GET /api/v1/crl/offline/status` on nodeC returned:
  - `"online": false`
  - `"pending": 0`
  - `"reconnects": 0`
  - `"entries_fetched": 0`

Repeated attempt with fresh DIDs on the same date showed the same blocker:
- nodeA `POST /api/v1/crl/revoke` for
  - `did:guardian:offline-test-007-20260722-r5a`
  - `did:guardian:offline-test-008-20260722-r5b`
  again returned:
  - `BAD_REQUEST`
  - `DID derivation signature failed`
  - `ERROR:sss.session: No open session, try connecting first`
- nodeA local `crl check` for both fresh DIDs returned `"revoked": false`
- nodeC local `crl check` for both fresh DIDs also returned `"revoked": false`
- nodeC status after restart stayed:
  - `"online": true`
  - `"pending": 0`
  - `"entries_fetched": 0`
```

**Updated-IP fetch-missed rerun (`2026-07-29`, nodeA source + nodeC reconnect):**
```text
Source revocations created on nodeA while nodeC was stopped:
- `POST /api/v1/crl/revoke` for `did:guardian:offline-req5-missed-a-20260729071536`
  returned success:
  - `id: urn:uuid:84de3f74-d908-4023-8edf-ca0d08d87c42`
  - `reason: compromised`
  - `severity: high`
  - `revoker_did: did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE`
  - `propagated: false`
  - nodeA `sequence: 7`
  - nodeA `merkle_root: 70404e8eecbe2109b3660101d612264285391447c6dc0a4cd2a3866bd8406041`
- `POST /api/v1/crl/revoke` for `did:guardian:offline-req5-missed-b-20260729071536`
  returned success:
  - `id: urn:uuid:9585858c-fcf6-454d-8169-03a7d19465d7`
  - `reason: lost`
  - `severity: high`
  - `revoker_did: did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE`
  - `propagated: false`
  - nodeA `sequence: 8`
  - nodeA `merkle_root: 3e5ab1248eba2affa5d39aa422755b337e58a1585cb2aa1f6f6a11814c5c738d`

NodeA local checks:
- `GET /api/v1/crl/check?did=did:guardian:offline-req5-missed-a-20260729071536`
  returned `"revoked": true`
- `GET /api/v1/crl/check?did=did:guardian:offline-req5-missed-b-20260729071536`
  returned `"revoked": true`
- `GET /api/v1/crl/root` returned:
  - `sequence: 8`
  - `merkle_root: 3e5ab1248eba2affa5d39aa422755b337e58a1585cb2aa1f6f6a11814c5c738d`

NodeC reconnect/offline-sync fetch:
- `POST /api/v1/crl/offline/sync` round 1 returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"fetched": 2`
  - `"pending_remaining": 0`
- later rounds were steady-state or had temporary reachability fluctuation, but no pending work remained.

NodeC after-fetch proof:
- `GET /api/v1/crl/check?did=did:guardian:offline-req5-missed-a-20260729071536`
  returned:
  - `"revoked": true`
  - same id `urn:uuid:84de3f74-d908-4023-8edf-ca0d08d87c42`
  - same owner revoker DID
- `GET /api/v1/crl/check?did=did:guardian:offline-req5-missed-b-20260729071536`
  returned:
  - `"revoked": true`
  - same id `urn:uuid:9585858c-fcf6-454d-8169-03a7d19465d7`
  - same owner revoker DID

NodeC version-vector observability:
- `GET /api/v1/crl/offline/status` returned:
  - `"entries_fetched": 2`
  - peer `did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE`
    - `last_seen_merkle_root: 3e5ab1248eba2affa5d39aa422755b337e58a1585cb2aa1f6f6a11814c5c738d`
    - `last_seen_sequence: 7`
    - `last_sync_at: 2026-07-29T07:22:18.382688238+00:00`
- `/var/lib/sgx-guardian/identity/crl/sync_state.json` contained the same non-empty root/sequence/timestamp.
- `GET /api/v1/crl/root` on nodeC returned:
  - `sequence: 7`
  - `merkle_root: 3e5ab1248eba2affa5d39aa422755b337e58a1585cb2aa1f6f6a11814c5c738d`
```

**Verdict:** ✅ PASS — Requirement 5 is proven on the updated board topology. NodeC rejoined after missing two nodeA-issued revocations, offline sync fetched exactly `2` entries during the reconnect cycle, both missed DIDs became `revoked:true` on nodeC, and the per-peer version-vector state recorded NodeA's non-empty Merkle root and sequence.

---

## ✅ Requirement 6 — [x] Resolve conflicts (deterministic) — CRL converges, no split-brain

> If two nodes independently revoke the same DID while offline, the conflict resolves deterministically on reconnect (current code: later-timestamp wins; tie -> lower fingerprint, shared gossip rule), and all three nodes converge to an identical Merkle root.

**Commands:**
```bash
# Stop both nodeB and nodeC, then revoke the SAME dummy DID on both nodes with different timestamps:
ssh root@192.168.1.195 "pkill -f sgx_guardian_client"
ssh root@192.168.1.196 "pkill -f sgx_guardian_client"
ssh root@192.168.1.195 "cd /home/root && ./sgx_guardian_client nodeB & sleep 5; /home/root/sgx-pa-cli crl revoke --did did:guardian:conflict-test-001 --reason compromised --severity high --note 'B first'"
sleep 3
ssh root@192.168.1.196 "cd /home/root && ./sgx_guardian_client nodeC & sleep 5; /home/root/sgx-pa-cli crl revoke --did did:guardian:conflict-test-001 --reason stolen --severity high --note 'C later'"
sleep 40   # let gossip + offline sync converge across all three

# Convergence check — all three nodes:
/home/root/sgx-pa-cli crl root
ssh root@192.168.1.195 "/home/root/sgx-pa-cli crl root"
ssh root@192.168.1.196 "/home/root/sgx-pa-cli crl root"
# The surviving entry (current code: later timestamp wins) same on all three:
for h in "" "root@192.168.1.195" "root@192.168.1.196"; do
  ${h:+ssh $h} python3 - <<'PY'
import json
p="/var/lib/sgx-guardian/identity/crl/crl.json"
d=json.load(open(p))
print([{"reason":e.get("reason"),"timestamp":e.get("timestamp"),"revoker_did":e.get("revoker_did")} for e in d.get("entries", []) if e.get("revoked_did")=="did:guardian:conflict-test-001"])
PY
done
```

**Expected:**
```
Identical merkle_root on all three nodes after convergence
The same single entry survives everywhere (current code: later timestamp wins — deterministic)
No split-brain: offline-fetched + gossip-fetched resolve identically
```

**Result:**
```
Attempt 1 (`2026-07-22`) with fresh DID `did:guardian:conflict-test-002-20260722-r6`:

Board B isolated successfully:
- after CRL port blocks, `/crl/offline/status` first showed `"online": true`, then on repeat showed `"online": false`
- Board B then issued the first conflicting revoke successfully:
  - `id: urn:uuid:6e002fd0-3e64-4832-bfcf-b67b686c4563`
  - `reason: compromised`
  - `timestamp: 2026-07-22T09:58:24.257337553+00:00`
  - `revoker_did: did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa`
  - `propagated: false`

Board C isolated successfully:
- after CRL port blocks, `/crl/offline/status` showed `"online": false`
- Board C then issued the second conflicting revoke successfully:
  - `id: urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`
  - `reason: stolen`
  - `timestamp: 2026-07-22T09:59:09.192115969+00:00`
  - `revoker_did: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB`
  - `propagated: false`

After unblocking and forcing sync:
- Board B `POST /crl/offline/sync` returned:
  - `"online": true`
  - `"reachable_peers": 2`
  - `"pending_remaining": 1`
- Board C `POST /crl/offline/sync` returned:
  - `"online": true`
  - `"reachable_peers": 2`
  - `"pending_remaining": 1`

Immediate post-sync state did NOT yet prove final convergence:
- Board B final local lookup returned:
  - `merkle_root: 1fcad438a0d944c2ca44bea12a2e1e1a46113d329e213ab0ce007fb7dd3da78e`
  - `sequence: 6`
  - surviving entry:
    - `id: urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`
    - `reason: stolen`
    - `timestamp: 2026-07-22T09:59:09.192115969+00:00`
    - `revoker_did: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB`
    - `propagated: false`
- Board C final local lookup returned:
  - `merkle_root: b3ca5c93df0ea637fa8cda70abed30e4dac7f4b72be2794f04038094e7a99e00`
  - `sequence: 11`
  - surviving entry:
    - `id: urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`
    - `reason: stolen`
    - `timestamp: 2026-07-22T09:59:09.192115969+00:00`
    - `revoker_did: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB`
    - `propagated: false`
- Board A check taken before B/C convergence was stale / not usable:
  - `merkle_root: 12550fb1ddc3db96988d0a3b082eed8b7ae52bff91e71b82196270913685b735`
  - `sequence: 9`
  - no entry for this DID at that moment

Follow-up convergence check on the same date (`2026-07-22`) still showed split state:
- Board C after `POST /api/v1/crl/offline/sync`:
  - `"online": true`
  - `"reachable_peers": 2`
  - `"pending_remaining": 1`
  - local entry:
    - `id: urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`
    - `reason: stolen`
    - `timestamp: 2026-07-22T09:59:09.192115969+00:00`
    - `revoker_did: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB`
    - `propagated: False`
  - board-level root stayed:
    - `merkle_root: b3ca5c93df0ea637fa8cda70abed30e4dac7f4b72be2794f04038094e7a99e00`
    - `sequence: 11`
- Board B after `POST /api/v1/crl/offline/sync`:
  - `"online": true`
  - `"reachable_peers": 2`
  - `"pending_remaining": 1`
  - `"entries_fetched": 1`
  - local entry:
    - `id: urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`
    - `reason: stolen`
    - `timestamp: 2026-07-22T09:59:09.192115969+00:00`
    - `revoker_did: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB`
    - `propagated: False`
  - board-level root stayed:
    - `merkle_root: 1fcad438a0d944c2ca44bea12a2e1e1a46113d329e213ab0ce007fb7dd3da78e`
    - `sequence: 6`
- Board A after `POST /api/v1/crl/offline/sync`:
  - `"online": true`
  - `"reachable_peers": 2`
  - `"pending_remaining": 0`
  - local lookup still returned no entry for this DID
  - board-level root stayed:
    - `merkle_root: 12550fb1ddc3db96988d0a3b082eed8b7ae52bff91e71b82196270913685b735`
    - `sequence: 9`

Additional gossip-trigger round (`2026-07-22`) improved but did not fully converge the cluster:
- Board A:
  - `POST /api/v1/crl/gossip/trigger` succeeded against `nodeB`
  - `merkle_root` became `1fcad438a0d944c2ca44bea12a2e1e1a46113d329e213ab0ce007fb7dd3da78e`
  - final conflict entry present:
    - `id: urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`
    - `reason: stolen`
    - `propagated: True`
- Board B:
  - `POST /api/v1/crl/gossip/trigger` succeeded against `nodeA`
  - `merkle_root` remained `1fcad438a0d944c2ca44bea12a2e1e1a46113d329e213ab0ce007fb7dd3da78e`
  - final conflict entry present:
    - `id: urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`
    - `reason: stolen`
    - `propagated: True`
- Board C:
  - `POST /api/v1/crl/gossip/trigger` succeeded against `nodeB`
  - response showed `pushed: 1`, `merged: 0`, `peer_merged: 0`
  - `merkle_root` stayed `b3ca5c93df0ea637fa8cda70abed30e4dac7f4b72be2794f04038094e7a99e00`
  - final conflict entry present:
    - `id: urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`
    - `reason: stolen`
    - `propagated: True`

Net state after this round:
- Boards A and B now match exactly on the conflict winner and `merkle_root`
- Board C matches the conflict winner entry, but still has a different `merkle_root`
```

**Historical attempt verdict:** ⏳ Partial / retry required — the actual conflict scenario was created successfully and the conflict winner now matches across all boards (`urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`, reason `stolen`). However, this older attempt did not fully prove Requirement 6 because full-root convergence had not happened: Boards A and B shared the same `merkle_root`, while Board C still reported a different root after a successful gossip-trigger round.

**Updated-IP board rerun (`2026-07-29`):**
```
Topology:
- NodeA: 192.168.1.92
- NodeB: 192.168.1.195
- NodeC: 192.168.1.252

Baseline before conflict:
- NodeA root: 3e5ab1248eba2affa5d39aa422755b337e58a1585cb2aa1f6f6a11814c5c738d
- NodeB root: 3e5ab1248eba2affa5d39aa422755b337e58a1585cb2aa1f6f6a11814c5c738d
- NodeC root: 3e5ab1248eba2affa5d39aa422755b337e58a1585cb2aa1f6f6a11814c5c738d

Conflict DID:
- did:guardian:offline-req6-conflict-retry-20260729080025

First isolated writer:
- NodeB issued id: urn:uuid:01060879-4323-4a8d-a9d5-5007903e65b6
- reason: compromised
- timestamp: 2026-07-29T08:00:35.436829696+00:00
- revoker_did: did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa
- propagated: false

Later isolated writer:
- NodeA issued id: urn:uuid:d9e0975b-04e0-4371-bf43-266ff6c37db0
- reason: stolen
- timestamp: 2026-07-29T09:12:39.842522973+00:00
- revoker_did: did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE
- revoker_role: owner
- propagated: false at issuance

NodeC note:
- NodeC could not be used as the later writer because its API/CLI revoke path hit an SE050 `No open session` signing blocker.
- NodeC still participated as the third convergence peer after SE050 session reset and daemon restart.
```

**Final convergence proof (`2026-07-29`):**
```
NodeA final:
- sequence: 12
- merkle_root: 3debb3b1367173d88625e1ee35f1402b593950265c4c6545b9eb4679d24ba001
- revoked: true
- surviving entry id: urn:uuid:d9e0975b-04e0-4371-bf43-266ff6c37db0
- reason: stolen
- timestamp: 2026-07-29T09:12:39.842522973+00:00
- revoker_did: did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE

NodeB final:
- sequence: 11
- merkle_root: 3debb3b1367173d88625e1ee35f1402b593950265c4c6545b9eb4679d24ba001
- revoked: true
- surviving entry id: urn:uuid:d9e0975b-04e0-4371-bf43-266ff6c37db0
- reason: stolen
- timestamp: 2026-07-29T09:12:39.842522973+00:00
- revoker_did: did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE

NodeC before fetch:
- sequence: 8
- merkle_root: 3e5ab1248eba2affa5d39aa422755b337e58a1585cb2aa1f6f6a11814c5c738d
- conflict DID missing

NodeC final after forced offline/gossip rounds:
- sequence: 11
- merkle_root: 3debb3b1367173d88625e1ee35f1402b593950265c4c6545b9eb4679d24ba001
- revoked: true
- surviving entry id: urn:uuid:d9e0975b-04e0-4371-bf43-266ff6c37db0
- reason: stolen
- timestamp: 2026-07-29T09:12:39.842522973+00:00
- revoker_did: did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE
- propagated: true
- peers_notified:
  - did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa
  - did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE
```

**Verdict:** ✅ PASS — Requirement 6 is proven on the updated board topology. Two isolated nodes independently revoked the same DID, the deterministic shared conflict rule selected the later entry (`reason: stolen`), and all three nodes converged to the identical Merkle root `3debb3b1367173d88625e1ee35f1402b593950265c4c6545b9eb4679d24ba001`. Sequence numbers differ by node, which is acceptable; the pass gate is identical Merkle root plus the same single surviving conflict entry.

---

## ✅ Requirement 7 — [x] Retry budget + never silently drop (parking) + restart persistence

> Undelivered revocations continue retrying; when `MAX_RETRIES` is set and the budget is exhausted, the entry is **parked** (retained on disk and audited, NOT dropped). The queue survives restart.

**Commands:**
```bash
# On nodeC with MAX_RETRIES=2, create a revocation that cannot be delivered (peers stopped):
ssh root@192.168.1.157 "pkill -f sgx_guardian_client"; ssh root@192.168.1.195 "pkill -f sgx_guardian_client"
ssh root@192.168.1.196 "pkill -f sgx_guardian_client"
ssh root@192.168.1.196 "cd /home/root && SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=6 SGX_CRL_OFFLINE_MAX_RETRIES=2 ./sgx_guardian_client nodeC &"
ssh root@192.168.1.196 "/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-005 --reason compromised --severity high --note 'CRL-039 park'"
sleep 30   # several cycles with no reachable peer
ssh root@192.168.1.196 "curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool"   # attempts ≥ 2, parked:true

# Restart persistence: restart nodeC and confirm pending survives:
ssh root@192.168.1.196 "pkill -f sgx_guardian_client && sleep 3 && cd /home/root && ./sgx_guardian_client nodeC &"
sleep 10
ssh root@192.168.1.196 "ls -la $PENDING_DIR/ && curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool"
```

**Expected:**
```
Pending entry reaches parked:true after 2 attempts — but STILL present (not dropped)
After daemon restart the pending file survives; entry still queued
audit trail shows attempts, no silent loss
```

**Result:**
```text
Board-safe attempt on nodeC with retry budget enabled (`2026-07-22`):

Setup used:
- nodeA kept ON for CA / lighthouse stability
- nodeC restarted with:
  `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=6`
  `SGX_CRL_OFFLINE_MAX_RETRIES=2`
- nodeC CRL ports blocked locally:
  - TCP `50063`
  - UDP `50064`

Isolated status proof:
- `GET /api/v1/crl/offline/status` returned:
  - `"online": false`
  - `"sync_interval_secs": 6`
  - `"max_retries": 2`
  - `"pending": 0`
  - `"sync_cycles": 4`
  - `"reconnects": 1`
  - `"entries_delivered": 0`
  - `"entries_fetched": 0`

Fresh revoke while isolated:
- `POST /api/v1/crl/revoke` for `did:guardian:offline-test-009-20260722-r7`
  returned success:
  - `id: urn:uuid:e7db8e58-10e9-47e1-9656-093c483e3c36`
  - `reason: compromised`
  - `severity: high`
  - `timestamp: 2026-07-22T10:20:30.747510045+00:00`
  - `propagated: false`
  - `sequence: 13`
  - `merkle_root: 6fcb47b34c61f7f93e4535cdf36f1dfc8113ce42f9dc8f8b5d141f69f231148d`

Post-wait queue state after `sleep 20`:
- `GET /api/v1/crl/offline/pending` returned:
  - `count: 1`
  - pending entry present for the same DID / UUID
  - `attempts: 0`
  - `last_attempt_at: null`
  - `parked: false`
  - `queued_at: 2026-07-22T10:20:34.142729843+00:00`

Local CRL view at the same moment:
- Python lookup in `/var/lib/sgx-guardian/identity/crl/crl.json` returned:
  `{'id': 'urn:uuid:e7db8e58-10e9-47e1-9656-093c483e3c36', 'revoked_did': 'did:guardian:offline-test-009-20260722-r7', 'propagated': True}`

Interpretation:
- queue persistence is proven again: the pending item still exists on disk/REST and was not dropped
- retry-budget / parking itself is NOT yet proven in this run because the entry never advanced to:
  - `attempts >= 2`
  - `parked: true`
- restart persistence is also NOT yet proven because nodeC was not restarted after this exact pending item was created
- there is a follow-up inconsistency to inspect: REST pending still shows the item queued, while local `crl.json` already shows `propagated: True`

Follow-up restart check on the same R7 entry (`2026-07-22`):
- before restart, `GET /api/v1/crl/offline/status` showed:
  - `"online": false`
  - `"pending": 1`
  - `"sync_cycles": 10`
  - `"max_retries": 2`
- forced `POST /api/v1/crl/offline/sync` while isolated returned:
  - `"online": false`
  - `"reachable_peers": 0`
  - `"pending_remaining": 1`
- pending state before restart still showed:
  - `attempts: 0`
  - `last_attempt_at: null`
  - `parked: false`
- pending file existed before restart:
  - `/var/lib/sgx-guardian/identity/crl/pending/urn_uuid_e7db8e58-10e9-47e1-9656-093c483e3c36.json`
- audit trail showed:
  - `CRL offline queued pending revocation revoked_did=did:guardian:offline-test-009-20260722-r7 id=urn:uuid:e7db8e58-10e9-47e1-9656-093c483e3c36`
  - `CRL entry propagated id=urn:uuid:e7db8e58-10e9-47e1-9656-093c483e3c36 threshold=2`
- after daemon restart:
  - process was running: `214958 ./sgx_guardian_client nodeC`
  - first immediate REST checks returned empty / non-JSON output (`python3 -m json.tool` failed at column 1), but a follow-up raw `curl -i` check confirmed REST was listening and returning JSON
  - pending file still existed on disk
  - local `crl.json` still showed the R7 entry with `propagated: True`

Follow-up REST/log check after restart (`2026-07-22`):
- daemon log confirmed healthy startup:
  - `CRL-OFFLINE sync starting interval_secs=6 flush_rounds=3 max_retries=2`
  - `REST admin API listening on http://0.0.0.0:8443/api/v1`
  - no panic / address-in-use error
- `GET /health` returned `404 Not Found`; this is not an offline-sync failure because the CRL REST routes were reachable
- raw `GET /api/v1/crl/offline/status` returned `200 OK` JSON:
  - `"online": false`
  - `"pending": 1`
  - `"sync_cycles": 11`
  - `"max_retries": 2`
  - `"entries_delivered": 0`
  - `"entries_fetched": 0`
- raw `GET /api/v1/crl/offline/pending` returned `200 OK` JSON:
  - `count: 1`
  - `id: urn:uuid:e7db8e58-10e9-47e1-9656-093c483e3c36`
  - `attempts: 0`
  - `last_attempt_at: null`
  - `parked: false`
- pending file content after restart also showed:
  - `entry.propagated: false`
  - `attempts: 0`
  - `last_attempt_at: null`
  - `parked: false`
- local `crl.json` for the same entry showed:
  - `propagated: True`
  - `peers_notified` contains both peers

Updated interpretation:
- disk + REST restart persistence are proven: the pending file survived restart and `/crl/offline/pending` lists it after restart
- parking is still not proven: even after a forced offline sync cycle, `attempts` remained `0` and `parked` remained `false`
- current behavior suggests the no-reachable-peer path does not count as a delivery attempt for `MAX_RETRIES`; if the requirement expects parking while fully offline, this is likely a code-side behavior gap or at least a requirement/implementation mismatch
- there is also a cleanup/state mismatch to investigate: the pending file remains queued with `entry.propagated:false`, while the canonical local `crl.json` marks the same entry `propagated:true` and both peers are listed in `peers_notified`

Later cleanup evidence during R8 setup (`2026-07-22`):
- nodeC forced offline-sync cycle returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"pending_remaining": 0`
- `/crl/offline/pending` then returned `count: 0`
- audit showed:
  - `CRL offline delivered revoked_did=did:guardian:offline-test-009-20260722-r7 id=urn:uuid:e7db8e58-10e9-47e1-9656-093c483e3c36 (propagated)`
- this confirms the stale R7 pending item was eventually delivered/dequeued once connectivity came back, but it still does not prove the parking path
```

**Historical attempt verdict:** ⏳ Partial / likely code-side gap — this run proves isolated issuance, queue retention, and restart persistence through both disk and REST. It still does not prove retry-budget parking because attempts never incremented to the configured limit and `parked:true` never appeared. The remaining gap is now specific: fully offline/no-reachable-peer cycles keep the pending item but do not count attempts, and a propagated CRL entry can still have a stale pending file.

**Updated-IP one-peer retry-budget rerun (`2026-07-29`, nodeB issuer):**
```text
Topology / test shape:
- NodeA kept running and reachable.
- NodeC was stopped so nodeB had only one reachable peer.
- NodeB restarted with:
  - SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=6
  - SGX_CRL_OFFLINE_MAX_RETRIES=2
  - SGX_CRL_GOSSIP_INTERVAL_SECS=10

NodeB status before issuing fresh R7 revocation:
- `GET /api/v1/crl/offline/status` returned:
  - `"enabled": true`
  - `"online": true`
  - `"sync_interval_secs": 6`
  - `"max_retries": 2`
  - `"pending": 1`
  - `"sync_cycles": 1`
  - `"reconnects": 1`
- forced one-peer proof via `POST /api/v1/crl/offline/sync` returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"delivered": 0`
  - `"pending_remaining": 1`

Fresh R7 revoke:
- DID: did:guardian:offline-req7-park-20260729093758
- `POST /api/v1/crl/revoke` returned success:
  - `id: urn:uuid:12472fe4-8cfb-49ee-bdc4-49ce07069aca`
  - `reason: compromised`
  - `severity: high`
  - `timestamp: 2026-07-29T09:38:08.317847092+00:00`
  - `revoker_did: did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa`
  - `propagated: false`
  - `sequence: 13`
  - `merkle_root: 7188e16175eeebcf6099d57e1f1ff32d732e56ed71e8a5ce0fddf1327e383045`

Initial pending proof:
- `GET /api/v1/crl/offline/pending` returned `count: 2`, including the fresh R7 entry:
  - `id: urn:uuid:12472fe4-8cfb-49ee-bdc4-49ce07069aca`
  - `revoked_did: did:guardian:offline-req7-park-20260729093758`
  - `attempts: 0`
  - `queued_at: 2026-07-29T09:38:11.647399420+00:00`
  - `last_attempt_at: null`
  - `last_error: null`
  - `parked: false`

Retry/parking proof:
- parking sync round 1 returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"delivered": 0`
  - `"pending_remaining": 2`
- exact pending JSON proof after round 1:
  - file: `/var/lib/sgx-guardian/identity/crl/pending/urn_uuid_12472fe4-8cfb-49ee-bdc4-49ce07069aca.json`
  - `attempts: 2`
  - `queued_at: 2026-07-29T09:38:11.647399420+00:00`
  - `last_attempt_at: 2026-07-29T09:38:54.567733638+00:00`
  - `last_error: null`
  - `parked: true`
- rounds 2 and 3 retained the same parked file:
  - `attempts: 2`
  - `parked: true`
  - file still present

Local CRL proof while parked:
- `GET /api/v1/crl/check?did=did:guardian:offline-req7-park-20260729093758`
  returned:
  - `"revoked": true`
  - same id `urn:uuid:12472fe4-8cfb-49ee-bdc4-49ce07069aca`
  - `peers_notified` contained only nodeA's DID
  - `"propagated": false`
```

**Restart persistence proof (`2026-07-29`):**
```text
After nodeB daemon restart with the same retry-budget env:
- `GET /api/v1/crl/offline/status` returned:
  - `"enabled": true`
  - `"online": true`
  - `"sync_interval_secs": 6`
  - `"max_retries": 2`
  - `"pending": 2`
  - `"sync_cycles": 1`
  - `"reconnects": 1`

Exact pending file proof after restart:
- file: `/var/lib/sgx-guardian/identity/crl/pending/urn_uuid_12472fe4-8cfb-49ee-bdc4-49ce07069aca.json`
- `id: urn:uuid:12472fe4-8cfb-49ee-bdc4-49ce07069aca`
- `attempts: 2`
- `queued_at: 2026-07-29T09:38:11.647399420+00:00`
- `last_attempt_at: 2026-07-29T09:38:54.567733638+00:00`
- `parked: true`
```

**Verdict:** ✅ PASS — Requirement 7 is proven on the updated board topology. With one reachable peer and a three-node 80% propagation threshold, the fresh nodeB revocation could not reach full delivery; the pending item reached the configured retry budget (`attempts: 2`), was marked `parked:true`, stayed on disk instead of being dropped, and survived daemon restart with the same queued timestamp, attempt count, last-attempt timestamp, and parked state.

---

## ✅ Requirement 8 — [x] Self-reconcile queue from local state (covers CLI-issued + restart)

> On every cycle, the sync loop reconciles local `crl.json`: any locally-issued entry (`revoker_did == self`) with `propagated == false` is automatically added to pending, even if it was issued through the CLI (without the REST handler).

**Commands (nodeA — issue via CLI, then confirm auto-reconcile even if pending file wasn't pre-seeded):**
```bash
# Fresh CLI revoke (CLI path), then delete its pending file to prove reconcile re-adds it:
/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-006 --reason policy_violation --severity high --note "CRL-040 reconcile"
ID=$(python3 - <<'PY'
import json
p="/var/lib/sgx-guardian/identity/crl/crl.json"
d=json.load(open(p))
for e in d.get("entries", []):
    if e.get("revoked_did") == "did:guardian:offline-test-006":
        print(e.get("id", ""))
        break
PY
)
rm -f "$PENDING_DIR/$(echo "$ID" | tr ':/' '__').json"    # simulate missing queue file
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
```text
Attempt 1 on nodeC with fresh DID `did:guardian:offline-test-010-20260722-r8` (`2026-07-22`):

Pre-status:
- `GET /api/v1/crl/offline/status` returned:
  - `"online": false`
  - `"sync_interval_secs": 8`
  - `"max_retries": 2`
  - `"pending": 1`
  - `"sync_cycles": 0`

CLI revoke failed before any local CRL entry was created:
- `/home/root/sgx-pa-cli crl revoke --did "$DID_R8" --reason policy_violation --severity high --note "CRL-040 self-reconcile"`
- error:
  - `DID derivation signature failed`
  - `DKP sign: SE050 sign failed`
  - `ERROR:sss.session: No open session, try connecting first`

Post-failure checks:
- local `crl.json` lookup for `did:guardian:offline-test-010-20260722-r8` returned `[]`
- `ID_R8` was empty, so the computed pending filename was invalid:
  - `/var/lib/sgx-guardian/identity/crl/pending/.json`
- forced `POST /api/v1/crl/offline/sync` returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"reconciled": 0`
  - `"pending_remaining": 0`
- `/crl/offline/pending` returned `count: 0`

Interpretation:
- this attempt did not test Requirement 8 because the CLI-issued local revocation was never created
- the blocker is nodeC SE050 session state for CLI signing (`No open session`), not self-reconcile behavior
```

**Historical attempt verdict:** ⏳ Blocked / retry required — this attempt did not test Requirement 8. First recover nodeC SE050 CLI signing, then retry with a fresh DID and only evaluate self-reconcile after `crl.json` contains the local CLI-issued entry.

**Updated-IP self-reconcile rerun (`2026-07-29`, nodeB source entry):**
```text
Fresh CLI issuance caveat:
- Fresh nodeB direct CLI revokes for new Req8 DIDs failed before CRL entry creation with:
  - `DID derivation signature failed`
  - `DKP sign: SE050 sign failed`
  - `ERROR:sss.session: No open session, try connecting first`
- Manual `ssscli sign 0x20000010 ...` succeeded on nodeB, so this was an `sgx-pa-cli`/SE050 session blocker, not a self-reconcile result.
- To verify the self-reconcile logic itself, the rerun used an existing nodeB-local, unpropagated CRL entry from Req7. Once a local entry exists in `crl.json`, reconcile is source-agnostic and applies the same rule that covers CLI-issued entries:
  `revoker_did == self_did && propagated == false`.

Source entry:
- DID: `did:guardian:offline-req7-park-20260729093758`
- ID: `urn:uuid:12472fe4-8cfb-49ee-bdc4-49ce07069aca`
- `GET /api/v1/crl/check?did=...` returned:
  - `"revoked": true`
  - `reason: compromised`
  - `severity: high`
  - `timestamp: 2026-07-29T09:38:08.317847092+00:00`
  - `revoker_did: did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa`
  - `peers_notified`: only nodeA DID
  - `"propagated": false`

Before reconcile:
- `GET /api/v1/crl/offline/status` returned:
  - `"enabled": true`
  - `"online": false`
  - `"sync_interval_secs": 600`
  - `"max_retries": 2`
  - `"pending": 2`
  - `"sync_cycles": 0`
- Existing pending file:
  - `/var/lib/sgx-guardian/identity/crl/pending/urn_uuid_12472fe4-8cfb-49ee-bdc4-49ce07069aca.json`
  - `attempts: 2`
  - `queued_at: 2026-07-29T09:38:11.647399420+00:00`
  - `last_attempt_at: 2026-07-29T09:38:54.567733638+00:00`
  - `parked: true`
- The pending file was moved aside:
  - `mv "$PENDING_FILE" /tmp/req8-reconcile-pending.bak`
  - follow-up `ls` confirmed `pending file removed OK`

Forced self-reconcile:
- `POST /api/v1/crl/offline/sync` returned:
  - `"online": true`
  - `"reachable_peers": 1`
  - `"reconciled": 1`
  - `"fetched": 0`
  - `"delivered": 0`
  - `"pending_remaining": 2`

Pending proof after reconcile:
- Python lookup under `/var/lib/sgx-guardian/identity/crl/pending/*.json` found the same DID again:
  - file: `/var/lib/sgx-guardian/identity/crl/pending/urn_uuid_12472fe4-8cfb-49ee-bdc4-49ce07069aca.json`
  - id: `urn:uuid:12472fe4-8cfb-49ee-bdc4-49ce07069aca`
  - revoked_did: `did:guardian:offline-req7-park-20260729093758`
  - attempts: 1
  - queued_at: `2026-07-29T10:50:57.277887532+00:00`
  - last_attempt_at: `2026-07-29T10:51:18.430981740+00:00`
  - parked: false
```

**Verdict:** ✅ PASS — Requirement 8's self-reconcile path is proven on the updated board topology. After the pending file was manually removed, the next offline-sync cycle scanned local `crl.json`, detected the locally-issued unpropagated entry, returned `reconciled: 1`, and recreated the missing pending JSON file. Fresh CLI issuance was still blocked by the board's SE050 session state, but the reconciler's local-state behavior that covers CLI-issued entries was verified directly.

---

# 🔌 API Verification

## ✅ API 1 — [x] GET `/api/v1/crl/offline/status`

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
```json
{
    "enabled": true,
    "online": true,
    "sync_interval_secs": 8,
    "flush_rounds": 3,
    "max_retries": 0,
    "pending": 3,
    "sync_cycles": 2,
    "reconnects": 1,
    "entries_delivered": 0,
    "entries_fetched": 0,
    "peer_sync_state": {
        "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa": {
            "last_seen_merkle_root": "",
            "last_seen_sequence": 0,
            "last_sync_at": "2026-07-22T07:02:30.396976754+00:00"
        },
        "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE": {
            "last_seen_merkle_root": "",
            "last_seen_sequence": 0,
            "last_sync_at": "2026-07-22T07:02:10.306194695+00:00"
        }
    }
}
```

**Verdict:** ✅ PASS — endpoint returns the expected observability shape including config, counters, pending count, and per-peer sync state.

## ✅ API 2 — [x] GET `/api/v1/crl/offline/pending`

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
```json
{
    "status": "success",
    "count": 3,
    "pending": [
        {
            "attempts": 1,
            "id": "urn:uuid:520e3c28-9aaa-4d5d-9af0-d06722f5a574",
            "last_attempt_at": "2026-07-22T07:46:56.916169043+00:00",
            "last_error": null,
            "parked": false,
            "queued_at": "2026-07-22T07:46:46.468350175+00:00",
            "reason": "compromised",
            "revoked_did": "did:guardian:offline-test-001-20260722-02",
            "severity": "high"
        },
        {
            "attempts": 1,
            "id": "urn:uuid:a980f383-eb5c-46e7-b9d0-97f6026b0159",
            "last_attempt_at": "2026-07-22T07:46:56.916837059+00:00",
            "last_error": null,
            "parked": false,
            "queued_at": "2026-07-22T07:46:46.468869313+00:00",
            "reason": "compromised",
            "revoked_did": "did:guardian:offline-test-001-20260722-manual-01",
            "severity": "high"
        },
        {
            "attempts": 0,
            "id": "urn:uuid:b0fac4d2-a544-47ab-8574-3bc40af610b2",
            "last_attempt_at": null,
            "last_error": null,
            "parked": false,
            "queued_at": "2026-07-22T07:47:08.617006612+00:00",
            "reason": "compromised",
            "revoked_did": "did:guardian:offline-test-001-20260722-rest-01",
            "severity": "high"
        }
    ]
}
```

**Verdict:** ✅ PASS — endpoint returns the expected list shape with retry metadata, timestamps, and parking state for each pending revocation.

## ✅ API 3 — [x] POST `/api/v1/crl/offline/sync` (deterministic cycle)

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
**Note:** If there is no pending work and everything is converged, `fetched`/`delivered` will be 0 (steady state); this is correct. When pending work exists, `delivered` will increase.

**Result:**
```json
{
    "online": true,
    "reachable_peers": 1,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 4
}
```

**Verdict:** ✅ PASS — endpoint returned the expected deterministic cycle summary on-board after connectivity restore. `delivered` was `0` in this run, but that does not affect API correctness; it only means this specific cycle did not confirm queue delivery.

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

## ⚙️ Known Issues / Board Caveats

### Issue 1 — SE050 session/tamper blocks CRL issuance
```
Symptoms:
- `POST /api/v1/crl/revoke` or `/home/root/sgx-pa-cli crl revoke` returns `DID derivation signature failed`
- board log includes `ERROR:sss.session: No open session, try connecting first`
- sometimes foreground daemon shows `SE050 TAMPER DETECTED`

Impact:
- Offline-sync cannot queue a fresh revocation if CRL issuance itself fails before creating `crl.json` entry.

Recovery probe used successfully on nodeC:
ssscli se05x uid
ssscli se05x readidlist | grep -i 20000010
printf probe >/tmp/offline_se050_probe.bin
ssscli sign 0x20000010 /tmp/offline_se050_probe.bin /tmp/offline_se050_probe.sig
```

### Issue 2 — Fully offline cycles retain queue but do not count attempts
```
Current code behavior:
- `run_cycle()` reconciles and returns early when `reachable_peers=0`
- `settle_pending()` is not called in that branch
- result: pending entry is retained, but `attempts` stays unchanged and `parked:true` is not reached while fully isolated

Board verification guidance:
- Req 3 should verify no-loss while fully offline
- Req 7 parking should use one-peer-reachable / threshold-not-met setup so attempts increment without delivery
```

### Issue 3 — Conflict rule wording mismatch
```
Current implementation:
- `src/crl/gossip/store.rs::incoming_wins`
- later RFC3339 timestamp wins
- tie -> lower fingerprint wins

Old plan/log wording in some historical evidence said earliest timestamp wins.
For board verification, expect the later conflicting entry to survive unless code is intentionally changed.
```

---

## 🧰 Emergency & Debug Commands

```bash
# Kill-switch (no rebuild): restart with offline sync OFF
SGX_CRL_OFFLINE_ENABLED=0 ./sgx_guardian_client nodeA

# Watch the offline sync trail:
grep -ai "CRL offline\|CRL-OFFLINE\|connectivity restored" /var/log/sgx-guardian/audit-nodeA.log | tail -20

# Inspect the queue + version vectors directly:
ls -la /var/lib/sgx-guardian/identity/crl/pending/
cat /var/lib/sgx-guardian/identity/crl/pending/*.json | python3 -m json.tool
cat /var/lib/sgx-guardian/identity/crl/sync_state.json | python3 -m json.tool

# Force one sync cycle immediately (instead of waiting for the interval):
curl -s -X POST http://localhost:8443/api/v1/crl/offline/sync | python3 -m json.tool

# Is gossip healthy? (offline sync rides the gossip exchange — check this first if fetch/flush stalls)
curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger | python3 -m json.tool

# Manually clear a parked/stuck pending entry after operator review (dummy DIDs only):
ID_TO_CLEAR="urn:uuid:REPLACE_WITH_DUMMY_ENTRY_ID"
PENDING_FILE="/var/lib/sgx-guardian/identity/crl/pending/$(python3 - "$ID_TO_CLEAR" <<'PY'
import sys
print(sys.argv[1].replace(":", "_").replace("/", "_") + ".json")
PY
)"
printf '%s\n' "$PENDING_FILE"
rm -f "$PENDING_FILE"

# Reset offline test state (unrevoke dummy DIDs on nodeA/Owner):
for d in offline-test-001 offline-test-002 offline-test-003 offline-test-004 offline-test-005 offline-test-006 conflict-test-001; do
  curl -s -X POST http://localhost:8443/api/v1/crl/unrevoke -H "Content-Type: application/json" -d "{\"did\":\"did:guardian:$d\"}"
done
```

**Timing cheat-sheet:** default sync interval 20 s → reconnect flush within ~1 cycle · `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8` → faster · `POST /crl/offline/sync` → instant. Delivery confirmation needs gossip to reach the `propagated` threshold, so allow gossip a round or two after the push.
