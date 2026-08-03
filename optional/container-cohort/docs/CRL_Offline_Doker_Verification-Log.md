# CRL Offline Revocation Sync - Docker Verification Log
**Environment:** Docker container cohort (WSL2 / laptop) | **Date:** 2026-07-22 | **Tester:** Asad Ali
**Test tag:** CRL-series (CRL-033 - CRL-043) | **Plan:** `docs/CRL_Offline_Revocation_Sync_Complete_Plan.md`

---

## Task Description

> Implement offline revocation queue for Guardians operating in disconnected environments. When Guardian goes offline, queue outgoing revocations locally. Track pending revocations with retry counter and timestamps. When connectivity restored, synchronously push queued revocations to peers. Fetch missed revocations from peers by comparing CRL version vectors. Resolve conflicts using timestamp-based last-writer-wins or signature-based trust hierarchy. Ensure Guardians can revoke compromised peers even when isolated.

---

## How To Use This File

Jab Docker me koi Requirement ya API verify ho jaye:

1. Checklist me `[ ]` ko `[x]` karo.
2. Section heading me `PENDING` ko `PASS` karo.
3. `Result:` block me exact terminal output ya short observed proof paste karo.
4. `Verdict:` me one-line PASS/FAIL likho.

Jab koi test fail ho:

1. Pehle command/environment side verify karo:
   - `docker ps` me `sgx-nodeA`, `sgx-nodeB`, `sgx-nodeC` expected state me hain?
   - Correct host REST ports use ho rahe hain? Current ports `optional/container-cohort/dev.env` se aate hain.
   - Daemon env me `SGX_FORCE_SOFTWARE_KEYS=1` hai?
   - Offline sync startup log aaya? `docker logs sgx-nodeC | grep "CRL-OFFLINE sync starting"`
   - `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=6` env active hai?
   - Test DID fresh hai?
   - Partition rules clear hain? `crl_unblock sgx-nodeA; crl_unblock sgx-nodeB; crl_unblock sgx-nodeC`
2. Sirf confirmed code-side failure par FAIL mark karo.
3. FAIL ke saath exact command, error, likely file/function, aur retry attempts record karo.

Common mistakes:

- Saari commands host terminal se chalani hain unless explicitly `docker exec` command diya ho.
- Container ke andar ja kar `docker exec` mat chalana.
- `sgx-pa-cli` ke liye `docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 ...` use karo.
- DUMMY DIDs use karo. Real `DID_A`, `DID_B`, `DID_C` revoke mat karo.
- `<...>` placeholders literally shell me mat likho.
- Har fresh run me `RUN_ID=$(date +%s)` se unique DIDs banao.
- Current repo ke `dev.env` me ports old docs se different ho sakte hain. Variables `A`, `B`, `C` use karo.

Board-test blockers jo Docker me avoid hone chahiye:

- SE050 `No open session` Docker me valid blocker nahi hona chahiye, kyun ke Docker run software-key mode me hota hai.
- Agar signing fail ho, pehle confirm karo service override me `SGX_FORCE_SOFTWARE_KEYS=1` set hai.

---

## Docker Status Checklist

Requirements:

- [x] Requirement 1 - Locally queue outgoing revocations; pending queue persists
- [x] Requirement 2 - Retry counter and timestamps are tracked
- [x] Requirement 3 - Queue works while isolated; nothing lost
- [x] Requirement 4 - Connectivity restore pushes queued revocations and dequeues on delivery
- [x] Requirement 5 - Missed revocations are fetched using CRL version vectors
- [x] Requirement 6 - Deterministic conflict resolution converges roots
- [x] Requirement 7 - Retry budget parks without dropping; restart persistence
- [x] Requirement 8 - Self-reconcile covers CLI-issued local revocations

APIs:

- [x] API 1 - GET `/api/v1/crl/offline/status`
- [x] API 2 - GET `/api/v1/crl/offline/pending`
- [x] API 3 - POST `/api/v1/crl/offline/sync`

---

## Terminal Layout

Use 2 host terminals:

- **Terminal 1 - Control:** setup, curl, docker exec, partitions, verification commands.
- **Terminal 2 - Logs:** `docker logs -f sgx-nodeA`, `docker logs -f sgx-nodeB`, or `docker logs -f sgx-nodeC`.

Optional third terminal:

- **Terminal 3 - Live status:** repeat `docker ps`, `curl $C/api/v1/crl/offline/status`, etc.

---

## Test Setup - Run Once Before Requirement 1

### Terminal 1 - Start Docker environment

```bash
cd ~/SGX

# Docker daemon reachable hona chahiye.
docker info >/dev/null

# Current repo ports load karo. This repo currently uses dev.env.
set -a
. optional/container-cohort/dev.env
set +a

A=http://127.0.0.1:${NODEA_REST_PORT:-18443}
B=http://127.0.0.1:${NODEB_REST_PORT:-28443}
C=http://127.0.0.1:${NODEC_REST_PORT:-38443}

echo "nodeA REST: $A"
echo "nodeB REST: $B"
echo "nodeC REST: $C"
```

### Terminal 1 - Create fast/offline Docker override

```bash
cat >/tmp/cc-crl-offline-fast.yml <<'EOF'
services:
  nodeA:
    environment:
      SGX_FORCE_SOFTWARE_KEYS: "1"
      SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS: "6"
      SGX_CRL_OFFLINE_FLUSH_ROUNDS: "5"
      SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS: "500"
      SGX_CRL_GOSSIP_INTERVAL_SECS: "10"
  nodeB:
    environment:
      SGX_FORCE_SOFTWARE_KEYS: "1"
      SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS: "6"
      SGX_CRL_OFFLINE_FLUSH_ROUNDS: "5"
      SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS: "500"
      SGX_CRL_GOSSIP_INTERVAL_SECS: "10"
  nodeC:
    environment:
      SGX_FORCE_SOFTWARE_KEYS: "1"
      SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS: "6"
      SGX_CRL_OFFLINE_FLUSH_ROUNDS: "5"
      SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS: "500"
      SGX_CRL_GOSSIP_INTERVAL_SECS: "10"
EOF
```

### Terminal 1 - Fresh boot

For full fresh verification, use `down -v`. This deletes old Docker named volumes.

```bash
docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml \
  -f /tmp/cc-crl-offline-fast.yml \
  down -v

docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml \
  -f /tmp/cc-crl-offline-fast.yml \
  up -d --build

docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml \
  -f /tmp/cc-crl-offline-fast.yml \
  ps
```

### Terminal 1 - Approve nodeB/nodeC membership requests

Fresh `down -v` ke baad nodeB/nodeC CA cert bootstrap par ruk sakte hain jab tak nodeA approval YAML me `approve: member` set na ho. Yeh step `Wait for offline APIs` se pehle run karo.

```bash
docker exec sgx-nodeA sh -lc '
  for i in $(seq 1 60); do
    test -f /var/lib/sgx-guardian/nebula/requests/nodeB.yaml &&
    test -f /var/lib/sgx-guardian/nebula/requests/nodeC.yaml &&
    break
    sleep 1
  done
  found=0
  for f in /var/lib/sgx-guardian/nebula/requests/nodeB.yaml /var/lib/sgx-guardian/nebula/requests/nodeC.yaml; do
    [ -f "$f" ] || continue
    found=1
    sed -i "s/^approve:.*/approve: member/" "$f"
    grep -H "approve:" "$f"
  done
  [ "$found" = 1 ] || echo "No pending nodeB/nodeC approval YAML files; approvals may already be consumed."
'
```

If `nodeB` ya `nodeC` wait me phans jaye, nodeA ne stale approved YAML delete karke fresh request recreate ki ho sakti hai. Us case me yeh re-run karo:

```bash
docker exec sgx-nodeA sh -lc '
  ls -la /var/lib/sgx-guardian/nebula/requests
  found=0
  for f in /var/lib/sgx-guardian/nebula/requests/*.yaml; do
    [ -e "$f" ] || continue
    found=1
    sed -i "s/^approve:.*/approve: member/" "$f"
    echo "===== $f"
    cat "$f"
  done
  [ "$found" = 1 ] || echo "No pending approval YAML files; approvals may already be consumed."
'
```

If you do not want to delete old Docker state, use this instead:

```bash
docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml \
  -f /tmp/cc-crl-offline-fast.yml \
  down

docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml \
  -f /tmp/cc-crl-offline-fast.yml \
  up -d --build
```

### Terminal 1 - Wait for offline APIs

```bash
until curl -sf "$A/api/v1/crl/offline/status" >/dev/null; do sleep 2; done
until curl -sf "$B/api/v1/crl/offline/status" >/dev/null; do sleep 2; done
until curl -sf "$C/api/v1/crl/offline/status" >/dev/null; do sleep 2; done

curl -s "$A/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$B/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$C/api/v1/crl/offline/status" | python3 -m json.tool
```

### Terminal 1 - Session helpers and DIDs

Run this in the same Terminal 1. Keep this shell open; functions/vars live in this shell.

```bash
RUN_ID=$(date +%s)

execA(){ docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA "$@"; }
execB(){ docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB "$@"; }
execC(){ docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC "$@"; }

crl_block(){
  docker exec "$1" sh -lc '
    nft delete table inet crloff 2>/dev/null || true
    nft add table inet crloff
    nft "add chain inet crloff input { type filter hook input priority -50; policy accept; }"
    nft "add chain inet crloff output { type filter hook output priority -50; policy accept; }"
    nft add rule inet crloff input tcp dport 50063 drop
    nft add rule inet crloff output tcp dport 50063 drop
  '
}

crl_unblock(){
  docker exec "$1" sh -lc 'nft delete table inet crloff 2>/dev/null || true'
}

crl_unblock sgx-nodeA
crl_unblock sgx-nodeB
crl_unblock sgx-nodeC

DID_A=$(docker exec sgx-nodeA cat /var/lib/sgx-guardian/identity/did.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["did"])')
DID_B=$(docker exec sgx-nodeB cat /var/lib/sgx-guardian/identity/did.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["did"])')
DID_C=$(docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/did.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["did"])')

echo "nodeA DID: $DID_A"
echo "nodeB DID: $DID_B"
echo "nodeC DID: $DID_C"

DID_033="did:guardian:docker-offline-req1-$RUN_ID"
DID_035="did:guardian:docker-offline-req3-$RUN_ID"
DID_037A="did:guardian:docker-offline-missed-a-$RUN_ID"
DID_037B="did:guardian:docker-offline-missed-b-$RUN_ID"
DID_038="did:guardian:docker-offline-conflict-$RUN_ID"
DID_039="did:guardian:docker-offline-park-$RUN_ID"
DID_040="did:guardian:docker-offline-cli-reconcile-$RUN_ID"

export DID_033 DID_035 DID_037A DID_037B DID_038 DID_039 DID_040
```

### Terminal 2 - Logs

Open one of these while testing:

```bash
docker logs --tail=100 -f sgx-nodeC
```

Or for all three in separate terminals:

```bash
docker logs --tail=100 -f sgx-nodeA
docker logs --tail=100 -f sgx-nodeB
docker logs --tail=100 -f sgx-nodeC
```

Expected startup evidence:

```text
CRL-OFFLINE sync starting interval_secs=6 flush_rounds=5 max_retries=unlimited
CRL-GOSSIP engine starting port=50063 interval_secs=10 threshold_pct=80
REST admin API listening on http://0.0.0.0:8443/api/v1
```

---

## PASS Requirement 1 - Locally queue outgoing revocations

Goal: REST-issued local revocation creates local CRL entry plus pending queue file.

### Terminal 1 - Keep only one peer reachable so pending does not immediately meet threshold

```bash
docker stop sgx-nodeB
sleep 3

curl -s -X POST "$C/api/v1/crl/revoke" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID_033"'","reason":"compromised","severity":"high","note":"CRL-033 Docker queue"}' \
  | python3 -m json.tool

curl -s "$C/api/v1/crl/offline/pending" | python3 -m json.tool

docker exec sgx-nodeC sh -lc 'ls -la /var/lib/sgx-guardian/identity/crl/pending'

docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/crl/crl.json \
  | python3 -c 'import json,sys,os; did=os.environ["DID_033"]; d=json.load(sys.stdin); print([{"id":e.get("id"),"revoked_did":e.get("revoked_did"),"propagated":e.get("propagated")} for e in d.get("entries",[]) if e.get("revoked_did")==did])'
```

Expected:

```text
POST /crl/revoke returns status=success.
/offline/pending count >= 1.
pending/ has urn_uuid_<entry-id>.json.
crl.json contains DID_033 with propagated=false.
```

Result:

```text
nodeB was stopped to keep the pending item from immediately reaching the 2-peer propagation threshold:
docker stop sgx-nodeB
→ sgx-nodeB

POST $C/api/v1/crl/revoke returned:
- status: success
- message: CRL entry issued
- entry.id: urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec
- revoked_did: did:guardian:docker-offline-req1-1784726557
- severity: high
- revoker_did: did:guardian:2EkUaYoZZsW1ZVAvrqxek5no4vnKhBahERBqwdLBTV2W
- revoker_role: member
- propagated: false
- sequence: 1
- merkle_root: 717990b3dd3516c70edb0c63a2e7d1ec598b5cb1d1e00baa82e7936db2d6e9a0

GET $C/api/v1/crl/offline/pending returned:
- status: success
- count: 1
- pending[0].id: urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec
- pending[0].revoked_did: did:guardian:docker-offline-req1-1784726557
- pending[0].reason: compromised
- pending[0].severity: high
- pending[0].attempts: 0
- pending[0].queued_at: 2026-07-22T13:22:57.340068996+00:00
- pending[0].last_attempt_at: null
- pending[0].last_error: null
- pending[0].parked: false

Pending directory proof:
- /var/lib/sgx-guardian/identity/crl/pending/urn_uuid_e56e44c8-6799-4790-95e8-fe9783a73cec.json exists on sgx-nodeC

Local CRL proof:
[{'id': 'urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec', 'revoked_did': 'did:guardian:docker-offline-req1-1784726557', 'propagated': False}]
```

Verdict: PASS - Docker nodeC successfully issued a local REST revocation, persisted it in `crl.json` with `propagated:false`, created the pending queue file, and exposed the same item via `/api/v1/crl/offline/pending`.

---

## PASS Requirement 2 - Retry counter and timestamps

Goal: Pending entry tracks `attempts`, fixed `queued_at`, and updated `last_attempt_at`.

### Terminal 1 - Force sync cycles while only nodeA is reachable from nodeC

```bash
curl -s "$C/api/v1/crl/offline/pending" | python3 -m json.tool

curl -s -X POST "$C/api/v1/crl/offline/sync" | python3 -m json.tool
sleep 2
curl -s -X POST "$C/api/v1/crl/offline/sync" | python3 -m json.tool

curl -s "$C/api/v1/crl/offline/pending" | python3 -m json.tool

for f in $(docker exec sgx-nodeC sh -lc 'ls /var/lib/sgx-guardian/identity/crl/pending/*.json 2>/dev/null'); do
  echo "===== $f"
  docker exec sgx-nodeC cat "$f" | python3 -m json.tool
done
```

Expected:

```text
attempts increments from 0 to >= 1.
last_attempt_at becomes non-null.
queued_at remains stable.
parked=false because normal max_retries is unlimited.
```

Result:

```text
Initial GET $C/api/v1/crl/offline/pending:
- count: 1
- id: urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec
- attempts: 0
- queued_at: 2026-07-22T13:22:57.340068996+00:00
- last_attempt_at: null
- last_error: null
- parked: false

First forced sync:
{
    "online": true,
    "reachable_peers": 1,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 1
}

Second forced sync:
{
    "online": true,
    "reachable_peers": 1,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 1
}

Final GET $C/api/v1/crl/offline/pending:
- count: 1
- id: urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec
- attempts: 2
- queued_at: 2026-07-22T13:22:57.340068996+00:00
- last_attempt_at: 2026-07-22T13:26:04.562521739+00:00
- last_error: null
- parked: false

Pending file proof:
/var/lib/sgx-guardian/identity/crl/pending/urn_uuid_e56e44c8-6799-4790-95e8-fe9783a73cec.json showed:
- attempts: 2
- queued_at: 2026-07-22T13:22:57.340068996+00:00
- last_attempt_at: 2026-07-22T13:26:04.562521739+00:00
- last_error: null
- parked: false
- entry.propagated: false
```

Verdict: PASS - retry metadata is tracked and persisted. Two deterministic sync cycles bumped attempts from 0 to 2, populated `last_attempt_at`, kept `queued_at` stable, and retained `parked:false` under unlimited retries.

---

## PASS Requirement 3 - Queue works while isolated; nothing lost

Goal: NodeC can create and retain a queued revocation while gossip reachability is blocked.

### Terminal 1 - Isolate nodeC gossip port but keep REST available

```bash
crl_block sgx-nodeC
sleep 8

curl -s "$C/api/v1/crl/offline/status" | python3 -m json.tool

curl -s -X POST "$C/api/v1/crl/revoke" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID_035"'","reason":"stolen","severity":"high","note":"CRL-035 Docker isolated queue"}' \
  | python3 -m json.tool

curl -s "$C/api/v1/crl/offline/pending" | python3 -m json.tool

docker exec sgx-nodeC sh -lc 'ls -la /var/lib/sgx-guardian/identity/crl/pending'

docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/crl/crl.json \
  | python3 -c 'import json,sys,os; did=os.environ["DID_035"]; d=json.load(sys.stdin); print([{"id":e.get("id"),"revoked_did":e.get("revoked_did"),"propagated":e.get("propagated")} for e in d.get("entries",[]) if e.get("revoked_did")==did])'
```

Expected:

```text
/offline/status shows online=false.
POST /crl/revoke succeeds.
The new DID_035 is present in crl.json with propagated=false.
/offline/pending includes DID_035.
Pending file remains on disk.
```

Result:

```text
Attempt 1 (`2026-07-22`) after `crl_block sgx-nodeC` and `sleep 8`:

Pre-issue status:
- `GET $C/api/v1/crl/offline/status` returned `online: true`
- `pending: 1`
- `sync_cycles: 2`
- `reconnects: 1`
- peer_sync_state had nodeA vector:
  - last_seen_merkle_root: 717990b3dd3516c70edb0c63a2e7d1ec598b5cb1d1e00baa82e7936db2d6e9a0
  - last_seen_sequence: 2
  - last_sync_at: 2026-07-22T13:26:04.562350902+00:00

Interpretation:
- The CRL port block was inserted, but the offline status flag had not yet been refreshed by a new sync cycle. `sync_cycles` was still `2`, so `online:true` is treated as stale for this attempt until a forced `/offline/sync` confirms isolation.

Fresh local revoke during the blocked run succeeded:
- status: success
- entry.id: urn:uuid:e0ecea9b-a20f-494c-95b5-b825f32fd812
- revoked_did: did:guardian:docker-offline-req3-1784726557
- reason: stolen
- severity: high
- revoker_did: did:guardian:2EkUaYoZZsW1ZVAvrqxek5no4vnKhBahERBqwdLBTV2W
- revoker_role: member
- propagated: false
- sequence: 3
- merkle_root: 3898dfc5dd396ccd649029baa0db4ecb3d497f0712e39ba7407d4769ff8f46b6

Pending queue after issue:
- `GET $C/api/v1/crl/offline/pending` returned `count: 2`
- prior Req 1 entry remained present:
  - id: urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec
  - attempts: 2
  - parked: false
- new Req 3 entry was present:
  - id: urn:uuid:e0ecea9b-a20f-494c-95b5-b825f32fd812
  - revoked_did: did:guardian:docker-offline-req3-1784726557
  - attempts: 0
  - queued_at: 2026-07-22T13:27:20.611934258+00:00
  - last_attempt_at: null
  - last_error: null
  - parked: false

Pending directory proof:
- /var/lib/sgx-guardian/identity/crl/pending/urn_uuid_e0ecea9b-a20f-494c-95b5-b825f32fd812.json
- /var/lib/sgx-guardian/identity/crl/pending/urn_uuid_e56e44c8-6799-4790-95e8-fe9783a73cec.json

Local CRL proof for DID_035:
[{'id': 'urn:uuid:e0ecea9b-a20f-494c-95b5-b825f32fd812', 'revoked_did': 'did:guardian:docker-offline-req3-1784726557', 'propagated': False}]

Forced isolation sync while `crl_block sgx-nodeC` remained active:
{
    "online": false,
    "reachable_peers": 0,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 2
}

Post-sync status:
- online: false
- pending: 2
- sync_cycles: 3
- reconnects: 1
- entries_delivered: 0
- entries_fetched: 0

Post-sync pending queue:
- count: 2
- prior Req 1 entry retained:
  - id: urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec
  - revoked_did: did:guardian:docker-offline-req1-1784726557
  - attempts: 2
  - parked: false
- new Req 3 entry retained:
  - id: urn:uuid:e0ecea9b-a20f-494c-95b5-b825f32fd812
  - revoked_did: did:guardian:docker-offline-req3-1784726557
  - attempts: 0
  - last_attempt_at: null
  - parked: false
```

Verdict: PASS - Docker nodeC successfully issued a revocation while CRL gossip was isolated, persisted it locally and in the pending queue, then a forced offline sync confirmed `online:false`, `reachable_peers:0`, and no pending revocation was dropped.

---

## PASS Requirement 4 - Restore pushes queued revocations and dequeues

Goal: When gossip connectivity comes back, NodeC pushes queued entries to peers. Once threshold is met, pending drains.

### Terminal 1 - Restore full mesh and force deterministic cycles

```bash
docker start sgx-nodeB
until curl -sf "$B/api/v1/crl/offline/status" >/dev/null; do sleep 2; done

crl_unblock sgx-nodeC
sleep 8

for i in $(seq 1 8); do
  echo "sync round $i"
  curl -s -X POST "$C/api/v1/crl/offline/sync" | python3 -m json.tool
  sleep 2
done

curl -s "$C/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$C/api/v1/crl/offline/pending" | python3 -m json.tool

execA sgx-pa-cli crl check --did "$DID_033"
execB sgx-pa-cli crl check --did "$DID_033"
execA sgx-pa-cli crl check --did "$DID_035"
execB sgx-pa-cli crl check --did "$DID_035"

docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/crl/crl.json \
  | python3 -c 'import json,sys,os; targets={os.environ["DID_033"],os.environ["DID_035"]}; d=json.load(sys.stdin); print([{"id":e.get("id"),"revoked_did":e.get("revoked_did"),"propagated":e.get("propagated"),"peers_notified":e.get("peers_notified")} for e in d.get("entries",[]) if e.get("revoked_did") in targets])'
```

Expected:

```text
NodeC status online=true.
pending count moves toward 0.
entries_delivered increases.
NodeA and nodeB check commands show revoked=true for DID_033 and DID_035.
NodeC local CRL shows propagated=true and peers_notified has both peer DIDs.
```

Result:

```text
Restore setup:
- `docker start sgx-nodeB` succeeded.
- `crl_unblock sgx-nodeC` removed the CRL gossip block.
- nodeB REST became reachable.

Forced sync rounds from nodeC:
- round 1:
  {
      "online": true,
      "reachable_peers": 2,
      "reconciled": 0,
      "fetched": 0,
      "delivered": 2,
      "pending_remaining": 0
  }
- rounds 2-8:
  - online: true
  - reachable_peers: 2
  - delivered: 0
  - pending_remaining: 0

Post-restore nodeC status:
- online: true
- pending: 0
- sync_cycles: 11
- reconnects: 2
- entries_delivered: 2
- entries_fetched: 0
- peer_sync_state contained both peers:
  - did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy
  - did:guardian:2X1EvM79LKMeUfCfuciVghGh6rig9SqyHcr4BhJyoq8W
  - both at merkle_root: 3898dfc5dd396ccd649029baa0db4ecb3d497f0712e39ba7407d4769ff8f46b6
  - both at sequence: 5

Pending queue after restore:
- `GET $C/api/v1/crl/offline/pending` returned:
  - count: 0
  - pending: []

Peer delivery proof:
- nodeA `crl check --did did:guardian:docker-offline-req1-1784726557` returned `revoked: true`
- nodeB `crl check --did did:guardian:docker-offline-req1-1784726557` returned `revoked: true`
- nodeA `crl check --did did:guardian:docker-offline-req3-1784726557` returned `revoked: true`
- nodeB `crl check --did did:guardian:docker-offline-req3-1784726557` returned `revoked: true`

NodeC canonical CRL proof:
[
  {
    "id": "urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec",
    "revoked_did": "did:guardian:docker-offline-req1-1784726557",
    "propagated": true,
    "peers_notified": [
      "did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy",
      "did:guardian:2X1EvM79LKMeUfCfuciVghGh6rig9SqyHcr4BhJyoq8W"
    ]
  },
  {
    "id": "urn:uuid:e0ecea9b-a20f-494c-95b5-b825f32fd812",
    "revoked_did": "did:guardian:docker-offline-req3-1784726557",
    "propagated": true,
    "peers_notified": [
      "did:guardian:2X1EvM79LKMeUfCfuciVghGh6rig9SqyHcr4BhJyoq8W",
      "did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy"
    ]
  }
]
```

Verdict: PASS - after connectivity restore, nodeC synchronously pushed both queued revocations to reachable peers, the queue drained to zero, `entries_delivered` advanced to 2, both nodeA and nodeB reported the DIDs revoked, and nodeC marked both entries `propagated:true` with both peer DIDs in `peers_notified`.

---

## PASS Requirement 5 - Fetch missed revocations using version vectors

Goal: NodeC misses revocations while partitioned, then fetches them after reconnect by running offline sync/gossip anti-entropy.

### Terminal 1 - Make nodeC miss two NodeA revocations

```bash
crl_block sgx-nodeC
sleep 8

curl -s "$C/api/v1/crl/offline/status" | python3 -m json.tool

curl -s -X POST "$A/api/v1/crl/revoke" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID_037A"'","reason":"compromised","severity":"high","note":"CRL-037 Docker missed A"}' \
  | python3 -m json.tool

curl -s -X POST "$A/api/v1/crl/revoke" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID_037B"'","reason":"lost","severity":"high","note":"CRL-037 Docker missed B"}' \
  | python3 -m json.tool

# Before reconnect, nodeC should not know the two fresh DIDs yet.
execC sgx-pa-cli crl check --did "$DID_037A"
execC sgx-pa-cli crl check --did "$DID_037B"
```

### Terminal 1 - Reconnect nodeC and let it fetch

```bash
crl_unblock sgx-nodeC
sleep 12

# Strict automatic proof: first check after wait, before manual gossip trigger.
execC sgx-pa-cli crl check --did "$DID_037A"
execC sgx-pa-cli crl check --did "$DID_037B"

# Deterministic accelerator if automatic cycle is slow:
for i in $(seq 1 8); do
  echo "nodeC offline-sync fetch round $i"
  curl -s -X POST "$C/api/v1/crl/offline/sync" | python3 -m json.tool
  sleep 2
done

execC sgx-pa-cli crl check --did "$DID_037A"
execC sgx-pa-cli crl check --did "$DID_037B"

curl -s "$C/api/v1/crl/offline/status" | python3 -m json.tool

docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/crl/sync_state.json \
  | python3 -m json.tool
```

Expected:

```text
Before reconnect, nodeC check shows revoked=false for DID_037A/DID_037B.
After reconnect/sync, nodeC check shows revoked=true for both.
NodeC /offline/status shows peer_sync_state with last_seen_merkle_root, last_seen_sequence, last_sync_at.
sync_state.json exists and contains per-peer version-vector state.
entries_fetched should increase when merge happens through offline sync.
```

Result:

```text
Partition setup:
- `crl_block sgx-nodeC` was applied.
- Initial status after block still showed `online: true`; this is treated as a stale status snapshot because no fresh offline cycle was forced before issuing the missed revocations.

NodeA source revocations while nodeC was blocked:
- DID_037A:
  - id: urn:uuid:777d5e20-191f-4b2c-9e05-e74ccc2ba9a7
  - revoked_did: did:guardian:docker-offline-missed-a-1784726557
  - reason: compromised
  - severity: high
  - revoker_did: did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy
  - revoker_role: owner
  - propagated: false
  - sequence: 6
  - merkle_root: 79e73444aebd58e8c2a2844bd89bc3497ca489a50ef19fc74f9422b3bd775a38
- DID_037B:
  - id: urn:uuid:d6e44f5f-cc56-4c1c-b59a-640f8198604c
  - revoked_did: did:guardian:docker-offline-missed-b-1784726557
  - reason: lost
  - severity: high
  - revoker_did: did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy
  - revoker_role: owner
  - propagated: false
  - sequence: 7
  - merkle_root: fbb57667fb2b037c26e6bbd3f2edb22f57b3906f6b2c7debcf46c1cbec0e9798

Before reconnect, nodeC did not know the two fresh DIDs:
- `execC sgx-pa-cli crl check --did "$DID_037A"` returned:
  - entry: null
  - revoked: false
- `execC sgx-pa-cli crl check --did "$DID_037B"` returned:
  - entry: null
  - revoked: false

Reconnect proof:
- `crl_unblock sgx-nodeC`
- after `sleep 12`, before any manual gossip trigger, nodeC checks already showed both missed revocations fetched:
  - DID_037A:
    - id: urn:uuid:777d5e20-191f-4b2c-9e05-e74ccc2ba9a7
    - revoked: true
    - reason: compromised
    - propagated: true
    - peers_notified:
      - did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy
      - did:guardian:2X1EvM79LKMeUfCfuciVghGh6rig9SqyHcr4BhJyoq8W
  - DID_037B:
    - id: urn:uuid:d6e44f5f-cc56-4c1c-b59a-640f8198604c
    - revoked: true
    - reason: lost
    - propagated: true
    - peers_notified:
      - did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy
      - did:guardian:2X1EvM79LKMeUfCfuciVghGh6rig9SqyHcr4BhJyoq8W

Manual deterministic cycles after convergence:
- eight `POST $C/api/v1/crl/offline/sync` rounds returned:
  - online: true
  - reachable_peers: 2
  - reconciled: 0
  - fetched: 0
  - delivered: 0
  - pending_remaining: 0

Final nodeC status:
- online: true
- pending: 0
- sync_cycles: 19
- reconnects: 2
- entries_delivered: 2
- entries_fetched: 0
- peer_sync_state contained both peers at:
  - last_seen_merkle_root: fbb57667fb2b037c26e6bbd3f2edb22f57b3906f6b2c7debcf46c1cbec0e9798
  - last_seen_sequence: 8
  - last_sync_at:
    - nodeA: 2026-07-22T13:31:48.326336604+00:00
    - nodeB: 2026-07-22T13:31:48.322831911+00:00

sync_state.json proof:
{
    "did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy": {
        "last_seen_merkle_root": "fbb57667fb2b037c26e6bbd3f2edb22f57b3906f6b2c7debcf46c1cbec0e9798",
        "last_seen_sequence": 8,
        "last_sync_at": "2026-07-22T13:31:48.326336604+00:00"
    },
    "did:guardian:2X1EvM79LKMeUfCfuciVghGh6rig9SqyHcr4BhJyoq8W": {
        "last_seen_merkle_root": "fbb57667fb2b037c26e6bbd3f2edb22f57b3906f6b2c7debcf46c1cbec0e9798",
        "last_seen_sequence": 8,
        "last_sync_at": "2026-07-22T13:31:48.322831911+00:00"
    }
}

Observation:
- `entries_fetched` stayed `0` because by the time manual deterministic cycles were run, nodeC had already converged after reconnect. The behavioral fetch proof is the before/after nodeC CRL check plus updated per-peer version-vector state.
```

Verdict: PASS - Docker nodeC missed two nodeA revocations while its CRL gossip path was blocked, reported both as `revoked:false` before reconnect, then automatically learned both after reconnect without manual pull; `sync_state.json` recorded updated per-peer merkle-root/sequence/timestamp version vectors.

---

## PASS Requirement 6 - Deterministic conflict resolution and root convergence

Goal: NodeB and NodeC independently revoke the same DID while partitioned. After reconnect, all nodes converge to the same winner and Merkle root.

Current implementation note:

- `src/crl/gossip/store.rs::incoming_wins` uses timestamp-based last-writer-wins: later timestamp wins.
- In this test, nodeB issues first (`reason=compromised`), nodeC issues later (`reason=stolen`), so expected final winner is nodeC's later `stolen` entry.

### Terminal 1 - Isolate B and C from gossip, issue conflicting revocations

```bash
crl_block sgx-nodeB
crl_block sgx-nodeC
sleep 8

curl -s "$B/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$C/api/v1/crl/offline/status" | python3 -m json.tool

curl -s -X POST "$B/api/v1/crl/revoke" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID_038"'","reason":"compromised","severity":"high","note":"CRL-038 Docker B first"}' \
  | python3 -m json.tool

sleep 3

curl -s -X POST "$C/api/v1/crl/revoke" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID_038"'","reason":"stolen","severity":"high","note":"CRL-038 Docker C later"}' \
  | python3 -m json.tool
```

### Terminal 1 - Reconnect and converge

```bash
crl_unblock sgx-nodeB
crl_unblock sgx-nodeC
sleep 8

for i in $(seq 1 12); do
  echo "convergence round $i"
  curl -s -X POST "$A/api/v1/crl/offline/sync" | python3 -m json.tool
  curl -s -X POST "$B/api/v1/crl/offline/sync" | python3 -m json.tool
  curl -s -X POST "$C/api/v1/crl/offline/sync" | python3 -m json.tool
  sleep 2
done

for c in sgx-nodeA sgx-nodeB sgx-nodeC; do
  echo "=== $c root ==="
  docker exec "$c" cat /var/lib/sgx-guardian/identity/crl/crl.json \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print({"sequence":d.get("sequence"),"merkle_root":d.get("merkle_root")})'
done

for c in sgx-nodeA sgx-nodeB sgx-nodeC; do
  echo "=== $c conflict entry ==="
  docker exec "$c" cat /var/lib/sgx-guardian/identity/crl/crl.json \
    | python3 -c 'import json,sys,os; did=os.environ["DID_038"]; d=json.load(sys.stdin); print([{"id":e.get("id"),"reason":e.get("reason"),"timestamp":e.get("timestamp"),"revoker_did":e.get("revoker_did"),"propagated":e.get("propagated")} for e in d.get("entries",[]) if e.get("revoked_did")==did])'
done
```

Expected:

```text
All three nodes have identical merkle_root after convergence.
All three nodes show exactly one entry for DID_038.
Winning entry reason is stolen because nodeC issued later.
No split-brain remains.
```

Result:

```text
Partition setup:
- `crl_block sgx-nodeB`
- `crl_block sgx-nodeC`

Pre-conflict status:
- nodeB status showed:
  - online: false
  - pending: 0
  - sync_cycles: 0
- nodeC status still showed stale `online:true` with prior sync state, but nodeC gossip was then blocked before the local conflicting revoke was issued.

Conflicting revocation issued first on nodeB:
- id: urn:uuid:fb9cd9df-dd30-4d5a-b1ef-c3fcb5d7c895
- revoked_did: did:guardian:docker-offline-conflict-1784726557
- reason: compromised
- timestamp: 2026-07-22T13:33:40.093832937+00:00
- revoker_did: did:guardian:2X1EvM79LKMeUfCfuciVghGh6rig9SqyHcr4BhJyoq8W
- revoker_role: member
- propagated: false
- sequence: 7
- merkle_root: 0443fefe81c9bcc72051fb40ab6957a0d6a49aa1107024b3511e7cf5bebe8010

Conflicting revocation issued later on nodeC:
- id: urn:uuid:40e30821-2719-45a2-8675-120c26f653db
- revoked_did: did:guardian:docker-offline-conflict-1784726557
- reason: stolen
- timestamp: 2026-07-22T13:33:45.281337629+00:00
- revoker_did: did:guardian:2EkUaYoZZsW1ZVAvrqxek5no4vnKhBahERBqwdLBTV2W
- revoker_role: member
- propagated: false
- sequence: 9
- merkle_root: 3df09141a682add9538ae2a5e0e2fd2e587b083d98d85a01295af83974d82c67

Reconnect/convergence cycles:
- `crl_unblock sgx-nodeB`
- `crl_unblock sgx-nodeC`
- 12 convergence rounds were forced across nodeA, nodeB, and nodeC.
- Round 1 showed delivery activity:
  - nodeA delivered: 2, pending_remaining: 0
  - nodeB pending_remaining: 1
  - nodeC delivered: 1, pending_remaining: 0
- Rounds 2-12 stayed online with reachable_peers: 2 on all nodes.

Final root convergence:
- nodeA:
  - sequence: 12
  - merkle_root: 3df09141a682add9538ae2a5e0e2fd2e587b083d98d85a01295af83974d82c67
- nodeB:
  - sequence: 10
  - merkle_root: 3df09141a682add9538ae2a5e0e2fd2e587b083d98d85a01295af83974d82c67
- nodeC:
  - sequence: 11
  - merkle_root: 3df09141a682add9538ae2a5e0e2fd2e587b083d98d85a01295af83974d82c67

Final conflict winner on all three nodes:
- nodeA:
  - id: urn:uuid:40e30821-2719-45a2-8675-120c26f653db
  - reason: stolen
  - timestamp: 2026-07-22T13:33:45.281337629+00:00
  - revoker_did: did:guardian:2EkUaYoZZsW1ZVAvrqxek5no4vnKhBahERBqwdLBTV2W
  - propagated: true
- nodeB:
  - id: urn:uuid:40e30821-2719-45a2-8675-120c26f653db
  - reason: stolen
  - timestamp: 2026-07-22T13:33:45.281337629+00:00
  - revoker_did: did:guardian:2EkUaYoZZsW1ZVAvrqxek5no4vnKhBahERBqwdLBTV2W
  - propagated: true
- nodeC:
  - id: urn:uuid:40e30821-2719-45a2-8675-120c26f653db
  - reason: stolen
  - timestamp: 2026-07-22T13:33:45.281337629+00:00
  - revoker_did: did:guardian:2EkUaYoZZsW1ZVAvrqxek5no4vnKhBahERBqwdLBTV2W
  - propagated: true

Observation:
- nodeB's cycle output kept `pending_remaining: 1` during convergence. This should be inspected later as pending cleanup for the losing local conflict entry, but it did not cause split-brain: all three canonical CRLs converged to the same root and same winning entry.
```

Verdict: PASS - deterministic conflict resolution converged across the Docker cohort. The later nodeC `stolen` entry won on every node, all three nodes reported the same final Merkle root, and no split-brain remained.

---

## PASS Requirement 7 - Retry budget, parking, and restart persistence

Goal: With `SGX_CRL_OFFLINE_MAX_RETRIES=2`, an undelivered pending entry becomes `parked:true`, stays on disk, and survives daemon restart.

Important Docker adaptation:

- Fully offline/no-reachable-peer cycles return early in current code and do not increment attempts.
- To test parking, keep exactly one peer reachable so flush cycles are attempted but propagation threshold cannot be met.
- In 3-node cohort, threshold is 2 peer acks. If nodeA can reach only nodeB while nodeC is stopped, attempts increment but `propagated` remains false.

### Terminal 1 - Recreate cohort with max retries enabled

```bash
cat >/tmp/cc-crl-offline-park.yml <<'EOF'
services:
  nodeA:
    environment:
      SGX_FORCE_SOFTWARE_KEYS: "1"
      SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS: "6"
      SGX_CRL_OFFLINE_MAX_RETRIES: "2"
      SGX_CRL_OFFLINE_FLUSH_ROUNDS: "5"
      SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS: "500"
      SGX_CRL_GOSSIP_INTERVAL_SECS: "10"
  nodeB:
    environment:
      SGX_FORCE_SOFTWARE_KEYS: "1"
      SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS: "6"
      SGX_CRL_OFFLINE_MAX_RETRIES: "2"
      SGX_CRL_OFFLINE_FLUSH_ROUNDS: "5"
      SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS: "500"
      SGX_CRL_GOSSIP_INTERVAL_SECS: "10"
  nodeC:
    environment:
      SGX_FORCE_SOFTWARE_KEYS: "1"
      SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS: "6"
      SGX_CRL_OFFLINE_MAX_RETRIES: "2"
      SGX_CRL_OFFLINE_FLUSH_ROUNDS: "5"
      SGX_CRL_OFFLINE_PROBE_TIMEOUT_MS: "500"
      SGX_CRL_GOSSIP_INTERVAL_SECS: "10"
EOF

docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml \
  -f /tmp/cc-crl-offline-park.yml \
  up -d --force-recreate

until curl -sf "$A/api/v1/crl/offline/status" >/dev/null; do sleep 2; done
until curl -sf "$B/api/v1/crl/offline/status" >/dev/null; do sleep 2; done
until curl -sf "$C/api/v1/crl/offline/status" >/dev/null; do sleep 2; done

curl -s "$A/api/v1/crl/offline/status" | python3 -m json.tool
```

### Terminal 1 - Keep nodeC stopped; issue on nodeA; force attempts

```bash
docker stop sgx-nodeC
sleep 3

curl -s -X POST "$A/api/v1/crl/revoke" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID_039"'","reason":"policy_violation","severity":"high","note":"CRL-039 Docker park"}' \
  | python3 -m json.tool

for i in $(seq 1 4); do
  echo "park attempt cycle $i"
  curl -s -X POST "$A/api/v1/crl/offline/sync" | python3 -m json.tool
  sleep 2
done

curl -s "$A/api/v1/crl/offline/pending" | python3 -m json.tool

docker exec sgx-nodeA sh -lc 'ls -la /var/lib/sgx-guardian/identity/crl/pending'
for f in $(docker exec sgx-nodeA sh -lc 'ls /var/lib/sgx-guardian/identity/crl/pending/*.json 2>/dev/null'); do
  echo "===== $f"
  docker exec sgx-nodeA cat "$f" | python3 -m json.tool
done
```

### Terminal 1 - Restart persistence proof

```bash
docker restart sgx-nodeA
until curl -sf "$A/api/v1/crl/offline/pending" >/dev/null; do sleep 2; done

curl -s "$A/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$A/api/v1/crl/offline/pending" | python3 -m json.tool

docker exec sgx-nodeA sh -lc 'ls -la /var/lib/sgx-guardian/identity/crl/pending'
```

Expected:

```text
/offline/status shows max_retries=2.
Pending entry for DID_039 reaches attempts >= 2 and parked=true.
Pending file remains on disk.
After docker restart sgx-nodeA, /offline/pending still lists the parked item.
```

Cleanup after proof:

```bash
docker start sgx-nodeC
until curl -sf "$C/api/v1/crl/offline/status" >/dev/null; do sleep 2; done
```

Result:

```text
Max-retry cohort recreate:
- `docker compose ... -f /tmp/cc-crl-offline-park.yml up -d --force-recreate` succeeded.
- nodeA, nodeB, and nodeC REST endpoints became reachable.

Initial nodeA status:
{
    "enabled": true,
    "online": false,
    "sync_interval_secs": 6,
    "flush_rounds": 5,
    "max_retries": 2,
    "pending": 0,
    "sync_cycles": 0,
    "reconnects": 0,
    "entries_delivered": 0,
    "entries_fetched": 0,
    "peer_sync_state": {}
}

Parking setup:
- `docker stop sgx-nodeC` succeeded.
- nodeA kept nodeB reachable, so sync attempts could happen while the 2-peer propagation threshold could not be met.

NodeA source revocation:
- id: urn:uuid:4e2c478e-811a-44fd-ada3-a6a641488ea6
- revoked_did: did:guardian:docker-offline-park-1784726557
- reason: policy_violation
- severity: high
- revoker_did: did:guardian:6c3w7HEr6Qbd4JcLkoKBCSZxPP1gsxS2icFwsyTqRzSy
- revoker_role: owner
- propagated: false
- sequence: 13
- merkle_root: 1cdd28e000cc1953a8b3ee701a34cd02317b4ebf6f2bd05649576412ecf9828b

Forced park-attempt cycles:
- cycles 1-4 each returned:
  - online: true
  - reachable_peers: 1
  - reconciled: 0
  - fetched: 0
  - delivered: 0
  - pending_remaining: 1

Pending REST proof before restart:
{
    "count": 1,
    "pending": [
        {
            "attempts": 2,
            "id": "urn:uuid:4e2c478e-811a-44fd-ada3-a6a641488ea6",
            "last_attempt_at": "2026-07-22T13:37:21.400898735+00:00",
            "last_error": null,
            "parked": true,
            "queued_at": "2026-07-22T13:36:48.299097921+00:00",
            "reason": "policy_violation",
            "revoked_did": "did:guardian:docker-offline-park-1784726557",
            "severity": "high"
        }
    ],
    "status": "success"
}

Pending file proof before restart:
- /var/lib/sgx-guardian/identity/crl/pending/urn_uuid_4e2c478e-811a-44fd-ada3-a6a641488ea6.json existed.
- File content showed:
  - attempts: 2
  - queued_at: 2026-07-22T13:36:48.299097921+00:00
  - last_attempt_at: 2026-07-22T13:37:21.400898735+00:00
  - last_error: null
  - parked: true
  - entry.propagated: false

Restart persistence:
- `docker restart sgx-nodeA` succeeded.
- After restart, nodeA status returned:
  - enabled: true
  - sync_interval_secs: 6
  - flush_rounds: 5
  - max_retries: 2
  - pending: 1
- After restart, `/offline/pending` still returned the same parked item:
  - id: urn:uuid:4e2c478e-811a-44fd-ada3-a6a641488ea6
  - attempts: 2
  - last_attempt_at: 2026-07-22T13:37:21.400898735+00:00
  - parked: true
  - revoked_did: did:guardian:docker-offline-park-1784726557
- Pending directory still contained:
  - urn_uuid_4e2c478e-811a-44fd-ada3-a6a641488ea6.json
```

Verdict: PASS - with `SGX_CRL_OFFLINE_MAX_RETRIES=2`, the undelivered revocation reached `attempts:2`, became `parked:true`, stayed on disk, and remained listed through REST after a nodeA restart. This proves retry budget, never-drop parking, and restart persistence in Docker.

---

## PASS Requirement 8 - Self-reconcile covers CLI-issued local revocations

Goal: CLI-issued revocation, even without REST handler enqueue, is reconciled from local `crl.json` into pending queue.

### Terminal 1 - Issue via CLI on isolated nodeC, delete any pending file, force reconcile

```bash
crl_block sgx-nodeC
sleep 8

execC sgx-pa-cli crl revoke \
  --did "$DID_040" \
  --reason policy_violation \
  --severity high \
  --note "CRL-040 Docker CLI self-reconcile"

ID_040=$(docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/crl/crl.json \
  | python3 -c 'import json,sys,os; did=os.environ["DID_040"]; d=json.load(sys.stdin); print(next(e["id"] for e in d.get("entries",[]) if e.get("revoked_did")==did))')

SAFE_ID_040=$(printf '%s' "$ID_040" | tr ':/' '_')

echo "ID_040=$ID_040"
echo "SAFE_ID_040=$SAFE_ID_040"

# Delete pending file if any exists, so reconcile has to recreate it from crl.json.
docker exec sgx-nodeC sh -lc "rm -f /var/lib/sgx-guardian/identity/crl/pending/$SAFE_ID_040.json"

curl -s -X POST "$C/api/v1/crl/offline/sync" | python3 -m json.tool
curl -s "$C/api/v1/crl/offline/pending" | python3 -m json.tool

docker exec sgx-nodeC sh -lc "ls -la /var/lib/sgx-guardian/identity/crl/pending | grep '$SAFE_ID_040'"
```

Expected:

```text
CLI revoke succeeds.
Forced /offline/sync while nodeC is isolated returns reconciled >= 1.
/offline/pending includes DID_040.
Pending file $SAFE_ID_040.json exists again.
```

Cleanup:

```bash
crl_unblock sgx-nodeC
```

Result:

```text
Setup:
- `docker start sgx-nodeC` succeeded.
- nodeC REST became reachable.
- `crl_unblock sgx-nodeC` then `crl_block sgx-nodeC` were run.
- status before CLI issue:
  - enabled: true
  - online: false
  - sync_interval_secs: 6
  - flush_rounds: 5
  - max_retries: 2
  - pending: 0
  - sync_cycles: 0

CLI revoke:
execC sgx-pa-cli crl revoke --did "$DID_040" --reason policy_violation --severity high --note "CRL-040 Docker CLI self-reconcile"
→ ✅ CRL entry issued: urn:uuid:0dfbe8b8-330c-41df-99c2-d264e45d8a94 (sequence=12, root=bcccd96a9f7b9fcc23c8368cc89ca5ff5ddbd1270b6a9945cbf5723da1dcc38c)

Extracted IDs:
- ID_040=urn:uuid:0dfbe8b8-330c-41df-99c2-d264e45d8a94
- SAFE_ID_040=urn_uuid_0dfbe8b8-330c-41df-99c2-d264e45d8a94

The pending file was manually deleted before reconcile:
- /var/lib/sgx-guardian/identity/crl/pending/urn_uuid_0dfbe8b8-330c-41df-99c2-d264e45d8a94.json

Forced offline sync:
{
    "online": false,
    "reachable_peers": 0,
    "reconciled": 1,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 1
}

Pending REST proof after reconcile:
{
    "count": 1,
    "pending": [
        {
            "attempts": 0,
            "id": "urn:uuid:0dfbe8b8-330c-41df-99c2-d264e45d8a94",
            "last_attempt_at": null,
            "last_error": null,
            "parked": false,
            "queued_at": "2026-07-22T13:40:36.366973705+00:00",
            "reason": "policy_violation",
            "revoked_did": "did:guardian:docker-offline-cli-reconcile-1784726557",
            "severity": "high"
        }
    ],
    "status": "success"
}

Pending file proof after reconcile:
- /var/lib/sgx-guardian/identity/crl/pending/urn_uuid_0dfbe8b8-330c-41df-99c2-d264e45d8a94.json exists again.
```

Verdict: PASS - Docker nodeC issued a revocation through the CLI path, the pending file was manually removed, and a forced offline sync recreated it from local `crl.json` with `reconciled:1`. This proves self-reconcile covers CLI-issued local revocations.

---

# API Verification

## PASS API 1 - GET `/api/v1/crl/offline/status`

### Terminal 1

```bash
curl -s "$A/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$B/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$C/api/v1/crl/offline/status" | python3 -m json.tool
```

Expected shape:

```json
{
  "enabled": true,
  "online": true,
  "sync_interval_secs": 6,
  "flush_rounds": 5,
  "max_retries": 0,
  "pending": 0,
  "sync_cycles": 1,
  "reconnects": 1,
  "entries_delivered": 0,
  "entries_fetched": 0,
  "peer_sync_state": {}
}
```

Result:

```text
nodeA:
{
    "enabled": true,
    "online": false,
    "sync_interval_secs": 6,
    "flush_rounds": 5,
    "max_retries": 0,
    "pending": 0,
    "sync_cycles": 0,
    "reconnects": 0,
    "entries_delivered": 0,
    "entries_fetched": 0,
    "peer_sync_state": {}
}

nodeB:
{
    "enabled": true,
    "online": false,
    "sync_interval_secs": 6,
    "flush_rounds": 5,
    "max_retries": 0,
    "pending": 0,
    "sync_cycles": 0,
    "reconnects": 0,
    "entries_delivered": 0,
    "entries_fetched": 0,
    "peer_sync_state": {}
}

nodeC:
{
    "enabled": true,
    "online": false,
    "sync_interval_secs": 6,
    "flush_rounds": 5,
    "max_retries": 0,
    "pending": 0,
    "sync_cycles": 0,
    "reconnects": 0,
    "entries_delivered": 0,
    "entries_fetched": 0,
    "peer_sync_state": {}
}
```

Verdict: PASS - all three Docker nodes return the expected offline status shape with config, counters, pending count, and peer sync state.

---

## PASS API 2 - GET `/api/v1/crl/offline/pending`

### Terminal 1

```bash
curl -s "$C/api/v1/crl/offline/pending" | python3 -m json.tool
```

Expected shape:

```json
{
  "status": "success",
  "count": 1,
  "pending": [
    {
      "id": "urn:uuid:...",
      "revoked_did": "did:guardian:...",
      "reason": "compromised",
      "severity": "high",
      "attempts": 1,
      "queued_at": "2026-...",
      "last_attempt_at": "2026-...",
      "last_error": null,
      "parked": false
    }
  ]
}
```

Result:

```json
{
    "count": 1,
    "pending": [
        {
            "attempts": 0,
            "id": "urn:uuid:e56e44c8-6799-4790-95e8-fe9783a73cec",
            "last_attempt_at": null,
            "last_error": null,
            "parked": false,
            "queued_at": "2026-07-22T13:22:57.340068996+00:00",
            "reason": "compromised",
            "revoked_did": "did:guardian:docker-offline-req1-1784726557",
            "severity": "high"
        }
    ],
    "status": "success"
}
```

Verdict: PASS - endpoint returned the expected pending-list shape with count, revocation identity, retry metadata, timestamps, error field, and parked state.

---

## PASS API 3 - POST `/api/v1/crl/offline/sync`

### Terminal 1

```bash
curl -s -X POST "$C/api/v1/crl/offline/sync" | python3 -m json.tool
```

Expected shape:

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

Note:

- Steady-state me `fetched=0` aur `delivered=0` valid hain.
- Pending entry available ho to `delivered` tab increment hota hai jab local CRL me `propagated=true` ho jaye.

Result:

```json
First forced sync:
{
    "online": true,
    "reachable_peers": 1,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 1
}

Second forced sync:
{
    "online": true,
    "reachable_peers": 1,
    "reconciled": 0,
    "fetched": 0,
    "delivered": 0,
    "pending_remaining": 1
}
```

Verdict: PASS - endpoint returned the deterministic cycle summary with online state, reachable peer count, reconcile/fetch/delivery counters, and remaining pending count.

---

## Test Tag Mapping

| Tag | Docker proof | Section |
|---|---|---|
| CRL-033 | Local pending queue persists | Requirement 1 |
| CRL-034 | Retry metadata | Requirement 2 |
| CRL-035 | Isolated queue, no loss | Requirement 3 |
| CRL-036 | Reconnect push + dequeue | Requirement 4 |
| CRL-037 | Fetch missed revocations | Requirement 5 |
| CRL-038 | Deterministic conflict convergence | Requirement 6 |
| CRL-039 | Retry budget parking + restart persistence | Requirement 7 |
| CRL-040 | CLI self-reconcile | Requirement 8 |
| CRL-041 | Offline status API | API 1 |
| CRL-042 | Offline pending API | API 2 |
| CRL-043 | Offline sync API | API 3 |

---

## Debug Commands

```bash
# Container status
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

# Offline/gossip startup logs
docker logs sgx-nodeA | grep -E 'CRL-OFFLINE|CRL-GOSSIP' | tail -40
docker logs sgx-nodeB | grep -E 'CRL-OFFLINE|CRL-GOSSIP' | tail -40
docker logs sgx-nodeC | grep -E 'CRL-OFFLINE|CRL-GOSSIP' | tail -40

# REST status
curl -s "$A/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$B/api/v1/crl/offline/status" | python3 -m json.tool
curl -s "$C/api/v1/crl/offline/status" | python3 -m json.tool

# Pending directories
docker exec sgx-nodeA sh -lc 'ls -la /var/lib/sgx-guardian/identity/crl/pending 2>/dev/null || true'
docker exec sgx-nodeB sh -lc 'ls -la /var/lib/sgx-guardian/identity/crl/pending 2>/dev/null || true'
docker exec sgx-nodeC sh -lc 'ls -la /var/lib/sgx-guardian/identity/crl/pending 2>/dev/null || true'

# Version vectors
docker exec sgx-nodeA cat /var/lib/sgx-guardian/identity/crl/sync_state.json | python3 -m json.tool
docker exec sgx-nodeB cat /var/lib/sgx-guardian/identity/crl/sync_state.json | python3 -m json.tool
docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/crl/sync_state.json | python3 -m json.tool

# Force deterministic cycles
curl -s -X POST "$A/api/v1/crl/offline/sync" | python3 -m json.tool
curl -s -X POST "$B/api/v1/crl/offline/sync" | python3 -m json.tool
curl -s -X POST "$C/api/v1/crl/offline/sync" | python3 -m json.tool

# Manual routine gossip trigger, useful if offline-sync stalls
curl -s -X POST "$A/api/v1/crl/gossip/trigger" | python3 -m json.tool
curl -s -X POST "$B/api/v1/crl/gossip/trigger" | python3 -m json.tool
curl -s -X POST "$C/api/v1/crl/gossip/trigger" | python3 -m json.tool

# Clear temporary partition rules
crl_unblock sgx-nodeA
crl_unblock sgx-nodeB
crl_unblock sgx-nodeC

# Restart full cohort without deleting volumes
docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml \
  -f /tmp/cc-crl-offline-fast.yml \
  restart
```

---

## Known Issue Placeholders

### Issue 1 - Fill during Docker testing

```text
Symptoms:

Root cause:

Likely file/function:

Fix / retry:
```
