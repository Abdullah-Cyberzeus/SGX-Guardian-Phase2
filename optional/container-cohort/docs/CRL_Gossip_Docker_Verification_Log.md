# CRL Gossip Protocol - Docker Verification Log
**Environment:** Docker container cohort (WSL2) | **Date:** 2026-07-17 | **Tester:** Asad Ali
**Test tag:** CRL-series (CRL-011 - CRL-021) | **Plan:** `docs/CRL_Gossip_Protocol_Complete_Plan.md`

---

## Task Description

> Implement epidemic-style gossip protocol for decentralized CRL propagation without central authority. Each Guardian maintains local CRL copy. Periodically, Guardian selects a peer and exchanges CRL updates. Peer merges received revocations into local CRL, then forwards to other peers. Uses probabilistic flooding with anti-entropy mechanisms. Track which peers received each revocation in `peers_notified`. Mark CRL entry as `propagated` after threshold (80% of Circle). Achieves eventual consistency across all Circle members even with partitions and restarts.

---

## Docker Notes

- Saari commands host terminal se chalai gayin.
- `sgx-nodeA` = Owner / CA / lighthouse, REST `http://localhost:18443`
- `sgx-nodeB` = Member, REST `http://localhost:28443`
- `sgx-nodeC` = Member, REST `http://localhost:38443`
- `sgx-pa-cli` ko containers me chalate waqt `-e SGX_FORCE_SOFTWARE_KEYS=1` use kiya gaya.
- Docker topology me `nodeA` CA/lighthouse bhi hai, is liye strict board-style "source node fully offline before any relay bootstrap" scenario ko Docker-adapted form me verify kiya gaya.

---

## Requirements Checklist (9 Requirements)

- [x] Requirement 1 - Each Guardian maintains local CRL copy, no central authority
- [x] Requirement 2 - Periodic rounds every 1-5 minutes with random peer selection
- [x] Requirement 3 - Peer merges received revocations into local CRL
- [x] Requirement 4 - Forwards to other peers (transitive epidemic relay)
- [x] Requirement 5 - Probabilistic flooding plus anti-entropy mechanisms
- [x] Requirement 6 - `peers_notified` tracking per entry
- [x] Requirement 7 - `propagated = true` at 80% Circle threshold
- [x] Requirement 8 - Eventual consistency across network partitions
- [x] Requirement 9 - Decentralized behavior without any central authority

---

## API Checklist (4 Gossip APIs)

- [x] API 1 - GET `/api/v1/crl/gossip/status`
- [x] API 2 - POST `/api/v1/crl/gossip/trigger`
- [x] API 3 - Security: tampered entry rejected (signature re-verification)
- [ ] API 4 - Revoked peer excluded both directions

API 4 note:
Exclusion behavior passed, but full restore/unrevoke convergence did not complete on every peer in Docker. Details are recorded in the API 4 section below.

---

## Session Bootstrap

**Commands:**
```bash
# Host shell
NODEA_DID=$(docker exec sgx-nodeA cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")
NODEB_DID=$(docker exec sgx-nodeB cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")
NODEC_DID=$(docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")

echo "$NODEA_DID"
echo "$NODEB_DID"
echo "$NODEC_DID"
```

**Observed:**
```text
nodeA DID: did:guardian:CVruXwNeHL63shHrfCQaUjk7kq9BGnj2WcRXF3PjrkzZ
nodeB DID: did:guardian:9TiAZcjJMMEPA6r337Wy4UnWFofRePsd4T2SRi4VXq5o
nodeC DID: did:guardian:sVNoXSb9wHaCfSkH6jtMLbFE6QXJoJG8H4vtAayKEUT
```

---

## Requirement 1 - Each Guardian maintains local CRL copy, no central authority

**Commands:**
```bash
# nodeA
docker exec sgx-nodeA sh -lc 'ss -ltn | grep 50063; grep -a "CRL gossip engine started" /var/log/sgx-guardian/audit-*.log | tail -1; pgrep -f sgx_guardian_client'

# nodeB
docker exec sgx-nodeB sh -lc 'ss -ltn | grep 50063; grep -a "CRL gossip engine started" /var/log/sgx-guardian/audit-*.log | tail -1; pgrep -f sgx_guardian_client'

# nodeC
docker exec sgx-nodeC sh -lc 'ss -ltn | grep 50063; grep -a "CRL gossip engine started" /var/log/sgx-guardian/audit-*.log | tail -1; pgrep -f sgx_guardian_client'
```

**Observed:**
```text
nodeA: LISTEN 0.0.0.0:50063, audit "CRL gossip engine started", sgx_guardian_client running
nodeB: LISTEN 0.0.0.0:50063, audit "CRL gossip engine started", sgx_guardian_client running
nodeC: LISTEN 0.0.0.0:50063, audit "CRL gossip engine started", sgx_guardian_client running
```

**Verdict:** PASS - tino nodes independent gossip listener run kar rahe thay.

---

## Requirement 2 - Periodic rounds every 1-5 minutes with random peer selection

**Commands:**
```bash
# nodeA
docker exec sgx-nodeA sh -lc 'grep -a "CRL gossip round" /var/log/sgx-guardian/audit-nodeA.log | tail -6'
```

**Observed:**
```text
nodeA rounds seen at timestamps:
1784270796
1784270860
1784270914
1784270972
1784271036
1784271090

Peers rotated between:
- nodeC
- nodeB
```

**Verdict:** PASS - rounds approximately every 60s fire huay aur peer selection B/C ke darmiyan rotate hui.

---

## Requirement 3 - Peer merges received revocations into local CRL

**Commands:**
```bash
# host
RUN_ID=$(date +%s)
R3_DID="did:guardian:gossiptest001-$RUN_ID"
echo "$R3_DID"

# nodeA - issue revocation
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$R3_DID" --reason compromised --severity critical --note "CRL-013 docker"

# nodeA - force one gossip round
curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool

# nodeB - verify arrival
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl check --did "$R3_DID"
```

**Observed:**
```text
Issued DID: did:guardian:gossiptest001-1784271221
nodeA trigger: success=true, peer_node=nodeB, pushed=1, peer_merged=1
nodeB check: revoked=true
entry id: urn:uuid:19ffd920-017a-4a39-928d-85ae3a9a8368
reason: compromised
severity: critical
revoker_role: owner
```

**Verdict:** PASS - nodeA ki revocation gossip ke through nodeB me merge hui.

---

## Requirement 4 - Forwards to other peers (transitive epidemic relay)

**Docker-adapted proof:**
`nodeC` ko offline rakha gaya, `nodeA` ne revocation `nodeB` ko seed ki, phir `nodeC` ko online la kar `nodeB -> nodeC` relay prove ki gayi. Yeh Docker topology ke liye valid relay proof hai.

**Commands:**
```bash
# host
NODEB_DID=$(docker exec sgx-nodeB cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")
R4_DOCKER_DID="did:guardian:gossiptest002-docker-$(date +%s)"
echo "$NODEB_DID"
echo "$R4_DOCKER_DID"

# nodeC OFF
docker stop sgx-nodeC

# nodeA - issue relay revocation
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$R4_DOCKER_DID" --reason stolen --severity critical --note "CRL-014 docker relay"

# nodeA -> nodeB until nodeB has it
until docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl check --did "$R4_DOCKER_DID" | grep -q '"revoked": true'; do
  curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool
  sleep 2
done

# nodeC ON
docker start sgx-nodeC
sleep 20

# nodeB -> nodeC until audit shows via_peer=nodeB
until docker exec sgx-nodeC sh -lc "grep -a 'revoked_did=$R4_DOCKER_DID' /var/log/sgx-guardian/audit-nodeC.log | grep -a 'via_peer=$NODEB_DID'"; do
  curl -s -X POST http://localhost:28443/api/v1/crl/gossip/trigger | python3 -m json.tool
  sleep 2
done

# nodeC final proof
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl check --did "$R4_DOCKER_DID"
docker exec sgx-nodeC sh -lc 'grep -a "CRL gossip merged" /var/log/sgx-guardian/audit-nodeC.log | tail -2'
```

**Observed:**
```text
R4_DOCKER_DID: did:guardian:gossiptest002-docker-1784285533
nodeA issue: urn:uuid:d98496bd-89cf-4c26-bb57-2ae95325d6c5
nodeA -> nodeB: success=true, peer_node=nodeB, pushed=1, peer_merged=1
nodeB check: revoked=true
nodeB -> nodeC: success=true, peer_node=nodeC, pushed=1, peer_merged=1
nodeC audit:
CRL gossip merged revocation revoked_did=did:guardian:gossiptest002-docker-1784285533
reason=stolen severity=critical
via_peer=did:guardian:9TiAZcjJMMEPA6r337Wy4UnWFofRePsd4T2SRi4VXq5o
nodeC check: revoked=true
```

**Verdict:** PASS - transitive relay `nodeA -> nodeB -> nodeC` prove hui, aur `nodeC` ne entry direct source ki bajaye `nodeB` se seekhi.

---

## Requirement 5 - Probabilistic flooding plus anti-entropy mechanisms

**Commands:**
```bash
# converged-state trigger checks
curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool
curl -s -X POST http://localhost:28443/api/v1/crl/gossip/trigger | python3 -m json.tool
curl -s -X POST http://localhost:38443/api/v1/crl/gossip/trigger | python3 -m json.tool
```

**Observed:**
```text
All three nodes returned:
- success=true
- merged=0
- pushed=0
- peer_merged=0
- message="gossip round completed"
```

**Verdict:** PASS - converged state me gossip cheap no-op anti-entropy rounds execute karti rahi.

---

## Requirement 6 - `peers_notified` tracking per entry

**Commands:**
```bash
# nodeA - check converged partition test entry
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl check --did "did:guardian:gossiptest004-1784287466"
```

**Observed:**
```text
For did:guardian:gossiptest004-1784287466
peers_notified:
- did:guardian:9TiAZcjJMMEPA6r337Wy4UnWFofRePsd4T2SRi4VXq5o
- did:guardian:sVNoXSb9wHaCfSkH6jtMLbFE6QXJoJG8H4vtAayKEUT
propagated: true
```

**Verdict:** PASS - entry-level peer acknowledgement tracking present hai.

---

## Requirement 7 - `propagated = true` at 80% Circle threshold

**Commands:**
```bash
# nodeA - threshold proof from partition test after all peers synced
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl check --did "did:guardian:gossiptest004-1784287466"
```

**Observed:**
```text
Circle size in Docker cohort:
- self + 2 other members
- threshold_pct = 80
- threshold_count = 2

For did:guardian:gossiptest004-1784287466
- peers_notified count = 2
- propagated = true
```

**Verdict:** PASS - entry propagated flag threshold completion ke baad true hui.

---

## Requirement 8 - Eventual consistency across network partitions

**Commands:**
```bash
# host
docker start sgx-nodeA >/dev/null 2>&1 || true
docker start sgx-nodeB >/dev/null 2>&1 || true
docker start sgx-nodeC >/dev/null 2>&1 || true
sleep 20

R8_TS=$(date +%s)
R8_DID1="did:guardian:gossiptest004-$R8_TS"
R8_DID2="did:guardian:gossiptest005-$R8_TS"
echo "$R8_DID1"
echo "$R8_DID2"

# nodeC partition
docker stop sgx-nodeC

# nodeA issues two revocations during partition
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$R8_DID1" --reason compromised --severity critical --note "CRL-018 part1"
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$R8_DID2" --reason policy_violation --severity high --note "CRL-018 part2"

# nodeA -> nodeB until both arrive
until docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl check --did "$R8_DID1" | grep -q '"revoked": true' && \
      docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl check --did "$R8_DID2" | grep -q '"revoked": true'; do
  curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool
  sleep 2
done

# nodeC rejoins
docker start sgx-nodeC
sleep 20

# nodeA + nodeB -> nodeC until both arrive
until docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl check --did "$R8_DID1" | grep -q '"revoked": true' && \
      docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl check --did "$R8_DID2" | grep -q '"revoked": true'; do
  curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool
  curl -s -X POST http://localhost:28443/api/v1/crl/gossip/trigger | python3 -m json.tool
  sleep 2
done

# final root convergence
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl root
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl root
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl root

# persistence check
docker restart sgx-nodeA
sleep 20
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl check --did "$R8_DID1"
```

**Observed:**
```text
R8_DID1: did:guardian:gossiptest004-1784287466
R8_DID2: did:guardian:gossiptest005-1784287466

nodeA issue #1:
- urn:uuid:bd4fd651-5a8e-4b3d-b1b6-6e9975569393
- sequence=73

nodeA issue #2:
- urn:uuid:976f1239-a60f-4def-a910-143bebda48dc
- sequence=74
- merkle_root=72c6547e105568228b17b950d2c31b936ed948aa5986f3272e3d3ac340d4888f

nodeA -> nodeB:
- success=true
- pushed=2
- peer_merged=2

nodeA -> nodeC after rejoin:
- success=true
- peer_node=nodeC
- pushed=2
- peer_merged=2

nodeC checks:
- R8_DID1 revoked=true
- R8_DID2 revoked=true

Final roots:
- nodeA: 72c6547e105568228b17b950d2c31b936ed948aa5986f3272e3d3ac340d4888f
- nodeB: 72c6547e105568228b17b950d2c31b936ed948aa5986f3272e3d3ac340d4888f
- nodeC: 72c6547e105568228b17b950d2c31b936ed948aa5986f3272e3d3ac340d4888f

After nodeA restart:
- R8_DID1 still revoked=true
- propagated=true
```

**Verdict:** PASS - partition ke baad teeno nodes identical Merkle root par converge huay aur restart persistence bhi sahi rahi.

---

## Requirement 9 - Decentralized behavior without any central authority

**Commands:**
```bash
# host
docker start sgx-nodeA >/dev/null 2>&1 || true
docker start sgx-nodeB >/dev/null 2>&1 || true
docker start sgx-nodeC >/dev/null 2>&1 || true
sleep 20

NODEB_DID=$(docker exec sgx-nodeB cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")
R9A_DID="did:guardian:gossiptest006a-$(date +%s)"
R9B_DID="did:guardian:gossiptest006b-$(date +%s)"
echo "$NODEB_DID"
echo "$R9A_DID"
echo "$R9B_DID"

# member-issued revocation with all nodes up
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl revoke --did "$R9A_DID" --reason compromised --severity high --note "CRL-020 member issued"

until docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl check --did "$R9A_DID" | grep -q '"revoked": true' && \
      docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl check --did "$R9A_DID" | grep -q '"revoked": true'; do
  curl -s -X POST http://localhost:28443/api/v1/crl/gossip/trigger | python3 -m json.tool
  sleep 2
done

# nodeA OFF, nodeB and nodeC remain ON
docker stop sgx-nodeA
sleep 5

# member issues revocation while owner/CA is OFF
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl revoke --did "$R9B_DID" --reason compromised --severity high --note "CRL-020 CA down"

until docker exec sgx-nodeC sh -lc "grep -a 'revoked_did=$R9B_DID' /var/log/sgx-guardian/audit-nodeC.log | grep -a 'via_peer=$NODEB_DID'"; do
  curl -s -X POST http://localhost:28443/api/v1/crl/gossip/trigger | python3 -m json.tool
  sleep 2
done

docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl check --did "$R9B_DID"
docker exec sgx-nodeC sh -lc 'grep -a "CRL gossip merged" /var/log/sgx-guardian/audit-nodeC.log | tail -2'
docker exec sgx-nodeB sh -lc 'grep -a "CRL gossip round" /var/log/sgx-guardian/audit-nodeB.log | tail -5'
docker exec sgx-nodeC sh -lc 'grep -a "CRL gossip round" /var/log/sgx-guardian/audit-nodeC.log | tail -5'

# restore nodeA
docker start sgx-nodeA
```

**Observed:**
```text
Member-issued DID with all nodes up:
- R9A_DID: did:guardian:gossiptest006a-1784287535
- nodeB issue: urn:uuid:c28ca9a5-1748-42fc-993b-22cac201541a
- nodeA check: revoked=true, revoker_role=member
- nodeC check: revoked=true, revoker_role=member

CA-down phase:
- nodeA status: Exited (137)
- R9B_DID: did:guardian:gossiptest006b-1784287535
- nodeB issue while nodeA OFF:
  urn:uuid:795674bd-c854-42c5-a6aa-58842b88599e
- nodeB -> nodeC trigger:
  success=true, peer_node=nodeC, pushed=1, peer_merged=1
- nodeC audit:
  CRL gossip merged revocation revoked_did=did:guardian:gossiptest006b-1784287535
  reason=compromised severity=high
  via_peer=did:guardian:9TiAZcjJMMEPA6r337Wy4UnWFofRePsd4T2SRi4VXq5o
- nodeC final check: revoked=true
- nodeB/nodeC audit logs show fresh gossip rounds during nodeA outage
```

**Verdict:** PASS - member-issued revocations propagate hui aur running `nodeB <-> nodeC` mesh `nodeA` ke outage ke dauran bhi kaam karti rahi.

---

# API Verification - Gossip Endpoints

## API 1 - GET `/api/v1/crl/gossip/status`

**Commands:**
```bash
curl -s http://localhost:18443/api/v1/crl/gossip/status | python3 -m json.tool
curl -s http://localhost:28443/api/v1/crl/gossip/status | python3 -m json.tool
curl -s http://localhost:38443/api/v1/crl/gossip/status | python3 -m json.tool
```

**Observed:**
```text
All three nodes returned valid JSON.
Common values observed:
- enabled=true
- port=50063
- interval_secs=60
- threshold_pct=80
- other_members=2
- threshold_count=2
- merkle_root=2c3ca11034a7f0f894e73ec6ef6b566d951f23f79db9bf1853ce12fd55a97fe0
```

**Verdict:** PASS - gossip status observability API teeno nodes par sahi kaam karti hai.

---

## API 2 - POST `/api/v1/crl/gossip/trigger`

**Commands:**
```bash
curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool
curl -s -X POST http://localhost:28443/api/v1/crl/gossip/trigger | python3 -m json.tool
curl -s -X POST http://localhost:38443/api/v1/crl/gossip/trigger | python3 -m json.tool
```

**Observed:**
```text
nodeA: success=true, peer_node=nodeB, merged=0, pushed=0, peer_merged=0
nodeB: success=true, peer_node=nodeA, merged=0, pushed=0, peer_merged=0
nodeC: success=true, peer_node=nodeA, merged=0, pushed=0, peer_merged=0
Common merkle_root:
2c3ca11034a7f0f894e73ec6ef6b566d951f23f79db9bf1853ce12fd55a97fe0
```

**Verdict:** PASS - manual one-round trigger API converged state me expected no-op result deti rahi.

---

## API 3 - Security: tampered entry rejected

**Commands:**
```bash
# host
API3_DID="did:guardian:gossip-api3-$(date +%s)"
echo "$API3_DID"

docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$API3_DID" --reason compromised --severity critical --note "API3 tamper seed"

until docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl check --did "$API3_DID" | grep -q '"revoked": true'; do
  curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool
  sleep 2
done

ROOT_BEFORE=$(docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl root | python3 -c "import sys,json; print(json.load(sys.stdin)['merkle_root'])")
REJECT_COUNT_BEFORE=$(docker exec sgx-nodeA sh -lc 'grep -a -c "CRL gossip rejected entry" /var/log/sgx-guardian/audit-nodeA.log || true')

docker run --rm -i --network container:sgx-nodeB --volumes-from sgx-nodeB:ro -e API3_DID="$API3_DID" python:3.12-slim python -u - <<'PY'
import json, os, socket, sys
self_did = json.load(open('/var/lib/sgx-guardian/identity/did.json'))['did']
crl = json.load(open('/var/lib/sgx-guardian/identity/crl/crl.json'))
target = os.environ["API3_DID"]
entry = None
for e in crl["entries"]:
    if e["revoked_did"] == target:
        entry = dict(e)
        break
if entry is None:
    print("ENTRY_NOT_FOUND", flush=True)
    sys.exit(1)
entry["severity"] = "low" if entry["severity"] != "low" else "high"
req = {"kind":"crl_sync_request","circle_id":crl["circle_id"],"sender_did":self_did,"sequence":0,"merkle_root":"","fingerprints":[]}
push = {"kind":"crl_sync_push","entries":[entry]}
s = socket.create_connection(("192.168.100.1", 50063), timeout=10)
f = s.makefile("rw")
f.write(json.dumps(req) + "\n"); f.flush(); print("RESPONSE:", f.readline().strip(), flush=True)
f.write(json.dumps(push) + "\n"); f.flush(); print("ACK:", f.readline().strip(), flush=True)
PY

docker exec sgx-nodeA sh -lc 'grep -a "CRL gossip rejected entry" /var/log/sgx-guardian/audit-nodeA.log | tail -1'

ROOT_AFTER=$(docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl root | python3 -c "import sys,json; print(json.load(sys.stdin)['merkle_root'])")
REJECT_COUNT_AFTER=$(docker exec sgx-nodeA sh -lc 'grep -a -c "CRL gossip rejected entry" /var/log/sgx-guardian/audit-nodeA.log || true')

[ "$ROOT_BEFORE" = "$ROOT_AFTER" ] && [ "$REJECT_COUNT_AFTER" -gt "$REJECT_COUNT_BEFORE" ] && echo "API3_PASS" || echo "API3_FAIL"
```

**Observed:**
```text
API3_DID: did:guardian:gossip-api3-1784288401
nodeA issue: urn:uuid:ad00a3fd-28cd-401d-87b9-7c0c7d323e5b
ROOT_BEFORE: 43bfeb185656788c8059c5fe7e22195e99a8a1e06e55a6ba3769a177fb8b64b1
RESPONSE received from nodeA
ACK: {"kind":"crl_sync_ack","merged":0,"merkle_root":"43bfeb185656788c8059c5fe7e22195e99a8a1e06e55a6ba3769a177fb8b64b1"}
nodeA audit:
CRL gossip rejected entry urn:uuid:ad00a3fd-28cd-401d-87b9-7c0c7d323e5b: invalid signature on CRL entry urn:uuid:ad00a3fd-28cd-401d-87b9-7c0c7d323e5b
ROOT_AFTER: 43bfeb185656788c8059c5fe7e22195e99a8a1e06e55a6ba3769a177fb8b64b1
Final check: API3_PASS
```

**Verdict:** PASS - tampered signed entry merge nahi hui, audit reject hua, Merkle root unchanged raha.

---

## API 4 - Revoked peer excluded both directions

**Commands:**
```bash
# host
NODEC_DID=$(docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")
echo "$NODEC_DID"

# cleanup old state on owner
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl unrevoke --did "$NODEC_DID" || true

# nodeA - revoke nodeC real DID
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$NODEC_DID" --reason compromised --severity critical --note "CRL-021 exclusion docker"

# status should drop
curl -s http://localhost:18443/api/v1/crl/gossip/status | python3 -m json.tool

# outbound exclusion
for i in 1 2 3; do
  curl -s -X POST http://localhost:18443/api/v1/crl/gossip/trigger | python3 -m json.tool
  sleep 1
done

# inbound rejection
until docker exec sgx-nodeA sh -lc "grep -a 'CRL gossip rejected sender' /var/log/sgx-guardian/audit-nodeA.log | grep -a '$NODEC_DID'"; do
  curl -s -X POST http://localhost:38443/api/v1/crl/gossip/trigger | python3 -m json.tool || true
  sleep 2
done

docker exec sgx-nodeA sh -lc 'grep -a "CRL gossip rejected sender" /var/log/sgx-guardian/audit-nodeA.log | tail -1'

# owner restore
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl unrevoke --did "$NODEC_DID"

# restore checks
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl check --did "$NODEC_DID"
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl check --did "$NODEC_DID"
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl check --did "$NODEC_DID"
curl -s http://localhost:18443/api/v1/crl/gossip/status | python3 -m json.tool
```

**Observed:**
```text
NODEC_DID:
did:guardian:sVNoXSb9wHaCfSkH6jtMLbFE6QXJoJG8H4vtAayKEUT

nodeA revoke:
urn:uuid:cb17f26b-0337-4ffb-b33e-0dc3053b2997

nodeA status after revoke:
- other_members=1
- threshold_count=1

nodeA trigger loop:
- peer_node=nodeB
- nodeC was not selected

nodeA audit:
CRL gossip rejected sender=did:guardian:sVNoXSb9wHaCfSkH6jtMLbFE6QXJoJG8H4vtAayKEUT: sender is revoked: did:guardian:sVNoXSb9wHaCfSkH6jtMLbFE6QXJoJG8H4vtAayKEUT

After owner unrevoke:
- nodeA check: revoked=false
- nodeC check: revoked=false
- nodeB check: revoked=true

Final nodeA status:
- other_members=2
- threshold_count=2
```

**Verdict:** PARTIAL PASS

What passed:
- revoked peer outbound exclusion worked
- revoked peer inbound rejection worked
- status counters recomputed correctly

What did not fully pass:
- owner unrevoke removed the entry on `nodeA`, and `nodeC` no longer showed revoked
- but `nodeB` still showed `revoked=true`
- therefore full cluster-wide restore convergence was not proven

Implementation note:
Current gossip implementation exchanges present entry fingerprints and missing entries, but unrevoke removes an entry locally rather than gossiping a delete/tombstone. That explains why exclusion behavior passes while full unrevoke convergence remains partial in Docker.

---

## Final Expected State

```text
Requirement 1: PASS
Requirement 2: PASS
Requirement 3: PASS
Requirement 4: PASS
Requirement 5: PASS
Requirement 6: PASS
Requirement 7: PASS
Requirement 8: PASS
Requirement 9: PASS

API 1: PASS
API 2: PASS
API 3: PASS
API 4: PARTIAL PASS
```
