# CRL Emergency Revocation - Docker Verification Log
**Environment:** Docker container cohort (WSL2) | **Date:** 2026-07-19 | **Tester:** Asad Ali
**Test tag:** CRL-series (CRL-022 - CRL-034) | **Plan:** `docs/CRL_Emergency_Revocation_Complete_Plan.md`

---

## 📌 Task Description

> **CRL Gossip - Emergency Revocation**
>
> Implement priority emergency broadcast channel for critical revocations (compromised devices, active attacks). When Guardian marked `severity: critical`, immediately broadcast `REVOCATION_NOTICE` to all connected peers, bypassing normal gossip intervals. Receiving Guardians prioritize forwarding emergency revocations before routine gossip. Terminate all active sessions with revoked DID instantly. Send push notifications to users. Emergency revocations propagate to 90%+ of Circle within 30 seconds vs 5-10 minutes for normal gossip. Essential for containing active breaches.

---

## 📋 How to Use This File

**Jab bhi koi Requirement ya API verify ho jaye (PASS):**
1. `[ ]` ko `[x]` karo aur `## ⏳` ko `## ✅` kar do
2. **Commands:** section mein woh exact command likhna jo run kiya
3. **Result:** section mein wohi terminal output ya short observed summary paste karna
4. **Verdict:** ek line mein confirm karna - kya pass hua

**Jab koi Requirement ya API FAIL ho:**
1. **Pehle command side verify karo**:
   - Kya teeno containers up hain?
   - Kya emergency REST status teeno nodes par respond kar raha hai?
   - Kya `SGX_FORCE_SOFTWARE_KEYS=1` active build/run profile use ho rahi hai?
   - Kya test DID fresh hai ya pehle se revoked nahi?
   - Kya nodeA ne peer requests approve kar li hain?
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai
   - Exact error message jo aaya
   - Kya try kiya aur kya nahi chala

**⚠️ Common mistakes jo dobara na karein:**
- DID hamesha poora `did:guardian:...` prefix ke sath likho
- Agar pehle se real peer DID revoked ho to `unrevoke` ya `down -v` clean reset karo
- Critical path ke liye `--severity critical` zaroor dena
- Session termination test se pehle واقعی active debug CoT session seed karo
- Docker cohort ke liye host shell variables `A/B/C`, `execA/B/C`, `IP_B/IP_C` pehle set karo

**Symbols:**
- `✅` = Verified and passed
- `❌` = Confirmed code-side failure
- `⏳` = Not yet retested in the current run

---

## ✅ Latest Verified Status

- 2026-07-19 ke successful Docker run mein `CRL-029` bhi pass hua.
- Effective status at that point:
  - Requirements: `8/8`
  - APIs: `4/4`
  - CLI / Runtime Hooks: `2/2`
- Session termination proof ke liye Docker cohort mein `/api/v1/crl/emergency/debug/session` helper use hua.

---

## 🐳 Docker Notes

- Saari commands host shell se chalani hain unless explicitly node/container mention ho.
- REST ports:
  - `nodeA` -> `http://127.0.0.1:18443`
  - `nodeB` -> `http://127.0.0.1:28443`
  - `nodeC` -> `http://127.0.0.1:38443`
- Overlay IPs:
  - `nodeA` -> `172.31.250.10`
  - `nodeB` -> `172.31.250.11`
  - `nodeC` -> `172.31.250.12`
- `sgx-pa-cli` commands ke liye `SGX_FORCE_SOFTWARE_KEYS=1` runtime env use ki gayi.
- Agar stale CRL state ya old real-DID revoke interfere kare to:
  - `docker compose -f optional/container-cohort/docker-compose.dev.yml down -v`
  - phir fresh `up -d --build`

---

## ⚡ Test Setup (run once before Requirement 1)

```bash
cd ~/SGX

docker info >/dev/null

cat >/tmp/cc-softkeys.yml <<'EOF'
services:
  nodeA: { environment: { SGX_FORCE_SOFTWARE_KEYS: "1" } }
  nodeB: { environment: { SGX_FORCE_SOFTWARE_KEYS: "1" } }
  nodeC: { environment: { SGX_FORCE_SOFTWARE_KEYS: "1" } }
EOF

docker compose -f optional/container-cohort/docker-compose.dev.yml down
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-softkeys.yml up -d --build
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-softkeys.yml ps

A=http://127.0.0.1:18443
B=http://127.0.0.1:28443
C=http://127.0.0.1:38443

IP_A=172.31.250.10
IP_B=172.31.250.11
IP_C=172.31.250.12

execA(){ docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA "$@"; }
execB(){ docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB "$@"; }
execC(){ docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC "$@"; }

until curl -sf $A/api/v1/crl/emergency/status >/dev/null; do sleep 2; done
until curl -sf $B/api/v1/crl/emergency/status >/dev/null; do sleep 2; done
until curl -sf $C/api/v1/crl/emergency/status >/dev/null; do sleep 2; done

# Fresh down -v ke baad peer approvals ko member par force kar do
docker exec sgx-nodeA sh -lc 'sed -i "s/approve: '\''false'\''/approve: member/" /var/lib/sgx-guardian/nebula/requests/nodeB.yaml /var/lib/sgx-guardian/nebula/requests/nodeC.yaml' 2>/dev/null || true

DID_A=$(docker exec sgx-nodeA cat /var/lib/sgx-guardian/identity/did.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["did"])')
DID_B=$(docker exec sgx-nodeB cat /var/lib/sgx-guardian/identity/did.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["did"])')
DID_C=$(docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/did.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["did"])')

echo "$DID_A"
echo "$DID_B"
echo "$DID_C"
```

---

## 📊 Requirements Checklist (8 Requirements)

- [ ] Requirement 1 - Emergency UDP listener on port `50064` with env gating
- [ ] Requirement 2 - Critical local revoke triggers immediate one-to-many emergency broadcast
- [ ] Requirement 3 - Receiving Guardian re-verifies and merges notice through the existing locked CRL path
- [ ] Requirement 4 - Receiver re-broadcast is bounded by TTL and fingerprint dedup
- [ ] Requirement 5 - Critical revoke terminates active CoT sessions for the revoked DID
- [ ] Requirement 6 - Durable emergency notification feed is recorded for frontend/mobile push
- [ ] Requirement 7 - Emergency observability and manual rebroadcast endpoints work
- [ ] Requirement 8 - Emergency path coexists with routine gossip and enforcement; Merkle roots still converge

---

## 📊 API Checklist (4 APIs)

- [ ] API 1 - POST `/api/v1/crl/revoke`
- [ ] API 2 - GET `/api/v1/crl/emergency/status`
- [ ] API 3 - POST `/api/v1/crl/emergency/broadcast?did=`
- [ ] API 4 - GET `/api/v1/crl/emergency/notifications`

---

## 🖥️ CLI / Runtime Hooks Checklist (2 Hooks)

- [ ] Hook 1 - `sgx-pa-cli crl revoke --severity critical` sends emergency broadcast
- [ ] Hook 2 - `SGX_CRL_EMERGENCY_ENABLED=0` disables listener/broadcast path cleanly

---

## ⏳ CRL-022 - Emergency listener starts on UDP 50064 and status reports enabled config

**Commands:**
```bash
curl -s $A/api/v1/crl/emergency/status | python3 -m json.tool
curl -s $B/api/v1/crl/emergency/status | python3 -m json.tool
curl -s $C/api/v1/crl/emergency/status | python3 -m json.tool

docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-softkeys.yml logs --since 10m nodeA nodeB nodeC | grep 'CRL-EMERGENCY listener on 0.0.0.0:50064'
```

**Result:**
```text
Pass condition:
- enabled=true
- port=50064
- ttl present
- listener log visible on running nodes
```

**Verdict:** ⏳ Fill after rerun. Successful Docker runs showed `enabled: true`, `port: 50064`, `ttl: 1`, and listener startup logs.

---

## ⏳ CRL-023 - Critical CLI revoke triggers immediate emergency broadcast

**Commands:**
```bash
DID_023="did:guardian:test-emergency-cli-001"

execA sgx-pa-cli crl revoke --did "$DID_023" --reason compromised --severity critical --note "CRL-023"

for i in $(seq 1 30); do execB sgx-pa-cli crl check --did "$DID_023" | grep -q '"revoked": true' && break; sleep 1; done
for i in $(seq 1 30); do execC sgx-pa-cli crl check --did "$DID_023" | grep -q '"revoked": true' && break; sleep 1; done

execB sgx-pa-cli crl check --did "$DID_023"
execC sgx-pa-cli crl check --did "$DID_023"

curl -s $A/api/v1/crl/emergency/status | python3 -m json.tool
curl -s $B/api/v1/crl/emergency/status | python3 -m json.tool
curl -s $C/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
Pass condition:
- nodeA CLI prints emergency broadcast line
- nodeB/nodeC eventually show "revoked": true
- receiver status counters increment on nodeB/nodeC
```

**Verdict:** ⏳ Fill after rerun. This section also covers Hook 1.

---

## ⏳ CRL-024 - Critical REST revoke triggers immediate emergency broadcast

**Commands:**
```bash
DID_024="did:guardian:test-emergency-rest-002"

curl -s -X POST $A/api/v1/crl/revoke \
  -H 'Content-Type: application/json' \
  -d '{"did":"'"$DID_024"'","reason":"compromised","severity":"critical","note":"CRL-024"}' \
  | python3 -m json.tool

for i in $(seq 1 30); do execB sgx-pa-cli crl check --did "$DID_024" | grep -q '"revoked": true' && break; sleep 1; done
for i in $(seq 1 30); do execC sgx-pa-cli crl check --did "$DID_024" | grep -q '"revoked": true' && break; sleep 1; done

execB sgx-pa-cli crl check --did "$DID_024"
execC sgx-pa-cli crl check --did "$DID_024"

curl -s $B/api/v1/crl/emergency/status | python3 -m json.tool
curl -s $C/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
Pass condition:
- REST returns status=success with CRL entry payload
- nodeB/nodeC eventually show revoked=true for the same DID
- receiver emergency counters move without waiting for routine gossip
```

**Verdict:** ⏳ Fill after rerun. Successful 2026-07-19 Docker run used `did:guardian:test-emergency-rest-002` and propagated to both peers.

---

## ⏳ CRL-025 - Non-critical revoke does not use emergency channel

**Commands:**
```bash
DID_025="did:guardian:test-emergency-negative-001"

curl -s $B/api/v1/crl/emergency/status > /tmp/b_pre_025.json
curl -s $C/api/v1/crl/emergency/status > /tmp/c_pre_025.json

execA sgx-pa-cli crl revoke --did "$DID_025" --reason policy_violation --severity medium --note "CRL-025"
sleep 5

curl -s $B/api/v1/crl/emergency/status > /tmp/b_post_025.json
curl -s $C/api/v1/crl/emergency/status > /tmp/c_post_025.json

python3 - <<'PY'
import json
for n in ("b","c"):
    a=json.load(open(f"/tmp/{n}_pre_025.json"))
    b=json.load(open(f"/tmp/{n}_post_025.json"))
    print(n, "received", b["notices_received"]-a["notices_received"],
             "merged", b["notices_merged"]-a["notices_merged"],
             "rebroadcast", b["notices_rebroadcast"]-a["notices_rebroadcast"])
PY
```

**Result:**
```text
Pass condition:
- all emergency deltas remain 0 on nodeB and nodeC
```

**Verdict:** ⏳ Fill after rerun. Successful run showed `received 0 merged 0 rebroadcast 0` on both receivers.

---

## ⏳ CRL-026 - Receiver verifies signed notice and merges into local CRL

**Commands:**
```bash
DID_026="did:guardian:test-merge-001"

execA sgx-pa-cli crl revoke --did "$DID_026" --reason compromised --severity critical --note "CRL-026"

for i in $(seq 1 30); do execB sgx-pa-cli crl check --did "$DID_026" | grep -q '"revoked": true' && break; sleep 1; done
for i in $(seq 1 30); do execC sgx-pa-cli crl check --did "$DID_026" | grep -q '"revoked": true' && break; sleep 1; done

execB sgx-pa-cli crl check --did "$DID_026"
execC sgx-pa-cli crl check --did "$DID_026"

execA sgx-pa-cli crl root
execB sgx-pa-cli crl root
execC sgx-pa-cli crl root
```

**Result:**
```text
Pass condition:
- nodeB/nodeC expose revoked=true for the same signed entry id
- roots/sequence converge across nodes after merge
```

**Verdict:** ⏳ Fill after rerun. Successful runs showed both receivers merged the same critical entry.

---

## ⏳ CRL-027 - Invalid or tampered emergency notice is rejected

**Commands:**
```bash
GOOD_DID="did:guardian:test-ttl-001"
BAD_DID="did:guardian:test-tampered-001"

curl -s "$A/api/v1/crl/check?did=$GOOD_DID" > /tmp/good_check.json
curl -s $B/api/v1/crl/emergency/status > /tmp/b_pre_027.json

python3 - <<'PY'
import json, uuid, datetime
good=json.load(open('/tmp/good_check.json'))
entry=good["entry"]
entry["revoked_did"]="did:guardian:test-tampered-001"
notice={
    "kind":"crl_revocation_notice",
    "circle_id":entry["circle_id"],
    "origin_did":entry["revoker_did"],
    "notice_id":str(uuid.uuid4()),
    "ttl":1,
    "sent_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "entry":entry
}
open('/tmp/tampered_notice.json','w').write(json.dumps(notice))
PY

python3 - <<'PY'
import socket
sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(open('/tmp/tampered_notice.json','rb').read(), ("172.31.250.11", 50064))
PY

sleep 2

execB sgx-pa-cli crl check --did "$BAD_DID"
curl -s $B/api/v1/crl/emergency/status | tee /tmp/b_post_027.json | python3 -m json.tool
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-softkeys.yml logs --since 2m nodeB | grep -E 'rejected|dropped|verify failed' || true
```

**Result:**
```text
Pass condition:
- nodeB check on BAD_DID stays revoked=false
- notices_merged does not increase
- no forged/tampered entry appears in nodeB CRL
```

**Verdict:** ⏳ Fill after rerun. Successful Docker run kept `BAD_DID` absent and merge counters unchanged.

---

## ⏳ CRL-028 - Re-broadcast is bounded by TTL and dedup

**Commands:**
```bash
DID_028="did:guardian:test-ttl-001"

curl -s $B/api/v1/crl/emergency/status > /tmp/b0.json
curl -s $C/api/v1/crl/emergency/status > /tmp/c0.json

execA sgx-pa-cli crl revoke --did "$DID_028" --reason compromised --severity critical --note "CRL-028"

for i in $(seq 1 30); do execB sgx-pa-cli crl check --did "$DID_028" | grep -q '"revoked": true' && break; sleep 1; done
for i in $(seq 1 30); do execC sgx-pa-cli crl check --did "$DID_028" | grep -q '"revoked": true' && break; sleep 1; done

curl -s $B/api/v1/crl/emergency/status > /tmp/b1.json
curl -s $C/api/v1/crl/emergency/status > /tmp/c1.json

curl -s -X POST "$A/api/v1/crl/emergency/broadcast?did=$DID_028" | python3 -m json.tool
sleep 2

curl -s $B/api/v1/crl/emergency/status > /tmp/b2.json
curl -s $C/api/v1/crl/emergency/status > /tmp/c2.json

python3 - <<'PY'
import json
for n in ("b","c"):
    s0=json.load(open(f"/tmp/{n}0.json"))
    s1=json.load(open(f"/tmp/{n}1.json"))
    s2=json.load(open(f"/tmp/{n}2.json"))
    print(n,
          "first_merge_delta", s1["notices_merged"]-s0["notices_merged"],
          "first_rebroadcast_delta", s1["notices_rebroadcast"]-s0["notices_rebroadcast"],
          "dup_merge_delta", s2["notices_merged"]-s1["notices_merged"],
          "dup_rebroadcast_delta", s2["notices_rebroadcast"]-s1["notices_rebroadcast"],
          "dup_received_delta", s2["notices_received"]-s1["notices_received"])
PY
```

**Result:**
```text
Pass condition:
- first critical event increments merge/rebroadcast once
- duplicate re-broadcast increments received only
- duplicate re-broadcast does not increment merged/rebroadcast again
```

**Verdict:** ⏳ Fill after rerun. Successful run showed on both receivers:
`first_merge_delta 1`, `first_rebroadcast_delta 1`, `dup_merge_delta 0`, `dup_rebroadcast_delta 0`, `dup_received_delta 1`.

---

## ⏳ CRL-029 - Critical revoke terminates active CoT sessions

**Commands:**
```bash
# If DID_C was previously revoked, clear it first
execA sgx-pa-cli crl unrevoke --did "$DID_C"

curl -s -X POST "$B/api/v1/crl/emergency/debug/session" \
  -H 'Content-Type: application/json' \
  -d '{"did":"'"$DID_C"'","transport":"Ethernet"}' \
  | python3 -m json.tool

curl -s "$B/api/v1/crl/emergency/debug/session?did=$DID_C" | python3 -m json.tool

execA sgx-pa-cli crl revoke --did "$DID_C" --reason compromised --severity critical --note "CRL-029"
sleep 3

curl -s "$B/api/v1/crl/emergency/debug/session?did=$DID_C" | python3 -m json.tool
curl -s $B/api/v1/crl/emergency/status | python3 -m json.tool
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-softkeys.yml logs --since 2m nodeB | grep 'sessions_terminated='
```

**Result:**
```text
Pass condition:
- before revoke: debug/session shows exists=true and active session present
- after revoke: debug/session shows exists=false and session=null
- nodeB emergency status shows sessions_terminated > 0
- nodeB logs show EMERGENCY applied ... sessions_terminated=1
```

**Verdict:** ⏳ Fill after rerun. Successful 2026-07-19 Docker run satisfied all four pass conditions.

---

## ⏳ CRL-030 - Durable emergency notification feed is recorded

**Commands:**
```bash
curl -s $B/api/v1/crl/emergency/notifications | python3 -m json.tool
curl -s $C/api/v1/crl/emergency/notifications | python3 -m json.tool

docker exec sgx-nodeB sh -lc 'tail -n 5 /var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl'
docker exec sgx-nodeC sh -lc 'tail -n 5 /var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl'
```

**Result:**
```text
Pass condition:
- API returns most-recent-first notification objects
- JSONL feed exists on receivers
- entries include revoked_did, severity, origin_did, sessions_terminated, headline
```

**Verdict:** ⏳ Fill after rerun. Successful runs showed durable feed entries for `test-emergency-cli-002`, `test-merge-001`, and `test-ttl-001`.

---

## ⏳ CRL-031 - GET /api/v1/crl/emergency/status exposes counters and last_notice

**Commands:**
```bash
curl -s $A/api/v1/crl/emergency/status | python3 -m json.tool
curl -s $B/api/v1/crl/emergency/status | python3 -m json.tool
curl -s $C/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
Pass condition:
- JSON includes enabled, port, ttl
- counters include notices_sent, notices_received, notices_merged, notices_rebroadcast, sessions_terminated
- last_notice includes direction, revoked_did, origin_did, peers, merged, at
```

**Verdict:** ⏳ Fill after rerun. Successful runs showed all fields populated as expected.

---

## ⏳ CRL-032 - POST /api/v1/crl/emergency/broadcast re-broadcasts an existing critical entry

**Commands:**
```bash
curl -s -X POST "$A/api/v1/crl/emergency/broadcast?did=$DID_028" | python3 -m json.tool

curl -s $B/api/v1/crl/emergency/status | python3 -m json.tool
curl -s $C/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
Pass condition:
- API returns success=true with same revoked_did
- receivers do not merge the same fingerprint again
- this doubles as manual rebroadcast proof for Requirement 7
```

**Verdict:** ⏳ Fill after rerun. Successful run returned `message: "emergency broadcast dispatched"` and duplicate merges stayed at `0`.

---

## ⏳ CRL-033 - UDP 50064 is allowed by enforcement and emergency path survives firewall policy

**Commands:**
```bash
grep -n '50063\|50064' src/enforcement/executor.rs

cat >/tmp/cc-enforcement.yml <<'EOF'
services:
  nodeA: { environment: { SGX_DISABLE_POLICY_ENFORCEMENT: "0" } }
  nodeB: { environment: { SGX_DISABLE_POLICY_ENFORCEMENT: "0" } }
  nodeC: { environment: { SGX_DISABLE_POLICY_ENFORCEMENT: "0" } }
EOF

docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-enforcement.yml down
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-enforcement.yml up -d --build
```

**Result:**
```text
Pass condition:
- source shows udp dport 50064 accept and udp sport 50064 accept
- enforcement-enabled cohort still boots successfully
- emergency tests continue to pass under the enforcement-enabled profile
```

**Verdict:** ⏳ Fill after rerun. Previously verified source allow-list:
`tcp dport 50063 accept`, `udp dport 50064 accept`, `udp sport 50064 accept`.

---

## ⏳ CRL-034 - Emergency path preserves root convergence with routine gossip

**Commands:**
```bash
curl -s $A/api/v1/crl/gossip/status > /tmp/a_034.json
curl -s $B/api/v1/crl/gossip/status > /tmp/b_034.json
curl -s $C/api/v1/crl/gossip/status > /tmp/c_034.json

python3 - <<'PY'
import json
a=json.load(open('/tmp/a_034.json'))
b=json.load(open('/tmp/b_034.json'))
c=json.load(open('/tmp/c_034.json'))
print("sequence:", a["sequence"], b["sequence"], c["sequence"])
print("root:", a["merkle_root"], b["merkle_root"], c["merkle_root"])
print("all_equal:", a["sequence"]==b["sequence"]==c["sequence"] and a["merkle_root"]==b["merkle_root"]==c["merkle_root"])
PY
```

**Result:**
```text
Pass condition:
- all three nodes report the same sequence
- all three nodes report the same merkle_root
- all_equal prints True
```

**Verdict:** ⏳ Fill after rerun. Successful Docker run showed `sequence: 12 12 12` and identical Merkle root on all three nodes.

---

## ⏳ Hook 2 - SGX_CRL_EMERGENCY_ENABLED=0 disables listener/broadcast path cleanly

**Commands:**
```bash
cat >/tmp/cc-emergency-off.yml <<'EOF'
services:
  nodeA: { environment: { SGX_CRL_EMERGENCY_ENABLED: "0" } }
  nodeB: { environment: { SGX_CRL_EMERGENCY_ENABLED: "0" } }
  nodeC: { environment: { SGX_CRL_EMERGENCY_ENABLED: "0" } }
EOF

docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-emergency-off.yml down
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-emergency-off.yml up -d

curl -s $A/api/v1/crl/emergency/status | python3 -m json.tool
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-emergency-off.yml logs --since 10m nodeA nodeB nodeC | grep 'CRL-EMERGENCY listener on' || true

DID_H2="did:guardian:test-emergency-disabled-001"
execA sgx-pa-cli crl revoke --did "$DID_H2" --reason compromised --severity critical --note "Hook2"
sleep 5

execB sgx-pa-cli crl check --did "$DID_H2"
execC sgx-pa-cli crl check --did "$DID_H2"

# restore normal profile afterwards
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-emergency-off.yml down
docker compose -f optional/container-cohort/docker-compose.dev.yml -f /tmp/cc-softkeys.yml up -d --build
```

**Result:**
```text
Pass condition:
- status.enabled=false
- no CRL-EMERGENCY listener log appears
- local critical revoke still creates local CRL entry
- peers do not receive it through emergency fast path
```

**Verdict:** ⏳ Fill after rerun. Successful run showed `enabled: false`, no listener log, and both peer checks stayed `revoked: false`.

---

## 📝 Notes / Issues Found During Verification

```text
- Docker cohort builds from optional/container-cohort/overlay/, so emergency/CoT fixes must exist there too.
- CRL-029 originally failed until overlay main.rs also registered the global CoT SessionManager.
- REST revoke in Docker requires the softkeys profile active so runtime signing does not fall back to missing SE050 tooling.
- If a real peer DID was revoked in an earlier test, use unrevoke or a full down -v reset before CRL-029.
```

---

## ✅ Final Summary

- Requirements Passed: `8/8` in the successful 2026-07-19 Docker run
- APIs Passed: `4/4` in the successful 2026-07-19 Docker run
- CLI / Runtime Hooks Passed: `2/2` in the successful 2026-07-19 Docker run
- Overall Verdict: `PASS` for Docker container cohort verification
